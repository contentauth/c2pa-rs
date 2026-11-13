// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Deterministic RFC 3161 CMS signature and message-imprint verification.
//!
//! Parsing and successful cryptography do **not** establish certificate-profile
//! validity, chain validity, TSA trust, or application acceptance. No clock,
//! randomness, network client, or executor is used. Generation time is attested
//! data, not an accepted signing time.
//!
//! Signers are tried in decoded CMS order. Each signer uses the first matching
//! certificate in decoded certificate order (issuer/serial or strictly decoded
//! SKI). The host can reject one candidate under its policy and try the next.
//!
//! ```
//! use contentauth_pki::timestamp::verification::ParsedTimestamp;
//!
//! # fn example(token: &[u8], message: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let parsed = ParsedTimestamp::parse(token)?;
//!
//! let signed = parsed
//!     .verify_signatures()
//!     .next()
//!     .ok_or("no timestamp signer")??;
//!
//! // Inspect signed.generation_time(), signed.signer_validity(), and
//! // signed.accuracy_seconds() under the host's temporal policy.
//! let verified = signed.verify_message_imprint(message)?;
//!
//! // The host must still validate the certificate profile and chain against
//! // its TSA trust anchors before accepting verified.generation_time().
//! let _certificate = verified.signature().signer_certificate();
//!
//! # Ok(())
//! # }
//! ```

use std::str::FromStr;

use asn1_rs::FromDer;
use bcder::{decode::Constructed, OctetString};
use c2pa_raw_crypto::validator_for_sig_and_hash_algs;
use chrono::{DateTime, Utc};
use der::asn1::ObjectIdentifier;
use rasn::{prelude::*, types};
use rasn_cms::{CertificateChoices, SignerIdentifier};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use thiserror::Error;

use super::response::{
    signed_data_and_bytes_from_time_stamp_response, signed_data_from_time_stamp_response,
    tst_info_from_signed_data, ContentInfo,
};
use crate::{
    asn1::rfc3161::{Accuracy, TimeStampResp, TstInfo},
    x509::certificate::subject_key_identifier_matches,
};

#[cfg(test)]
mod rsa_pss_ski_regression;
#[cfg(test)]
mod signed_attrs_tests;

/// Stage at which a candidate failed, independent of host status-code policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationStage {
    /// Outer response, token, or CMS decoding.
    Envelope,

    /// Ambiguous duplicate CMS signatures.
    DuplicateSigners,

    /// Missing or unsupported certificate choices.
    Certificates,

    /// No certificate matches this signer's identifier.
    SignerIdentifier,

    /// Missing or malformed timestamp information.
    TimestampInfo,

    /// CMS signed attributes or their digest.
    SignedAttributes,

    /// Signature algorithm, parameters, or public-key compatibility.
    SignatureAlgorithm,

    /// Cryptographic signature validation.
    Signature,

    /// Algorithm or digest of the time-stamped message.
    MessageImprint,
}

/// Typed cryptographic/codec failure, without a profile or trust verdict.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VerificationErrorKind {
    /// The encoded data could not be interpreted.
    #[error("decode error ({0})")]
    DecodeError(String),

    /// Signed content or the message imprint does not match.
    #[error("time stamp does not match data")]
    InvalidData,

    /// The algorithm or its parameters are outside the supported profiles.
    #[error("time stamp contains an unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The CMS signature does not verify; this says nothing about TSA trust.
    #[error("timestamp signature did not verify")]
    SignatureMismatch,

    /// This signer has no matching embedded certificate.
    #[error("no matching timestamp signer certificate")]
    NoMatchingCertificate,
}

/// A typed failure with its stage and diagnostic, for host reporting.
#[derive(Debug, Error)]
#[error("{kind}")]
pub struct VerificationError {
    /// Failed operation.
    pub stage: VerificationStage,

    /// Codec or cryptographic failure.
    pub kind: VerificationErrorKind,

    /// Human-readable diagnostic; not an application status code.
    pub diagnostic: &'static str,
}

impl VerificationError {
    fn new(
        stage: VerificationStage,
        kind: VerificationErrorKind,
        diagnostic: &'static str,
    ) -> Self {
        Self {
            stage,
            kind,
            diagnostic,
        }
    }
}

/// Parsed response/token and its embedded certificates, all still unverified.
///
/// Both granted `TimeStampResp` and legacy bare `TimeStampToken` forms are
/// accepted. The original signed-data bytes are retained for signed-attribute
/// fidelity; duplicate signature values are rejected before trying any signer.
pub struct ParsedTimestamp {
    signed_data: rasn_cms::SignedData,
    signed_data_bytes: Vec<u8>,
    certificates: Vec<Vec<u8>>,
}

impl ParsedTimestamp {
    /// Parse a timestamp envelope without establishing authenticity.
    pub fn parse(token: &[u8]) -> Result<Self, VerificationError> {
        let (signed_data, signed_data_bytes) =
            signed_data_and_bytes_from_time_stamp_response(token)
                .map_err(|kind| {
                    VerificationError::new(
                        VerificationStage::Envelope,
                        kind,
                        "could not parse timestamp data",
                    )
                })?
                .ok_or_else(|| {
                    VerificationError::new(
                        VerificationStage::Envelope,
                        VerificationErrorKind::DecodeError("unable to find signed data".into()),
                        "could not parse timestamp data",
                    )
                })?;

        let raw = received_signer_infos(&signed_data_bytes);

        if has_duplicate_signatures(&signed_data, raw.as_deref()) {
            return Err(VerificationError::new(
                VerificationStage::DuplicateSigners,
                VerificationErrorKind::DecodeError(
                    "timestamp signer infos contain duplicate signatures".into(),
                ),
                "timestamp signer infos contain duplicate signatures",
            ));
        }

        let certificates = certificate_ders(&signed_data)?.ok_or_else(|| {
            VerificationError::new(
                VerificationStage::Certificates,
                VerificationErrorKind::DecodeError("time stamp contains no certificates".into()),
                "could not parse timestamp data",
            )
        })?;

        Ok(Self {
            signed_data,
            signed_data_bytes,
            certificates,
        })
    }

    /// Verify each CMS signer, preserving decoded order and per-signer failures.
    ///
    /// This checks signed-attribute digests and signature algorithms/parameters,
    /// but not the message imprint, temporal policy, certificate profile, or trust.
    /// A missing matching certificate is a typed per-signer failure, so hosts may
    /// retain their own last-candidate diagnostic semantics.
    pub fn verify_signatures(
        &self,
    ) -> impl Iterator<Item = Result<SignatureVerifiedTimestamp<'_>, VerificationError>> {
        let raw = received_signer_infos(&self.signed_data_bytes);

        self.signed_data
            .signer_infos
            .to_vec()
            .into_iter()
            .map(move |signer| self.verify_signature(signer, raw.as_deref()))
    }

    fn verify_signature(
        &self,
        signer: &rasn_cms::SignerInfo,
        raw: Option<&[asn1_rs::Any<'_>]>,
    ) -> Result<SignatureVerifiedTimestamp<'_>, VerificationError> {
        let choices = self
            .signed_data
            .certificates
            .as_ref()
            .ok_or_else(|| {
                VerificationError::new(
                    VerificationStage::Certificates,
                    VerificationErrorKind::DecodeError(
                        "time stamp contains no certificates".into(),
                    ),
                    "could not parse timestamp data",
                )
            })?
            .to_vec();

        let signer_index = choices
            .iter()
            .position(|choice| signer_certificate_matches(choice, &signer.sid))
            .ok_or_else(|| {
                VerificationError::new(
                    VerificationStage::SignerIdentifier,
                    VerificationErrorKind::NoMatchingCertificate,
                    "no matching timestamp signer certificate",
                )
            })?;

        let CertificateChoices::Certificate(cert) = choices[signer_index] else {
            return Err(VerificationError::new(
                VerificationStage::Certificates,
                VerificationErrorKind::DecodeError(
                    "time stamp certificate could not be processed".into(),
                ),
                "could not parse timestamp data",
            ));
        };

        let tst = tst_info_from_signed_data(&self.signed_data)
            .map_err(|_| {
                VerificationError::new(
                    VerificationStage::TimestampInfo,
                    VerificationErrorKind::InvalidData,
                    "timestamp response had no TstInfo",
                )
            })?
            .ok_or_else(|| {
                VerificationError::new(
                    VerificationStage::TimestampInfo,
                    VerificationErrorKind::InvalidData,
                    "timestamp response had no TstInfo",
                )
            })?;

        verify_attribute_digest(signer, &self.signed_data)?;

        let malformed = |kind, diagnostic| {
            VerificationError::new(VerificationStage::SignedAttributes, kind, diagnostic)
        };

        let tbs = match signed_attributes_digested_content(signer).map_err(|_| {
            malformed(
                VerificationErrorKind::DecodeError("timestamp signer info malformed".into()),
                "timestamp signer attributes malformed",
            )
        })? {
            Some(encoded) => raw
                .and_then(|entries| received_signed_attributes(entries, signer))
                .unwrap_or(encoded),

            None => self
                .signed_data
                .encap_content_info
                .content
                .as_ref()
                .ok_or_else(|| {
                    malformed(
                        VerificationErrorKind::DecodeError(
                            "time stamp does not contain digested content".into(),
                        ),
                        "timestamp no message digest",
                    )
                })?
                .to_vec(),
        };

        let hash_alg = bcder::Oid::from_str(&signer.digest_algorithm.algorithm.to_string())
            .map_err(|_| {
                VerificationError::new(
                    VerificationStage::SignatureAlgorithm,
                    VerificationErrorKind::DecodeError("timestamp bad tbs certificate".into()),
                    "timestamp bad hash alg",
                )
            })?;

        let key =
            rasn::der::encode(&cert.tbs_certificate.subject_public_key_info).map_err(|_| {
                VerificationError::new(
                    VerificationStage::SignatureAlgorithm,
                    VerificationErrorKind::DecodeError("timestamp bad tbs certificate".into()),
                    "timestamp bad signing key",
                )
            })?;

        let algorithm = timestamp_signature_algorithm(
            signer,
            &cert.tbs_certificate.subject_public_key_info.algorithm,
        )
        .map_err(|kind| {
            VerificationError::new(
                VerificationStage::SignatureAlgorithm,
                kind,
                "timestamp invalid signature algorithm or parameters",
            )
        })?;

        let signature = OctetString::new(bytes::Bytes::copy_from_slice(&signer.signature));

        validate_timestamp_sig(&algorithm, &hash_alg, &signature, &tbs, &key).map_err(|_| {
            VerificationError::new(
                VerificationStage::Signature,
                VerificationErrorKind::SignatureMismatch,
                "timestamp signed data did not match signature",
            )
        })?;

        Ok(SignatureVerifiedTimestamp {
            tst,
            certificates: &self.certificates,
            signer_index,
            validity: (
                time_to_datetime(cert.tbs_certificate.validity.not_before).timestamp(),
                time_to_datetime(cert.tbs_certificate.validity.not_after).timestamp(),
            ),
        })
    }
}

/// Facts authenticated by a CMS signature, but not yet bound to the host message.
///
/// This type is not a trusted/accepted signing time. Temporal, profile, and trust
/// checks remain host decisions. In particular, validity bounds are facts rather
/// than an implicit ambient-time or accuracy policy.
pub struct SignatureVerifiedTimestamp<'a> {
    tst: TstInfo,
    certificates: &'a [Vec<u8>],
    signer_index: usize,
    validity: (i64, i64),
}

impl<'a> SignatureVerifiedTimestamp<'a> {
    /// Time attested by TSTInfo, not a CMS signingTime attribute.
    pub fn generation_time(&self) -> DateTime<Utc> {
        self.tst.gen_time.clone().into()
    }

    /// Accuracy margin rounded up to seconds, preserving SDK saturation semantics.
    pub fn accuracy_seconds(&self) -> i64 {
        tst_accuracy_seconds(self.tst.accuracy.as_ref())
    }

    /// Signer certificate validity bounds as Unix seconds (notBefore, notAfter).
    pub fn signer_validity(&self) -> (i64, i64) {
        self.validity
    }

    /// Selected signer certificate as DER, without profile or trust validation.
    pub fn signer_certificate(&self) -> &[u8] {
        &self.certificates[self.signer_index]
    }

    /// All embedded certificates as DER, preserving decoded order.
    ///
    /// These are not a validated or ordered trust chain.
    pub fn certificates(&self) -> &[Vec<u8>] {
        self.certificates
    }

    /// Index of the first matching certificate in [`Self::certificates`].
    pub fn signer_certificate_index(&self) -> usize {
        self.signer_index
    }

    /// Bind this signature-verified timestamp to the supplied message.
    ///
    /// Only SHA-256/384/512 message imprints are accepted. SHA-1 remains supported
    /// for the separate CMS digest for compatibility, not for message imprints.
    pub fn verify_message_imprint(
        self,
        message: &[u8],
    ) -> Result<VerifiedTimestamp<'a>, VerificationError> {
        let imprint = &self.tst.message_imprint;

        let algorithm = DigestAlgorithm::for_message_imprint(&imprint.hash_algorithm.algorithm)
            .ok_or_else(|| {
                VerificationError::new(
                    VerificationStage::MessageImprint,
                    VerificationErrorKind::UnsupportedAlgorithm,
                    "timestamp unknown message digest algorithm",
                )
            })?;

        let mut hasher = algorithm.digester();

        hasher.update(message);

        if hasher.finish().as_ref() != imprint.hashed_message.to_bytes() {
            return Err(VerificationError::new(
                VerificationStage::MessageImprint,
                VerificationErrorKind::InvalidData,
                "timestamp message digest did not match",
            ));
        }

        Ok(VerifiedTimestamp(self))
    }
}

/// A CMS signature and message imprint verified for the supplied message.
///
/// **Not** certificate-profile-valid, chain-valid, trusted, or SDK-accepted.
/// Only the host can establish those independent outcomes.
pub struct VerifiedTimestamp<'a>(SignatureVerifiedTimestamp<'a>);

impl VerifiedTimestamp<'_> {
    /// Cryptographically authenticated facts for host policy evaluation.
    pub fn signature(&self) -> &SignatureVerifiedTimestamp<'_> {
        &self.0
    }

    /// Attested generation time, not an accepted or trusted signing time.
    pub fn generation_time(&self) -> DateTime<Utc> {
        self.0.generation_time()
    }

    #[cfg(feature = "sdk-compat")]
    pub(crate) fn legacy_info(&self) -> TstInfo {
        self.0.tst.clone()
    }
}

/// Locate the first signer's certificate without verifying any cryptography.
///
/// Supports response and bare-token forms and the same first-match issuer/serial
/// and strict SKI lookup as verification. `None` means no token, certificates,
/// signer, or matching certificate; it is not a validation success.
pub fn signer_certificate_from_token(token: &[u8]) -> Result<Option<Vec<u8>>, VerificationError> {
    let Some(sd) = signed_data_from_time_stamp_response(token).map_err(|kind| {
        VerificationError::new(
            VerificationStage::Envelope,
            kind,
            "could not parse timestamp data",
        )
    })?
    else {
        return Ok(None);
    };

    let Some(ders) = certificate_ders(&sd)? else {
        return Ok(None);
    };

    let Some(certs) = &sd.certificates else {
        return Ok(None);
    };

    let signers = sd.signer_infos.to_vec();

    let Some(signer) = signers.first() else {
        return Ok(None);
    };

    Ok(certs
        .to_vec()
        .iter()
        .position(|choice| signer_certificate_matches(choice, &signer.sid))
        .map(|index| ders[index].clone()))
}

/// Extract and encode the bare CMS token from an RFC 3161 response.
///
/// Intended for containers such as COSE `sigTst2`; this only changes the envelope.
/// It does not check the TSA status, message imprint, signature, profile, or trust.
/// Callers retaining a legacy `sigTst` response should preserve its original bytes.
pub fn token_from_response(response: &[u8]) -> Result<Vec<u8>, VerificationErrorKind> {
    let response = Constructed::decode(response, bcder::Mode::Der, TimeStampResp::take_from)
        .map_err(|error| {
            VerificationErrorKind::DecodeError(format!("invalid timestamp response: {error:?}"))
        })?;

    let token = response
        .time_stamp_token
        .ok_or_else(|| VerificationErrorKind::DecodeError("invalid timestamp token".into()))?;

    let oid = token
        .content_type
        .iter()
        .map(|component| {
            component
                .to_u32()
                .ok_or_else(|| VerificationErrorKind::DecodeError("invalid component".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let content = ContentInfo {
        content_type: types::ObjectIdentifier::new(oid).ok_or_else(|| {
            VerificationErrorKind::DecodeError(
                "invalid object identifier for timestamp response".into(),
            )
        })?,
        content: types::Any::new(token.content.as_slice().to_vec()),
    };

    rasn::der::encode(&content).map_err(|error| {
        VerificationErrorKind::DecodeError(format!("failed to encode timestamp token: {error:?}"))
    })
}

fn certificate_ders(sd: &rasn_cms::SignedData) -> Result<Option<Vec<Vec<u8>>>, VerificationError> {
    let Some(certs) = &sd.certificates else {
        return Ok(None);
    };

    let invalid = || {
        VerificationError::new(
            VerificationStage::Certificates,
            VerificationErrorKind::DecodeError(
                "time stamp certificate could not be processed".into(),
            ),
            "could not parse timestamp data",
        )
    };

    certs
        .to_vec()
        .iter()
        .map(|choice| match choice {
            CertificateChoices::Certificate(cert) => rasn::der::encode(cert).map_err(|_| invalid()),
            _ => Err(invalid()),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn verify_attribute_digest(
    signer: &rasn_cms::SignerInfo,
    sd: &rasn_cms::SignedData,
) -> Result<(), VerificationError> {
    let Some(attributes) = &signer.signed_attrs else {
        return Ok(());
    };

    let invalid = |kind, diagnostic| {
        VerificationError::new(VerificationStage::SignedAttributes, kind, diagnostic)
    };

    let attrs = attributes.to_vec();

    let digest = attrs
        .iter()
        .find(|attribute| attribute.r#type == Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_MESSAGE_DIGEST)
        .ok_or_else(|| {
            invalid(
                VerificationErrorKind::DecodeError("no message imprint".into()),
                "timestamp no message digest",
            )
        })?;

    if digest.values.len() != 1 {
        return Err(invalid(
            VerificationErrorKind::DecodeError(format!(
                "message digest attribute has {} values, should have one",
                digest.values.len(),
            )),
            "timestamp response contained multiple message digests",
        ));
    }

    let values = digest.values.to_vec();

    let value = values.first().ok_or_else(|| {
        invalid(
            VerificationErrorKind::DecodeError("unable to decode message digest".into()),
            "timestamp bad message digest",
        )
    })?;

    let expected = rasn::der::decode::<types::OctetString>(value.as_bytes()).map_err(|_| {
        invalid(
            VerificationErrorKind::DecodeError("unable to decode signed message data".into()),
            "timestamp could not decode signed message data",
        )
    })?;

    let oid =
        bcder::Oid::from_str(&signer.digest_algorithm.algorithm.to_string()).map_err(|_| {
            invalid(
                VerificationErrorKind::DecodeError("unsupported digest algorithm".into()),
                "timestamp bad message digest algorithm",
            )
        })?;

    let algorithm = DigestAlgorithm::try_from(&oid).map_err(|_| {
        invalid(
            VerificationErrorKind::DecodeError("unsupported digest algorithm".into()),
            "timestamp bad message digest algorithm",
        )
    })?;

    let mut hasher = algorithm.digester();

    if let Some(content) = &sd.encap_content_info.content {
        hasher.update(content);
    }

    if expected.as_ref() != hasher.finish().as_ref() {
        return Err(invalid(
            VerificationErrorKind::InvalidData,
            "timestamp bad message digest",
        ));
    }

    Ok(())
}

// When signed attributes are present, the digest is the DER
// encoding of the SignerInfo SignedAttributes.
fn signed_attributes_digested_content(
    signer_info: &rasn_cms::SignerInfo,
) -> Result<Option<Vec<u8>>, rasn::error::EncodeError> {
    if let Some(signed_attributes) = &signer_info.signed_attrs {
        match rasn::der::encode(signed_attributes) {
            Ok(encoded) => Ok(Some(encoded)),
            Err(e) => Err(e),
        }
    } else {
        Ok(None)
    }
}

// Decode the raw SignerInfo entries from the same SignedData bytes used by
// rasn. Preserve duplicates here: a SET OF decoder may collapse equal entries.
// Returns None if the entries cannot be parsed, in which case callers fall back
// to the DER re-encoding of each decoded SignerInfo's attributes.
fn received_signer_infos(sd_bytes: &[u8]) -> Option<Vec<asn1_rs::Any<'_>>> {
    use asn1_rs::{Class, Tag};

    let (rest, sd) = asn1_rs::Any::from_der(sd_bytes).ok()?;

    if !rest.is_empty() || sd.class() != Class::Universal || sd.tag() != Tag::Sequence {
        return None;
    }

    let signer_infos = timestamp_asn1_children(sd.data)?.pop()?;

    if signer_infos.class() != Class::Universal || signer_infos.tag() != Tag::Set {
        return None;
    }

    let entries = timestamp_asn1_children(signer_infos.data)?;

    for entry in &entries {
        if entry.class() != Class::Universal || entry.tag() != Tag::Sequence {
            return None;
        }

        raw_signature(entry)?;
    }

    Some(entries)
}

fn raw_signature<'a>(signer_info: &asn1_rs::Any<'a>) -> Option<&'a [u8]> {
    use asn1_rs::{Class, Tag};

    timestamp_asn1_children(signer_info.data)?
        .into_iter()
        .find(|field| field.class() == Class::Universal && field.tag() == Tag::OctetString)
        .map(|field| field.data)
}

// A signature value must identify exactly one SignerInfo. Check the decoded
// entries and, when available, the raw entries, since rasn may collapse
// identical entries while decoding the SET OF.
fn has_duplicate_signatures(
    sd: &rasn_cms::SignedData,
    raw_signer_infos: Option<&[asn1_rs::Any<'_>]>,
) -> bool {
    let mut decoded = std::collections::HashSet::new();

    if !sd
        .signer_infos
        .to_vec()
        .iter()
        .all(|si| decoded.insert(si.signature.as_ref()))
    {
        return true;
    }

    let mut raw = std::collections::HashSet::new();

    raw_signer_infos.is_some_and(|entries| {
        !entries
            .iter()
            .all(|entry| raw_signature(entry).is_some_and(|sig| raw.insert(sig)))
    })
}

fn timestamp_asn1_children(data: &[u8]) -> Option<Vec<asn1_rs::Any<'_>>> {
    let mut rest = data;
    let mut items = Vec::new();

    while !rest.is_empty() {
        let (rem, item) = asn1_rs::Any::from_der(rest).ok()?;
        items.push(item);
        rest = rem;
    }

    Some(items)
}

// RFC 5652 section 5.4 requires DER-encoded signed attributes (including sorted
// SET OF order). Accepting an unsorted encoding is an interoperability allowance
// for nonconforming tokens, not an alternative permitted by that RFC.
//
// Replace the IMPLICIT [0] tag with a SET OF header, and require the located bytes
// to decode to the attributes whose message digest was checked.
// Signature values are unique because verify_time_stamp rejects duplicates.
fn received_signed_attributes(
    signer_infos: &[asn1_rs::Any<'_>],
    signer_info: &rasn_cms::SignerInfo,
) -> Option<Vec<u8>> {
    use asn1_rs::{Class, Header, Length, Tag, ToDer};

    let signature: &[u8] = signer_info.signature.as_ref();
    let expected = signer_info.signed_attrs.as_ref()?;
    let mut found: Option<&[u8]> = None;

    for si in signer_infos {
        let fields = timestamp_asn1_children(si.data)?;

        let matches = fields.iter().any(|f| {
            f.class() == Class::Universal && f.tag() == Tag::OctetString && f.data == signature
        });

        if !matches {
            continue;
        }

        if found.is_some() {
            return None;
        }

        // The signedAttrs field is a constructed [0]. A subjectKeyIdentifier sid is a
        // primitive [0] and must not be mistaken for the attributes.
        let attrs = fields.iter().find(|f| {
            f.class() == Class::ContextSpecific && f.tag() == Tag(0) && f.header.is_constructed()
        })?;

        found = Some(attrs.data);
    }

    let attrs_body = found?;

    let header = Header::new(
        Class::Universal,
        true,
        Tag::Set,
        Length::Definite(attrs_body.len()),
    );

    let mut out = header.to_der_vec().ok()?;
    out.extend_from_slice(attrs_body);

    let decoded: rasn_cms::SignedAttributes = rasn::der::decode(&out).ok()?;

    if &decoded != expected {
        return None;
    }

    Some(out)
}

fn signer_certificate_matches(choice: &CertificateChoices, sid: &SignerIdentifier) -> bool {
    let CertificateChoices::Certificate(cert) = choice else {
        return false;
    };

    match sid {
        SignerIdentifier::IssuerAndSerialNumber(sn) => {
            sn.issuer == cert.tbs_certificate.issuer
                && sn.serial_number == cert.tbs_certificate.serial_number
        }

        SignerIdentifier::SubjectKeyIdentifier(ski) => cert
            .tbs_certificate
            .extensions
            .as_ref()
            .is_some_and(|extensions| {
                extensions.iter().any(|extension| {
                    extension.extn_id
                        == Oid::JOINT_ISO_ITU_T_DS_CERTIFICATE_EXTENSION_SUBJECT_KEY_IDENTIFIER
                        && subject_key_identifier_matches(&extension.extn_value, ski)
                })
            }),
    }
}

const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const RSA_PSS: &str = "1.2.840.113549.1.1.10";
const MGF1: &str = "1.2.840.113549.1.1.8";
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const ED25519_SIGNATURE: &str = "1.3.101.112";
const SHA1_DIGEST: &str = "1.3.14.3.2.26";
const SHA256_DIGEST: &str = "2.16.840.1.101.3.4.2.1";
const SHA384_DIGEST: &str = "2.16.840.1.101.3.4.2.2";
const SHA512_DIGEST: &str = "2.16.840.1.101.3.4.2.3";
const RSA_PKCS1_SHA1: &str = "1.2.840.113549.1.1.5";
const RSA_PKCS1_SHA256: &str = "1.2.840.113549.1.1.11";
const RSA_PKCS1_SHA384: &str = "1.2.840.113549.1.1.12";
const RSA_PKCS1_SHA512: &str = "1.2.840.113549.1.1.13";
const ECDSA_SHA1: &str = "1.2.840.10045.4.1";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";

struct PssParameters {
    hash: String,
    mgf_hash: String,
    salt_length: u64,
    trailer: u64,
}

fn pss_parameters(parameters: &types::Any) -> Result<PssParameters, VerificationErrorKind> {
    use asn1_rs::{Class, Tag};

    let invalid =
        || VerificationErrorKind::DecodeError("invalid timestamp RSA-PSS parameters".into());

    let bytes = parameters.as_bytes();

    let (rest, sequence) = asn1_rs::Any::from_der(bytes).map_err(|_| invalid())?;

    if !rest.is_empty()
        || sequence.class() != Class::Universal
        || sequence.tag() != Tag::Sequence
        || !sequence.header.is_constructed()
    {
        return Err(invalid());
    }

    // RFC 4055 defaults apply to fields omitted within the required sequence.
    let mut result = PssParameters {
        hash: SHA1_DIGEST.into(),
        mgf_hash: SHA1_DIGEST.into(),
        salt_length: 20,
        trailer: 1,
    };

    let fields = timestamp_asn1_children(sequence.data).ok_or_else(invalid)?;
    let mut previous = None;

    for field in fields {
        let tag = field.tag().0;

        if field.class() != Class::ContextSpecific
            || !field.header.is_constructed()
            || tag > 3
            || previous.is_some_and(|previous| tag <= previous)
        {
            return Err(invalid());
        }

        previous = Some(tag);
        let (rest, _) = asn1_rs::Any::from_der(field.data).map_err(|_| invalid())?;

        if !rest.is_empty() {
            return Err(invalid());
        }

        match tag {
            0 => result.hash = pss_hash_algorithm(field.data)?,
            1 => {
                let mgf: rasn_pkix::AlgorithmIdentifier =
                    rasn::der::decode(field.data).map_err(|_| invalid())?;

                if mgf.algorithm.to_string() != MGF1 {
                    return Err(VerificationErrorKind::UnsupportedAlgorithm);
                }

                let hash = mgf.parameters.ok_or_else(invalid)?;
                result.mgf_hash = pss_hash_algorithm(hash.as_bytes())?;
            }

            2 => {
                result.salt_length = pss_unsigned_integer(field.data)?;
            }

            3 => result.trailer = pss_unsigned_integer(field.data)?,
            _ => return Err(invalid()),
        }
    }

    Ok(result)
}

fn pss_unsigned_integer(bytes: &[u8]) -> Result<u64, VerificationErrorKind> {
    use asn1_rs::{Class, Tag};

    let invalid = || VerificationErrorKind::DecodeError("invalid timestamp RSA-PSS integer".into());
    let (rest, value) = asn1_rs::Any::from_der(bytes).map_err(|_| invalid())?;

    if !rest.is_empty()
        || value.class() != Class::Universal
        || value.tag() != Tag::Integer
        || value.header.is_constructed()
        || value.data.is_empty()
        || value.data[0] & 0x80 != 0
        || (value.data.len() > 1 && value.data[0] == 0 && value.data[1] & 0x80 == 0)
    {
        return Err(invalid());
    }

    value.data.iter().try_fold(0_u64, |integer, byte| {
        integer
            .checked_mul(256)
            .and_then(|integer| integer.checked_add(u64::from(*byte)))
            .ok_or_else(invalid)
    })
}

fn pss_hash_algorithm(bytes: &[u8]) -> Result<String, VerificationErrorKind> {
    let invalid =
        || VerificationErrorKind::DecodeError("invalid timestamp RSA-PSS hash parameters".into());

    let (rest, _) = asn1_rs::Any::from_der(bytes).map_err(|_| invalid())?;

    if !rest.is_empty() {
        return Err(invalid());
    }

    let algorithm: rasn_pkix::AlgorithmIdentifier =
        rasn::der::decode(bytes).map_err(|_| invalid())?;

    if algorithm
        .parameters
        .is_some_and(|parameters| parameters.as_bytes() != [0x05, 0x00])
    {
        return Err(invalid());
    }

    Ok(algorithm.algorithm.to_string())
}

fn timestamp_signature_algorithm(
    signer: &rasn_cms::SignerInfo,
    key: &rasn_pkix::AlgorithmIdentifier,
) -> Result<bcder::Oid, VerificationErrorKind> {
    let signature = signer.signature_algorithm.algorithm.to_string();
    let digest = signer.digest_algorithm.algorithm.to_string();
    let key_algorithm = key.algorithm.to_string();
    let mut validator_algorithm = signature.as_str();

    if signature == RSA_PSS {
        if key_algorithm != RSA_ENCRYPTION && key_algorithm != RSA_PSS {
            return Err(VerificationErrorKind::UnsupportedAlgorithm);
        }

        let parameters = signer
            .signature_algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| {
                VerificationErrorKind::DecodeError("missing timestamp RSA-PSS parameters".into())
            })?;

        let pss = pss_parameters(parameters)?;

        let salt_length = match pss.hash.as_str() {
            SHA256_DIGEST => 32,
            SHA384_DIGEST => 48,
            SHA512_DIGEST => 64,
            _ => return Err(VerificationErrorKind::UnsupportedAlgorithm),
        };

        if pss.hash != digest
            || pss.mgf_hash != digest
            || pss.salt_length != salt_length
            || pss.trailer != 1
        {
            return Err(VerificationErrorKind::UnsupportedAlgorithm);
        }

        if key_algorithm == RSA_PSS {
            if let Some(parameters) = &key.parameters {
                let restrictions = pss_parameters(parameters)?;

                // A PSS key's saltLength is a minimum, not an exact signature salt length.
                if restrictions.hash != pss.hash
                    || restrictions.mgf_hash != pss.mgf_hash
                    || restrictions.salt_length > pss.salt_length
                    || restrictions.trailer != pss.trailer
                {
                    return Err(VerificationErrorKind::UnsupportedAlgorithm);
                }
            }
        }
    } else {
        let compatible = match signature.as_str() {
            RSA_ENCRYPTION => key_algorithm == RSA_ENCRYPTION,
            RSA_PKCS1_SHA1 => key_algorithm == RSA_ENCRYPTION && digest == SHA1_DIGEST,
            RSA_PKCS1_SHA256 => key_algorithm == RSA_ENCRYPTION && digest == SHA256_DIGEST,
            RSA_PKCS1_SHA384 => key_algorithm == RSA_ENCRYPTION && digest == SHA384_DIGEST,
            RSA_PKCS1_SHA512 => key_algorithm == RSA_ENCRYPTION && digest == SHA512_DIGEST,
            ECDSA_SHA1 => key_algorithm == EC_PUBLIC_KEY && digest == SHA1_DIGEST,
            ECDSA_SHA256 => key_algorithm == EC_PUBLIC_KEY && digest == SHA256_DIGEST,
            ECDSA_SHA384 => key_algorithm == EC_PUBLIC_KEY && digest == SHA384_DIGEST,
            ECDSA_SHA512 => key_algorithm == EC_PUBLIC_KEY && digest == SHA512_DIGEST,
            ED25519_SIGNATURE => key_algorithm == signature,
            _ => false,
        };

        if !compatible {
            return Err(VerificationErrorKind::UnsupportedAlgorithm);
        }

        if key_algorithm == RSA_ENCRYPTION {
            validator_algorithm = RSA_ENCRYPTION;
        }
    }

    bcder::Oid::from_str(validator_algorithm)
        .map_err(|_| VerificationErrorKind::UnsupportedAlgorithm)
}

fn generalized_time_to_datetime<T: Into<DateTime<Utc>>>(gt: T) -> DateTime<Utc> {
    gt.into()
}

/// Represent digest algorithms compatible with bcder OIDs.
#[derive(Clone, Copy, Debug)]
enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    fn digester(self) -> Hasher {
        match self {
            // `Sha1` follows the `digest` 0.10 traits, while `Sha2*` follows
            // `digest` 0.11, so each `new()` must be fully qualified to the
            // matching `Digest` trait.
            DigestAlgorithm::Sha1 => Hasher::Sha1(<Sha1 as sha1::Digest>::new()),
            DigestAlgorithm::Sha256 => Hasher::Sha256(<Sha256 as sha2::Digest>::new()),
            DigestAlgorithm::Sha384 => Hasher::Sha384(<Sha384 as sha2::Digest>::new()),
            DigestAlgorithm::Sha512 => Hasher::Sha512(<Sha512 as sha2::Digest>::new()),
        }
    }

    // C2PA 13.1/15.8.2: a messageImprint must use SHA-256/384/512. SHA-1 is only tolerated for the CMS digest.
    fn for_message_imprint(oid: &bcder::Oid) -> Option<Self> {
        Self::try_from(oid)
            .ok()
            .filter(|d| !matches!(d, DigestAlgorithm::Sha1))
    }
}

impl TryFrom<&bcder::Oid> for DigestAlgorithm {
    type Error = ();

    fn try_from(oid: &bcder::Oid) -> Result<Self, Self::Error> {
        // Use der::asn1 instead of OIDs defined in oid.rs because it is faster
        // and we intend to remove x509_parser eventually.
        // Convert bcder::Oid to a string, then parse as ObjectIdentifier for comparison.
        let oid_str = oid.to_string();
        let const_oid = ObjectIdentifier::new(&oid_str).map_err(|_| ())?;

        // The SHA-1 OID is 1.3.14.3.2.26.
        const SHA1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

        // The SHA-256 OID is 2.16.840.1.101.3.4.2.1.
        const SHA256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

        // The SHA-384 OID is 2.16.840.1.101.3.4.2.2.
        const SHA384_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

        // The SHA-512 OID is 2.16.840.1.101.3.4.2.3.
        const SHA512_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

        if const_oid == SHA1_OID {
            Ok(DigestAlgorithm::Sha1)
        } else if const_oid == SHA256_OID {
            Ok(DigestAlgorithm::Sha256)
        } else if const_oid == SHA384_OID {
            Ok(DigestAlgorithm::Sha384)
        } else if const_oid == SHA512_OID {
            Ok(DigestAlgorithm::Sha512)
        } else {
            Err(())
        }
    }
}

/// Hold the supported digest implementations.
enum Hasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha1(h) => {
                use sha1::Digest;
                h.update(data);
            }

            Hasher::Sha256(h) => {
                use sha2::Digest;
                h.update(data);
            }

            Hasher::Sha384(h) => {
                use sha2::Digest;
                h.update(data);
            }

            Hasher::Sha512(h) => {
                use sha2::Digest;
                h.update(data);
            }
        }
    }

    fn finish(self) -> HasherOutput {
        match self {
            Hasher::Sha1(h) => {
                use sha1::Digest;
                HasherOutput(h.finalize().to_vec())
            }

            Hasher::Sha256(h) => {
                use sha2::Digest;
                HasherOutput(h.finalize().to_vec())
            }

            Hasher::Sha384(h) => {
                use sha2::Digest;
                HasherOutput(h.finalize().to_vec())
            }

            Hasher::Sha512(h) => {
                use sha2::Digest;
                HasherOutput(h.finalize().to_vec())
            }
        }
    }
}

/// Wrap hash output to implement AsRef<[u8]>.
struct HasherOutput(Vec<u8>);

impl AsRef<[u8]> for HasherOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn time_to_datetime(t: rasn_pkix::Time) -> DateTime<Utc> {
    match t {
        rasn_pkix::Time::Utc(u) => u,
        rasn_pkix::Time::General(gt) => generalized_time_to_datetime(gt),
    }
}

/// Interpret the bcder integer bytes as a non-negative, big-endian value.
fn integer_to_i64(int: &bcder::Integer) -> i64 {
    let bytes = int.as_slice();

    if bytes.is_empty() || bytes.len() > 8 {
        return 0;
    }

    let mut result = 0i64;

    for &b in bytes {
        result = (result << 8) | (b as i64);
    }

    result
}

/// Convert a TSTInfo Accuracy value to a whole-second margin (ceiling).
fn tst_accuracy_seconds(accuracy: Option<&Accuracy>) -> i64 {
    let Some(acc) = accuracy else {
        return 0;
    };

    let secs = acc.seconds.as_ref().map(integer_to_i64).unwrap_or(0);
    let millis = acc.millis.as_ref().map(integer_to_i64).unwrap_or(0);
    let micros = acc.micros.as_ref().map(integer_to_i64).unwrap_or(0);

    let total_micros = secs
        .saturating_mul(1_000_000)
        .saturating_add(millis.saturating_mul(1_000))
        .saturating_add(micros);

    // Round up to full seconds.
    total_micros.saturating_add(999_999) / 1_000_000
}

fn validate_timestamp_sig(
    sig_alg: &bcder::Oid,
    hash_alg: &bcder::Oid,
    sig_val: &OctetString,
    tbs: &[u8],
    signing_key_der: &[u8],
) -> Result<(), VerificationErrorKind> {
    let Some(validator) = validator_for_sig_and_hash_algs(
        &c2pa_raw_crypto::Oid::new(sig_alg.as_ref()),
        &c2pa_raw_crypto::Oid::new(hash_alg.as_ref()),
    ) else {
        return Err(VerificationErrorKind::UnsupportedAlgorithm);
    };

    validator
        .validate(&sig_val.to_bytes(), tbs, signing_key_der)
        .map_err(|_| VerificationErrorKind::InvalidData)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::DigestAlgorithm;

    fn oid(s: &str) -> Result<bcder::Oid, Box<dyn std::error::Error>> {
        Ok(bcder::Oid::from_str(s)?)
    }

    #[test]
    fn message_imprint_rejects_sha1_and_unlisted_algorithms(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for o in [
            "1.3.14.3.2.26",          // This is SHA-1.
            "2.16.840.1.101.3.4.2.4", // This is SHA-224.
            "2.16.840.1.101.3.4.2.8", // This is SHA3-256.
            "1.2.840.113549.2.5",     // This is MD5.
        ] {
            assert!(
                DigestAlgorithm::for_message_imprint(&oid(o)?).is_none(),
                "{o}"
            );
        }

        Ok(())
    }

    #[test]
    fn message_imprint_accepts_sha2() -> Result<(), Box<dyn std::error::Error>> {
        for o in [
            "2.16.840.1.101.3.4.2.1",
            "2.16.840.1.101.3.4.2.2",
            "2.16.840.1.101.3.4.2.3",
        ] {
            assert!(DigestAlgorithm::for_message_imprint(&oid(o)?).is_some());
        }

        Ok(())
    }

    #[test]
    fn cms_digest_still_accepts_sha1() -> Result<(), Box<dyn std::error::Error>> {
        assert!(DigestAlgorithm::try_from(&oid("1.3.14.3.2.26")?).is_ok());

        Ok(())
    }

    #[test]
    fn digesters_match_published_abc_vectors_across_updates() {
        for (algorithm, expected) in [
            (DigestAlgorithm::Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (DigestAlgorithm::Sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (DigestAlgorithm::Sha384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
            (DigestAlgorithm::Sha512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        ] {
            let mut hasher = algorithm.digester();
            hasher.update(b"a");
            hasher.update(b"bc");

            assert_eq!(hex::encode(hasher.finish().as_ref()), expected);
        }
    }

    #[test]
    fn accuracy_rounds_up_subseconds_and_saturates() {
        use super::{integer_to_i64, tst_accuracy_seconds, Accuracy};

        assert_eq!(tst_accuracy_seconds(None), 0);

        let mut accuracy = Accuracy {
            seconds: None,
            millis: None,
            micros: None,
        };

        assert_eq!(tst_accuracy_seconds(Some(&accuracy)), 0);
        accuracy.micros = Some(1.into());

        assert_eq!(tst_accuracy_seconds(Some(&accuracy)), 1);
        accuracy.seconds = Some(2.into());
        accuracy.millis = Some(999.into());
        accuracy.micros = Some(999.into());

        assert_eq!(tst_accuracy_seconds(Some(&accuracy)), 3);
        accuracy.seconds = Some(i64::MAX.into());

        assert_eq!(tst_accuracy_seconds(Some(&accuracy)), i64::MAX / 1_000_000);
        assert_eq!(integer_to_i64(&bcder::Integer::from(-1)), 255);
    }

    #[test]
    fn timestamp_conversions_preserve_utc_and_generalized_dates(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use chrono::{TimeZone, Utc};

        use super::time_to_datetime;

        let utc = Utc
            .timestamp_opt(1_577_836_800, 0)
            .single()
            .ok_or("invalid test date")?;

        assert_eq!(time_to_datetime(rasn_pkix::Time::Utc(utc)), utc);

        assert_eq!(time_to_datetime(rasn_pkix::Time::General(utc.into())), utc);

        Ok(())
    }
}
