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

//! Deterministic OCSP discovery, request encoding, and response verification.
//!
//! Parsed statuses are claims, not acceptance decisions. A verified signature
//! authenticates the responder and its claims, not its authority, profile,
//! trust, or freshness. The host selects roles, policy, and time, and commits
//! its own diagnostics only after accepting the responder. No I/O is performed.

use std::str::FromStr;

use c2pa_raw_crypto::RawSignatureValidationError;
use chrono::{DateTime, NaiveDateTime, Utc};
use rasn_ocsp::{BasicOcspResponse, CertId, CertStatus, OcspResponseStatus, ResponderId};
use rasn_pkix::Certificate;
use sha1::Digest;
use thiserror::Error;

use crate::x509::ParsedCertificate;

/// A failure to discover OCSP responder URI facts in a parsed certificate.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// Duplicate extensions make the extension map ambiguous.
    #[error("Duplicate certificate extensions")]
    DuplicateExtensions,

    /// The authority information access extension could not be decoded.
    #[error("Malformed authority information access extension")]
    MalformedAuthorityInfoAccess,
}

/// Return OCSP URI facts in certificate order, preserving duplicates.
///
/// Missing AIA or AIA without OCSP URIs returns an empty vector. URI syntax,
/// schemes, responder selection, and transport remain host decisions. Discovery
/// establishes no certificate authenticity, responder authority, or trust.
pub fn responder_uris(certificate: &ParsedCertificate<'_>) -> Result<Vec<String>, DiscoveryError> {
    use x509_parser::{
        der_parser::oid,
        extensions::{GeneralName, ParsedExtension},
    };

    let extensions = certificate
        .parsed()
        .extensions_map()
        .map_err(|_| DiscoveryError::DuplicateExtensions)?;

    let Some(extension) = extensions.get(&oid!(1.3.6 .1 .5 .5 .7 .1 .1)) else {
        return Ok(Vec::new());
    };

    let ParsedExtension::AuthorityInfoAccess(aia) = extension.parsed_extension() else {
        return Err(DiscoveryError::MalformedAuthorityInfoAccess);
    };

    Ok(aia
        .accessdescs
        .iter()
        .filter_map(|description| match description.access_location {
            GeneralName::URI(uri)
                if description.access_method == oid!(1.3.6 .1 .5 .5 .7 .48 .1) =>
            {
                Some(uri.to_owned())
            }
            _ => None,
        })
        .collect())
}

/// A failure to decode certificate inputs or encode an OCSP request.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RequestError {
    /// The subject certificate could not be decoded by the request codec.
    #[error("Malformed OCSP subject certificate")]
    MalformedSubject,

    /// The issuer certificate could not be decoded by the request codec.
    #[error("Malformed OCSP issuer certificate")]
    MalformedIssuer,

    /// The issuer name or request could not be DER encoded.
    #[error("Could not encode OCSP request")]
    Encoding,
}

/// Encode one unsigned, nonce-free OCSP request using a SHA-1 CertID.
///
/// The issuer name is DER re-encoded and the issuer key's raw bit-string bytes
/// are hashed, preserving the SDK request codec's serial and trailing-DER
/// handling. SHA-1 parameters are explicitly NULL for responder compatibility.
/// This does not check issuer linkage, certificate authorization, or trust.
/// Hosts select the certificate pair and own URI/HTTP encoding and all policy;
/// constructing a request is not evidence of a valid response or status.
pub fn request_der(subject_der: &[u8], issuer_der: &[u8]) -> Result<Vec<u8>, RequestError> {
    let inputs = CertificateIdInputs::from_der(subject_der, issuer_der)?;
    let algorithm = rasn::types::Oid::new(&[1, 3, 14, 3, 2, 26])
        .ok_or(RequestError::Encoding)?
        .to_owned();

    let req_cert = CertId {
        issuer_name_hash: hash_by_oid(&algorithm, &inputs.issuer_name)
            .ok_or(RequestError::Encoding)?
            .into(),
        issuer_key_hash: hash_by_oid(&algorithm, inputs.issuer_key.as_raw_slice())
            .ok_or(RequestError::Encoding)?
            .into(),
        serial_number: inputs.serial,
        hash_algorithm: rasn_pkix::AlgorithmIdentifier {
            algorithm,
            parameters: Some(rasn::types::Any::new(
                rasn::der::encode(&()).map_err(|_| RequestError::Encoding)?,
            )),
        },
    };

    let request = rasn_ocsp::OcspRequest {
        tbs_request: rasn_ocsp::TbsRequest {
            version: rasn_ocsp::Version::from(0u8),
            requestor_name: None,
            request_list: vec![rasn_ocsp::Request {
                req_cert,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    };

    rasn::der::encode(&request).map_err(|_| RequestError::Encoding)
}

struct CertificateIdInputs {
    serial: rasn::types::Integer,
    issuer_name: Vec<u8>,
    issuer_key: rasn::types::BitString,
}

impl CertificateIdInputs {
    fn from_der(subject_der: &[u8], issuer_der: &[u8]) -> Result<Self, RequestError> {
        let subject: Certificate =
            rasn::der::decode(subject_der).map_err(|_| RequestError::MalformedSubject)?;

        let issuer: Certificate =
            rasn::der::decode(issuer_der).map_err(|_| RequestError::MalformedIssuer)?;

        Ok(Self {
            serial: subject.tbs_certificate.serial_number,
            issuer_name: rasn::der::encode(&issuer.tbs_certificate.subject)
                .map_err(|_| RequestError::Encoding)?,
            issuer_key: issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key,
        })
    }
}

/// A failure to interpret the response or its signature algorithm.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The response envelope or basic response could not be decoded.
    #[error("Malformed OCSP response")]
    MalformedResponse,

    /// The responder did not report successful processing.
    #[error("OCSP response was not successful")]
    UnsuccessfulResponse,

    /// A successful response contained no response bytes.
    #[error("Missing OCSP response bytes")]
    MissingResponse,

    /// The signature algorithm is not supported by the existing OCSP verifier.
    #[error("Unsupported OCSP signature algorithm")]
    UnsupportedAlgorithm,
}

/// A failure to authenticate a response's signer.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum VerificationError {
    /// A candidate certificate could not be decoded or encoded.
    #[error("Invalid certificate detected")]
    InvalidCertificate,

    /// No embedded signer matched and no issuing certificate was supplied.
    #[error("Missing issuing certificate")]
    MissingIssuer,

    /// Responder identification, issuance, or signature verification failed.
    #[error("Unauthenticated OCSP response")]
    UnauthenticatedResponse,
}

/// An uninterpretable time in a matching single response.
#[derive(Debug, Eq, Error, PartialEq)]
#[error("Invalid OCSP status time")]
pub struct InvalidStatusTime;

/// A decoded response carrying no authenticity or acceptance guarantee.
pub struct ParsedOcspResponse<'a> {
    /// Host-supplied original encoding.
    der: &'a [u8],

    /// Private decoded claims, including embedded candidate certificates.
    basic: BasicOcspResponse,

    /// Existing OCSP signature algorithm and paired digest.
    signature_algorithm: bcder::Oid,

    /// Digest selected by the existing signature compatibility mapping.
    hash_algorithm: bcder::Oid,

    /// Existing re-encoded TBS input, not the entire response envelope.
    signed_data: Vec<u8>,
}

impl<'a> ParsedOcspResponse<'a> {
    /// Decode a response without verifying its claims.
    ///
    /// Preserves the SDK's envelope and algorithm compatibility, including its
    /// basic-response decoding without an additional response-type selector.
    pub fn from_der(der: &'a [u8]) -> Result<Self, ParseError> {
        let response: rasn_ocsp::OcspResponse =
            rasn::der::decode(der).map_err(|_| ParseError::MalformedResponse)?;

        if response.status != OcspResponseStatus::Successful {
            return Err(ParseError::UnsuccessfulResponse);
        }

        let bytes = response.bytes.ok_or(ParseError::MissingResponse)?;

        let basic: BasicOcspResponse =
            rasn::der::decode(&bytes.response).map_err(|_| ParseError::MalformedResponse)?;

        let signature_algorithm =
            bcder::Oid::from_str(&basic.signature_algorithm.algorithm.to_string())
                .map_err(|_| ParseError::UnsupportedAlgorithm)?;

        let hash_algorithm = hash_alg_for_sig_alg(&basic.signature_algorithm.algorithm)
            .ok_or(ParseError::UnsupportedAlgorithm)?;

        let signed_data = rasn::der::encode(&basic.tbs_response_data)
            .map_err(|_| ParseError::MalformedResponse)?;

        Ok(Self {
            der,
            basic,
            signature_algorithm,
            hash_algorithm,
            signed_data,
        })
    }

    /// Original unverified response encoding.
    pub fn response_der(&self) -> &'a [u8] {
        self.der
    }

    /// Inspect unverified claims; no status is authenticated by this iterator.
    pub fn claimed_responses(&self) -> impl Iterator<Item = SingleResponse<'_>> {
        self.basic
            .tbs_response_data
            .responses
            .iter()
            .map(|response| SingleResponse { response })
    }

    /// Authenticate the responder ID and signature, without granting authority.
    ///
    /// Embedded certificates are unordered candidates. If none authenticates,
    /// `signing_chain[1]` may sign directly, including without embedded
    /// certificates. Direct issuance of `signing_chain[0]` and CA authority are
    /// checked in that case. Neither this chain nor embedded certificates are
    /// implicitly trusted, and delegated role/profile checks remain host-side.
    pub fn verify_signature(
        self,
        signing_chain: &[Vec<u8>],
    ) -> Result<SignatureVerifiedOcspResponse<'a>, VerificationError> {
        let mut certificates = self
            .basic
            .certs
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|cert| rasn::der::encode(cert).map_err(|_| VerificationError::InvalidCertificate))
            .collect::<Result<Vec<_>, _>>()?;

        let signature = bcder::OctetString::new(bytes::Bytes::copy_from_slice(
            self.basic.signature.as_raw_slice(),
        ));

        let responder_id = &self.basic.tbs_response_data.responder_id;

        let responder_index = certificates.iter().position(|der| {
            let Ok(cert) = rasn::der::decode::<Certificate>(der) else {
                return false;
            };

            responder_id_matches(responder_id, &cert)
                && rasn::der::encode(&cert.tbs_certificate.subject_public_key_info).is_ok_and(
                    |key| {
                        validate_ocsp_sig(
                            &self.signature_algorithm,
                            &self.hash_algorithm,
                            &signature,
                            &self.signed_data,
                            &key,
                        )
                        .is_ok()
                    },
                )
        });

        if let Some(index) = responder_index {
            let responder = certificates.remove(index);
            certificates.insert(0, responder);
        } else {
            let issuer_der = signing_chain
                .get(1)
                .ok_or(VerificationError::MissingIssuer)?;
            let issuer = rasn::der::decode::<Certificate>(issuer_der)
                .map_err(|_| VerificationError::InvalidCertificate)?;

            if !signing_chain
                .first()
                .is_some_and(|leaf| certificate_issued_by(leaf, issuer_der))
                || !responder_id_matches(responder_id, &issuer)
            {
                return Err(VerificationError::UnauthenticatedResponse);
            }

            let key = rasn::der::encode(&issuer.tbs_certificate.subject_public_key_info)
                .map_err(|_| VerificationError::InvalidCertificate)?;

            validate_ocsp_sig(
                &self.signature_algorithm,
                &self.hash_algorithm,
                &signature,
                &self.signed_data,
                &key,
            )
            .map_err(|_| VerificationError::UnauthenticatedResponse)?;

            certificates = signing_chain[1..].to_vec();
        }

        if signing_chain.get(1) == certificates.first()
            && !signing_chain
                .first()
                .is_some_and(|leaf| certificate_issued_by(leaf, &certificates[0]))
        {
            return Err(VerificationError::UnauthenticatedResponse);
        }

        Ok(SignatureVerifiedOcspResponse {
            parsed: self,
            certificates,
        })
    }
}

/// Responder-identifying, signature-verified evidence, not an accepted response.
///
/// Construction checks the response signature, not delegated authorization,
/// certificate profile/validity, path trust, freshness, or host acceptance.
pub struct SignatureVerifiedOcspResponse<'a> {
    /// Claims whose response signature was authenticated.
    parsed: ParsedOcspResponse<'a>,

    /// Authenticated responder first, followed by untrusted path candidates.
    certificates: Vec<Vec<u8>>,
}

impl<'a> SignatureVerifiedOcspResponse<'a> {
    /// Original response whose decoded TBS signature was authenticated.
    ///
    /// The verifier preserves the existing re-encoded TBS signature input; it
    /// does not promise canonical encoding of the original envelope.
    pub fn response_der(&self) -> &'a [u8] {
        self.parsed.der
    }

    /// Candidate path with the authenticated responder first.
    ///
    /// Remaining certificates are untrusted path-building input. For a direct
    /// issuer response this is the supplied signing chain without its leaf.
    pub fn responder_certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }

    /// Unaccepted `producedAt` claim, without freshness validation.
    pub fn produced_at(&self) -> DateTime<Utc> {
        self.parsed.basic.tbs_response_data.produced_at.to_utc()
    }

    /// Authenticated claims whose serial and both issuer hashes match the host's
    /// supplied leaf and issuer. SHA-1 and SHA-256 CertIDs retain SDK support.
    ///
    /// Missing/malformed certificates and unsupported hash algorithms produce
    /// no matching claim, not a Good status. Binding does not prove trust or
    /// delegated authority. Status times are decoded lazily so the host can
    /// retain its existing error and time-filtering precedence.
    pub fn responses_for_certificate<'s>(
        &'s self,
        signing_chain: &'s [Vec<u8>],
    ) -> impl Iterator<Item = CertificateBoundResponse<'s>> {
        self.parsed
            .basic
            .tbs_response_data
            .responses
            .iter()
            .filter(move |response| cert_id_matches_signer(&response.cert_id, signing_chain))
            .map(|response| CertificateBoundResponse {
                claim: SingleResponse { response },
            })
    }
}

/// A signature-authenticated claim bound to the supplied certificate's CertID.
///
/// This type cannot be constructed from a merely parsed claim. Binding checks
/// serial, issuer-name hash, and issuer-key hash, but grants no responder
/// authorization, profile validity, trust, freshness, or host acceptance.
pub struct CertificateBoundResponse<'a> {
    /// Claim produced only by signature verification and CertID matching.
    claim: SingleResponse<'a>,
}

impl CertificateBoundResponse<'_> {
    /// Inspect the authenticated, certificate-bound claims without accepting them.
    pub fn claims(&self) -> &SingleResponse<'_> {
        &self.claim
    }
}

/// A single response claim; authenticity depends on the iterator producing it.
pub struct SingleResponse<'a> {
    /// Private decoded claim; the producing iterator establishes its provenance.
    response: &'a rasn_ocsp::SingleResponse,
}

/// The responder's claimed certificate status, not a host revocation verdict.
#[derive(Debug, Eq, PartialEq)]
pub enum ClaimedStatus {
    /// The responder claims the certificate is good.
    Good,

    /// The responder claims revocation at the supplied time.
    Revoked {
        /// Claimed revocation time, with existing whole-second compatibility.
        revocation_time: DateTime<Utc>,

        /// RFC 5280 CRL reason code, if supplied; 8 is removeFromCRL.
        reason: Option<u8>,
    },

    /// The responder cannot determine the certificate status.
    Unknown,
}

impl SingleResponse<'_> {
    /// Decimal serial number claimed by this response.
    pub fn certificate_serial_number(&self) -> String {
        self.response.cert_id.serial_number.to_string()
    }

    /// Claimed start time; fractional status times retain SDK rejection.
    pub fn this_update(&self) -> Result<DateTime<Utc>, InvalidStatusTime> {
        status_time(&self.response.this_update)
    }

    /// Claimed end time, without applying a fallback or freshness rule.
    pub fn next_update(&self) -> Result<Option<DateTime<Utc>>, InvalidStatusTime> {
        self.response
            .next_update
            .as_ref()
            .map(status_time)
            .transpose()
    }

    /// Decode the claimed status without applying signing-time policy.
    pub fn status(&self) -> Result<ClaimedStatus, InvalidStatusTime> {
        match &self.response.cert_status {
            CertStatus::Good => Ok(ClaimedStatus::Good),
            CertStatus::Revoked(info) => Ok(ClaimedStatus::Revoked {
                revocation_time: status_time(&info.revocation_time)?,
                reason: info.revocation_reason.map(|reason| reason as u8),
            }),
            CertStatus::Unknown(_) => Ok(ClaimedStatus::Unknown),
        }
    }
}

fn status_time(time: &rasn::types::GeneralizedTime) -> Result<DateTime<Utc>, InvalidStatusTime> {
    NaiveDateTime::parse_from_str(&time.to_string(), "%Y-%m-%d %H:%M:%S %Z")
        .map(|time| time.and_utc())
        .map_err(|_| InvalidStatusTime)
}

pub(crate) fn certificate_issued_by(cert_der: &[u8], issuer_der: &[u8]) -> bool {
    let (Ok(cert), Ok(issuer)) = (
        ParsedCertificate::from_der(cert_der),
        ParsedCertificate::from_der(issuer_der),
    ) else {
        return false;
    };

    cert.is_issued_by(&issuer)
}

fn validate_ocsp_sig(
    sig_alg: &bcder::Oid,
    hash_alg: &bcder::Oid,
    sig_val: &bcder::OctetString,
    tbs: &[u8],
    signing_key_der: &[u8],
) -> Result<(), RawSignatureValidationError> {
    if let Some(validator) = c2pa_raw_crypto::validator_for_sig_and_hash_algs(
        &c2pa_raw_crypto::Oid::new(sig_alg.as_ref()),
        &c2pa_raw_crypto::Oid::new(hash_alg.as_ref()),
    ) {
        validator
            .validate(&sig_val.to_bytes(), tbs, signing_key_der)
            .map_err(|e| RawSignatureValidationError::CryptoLibraryError(e.to_string()))
    } else {
        Err(RawSignatureValidationError::UnsupportedAlgorithm)
    }
}

fn responder_id_matches(id: &ResponderId, cert: &Certificate) -> bool {
    match id {
        ResponderId::ByName(name) => name == &cert.tbs_certificate.subject,
        ResponderId::ByKey(hash) => {
            hash.as_ref()
                == sha1::Sha1::digest(
                    cert.tbs_certificate
                        .subject_public_key_info
                        .subject_public_key
                        .as_raw_slice(),
                )
                .as_slice()
        }
    }
}

fn cert_id_matches_signer(cert_id: &CertId, signing_chain: &[Vec<u8>]) -> bool {
    let (Some(subject_der), Some(issuer_der)) = (signing_chain.first(), signing_chain.get(1))
    else {
        return false;
    };

    let Ok(inputs) = CertificateIdInputs::from_der(subject_der, issuer_der) else {
        return false;
    };

    if cert_id.serial_number != inputs.serial {
        return false;
    }

    let Some(name_hash) = hash_by_oid(&cert_id.hash_algorithm.algorithm, &inputs.issuer_name)
    else {
        return false;
    };
    let Some(key_hash) = hash_by_oid(
        &cert_id.hash_algorithm.algorithm,
        inputs.issuer_key.as_raw_slice(),
    ) else {
        return false;
    };

    cert_id.issuer_name_hash.as_ref() == name_hash.as_slice()
        && cert_id.issuer_key_hash.as_ref() == key_hash.as_slice()
}

fn hash_by_oid(alg: &rasn::types::ObjectIdentifier, data: &[u8]) -> Option<Vec<u8>> {
    match alg.to_string().as_str() {
        "1.3.14.3.2.26" => Some(sha1::Sha1::digest(data).to_vec()),
        "2.16.840.1.101.3.4.2.1" => Some(sha2::Sha256::digest(data).to_vec()),
        _ => None,
    }
}

fn hash_alg_for_sig_alg(sig_alg: &rasn::types::ObjectIdentifier) -> Option<bcder::Oid> {
    let hash = match sig_alg.to_string().as_str() {
        "1.2.840.10045.4.3.2" | "1.2.840.113549.1.1.11" => "2.16.840.1.101.3.4.2.1",
        "1.2.840.10045.4.3.3" | "1.2.840.113549.1.1.12" => "2.16.840.1.101.3.4.2.2",
        "1.2.840.10045.4.3.4" | "1.2.840.113549.1.1.13" | "1.3.101.112" => "2.16.840.1.101.3.4.2.3",
        _ => return None,
    };

    bcder::Oid::from_str(hash).ok()
}

#[cfg(test)]
mod tests {
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

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const GOOD: &[u8] = include_bytes!("../../sdk/tests/fixtures/crypto/ocsp/response_good.der");

    fn chain() -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        Ok(pem::parse_many(include_bytes!(
            "../../sdk/tests/fixtures/crypto/ocsp/ocsp_chain.pem"
        ))?
        .into_iter()
        .map(|pem| pem.into_contents())
        .collect())
    }

    #[test]
    fn discovery_preserves_uri_facts_and_rejects_ambiguous_extensions() -> TestResult {
        let chain = chain()?;
        let mut certificate: Certificate = rasn::der::decode(&chain[0])?;
        let extensions = certificate
            .tbs_certificate
            .extensions
            .as_mut()
            .ok_or("missing extensions")?;

        let index = extensions
            .iter()
            .position(|e| e.extn_id.to_string() == "1.3.6.1.5.5.7.1.1")
            .ok_or("missing AIA")?;

        let mut aia = extensions.remove(index);
        let without_aia = rasn::der::encode(&certificate)?;
        assert!(responder_uris(&ParsedCertificate::from_der(&without_aia)?)?.is_empty());

        // OCSP URI, CA-issuer URI, OCSP DNS name, invalid URL, and duplicate URI.
        let description = |method: u8, tag: u8, value: &[u8]| {
            let mut der = vec![
                0x30,
                (12 + value.len()) as u8,
                0x06,
                0x08,
                0x2b,
                0x06,
                0x01,
                0x05,
                0x05,
                0x07,
                0x30,
                method,
                tag,
                value.len() as u8,
            ];

            der.extend_from_slice(value);
            rasn::types::Any::new(der)
        };

        let entries = vec![
            description(1, 0x86, b"http://first.test"),
            description(2, 0x86, b"http://issuer.test"),
            description(1, 0x82, b"dns.test"),
            description(1, 0x86, b"not a URL"),
            description(1, 0x86, b"http://first.test"),
        ];

        let cases = [
            (
                rasn::der::encode(&entries)?,
                Ok(vec![
                    "http://first.test".to_owned(),
                    "not a URL".to_owned(),
                    "http://first.test".to_owned(),
                ]),
            ),
            (vec![0x30, 0], Ok(vec![])),
            (rasn::der::encode(&entries[1..3].to_vec())?, Ok(vec![])),
            (
                vec![0xff],
                Err(DiscoveryError::MalformedAuthorityInfoAccess),
            ),
        ];

        for (value, expected) in cases {
            aia.extn_value = value.into();
            certificate.tbs_certificate.extensions = Some(vec![aia.clone()].into());
            let mut der = rasn::der::encode(&certificate)?;
            der.extend_from_slice(b"trailing");
            let parsed = ParsedCertificate::from_der(&der)?;
            assert_eq!(responder_uris(&parsed), expected);
        }

        certificate.tbs_certificate.extensions = Some(vec![aia.clone(), aia].into());
        let der = rasn::der::encode(&certificate)?;
        assert_eq!(
            responder_uris(&ParsedCertificate::from_der(&der)?),
            Err(DiscoveryError::DuplicateExtensions)
        );

        Ok(())
    }

    #[test]
    fn request_preserves_codec_serial_name_and_raw_key_bits() -> TestResult {
        let chain = chain()?;
        let mut subject: Certificate = rasn::der::decode(&chain[0])?;
        let mut issuer: Certificate = rasn::der::decode(&chain[1])?;
        subject.tbs_certificate.serial_number = (-129).into();
        let key = &mut issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;

        key.pop();

        let expected_name_hash =
            sha1::Sha1::digest(rasn::der::encode(&issuer.tbs_certificate.subject)?).to_vec();

        let subject_der = rasn::der::encode(&subject)?;
        let issuer_der = rasn::der::encode(&issuer)?;
        let decoded_issuer: Certificate = rasn::der::decode(&issuer_der)?;
        let expected_key_hash = sha1::Sha1::digest(
            decoded_issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_raw_slice(),
        )
        .to_vec();

        let der = request_der(&subject_der, &issuer_der)?;
        let request: rasn_ocsp::OcspRequest = rasn::der::decode(&der)?;
        let id = &request.tbs_request.request_list[0].req_cert;
        assert_eq!(id.serial_number, subject.tbs_certificate.serial_number);
        assert_eq!(id.issuer_name_hash.as_ref(), expected_name_hash);
        assert_eq!(id.issuer_key_hash.as_ref(), expected_key_hash);
        assert_eq!(
            id.hash_algorithm.parameters.as_ref().map(|p| p.as_bytes()),
            Some(&[0x05, 0x00][..])
        );

        assert_eq!(request.tbs_request.request_list.len(), 1);

        assert!(request.tbs_request.request_list[0]
            .single_request_extensions
            .is_none());

        assert!(request.tbs_request.request_extensions.is_none());
        assert!(request.tbs_request.requestor_name.is_none());
        assert!(request.optional_signature.is_none());

        let mut trailing_subject = subject_der.clone();
        trailing_subject.extend_from_slice(b"trailing");
        let mut trailing_issuer = issuer_der.clone();
        trailing_issuer.extend_from_slice(b"trailing");
        assert_eq!(request_der(&trailing_subject, &trailing_issuer)?, der);

        assert_eq!(
            request_der(&[], &issuer_der),
            Err(RequestError::MalformedSubject)
        );

        assert_eq!(
            request_der(&subject_der, &[]),
            Err(RequestError::MalformedIssuer)
        );

        Ok(())
    }

    #[test]
    fn parsed_claims_and_authenticated_bound_facts_are_distinct() -> TestResult {
        let parsed = ParsedOcspResponse::from_der(GOOD)?;
        assert_eq!(parsed.response_der(), GOOD);
        assert_eq!(
            parsed
                .claimed_responses()
                .next()
                .ok_or("missing claim")?
                .status()?,
            ClaimedStatus::Good
        );

        let signing_chain = chain()?;
        let verified = parsed.verify_signature(&signing_chain)?;
        assert_eq!(verified.response_der(), GOOD);
        assert!(!verified.responder_certificates().is_empty());

        let response = verified
            .responses_for_certificate(&signing_chain)
            .next()
            .ok_or("missing bound claim")?;
        assert_eq!(response.claims().status()?, ClaimedStatus::Good);
        assert!(!response.claims().certificate_serial_number().is_empty());
        assert!(response.claims().this_update()? <= verified.produced_at());
        assert_eq!(response.claims().next_update()?, None);
        assert_eq!(verified.responses_for_certificate(&[]).count(), 0);
        assert_eq!(
            verified
                .responses_for_certificate(&signing_chain[..1])
                .count(),
            0
        );

        // A parsed Good claim cannot manufacture signature-verified evidence.
        let mut damaged = ParsedOcspResponse::from_der(GOOD)?;
        damaged.basic.signature = rasn::types::BitString::from_vec(vec![0; 64]);
        assert!(matches!(
            damaged.verify_signature(&signing_chain),
            Err(VerificationError::UnauthenticatedResponse)
        ));

        Ok(())
    }

    #[test]
    fn cert_id_requires_serial_both_issuer_hashes_and_supported_algorithm() -> TestResult {
        let chain = chain()?;
        let parsed = ParsedOcspResponse::from_der(GOOD)?;
        let original = parsed.basic.tbs_response_data.responses[0].cert_id.clone();
        assert!(cert_id_matches_signer(&original, &chain));

        for invalid_chain in [
            vec![],
            chain[..1].to_vec(),
            vec![vec![0], chain[1].clone()],
            vec![chain[0].clone(), vec![0]],
        ] {
            assert!(!cert_id_matches_signer(&original, &invalid_chain));
        }

        let mut wrong_serial = original.clone();
        wrong_serial.serial_number = 0.into();
        let mut wrong_name = original.clone();
        wrong_name.issuer_name_hash = vec![0; 20].into();
        let mut wrong_key = original.clone();
        wrong_key.issuer_key_hash = vec![0; 20].into();
        let mut unsupported = original.clone();
        unsupported.hash_algorithm.algorithm =
            rasn::types::ObjectIdentifier::new_unchecked(vec![1, 2, 3, 4].into());

        for invalid in [wrong_serial, wrong_name, wrong_key, unsupported] {
            assert!(!cert_id_matches_signer(&invalid, &chain));
        }

        let issuer: Certificate = rasn::der::decode(&chain[1])?;
        let mut sha256 = original;
        sha256.hash_algorithm.algorithm = rasn::types::ObjectIdentifier::new_unchecked(
            vec![2, 16, 840, 1, 101, 3, 4, 2, 1].into(),
        );
        sha256.issuer_name_hash =
            sha2::Sha256::digest(rasn::der::encode(&issuer.tbs_certificate.subject)?)
                .to_vec()
                .into();
        sha256.issuer_key_hash = sha2::Sha256::digest(
            issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_raw_slice(),
        )
        .to_vec()
        .into();
        assert!(cert_id_matches_signer(&sha256, &chain));

        Ok(())
    }

    #[test]
    fn malformed_and_unsupported_inputs_remain_typed() -> TestResult {
        assert!(matches!(
            ParsedOcspResponse::from_der(b"not DER"),
            Err(ParseError::MalformedResponse)
        ));

        let mut malformed: rasn_ocsp::OcspResponse = rasn::der::decode(GOOD)?;
        malformed
            .bytes
            .as_mut()
            .ok_or("missing basic response")?
            .response = vec![0xde, 0xad].into();

        assert!(matches!(
            ParsedOcspResponse::from_der(&rasn::der::encode(&malformed)?),
            Err(ParseError::MalformedResponse)
        ));

        let mut response: rasn_ocsp::OcspResponse = rasn::der::decode(GOOD)?;
        response.status = OcspResponseStatus::Unauthorized;
        assert!(matches!(
            ParsedOcspResponse::from_der(&rasn::der::encode(&response)?),
            Err(ParseError::UnsuccessfulResponse)
        ));
        response.status = OcspResponseStatus::Successful;
        response.bytes = None;
        assert!(matches!(
            ParsedOcspResponse::from_der(&rasn::der::encode(&response)?),
            Err(ParseError::MissingResponse)
        ));

        let mut response: rasn_ocsp::OcspResponse = rasn::der::decode(GOOD)?;
        let bytes = response.bytes.as_mut().ok_or("missing basic response")?;
        let mut basic: BasicOcspResponse = rasn::der::decode(&bytes.response)?;
        basic.signature_algorithm.algorithm =
            rasn::types::ObjectIdentifier::new_unchecked(vec![1, 2, 3, 4].into());
        bytes.response = rasn::der::encode(&basic)?.into();

        assert!(matches!(
            ParsedOcspResponse::from_der(&rasn::der::encode(&response)?),
            Err(ParseError::UnsupportedAlgorithm)
        ));

        let unsupported = "1.2.3.4".parse::<bcder::Oid>()?;
        assert_eq!(
            validate_ocsp_sig(
                &unsupported,
                &unsupported,
                &bcder::OctetString::new(bytes::Bytes::new()),
                b"data",
                b"key",
            ),
            Err(RawSignatureValidationError::UnsupportedAlgorithm)
        );

        Ok(())
    }

    #[test]
    fn missing_and_malformed_issuer_inputs_do_not_authenticate_claims() -> TestResult {
        let mut envelope: rasn_ocsp::OcspResponse = rasn::der::decode(GOOD)?;
        let bytes = envelope.bytes.as_mut().ok_or("missing basic response")?;
        let mut basic: BasicOcspResponse = rasn::der::decode(&bytes.response)?;
        basic.certs = None;
        bytes.response = rasn::der::encode(&basic)?.into();
        let der = rasn::der::encode(&envelope)?;
        let chain = chain()?;

        for missing_issuer in [vec![], chain[..1].to_vec()] {
            assert!(matches!(
                ParsedOcspResponse::from_der(&der)?.verify_signature(&missing_issuer),
                Err(VerificationError::MissingIssuer)
            ));
        }

        assert!(matches!(
            ParsedOcspResponse::from_der(&der)?
                .verify_signature(&[chain[0].clone(), vec![0xde, 0xad]]),
            Err(VerificationError::InvalidCertificate)
        ));
        assert!(!certificate_issued_by(&[0xde, 0xad], &chain[1]));
        assert!(!certificate_issued_by(&chain[0], &[0xde, 0xad]));

        Ok(())
    }

    #[test]
    fn status_time_errors_are_lazy_and_do_not_become_good_claims() -> TestResult {
        let mut parsed = ParsedOcspResponse::from_der(GOOD)?;
        let fractional = DateTime::parse_from_rfc3339("2025-03-08T00:00:00.500Z")?;
        parsed.basic.tbs_response_data.responses[0].this_update = fractional;

        let claim = parsed.claimed_responses().next().ok_or("missing claim")?;
        assert_eq!(claim.this_update(), Err(InvalidStatusTime));
        assert_eq!(claim.status()?, ClaimedStatus::Good);

        parsed.basic.tbs_response_data.responses[0].cert_status =
            CertStatus::Revoked(rasn_ocsp::RevokedInfo {
                revocation_time: fractional,
                revocation_reason: None,
            });

        assert_eq!(
            parsed
                .claimed_responses()
                .next()
                .ok_or("missing claim")?
                .status(),
            Err(InvalidStatusTime)
        );

        Ok(())
    }

    #[test]
    fn signature_algorithm_hash_mapping_preserves_compatibility() -> TestResult {
        for (signature, digest) in [
            ("1.2.840.10045.4.3.2", "2.16.840.1.101.3.4.2.1"),
            ("1.2.840.10045.4.3.3", "2.16.840.1.101.3.4.2.2"),
            ("1.2.840.10045.4.3.4", "2.16.840.1.101.3.4.2.3"),
            ("1.2.840.113549.1.1.11", "2.16.840.1.101.3.4.2.1"),
            ("1.2.840.113549.1.1.12", "2.16.840.1.101.3.4.2.2"),
            ("1.2.840.113549.1.1.13", "2.16.840.1.101.3.4.2.3"),
            ("1.3.101.112", "2.16.840.1.101.3.4.2.3"),
        ] {
            let oid = rasn::types::ObjectIdentifier::new_unchecked(
                signature
                    .split('.')
                    .map(str::parse)
                    .collect::<Result<Vec<u32>, _>>()?
                    .into(),
            );
            assert_eq!(
                hash_alg_for_sig_alg(&oid)
                    .ok_or("missing algorithm")?
                    .to_string(),
                digest
            );
        }

        Ok(())
    }
}
