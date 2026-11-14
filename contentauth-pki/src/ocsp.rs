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

//! Deterministic OCSP parsing, signature verification, and certificate binding.
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

/// A failure to interpret the response or its signature algorithm.
#[derive(Debug, Eq, Error, PartialEq)]
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

    let Ok(subject) = rasn::der::decode::<Certificate>(subject_der) else {
        return false;
    };
    let Ok(issuer) = rasn::der::decode::<Certificate>(issuer_der) else {
        return false;
    };

    if cert_id.serial_number != subject.tbs_certificate.serial_number {
        return false;
    }

    let Ok(issuer_name_raw) = rasn::der::encode(&issuer.tbs_certificate.subject) else {
        return false;
    };
    let issuer_key_raw = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_raw_slice();

    let Some(name_hash) = hash_by_oid(&cert_id.hash_algorithm.algorithm, &issuer_name_raw) else {
        return false;
    };
    let Some(key_hash) = hash_by_oid(&cert_id.hash_algorithm.algorithm, issuer_key_raw) else {
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
mod tests;
