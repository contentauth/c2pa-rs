// Copyright 2022 Adobe. All rights reserved.
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

//! Tools for working with OCSP responses.

use chrono::{DateTime, Utc};
use contentauth_pki::ocsp::{ClaimedStatus, ParsedOcspResponse, VerificationError};
use thiserror::Error;

use crate::{
    crypto::internal::time, log_item, status_tracker::StatusTracker,
    validation_results::validation_codes,
};

/// OcspResponse - struct to contain the OCSPResponse DER and the time
/// for the next OCSP check
pub struct OcspResponse {
    /// Original OCSP DER response.
    pub ocsp_der: Vec<u8>,

    /// Time when OCSP response should be re-checked.
    pub next_update: DateTime<Utc>,

    /// Time when certificate was revoked, if applicable.
    pub revoked_at: Option<DateTime<Utc>>,

    /// Authenticated responder certificate chain, including an issuing CA
    /// resolved from the signing chain when it signs the response directly.
    pub ocsp_certs: Option<Vec<Vec<u8>>>,

    /// Associated certificate serial number
    pub certificate_serial_num: String,
}

impl Default for OcspResponse {
    fn default() -> Self {
        Self {
            ocsp_der: Vec::new(),
            next_update: time::utc_now(),
            revoked_at: None,
            ocsp_certs: None,
            certificate_serial_num: String::new(),
        }
    }
}

impl OcspResponse {
    /// Convert an OCSP response in DER format to `OcspResponse`.
    /// The correct usage when there is no attested signing time
    /// to pass a signing_time of None.  The OCSP responses the
    /// follow the current time rules as outlined in the C2PA spec.
    ///
    /// `signing_cert_chain` is the certificate chain of the credential whose
    /// revocation status is being checked (`chain[0]` is the end-entity
    /// certificate, `chain[1]` its issuer).  Per RFC 6960 §4.1.1/§4.2.1 every
    /// single response in the OCSP response whose `certId` does not identify
    /// that certificate is ignored, so a validly-signed response issued for an
    /// unrelated certificate cannot produce a status for the signer.
    ///
    /// The responder is selected by `ResponderID` and its response signature.
    /// The issuing CA may sign without embedding its certificate (RFC 6960
    /// section 4.2.2.2). Callers must still validate responder authorization and
    /// certificate validity before accepting the response's status log.
    pub(crate) fn from_der_checked(
        der: &[u8],
        signing_cert_chain: &[Vec<u8>],
        signing_time: Option<DateTime<Utc>>,
        validation_log: &mut StatusTracker,
    ) -> Result<Self, OcspError> {
        Self::from_der_checked_at(
            der,
            signing_cert_chain,
            signing_time,
            time::utc_now(),
            validation_log,
        )
    }

    /// As [`from_der_checked`](Self::from_der_checked), evaluated at the
    /// current time `now`.
    fn from_der_checked_at(
        der: &[u8],
        signing_cert_chain: &[Vec<u8>],
        signing_time: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        validation_log: &mut StatusTracker,
    ) -> Result<Self, OcspError> {
        let now = now.timestamp();
        let mut output = OcspResponse {
            ocsp_der: der.to_vec(),
            ..Default::default()
        };

        // Per spec if we cannot interpret the OCSP data, we must treat it as if it did
        // not exist.
        let Ok(parsed) = ParsedOcspResponse::from_der(der) else {
            return Ok(output);
        };

        let verified = match parsed.verify_signature(signing_cert_chain) {
            Ok(verified) => verified,
            Err(VerificationError::MissingIssuer) => return Ok(output),
            Err(VerificationError::InvalidCertificate) => {
                return Err(OcspError::InvalidCertificate);
            }
            Err(VerificationError::UnauthenticatedResponse) => {
                return Ok(OcspResponse::default());
            }
        };

        let mut internal_validation_log = StatusTracker::default();
        output.ocsp_certs = Some(verified.responder_certificates().to_vec());

        for single_response in verified.responses_for_certificate(signing_cert_chain) {
            let single_response = single_response.claims();

            // RFC 6960 §4.1.1/§4.2.1: only a single response whose `certId`
            // identifies the signing certificate tells us anything about that
            // certificate. Skip any response for a different certificate;
            // otherwise an attacker could staple a validly-signed "good"
            // response issued for an unrelated certificate and obtain a false
            // "not revoked" attestation for a revoked signing certificate.
            // C2PA only accepts a response whose thisUpdate is not in the future
            // ("The current time is no earlier than thisUpdate"). Such a response
            // says nothing about the certificate, whatever its status.
            let this_update = single_response
                .this_update()
                .map_err(|_| OcspError::InvalidCertificate)?
                .timestamp();
            if now < this_update {
                continue;
            }

            let cert_status = single_response
                .status()
                .map_err(|_| OcspError::InvalidCertificate)?;

            // Extract certificate serial number from cert_id
            if output.certificate_serial_num.is_empty() {
                output.certificate_serial_num = single_response.certificate_serial_number();
            }

            match cert_status {
                ClaimedStatus::Good => {
                    // check cert range against signing time
                    let claimed_next_update = single_response
                        .next_update()
                        .map_err(|_| OcspError::InvalidCertificate)?;

                    let next_update = if let Some(nu) = claimed_next_update {
                        nu.timestamp()
                    } else {
                        // use producedAt + 24hr when there is no nextUpdate
                        verified.produced_at().timestamp() + (24 * 60 * 60)
                    };

                    // Was signing time within the acceptable range?
                    let in_range = if let Some(st) = signing_time {
                        st.timestamp() < this_update
                            || (st.timestamp() >= this_update && st.timestamp() <= next_update)
                    } else {
                        // If no signing time was provided, use current system time.
                        now >= this_update && now <= next_update
                    };

                    if let Some(nu) = claimed_next_update {
                        output.next_update = nu;
                    }

                    // A good response outside its validity window cannot be
                    // used, but is not evidence that the certificate was revoked.
                    if in_range {
                        // As soon as we find one successful match, nothing else matters.
                        log_item!("", "certificate not revoked", "check_ocsp_response")
                            .validation_status(validation_codes::SIGNING_CREDENTIAL_NOT_REVOKED)
                            .success(validation_log);

                        return Ok(output);
                    }
                }

                ClaimedStatus::Revoked {
                    revocation_time,
                    reason,
                } => {
                    let revoked_at = revocation_time.timestamp();
                    let revoked_at_native = revocation_time.naive_utc();

                    if let Some(reason) = reason {
                        if reason == 8 {
                            // Was signing time prior to revocation?
                            let in_range = if let Some(st) = signing_time {
                                revoked_at > st.timestamp()
                            } else {
                                // No signing time was provided; use current system time.
                                revoked_at > now
                            };

                            if !in_range {
                                let utc_with_offset: DateTime<Utc> =
                                    DateTime::from_naive_utc_and_offset(revoked_at_native, Utc);

                                let msg = format!("certificate revoked at: {utc_with_offset}");

                                log_item!("", msg, "check_ocsp_response")
                                    .validation_status(validation_codes::SIGNING_CREDENTIAL_REVOKED)
                                    .failure_no_throw(
                                        &mut internal_validation_log,
                                        OcspError::CertificateRevoked,
                                    );

                                output.revoked_at = Some(DateTime::from_naive_utc_and_offset(
                                    revoked_at_native,
                                    Utc,
                                ));
                            }
                        } else {
                            let utc_with_offset: DateTime<Utc> =
                                DateTime::from_naive_utc_and_offset(revoked_at_native, Utc);

                            // Was the cert signed before revocation?
                            let in_range = if let Some(st) = signing_time {
                                st.timestamp() < utc_with_offset.timestamp()
                            } else {
                                false
                            };

                            if !in_range {
                                log_item!(
                                    "",
                                    format!("certificate revoked at: {}", utc_with_offset),
                                    "check_ocsp_response"
                                )
                                .validation_status(validation_codes::SIGNING_CREDENTIAL_REVOKED)
                                .failure_no_throw(
                                    &mut internal_validation_log,
                                    OcspError::CertificateRevoked,
                                );

                                output.revoked_at = Some(DateTime::from_naive_utc_and_offset(
                                    revoked_at_native,
                                    Utc,
                                ));
                            } else {
                                // As soon as we find one successful match, we're done.
                                output.revoked_at = None;
                                return Ok(output);
                            }
                        }
                    } else {
                        log_item!("", "certificate revoked", "check_ocsp_response")
                            .validation_status(validation_codes::SIGNING_CREDENTIAL_REVOKED)
                            .failure_no_throw(
                                &mut internal_validation_log,
                                OcspError::CertificateRevoked,
                            );
                        output.revoked_at =
                            Some(DateTime::from_naive_utc_and_offset(revoked_at_native, Utc));
                    }
                }

                ClaimedStatus::Unknown => {
                    log_item!("", "unknown certStatus", "check_ocsp_response")
                        .validation_status(validation_codes::SIGNING_CREDENTIAL_OCSP_UNKNOWN)
                        .informational(&mut internal_validation_log);
                }
            }
        }

        // We did not find a viable match; return all the diagnostic log information.
        validation_log.append(&internal_validation_log);

        Ok(output)
    }
}

/// Checks direct issuance and CA authority, not path trust or validity times.
pub(crate) fn certificate_issued_by(cert_der: &[u8], issuer_der: &[u8]) -> bool {
    use contentauth_pki::x509::ParsedCertificate;

    let (Ok(cert), Ok(issuer)) = (
        ParsedCertificate::from_der(cert_der),
        ParsedCertificate::from_der(issuer_der),
    ) else {
        return false;
    };

    cert.is_issued_by(&issuer)
}

/// Describes errors that can be identified when parsing an OCSP response.
#[derive(Debug, Eq, Error, PartialEq)]
#[allow(unused)] // InvalidSystemTime may not exist on all platforms.
pub(crate) enum OcspError {
    /// An invalid certificate was detected.
    #[error("Invalid certificate detected")]
    InvalidCertificate,

    /// The system time was invalid (making validation impossible).
    #[error("Invalid system time")]
    InvalidSystemTime,

    /// The certificate has been revoked.
    #[error("Certificate revoked")]
    CertificateRevoked,

    /// The certificate's status can not be determined.
    #[error("Unknown certificate status")]
    CertificateStatusUnknown,
}

mod fetch;

pub(crate) use fetch::{fetch_ocsp_response, fetch_ocsp_response_async};

#[cfg(test)]
pub(crate) mod test_responder;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
    use chrono::DateTime;
    use chrono::{TimeZone, Utc};
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{
        crypto::{
            internal::time,
            ocsp::{
                test_responder::{encode_response, good_basic_response as basic_response},
                OcspResponse,
            },
        },
        status_tracker::{LogKind, StatusTracker},
        validation_status::{
            SIGNING_CREDENTIAL_NOT_REVOKED, SIGNING_CREDENTIAL_OCSP_UNKNOWN,
            SIGNING_CREDENTIAL_REVOKED,
        },
    };

    /// The signing certificate chain (end-entity + issuer) that the
    /// `response_*.der` fixtures were issued for. Used to satisfy the RFC 6960
    /// certId binding check.
    fn signing_cert_chain() -> Vec<Vec<u8>> {
        let pem = include_bytes!("../../../tests/fixtures/crypto/ocsp/ocsp_chain.pem");
        pem::parse_many(pem)
            .unwrap()
            .into_iter()
            .map(|p| p.into_contents())
            .collect()
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn good() {
        let rsp_data = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");

        let mut validation_log = StatusTracker::default();

        let test_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();

        let ocsp_data = OcspResponse::from_der_checked(
            rsp_data,
            &signing_cert_chain(),
            Some(test_time),
            &mut validation_log,
        )
        .unwrap();

        assert_eq!(ocsp_data.revoked_at, None);
        assert!(ocsp_data.ocsp_certs.is_some());
        assert!(validation_log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn revoked() {
        let rsp_data = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_revoked.der");

        let mut validation_log = StatusTracker::default();

        let test_time = Utc.with_ymd_and_hms(2024, 2, 1, 8, 0, 0).unwrap();

        let ocsp_data = OcspResponse::from_der_checked(
            rsp_data,
            &signing_cert_chain(),
            Some(test_time),
            &mut validation_log,
        )
        .unwrap();

        assert!(ocsp_data.revoked_at.is_some());
        assert!(validation_log.has_status(SIGNING_CREDENTIAL_REVOKED));
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn revoked_status_uses_current_uri() {
        // OCSP status codes must identify the claim signature box (the
        // tracker's current URI), not a placeholder label.
        let rsp_data = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_revoked.der");
        let signature_uri = "self#jumbf=/c2pa/urn:c2pa:test/c2pa.signature";

        let mut validation_log = StatusTracker::default();
        validation_log.push_current_uri(signature_uri);

        let test_time = Utc.with_ymd_and_hms(2024, 2, 1, 8, 0, 0).unwrap();

        OcspResponse::from_der_checked(
            rsp_data,
            &signing_cert_chain(),
            Some(test_time),
            &mut validation_log,
        )
        .unwrap();

        let item = validation_log
            .logged_items()
            .iter()
            .find(|item| item.validation_status.as_deref() == Some(SIGNING_CREDENTIAL_REVOKED))
            .expect("SIGNING_CREDENTIAL_REVOKED log item");
        assert_eq!(item.label, signature_uri);
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn unknown() {
        let rsp_data = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_unknown.der");

        let mut validation_log = StatusTracker::default();

        let test_time = Utc.with_ymd_and_hms(2024, 2, 1, 8, 0, 0).unwrap();

        let ocsp_data = OcspResponse::from_der_checked(
            rsp_data,
            &signing_cert_chain(),
            Some(test_time),
            &mut validation_log,
        )
        .unwrap();

        assert!(ocsp_data.revoked_at.is_none());
        assert!(validation_log.has_status(SIGNING_CREDENTIAL_OCSP_UNKNOWN));

        let item = validation_log
            .logged_items()
            .iter()
            .find(|item| item.validation_status.as_deref() == Some(SIGNING_CREDENTIAL_OCSP_UNKNOWN))
            .expect("SIGNING_CREDENTIAL_OCSP_UNKNOWN log item");
        assert_eq!(item.kind, LogKind::Informational);
    }

    /// Crafted OcspResponse DER with `certs = Some([])` (present but empty).
    ///
    /// Structure:
    ///   OcspResponse { status=successful, responseBytes = BasicOcspResponse {
    ///     tbs_response_data = ResponseData { responderID=byKey(zeros),
    ///                                        producedAt="20230101000000Z",
    ///                                        responses=[] },
    ///     signature_algorithm = sha256WithRSA,
    ///     signature = dummy bytes,
    ///     certs = [0] EXPLICIT SEQUENCE OF Certificate {}  ← empty
    ///   }}
    ///
    /// This is syntactically valid DER.  The old code panicked at `ocsp_certs[0]`
    /// when `basic_response.certs = Some([])` and all earlier guards passed.
    /// The fix uses `.first()` and returns early when the vec is empty.
    const OCSP_EMPTY_CERTS_DER: &[u8] = &[
        0x30, 0x5d, // OcspResponse SEQUENCE (93 bytes)
        0x0a, 0x01, 0x00, // status ENUMERATED 0 (successful)
        0xa0, 0x58, // [0] EXPLICIT responseBytes (88 bytes)
        0x30, 0x56, // ResponseBytes SEQUENCE (86 bytes)
        0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01,
        0x01, // id-pkix-ocsp-basic
        0x04, 0x49, // OCTET STRING — BasicOcspResponse DER (73 bytes)
        0x30, 0x47, // BasicOcspResponse SEQUENCE (71 bytes)
        0x30, 0x2b, // ResponseData SEQUENCE (43 bytes)
        0xa2, 0x16, // responderID [2] EXPLICIT byKey (22 bytes)
        0x04, 0x14, // KeyHash OCTET STRING (20 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 20-byte placeholder
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
        0x0f, // producedAt GeneralizedTime (15 bytes)
        0x32, 0x30, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, // "20230101"
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, // "000000Z"
        0x30, 0x00, // responses SEQUENCE OF SingleResponse (empty)
        0x30, 0x0d, // AlgorithmIdentifier sha256WithRSA (15 bytes)
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, // OID
        0x05, 0x00, // NULL params
        0x03, 0x05, // BIT STRING signature (5 bytes content)
        0x00, 0xde, 0xad, 0xbe, 0xef, // 0 unused bits + 4 dummy bytes
        0xa0, 0x02, // certs [0] EXPLICIT (2 bytes content)
        0x30, 0x00, // SEQUENCE OF Certificate — empty
    ];

    #[test]
    fn from_der_checked_empty_certs_returns_default_not_panic() {
        // Regression: old code panicked at `ocsp_certs[0]` when
        // `basic_response.certs = Some([])`.  The fix uses `.first()` and
        // returns Ok(output) (with ocsp_certs = None) instead of panicking.
        let mut log = StatusTracker::default();
        let result = OcspResponse::from_der_checked(OCSP_EMPTY_CERTS_DER, &[], None, &mut log);
        assert!(result.is_ok());
        // certs were empty so no cert data flows through
        assert!(result.unwrap().ocsp_certs.is_none());
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn response_from_the_future_is_ignored() {
        // response_good.der has thisUpdate 2025-03-07T14:53:24Z.
        let rsp_data = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");
        let signing_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();

        let this_update = Utc.with_ymd_and_hms(2025, 3, 7, 14, 53, 24).unwrap();
        for signing_time in [None, Some(signing_time)] {
            for (now, accepted) in [
                (this_update - chrono::Duration::seconds(1), false),
                (this_update, true),
                (this_update + chrono::Duration::seconds(1), true),
            ] {
                let mut validation_log = StatusTracker::default();
                let parsed = OcspResponse::from_der_checked_at(
                    rsp_data,
                    &signing_cert_chain(),
                    signing_time,
                    now,
                    &mut validation_log,
                )
                .unwrap();
                assert_eq!(
                    validation_log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED),
                    accepted
                );
                assert!(!validation_log.has_status(SIGNING_CREDENTIAL_REVOKED));
                assert_eq!(parsed.certificate_serial_num.is_empty(), !accepted);
                assert!(parsed.revoked_at.is_none());
            }
        }
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn validity() {
        let rsp_data = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");

        let mut validation_log = StatusTracker::default();

        let test_time = Utc.with_ymd_and_hms(2026, 2, 1, 8, 0, 0).unwrap();

        let ocsp_data = OcspResponse::from_der_checked(
            rsp_data,
            &signing_cert_chain(),
            Some(test_time),
            &mut validation_log,
        )
        .unwrap();

        // A good response that is outside its validity window at the signing
        // time cannot be used, but does not mean the certificate was revoked.
        assert!(ocsp_data.revoked_at.is_none());
        assert!(!validation_log.has_any_error());
        assert!(!validation_log.has_status(SIGNING_CREDENTIAL_REVOKED));
        assert!(!validation_log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn good_response_for_wrong_cert_is_ignored() {
        // Regression test for VULN-34623: a validly-signed "good" OCSP response
        // whose certId does not identify the signing certificate must not
        // produce a SIGNING_CREDENTIAL_NOT_REVOKED attestation.
        let rsp_data = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");

        let mut validation_log = StatusTracker::default();

        let test_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();

        // Reverse the chain so chain[0] is the root, whose serial number does
        // not match the response's certId serial number.
        let mut wrong_chain = signing_cert_chain();
        wrong_chain.reverse();

        let ocsp_data = OcspResponse::from_der_checked(
            rsp_data,
            &wrong_chain,
            Some(test_time),
            &mut validation_log,
        )
        .unwrap();

        // No single response bound to the signer, so no status was learned.
        assert!(ocsp_data.certificate_serial_num.is_empty());
        assert!(!validation_log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn stale_good_response_without_signing_time() {
        let basic = basic_response();
        let next_update = basic.tbs_response_data.responses[0]
            .next_update
            .as_ref()
            .map(|next_update| next_update.to_utc())
            .unwrap_or_else(|| {
                basic.tbs_response_data.produced_at.to_utc() + chrono::Duration::hours(24)
            });
        assert!(time::utc_now() > next_update);

        let mut log = StatusTracker::default();
        OcspResponse::from_der_checked(
            include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der"),
            &signing_cert_chain(),
            None,
            &mut log,
        )
        .unwrap();

        // A stale response is unusable evidence: neither "not revoked" nor "revoked".
        assert!(!log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
        assert!(!log.has_status(SIGNING_CREDENTIAL_REVOKED));
        assert!(!log.has_any_error());
    }

    #[test]
    fn uninterpretable_responses_preserve_der_without_asserting_status() {
        let mut responses = vec![Vec::new(), vec![0xde, 0xad]];
        let mut response: rasn_ocsp::OcspResponse = rasn::der::decode(include_bytes!(
            "../../../tests/fixtures/crypto/ocsp/response_good.der"
        ))
        .unwrap();
        response.status = rasn_ocsp::OcspResponseStatus::Unauthorized;
        responses.push(rasn::der::encode(&response).unwrap());
        response.status = rasn_ocsp::OcspResponseStatus::Successful;
        response.bytes.as_mut().unwrap().response = vec![0xde, 0xad].into();
        responses.push(rasn::der::encode(&response).unwrap());
        response.bytes = None;
        responses.push(rasn::der::encode(&response).unwrap());

        let mut basic = basic_response();
        basic.signature_algorithm.algorithm =
            rasn::types::ObjectIdentifier::new_unchecked(vec![1, 2, 3, 4].into());
        responses.push(encode_response(&basic));
        for der in responses {
            let mut log = StatusTracker::default();
            let parsed =
                OcspResponse::from_der_checked(&der, &signing_cert_chain(), None, &mut log)
                    .unwrap();
            assert_eq!(parsed.ocsp_der, der);
            assert!(parsed.ocsp_certs.is_none());
            assert!(parsed.revoked_at.is_none());
            assert!(parsed.certificate_serial_num.is_empty());
            assert!(log.logged_items().is_empty());
        }
    }

    #[test]
    fn unverifiable_signatures_discard_response_including_original_der() {
        let mut no_certs = basic_response();
        no_certs.certs = None;
        let mut bad_signature = basic_response();
        bad_signature.signature = rasn::types::BitString::from_vec(vec![0; 64]);
        for basic in [no_certs, bad_signature] {
            let mut log = StatusTracker::default();
            let parsed = OcspResponse::from_der_checked(
                &encode_response(&basic),
                &signing_cert_chain(),
                None,
                &mut log,
            )
            .unwrap();
            assert!(parsed.ocsp_der.is_empty());
            assert!(parsed.ocsp_certs.is_none());
            assert!(log.logged_items().is_empty());
        }
    }

    #[test]
    fn issuer_signed_response_without_certs_authenticates_both_responder_ids() {
        use super::test_responder::IssuerResponder;

        let responder = IssuerResponder::new();
        let now = Utc.with_ymd_and_hms(2025, 3, 8, 0, 0, 0).unwrap();

        for by_name in [false, true] {
            for certs in [
                None,
                Some(vec![]),
                Some(basic_response().certs.unwrap()),
                Some(vec![rasn::der::decode(&responder.chain[1]).unwrap()]),
            ] {
                let mut basic = responder.basic_response(by_name);
                basic.certs = certs;
                let der = responder.sign(basic);
                let verified = contentauth_pki::ocsp::ParsedOcspResponse::from_der(&der)
                    .unwrap()
                    .verify_signature(&responder.chain)
                    .unwrap();

                assert_eq!(verified.responder_certificates()[0], responder.chain[1]);
                assert_eq!(
                    verified
                        .responses_for_certificate(&responder.chain)
                        .next()
                        .unwrap()
                        .claims()
                        .status()
                        .unwrap(),
                    contentauth_pki::ocsp::ClaimedStatus::Good
                );

                let mut log = StatusTracker::default();
                let parsed =
                    OcspResponse::from_der_checked_at(&der, &responder.chain, None, now, &mut log)
                        .unwrap();

                assert_eq!(parsed.ocsp_der, der);
                assert_eq!(parsed.ocsp_certs.as_ref().unwrap()[0], responder.chain[1]);
                assert!(!parsed.certificate_serial_num.is_empty());
                assert!(log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
                assert!(!log.has_status(SIGNING_CREDENTIAL_REVOKED));
            }
        }
    }

    #[test]
    fn issuer_response_rejects_signed_wrong_ids_and_cert_ids_and_bad_signature() {
        use super::test_responder::IssuerResponder;

        let responder = IssuerResponder::new();
        let original = responder.basic_response(false);
        let now = Utc.with_ymd_and_hms(2025, 3, 8, 0, 0, 0).unwrap();
        let mut wrong_key_id = original.clone();
        wrong_key_id.tbs_response_data.responder_id =
            rasn_ocsp::ResponderId::ByKey(vec![0; 20].into());

        let mut wrong_name_id = original.clone();
        let leaf: rasn_pkix::Certificate = rasn::der::decode(&responder.chain[0]).unwrap();
        wrong_name_id.tbs_response_data.responder_id =
            rasn_ocsp::ResponderId::ByName(leaf.tbs_certificate.subject);

        let mut variants = vec![wrong_key_id, wrong_name_id];

        for field in 0..3 {
            let mut basic = original.clone();
            let id = &mut basic.tbs_response_data.responses[0].cert_id;
            match field {
                0 => id.serial_number = 0.into(),
                1 => id.issuer_name_hash = vec![0; 20].into(),
                _ => id.issuer_key_hash = vec![0; 20].into(),
            }

            variants.push(basic);
        }

        let mut ders: Vec<_> = variants.into_iter().map(|b| responder.sign(b)).collect();
        let mut bad_signature = original;
        bad_signature.signature = rasn::types::BitString::from_vec(vec![0; 64]);
        ders.push(encode_response(&bad_signature));

        for der in ders {
            let mut log = StatusTracker::default();
            let parsed =
                OcspResponse::from_der_checked_at(&der, &responder.chain, None, now, &mut log)
                    .unwrap();

            assert!(parsed.certificate_serial_num.is_empty());
            assert!(parsed.revoked_at.is_none());
            assert!(log.logged_items().is_empty());
        }
    }

    #[test]
    fn issuer_candidate_must_actually_issue_leaf_and_be_a_ca() {
        use super::test_responder::IssuerResponder;

        let responder = IssuerResponder::new();
        let der = responder.sign(responder.basic_response(false));
        let now = Utc.with_ymd_and_hms(2025, 3, 8, 0, 0, 0).unwrap();

        for variant in 0..6 {
            let mut chain = responder.chain.clone();
            match variant {
                0 => chain.truncate(1),
                1 => {
                    let mut leaf: rasn_pkix::Certificate = rasn::der::decode(&chain[0]).unwrap();
                    leaf.signature_value = rasn::types::BitString::from_vec(vec![0; 64]);
                    chain[0] = rasn::der::encode(&leaf).unwrap();
                }
                2 => {
                    let mut issuer: rasn_pkix::Certificate = rasn::der::decode(&chain[1]).unwrap();
                    issuer.tbs_certificate.extensions = None;
                    chain[1] = rasn::der::encode(&issuer).unwrap();
                }
                3 => chain[1] = signing_cert_chain()[1].clone(),
                4 => {
                    let mut issuer: rasn_pkix::Certificate = rasn::der::decode(&chain[1]).unwrap();
                    issuer
                        .tbs_certificate
                        .extensions
                        .as_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|ext| ext.extn_id.to_string() == "2.5.29.15")
                        .unwrap()
                        .extn_value = vec![0x03, 0x02, 0x07, 0x80].into();

                    chain[1] = rasn::der::encode(&issuer).unwrap();
                }
                _ => {
                    let leaf: rasn_pkix::Certificate = rasn::der::decode(&chain[0]).unwrap();
                    let mut issuer: rasn_pkix::Certificate = rasn::der::decode(&chain[1]).unwrap();
                    issuer.tbs_certificate.subject = leaf.tbs_certificate.subject;
                    chain[1] = rasn::der::encode(&issuer).unwrap();
                }
            }

            let mut log = StatusTracker::default();
            let parsed =
                OcspResponse::from_der_checked_at(&der, &chain, None, now, &mut log).unwrap();

            assert!(parsed.ocsp_certs.is_none());
            assert!(parsed.certificate_serial_num.is_empty());
            assert!(log.logged_items().is_empty());
        }
    }

    #[test]
    fn issuance_authentication_preserves_rsa_pss_certificate_support() {
        let chain = signing_cert_chain();
        let mut leaf: rasn_pkix::Certificate = rasn::der::decode(&chain[0]).unwrap();
        let mut issuer: rasn_pkix::Certificate = rasn::der::decode(&chain[1]).unwrap();
        let rsa_cert = pem::parse_many(include_bytes!("../../../tests/fixtures/certs/ps256.pub"))
            .unwrap()
            .remove(0);

        let rsa_cert: rasn_pkix::Certificate = rasn::der::decode(rsa_cert.contents()).unwrap();
        issuer.tbs_certificate.subject_public_key_info =
            rsa_cert.tbs_certificate.subject_public_key_info;

        // SHA-256, MGF1(SHA-256), 32-byte salt, default trailer field.
        let params = [
            0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48,
            0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
        ];

        let issuer = rasn::der::encode(&issuer).unwrap();

        for (alg, hash_suffix, salt_len) in [
            (c2pa_raw_crypto::SigningAlg::Ps256, 1, 32),
            (c2pa_raw_crypto::SigningAlg::Ps384, 2, 48),
            (c2pa_raw_crypto::SigningAlg::Ps512, 3, 64),
        ] {
            let mut params = params;
            params[16] = hash_suffix;
            params[46] = hash_suffix;
            params[53] = salt_len;
            leaf.signature_algorithm = rasn_pkix::AlgorithmIdentifier {
                algorithm: rasn::types::ObjectIdentifier::new_unchecked(
                    vec![1, 2, 840, 113549, 1, 1, 10].into(),
                ),
                parameters: Some(rasn::der::decode(&params).unwrap()),
            };

            leaf.tbs_certificate.signature = leaf.signature_algorithm.clone();
            let signer = c2pa_raw_crypto::signer_from_private_key(
                include_bytes!("../../../tests/fixtures/certs/ps256.pem"),
                alg,
            )
            .unwrap();

            leaf.signature_value = rasn::types::BitString::from_vec(
                signer
                    .sign(&rasn::der::encode(&leaf.tbs_certificate).unwrap())
                    .unwrap(),
            );

            assert!(super::certificate_issued_by(
                &rasn::der::encode(&leaf).unwrap(),
                &issuer
            ));

            let mut wrong_salt = params;
            wrong_salt[53] -= 1;
            let mut wrong_mgf_hash = params;
            wrong_mgf_hash[46] = if hash_suffix == 1 { 2 } else { 1 };
            let mut unsupported_hash = params;
            unsupported_hash[16] = 4;
            let mut malformed_mgf = params.to_vec();
            // Replace MGF1's nested digest AlgorithmIdentifier with NULL.
            malformed_mgf.splice(34..49, [0x05, 0x00]);
            malformed_mgf[1] -= 13;
            malformed_mgf[20] -= 13;
            malformed_mgf[22] -= 13;
            let mut wrong_mgf = params;
            wrong_mgf[33] = 9;
            let mut wrong_trailer = params.to_vec();
            wrong_trailer[1] += 5;
            wrong_trailer.extend_from_slice(&[0xa3, 0x03, 0x02, 0x01, 0x02]);

            for invalid_params in [
                Some(rasn::der::decode(&wrong_salt).unwrap()),
                Some(rasn::der::decode(&wrong_mgf_hash).unwrap()),
                Some(rasn::der::decode(&unsupported_hash).unwrap()),
                Some(rasn::der::decode(&malformed_mgf).unwrap()),
                Some(rasn::der::decode(&wrong_mgf).unwrap()),
                Some(rasn::der::decode(&wrong_trailer).unwrap()),
                Some(rasn::der::decode(&[0x05, 0x00]).unwrap()),
                None,
            ] {
                leaf.signature_algorithm.parameters = invalid_params;
                leaf.tbs_certificate.signature = leaf.signature_algorithm.clone();
                // A fresh signature isolates parameter validation from signature failure.
                leaf.signature_value = rasn::types::BitString::from_vec(
                    signer
                        .sign(&rasn::der::encode(&leaf.tbs_certificate).unwrap())
                        .unwrap(),
                );

                assert!(!super::certificate_issued_by(
                    &rasn::der::encode(&leaf).unwrap(),
                    &issuer
                ));
            }
        }
    }

    #[test]
    fn issuance_authentication_rejects_malformed_and_unsupported_certificates() {
        let responder = super::test_responder::IssuerResponder::new();
        let [leaf_der, issuer_der] = responder.chain.as_slice() else {
            panic!("test chain must contain the leaf and its issuer");
        };

        assert!(!super::certificate_issued_by(&[0xde, 0xad], issuer_der));
        assert!(!super::certificate_issued_by(leaf_der, &[0xde, 0xad]));

        let leaf: rasn_pkix::Certificate = rasn::der::decode(leaf_der).unwrap();
        let mut mismatched = leaf.clone();
        mismatched.tbs_certificate.signature.algorithm =
            rasn::types::ObjectIdentifier::new_unchecked(vec![1, 2, 3, 4].into());
        assert!(!super::certificate_issued_by(
            &rasn::der::encode(&mismatched).unwrap(),
            issuer_der,
        ));

        let mut unsupported = leaf;
        unsupported.signature_algorithm.algorithm =
            rasn::types::ObjectIdentifier::new_unchecked(vec![1, 2, 3, 4].into());
        unsupported.tbs_certificate.signature = unsupported.signature_algorithm.clone();
        assert!(!super::certificate_issued_by(
            &rasn::der::encode(&unsupported).unwrap(),
            issuer_der,
        ));
    }

    #[test]
    fn issuer_response_preserves_stale_good_and_trusted_time_windows() {
        use super::test_responder::IssuerResponder;

        let responder = IssuerResponder::new();

        for has_next_update in [false, true] {
            let mut basic = responder.basic_response(false);
            let start = basic.tbs_response_data.responses[0].this_update.to_utc();
            let end = if has_next_update {
                let end = start + chrono::Duration::hours(48);
                basic.tbs_response_data.responses[0].next_update = Some(end.fixed_offset());
                end
            } else {
                basic.tbs_response_data.responses[0].next_update = None;
                basic.tbs_response_data.produced_at.to_utc() + chrono::Duration::hours(24)
            };

            let der = responder.sign(basic);

            for (now, signing_time, accepted) in [
                (start - chrono::Duration::seconds(1), Some(start), false),
                (start, None, true),
                (end, None, true),
                (end + chrono::Duration::seconds(1), None, false),
                (end + chrono::Duration::days(1), Some(start), true),
                (end + chrono::Duration::days(1), Some(end), true),
                (
                    end + chrono::Duration::days(1),
                    Some(start - chrono::Duration::seconds(1)),
                    true,
                ),
                (
                    end + chrono::Duration::days(1),
                    Some(end + chrono::Duration::seconds(1)),
                    false,
                ),
            ] {
                let mut log = StatusTracker::default();
                let parsed = OcspResponse::from_der_checked_at(
                    &der,
                    &responder.chain,
                    signing_time,
                    now,
                    &mut log,
                )
                .unwrap();

                assert_eq!(log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED), accepted);
                assert!(!log.has_status(SIGNING_CREDENTIAL_REVOKED));
                assert!(!log.has_any_error());
                assert!(parsed.revoked_at.is_none());
            }
        }
    }

    #[test]
    fn issuer_signed_revoked_and_unknown_responses_preserve_status_codes() {
        use super::test_responder::IssuerResponder;

        let responder = IssuerResponder::new();
        let outer: rasn_ocsp::OcspResponse = rasn::der::decode(include_bytes!(
            "../../../tests/fixtures/crypto/ocsp/response_revoked.der"
        ))
        .unwrap();

        let revoked: rasn_ocsp::BasicOcspResponse =
            rasn::der::decode(&outer.bytes.unwrap().response).unwrap();

        for (status, expected) in [
            (
                revoked.tbs_response_data.responses[0].cert_status.clone(),
                SIGNING_CREDENTIAL_REVOKED,
            ),
            (
                rasn_ocsp::CertStatus::Unknown(()),
                SIGNING_CREDENTIAL_OCSP_UNKNOWN,
            ),
        ] {
            let mut basic = responder.basic_response(false);
            basic.tbs_response_data.responses[0].cert_status = status;
            let mut log = StatusTracker::default();
            let parsed = OcspResponse::from_der_checked_at(
                &responder.sign(basic),
                &responder.chain,
                None,
                Utc.with_ymd_and_hms(2025, 3, 8, 0, 0, 0).unwrap(),
                &mut log,
            )
            .unwrap();

            assert_eq!(
                parsed.revoked_at.is_some(),
                expected == SIGNING_CREDENTIAL_REVOKED
            );

            assert!(log.has_status(expected));
            assert!(!log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
        }
    }

    #[test]
    fn delegated_responder_is_selected_by_id_not_certificate_order() {
        let mut basic = basic_response();
        let responder = basic.certs.as_ref().unwrap()[0].clone();
        basic
            .certs
            .as_mut()
            .unwrap()
            .insert(0, rasn::der::decode(&signing_cert_chain()[1]).unwrap());

        let mut log = StatusTracker::default();
        let parsed = OcspResponse::from_der_checked(
            &encode_response(&basic),
            &signing_cert_chain(),
            Some(Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap()),
            &mut log,
        )
        .unwrap();

        assert_eq!(
            parsed.ocsp_certs.unwrap()[0],
            rasn::der::encode(&responder).unwrap()
        );

        assert!(log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));

        basic.tbs_response_data.responder_id = rasn_ocsp::ResponderId::ByKey(vec![0; 20].into());
        let mut log = StatusTracker::default();
        let parsed = OcspResponse::from_der_checked(
            &encode_response(&basic),
            &signing_cert_chain(),
            None,
            &mut log,
        )
        .unwrap();

        assert!(parsed.ocsp_certs.is_none());
        assert!(log.logged_items().is_empty());
    }

    // Re-sign mutated response data so the tests exercise status interpretation,
    // rather than stopping at signature verification.
    #[cfg(feature = "openssl")]
    fn sign_response(basic: rasn_ocsp::BasicOcspResponse) -> Vec<u8> {
        super::test_responder::TestResponder::new().sign(basic)
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn good_time_boundaries_and_missing_next_update() {
        let mut basic = basic_response();
        let this_update = basic.tbs_response_data.responses[0].this_update.to_utc();
        let next_update = this_update + chrono::Duration::days(1);
        basic.tbs_response_data.responses[0].next_update = Some(next_update.fixed_offset());
        let der = sign_response(basic.clone());
        for (signing_time, accepted) in [
            (Some(this_update - chrono::Duration::seconds(1)), true),
            (Some(this_update), true),
            (Some(next_update), true),
            (Some(next_update + chrono::Duration::seconds(1)), false),
        ] {
            let mut log = StatusTracker::default();
            let parsed =
                OcspResponse::from_der_checked(&der, &signing_cert_chain(), signing_time, &mut log)
                    .unwrap();
            assert_eq!(parsed.next_update, next_update);
            assert!(parsed.revoked_at.is_none());
            assert!(!log.has_any_error());
            assert_eq!(log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED), accepted);
            // Outside the window is inconclusive, never a revocation.
            assert!(!log.has_status(SIGNING_CREDENTIAL_REVOKED));
        }

        // Without an attested signing time the response has long expired, which is
        // inconclusive rather than a revocation.
        let mut log = StatusTracker::default();
        let parsed =
            OcspResponse::from_der_checked(&der, &signing_cert_chain(), None, &mut log).unwrap();
        assert_eq!(parsed.next_update, next_update);
        assert!(!log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
        assert!(!log.has_status(SIGNING_CREDENTIAL_REVOKED));
        assert!(!log.has_any_error());

        let mut no_next_update = basic;
        no_next_update.tbs_response_data.responses[0].next_update = None;
        let expiry =
            no_next_update.tbs_response_data.produced_at.to_utc() + chrono::Duration::hours(24);
        let der = sign_response(no_next_update);
        for (signing_time, accepted) in [
            (expiry, true),
            (expiry + chrono::Duration::seconds(1), false),
        ] {
            let mut log = StatusTracker::default();
            let parsed = OcspResponse::from_der_checked(
                &der,
                &signing_cert_chain(),
                Some(signing_time),
                &mut log,
            )
            .unwrap();
            assert!(parsed.revoked_at.is_none());
            assert!(!log.has_any_error());
            assert_eq!(log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED), accepted);
            assert!(!log.has_status(SIGNING_CREDENTIAL_REVOKED));
        }

        let mut future = basic_response();
        let tomorrow =
            DateTime::from_timestamp((Utc::now() + chrono::Duration::days(1)).timestamp(), 0)
                .unwrap();
        future.tbs_response_data.responses[0].this_update = tomorrow.fixed_offset();
        future.tbs_response_data.responses[0].next_update =
            Some((tomorrow + chrono::Duration::days(1)).fixed_offset());
        let mut log = StatusTracker::default();
        OcspResponse::from_der_checked(
            &sign_response(future),
            &signing_cert_chain(),
            None,
            &mut log,
        )
        .unwrap();
        assert!(log.logged_items().is_empty());
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn good_response_current_time_requires_freshness() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap();
        for (this_update_hours, produced_at_hours, next_update_hours, accepted) in [
            (-48, -48, Some(-24), false),
            (-24, -12, Some(24), true),
            (24, 0, Some(48), false),
            (-48, -48, None, false),
            (-24, -12, None, true),
            (24, 0, None, false),
        ] {
            let mut basic = basic_response();
            basic.tbs_response_data.produced_at =
                (now + chrono::Duration::hours(produced_at_hours)).fixed_offset();
            let response = &mut basic.tbs_response_data.responses[0];
            response.this_update =
                (now + chrono::Duration::hours(this_update_hours)).fixed_offset();
            response.next_update = next_update_hours
                .map(|hours| (now + chrono::Duration::hours(hours)).fixed_offset());

            let mut log = StatusTracker::default();
            OcspResponse::from_der_checked_at(
                &sign_response(basic),
                &signing_cert_chain(),
                None,
                now,
                &mut log,
            )
            .unwrap();

            assert_eq!(
                log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED),
                accepted,
                "thisUpdate={this_update_hours}h, producedAt={produced_at_hours}h, nextUpdate={next_update_hours:?}h"
            );
            // Out-of-window responses are inconclusive, never a revocation.
            assert!(!log.has_status(SIGNING_CREDENTIAL_REVOKED));
            assert!(!log.has_any_error());
        }
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn future_responses_are_ignored_regardless_of_certificate_status() {
        use rasn_ocsp::{CertStatus, RevokedInfo};
        use rasn_pkix::CrlReason;

        let this_update = Utc.with_ymd_and_hms(2025, 3, 7, 14, 53, 24).unwrap();
        let revoked_at = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let signing_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();
        for status in [
            CertStatus::Good,
            CertStatus::Unknown(()),
            CertStatus::Revoked(RevokedInfo {
                revocation_time: revoked_at.fixed_offset(),
                revocation_reason: None,
            }),
            CertStatus::Revoked(RevokedInfo {
                revocation_time: revoked_at.fixed_offset(),
                revocation_reason: Some(CrlReason::KeyCompromise),
            }),
            CertStatus::Revoked(RevokedInfo {
                revocation_time: revoked_at.fixed_offset(),
                revocation_reason: Some(CrlReason::RemoveFromCRL),
            }),
        ] {
            let mut basic = basic_response();
            basic.tbs_response_data.responses[0].this_update = this_update.fixed_offset();
            basic.tbs_response_data.responses[0].cert_status = status;
            let der = sign_response(basic);
            for signing_time in [None, Some(signing_time)] {
                let mut log = StatusTracker::default();
                let parsed = OcspResponse::from_der_checked_at(
                    &der,
                    &signing_cert_chain(),
                    signing_time,
                    this_update - chrono::Duration::seconds(1),
                    &mut log,
                )
                .unwrap();
                assert!(log.logged_items().is_empty());
                assert!(parsed.certificate_serial_num.is_empty());
                assert!(parsed.revoked_at.is_none());
            }
        }
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn revocation_reason_and_signing_time_matrix() {
        use rasn_ocsp::{CertStatus, RevokedInfo};
        use rasn_pkix::CrlReason;

        for reason in [
            None,
            Some(CrlReason::KeyCompromise),
            Some(CrlReason::RemoveFromCRL),
        ] {
            for future in [false, true] {
                let revoked_at = if future {
                    Utc::now() + chrono::Duration::days(365)
                } else {
                    Utc.with_ymd_and_hms(2023, 2, 1, 0, 0, 0).unwrap()
                };
                // DER GeneralizedTime rounds fractional seconds.
                let revoked_at = DateTime::from_timestamp(revoked_at.timestamp(), 0).unwrap();
                let mut basic = basic_response();
                basic.tbs_response_data.responses[0].cert_status =
                    CertStatus::Revoked(RevokedInfo {
                        revocation_time: revoked_at.fixed_offset(),
                        revocation_reason: reason,
                    });
                let der = sign_response(basic);
                for signing_time in [
                    None,
                    Some(revoked_at - chrono::Duration::seconds(1)),
                    Some(revoked_at),
                    Some(revoked_at + chrono::Duration::seconds(1)),
                ] {
                    let expected_revoked = match reason {
                        None => true,
                        Some(CrlReason::RemoveFromCRL) => {
                            signing_time.map(|st| st >= revoked_at).unwrap_or(!future)
                        }
                        _ => signing_time.map(|st| st >= revoked_at).unwrap_or(true),
                    };

                    let mut log = StatusTracker::default();
                    let parsed = OcspResponse::from_der_checked(
                        &der,
                        &signing_cert_chain(),
                        signing_time,
                        &mut log,
                    )
                    .unwrap();
                    assert_eq!(parsed.revoked_at, expected_revoked.then_some(revoked_at));
                    assert_eq!(log.has_status(SIGNING_CREDENTIAL_REVOKED), expected_revoked);
                    assert!(!log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
                }
            }
        }
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn matching_good_response_suppresses_earlier_unknown_diagnostics() {
        let mut basic = basic_response();
        basic.tbs_response_data.produced_at =
            (time::utc_now() - chrono::Duration::hours(1)).fixed_offset();
        let good = basic.tbs_response_data.responses[0].clone();
        let mut unknown = good.clone();
        unknown.cert_status = rasn_ocsp::CertStatus::Unknown(());
        let mut unrelated = good.clone();
        unrelated.cert_id.serial_number = 0.into();
        basic.tbs_response_data.responses = vec![unrelated, unknown, good];
        let mut log = StatusTracker::default();
        let parsed = OcspResponse::from_der_checked(
            &sign_response(basic),
            &signing_cert_chain(),
            None,
            &mut log,
        )
        .unwrap();
        assert!(!parsed.certificate_serial_num.is_empty());
        assert!(log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
        assert!(!log.has_status(SIGNING_CREDENTIAL_OCSP_UNKNOWN));
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn fractional_ocsp_status_times_are_rejected_as_invalid_certificates() {
        let fractional = Utc.with_ymd_and_hms(2025, 3, 7, 15, 0, 0).unwrap()
            + chrono::Duration::milliseconds(123);
        for field in 0..3 {
            let mut basic = basic_response();
            let single = &mut basic.tbs_response_data.responses[0];
            match field {
                0 => single.this_update = fractional.fixed_offset(),
                1 => single.next_update = Some(fractional.fixed_offset()),
                _ => {
                    single.cert_status = rasn_ocsp::CertStatus::Revoked(rasn_ocsp::RevokedInfo {
                        revocation_time: fractional.fixed_offset(),
                        revocation_reason: None,
                    });
                }
            }

            let mut log = StatusTracker::default();
            let result = OcspResponse::from_der_checked(
                &sign_response(basic),
                &signing_cert_chain(),
                None,
                &mut log,
            );
            assert!(matches!(result, Err(super::OcspError::InvalidCertificate)));
            assert!(log.logged_items().is_empty());
        }
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn later_good_response_keeps_earlier_revoked_at_but_discards_its_diagnostic() {
        let mut basic = basic_response();
        basic.tbs_response_data.produced_at =
            (time::utc_now() - chrono::Duration::hours(1)).fixed_offset();
        let good = basic.tbs_response_data.responses[0].clone();
        let mut revoked = good.clone();
        let revoked_at = Utc.with_ymd_and_hms(2023, 2, 1, 0, 0, 0).unwrap();
        revoked.cert_status = rasn_ocsp::CertStatus::Revoked(rasn_ocsp::RevokedInfo {
            revocation_time: revoked_at.fixed_offset(),
            revocation_reason: None,
        });
        basic.tbs_response_data.responses = vec![revoked, good];
        let mut log = StatusTracker::default();
        let parsed = OcspResponse::from_der_checked(
            &sign_response(basic),
            &signing_cert_chain(),
            None,
            &mut log,
        )
        .unwrap();
        assert_eq!(parsed.revoked_at, Some(revoked_at));
        assert!(log.has_status(SIGNING_CREDENTIAL_NOT_REVOKED));
        assert!(!log.has_status(SIGNING_CREDENTIAL_REVOKED));
    }
}
