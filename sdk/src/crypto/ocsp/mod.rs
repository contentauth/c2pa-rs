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

use chrono::{DateTime, NaiveDateTime, Utc};
use rasn_ocsp::{BasicOcspResponse, CertStatus, OcspResponseStatus};
use rasn_pkix::CrlReason;
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

    /// OCSP certificate chain.
    pub ocsp_certs: Option<Vec<Vec<u8>>>,
}

impl Default for OcspResponse {
    fn default() -> Self {
        Self {
            ocsp_der: Vec::new(),
            next_update: time::utc_now(),
            revoked_at: None,
            ocsp_certs: None,
        }
    }
}

impl OcspResponse {
    /// Convert an OCSP response in DER format to `OcspResponse`.
    /// The correct usage when there is no attested signing time
    /// to pass a signing_time of None.  The OCSP responses the
    /// follow the current time rules as outlined in the C2PA spec.
    pub(crate) fn from_der_checked(
        der: &[u8],
        signing_time: Option<DateTime<Utc>>,
        validation_log: &mut StatusTracker,
    ) -> Result<Self, OcspError> {
        let mut output = OcspResponse {
            ocsp_der: der.to_vec(),
            ..Default::default()
        };

        // Per spec if we cannot interpret the OCSP data, we must treat it as if it did
        // not exist.
        let Ok(ocsp_response) = rasn::der::decode::<rasn_ocsp::OcspResponse>(der) else {
            return Ok(output);
        };

        if ocsp_response.status != OcspResponseStatus::Successful {
            return Ok(output);
        }

        let Some(response_bytes) = ocsp_response.bytes else {
            return Ok(output);
        };

        let Ok(basic_response) = rasn::der::decode::<BasicOcspResponse>(&response_bytes.response)
        else {
            return Ok(output);
        };

        let mut internal_validation_log = StatusTracker::default();
        let response_data = &basic_response.tbs_response_data;

        // get OCSP cert chain if available
        if let Some(ocsp_certs) = &basic_response.certs {
            let mut cert_der_vec = Vec::new();

            for ocsp_cert in ocsp_certs {
                let cert_der =
                    rasn::der::encode(ocsp_cert).map_err(|_e| OcspError::InvalidCertificate)?;

                cert_der_vec.push(cert_der);
            }

            if output.ocsp_certs.is_none() {
                output.ocsp_certs = Some(cert_der_vec);
            }
        }

        for single_response in &response_data.responses {
            let cert_status = &single_response.cert_status;

            match cert_status {
                CertStatus::Good => {
                    // check cert range against signing time
                    let this_update = NaiveDateTime::parse_from_str(
                        &single_response.this_update.to_string(),
                        DATE_FMT,
                    )
                    .map_err(|_e| OcspError::InvalidCertificate)?
                    .and_utc()
                    .timestamp();

                    let next_update = if let Some(nu) = &single_response.next_update {
                        NaiveDateTime::parse_from_str(&nu.to_string(), DATE_FMT)
                            .map_err(|_e| OcspError::InvalidCertificate)?
                            .and_utc()
                            .timestamp()
                    } else {
                        // use producedAt + 24hr when there is no nextUpdate
                        response_data.produced_at.to_utc().timestamp() + (24 * 60 * 60)
                    };

                    // Was signing time within the acceptable range?
                    let in_range = if let Some(st) = signing_time {
                        st.timestamp() < this_update
                            || (st.timestamp() >= this_update && st.timestamp() <= next_update)
                    } else {
                        // If no signing time was provided, use current system time.
                        let now = time::utc_now().timestamp();

                        now >= this_update && now <= next_update
                    };

                    if let Some(nu) = &single_response.next_update {
                        let nu_utc = nu.naive_utc();
                        output.next_update = DateTime::from_naive_utc_and_offset(nu_utc, Utc);
                    }

                    if !in_range {
                        log_item!(
                            "OCSP_RESPONSE",
                            "certificate revoked",
                            "check_ocsp_response"
                        )
                        .validation_status(validation_codes::SIGNING_CREDENTIAL_REVOKED)
                        .failure_no_throw(
                            &mut internal_validation_log,
                            OcspError::CertificateRevoked,
                        );
                    } else {
                        // As soon as we find one successful match, nothing else matters.
                        log_item!(
                            "OCSP_RESPONSE",
                            "certificate not revoked",
                            "check_ocsp_response"
                        )
                        .validation_status(validation_codes::SIGNING_CREDENTIAL_NOT_REVOKED)
                        .success(validation_log);

                        return Ok(output);
                    }
                }

                CertStatus::Revoked(revoked_info) => {
                    let revocation_time = &revoked_info.revocation_time;

                    let revoked_at =
                        NaiveDateTime::parse_from_str(&revocation_time.to_string(), DATE_FMT)
                            .map_err(|_e| OcspError::InvalidCertificate)?
                            .and_utc()
                            .timestamp();

                    let revoked_at_native =
                        NaiveDateTime::parse_from_str(&revocation_time.to_string(), DATE_FMT)
                            .map_err(|_e| OcspError::InvalidCertificate)?;

                    if let Some(reason) = revoked_info.revocation_reason {
                        if reason == CrlReason::RemoveFromCRL {
                            // Was signing time prior to revocation?
                            let in_range = if let Some(st) = signing_time {
                                revoked_at > st.timestamp()
                            } else {
                                // No signing time was provided; use current system time.
                                let now = time::utc_now().timestamp();
                                revoked_at > now
                            };

                            if !in_range {
                                let utc_with_offset: DateTime<Utc> =
                                    DateTime::from_naive_utc_and_offset(revoked_at_native, Utc);

                                let msg = format!("certificate revoked at: {utc_with_offset}");

                                log_item!("OCSP_RESPONSE", msg, "check_ocsp_response")
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
                            let Ok(revoked_at_native) = NaiveDateTime::parse_from_str(
                                &revoked_info.revocation_time.to_string(),
                                DATE_FMT,
                            ) else {
                                return Err(OcspError::InvalidCertificate);
                            };

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
                                    "OCSP_RESPONSE",
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
                        log_item!(
                            "OCSP_RESPONSE",
                            "certificate revoked",
                            "check_ocsp_response"
                        )
                        .validation_status(validation_codes::SIGNING_CREDENTIAL_REVOKED)
                        .failure_no_throw(
                            &mut internal_validation_log,
                            OcspError::CertificateRevoked,
                        );
                        output.revoked_at =
                            Some(DateTime::from_naive_utc_and_offset(revoked_at_native, Utc));
                    }
                }

                CertStatus::Unknown(_) => {
                    log_item!("OCSP_RESPONSE", "unknown certStatus", "check_ocsp_response")
                        .validation_status(validation_codes::SIGNING_CREDENTIAL_OCSP_UNKNOWN)
                        .failure_no_throw(
                            &mut internal_validation_log,
                            OcspError::CertificateStatusUnknown,
                        );
                }
            }
        }

        // We did not find a viable match; return all the diagnostic log information.
        validation_log.append(&internal_validation_log);

        Ok(output)
    }
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

const DATE_FMT: &str = "%Y-%m-%d %H:%M:%S %Z";

#[cfg(not(target_arch = "wasm32"))]
mod fetch;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) use fetch::fetch_ocsp_response;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use chrono::{TimeZone, Utc};
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{
        crypto::ocsp::OcspResponse,
        status_tracker::StatusTracker,
        validation_status::{
            SIGNING_CREDENTIAL_NOT_REVOKED, SIGNING_CREDENTIAL_OCSP_UNKNOWN,
            SIGNING_CREDENTIAL_REVOKED,
        },
    };

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn good() {
        let rsp_data = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_good.der");

        let mut validation_log = StatusTracker::default();

        let test_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();

        let ocsp_data =
            OcspResponse::from_der_checked(rsp_data, Some(test_time), &mut validation_log).unwrap();

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

        let ocsp_data =
            OcspResponse::from_der_checked(rsp_data, Some(test_time), &mut validation_log).unwrap();

        assert!(ocsp_data.revoked_at.is_some());
        assert!(validation_log.has_status(SIGNING_CREDENTIAL_REVOKED));
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

        let ocsp_data =
            OcspResponse::from_der_checked(rsp_data, Some(test_time), &mut validation_log).unwrap();

        assert!(ocsp_data.revoked_at.is_none());
        assert!(validation_log.has_any_error());
        assert!(validation_log.has_status(SIGNING_CREDENTIAL_OCSP_UNKNOWN));
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

        let ocsp_data =
            OcspResponse::from_der_checked(rsp_data, Some(test_time), &mut validation_log).unwrap();

        assert!(ocsp_data.revoked_at.is_none());
        assert!(validation_log.has_any_error());
        assert!(validation_log.has_status(SIGNING_CREDENTIAL_REVOKED));
    }
}
