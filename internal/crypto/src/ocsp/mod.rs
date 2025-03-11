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

use std::str::FromStr;

use c2pa_status_tracker::{log_item, validation_codes, StatusTracker};
use chrono::{DateTime, NaiveDateTime, Utc};
use rasn::prelude::*;
use rasn_ocsp::{BasicOcspResponse, CertStatus, OcspResponseStatus};
use rasn_pkix::{Certificate, CrlReason};
use thiserror::Error;

use crate::{internal::time, raw_signature::validator_for_sig_and_hash_algs};

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

fn dump_cert_chain(
    certs: &[Vec<u8>],
    output_path: Option<&str>,
) -> Result<Vec<u8>, crate::cose::CoseError> {
    let mut writer = Vec::new();

    let line_len = 64;
    let cert_begin = "-----BEGIN CERTIFICATE-----";
    let cert_end = "-----END CERTIFICATE-----";

    for der_bytes in certs {
        let cert_base_str = crate::base64::encode(der_bytes);

        // Break line into fixed-length lines.
        let cert_lines = cert_base_str
            .chars()
            .collect::<Vec<char>>()
            .chunks(line_len)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>();

        std::io::Write::write_fmt(&mut writer, format_args!("{}\n", cert_begin)).map_err(|_e| {
            crate::cose::CoseError::InternalError("could not write PEM".to_string())
        })?;

        for l in cert_lines {
            std::io::Write::write_fmt(&mut writer, format_args!("{}\n", l)).map_err(|_e| {
                crate::cose::CoseError::InternalError("could not write PEM".to_string())
            })?;
        }

        std::io::Write::write_fmt(&mut writer, format_args!("{}\n", cert_end)).map_err(|_e| {
            crate::cose::CoseError::InternalError("could not write PEM".to_string())
        })?;
    }

    // If output path is provided, write the PEM data to the file
    if let Some(path) = output_path {
        std::fs::write(path, &writer).map_err(|_e| {
            crate::cose::CoseError::InternalError("could not write PEM to file".to_string())
        })?;
    }

    Ok(writer)
}

// Create OCSP CertId from a certificate der chain. The chain must start with
// the certificate you want to check followed by the its issuing certificate.
pub(crate) fn make_ocsp_cert_id(cert_chain: &[Vec<u8>]) -> Option<rasn_ocsp::CertId> {
    // make CertId of our signing cert
    if cert_chain.len() < 2 {
        return None;
    }
    let subject: Certificate = rasn::der::decode(&cert_chain[0]).ok()?;
    let issuer: Certificate = rasn::der::decode(&cert_chain[1]).ok()?;

    let issuer_name_raw = rasn::der::encode(&issuer.tbs_certificate.subject).ok()?;

    let issuer_key_raw = &issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_raw_slice();

    let issuer_name_hash = crate::hash::sha1(&issuer_name_raw);
    let issuer_key_hash = crate::hash::sha1(issuer_key_raw);
    let serial_number = subject.tbs_certificate.serial_number;

    let sha1_oid = rasn::types::Oid::new(&[1, 3, 14, 3, 2, 26])?;
    let alg = rasn::types::ObjectIdentifier::from(sha1_oid);

    let sha1_ai = rasn_pkix::AlgorithmIdentifier {
        algorithm: alg,
        parameters: Some(Any::new(rasn::der::encode(&()).ok()?)),
        // Many OCSP responders expect this to be NULL not None.
    };

    // create CertID
    Some(rasn_ocsp::CertId {
        hash_algorithm: sha1_ai.clone(),
        issuer_name_hash: OctetString::from(issuer_name_hash),
        issuer_key_hash: OctetString::from(issuer_key_hash),
        serial_number,
    })
}

impl OcspResponse {
    /// Convert an OCSP response in DER format to `OcspResponse`.
    pub(crate) fn from_der_checked(
        der: &[u8],
        cert_id: Option<rasn_ocsp::CertId>,
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

            let mut ocsp_signed = false;
            for ocsp_cert in ocsp_certs {
                // save the OCSP cert
                let cert_der =
                    rasn::der::encode(ocsp_cert).map_err(|_e| OcspError::InvalidCertificate)?;
                cert_der_vec.push(cert_der);

                // make sure response is for our cert
                match &response_data.responder_id {
                    rasn_ocsp::ResponderId::ByName(name) => {
                        if *name != ocsp_cert.tbs_certificate.subject {
                            continue;
                        }
                    }
                    rasn_ocsp::ResponderId::ByKey(bytes) => {
                        let issuer_key_hash = crate::hash::sha1(
                            ocsp_cert
                                .tbs_certificate
                                .subject_public_key_info
                                .subject_public_key
                                .as_raw_slice(),
                        );
                        if *bytes != issuer_key_hash {
                            continue;
                        }
                    }
                }

                // one of these certs should have signed the response
                // check signature of the response
                let tbs_response_data =
                    rasn::der::encode(response_data).map_err(|_e| OcspError::InvalidCertificate)?;

                let signing_oid = &ocsp_cert.tbs_certificate.subject_public_key_info.algorithm;
                let signing_key_der =
                    rasn::der::encode(&ocsp_cert.tbs_certificate.subject_public_key_info)
                        .map_err(|_e| OcspError::InvalidCertificate)?;

                let sig_alg = bcder::Oid::from_str(&signing_oid.algorithm.to_string())
                    .map_err(|_e| OcspError::InvalidCertificate)?;
                let hash_alg =
                    bcder::Oid::from_str(&basic_response.signature_algorithm.algorithm.to_string())
                        .map_err(|_e| OcspError::InvalidCertificate)?;

                let signature_bytes = basic_response.signature.as_raw_slice();

                
                if let Some(validator) = validator_for_sig_and_hash_algs(&sig_alg, &hash_alg) {
                    // try next value if no good value has been found
                    if ocsp_signed == false {
                        ocsp_signed = validator
                            .validate(
                                signature_bytes,
                                &tbs_response_data,
                                &signing_key_der,
                            )
                            .is_ok()
                    }
                }

                std::fs::write("/Users/mfisher/Downloads/ocsp_orig.der", der).expect("ok");

                std::fs::write("/Users/mfisher/Downloads/tbs_response_data.der", &tbs_response_data).expect("ok");
            }

            dump_cert_chain(&cert_der_vec, Some("/Users/mfisher/Downloads/ocsp.pem"))
                .expect("could not dump");

            if output.ocsp_certs.is_none() {
                output.ocsp_certs = Some(cert_der_vec);
            }
        } else {
            // no certs so we cannot validate trust
            log_item!(
                "OCSP_RESPONSE",
                "OCSP response was not signed",
                "check_ocsp_response"
            )
            .validation_status(validation_codes::SIGNING_CREDENTIAL_OCSP_UNKNOWN)
            .failure(
                &mut internal_validation_log,
                OcspError::CertificateStatusUnknown,
            )?;
        }

        for single_response in &response_data.responses {
            // we only care about responses that match our CertId
            match cert_id {
                Some(ref id) => {
                    if single_response.cert_id != *id {
                        continue;
                    }
                }
                None => continue,
            }

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
                        this_update
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
                                let revoked_at_native = NaiveDateTime::parse_from_str(
                                    &revocation_time.to_string(),
                                    DATE_FMT,
                                )
                                .map_err(|_e| OcspError::InvalidCertificate)?;

                                let utc_with_offset: DateTime<Utc> =
                                    DateTime::from_naive_utc_and_offset(revoked_at_native, Utc);

                                let msg = format!("certificate revoked at: {}", utc_with_offset);

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
                                &revocation_time.to_string(),
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
                                return Ok(output);
                            }
                        }
                    } else {
                        let revoked_at_native =
                            NaiveDateTime::parse_from_str(&revocation_time.to_string(), DATE_FMT)
                                .map_err(|_e| OcspError::InvalidCertificate)?;

                        let utc_with_offset: DateTime<Utc> =
                            DateTime::from_naive_utc_and_offset(revoked_at_native, Utc);

                        let msg = format!("certificate revoked at: {}", utc_with_offset);

                        log_item!("OCSP_RESPONSE", msg, "check_ocsp_response")
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
                    log_item!(
                        "OCSP_RESPONSE",
                        "unknown certificate status",
                        "check_ocsp_response"
                    )
                    .validation_status(validation_codes::SIGNING_CREDENTIAL_OCSP_UNKNOWN)
                    .failure(
                        &mut internal_validation_log,
                        OcspError::CertificateStatusUnknown,
                    )?;
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
