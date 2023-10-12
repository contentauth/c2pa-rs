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

use std::io::Read;

use chrono::{DateTime, NaiveDateTime, Utc};
use conv::ConvUtil;
use openssl::ocsp::{self, OcspBasicResponse, OcspCertStatus, OcspRevokedStatus};

use crate::{
    error::{Error, Result},
    openssl::check_chain_order_der,
    status_tracker::{log_item, StatusTracker},
    utils::base64,
    validation_status,
};

const DATE_FMT: &str = "%b %d %H:%M:%S %Y %Z";

/// OcspData - struct to contain the OCSPResponse DER and the time
/// for the next OCSP check
pub struct OcspData {
    pub ocsp_der: Vec<u8>,
    pub next_update: DateTime<Utc>,
}

impl OcspData {
    pub fn new() -> Self {
        OcspData {
            ocsp_der: Vec::new(),
            next_update: Utc::now(),
        }
    }
}

impl Default for OcspData {
    fn default() -> Self {
        Self {
            ocsp_der: Vec::new(),
            next_update: Utc::now(),
        }
    }
}

fn get_ocsp_responders(cert_der: &[u8]) -> Option<Vec<String>> {
    let cert = openssl::x509::X509::from_der(cert_der).ok()?;

    if let Ok(stack) = cert.ocsp_responders() {
        let mut output: Vec<String> = Vec::new();
        for responder in stack {
            output.push(responder.to_string());
        }
        Some(output)
    } else {
        None
    }
}

/// Check the supplied cert chain for an OCSP responder in the end-entity cert.  If found it will attempt to
/// retrieve the OCSPResponse.
/// If successful returns OcspData containing the DER encoded OCSPResponse and the DateTime for when this cached response should
/// be refreshed.  None otherwise.
pub fn get_ocsp_response(certs: &[Vec<u8>]) -> Option<OcspData> {
    //} Option<DateTime<Utc>>) {
    // must be in hierarchical order for this to work
    if certs.len() < 2 || !check_chain_order_der(certs) {
        return None;
    }

    if let Some(responders) = get_ocsp_responders(&certs[0]) {
        for r in responders {
            let url = url::Url::parse(&r).ok()?;
            let subject = openssl::x509::X509::from_der(&certs[0]).ok()?;
            let issuer = openssl::x509::X509::from_der(&certs[1]).ok()?;

            let cert_id = openssl::ocsp::OcspCertId::from_cert(
                openssl::hash::MessageDigest::sha1(),
                &subject,
                &issuer,
            )
            .ok()?;

            let mut ocsp_req = ocsp::OcspRequest::new().ok()?;
            ocsp_req.add_id(cert_id).ok()?;
            let request_str = base64::encode(&ocsp_req.to_der().ok()?);

            let req_url = url.join(&request_str).ok()?;

            let request = ureq::get(req_url.as_str());
            let response = if let Some(host) = url.host() {
                request.set("Host", &host.to_string()).call().ok()? // for responders that don't support http 1.0
            } else {
                request.call().ok()?
            };

            if response.status() == 200 {
                let len = response
                    .header("Content-Length")
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(2000);

                let mut ocsp_rsp: Vec<u8> = Vec::with_capacity(len);

                response
                    .into_reader()
                    .take(1000000)
                    .read_to_end(&mut ocsp_rsp)
                    .ok()?;

                // sanity check response
                let ocsp_response = ocsp::OcspResponse::from_der(&ocsp_rsp).ok()?;
                if ocsp_response.status() == ocsp::OcspResponseStatus::SUCCESSFUL {
                    if let Ok(basic_response) = ocsp_response.basic() {
                        if let Some(cert_status) =
                            get_end_entity_cert_status(certs, &basic_response)
                        {
                            if cert_status.status == OcspCertStatus::GOOD
                                || cert_status.status == OcspCertStatus::REVOKED
                                    && cert_status.reason == OcspRevokedStatus::REMOVE_FROM_CRL
                            {
                                let next_update = NaiveDateTime::parse_from_str(
                                    &cert_status.next_update.to_string(),
                                    DATE_FMT,
                                )
                                .ok()?;

                                let output = OcspData {
                                    ocsp_der: ocsp_rsp,
                                    next_update: DateTime::from_naive_utc_and_offset(
                                        next_update,
                                        chrono::Utc,
                                    ),
                                };

                                return Some(output);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// find the certificate to check
fn get_end_entity_cert_status<'a>(
    certs: &[Vec<u8>],
    basic_response: &'a OcspBasicResponse,
) -> Option<ocsp::OcspStatus<'a>> {
    if certs.len() < 2 || !check_chain_order_der(certs) {
        return None;
    }

    let subject = openssl::x509::X509::from_der(&certs[0]).ok()?;
    let issuer = openssl::x509::X509::from_der(&certs[1]).ok()?;

    let cert_id = openssl::ocsp::OcspCertId::from_cert(
        openssl::hash::MessageDigest::sha1(),
        &subject,
        &issuer,
    )
    .ok()?;

    basic_response.find_status(&cert_id)
}

// check to OCSP response against the supplied certs and signing time (if available)
// Returns - empty result on success
pub(crate) fn _check_ocsp_response(
    ocsp_response_der: &[u8],
    certs: &[Vec<u8>],
    signing_time: Option<chrono::DateTime<chrono::Utc>>,
    validation_log: &mut impl StatusTracker,
) -> Result<()> {
    if certs.len() < 2 || !check_chain_order_der(certs) {
        return Err(Error::BadParam("certs vector not valid".to_string()));
    }

    if let Ok(ocsp_response) = ocsp::OcspResponse::from_der(ocsp_response_der) {
        if ocsp_response.status() == ocsp::OcspResponseStatus::SUCCESSFUL {
            if let Ok(basic_response) = ocsp_response.basic() {
                if let Some(cert_status) = get_end_entity_cert_status(certs, &basic_response) {
                    if cert_status.status == OcspCertStatus::GOOD
                        || cert_status.status == OcspCertStatus::REVOKED
                            && cert_status.reason == OcspRevokedStatus::REMOVE_FROM_CRL
                    {
                        // check cert range against signing time
                        let this_update = NaiveDateTime::parse_from_str(
                            &cert_status.this_update.to_string(),
                            DATE_FMT,
                        )
                        .map_err(|_e| Error::CoseInvalidCert)?
                        .timestamp();
                        let next_update = NaiveDateTime::parse_from_str(
                            &cert_status.next_update.to_string(),
                            DATE_FMT,
                        )
                        .map_err(|_e| Error::CoseInvalidCert)?
                        .timestamp();

                        // check to see if we are within range or current time within range
                        let in_range = if let Some(st) = signing_time {
                            println!("{}, {}, {}", this_update, next_update, st.timestamp());
                            st.timestamp() >= this_update && st.timestamp() <= next_update
                        } else {
                            // no timestamp so check against current time
                            // use instant to avoid wasm issues
                            let now_f64 = instant::now() / 1000.0;
                            let now: i64 = now_f64
                                .approx_as::<i64>()
                                .map_err(|_e| Error::BadParam("system time invalid".to_string()))?;

                            now >= this_update && now <= next_update
                        };

                        if !in_range {
                            let log_item = log_item!(
                                "OCSP_RESPONSE",
                                "certificate revoked",
                                "check_ocsp_response"
                            )
                            .error(Error::CoseCertRevoked)
                            .validation_status(validation_status::SIGNING_CREDENTIAL_REVOKED);
                            validation_log.log_silent(log_item);

                            return Err(Error::CoseCertRevoked);
                        }
                    } else if cert_status.status == OcspCertStatus::REVOKED
                        && cert_status.reason != OcspRevokedStatus::REMOVE_FROM_CRL
                    {
                        // if it was revoked check if was revoked after signing time
                        if let Some(revocation_time) = cert_status.revocation_time {
                            // check cert range against signing time
                            let revoked_at = NaiveDateTime::parse_from_str(
                                &revocation_time.to_string(),
                                DATE_FMT,
                            )
                            .map_err(|_e| Error::CoseInvalidCert)?
                            .timestamp();

                            // check to see if we are within range or current time within range
                            let in_range = if let Some(st) = signing_time {
                                revoked_at > st.timestamp()
                            } else {
                                // no timestamp so check against current time
                                // use instant to avoid wasm issues
                                let now_f64 = instant::now() / 1000.0;
                                let now: i64 = now_f64.approx_as::<i64>().map_err(|_e| {
                                    Error::BadParam("system time invalid".to_string())
                                })?;

                                revoked_at > now
                            };

                            if !in_range {
                                let log_item = log_item!(
                                    "OCSP_RESPONSE",
                                    "certificate revoked",
                                    "check_ocsp_response"
                                )
                                .error(Error::CoseCertRevoked)
                                .validation_status(validation_status::SIGNING_CREDENTIAL_REVOKED);
                                validation_log.log_silent(log_item);

                                return Err(Error::CoseCertRevoked);
                            }
                        } else {
                            let log_item = log_item!(
                                "OCSP_RESPONSE",
                                "certificate revoked",
                                "check_ocsp_response"
                            )
                            .error(Error::CoseCertRevoked)
                            .validation_status(validation_status::SIGNING_CREDENTIAL_REVOKED);
                            validation_log.log_silent(log_item);

                            return Err(Error::CoseCertRevoked);
                        }
                    }
                }
            };
        }
    }

    // Per the spec if we cannot interpret the OCSP data treat it as if it did not exist
    Ok(())
}
