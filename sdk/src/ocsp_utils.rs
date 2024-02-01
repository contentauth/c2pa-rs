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

use chrono::{DateTime, NaiveDateTime, Utc};
use conv::ConvUtil;
use rasn_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus};
use rasn_pkix::{Certificate, CrlReason};

use crate::{
    status_tracker::{log_item, DetailedStatusTracker, StatusTracker},
    validation_status, Error, Result,
};

/// OcspData - struct to contain the OCSPResponse DER and the time
/// for the next OCSP check
pub(crate) struct OcspData {
    pub ocsp_der: Vec<u8>,
    pub next_update: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub ocsp_certs: Option<Vec<Vec<u8>>>,
}

impl OcspData {
    pub fn new() -> Self {
        OcspData {
            ocsp_der: Vec::new(),
            next_update: Utc::now(),
            revoked_at: None,
            ocsp_certs: None,
        }
    }
}

impl Default for OcspData {
    fn default() -> Self {
        Self {
            ocsp_der: Vec::new(),
            next_update: Utc::now(),
            revoked_at: None,
            ocsp_certs: None,
        }
    }
}

#[cfg(feature = "fetch_ocsp_response")]
fn extract_aia_responders(cert: &x509_parser::certificate::X509Certificate) -> Option<Vec<String>> {
    use x509_parser::der_parser::{oid, Oid};

    const AD_OCSP_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .1);
    const AUTHORITY_INFO_ACCESS_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .1);

    let em = cert.extensions_map().ok()?;

    let aia_extension = em.get(&AUTHORITY_INFO_ACCESS_OID)?;

    match aia_extension.parsed_extension() {
        x509_parser::extensions::ParsedExtension::AuthorityInfoAccess(aia) => {
            let mut output = Vec::new();

            for ad in &aia.accessdescs {
                if let x509_parser::extensions::GeneralName::URI(uri) = ad.access_location {
                    if ad.access_method == AD_OCSP_OID {
                        output.push(uri.to_string())
                    }
                }
            }
            Some(output)
        }
        _ => None,
    }
}

/// Check the supplied cert chain for an OCSP responder in the end-entity cert.  If found it will attempt to
/// retrieve the OCSPResponse.  If successful returns OcspData containing the DER encoded OCSPResponse and
/// the DateTime for when this cached response should be refreshed, and the OCSP signer certificate chain.  
/// None otherwise.
#[cfg(feature = "fetch_ocsp_response")]
pub(crate) fn fetch_ocsp_response(certs: &[Vec<u8>]) -> Option<Vec<u8>> {
    use std::io::Read;

    use rasn::prelude::*;
    use x509_parser::prelude::*;

    // must have minimal chain in hierarchical order
    if certs.len() < 2 {
        return None;
    }

    let (_rem, cert) = X509Certificate::from_der(&certs[0]).ok()?;

    if let Some(responders) = extract_aia_responders(&cert) {
        let sha1_oid = rasn::types::Oid::new(&[1, 3, 14, 3, 2, 26])?; // Sha1 Oid
        let alg = rasn::types::ObjectIdentifier::from(sha1_oid);

        let sha1_ai = rasn_pkix::AlgorithmIdentifier {
            algorithm: alg,
            parameters: Some(Any::new(rasn::der::encode(&()).ok()?)), /* many OCSP responders expect this to be NULL not None */
        };

        for r in responders {
            let url = url::Url::parse(&r).ok()?;
            let subject = rasn::der::decode::<rasn_pkix::Certificate>(&certs[0]).ok()?;
            let issuer = rasn::der::decode::<rasn_pkix::Certificate>(&certs[1]).ok()?;

            let issuer_name_raw =
                rasn::der::encode::<rasn_pkix::Name>(&issuer.tbs_certificate.subject).ok()?;
            let issuer_key_raw = &issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_raw_slice();

            let issuer_name_hash =
                OctetString::from(crate::hash_utils::hash_sha1(&issuer_name_raw));
            let issuer_key_hash = OctetString::from(crate::hash_utils::hash_sha1(issuer_key_raw));
            let serial_num = subject.tbs_certificate.serial_number;

            // build request structures

            let req_cert = rasn_ocsp::CertId {
                hash_algorithm: sha1_ai.clone(),
                issuer_name_hash,
                issuer_key_hash,
                serial_number: serial_num,
            };

            let ocsp_req = rasn_ocsp::Request {
                req_cert,
                single_request_extensions: None,
            };

            let request_list = vec![ocsp_req];

            let tbs_request = rasn_ocsp::TbsRequest {
                version: rasn_ocsp::Version::parse_bytes(b"0", 16)?,
                requestor_name: None,
                request_list,
                request_extensions: None,
            };

            let ocsp_request = rasn_ocsp::OcspRequest {
                tbs_request,
                optional_signature: None,
            };

            // build query param
            let request_der = rasn::der::encode::<rasn_ocsp::OcspRequest>(&ocsp_request).ok()?;
            let request_str = crate::utils::base64::encode(&request_der);

            let req_url = url.join(&request_str).ok()?;

            // fetch OCSP response
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

                return Some(ocsp_rsp);
            }
        }
    }
    None
}
// check to OCSP response with optional signing time (if available)
// Returns - returns OcspData unless their is a structural error in the response.
pub(crate) fn check_ocsp_response(
    ocsp_response_der: &[u8],
    signing_time: Option<DateTime<Utc>>,
    validation_log_out: &mut impl StatusTracker,
) -> Result<OcspData> {
    const DATE_FMT: &str = "%Y-%m-%d %H:%M:%S %Z";

    let mut validation_log = DetailedStatusTracker::default();

    let mut output = OcspData::new();
    output.ocsp_der = ocsp_response_der.to_vec();
    let mut found_good = false;

    if let Ok(ocsp_response) = rasn::der::decode::<OcspResponse>(ocsp_response_der) {
        if ocsp_response.status == OcspResponseStatus::Successful {
            if let Some(response_bytes) = ocsp_response.bytes {
                if let Ok(basic_response) =
                    rasn::der::decode::<BasicOcspResponse>(&response_bytes.response)
                {
                    let response_data = &basic_response.tbs_response_data;

                    // get OCSP cert chain if available
                    if let Some(ocsp_certs) = &basic_response.certs {
                        let mut cert_der_vec = Vec::new();

                        for ocsp_cert in ocsp_certs {
                            let cert_der = rasn::der::encode::<Certificate>(ocsp_cert)
                                .map_err(|_e| Error::CoseInvalidCert)?;
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
                                .map_err(|_e| Error::CoseInvalidCert)?
                                .timestamp();

                                let next_update = if let Some(nu) = &single_response.next_update {
                                    NaiveDateTime::parse_from_str(&nu.to_string(), DATE_FMT)
                                        .map_err(|_e| Error::CoseInvalidCert)?
                                        .timestamp()
                                } else {
                                    this_update
                                };

                                // check to see if we are within range or current time within range
                                let in_range = if let Some(st) = signing_time {
                                    st.timestamp() < this_update
                                        || (st.timestamp() >= this_update
                                            && st.timestamp() <= next_update)
                                } else {
                                    // no timestamp so check against current time
                                    // use instant to avoid wasm issues
                                    let now_f64 = instant::now() / 1000.0;
                                    let now: i64 = now_f64.approx_as::<i64>().map_err(|_e| {
                                        Error::BadParam("system time invalid".to_string())
                                    })?;

                                    now >= this_update && now <= next_update
                                };

                                output.next_update = DateTime::from_timestamp(next_update, 0)
                                    .ok_or(Error::CoseInvalidCert)?;

                                if !in_range {
                                    let log_item = log_item!(
                                        "OCSP_RESPONSE",
                                        "certificate revoked",
                                        "check_ocsp_response"
                                    )
                                    .error(Error::CoseCertRevoked)
                                    .validation_status(
                                        validation_status::SIGNING_CREDENTIAL_REVOKED,
                                    );
                                    validation_log.log_silent(log_item);
                                } else {
                                    found_good = true;
                                    break; // found good match so break
                                }
                            }
                            CertStatus::Revoked(revoked_info) => {
                                if let Some(reason) = revoked_info.revocation_reason {
                                    if reason == CrlReason::RemoveFromCRL {
                                        // if it was revoked check if was revoked after signing time
                                        let revocation_time = &revoked_info.revocation_time;
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
                                            let now: i64 =
                                                now_f64.approx_as::<i64>().map_err(|_e| {
                                                    Error::BadParam(
                                                        "system time invalid".to_string(),
                                                    )
                                                })?;

                                            revoked_at > now
                                        };

                                        if !in_range {
                                            let revoked_at_native = NaiveDateTime::parse_from_str(
                                                &revocation_time.to_string(),
                                                DATE_FMT,
                                            )
                                            .map_err(|_e| Error::CoseInvalidCert)?;

                                            let utc_with_offset: DateTime<Utc> =
                                                DateTime::from_naive_utc_and_offset(
                                                    revoked_at_native,
                                                    Utc,
                                                );

                                            let msg = format!(
                                                "certificate revoked at: {}",
                                                utc_with_offset
                                            );
                                            let log_item = log_item!(
                                                "OCSP_RESPONSE",
                                                &msg,
                                                "check_ocsp_response"
                                            )
                                            .error(Error::CoseCertRevoked)
                                            .validation_status(
                                                validation_status::SIGNING_CREDENTIAL_REVOKED,
                                            );
                                            validation_log.log_silent(log_item);

                                            output.revoked_at =
                                                Some(DateTime::from_naive_utc_and_offset(
                                                    revoked_at_native,
                                                    Utc,
                                                ));
                                        }
                                    } else {
                                        let revoked_at_native = NaiveDateTime::parse_from_str(
                                            &revoked_info.revocation_time.to_string(),
                                            DATE_FMT,
                                        )
                                        .map_err(|_e| Error::CoseInvalidCert)?;

                                        let utc_with_offset: DateTime<Utc> =
                                            DateTime::from_naive_utc_and_offset(
                                                revoked_at_native,
                                                Utc,
                                            );

                                        let msg =
                                            format!("certificate revoked at: {}", utc_with_offset);
                                        let log_item =
                                            log_item!("OCSP_RESPONSE", &msg, "check_ocsp_response")
                                                .error(Error::CoseCertRevoked)
                                                .validation_status(
                                                    validation_status::SIGNING_CREDENTIAL_REVOKED,
                                                );
                                        validation_log.log_silent(log_item);

                                        output.revoked_at =
                                            Some(DateTime::from_naive_utc_and_offset(
                                                revoked_at_native,
                                                Utc,
                                            ));
                                    }
                                } else {
                                    let log_item = log_item!(
                                        "OCSP_RESPONSE",
                                        "certificate revoked",
                                        "check_ocsp_response"
                                    )
                                    .error(Error::CoseCertRevoked)
                                    .validation_status(
                                        validation_status::SIGNING_CREDENTIAL_REVOKED,
                                    );
                                    validation_log.log_silent(log_item);
                                }
                            }
                            CertStatus::Unknown(_) => return Err(Error::UnsupportedType), /* noop for this case */
                        }
                    }
                }
            }
        }
    }
    // Per the spec if we cannot interpret the OCSP data treat it as if it did not exist
    if !found_good {
        validation_log_out
            .get_log_mut()
            .append(validation_log.get_log_mut());
    }

    Ok(output)
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use chrono::TimeZone;

    use super::*;
    use crate::status_tracker::report_split_errors;
    #[test]
    fn test_good_response() {
        let rsp_data = include_bytes!("../tests/fixtures/ocsp_good.data");

        let mut validation_log = DetailedStatusTracker::default();

        let test_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();

        let ocsp_data =
            check_ocsp_response(rsp_data, Some(test_time), &mut validation_log).unwrap();

        assert!(ocsp_data.revoked_at.is_none());
        assert!(ocsp_data.ocsp_certs.is_some());
    }

    #[test]
    fn test_revoked_response() {
        let rsp_data = include_bytes!("../tests/fixtures/ocsp_revoked.data");

        let mut validation_log = DetailedStatusTracker::default();

        let test_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();

        let ocsp_data =
            check_ocsp_response(rsp_data, Some(test_time), &mut validation_log).unwrap();

        let errors = report_split_errors(validation_log.get_log_mut());

        assert!(ocsp_data.revoked_at.is_some());
        assert!(!errors.is_empty());
    }
}
