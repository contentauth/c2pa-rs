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

use std::collections::HashMap;

use async_generic::async_generic;
use chrono::{DateTime, Utc};
use ciborium::value::Value;
use coset::{CoseSign1, Label};

use crate::{
    cose_validator::get_serial_num,
    crypto::{
        cose::{
            check_certificate_profile, validate_cose_tst_info, validate_cose_tst_info_async,
            CertificateTrustError, CertificateTrustPolicy, CoseError,
        },
        ocsp::OcspResponse,
    },
    status_tracker::StatusTracker,
    validation_status,
};

/// Given a COSE signature, extract the OCSP data and validate the status of
/// that report.
#[async_generic]
pub fn check_ocsp_status(
    sign1: &CoseSign1,
    data: &[u8],
    fetch_policy: OcspFetchPolicy,
    ctp: &CertificateTrustPolicy,
    certificate_statuses: &HashMap<String, Vec<Vec<u8>>>,
    validation_log: &mut StatusTracker,
) -> Result<OcspResponse, CoseError> {
    match get_ocsp_der(sign1) {
        Some(ocsp_response_der) => {
            if _sync {
                check_stapled_ocsp_response(sign1, &ocsp_response_der, data, ctp, validation_log)
            } else {
                check_stapled_ocsp_response_async(
                    sign1,
                    &ocsp_response_der,
                    data,
                    ctp,
                    validation_log,
                )
                .await
            }
        }

        None => match fetch_policy {
            OcspFetchPolicy::FetchAllowed => {
                fetch_and_check_ocsp_response(sign1, data, ctp, validation_log)
            }
            OcspFetchPolicy::DoNotFetch => {
                let certificate_serial_num = get_serial_num(sign1)?.to_string();
                if let Some(ocsp_response_ders) = certificate_statuses.get(&certificate_serial_num)
                {
                    for ocsp_response_der in ocsp_response_ders {
                        if let Ok(ocsp_response) = check_stapled_ocsp_response(
                            sign1,
                            ocsp_response_der,
                            data,
                            ctp,
                            validation_log,
                        ) {
                            if validation_log
                                .has_status(validation_status::SIGNING_CREDENTIAL_REVOKED)
                            {
                                return Err(CoseError::CertificateTrustError(
                                    CertificateTrustError::CertificateNotTrusted,
                                ));
                            }
                            if validation_log
                                .has_status(validation_status::SIGNING_CREDENTIAL_NOT_REVOKED)
                            {
                                return Ok(ocsp_response);
                            }
                        }
                    }
                }
                Ok(OcspResponse::default())
            }
        },
    }
}

/// Policy for fetching OCSP responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OcspFetchPolicy {
    /// Allow internet connection to fetch OCSP response.
    FetchAllowed,

    /// Do not connect and ignore OCSP status if not available.
    DoNotFetch,
}

#[async_generic]
fn check_stapled_ocsp_response(
    sign1: &CoseSign1,
    ocsp_response_der: &[u8],
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
) -> Result<OcspResponse, CoseError> {
    let time_stamp_info = if _sync {
        validate_cose_tst_info(sign1, data)
    } else {
        validate_cose_tst_info_async(sign1, data).await
    };

    // If the stapled OCSP response has a time stamp, we can validate it.
    let Ok(tst_info) = &time_stamp_info else {
        return Ok(OcspResponse::default());
    };

    let signing_time: DateTime<Utc> = tst_info.gen_time.clone().into();

    let Ok(ocsp_data) =
        OcspResponse::from_der_checked(ocsp_response_der, Some(signing_time), validation_log)
    else {
        return Ok(OcspResponse::default());
    };

    // If we get a valid response, validate the certs.
    if ocsp_data.revoked_at.is_none() {
        if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
            check_certificate_profile(&ocsp_certs[0], ctp, validation_log, Some(tst_info))?;
        }
    }

    Ok(ocsp_data)
}

// TO DO: Add async version of this?
/// TO DO: Add documentation
pub(crate) fn fetch_and_check_ocsp_response(
    sign1: &CoseSign1,
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
) -> Result<OcspResponse, CoseError> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (sign1, data, ctp, validation_log);
        Ok(OcspResponse::default())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        use asn1_rs::FromDer;
        use x509_parser::prelude::X509Certificate;

        use crate::crypto::cose::cert_chain_from_sign1;

        let certs = cert_chain_from_sign1(sign1)?;

        let Some(ocsp_der) = crate::crypto::ocsp::fetch_ocsp_response(&certs) else {
            return Ok(OcspResponse::default());
        };

        let ocsp_response_der = ocsp_der;

        let signing_time: Option<DateTime<Utc>> = validate_cose_tst_info(sign1, data)
            .ok()
            .map(|tst_info| tst_info.gen_time.clone().into());

        // Check the OCSP response, but only if it is well-formed.
        // Revocation errors are reported in the validation log.
        let Ok(mut ocsp_data) =
            OcspResponse::from_der_checked(&ocsp_response_der, signing_time, validation_log)
        else {
            // TO REVIEW: This is how the old code worked, but is it correct to ignore a
            // malformed OCSP response?
            return Ok(OcspResponse::default());
        };

        // Extract certificate serial number from the certificate chain
        let (_rem, cert) = X509Certificate::from_der(&certs[0])
            .map_err(|e| CoseError::InternalError(e.to_string()))?;
        ocsp_data.certificate_serial_num = cert.serial.to_string();

        // If we get a valid response validate the certs.
        if ocsp_data.revoked_at.is_none() {
            if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
                check_certificate_profile(&ocsp_certs[0], ctp, validation_log, None)?;
            }
        }

        Ok(ocsp_data)
    }
}

pub(crate) fn get_ocsp_der(sign1: &coset::CoseSign1) -> Option<Vec<u8>> {
    let der = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("rVals".to_string()) {
                Some(x.1.clone())
            } else {
                None
            }
        })?;

    let Value::Map(rvals_map) = der else {
        return None;
    };

    // Find OCSP value if available.
    rvals_map.iter().find_map(|x: &(Value, Value)| {
        if x.0 == Value::Text("ocspVals".to_string()) {
            x.1.as_array()
                .and_then(|ocsp_rsp_val| ocsp_rsp_val.first())
                .and_then(Value::as_bytes)
                .cloned()
        } else {
            None
        }
    })
}
