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

use async_generic::async_generic;
use c2pa_status_tracker::StatusTracker;
use chrono::{DateTime, Utc};
use ciborium::value::Value;
use coset::{
    iana::{self, EnumI64},
    CoseSign1, Label,
};

use crate::{
    cose::{
        check_certificate_profile, validate_cose_tst_info, validate_cose_tst_info_async,
        CertificateTrustPolicy, CoseError,
    },
    ocsp::{fetch_ocsp_response, OcspResponse},
};

/// Given a COSE signature, extract the OCSP data and validate the status of
/// that report.
///
/// TO DO: Determine if this needs to remain fully public after refactoring.
#[async_generic]
pub fn check_ocsp_status(
    sign1: &CoseSign1,
    data: &[u8],
    fetch_policy: OcspFetchPolicy,
    ctp: &CertificateTrustPolicy,
    validation_log: &mut impl StatusTracker,
) -> Result<OcspResponse, CoseError> {
    let mut result = Ok(OcspResponse::default());

    if let Some(ocsp_response_der) = get_ocsp_der(&sign1) {
        let time_stamp_info = if _sync {
            validate_cose_tst_info(&sign1, data)
        } else {
            validate_cose_tst_info_async(&sign1, data).await
        };

        // check stapled OCSP response, must have timestamp
        if let Ok(tst_info) = &time_stamp_info {
            let signing_time: DateTime<Utc> = tst_info.gen_time.clone().into();

            // Check the OCSP response, only use if not malformed.  Revocation errors are
            // reported in the validation log
            if let Ok(ocsp_data) = OcspResponse::from_der_checked(
                &ocsp_response_der,
                Some(signing_time),
                validation_log,
            ) {
                // if we get a valid response validate the certs
                if ocsp_data.revoked_at.is_none() {
                    if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
                        check_certificate_profile(
                            &ocsp_certs[0],
                            ctp,
                            validation_log,
                            Some(tst_info),
                        )?;
                    }
                }
                result = Ok(ocsp_data);
            }
        }
    } else {
        #[cfg(not(target_arch = "wasm32"))]
        {
            match fetch_policy {
                OcspFetchPolicy::FetchAllowed => {
                    // get the cert chain
                    let certs = get_sign_certs(&sign1)?;

                    if let Some(ocsp_der) = fetch_ocsp_response(&certs) {
                        // fetch_ocsp_response(&certs) {
                        let ocsp_response_der = ocsp_der;

                        let time_stamp_info = validate_cose_tst_info(&sign1, data);

                        let signing_time = match &time_stamp_info {
                            Ok(tst_info) => {
                                let signing_time: DateTime<Utc> = tst_info.gen_time.clone().into();
                                Some(signing_time)
                            }
                            Err(_) => None,
                        };

                        // Check the OCSP response, only use if not malformed.  Revocation errors
                        // are reported in the validation log
                        if let Ok(ocsp_data) = OcspResponse::from_der_checked(
                            &ocsp_response_der,
                            signing_time,
                            validation_log,
                        ) {
                            // if we get a valid response validate the certs
                            if ocsp_data.revoked_at.is_none() {
                                if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
                                    check_certificate_profile(
                                        &ocsp_certs[0],
                                        ctp,
                                        validation_log,
                                        None,
                                    )?;
                                }
                            }
                            result = Ok(ocsp_data);
                        }
                    }
                }

                OcspFetchPolicy::DoNotFetch => (),
            }
        }
    }

    result
}

/// Policy for fetching OCSP responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OcspFetchPolicy {
    /// Allow internet connection to fetch OCSP response.
    FetchAllowed,

    /// Do not connect and ignore OCSP status if not available.
    DoNotFetch,
}

// get OCSP der
fn get_ocsp_der(sign1: &coset::CoseSign1) -> Option<Vec<u8>> {
    if let Some(der) = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("rVals".to_string()) {
                Some(x.1.clone())
            } else {
                None
            }
        })
    {
        match der {
            Value::Map(rvals_map) => {
                // find OCSP value if available
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
            _ => None,
        }
    } else {
        None
    }
}

// TO DO: See if this gets more widely used in crate.
// get the public key der
fn get_sign_certs(sign1: &coset::CoseSign1) -> Result<Vec<Vec<u8>>, CoseError> {
    // check for protected header int, then protected header x5chain,
    // then the legacy unprotected x5chain to get the public key der

    // check the protected header
    if let Some(der) = sign1
        .protected
        .header
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("x5chain".to_string())
                || x.0 == Label::Int(iana::HeaderParameter::X5Chain.to_i64())
            {
                Some(x.1.clone())
            } else {
                None
            }
        })
    {
        // make sure there are no certs in the legacy unprotected header, certs
        // are only allowing in protect OR unprotected header
        if get_unprotected_header_certs(sign1).is_ok() {
            return Err(CoseError::MultipleSigningCertificateChains);
        }

        let mut certs: Vec<Vec<u8>> = Vec::new();

        match der {
            Value::Array(cert_chain) => {
                // handle array of certs
                for c in cert_chain {
                    if let Value::Bytes(der_bytes) = c {
                        certs.push(der_bytes.clone());
                    }
                }

                if certs.is_empty() {
                    return Err(CoseError::MissingSigningCertificateChain);
                } else {
                    return Ok(certs);
                }
            }
            Value::Bytes(ref der_bytes) => {
                // handle single cert case
                certs.push(der_bytes.clone());
                return Ok(certs);
            }
            _ => return Err(CoseError::MissingSigningCertificateChain),
        }
    }

    // check the unprotected header if necessary
    get_unprotected_header_certs(sign1)
}

fn get_unprotected_header_certs(sign1: &coset::CoseSign1) -> Result<Vec<Vec<u8>>, CoseError> {
    if let Some(der) = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("x5chain".to_string()) {
                Some(x.1.clone())
            } else {
                None
            }
        })
    {
        let mut certs: Vec<Vec<u8>> = Vec::new();

        match der {
            Value::Array(cert_chain) => {
                // handle array of certs
                for c in cert_chain {
                    if let Value::Bytes(der_bytes) = c {
                        certs.push(der_bytes.clone());
                    }
                }

                if certs.is_empty() {
                    Err(CoseError::MissingSigningCertificateChain)
                } else {
                    Ok(certs)
                }
            }
            Value::Bytes(ref der_bytes) => {
                // handle single cert case
                certs.push(der_bytes.clone());
                Ok(certs)
            }
            _ => Err(CoseError::MissingSigningCertificateChain),
        }
    } else {
        Err(CoseError::MissingSigningCertificateChain)
    }
}
