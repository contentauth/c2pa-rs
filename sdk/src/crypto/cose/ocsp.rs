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
use chrono::{DateTime, Utc};
use coset::{cbor::value::Value, CoseSign1, Label};

use crate::{
    context::Context,
    crypto::{
        asn1::rfc3161::TstInfo,
        cose::{
            cert_chain_from_sign1, check_end_entity_certificate_profile, validate_cose_tst_info,
            validate_cose_tst_info_async, CertificateTrustError, CertificateTrustPolicy, CoseError,
        },
        ocsp::OcspResponse,
    },
    log_item,
    settings::Settings,
    status_tracker::StatusTracker,
    validation_status::{self, SIGNING_CREDENTIAL_NOT_REVOKED, SIGNING_CREDENTIAL_REVOKED},
};

/// Given a COSE signature, extract the OCSP data and validate the status of
/// that report.
#[async_generic(async_signature(
    sign1: &CoseSign1,
    data: &[u8],
    fetch_policy: OcspFetchPolicy,
    ctp: &CertificateTrustPolicy,
    ocsp_responses: Option<&Vec<Vec<u8>>>,
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
    context: &Context,
))]
#[allow(clippy::too_many_arguments)]
pub fn check_ocsp_status(
    sign1: &CoseSign1,
    data: &[u8],
    fetch_policy: OcspFetchPolicy,
    ctp: &CertificateTrustPolicy,
    ocsp_responses: Option<&Vec<Vec<u8>>>,
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
    context: &Context,
) -> Result<OcspResponse, CoseError> {
    if context
        .settings()
        .builder
        .certificate_status_should_override
        .unwrap_or(false)
    {
        if let Some(ocsp_response_ders) = ocsp_responses {
            if !ocsp_response_ders.is_empty() {
                return if _sync {
                    process_ocsp_responses(
                        sign1,
                        data,
                        ctp,
                        ocsp_response_ders,
                        tst_info,
                        validation_log,
                        context.settings(),
                    )
                } else {
                    process_ocsp_responses_async(
                        sign1,
                        data,
                        ctp,
                        ocsp_response_ders,
                        tst_info,
                        validation_log,
                        context.settings(),
                    )
                    .await
                };
            }
        }
    }

    match get_ocsp_der(sign1) {
        Some(ocsp_response_der) => {
            if _sync {
                check_stapled_ocsp_response(
                    sign1,
                    &ocsp_response_der,
                    data,
                    ctp,
                    tst_info,
                    validation_log,
                    context.settings(),
                )
            } else {
                check_stapled_ocsp_response_async(
                    sign1,
                    &ocsp_response_der,
                    data,
                    ctp,
                    tst_info,
                    validation_log,
                    context.settings(),
                )
                .await
            }
        }

        None => match fetch_policy {
            OcspFetchPolicy::FetchAllowed => {
                if _sync {
                    fetch_and_check_ocsp_response(
                        sign1,
                        data,
                        ctp,
                        tst_info,
                        validation_log,
                        context,
                    )
                } else {
                    fetch_and_check_ocsp_response_async(
                        sign1,
                        data,
                        ctp,
                        tst_info,
                        validation_log,
                        context,
                    )
                    .await
                }
            }
            OcspFetchPolicy::DoNotFetch => {
                if let Some(ocsp_response_ders) = ocsp_responses {
                    if !ocsp_response_ders.is_empty() {
                        if _sync {
                            process_ocsp_responses(
                                sign1,
                                data,
                                ctp,
                                ocsp_response_ders,
                                tst_info,
                                validation_log,
                                context.settings(),
                            )
                        } else {
                            process_ocsp_responses_async(
                                sign1,
                                data,
                                ctp,
                                ocsp_response_ders,
                                tst_info,
                                validation_log,
                                context.settings(),
                            )
                            .await
                        }
                    } else {
                        Ok(OcspResponse::default())
                    }
                } else {
                    Ok(OcspResponse::default())
                }
            }
        },
    }
}

/// Processes a list of OCSP responses and validates them.
/// Returns the first valid non-revoked response or an error if revoked.
#[async_generic]
fn process_ocsp_responses(
    sign1: &CoseSign1,
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    ocsp_response_ders: &[Vec<u8>],
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
    settings: &Settings,
) -> Result<OcspResponse, CoseError> {
    for ocsp_response_der in ocsp_response_ders {
        let mut current_validation_log = StatusTracker::default();
        if let Ok(ocsp_response) = if _sync {
            check_stapled_ocsp_response(
                sign1,
                ocsp_response_der,
                data,
                ctp,
                tst_info,
                &mut current_validation_log,
                settings,
            )
        } else {
            check_stapled_ocsp_response_async(
                sign1,
                ocsp_response_der,
                data,
                ctp,
                tst_info,
                &mut current_validation_log,
                settings,
            )
            .await
        } {
            // If certificate is revoked, return error immediately
            if current_validation_log.has_status(validation_status::SIGNING_CREDENTIAL_REVOKED) {
                log_item!(
                    "",
                    format!(
                        "signing cert revoked: {}",
                        ocsp_response.certificate_serial_num
                    ),
                    "check_ocsp_status"
                )
                .validation_status(SIGNING_CREDENTIAL_REVOKED)
                .informational(validation_log);

                return Err(CoseError::CertificateTrustError(
                    CertificateTrustError::CertificateNotTrusted,
                ));
            }
            // If certificate is confirmed not revoked, return success
            if current_validation_log.has_status(validation_status::SIGNING_CREDENTIAL_NOT_REVOKED)
            {
                log_item!(
                    "",
                    format!(
                        "signing cert not revoked: {}",
                        ocsp_response.certificate_serial_num
                    ),
                    "check_ocsp_status"
                )
                .validation_status(SIGNING_CREDENTIAL_NOT_REVOKED)
                .informational(validation_log);

                return Ok(ocsp_response);
            }
        }
    }
    Ok(OcspResponse::default())
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
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
    settings: &Settings,
) -> Result<OcspResponse, CoseError> {
    // this timestamp is checked as part of Cose Signature so don't need to log its results here
    let mut local_log_sync = StatusTracker::default();

    // get TstInfo or use supplied value
    let time_stamp_info = match tst_info {
        Some(tst_info) => Ok(tst_info.clone()),
        None => {
            if _sync {
                validate_cose_tst_info(
                    sign1,
                    data,
                    ctp,
                    &mut local_log_sync,
                    settings.verify.verify_timestamp_trust,
                )
            } else {
                validate_cose_tst_info_async(
                    sign1,
                    data,
                    ctp,
                    &mut local_log_sync,
                    settings.verify.verify_timestamp_trust,
                )
                .await
            }
        }
    };

    // If there is a timestamp use it for OCSP cert validation,
    // otherwise follow default rules for OCSP checking
    let (tst_info, signing_time) = match time_stamp_info {
        Ok(tstinfo) => {
            let signing_time = tstinfo.gen_time.clone().into();
            (Some(tstinfo), Some(signing_time))
        }
        Err(_) => (None, None),
    };

    let mut current_validation_log = StatusTracker::default();
    let Ok(ocsp_data) = OcspResponse::from_der_checked(
        ocsp_response_der,
        signing_time,
        &mut current_validation_log,
    ) else {
        return Ok(OcspResponse::default());
    };

    // If we get a valid response, validate the certs.
    if ocsp_data.revoked_at.is_none() {
        if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
            // if the OCSP signing cert cannot be validated do not use this response
            if check_end_entity_certificate_profile(
                &ocsp_certs[0],
                ctp,
                &mut current_validation_log,
                tst_info.as_ref(),
            )
            .is_err()
            {
                return Ok(OcspResponse::default());
            }
        }
    }
    // only append usable OCSP responses to validation_log
    validation_log.append(&current_validation_log);
    Ok(ocsp_data)
}

/// Fetches and validates an OCSP response for the given COSE signature.
#[async_generic(async_signature(
    sign1: &CoseSign1,
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
    context: &crate::context::Context,
))]
pub(crate) fn fetch_and_check_ocsp_response(
    sign1: &CoseSign1,
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
    context: &crate::context::Context,
) -> Result<OcspResponse, CoseError> {
    let certs = cert_chain_from_sign1(sign1)?;

    let ocsp_der = if _sync {
        crate::crypto::ocsp::fetch_ocsp_response(&certs, context)
    } else {
        crate::crypto::ocsp::fetch_ocsp_response_async(&certs, context).await
    };

    let Some(ocsp_response_der) = ocsp_der else {
        return Ok(OcspResponse::default());
    };

    // use supplied override time if provided
    let signing_time: Option<DateTime<Utc>> = match tst_info {
        Some(tst_info) => Some(tst_info.gen_time.clone().into()),
        None => validate_cose_tst_info(
            sign1,
            data,
            ctp,
            validation_log,
            context.settings().verify.verify_timestamp_trust,
        )
        .ok()
        .map(|tst_info| tst_info.gen_time.clone().into()),
    };

    // Check the OCSP response, but only if it is well-formed.
    // Revocation errors are reported in the validation log.
    let ocsp_data =
        match OcspResponse::from_der_checked(&ocsp_response_der, signing_time, validation_log) {
            Ok(data) => data,
            Err(_) => return Ok(OcspResponse::default()),
        };

    // If we get a valid response validate the certs.
    if ocsp_data.revoked_at.is_none() {
        if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
            check_end_entity_certificate_profile(&ocsp_certs[0], ctp, validation_log, None)?;
        }
    }

    Ok(ocsp_data)
}

/// Returns the DER-encoded OCSP response from the "rVals" unprotected header in a COSE_Sign1 message.
pub fn get_ocsp_der(sign1: &coset::CoseSign1) -> Option<Vec<u8>> {
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
