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

use asn1_rs::FromDer;
use async_generic::async_generic;
use chrono::{DateTime, Utc};
use coset::{cbor::value::Value, CoseSign1, Label};
use x509_parser::prelude::X509Certificate;

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
    validation_status::{
        self, SIGNING_CREDENTIAL_NOT_REVOKED, SIGNING_CREDENTIAL_OCSP_INACCESSIBLE,
        SIGNING_CREDENTIAL_OCSP_SKIPPED, SIGNING_CREDENTIAL_REVOKED, SIGNING_CREDENTIAL_UNTRUSTED,
    },
};

const OCSP_OID_STR: &str = "1.3.6.1.5.5.7.3.9";

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
            let mut ocsp_log = StatusTracker::default();
            let result = if _sync {
                check_stapled_ocsp_response(
                    sign1,
                    &ocsp_response_der,
                    data,
                    ctp,
                    tst_info,
                    &mut ocsp_log,
                    context.settings(),
                )
            } else {
                check_stapled_ocsp_response_async(
                    sign1,
                    &ocsp_response_der,
                    data,
                    ctp,
                    tst_info,
                    &mut ocsp_log,
                    context.settings(),
                )
                .await
            };

            // we only care about OCSP value log info if the result is OK
            if let Ok(ocsp_response) = result {
                if ocsp_log.has_status(validation_status::SIGNING_CREDENTIAL_REVOKED) {
                    return Err(log_item!(
                        "",
                        format!(
                            "signing cert revoked: {}",
                            ocsp_response.certificate_serial_num
                        ),
                        "check_ocsp_status"
                    )
                    .validation_status(SIGNING_CREDENTIAL_REVOKED)
                    .failure_as_err(
                        validation_log,
                        CoseError::CertificateTrustError(
                            CertificateTrustError::CertificateNotTrusted,
                        ),
                    ));
                }

                // If certificate is confirmed not revoked, return success
                if ocsp_log.has_status(validation_status::SIGNING_CREDENTIAL_NOT_REVOKED) {
                    log_item!(
                        "",
                        format!(
                            "signing cert not revoked: {}",
                            ocsp_response.certificate_serial_num
                        ),
                        "check_ocsp_status"
                    )
                    .validation_status(SIGNING_CREDENTIAL_NOT_REVOKED)
                    .success(validation_log);

                    return Ok(ocsp_response);
                }
            }
            // errors mean we don't interpret the value
            Ok(OcspResponse::default())
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
                        log_item!("", "OCSP fetching skipped", "check_ocsp_status")
                            .validation_status(SIGNING_CREDENTIAL_OCSP_SKIPPED)
                            .informational(validation_log);

                        Ok(OcspResponse::default())
                    }
                } else {
                    log_item!("", "OCSP fetching skipped", "check_ocsp_status")
                        .validation_status(SIGNING_CREDENTIAL_OCSP_SKIPPED)
                        .informational(validation_log);

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
                return Err(log_item!(
                    "",
                    format!(
                        "signing cert revoked: {}",
                        ocsp_response.certificate_serial_num
                    ),
                    "check_ocsp_status"
                )
                .validation_status(SIGNING_CREDENTIAL_REVOKED)
                .failure_as_err(
                    validation_log,
                    CoseError::CertificateTrustError(CertificateTrustError::CertificateNotTrusted),
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
                .success(validation_log);

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

    // The OCSP response must pertain to the certificate that signed this
    // manifest, so bind it to that signer's certificate chain.
    let signing_cert_chain = cert_chain_from_sign1(sign1)?;

    let mut current_validation_log = StatusTracker::default();
    let Ok(ocsp_data) = OcspResponse::from_der_checked(
        ocsp_response_der,
        &signing_cert_chain,
        signing_time,
        &mut current_validation_log,
    ) else {
        return Ok(OcspResponse::default());
    };

    // If we get a valid response, validate the certs.
    if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
        let Some(first_cert) = ocsp_certs.first() else {
            return Ok(OcspResponse::default());
        };

        // make sure this is an OCSP signing EKU
        let mut new_ctp = CertificateTrustPolicy::default();
        new_ctp.clear_ekus();
        new_ctp.add_mandatory_ekus(OCSP_OID_STR.as_bytes()); // ocsp signing EKU
        if check_end_entity_certificate_profile(
            first_cert,
            &new_ctp,
            validation_log,
            tst_info.as_ref(),
        )
        .is_err()
        {
            return Ok(OcspResponse::default());
        }

        // validate the trust; complete the responder's path from the signer's
        // x5chain if the response does not embed the responder's issuing CA
        let ocsp_cert_chain = extend_ocsp_cert_chain(ocsp_certs, &signing_cert_chain);
        if ctp
            .check_certificate_trust(
                &ocsp_cert_chain,
                first_cert,
                signing_time.map(|t| t.timestamp()),
            )
            .is_err()
        {
            return Ok(OcspResponse::default());
        }
    } else {
        // we cannot validate the OCSP response was signed by a valid authorized responder so treat as unknown
        return Ok(OcspResponse::default());
    }
    // only append usable OCSP responses to validation_log
    validation_log.append(&current_validation_log);
    Ok(ocsp_data)
}

/// Extends the certificates embedded in an OCSP response with the signer's
/// issuing CA certificates so the responder's path can be validated.
///
/// OCSP responses often embed only the responder certificate itself. A
/// delegated responder is issued directly by the CA that issued the
/// certificate in question (RFC 6960, section 4.2.2.2) — here the signer's
/// issuing CA, which is required to be present in the signer's `x5chain`
/// ([§14.5, X.509 Certificates]). So when the response embeds exactly the
/// responder certificate and its issuer name matches the signer's issuing CA,
/// complete the responder's path with `signing_cert_chain[1..]` (ordered
/// end-entity upward per RFC 9360); otherwise return `ocsp_certs` unchanged.
/// The `x5chain` is untrusted path-building input; trust is still established
/// solely by [`CertificateTrustPolicy::check_certificate_trust`].
///
/// [§14.5, X.509 Certificates]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#x509_certificates
fn extend_ocsp_cert_chain(ocsp_certs: &[Vec<u8>], signing_cert_chain: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if let ([responder_der], [_, issuer_der, ..]) = (ocsp_certs, signing_cert_chain) {
        if let (Ok((_, responder)), Ok((_, issuer))) = (
            X509Certificate::from_der(responder_der),
            X509Certificate::from_der(issuer_der),
        ) {
            if responder.issuer().as_raw() == issuer.subject().as_raw() {
                return [ocsp_certs, &signing_cert_chain[1..]].concat();
            }
        }
    }
    ocsp_certs.to_vec()
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

    // C2PA 2.4 section 15.9: a revoked issuing CA makes the credential untrusted.
    // Query each CA against its own AIA responder (subject = certs[i], issuer =
    // certs[i + 1]); the self-signed anchor at the end has no in-chain issuer.
    for i in 1..certs.len().saturating_sub(1) {
        let ca_der = if _sync {
            crate::crypto::ocsp::fetch_ocsp_response(&certs, i, context)
        } else {
            crate::crypto::ocsp::fetch_ocsp_response_async(&certs, i, context).await
        };
        let Some(ca_der) = ca_der else {
            continue;
        };

        let mut ca_log = StatusTracker::default();
        let ca_response =
            validate_fetched_ocsp(&ca_der, &certs[i..], ctp, signing_time, &mut ca_log);

        if ca_response.revoked_at.is_some() {
            log_item!("", "issuing CA revoked", "fetch_and_check_ocsp_response")
                .validation_status(SIGNING_CREDENTIAL_UNTRUSTED)
                .failure_no_throw(validation_log, CertificateTrustError::CertificateNotTrusted);

            return Err(CoseError::CertificateTrustError(
                CertificateTrustError::CertificateNotTrusted,
            ));
        }
    }

    let ocsp_der = if _sync {
        crate::crypto::ocsp::fetch_ocsp_response(&certs, 0, context)
    } else {
        crate::crypto::ocsp::fetch_ocsp_response_async(&certs, 0, context).await
    };

    let Some(ocsp_response_der) = ocsp_der else {
        log_item!(
            "",
            "signing cert not fetched".to_string(),
            "fetch_and_check_ocsp_response"
        )
        .validation_status(SIGNING_CREDENTIAL_OCSP_INACCESSIBLE)
        .informational(validation_log);

        return Ok(OcspResponse::default());
    };

    Ok(validate_fetched_ocsp(
        &ocsp_response_der,
        &certs,
        ctp,
        signing_time,
        validation_log,
    ))
}

/// Validate a fetched OCSP response for the certificate identified by
/// `subject_chain[0]` (with `subject_chain[1]` its issuer), completing the
/// responder's path from `subject_chain`. Returns the parsed response only if the
/// responder is authorized (RFC 6960 section 3.2); status codes are appended to
/// `validation_log` only on that acceptance.
fn validate_fetched_ocsp(
    ocsp_response_der: &[u8],
    subject_chain: &[Vec<u8>],
    ctp: &CertificateTrustPolicy,
    signing_time: Option<DateTime<Utc>>,
    validation_log: &mut StatusTracker,
) -> OcspResponse {
    // Check the OCSP response, but only if it is well-formed.
    // Revocation errors are reported in the validation log.
    // `subject_chain` is the certificate chain to bind the OCSP response to.
    //
    // Status codes go to a scratch log until the responder has been accepted, then
    // are appended below. RFC 6960 section 3.2 requires all of requirements 1-4
    // before a response may be accepted, and C2PA 2.4 section 15.9.2 conditions
    // `signingCredential.ocsp.notRevoked` on that acceptance – but
    // `from_der_checked` logs the success as soon as requirements 1 and 2 hold. With
    // the caller's log passed in directly, an early return below discarded the
    // response while leaving that success code behind.
    let mut current_validation_log = StatusTracker::default();

    let ocsp_data = match OcspResponse::from_der_checked(
        ocsp_response_der,
        subject_chain,
        signing_time,
        &mut current_validation_log,
    ) {
        Ok(data) => data,
        Err(_) => return OcspResponse::default(),
    };

    // If we get a valid response validate the certs.
    if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
        let Some(first_cert) = ocsp_certs.first() else {
            return OcspResponse::default();
        };

        // make sure this is an OCSP signing EKU
        let mut new_ctp = CertificateTrustPolicy::default();
        new_ctp.clear_ekus();
        new_ctp.add_mandatory_ekus(OCSP_OID_STR.as_bytes()); // ocsp signing EKU
        if check_end_entity_certificate_profile(
            first_cert,
            &new_ctp,
            &mut current_validation_log,
            None,
        )
        .is_err()
        {
            return OcspResponse::default();
        }

        // Validate the trust; complete the responder's path from the signer's
        // x5chain if the response does not embed the responder's issuing CA.
        //
        // This is RFC 6960 section 3.2 requirement 4, "the signer is currently
        // authorized to provide a response for the certificate in question". The
        // EKU check above does not establish it: `check_certificate_profile`
        // inspects a single certificate and builds no path, so a self-signed
        // certificate carrying id-kp-OCSPSigning satisfies it.
        let ocsp_cert_chain = extend_ocsp_cert_chain(ocsp_certs, subject_chain);

        if ctp
            .check_certificate_trust(
                &ocsp_cert_chain,
                first_cert,
                signing_time.map(|t| t.timestamp()),
            )
            .is_err()
        {
            return OcspResponse::default();
        }
    } else {
        // OCSP response must be signed by and the cert chain provided.
        return OcspResponse::default();
    }

    // Only append usable OCSP responses to validation_log.
    validation_log.append(&current_validation_log);
    ocsp_data
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::crypto::cert_chain_pem_to_der;

    // es256.pub is a two-certificate chain: [signing leaf, intermediate CA]
    fn leaf_and_intermediate() -> Vec<Vec<u8>> {
        let pem = include_bytes!("../../../tests/fixtures/certs/es256.pub");
        cert_chain_pem_to_der(pem).unwrap()
    }

    fn ocsp_signing_chain() -> Vec<Vec<u8>> {
        let pem = include_bytes!("../../../tests/fixtures/crypto/ocsp/ocsp_chain.pem");
        cert_chain_pem_to_der(pem).unwrap()
    }

    #[test]
    fn extends_chain_only_when_responder_issued_by_signing_ca() {
        let chain = leaf_and_intermediate();
        // the leaf stands in for a responder issued by the signer's issuing CA
        assert_eq!(extend_ocsp_cert_chain(&chain[..1], &chain), chain);
        // the intermediate's issuer is the (absent) root: no extension
        assert_eq!(extend_ocsp_cert_chain(&chain[1..], &chain), &chain[1..]);
    }

    #[test]
    fn extend_ocsp_cert_chain_builds_from_subject_issuer() {
        // Regression: the responder path must be built from the subject's own
        // sub-chain (certs[i..]), whose [1] is the subject's real issuer -- not
        // the full leaf-anchored chain. For [leaf, CA, root], validating the CA
        // must use [CA, root] so a root-issued responder chains through.
        let certs = ca_chain();
        let responder = vec![certs[2].clone()]; // stand-in responder issued by root
        assert_eq!(extend_ocsp_cert_chain(&responder, &certs[1..]).len(), 2);
        // The full chain's [1] is the CA, not root, so no path is built.
        assert_eq!(extend_ocsp_cert_chain(&responder, &certs).len(), 1);
    }

    #[test]
    fn validate_fetched_ocsp_rejects_unauthorized_responder() {
        // A validly-signed "revoked" response whose responder is not authorized
        // (does not chain to a trust anchor with the OCSP-signing EKU) is
        // discarded, so no revocation is asserted from it (RFC 6960 section 3.2).
        let rsp = include_bytes!("../../../tests/fixtures/crypto/ocsp/response_revoked.der");
        let chain = ocsp_signing_chain();
        let test_time = Utc.with_ymd_and_hms(2024, 2, 1, 8, 0, 0).unwrap();

        let mut log = StatusTracker::default();
        let resp = validate_fetched_ocsp(
            rsp,
            &chain,
            &CertificateTrustPolicy::default(),
            Some(test_time),
            &mut log,
        );

        assert!(resp.revoked_at.is_none());
    }

    #[test]
    fn validate_fetched_ocsp_ignores_unusable_response() {
        // An undecodable response yields no cert data and no status.
        let chain = ocsp_signing_chain();
        let mut log = StatusTracker::default();
        let resp = validate_fetched_ocsp(
            &[0xde, 0xad, 0xbe, 0xef],
            &chain,
            &CertificateTrustPolicy::default(),
            None,
            &mut log,
        );
        assert!(resp.revoked_at.is_none());
        assert!(resp.ocsp_certs.is_none());
    }

    // [leaf(AIA=leaf-ocsp.test), issuing CA(AIA=ca-ocsp.test), root].
    fn ca_chain() -> Vec<Vec<u8>> {
        let pem = include_bytes!("../../../tests/fixtures/crypto/ocsp/ocsp_ca_chain.pem");
        cert_chain_pem_to_der(pem).unwrap()
    }

    fn sign1_with_x5chain(certs: &[Vec<u8>]) -> CoseSign1 {
        let x5 = Value::Array(certs.iter().map(|c| Value::Bytes(c.clone())).collect());
        let mut unprotected = coset::Header::default();
        unprotected
            .rest
            .push((Label::Text("x5chain".to_string()), x5));
        CoseSign1 {
            protected: coset::ProtectedHeader::default(),
            unprotected,
            payload: None,
            signature: vec![0u8; 8],
        }
    }

    // Drives the full online path: each cert (leaf and issuing CA) is queried
    // against its own AIA responder and the responses are processed.
    #[test]
    fn fetch_and_check_queries_leaf_and_ca() {
        use std::io::{Cursor, Read};

        use http::{Request, Response};

        use crate::{
            context::Context,
            http::{HttpResolverError, SyncHttpResolver},
        };

        struct OcspResolver;
        impl SyncHttpResolver for OcspResolver {
            fn http_resolve(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
                let der =
                    include_bytes!("../../../tests/fixtures/crypto/ocsp/response_revoked.der")
                        .to_vec();
                Ok(Response::builder()
                    .status(200)
                    .body(Box::new(Cursor::new(der)) as Box<dyn Read>)
                    .unwrap())
            }
        }

        let sign1 = sign1_with_x5chain(&ca_chain());
        let context = Context::new().with_resolver(OcspResolver);
        let ctp = CertificateTrustPolicy::default();
        let mut log = StatusTracker::default();

        // The responses don't identify these certs and the responder is
        // untrusted, so nothing is asserted -- but the leaf and CA responders
        // were both queried and their responses processed without error.
        let result =
            fetch_and_check_ocsp_response(&sign1, b"payload", &ctp, None, &mut log, &context);
        assert!(result.is_ok());
    }

    // Async variant of the full-path drive, covering the async-generated
    // `fetch_and_check_ocsp_response_async` / `fetch_ocsp_response_async`.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn fetch_and_check_queries_leaf_and_ca_async() {
        use std::io::{Cursor, Read};

        use async_trait::async_trait;
        use http::{Request, Response};

        use crate::{
            context::Context,
            http::{AsyncHttpResolver, HttpResolverError},
        };

        struct OcspResolver;
        #[async_trait]
        impl AsyncHttpResolver for OcspResolver {
            async fn http_resolve_async(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
                let der =
                    include_bytes!("../../../tests/fixtures/crypto/ocsp/response_revoked.der")
                        .to_vec();
                Ok(Response::builder()
                    .status(200)
                    .body(Box::new(Cursor::new(der)) as Box<dyn Read>)
                    .unwrap())
            }
        }

        let sign1 = sign1_with_x5chain(&ca_chain());
        let context = Context::new().with_resolver_async(OcspResolver);
        let ctp = CertificateTrustPolicy::default();
        let mut log = StatusTracker::default();

        let result =
            fetch_and_check_ocsp_response_async(&sign1, b"payload", &ctp, None, &mut log, &context)
                .await;
        assert!(result.is_ok());
    }

    // When every responder is unreachable, each CA fetch returns None (loop
    // continues) and the leaf is reported inaccessible.
    #[test]
    fn fetch_and_check_handles_unreachable_responders() {
        use std::io::Read;

        use http::{Request, Response};

        use crate::{
            context::Context,
            http::{HttpResolverError, SyncHttpResolver},
        };

        struct FailingResolver;
        impl SyncHttpResolver for FailingResolver {
            fn http_resolve(
                &self,
                _request: Request<Vec<u8>>,
            ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
                Ok(Response::builder()
                    .status(404)
                    .body(Box::new(std::io::empty()) as Box<dyn Read>)
                    .unwrap())
            }
        }

        let sign1 = sign1_with_x5chain(&ca_chain());
        let context = Context::new().with_resolver(FailingResolver);
        let ctp = CertificateTrustPolicy::default();
        let mut log = StatusTracker::default();

        let result =
            fetch_and_check_ocsp_response(&sign1, b"payload", &ctp, None, &mut log, &context);
        assert!(result.is_ok());
        assert!(log.has_status(SIGNING_CREDENTIAL_OCSP_INACCESSIBLE));
    }
}
