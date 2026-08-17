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
        SIGNING_CREDENTIAL_REVOKED,
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

    // If a stapled response is present, it takes precedence over fetching --
    // but only when it affirmatively resolves revocation status. A present
    // but inconclusive staple (malformed DER, untrusted OCSP signer, wrong
    // EKU, etc.) falls through to the `fetch_policy` dispatch below, exactly
    // as if no stapled response were present at all, instead of silently
    // treating the unusable staple as a clean result and skipping the
    // configured online check.
    if let Some(ocsp_response_der) = get_ocsp_der(sign1) {
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
                .informational(validation_log);

                return Ok(ocsp_response);
            }
        }
    }

    match fetch_policy {
        OcspFetchPolicy::FetchAllowed => {
            if _sync {
                fetch_and_check_ocsp_response(sign1, data, ctp, tst_info, validation_log, context)
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
        let mut new_ctp = ctp.clone();
        new_ctp.clear_ekus();
        new_ctp.add_valid_ekus(OCSP_OID_STR.as_bytes()); // ocsp signing EKU
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
        if new_ctp
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
#[async_generic]
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
        log_item!(
            "",
            "signing cert not fetched".to_string(),
            "fetch_and_check_ocsp_response"
        )
        .validation_status(SIGNING_CREDENTIAL_OCSP_INACCESSIBLE)
        .informational(validation_log);

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
    // `certs` is the signing certificate chain; bind the OCSP response to it.
    let ocsp_data = match OcspResponse::from_der_checked(
        &ocsp_response_der,
        &certs,
        signing_time,
        validation_log,
    ) {
        Ok(data) => data,
        Err(_) => return Ok(OcspResponse::default()),
    };

    // If we get a valid response validate the certs.
    if let Some(ocsp_certs) = &ocsp_data.ocsp_certs {
        let Some(first_cert) = ocsp_certs.first() else {
            return Ok(OcspResponse::default());
        };

        // make sure this is an OCSP signing EKU
        let mut new_ctp = ctp.clone();
        new_ctp.clear_ekus();
        new_ctp.add_valid_ekus(OCSP_OID_STR.as_bytes()); // ocsp signing EKU

        if check_end_entity_certificate_profile(first_cert, &new_ctp, validation_log, None).is_err()
        {
            return Ok(OcspResponse::default());
        }

        // no need to check trust here, that is checked during validation
    } else {
        // OCSP response must be signed by and the cert chain provided
        return Ok(OcspResponse::default());
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::extend_ocsp_cert_chain;
    use crate::crypto::cert_chain_pem_to_der;

    // es256.pub is a two-certificate chain: [signing leaf, intermediate CA]
    fn leaf_and_intermediate() -> Vec<Vec<u8>> {
        let pem = include_bytes!("../../../tests/fixtures/certs/es256.pub");
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

    /// Regression test for CAI-13013 / VULN-37149: a malformed stapled OCSP
    /// response must not silently suppress the configured online OCSP fetch.
    #[test]
    fn malformed_stapled_ocsp_falls_back_to_fetch_when_allowed() {
        use c2pa_raw_crypto::{signer_from_private_key, RawSigner};

        use super::{check_ocsp_status, OcspFetchPolicy};
        use crate::{
            claim::Claim,
            context::Context,
            crypto::cose::{cose_reserve_size, parse_cose_sign1, CertificateTrustPolicy},
            settings::Settings,
            status_tracker::StatusTracker,
            validation_status::SIGNING_CREDENTIAL_OCSP_INACCESSIBLE,
            Result, Signer, SigningAlg,
        };

        // A signer that staples an OCSP response consisting of garbage,
        // non-DER bytes into the unsigned `rVals` header, mirroring the
        // reported attack (an intermediary appending arbitrary bytes to an
        // otherwise honestly-signed asset's unsigned COSE header).
        struct OcspSigner {
            raw_signer: Box<dyn RawSigner>,
            cert_chain: Vec<Vec<u8>>,
            ocsp_rsp: Vec<u8>,
        }

        impl Signer for OcspSigner {
            fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
                Ok(self.raw_signer.sign(data)?)
            }

            fn alg(&self) -> SigningAlg {
                SigningAlg::Ps256
            }

            fn certs(&self) -> Result<Vec<Vec<u8>>> {
                Ok(self.cert_chain.clone())
            }

            fn reserve_size(&self) -> usize {
                cose_reserve_size(
                    self.raw_signer.max_signature_size(),
                    &self.cert_chain,
                    false,
                    Some(&self.ocsp_rsp),
                )
            }

            fn ocsp_val(&self) -> Option<Vec<u8>> {
                Some(self.ocsp_rsp.clone())
            }
        }

        let mut claim = Claim::new("ocsp_fallback_test", Some("contentauth"), 1);
        claim.build().unwrap();
        let claim_bytes = claim.data().unwrap();

        let sign_cert = include_bytes!("../../../tests/fixtures/certs/ps256.pub").to_vec();
        let pem_key = include_bytes!("../../../tests/fixtures/certs/ps256.pem").to_vec();

        let raw_signer = signer_from_private_key(&pem_key, SigningAlg::Ps256).unwrap();
        let cert_chain = cert_chain_pem_to_der(&sign_cert).unwrap();

        let ocsp_signer = OcspSigner {
            raw_signer,
            cert_chain,
            ocsp_rsp: vec![0xde, 0xad, 0xbe, 0xef], // not valid OCSP DER
        };

        let settings = Settings::default();
        let cose_bytes = crate::cose_sign::sign_claim(
            &claim_bytes,
            &ocsp_signer,
            ocsp_signer.reserve_size(),
            &settings,
        )
        .unwrap();

        let mut parse_log = StatusTracker::default();
        let sign1 = parse_cose_sign1(&cose_bytes, &claim_bytes, &mut parse_log).unwrap();

        let ctp = CertificateTrustPolicy::default();
        let context = Context::new();
        let mut validation_log = StatusTracker::default();

        let result = check_ocsp_status(
            &sign1,
            &claim_bytes,
            OcspFetchPolicy::FetchAllowed,
            &ctp,
            None,
            None,
            &mut validation_log,
            &context,
        );

        // The malformed staple is inconclusive either way, so the returned
        // value is still a default (no cached revocation status available)
        // -- but the code must actually route through the online-fetch
        // fallback rather than silently accepting the garbage staple as
        // "checked". The test cert has no AIA/OCSP responder URL, so the
        // fetch deterministically fails closed and logs
        // SIGNING_CREDENTIAL_OCSP_INACCESSIBLE -- that status is only ever
        // logged from the fetch fallback path, so its presence proves the
        // fallback fired instead of short-circuiting on the unusable staple.
        assert!(result.is_ok());
        assert!(validation_log.has_status(SIGNING_CREDENTIAL_OCSP_INACCESSIBLE));
    }
}
