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

use std::io::Write;

use asn1_rs::FromDer;
use async_generic::async_generic;
use coset::CoseSign1;
use x509_parser::prelude::X509Certificate;

use crate::{
    crypto::{
        asn1::rfc3161::TstInfo,
        base64::encode,
        cose::{
            cert_chain_from_sign1, check_end_entity_certificate_profile, parse_cose_sign1,
            signing_alg_from_sign1, CertificateInfo, CertificateTrustPolicy, CoseError,
            TrustAnchorType,
        },
        ec_utils::parse_ec_der_sig,
        raw_signature::{validator_for_signing_alg, SigningAlg},
    },
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        ALGORITHM_UNSUPPORTED, SIGNING_CREDENTIAL_INVALID, SIGNING_CREDENTIAL_TRUSTED,
        SIGNING_CREDENTIAL_UNTRUSTED,
    },
};

/// A `Verifier` reads a COSE signature and reports on its validity.
///
/// It can provide different levels of verification depending on the enum value
/// chosen.
#[derive(Debug)]
#[non_exhaustive]
pub enum Verifier<'a> {
    /// Use a [`CertificateTrustPolicy`] to validate the signing certificate's
    /// profile against C2PA requirements _and_ validate the certificate's
    /// membership against a trust configuration.
    VerifyTrustPolicy(&'a CertificateTrustPolicy),

    /// Validate the certificate's membership against a trust configuration, but
    /// do not against any trust list. The [`CertificateTrustPolicy`] is used to
    /// enforce EKU (Extended Key Usage) policy only.
    VerifyCertificateProfileOnly(&'a CertificateTrustPolicy),

    /// Ignore both trust configuration and trust lists.
    IgnoreProfileAndTrustPolicy,
}

impl Verifier<'_> {
    /// Verify a COSE signature according to the configured policies.
    #[async_generic]
    pub fn verify_signature(
        &self,
        cose_sign1: &[u8],
        data: &[u8],
        additional_data: &[u8],
        tst_info: Option<&TstInfo>,
        validation_log: &mut StatusTracker,
    ) -> Result<CertificateInfo, CoseError> {
        let mut sign1 = parse_cose_sign1(cose_sign1, data, validation_log)?;

        let Ok(alg) = signing_alg_from_sign1(&sign1) else {
            log_item!(
                "Cose_Sign1",
                "unsupported or missing Cose algorithm",
                "verify_cose"
            )
            .validation_status(ALGORITHM_UNSUPPORTED)
            .failure_no_throw(validation_log, CoseError::UnsupportedSigningAlgorithm);

            return Err(CoseError::UnsupportedSigningAlgorithm);
        };

        match alg {
            SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
                if parse_ec_der_sig(&sign1.signature).is_ok() {
                    // Should have been in P1363 format, not DER.
                    log_item!(
                        "Cose_Sign1",
                        "unsupported signature format (EC signature should be in P1363 r|s format)",
                        "verify_cose"
                    )
                    .validation_status(SIGNING_CREDENTIAL_INVALID)
                    .failure_no_throw(validation_log, CoseError::InvalidEcdsaSignature);

                    // validation_log.log(log_item, CoseError::InvalidEcdsaSignature)?;
                    return Err(CoseError::InvalidEcdsaSignature);
                }
            }
            _ => (),
        }

        if _sync {
            self.verify_profile(&sign1, tst_info, validation_log)?;
            self.verify_trust(&sign1, tst_info, validation_log)?;
        } else {
            self.verify_profile_async(&sign1, tst_info, validation_log)
                .await?;
            self.verify_trust_async(&sign1, tst_info, validation_log)
                .await?;
        }

        // Reconstruct payload and additional data as it should have been at time of
        // signing.
        sign1.payload = Some(data.to_vec());
        let tbs = sign1.tbs_data(additional_data);

        let certs = cert_chain_from_sign1(&sign1)?;
        let end_entity_cert_der = &certs[0];

        let (_rem, sign_cert) = X509Certificate::from_der(end_entity_cert_der)
            .map_err(|_| CoseError::CborParsingError("invalid X509 certificate".to_string()))?;
        let pk = sign_cert.public_key();
        let pk_der = pk.raw;

        #[allow(unused_mut)] // never written to in the _sync case
        let mut validated = false;

        if _async {
            // This awkward configuration is necessary because we only have async validator
            // implementations for _some_ algorithms, but we also can't easily wrap the sync
            // implementations due to the joys of `Send`. So we have to fall back to the
            // synchronous implementation, even on WASM, for some algorithms.
            #[cfg(target_arch = "wasm32")]
            if let Some(validator) =
                crate::crypto::raw_signature::async_validator_for_signing_alg(alg)
            {
                validator
                    .validate_async(&sign1.signature, &tbs, pk_der)
                    .await?;

                validated = true;
            }
        }

        if !validated {
            let Some(validator) = validator_for_signing_alg(alg) else {
                return Err(CoseError::UnsupportedSigningAlgorithm);
            };

            validator.validate(&sign1.signature, &tbs, pk_der)?;
        }

        let subject = sign_cert
            .subject()
            .iter_organization()
            .map(|attr| attr.as_str())
            .last()
            .ok_or(CoseError::MissingSigningCertificateChain)?
            .map(|attr| attr.to_string())
            .map_err(|_| CoseError::MissingSigningCertificateChain)?;

        Ok(CertificateInfo {
            alg: Some(alg),
            date: tst_info.map(|t| t.gen_time.clone().into()),
            cert_serial_number: Some(sign_cert.serial.clone()),
            issuer_org: Some(subject),
            validated: true,
            cert_chain: dump_cert_chain(&certs)?,
            revocation_status: Some(true),
            ..Default::default()
        })
    }

    /// Verify certificate profile if so configured.
    #[async_generic]
    pub(crate) fn verify_profile(
        &self,
        sign1: &CoseSign1,
        tst_info: Option<&TstInfo>,
        validation_log: &mut StatusTracker,
    ) -> Result<(), CoseError> {
        let ctp = match self {
            Self::VerifyTrustPolicy(ctp) => *ctp,
            Self::VerifyCertificateProfileOnly(ctp) => *ctp,
            Self::IgnoreProfileAndTrustPolicy => {
                return Ok(());
            }
        };

        let certs = cert_chain_from_sign1(sign1)?;
        let end_entity_cert_der = &certs[0];

        Ok(check_end_entity_certificate_profile(
            end_entity_cert_der,
            ctp,
            validation_log,
            tst_info,
        )?)
    }

    /// Verify certificate profile if so configured.
    #[async_generic]
    pub(crate) fn verify_trust(
        &self,
        sign1: &CoseSign1,
        tst_info_res: Option<&TstInfo>,
        validation_log: &mut StatusTracker,
    ) -> Result<TrustAnchorType, CoseError> {
        // IMPORTANT: This function assumes that verify_profile has already been called.

        let ctp = match self {
            Self::VerifyTrustPolicy(ctp) => *ctp,

            Self::VerifyCertificateProfileOnly(_ctp) => {
                return Ok(TrustAnchorType::NoCheck);
            }

            Self::IgnoreProfileAndTrustPolicy => {
                return Ok(TrustAnchorType::NoCheck);
            }
        };

        let certs = cert_chain_from_sign1(sign1)?;
        let end_entity_cert_der = &certs[0];
        let chain_der = &certs[1..];

        let signing_time_epoch = tst_info_res.map(|tst_info| {
            let dt: chrono::DateTime<chrono::Utc> = tst_info.gen_time.clone().into();
            dt.timestamp()
        });

        let verify_result = if _sync {
            ctp.check_certificate_trust(chain_der, end_entity_cert_der, signing_time_epoch)
        } else {
            ctp.check_certificate_trust_async(chain_der, end_entity_cert_der, signing_time_epoch)
                .await
        };

        match verify_result {
            Ok(tat) => {
                log_item!(
                    "",
                    format!(
                        "signing certificate trusted, found in {:?} trust anchors",
                        tat
                    ),
                    "verify_cose"
                )
                .validation_status(SIGNING_CREDENTIAL_TRUSTED)
                .success(validation_log);

                Ok(tat)
            }
            Err(e) => Err(
                log_item!("", "signing certificate untrusted", "verify_cose")
                    .validation_status(SIGNING_CREDENTIAL_UNTRUSTED)
                    .failure_as_err(validation_log, e.into()),
            ),
        }
    }
}

fn dump_cert_chain(certs: &[Vec<u8>]) -> Result<Vec<u8>, CoseError> {
    let mut writer = Vec::new();

    let line_len = 64;
    let cert_begin = "-----BEGIN CERTIFICATE-----";
    let cert_end = "-----END CERTIFICATE-----";

    for der_bytes in certs {
        let cert_base_str = encode(der_bytes);

        // Break line into fixed-length lines.
        let cert_lines = cert_base_str
            .chars()
            .collect::<Vec<char>>()
            .chunks(line_len)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>();

        writer
            .write_fmt(format_args!("{cert_begin}\n"))
            .map_err(|_e| CoseError::InternalError("could not write PEM".to_string()))?;

        for l in cert_lines {
            writer
                .write_fmt(format_args!("{l}\n"))
                .map_err(|_e| CoseError::InternalError("could not write PEM".to_string()))?;
        }

        writer
            .write_fmt(format_args!("{cert_end}\n"))
            .map_err(|_e| CoseError::InternalError("could not write PEM".to_string()))?;
    }

    Ok(writer)
}
