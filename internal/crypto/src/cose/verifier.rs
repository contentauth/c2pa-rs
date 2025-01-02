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

use std::io::Cursor;

use asn1_rs::FromDer;
use async_generic::async_generic;
use c2pa_status_tracker::{
    log_item,
    validation_codes::{
        ALGORITHM_UNSUPPORTED, SIGNING_CREDENTIAL_INVALID, SIGNING_CREDENTIAL_TRUSTED,
        SIGNING_CREDENTIAL_UNTRUSTED, TIMESTAMP_MISMATCH, TIMESTAMP_OUTSIDE_VALIDITY,
    },
    StatusTracker,
};
use coset::CoseSign1;
use x509_parser::prelude::X509Certificate;

use crate::{
    asn1::rfc3161::TstInfo,
    cose::{
        cert_chain_from_sign1, check_certificate_profile, parse_cose_sign1, signing_alg_from_sign1,
        validate_cose_tst_info, validate_cose_tst_info_async, CertificateTrustError,
        CertificateTrustPolicy, CoseError,
    },
    p1363::parse_ec_der_sig,
    raw_signature::{async_validator_for_signing_alg, validator_for_signing_alg},
    time_stamp::TimeStampError,
    SigningAlg, ValidationInfo,
};

/// A `Verifier` reads a COSE signature and reports on its validity.
///
/// It can provide different levels of verification depending on the enum value
/// chosen.
#[derive(Debug)]
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
        validation_log: &mut impl StatusTracker,
    ) -> Result<ValidationInfo, CoseError> {
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

        let tst_info_res = if _sync {
            validate_cose_tst_info(&sign1, data)
        } else {
            validate_cose_tst_info_async(&sign1, data).await
        };
        
        match alg {
            SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
                if parse_ec_der_sig(&sign1.signature).is_ok() {
                    // Should have been in P1363 format, not DER.
                    log_item!("Cose_Sign1", "unsupported signature format", "verify_cose")
                        .validation_status(SIGNING_CREDENTIAL_INVALID)
                        .failure_no_throw(validation_log, CoseError::InvalidEcdsaSignature);

                    // validation_log.log(log_item, CoseError::InvalidEcdsaSignature)?;
                    return Err(CoseError::InvalidEcdsaSignature);
                }
            }
            _ => (),
        }

        if _sync {
            self.verify_profile(&sign1, &tst_info_res, validation_log)?;
            self.verify_trust(&sign1, &tst_info_res, validation_log)?;
        } else {
            self.verify_profile_async(&sign1, &tst_info_res, validation_log)
                .await?;
            self.verify_trust_async(&sign1, &tst_info_res, validation_log)
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

        if _sync {
            let Some(validator) = validator_for_signing_alg(alg) else {
                return Err(CoseError::UnsupportedSigningAlgorithm);
            };

            validator.validate(&sign1.signature, &tbs, pk_der)?;
        } else {
            let Some(validator) = async_validator_for_signing_alg(alg) else {
                return Err(CoseError::UnsupportedSigningAlgorithm);
            };

            validator
                .validate_async(&sign1.signature, &tbs, pk_der)
                .await?;
        }

        let subject = sign_cert
            .subject()
            .iter_organization()
            .map(|attr| attr.as_str())
            .last()
            .ok_or(CoseError::MissingSigningCertificateChain)?
            .map(|attr| attr.to_string())
            .map_err(|_| CoseError::MissingSigningCertificateChain)?;

        Ok(ValidationInfo {
            alg: Some(alg),
            date: tst_info_res.map(|t| t.gen_time.into()).ok(),
            cert_serial_number: Some(sign_cert.serial.clone()),
            issuer_org: Some(subject),
            validated: true,
            cert_chain: dump_cert_chain(&certs)?,
            revocation_status: Some(true),
        })
    }

    /// Verify certificate profile if so configured.
    ///
    /// TO DO: This might not need to be public after refactoring.
    #[async_generic]
    pub fn verify_profile(
        &self,
        sign1: &CoseSign1,
        tst_info_res: &Result<TstInfo, CoseError>,
        validation_log: &mut impl StatusTracker,
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

        match tst_info_res {
            Ok(tst_info) => Ok(check_certificate_profile(
                end_entity_cert_der,
                ctp,
                validation_log,
                Some(tst_info),
            )?),

            Err(CoseError::NoTimeStampToken) => Ok(check_certificate_profile(
                end_entity_cert_der,
                ctp,
                validation_log,
                None,
            )?),

            Err(CoseError::TimeStampError(TimeStampError::InvalidData)) => {
                log_item!(
                    "Cose_Sign1",
                    "timestamp did not match signed data",
                    "verify_cose"
                )
                .validation_status(TIMESTAMP_MISMATCH)
                .failure_no_throw(validation_log, TimeStampError::InvalidData);

                Err(TimeStampError::InvalidData.into())
            }

            Err(CoseError::TimeStampError(TimeStampError::ExpiredCertificate)) => {
                log_item!(
                    "Cose_Sign1",
                    "timestamp certificate outside of validity",
                    "verify_cose"
                )
                .validation_status(TIMESTAMP_OUTSIDE_VALIDITY)
                .failure_no_throw(validation_log, TimeStampError::ExpiredCertificate);

                Err(TimeStampError::ExpiredCertificate.into())
            }

            Err(e) => {
                log_item!("Cose_Sign1", "error parsing timestamp", "verify_cose")
                    .failure_no_throw(validation_log, e);

                // Frustratingly, we can't clone CoseError. The likely cases are already handled
                // above, so we'll call this an internal error.

                Err(CoseError::InternalError(e.to_string()))
            }
        }
    }

    /// Verify certificate profile if so configured.
    ///
    /// TO DO: This might not need to be public after refactoring.
    #[async_generic]
    pub fn verify_trust(
        &self,
        sign1: &CoseSign1,
        tst_info_res: &Result<TstInfo, CoseError>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<(), CoseError> {
        // IMPORTANT: This function assumes that verify_profile has already been called.

        let ctp = match self {
            Self::VerifyTrustPolicy(ctp) => *ctp,

            Self::VerifyCertificateProfileOnly(_ctp) => {
                return Ok(());
            }

            Self::IgnoreProfileAndTrustPolicy => {
                return Ok(());
            }
        };

        let certs = cert_chain_from_sign1(sign1)?;
        let end_entity_cert_der = &certs[0];
        let chain_der = &certs[1..];

        let signing_time_epoch = tst_info_res.as_ref().ok().map(|tst_info| {
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
            Ok(()) => {
                log_item!("Cose_Sign1", "signing certificate trusted", "verify_cose")
                    .validation_status(SIGNING_CREDENTIAL_TRUSTED)
                    .success(validation_log);

                Ok(())
            }

            Err(CertificateTrustError::CertificateNotTrusted) => {
                log_item!("Cose_Sign1", "signing certificate untrusted", "verify_cose")
                    .validation_status(SIGNING_CREDENTIAL_UNTRUSTED)
                    .failure_no_throw(validation_log, CertificateTrustError::CertificateNotTrusted);

                Err(CertificateTrustError::CertificateNotTrusted.into())
            }

            Err(e) => {
                log_item!("Cose_Sign1", "signing certificate untrusted", "verify_cose")
                    .validation_status(SIGNING_CREDENTIAL_UNTRUSTED)
                    .failure_no_throw(validation_log, &e);

                // TO REVIEW: Mixed message: Are we using CoseCertUntrusted in log or &e from
                // above? validation_log.log(log_item,
                // Error::CoseCertUntrusted)?;
                Err(e.into())
            }
        }
    }
}

fn dump_cert_chain(certs: &[Vec<u8>]) -> Result<Vec<u8>, CoseError> {
    let mut out_buf: Vec<u8> = Vec::new();
    let mut writer = Cursor::new(out_buf);

    for der_bytes in certs {
        let c = x509_certificate::X509Certificate::from_der(der_bytes)
            .map_err(|_e| CoseError::CborParsingError("invalid X509 certificate".to_string()))?;

        c.write_pem(&mut writer).map_err(|_| {
            CoseError::InternalError("I/O error constructing cert_chain dump".to_string())
        })?;
    }

    out_buf = writer.into_inner();
    Ok(out_buf)
}
