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

use std::{borrow::Cow, io::Write};

use asn1_rs::FromDer;
use async_generic::async_generic;
use c2pa_raw_crypto::{
    ec_utils::parse_ec_der_sig, validator_for_signing_alg, RawSignatureValidationError, SigningAlg,
};
use coset::CoseSign1;
use x509_parser::{
    der_parser::oid, oid_registry::Oid, prelude::X509Certificate, x509::AlgorithmIdentifier,
};

use crate::{
    crypto::{
        asn1::rfc3161::TstInfo,
        base64::encode,
        cose::{
            cert_chain_from_sign1, check_end_entity_certificate_profile, parse_cose_sign1,
            signing_alg_from_sign1, CertificateInfo, CertificateTrustPolicy, CoseError,
            TrustAnchorType,
        },
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
    VerifyTrustPolicy(Cow<'a, CertificateTrustPolicy>),

    /// Validate the certificate's membership against a trust configuration, but
    /// do not against any trust list. The [`CertificateTrustPolicy`] is used to
    /// enforce EKU (Extended Key Usage) policy only.
    VerifyCertificateProfileOnly(Cow<'a, CertificateTrustPolicy>),

    /// Ignore both trust configuration and trust lists.
    IgnoreProfileAndTrustPolicy,
}

const EC_PUBLICKEY_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
const RSA_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .1);
const RSASSA_PSS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10);
const ED25519_OID: Oid<'static> = oid!(1.3.101 .112);
const PRIME256V1_OID: Oid<'static> = oid!(1.2.840 .10045 .3 .1 .7);
const SECP384R1_OID: Oid<'static> = oid!(1.3.132 .0 .34);
const SECP521R1_OID: Oid<'static> = oid!(1.3.132 .0 .35);

// Does the certificate's key match the algorithm -- and, for EC, the curve --
// implied by the COSE `SigningAlg` (RFC 8152: Es256/384/512 are P-256/384/521)?
// Fails closed: an unmapped future `SigningAlg` is rejected so this map must be
// updated when a new algorithm is added.
fn spki_matches_signing_alg(alg: SigningAlg, spki: &AlgorithmIdentifier) -> bool {
    let key_alg = &spki.algorithm;
    let ec_named_curve_is = |curve: &Oid| {
        *key_alg == EC_PUBLICKEY_OID
            && spki
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .is_some_and(|c| c == *curve)
    };
    match alg {
        SigningAlg::Es256 => ec_named_curve_is(&PRIME256V1_OID),
        SigningAlg::Es384 => ec_named_curve_is(&SECP384R1_OID),
        SigningAlg::Es512 => ec_named_curve_is(&SECP521R1_OID),
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => {
            *key_alg == RSA_OID || *key_alg == RSASSA_PSS_OID
        }
        SigningAlg::Ed25519 => *key_alg == ED25519_OID,
        _ => false,
    }
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

        if let (SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512, true) =
            (alg, parse_ec_der_sig(&sign1.signature).is_some())
        {
            // Should have been in P1363 format, not DER.
            log_item!(
                "Cose_Sign1",
                "unsupported signature format (EC signature should be in P1363 r|s format)",
                "verify_cose"
            )
            .validation_status(SIGNING_CREDENTIAL_INVALID)
            .failure_no_throw(validation_log, CoseError::InvalidEcdsaSignature);

            return Err(CoseError::InvalidEcdsaSignature);
        }

        // check the trust for this item
        let result = if _sync {
            self.verify_trust(&sign1, tst_info, validation_log)
        } else {
            self.verify_trust_async(&sign1, tst_info, validation_log)
                .await
        }; // Ignore errors here - they have already been logged.

        // see if this trusted anchor set had custom EKU overrides
        let override_ekus = match result {
            // only case where we have named trust sets
            Ok((trust_type, Some(trust_uri))) => match self {
                Self::VerifyTrustPolicy(ref ctp) => {
                    if let Some(anchor) = ctp.get_anchor_set(trust_type, &trust_uri) {
                        anchor.trust_config.clone()
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        };

        // check the profile of the cert
        if _sync {
            self.verify_profile(&sign1, tst_info, override_ekus, validation_log)
        } else {
            self.verify_profile_async(&sign1, tst_info, override_ekus, validation_log)
                .await
        }
        .ok(); // Ignore errors here - they have already been logged.

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

        // Reject a certificate whose key algorithm does not match the declared
        // COSE signing algorithm (e.g. an Ed448 key under the Ed25519 selection).
        if !spki_matches_signing_alg(alg, &pk.algorithm) {
            log_item!(
                "Cose_Sign1",
                "certificate key algorithm does not match COSE signing algorithm",
                "verify_cose"
            )
            .validation_status(SIGNING_CREDENTIAL_INVALID)
            .failure_no_throw(
                validation_log,
                CoseError::RawSignatureValidationError(
                    RawSignatureValidationError::InvalidPublicKey,
                ),
            );

            return Err(RawSignatureValidationError::InvalidPublicKey.into());
        }

        // The built-in validators are pure-Rust and synchronous on every target
        // (including WASM), so the synchronous validator is used directly even on
        // the async path.
        let Some(validator) = validator_for_signing_alg(alg) else {
            return Err(CoseError::UnsupportedSigningAlgorithm);
        };

        validator.validate(&sign1.signature, &tbs, pk_der)?;

        let subject = sign_cert
            .subject()
            .iter_organization()
            .map(|attr| attr.as_str())
            .last()
            .and_then(|attr| attr.ok())
            .map(|a| a.to_string());

        let common_name = sign_cert
            .subject()
            .iter_common_name()
            .map(|attr| attr.as_str())
            .last()
            .and_then(|attr| attr.ok())
            .map(|a| a.to_string());

        Ok(CertificateInfo {
            alg: Some(alg),
            date: tst_info.map(|t| t.gen_time.clone().into()),
            cert_serial_number: Some(sign_cert.serial.clone()),
            issuer_org: subject,
            common_name,
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
        additional_ekus: Option<String>,
        validation_log: &mut StatusTracker,
    ) -> Result<(), CoseError> {
        let ctp = match self {
            Self::VerifyTrustPolicy(ref ctp) => ctp,
            Self::VerifyCertificateProfileOnly(ref ctp) => ctp,
            Self::IgnoreProfileAndTrustPolicy => {
                return Ok(());
            }
        };

        let certs = cert_chain_from_sign1(sign1)?;
        let end_entity_cert_der = &certs[0];

        if let Some(ekus) = additional_ekus {
            let mut adjusted_ctp = ctp.clone();
            adjusted_ctp.to_mut().add_valid_ekus(ekus.as_bytes());

            Ok(check_end_entity_certificate_profile(
                end_entity_cert_der,
                adjusted_ctp.as_ref(),
                validation_log,
                tst_info,
            )?)
        } else {
            Ok(check_end_entity_certificate_profile(
                end_entity_cert_der,
                ctp.as_ref(),
                validation_log,
                tst_info,
            )?)
        }
    }

    /// Verify certificate trust if so configured.
    #[async_generic]
    pub(crate) fn verify_trust(
        &self,
        sign1: &CoseSign1,
        tst_info_res: Option<&TstInfo>,
        validation_log: &mut StatusTracker,
    ) -> Result<(TrustAnchorType, Option<String>), CoseError> {
        // should be used in conjunction with verify_profile in most cases

        let ctp = match self {
            Self::VerifyTrustPolicy(ref ctp) => ctp,

            Self::VerifyCertificateProfileOnly(ref _ctp) => {
                return Ok((TrustAnchorType::NoCheck, None));
            }

            Self::IgnoreProfileAndTrustPolicy => {
                return Ok((TrustAnchorType::NoCheck, None));
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
            Ok((tat, trust_uri)) => {
                log_item!(
                    "",
                    format!(
                        "signing certificate trusted, found in [{}] trust anchors",
                        &trust_uri
                    ),
                    "verify_cose"
                )
                .validation_status(SIGNING_CREDENTIAL_TRUSTED)
                .set_trust_list_uri(&trust_uri)
                .success(validation_log);

                Ok((tat, Some(trust_uri)))
            }
            Err(e) => Err(
                log_item!("", "signing certificate untrusted", "verify_cose")
                    .validation_status(SIGNING_CREDENTIAL_UNTRUSTED)
                    .failure_as_err(validation_log, e.into()),
            ),
        }
    }
}

impl Default for Verifier<'_> {
    fn default() -> Self {
        Self::VerifyTrustPolicy(Cow::Owned(CertificateTrustPolicy::default()))
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use c2pa_raw_crypto::SigningAlg;
    use x509_parser::prelude::{FromDer, Pem, X509Certificate};

    use super::spki_matches_signing_alg;

    const ES256: &[u8] = include_bytes!("../../../tests/fixtures/crypto/raw_signature/es256.pub");
    const ES384: &[u8] = include_bytes!("../../../tests/fixtures/crypto/raw_signature/es384.pub");
    const ES512: &[u8] = include_bytes!("../../../tests/fixtures/crypto/raw_signature/es512.pub");
    const PS256: &[u8] = include_bytes!("../../../tests/fixtures/crypto/raw_signature/ps256.pub");
    const PS384: &[u8] = include_bytes!("../../../tests/fixtures/crypto/raw_signature/ps384.pub");
    const ED25519: &[u8] = include_bytes!("../../../tests/fixtures/certs/ed25519.pub");
    const ED448: &[u8] = include_bytes!("../../../tests/fixtures/crypto/raw_signature/ed448.pub");

    fn key_matches(cert_pem: &[u8], alg: SigningAlg) -> bool {
        let pem = Pem::iter_from_buffer(cert_pem).next().unwrap().unwrap();
        let (_, cert) = X509Certificate::from_der(&pem.contents).unwrap();
        spki_matches_signing_alg(alg, &cert.public_key().algorithm)
    }

    #[test]
    fn matching_keys_accepted() {
        assert!(key_matches(ED25519, SigningAlg::Ed25519));
        assert!(key_matches(ES256, SigningAlg::Es256));
        assert!(key_matches(ES384, SigningAlg::Es384));
        assert!(key_matches(ES512, SigningAlg::Es512));
        assert!(key_matches(PS256, SigningAlg::Ps256));
        assert!(key_matches(PS384, SigningAlg::Ps384));
    }

    #[test]
    fn wrong_key_type_rejected() {
        // The reported bypass: an Ed448 key must not match Ed25519.
        assert!(!key_matches(ED448, SigningAlg::Ed25519));
        // EC vs RSA vs Ed in either direction.
        assert!(!key_matches(ES256, SigningAlg::Ed25519));
        assert!(!key_matches(ED25519, SigningAlg::Es256));
        assert!(!key_matches(PS256, SigningAlg::Es256));
        assert!(!key_matches(ES256, SigningAlg::Ps256));
        assert!(!key_matches(PS256, SigningAlg::Ed25519));
    }

    #[test]
    fn wrong_ec_curve_rejected() {
        // Right key type (EC) but the wrong curve for the declared alg.
        assert!(!key_matches(ES256, SigningAlg::Es384));
        assert!(!key_matches(ES256, SigningAlg::Es512));
        assert!(!key_matches(ES384, SigningAlg::Es256));
        assert!(!key_matches(ES512, SigningAlg::Es256));
    }
}
