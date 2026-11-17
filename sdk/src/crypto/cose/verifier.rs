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

use async_generic::async_generic;
use c2pa_raw_crypto::RawSignatureValidationError;
use contentauth_pki::{
    cose::{CertificateHeaderPolicy, VerificationError},
    sdk_compat::cose as pki_cose,
};
use coset::CoseSign1;
use x509_parser::num_bigint::BigUint;

use crate::{
    crypto::{
        asn1::rfc3161::TstInfo,
        base64::encode,
        cose::{
            cert_chain_from_sign1, check_end_entity_certificate_profile_with_sdk_policy,
            parse_cose_sign1, signing_alg_from_sign1, CertificateInfo, CertificateRole,
            CertificateTrustError, CertificateTrustPolicy, CoseError, TrustAnchorType,
        },
    },
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        ALGORITHM_UNSUPPORTED, CLAIM_SIGNATURE_OUTSIDE_VALIDITY, SIGNING_CREDENTIAL_INVALID,
        SIGNING_CREDENTIAL_TRUSTED, SIGNING_CREDENTIAL_UNTRUSTED,
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
    ///
    /// The certificate must chain to a [`TrustAnchorType::Manifest`] anchor, as
    /// a claim signer must; use [`Self::VerifyTrustPolicyFor`] for other signers.
    VerifyTrustPolicy(Cow<'a, CertificateTrustPolicy>),

    /// As [`Self::VerifyTrustPolicy`], but the certificate must chain to a trust
    /// anchor of the given type, e.g. [`TrustAnchorType::CAWG`] for a CAWG X.509
    /// identity assertion signer. Anchors of other types do not make it trusted.
    VerifyTrustPolicyFor(Cow<'a, CertificateTrustPolicy>, TrustAnchorType),

    /// Validate the certificate's membership against a trust configuration, but
    /// do not against any trust list. The [`CertificateTrustPolicy`] is used to
    /// enforce EKU (Extended Key Usage) policy only.
    VerifyCertificateProfileOnly(Cow<'a, CertificateTrustPolicy>),

    /// Ignore both trust configuration and trust lists.
    IgnoreProfileAndTrustPolicy,
}

impl Verifier<'_> {
    /// Verify a claim signature with role checks independent of anchor selection.
    #[async_generic]
    pub(crate) fn verify_claim_signature(
        &self,
        cose_sign1: &[u8],
        data: &[u8],
        additional_data: &[u8],
        tst_info: Option<&TstInfo>,
        validation_log: &mut StatusTracker,
    ) -> Result<CertificateInfo, CoseError> {
        if _sync {
            self.verify_signature_for_role(
                CertificateRole::ClaimSigner,
                cose_sign1,
                data,
                additional_data,
                tst_info,
                validation_log,
            )
        } else {
            self.verify_signature_for_role_async(
                CertificateRole::ClaimSigner,
                cose_sign1,
                data,
                additional_data,
                tst_info,
                validation_log,
            )
            .await
        }
    }

    #[async_generic]
    pub(crate) fn verify_signature_for_role(
        &self,
        role: CertificateRole,
        cose_sign1: &[u8],
        data: &[u8],
        additional_data: &[u8],
        tst_info: Option<&TstInfo>,
        validation_log: &mut StatusTracker,
    ) -> Result<CertificateInfo, CoseError> {
        if !matches!(self, Self::IgnoreProfileAndTrustPolicy) {
            let sign1 = parse_cose_sign1(cose_sign1, data, validation_log)?;
            let certificates = cert_chain_from_sign1(&sign1)?;
            role.check_purpose(&certificates[0], validation_log)?;
        }

        if _sync {
            self.verify_signature(cose_sign1, data, additional_data, tst_info, validation_log)
        } else {
            self.verify_signature_async(cose_sign1, data, additional_data, tst_info, validation_log)
                .await
        }
    }

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
        let sign1 = parse_cose_sign1(cose_sign1, data, validation_log)?;

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

        if pki_cose::check_signature_encoding(&sign1, alg).is_err() {
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
        let trust_log_start = validation_log.logged_items().len();
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
                Self::VerifyTrustPolicy(ref ctp) | Self::VerifyTrustPolicyFor(ref ctp, _) => {
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
        let profile_log_start = validation_log.logged_items().len();
        let profile_failed = if _sync {
            self.verify_profile(&sign1, tst_info, override_ekus, validation_log)
        } else {
            self.verify_profile_async(&sign1, tst_info, override_ekus, validation_log)
                .await
        }
        .is_err(); // Errors have already been logged.

        // A certificate that fails the profile check is not a trusted signing
        // credential, even when it chains to a trust anchor.
        if profile_failed
            || validation_log.logged_items()[profile_log_start..]
                .iter()
                .any(|item| item.validation_status.as_deref() == Some(SIGNING_CREDENTIAL_INVALID))
        {
            validation_log.remove_status_since(trust_log_start, SIGNING_CREDENTIAL_TRUSTED);
        }

        let certs = cert_chain_from_sign1(&sign1)?;
        let verified = pki_cose::verify_signature(
            &sign1,
            data,
            additional_data,
            CertificateHeaderPolicy::C2pa,
        )
        .map_err(|error| {
            if matches!(error, VerificationError::IncompatibleCertificateKey) {
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
            }

            CoseError::from(error)
        })?;
        let sign_cert = verified.signer_certificate();

        Ok(CertificateInfo {
            alg: Some(alg),
            date: tst_info.map(|t| t.gen_time.clone().into()),
            cert_serial_number: Some(BigUint::from_bytes_be(sign_cert.serial_number())),
            issuer_org: sign_cert.subject_organization(),
            common_name: sign_cert.subject_common_name(),
            validated: true,
            cert_chain: dump_cert_chain(&certs)?,
            // No revocation check runs here, so the status is unknown.
            revocation_status: None,
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
            Self::VerifyTrustPolicyFor(ref ctp, _) => ctp,
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

            Ok(check_end_entity_certificate_profile_with_sdk_policy(
                end_entity_cert_der,
                adjusted_ctp.as_ref(),
                validation_log,
                tst_info,
            )?)
        } else {
            Ok(check_end_entity_certificate_profile_with_sdk_policy(
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

        // A claim signer must chain to a manifest trust anchor, not a TSA or CAWG
        // one; other signers say which anchor type they need.
        let (ctp, anchor_type) = match self {
            Self::VerifyTrustPolicy(ref ctp) => (ctp, TrustAnchorType::Manifest),
            Self::VerifyTrustPolicyFor(ref ctp, anchor_type) => (ctp, *anchor_type),

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
            ctp.check_certificate_trust_for(
                Some(anchor_type),
                chain_der,
                end_entity_cert_der,
                signing_time_epoch,
            )
        } else {
            ctp.check_certificate_trust_for_async(
                Some(anchor_type),
                chain_der,
                end_entity_cert_der,
                signing_time_epoch,
            )
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
            Err(e) => {
                // C2PA requires every CA certificate in the chain to be valid at
                // the validation time, and reports a failure as
                // claimSignature.outsideValidity.
                if e == CertificateTrustError::CaCertificateOutsideValidity {
                    log_item!(
                        "",
                        "certificate chain outside validity period",
                        "verify_cose"
                    )
                    .validation_status(CLAIM_SIGNATURE_OUTSIDE_VALIDITY)
                    .failure_no_throw(
                        validation_log,
                        CertificateTrustError::CaCertificateOutsideValidity,
                    );
                }

                Err(
                    log_item!("", "signing certificate untrusted", "verify_cose")
                        .validation_status(SIGNING_CREDENTIAL_UNTRUSTED)
                        .failure_as_err(validation_log, e.into()),
                )
            }
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
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    /// A chain whose end-entity certificate carries no `O=` (Organization) attribute.
    const ES256_NO_ORG_CHAIN: &[u8] =
        include_bytes!("../../../tests/fixtures/certs/es256_no_org.pub");
    const ES256_NO_ORG_KEY: &[u8] =
        include_bytes!("../../../tests/fixtures/certs/es256_no_org.pem");

    /// A certificate without an Organization attribute is missing optional
    /// information, not a verification failure (#2262, fixed in #2540).
    ///
    /// `verify_signature` must still succeed, and `issuer_org` must come back as
    /// `None` rather than the whole call erroring out.
    #[c2pa_macros::c2pa_test_async]
    async fn verify_signature_succeeds_without_organization_attribute() {
        use c2pa_raw_crypto::signer_from_private_key;

        use crate::{
            crypto::{
                cert_chain_pem_to_der,
                cose::{sign, RawSignerCoseSigner, TimeStampStorage, Verifier},
            },
            status_tracker::StatusTracker,
        };

        let signer = signer_from_private_key(ES256_NO_ORG_KEY, SigningAlg::Es256).unwrap();
        let cert_chain = cert_chain_pem_to_der(ES256_NO_ORG_CHAIN).unwrap();

        let data: &[u8] = b"c2pa certificate info regression payload";
        let cose_sign1 = sign(
            &RawSignerCoseSigner::new(signer.as_ref(), &cert_chain),
            data,
            None,
            TimeStampStorage::V1_sigTst,
            &crate::Context::new(),
        )
        .unwrap();

        let verifier = Verifier::IgnoreProfileAndTrustPolicy;
        for use_async in [false, true] {
            let mut validation_log = StatusTracker::default();
            let cert_info = if use_async {
                verifier
                    .verify_signature_async(&cose_sign1, data, b"", None, &mut validation_log)
                    .await
            } else {
                verifier.verify_signature(&cose_sign1, data, b"", None, &mut validation_log)
            }
            .unwrap();

            assert_eq!(cert_info.issuer_org, None);
            assert_eq!(cert_info.common_name.as_deref(), Some("C2PA Signer"));
            assert!(cert_info.validated);
            assert!(!validation_log.has_any_error());
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn malformed_algorithms_and_signature_formats_fail_with_status() {
        use coset::{iana::Algorithm, RegisteredLabelWithPrivate, TaggedCborSerializable};

        use super::*;
        use crate::crypto::cose::{cose_signer::tests::TestSigner, sign, TimeStampStorage};

        let signer = TestSigner::new(SigningAlg::Es256);
        let bytes = sign(
            &signer,
            b"data",
            None,
            TimeStampStorage::V2_sigTst2_CTT,
            &crate::Context::new(),
        )
        .unwrap();
        let original = CoseSign1::from_tagged_slice(&bytes).unwrap();
        let verifier = Verifier::IgnoreProfileAndTrustPolicy;
        for (alg, signature, expected_status) in [
            (None, original.signature.clone(), ALGORITHM_UNSUPPORTED),
            (
                Some(RegisteredLabelWithPrivate::Assigned(Algorithm::ES256)),
                vec![0x30, 6, 2, 1, 1, 2, 1, 2],
                SIGNING_CREDENTIAL_INVALID,
            ),
            (
                Some(RegisteredLabelWithPrivate::Assigned(Algorithm::EdDSA)),
                original.signature.clone(),
                SIGNING_CREDENTIAL_INVALID,
            ),
        ] {
            let mut sign1 = original.clone();
            sign1.protected.original_data = None;
            sign1.protected.header.alg = alg;
            sign1.signature = signature;
            let bytes = sign1.to_tagged_vec().unwrap();
            let mut log = StatusTracker::default();
            assert!(verifier
                .verify_signature(&bytes, b"data", b"", None, &mut log)
                .is_err());
            assert!(log.has_status(expected_status));
            let mut log = StatusTracker::default();
            assert!(verifier
                .verify_signature_async(&bytes, b"data", b"", None, &mut log)
                .await
                .is_err());
            assert!(log.has_status(expected_status));
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn detached_payload_and_failure_mappings_remain_compatible() {
        use coset::{cbor::value::Value, Label, TaggedCborSerializable};

        use super::*;
        use crate::crypto::cose::{cose_signer::tests::TestSigner, sign, TimeStampStorage};

        let signer = TestSigner::new(SigningAlg::Es256);
        let signature = sign(
            &signer,
            b"data",
            None,
            TimeStampStorage::V2_sigTst2_CTT,
            &crate::Context::new(),
        )
        .unwrap();
        let mut sign1 = CoseSign1::from_tagged_slice(&signature).unwrap();
        sign1.payload = Some(b"ignored embedded payload".to_vec());
        let signature = sign1.clone().to_tagged_vec().unwrap();
        let verifier = Verifier::IgnoreProfileAndTrustPolicy;

        for result in [
            verifier.verify_signature(
                &signature,
                b"data",
                b"",
                None,
                &mut StatusTracker::default(),
            ),
            verifier
                .verify_signature_async(
                    &signature,
                    b"data",
                    b"",
                    None,
                    &mut StatusTracker::default(),
                )
                .await,
        ] {
            let info = result.unwrap();
            assert!(info.validated);
            assert_eq!(info.alg, Some(SigningAlg::Es256));
            assert_eq!(info.revocation_status, None);
            assert!(info.date.is_none());
            assert!(info.cert_serial_number.is_some());
            assert!(!info.cert_chain.is_empty());
        }

        for (payload, aad) in [(b"changed".as_slice(), b"".as_slice()), (b"data", b"aad")] {
            let mut log = StatusTracker::default();
            assert!(matches!(
                verifier.verify_signature(&signature, payload, aad, None, &mut log),
                Err(CoseError::RawSignatureValidationError(
                    RawSignatureValidationError::SignatureMismatch
                ))
            ));
            assert!(log.logged_items().is_empty());
            assert!(matches!(
                verifier
                    .verify_signature_async(&signature, payload, aad, None, &mut log)
                    .await,
                Err(CoseError::RawSignatureValidationError(
                    RawSignatureValidationError::SignatureMismatch
                ))
            ));
            assert!(log.logged_items().is_empty());
        }

        sign1.protected.header.rest.clear();
        sign1.protected.original_data = None;
        sign1.unprotected.rest.clear();

        for certificate in [None, Some(Value::Bytes(vec![]))] {
            let mut malformed = sign1.clone();

            if let Some(certificate) = certificate {
                malformed
                    .unprotected
                    .rest
                    .push((Label::Int(33), certificate));
            }

            let encoded = malformed.clone().to_tagged_vec().unwrap();
            let mut log = StatusTracker::default();
            let error = verifier
                .verify_signature(&encoded, b"data", b"", None, &mut log)
                .unwrap_err();

            if malformed.unprotected.rest.is_empty() {
                assert!(matches!(error, CoseError::MissingSigningCertificateChain));
            } else {
                assert!(matches!(
                    error,
                    CoseError::CborParsingError(message) if message == "invalid X509 certificate"
                ));
            }

            assert!(log.logged_items().is_empty());

            malformed.signature = vec![0x30, 6, 2, 1, 1, 2, 1, 2];
            let encoded = malformed.to_tagged_vec().unwrap();
            assert!(matches!(
                verifier.verify_signature(&encoded, b"data", b"", None, &mut log),
                Err(CoseError::InvalidEcdsaSignature)
            ));
            assert!(log.has_status(SIGNING_CREDENTIAL_INVALID));
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn profile_only_skips_trust_and_applies_additional_ekus() {
        use std::borrow::Cow;

        use coset::TaggedCborSerializable;

        use super::*;
        use crate::crypto::cose::{cose_signer::tests::TestSigner, sign, TimeStampStorage};

        let signer = TestSigner::new(SigningAlg::Ed25519);
        let bytes = sign(
            &signer,
            b"data",
            None,
            TimeStampStorage::V1_sigTst,
            &crate::Context::new(),
        )
        .unwrap();
        let sign1 = CoseSign1::from_tagged_slice(&bytes).unwrap();
        let policy = CertificateTrustPolicy::default();
        let verifier = Verifier::VerifyCertificateProfileOnly(Cow::Borrowed(&policy));
        let mut log = StatusTracker::default();
        assert_eq!(
            verifier.verify_trust(&sign1, None, &mut log).unwrap(),
            (TrustAnchorType::NoCheck, None)
        );
        assert_eq!(
            verifier
                .verify_trust_async(&sign1, None, &mut log)
                .await
                .unwrap(),
            (TrustAnchorType::NoCheck, None)
        );
        assert!(verifier
            .verify_profile(&sign1, None, Some("1.2.3.4".into()), &mut log)
            .is_ok());
        assert!(verifier
            .verify_profile_async(&sign1, None, Some("1.2.3.4".into()), &mut log)
            .await
            .is_ok());
        assert!(!log.has_any_error());
        assert!(matches!(
            Verifier::default(),
            Verifier::VerifyTrustPolicy(_)
        ));
    }

    /// CA validity failures reject trust and report the C2PA 2.5 section 14.8.2 code.
    #[c2pa_macros::c2pa_test_async]
    async fn ca_outside_validity_reports_both_failure_codes() {
        use std::borrow::Cow;

        use coset::cbor::value::Value;

        use super::*;
        use crate::crypto::{
            asn1::{rfc3161::MessageImprint, AlgorithmIdentifier, GeneralizedTime},
            cert_chain_pem_to_der,
        };

        let tst_info = TstInfo {
            version: 1.into(),
            policy: "1.2.3".parse().unwrap(),
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifier {
                    algorithm: "2.16.840.1.101.3.4.2.1".parse().unwrap(),
                },
                hashed_message: bcder::OctetString::new(bytes::Bytes::from_static(&[0; 32])),
            },
            serial_number: 1.into(),
            gen_time: GeneralizedTime::from_der_bytes(b"\x18\x0f20260901000000Z").unwrap(),
            accuracy: None,
            ordering: None,
            nonce: None,
            tsa: None,
            extensions: None,
        };

        for (chain_pem, root_pem, outside_validity) in [
            (
                include_bytes!(
                    "../../../tests/fixtures/crypto/cose/chain_trust_expired_intermediate.pub"
                )
                .as_slice(),
                include_bytes!("../../../tests/fixtures/crypto/cose/chain_trust_root.pub")
                    .as_slice(),
                true,
            ),
            (
                include_bytes!(
                    "../../../tests/fixtures/crypto/cose/chain_trust_future_intermediate.pub"
                )
                .as_slice(),
                include_bytes!("../../../tests/fixtures/crypto/cose/chain_trust_future_root.pub")
                    .as_slice(),
                true,
            ),
            (
                include_bytes!("../../../tests/fixtures/crypto/cose/chain_trust_valid.pub")
                    .as_slice(),
                include_bytes!("../../../tests/fixtures/crypto/cose/chain_trust_root.pub")
                    .as_slice(),
                false,
            ),
        ] {
            let certs = cert_chain_pem_to_der(chain_pem).unwrap();
            let mut sign1 = CoseSign1::default();
            sign1.protected.header.rest.push((
                coset::Label::Int(coset::iana::HeaderParameter::X5Chain as i64),
                Value::Array(certs.into_iter().map(Value::Bytes).collect()),
            ));
            let mut policy = CertificateTrustPolicy::new();
            policy
                .add_trust_anchors(
                    root_pem,
                    "http://some_trust_list",
                    TrustAnchorType::Manifest,
                    None,
                )
                .unwrap();
            let verifier = Verifier::VerifyTrustPolicy(Cow::Borrowed(&policy));

            for is_async in [false, true] {
                let mut log = StatusTracker::default();
                let result = if is_async {
                    verifier
                        .verify_trust_async(&sign1, Some(&tst_info), &mut log)
                        .await
                } else {
                    verifier.verify_trust(&sign1, Some(&tst_info), &mut log)
                };
                if outside_validity {
                    assert!(matches!(
                        result,
                        Err(CoseError::CertificateTrustError(
                            CertificateTrustError::CaCertificateOutsideValidity
                        ))
                    ));
                    assert!(log.has_status(CLAIM_SIGNATURE_OUTSIDE_VALIDITY));
                    assert!(log.has_status(SIGNING_CREDENTIAL_UNTRUSTED));
                    assert!(!log.has_status(SIGNING_CREDENTIAL_TRUSTED));
                    assert_eq!(log.logged_items().len(), 2);
                } else {
                    assert_eq!(
                        result.unwrap(),
                        (
                            TrustAnchorType::Manifest,
                            Some("http://some_trust_list".into())
                        )
                    );
                    assert!(log.has_status(SIGNING_CREDENTIAL_TRUSTED));
                    assert!(!log.has_any_error());
                    assert!(!log.has_status(CLAIM_SIGNATURE_OUTSIDE_VALIDITY));
                    assert!(!log.has_status(SIGNING_CREDENTIAL_UNTRUSTED));
                }
            }
        }
    }

    /// A certificate that fails the certificate profile check is not a trusted
    /// signing credential, even when it chains to a trust anchor.
    #[c2pa_macros::c2pa_test_async]
    async fn profile_failure_is_not_trusted() {
        use std::borrow::Cow;

        use c2pa_raw_crypto::signer_from_private_key;

        use super::Verifier;
        use crate::{
            crypto::{
                cert_chain_pem_to_der,
                cose::{CertificateTrustPolicy, TrustAnchorType},
            },
            settings::Settings,
            signer::RawSignerWrapper,
            status_tracker::StatusTracker,
            validation_results::validation_codes::{
                SIGNING_CREDENTIAL_INVALID, SIGNING_CREDENTIAL_TRUSTED,
            },
        };

        // The leaf chains to the root, but its only EKU is id-kp-documentSigning,
        // which this trust policy does not allow, so it fails the certificate profile.
        let cert_chain = include_bytes!("../../../tests/fixtures/crypto/cose/disallowed_eku.pub");
        let private_key = include_bytes!("../../../tests/fixtures/crypto/cose/disallowed_eku.priv");
        let root = include_bytes!("../../../tests/fixtures/crypto/cose/key_usage_root.pub");

        let signer = RawSignerWrapper::new(
            signer_from_private_key(private_key, SigningAlg::Es256).unwrap(),
            cert_chain_pem_to_der(cert_chain).unwrap(),
            None,
        );

        let mut claim = crate::claim::Claim::new("profile_test", Some("contentauth"), 1);
        claim.build().unwrap();
        let claim_bytes = claim.data().unwrap();

        let mut settings = Settings::default();
        settings.verify.verify_trust = false;
        let cose_bytes = crate::cose_sign::sign_claim(
            &claim_bytes,
            &signer,
            10000,
            &crate::Context::new()
                .with_settings(settings.clone())
                .unwrap(),
        )
        .unwrap();

        let sign1 =
            super::parse_cose_sign1(&cose_bytes, &claim_bytes, &mut StatusTracker::default())
                .unwrap();
        for (allow_eku, require_missing_eku) in [(false, false), (true, true), (true, false)] {
            let mut ctp = CertificateTrustPolicy::new();
            ctp.add_trust_anchors(
                root,
                "http://some_trust_list",
                TrustAnchorType::Manifest,
                None,
            )
            .unwrap();
            if allow_eku {
                ctp.add_valid_ekus(b"1.3.6.1.5.5.7.3.36");
            }
            if require_missing_eku {
                ctp.add_mandatory_ekus(b"1.3.6.1.5.5.7.3.8");
            }
            let verifier = Verifier::VerifyTrustPolicy(Cow::Owned(ctp));
            let invalid = !allow_eku || require_missing_eku;
            for use_async in [false, true] {
                let mut profile_log = StatusTracker::default();
                let profile = if use_async {
                    verifier
                        .verify_profile_async(&sign1, None, None, &mut profile_log)
                        .await
                } else {
                    verifier.verify_profile(&sign1, None, None, &mut profile_log)
                };
                assert_eq!(profile.is_err(), invalid);
                assert_eq!(profile_log.has_status(SIGNING_CREDENTIAL_INVALID), invalid);

                let mut log = StatusTracker::default();
                crate::log_item!(
                    "previous claim",
                    "trusted",
                    "profile_failure_is_not_trusted"
                )
                .validation_status(SIGNING_CREDENTIAL_TRUSTED)
                .success(&mut log);
                crate::log_item!(
                    "previous claim",
                    "invalid",
                    "profile_failure_is_not_trusted"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(&mut log, super::CoseError::UnsupportedSigningAlgorithm);
                let verification_log_start = log.logged_items().len();
                let result = if use_async {
                    verifier
                        .verify_signature_async(&cose_bytes, &claim_bytes, b"", None, &mut log)
                        .await
                } else {
                    verifier.verify_signature(&cose_bytes, &claim_bytes, b"", None, &mut log)
                };
                assert!(result.unwrap().validated);
                assert_eq!(
                    log.logged_items()[verification_log_start..]
                        .iter()
                        .any(|item| item.validation_status.as_deref()
                            == Some(SIGNING_CREDENTIAL_INVALID)),
                    invalid
                );
                assert_eq!(
                    log.logged_items()
                        .iter()
                        .filter(|item| item.validation_status.as_deref()
                            == Some(SIGNING_CREDENTIAL_TRUSTED))
                        .count(),
                    if invalid { 1 } else { 2 }
                );
                assert_eq!(log.logged_items()[0].label, "previous claim");
            }
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn per_anchor_eku_additions_are_local_and_backend_independent() {
        use c2pa_raw_crypto::signer_from_private_key;

        use super::*;
        use crate::crypto::{
            cert_chain_pem_to_der,
            cose::{cose_signer::RawSignerCoseSigner, sign, TimeStampStorage},
        };

        let certs = cert_chain_pem_to_der(include_bytes!(
            "../../../tests/fixtures/crypto/cose/disallowed_eku.pub"
        ))
        .unwrap();

        let raw_signer = signer_from_private_key(
            include_bytes!("../../../tests/fixtures/crypto/cose/disallowed_eku.priv"),
            SigningAlg::Es256,
        )
        .unwrap();

        let signer = RawSignerCoseSigner::new(raw_signer.as_ref(), &certs);

        let signature = sign(
            &signer,
            b"claim",
            None,
            TimeStampStorage::V2_sigTst2_CTT,
            &crate::Context::new(),
        )
        .unwrap();

        let sign1 = parse_cose_sign1(&signature, b"claim", &mut StatusTracker::default()).unwrap();

        for use_defaults in [false, true] {
            for config in [None, Some(""), Some("1.3.6.1.5.5.7.3.36")] {
                let mut policy = CertificateTrustPolicy::new();

                if use_defaults {
                    policy.add_default_valid_ekus();
                }

                // This earlier anchor accepts the EKU but cannot validate this chain.
                policy
                    .add_trust_anchors(
                        include_bytes!("../../../tests/fixtures/crypto/cose/chain_trust_root.pub"),
                        "urn:test:unrelated",
                        TrustAnchorType::Manifest,
                        Some("1.3.6.1.5.5.7.3.36".into()),
                    )
                    .unwrap();

                policy
                    .add_trust_anchors(
                        include_bytes!("../../../tests/fixtures/crypto/cose/key_usage_root.pub"),
                        "urn:test:matching",
                        TrustAnchorType::Manifest,
                        config.map(str::to_owned),
                    )
                    .unwrap();

                let verifier = Verifier::VerifyTrustPolicy(Cow::Borrowed(&policy));
                let allowed = use_defaults || config == Some("1.3.6.1.5.5.7.3.36");

                for use_async in [false, true] {
                    let mut log = StatusTracker::default();

                    let trust = if use_async {
                        verifier.verify_trust_async(&sign1, None, &mut log).await
                    } else {
                        verifier.verify_trust(&sign1, None, &mut log)
                    };

                    assert_eq!(trust.is_ok(), allowed);

                    if allowed {
                        assert_eq!(
                            trust.unwrap(),
                            (TrustAnchorType::Manifest, Some("urn:test:matching".into()))
                        );
                    } else {
                        assert!(matches!(
                            trust,
                            Err(CoseError::CertificateTrustError(
                                CertificateTrustError::CertificateNotTrusted
                            ))
                        ));
                    }

                    assert_eq!(log.has_status(SIGNING_CREDENTIAL_TRUSTED), allowed);
                    assert_eq!(log.has_status(SIGNING_CREDENTIAL_UNTRUSTED), !allowed);

                    let mut log = StatusTracker::default();

                    let result = if use_async {
                        verifier
                            .verify_signature_async(&signature, b"claim", b"", None, &mut log)
                            .await
                    } else {
                        verifier.verify_signature(&signature, b"claim", b"", None, &mut log)
                    };

                    assert!(result.unwrap().validated);
                    assert_eq!(log.has_status(SIGNING_CREDENTIAL_TRUSTED), allowed);
                    assert_eq!(log.has_status(SIGNING_CREDENTIAL_INVALID), !allowed);
                }
            }
        }
    }

    /// A certificate that chains to a trust anchor but fails a rule only the certificate
    /// profile enforces is not a trusted signing credential.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn profile_failure_without_key_usage_is_not_trusted() {
        use std::borrow::Cow;

        use c2pa_raw_crypto::signer_from_private_key;

        use super::Verifier;
        use crate::{
            crypto::cose::{
                cose_signer::RawSignerCoseSigner, sign, CertificateTrustPolicy, TimeStampStorage,
                TrustAnchorType,
            },
            status_tracker::StatusTracker,
            utils::ephemeral_cert::generate_ephemeral_chain_with_ee_skip,
            validation_results::validation_codes::{
                SIGNING_CREDENTIAL_INVALID, SIGNING_CREDENTIAL_TRUSTED,
            },
        };

        // The leaf chains to the CA, which is a trust anchor, so the trust check passes
        // and logs signingCredential.trusted. Without a key usage extension it then fails
        // the certificate profile, which only that check enforces. (The rust_native
        // backend trusts this chain; OpenSSL already rejects it at the trust check.)
        let chain =
            generate_ephemeral_chain_with_ee_skip("profile-test.example.com", &["key_usage"])
                .unwrap();
        let raw_signer =
            signer_from_private_key(chain.ee_private_key_pem.as_bytes(), SigningAlg::Ed25519)
                .unwrap();
        let cert_chain = vec![chain.ee_der.clone(), chain.ca_der.clone()];
        // Sign below the layer that checks the certificate profile, which would refuse it.
        let signer = RawSignerCoseSigner::new(raw_signer.as_ref(), &cert_chain);
        let claim_bytes = b"claim";
        let cose_bytes = sign(
            &signer,
            claim_bytes,
            None,
            TimeStampStorage::V2_sigTst2_CTT,
            &crate::Context::new(),
        )
        .unwrap();

        let mut ctp = CertificateTrustPolicy::default();
        ctp.add_trust_anchors(
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                crate::crypto::base64::encode(&chain.ca_der)
            )
            .as_bytes(),
            "http://some_trust_list",
            TrustAnchorType::Manifest,
            None,
        )
        .unwrap();

        let mut log = StatusTracker::default();
        let _ = Verifier::VerifyTrustPolicy(Cow::Owned(ctp)).verify_signature(
            &cose_bytes,
            claim_bytes,
            b"",
            None,
            &mut log,
        );

        assert!(log.has_status(SIGNING_CREDENTIAL_INVALID));
        assert!(!log.has_status(SIGNING_CREDENTIAL_TRUSTED));
    }
}
