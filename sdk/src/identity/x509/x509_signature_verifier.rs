// Copyright 2025 Adobe. All rights reserved.
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
use async_trait::async_trait;
use c2pa_raw_crypto::RawSignatureValidationError;
use coset::CoseSign1;
use serde::Serialize;

use crate::{
    crypto::cose::{parse_cose_sign1, CertificateInfo, CoseError, Verifier},
    identity::{
        identity_assertion::signature_verifier::ToCredentialSummary, SignatureVerifier,
        SignerPayload, ValidationError,
    },
    log_current_item,
    status_tracker::StatusTracker,
    validation_status::{CAWG_X509_SIGNATURE_MISMATCH, CAWG_X509_SIGNATURE_VALIDATED},
};

/// An implementation of [`SignatureVerifier`] that supports COSE signatures
/// generated from X.509 credentials as specified in [§8.2, X.509 certificates
/// and COSE signatures].
///
/// [`SignatureVerifier`]: crate::identity::SignatureVerifier
/// [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.3/#_x_509_certificates_and_cose_signatures
#[derive(Debug, Default)]
pub struct X509SignatureVerifier<'a> {
    /// Describes the verification policy to use for COSE signatures.
    pub cose_verifier: Verifier<'a>,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureVerifier for X509SignatureVerifier<'_> {
    type Error = CoseError;
    type Output = X509SignatureInfo;

    fn check_signature(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<Self::Output, ValidationError<Self::Error>> {
        self.check_x509_cose_signature(signer_payload, signature, status_tracker)
    }

    async fn check_signature_async(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<Self::Output, ValidationError<Self::Error>> {
        self.check_x509_cose_signature_async(signer_payload, signature, status_tracker)
            .await
    }
}

impl X509SignatureVerifier<'_> {
    /// Shared implementation for [`SignatureVerifier::check_signature`] and
    /// [`SignatureVerifier::check_signature_async`].
    ///
    /// This method exists (rather than duplicating its body in each of those
    /// two methods) so that the CAWG X.509-specific status-code handling below
    /// is exercised by tests regardless of which of the two entry points they
    /// call.
    #[async_generic]
    fn check_x509_cose_signature(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<X509SignatureInfo, ValidationError<CoseError>> {
        if signer_payload.sig_type != super::CAWG_X509_SIG_TYPE {
            log_current_item!(
                "unsupported signature type",
                "X509SignatureVerifier::check_x509_cose_signature"
            )
            .validation_status("cawg.identity.sig_type.unknown")
            .failure_no_throw(
                status_tracker,
                ValidationError::<CoseError>::UnknownSignatureType(signer_payload.sig_type.clone()),
            );

            return Err(ValidationError::UnknownSignatureType(
                signer_payload.sig_type.clone(),
            ));
        }

        let mut signer_payload_cbor: Vec<u8> = vec![];
        c2pa_cbor::to_writer(&mut signer_payload_cbor, signer_payload)
            .map_err(|_| ValidationError::InternalError("CBOR serialization error".to_string()))?;

        let first_new_item = status_tracker.logged_items().len();

        let result = match parse_cose_sign1(signature, &signer_payload_cbor, status_tracker) {
            Ok(cose_sign1) => {
                let verify_result = if _sync {
                    self.cose_verifier.verify_signature(
                        signature,
                        &signer_payload_cbor,
                        &[],
                        None,
                        status_tracker,
                    )
                } else {
                    self.cose_verifier
                        .verify_signature_async(
                            signature,
                            &signer_payload_cbor,
                            &[],
                            None,
                            status_tracker,
                        )
                        .await
                };

                verify_result
                    .map_err(|e| match e {
                        CoseError::RawSignatureValidationError(
                            RawSignatureValidationError::SignatureMismatch,
                        ) => {
                            log_current_item!(
                                "signature mismatch",
                                "X509SignatureVerifier::check_x509_cose_signature"
                            )
                            .validation_status(CAWG_X509_SIGNATURE_MISMATCH)
                            .failure_no_throw(
                                status_tracker,
                                ValidationError::<CoseError>::SignatureMismatch,
                            );

                            ValidationError::SignatureMismatch
                        }

                        e => ValidationError::SignatureError(e),
                    })
                    .map(|cert_info| X509SignatureInfo {
                        signer_payload: signer_payload.clone(),
                        cose_sign1,
                        cert_info,
                    })
            }

            Err(e) => Err(e.into()),
        };

        super::remap_x509_cose_status_codes(status_tracker, first_new_item);

        if result.is_ok() {
            log_current_item!(
                "X.509 identity assertion signature validated",
                "X509SignatureVerifier::check_x509_cose_signature"
            )
            .validation_status(CAWG_X509_SIGNATURE_VALIDATED)
            .success(status_tracker);
        }

        result
    }
}

/// Contains information the X.509 certificate chain and the COSE signature that
/// was used to generate this identity assertion signature.
#[derive(Debug)]
pub struct X509SignatureInfo {
    /// The signer payload that was used to generate the signature.
    pub signer_payload: SignerPayload,

    /// Parsed COSE signature.
    pub cose_sign1: CoseSign1,

    /// Information about the X.509 certificate chain.
    pub cert_info: CertificateInfo,
}

impl ToCredentialSummary for X509SignatureInfo {
    type CredentialSummary = X509SignatureReport;

    fn to_summary(&self) -> Self::CredentialSummary {
        X509SignatureReport::from_x509_signature_info(self)
    }
}

// #[derive(Serialize)] <- uncomment once the type is populated
#[doc(hidden)]
#[derive(Serialize)]
pub struct X509SignatureReport {
    pub signer_payload: SignerPayload,
    pub signature_info: crate::SignatureInfo,
}

impl X509SignatureReport {
    fn from_x509_signature_info(info: &X509SignatureInfo) -> Self {
        X509SignatureReport {
            signer_payload: info.signer_payload.clone(),
            signature_info: crate::SignatureInfo {
                alg: info.cert_info.alg,
                issuer: info.cert_info.issuer_org.clone(),
                common_name: info.cert_info.common_name.clone(),
                time: info.cert_info.date.map(|d| d.to_rfc3339()),
                cert_serial_number: info
                    .cert_info
                    .cert_serial_number
                    .as_ref()
                    .map(|s| s.to_string()),
                cert_chain: String::from_utf8(info.cert_info.cert_chain.to_vec())
                    .unwrap_or_default(),
                revocation_status: info.cert_info.revocation_status,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::{
        borrow::Cow,
        io::{Cursor, Seek},
    };

    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{
        crypto::cose::{CertificateTrustPolicy, Verifier},
        identity::{
            builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
            tests::{
                fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
                read_manifest,
            },
            x509::{X509CredentialHolder, X509SignatureVerifier},
            IdentityAssertion, SignatureVerifier, ValidationError,
        },
        status_tracker::{LogKind, StatusTracker},
        validation_status::{
            CAWG_X509_CREDENTIAL_UNTRUSTED, CAWG_X509_SIGNATURE_MISMATCH,
            CAWG_X509_SIGNATURE_VALIDATED,
        },
        Builder, SigningAlg,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

    // NOTE: Success case is covered in tests for x509_credential_holder.rs.

    #[c2pa_test_async]
    async fn untrusted_cert() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::default().with_definition(manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let mut c2pa_signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let (cawg_cert_chain, cawg_private_key) =
            cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

        let cawg_raw_signer =
            c2pa_raw_crypto::signer_from_private_key(&cawg_private_key, SigningAlg::Ed25519)
                .unwrap();

        let x509_holder = X509CredentialHolder::from_raw_signer(
            cawg_raw_signer,
            crate::crypto::cert_chain_pem_to_der(&cawg_cert_chain).unwrap(),
        );
        let iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
        c2pa_signer.add_identity_assertion(iab);

        builder
            .sign(&c2pa_signer, format, &mut source, &mut dest)
            .unwrap();

        // Read back the Manifest that was generated.
        dest.rewind().unwrap();

        let manifest_store = read_manifest(format, &mut dest).await;
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        // While the identity assertion should be valid for this manifest,
        // the self-signed cert that we use in test configs is not on our
        // default trust list. Note that CertificateTrustPolicy::default
        // *includes* the test credential suite by default, which would sort
        // of defeat the purpose of this test. That's why we have to build
        // a non-default signature verifier.
        let mut ctp = CertificateTrustPolicy::new();
        ctp.add_default_valid_ekus();

        let cose_verifier = Verifier::VerifyTrustPolicy(Cow::Owned(ctp));

        let x509_verifier = X509SignatureVerifier { cose_verifier };

        let result = ia.validate(manifest, &mut st, &x509_verifier).await;
        // this should log an error but return Ok
        assert!(result.is_ok());

        assert_eq!(st.logged_items().len(), 2);

        let log = &st.logged_items()[0];
        assert_eq!(log.kind, LogKind::Failure);

        assert!(log.label.ends_with("/c2pa.assertions/cawg.identity"));
        assert_eq!(log.description, "signing certificate untrusted");

        assert_eq!(
            log.validation_status.as_ref().unwrap().as_ref() as &str,
            CAWG_X509_CREDENTIAL_UNTRUSTED
        );

        // The cryptographic signature itself is still valid, independent of
        // whether the signing certificate is trusted.
        let log = &st.logged_items()[1];
        assert_eq!(log.kind, LogKind::Success);

        assert!(log.label.ends_with("/c2pa.assertions/cawg.identity"));
        assert_eq!(
            log.description,
            "X.509 identity assertion signature validated"
        );

        assert_eq!(
            log.validation_status.as_ref().unwrap().as_ref() as &str,
            CAWG_X509_SIGNATURE_VALIDATED
        );

        // The sync `check_signature` entry point must behave identically to
        // `check_signature_async`.
        let mut sync_st = StatusTracker::default();
        let sync_result =
            x509_verifier.check_signature(&ia.signer_payload, &ia.signature, &mut sync_st);
        assert!(sync_result.is_ok());
        assert_eq!(sync_st.logged_items().len(), 2);
    }

    #[c2pa_test_async]
    async fn signature_mismatch() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::default().with_definition(manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let mut c2pa_signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let (cawg_cert_chain, cawg_private_key) =
            cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

        let cawg_raw_signer =
            c2pa_raw_crypto::signer_from_private_key(&cawg_private_key, SigningAlg::Ed25519)
                .unwrap();

        let x509_holder = X509CredentialHolder::from_raw_signer(
            cawg_raw_signer,
            crate::crypto::cert_chain_pem_to_der(&cawg_cert_chain).unwrap(),
        );
        let iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
        c2pa_signer.add_identity_assertion(iab);

        builder
            .sign(&c2pa_signer, format, &mut source, &mut dest)
            .unwrap();

        // Read back the Manifest that was generated.
        dest.rewind().unwrap();

        let manifest_store = read_manifest(format, &mut dest).await;
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        let x509_verifier = X509SignatureVerifier {
            cose_verifier: Verifier::IgnoreProfileAndTrustPolicy,
        };

        // Tamper with the signer payload (leaving the original signature bytes
        // untouched) so that the COSE signature no longer matches. This is a
        // syntactically valid `SignerPayload`, so it exercises a genuine
        // cryptographic mismatch rather than a CBOR parsing failure.
        let mut tampered_signer_payload = ia.signer_payload.clone();
        tampered_signer_payload.roles.push("tampered".to_string());

        let err = x509_verifier
            .check_signature_async(&tampered_signer_payload, &ia.signature, &mut st)
            .await
            .unwrap_err();

        assert!(matches!(err, ValidationError::SignatureMismatch));

        assert_eq!(st.logged_items().len(), 1);

        let log = &st.logged_items()[0];
        assert_eq!(log.kind, LogKind::Failure);
        assert_eq!(log.description, "signature mismatch");

        assert_eq!(
            log.validation_status.as_ref().unwrap().as_ref() as &str,
            CAWG_X509_SIGNATURE_MISMATCH
        );

        // The sync `check_signature` entry point must behave identically to
        // `check_signature_async`.
        let mut sync_st = StatusTracker::default();
        let sync_err = x509_verifier
            .check_signature(&tampered_signer_payload, &ia.signature, &mut sync_st)
            .unwrap_err();
        assert!(matches!(sync_err, ValidationError::SignatureMismatch));
        assert_eq!(sync_st.logged_items().len(), 1);

        // Signature bytes that don't even parse as a COSE_Sign1 structure must be
        // reported as a `SignatureError`, distinct from a cryptographic mismatch.
        let mut malformed_st = StatusTracker::default();
        let malformed_err = x509_verifier
            .check_signature_async(
                &ia.signer_payload,
                b"not a COSE_Sign1 structure",
                &mut malformed_st,
            )
            .await
            .unwrap_err();
        assert!(matches!(malformed_err, ValidationError::SignatureError(_)));
        assert_eq!(malformed_st.logged_items().len(), 1);
        assert_eq!(
            malformed_st.logged_items()[0]
                .validation_status
                .as_ref()
                .unwrap()
                .as_ref() as &str,
            CAWG_X509_SIGNATURE_MISMATCH
        );
    }
}
