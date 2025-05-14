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

use async_trait::async_trait;
use c2pa_crypto::{
    cose::{sign_async, TimeStampStorage},
    raw_signature::AsyncRawSigner,
};

use crate::identity::{
    builder::{AsyncCredentialHolder, IdentityBuilderError},
    SignerPayload,
};

/// An implementation of [`AsyncCredentialHolder`] that generates COSE
/// signatures using X.509 credentials as specified in [§8.2, X.509 certificates
/// and COSE signatures].
///
/// [`SignatureVerifier`]: crate::identity::SignatureVerifier
/// [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.1-draft/#_x_509_certificates_and_cose_signatures
#[cfg(not(target_arch = "wasm32"))]
pub struct AsyncX509CredentialHolder(Box<dyn AsyncRawSigner + Send + Sync + 'static>);

/// An implementation of [`AsyncCredentialHolder`] that generates COSE
/// signatures using X.509 credentials as specified in [§8.2, X.509 certificates
/// and COSE signatures].
///
/// [`AsyncCredentialHolder`]: crate::identity::builder::AsyncCredentialHolder
/// [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.1-draft/#_x_509_certificates_and_cose_signatures
#[cfg(target_arch = "wasm32")]
pub struct AsyncX509CredentialHolder(Box<dyn AsyncRawSigner + 'static>);

impl AsyncX509CredentialHolder {
    /// Create an `AsyncX509CredentialHolder` instance by wrapping an instance
    /// of [`AsyncRawSigner`].
    ///
    /// The [`AsyncRawSigner`] implementation actually holds (or has access to)
    /// the relevant certificates and private key material.
    ///
    /// [`AsyncRawSigner`]: c2pa_crypto::raw_signature::AsyncRawSigner
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_async_raw_signer(signer: Box<dyn AsyncRawSigner + Send + Sync + 'static>) -> Self {
        Self(signer)
    }

    /// Create an `AsyncX509CredentialHolder` instance by wrapping an instance
    /// of [`AsyncRawSigner`].
    ///
    /// The [`AsyncRawSigner`] implementation actually holds (or has access to)
    /// the relevant certificates and private key material.
    ///
    /// [`AsyncRawSigner`]: c2pa_crypto::raw_signature::AsyncRawSigner
    #[cfg(target_arch = "wasm32")]
    pub fn from_async_raw_signer(signer: Box<dyn AsyncRawSigner + 'static>) -> Self {
        Self(signer)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncCredentialHolder for AsyncX509CredentialHolder {
    fn sig_type(&self) -> &'static str {
        super::CAWG_X509_SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        // TO DO: Check signing cert (see signing_cert_valid in c2pa-rs's cose_sign).

        let mut sp_cbor: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut sp_cbor)
            .map_err(|e| IdentityBuilderError::CborGenerationError(e.to_string()))?;

        Ok(sign_async(
            self.0.as_ref(),
            &sp_cbor,
            None,
            TimeStampStorage::V2_sigTst2_CTT,
        )
        .await
        .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use c2pa_crypto::raw_signature;
    use c2pa_status_tracker::StatusTracker;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{
        identity::{
            builder::{AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner},
            tests::fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
            x509::{AsyncX509CredentialHolder, X509SignatureVerifier},
            IdentityAssertion,
        },
        Builder, Reader, SigningAlg,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

    #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn simple_case_async() {
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let mut builder = Builder::from_json(&manifest_json()).unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();

        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        let mut c2pa_signer =
            AsyncIdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let (cawg_cert_chain, cawg_private_key) =
            cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

        let cawg_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
            &cawg_cert_chain,
            &cawg_private_key,
            SigningAlg::Ed25519,
            None,
        )
        .unwrap();

        let x509_holder = AsyncX509CredentialHolder::from_async_raw_signer(cawg_raw_signer);
        let iab = AsyncIdentityAssertionBuilder::for_credential_holder(x509_holder);
        c2pa_signer.add_identity_assertion(iab);

        builder
            .sign_async(&c2pa_signer, format, &mut source, &mut dest)
            .await
            .unwrap();

        // Read back the Manifest that was generated.
        dest.rewind().unwrap();

        let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        // And that identity assertion should be valid for this manifest.
        let x509_verifier = X509SignatureVerifier {};
        let sig_info = ia
            .validate(manifest, &mut st, &x509_verifier)
            .await
            .unwrap();

        let cert_info = &sig_info.cert_info;
        assert_eq!(cert_info.alg.unwrap(), SigningAlg::Ed25519);
        assert_eq!(
            cert_info.issuer_org.as_ref().unwrap(),
            "C2PA Test Signing Cert"
        );

        // TO DO: Not sure what to check from COSE_Sign1.
    }
}
