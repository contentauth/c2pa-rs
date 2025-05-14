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

use c2pa_crypto::{
    cose::{sign, TimeStampStorage},
    raw_signature::RawSigner,
};

use crate::identity::{
    builder::{CredentialHolder, IdentityBuilderError},
    SignerPayload,
};

/// An implementation of [`CredentialHolder`] that generates COSE signatures
/// using X.509 credentials as specified in [§8.2, X.509 certificates and COSE
/// signatures].
///
/// [`SignatureVerifier`]: crate::identity::SignatureVerifier
/// [§8.2, X.509 certificates and COSE signatures]: https://cawg.io/identity/1.1-draft/#_x_509_certificates_and_cose_signatures
pub struct X509CredentialHolder(Box<dyn RawSigner + Sync + Send + 'static>);

impl X509CredentialHolder {
    /// Create an `X509CredentialHolder` instance by wrapping an instance of
    /// [`RawSigner`].
    ///
    /// The [`RawSigner`] implementation actually holds (or has access to)
    /// the relevant certificates and private key material.
    ///
    /// [`RawSigner`]: c2pa_crypto::raw_signature::RawSigner
    pub fn from_raw_signer(signer: Box<dyn RawSigner + Sync + Send + 'static>) -> Self {
        Self(signer)
    }
}

impl CredentialHolder for X509CredentialHolder {
    fn sig_type(&self) -> &'static str {
        super::CAWG_X509_SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        // TO DO: Check signing cert (see signing_cert_valid in c2pa-rs's cose_sign).

        let mut sp_cbor: Vec<u8> = vec![];
        ciborium::into_writer(signer_payload, &mut sp_cbor)
            .map_err(|e| IdentityBuilderError::CborGenerationError(e.to_string()))?;

        sign(
            self.0.as_ref(),
            &sp_cbor,
            None,
            TimeStampStorage::V2_sigTst2_CTT,
        )
        .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))
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
            builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
            tests::fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
            x509::{X509CredentialHolder, X509SignatureVerifier},
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
    async fn simple_case() {
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

        let mut c2pa_signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let (cawg_cert_chain, cawg_private_key) =
            cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

        let cawg_raw_signer = raw_signature::signer_from_cert_chain_and_private_key(
            &cawg_cert_chain,
            &cawg_private_key,
            SigningAlg::Ed25519,
            None,
        )
        .unwrap();

        let x509_holder = X509CredentialHolder::from_raw_signer(cawg_raw_signer);
        let iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
        c2pa_signer.add_identity_assertion(iab);

        builder
            .sign(&c2pa_signer, format, &mut source, &mut dest)
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
