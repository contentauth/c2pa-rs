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

use std::sync::RwLock;

use crate::{
    crypto::raw_signature::SigningAlg,
    dynamic_assertion::DynamicAssertion,
    identity::{builder::IdentityAssertionBuilder, x509::X509CredentialHolder},
    signer::BoxedSigner,
    Result, Signer,
};

/// An `IdentityAssertionSigner` extends the [`Signer`] interface to add zero or
/// more identity assertions to a C2PA [`Manifest`] that is being produced.
///
/// [`Signer`]: crate::Signer
/// [`Manifest`]: crate::Manifest
pub struct IdentityAssertionSigner {
    signer: BoxedSigner,
    identity_assertions: RwLock<Vec<IdentityAssertionBuilder>>,
}

impl IdentityAssertionSigner {
    /// Create an `IdentityAssertionSigner` wrapping the provided [`Signer`]
    /// instance.
    pub fn new(signer: BoxedSigner) -> Self {
        Self {
            signer,
            identity_assertions: RwLock::new(vec![]),
        }
    }

    /// Create an `IdentityAssertionSigner` that embeds a single X.509 identity assertion
    /// (sig type `cawg.x509.cose`) into every manifest it signs.
    ///
    /// # Parameters
    /// * `c2pa_signer` — used to sign the C2PA claim.
    /// * `identity_signer` — used to sign the X.509 identity assertion.
    /// * `referenced_assertions` — assertion labels to include in the identity assertion's
    ///   `referenced_assertions` list. Pass an empty slice to include none.
    /// * `roles` — named actor roles to attach to the identity assertion. Pass an empty slice
    ///   to include none.
    pub fn with_x509_identity(
        c2pa_signer: BoxedSigner,
        identity_signer: BoxedSigner,
        referenced_assertions: &[&str],
        roles: &[&str],
    ) -> Self {
        let x509_holder = X509CredentialHolder::from_signer(identity_signer);
        let mut iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
        if !referenced_assertions.is_empty() {
            iab.add_referenced_assertions(referenced_assertions);
        }
        if !roles.is_empty() {
            iab.add_roles(roles);
        }
        let mut signer = Self::new(c2pa_signer);
        signer.add_identity_assertion(iab);
        signer
    }

    /// (FOR USE BY INTERNAL TESTS ONLY): Create an IdentityAssertionSigner
    /// using test credentials for a particular algorithm.
    #[cfg(test)]
    pub(crate) fn from_test_credentials(alg: SigningAlg) -> Self {
        use crate::utils::test_signer::test_signer;

        Self {
            signer: test_signer(alg),
            identity_assertions: RwLock::new(vec![]),
        }
    }

    /// Add an [`IdentityAssertionBuilder`] to be used when signing the
    /// next [`Manifest`].
    ///
    /// IMPORTANT: When [`sign()`] is called, the list of
    /// [`IdentityAssertionBuilder`]s will be cleared.
    ///
    /// [`Manifest`]: crate::Manifest
    /// [`sign()`]: Self::sign
    pub fn add_identity_assertion(&mut self, iab: IdentityAssertionBuilder) {
        #[allow(clippy::unwrap_used)]
        let mut identity_assertions = self.identity_assertions.write().unwrap();
        // TO DO: Replace with error handling in the very unlikely case of a panic here.

        identity_assertions.push(iab);
    }
}

impl Signer for IdentityAssertionSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.signer.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.signer.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.signer.certs()
    }

    fn reserve_size(&self) -> usize {
        self.signer.reserve_size()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.signer.ocsp_val()
    }

    fn time_authority_url(&self) -> Option<String> {
        self.signer.time_authority_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.signer.timestamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signer.timestamp_request_body(message)
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.signer.send_timestamp_request(message)
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        #[allow(clippy::unwrap_used)]
        let mut identity_assertions = self.identity_assertions.write().unwrap();
        // TO DO: Replace with error handling in the very unlikely case of a panic here.

        let ia_clone = identity_assertions.split_off(0);
        let mut dynamic_assertions: Vec<Box<dyn DynamicAssertion>> = vec![];

        for ia in ia_clone.into_iter() {
            dynamic_assertions.push(Box::new(ia));
        }

        dynamic_assertions
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        crypto::cose::Verifier,
        identity::{
            tests::fixtures::{manifest_json, parent_json},
            x509::X509SignatureVerifier,
            IdentityAssertion,
        },
        status_tracker::StatusTracker,
        utils::test_signer::test_signer,
        Builder, Reader,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

    /// Verify that `with_x509_identity` produces a valid manifest containing
    /// one X.509 identity assertion signed by the CAWG (identity) signer and
    /// one valid C2PA claim signed by the C2PA signer.
    #[c2pa_test_async]
    async fn with_x509_identity_signs_and_validates() {
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

        // Two separate signers: one for the C2PA claim, one for the X.509
        // identity assertion.
        let c2pa_signer = test_signer(SigningAlg::Ps256);
        let identity_signer = test_signer(SigningAlg::Ed25519);

        let signer = IdentityAssertionSigner::with_x509_identity(
            c2pa_signer,
            identity_signer,
            &["c2pa.actions"],
            &[],
        );

        builder
            .sign(&signer, format, &mut source, &mut dest)
            .unwrap();

        // ── Validation ────────────────────────────────────────────────────
        dest.rewind().unwrap();

        let manifest_store = Reader::default().with_stream(format, &mut dest).unwrap();
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        let label = ia.label.as_ref().unwrap();
        assert!(label.ends_with("cawg.identity"));
        assert!(label.contains("/c2pa.assertions/"));

        // The identity assertion must validate with X.509 verification.
        let x509_verifier = X509SignatureVerifier {
            cose_verifier: Verifier::IgnoreProfileAndTrustPolicy,
        };
        let sig_info = ia
            .validate(manifest, &mut st, &x509_verifier)
            .await
            .unwrap();

        // The identity assertion was signed with Ed25519.
        assert_eq!(sig_info.cert_info.alg.unwrap(), SigningAlg::Ed25519);
    }
}
