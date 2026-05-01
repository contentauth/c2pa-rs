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
    crypto::raw_signature::SigningAlg, dynamic_assertion::DynamicAssertion,
    identity::{builder::IdentityAssertionBuilder, x509::X509CredentialHolder},
    signer::BoxedSigner, Result, Signer,
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

    /// Create an `IdentityAssertionSigner` that embeds a single CAWG X.509 identity assertion
    /// (sig type `cawg.x509.cose`) into every manifest it signs.
    ///
    /// # Parameters
    /// * `c2pa_signer` — used to sign the C2PA claim.
    /// * `cawg_signer` — used to sign the CAWG identity assertion.
    /// * `referenced_assertions` — assertion labels to include in the identity assertion's
    ///   `referenced_assertions` list. Pass an empty slice to include none.
    /// * `roles` — named actor roles to attach to the identity assertion. Pass an empty slice
    ///   to include none.
    pub fn from_cawg_x509(
        c2pa_signer: BoxedSigner,
        cawg_signer: BoxedSigner,
        referenced_assertions: &[&str],
        roles: &[&str],
    ) -> Self {
        let x509_holder = X509CredentialHolder::from_signer(cawg_signer);
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
