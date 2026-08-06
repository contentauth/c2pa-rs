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

use std::sync::{Arc, RwLock};

use c2pa_raw_crypto::{RawSigner, SigningAlg};

use crate::{
    crypto::cose::cose_reserve_size, dynamic_assertion::DynamicAssertion,
    identity::builder::IdentityAssertionBuilder, Result, Signer,
};

/// An `IdentityAssertionSigner` extends the [`Signer`] interface to add zero or
/// more identity assertions to a C2PA [`Manifest`] that is being produced.
///
/// [`Signer`]: crate::Signer
/// [`Manifest`]: crate::Manifest
pub struct IdentityAssertionSigner {
    signer: Box<dyn RawSigner + Send + Sync>,
    cert_chain: Vec<Vec<u8>>,
    identity_assertions: RwLock<Vec<Arc<IdentityAssertionBuilder>>>,
}

impl IdentityAssertionSigner {
    /// Create an `IdentityAssertionSigner` wrapping the provided [`RawSigner`]
    /// instance and its signing certificate chain (each certificate in DER
    /// form, end-entity first).
    pub fn new(signer: Box<dyn RawSigner + Send + Sync>, cert_chain: Vec<Vec<u8>>) -> Self {
        Self {
            signer,
            cert_chain,
            identity_assertions: RwLock::new(vec![]),
        }
    }

    /// (FOR USE BY INTERNAL TESTS ONLY): Create an IdentityAssertionSigner
    /// using test credentials for a particular algorithm.
    #[cfg(test)]
    pub(crate) fn from_test_credentials(alg: SigningAlg) -> Self {
        use c2pa_raw_crypto::signer_from_private_key;

        use crate::{
            crypto::cert_chain_pem_to_der,
            identity::tests::fixtures::cert_chain_and_private_key_for_alg,
        };

        let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

        #[allow(clippy::unwrap_used)]
        Self {
            signer: signer_from_private_key(&private_key, alg).unwrap(),
            cert_chain: cert_chain_pem_to_der(&cert_chain).unwrap(),
            identity_assertions: RwLock::new(vec![]),
        }
    }

    /// Add an [`IdentityAssertionBuilder`] to be used when signing the
    /// next [`Manifest`].
    ///
    /// The registered assertions are retained after signing so that the same
    /// signer can be used across every signing path, including the split
    /// signing paths ([`Builder::placeholder`] + [`Builder::sign_embeddable`])
    /// that query [`dynamic_assertions()`] more than once per manifest.
    ///
    /// [`Manifest`]: crate::Manifest
    /// [`Builder::placeholder`]: crate::Builder::placeholder
    /// [`Builder::sign_embeddable`]: crate::Builder::sign_embeddable
    /// [`dynamic_assertions()`]: Signer::dynamic_assertions
    pub fn add_identity_assertion(&mut self, iab: IdentityAssertionBuilder) {
        #[allow(clippy::unwrap_used)]
        let mut identity_assertions = self.identity_assertions.write().unwrap();
        // TO DO: Replace with error handling in the very unlikely case of a panic here.

        identity_assertions.push(Arc::new(iab));
    }
}

impl Signer for IdentityAssertionSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.signer.sign(data).map_err(|e| e.into())
    }

    fn alg(&self) -> SigningAlg {
        self.signer.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.cert_chain.clone())
    }

    fn reserve_size(&self) -> usize {
        cose_reserve_size(
            self.signer.max_signature_size(),
            &self.cert_chain,
            false,
            None,
        )
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        #[allow(clippy::unwrap_used)]
        let identity_assertions = self.identity_assertions.read().unwrap();
        // TO DO: Replace with error handling in the very unlikely case of a panic here.

        // Hand out shared clones instead of draining the list. Several signing
        // paths (notably `Builder::placeholder` + `Builder::sign_embeddable`)
        // call this method more than once per manifest – once to reserve
        // placeholder slots and again to write the assertion content. Draining
        // on the first call left later calls empty, which silently dropped the
        // identity assertion (see issue #2055).
        identity_assertions
            .iter()
            .map(|ia| Box::new(Arc::clone(ia)) as Box<dyn DynamicAssertion>)
            .collect()
    }
}
