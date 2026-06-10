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
    identity_assertions: RwLock<Vec<IdentityAssertionBuilder>>,
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
