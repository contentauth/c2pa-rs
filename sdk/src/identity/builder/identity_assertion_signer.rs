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

use crate::{
    crypto::raw_signature::{RawSigner, SigningAlg},
    dynamic_assertion::DynamicAssertion,
    identity::builder::IdentityAssertionBuilder,
    Result, Signer,
};

/// An `IdentityAssertionSigner` extends the [`Signer`] interface to add zero or
/// more identity assertions to a C2PA [`Manifest`] that is being produced.
///
/// [`Signer`]: crate::Signer
/// [`Manifest`]: crate::Manifest
pub struct IdentityAssertionSigner {
    signer: Box<dyn RawSigner + Send + Sync>,
    identity_assertions: RwLock<Vec<Arc<IdentityAssertionBuilder>>>,
}

impl IdentityAssertionSigner {
    /// Create an `IdentityAssertionSigner` wrapping the provided [`RawSigner`]
    /// instance.
    pub fn new(signer: Box<dyn RawSigner + Send + Sync>) -> Self {
        Self {
            signer,
            identity_assertions: RwLock::new(vec![]),
        }
    }

    /// (FOR USE BY INTERNAL TESTS ONLY): Create an IdentityAssertionSigner
    /// using test credentials for a particular algorithm.
    #[cfg(test)]
    pub(crate) fn from_test_credentials(alg: SigningAlg) -> Self {
        use crate::{
            crypto::raw_signature::signer_from_cert_chain_and_private_key,
            identity::tests::fixtures::cert_chain_and_private_key_for_alg,
        };

        let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

        #[allow(clippy::unwrap_used)]
        Self {
            signer: signer_from_cert_chain_and_private_key(&cert_chain, &private_key, alg, None)
                .unwrap(),
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
        self.signer.cert_chain().map_err(|e| e.into())
    }

    fn reserve_size(&self) -> usize {
        self.signer.reserve_size()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.signer.ocsp_response()
    }

    fn time_authority_url(&self) -> Option<String> {
        self.signer.time_stamp_service_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.signer.time_stamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signer
            .time_stamp_request_body(message)
            .map_err(|e| e.into())
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.signer
            .send_time_stamp_request(message)
            .map(|r| r.map_err(|e| e.into()))
    }

    fn raw_signer(&self) -> Option<Box<&dyn RawSigner>> {
        Some(Box::new(&*self.signer))
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
