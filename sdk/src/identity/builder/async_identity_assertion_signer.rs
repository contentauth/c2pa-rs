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

use crate::{
    crypto::raw_signature::SigningAlg, dynamic_assertion::AsyncDynamicAssertion,
    identity::builder::AsyncIdentityAssertionBuilder, AsyncSigner, Result,
};

/// An `AsyncIdentityAssertionSigner` extends the [`AsyncSigner`] interface to
/// add zero or more identity assertions to a C2PA [`Manifest`] that is being
/// produced.
///
/// [`AsyncSigner`]: crate::AsyncSigner
/// [`Manifest`]: crate::Manifest
pub struct AsyncIdentityAssertionSigner {
    #[cfg(not(target_arch = "wasm32"))]
    signer: Box<dyn AsyncSigner + Sync + Send>,

    #[cfg(target_arch = "wasm32")]
    signer: Box<dyn AsyncSigner>,

    identity_assertions: std::sync::RwLock<Vec<AsyncIdentityAssertionBuilder>>,
}

impl AsyncIdentityAssertionSigner {
    /// Create an `AsyncIdentityAssertionSigner` wrapping the provided
    /// [`AsyncSigner`] instance.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(signer: Box<dyn AsyncSigner + Sync + Send>) -> Self {
        Self {
            signer,
            identity_assertions: std::sync::RwLock::new(vec![]),
        }
    }

    /// Create an `AsyncIdentityAssertionSigner` wrapping the provided
    /// [`AsyncSigner`] instance.
    #[cfg(target_arch = "wasm32")]
    pub fn new(signer: Box<dyn AsyncSigner>) -> Self {
        Self {
            signer,
            identity_assertions: std::sync::RwLock::new(vec![]),
        }
    }

    /// (FOR USE BY INTERNAL TESTS ONLY): Create an AsyncIdentityAssertionSigner
    /// using test credentials for a particular algorithm.
    #[cfg(test)]
    pub(crate) fn from_test_credentials(alg: SigningAlg) -> Self {
        use crate::utils::test_signer::async_test_signer;

        #[allow(clippy::unwrap_used)]
        Self {
            signer: async_test_signer(alg),
            identity_assertions: std::sync::RwLock::new(vec![]),
        }
    }

    /// Add an [`AsyncIdentityAssertionBuilder`] to be used when signing the
    /// next [`Manifest`].
    ///
    /// IMPORTANT: When [`sign()`] is called, the list of
    /// [`AsyncIdentityAssertionBuilder`]s will be cleared.
    ///
    /// [`Manifest`]: crate::Manifest
    /// [`sign()`]: Self::sign
    pub fn add_identity_assertion(&mut self, iab: AsyncIdentityAssertionBuilder) {
        #[allow(clippy::unwrap_used)]
        let mut identity_assertions = self.identity_assertions.write().unwrap();
        // TO DO: Replace with error handling in the very unlikely case of a panic here.
        identity_assertions.push(iab);
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncSigner for AsyncIdentityAssertionSigner {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.signer.sign(data).await
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

    async fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.signer.ocsp_val().await
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

    async fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.signer.send_timestamp_request(message).await
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn AsyncDynamicAssertion>> {
        #[allow(clippy::unwrap_used)]
        let mut identity_assertions = self.identity_assertions.write().unwrap();
        // TO DO: Replace with error handling in the very unlikely case of a panic here.

        let ia_clone = identity_assertions.split_off(0);
        let mut dynamic_assertions: Vec<Box<dyn AsyncDynamicAssertion>> = vec![];

        for ia in ia_clone.into_iter() {
            dynamic_assertions.push(Box::new(ia));
        }

        dynamic_assertions
    }
}
