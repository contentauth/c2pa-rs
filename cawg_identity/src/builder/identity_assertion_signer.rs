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
use c2pa::{AsyncSigner, DynamicAssertion, Result};
use c2pa_crypto::raw_signature::{AsyncRawSigner, SigningAlg};

use super::CredentialHolder;
use crate::builder::IdentityAssertionBuilder;

/// An `IdentityAssertionSigner` extends the [`AsyncSigner`] interface to add
/// zero or more identity assertions to a C2PA [`Manifest`] that is being
/// produced.
///
/// [`AsyncSigner`]: c2pa::AsyncSigner
/// [`Manifest`]: c2pa::Manifest
pub struct IdentityAssertionSigner {
    #[cfg(not(target_arch = "wasm32"))]
    signer: Box<dyn AsyncRawSigner + Sync + Send>,

    #[cfg(target_arch = "wasm32")]
    signer: Box<dyn AsyncRawSigner>,

    #[cfg(not(target_arch = "wasm32"))]
    identity_assertions: std::sync::RwLock<Vec<Box<dyn DynamicAssertion + Send + Sync + 'static>>>,

    #[cfg(target_arch = "wasm32")]
    identity_assertions: std::cell::RefCell<Vec<Box<dyn DynamicAssertion>>>,
}

impl IdentityAssertionSigner {
    /// Create an `IdentityAssertionSigner` wrapping the provided
    /// [`AsyncRawSigner`] instance.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(signer: Box<dyn AsyncRawSigner + Sync + Send>) -> Self {
        Self {
            signer,
            identity_assertions: Self::ia_default(),
        }
    }

    /// Create an `IdentityAssertionSigner` wrapping the provided
    /// [`AsyncRawSigner`] instance.
    #[cfg(target_arch = "wasm32")]
    pub fn new(signer: Box<dyn AsyncRawSigner>) -> Self {
        Self {
            signer,
            identity_assertions: Self::ia_default(),
        }
    }

    /// (FOR USE BY INTERNAL TESTS ONLY): Create an IdentityAssertionSigner
    /// using test credentials for a particular algorithm.
    #[cfg(test)]
    pub(crate) fn from_test_credentials(alg: SigningAlg) -> Self {
        use c2pa_crypto::raw_signature::async_signer_from_cert_chain_and_private_key;

        use crate::tests::fixtures::cert_chain_and_private_key_for_alg;

        let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

        #[allow(clippy::unwrap_used)]
        Self {
            signer: async_signer_from_cert_chain_and_private_key(
                &cert_chain,
                &private_key,
                alg,
                None,
            )
            .unwrap(),
            identity_assertions: Self::ia_default(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn ia_default() -> std::sync::RwLock<Vec<Box<dyn DynamicAssertion + Send + Sync + 'static>>> {
        std::sync::RwLock::new(vec![])
    }

    #[cfg(target_arch = "wasm32")]
    fn ia_default() -> std::cell::RefCell<Vec<Box<dyn DynamicAssertion>>> {
        std::cell::RefCell::new(vec![])
    }

    /// Add an [`IdentityAssertionBuilder`] to be used when signing the next
    /// [`Manifest`].
    ///
    /// IMPORTANT: When [`sign()`] is called, the list of
    /// [`IdentityAssertionBuilder`]s will be cleared.
    ///
    /// [`Manifest`]: c2pa::Manifest
    /// [`sign()`]: Self::sign
    pub fn add_identity_assertion<CH: CredentialHolder + 'static>(
        &mut self,
        iab: IdentityAssertionBuilder<CH>,
    ) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            #[allow(clippy::unwrap_used)]
            let mut identity_assertions = self.identity_assertions.write().unwrap();
            // TO DO: Replace with error handling in the very unlikely case of a panic here.
            identity_assertions.push(Box::new(iab));
        }

        #[cfg(target_arch = "wasm32")]
        {
            #[allow(clippy::unwrap_used)]
            let mut identity_assertions = self.identity_assertions.try_borrow_mut().unwrap();
            // TO DO: Replace with error handling in the very unlikely case of a panic here.
            identity_assertions.push(Box::new(iab));
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncSigner for IdentityAssertionSigner {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        self.signer.sign(data).await.map_err(|e| e.into())
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

    async fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.signer.ocsp_response().await
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

    async fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.signer
            .send_time_stamp_request(message)
            .await
            .map(|r| r.map_err(|e| e.into()))
    }

    fn async_raw_signer(&self) -> Option<Box<&dyn AsyncRawSigner>> {
        Some(Box::new(&*self.signer))
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            #[allow(clippy::unwrap_used)]
            let mut identity_assertions = self.identity_assertions.write().unwrap();
            // TO DO: Replace with error handling in the very unlikely case of a panic here.

            let ia_clone = identity_assertions.split_off(0);
            let mut dynamic_assertions: Vec<Box<dyn DynamicAssertion>> = vec![];

            for ia in ia_clone.into_iter() {
                dynamic_assertions.push(ia);
            }

            dynamic_assertions
        }

        #[cfg(target_arch = "wasm32")]
        {
            #[allow(clippy::unwrap_used)]
            let mut identity_assertions = self.identity_assertions.try_borrow_mut().unwrap();
            // TO DO: Replace with error handling in the very unlikely case of a panic here.

            let ia_clone = identity_assertions.split_off(0);
            let mut dynamic_assertions: Vec<Box<dyn DynamicAssertion>> = vec![];

            for ia in ia_clone.into_iter() {
                dynamic_assertions.push(Box::new(ia));
            }

            dynamic_assertions
        }
    }
}
