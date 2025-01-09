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
    // identity_assertions: Vec<IdentityAssertionBuilder>,
}

impl IdentityAssertionSigner {
    /// Create an `IdentityAssertionSigner` wrapping the provided
    /// [`AsyncRawSigner`] instance.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new(signer: Box<dyn AsyncRawSigner + Sync + Send>) -> Self {
        Self { signer }
    }

    /// Create an `IdentityAssertionSigner` wrapping the provided
    /// [`AsyncRawSigner`] instance.
    #[cfg(target_arch = "wasm32")]
    pub fn new(signer: Box<dyn AsyncRawSigner>) -> Self {
        Self { signer }
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

    fn async_raw_signer(&self) -> Box<&dyn AsyncRawSigner> {
        Box::new(&*self.signer)
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        Vec::new()
    }
}
