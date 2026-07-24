// Copyright 2024 Adobe. All rights reserved.
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

#![deny(missing_docs)]

//! The `callback_signer` module provides a way to obtain a [`Signer`] or [`AsyncSigner`]
//! using a callback and public signing certificates.

use async_trait::async_trait;

use crate::{AsyncSigner, Error, Result, Signer, SigningAlg};

/// Defines a callback function interface for a [`CallbackSigner`].
///
/// The callback should return a signature for the given data.
/// The callback should return an error if the data cannot be signed.
pub type CallbackFunc =
    dyn Fn(*const (), &[u8]) -> std::result::Result<Vec<u8>, Error> + Send + Sync;

/// Defines a signer that uses a callback to sign data.
///
/// The private key should only be known by the callback.
pub struct CallbackSigner {
    /// An opaque context for the signer, used to store any necessary state.
    pub context: *const (),

    /// The callback to use to sign data.
    pub callback: Box<CallbackFunc>,

    /// The signing algorithm to use.
    pub alg: SigningAlg,

    /// The public certificates to use in PEM format.
    pub certs: Vec<u8>,

    /// A max size to reserve for the signature.
    pub reserve_size: usize,

    /// The optional URL of a Time Stamping Authority.
    pub tsa_url: Option<String>,
}

unsafe impl Send for CallbackSigner {}
unsafe impl Sync for CallbackSigner {}

impl CallbackSigner {
    /// Create a new callback signer.
    pub fn new<F, T>(callback: F, alg: SigningAlg, certs: T) -> Self
    where
        F: Fn(*const (), &[u8]) -> std::result::Result<Vec<u8>, Error> + Send + Sync + 'static,
        T: Into<Vec<u8>>,
    {
        let certs = certs.into();
        let reserve_size = 10000 + certs.len();

        Self {
            context: std::ptr::null(),
            callback: Box::new(callback),
            alg,
            certs,
            reserve_size,
            ..Default::default()
        }
    }

    /// Set a time stamping authority URL to call when signing.
    pub fn set_tsa_url<S: Into<String>>(mut self, url: S) -> Self {
        self.tsa_url = Some(url.into());
        self
    }

    /// Set a context value for the signer.
    ///
    /// This can be used to store any necessary state for the callback.
    /// Safety: The context must be valid for the lifetime of the signer.
    /// There is no Rust memory management for the context since it may also come from FFI.
    pub fn set_context(mut self, context: *const ()) -> Self {
        self.context = context;
        self
    }

    /// Sign data using an Ed25519 private key.
    /// This static function is provided for testing with [`CallbackSigner`].
    /// For a released product the private key should be stored securely.
    /// The signing should be done in a secure environment.
    /// The private key should not be exposed to the client.
    /// Example: (only for testing)
    /// ```
    /// use c2pa::{CallbackSigner, SigningAlg};
    ///
    /// const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
    /// const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
    ///
    /// let ed_signer =
    ///     |_context: *const _, data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    /// let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);
    /// ```
    pub fn ed25519_sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
        use ed25519_dalek::{Signature, Signer, SigningKey};
        use pem::parse;

        // Parse the PEM data to get the private key
        let pem = parse(private_key).map_err(|e| Error::OtherError(Box::new(e)))?;

        // For Ed25519, the key is 32 bytes long, so we skip the first 16 bytes of the PEM data
        let key_bytes = pem.contents().get(16..).ok_or(Error::InvalidSigningKey)?;
        let signing_key =
            SigningKey::try_from(key_bytes).map_err(|e| Error::OtherError(Box::new(e)))?;

        // Sign the data
        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

// This default is only intended for struct completion, do not use on its own.
impl Default for CallbackSigner {
    fn default() -> Self {
        Self {
            context: std::ptr::null(),
            callback: Box::new(|_, _| Err(Error::UnsupportedType)),
            alg: SigningAlg::Es256,
            certs: Vec::new(),
            reserve_size: 10000,
            tsa_url: None,
        }
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        (self.callback)(self.context, data)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let pems = pem::parse_many(&self.certs).map_err(|e| Error::OtherError(Box::new(e)))?;
        Ok(pems.into_iter().map(|p| p.into_contents()).collect())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AsyncSigner for CallbackSigner {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        (self.callback)(self.context, &data)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        let pems = pem::parse_many(&self.certs).map_err(|e| Error::OtherError(Box::new(e)))?;
        Ok(pems.into_iter().map(|p| p.into_contents()).collect())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{AsyncSigner, Signer, SigningAlg};

    const ED25519_CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
    const ED25519_PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

    fn make_ed25519_signer() -> CallbackSigner {
        let callback =
            |_ctx: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, ED25519_PRIVATE_KEY);
        CallbackSigner::new(callback, SigningAlg::Ed25519, ED25519_CERTS)
    }

    #[test]
    fn new_sets_expected_defaults() {
        let signer = make_ed25519_signer();
        assert_eq!(signer.alg, SigningAlg::Ed25519);
        assert_eq!(signer.tsa_url, None);
        assert!(signer.context.is_null());
        assert!(!signer.certs.is_empty());
        assert!(signer.reserve_size >= 10000);
    }

    #[test]
    fn set_tsa_url_stores_url() {
        let signer = make_ed25519_signer().set_tsa_url("http://timestamp.example.com");
        assert_eq!(
            signer.tsa_url,
            Some("http://timestamp.example.com".to_string())
        );
        assert_eq!(
            Signer::time_authority_url(&signer),
            Some("http://timestamp.example.com".to_string())
        );
    }

    #[test]
    fn set_context_stores_pointer() {
        let value: u32 = 42;
        let ptr = &value as *const u32 as *const ();
        let signer = make_ed25519_signer().set_context(ptr);
        assert_eq!(signer.context, ptr);
    }

    #[test]
    fn ed25519_sign_produces_valid_signature() {
        let data = b"test data to sign";
        let sig = CallbackSigner::ed25519_sign(data, ED25519_PRIVATE_KEY).unwrap();
        assert_eq!(sig.len(), 64); // Ed25519 signatures are always 64 bytes
    }

    #[test]
    fn signer_trait_sign_and_alg() {
        let signer = make_ed25519_signer();
        assert_eq!(Signer::alg(&signer), SigningAlg::Ed25519);
        let sig = Signer::sign(&signer, b"hello").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn signer_trait_certs_parses_pem() {
        let signer = make_ed25519_signer();
        let certs = Signer::certs(&signer).unwrap();
        assert!(!certs.is_empty());
    }

    #[test]
    fn signer_trait_reserve_size_is_reasonable() {
        let signer = make_ed25519_signer();
        assert!(Signer::reserve_size(&signer) >= 10000);
    }

    #[test]
    fn default_callback_returns_unsupported_type() {
        let signer = CallbackSigner::default();
        assert!(matches!(
            Signer::sign(&signer, b"data"),
            Err(crate::Error::UnsupportedType)
        ));
    }

    #[c2pa_test_async]
    async fn async_signer_sign_produces_same_result() {
        let signer = make_ed25519_signer();
        let data = b"async test data".to_vec();
        let sig = AsyncSigner::sign(&signer, data.clone()).await.unwrap();
        assert_eq!(sig.len(), 64);
        // Verify async and sync produce identical signatures (Ed25519 is deterministic)
        let sync_sig = Signer::sign(&signer, &data).unwrap();
        assert_eq!(sig, sync_sig);
    }

    #[c2pa_test_async]
    async fn async_signer_alg_and_certs_match_sync() {
        let signer = make_ed25519_signer();
        assert_eq!(AsyncSigner::alg(&signer), Signer::alg(&signer));
        assert_eq!(
            AsyncSigner::certs(&signer).unwrap(),
            Signer::certs(&signer).unwrap()
        );
        assert_eq!(
            AsyncSigner::reserve_size(&signer),
            Signer::reserve_size(&signer)
        );
        assert_eq!(
            AsyncSigner::time_authority_url(&signer),
            Signer::time_authority_url(&signer)
        );
    }
}
