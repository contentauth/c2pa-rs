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

use crate::{
    crypto::raw_signature::{cose_reserve_size, SigningAlg, TIMESTAMP_RESERVE},
    AsyncSigner, Error, Result, Signer,
};

/// Defines a callback function interface for a [`CallbackSigner`].
///
/// The callback should return a signature for the given data.
/// The callback should return an error if the data cannot be signed.
pub type CallbackFunc =
    dyn Fn(*const (), &[u8]) -> std::result::Result<Vec<u8>, Error> + Send + Sync;

/// Defines a callback function interface for timestamp requests in a [`CallbackSigner`].
///
/// The callback receives the message hash and should return a raw RFC 3161
/// timestamp token as bytes, or an error if the request fails.
///
/// Use this when the timestamp service call should be owned by the signer
/// (e.g., in a subprocess or KMS integration) rather than by the SDK.
pub type TimestampFunc =
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

    /// An optional callback that performs the timestamp request.
    ///
    /// When set, this callback is called instead of the SDK's built-in HTTP
    /// request to [`Self::tsa_url`].  Use it when the signer owns the TSA
    /// call — for example, in a subprocess or KMS integration.
    timestamp_callback: Option<Box<TimestampFunc>>,

    /// Caller-supplied byte allowance for the timestamp token.
    ///
    /// When `None`, [`TIMESTAMP_RESERVE`] is used as the default.  Set this
    /// via [`Self::set_timestamp_size`] when your TSA consistently returns
    /// tokens larger or smaller than the default.
    timestamp_size: Option<usize>,
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
        let reserve_size = cose_reserve_size(alg, &certs, 0).unwrap_or(10000 + certs.len());

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
    ///
    /// This also increases [`Self::reserve_size`] to accommodate the estimated
    /// timestamp token size ([`TIMESTAMP_RESERVE`]).
    pub fn set_tsa_url<S: Into<String>>(mut self, url: S) -> Self {
        self.tsa_url = Some(url.into());
        self.update_reserve_size();
        self
    }

    /// Set a callback that performs the RFC 3161 timestamp request.
    ///
    /// When set, the callback is called with the message hash and must return
    /// the raw timestamp token bytes.  This takes priority over
    /// [`Self::tsa_url`]: if both are set, the callback is used.
    ///
    /// This also increases [`Self::reserve_size`] to accommodate the estimated
    /// timestamp token size ([`TIMESTAMP_RESERVE`]).
    pub fn set_timestamp_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(*const (), &[u8]) -> std::result::Result<Vec<u8>, Error> + Send + Sync + 'static,
    {
        self.timestamp_callback = Some(Box::new(callback));
        self.update_reserve_size();
        self
    }

    /// Override the byte allowance reserved for the timestamp token.
    ///
    /// By default [`TIMESTAMP_RESERVE`] is used when a TSA URL or timestamp
    /// callback is configured.  Call this when your TSA consistently returns
    /// tokens that are larger or smaller than that default.
    ///
    /// Has no effect on `reserve_size` when no timestamp mechanism is
    /// configured; the preference is stored and applied if one is added later.
    pub fn set_timestamp_size(mut self, size: usize) -> Self {
        self.timestamp_size = Some(size);
        self.update_reserve_size();
        self
    }

    /// Recomputes `reserve_size` based on current alg, certs, and whether any
    /// timestamp mechanism (URL or callback) is configured.
    fn update_reserve_size(&mut self) {
        let ts_len = if self.tsa_url.is_some() || self.timestamp_callback.is_some() {
            self.timestamp_size.unwrap_or(TIMESTAMP_RESERVE)
        } else {
            0
        };
        self.reserve_size = cose_reserve_size(self.alg, &self.certs, ts_len)
            .unwrap_or(10000 + self.certs.len() + ts_len);
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
            timestamp_callback: None,
            timestamp_size: None,
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

    // TODO: consider threading the caller's resolver through here instead of
    // constructing a new one; follow up once resolver plumbing is stabilised.
    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        if let Some(ref callback) = self.timestamp_callback {
            return Some(callback(self.context, message));
        }
        if let Some(url) = Signer::time_authority_url(self) {
            if let Ok(body) = Signer::timestamp_request_body(self, message) {
                let headers = Signer::timestamp_request_headers(self);
                return Some(
                    crate::crypto::time_stamp::default_rfc3161_request(
                        &url,
                        headers,
                        &body,
                        message,
                        &crate::http::SyncGenericResolver::with_redirects().unwrap_or_default(),
                    )
                    .map_err(|e| e.into()),
                );
            }
        }
        None
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

    async fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        if let Some(ref callback) = self.timestamp_callback {
            return Some(callback(self.context, message));
        }
        if let Some(url) = AsyncSigner::time_authority_url(self) {
            if let Ok(body) = AsyncSigner::timestamp_request_body(self, message) {
                use crate::http::AsyncGenericResolver;
                let headers = AsyncSigner::timestamp_request_headers(self);
                return Some(
                    crate::crypto::time_stamp::default_rfc3161_request_async(
                        &url,
                        headers,
                        &body,
                        message,
                        &AsyncGenericResolver::with_redirects().unwrap_or_default(),
                    )
                    .await
                    .map_err(|e| e.into()),
                );
            }
        }
        None
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
        use crate::crypto::raw_signature::cose_reserve_size;
        let signer = make_ed25519_signer();
        assert_eq!(signer.alg, SigningAlg::Ed25519);
        assert_eq!(signer.tsa_url, None);
        assert!(signer.context.is_null());
        assert!(!signer.certs.is_empty());
        // reserve_size is now computed exactly from alg + cert, not a fixed estimate
        let expected = cose_reserve_size(SigningAlg::Ed25519, ED25519_CERTS, 0).unwrap();
        assert_eq!(signer.reserve_size, expected);
        assert!(signer.reserve_size > 0);
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
    fn new_uses_exact_cose_reserve_size() {
        use crate::crypto::raw_signature::{cert_chain_der_len, cose_reserve_size, COSE_OVERHEAD};
        let signer = make_ed25519_signer();
        let expected = cose_reserve_size(SigningAlg::Ed25519, ED25519_CERTS, 0).unwrap();
        assert_eq!(Signer::reserve_size(&signer), expected);
        // Verify it is COSE_OVERHEAD + 64 (Ed25519 sig) + DER cert bytes
        assert_eq!(
            expected,
            COSE_OVERHEAD + 64 + cert_chain_der_len(ED25519_CERTS)
        );
    }

    #[test]
    fn set_tsa_url_increases_reserve_size() {
        use crate::crypto::raw_signature::{cose_reserve_size, TIMESTAMP_RESERVE};
        let base = make_ed25519_signer();
        let base_reserve = Signer::reserve_size(&base);
        let with_tsa = base.set_tsa_url("http://timestamp.example.com");
        let expected =
            cose_reserve_size(SigningAlg::Ed25519, ED25519_CERTS, TIMESTAMP_RESERVE).unwrap();
        assert_eq!(Signer::reserve_size(&with_tsa), expected);
        assert!(Signer::reserve_size(&with_tsa) > base_reserve);
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

    #[test]
    fn set_timestamp_callback_increases_reserve_size() {
        use crate::crypto::raw_signature::{cose_reserve_size, TIMESTAMP_RESERVE};
        let base = make_ed25519_signer();
        let base_reserve = Signer::reserve_size(&base);
        let with_cb = base.set_timestamp_callback(|_, _| Ok(vec![0u8; 32]));
        let expected =
            cose_reserve_size(SigningAlg::Ed25519, ED25519_CERTS, TIMESTAMP_RESERVE).unwrap();
        assert_eq!(Signer::reserve_size(&with_cb), expected);
        assert!(Signer::reserve_size(&with_cb) > base_reserve);
    }

    #[test]
    fn timestamp_callback_is_called_via_send_timestamp_request() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();
        let signer = make_ed25519_signer().set_timestamp_callback(move |_, _data| {
            called_clone.store(true, Ordering::SeqCst);
            Ok(b"fake-timestamp-token".to_vec())
        });
        let result = Signer::send_timestamp_request(&signer, b"message-hash");
        assert!(called.load(Ordering::SeqCst), "callback was not called");
        assert!(result.is_some());
        assert_eq!(result.unwrap().unwrap(), b"fake-timestamp-token");
    }

    #[test]
    fn no_timestamp_send_request_returns_none_without_url_or_callback() {
        let signer = make_ed25519_signer();
        assert!(Signer::send_timestamp_request(&signer, b"msg").is_none());
    }

    #[test]
    fn set_timestamp_size_overrides_default_reserve() {
        use crate::crypto::raw_signature::{cert_chain_der_len, cose_reserve_size, COSE_OVERHEAD};
        let custom_ts_size = 12_000usize;
        let signer = make_ed25519_signer()
            .set_tsa_url("http://timestamp.example.com")
            .set_timestamp_size(custom_ts_size);
        let expected =
            cose_reserve_size(SigningAlg::Ed25519, ED25519_CERTS, custom_ts_size).unwrap();
        assert_eq!(Signer::reserve_size(&signer), expected);
        assert_eq!(
            expected,
            COSE_OVERHEAD + 64 + cert_chain_der_len(ED25519_CERTS) + custom_ts_size
        );
    }

    #[test]
    fn set_timestamp_size_without_tsa_does_not_inflate_reserve() {
        // No TSA configured — custom size should have no effect on reserve_size.
        let base = make_ed25519_signer();
        let base_reserve = Signer::reserve_size(&base);
        let signer = base.set_timestamp_size(99_999);
        assert_eq!(Signer::reserve_size(&signer), base_reserve);
    }

    #[test]
    fn set_timestamp_size_before_tsa_url_is_applied() {
        use crate::crypto::raw_signature::cose_reserve_size;
        let custom_ts_size = 3_000usize;
        // Size set first, URL second — update_reserve_size() called by set_tsa_url
        // must pick up the stored timestamp_size.
        let signer = make_ed25519_signer()
            .set_timestamp_size(custom_ts_size)
            .set_tsa_url("http://timestamp.example.com");
        let expected =
            cose_reserve_size(SigningAlg::Ed25519, ED25519_CERTS, custom_ts_size).unwrap();
        assert_eq!(Signer::reserve_size(&signer), expected);
    }

    #[test]
    fn callback_takes_priority_over_tsa_url() {
        let signer = make_ed25519_signer()
            .set_tsa_url("http://timestamp.example.com")
            .set_timestamp_callback(|_, _| Ok(b"callback-token".to_vec()));
        let result = Signer::send_timestamp_request(&signer, b"msg");
        assert_eq!(result.unwrap().unwrap(), b"callback-token");
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

    #[c2pa_test_async]
    async fn async_timestamp_callback_is_called() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();
        let signer = make_ed25519_signer().set_timestamp_callback(move |_, _| {
            called_clone.store(true, Ordering::SeqCst);
            Ok(b"async-fake-token".to_vec())
        });
        let result = AsyncSigner::send_timestamp_request(&signer, b"msg").await;
        assert!(
            called.load(Ordering::SeqCst),
            "async callback was not called"
        );
        assert_eq!(result.unwrap().unwrap(), b"async-fake-token");
    }
}
