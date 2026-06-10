// Copyright 2022 Adobe. All rights reserved.
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
use c2pa_raw_crypto::{RawSigner, RawSignerError, SigningAlg};

use crate::{
    crypto::cose::cose_reserve_size,
    dynamic_assertion::{AsyncDynamicAssertion, DynamicAssertion},
    http::SyncGenericResolver,
    maybe_send_sync::{MaybeSend, MaybeSync},
    Result,
};

// Type aliases for boxed trait objects with conditional Send + Sync bounds
// These are the canonical definitions used throughout the codebase

/// Type alias for a boxed [`Signer`] with conditional Send + Sync bounds.
/// On non-WASM targets, the signer is Send + Sync for thread-safe usage.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSigner = Box<dyn Signer + Send + Sync>;

/// Type alias for a boxed [`Signer`] without Send + Sync bounds (WASM only).
#[cfg(target_arch = "wasm32")]
pub type BoxedSigner = Box<dyn Signer>;

/// Type alias for a boxed [`AsyncSigner`] with conditional Send + Sync bounds.
/// On non-WASM targets, the signer is Send + Sync for thread-safe usage.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedAsyncSigner = Box<dyn AsyncSigner + Send + Sync>;

/// Type alias for a boxed [`AsyncSigner`] without Send + Sync bounds (WASM only).
#[cfg(target_arch = "wasm32")]
pub type BoxedAsyncSigner = Box<dyn AsyncSigner>;

/// The `Signer` trait generates a cryptographic signature over a byte array.
///
/// This trait exists to allow the signature mechanism to be extended.
pub trait Signer {
    /// Returns a new byte array which is a signature over the original.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Returns the algorithm of the Signer.
    fn alg(&self) -> SigningAlg;

    /// Returns the certificates as a Vec containing a Vec of DER bytes for each certificate.
    fn certs(&self) -> Result<Vec<Vec<u8>>>;

    /// Returns the size in bytes of the largest possible expected signature.
    /// Signing will fail if the result of the `sign` function is larger
    /// than this value.
    fn reserve_size(&self) -> usize;

    /// URL for time authority to time stamp the signature
    fn time_authority_url(&self) -> Option<String> {
        None
    }

    /// Additional request headers to pass to the time stamp authority.
    ///
    /// IMPORTANT: You should not include the "Content-type" header here.
    /// That is provided by default.
    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        None
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::time_stamp::default_rfc3161_message(message).map_err(|e| e.into())
    }

    /// Request RFC 3161 timestamp to be included in the manifest data
    /// structure.
    ///
    /// `message` is a preliminary hash of the claim
    ///
    /// The default implementation will send the request to the URL
    /// provided by [`Self::time_authority_url()`], if any.
    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        if let Some(url) = self.time_authority_url() {
            if let Ok(body) = self.timestamp_request_body(message) {
                let headers: Option<Vec<(String, String)>> = self.timestamp_request_headers();
                return Some(
                    crate::crypto::time_stamp::default_rfc3161_request(
                        &url,
                        headers,
                        &body,
                        message,
                        &SyncGenericResolver::with_redirects().unwrap_or_default(),
                    )
                    .map_err(|e| e.into()),
                );
            }
        }

        None
    }

    /// OCSP response for the signing cert if available
    /// This is the only C2PA supported cert revocation method.
    /// By pre-querying the value for a your signing cert the value can
    /// be cached taking pressure off of the CA (recommended by C2PA spec)
    fn ocsp_val(&self) -> Option<Vec<u8>> {
        None
    }

    /// If this returns true the sign function is responsible for for direct handling of the COSE structure.
    ///
    /// This is useful for cases where the signer needs to handle the COSE structure directly.
    /// Not recommended for general use.
    fn direct_cose_handling(&self) -> bool {
        false
    }

    /// Returns a list of dynamic assertions that should be included in the manifest.
    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        Vec::new()
    }
}

/// Trait to allow loading of signing credential from external sources
#[allow(dead_code)] // this here for wasm builds to pass clippy  (todo: remove)
pub(crate) trait ConfigurableSigner: Signer + Sized {
    /// Create signer form credential files
    #[cfg(feature = "file_io")]
    fn from_files<P: AsRef<std::path::Path>>(
        signcert_path: P,
        pkey_path: P,
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        let signcert = std::fs::read(signcert_path).map_err(crate::Error::IoError)?;
        let pkey = std::fs::read(pkey_path).map_err(crate::Error::IoError)?;

        Self::from_signcert_and_pkey(&signcert, &pkey, alg, tsa_url)
    }

    /// Create signer from credentials data
    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self>;
}

/// The `AsyncSigner` trait generates a cryptographic signature over a byte array.
///
/// This trait exists to allow the signature mechanism to be extended.
///
/// Use this when the implementation is asynchronous.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncSigner: MaybeSend + MaybeSync {
    /// Returns a new byte array which is a signature over the original.
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>>;

    /// Returns the algorithm of the Signer.
    fn alg(&self) -> SigningAlg;

    /// Returns the certificates as a Vec containing a Vec of DER bytes for each certificate.
    fn certs(&self) -> Result<Vec<Vec<u8>>>;

    /// Returns the size in bytes of the largest possible expected signature.
    /// Signing will fail if the result of the `sign` function is larger
    /// than this value.
    fn reserve_size(&self) -> usize;

    /// URL for time authority to time stamp the signature
    fn time_authority_url(&self) -> Option<String> {
        None
    }

    /// Additional request headers to pass to the time stamp authority.
    ///
    /// IMPORTANT: You should not include the "Content-type" header here.
    /// That is provided by default.
    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        None
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::time_stamp::default_rfc3161_message(message).map_err(|e| e.into())
    }

    /// Request RFC 3161 timestamp to be included in the manifest data
    /// structure.
    ///
    /// `message` is a preliminary hash of the claim
    ///
    /// The default implementation will send the request to the URL
    /// provided by [`Self::time_authority_url()`], if any.
    async fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        if let Some(url) = self.time_authority_url() {
            if let Ok(body) = self.timestamp_request_body(message) {
                use crate::http::AsyncGenericResolver;

                let headers: Option<Vec<(String, String)>> = self.timestamp_request_headers();
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

    /// OCSP response for the signing cert if available
    /// This is the only C2PA supported cert revocation method.
    /// By pre-querying the value for a your signing cert the value can
    /// be cached taking pressure off of the CA (recommended by C2PA spec)
    async fn ocsp_val(&self) -> Option<Vec<u8>> {
        None
    }

    /// If this returns true the sign function is responsible for for direct handling of the COSE structure.
    ///
    /// This is useful for cases where the signer needs to handle the COSE structure directly.
    /// Not recommended for general use.
    fn direct_cose_handling(&self) -> bool {
        false
    }

    /// Returns a list of dynamic assertions that should be included in the manifest.
    fn dynamic_assertions(&self) -> Vec<Box<dyn AsyncDynamicAssertion>> {
        Vec::new()
    }
}

// Generic implementation for Box<T> where T implements Signer
// This covers Box<dyn Signer>, Box<dyn Signer + Send + Sync>, and concrete types
impl<T: ?Sized + Signer> Signer for Box<T> {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        (**self).sign(data)
    }

    fn alg(&self) -> SigningAlg {
        (**self).alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        (**self).certs()
    }

    fn reserve_size(&self) -> usize {
        (**self).reserve_size()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        (**self).ocsp_val()
    }

    fn direct_cose_handling(&self) -> bool {
        (**self).direct_cose_handling()
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        (**self).dynamic_assertions()
    }

    fn time_authority_url(&self) -> Option<String> {
        (**self).time_authority_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        (**self).timestamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        (**self).timestamp_request_body(message)
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        (**self).send_timestamp_request(message)
    }
}

// Generic implementation for Box<T> where T implements AsyncSigner
// This covers Box<dyn AsyncSigner>, Box<dyn AsyncSigner + Send + Sync>, and concrete types
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<T: ?Sized + AsyncSigner> AsyncSigner for Box<T> {
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        (**self).sign(data).await
    }

    fn alg(&self) -> SigningAlg {
        (**self).alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        (**self).certs()
    }

    fn reserve_size(&self) -> usize {
        (**self).reserve_size()
    }

    fn time_authority_url(&self) -> Option<String> {
        (**self).time_authority_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        (**self).timestamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        (**self).timestamp_request_body(message)
    }

    async fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        (**self).send_timestamp_request(message).await
    }

    async fn ocsp_val(&self) -> Option<Vec<u8>> {
        (**self).ocsp_val().await
    }

    fn direct_cose_handling(&self) -> bool {
        (**self).direct_cose_handling()
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn AsyncDynamicAssertion>> {
        (**self).dynamic_assertions()
    }
}

/// Wraps a [`RawSigner`] (raw signature only) into a full [`Signer`], layering
/// on the optional time stamp service URL and the overall COSE reserve-size
/// calculation that the raw signer does not know about.
#[allow(dead_code)] // Not used in all configurations.
pub(crate) struct RawSignerWrapper {
    raw_signer: Box<dyn RawSigner + Send + Sync>,
    cert_chain: Vec<Vec<u8>>,
    time_stamp_service_url: Option<String>,
}

impl RawSignerWrapper {
    pub(crate) fn new(
        raw_signer: Box<dyn RawSigner + Send + Sync>,
        cert_chain: Vec<Vec<u8>>,
        time_stamp_service_url: Option<String>,
    ) -> Self {
        Self {
            raw_signer,
            cert_chain,
            time_stamp_service_url,
        }
    }
}

impl Signer for RawSignerWrapper {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.raw_signer.sign(data).map_err(|e| e.into())
    }

    fn alg(&self) -> SigningAlg {
        self.raw_signer.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.cert_chain.clone())
    }

    fn reserve_size(&self) -> usize {
        cose_reserve_size(
            self.raw_signer.max_signature_size(),
            &self.cert_chain,
            self.time_stamp_service_url.is_some(),
            None,
        )
    }

    fn time_authority_url(&self) -> Option<String> {
        self.time_stamp_service_url.clone()
    }
}

/// Adapts an owned [`BoxedSigner`] to implement [`RawSigner`].
///
/// This is the reverse of [`RawSignerWrapper`]: it allows a `BoxedSigner` to be
/// used wherever a `Box<dyn RawSigner + Send + Sync>` is expected. Time stamp
/// and OCSP information are not part of the [`RawSigner`] contract and are not
/// surfaced here.
#[allow(dead_code)]
pub(crate) struct OwnedSignerWrapper(pub(crate) BoxedSigner);

// SAFETY: WASM is single-threaded; no concurrent access is possible.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for OwnedSignerWrapper {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for OwnedSignerWrapper {}

impl RawSigner for OwnedSignerWrapper {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        Signer::sign(self.0.as_ref(), data)
            .map_err(|e| RawSignerError::InternalError(e.to_string()))
    }

    fn alg(&self) -> SigningAlg {
        Signer::alg(self.0.as_ref())
    }

    // The wrapped signer only knows its overall COSE reserve size, so we report
    // that as a (conservative) upper bound for the raw signature size.
    fn max_signature_size(&self) -> usize {
        Signer::reserve_size(self.0.as_ref())
    }
}
