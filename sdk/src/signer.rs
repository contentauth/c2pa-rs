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

#![deny(missing_docs)]

use async_trait::async_trait;

use crate::{
    crypto::{
        raw_signature::{AsyncRawSigner, RawSigner, RawSignerError, SigningAlg},
        time_stamp::{TimeStampError, TimeStampProvider},
    },
    dynamic_assertion::{AsyncDynamicAssertion, DynamicAssertion},
    http::SyncGenericResolver,
    Result,
};

/// Generates a cryptographic signature over a byte array and configures various
/// aspects of how a C2PA Manifest is generated.
///
/// This trait exists to allow the signature mechanism to be extended.
pub trait Signer {
    /// Returns a new byte array which is a signature over the original.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Returns the algorithm implemented by this `Signer`.
    fn alg(&self) -> SigningAlg;

    /// Returns the signing certificate chain as a Vec containing a DER-encoded
    /// byte array for each certificate.
    fn certs(&self) -> Result<Vec<Vec<u8>>>;

    /// Returns the size in bytes of the largest possible expected signature.
    ///
    /// Signing will fail if the result of the `sign` function is larger
    /// than this value.
    fn reserve_size(&self) -> usize;

    /// Returns the URL for the time-stamp authority to use for this signature.
    fn time_authority_url(&self) -> Option<String> {
        None
    }

    /// Additional request headers to pass to the time-stamp authority.
    ///
    /// IMPORTANT: You should not include the `Content-type` header here.
    /// That is provided by default.
    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        None
    }

    /// Specifies the request body for the request to the time-stamp authority.
    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::time_stamp::default_rfc3161_message(message).map_err(|e| e.into())
    }

    /// Request RFC 3161 time-stamp to be included in the manifest data
    /// structure.
    ///
    /// `message` is a preliminary hash of the claim
    ///
    /// The default implementation will send the request to the URL
    /// provided by [`Self::time_authority_url()`], if any.
    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        let url = self.time_authority_url()?;
        let body = self.timestamp_request_body(message).ok()?;
        let headers = self.timestamp_request_headers();

        Some(
            crate::crypto::time_stamp::default_rfc3161_request(
                &url,
                headers,
                &body,
                message,
                &SyncGenericResolver::new(),
            )
            .map_err(|e| e.into()),
        )
    }

    /// Returns the OCSP response for the signing certificate if available.
    ///
    /// This is the only C2PA-supported cert revocation method.
    ///
    /// By pre-querying the value for a your signing cert the value can be
    /// cached, taking pressure off of the CA. (Doing so is recommended by the
    /// C2PA spec.)
    fn ocsp_val(&self) -> Option<Vec<u8>> {
        None
    }

    /// Returns `true` if the `sign` function is responsible for for direct
    /// handling of the COSE structure.
    ///
    /// Not recommended for general use.
    fn direct_cose_handling(&self) -> bool {
        false
    }

    /// Returns a list of dynamic assertions that should be included in the
    /// manifest.
    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        Vec::new()
    }

    /// If this struct also implements or wraps [`RawSigner`], it should
    /// return a reference to that trait implementation.
    ///
    /// If this function returns `None` (the default behavior), a temporary
    /// wrapper will be constructed for it.
    ///
    /// NOTE: Due to limitations in some of the FFI tooling that we use to
    /// bridge c2pa-rs to other languages, we can not make [`RawSigner`] a
    /// supertrait of this trait. This API is a workaround for that
    /// limitation.
    ///
    /// [`RawSigner`]: crate::crypto::raw_signature::RawSigner
    fn raw_signer(&self) -> Option<Box<&dyn RawSigner>> {
        None
    }
}

/// Generates a cryptographic signature over a byte array and configures various
/// aspects of how a C2PA Manifest is generated.
///
/// This trait exists to allow the signature mechanism to be extended.
///
/// Use this when the implementation is asynchronous.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncSigner: Sync {
    /// Returns a new byte array which is a signature over the original.
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>>;

    /// Returns the algorithm implemented by this `Signer`.
    fn alg(&self) -> SigningAlg;

    /// Returns the signing certificate chain as a Vec containing a DER-encoded
    /// byte array for each certificate.
    fn certs(&self) -> Result<Vec<Vec<u8>>>;

    /// Returns the size in bytes of the largest possible expected signature.
    ///
    /// Signing will fail if the result of the `sign` function is larger
    /// than this value.
    fn reserve_size(&self) -> usize;

    /// Returns the URL for the time-stamp authority to use for this signature.
    fn time_authority_url(&self) -> Option<String> {
        None
    }

    /// Additional request headers to pass to the time-stamp authority.
    ///
    /// IMPORTANT: You should not include the `Content-type` header here.
    /// That is provided by default.
    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        None
    }

    /// Specifies the request body for the request to the time-stamp authority.
    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        crate::crypto::time_stamp::default_rfc3161_message(message).map_err(|e| e.into())
    }

    /// Request RFC 3161 time-stamp to be included in the manifest data
    /// structure.
    ///
    /// `message` is a preliminary hash of the claim
    ///
    /// The default implementation will send the request to the URL
    /// provided by [`Self::time_authority_url()`], if any.
    async fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        use crate::http::AsyncGenericResolver;

        let url = self.time_authority_url()?;
        let body = self.timestamp_request_body(message).ok()?;
        let headers = self.timestamp_request_headers();

        Some(
            crate::crypto::time_stamp::default_rfc3161_request_async(
                &url,
                headers,
                &body,
                message,
                &AsyncGenericResolver::new(),
            )
            .await
            .map_err(|e| e.into()),
        )
    }

    /// Returns the OCSP response for the signing certificate if available.
    ///
    /// This is the only C2PA-supported cert revocation method.
    ///
    /// By pre-querying the value for a your signing cert the value can be
    /// cached, taking pressure off of the CA. (Doing so is recommended by the
    /// C2PA spec.)
    async fn ocsp_val(&self) -> Option<Vec<u8>> {
        None
    }

    /// Returns `true` if the `sign` function is responsible for for direct
    /// handling of the COSE structure.
    ///
    /// Not recommended for general use.
    fn direct_cose_handling(&self) -> bool {
        false
    }

    /// Returns a list of dynamic assertions that should be included in the
    /// manifest.
    fn dynamic_assertions(&self) -> Vec<Box<dyn AsyncDynamicAssertion>> {
        Vec::new()
    }

    /// If this struct also implements or wraps [`AsyncRawSigner`], it should
    /// return a reference to that trait implementation.
    ///
    /// If this function returns `None` (the default behavior), a temporary
    /// wrapper will be constructed for it when needed.
    ///
    /// NOTE: Due to limitations in some of the FFI tooling that we use to
    /// bridge c2pa-rs to other languages, we can not make
    /// [`AsyncRawSigner`] a supertrait of this trait. This API is a
    /// workaround for that limitation.
    ///
    /// [`AsyncRawSigner`]: crate::crypto::raw_signature::AsyncRawSigner
    fn async_raw_signer(&self) -> Option<Box<&dyn AsyncRawSigner>> {
        None
    }
}

impl Signer for Box<dyn Signer> {
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

    fn raw_signer(&self) -> Option<Box<&dyn RawSigner>> {
        (**self).raw_signer()
    }
}

impl RawSigner for Box<dyn Signer> {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        Ok(self.as_ref().sign(data)?)
    }

    fn alg(&self) -> SigningAlg {
        self.as_ref().alg()
    }

    fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.as_ref().certs()?)
    }

    fn reserve_size(&self) -> usize {
        self.as_ref().reserve_size()
    }

    fn ocsp_response(&self) -> Option<Vec<u8>> {
        eprintln!("HUH, A DIFFERENT I WANTED @ 397");
        self.as_ref().ocsp_val()
    }
}

impl TimeStampProvider for Box<dyn Signer> {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.as_ref().time_authority_url()
    }

    fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.as_ref().timestamp_request_headers()
    }

    fn time_stamp_request_body(
        &self,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, TimeStampError> {
        Ok(self.as_ref().sign(message)?)
    }

    fn send_time_stamp_request(
        &self,
        message: &[u8],
    ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
        self.as_ref()
            .send_timestamp_request(message)
            .map(|r| Ok(r?))
    }
}

/// Boxed [`AsyncSigner`] that handles `Send` bounds if appropriate for the
/// platform.
#[cfg(not(target_arch = "wasm32"))]
type BoxedAsyncSigner = Box<dyn AsyncSigner + Send + Sync>;

#[cfg(target_arch = "wasm32")]
type BoxedAsyncSigner = Box<dyn AsyncSigner>;

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl AsyncSigner for BoxedAsyncSigner {
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

    fn async_raw_signer(&self) -> Option<Box<&dyn AsyncRawSigner>> {
        (**self).async_raw_signer()
    }
}

#[allow(dead_code)] // Not used in all configurations.
pub(crate) struct RawSignerWrapper(pub(crate) Box<dyn RawSigner>);

impl Signer for RawSignerWrapper {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(data).map_err(|e| e.into())
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.0.cert_chain().map_err(|e| e.into())
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.0.ocsp_response()
    }

    fn time_authority_url(&self) -> Option<String> {
        self.0.time_stamp_service_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.0.time_stamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.0
            .time_stamp_request_body(message)
            .map_err(|e| e.into())
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.0
            .send_time_stamp_request(message)
            .map(|r| r.map_err(|e| e.into()))
    }

    fn raw_signer(&self) -> Option<Box<&dyn RawSigner>> {
        Some(Box::new(&*self.0))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    mod async_signer {
        use super::super::*;
        use crate::crypto::raw_signature::SigningAlg;

        // Minimal AsyncSigner implementation for testing default methods.
        struct MinimalAsyncSigner;

        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        impl AsyncSigner for MinimalAsyncSigner {
            async fn sign(&self, _data: Vec<u8>) -> Result<Vec<u8>> {
                Ok(vec![])
            }

            fn alg(&self) -> SigningAlg {
                SigningAlg::Ed25519
            }

            fn certs(&self) -> Result<Vec<Vec<u8>>> {
                Ok(vec![])
            }

            fn reserve_size(&self) -> usize {
                1024
            }
        }

        #[test]
        fn default_time_authority_url() {
            // Test that the default implementation of time_authority_url returns None.
            let signer = MinimalAsyncSigner;
            assert_eq!(signer.time_authority_url(), None);
        }

        #[test]
        fn default_timestamp_request_headers() {
            // Test that the default implementation of timestamp_request_headers returns
            // None.
            let signer = MinimalAsyncSigner;
            assert_eq!(signer.timestamp_request_headers(), None);
        }

        #[test]
        fn default_timestamp_request_body() {
            // Test that the default implementation of timestamp_request_body
            // calls the default_rfc3161_message function
            let signer = MinimalAsyncSigner;
            let message = b"test message";

            // The default implementation should successfully create an RFC 3161 message.
            let result = signer.timestamp_request_body(message);
            let body = result.unwrap();
            assert!(!body.is_empty());
        }
    }
}
