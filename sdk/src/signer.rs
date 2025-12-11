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

    mod signer {
        use super::super::*;
        use crate::crypto::raw_signature::SigningAlg;

        // Minimal Signer implementation for testing default methods.
        struct MinimalSigner;

        impl Signer for MinimalSigner {
            fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
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
        fn default_timestamp_request_headers() {
            // Test that the default implementation of timestamp_request_headers returns
            // None.
            let signer = MinimalSigner;
            assert_eq!(signer.timestamp_request_headers(), None);
        }

        #[test]
        fn default_timestamp_request_body() {
            // Test that the default implementation of timestamp_request_body
            // calls the default_rfc3161_message function.
            let signer = MinimalSigner;
            let message = b"test message";

            // The default implementation should successfully create an RFC 3161 message.
            let result = signer.timestamp_request_body(message);
            let body = result.unwrap();
            assert!(!body.is_empty());
        }

        #[test]
        fn default_send_timestamp_request_without_url() {
            // Test that send_timestamp_request returns None when time_authority_url is None.
            let signer = MinimalSigner;
            let message = b"test message";
            assert!(signer.send_timestamp_request(message).is_none());
        }

        // Signer with a custom time authority URL for testing error paths.
        #[cfg(not(target_arch = "wasm32"))]
        struct SignerWithUrl {
            url: String,
        }

        #[cfg(not(target_arch = "wasm32"))]
        impl Signer for SignerWithUrl {
            fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
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

            fn time_authority_url(&self) -> Option<String> {
                Some(self.url.clone())
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        #[test]
        fn send_timestamp_request_error_path() {
            use httpmock::MockServer;

            // Create a mock server that returns an error response (not a valid timestamp).
            let server = MockServer::start();
            let mock = server.mock(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(500).body("Internal Server Error");
            });

            let signer = SignerWithUrl {
                url: server.url("/timestamp"),
            };
            let message = b"test message";

            // This should return Some(Err(_)) because the mock server returns a 500 error.
            let result = signer.send_timestamp_request(message);
            assert!(result.is_some());
            assert!(result.unwrap().is_err());

            mock.assert();
        }
    }

    mod boxed_signer {
        use super::super::*;
        use crate::crypto::{
            raw_signature::{RawSigner, SigningAlg},
            time_stamp::TimeStampProvider,
        };

        // Test signer that returns specific values for testing delegation.
        struct TestSigner {
            has_timestamp_headers: bool,
            has_ocsp: bool,
        }

        impl Signer for TestSigner {
            fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
                // Simple test signature: just reverse the input.
                Ok(data.iter().copied().rev().collect())
            }

            fn alg(&self) -> SigningAlg {
                SigningAlg::Es256
            }

            fn certs(&self) -> Result<Vec<Vec<u8>>> {
                Ok(vec![vec![1, 2, 3], vec![4, 5, 6]])
            }

            fn reserve_size(&self) -> usize {
                2048
            }

            fn time_authority_url(&self) -> Option<String> {
                Some("https://timestamp.example.com".to_string())
            }

            fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
                if self.has_timestamp_headers {
                    Some(vec![
                        ("X-Custom-Header".to_string(), "test-value".to_string()),
                        ("Authorization".to_string(), "Bearer token123".to_string()),
                    ])
                } else {
                    None
                }
            }

            fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
                // Return a simple test body based on the message.
                Ok(format!("timestamp-body-for-{}", message.len()).into_bytes())
            }

            fn ocsp_val(&self) -> Option<Vec<u8>> {
                if self.has_ocsp {
                    Some(vec![7, 8, 9, 10])
                } else {
                    None
                }
            }
        }

        #[test]
        fn timestamp_request_headers_with_headers() {
            // Test that Box<dyn Signer> correctly delegates timestamp_request_headers.
            let signer = TestSigner {
                has_timestamp_headers: true,
                has_ocsp: false,
            };
            let boxed: Box<dyn Signer> = Box::new(signer);

            let headers = boxed.timestamp_request_headers();
            assert!(headers.is_some());
            let headers = headers.unwrap();
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "X-Custom-Header");
            assert_eq!(headers[0].1, "test-value");
        }

        #[test]
        fn timestamp_request_headers_without_headers() {
            // Test that Box<dyn Signer> returns None when inner signer has no headers.
            let signer = TestSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            let boxed: Box<dyn Signer> = Box::new(signer);

            assert!(boxed.timestamp_request_headers().is_none());
        }

        #[test]
        fn timestamp_request_body() {
            // Test that Box<dyn Signer> correctly delegates timestamp_request_body.
            let signer = TestSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            let boxed: Box<dyn Signer> = Box::new(signer);

            let message = b"test message";
            let result = boxed.timestamp_request_body(message);
            assert!(result.is_ok());
            let body = result.unwrap();
            assert_eq!(body, b"timestamp-body-for-12");
        }

        #[test]
        fn send_timestamp_request() {
            // Test that Box<dyn Signer> correctly delegates send_timestamp_request.
            let signer = TestSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            let boxed: Box<dyn Signer> = Box::new(signer);

            let message = b"test message";
            // This will return None because the default implementation will try to
            // make an actual HTTP request which we're not mocking here.
            let _result = boxed.send_timestamp_request(message);
            // We're just testing that the delegation happens without panic.
        }

        #[test]
        fn as_raw_signer() {
            // Test that Box<dyn Signer> implements RawSigner correctly.
            let signer = TestSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            let boxed: Box<dyn Signer> = Box::new(signer);

            // Test sign via RawSigner trait.
            let data = b"test data";
            let signature = RawSigner::sign(&boxed, data);
            assert!(signature.is_ok());
            let sig = signature.unwrap();
            // Should be reversed.
            assert_eq!(sig, b"atad tset");

            // Test alg via RawSigner trait.
            assert_eq!(RawSigner::alg(&boxed), SigningAlg::Es256);

            // Test cert_chain via RawSigner trait.
            let certs = RawSigner::cert_chain(&boxed);
            assert!(certs.is_ok());
            let cert_chain = certs.unwrap();
            assert_eq!(cert_chain.len(), 2);
            assert_eq!(cert_chain[0], vec![1, 2, 3]);
            assert_eq!(cert_chain[1], vec![4, 5, 6]);

            // Test reserve_size via RawSigner trait.
            assert_eq!(RawSigner::reserve_size(&boxed), 2048);

            // Test ocsp_response via RawSigner trait.
            assert!(RawSigner::ocsp_response(&boxed).is_none());
        }

        #[test]
        fn as_raw_signer_with_ocsp() {
            // Test RawSigner::ocsp_response delegation.
            let signer = TestSigner {
                has_timestamp_headers: false,
                has_ocsp: true,
            };
            let boxed: Box<dyn Signer> = Box::new(signer);

            // Test ocsp_response via RawSigner trait.
            let ocsp = RawSigner::ocsp_response(&boxed);
            assert!(ocsp.is_some());
            assert_eq!(ocsp.unwrap(), vec![7, 8, 9, 10]);
        }

        #[test]
        fn as_timestamp_provider() {
            // Test that Box<dyn Signer> implements TimeStampProvider correctly.
            let signer = TestSigner {
                has_timestamp_headers: true,
                has_ocsp: false,
            };
            let boxed: Box<dyn Signer> = Box::new(signer);

            // Test time_stamp_service_url via TimeStampProvider trait.
            let url = TimeStampProvider::time_stamp_service_url(&boxed);
            assert!(url.is_some());
            assert_eq!(url.unwrap(), "https://timestamp.example.com");

            // Test time_stamp_request_headers via TimeStampProvider trait.
            let headers = TimeStampProvider::time_stamp_request_headers(&boxed);
            assert!(headers.is_some());
            assert_eq!(headers.unwrap().len(), 2);

            // Test time_stamp_request_body via TimeStampProvider trait
            // (which calls sign on the inner signer).
            let message = b"test";
            let body = TimeStampProvider::time_stamp_request_body(&boxed, message);
            assert!(body.is_ok());
            assert_eq!(body.unwrap(), b"tset"); // reversed

            // Test send_time_stamp_request via TimeStampProvider trait.
            let message = b"test message";
            let _result = TimeStampProvider::send_time_stamp_request(&boxed, message);
            // We're just testing that the delegation happens without panic.
        }
    }

    mod boxed_async_signer {
        #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
        use wasm_bindgen_test::*;

        use super::super::*;
        use crate::crypto::raw_signature::SigningAlg;

        // Test async signer that returns specific values for testing delegation.
        struct TestAsyncSigner {
            has_timestamp_headers: bool,
            has_ocsp: bool,
        }

        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        impl AsyncSigner for TestAsyncSigner {
            async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
                // Simple test signature: just reverse the input.
                Ok(data.into_iter().rev().collect())
            }

            fn alg(&self) -> SigningAlg {
                SigningAlg::Es384
            }

            fn certs(&self) -> Result<Vec<Vec<u8>>> {
                Ok(vec![vec![11, 12, 13], vec![14, 15, 16]])
            }

            fn reserve_size(&self) -> usize {
                4096
            }

            fn time_authority_url(&self) -> Option<String> {
                Some("https://async-timestamp.example.com".to_string())
            }

            fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
                if self.has_timestamp_headers {
                    Some(vec![(
                        "X-Async-Header".to_string(),
                        "async-value".to_string(),
                    )])
                } else {
                    None
                }
            }

            fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
                Ok(format!("async-timestamp-{}", message.len()).into_bytes())
            }

            async fn ocsp_val(&self) -> Option<Vec<u8>> {
                if self.has_ocsp {
                    Some(vec![17, 18, 19, 20])
                } else {
                    None
                }
            }
        }

        #[c2pa_macros::c2pa_test_async]
        async fn sign_delegation() {
            // Test that BoxedAsyncSigner correctly delegates sign.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            let data = b"async test".to_vec();
            let signature = AsyncSigner::sign(&boxed, data).await;
            assert!(signature.is_ok());
            assert_eq!(signature.unwrap(), b"tset cnysa");
        }

        #[test]
        fn alg_delegation() {
            // Test that BoxedAsyncSigner correctly delegates alg.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            assert_eq!(AsyncSigner::alg(&boxed), SigningAlg::Es384);
        }

        #[test]
        fn certs_delegation() {
            // Test that BoxedAsyncSigner correctly delegates certs.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            let certs = AsyncSigner::certs(&boxed);
            assert!(certs.is_ok());
            let cert_chain = certs.unwrap();
            assert_eq!(cert_chain.len(), 2);
            assert_eq!(cert_chain[0], vec![11, 12, 13]);
            assert_eq!(cert_chain[1], vec![14, 15, 16]);
        }

        #[test]
        fn reserve_size_delegation() {
            // Test that BoxedAsyncSigner correctly delegates reserve_size.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            assert_eq!(AsyncSigner::reserve_size(&boxed), 4096);
        }

        #[test]
        fn time_authority_url_delegation() {
            // Test that BoxedAsyncSigner correctly delegates time_authority_url.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            let url = AsyncSigner::time_authority_url(&boxed);
            assert_eq!(url, Some("https://async-timestamp.example.com".to_string()));
        }

        #[test]
        fn timestamp_request_headers_with_headers() {
            // Test that BoxedAsyncSigner correctly delegates timestamp_request_headers.
            let signer = TestAsyncSigner {
                has_timestamp_headers: true,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            let headers = AsyncSigner::timestamp_request_headers(&boxed);
            assert!(headers.is_some());
            let headers = headers.unwrap();
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].0, "X-Async-Header");
        }

        #[test]
        fn timestamp_request_headers_without_headers() {
            // Test that BoxedAsyncSigner returns None when no headers.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            assert!(AsyncSigner::timestamp_request_headers(&boxed).is_none());
        }

        #[test]
        fn timestamp_request_body_delegation() {
            // Test that BoxedAsyncSigner correctly delegates timestamp_request_body.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            let message = b"test message";
            let body = AsyncSigner::timestamp_request_body(&boxed, message);
            assert!(body.is_ok());
            assert_eq!(body.unwrap(), b"async-timestamp-12");
        }

        #[c2pa_macros::c2pa_test_async]
        async fn send_timestamp_request_delegation() {
            // Test that BoxedAsyncSigner correctly delegates send_timestamp_request.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            let message = b"test";
            let _result = AsyncSigner::send_timestamp_request(&boxed, message).await;
            // Just testing delegation without panic.
        }

        #[c2pa_macros::c2pa_test_async]
        async fn ocsp_val_without_ocsp() {
            // Test that BoxedAsyncSigner correctly delegates ocsp_val when None.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            let ocsp = AsyncSigner::ocsp_val(&boxed).await;
            assert!(ocsp.is_none());
        }

        #[c2pa_macros::c2pa_test_async]
        async fn ocsp_val_with_ocsp() {
            // Test that BoxedAsyncSigner correctly delegates ocsp_val when Some.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: true,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            let ocsp = AsyncSigner::ocsp_val(&boxed).await;
            assert!(ocsp.is_some());
            assert_eq!(ocsp.unwrap(), vec![17, 18, 19, 20]);
        }

        #[test]
        fn direct_cose_handling_delegation() {
            // Test that BoxedAsyncSigner correctly delegates direct_cose_handling.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            // Default implementation returns false.
            assert!(!AsyncSigner::direct_cose_handling(&boxed));
        }

        #[test]
        fn dynamic_assertions_delegation() {
            // Test that BoxedAsyncSigner correctly delegates dynamic_assertions.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            // Default implementation returns empty vec.
            let assertions = AsyncSigner::dynamic_assertions(&boxed);
            assert!(assertions.is_empty());
        }

        #[test]
        fn async_raw_signer_delegation() {
            // Test that BoxedAsyncSigner correctly delegates async_raw_signer.
            let signer = TestAsyncSigner {
                has_timestamp_headers: false,
                has_ocsp: false,
            };
            #[cfg(not(target_arch = "wasm32"))]
            let boxed: Box<dyn AsyncSigner + Send + Sync> = Box::new(signer);
            #[cfg(target_arch = "wasm32")]
            let boxed: Box<dyn AsyncSigner> = Box::new(signer);

            // Default implementation returns None.
            assert!(AsyncSigner::async_raw_signer(&boxed).is_none());
        }
    }

    mod raw_signer_wrapper {
        use super::super::*;
        use crate::crypto::{
            raw_signature::{RawSigner, RawSignerError, SigningAlg},
            time_stamp::{TimeStampError, TimeStampProvider},
        };

        // Test RawSigner that implements TimeStampProvider for testing delegation.
        struct TestRawSigner {
            has_timestamp_headers: bool,
            has_timestamp_url: bool,
        }

        impl RawSigner for TestRawSigner {
            fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
                // Simple test signature: uppercase the input.
                Ok(data.iter().map(|b| b.to_ascii_uppercase()).collect())
            }

            fn alg(&self) -> SigningAlg {
                SigningAlg::Ps256
            }

            fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
                Ok(vec![vec![21, 22, 23]])
            }

            fn reserve_size(&self) -> usize {
                512
            }
        }

        impl TimeStampProvider for TestRawSigner {
            fn time_stamp_service_url(&self) -> Option<String> {
                if self.has_timestamp_url {
                    Some("https://raw-timestamp.example.com".to_string())
                } else {
                    None
                }
            }

            fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
                if self.has_timestamp_headers {
                    Some(vec![
                        ("X-Raw-Header".to_string(), "raw-value".to_string()),
                        ("Content-Length".to_string(), "1234".to_string()),
                    ])
                } else {
                    None
                }
            }

            fn time_stamp_request_body(
                &self,
                message: &[u8],
            ) -> std::result::Result<Vec<u8>, TimeStampError> {
                Ok(format!("raw-ts-body-{}", message.len()).into_bytes())
            }

            fn send_time_stamp_request(
                &self,
                _message: &[u8],
            ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
                if self.has_timestamp_url {
                    // Return a mock success response.
                    Some(Ok(vec![99, 100, 101]))
                } else {
                    None
                }
            }
        }

        #[test]
        fn time_authority_url_with_url() {
            // Test that RawSignerWrapper correctly delegates time_authority_url.
            let raw_signer = TestRawSigner {
                has_timestamp_headers: false,
                has_timestamp_url: true,
            };
            let wrapper = RawSignerWrapper(Box::new(raw_signer));

            let url = Signer::time_authority_url(&wrapper);
            assert_eq!(url, Some("https://raw-timestamp.example.com".to_string()));
        }

        #[test]
        fn time_authority_url_without_url() {
            // Test that RawSignerWrapper returns None when no URL.
            let raw_signer = TestRawSigner {
                has_timestamp_headers: false,
                has_timestamp_url: false,
            };
            let wrapper = RawSignerWrapper(Box::new(raw_signer));

            assert!(Signer::time_authority_url(&wrapper).is_none());
        }

        #[test]
        fn timestamp_request_headers_with_headers() {
            // Test that RawSignerWrapper correctly delegates timestamp_request_headers.
            let raw_signer = TestRawSigner {
                has_timestamp_headers: true,
                has_timestamp_url: false,
            };
            let wrapper = RawSignerWrapper(Box::new(raw_signer));

            let headers = Signer::timestamp_request_headers(&wrapper);
            assert!(headers.is_some());
            let headers = headers.unwrap();
            assert_eq!(headers.len(), 2);
            assert_eq!(headers[0].0, "X-Raw-Header");
            assert_eq!(headers[0].1, "raw-value");
            assert_eq!(headers[1].0, "Content-Length");
        }

        #[test]
        fn timestamp_request_headers_without_headers() {
            // Test that RawSignerWrapper returns None when no headers.
            let raw_signer = TestRawSigner {
                has_timestamp_headers: false,
                has_timestamp_url: false,
            };
            let wrapper = RawSignerWrapper(Box::new(raw_signer));

            assert!(Signer::timestamp_request_headers(&wrapper).is_none());
        }

        #[test]
        fn timestamp_request_body_delegation() {
            // Test that RawSignerWrapper correctly delegates timestamp_request_body.
            let raw_signer = TestRawSigner {
                has_timestamp_headers: false,
                has_timestamp_url: false,
            };
            let wrapper = RawSignerWrapper(Box::new(raw_signer));

            let message = b"test timestamp message";
            let body = Signer::timestamp_request_body(&wrapper, message);
            assert!(body.is_ok());
            assert_eq!(body.unwrap(), b"raw-ts-body-22");
        }

        #[test]
        fn send_timestamp_request_with_url() {
            // Test that RawSignerWrapper correctly delegates send_timestamp_request.
            let raw_signer = TestRawSigner {
                has_timestamp_headers: false,
                has_timestamp_url: true,
            };
            let wrapper = RawSignerWrapper(Box::new(raw_signer));

            let message = b"test";
            let result = Signer::send_timestamp_request(&wrapper, message);
            assert!(result.is_some());
            let response = result.unwrap();
            assert!(response.is_ok());
            assert_eq!(response.unwrap(), vec![99, 100, 101]);
        }

        #[test]
        fn send_timestamp_request_without_url() {
            // Test that RawSignerWrapper returns None when no URL.
            let raw_signer = TestRawSigner {
                has_timestamp_headers: false,
                has_timestamp_url: false,
            };
            let wrapper = RawSignerWrapper(Box::new(raw_signer));

            let message = b"test";
            assert!(Signer::send_timestamp_request(&wrapper, message).is_none());
        }

        #[test]
        fn raw_signer_delegation() {
            // Test that RawSignerWrapper correctly delegates raw_signer.
            let raw_signer = TestRawSigner {
                has_timestamp_headers: false,
                has_timestamp_url: false,
            };
            let wrapper = RawSignerWrapper(Box::new(raw_signer));

            let raw_signer_ref = Signer::raw_signer(&wrapper);
            assert!(raw_signer_ref.is_some());
        }
    }

    mod async_signer {
        #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
        use wasm_bindgen_test::*;

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
            // calls the default_rfc3161_message function.
            let signer = MinimalAsyncSigner;
            let message = b"test message";

            // The default implementation should successfully create an RFC 3161 message.
            let result = signer.timestamp_request_body(message);
            let body = result.unwrap();
            assert!(!body.is_empty());
        }

        #[c2pa_macros::c2pa_test_async]
        async fn default_ocsp_val() {
            // Test that the default implementation of ocsp_val returns None.
            let signer = MinimalAsyncSigner;
            assert!(signer.ocsp_val().await.is_none());
        }

        // AsyncSigner with a custom time authority URL for testing error paths.
        #[cfg(not(target_arch = "wasm32"))]
        struct AsyncSignerWithUrl {
            url: String,
        }

        #[cfg(not(target_arch = "wasm32"))]
        #[async_trait]
        impl AsyncSigner for AsyncSignerWithUrl {
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

            fn time_authority_url(&self) -> Option<String> {
                Some(self.url.clone())
            }
        }

        #[c2pa_macros::c2pa_test_async]
        #[cfg(not(target_arch = "wasm32"))]
        async fn send_timestamp_request_error_path() {
            use httpmock::MockServer;

            // Create a mock server that returns an error response (not a valid timestamp).
            let server = MockServer::start();
            let mock = server.mock(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(500).body("Internal Server Error");
            });

            let signer = AsyncSignerWithUrl {
                url: server.url("/timestamp"),
            };
            let message = b"test message";

            // This should return Some(Err(_)) because the mock server returns a 500 error.
            let result = signer.send_timestamp_request(message).await;
            assert!(result.is_some());
            assert!(result.unwrap().is_err());

            mock.assert();
        }
    }
}
