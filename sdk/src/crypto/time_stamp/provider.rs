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
use rand::RngExt;

use crate::{context::Context, crypto::time_stamp::TimeStampError, maybe_send_sync::MaybeSync};

/// A `TimeStampProvider` implementation can contact a [RFC 3161] time stamp
/// service and generate a corresponding time stamp for a specific piece of
/// data.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
pub trait TimeStampProvider {
    /// Return the URL for time stamp service.
    fn time_stamp_service_url(&self) -> Option<String> {
        None
    }

    /// Additional request headers to pass to the time stamp service.
    ///
    /// IMPORTANT: You should not include the "Content-type" header here.
    /// That is provided by default.
    fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        None
    }

    /// Generate the request body for the HTTPS request to the time stamp
    /// service.
    fn time_stamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>, TimeStampError> {
        default_rfc3161_message(message)
    }

    /// Request a [RFC 3161] time stamp over an arbitrary data packet.
    ///
    /// The default implementation will send the request to the URL
    /// provided by [`Self::time_stamp_service_url()`], if any.
    ///
    /// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
    ///
    /// todo: THIS CODE IS NOT COMPATIBLE WITH C2PA 2.x sigTst2
    fn send_time_stamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>, TimeStampError>> {
        if let Some(url) = self.time_stamp_service_url() {
            if let Ok(body) = self.time_stamp_request_body(message) {
                let headers: Option<Vec<(String, String)>> = self.time_stamp_request_headers();
                let context = Context::new();
                return Some(super::http_request::default_rfc3161_request(
                    &url, headers, &body, message, &context,
                ));
            }
        }

        None
    }
}

/// An `AsyncTimeStampProvider` implementation can contact a [RFC 3161] time
/// stamp service and generate a corresponding time stamp for a specific piece
/// of data.
///
/// This is identical to [`TimeStampProvider`] except for performing its work
/// asynchronously.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncTimeStampProvider: MaybeSync {
    /// Return the URL for time stamp service.
    fn time_stamp_service_url(&self) -> Option<String> {
        None
    }

    /// Additional request headers to pass to the time stamp service.
    ///
    /// IMPORTANT: You should not include the "Content-type" header here.
    /// That is provided by default.
    fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        None
    }

    /// Generate the request body for the HTTPS request to the time stamp
    /// service.
    fn time_stamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>, TimeStampError> {
        default_rfc3161_message(message)
    }

    /// Request a [RFC 3161] time stamp over an arbitrary data packet.
    ///
    /// The default implementation will send the request to the URL
    /// provided by [`Self::time_stamp_service_url()`], if any.
    ///
    /// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
    async fn send_time_stamp_request(
        &self,
        message: &[u8],
    ) -> Option<Result<Vec<u8>, TimeStampError>> {
        if let Some(url) = self.time_stamp_service_url() {
            if let Ok(body) = self.time_stamp_request_body(message) {
                let headers: Option<Vec<(String, String)>> = self.time_stamp_request_headers();
                let context = Context::new();
                return Some(
                    super::http_request::default_rfc3161_request_async(
                        &url, headers, &body, message, &context,
                    )
                    .await,
                );
            }
        }

        None
    }
}

/// Create an [RFC 3161] time stamp request message for a given piece of data.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
pub fn default_rfc3161_message(data: &[u8]) -> Result<Vec<u8>, TimeStampError> {
    let mut random = [0u8; 8];
    rand::rng().fill(&mut random);
    contentauth_rfc3161::request_body(data, u64::from_le_bytes(random)).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use bcder::decode::Constructed;
    use sha2::{Digest, Sha256};
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::crypto::asn1::rfc3161::TimeStampReq;

    #[test]
    fn default_request_has_sha256_imprint_nonce_and_certificate_request() {
        for data in [b"".as_slice(), b"payload"] {
            let encoded = default_rfc3161_message(data).unwrap();
            let request = Constructed::decode(
                encoded.as_slice(),
                bcder::Mode::Der,
                TimeStampReq::take_from,
            )
            .unwrap();
            assert_eq!(request.version, bcder::Integer::from(1));
            assert_eq!(
                request.message_imprint.hash_algorithm.algorithm.to_string(),
                "2.16.840.1.101.3.4.2.1"
            );
            assert_eq!(
                request.message_imprint.hashed_message.to_bytes().as_ref(),
                Sha256::digest(data).as_slice()
            );
            assert!(request.nonce.is_some());
            assert_eq!(request.cert_req, Some(true));
            assert!(request.req_policy.is_none());
            assert!(request.extensions.is_none());
        }
    }

    #[c2pa_macros::c2pa_test_async]
    async fn default_providers_do_not_request_timestamps_without_a_url() {
        struct DefaultProvider;
        impl TimeStampProvider for DefaultProvider {}
        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        impl AsyncTimeStampProvider for DefaultProvider {}

        assert!(TimeStampProvider::time_stamp_service_url(&DefaultProvider).is_none());
        assert!(TimeStampProvider::time_stamp_request_headers(&DefaultProvider).is_none());
        assert!(TimeStampProvider::time_stamp_request_body(&DefaultProvider, b"data").is_ok());
        assert!(TimeStampProvider::send_time_stamp_request(&DefaultProvider, b"data").is_none());
        assert!(AsyncTimeStampProvider::time_stamp_service_url(&DefaultProvider).is_none());
        assert!(AsyncTimeStampProvider::time_stamp_request_headers(&DefaultProvider).is_none());
        assert!(AsyncTimeStampProvider::time_stamp_request_body(&DefaultProvider, b"data").is_ok());
        assert!(
            AsyncTimeStampProvider::send_time_stamp_request(&DefaultProvider, b"data")
                .await
                .is_none()
        );
    }

    #[c2pa_macros::c2pa_test_async]
    async fn request_body_failure_currently_behaves_like_no_provider() {
        struct InvalidBody;
        impl TimeStampProvider for InvalidBody {
            fn time_stamp_service_url(&self) -> Option<String> {
                Some("https://unused.invalid/".into())
            }

            fn time_stamp_request_body(&self, _message: &[u8]) -> Result<Vec<u8>, TimeStampError> {
                Err(TimeStampError::InternalError("test body failure".into()))
            }
        }
        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        impl AsyncTimeStampProvider for InvalidBody {
            fn time_stamp_service_url(&self) -> Option<String> {
                TimeStampProvider::time_stamp_service_url(self)
            }

            fn time_stamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>, TimeStampError> {
                TimeStampProvider::time_stamp_request_body(self, message)
            }
        }

        assert!(TimeStampProvider::send_time_stamp_request(&InvalidBody, b"data").is_none());
        assert!(
            AsyncTimeStampProvider::send_time_stamp_request(&InvalidBody, b"data")
                .await
                .is_none()
        );
    }
}
