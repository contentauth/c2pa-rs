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
use bcder::{encode::Values, OctetString};
use rand::{thread_rng, Rng};
use x509_certificate::DigestAlgorithm;

use crate::{asn1::rfc3161::TimeStampReq, time_stamp::TimeStampError};

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
    #[allow(unused_variables)] // `message` not used on WASM
    fn send_time_stamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>, TimeStampError>> {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(url) = self.time_stamp_service_url() {
            if let Ok(body) = self.time_stamp_request_body(message) {
                let headers: Option<Vec<(String, String)>> = self.time_stamp_request_headers();
                return Some(super::http_request::default_rfc3161_request(
                    &url, headers, &body, message,
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
pub trait AsyncTimeStampProvider {
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
    #[allow(unused_variables)] // `message` not used on WASM
    async fn send_time_stamp_request(
        &self,
        message: &[u8],
    ) -> Option<Result<Vec<u8>, TimeStampError>> {
        // NOTE: This is currently synchronous, but may become
        // async in the future.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(url) = self.time_stamp_service_url() {
            if let Ok(body) = self.time_stamp_request_body(message) {
                let headers: Option<Vec<(String, String)>> = self.time_stamp_request_headers();
                return Some(
                    super::http_request::default_rfc3161_request_async(
                        &url, headers, &body, message,
                    )
                    .await,
                );
            }
        }

        None
    }
}

fn default_rfc3161_message(data: &[u8]) -> Result<Vec<u8>, TimeStampError> {
    let request = time_stamp_message_http(data, DigestAlgorithm::Sha256)?;

    let mut body = Vec::<u8>::new();
    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)?;

    Ok(body)
}

fn time_stamp_message_http(
    message: &[u8],
    digest_algorithm: DigestAlgorithm,
) -> Result<TimeStampReq, TimeStampError> {
    let mut h = digest_algorithm.digester();
    h.update(message);
    let digest = h.finish();

    let mut random = [0u8; 8];
    thread_rng().try_fill(&mut random).map_err(|_| {
        TimeStampError::InternalError("Unable to generate random number".to_string())
    })?;

    let request = TimeStampReq {
        version: bcder::Integer::from(1_u8),
        message_imprint: crate::asn1::rfc3161::MessageImprint {
            hash_algorithm: digest_algorithm.into(),
            hashed_message: OctetString::new(bytes::Bytes::copy_from_slice(digest.as_ref())),
        },
        req_policy: None,
        nonce: Some(bcder::Integer::from(u64::from_le_bytes(random))),
        cert_req: Some(true),
        extensions: None,
    };

    Ok(request)
}
