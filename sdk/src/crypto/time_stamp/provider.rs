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

use async_generic::async_generic;
use async_trait::async_trait;
use bcder::{encode::Values, OctetString};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{
        asn1::rfc3161::TimeStampReq,
        raw_signature::oids::{ans1_oid_bcder_oid, SHA256_OID},
        time_stamp::TimeStampError,
    },
    http::{AsyncHttpResolver, SyncHttpResolver},
    maybe_send_sync::MaybeSync,
};

/// A `TimeStampProvider` implementation can contact a [RFC 3161] time stamp
/// service and generate a corresponding time stamp for a specific piece of
/// data.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
pub trait TimeStampProvider {
    /// URL for the timestamp authority used to timestamp the signature.
    ///
    /// If this is set and [`TimeStampProvider::send_time_stamp_request`] returns
    /// `None` (the default behavior), the SDK uses its built-in networking
    /// implementation to submit the request.
    fn time_stamp_service_url(&self) -> Option<String> {
        None
    }

    /// Additional request headers to pass to the time stamp service.
    ///
    /// The default implementation returns `None`.
    ///
    /// IMPORTANT: You should not include the "Content-type" header here.
    /// That is provided by default.
    fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        None
    }

    /// Generate the request body for the HTTPS request to the time stamp
    /// service.
    ///
    /// The default implementation builds a RFC 3161 timestmap request body from `message`.
    /// service.
    fn time_stamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>, TimeStampError> {
        default_rfc3161_message(message)
    }

    /// Request a [RFC 3161] time stamp over an arbitrary data packet.
    ///
    /// Implement this function to provide custom networking for timestamp
    /// requests. The default implementation returns
    /// `Some(Err(TimeStampError::NotImplemented))`.
    ///
    /// If this method returns `None`, timestamping is skipped entirely.
    /// If this method returns `Some(Err(TimeStampError::NotImplemented))` and
    /// [`TimeStampProvider::time_stamp_service_url`] is set, the SDK falls back
    /// to its built-in networking implementation.
    ///
    /// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
    ///
    /// todo: THIS CODE IS NOT COMPATIBLE WITH C2PA 2.x sigTst2
    fn send_time_stamp_request(&self, _message: &[u8]) -> Option<Result<Vec<u8>, TimeStampError>> {
        Some(Err(TimeStampError::NotImplemented))
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
    /// URL for the timestamp authority used to timestamp the signature.
    ///
    /// If this is set and [`AsyncTimeStampProvider::send_time_stamp_request`] returns
    /// `None` (the default behavior), the SDK uses its built-in networking
    /// implementation to submit the request.
    fn time_stamp_service_url(&self) -> Option<String> {
        None
    }

    /// Additional request headers to pass to the time stamp service.
    ///
    /// The default implementation returns `None`.
    ///
    /// IMPORTANT: You should not include the "Content-type" header here.
    /// That is provided by default.
    fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        None
    }

    /// Generate the request body for the HTTPS request to the time stamp
    /// service.
    ///
    /// The default implementation builds a RFC 3161 timestmap request body from `message`.
    fn time_stamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>, TimeStampError> {
        default_rfc3161_message(message)
    }

    /// Request a [RFC 3161] time stamp over an arbitrary data packet.
    ///
    /// `message` is a preliminary hash of the claim.
    ///
    /// Implement this function to provide custom networking for timestamp
    /// requests. The default implementation returns
    /// `Some(Err(TimeStampError::NotImplemented))`.
    ///
    /// If this method returns `None`, timestamping is skipped entirely.
    /// If this method returns `Some(Err(TimeStampError::NotImplemented))` and
    /// [`AsyncTimeStampProvider::time_stamp_service_url`] is set, the SDK falls
    /// back to its built-in networking implementation.
    ///
    /// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
    async fn send_time_stamp_request(
        &self,
        _message: &[u8],
    ) -> Option<Result<Vec<u8>, TimeStampError>> {
        Some(Err(TimeStampError::NotImplemented))
    }
}

/// Request a timestamp from the provider, falling back to a built-in networking
/// implementation if the provider returns [`TimeStampError::NotImplemented`].
///
/// If [`TimeStampProvider::send_time_stamp_request`] returns `None`, timestamping is
/// skipped and [`TimeStampError::NotImplemented`] is returned. If it returns
/// `Some(Err(TimeStampError::NotImplemented))` and
/// [`TimeStampProvider::time_stamp_service_url`] is set, the SDK falls back to its
/// built-in networking implementation. If no URL is configured either,
/// [`TimeStampError::NotImplemented`] is returned.
#[async_generic(async_signature(
    ts_provider: &(impl AsyncTimeStampProvider + ?Sized),
    message: &[u8],
    http_resolver: &(impl AsyncHttpResolver + ?Sized),
))]
pub(crate) fn send_time_stamp_request_with_fallback(
    ts_provider: &(impl TimeStampProvider + ?Sized),
    message: &[u8],
    http_resolver: &(impl SyncHttpResolver + ?Sized),
) -> Result<Vec<u8>, TimeStampError> {
    if _sync {
        match ts_provider.send_time_stamp_request(message) {
            None => Err(TimeStampError::NotImplemented),
            Some(Err(TimeStampError::NotImplemented)) => {
                let Some(url) = ts_provider.time_stamp_service_url() else {
                    return Err(TimeStampError::NotImplemented);
                };
                super::default_rfc3161_request(
                    &url,
                    ts_provider.time_stamp_request_headers(),
                    &ts_provider.time_stamp_request_body(message)?,
                    message,
                    http_resolver,
                )
            }
            Some(result) => result,
        }
    } else {
        match ts_provider.send_time_stamp_request(message).await {
            None => Err(TimeStampError::NotImplemented),
            Some(Err(TimeStampError::NotImplemented)) => {
                let Some(url) = ts_provider.time_stamp_service_url() else {
                    return Err(TimeStampError::NotImplemented);
                };
                super::default_rfc3161_request_async(
                    &url,
                    ts_provider.time_stamp_request_headers(),
                    &ts_provider.time_stamp_request_body(message)?,
                    message,
                    http_resolver,
                )
                .await
            }
            Some(result) => result,
        }
    }
}

/// Create an [RFC 3161] time stamp request message for a given piece of data.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
pub fn default_rfc3161_message(data: &[u8]) -> Result<Vec<u8>, TimeStampError> {
    // Hash the data with SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let mut random = [0u8; 8];
    thread_rng().try_fill(&mut random).map_err(|_| {
        TimeStampError::InternalError("Unable to generate random number".to_string())
    })?;

    // SHA-256 OID: 2.16.840.1.101.3.4.2.1
    let sha256_oid = ans1_oid_bcder_oid(&SHA256_OID)
        .ok_or_else(|| TimeStampError::InternalError("Invalid SHA-256 OID".to_string()))?;

    let request = TimeStampReq {
        version: bcder::Integer::from(1_u8),
        message_imprint: crate::crypto::asn1::rfc3161::MessageImprint {
            hash_algorithm: crate::crypto::asn1::AlgorithmIdentifier {
                algorithm: sha256_oid,
            },
            hashed_message: OctetString::new(bytes::Bytes::copy_from_slice(&digest)),
        },
        req_policy: None,
        nonce: Some(bcder::Integer::from(u64::from_le_bytes(random))),
        cert_req: Some(true),
        extensions: None,
    };

    let mut body = Vec::<u8>::new();
    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)?;

    Ok(body)
}
