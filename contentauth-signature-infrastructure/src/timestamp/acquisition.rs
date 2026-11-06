// Copyright 2026 Adobe. All rights reserved.
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

//! Host-driven RFC 3161 timestamp acquisition.
//!
//! Checks the HTTP envelope, DER structure and reflected nonce only. The host
//! supplies entropy, bounds response reads, performs HTTP, and drives the workflow.
//!
//! # Host example
//!
//! This blocking driver accepts an HTTP adapter supplied by your application.
//! Connect `send` to your HTTP client, configuring credentials, network policy
//! and timeout there. Supply a fresh nonce from your application's entropy
//! source; the workflow neither generates randomness nor performs I/O itself.
//! An async host follows the same loop, awaiting its HTTP client instead.
//!
//! ```no_run
//! use std::{
//!     error::Error,
//!     io::{self, Read},
//! };
//!
//! use contentauth_sans_io_core::{Step, Workflow};
//! use contentauth_signature_infrastructure::timestamp::acquisition::{
//!     acquire, AcquisitionReply, AcquisitionRequest, UnverifiedTimeStampResponse,
//!     MAX_RESPONSE_BYTES,
//! };
//! use http::{header::CONTENT_TYPE, Request, Response};
//!
//! fn acquire_timestamp(
//!     url: &str,
//!     message: &[u8],
//!     fresh_nonce: u64,
//!     mut send: impl FnMut(Request<Vec<u8>>) -> io::Result<Response<Box<dyn Read>>>,
//! ) -> Result<UnverifiedTimeStampResponse, Box<dyn Error>> {
//!     let mut workflow = acquire(url, Vec::new(), message, fresh_nonce)?;
//!
//!     loop {
//!         match workflow.advance()? {
//!             Step::Complete => return Ok(workflow.finish()?),
//!             Step::AwaitHost => {}
//!             _ => return Err(io::Error::other("unexpected workflow step").into()),
//!         }
//!
//!         let operation = workflow
//!             .outstanding_requests()
//!             .first()
//!             .ok_or_else(|| io::Error::other("missing HTTP operation"))?;
//!         let id = operation.id;
//!         let AcquisitionRequest::HttpPost(request) = &operation.kind;
//!
//!         // Transport and body-read failures propagate to the host's caller.
//!         let response = send(request.clone())?;
//!         let (parts, body) = response.into_parts();
//!         let content_type = parts
//!             .headers
//!             .get(CONTENT_TYPE)
//!             .and_then(|value| value.to_str().ok());
//!         let mut bytes = Vec::new();
//!
//!         // Read one byte beyond the limit so the workflow can detect overflow.
//!         // Never size the buffer from Content-Length or read HTTP-error bodies.
//!         if parts.status == 200 && content_type == Some("application/timestamp-reply") {
//!             body.take(MAX_RESPONSE_BYTES as u64 + 1)
//!                 .read_to_end(&mut bytes)?;
//!         }
//!
//!         workflow.fulfill(
//!             id,
//!             AcquisitionReply::Http(Ok(Response::from_parts(parts, bytes))),
//!         )?;
//!     }
//! }
//! ```
//!
//! The returned [`UnverifiedTimeStampResponse`] must still pass your timestamp
//! verifier and applicable certificate/profile/trust checks. This driver adds
//! no retries; the host decides whether and when to attempt acquisition again.

use bcder::{decode::Constructed, encode::Values, Integer, OctetString};
use contentauth_sans_io_core::{CoroutineWorkflow, Host, ProtocolError, Request};
use http::{header, Request as HttpRequest, Response as HttpResponse};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::response;
use crate::{asn1, asn1::rfc3161::TimeStampReq};

/// Maximum accepted response size. Hosts must read at most this limit plus one
/// byte to detect overflow, without trusting `Content-Length`.
pub const MAX_RESPONSE_BYTES: usize = 1_000_000;

/// Acquisition failures, never signature, profile or trust verdicts.
#[derive(Debug, Error)]
pub enum AcquisitionError {
    /// Invalid workflow interaction.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// The DER request could not be decoded or encoded.
    #[error("invalid timestamp request: {0}")]
    InvalidRequest(String),

    /// The HTTP URI or headers could not be represented.
    #[error("invalid timestamp HTTP request ({0})")]
    HttpRequestError(#[from] http::Error),

    /// The response DER or CMS content could not be decoded.
    #[error("decode error ({0})")]
    DecodeError(String),

    /// The status or exact content type did not identify a timestamp reply.
    #[error("service responded with an HTTP error (status = {0}, content-type = {1:?})")]
    HttpErrorResponse(u16, Option<String>),

    /// The host reported a transport failure.
    #[error("unable to complete HTTP request ({0})")]
    Transport(String),

    /// The response did not reflect the request's nonce.
    #[error("nonce mismatch")]
    NonceMismatch,

    /// The response exceeded the acquisition limit.
    #[error("timestamp response exceeds {MAX_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
}

/// An external operation required by acquisition.
#[derive(Clone, Debug)]
pub enum AcquisitionRequest {
    /// Perform this POST, retaining host control of credentials, network policy,
    /// timeout, retries and cancellation.
    HttpPost(HttpRequest<Vec<u8>>),
}

/// Owned, bounded host input to the workflow.
#[derive(Clone, Debug)]
pub enum AcquisitionReply {
    /// A response (including non-200 status) or a transport failure.
    Http(Result<HttpResponse<Vec<u8>>, String>),
}

impl Request for AcquisitionRequest {
    type Reply = AcquisitionReply;

    fn expected_reply(&self) -> &'static str {
        "HTTP response or transport failure"
    }

    fn accepts(&self, reply: &Self::Reply) -> bool {
        matches!(
            (self, reply),
            (Self::HttpPost(_), AcquisitionReply::Http(_))
        )
    }
}

/// Original response bytes, acquired but **not cryptographically verified**.
///
/// Successful acquisition does not establish a correct message imprint,
/// signature, certificate validity, certificate profile or TSA trust.
#[derive(Debug)]
pub struct UnverifiedTimeStampResponse(Vec<u8>);

impl UnverifiedTimeStampResponse {
    /// Inspect the original DER without re-encoding signed data.
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }

    /// Transfer the original DER to the host's verifier.
    pub fn into_der(self) -> Vec<u8> {
        self.0
    }
}

/// Acquisition state driven through `contentauth_sans_io_core::Workflow`.
pub type AcquisitionWorkflow =
    CoroutineWorkflow<AcquisitionRequest, UnverifiedTimeStampResponse, AcquisitionError>;

/// Build a SHA-256 request using a fresh nonce supplied by the host.
pub fn request_body(message: &[u8], nonce: u64) -> Result<Vec<u8>, AcquisitionError> {
    encode_request(&standard_request(message, nonce))
}

fn standard_request(message: &[u8], nonce: u64) -> TimeStampReq {
    TimeStampReq {
        version: Integer::from(1_u8),

        message_imprint: asn1::rfc3161::MessageImprint {
            hash_algorithm: asn1::AlgorithmIdentifier {
                algorithm: bcder::Oid(bytes::Bytes::from_static(&[
                    96, 134, 72, 1, 101, 3, 4, 2, 1,
                ])),
            },

            hashed_message: OctetString::new(bytes::Bytes::copy_from_slice(&Sha256::digest(
                message,
            ))),
        },

        req_policy: None,
        nonce: Some(Integer::from(nonce)),
        cert_req: Some(true),
        extensions: None,
    }
}

fn encode_request(request: &TimeStampReq) -> Result<Vec<u8>, AcquisitionError> {
    let mut body = Vec::new();

    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)
        .map_err(|err| AcquisitionError::InvalidRequest(err.to_string()))?;

    Ok(body)
}

/// Acquire a timestamp with a standard request and host-supplied nonce.
pub fn acquire(
    url: &str,
    headers: Vec<(String, String)>,
    message: &[u8],
    nonce: u64,
) -> Result<AcquisitionWorkflow, AcquisitionError> {
    acquire_with_request(url, headers, standard_request(message, nonce))
}

/// Acquire using a customized DER request.
///
/// Decode and re-encode the body, preserving the SDK's historical behavior and
/// retaining the actual request nonce for comparison with the response.
pub fn acquire_with_body(
    url: &str,
    headers: Vec<(String, String)>,
    body: &[u8],
) -> Result<AcquisitionWorkflow, AcquisitionError> {
    let timestamp_request = Constructed::decode(body, bcder::Mode::Der, TimeStampReq::take_from)
        .map_err(|err| AcquisitionError::InvalidRequest(err.to_string()))?;

    acquire_with_request(url, headers, timestamp_request)
}

fn acquire_with_request(
    url: &str,
    headers: Vec<(String, String)>,
    timestamp_request: TimeStampReq,
) -> Result<AcquisitionWorkflow, AcquisitionError> {
    let mut request = HttpRequest::post(url);

    for (name, value) in headers {
        request = request.header(name, value);
    }

    let request = request
        .header(header::CONTENT_TYPE, "application/timestamp-query")
        .body(encode_request(&timestamp_request)?)?;

    Ok(CoroutineWorkflow::new(move |host| async move {
        acquire_response(host, request, timestamp_request.nonce).await
    }))
}

async fn acquire_response(
    host: Host<AcquisitionRequest>,
    request: HttpRequest<Vec<u8>>,
    nonce: Option<Integer>,
) -> Result<UnverifiedTimeStampResponse, AcquisitionError> {
    host.set_phase("Requesting timestamp");

    let response = host
        .ask(AcquisitionRequest::HttpPost(request), |_, reply| {
            let AcquisitionReply::Http(result) = reply;
            result.map_err(AcquisitionError::Transport)
        })
        .await?;

    host.set_phase("Checking timestamp response");

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());

    if response.status() != 200 || content_type != Some("application/timestamp-reply") {
        return Err(AcquisitionError::HttpErrorResponse(
            response.status().as_u16(),
            content_type.map(str::to_owned),
        ));
    }

    if response.body().len() > MAX_RESPONSE_BYTES {
        return Err(AcquisitionError::ResponseTooLarge);
    }

    let bytes = response.into_body();
    response::check_nonce(&bytes, nonce)?;

    Ok(UnverifiedTimeStampResponse(bytes))
}
