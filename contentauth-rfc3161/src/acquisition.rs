// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Host-driven RFC 3161 timestamp acquisition.
//!
//! Acquisition checks the HTTP envelope, DER structure and reflected nonce.
//! It does **not** verify the CMS signature, message imprint, certificate
//! validity, certificate profile or TSA trust. Those checks belong to the
//! caller before using a timestamp as evidence.
//!
//! The host supplies entropy and performs HTTP, including response-body limits.
//! No network client, executor, clock, or random-number generator is used here.

use bcder::{decode::Constructed, encode::Values, Integer, OctetString};
use contentauth_sans_io_core::{CoroutineWorkflow, Host, ProtocolError, Request};
use http::{header, Request as HttpRequest, Response as HttpResponse};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{asn1, asn1::rfc3161::TimeStampReq, response};

/// Maximum accepted timestamp response size, in bytes.
///
/// Hosts must bound reads to this limit plus one byte to detect overflow,
/// regardless of the peer's Content-Length.
pub const MAX_RESPONSE_BYTES: usize = 1_000_000;

/// Failures while preparing or acquiring a timestamp; never a trust verdict.
#[derive(Debug, Error)]
pub enum AcquisitionError {
    /// Invalid host/workflow interaction.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),

    /// A request could not be built.
    #[error("invalid timestamp request: {0}")]
    InvalidRequest(String),

    /// The HTTP request URI or headers were invalid.
    #[error("invalid timestamp HTTP request ({0})")]
    HttpRequestError(#[from] http::Error),

    /// DER or CMS content could not be decoded.
    #[error("decode error ({0})")]
    DecodeError(String),

    /// HTTP status or Content-Type was not the expected timestamp reply.
    #[error("service responded with an HTTP error (status = {0}, content-type = {1:?})")]
    HttpErrorResponse(u16, Option<String>),

    /// The host could not complete the HTTP operation.
    #[error("unable to complete HTTP request ({0})")]
    Transport(String),

    /// The timestamp response did not reflect the request's nonce.
    #[error("nonce mismatch")]
    NonceMismatch,

    /// The response exceeded the bounded acquisition buffer.
    #[error("timestamp response exceeds {MAX_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
}

/// External operations required by timestamp acquisition.
#[derive(Clone, Debug)]
pub enum AcquisitionRequest {
    /// Perform this POST, returning an owned, bounded HTTP response.
    ///
    /// The host owns redirects, credentials, timeouts and network policy.
    HttpPost(HttpRequest<Vec<u8>>),
}

/// The host's HTTP result, including explicit transport failure.
#[derive(Clone, Debug)]
pub enum AcquisitionReply {
    /// HTTP completed; non-200 status is still a response, not a transport error.
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

/// Raw timestamp response bytes that have **not** been cryptographically verified.
#[derive(Debug)]
pub struct UnverifiedTimeStampResponse(Vec<u8>);

impl UnverifiedTimeStampResponse {
    /// Inspect the original DER response, without re-encoding the CMS token.
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }

    /// Consume the response for the caller's timestamp verifier.
    pub fn into_der(self) -> Vec<u8> {
        self.0
    }
}

/// A runtime-independent acquisition workflow driven through `Workflow`.
pub type AcquisitionWorkflow =
    CoroutineWorkflow<AcquisitionRequest, UnverifiedTimeStampResponse, AcquisitionError>;

/// Build a SHA-256 request using entropy supplied by the host.
///
/// Supply a fresh nonce for each acquisition. The SDK compatibility adapter
/// retains its existing eight-byte nonce generation outside this crate.
pub fn request_body(message: &[u8], nonce: u64) -> Result<Vec<u8>, AcquisitionError> {
    let request = TimeStampReq {
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
    };

    let mut body = Vec::new();

    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)
        .map_err(|err| AcquisitionError::InvalidRequest(err.to_string()))?;

    Ok(body)
}

/// Acquire a timestamp using the standard SHA-256 request.
///
/// All external effects are represented by requests to the host. Successful
/// completion is not evidence of a valid or trusted timestamp.
pub fn acquire(
    url: &str,
    headers: Vec<(String, String)>,
    message: &[u8],
    nonce: u64,
) -> Result<AcquisitionWorkflow, AcquisitionError> {
    acquire_with_body(url, headers, &request_body(message, nonce)?)
}

/// Acquire a timestamp using a caller-customized DER request body.
///
/// The request is decoded and re-encoded, matching the SDK's existing behavior.
/// Its nonce is retained for comparison with a successful response.
pub fn acquire_with_body(
    url: &str,
    headers: Vec<(String, String)>,
    body: &[u8],
) -> Result<AcquisitionWorkflow, AcquisitionError> {
    let timestamp_request = Constructed::decode(body, bcder::Mode::Der, TimeStampReq::take_from)
        .map_err(|err| AcquisitionError::InvalidRequest(err.to_string()))?;

    let mut body = Vec::new();

    timestamp_request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)
        .map_err(|err| AcquisitionError::InvalidRequest(err.to_string()))?;

    let mut request = HttpRequest::post(url);

    for (name, value) in headers {
        request = request.header(name, value);
    }

    let request = request
        .header(header::CONTENT_TYPE, "application/timestamp-query")
        .body(body)?;

    let nonce = timestamp_request.nonce;

    Ok(CoroutineWorkflow::new(move |host| async move {
        acquire_response(host, request, nonce).await
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

    let response = response::TimeStampResponse(
        Constructed::decode(
            bytes.as_slice(),
            bcder::Mode::Der,
            asn1::rfc3161::TimeStampResp::take_from,
        )
        .map_err(|err| AcquisitionError::DecodeError(err.to_string()))?,
    );

    // Non-granted responses and missing tokens remain for the caller's verifier
    // to reject, as in the existing SDK acquisition layer.
    if response.is_success() {
        if let Some(info) = response.tst_info()? {
            if info.nonce != nonce {
                return Err(AcquisitionError::NonceMismatch);
            }
        }
    }

    Ok(UnverifiedTimeStampResponse(bytes))
}
