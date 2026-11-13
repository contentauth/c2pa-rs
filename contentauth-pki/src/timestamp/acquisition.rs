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
//! use contentauth_pki::timestamp::acquisition::{
//!     acquire, AcquisitionReply, AcquisitionRequest, UnverifiedTimeStampResponse,
//!     MAX_RESPONSE_BYTES,
//! };
//! use contentauth_sans_io_core::{Step, Workflow};
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use bcder::{decode::Constructed, encode::Values, Integer as BcderInteger};
    use contentauth_sans_io_core::{ProtocolError, Step, Workflow};
    use http::{header, Response};
    use rasn::prelude::*;
    use sha2::{Digest, Sha256};

    use super::{
        acquire, acquire_with_body, request_body, AcquisitionError, AcquisitionReply,
        AcquisitionRequest, AcquisitionWorkflow, MAX_RESPONSE_BYTES,
    };
    use crate::asn1::rfc3161::TimeStampReq;

    #[derive(AsnType, Encode)]
    struct Status {
        status: Integer,
        text: Option<Vec<Utf8String>>,
    }

    #[derive(AsnType, Encode)]
    struct TimestampResponse {
        status: Status,
        token: Option<Any>,
    }

    #[derive(AsnType, Encode)]
    struct ContentInfo {
        content_type: ObjectIdentifier,
        #[rasn(tag(explicit(0)))]
        content: Any,
    }

    #[derive(AsnType, Encode)]
    struct SignedData {
        version: Integer,
        digests: SetOf<Any>,
        content: rasn_cms::EncapsulatedContentInfo,
        signers: SetOf<Any>,
    }

    #[derive(AsnType, Encode)]
    struct MessageImprint {
        algorithm: rasn_cms::AlgorithmIdentifier,
        digest: OctetString,
    }

    #[derive(AsnType, Encode)]
    struct TimestampInfo {
        version: Integer,
        policy: ObjectIdentifier,
        imprint: MessageImprint,
        serial: Integer,
        generated: GeneralizedTime,
        nonce: Option<Integer>,
    }

    fn response_der(status: u8, nonce: Option<u64>, token: bool, text: Option<String>) -> Vec<u8> {
        let token = token.then(|| {
            let info = TimestampInfo {
                version: 1.into(),
                policy: ObjectIdentifier::new(vec![1, 2, 3]).unwrap(),

                imprint: MessageImprint {
                    algorithm: rasn_cms::AlgorithmIdentifier {
                        algorithm: ObjectIdentifier::new(vec![2, 16, 840, 1, 101, 3, 4, 2, 1])
                            .unwrap(),
                        parameters: None,
                    },

                    digest: Sha256::digest(b"message").to_vec().into(),
                },

                serial: 1.into(),
                generated: chrono::DateTime::from_timestamp(1_700_000_000, 0)
                    .unwrap()
                    .into(),
                nonce: nonce.map(Into::into),
            };

            let data = SignedData {
                version: 3.into(),
                digests: SetOf::default(),

                content: rasn_cms::EncapsulatedContentInfo {
                    content_type: Oid::ISO_MEMBER_BODY_US_RSADSI_PKCS9_SMIME_CT_TSTINFO.to_owned(),
                    content: Some(rasn::der::encode(&info).unwrap().into()),
                },

                signers: SetOf::default(),
            };

            Any::new(
                rasn::der::encode(&ContentInfo {
                    content_type: ObjectIdentifier::new(vec![1, 2, 840, 113549, 1, 7, 2]).unwrap(),
                    content: Any::new(rasn::der::encode(&data).unwrap()),
                })
                .unwrap(),
            )
        });

        rasn::der::encode(&TimestampResponse {
            status: Status {
                status: status.into(),
                text: text.map(|text| vec![text]),
            },

            token,
        })
        .unwrap()
    }

    fn http_response(bytes: Vec<u8>) -> Response<Vec<u8>> {
        Response::builder()
            .header(header::CONTENT_TYPE, "application/timestamp-reply")
            .body(bytes)
            .unwrap()
    }

    fn workflow() -> AcquisitionWorkflow {
        acquire(
            "https://tsa.example/",
            vec![("x-test".into(), "custom".into())],
            b"message",
            42,
        )
        .unwrap()
    }

    fn fulfill(workflow: &mut AcquisitionWorkflow, reply: AcquisitionReply) {
        assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);

        workflow
            .fulfill(workflow.outstanding_requests()[0].id, reply)
            .unwrap();
    }

    #[test]
    fn host_drives_one_post_and_result_is_unverified_original_bytes() {
        let mut workflow = workflow();
        assert!(workflow.outstanding_requests().is_empty());
        assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
        assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
        assert_eq!(workflow.outstanding_requests().len(), 1);
        let AcquisitionRequest::HttpPost(request) = &workflow.outstanding_requests()[0].kind;
        assert_eq!(request.uri(), "https://tsa.example/");
        assert_eq!(request.method(), "POST");
        assert_eq!(request.headers()["x-test"], "custom");

        assert_eq!(
            request.headers()[header::CONTENT_TYPE],
            "application/timestamp-query"
        );

        assert_eq!(request.body(), &request_body(b"message", 42).unwrap());

        // No signatures or certificates: acquisition must not imply verification.
        let bytes = response_der(0, Some(42), true, None);
        fulfill(
            &mut workflow,
            AcquisitionReply::Http(Ok(http_response(bytes.clone()))),
        );

        assert_eq!(workflow.advance().unwrap(), Step::Complete);
        let acquired = workflow.finish().unwrap();
        assert_eq!(acquired.as_der(), bytes);
        assert_eq!(acquired.into_der(), bytes);
    }

    #[test]
    fn standard_and_encoded_request_paths_yield_the_same_post() {
        let url = "https://tsa.example/";
        let headers = vec![("x-test".into(), "custom".into())];
        let body = request_body(b"message", 42).unwrap();
        let mut standard = acquire(url, headers.clone(), b"message", 42).unwrap();
        let mut custom = acquire_with_body(url, headers, &body).unwrap();

        assert_eq!(standard.advance().unwrap(), Step::AwaitHost);
        assert_eq!(custom.advance().unwrap(), Step::AwaitHost);

        let AcquisitionRequest::HttpPost(standard_post) = &standard.outstanding_requests()[0].kind;
        let AcquisitionRequest::HttpPost(custom_post) = &custom.outstanding_requests()[0].kind;

        assert_eq!(standard_post.method(), custom_post.method());
        assert_eq!(standard_post.uri(), custom_post.uri());
        assert_eq!(standard_post.headers(), custom_post.headers());
        assert_eq!(standard_post.body(), custom_post.body());

        let bytes = response_der(0, Some(42), true, None);

        for workflow in [&mut standard, &mut custom] {
            fulfill(
                workflow,
                AcquisitionReply::Http(Ok(http_response(bytes.clone()))),
            );

            assert_eq!(workflow.advance().unwrap(), Step::Complete);
        }

        assert_eq!(standard.finish().unwrap().as_der(), bytes);
        assert_eq!(custom.finish().unwrap().as_der(), bytes);
    }

    #[test]
    fn request_has_deterministic_imprint_and_host_nonce() {
        for nonce in [0, 42, u64::MAX] {
            let body = request_body(b"message", nonce).unwrap();
            assert_eq!(body, request_body(b"message", nonce).unwrap());

            let parsed =
                Constructed::decode(body.as_slice(), bcder::Mode::Der, TimeStampReq::take_from)
                    .unwrap();

            assert_eq!(parsed.version, BcderInteger::from(1));
            assert_eq!(parsed.nonce, Some(BcderInteger::from(nonce)));
            assert_eq!(parsed.cert_req, Some(true));

            assert_eq!(
                parsed.message_imprint.hash_algorithm.algorithm.to_string(),
                "2.16.840.1.101.3.4.2.1"
            );

            assert_eq!(
                parsed.message_imprint.hashed_message.to_bytes().as_ref(),
                Sha256::digest(b"message").as_slice()
            );
        }
    }

    #[test]
    fn custom_policy_body_and_nonce_presence_are_preserved() {
        for requested in [None, Some(42)] {
            let body = request_body(b"custom", 123).unwrap();

            let mut parsed =
                Constructed::decode(body.as_slice(), bcder::Mode::Der, TimeStampReq::take_from)
                    .unwrap();

            parsed.nonce = requested.map(BcderInteger::from);
            parsed.cert_req = Some(false);
            parsed.req_policy = Some("1.2.3.4".parse().unwrap());
            let mut body = Vec::new();

            parsed
                .encode_ref()
                .write_encoded(bcder::Mode::Der, &mut body)
                .unwrap();

            for reflected in [None, Some(41), Some(42)] {
                let mut workflow =
                    acquire_with_body("https://tsa.example/", vec![], &body).unwrap();
                assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
                let AcquisitionRequest::HttpPost(post) = &workflow.outstanding_requests()[0].kind;
                assert_eq!(post.body(), &body);
                fulfill(
                    &mut workflow,
                    AcquisitionReply::Http(Ok(http_response(response_der(
                        1, reflected, true, None,
                    )))),
                );

                if requested == reflected {
                    assert_eq!(workflow.advance().unwrap(), Step::Complete);
                } else {
                    assert!(matches!(
                        workflow.advance(),
                        Err(AcquisitionError::NonceMismatch)
                    ));
                }
            }
        }
    }

    #[test]
    fn non_granted_and_missing_token_responses_are_not_verification() {
        for status in 0..=5 {
            let bytes = response_der(status, None, false, None);
            let mut workflow = workflow();
            fulfill(
                &mut workflow,
                AcquisitionReply::Http(Ok(http_response(bytes.clone()))),
            );

            assert_eq!(workflow.advance().unwrap(), Step::Complete);
            assert_eq!(workflow.finish().unwrap().as_der(), bytes);
        }
    }

    #[test]
    fn envelope_transport_and_decode_errors_stay_distinct() {
        for (status, content_type) in [
            (201, Some("application/timestamp-reply")),
            (503, Some("application/timestamp-reply")),
            (200, Some("application/timestamp-reply; charset=binary")),
            (200, Some("application/octet-stream")),
            (200, None),
        ] {
            let mut response = Response::builder().status(status);

            if let Some(value) = content_type {
                response = response.header(header::CONTENT_TYPE, value);
            }

            let mut workflow = workflow();
            fulfill(
                &mut workflow,
                AcquisitionReply::Http(Ok(response.body(vec![0]).unwrap())),
            );

            assert!(
                matches!(workflow.advance(), Err(AcquisitionError::HttpErrorResponse(s, c)) if s == status && c.as_deref() == content_type)
            );
        }

        for bytes in [vec![], vec![0]] {
            let mut workflow = workflow();
            fulfill(
                &mut workflow,
                AcquisitionReply::Http(Ok(http_response(bytes))),
            );

            assert!(matches!(
                workflow.advance(),
                Err(AcquisitionError::DecodeError(_))
            ));
        }

        let mut failed = workflow();
        fulfill(
            &mut failed,
            AcquisitionReply::Http(Err("cancelled by host".into())),
        );

        assert!(
            matches!(failed.advance(), Err(AcquisitionError::Transport(message)) if message == "cancelled by host")
        );

        assert!(failed.outstanding_requests().is_empty());

        assert!(matches!(
            failed.advance(),
            Err(AcquisitionError::Protocol(ProtocolError::WorkflowFailed(_)))
        ));
    }

    #[test]
    fn acquisition_request_describes_and_accepts_its_host_reply() {
        let mut workflow = workflow();
        assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
        let request = &workflow.outstanding_requests()[0].kind;

        assert_eq!(
            contentauth_sans_io_core::Request::expected_reply(request),
            "HTTP response or transport failure"
        );

        for reply in [
            AcquisitionReply::Http(Err("cancelled".into())),
            AcquisitionReply::Http(Ok(http_response(Vec::new()))),
        ] {
            assert!(contentauth_sans_io_core::Request::accepts(request, &reply));
        }
    }

    #[test]
    fn invalid_requests_fail_before_host_io() {
        assert!(matches!(
            acquire_with_body("https://tsa.example/", vec![], &[0]),
            Err(AcquisitionError::InvalidRequest(_))
        ));

        assert!(matches!(
            acquire(
                "https://tsa.example/",
                vec![("bad\nheader".into(), "x".into())],
                b"",
                1
            ),
            Err(AcquisitionError::HttpRequestError(_))
        ));
    }

    #[test]
    fn exact_limit_is_accepted_and_limit_plus_one_rejected() {
        let encode = |length| response_der(2, None, false, Some("x".repeat(length)));
        let overhead = encode(MAX_RESPONSE_BYTES).len() - MAX_RESPONSE_BYTES;

        for extra in [0, 1] {
            let bytes = encode(MAX_RESPONSE_BYTES - overhead + extra);
            assert_eq!(bytes.len(), MAX_RESPONSE_BYTES + extra);
            let mut workflow = workflow();
            let mut response = http_response(bytes.clone());

            response
                .headers_mut()
                .insert(header::CONTENT_LENGTH, "0".parse().unwrap());

            fulfill(&mut workflow, AcquisitionReply::Http(Ok(response)));

            if extra == 0 {
                assert_eq!(workflow.advance().unwrap(), Step::Complete);
                assert_eq!(workflow.finish().unwrap().as_der(), bytes);
            } else {
                assert!(matches!(
                    workflow.advance(),
                    Err(AcquisitionError::ResponseTooLarge)
                ));
            }
        }
    }

    #[test]
    fn incomplete_duplicate_and_late_replies_are_not_success() {
        assert!(matches!(
            workflow().finish(),
            Err(AcquisitionError::Protocol(
                ProtocolError::WorkflowNotComplete
            ))
        ));

        let mut workflow = workflow();
        assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
        let id = workflow.outstanding_requests()[0].id;

        workflow
            .fulfill(
                id,
                AcquisitionReply::Http(Ok(http_response(response_der(2, None, false, None)))),
            )
            .unwrap();

        assert!(matches!(
            workflow.fulfill(id, AcquisitionReply::Http(Err("duplicate".into()))),
            Err(AcquisitionError::Protocol(_))
        ));

        assert_eq!(workflow.advance().unwrap(), Step::Complete);

        assert!(matches!(
            workflow.fulfill(id, AcquisitionReply::Http(Err("late".into()))),
            Err(AcquisitionError::Protocol(ProtocolError::WorkflowComplete))
        ));
    }
}
