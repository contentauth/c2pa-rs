// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use bcder::{decode::Constructed, encode::Values, Integer as BcderInteger};
use contentauth_sans_io_core::{ProtocolError, Step, Workflow};
use http::{header, Response};
use rasn::prelude::*;
use sha2::{Digest, Sha256};

use crate::{
    acquire, acquire_with_body, asn1::rfc3161::TimeStampReq, request_body, AcquisitionError,
    AcquisitionReply, AcquisitionRequest, AcquisitionWorkflow, MAX_RESPONSE_BYTES,
};

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

fn response_der(status: u8, nonce: Option<u64>, token: bool) -> Vec<u8> {
    let token = token.then(|| {
        let info = TimestampInfo {
            version: 1.into(),
            policy: ObjectIdentifier::new(vec![1, 2, 3]).unwrap(),

            imprint: MessageImprint {
                algorithm: rasn_cms::AlgorithmIdentifier {
                    algorithm: ObjectIdentifier::new(vec![2, 16, 840, 1, 101, 3, 4, 2, 1]).unwrap(),
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
            text: None,
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

fn workflow(nonce: u64) -> AcquisitionWorkflow {
    acquire(
        "https://tsa.example/",
        vec![("x-test".into(), "custom".into())],
        b"message",
        nonce,
    )
    .unwrap()
}

fn fulfill(workflow: &mut AcquisitionWorkflow, reply: AcquisitionReply) {
    assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
    let id = workflow.outstanding_requests()[0].id;
    workflow.fulfill(id, reply).unwrap();
}

#[test]
fn request_is_deterministic_and_contains_host_nonce_and_sha256_imprint() {
    for nonce in [0, 42, u64::MAX] {
        let body = request_body(b"message", nonce).unwrap();
        assert_eq!(body, request_body(b"message", nonce).unwrap());

        let request =
            Constructed::decode(body.as_slice(), bcder::Mode::Der, TimeStampReq::take_from)
                .unwrap();

        assert_eq!(request.version, BcderInteger::from(1));
        assert_eq!(request.nonce, Some(BcderInteger::from(nonce)));
        assert_eq!(request.cert_req, Some(true));

        assert_eq!(
            request.message_imprint.hash_algorithm.algorithm.to_string(),
            "2.16.840.1.101.3.4.2.1"
        );

        assert_eq!(
            request.message_imprint.hashed_message.to_bytes().as_ref(),
            Sha256::digest(b"message").as_slice()
        );
    }
}

#[test]
fn host_drives_one_post_and_success_is_explicitly_unverified() {
    let mut workflow = workflow(42);
    assert!(workflow.outstanding_requests().is_empty());
    assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
    assert_eq!(workflow.phase(), "Requesting timestamp");
    assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
    assert_eq!(workflow.outstanding_requests().len(), 1);
    let operation = &workflow.outstanding_requests()[0];
    let AcquisitionRequest::HttpPost(request) = &operation.kind;
    assert_eq!(request.method(), "POST");
    assert_eq!(request.uri(), "https://tsa.example/");
    assert_eq!(request.headers()["x-test"], "custom");

    assert_eq!(
        request.headers()[header::CONTENT_TYPE],
        "application/timestamp-query"
    );

    assert_eq!(request.body(), &request_body(b"message", 42).unwrap());
    // No certificates or signatures: acquisition must not imply verification.
    let bytes = response_der(0, Some(42), true);
    let id = operation.id;

    workflow
        .fulfill(id, AcquisitionReply::Http(Ok(http_response(bytes.clone()))))
        .unwrap();

    assert_eq!(workflow.advance().unwrap(), Step::Complete);
    assert!(workflow.outstanding_requests().is_empty());
    let unverified = workflow.finish().unwrap();
    assert_eq!(unverified.as_der(), bytes);
    assert_eq!(unverified.into_der(), bytes);
}

#[test]
fn custom_request_policy_headers_and_absent_nonce_are_preserved() {
    let body = request_body(b"custom", 123).unwrap();

    let mut request =
        Constructed::decode(body.as_slice(), bcder::Mode::Der, TimeStampReq::take_from).unwrap();

    request.nonce = None;
    request.cert_req = Some(false);
    request.req_policy = Some("1.2.3.4".parse().unwrap());
    let mut body = Vec::new();

    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)
        .unwrap();

    let mut workflow = acquire_with_body("https://tsa.example/", vec![], &body).unwrap();
    assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
    let operation = &workflow.outstanding_requests()[0];
    let AcquisitionRequest::HttpPost(post) = &operation.kind;
    assert_eq!(post.body(), &body);
    let id = operation.id;

    workflow
        .fulfill(
            id,
            AcquisitionReply::Http(Ok(http_response(response_der(1, None, true)))),
        )
        .unwrap();

    assert_eq!(workflow.advance().unwrap(), Step::Complete);
}

#[test]
fn nonce_mismatch_including_missing_and_unexpected_nonce_is_rejected() {
    for nonce in [None, Some(41)] {
        let mut workflow = workflow(42);

        fulfill(
            &mut workflow,
            AcquisitionReply::Http(Ok(http_response(response_der(0, nonce, true)))),
        );

        assert!(matches!(
            workflow.advance(),
            Err(AcquisitionError::NonceMismatch)
        ));
    }

    let body = request_body(b"message", 42).unwrap();

    let mut request =
        Constructed::decode(body.as_slice(), bcder::Mode::Der, TimeStampReq::take_from).unwrap();

    request.nonce = None;
    let mut body = Vec::new();

    request
        .encode_ref()
        .write_encoded(bcder::Mode::Der, &mut body)
        .unwrap();

    let mut workflow = acquire_with_body("https://tsa.example/", vec![], &body).unwrap();

    fulfill(
        &mut workflow,
        AcquisitionReply::Http(Ok(http_response(response_der(0, Some(42), true)))),
    );

    assert!(matches!(
        workflow.advance(),
        Err(AcquisitionError::NonceMismatch)
    ));
}

#[test]
fn non_granted_and_missing_tokens_remain_for_the_callers_verifier() {
    for status in 0..=5 {
        let bytes = response_der(status, None, false);
        let mut workflow = workflow(42);

        fulfill(
            &mut workflow,
            AcquisitionReply::Http(Ok(http_response(bytes.clone()))),
        );

        assert_eq!(workflow.advance().unwrap(), Step::Complete);
        assert_eq!(workflow.finish().unwrap().into_der(), bytes);
    }
}

#[test]
fn status_content_type_transport_and_der_errors_are_distinct() {
    for (status, content_type) in [
        (503, Some("application/timestamp-reply")),
        (200, Some("application/octet-stream")),
        (200, None),
    ] {
        let mut response = Response::builder().status(status);

        if let Some(content_type) = content_type {
            response = response.header(header::CONTENT_TYPE, content_type);
        }

        let mut workflow = workflow(42);

        fulfill(
            &mut workflow,
            AcquisitionReply::Http(Ok(response.body(vec![0]).unwrap())),
        );

        assert!(matches!(
            workflow.advance(),
            Err(AcquisitionError::HttpErrorResponse(s, c))
                if s == status && c.as_deref() == content_type
        ));
    }

    let mut failed = workflow(42);

    fulfill(
        &mut failed,
        AcquisitionReply::Http(Err("host timeout".into())),
    );

    assert!(matches!(
        failed.advance(),
        Err(AcquisitionError::Transport(message)) if message == "host timeout"
    ));

    assert!(failed.outstanding_requests().is_empty());

    assert!(matches!(
        failed.advance(),
        Err(AcquisitionError::Protocol(ProtocolError::WorkflowFailed(_)))
    ));

    for bytes in [vec![0], vec![]] {
        let mut workflow = workflow(42);

        fulfill(
            &mut workflow,
            AcquisitionReply::Http(Ok(http_response(bytes))),
        );

        assert!(matches!(
            workflow.advance(),
            Err(AcquisitionError::DecodeError(_))
        ));
    }
}

#[test]
fn malformed_request_and_http_headers_fail_before_host_io() {
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
fn response_limit_is_enforced_at_exact_boundary_without_truncation() {
    let encode = |text_length| {
        rasn::der::encode(&TimestampResponse {
            status: Status {
                status: 2.into(),
                text: Some(vec!["x".repeat(text_length)]),
            },

            token: None,
        })
        .unwrap()
    };

    let overhead = encode(MAX_RESPONSE_BYTES).len() - MAX_RESPONSE_BYTES;
    let bytes = encode(MAX_RESPONSE_BYTES - overhead);
    assert_eq!(bytes.len(), MAX_RESPONSE_BYTES);
    let mut accepted = workflow(42);

    fulfill(
        &mut accepted,
        AcquisitionReply::Http(Ok(http_response(bytes.clone()))),
    );

    assert_eq!(accepted.advance().unwrap(), Step::Complete);
    assert_eq!(accepted.finish().unwrap().as_der(), bytes);

    let oversized = encode(MAX_RESPONSE_BYTES - overhead + 1);
    assert_eq!(oversized.len(), MAX_RESPONSE_BYTES + 1);
    let mut rejected = workflow(42);
    let mut response = http_response(oversized);

    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, "0".parse().unwrap());

    fulfill(&mut rejected, AcquisitionReply::Http(Ok(response)));

    assert!(matches!(
        rejected.advance(),
        Err(AcquisitionError::ResponseTooLarge)
    ));
}

#[test]
fn lifecycle_errors_are_not_successful_acquisition() {
    let unfinished = workflow(42);

    assert!(matches!(
        unfinished.finish(),
        Err(AcquisitionError::Protocol(
            ProtocolError::WorkflowNotComplete
        ))
    ));

    let mut finished = workflow(42);
    assert_eq!(finished.advance().unwrap(), Step::AwaitHost);
    let id = finished.outstanding_requests()[0].id;

    finished
        .fulfill(
            id,
            AcquisitionReply::Http(Ok(http_response(response_der(2, None, false)))),
        )
        .unwrap();

    assert!(matches!(
        finished.fulfill(id, AcquisitionReply::Http(Err("duplicate".into()))),
        Err(AcquisitionError::Protocol(_))
    ));

    assert_eq!(finished.advance().unwrap(), Step::Complete);

    assert!(matches!(
        finished.fulfill(id, AcquisitionReply::Http(Err("late".into()))),
        Err(AcquisitionError::Protocol(ProtocolError::WorkflowComplete))
    ));
}
