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

fn response_der(status: u8, nonce: Option<u64>, token: bool, text: Option<String>) -> Vec<u8> {
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
            let mut workflow = acquire_with_body("https://tsa.example/", vec![], &body).unwrap();
            assert_eq!(workflow.advance().unwrap(), Step::AwaitHost);
            let AcquisitionRequest::HttpPost(post) = &workflow.outstanding_requests()[0].kind;
            assert_eq!(post.body(), &body);
            fulfill(
                &mut workflow,
                AcquisitionReply::Http(Ok(http_response(response_der(1, reflected, true, None)))),
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
