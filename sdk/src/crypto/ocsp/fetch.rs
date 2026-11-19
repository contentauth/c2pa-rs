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

use std::io::{self, Read};

use async_generic::async_generic;
use http::header;
use rasn::prelude::*;
use rasn_pkix::Certificate;
use x509_parser::{
    der_parser::{oid, Oid},
    extensions::ParsedExtension,
    prelude::*,
};

use crate::{
    context::{Context, ProgressPhase},
    crypto::base64,
    http::HttpResolverError,
};

const AD_OCSP_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .48 .1);
const AUTHORITY_INFO_ACCESS_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .1 .1);

// Preserve the existing fetch budget; verification-side budgets are tracked in #3026.
const MAX_OCSP_RESPONSE_SIZE: usize = 1_000_000;
const OCSP_READ_BUFFER_SIZE: usize = 8192;

fn read_ocsp_response(body: impl Read) -> Result<Vec<u8>, HttpResolverError> {
    let mut body = body.take(MAX_OCSP_RESPONSE_SIZE as u64 + 1);
    let mut response = Vec::new();
    let mut chunk = [0; OCSP_READ_BUFFER_SIZE];

    loop {
        let count = match body.read(&mut chunk) {
            Ok(0) => return Ok(response),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };

        let needed = response.len() + count;

        if needed > MAX_OCSP_RESPONSE_SIZE {
            return Err(HttpResolverError::ResponseTooLarge);
        }

        if needed > response.capacity() {
            // Explicit growth avoids read_to_end's speculative allocation past the budget.
            let capacity = response
                .capacity()
                .saturating_mul(2)
                .max(needed)
                .min(MAX_OCSP_RESPONSE_SIZE);
            response.reserve_exact(capacity - response.len());
        }

        response.extend_from_slice(&chunk[..count]);
    }
}

// Common types and structures used across all targets
struct OcspRequestData {
    request_str: String,
    url: url::Url,
}

// Common function to extract AIA responders from a certificate
fn extract_aia_responders(cert: &x509_parser::certificate::X509Certificate) -> Option<Vec<String>> {
    let em = cert.extensions_map().ok()?;

    let aia_extension = em.get(&AUTHORITY_INFO_ACCESS_OID)?;

    let ParsedExtension::AuthorityInfoAccess(aia) = aia_extension.parsed_extension() else {
        return None;
    };

    let mut output = Vec::new();

    for ad in &aia.accessdescs {
        if let x509_parser::extensions::GeneralName::URI(uri) = ad.access_location {
            if ad.access_method == AD_OCSP_OID {
                output.push(uri.to_string())
            }
        }
    }
    Some(output)
}

// Common function to build OCSP request data
fn build_ocsp_request(
    subject_der: &[u8],
    issuer_der: &[u8],
    responder_url: &str,
) -> Option<OcspRequestData> {
    let subject: Certificate = rasn::der::decode(subject_der).ok()?;
    let issuer: Certificate = rasn::der::decode(issuer_der).ok()?;

    let issuer_name_raw = rasn::der::encode(&issuer.tbs_certificate.subject).ok()?;
    let issuer_key_raw = &issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_raw_slice();

    let issuer_name_hash = OctetString::from(crate::crypto::hash::sha1(&issuer_name_raw));
    let issuer_key_hash = OctetString::from(crate::crypto::hash::sha1(issuer_key_raw));
    let serial_number = subject.tbs_certificate.serial_number;

    // Build request structures
    let sha1_oid = rasn::types::Oid::new(&[1, 3, 14, 3, 2, 26])?;
    let alg = rasn::types::ObjectIdentifier::from(sha1_oid);

    let sha1_ai = rasn_pkix::AlgorithmIdentifier {
        algorithm: alg,
        parameters: Some(Any::new(rasn::der::encode(&()).ok()?)),
        // Many OCSP responders expect this to be NULL not None.
    };

    let req_cert = rasn_ocsp::CertId {
        hash_algorithm: sha1_ai,
        issuer_name_hash,
        issuer_key_hash,
        serial_number,
    };

    let ocsp_req = rasn_ocsp::Request {
        req_cert,
        single_request_extensions: None,
    };

    let request_list = vec![ocsp_req];

    let tbs_request = rasn_ocsp::TbsRequest {
        version: rasn_ocsp::Version::from(0u8),
        requestor_name: None,
        request_list,
        request_extensions: None,
    };

    let ocsp_request = rasn_ocsp::OcspRequest {
        tbs_request,
        optional_signature: None,
    };

    let request_der = rasn::der::encode(&ocsp_request).ok()?;
    let request_str = base64::encode(&request_der);
    let url = url::Url::parse(responder_url).ok()?;

    Some(OcspRequestData { request_str, url })
}

// Build OCSP requests for the certificate at `subject_index`, read from its own
// AIA responder(s) with `certs[subject_index + 1]` as the issuer. This lets each
// certificate in the chain (the leaf and each issuing CA) be queried, not just
// the leaf.
fn process_ocsp_responders(
    certs: &[Vec<u8>],
    subject_index: usize,
) -> Option<Vec<OcspRequestData>> {
    let subject_der = certs.get(subject_index)?;
    let issuer_der = certs.get(subject_index + 1)?;

    let (_rem, cert) = X509Certificate::from_der(subject_der).ok()?;

    let requests: Vec<_> = extract_aia_responders(&cert)
        .into_iter()
        .flat_map(|responders| {
            responders
                .into_iter()
                .filter_map(|responder| build_ocsp_request(subject_der, issuer_der, &responder))
        })
        .collect();

    if requests.is_empty() {
        None
    } else {
        Some(requests)
    }
}

/// Retrieve an OCSP response for the certificate at `subject_index` if available.
///
/// Checks for an OCSP responder in that certificate's AIA extension. If found,
/// it will attempt to retrieve the raw DER-encoded OCSP response.
///
/// Both fetch APIs accept at most 1,000,000 body bytes, ignoring `Content-Length`.
/// They consume at most one extra byte to detect overflow and try the next AIA
/// responder on overflow. SDK response-vector capacity requests are bounded by
/// that budget, plus an 8192-byte stack read buffer. This does not bound buffering
/// performed by the HTTP resolver before it returns the body.
#[async_generic]
pub(crate) fn fetch_ocsp_response(
    certs: &[Vec<u8>],
    subject_index: usize,
    context: &Context,
) -> Option<Vec<u8>> {
    let requests = process_ocsp_responders(certs, subject_index)?;
    let requests_len = requests.len() as u32;
    for (step, request_data) in (1..).zip(requests) {
        context
            .check_progress(ProgressPhase::FetchingOCSP, step, requests_len)
            .ok()?;
        let req_url = request_data.url.join(&request_data.request_str).ok()?;

        let mut request = http::Request::get(req_url.to_string());
        if let Some(host) = req_url.host() {
            // for responders that don't support http 1.0
            request = request.header(header::HOST, host.to_string());
        }

        let request = request.body(Vec::new()).ok()?;
        let response = if _sync {
            context.resolver().http_resolve(request).ok()?
        } else {
            context
                .resolver_async()
                .http_resolve_async(request)
                .await
                .ok()?
        };

        if response.status() == 200 {
            match read_ocsp_response(response.into_body()) {
                Ok(response) => return Some(response),
                Err(HttpResolverError::ResponseTooLarge) => {
                    log::warn!(
                        "OCSP response exceeds the {MAX_OCSP_RESPONSE_SIZE}-byte fetch limit"
                    );
                }
                Err(error) => {
                    log::debug!("Could not read OCSP response: {error}");
                    return None;
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{
        io::{self, Cursor, Read},
        sync::{Arc, Mutex},
    };

    use http::{Request, Response};

    use super::*;
    use crate::{
        crypto::cert_chain_pem_to_der,
        http::{HttpResolverError, SyncHttpResolver},
    };

    // [leaf(AIA=leaf-ocsp.test), issuing CA(AIA=ca-ocsp.test), root].
    fn ca_chain() -> Vec<Vec<u8>> {
        let pem = include_bytes!("../../../tests/fixtures/crypto/ocsp/ocsp_ca_chain.pem");
        cert_chain_pem_to_der(pem).unwrap()
    }

    fn responder_hosts(certs: &[Vec<u8>], subject_index: usize) -> Vec<String> {
        process_ocsp_responders(certs, subject_index)
            .unwrap()
            .iter()
            .filter_map(|r| r.url.host_str().map(|h| h.to_string()))
            .collect()
    }

    #[test]
    fn each_cert_is_queried_against_its_own_responder() {
        let certs = ca_chain();

        // The leaf is queried against its own responder...
        let leaf_hosts = responder_hosts(&certs, 0);
        assert!(leaf_hosts.iter().any(|h| h == "leaf-ocsp.test"));
        assert!(!leaf_hosts.iter().any(|h| h == "ca-ocsp.test"));

        // ...and the issuing CA against its own responder (the fix: previously
        // the CA was never contacted, so a revoked CA went undetected).
        let ca_hosts = responder_hosts(&certs, 1);
        assert!(ca_hosts.iter().any(|h| h == "ca-ocsp.test"));
    }

    #[test]
    fn request_encodes_subject_serial_issuer_hashes_and_null_sha1_parameters() {
        let certs = ca_chain();
        for index in [0, 1] {
            let requests = process_ocsp_responders(&certs, index).unwrap();
            let der = base64::decode(&requests[0].request_str).unwrap();
            let request: rasn_ocsp::OcspRequest = rasn::der::decode(&der).unwrap();
            assert!(request.optional_signature.is_none());
            let tbs = request.tbs_request;
            assert!(tbs.requestor_name.is_none());
            assert!(tbs.request_extensions.is_none());
            assert_eq!(tbs.request_list.len(), 1);
            let id = &tbs.request_list[0].req_cert;
            assert_eq!(id.hash_algorithm.algorithm.to_string(), "1.3.14.3.2.26");
            assert_eq!(
                id.hash_algorithm.parameters.as_ref().unwrap().as_bytes(),
                &[0x05, 0x00]
            );
            assert!(super::super::cert_id_matches_signer(id, &certs[index..]));
        }
    }

    #[test]
    fn request_building_rejects_missing_invalid_certificates_and_urls() {
        let certs = ca_chain();
        for (subject, issuer, url) in [
            (&[][..], certs[1].as_slice(), "http://ocsp.test"),
            (certs[0].as_slice(), &[][..], "http://ocsp.test"),
            (certs[0].as_slice(), certs[1].as_slice(), "not a URL"),
        ] {
            assert!(build_ocsp_request(subject, issuer, url).is_none());
        }

        assert!(process_ocsp_responders(&[], 0).is_none());
        assert!(process_ocsp_responders(&certs, 2).is_none());
        assert!(process_ocsp_responders(&certs, 3).is_none());
        assert!(process_ocsp_responders(&[vec![0], certs[1].clone()], 0).is_none());
        // The root has no OCSP AIA; supplying an issuer does not invent one.
        assert!(process_ocsp_responders(&[certs[2].clone(), certs[2].clone()], 0).is_none());
    }

    #[derive(Clone, Copy)]
    enum Reply {
        Bytes,
        NoLength,
        InvalidLength,
        NonTextLength,
        CombinedLength,
        ConflictingLength,
        ZeroLength,
        ShortLength,
        LongLength,
        HugeLength,
        Chunked,
        NonSuccess,
        TransportError,
        ReadError,
        AtLimit,
        ChunkedAtLimit,
        Oversize,
        ChunkedOversize,
        Infinite,
    }

    const REPLIES: &[Reply] = &[
        Reply::Bytes,
        Reply::NoLength,
        Reply::InvalidLength,
        Reply::NonTextLength,
        Reply::CombinedLength,
        Reply::ConflictingLength,
        Reply::ZeroLength,
        Reply::ShortLength,
        Reply::LongLength,
        Reply::HugeLength,
        Reply::Chunked,
        Reply::NonSuccess,
        Reply::TransportError,
        Reply::ReadError,
        Reply::AtLimit,
        Reply::ChunkedAtLimit,
        Reply::Oversize,
        Reply::ChunkedOversize,
        Reply::Infinite,
    ];

    type RecordedRequests = Arc<Mutex<Vec<Request<Vec<u8>>>>>;

    #[derive(Default)]
    struct ReadStats {
        bytes: usize,
        calls: usize,
        max_buffer: usize,
    }

    struct TestResolver {
        reply: Reply,
        requests: RecordedRequests,
        reads: Arc<Mutex<ReadStats>>,
        later_reply: Option<Reply>,
    }

    struct RecordingReader {
        body: Box<dyn Read>,
        reads: Arc<Mutex<ReadStats>>,
        chunk_size: usize,
        consumed: usize,
    }

    impl Read for RecordingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let mut reads = self.reads.lock().unwrap();
            reads.calls += 1;
            reads.max_buffer = reads.max_buffer.max(buffer.len());
            assert!(buffer.len() <= OCSP_READ_BUFFER_SIZE);
            let count = buffer.len().min(self.chunk_size);
            let count = self.body.read(&mut buffer[..count])?;
            reads.bytes += count;
            self.consumed += count;
            assert!(self.consumed <= MAX_OCSP_RESPONSE_SIZE + 1);
            Ok(count)
        }
    }

    struct BrokenReader;
    impl Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture read failure"))
        }
    }

    impl SyncHttpResolver for TestResolver {
        fn http_resolve(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            let reply = {
                let mut requests = self.requests.lock().unwrap();
                let reply = if requests.is_empty() {
                    self.reply
                } else {
                    self.later_reply.unwrap_or(self.reply)
                };

                requests.push(request);
                reply
            };

            if matches!(reply, Reply::TransportError) {
                return Err(HttpResolverError::Other("fixture transport failure".into()));
            }

            let mut response = Response::builder().status(if matches!(reply, Reply::NonSuccess) {
                503
            } else {
                200
            });
            response = match reply {
                Reply::Bytes => response.header(header::CONTENT_LENGTH, "3"),
                Reply::InvalidLength => response.header(header::CONTENT_LENGTH, "not-a-number"),
                Reply::NonTextLength => response.header(
                    header::CONTENT_LENGTH,
                    http::HeaderValue::from_bytes(&[0xff]).unwrap(),
                ),
                Reply::CombinedLength => response.header(header::CONTENT_LENGTH, "3, 999999999"),
                Reply::ConflictingLength => response
                    .header(header::CONTENT_LENGTH, "3")
                    .header(header::CONTENT_LENGTH, "999999999"),
                Reply::ZeroLength => response.header(header::CONTENT_LENGTH, "0"),
                Reply::ShortLength => response.header(header::CONTENT_LENGTH, "1"),
                Reply::LongLength => response.header(header::CONTENT_LENGTH, "1000001"),
                Reply::HugeLength => {
                    response.header(header::CONTENT_LENGTH, "18446744073709551615")
                }
                Reply::Chunked | Reply::ChunkedAtLimit | Reply::ChunkedOversize => {
                    response.header(header::TRANSFER_ENCODING, "chunked")
                }
                Reply::Oversize => response.header(header::CONTENT_LENGTH, "3"),
                _ => response,
            };

            let body: Box<dyn Read> = match reply {
                Reply::ReadError => Box::new(BrokenReader),
                Reply::AtLimit | Reply::ChunkedAtLimit => {
                    Box::new(io::repeat(42).take(MAX_OCSP_RESPONSE_SIZE as u64))
                }
                Reply::Oversize | Reply::ChunkedOversize => {
                    Box::new(io::repeat(42).take(MAX_OCSP_RESPONSE_SIZE as u64 + 1))
                }
                Reply::Infinite => Box::new(io::repeat(42)),
                _ => Box::new(Cursor::new(vec![1, 2, 3])),
            };

            let body: Box<dyn Read> = Box::new(RecordingReader {
                body,
                reads: self.reads.clone(),
                chunk_size: match reply {
                    Reply::Chunked => 1,
                    Reply::ChunkedAtLimit | Reply::ChunkedOversize => 1023,
                    _ => OCSP_READ_BUFFER_SIZE,
                },
                consumed: 0,
            });

            Ok(response.body(body).unwrap())
        }
    }

    fn resolver(reply: Reply) -> (TestResolver, RecordedRequests) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            TestResolver {
                reply,
                requests: requests.clone(),
                reads: Arc::new(Mutex::new(ReadStats::default())),
                later_reply: None,
            },
            requests,
        )
    }

    fn assert_fetch_result(reply: Reply, result: Option<Vec<u8>>, reads: &ReadStats) {
        match reply {
            Reply::NonSuccess | Reply::TransportError | Reply::ReadError => {
                assert!(result.is_none());
                assert_eq!(reads.bytes, 0);
            }
            Reply::Oversize | Reply::ChunkedOversize | Reply::Infinite => {
                assert!(result.is_none());
                assert_eq!(reads.bytes, MAX_OCSP_RESPONSE_SIZE + 1);
            }
            Reply::AtLimit | Reply::ChunkedAtLimit => {
                let result = result.unwrap();
                assert_eq!(result.len(), MAX_OCSP_RESPONSE_SIZE);
                assert!(result.iter().all(|byte| *byte == 42));
                assert!(result.capacity() <= MAX_OCSP_RESPONSE_SIZE);
                assert_eq!(reads.bytes, MAX_OCSP_RESPONSE_SIZE);
            }
            _ => {
                let result = result.unwrap();
                assert_eq!(result, [1, 2, 3]);
                assert!(result.capacity() <= OCSP_READ_BUFFER_SIZE);
                assert_eq!(reads.bytes, 3);

                if matches!(reply, Reply::Chunked) {
                    assert_eq!(reads.calls, 4);
                }
            }
        }

        assert!(reads.max_buffer <= OCSP_READ_BUFFER_SIZE);
    }

    #[test]
    fn fetch_transport_status_body_limits_and_request_shape() {
        for &reply in REPLIES {
            let (resolver, requests) = resolver(reply);
            let reads = resolver.reads.clone();
            let context = Context::new().with_resolver(resolver);
            let result = fetch_ocsp_response(&ca_chain(), 0, &context);
            assert_fetch_result(reply, result, &reads.lock().unwrap());

            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method(), http::Method::GET);
            assert_eq!(requests[0].headers()[header::HOST], "leaf-ocsp.test");
            assert_eq!(
                requests[0]
                    .extensions()
                    .get::<crate::http::RequestTimeout>(),
                Some(&crate::http::RequestTimeout(
                    std::time::Duration::from_secs(10)
                ))
            );
            assert!(requests[0].body().is_empty());
            let request_data = process_ocsp_responders(&ca_chain(), 0).unwrap();
            assert_eq!(
                requests[0].uri().to_string(),
                request_data[0]
                    .url
                    .join(&request_data[0].request_str)
                    .unwrap()
                    .as_str()
            );
        }
    }

    #[test]
    fn cancelled_progress_never_contacts_resolver() {
        let (resolver, requests) = resolver(Reply::Bytes);
        let context = Context::new()
            .with_resolver(resolver)
            .with_progress_callback(|phase, step, total| {
                assert_eq!(phase, ProgressPhase::FetchingOCSP);
                assert_eq!((step, total), (1, 1));
                false
            });
        assert!(fetch_ocsp_response(&ca_chain(), 0, &context).is_none());
        assert!(requests.lock().unwrap().is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[async_trait::async_trait]
    impl crate::http::AsyncHttpResolver for TestResolver {
        async fn http_resolve_async(
            &self,
            request: Request<Vec<u8>>,
        ) -> Result<Response<Box<dyn Read>>, HttpResolverError> {
            self.http_resolve(request)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn async_fetch_obeys_transport_failures_and_cancellation() {
        for &reply in REPLIES {
            let (resolver, requests) = resolver(reply);
            let reads = resolver.reads.clone();
            let context = Context::new().with_resolver_async(resolver);
            let result = fetch_ocsp_response_async(&ca_chain(), 1, &context).await;
            assert_fetch_result(reply, result, &reads.lock().unwrap());

            assert_eq!(
                requests.lock().unwrap()[0].headers()[header::HOST],
                "ca-ocsp.test"
            );
        }

        let (resolver, requests) = resolver(Reply::Bytes);
        let context = Context::new()
            .with_resolver_async(resolver)
            .with_progress_callback(|_, _, _| false);
        assert!(fetch_ocsp_response_async(&ca_chain(), 0, &context)
            .await
            .is_none());
        assert!(requests.lock().unwrap().is_empty());
    }

    fn chain_with_two_responders() -> Vec<Vec<u8>> {
        let mut certs = ca_chain();
        let mut leaf: Certificate = rasn::der::decode(&certs[0]).unwrap();
        let extension = leaf
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|extension| extension.extn_id.to_string() == "1.3.6.1.5.5.7.1.1")
            .unwrap();

        // Fetching parses AIA without checking the certificate's signature.
        let mut responders: Vec<Any> = rasn::der::decode(&extension.extn_value).unwrap();
        responders.push(responders[0].clone());
        extension.extn_value = rasn::der::encode(&responders).unwrap().into();
        certs[0] = rasn::der::encode(&leaf).unwrap();
        assert_eq!(process_ocsp_responders(&certs, 0).unwrap().len(), 2);
        certs
    }

    #[test]
    fn oversize_response_falls_back_to_next_responder_and_honors_cancellation() {
        let certs = chain_with_two_responders();

        for cancel in [false, true] {
            let (mut resolver, requests) = resolver(Reply::Oversize);
            resolver.later_reply = Some(Reply::Bytes);
            let context = Context::new()
                .with_resolver(resolver)
                .with_progress_callback(move |_, step, total| {
                    assert_eq!(total, 2);
                    !cancel || step == 1
                });

            let result = fetch_ocsp_response(&certs, 0, &context);
            assert_eq!(result, if cancel { None } else { Some(vec![1, 2, 3]) });
            assert_eq!(requests.lock().unwrap().len(), if cancel { 1 } else { 2 });
        }
    }

    #[test]
    fn first_usable_responder_keeps_precedence() {
        let (mut resolver, requests) = resolver(Reply::Bytes);
        resolver.later_reply = Some(Reply::Oversize);
        let context = Context::new().with_resolver(resolver);
        assert_eq!(
            fetch_ocsp_response(&chain_with_two_responders(), 0, &context),
            Some(vec![1, 2, 3])
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn async_oversize_response_falls_back_and_honors_cancellation() {
        let certs = chain_with_two_responders();

        for cancel in [false, true] {
            let (mut resolver, requests) = resolver(Reply::Oversize);
            resolver.later_reply = Some(Reply::Bytes);
            let context = Context::new()
                .with_resolver_async(resolver)
                .with_progress_callback(move |_, step, total| {
                    assert_eq!(total, 2);
                    !cancel || step == 1
                });

            let result = fetch_ocsp_response_async(&certs, 0, &context).await;
            assert_eq!(result, if cancel { None } else { Some(vec![1, 2, 3]) });
            assert_eq!(requests.lock().unwrap().len(), if cancel { 1 } else { 2 });
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn async_first_usable_responder_keeps_precedence() {
        let (mut resolver, requests) = resolver(Reply::Bytes);
        resolver.later_reply = Some(Reply::Oversize);
        let context = Context::new().with_resolver_async(resolver);
        assert_eq!(
            fetch_ocsp_response_async(&chain_with_two_responders(), 0, &context).await,
            Some(vec![1, 2, 3])
        );
        assert_eq!(requests.lock().unwrap().len(), 1);
    }

    #[test]
    fn bounded_reader_reports_typed_overflow_and_retries_interrupted_reads() {
        assert_eq!(MAX_OCSP_RESPONSE_SIZE, 1_000_000);
        assert_eq!(OCSP_READ_BUFFER_SIZE, 8192);
        assert!(matches!(
            read_ocsp_response(io::repeat(42)),
            Err(HttpResolverError::ResponseTooLarge)
        ));

        struct InterruptedReader(bool);

        impl Read for InterruptedReader {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    Err(io::ErrorKind::Interrupted.into())
                } else {
                    io::empty().read(buffer)
                }
            }
        }

        assert!(read_ocsp_response(InterruptedReader(false))
            .unwrap()
            .is_empty());
        assert!(matches!(
            read_ocsp_response(BrokenReader),
            Err(HttpResolverError::Io(_))
        ));
    }
}
