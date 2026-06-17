// Loosely derived from
// https://github.com/spruceid/ssi/blob/ssi/v0.9.0/crates/dids/methods/web/src/lib.rs
// which was published under an Apache 2.0 license.

// Subsequent modifications are subject to license from Adobe
// as follows:

// Copyright 2024 Adobe. All rights reserved.
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

use std::io::Read;

use async_generic::async_generic;

use super::{did::Did, did_doc::DidDocument};
use crate::http::{
    AsyncHttpResolver, HttpResolverError, HttpResolvers, SyncGenericResolver, SyncHttpResolver,
};

/// Maximum number of bytes accepted from a DID Web server response body.
pub(crate) const MAX_DID_DOC_SIZE: u64 = 1024 * 1024; // 1 MiB

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
use std::{cell::RefCell, collections::HashMap};

#[cfg(test)]
thread_local! {
    /// Maps a `did:web` domain name to a URL prefix (ending in `/`) that should
    /// be used in place of the real `https://{domain}/` origin. Tests register
    /// entries here to redirect DID document resolution to a local mock server,
    /// keeping the suite hermetic.
    pub(crate) static PROXIES: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
}

/// Redirect `did:web` resolution for `domain` to `url_prefix` (a base URL
/// ending in `/`, such as a mock server origin) for the current thread.
#[cfg(test)]
pub(crate) fn set_proxy(domain: &str, url_prefix: &str) {
    PROXIES.with(|proxies| {
        proxies
            .borrow_mut()
            .insert(domain.to_string(), url_prefix.to_string());
    });
}

/// Remove all `did:web` resolution redirects for the current thread.
#[cfg(test)]
pub(crate) fn clear_proxies() {
    PROXIES.with(|proxies| proxies.borrow_mut().clear());
}

use http::header;

#[derive(Debug, thiserror::Error)]
pub enum DidWebError {
    #[error("error building HTTP client: {0}")]
    Client(HttpResolverError),

    #[error("error sending HTTP request ({0}): {1}")]
    Request(String, HttpResolverError),

    #[error("server error: {0}")]
    Server(String),

    #[error("error reading HTTP response: {0}")]
    Response(HttpResolverError),

    #[error("the document was not found: {0}")]
    NotFound(String),

    #[error("the document was not a valid DID document: {0}")]
    InvalidData(String),

    #[error("invalid web DID: {0}")]
    InvalidWebDid(String),

    #[error("response body exceeded size limit of {MAX_DID_DOC_SIZE} bytes")]
    ResponseTooLarge,
}

fn prepare_url(did: &Did<'_>) -> Result<String, DidWebError> {
    let method = did.method_name();
    #[allow(clippy::panic)] // TEMPORARY while refactoring
    if method != "web" {
        panic!("Unexpected DID method {method}");
    }
    to_url(did.method_specific_id())
}

fn parse_did_doc(bytes: Vec<u8>, url: &str) -> Result<DidDocument, DidWebError> {
    let json = String::from_utf8(bytes).map_err(|_| DidWebError::InvalidData(url.to_owned()))?;
    DidDocument::from_json(&json).map_err(|_| DidWebError::InvalidData(url.to_owned()))
}

pub(crate) async fn resolve_async(
    did: &Did<'_>,
    resolvers: &dyn HttpResolvers,
) -> Result<DidDocument, DidWebError> {
    let url = prepare_url(did)?;
    // TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security
    let bytes = get_did_doc_async(&url, resolvers).await?;
    parse_did_doc(bytes, &url)
}

fn build_request(url: &str) -> Result<http::Request<Vec<u8>>, DidWebError> {
    http::Request::get(url)
        .header(header::USER_AGENT, USER_AGENT)
        .header(header::ACCEPT, "application/did+json")
        .body(Vec::new())
        .map_err(|e| DidWebError::Request(url.to_owned(), e.into()))
}

fn check_response_status(status: http::StatusCode, url: &str) -> Result<(), DidWebError> {
    match status {
        http::StatusCode::OK => Ok(()),
        http::StatusCode::NOT_FOUND => Err(DidWebError::NotFound(url.to_string())),
        _ => Err(DidWebError::Server(status.to_string())),
    }
}

fn read_body_with_limit(body: Box<dyn Read>, url: &str) -> Result<Vec<u8>, DidWebError> {
    let mut document = Vec::new();
    body.take(MAX_DID_DOC_SIZE + 1)
        .read_to_end(&mut document)
        .map_err(|e| DidWebError::Response(e.into()))?;
    if document.len() as u64 > MAX_DID_DOC_SIZE {
        return Err(DidWebError::ResponseTooLarge);
    }
    Ok(document)
}

#[async_generic]
fn get_did_doc(url: &str, resolvers: &dyn HttpResolvers) -> Result<Vec<u8>, DidWebError> {
    let request = build_request(url)?;

    let response = if _sync {
        resolvers
            .sync_resolver()
            .http_resolve(request)
            .map_err(|e| DidWebError::Request(url.to_owned(), e))?
    } else {
        resolvers
            .async_resolver()
            .http_resolve_async(request)
            .await
            .map_err(|e| DidWebError::Request(url.to_owned(), e))?
    };

    // Fast-fail if Content-Length exceeds the limit before reading any body bytes.
    let reported_len = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    if let Some(len) = reported_len {
        if len > MAX_DID_DOC_SIZE {
            return Err(DidWebError::ResponseTooLarge);
        }
    }

    let (parts, body) = response.into_parts();
    check_response_status(parts.status, url)?;
    read_body_with_limit(body, url)
}

pub(crate) fn resolve(
    did: &Did<'_>,
    resolvers: &dyn HttpResolvers,
) -> Result<DidDocument, DidWebError> {
    let url = prepare_url(did)?;
    // TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security
    let bytes = get_did_doc(&url, resolvers)?;
    parse_did_doc(bytes, &url)
}

pub(crate) fn to_url(did: &str) -> Result<String, DidWebError> {
    let mut parts = did.split(':').peekable();
    let domain_name = parts
        .next()
        .ok_or_else(|| DidWebError::InvalidWebDid(did.to_owned()))?;

    // TODO:
    // - Ensure domain name matches TLS certificate common name
    // - Support punycode?
    // - Support query strings?

    // Reject bare IPv4/IPv6 literals — did:web requires a DNS domain name.
    // Domain may include a %3A-encoded port (e.g. "192.168.1.1%3A8080"), so
    // strip the port suffix before checking.
    let host_part = domain_name.split("%3A").next().unwrap_or(domain_name);
    if host_part.parse::<std::net::IpAddr>().is_ok() {
        return Err(DidWebError::InvalidWebDid(did.to_owned()));
    }

    let path = match parts.peek() {
        Some(_) => parts.collect::<Vec<&str>>().join("/"),
        None => ".well-known".to_string(),
    };

    // Use http for localhost in tests only — production always requires HTTPS.
    #[cfg(test)]
    let proto = if domain_name.starts_with("localhost") {
        "http"
    } else {
        "https"
    };
    #[cfg(not(test))]
    let proto = "https";

    #[allow(unused_mut)]
    let mut url = format!(
        "{proto}://{}/{path}/did.json",
        domain_name.replacen("%3A", ":", 1)
    );

    #[cfg(test)]
    PROXIES.with(|proxies| {
        if let Some(prefix) = proxies.borrow().get(domain_name) {
            url = format!("{prefix}{path}/did.json");
        }
    });

    Ok(url)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::identity::claim_aggregation::w3c_vc::{did::Did, did_web};

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn to_url() {
        // https://w3c-ccg.github.io/did-method-web/#example-3-creating-the-did
        assert_eq!(
            did_web::to_url(did("did:web:w3c-ccg.github.io").method_specific_id()).unwrap(),
            "https://w3c-ccg.github.io/.well-known/did.json"
        );
        // https://w3c-ccg.github.io/did-method-web/#example-4-creating-the-did-with-optional-path
        assert_eq!(
            did_web::to_url(did("did:web:w3c-ccg.github.io:user:alice").method_specific_id())
                .unwrap(),
            "https://w3c-ccg.github.io/user/alice/did.json"
        );
        // https://w3c-ccg.github.io/did-method-web/#optional-path-considerations
        assert_eq!(
            did_web::to_url(did("did:web:example.com:u:bob").method_specific_id()).unwrap(),
            "https://example.com/u/bob/did.json"
        );
        // https://w3c-ccg.github.io/did-method-web/#example-creating-the-did-with-optional-path-and-port
        assert_eq!(
            did_web::to_url(did("did:web:example.com%3A443:u:bob").method_specific_id()).unwrap(),
            "https://example.com:443/u/bob/did.json"
        );

        // IPv4 literals must be rejected (SSRF: CAI-10364)
        assert!(
            did_web::to_url(did("did:web:192.168.1.1").method_specific_id()).is_err(),
            "RFC-1918 IPv4 must be rejected"
        );
        assert!(
            did_web::to_url(did("did:web:169.254.169.254").method_specific_id()).is_err(),
            "link-local IPv4 (AWS metadata) must be rejected"
        );
        assert!(
            did_web::to_url(did("did:web:127.0.0.1").method_specific_id()).is_err(),
            "loopback IPv4 must be rejected"
        );
        // IPv4 with %3A-encoded port must also be rejected
        assert!(
            did_web::to_url(did("did:web:192.168.1.1%3A8080:path").method_specific_id()).is_err(),
            "RFC-1918 IPv4 with port must be rejected"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod resolve {
        use httpmock::prelude::*;

        use super::did;
        use crate::{
            http::{AsyncGenericResolver, ResolverBundle, SyncGenericResolver},
            identity::claim_aggregation::w3c_vc::{
                did_doc::DidDocument,
                did_web::{self, DidWebError, MAX_DID_DOC_SIZE},
            },
        };

        #[tokio::test]
        // #[cfg_attr(all(target_arch = "wasm32", not(target_os = "wasi")),
        // wasm_bindgen_test)] Can't test this on WASM until we find an httpmock
        // replacement.
        async fn from_did_key() {
            const DID_JSON: &str = r#"{
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:web:localhost",
            "verificationMethod": [{
                "id": "did:web:localhost#key1",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:web:localhost",
                "publicKeyBase58": "2sXRz2VfrpySNEL6xmXJWQg6iY94qwNp1qrJJFBuPWmH"
            }],
            "assertionMethod": ["did:web:localhost#key1"]
        }"#;

            let server = MockServer::start();

            let server_url = server.url("/").replace("127.0.0.1", "localhost");
            did_web::set_proxy("localhost", &server_url);

            let did_doc_mock = server.mock(|when, then| {
                when.method(GET).path("/.well-known/did.json");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(DID_JSON);
            });

            let resolvers =
                ResolverBundle::new(SyncGenericResolver::new(), AsyncGenericResolver::new());
            let doc = did_web::resolve_async(&did("did:web:localhost"), &resolvers)
                .await
                .unwrap();
            let doc_expected = DidDocument::from_json(DID_JSON).unwrap();
            assert_eq!(doc, doc_expected);

            did_web::clear_proxies();

            did_doc_mock.assert();
        }

        #[tokio::test]
        async fn content_length_above_limit_rejected() {
            let server = MockServer::start();

            let server_url = server.url("/").replace("127.0.0.1", "localhost");
            did_web::set_proxy("localhost", &server_url);

            let oversized_body = vec![b'X'; (MAX_DID_DOC_SIZE + 1) as usize];
            let _mock = server.mock(|when, then| {
                when.method(GET).path("/.well-known/did.json");
                then.status(200)
                    .header("content-type", "application/did+json")
                    .header("content-length", (MAX_DID_DOC_SIZE + 1).to_string())
                    .body(oversized_body);
            });

            let resolvers =
                ResolverBundle::new(SyncGenericResolver::new(), AsyncGenericResolver::new());
            let result = did_web::resolve_async(&did("did:web:localhost"), &resolvers).await;

            did_web::clear_proxies();

            assert!(
                matches!(result, Err(did_web::DidWebError::ResponseTooLarge)),
                "expected ResponseTooLarge, got {result:?}"
            );
        }

        #[tokio::test]
        async fn oversized_response_returns_error() {
            let server = MockServer::start();

            let server_url = server.url("/").replace("127.0.0.1", "localhost");
            did_web::set_proxy("localhost", &server_url);

            // Serve a body one byte larger than the allowed limit.
            let oversized_body = vec![b'X'; (MAX_DID_DOC_SIZE + 1) as usize];
            let _mock = server.mock(|when, then| {
                when.method(GET).path("/.well-known/did.json");
                then.status(200)
                    .header("content-type", "application/did+json")
                    .body(oversized_body);
            });

            let resolvers =
                ResolverBundle::new(SyncGenericResolver::new(), AsyncGenericResolver::new());
            let result = did_web::resolve_async(&did("did:web:localhost"), &resolvers).await;

            did_web::clear_proxies();

            assert!(
                matches!(result, Err(did_web::DidWebError::ResponseTooLarge)),
                "expected ResponseTooLarge, got {result:?}"
            );
        }

        // --- CAI-10364 regression tests ---
        //
        // Before the fix, both of these tests would have demonstrated live SSRF:
        //
        // 1. ip_literal_no_network_request: `did:web:169.254.169.254` reached the
        //    AWS EC2 metadata service.  The PanicResolver proves no outbound call
        //    is made; before Fix 2 (IP literal rejection in to_url) it would have
        //    panicked because the resolver was invoked.
        //
        // 2. restricted_resolver_is_honoured: the old get_did_doc() created its
        //    own AsyncGenericResolver internally, discarding whatever resolver the
        //    caller supplied.  A RestrictedResolver with an empty allowlist was
        //    silently bypassed.  After Fix 1 the passed resolver is used, so the
        //    empty allowlist correctly blocks the request.

        #[tokio::test]
        async fn ip_literal_no_network_request() {
            use async_trait::async_trait;
            use http::{Request, Response};

            use crate::http::HttpResolverError;

            struct PanicResolver;

            #[async_trait]
            impl crate::http::AsyncHttpResolver for PanicResolver {
                async fn http_resolve_async(
                    &self,
                    _request: Request<Vec<u8>>,
                ) -> Result<Response<Box<dyn std::io::Read>>, HttpResolverError> {
                    panic!(
                        "outbound HTTP request must not be made for IP-literal DIDs (CAI-10364)"
                    );
                }
            }

            let resolver = PanicResolver;

            let resolvers = ResolverBundle::new(SyncGenericResolver::new(), resolver);
            // AWS EC2 metadata endpoint — the canonical SSRF target from the report.
            let result = did_web::resolve_async(&did("did:web:169.254.169.254"), &resolvers).await;
            assert!(
                matches!(result, Err(DidWebError::InvalidWebDid(_))),
                "expected InvalidWebDid for link-local IP, got {result:?}"
            );

            let result = did_web::resolve_async(&did("did:web:192.168.1.1"), &resolvers).await;
            assert!(
                matches!(result, Err(DidWebError::InvalidWebDid(_))),
                "expected InvalidWebDid for RFC-1918 IP, got {result:?}"
            );
        }

        #[tokio::test]
        async fn restricted_resolver_is_honoured() {
            use crate::http::{
                restricted::{HostPattern, RestrictedResolver},
                AsyncGenericResolver,
            };

            let server = MockServer::start();

            let server_url = server.url("/").replace("127.0.0.1", "localhost");
            did_web::set_proxy("localhost", &server_url);

            // Empty allowlist — every host blocked.
            // Before Fix 1, get_did_doc() ignored this and created its own resolver.
            let inner = AsyncGenericResolver::new();
            let restricted =
                RestrictedResolver::with_allowed_hosts(inner, vec![] as Vec<HostPattern>);
            let resolvers = ResolverBundle::new(SyncGenericResolver::new(), restricted);

            let result = did_web::resolve_async(&did("did:web:localhost"), &resolvers).await;

            did_web::clear_proxies();

            // The request must be blocked — UriDisallowed surfaces as DidWebError::Request.
            assert!(
                matches!(result, Err(DidWebError::Request(_, _))),
                "expected Request(UriDisallowed) from RestrictedResolver, got {result:?}"
            );
        }

        /*
            #[tokio::test]
        #[cfg_attr(all(target_arch = "wasm32", not(target_os = "wasi")), wasm_bindgen_test)]
            async fn credential_prove_verify_did_web() {
                let didweb = VerificationMethodDIDResolver::new(DIDWeb);
                let params = VerificationParameters::from_resolver(&didweb);

                let (url, shutdown) = web_server().unwrap();
                PROXY.with(|proxy| {
                    proxy.replace(Some(url));
                });

                let cred = JsonCredential::new(
                    None,
                    did!("did:web:localhost").to_owned().into_uri().into(),
                    "2021-01-26T16:57:27Z".parse().unwrap(),
                    vec![serde_json::json!({
                        "id": "did:web:localhost"
                    })],
                );

                let key: JWK = include_str!("../../../../../tests/ed25519-2020-10-18.json")
                    .parse()
                    .unwrap();
                let verification_method = iri!("did:web:localhost#key1").to_owned().into();
                let suite = AnySuite::pick(&key, Some(&verification_method)).unwrap();
                let issue_options = ProofOptions::new(
                    "2021-01-26T16:57:27Z".parse().unwrap(),
                    verification_method,
                    ProofPurpose::Assertion,
                    Default::default(),
                );
                let signer = SingleSecretSigner::new(key).into_local();
                let vc = suite
                    .sign(cred, &didweb, &signer, issue_options)
                    .await
                    .unwrap();

                println!(
                    "proof: {}",
                    serde_json::to_string_pretty(&vc.proofs).unwrap()
                );
                assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..BCvVb4jz-yVaTeoP24Wz0cOtiHKXCdPcmFQD_pxgsMU6aCAj1AIu3cqHyoViU93nPmzqMLswOAqZUlMyVnmzDw");
                assert!(vc.verify(&params).await.unwrap().is_ok());

                // test that issuer property is used for verification
                let mut vc_bad_issuer = vc.clone();
                vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();
                // It should fail.
                assert!(vc_bad_issuer.verify(params).await.unwrap().is_err());

                PROXY.with(|proxy| {
                    proxy.replace(None);
                });
                shutdown().ok();
            }
            */
    }

    fn did(s: &'static str) -> Did<'static> {
        Did::new(s).unwrap()
    }
}
