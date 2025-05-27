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

use super::{did::Did, did_doc::DidDocument};

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    pub(crate) static PROXY: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[cfg(not(target_os = "wasi"))]
use reqwest::Error as HttpError;
#[cfg(target_os = "wasi")]
use String as HttpError;

#[derive(Debug, thiserror::Error)]
pub enum DidWebError {
    #[error("error building HTTP client: {0}")]
    Client(HttpError),

    #[error("error sending HTTP request ({0}): {1}")]
    Request(String, HttpError),

    #[error("server error: {0}")]
    Server(String),

    #[error("error reading HTTP response: {0}")]
    Response(HttpError),

    #[error("the document was not found: {0}")]
    NotFound(String),

    #[error("the document was not a valid DID document: {0}")]
    InvalidData(String),

    #[error("invalid web DID: {0}")]
    InvalidWebDid(String),
}

pub(crate) async fn resolve(did: &Did<'_>) -> Result<DidDocument, DidWebError> {
    let method = did.method_name();
    #[allow(clippy::panic)] // TEMPORARY while refactoring
    if method != "web" {
        panic!("Unexpected DID method {method}");
    }

    let method_specific_id = did.method_specific_id();

    let url = to_url(method_specific_id)?;
    // TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security

    let did_doc = get_did_doc(&url).await?;

    let json = String::from_utf8(did_doc).map_err(|_| DidWebError::InvalidData(url.clone()))?;

    DidDocument::from_json(&json).map_err(|_| DidWebError::InvalidData(url))
}

async fn get_did_doc(url: &str) -> Result<Vec<u8>, DidWebError> {
    #[cfg(not(target_os = "wasi"))]
    {
        use reqwest::header;

        let mut headers = reqwest::header::HeaderMap::new();

        headers.insert(
            "User-Agent",
            reqwest::header::HeaderValue::from_static(USER_AGENT),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(DidWebError::Client)?;

        let resp = client
            .get(url)
            .header(header::ACCEPT, "application/did+json")
            .send()
            .await
            .map_err(|e: reqwest::Error| DidWebError::Request(url.to_owned(), e))?;

        resp.error_for_status_ref().map_err(|err| {
            if err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                DidWebError::NotFound(url.to_string())
            } else {
                DidWebError::Server(err.to_string())
            }
        })?;

        let document = resp.bytes().await.map_err(DidWebError::Response)?;
        Ok(document.to_vec())
    }

    #[cfg(target_os = "wasi")]
    {
        use wstd::{http, io, io::AsyncRead};

        let request = http::Request::get(url)
            .header("User-Agent", http::HeaderValue::from_static(USER_AGENT))
            .header(
                "Accept",
                http::HeaderValue::from_static("application/did+json"),
            )
            .body(io::empty())
            .map_err(|e| DidWebError::Request(url.to_owned(), e.to_string()))?;
        let resp = http::Client::new()
            .send(request)
            .await
            .map_err(|e| DidWebError::Request(url.to_owned(), e.to_string()))?;

        let (parts, mut body) = resp.into_parts();
        match parts.status {
            http::StatusCode::OK => (),
            http::StatusCode::NOT_FOUND => return Err(DidWebError::NotFound(url.to_string())),
            _ => return Err(DidWebError::Server(parts.status.to_string())),
        };

        let mut document = Vec::new();
        body.read_to_end(&mut document)
            .await
            .map_err(|e| DidWebError::Response(e.to_string()))?;
        Ok(document)
    }
}

pub(crate) fn to_url(did: &str) -> Result<String, DidWebError> {
    let mut parts = did.split(':').peekable();
    let domain_name = parts
        .next()
        .ok_or_else(|| DidWebError::InvalidWebDid(did.to_owned()))?;

    // TODO:
    // - Validate domain name: alphanumeric, hyphen, dot. no IP address.
    // - Ensure domain name matches TLS certificate common name
    // - Support punycode?
    // - Support query strings?
    let path = match parts.peek() {
        Some(_) => parts.collect::<Vec<&str>>().join("/"),
        None => ".well-known".to_string(),
    };

    // Use http for localhost, for testing purposes.
    let proto = if domain_name.starts_with("localhost") {
        "http"
    } else {
        "https"
    };

    #[allow(unused_mut)]
    let mut url = format!(
        "{proto}://{}/{path}/did.json",
        domain_name.replacen("%3A", ":", 1)
    );

    #[cfg(test)]
    PROXY.with(|proxy| {
        if let Some(ref proxy) = *proxy.borrow() {
            if domain_name == "localhost" {
                url = format!("{proxy}{path}/did.json");
                dbg!(&url);
            }
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
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod resolve {
        use httpmock::prelude::*;

        use super::did;
        use crate::identity::claim_aggregation::w3c_vc::{
            did_doc::DidDocument,
            did_web::{self, PROXY},
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

            PROXY.with(|proxy| {
                let server_url = server.url("/").replace("127.0.0.1", "localhost");
                dbg!(&server_url);
                proxy.replace(Some(server_url));
            });

            let did_doc_mock = server.mock(|when, then| {
                when.method(GET).path("/.well-known/did.json");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(DID_JSON);
            });

            let doc = did_web::resolve(&did("did:web:localhost")).await.unwrap();
            let doc_expected = DidDocument::from_json(DID_JSON).unwrap();
            assert_eq!(doc, doc_expected);

            PROXY.with(|proxy| {
                proxy.replace(None);
            });

            did_doc_mock.assert();
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
