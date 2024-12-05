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

// #[cfg(not(target_arch = "wasm32"))]
use reqwest::Error as HttpError;
// #[cfg(target_arch = "wasm32")]
// use String as HttpError;

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

    dbg!(method_specific_id);

    let url = to_url(method_specific_id)?;
    // TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security

    let did_doc = get_did_doc(&url).await?;

    let json = String::from_utf8(did_doc).map_err(|_| DidWebError::InvalidData(url.clone()))?;

    DidDocument::from_json(&json).map_err(|_| DidWebError::InvalidData(url))
}

async fn get_did_doc(url: &str) -> Result<Vec<u8>, DidWebError> {
    // #[cfg(not(target_arch = "wasm32"))]
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

    // #[cfg(target_arch = "wasm32")]
    // {
    //     use wasm_bindgen::prelude::*;
    //     use wasm_bindgen_futures::JsFuture;
    //     use web_sys::{Request, RequestInit, RequestMode, Response};

    //     let opts = RequestInit::new();
    //     opts.set_method("GET");
    //     opts.set_mode(RequestMode::Cors);

    //     let request = Request::new_with_str_and_init(&url, &opts)
    //         .map_err(|_|
    // DidWebError::Client("Request::new_with_str_and_init".to_string()))?;

    //     request
    //         .headers()
    //         .set("accept", "application/did+json")
    //         .map_err(|_| DidWebError::Client("Set headers".to_string()))?;

    //     let window = web_sys::window().unwrap();
    //     let resp_value = JsFuture::from(window.fetch_with_request(&request))
    //         .await
    //         .map_err(|_|
    // DidWebError::Client("window.fetch_with_request".to_string()))?;

    //     assert!(resp_value.is_instance_of::<Response>());
    //     let resp: Response = resp_value.dyn_into().unwrap();

    //     JsFuture::from(
    //         resp.blob()
    //             .map_err(|_|
    // DidWebError::Client("window.resp.bytes()".to_string()))?,     )
    //     .await
    //     .map(|blob| {
    //         let array = js_sys::Uint8Array::new(&blob);
    //         array.to_vec()
    //     })
    //     .map_err(|e| DidWebError::Server("resp.blob()".to_string()))
    // }
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
