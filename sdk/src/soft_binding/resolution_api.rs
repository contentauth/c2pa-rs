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

//! A client for the [Soft Binding Resolution API](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html#soft-binding-resolution-api)
//! defined by the C2PA "Decoupled" soft binding spec.
//!
//! This module is a pure HTTP client wrapper with no domain-specific logic. It is built
//! entirely on [`Context::resolver`]/[`Context::resolver_async`], so it has no bespoke
//! authentication mechanism of its own: a caller needing to authenticate against a
//! particular resolution API host should register a custom [`SyncHttpResolver`]/
//! [`AsyncHttpResolver`] via [`Context::with_resolver`]/[`Context::with_resolver_async`]
//! that attaches the required headers.
//!
//! [`SyncHttpResolver`]: crate::http::SyncHttpResolver
//! [`AsyncHttpResolver`]: crate::http::AsyncHttpResolver
//! [`Context::with_resolver`]: crate::Context::with_resolver
//! [`Context::with_resolver_async`]: crate::Context::with_resolver_async

use std::io::Read;

use async_generic::async_generic;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{crypto::base64, error::Error, Context, Result};

/// Maximum number of bytes read from a Soft Binding Resolution API JSON response.
///
/// Match-query responses are expected to be small (a short list of manifest identifiers),
/// so this is far smaller than the cap used for fetching manifest bytes themselves.
const MAX_QUERY_RESPONSE_SIZE: u64 = 1024 * 1024; // 1 MB

/// A soft binding match returned by a Soft Binding Resolution API.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SoftBindingMatch {
    /// Unique identifier of a matched C2PA Manifest.
    pub manifest_id: String,
    /// Endpoint of a Soft Binding Resolution API from which the C2PA Manifest may be
    /// obtained. If absent, the C2PA Manifest is available from the same endpoint the
    /// query was sent to, using the `/manifests` endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// An integer score in the range (0-100) representing the strength of match, if
    /// appropriate, where 0 is the weakest possible match and 100 is the strongest
    /// possible match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub similarity_score: Option<u8>,
}

/// A list of soft binding matches returned by a soft binding resolution API.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct SoftBindingQueryResult {
    #[serde(default)]
    pub matches: Vec<SoftBindingMatch>,
}

/// Internal struct used for constructing the query string for [`query_by_binding_get`].
#[derive(Debug, Clone, Copy)]
struct ByBindingQuery<'a> {
    alg: &'a str,
    value: &'a [u8],
    max_results: Option<u32>,
}

fn base_url(endpoint: &str) -> Result<Url> {
    let mut base = endpoint.to_owned();
    if !base.ends_with('/') {
        base.push('/');
    }
    Url::parse(&base).map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))
}

fn join_url(endpoint: &str, path: &str) -> Result<Url> {
    base_url(endpoint)?
        .join(path)
        .map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))
}

/// Construct the URL for fetching a manifest by id from a Soft Binding Resolution API,
/// per the spec's `GET {endpoint}/manifests/{manifestId}` endpoint. `manifest_id` is
/// percent-encoded as a path segment.
pub(crate) fn manifest_url(endpoint: &str, manifest_id: &str) -> Result<Url> {
    let mut url = base_url(endpoint)?;
    url.path_segments_mut()
        .map_err(|_| {
            Error::SoftBindingResolutionFetch(format!("endpoint {endpoint} cannot be a base URL"))
        })?
        .push("manifests")
        .push(manifest_id);
    Ok(url)
}

#[async_generic(async_signature(
    url: Url,
    context: &Context,
))]
fn get_json<T: for<'de> Deserialize<'de>>(url: Url, context: &Context) -> Result<T> {
    let request = http::Request::get(url.as_str())
        .body(Vec::new())
        .map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))?;

    let response = if _sync {
        context.resolver().http_resolve(request)
    } else {
        context.resolver_async().http_resolve_async(request).await
    }
    .map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))?;

    if response.status() != 200 {
        return Err(Error::SoftBindingResolutionFetch(format!(
            "request to {url} failed: code: {}, status: {}",
            response.status().as_u16(),
            response.status().as_str()
        )));
    }

    let mut body = Vec::new();
    response
        .into_body()
        .take(MAX_QUERY_RESPONSE_SIZE)
        .read_to_end(&mut body)
        .map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))?;

    serde_json::from_slice(&body).map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))
}

/// Given one soft binding `alg`/`value`, find zero or more manifest identifiers within a
/// manifest repository matching the soft binding, by querying `{endpoint}/matches/byBinding`.
///
/// `value` is base64-encoded before being placed in the query string, per the spec's
/// `c2pa.softBindingQuery` schema.
#[async_generic(async_signature(
    endpoint: &str,
    alg: &str,
    value: &[u8],
    max_results: Option<u32>,
    context: &Context,
))]
pub fn query_by_binding_get(
    endpoint: &str,
    alg: &str,
    value: &[u8],
    max_results: Option<u32>,
    context: &Context,
) -> Result<SoftBindingQueryResult> {
    let query = ByBindingQuery {
        alg,
        value,
        max_results,
    };

    let mut url = join_url(endpoint, "matches/byBinding")?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("alg", query.alg);
        pairs.append_pair("value", &base64::encode(query.value));
        if let Some(max_results) = query.max_results {
            pairs.append_pair("maxResults", &max_results.to_string());
        }
    }

    if _sync {
        get_json(url, context)
    } else {
        get_json_async(url, context).await
    }
}

/// Find zero or more C2PA Manifest identifiers within a manifest repository using an
/// uploaded file containing a digital asset, by querying `{endpoint}/matches/byContent`.
///
/// This is a spec-complete, optional utility that knows the wire shape of the Soft
/// Binding Resolution API's upload endpoint. It is never called automatically by the
/// SDK — a caller must invoke it explicitly if they choose to accept the cost of
/// uploading raw asset content to a third-party resolution service.
#[allow(clippy::too_many_arguments)]
#[async_generic(async_signature(
    endpoint: &str,
    content: &[u8],
    mime_type: &str,
    alg: Option<&str>,
    max_results: Option<u32>,
    hint_alg: Option<&str>,
    hint_value: Option<&[u8]>,
    context: &Context,
))]
pub fn query_by_content(
    endpoint: &str,
    content: &[u8],
    mime_type: &str,
    alg: Option<&str>,
    max_results: Option<u32>,
    hint_alg: Option<&str>,
    hint_value: Option<&[u8]>,
    context: &Context,
) -> Result<SoftBindingQueryResult> {
    let mut url = join_url(endpoint, "matches/byContent")?;
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(alg) = alg {
            pairs.append_pair("alg", alg);
        }
        if let Some(max_results) = max_results {
            pairs.append_pair("maxResults", &max_results.to_string());
        }
        if let Some(hint_alg) = hint_alg {
            pairs.append_pair("hintAlg", hint_alg);
        }
        if let Some(hint_value) = hint_value {
            pairs.append_pair("hintValue", &base64::encode(hint_value));
        }
    }

    let request = http::Request::post(url.as_str())
        .header(http::header::CONTENT_TYPE, mime_type)
        .body(content.to_vec())
        .map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))?;

    let response = if _sync {
        context.resolver().http_resolve(request)
    } else {
        context.resolver_async().http_resolve_async(request).await
    }
    .map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))?;

    if response.status() != 200 {
        return Err(Error::SoftBindingResolutionFetch(format!(
            "request to {url} failed: code: {}, status: {}",
            response.status().as_u16(),
            response.status().as_str()
        )));
    }

    let mut body = Vec::new();
    response
        .into_body()
        .take(MAX_QUERY_RESPONSE_SIZE)
        .read_to_end(&mut body)
        .map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))?;

    serde_json::from_slice(&body).map_err(|e| Error::SoftBindingResolutionFetch(e.to_string()))
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use httpmock::{Method, MockServer};

    use super::*;

    #[test]
    fn test_query_by_binding_get_happy_path() {
        let server = MockServer::start();
        let result = SoftBindingQueryResult {
            matches: vec![SoftBindingMatch {
                manifest_id: "some-manifest-id".to_owned(),
                endpoint: None,
                similarity_score: Some(75),
            }],
        };

        let mock = server.mock(|when, then| {
            when.method(Method::GET)
                .path("/matches/byBinding")
                .query_param("alg", "com.example.watermark")
                .query_param("value", base64::encode(b"some value"))
                .query_param("maxResults", "5");
            then.status(200).json_body_obj(&result);
        });

        let context = Context::new();
        let response = query_by_binding_get(
            &server.base_url(),
            "com.example.watermark",
            b"some value",
            Some(5),
            &context,
        )
        .unwrap();

        assert_eq!(response, result);
        mock.assert();
    }

    #[test]
    fn test_query_by_binding_get_non_200() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(Method::GET).path("/matches/byBinding");
            then.status(500);
        });

        let context = Context::new();
        let err = query_by_binding_get(
            &server.base_url(),
            "com.example.watermark",
            b"some value",
            None,
            &context,
        )
        .unwrap_err();

        assert!(matches!(err, Error::SoftBindingResolutionFetch(_)));
        mock.assert();
    }

    #[test]
    fn test_query_by_binding_get_malformed_json() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(Method::GET).path("/matches/byBinding");
            then.status(200).body("not json");
        });

        let context = Context::new();
        let err = query_by_binding_get(
            &server.base_url(),
            "com.example.watermark",
            b"some value",
            None,
            &context,
        )
        .unwrap_err();

        assert!(matches!(err, Error::SoftBindingResolutionFetch(_)));
        mock.assert();
    }

    #[test]
    fn test_query_by_content_sets_content_type_and_body() {
        let server = MockServer::start();
        let result = SoftBindingQueryResult {
            matches: vec![SoftBindingMatch {
                manifest_id: "some-manifest-id".to_owned(),
                endpoint: Some("https://other.example.com".to_owned()),
                similarity_score: None,
            }],
        };

        let mock = server.mock(|when, then| {
            when.method(Method::POST)
                .path("/matches/byContent")
                .query_param("alg", "com.example.fingerprint")
                .header("content-type", "image/jpeg")
                .body("raw asset bytes");
            then.status(200).json_body_obj(&result);
        });

        let context = Context::new();
        let response = query_by_content(
            &server.base_url(),
            b"raw asset bytes",
            "image/jpeg",
            Some("com.example.fingerprint"),
            None,
            None,
            None,
            &context,
        )
        .unwrap();

        assert_eq!(response, result);
        mock.assert();
    }

    #[tokio::test]
    async fn test_query_by_binding_get_async() {
        let server = MockServer::start();
        let result = SoftBindingQueryResult {
            matches: vec![SoftBindingMatch {
                manifest_id: "some-manifest-id".to_owned(),
                endpoint: None,
                similarity_score: Some(50),
            }],
        };

        let mock = server.mock(|when, then| {
            when.method(Method::GET).path("/matches/byBinding");
            then.status(200).json_body_obj(&result);
        });

        let context = Context::new();
        let response = query_by_binding_get_async(
            &server.base_url(),
            "com.example.watermark",
            b"some value",
            None,
            &context,
        )
        .await
        .unwrap();

        assert_eq!(response, result);
        mock.assert();
    }
}
