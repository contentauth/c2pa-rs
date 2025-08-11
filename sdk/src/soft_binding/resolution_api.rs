// Copyright 2025 Adobe. All rights reserved.
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

use http::header;
use serde::{Deserialize, Serialize};
use ureq::SendBody;

use crate::{Error, Result};

/// Information on the algorithm used for the sot binding.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SoftBindingAlg {
    /// Unique identifier of a fingerprint algorithm.
    pub alg: String,
}

// TODO: the spec has a very questionable definition for this schema
/// List of the names of soft binding algorithms supported by this service. The authoritative
/// list of name is available here: <https://github.com/c2pa-org/softbinding-algorithm-list>.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SoftBindingAlgList {
    /// Unique identifier of a watermark algorithm.
    pub watermarks: Vec<SoftBindingAlg>,
    /// Unique identifier of a fingerprint algorithm.
    pub fingerprints: Vec<SoftBindingAlg>,
}

/// A soft binding match containing information about the match.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftBindingQueryResultMatch {
    /// Unique identifier of a matched C2PA Manifest.
    pub manifest_id: String,
    /// Endpoint of a Soft Binding Resolution API from which the C2PA Manifest may be
    /// obtained. If the endpoint is absent then the C2PA Manifest is available from
    /// same endpoint the query was sent to using the /manifests endpoint.
    pub endpoint: Option<String>,
    /// An integer score in the range (0-100) representing the strength of match, if
    /// appropriate, where 0 is the weakest possible match and 100 is the strongest
    /// possible match.
    pub similarity_score: Option<u32>,
}

/// A list of soft binding matches returned by a soft binding resolution API.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct SoftBindingQueryResult {
    pub matches: Vec<SoftBindingQueryResultMatch>,
}

/// Internal struct used for constructing the body for [`SoftBindingResolutionApi::query_by_large_binding`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct SoftBindingQuery<'a> {
    /// A string identifying the soft binding algorithm and version of that algorithm used.
    pub alg: &'a str,
    /// A base64-encoded string describing, in algorithm specific format, the value of the
    /// soft binding to be used as the query.
    pub value: &'a str,
}

/// Raw web API for interacting with a soft binding resolution API.
///
/// Read more [in the spec](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html#soft-binding-resolution-api).
#[derive(Debug)]
pub struct SoftBindingResolutionApi;

// TODO: also need async counterparts for these functions
impl SoftBindingResolutionApi {
    /// Given one soft binding, find zero or more manifests identifiers within the manifest
    /// store matching the soft binding.
    pub fn query_by_binding(
        base_url: &str,
        bearer_token: &str,
        alg: &str,
        value: &str,
        max_results: Option<u32>,
    ) -> Result<SoftBindingQueryResult> {
        let mut url = format!("{base_url}/matches/byBinding?value={value}&alg={alg}");
        if let Some(max_results) = max_results {
            if max_results < 1 {
                return Err(Error::MaxResultsTooSmall);
            }

            url.push_str(&format!("&maxResults={max_results}"));
        }

        let response = ureq::get(url)
            .header(header::AUTHORIZATION, &format!("Bearer {bearer_token}"))
            .call()?;

        Ok(response.into_body().read_json()?)
    }

    /// Given a large soft binding value, find zero or more matching manifest identifiers.
    /// Use this method if the size of the soft binding value is expected to be large too
    /// large to fit in a URL, otherwise favor the use of GET.
    pub fn query_by_large_binding(
        base_url: &str,
        bearer_token: &str,
        alg: &str,
        value: &str,
        max_results: Option<u32>,
    ) -> Result<SoftBindingQueryResult> {
        let mut url = format!("{base_url}/matches/byBinding");
        if let Some(max_results) = max_results {
            if max_results < 1 {
                return Err(Error::MaxResultsTooSmall);
            }

            url.push_str(&format!("?maxResults={max_results}"));
        }

        let response = ureq::post(url)
            .header(header::AUTHORIZATION, &format!("Bearer {bearer_token}"))
            .send_json(SoftBindingQuery { alg, value })?;

        Ok(response.into_body().read_json()?)
    }

    /// Find zero or more C2PA Manifest identifiers within the manifest store using an
    /// uploaded file containing a digital asset.
    pub fn upload_file(
        base_url: &str,
        bearer_token: &str,
        alg: &str,
        mime_type: &str,
        asset_stream: &mut impl Read,
        max_results: Option<u32>,
        // TODO: when is hint_alg actually used?
        hint_alg: Option<&str>,
        hint_value: Option<&str>,
    ) -> Result<SoftBindingQueryResult> {
        let mut url = format!("{base_url}/matches/byContent?alg={alg}");
        if let Some(hint_alg) = hint_alg {
            url.push_str(&format!("&hintAlg={hint_alg}"));
        }
        if let Some(hint_value) = hint_value {
            url.push_str(&format!("&hintValue={hint_value}"));
        }
        if let Some(max_results) = max_results {
            if max_results < 1 {
                return Err(Error::MaxResultsTooSmall);
            }

            url.push_str(&format!("&maxResults={max_results}"));
        }

        let response = ureq::post(url)
            .header(header::AUTHORIZATION, &format!("Bearer {bearer_token}"))
            .header(header::CONTENT_TYPE, mime_type)
            .send(SendBody::from_reader(asset_stream))?;

        Ok(response.into_body().read_json()?)
    }

    /// Retrieve a C2PA Manifest by manifest identifier. This either returns the active
    /// manifest or the entire C2PA Manifest Store that the active manifest identifier
    /// is part of. C2PA Manifest identifiers should follow the format described in the
    /// C2PA Technical specification at xref:specs:C2PA_Specification.adoc\[_unique_identifiers]
    pub fn get_manifest_by_id(
        base_url: &str,
        bearer_token: &str,
        manifest_id: &str,
        return_active_manifest: Option<bool>,
    ) -> Result<Vec<u8>> {
        let mut url = format!("{base_url}/manifests/{manifest_id}");
        if let Some(return_active_manifest) = return_active_manifest {
            url.push_str(&format!("?returnActiveManifest={return_active_manifest}"));
        }

        let response = ureq::get(url)
            .header(header::AUTHORIZATION, &format!("Bearer {bearer_token}"))
            .call()?;

        Ok(response.into_body().read_to_vec()?)
    }

    /// Enumerate the names of soft binding algorithms supported as queries by the service.
    /// See <https://github.com/c2pa-org/softbinding-algorithm-list> for an authoritative
    /// list of C2PA soft binding algorithm names.
    pub fn get_supported_bindings(base_url: &str) -> Result<SoftBindingAlgList> {
        let url = format!("{base_url}/services/supportedAlgorithms");

        let response = ureq::get(url).call()?;
        Ok(response.into_body().read_json()?)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use httpmock::MockServer;

    use super::*;

    pub const TEST_BEARER_TOKEN: &str = "some bearer token";

    // Note that these mock server functions can be used in higher-level tests when testing
    // soft binding resolution API-related functions.

    #[derive(Debug)]
    pub struct ByBindingQuery {
        pub value: String,
        pub alg: String,
        pub max_results: Option<u32>,
    }

    pub fn mock_by_binding<'a>(
        server: &'a httpmock::MockServer,
        query: &ByBindingQuery,
        result: &SoftBindingQueryResult,
    ) -> httpmock::Mock<'a> {
        let mut result = result.clone();
        if let Some(max_results) = query.max_results {
            result.matches.truncate(max_results as usize);
        }

        server.mock(|when, then| {
            let when = when
                .method("GET")
                .path("/matches/byBinding")
                .query_param("value", &query.value)
                .query_param("alg", &query.alg)
                .header(header::AUTHORIZATION.as_str(), TEST_BEARER_TOKEN);
            if let Some(max_results) = query.max_results {
                when.query_param("maxResults", max_results.to_string());
            }
            then.status(200).json_body_obj(&result);
        })
    }

    pub fn mock_by_large_binding<'a>(
        server: &'a httpmock::MockServer,
        query: &ByBindingQuery,
        result: &SoftBindingQueryResult,
    ) -> httpmock::Mock<'a> {
        let mut result = result.clone();
        if let Some(max_results) = query.max_results {
            result.matches.truncate(max_results as usize);
        }

        server.mock(|when, then| {
            let when = when
                .method("POST")
                .path("/matches/byBinding")
                .body(
                    serde_json::to_string(&SoftBindingQuery {
                        alg: &query.alg,
                        value: &query.value,
                    })
                    .unwrap(),
                )
                .header(header::AUTHORIZATION.as_str(), TEST_BEARER_TOKEN);
            if let Some(max_results) = query.max_results {
                when.query_param("maxResults", max_results.to_string());
            }
            then.status(200).json_body_obj(&result);
        })
    }

    #[derive(Debug)]
    pub struct UploadFileQuery {
        pub alg: String,
        pub mime_type: String,
        pub asset_bytes: Vec<u8>,
        pub max_results: Option<u32>,
        pub hint_alg: Option<String>,
        pub hint_value: Option<String>,
    }

    pub fn mock_upload_file<'a>(
        server: &'a httpmock::MockServer,
        query: &UploadFileQuery,
        result: &SoftBindingQueryResult,
    ) -> httpmock::Mock<'a> {
        let mut result = result.clone();
        if let Some(max_results) = query.max_results {
            result.matches.truncate(max_results as usize);
        }

        server.mock(|when, then| {
            let when = when
                .method("POST")
                .path("/matches/byContent")
                .query_param("alg", &query.alg)
                .header(header::CONTENT_TYPE.as_str(), &query.mime_type)
                .body(str::from_utf8(&query.asset_bytes).unwrap())
                .header(header::AUTHORIZATION.as_str(), TEST_BEARER_TOKEN);
            let when = if let Some(max_results) = query.max_results {
                when.query_param("maxResults", max_results.to_string())
            } else {
                when
            };
            let when = if let Some(hint_alg) = query.hint_alg.as_ref() {
                when.query_param("hintAlg", hint_alg)
            } else {
                when
            };
            if let Some(hint_value) = query.hint_value.as_ref() {
                when.query_param("hintValue", hint_value);
            }
            then.status(200).json_body_obj(&result);
        })
    }

    #[derive(Debug)]
    pub struct GetManifestByIdQuery {
        pub manifest_id: String,
        pub return_active_manifest: Option<bool>,
    }

    pub fn mock_get_manifest_by_id<'a>(
        server: &'a httpmock::MockServer,
        query: &GetManifestByIdQuery,
        result: &[u8],
    ) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            let when = when
                .method("GET")
                .path(format!("/manifests/{}", query.manifest_id))
                .header(header::AUTHORIZATION.as_str(), TEST_BEARER_TOKEN);
            if let Some(return_active_manifest) = query.return_active_manifest {
                when.query_param("returnActiveManifest", return_active_manifest.to_string());
            }
            then.status(200)
                .header(header::CONTENT_TYPE.as_str(), "application/c2pa")
                .body(result);
        })
    }

    pub fn mock_get_supported_algorithms<'a>(
        server: &'a httpmock::MockServer,
        result: &SoftBindingAlgList,
    ) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method("GET").path("/services/supportedAlgorithms");
            then.status(200).json_body_obj(&result);
        })
    }

    #[test]
    fn test_by_binding() {
        let query = ByBindingQuery {
            value: "test value".to_owned(),
            alg: "com.example.dense".to_owned(),
            max_results: Some(1),
        };
        let result = SoftBindingQueryResult {
            matches: vec![SoftBindingQueryResultMatch {
                manifest_id: "some manifest id".to_owned(),
                endpoint: None,
                similarity_score: Some(75),
            }],
        };

        let server = MockServer::start();
        let by_binding_mock = mock_by_binding(&server, &query, &result);

        let response = SoftBindingResolutionApi::query_by_binding(
            &server.base_url(),
            TEST_BEARER_TOKEN,
            &query.alg,
            &query.value,
            query.max_results,
        )
        .unwrap();

        assert_eq!(result, response);

        by_binding_mock.assert();
    }

    #[test]
    fn test_by_large_binding() {
        let query = ByBindingQuery {
            value: "test value".to_owned(),
            alg: "com.example.dense".to_owned(),
            max_results: Some(1),
        };
        let result = SoftBindingQueryResult {
            matches: vec![SoftBindingQueryResultMatch {
                manifest_id: "some manifest id".to_owned(),
                endpoint: None,
                similarity_score: Some(75),
            }],
        };

        let server = MockServer::start();
        let by_large_binding_mock = mock_by_large_binding(&server, &query, &result);

        let response = SoftBindingResolutionApi::query_by_large_binding(
            &server.base_url(),
            TEST_BEARER_TOKEN,
            &query.alg,
            &query.value,
            query.max_results,
        )
        .unwrap();

        assert_eq!(result, response);

        by_large_binding_mock.assert();
    }

    #[test]
    fn test_upload_file() {
        let query = UploadFileQuery {
            alg: "com.example.dense".to_owned(),
            max_results: Some(1),
            mime_type: "image/jpeg".to_owned(),
            asset_bytes: vec![1, 2, 3],
            hint_alg: None,
            hint_value: None,
        };
        let result = SoftBindingQueryResult {
            matches: vec![SoftBindingQueryResultMatch {
                manifest_id: "some manifest id".to_owned(),
                endpoint: None,
                similarity_score: Some(75),
            }],
        };

        let server = MockServer::start();
        let upload_file_mock = mock_upload_file(&server, &query, &result);

        let response = SoftBindingResolutionApi::upload_file(
            &server.base_url(),
            TEST_BEARER_TOKEN,
            &query.alg,
            &query.mime_type,
            &mut Cursor::new(&query.asset_bytes),
            query.max_results,
            query.hint_alg.as_deref(),
            query.hint_value.as_deref(),
        )
        .unwrap();

        assert_eq!(result, response);

        upload_file_mock.assert();
    }

    #[test]
    fn test_get_manifest_by_id() {
        let query = GetManifestByIdQuery {
            manifest_id: "some manifest id".to_owned(),
            return_active_manifest: None,
        };
        let result = vec![1, 2, 3];

        let server = MockServer::start();
        let get_manifest_by_id_mock = mock_get_manifest_by_id(&server, &query, &result);

        let response = SoftBindingResolutionApi::get_manifest_by_id(
            &server.base_url(),
            TEST_BEARER_TOKEN,
            &query.manifest_id,
            query.return_active_manifest,
        )
        .unwrap();

        assert_eq!(result, response);

        get_manifest_by_id_mock.assert();
    }

    #[test]
    fn test_get_supported_bindings() {
        let result = SoftBindingAlgList {
            watermarks: vec![SoftBindingAlg {
                alg: "com.example.watermark".to_owned(),
            }],
            fingerprints: vec![SoftBindingAlg {
                alg: "com.example.fingerprint".to_owned(),
            }],
        };

        let server = MockServer::start();
        let get_supported_algorithms_mock = mock_get_supported_algorithms(&server, &result);

        let response =
            SoftBindingResolutionApi::get_supported_bindings(&server.base_url()).unwrap();

        assert_eq!(result, response);

        get_supported_algorithms_mock.assert();
    }
}
