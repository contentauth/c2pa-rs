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

use std::{
    cell::RefCell,
    cmp::Ordering,
    io::{Read, Seek},
};

use crate::{
    soft_binding::{
        algorithm_list::SoftBindingAlgorithmEntry,
        resolution_api::{
            SoftBindingQueryResult, SoftBindingQueryResultMatch, SoftBindingResolutionApi,
        },
    },
    Error, Result,
};

/// A soft binding match contaning information about the match.
#[derive(Debug, PartialEq, Eq)]
pub struct SoftBindingMatch {
    /// Unique identifier of a matched C2PA Manifest.
    pub manifest_id: String,
    /// Absolute URL to the web API implementing the "getManifestById" endpoint.
    pub url: String,
    /// An integer score in the range (0-100) representing the strength of match, if
    /// appropriate, where 0 is the weakest possible match and 100 is the strongest
    /// possible match.
    pub similarity_score: Option<u32>,
}

impl SoftBindingMatch {
    /// Create a [`SoftBindingMatch`] from a "raw" [`SoftBindingQueryResultMatch`] returned by
    /// the resolution API.
    ///
    /// The [`SoftBindingQueryResultMatch`] differs in that it contains an optional
    /// [`SoftBindingQueryResultMatch::endpoint`] field which is fully qualified in the
    /// [`SoftBindingMatch::url`] field.
    fn from_query(mut base_url: String, query: SoftBindingQueryResultMatch) -> Self {
        SoftBindingMatch {
            manifest_id: query.manifest_id,
            url: match query.endpoint {
                Some(endpoint) => {
                    base_url.push_str(&endpoint);
                    base_url
                }
                None => base_url,
            },
            similarity_score: query.similarity_score,
        }
    }
}

impl Ord for SoftBindingMatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.similarity_score.as_ref(), &self.manifest_id, &self.url).cmp(&(
            other.similarity_score.as_ref(),
            &other.manifest_id,
            &other.url,
        ))
    }
}

impl PartialOrd for SoftBindingMatch {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A high-level client for interacting with the [`SoftBindingResolutionApi`]
/// [defined in the spec](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html).
#[derive(Debug)]
pub struct SoftBindingClient<T> {
    oauth_resolver: T,
}

impl<T> SoftBindingClient<T>
where
    T: Fn(&str) -> Option<&str>,
{
    // TODO: provide more info and example code on how to obtain a bearer token. note that this will require a
    //       custom redirect URI that the user will need to handle (and hence why we don't provide this functionality)
    /// Create a new [`SoftBindingClient`] with an oauth2 resolver callback.
    ///
    /// The callback takes in a complete URL to the soft binding algorithm API and returns a
    /// bearer token for accessing that API.
    ///
    /// For more information on how to obtain a bearer token, read the
    /// "[Soft Binding Resolution API specification](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html#soft-binding-resolution-api)"
    /// described by the spec.
    pub fn new(oauth_resolver: T) -> Self {
        SoftBindingClient { oauth_resolver }
    }

    /// Fetch the closest fingerprint match for an asset by a byte stream.
    ///
    /// Given the specified algorithm entries, this function will query all soft binding resolution APIs
    /// and return the match with the highest [`SoftBindingMatch::similarity_score`].
    ///
    /// This is derived from the [fingerprint-golden](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html#_fingerprinting_algorithms_2)
    /// usage flow defined in the spec.
    pub fn fingerprint_match_by_stream<U: Read + Seek>(
        &self,
        entry: &SoftBindingAlgorithmEntry,
        mime_type: &str,
        asset_stream: &mut U,
    ) -> Result<Option<SoftBindingMatch>> {
        let matches = self.fetch_matches_by_stream(
            entry,
            mime_type,
            asset_stream,
            // TODO: what would hint value be for a fingerprint or is it only for watermark?
            None,
            None,
            None,
        )?;

        Ok(matches.into_iter().flatten().max())
    }

    /// Fetch the watermark match for an asset by a byte stream.
    ///
    /// Given the specified algorithm entries, this function will query all soft binding resolution APIs
    /// until the first match is found.
    ///
    /// This is derived from the [watermark-golden](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html#_watermarking_algorithms_2)
    /// usage flow defined in the spec.
    pub fn watermark_match_by_stream<U: Read + Seek>(
        &self,
        entry: &SoftBindingAlgorithmEntry,
        mime_type: &str,
        asset_stream: &mut U,
    ) -> Result<Option<SoftBindingMatch>> {
        let matches = self.fetch_matches_by_stream(
            entry,
            mime_type,
            asset_stream,
            // TODO: can we take a hint?
            None,
            Some(1),
            Some(1),
        )?;

        Ok(matches.into_iter().find_map(|a_match| a_match.ok()))
    }

    /// Fetch matches by an algorithm value.
    ///
    /// This is commonly used when the watermark/fingerprint algorithm is computed for an asset locally and
    /// can be looked up via a small identifier value.
    #[inline]
    pub fn fetch_matches_by_algorithm_value(
        &self,
        entry: &SoftBindingAlgorithmEntry,
        value: &str,
        max_results_per_api: Option<u32>,
        hint_max_results: Option<u32>,
    ) -> Result<Vec<Result<SoftBindingMatch>>> {
        self.fetch_matches_impl(entry, hint_max_results, |url: &str, token: &str| {
            // TODO: should we always use large binding API or set a cutoff?
            SoftBindingResolutionApi::query_by_large_binding(
                url,
                token,
                &entry.alg,
                value,
                max_results_per_api,
            )
        })
    }

    /// Fetch matches by stream.
    ///
    /// This is commonly used when the algorithm identifier value is unknown and can't be computed locally,
    /// but can be computed by a remote soft binding resolution API on the source asset.
    #[inline]
    pub fn fetch_matches_by_stream<U: Read + Seek>(
        &self,
        entry: &SoftBindingAlgorithmEntry,
        mime_type: &str,
        asset_stream: &mut U,
        hint_value: Option<&str>,
        max_results_per_api: Option<u32>,
        hint_max_results: Option<u32>,
    ) -> Result<Vec<Result<SoftBindingMatch>>> {
        // TODO: not a great solution but allows us to mutate the asset stream from the closure multiple times
        let cell = RefCell::new(asset_stream);
        self.fetch_matches_impl(entry, hint_max_results, |url: &str, token: &str| {
            let mut asset_stream = cell.borrow_mut();
            asset_stream.rewind()?;

            // TODO: depending on what hint_value is, if that's specified we can just call the binding APIs
            SoftBindingResolutionApi::upload_file(
                url,
                token,
                &entry.alg,
                mime_type,
                &mut *asset_stream,
                max_results_per_api,
                Some(&entry.alg),
                hint_value,
            )
        })
    }

    /// Fetch the manifest bytes for a [`SoftBindingMatch`], querying the soft binding resolution API
    /// defined in [`SoftBindingMatch::url`].
    #[inline]
    pub fn fetch_manifest_bytes(&self, manifest_match: &SoftBindingMatch) -> Result<Vec<u8>> {
        self.fetch_manifest_bytes_impl(manifest_match, false)
    }

    /// Fetch the active manifest bytes for a [`SoftBindingMatch`], querying the soft binding resolution API
    /// defined in [`SoftBindingMatch::url`].
    #[inline]
    pub fn fetch_active_manifest_bytes(
        &self,
        manifest_match: &SoftBindingMatch,
    ) -> Result<Vec<u8>> {
        self.fetch_manifest_bytes_impl(manifest_match, true)
    }

    /// Fetch the manifest or active manifest bytes for a [`SoftBindingMatch`], querying the soft binding resolution API
    /// defined in [`SoftBindingMatch::url`].
    fn fetch_manifest_bytes_impl(
        &self,
        manifest_match: &SoftBindingMatch,
        only_active: bool,
    ) -> Result<Vec<u8>> {
        if let Some(token) = (self.oauth_resolver)(&manifest_match.url) {
            SoftBindingResolutionApi::get_manifest_by_id(
                &manifest_match.url,
                token,
                &manifest_match.manifest_id,
                Some(only_active),
            )
        } else {
            Err(Error::MissingBearerToken(manifest_match.url.to_owned()))
        }
    }

    /// Fetch matches given a callback that calls the [`SoftBindingResolutionApi`].
    ///
    /// The callback takes two parameters, (1) the url and (2) the bearer token for the url, and
    /// is expected to return the [`SoftBindingQueryResult`] obtained from the [`SoftBindingResolutionApi`].
    fn fetch_matches_impl<F>(
        &self,
        entry: &SoftBindingAlgorithmEntry,
        hint_max_results: Option<u32>,
        callback: F,
    ) -> Result<Vec<Result<SoftBindingMatch>>>
    where
        F: Fn(&str, &str) -> Result<SoftBindingQueryResult>,
    {
        if entry.deprecated.unwrap_or(false) {
            log::warn!(
                "fetching matches for deprecated soft binding algorithm `{}`",
                entry.alg
            );
        }

        match &entry.soft_binding_resolution_apis {
            Some(urls) => {
                let mut matches = Vec::new();

                for url in urls {
                    if let Some(token) = (self.oauth_resolver)(url) {
                        match callback(url, token) {
                            Ok(response) => {
                                matches.extend(response.matches.into_iter().map(|query| {
                                    Ok(SoftBindingMatch::from_query(url.to_owned(), query))
                                }))
                            }
                            Err(err) => matches.push(Err(err)),
                        }

                        if let Some(max_results) = hint_max_results {
                            if matches.len() == max_results as usize {
                                break;
                            }
                        }
                    } else {
                        // TODO: reconsider if we need this
                        matches.push(Err(Error::MissingBearerToken(url.to_owned())));
                    }
                }

                Ok(matches)
            }
            None => Err(Error::NoSoftBindingResolutionApisFound(
                entry.alg.to_owned(),
            )),
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use httpmock::MockServer;

    use crate::soft_binding::{
        algorithm_list::tests::mock_soft_binding_algorithm_list,
        resolution_api::tests::{
            mock_by_large_binding, mock_get_manifest_by_id, mock_upload_file, ByBindingQuery,
            GetManifestByIdQuery, UploadFileQuery, TEST_BEARER_TOKEN,
        },
    };

    use super::*;

    /// A mock soft binding client that includes an oauth resolver to a test bearer token.
    pub fn mock_soft_binding_client() -> SoftBindingClient<impl Fn(&str) -> Option<&str>> {
        SoftBindingClient::new(|_| Some(TEST_BEARER_TOKEN))
    }

    #[test]
    fn test_fingerprint_match_by_stream() {
        let server = MockServer::start();
        let list = mock_soft_binding_algorithm_list(&server.base_url());
        let entry = list.first().unwrap();

        let query = UploadFileQuery {
            alg: entry.alg.to_owned(),
            max_results: None,
            mime_type: "image/jpeg".to_owned(),
            asset_bytes: vec![1, 2, 3],
            hint_alg: None,
            hint_value: None,
        };
        let result = SoftBindingQueryResult {
            matches: vec![
                SoftBindingQueryResultMatch {
                    manifest_id: "some manifest id 1".to_owned(),
                    endpoint: None,
                    similarity_score: Some(75),
                },
                SoftBindingQueryResultMatch {
                    manifest_id: "some manifest id 2".to_owned(),
                    endpoint: None,
                    similarity_score: Some(50),
                },
            ],
        };

        let upload_file_mock = mock_upload_file(&server, &query, &result);

        let client = mock_soft_binding_client();
        let fingerprint_match = client
            .fingerprint_match_by_stream(entry, "image/jpeg", &mut Cursor::new(&query.asset_bytes))
            .unwrap()
            .unwrap();

        let correct_fingerprint_match = SoftBindingMatch::from_query(
            server.base_url(),
            result.matches.first().unwrap().to_owned(),
        );
        assert_eq!(correct_fingerprint_match, fingerprint_match);

        upload_file_mock.assert();
    }

    #[test]
    fn test_watermark_match_by_stream() {
        let server = MockServer::start();
        let list = mock_soft_binding_algorithm_list(&server.base_url());
        let entry = list.first().unwrap();

        let query = UploadFileQuery {
            alg: entry.alg.to_owned(),
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
                similarity_score: None,
            }],
        };

        let upload_file_mock = mock_upload_file(&server, &query, &result);

        let client = mock_soft_binding_client();
        let watermark_match = client
            .watermark_match_by_stream(entry, "image/jpeg", &mut Cursor::new(&query.asset_bytes))
            .unwrap()
            .unwrap();

        let correct_watermark_match = SoftBindingMatch::from_query(
            server.base_url(),
            result.matches.first().unwrap().to_owned(),
        );
        assert_eq!(correct_watermark_match, watermark_match);

        upload_file_mock.assert();
    }

    #[test]
    fn test_fetch_matches_by_algorithm_value() {
        let server = MockServer::start();
        let list = mock_soft_binding_algorithm_list(&server.base_url());
        let entry = list.first().unwrap();

        let query = ByBindingQuery {
            value: "test value".to_owned(),
            alg: entry.alg.clone(),
            max_results: None,
        };
        let result = SoftBindingQueryResult {
            matches: vec![SoftBindingQueryResultMatch {
                manifest_id: "some manifest id".to_owned(),
                endpoint: None,
                similarity_score: None,
            }],
        };

        let by_large_binding_mock = mock_by_large_binding(&server, &query, &result);

        let client = mock_soft_binding_client();
        let a_match: Vec<SoftBindingMatch> = client
            .fetch_matches_by_algorithm_value(entry, &query.value, query.max_results, None)
            .unwrap()
            .into_iter()
            .collect::<Result<_>>()
            .unwrap();

        let correct_match = SoftBindingMatch::from_query(
            server.base_url(),
            result.matches.first().unwrap().to_owned(),
        );
        assert_eq!(vec![correct_match], a_match);

        by_large_binding_mock.assert();
    }

    #[test]
    fn test_fetch_matches_by_stream() {
        let server = MockServer::start();
        let list = mock_soft_binding_algorithm_list(&server.base_url());
        let entry = list.first().unwrap();

        let query = UploadFileQuery {
            alg: entry.alg.clone(),
            max_results: None,
            mime_type: "image/jpeg".to_owned(),
            asset_bytes: vec![1, 2, 3],
            hint_alg: None,
            hint_value: None,
        };
        let result = SoftBindingQueryResult {
            matches: vec![SoftBindingQueryResultMatch {
                manifest_id: "some manifest id".to_owned(),
                endpoint: None,
                similarity_score: None,
            }],
        };

        let upload_file_mock = mock_upload_file(&server, &query, &result);

        let client = mock_soft_binding_client();
        let a_match: Vec<SoftBindingMatch> = client
            .fetch_matches_by_stream(
                entry,
                &query.mime_type,
                &mut Cursor::new(&query.asset_bytes),
                None,
                query.max_results,
                None,
            )
            .unwrap()
            .into_iter()
            .flatten()
            .collect();

        let correct_match = SoftBindingMatch::from_query(
            server.base_url(),
            result.matches.first().unwrap().to_owned(),
        );
        assert_eq!(vec![correct_match], a_match);

        upload_file_mock.assert();
    }

    #[test]
    fn test_fetch_manifest_bytes() {
        let query = GetManifestByIdQuery {
            manifest_id: "some manifest id".to_owned(),
            return_active_manifest: Some(false),
        };
        let result = vec![1, 2, 3];

        let server = MockServer::start();
        let get_manifest_by_id_mock = mock_get_manifest_by_id(&server, &query, &result);

        let a_match = SoftBindingMatch {
            manifest_id: query.manifest_id,
            url: server.base_url(),
            similarity_score: None,
        };

        let client = mock_soft_binding_client();
        let response = client.fetch_manifest_bytes(&a_match).unwrap();

        assert_eq!(result, response);

        get_manifest_by_id_mock.assert();
    }

    #[test]
    fn test_fetch_active_manifest_bytes() {
        let query = GetManifestByIdQuery {
            manifest_id: "some manifest id".to_owned(),
            return_active_manifest: Some(true),
        };
        let result = vec![1, 2, 3];

        let server = MockServer::start();
        let get_manifest_by_id_mock = mock_get_manifest_by_id(&server, &query, &result);

        let a_match = SoftBindingMatch {
            manifest_id: query.manifest_id,
            url: server.base_url(),
            similarity_score: None,
        };

        let client = mock_soft_binding_client();
        let response = client.fetch_active_manifest_bytes(&a_match).unwrap();

        assert_eq!(result, response);

        get_manifest_by_id_mock.assert();
    }
}
