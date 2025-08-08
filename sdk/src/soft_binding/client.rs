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

use std::cmp::Ordering;

use crate::{
    soft_binding::{
        algorithm_list::SoftBindingAlgorithmEntry,
        resolution_api::{
            SoftBindingQueryResult, SoftBindingQueryResultMatch, SoftBindingResolutionApi,
        },
    },
    Error, Result,
};

#[derive(Debug, PartialEq, Eq)]
pub struct SoftBindingMatch {
    /// Unique identifier of a matched C2PA Manifest.
    pub manifest_id: String,
    /// TODO: doc
    pub url: String,
    /// An integer score in the range (0-100) representing the strength of match, if
    /// appropriate, where 0 is the weakest possible match and 100 is the strongest
    /// possible match.
    pub similarity_score: Option<u32>,
}

impl SoftBindingMatch {
    pub fn from_query(mut base_url: String, query: SoftBindingQueryResultMatch) -> Self {
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

// TODO: I don't think we need to do this comparison, the spec refers to a "matcher" in what I assume
//       is the server we fetch the soft binding match from. Thus, I believe we just have to trust
//       what they return?
// #[derive(Debug)]
// pub struct SoftBindingManifest {
//     bytes: Vec<u8>,
// }

// impl SoftBindingManifest {
//     pub fn matches(&self, that_manifest: &Manifest) -> bool {
//         // TODO: ensure if .alg is absent it's taken from the claim
//         let this_soft_binding: SoftBinding = todo!();
//         let that_soft_binding: SoftBinding = todo!();

//         // TODO: line up this and that blocks

//         // IMPORTANT:
//         // https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_validating_soft_binding_matches
//         // > Matching is performed in the manner prescribed by the specified algorithm.
//         // so how would we see if a soft binding matches another generically?

//         this_soft_binding.alg.is_some()
//             && that_soft_binding.alg.is_some()
//             && this_soft_binding.alg == that_soft_binding.alg
//             && this_soft_binding.blocks == that_soft_binding.blocks
//     }
// }

#[derive(Debug)]
pub struct SoftBindingClient<T> {
    oauth_resolver: T,
}

impl<T> SoftBindingClient<T>
where
    T: Fn(&str) -> Option<&str>,
{
    pub fn new(oauth_resolver: T) -> Self {
        SoftBindingClient { oauth_resolver }
    }

    // this is impled according to the fingerprint-golden in the spec
    pub fn fingerprint_match_by_stream(
        &self,
        entry: &SoftBindingAlgorithmEntry,
        // TODO: validate this based on the entry
        mime_type: &str,
        // TODO: stream this
        asset_bytes: &[u8],
    ) -> Result<Option<SoftBindingMatch>> {
        let matches = self.fetch_matches_by_stream(
            entry,
            mime_type,
            asset_bytes,
            // TODO: what would hint value be for a fingerprint or is it only for watermark?
            None,
            None,
            None,
        )?;

        Ok(matches.into_iter().flatten().max())
    }

    // this is impled according to the watermark-golden in the spec
    pub fn watermark_match_by_stream(
        &self,
        entry: &SoftBindingAlgorithmEntry,
        // TODO: validate this based on the entry
        mime_type: &str,
        // TODO: stream this
        asset_bytes: &[u8],
    ) -> Result<Option<SoftBindingMatch>> {
        let matches = self.fetch_matches_by_stream(
            entry,
            mime_type,
            asset_bytes,
            // TODO: can we take a hint?
            None,
            Some(1),
            Some(1),
        )?;

        Ok(matches.into_iter().find_map(|a_match| a_match.ok()))
    }

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

    #[inline]
    pub fn fetch_matches_by_stream(
        &self,
        entry: &SoftBindingAlgorithmEntry,
        // TODO: validate this based on the entry
        mime_type: &str,
        // TODO: stream this
        asset_bytes: &[u8],
        hint_value: Option<&str>,
        max_results_per_api: Option<u32>,
        hint_max_results: Option<u32>,
    ) -> Result<Vec<Result<SoftBindingMatch>>> {
        self.fetch_matches_impl(entry, hint_max_results, |url: &str, token: &str| {
            // TODO: depending on what hint_value is, if that's specified we can just call the binding APIs
            SoftBindingResolutionApi::upload_file(
                url,
                token,
                &entry.alg,
                mime_type,
                asset_bytes,
                max_results_per_api,
                Some(&entry.alg),
                hint_value,
            )
        })
    }

    #[inline]
    pub fn fetch_manifest_bytes(&self, manifest_match: &SoftBindingMatch) -> Result<Vec<u8>> {
        self.fetch_manifest_bytes_impl(manifest_match, false)
    }

    #[inline]
    pub fn fetch_active_manifest_bytes(
        &self,
        manifest_match: &SoftBindingMatch,
    ) -> Result<Vec<u8>> {
        self.fetch_manifest_bytes_impl(manifest_match, true)
    }

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

    use httpmock::MockServer;

    use crate::soft_binding::{
        algorithm_list::tests::mock_soft_binding_algorithm_list,
        resolution_api::tests::{mock_upload_file, UploadFileQuery, TEST_BEARER_TOKEN},
    };

    use super::*;

    pub fn mock_soft_binding_client() -> SoftBindingClient<impl Fn(&str) -> Option<&str>> {
        SoftBindingClient::new(|_| Some(TEST_BEARER_TOKEN))
    }

    #[test]
    fn test_fingerprint_match_by_stream() {
        let list = mock_soft_binding_algorithm_list();
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
                similarity_score: Some(75),
            }],
        };

        let server = MockServer::start();
        let upload_file_mock = mock_upload_file(&server, &query, &result);

        let client = mock_soft_binding_client();
        let fingerprint_match = client
            .fingerprint_match_by_stream(entry, "image/jpeg", &query.asset_bytes)
            .unwrap()
            .unwrap();

        let correct_fingerprint_match = SoftBindingMatch::from_query(
            server.base_url(),
            result.matches.first().unwrap().to_owned(),
        );
        assert_eq!(correct_fingerprint_match, fingerprint_match);

        upload_file_mock.assert();
    }

    // TODO: rest of the tests
}
