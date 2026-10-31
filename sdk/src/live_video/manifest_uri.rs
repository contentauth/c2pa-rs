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

use super::{fail_validation, LiveVideoValidator};
use crate::{
    error::{Error, Result},
    status_tracker::StatusTracker,
    utils::hash_utils::hash_size_by_alg,
    validation_results::validation_codes::LIVEVIDEO_SEGMENT_INVALID,
    HashedUri,
};

/// A hashed-ext-uri requires an explicit algorithm, unlike an in-store hashed URI.
pub(super) fn validate_reference(uri: &HashedUri) -> Result<()> {
    if !crate::store::Store::is_valid_remote_url(&uri.url()) {
        return Err(Error::BadParam(
            "manifestUri must be an absolute HTTP(S) URL".into(),
        ));
    }
    let alg = uri
        .alg()
        .ok_or_else(|| Error::BadParam("manifestUri requires an explicit alg".into()))?;
    if hash_size_by_alg(&alg)? != uri.hash().len() {
        return Err(Error::BadParam(
            "manifestUri hash length does not match alg".into(),
        ));
    }
    Ok(())
}

impl LiveVideoValidator {
    pub(super) fn resolve_manifest_uri(
        &mut self,
        segment_data: &[u8],
        parsed: &super::verifiable_segment_info::ParsedVsi,
        context: &std::sync::Arc<crate::Context>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let Some(uri) = &parsed.segment_info_map.manifest_uri else {
            return Ok(());
        };
        if let Err(error) = validate_reference(uri) {
            return fail_validation(
                format!("invalid manifestUri: {error}"),
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        let kid = &parsed.sign1.unprotected.key_id;
        let known = self.session_keys.iter().any(|entry| {
            entry.manifest_id == parsed.segment_info_map.manifest_id
                && super::cose_key::kid_from_cose_key(&entry.key.key)
                    .is_some_and(|value| value == *kid)
        });
        if kid.is_empty() || known {
            return Ok(());
        }
        // An embedded manifest takes precedence; `read_segment_session_keys` has handled it.
        if super::box_walk::top_level_boxes(segment_data).any(|(kind, bytes)| {
            kind == b"uuid"
                && super::box_walk::box_payload(bytes)
                    .is_some_and(|payload| payload.starts_with(&super::C2PA_UUID))
        }) {
            return Ok(());
        }
        #[cfg(feature = "fetch_remote_manifests")]
        {
            if !context.settings().verify.remote_manifest_fetch {
                return fail_validation(
                    "manifestUri key is unknown and remote manifest fetching is disabled",
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                );
            }
            self.fetch_manifest_uri(segment_data, parsed, uri, context, tracker)
        }
        #[cfg(not(feature = "fetch_remote_manifests"))]
        {
            let _ = context;
            fail_validation(
                "manifestUri key is unknown; enable fetch_remote_manifests to retrieve it",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )
        }
    }

    #[cfg(feature = "fetch_remote_manifests")]
    fn fetch_manifest_uri(
        &mut self,
        segment_data: &[u8],
        parsed: &super::verifiable_segment_info::ParsedVsi,
        uri: &HashedUri,
        context: &std::sync::Arc<crate::Context>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        use crate::{
            store::Store, utils::hash_utils::verify_by_alg,
            validation_results::validation_codes::LIVEVIDEO_MANIFEST_INVALID, Reader,
            ValidationState,
        };
        if !context.settings().verify.verify_after_reading {
            return fail_validation(
                "manifestUri requires manifest validation to be enabled",
                LIVEVIDEO_MANIFEST_INVALID,
                tracker,
            );
        }
        let bytes = match Store::fetch_remote_manifest(&uri.url(), context) {
            Ok(bytes) => bytes,
            Err(error) => {
                return fail_validation(
                    format!("could not retrieve manifestUri: {error}"),
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                )
            }
        };
        // Check the entire downloaded store before parsing or accepting any of its keys.
        let alg = uri
            .alg()
            .ok_or_else(|| Error::BadParam("manifestUri requires alg".into()))?;
        if !verify_by_alg(&alg, &uri.hash(), &bytes, None) {
            return fail_validation(
                "manifestUri hash does not match the downloaded manifest store",
                LIVEVIDEO_MANIFEST_INVALID,
                tracker,
            );
        }
        let trust_configured = super::trust_configured(context.settings());
        // A referenced manifest can bind the current segment or the stream's initialization
        // segment. Both paths run complete Reader validation, including the hard binding.
        let reader = [Some(segment_data), self.init_segment_data.as_deref()]
            .into_iter()
            .flatten()
            .find_map(|asset| {
                Reader::from_shared_context(context)
                    .with_manifest_data_and_stream(&bytes, "video/mp4", std::io::Cursor::new(asset))
                    .ok()
                    .filter(|reader| {
                        reader.validation_state() != ValidationState::Invalid
                            && (!context.settings().verify.verify_trust
                                || !trust_configured
                                || reader.validation_state() == ValidationState::Trusted)
                    })
            });
        let Some(reader) = reader else {
            return fail_validation("manifestUri manifest failed validation against the media and initialization segments",
                LIVEVIDEO_MANIFEST_INVALID, tracker);
        };
        if reader
            .active_manifest()
            .and_then(|manifest| manifest.label())
            != Some(&parsed.segment_info_map.manifest_id)
        {
            return fail_validation(
                "manifestUri manifest identifier does not match VSI manifestId",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        // Stage key discovery so failed binding/sequence checks cannot replace cached keys.
        let mut candidate = Self::new();
        candidate.session_keys = self.session_keys.clone();
        candidate.session_key_signer = self.session_key_signer.clone();
        let before = tracker.filter_errors().count();
        // Retrieving an existing remote manifest is not a new embedded announcement.
        // Its key may have started earlier; normal VSI validation enforces sequence >= min.
        candidate.validate_session_keys_from_reader(&reader, None, tracker)?;
        if tracker.filter_errors().count() != before {
            return Ok(());
        }
        let found = candidate.session_keys.iter().any(|entry| {
            entry.manifest_id == parsed.segment_info_map.manifest_id
                && super::cose_key::kid_from_cose_key(&entry.key.key)
                    .is_some_and(|value| value == parsed.sign1.unprotected.key_id)
        });
        if !found {
            return fail_validation(
                "manifestUri manifest does not contain the VSI session key",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        self.session_keys = candidate.session_keys;
        self.session_key_signer = candidate.session_key_signer;
        Ok(())
    }
}
