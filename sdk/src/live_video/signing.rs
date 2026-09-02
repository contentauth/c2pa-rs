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

//! Live video signing support for C2PA section 19.3 (per-segment C2PA Manifest Box method).

use std::{collections::HashMap, io::Cursor};

use crate::{
    assertions::{ContinuityMethod, LiveVideoSegment},
    builder::Builder,
    error::{Error, Result},
    Reader, Signer,
};

/// Signs a sequence of live video segments using the per-segment C2PA Manifest Box method (§19.3).
///
/// Call [`sign_media_segment`] once per segment; sequence numbers and continuity links are managed
/// automatically. Optionally call [`sign_init_segment`] to embed a manifest into the init segment.
///
/// [`sign_media_segment`]: LiveVideoSigner::sign_media_segment
/// [`sign_init_segment`]: LiveVideoSigner::sign_init_segment
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
pub struct LiveVideoSigner {
    stream_id: String,
    next_sequence_number: u64,
    previous_manifest_id: Option<String>,
    base_manifest_json: String,
}

impl LiveVideoSigner {
    /// Creates a new signer from a manifest JSON string.
    ///
    /// The manifest must contain a `c2pa.livevideo.segment` assertion with a `streamId` field.
    /// That assertion is used only to read `streamId` — it is stripped from the base manifest
    /// and rebuilt with full continuity metadata on each [`sign_media_segment`] call.
    ///
    /// [`sign_media_segment`]: LiveVideoSigner::sign_media_segment
    pub fn from_manifest_json(manifest_json: impl Into<String>) -> Result<Self> {
        let json = manifest_json.into();
        let (stream_id, base_manifest_json) = extract_live_video_state(&json)?;
        Ok(Self {
            stream_id,
            // A fresh signer starts the chain; `resume_from_segment` overrides this when
            // continuing an existing one.
            next_sequence_number: 1,
            previous_manifest_id: None,
            base_manifest_json,
        })
    }

    /// Restores continuity state from a previously signed segment.
    ///
    /// Reads `previousManifestId` and `sequenceNumber` from the segment's embedded manifest.
    /// Use this when signing one segment per process invocation, pointing to the last signed
    /// segment so the chain is not broken.
    pub fn resume_from_segment(&mut self, segment_data: &[u8], format: &str) -> Result<()> {
        let reader = Reader::from_context(super::context_from_thread_local_settings()?)
            .with_stream(format, Cursor::new(segment_data))?;
        let manifest = reader.active_manifest().ok_or(Error::NotFound)?;

        let assertion: LiveVideoSegment = manifest
            .find_assertion(LiveVideoSegment::LABEL)
            .map_err(|_| {
                Error::BadParam(format!(
                    "segment has no '{}' assertion",
                    LiveVideoSegment::LABEL
                ))
            })?;

        let manifest_id = manifest
            .label()
            .ok_or_else(|| Error::BadParam("segment's active manifest has no label".to_string()))?
            .to_string();
        self.previous_manifest_id = Some(manifest_id);
        self.next_sequence_number = assertion.sequence_number + 1;
        Ok(())
    }

    /// Signs an init segment with the base manifest (§19.2.3). Optional for §19.3 streams.
    ///
    /// No `c2pa.livevideo.segment` assertion is added and continuity state is not updated.
    pub fn sign_init_segment(
        &self,
        segment_data: &[u8],
        format: &str,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let mut builder = Builder::from_context(super::context_from_thread_local_settings()?)
            .with_definition(self.base_manifest_json.as_str())?;
        let mut source = Cursor::new(segment_data);
        let mut dest = Cursor::new(Vec::new());
        builder.sign(signer, format, &mut source, &mut dest)?;
        Ok(dest.into_inner())
    }

    /// Signs a media segment, embeds a `c2pa.livevideo.segment` assertion, and advances state.
    pub fn sign_media_segment(
        &mut self,
        segment_data: &[u8],
        format: &str,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let assertion = self.build_live_video_assertion();

        let mut builder = Builder::from_context(super::context_from_thread_local_settings()?)
            .with_definition(self.base_manifest_json.as_str())?;
        builder.add_assertion(LiveVideoSegment::LABEL, &assertion)?;

        let mut source = Cursor::new(segment_data);
        let mut dest = Cursor::new(Vec::new());
        builder.sign(signer, format, &mut source, &mut dest)?;

        let signed_bytes = dest.into_inner();
        let manifest_id = extract_signed_manifest_id(&signed_bytes, format)?;

        self.next_sequence_number += 1;
        self.previous_manifest_id = Some(manifest_id);

        Ok(signed_bytes)
    }

    /// Returns the manifest ID of the most recently signed media segment, if any.
    pub fn previous_manifest_id(&self) -> Option<&str> {
        self.previous_manifest_id.as_deref()
    }

    fn build_live_video_assertion(&self) -> LiveVideoSegment {
        LiveVideoSegment {
            sequence_number: self.next_sequence_number,
            stream_id: self.stream_id.clone(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: self.previous_manifest_id.clone(),
            additional_fields: HashMap::new(),
        }
    }
}

fn extract_signed_manifest_id(signed_segment: &[u8], format: &str) -> Result<String> {
    let reader = Reader::from_context(super::context_from_thread_local_settings()?)
        .with_stream(format, Cursor::new(signed_segment))?;
    reader
        .active_manifest()
        .and_then(|m| m.label())
        .map(|l| l.to_string())
        .ok_or(Error::NotFound)
}

/// Parses the manifest JSON and extracts the live video signer state.
///
/// Returns `(stream_id, base_manifest_json)`.
///
/// Only `streamId` is read. `sequenceNumber`, `continuityMethod` and `previousManifestId` are
/// the signer's to manage, as `cli/docs/manifest.md` states: a `previousManifestId` left in a
/// manifest file between sessions would otherwise be signed verbatim into the first segment as
/// a claim about a predecessor this stream does not contain, and no validator would catch it,
/// since §19.3.2's continuity check has no previous segment to compare against. Resuming a
/// chain is `resume_from_segment`'s job, which reads the real predecessor.
/// The `c2pa.livevideo.segment` assertion is removed from `base_manifest_json` so it is
/// not duplicated when the full assertion is added at signing time.
fn extract_live_video_state(manifest_json: &str) -> Result<(String, String)> {
    let mut value: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|e| Error::BadParam(format!("invalid manifest JSON: {e}")))?;

    let assertions = value["assertions"]
        .as_array_mut()
        .ok_or_else(|| Error::BadParam("manifest must have an 'assertions' array".to_string()))?;

    let position = assertions
        .iter()
        .position(|a| a["label"].as_str() == Some(LiveVideoSegment::LABEL))
        .ok_or_else(|| {
            Error::BadParam(format!(
                "manifest must include a '{}' assertion with 'streamId'",
                LiveVideoSegment::LABEL
            ))
        })?;

    let live_video_assertion = assertions.remove(position);
    let data = &live_video_assertion["data"];

    let stream_id = data["streamId"]
        .as_str()
        .ok_or_else(|| {
            Error::BadParam(format!(
                "'{}' assertion must have a 'streamId' string field",
                LiveVideoSegment::LABEL
            ))
        })?
        .to_string();

    let base_json = serde_json::to_string(&value)
        .map_err(|e| Error::BadParam(format!("failed to serialize manifest: {e}")))?;

    Ok((stream_id, base_json))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::utils::ephemeral_signer::EphemeralSigner;

    fn test_signer() -> EphemeralSigner {
        EphemeralSigner::new("test-manifestbox.local").unwrap()
    }

    fn test_manifest_json() -> &'static str {
        r#"{"assertions": [
            {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"}]}},
            {"label": "c2pa.livevideo.segment", "data": {"sequenceNumber": 1, "streamId": "stream-1", "continuityMethod": "c2pa.manifestId"}}
        ]}"#
    }

    /// `verify.verify_trust` is thread-local and `cargo test` reuses threads, so leaving it off
    /// would let a later test on the same thread pass while masking a real trust failure.
    struct TrustVerificationOff;

    impl TrustVerificationOff {
        fn new() -> Self {
            // EphemeralSigner certs are intentionally untrusted (see ephemeral_signer.rs).
            crate::settings::set_settings_value("verify.verify_trust", false).unwrap();
            Self
        }
    }

    impl Drop for TrustVerificationOff {
        fn drop(&mut self) {
            crate::settings::set_settings_value("verify.verify_trust", true).unwrap();
        }
    }

    fn init_fixture() -> &'static [u8] {
        include_bytes!("../../tests/fixtures/bunny/bunny_791182bps/BigBuckBunny_2s_init.mp4")
    }

    fn segment_fixture() -> &'static [u8] {
        include_bytes!("../../tests/fixtures/bunny/bunny_791182bps/BigBuckBunny_2s5.m4s")
    }

    /// `extract_live_video_state` is the only validation a caller's manifest gets before
    /// signing starts, so each way it can be malformed must be rejected with a usable message
    /// rather than panicking or silently signing something incomplete.
    #[test]
    fn from_manifest_json_rejects_malformed_manifests() {
        for (json, expected) in [
            ("not json at all", "invalid manifest JSON"),
            (r#"{"assertions": {}}"#, "assertions"),
            (r#"{"assertions": []}"#, LiveVideoSegment::LABEL),
            (
                r#"{"assertions": [{"label": "c2pa.livevideo.segment", "data": {}}]}"#,
                "streamId",
            ),
        ] {
            let result = LiveVideoSigner::from_manifest_json(json);
            assert!(
                result.is_err(),
                "malformed manifest must be rejected: {json}"
            );
            let err = result.err().map(|e| e.to_string()).unwrap_or_default();
            assert!(
                err.contains(expected),
                "error should mention {expected:?}, got: {err}"
            );
        }
    }

    /// `cli/docs/manifest.md` says the signer manages `sequenceNumber`, `continuityMethod` and
    /// `previousManifestId`. A `previousManifestId` left in a manifest file between sessions
    /// used to be signed verbatim into the first segment, as a claim about a predecessor the
    /// stream does not contain, which no validator catches: §19.3.2's continuity check has no
    /// previous segment to compare it against.
    #[test]
    fn a_manifest_supplied_previous_manifest_id_is_not_signed_into_the_first_segment() {
        let _guard = TrustVerificationOff::new();
        let signer = test_signer();

        let manifest = r#"{"assertions": [
            {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"}]}},
            {"label": "c2pa.livevideo.segment", "data": {
                "sequenceNumber": 5000,
                "streamId": "stream-1",
                "continuityMethod": "c2pa.manifestId",
                "previousManifestId": "urn:c2pa:SEEDED-BY-USER"}}
        ]}"#;

        let mut live_signer = LiveVideoSigner::from_manifest_json(manifest).unwrap();
        assert!(live_signer.previous_manifest_id().is_none());

        let signed = live_signer
            .sign_media_segment(segment_fixture(), "video/mp4", &signer)
            .unwrap();
        let reader =
            Reader::from_context(crate::live_video::context_from_thread_local_settings().unwrap())
                .with_stream("video/mp4", Cursor::new(&signed))
                .unwrap();
        let assertion: LiveVideoSegment = reader
            .active_manifest()
            .unwrap()
            .find_assertion(LiveVideoSegment::LABEL)
            .unwrap();

        assert_eq!(assertion.previous_manifest_id, None);
        assert_eq!(assertion.sequence_number, 1);
    }

    /// §19.3.2 chains each segment to the previous one through `previousManifestId`. The first
    /// segment has none, and every later one must carry the label of the segment before it.
    #[test]
    fn previous_manifest_id_chains_across_segments() {
        let _guard = TrustVerificationOff::new();
        let signer = test_signer();
        let mut live_signer = LiveVideoSigner::from_manifest_json(test_manifest_json()).unwrap();

        assert!(
            live_signer.previous_manifest_id().is_none(),
            "a fresh signer has nothing to chain to"
        );

        let mut labels = Vec::new();
        for _ in 0..3 {
            let signed = live_signer
                .sign_media_segment(segment_fixture(), "video/mp4", &signer)
                .unwrap();
            let reader = Reader::from_context(
                crate::live_video::context_from_thread_local_settings().unwrap(),
            )
            .with_stream("video/mp4", Cursor::new(&signed))
            .unwrap();
            let label = reader
                .active_manifest()
                .unwrap()
                .label()
                .unwrap()
                .to_string();

            // After signing segment N, the signer points at N: that is what segment N+1 will
            // record as its `previousManifestId`.
            assert_eq!(live_signer.previous_manifest_id(), Some(label.as_str()));
            labels.push(label);
        }

        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), 3, "each segment must get its own manifest id");
    }

    /// §19.2.3 makes signing the init segment optional, and it carries no
    /// `c2pa.livevideo.segment` assertion: it must not advance the continuity state.
    #[test]
    fn sign_init_segment_does_not_advance_the_chain() {
        let _guard = TrustVerificationOff::new();
        let signer = test_signer();
        let live_signer = LiveVideoSigner::from_manifest_json(test_manifest_json()).unwrap();

        let signed = live_signer
            .sign_init_segment(init_fixture(), "video/mp4", &signer)
            .unwrap();

        assert!(live_signer.previous_manifest_id().is_none());

        let reader =
            Reader::from_context(crate::live_video::context_from_thread_local_settings().unwrap())
                .with_stream("video/mp4", Cursor::new(&signed))
                .unwrap();
        let manifest = reader.active_manifest().unwrap();
        assert!(
            manifest
                .find_assertion::<LiveVideoSegment>(LiveVideoSegment::LABEL)
                .is_err(),
            "the init segment carries no live video segment assertion"
        );
    }

    /// Signing one segment per process invocation is the live case, so a fresh signer must be
    /// able to pick the chain up from the last segment the previous run wrote.
    #[test]
    fn resume_from_segment_restores_the_chain() {
        let _guard = TrustVerificationOff::new();
        let signer = test_signer();

        let mut first_run = LiveVideoSigner::from_manifest_json(test_manifest_json()).unwrap();
        let signed = first_run
            .sign_media_segment(segment_fixture(), "video/mp4", &signer)
            .unwrap();
        let expected = first_run.previous_manifest_id().unwrap().to_string();

        let mut second_run = LiveVideoSigner::from_manifest_json(test_manifest_json()).unwrap();
        second_run
            .resume_from_segment(&signed, "video/mp4")
            .unwrap();

        assert_eq!(second_run.previous_manifest_id(), Some(expected.as_str()));
    }

    #[test]
    fn resume_from_segment_rejects_a_segment_without_a_manifest() {
        let _guard = TrustVerificationOff::new();
        let mut live_signer = LiveVideoSigner::from_manifest_json(test_manifest_json()).unwrap();

        assert!(live_signer
            .resume_from_segment(segment_fixture(), "video/mp4")
            .is_err());
    }

    /// Regression test: `manifestId`/`previousManifestId` must be the manifest's c2pa URN
    /// label (§8.1), not its XMP instance ID — otherwise continuity breaks with any
    /// spec-compliant third-party validator, since instance IDs and manifest labels are
    /// different, unrelated identifiers.
    #[test]
    fn sign_media_segment_manifest_id_is_c2pa_urn_label() {
        // EphemeralSigner certs are intentionally untrusted (see ephemeral_signer.rs).
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let signer = test_signer();
        let segment_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_791182bps/BigBuckBunny_2s5.m4s");

        let mut live_signer = LiveVideoSigner::from_manifest_json(test_manifest_json()).unwrap();
        let signed = live_signer
            .sign_media_segment(segment_data, "video/mp4", &signer)
            .unwrap();

        let manifest_id = live_signer.previous_manifest_id().unwrap().to_string();
        assert!(
            manifest_id.starts_with("urn:c2pa:"),
            "manifestId must be the manifest's c2pa URN label (§8.1), got: {manifest_id}"
        );

        // Cross-check against the label actually embedded in the signed segment's manifest.
        let reader =
            Reader::from_context(crate::live_video::context_from_thread_local_settings().unwrap())
                .with_stream("video/mp4", Cursor::new(&signed))
                .unwrap();
        let manifest = reader.active_manifest().unwrap();
        assert_eq!(manifest.label().unwrap(), manifest_id);
    }
}
