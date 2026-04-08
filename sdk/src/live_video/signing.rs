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
        let (stream_id, previous_manifest_id, next_sequence_number, base_manifest_json) =
            extract_live_video_state(&json)?;
        Ok(Self {
            stream_id,
            next_sequence_number,
            previous_manifest_id,
            base_manifest_json,
        })
    }

    /// Returns the original manifest JSON updated with the current continuity state.
    ///
    /// Call this after signing a batch of segments and persist the result back to the manifest
    /// file so that the next invocation resumes the chain automatically.
    pub fn updated_manifest_json(&self, original_manifest_json: &str) -> Result<String> {
        let mut value: serde_json::Value = serde_json::from_str(original_manifest_json)
            .map_err(|e| Error::BadParam(format!("invalid manifest JSON: {e}")))?;

        let assertions = value["assertions"]
            .as_array_mut()
            .ok_or_else(|| Error::BadParam("manifest must have an 'assertions' array".to_string()))?;

        let assertion = assertions
            .iter_mut()
            .find(|a| a["label"].as_str() == Some(LiveVideoSegment::LABEL))
            .ok_or_else(|| {
                Error::BadParam(format!(
                    "manifest must include a '{}' assertion",
                    LiveVideoSegment::LABEL
                ))
            })?;

        if let Some(prev_id) = &self.previous_manifest_id {
            assertion["data"]["previousManifestId"] =
                serde_json::Value::String(prev_id.clone());
        }
        assertion["data"]["nextSequenceNumber"] =
            serde_json::Value::Number(self.next_sequence_number.into());

        serde_json::to_string_pretty(&value)
            .map_err(|e| Error::BadParam(format!("failed to serialize manifest: {e}")))
    }

    /// Restores continuity state from a previously signed segment.
    ///
    /// Reads `previousManifestId` and `sequenceNumber` from the segment's embedded manifest.
    /// Use this when signing one segment per process invocation, pointing to the last signed
    /// segment so the chain is not broken.
    pub fn resume_from_segment(&mut self, segment_data: &[u8], format: &str) -> Result<()> {
        let reader = Reader::from_stream(format, &mut Cursor::new(segment_data))?;
        let manifest = reader.active_manifest().ok_or(Error::NotFound)?;

        let assertion: LiveVideoSegment = manifest
            .find_assertion(LiveVideoSegment::LABEL)
            .map_err(|_| {
                Error::BadParam(format!(
                    "segment has no '{}' assertion",
                    LiveVideoSegment::LABEL
                ))
            })?;

        self.previous_manifest_id = Some(manifest.instance_id().to_string());
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
        let mut builder = Builder::from_json(&self.base_manifest_json)?;
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

        let mut builder = Builder::from_json(&self.base_manifest_json)?;
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

    /// Returns the sequence number that will be assigned to the next media segment.
    pub fn next_sequence_number(&self) -> u64 {
        self.next_sequence_number
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
    let reader = Reader::from_stream(format, &mut Cursor::new(signed_segment))?;
    reader
        .active_manifest()
        .map(|m| m.instance_id().to_string())
        .ok_or(Error::NotFound)
}

/// Parses the manifest JSON and extracts the live video signer state.
///
/// Returns `(stream_id, previous_manifest_id, next_sequence_number, base_manifest_json)`.
/// The `c2pa.livevideo.segment` assertion is removed from `base_manifest_json` so it is
/// not duplicated when the full assertion is added at signing time.
fn extract_live_video_state(
    manifest_json: &str,
) -> Result<(String, Option<String>, u64, String)> {
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

    let previous_manifest_id = data["previousManifestId"]
        .as_str()
        .map(String::from);

    let next_sequence_number = data["nextSequenceNumber"]
        .as_u64()
        .unwrap_or(1);

    let base_json = serde_json::to_string(&value)
        .map_err(|e| Error::BadParam(format!("failed to serialize manifest: {e}")))?;

    Ok((stream_id, previous_manifest_id, next_sequence_number, base_json))
}
