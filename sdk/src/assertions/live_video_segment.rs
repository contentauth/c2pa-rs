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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::labels;
use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    Result,
};

/// Method used to establish cryptographic continuity between adjacent live video segments.
///
/// See [Live Video - C2PA Technical Specification section 19.3.2](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box).
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ContinuityMethod {
    /// Links segments by matching `previousManifestId` to the previous segment's C2PA Manifest ID.
    #[serde(rename = "c2pa.manifestId")]
    ManifestId,

    /// An unrecognized or future continuity method. Preserved verbatim for lossless round-trip.
    #[serde(untagged)]
    Unknown(String),
}

impl ContinuityMethod {
    /// Sentinel used when `continuityMethod` is absent from the wire (§19.7.2), so that
    /// deserializing [`LiveVideoSegment`] still succeeds and validation can report the
    /// spec-mandated `livevideo.continuityMethod.invalid` failure, instead of the whole
    /// assertion failing to parse and surfacing a generic/misleading error upstream.
    fn missing() -> Self {
        ContinuityMethod::Unknown(String::new())
    }
}

/// Assertion embedded in each live video segment's C2PA Manifest (`c2pa.livevideo.segment`).
///
/// Carries the metadata required to validate segment ordering and stream continuity
/// using the per-segment C2PA Manifest Box method.
///
/// See [Live Video - C2PA Technical Specification section 19.3.2](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box).
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LiveVideoSegment {
    /// Monotonically increasing counter identifying this segment within the stream.
    pub sequence_number: u64,

    /// Unique identifier for the live stream this segment belongs to.
    pub stream_id: String,

    /// Method used to establish cryptographic continuity with the previous segment.
    ///
    /// Defaults to `ContinuityMethod::missing()` when absent from the wire, rather than
    /// failing deserialization outright, so that validation can report the spec-mandated
    /// `livevideo.continuityMethod.invalid` failure (§19.7.2) instead of a generic parse error.
    #[serde(default = "ContinuityMethod::missing")]
    pub continuity_method: ContinuityMethod,

    /// C2PA Manifest identifier of the immediately preceding segment.
    ///
    /// Required when `continuity_method` is [`ContinuityMethod::ManifestId`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_manifest_id: Option<String>,

    /// Extension fields for future or vendor-specific continuity methods (`* tstr => any`).
    #[serde(flatten)]
    pub additional_fields: HashMap<String, c2pa_cbor::Value>,
}

impl LiveVideoSegment {
    /// The assertion label as defined in the C2PA specification.
    pub const LABEL: &'static str = labels::LIVE_VIDEO_SEGMENT;
}

impl AssertionBase for LiveVideoSegment {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

impl AssertionCbor for LiveVideoSegment {}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn make_base_segment() -> LiveVideoSegment {
        LiveVideoSegment {
            sequence_number: 1,
            stream_id: "urn:uuid:123e4567-e89b-12d3-a456-426614174000".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("urn:c2pa:F9168C5E-CEB2-4FAA-B6BF-329BF39FA1E4".to_string()),
            additional_fields: HashMap::new(),
        }
    }

    #[test]
    fn round_trip_with_manifest_id_continuity() {
        let segment = make_base_segment();
        let assertion = segment.to_assertion().unwrap();

        assert_eq!(assertion.label(), LiveVideoSegment::LABEL);

        let restored = LiveVideoSegment::from_assertion(&assertion).unwrap();
        assert_eq!(segment, restored);
    }

    #[test]
    fn round_trip_without_previous_manifest_id() {
        let segment = LiveVideoSegment {
            sequence_number: 0,
            stream_id: "stream-first".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let assertion = segment.to_assertion().unwrap();
        let restored = LiveVideoSegment::from_assertion(&assertion).unwrap();
        assert_eq!(segment, restored);
    }

    #[test]
    fn round_trip_unknown_continuity_method() {
        let segment = LiveVideoSegment {
            sequence_number: 5,
            stream_id: "stream-xyz".to_string(),
            continuity_method: ContinuityMethod::Unknown("vendor.customMethod".to_string()),
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let assertion = segment.to_assertion().unwrap();
        let restored = LiveVideoSegment::from_assertion(&assertion).unwrap();
        assert_eq!(segment, restored);
    }

    /// Regression test: per §19.7.2, a `c2pa.livevideo.segment` assertion missing the
    /// `continuityMethod` field must still deserialize (so validation can report the
    /// spec-mandated `livevideo.continuityMethod.invalid` failure) rather than fail parsing
    /// outright and surface a generic/misleading error further up the call stack.
    #[test]
    fn missing_continuity_method_deserializes_to_missing_sentinel() {
        use std::collections::BTreeMap;

        let mut map = BTreeMap::new();
        map.insert(
            c2pa_cbor::Value::Text("sequenceNumber".to_string()),
            c2pa_cbor::Value::Integer(1),
        );
        map.insert(
            c2pa_cbor::Value::Text("streamId".to_string()),
            c2pa_cbor::Value::Text("stream-1".to_string()),
        );
        // continuityMethod intentionally omitted.

        let bytes = c2pa_cbor::to_vec(&c2pa_cbor::Value::Map(map)).unwrap();
        let segment: LiveVideoSegment = c2pa_cbor::from_slice(&bytes).unwrap();

        assert_eq!(
            segment.continuity_method,
            ContinuityMethod::Unknown(String::new())
        );
    }

    #[test]
    fn label_matches_spec() {
        assert_eq!(LiveVideoSegment::LABEL, "c2pa.livevideo.segment");
    }
}
