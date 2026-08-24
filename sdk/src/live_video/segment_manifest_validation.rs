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

use std::io::{Cursor, Read, Seek, SeekFrom};

use super::{fail_validation, LiveVideoValidator, SegmentState, C2PA_UUID, UUID_BOX_TYPE};
use crate::{
    assertions::{ContinuityMethod, LiveVideoSegment},
    error::{Error, Result},
    live_video::verifiable_segment_info::extract_vsi_payload_from_segment,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_ASSERTION_INVALID, LIVEVIDEO_CONTINUITY_METHOD_INVALID, LIVEVIDEO_SEGMENT_INVALID,
    },
};

impl LiveVideoValidator {
    pub(super) fn validate_segment_has_c2pa_or_emsg(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let has_c2pa_manifest_box = segment_contains_c2pa_uuid_box(segment_data);
        // Per §19.7.1, an emsg box only satisfies this check if it meets the VSI
        // requirements of §19.4.2 (scheme_id_uri = urn:c2pa:verifiable-segment-info,
        // value = fseg) — an unrelated emsg (e.g. SCTE-35 ad cues) does not count.
        let has_vsi_emsg_box = extract_vsi_payload_from_segment(segment_data).is_some();

        if !has_c2pa_manifest_box && !has_vsi_emsg_box {
            fail_validation(
                "segment must contain a C2PA Manifest Box (uuid) or a conformant VSI emsg box",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }

    pub(super) fn validate_sequence_number(
        &self,
        assertion: &LiveVideoSegment,
        previous: &SegmentState,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if assertion.sequence_number <= previous.sequence_number {
            fail_validation(
                "sequenceNumber must be strictly greater than the previous segment's",
                LIVEVIDEO_ASSERTION_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }

    pub(super) fn validate_stream_id(
        &self,
        assertion: &LiveVideoSegment,
        previous: &SegmentState,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if assertion.stream_id != previous.stream_id {
            fail_validation(
                "streamId must match the previous segment's streamId",
                LIVEVIDEO_ASSERTION_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }

    pub(super) fn validate_continuity_rules(
        &self,
        assertion: &LiveVideoSegment,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        match &assertion.continuity_method {
            ContinuityMethod::ManifestId => {
                self.validate_manifest_id_continuity(assertion, tracker)
            }
            // Per §19.7.2, a missing `continuityMethod` field (deserialized to the empty-string
            // sentinel, see `ContinuityMethod::missing`) and an unrecognized value both fail
            // with the same code, so no separate branch is needed for the missing case.
            ContinuityMethod::Unknown(method) => fail_validation(
                format!("unsupported continuity method: {method}"),
                LIVEVIDEO_CONTINUITY_METHOD_INVALID,
                tracker,
            ),
        }
    }

    fn validate_manifest_id_continuity(
        &self,
        assertion: &LiveVideoSegment,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let Some(previous) = &self.previous_segment else {
            return Ok(());
        };

        let previous_manifest_id = match &assertion.previous_manifest_id {
            Some(id) => id,
            None => {
                return fail_validation(
                    "previousManifestId is required when continuityMethod is c2pa.manifestId",
                    LIVEVIDEO_CONTINUITY_METHOD_INVALID,
                    tracker,
                );
            }
        };

        if previous_manifest_id != &previous.manifest_id {
            fail_validation(
                "previousManifestId does not match the previous segment's manifest identifier",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }
}

/// Returns the offset of the box following the one starting at `box_start` with the given
/// declared `box_size`, or `None` if the box extends to (or past) the end of `data` — a
/// `box_size` of `u64::MAX` (the "extends to EOF" sentinel from a declared size of 0) always
/// takes this path, as would any size large enough to overflow `box_start + box_size`.
fn next_box_offset(box_start: u64, box_size: u64, data_len: u64) -> Option<u64> {
    match box_start.checked_add(box_size) {
        Some(next) if next <= data_len => Some(next),
        _ => None,
    }
}

/// Returns `true` if the BMFF data contains a top-level box with the given FourCC type.
pub(super) fn segment_contains_box_type(data: &[u8], target_type: u32) -> bool {
    let mut cursor = Cursor::new(data);
    loop {
        let box_start = cursor.stream_position().unwrap_or(0);
        match read_box_header(&mut cursor) {
            Ok((box_type, box_size)) => {
                if box_type == target_type {
                    return true;
                }
                match next_box_offset(box_start, box_size, data.len() as u64) {
                    Some(next) if cursor.seek(SeekFrom::Start(next)).is_ok() => {}
                    _ => break,
                }
            }
            Err(_) => break,
        }
    }
    false
}

/// Returns `true` if the BMFF data contains a `uuid` box with the C2PA Manifest Store UUID.
fn segment_contains_c2pa_uuid_box(data: &[u8]) -> bool {
    let mut cursor = Cursor::new(data);
    loop {
        let box_start = cursor.stream_position().unwrap_or(0);
        match read_box_header(&mut cursor) {
            Ok((box_type, box_size)) => {
                if box_type == UUID_BOX_TYPE {
                    let mut uuid_bytes = [0u8; 16];
                    if cursor.read_exact(&mut uuid_bytes).is_ok() && uuid_bytes == C2PA_UUID {
                        return true;
                    }
                }
                match next_box_offset(box_start, box_size, data.len() as u64) {
                    Some(next) if cursor.seek(SeekFrom::Start(next)).is_ok() => {}
                    _ => break,
                }
            }
            Err(_) => break,
        }
    }
    false
}

/// Reads a single ISO BMFF box header and returns `(fourcc, total_box_size_in_bytes)`.
fn read_box_header<R: Read + Seek>(reader: &mut R) -> Result<(u32, u64)> {
    let mut header = [0u8; 8];
    reader
        .read_exact(&mut header)
        .map_err(|_| Error::NotFound)?;

    let size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let box_type = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

    let total_size = if size == 1 {
        let mut large_size_bytes = [0u8; 8];
        reader
            .read_exact(&mut large_size_bytes)
            .map_err(|_| Error::NotFound)?;
        u64::from_be_bytes(large_size_bytes)
    } else if size == 0 {
        u64::MAX
    } else {
        size as u64
    };

    Ok((box_type, total_size))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::collections::HashMap;

    use super::super::{test_helpers::*, LiveVideoValidator};
    use crate::{
        assertions::{ContinuityMethod, LiveVideoSegment},
        validation_results::validation_codes::{
            LIVEVIDEO_ASSERTION_INVALID, LIVEVIDEO_CONTINUITY_METHOD_INVALID,
            LIVEVIDEO_INIT_INVALID, LIVEVIDEO_MANIFEST_INVALID, LIVEVIDEO_SEGMENT_INVALID,
        },
    };

    #[test]
    fn init_segment_without_mdat_is_valid() {
        let validator = LiveVideoValidator::new();
        let segment = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        validator
            .validate_init_segment(&segment, &mut tracker)
            .unwrap();

        let failures: Vec<_> = tracker
            .logged_items()
            .iter()
            .filter(|i| {
                i.validation_status
                    .as_deref()
                    .map(|s| s.starts_with("livevideo"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(failures.is_empty());
    }

    #[test]
    fn init_segment_with_mdat_fails() {
        let validator = LiveVideoValidator::new();
        let mut segment = make_uuid_box(true);
        segment.extend(make_mdat_box());
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_init_segment(&segment, &mut tracker);

        let has_init_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_INIT_INVALID));
        assert!(has_init_invalid);
    }

    #[test]
    fn fail_segment_manifest_records_manifest_invalid() {
        let validator = LiveVideoValidator::new();
        let mut tracker = aggregate_tracker();

        let _ = validator.fail_segment_manifest("no active manifest in segment", &mut tracker);

        let has_manifest_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_MANIFEST_INVALID));
        assert!(has_manifest_invalid);
    }

    #[test]
    fn media_segment_without_c2pa_or_emsg_fails() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_mdat_box();
        let assertion = make_segment(1, "stream-1");
        let mut tracker = aggregate_tracker();

        let _ = validator.validate_media_segment(
            &segment_data,
            "urn:c2pa:manifest-1",
            &assertion,
            &mut tracker,
        );

        let has_segment_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID));
        assert!(has_segment_invalid);
    }

    #[test]
    fn valid_sequence_advances_state() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        validator
            .validate_media_segment(&segment_data, "urn:c2pa:manifest-1", &first, &mut tracker)
            .unwrap();

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("urn:c2pa:manifest-1".to_string()),
            additional_fields: HashMap::new(),
        };
        validator
            .validate_media_segment(&segment_data, "urn:c2pa:manifest-2", &second, &mut tracker)
            .unwrap();

        let live_failures: Vec<_> = tracker
            .logged_items()
            .iter()
            .filter(|i| {
                i.validation_status
                    .as_deref()
                    .map(|s| s.starts_with("livevideo"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(live_failures.is_empty());
    }

    #[test]
    fn regressed_sequence_number_fails() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 5,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ = validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 4, // regressed!
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-1".to_string()),
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_assertion_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID));
        assert!(has_assertion_invalid);
    }

    #[test]
    fn mismatched_stream_id_fails() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-A".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ = validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-B".to_string(), // different!
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-1".to_string()),
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_assertion_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID));
        assert!(has_assertion_invalid);
    }

    #[test]
    fn missing_previous_manifest_id_fails_with_continuity_method_invalid() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ = validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None, // missing!
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_continuity_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_CONTINUITY_METHOD_INVALID));
        assert!(has_continuity_invalid);
    }

    #[test]
    fn wrong_previous_manifest_id_fails_with_segment_invalid() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ = validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-WRONG".to_string()), // incorrect!
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_segment_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID));
        assert!(has_segment_invalid);
    }

    #[test]
    fn unknown_continuity_method_fails() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let assertion = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::Unknown("vendor.custom".to_string()),
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &assertion, &mut tracker);

        let has_continuity_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_CONTINUITY_METHOD_INVALID));
        assert!(has_continuity_invalid);
    }

    /// Regression test: per §19.7.2, a segment whose `continuityMethod` field is absent must
    /// fail with `livevideo.continuityMethod.invalid` — the same code as an unrecognized
    /// value — not some other/generic failure from further up the call stack.
    #[test]
    fn missing_continuity_method_fails_with_continuity_method_invalid() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        let assertion = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::Unknown(String::new()),
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &assertion, &mut tracker);

        let has_continuity_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_CONTINUITY_METHOD_INVALID));
        assert!(has_continuity_invalid);
    }

    #[test]
    fn conformant_vsi_emsg_box_satisfies_presence_check() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_vsi_conformant_emsg_box();
        let mut tracker = aggregate_tracker();

        let assertion = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &assertion, &mut tracker);

        let has_segment_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID));
        assert!(!has_segment_invalid);
    }

    /// Per §19.7.1, an emsg box only satisfies the presence check if it meets the VSI
    /// requirements of §19.4.2 — an unrelated emsg box (e.g. SCTE-35 ad cues) must not.
    #[test]
    fn non_conformant_emsg_box_does_not_satisfy_presence_check() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_emsg_box();
        let mut tracker = aggregate_tracker();

        let assertion = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &assertion, &mut tracker);

        let has_segment_invalid = tracker
            .logged_items()
            .iter()
            .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID));
        assert!(has_segment_invalid);
    }
}
