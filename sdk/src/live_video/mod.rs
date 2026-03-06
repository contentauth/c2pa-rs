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

//! Support for C2PA Live Video validation (section 19 of the C2PA Technical Specification).
//!
//! Implements the per-segment C2PA Manifest Box method (section 19.3), where each segment
//! carries its own C2PA Manifest with a [`LiveVideoSegment`] assertion for continuity tracking.
//!
//! See [C2PA Technical Specification — Live Video](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_live_video).

use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::{
    assertions::{ContinuityMethod, LiveVideoSegment},
    error::{Error, Result},
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_ASSERTION_INVALID, LIVEVIDEO_CONTINUITY_METHOD_INVALID,
        LIVEVIDEO_INIT_INVALID, LIVEVIDEO_SEGMENT_INVALID,
    },
};

/// FourCC byte value for an ISO BMFF `mdat` (Media Data) box.
const MDAT_BOX_TYPE: u32 = 0x6d646174;

/// FourCC byte value for an ISO BMFF `uuid` (User Data) box.
const UUID_BOX_TYPE: u32 = 0x75756964;

/// FourCC byte value for an ISO BMFF `emsg` (Event Message) box.
const EMSG_BOX_TYPE: u32 = 0x656d7367;

/// C2PA UUID identifying a `uuid` box that contains a C2PA Manifest Store.
///
/// See [C2PA Technical Specification section A.5.1](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_the_uuid_box_for_c2pa).
const C2PA_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c,
    0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

/// Snapshot of the validated state from the most recently accepted segment.
///
/// Used to enforce cross-segment continuity rules ([section 19.7.2](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_live_video_validation_process)).
struct SegmentState {
    sequence_number: u64,
    stream_id: String,
    manifest_id: String,
}

/// Validates a sequence of live video segments against the C2PA section 19 rules.
///
/// Create one instance per live stream and call [`validate_init_segment`] followed by
/// [`validate_media_segment`] for each subsequent segment, in order.
///
/// [`validate_init_segment`]: LiveVideoValidator::validate_init_segment
/// [`validate_media_segment`]: LiveVideoValidator::validate_media_segment
pub struct LiveVideoValidator {
    previous_segment: Option<SegmentState>,
}

impl LiveVideoValidator {
    /// Creates a new validator for a live stream.
    pub fn new() -> Self {
        Self {
            previous_segment: None,
        }
    }

    /// Validates an initialization segment.
    ///
    /// Per [section 19.7.1](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_live_video_validation_process), an init segment must not contain an `mdat` box.
    pub fn validate_init_segment(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if segment_contains_box_type(segment_data, MDAT_BOX_TYPE) {
            log_item!(
                "live_video_init",
                "initialization segment must not contain an mdat box",
                "LiveVideoValidator::validate_init_segment"
            )
            .validation_status(LIVEVIDEO_INIT_INVALID)
            .failure(tracker, Error::BadParam("livevideo.init.invalid".into()))?;
        }
        Ok(())
    }

    /// Validates a media segment using the per-segment C2PA Manifest Box method (19.3 https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#using_c2pa_manifest_box).
    ///
    /// Enforces continuity rules from [section 19.7.2](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_live_video_validation_process): sequence number strictly increases,
    /// `streamId` is consistent, and `previousManifestId` matches the prior segment's manifest.
    /// On success, advances internal state so the next segment can be validated against this one.
    pub fn validate_media_segment(
        &mut self,
        segment_data: &[u8],
        manifest_id: &str,
        assertion: &LiveVideoSegment,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.validate_segment_has_c2pa_or_emsg(segment_data, tracker)?;
        self.validate_continuity_rules(assertion, manifest_id, tracker)?;

        if let Some(previous) = &self.previous_segment {
            self.validate_sequence_number(assertion, previous, tracker)?;
            self.validate_stream_id(assertion, previous, tracker)?;
        }

        self.previous_segment = Some(SegmentState {
            sequence_number: assertion.sequence_number,
            stream_id: assertion.stream_id.clone(),
            manifest_id: manifest_id.to_string(),
        });

        Ok(())
    }

    fn validate_segment_has_c2pa_or_emsg(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let has_c2pa_manifest_box = segment_contains_c2pa_uuid_box(segment_data);
        let has_emsg_box = segment_contains_box_type(segment_data, EMSG_BOX_TYPE);

        if !has_c2pa_manifest_box && !has_emsg_box {
            log_item!(
                "live_video_segment",
                "segment must contain a C2PA Manifest Box (uuid) or an emsg box",
                "LiveVideoValidator::validate_media_segment"
            )
            .validation_status(LIVEVIDEO_SEGMENT_INVALID)
            .failure(
                tracker,
                Error::BadParam("livevideo.segment.invalid".into()),
            )?;
        }
        Ok(())
    }

    fn validate_sequence_number(
        &self,
        assertion: &LiveVideoSegment,
        previous: &SegmentState,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if assertion.sequence_number <= previous.sequence_number {
            log_item!(
                "live_video_segment",
                "sequenceNumber must be strictly greater than the previous segment's",
                "LiveVideoValidator::validate_media_segment"
            )
            .validation_status(LIVEVIDEO_ASSERTION_INVALID)
            .failure(
                tracker,
                Error::BadParam("livevideo.assertion.invalid".into()),
            )?;
        }
        Ok(())
    }

    fn validate_stream_id(
        &self,
        assertion: &LiveVideoSegment,
        previous: &SegmentState,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if assertion.stream_id != previous.stream_id {
            log_item!(
                "live_video_segment",
                "streamId must match the previous segment's streamId",
                "LiveVideoValidator::validate_media_segment"
            )
            .validation_status(LIVEVIDEO_ASSERTION_INVALID)
            .failure(
                tracker,
                Error::BadParam("livevideo.assertion.invalid".into()),
            )?;
        }
        Ok(())
    }

    fn validate_continuity_rules(
        &self,
        assertion: &LiveVideoSegment,
        manifest_id: &str,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        match &assertion.continuity_method {
            ContinuityMethod::ManifestId => {
                self.validate_manifest_id_continuity(assertion, manifest_id, tracker)
            }
            ContinuityMethod::Unknown(method) => {
                log_item!(
                    "live_video_segment",
                    format!("unsupported continuity method: {method}"),
                    "LiveVideoValidator::validate_continuity_rules"
                )
                .validation_status(LIVEVIDEO_CONTINUITY_METHOD_INVALID)
                .failure(
                    tracker,
                    Error::BadParam("livevideo.continuityMethod.invalid".into()),
                )?;
                Ok(())
            }
        }
    }

    fn validate_manifest_id_continuity(
        &self,
        assertion: &LiveVideoSegment,
        _current_manifest_id: &str,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let Some(previous) = &self.previous_segment else {
            // No previously validated segment: this is the first segment the validator
            // has seen. previousManifestId cannot be checked against a prior segment,
            // so we skip the continuity check.
            return Ok(());
        };

        let previous_manifest_id = match &assertion.previous_manifest_id {
            Some(id) => id,
            None => {
                log_item!(
                    "live_video_segment",
                    "previousManifestId is required when continuityMethod is c2pa.manifestId",
                    "LiveVideoValidator::validate_manifest_id_continuity"
                )
                .validation_status(LIVEVIDEO_CONTINUITY_METHOD_INVALID)
                .failure(
                    tracker,
                    Error::BadParam("livevideo.continuityMethod.invalid".into()),
                )?;
                return Ok(());
            }
        };

        if previous_manifest_id != &previous.manifest_id {
            log_item!(
                "live_video_segment",
                "previousManifestId does not match the previous segment's manifest identifier",
                "LiveVideoValidator::validate_manifest_id_continuity"
            )
            .validation_status(LIVEVIDEO_SEGMENT_INVALID)
            .failure(
                tracker,
                Error::BadParam("livevideo.segment.invalid".into()),
            )?;
        }
        Ok(())
    }
}

impl Default for LiveVideoValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` if the BMFF data contains a top-level box with the given FourCC type.
fn segment_contains_box_type(data: &[u8], target_type: u32) -> bool {
    let mut cursor = Cursor::new(data);
    loop {
        let box_start = cursor.stream_position().unwrap_or(0);
        match read_box_header(&mut cursor) {
            Ok((box_type, box_size)) => {
                if box_type == target_type {
                    return true;
                }
                // box_size is the total size from the start of the box header.
                let next = box_start + box_size;
                if cursor.seek(SeekFrom::Start(next)).is_err() {
                    break;
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
                // box_size is the total size from the start of the box header.
                let next = box_start + box_size;
                if cursor.seek(SeekFrom::Start(next)).is_err() {
                    break;
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
    reader.read_exact(&mut header).map_err(|_| Error::NotFound)?;

    let size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let box_type = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);

    let total_size = if size == 1 {
        // Extended (64-bit) size field follows the 8-byte header.
        let mut large_size_bytes = [0u8; 8];
        reader
            .read_exact(&mut large_size_bytes)
            .map_err(|_| Error::NotFound)?;
        u64::from_be_bytes(large_size_bytes)
    } else if size == 0 {
        // Size == 0 means "extends to end of stream"; treat as very large.
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

    use super::*;
    use crate::{
        assertions::{ContinuityMethod, LiveVideoSegment},
        status_tracker::StatusTracker,
    };

    fn make_segment(sequence_number: u64, stream_id: &str) -> LiveVideoSegment {
        LiveVideoSegment {
            sequence_number,
            stream_id: stream_id.to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("urn:c2pa:prev-manifest".to_string()),
            additional_fields: HashMap::new(),
        }
    }

    fn make_uuid_box(include_c2pa_uuid: bool) -> Vec<u8> {
        let mut data = Vec::new();
        // size: 8 header + 16 uuid = 24
        let size: u32 = 24;
        data.extend_from_slice(&size.to_be_bytes());
        data.extend_from_slice(b"uuid");
        if include_c2pa_uuid {
            data.extend_from_slice(&C2PA_UUID);
        } else {
            data.extend_from_slice(&[0u8; 16]);
        }
        data
    }

    fn make_mdat_box() -> Vec<u8> {
        let mut data = Vec::new();
        let size: u32 = 8;
        data.extend_from_slice(&size.to_be_bytes());
        data.extend_from_slice(b"mdat");
        data
    }

    fn make_emsg_box() -> Vec<u8> {
        let mut data = Vec::new();
        let size: u32 = 8;
        data.extend_from_slice(&size.to_be_bytes());
        data.extend_from_slice(b"emsg");
        data
    }

    fn aggregate_tracker() -> StatusTracker {
        StatusTracker::default()
    }

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

        let has_init_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_INIT_INVALID)
        });
        assert!(has_init_invalid);
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

        let has_segment_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        });
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
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 4, // regressed!
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-1".to_string()),
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_assertion_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID)
        });
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
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-B".to_string(), // different!
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-1".to_string()),
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_assertion_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID)
        });
        assert!(has_assertion_invalid);
    }

    #[test]
    fn missing_previous_manifest_id_fails_with_continuity_method_invalid() {
        let mut validator = LiveVideoValidator::new();
        let segment_data = make_uuid_box(true);
        let mut tracker = aggregate_tracker();

        // Advance state to segment 1
        let first = LiveVideoSegment {
            sequence_number: 1,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None,
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        // Segment 2 missing previousManifestId
        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: None, // missing!
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_continuity_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_CONTINUITY_METHOD_INVALID)
        });
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
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-1", &first, &mut tracker);

        let second = LiveVideoSegment {
            sequence_number: 2,
            stream_id: "stream-1".to_string(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: Some("manifest-WRONG".to_string()), // incorrect!
            additional_fields: HashMap::new(),
        };
        let _ =
            validator.validate_media_segment(&segment_data, "manifest-2", &second, &mut tracker);

        let has_segment_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        });
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
        let _ = validator.validate_media_segment(
            &segment_data,
            "manifest-1",
            &assertion,
            &mut tracker,
        );

        let has_continuity_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_CONTINUITY_METHOD_INVALID)
        });
        assert!(has_continuity_invalid);
    }

    #[test]
    fn emsg_box_satisfies_presence_check() {
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
        // Should NOT produce livevideo.segment.invalid for missing C2PA box
        let _ = validator.validate_media_segment(
            &segment_data,
            "manifest-1",
            &assertion,
            &mut tracker,
        );

        let has_segment_invalid = tracker.logged_items().iter().any(|i| {
            i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
        });
        assert!(!has_segment_invalid);
    }
}
