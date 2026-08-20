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
//! Implements the per-segment C2PA Manifest Box method ([Section 19.3]): each segment
//! carries its own C2PA Manifest with a [`LiveVideoSegment`] assertion. Use
//! [`LiveVideoValidator::validate_media_segment`].
//!
//! [Section 19.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box
//!
//! # Validation
//!
//! Use [`LiveVideoValidator`] to validate a signed live video stream.
//!
//! See [C2PA Technical Specification - Live Video](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#live-video).

mod segment_manifest_validation;
pub mod verifiable_segment_info;

use crate::{
    assertions::LiveVideoSegment,
    error::{Error, Result},
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{LIVEVIDEO_INIT_INVALID, LIVEVIDEO_MANIFEST_INVALID},
};

/// Builds a [`crate::Context`] from thread-local settings, for callers ([`LiveVideoSigner`],
/// [`LiveVideoVsiSigner`]) that don't yet take an explicit `Context`.
pub(super) fn context_from_thread_local_settings() -> Result<crate::Context> {
    let settings = crate::settings::get_thread_local_settings();
    crate::Context::new().with_settings(settings)
}

/// C2PA UUID identifying a `uuid` box that contains a C2PA Manifest Store.
const C2PA_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

const MDAT_BOX_TYPE: u32 = 0x6d646174;
const UUID_BOX_TYPE: u32 = 0x75756964;

fn fail_validation(
    description: impl Into<String>,
    status_code: &'static str,
    tracker: &mut StatusTracker,
) -> Result<()> {
    let description: String = description.into();
    log_item!("live_video", description, "LiveVideoValidator")
        .validation_status(status_code)
        .failure(tracker, Error::BadParam(status_code.into()))?;
    Ok(())
}

struct SegmentState {
    sequence_number: u64,
    stream_id: String,
    manifest_id: String,
}

/// Validates a sequence of live video segments against C2PA section 19 rules.
///
/// Supports section [19.3] (per-segment C2PA Manifest Box). Create one instance per live
/// stream.
///
/// [19.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box
pub struct LiveVideoValidator {
    previous_segment: Option<SegmentState>,
}

impl LiveVideoValidator {
    pub fn new() -> Self {
        Self {
            previous_segment: None,
        }
    }

    /// Validates an initialization segment ([§19.7.1]).
    ///
    /// [§19.7.1]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_live_video_validation_process
    pub fn validate_init_segment(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if segment_manifest_validation::segment_contains_box_type(segment_data, MDAT_BOX_TYPE) {
            fail_validation(
                "initialization segment must not contain an mdat box",
                LIVEVIDEO_INIT_INVALID,
                tracker,
            )?;
        }
        Ok(())
    }

    /// Records a manifest-level validation failure for a segment ([§19.3]).
    ///
    /// Use this when the segment's C2PA manifest cannot be read or has no active manifest.
    ///
    /// [§19.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box
    pub fn fail_segment_manifest(
        &self,
        description: impl Into<String>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        fail_validation(description, LIVEVIDEO_MANIFEST_INVALID, tracker)
    }

    /// Records an initialization-segment-level validation failure ([§19.7.1]).
    ///
    /// Use this when the init segment's C2PA manifest cannot be read, has no active manifest,
    /// or is not cryptographically valid and trusted.
    ///
    /// [§19.7.1]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_live_video_validation_process
    pub fn fail_init_manifest(
        &self,
        description: impl Into<String>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        fail_validation(description, LIVEVIDEO_INIT_INVALID, tracker)
    }

    /// Validates a media segment using the per-segment C2PA Manifest Box method ([§19.3]).
    ///
    /// [§19.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box
    pub fn validate_media_segment(
        &mut self,
        segment_data: &[u8],
        manifest_id: &str,
        assertion: &LiveVideoSegment,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        // `fail_validation` logs failures via `StatusTracker::failure`, which under the
        // default `ErrorBehavior::ContinueWhenPossible` returns `Ok(())` even after logging
        // a real failure — so the `?` calls below do not short-circuit on a failed check.
        // Snapshot the failure count so a failed segment doesn't become the trusted
        // continuity baseline for the next one.
        let failures_before = tracker.filter_errors().count();

        self.validate_segment_has_c2pa_or_emsg(segment_data, tracker)?;
        self.validate_continuity_rules(assertion, manifest_id, tracker)?;

        if let Some(previous) = &self.previous_segment {
            self.validate_sequence_number(assertion, previous, tracker)?;
            self.validate_stream_id(assertion, previous, tracker)?;
        }

        if tracker.filter_errors().count() > failures_before {
            return Ok(());
        }

        self.previous_segment = Some(SegmentState {
            sequence_number: assertion.sequence_number,
            stream_id: assertion.stream_id.clone(),
            manifest_id: manifest_id.to_string(),
        });

        Ok(())
    }
}

impl Default for LiveVideoValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test_helpers;
