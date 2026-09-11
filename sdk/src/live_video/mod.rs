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

//! Support for C2PA Live Video signing and validation (section 19 of the C2PA Technical Specification).
//!
//! Implements two validation methods:
//!
//! - **Section 19.3** (per-segment C2PA Manifest Box): each segment carries its own C2PA
//!   Manifest with a [`LiveVideoSegment`] assertion. Use [`LiveVideoValidator::validate_media_segment`].
//!
//! - **Section 19.4** (Verifiable Segment Info): the init segment manifest contains a
//!   [`crate::assertions::SessionKeys`] assertion; each media segment carries a COSE_Sign1 in
//!   an `emsg` box. Use [`LiveVideoValidator::validate_session_keys`] and
//!   [`LiveVideoValidator::validate_verifiable_segment_info`].
//!
//! # Signing
//!
//! Use [`LiveVideoSigner`] to sign an init segment and a sequence of media segments.
//!
//! # Validation
//!
//! Use [`LiveVideoValidator`] to validate a signed live video stream.
//!
//! See [C2PA Technical Specification - Live Video](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#live-video).
//!
//! # Experimental
//!
//! This module is gated behind the `unstable_live_video` crate feature and exempt from the
//! crate's usual semver stability guarantees. See
//! [`docs/experimental-features.md`](https://github.com/contentauth/c2pa-rs/blob/main/docs/experimental-features.md).

mod box_walk;
pub(crate) mod cose_key;
mod segment_manifest_validation;
mod session_key_validation;
mod signing;
pub(crate) mod verifiable_segment_info;
mod vsi_signing;

/// Ed25519 signing key type used for VSI session keys ([§19.4]/[§18.25]), re-exported from
/// `ed25519-dalek` for callers constructing a [`LiveVideoVsiSigner`].
///
/// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
/// [§18.25]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_session_keys
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release. Being a
/// re-export of an external crate's type, it also tracks that crate's own version and API.
///
/// </div>
pub use ed25519_dalek::SigningKey as Ed25519SessionKey;
pub use signing::LiveVideoSigner;
pub use vsi_signing::{moof_sequence_number, LiveVideoVsiSigner};

use self::cose_key::kid_from_cose_key;
use crate::{
    assertions::{LiveVideoSegment, SessionKey, SessionKeys},
    error::{Error, Result},
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_INIT_INVALID, LIVEVIDEO_MANIFEST_INVALID, LIVEVIDEO_SEGMENT_INVALID,
        LIVEVIDEO_SESSIONKEY_INVALID,
    },
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
/// Supports section [19.3] (per-segment C2PA Manifest Box) and section [19.4] (Verifiable
/// Segment Info). Create one instance per live stream; for 19.4 call
/// [`validate_session_keys`] after [`validate_init_segment`].
///
/// [19.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#using_c2pa_manifest_box
/// [19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
/// [`validate_session_keys`]: LiveVideoValidator::validate_session_keys
/// [`validate_init_segment`]: LiveVideoValidator::validate_init_segment
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
pub struct LiveVideoValidator {
    previous_segment: Option<SegmentState>,
    session_keys: Vec<SessionKey>,
    /// The manifest identifier (c2pa URN label) of the trusted manifest that carried the
    /// `c2pa.session-keys` assertion, captured by [`validate_session_keys`]. Every VSI
    /// segment's `manifestId` is checked against this (§19.4.4).
    ///
    /// [`validate_session_keys`]: LiveVideoValidator::validate_session_keys
    expected_manifest_id: Option<String>,
}

impl LiveVideoValidator {
    pub fn new() -> Self {
        Self {
            previous_segment: None,
            session_keys: Vec::new(),
            expected_manifest_id: None,
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

    /// Records a segment-level validation failure ([§19.7.1]).
    ///
    /// Use this when the segment itself cannot be shown to satisfy §19.7, as opposed to a
    /// manifest that was read and failed to validate: a segment that cannot be read carries
    /// neither a C2PA Manifest Box nor a qualifying `emsg`, which §19.7.1 assigns
    /// `livevideo.segment.invalid`.
    ///
    /// [§19.7.1]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_live_video_validation_process
    pub fn fail_segment_invalid(
        &self,
        description: impl Into<String>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        fail_validation(description, LIVEVIDEO_SEGMENT_INVALID, tracker)
    }

    /// Records a manifest validation failure for the initialization segment ([§19.7.1]).
    ///
    /// Use this when the init segment's C2PA manifest cannot be read, has no active manifest,
    /// or fails the general validation rules of Chapter 15.
    ///
    /// Logged as `livevideo.manifest.invalid`, not `livevideo.init.invalid`: §19.7.1 reserves
    /// the latter for an init segment that contains an `mdat` box, and assigns
    /// `livevideo.manifest.invalid` to a C2PA Manifest that fails validation.
    ///
    /// [§19.7.1]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_live_video_validation_process
    pub fn fail_init_manifest(
        &self,
        description: impl Into<String>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        fail_validation(description, LIVEVIDEO_MANIFEST_INVALID, tracker)
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
        self.validate_continuity_rules(assertion, tracker)?;

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

    /// Validates a `c2pa.session-keys` assertion and stores the keys for VSI verification ([§19.4]).
    ///
    /// `ee_cert_der` must be the DER-encoded end-entity certificate of the *trusted* manifest
    /// signer that carried this assertion; each key's `signerBinding` COSE_Sign1 is verified
    /// against it ([§19.7.3]). Per §19.7.3, a key whose `signerBinding` does not verify shall
    /// not be used to validate any media segment — if `ee_cert_der` is `None` (the caller could
    /// not obtain a trusted certificate), no key in this assertion can be verified, so all keys
    /// are rejected rather than accepted unchecked.
    ///
    /// `manifest_id` is the c2pa URN label of that same trusted manifest; every subsequent VSI
    /// segment's `manifestId` is checked against it ([§19.4.4]).
    ///
    /// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
    /// [§19.4.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_manifest_retrieval_from_the_manifestid_field
    /// [§19.7.3]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_verifiable_segment_info_validation
    pub fn validate_session_keys(
        &mut self,
        assertion: &SessionKeys,
        manifest_id: &str,
        ee_cert_der: Option<&[u8]>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if assertion.keys.is_empty() {
            return fail_validation(
                "session-keys assertion must contain at least one key",
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        }

        let Some(cert) = ee_cert_der else {
            return fail_validation(
                "cannot verify session key signerBinding without the manifest signer's \
                 end-entity certificate; per §19.7.3 a key that cannot be verified shall not \
                 be used",
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        };

        let mut verified_keys = Vec::with_capacity(assertion.keys.len());
        for key in &assertion.keys {
            if kid_from_cose_key(&key.key).is_none() {
                return fail_validation(
                    "session key COSE_Key must include a kid (key identifier)",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }

            if key.validity_period == 0 {
                return fail_validation(
                    "session key validityPeriod must be greater than zero",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }

            // Per §19.7.3, a key whose signerBinding fails to verify shall not be used to
            // validate any media segment, so it must not be added to `verified_keys` below.
            if !self.verify_signer_binding(key, cert, tracker)? {
                continue;
            }

            verified_keys.push(key.clone());
        }

        self.session_keys = verified_keys;
        self.expected_manifest_id = Some(manifest_id.to_string());
        Ok(())
    }

    /// Validates a media segment using the Verifiable Segment Info method ([§19.4]).
    ///
    /// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
    pub fn validate_verifiable_segment_info(
        &mut self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.require_session_keys(tracker)?;
        let parsed = self.extract_and_parse_vsi(segment_data, tracker)?;
        let session_key = self.resolve_session_key(&parsed.sign1, tracker)?;
        let seq_num = parsed.segment_info_map.sequence_number;

        // See the comment in `validate_media_segment`: `fail_validation` logs a failure but
        // still returns `Ok(())` under the default tracker, so these `?` calls do not
        // short-circuit on failure. Snapshot the failure count so a failed segment doesn't
        // become the trusted continuity baseline for the next one.
        let failures_before = tracker.filter_errors().count();

        self.validate_vsi_manifest_id(&parsed.segment_info_map.manifest_id, tracker)?;
        self.validate_vsi_sequence_bounds(seq_num, &session_key, tracker)?;
        self.validate_vsi_key_validity(&session_key, &parsed.sign1, tracker)?;
        self.validate_vsi_signature(&parsed.sign1, &session_key, tracker)?;
        self.validate_vsi_sequence_continuity(seq_num, tracker)?;
        self.validate_vsi_bmff_hash(segment_data, &parsed.segment_info_map.bmff_hash, tracker)?;

        if tracker.filter_errors().count() > failures_before {
            return Ok(());
        }

        self.previous_segment = Some(SegmentState {
            sequence_number: seq_num,
            stream_id: String::new(),
            manifest_id: parsed.segment_info_map.manifest_id.clone(),
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
