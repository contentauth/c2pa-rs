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
mod manifest_uri;
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
pub use vsi_signing::{moof_sequence_number, LiveVideoVsiSigner, SessionSigningKey};

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

#[derive(Clone, Debug, PartialEq)]
struct TrustedSessionKey {
    key: SessionKey,
    manifest_id: String,
    manifest_state: Option<crate::ValidationState>,
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
    /// The init segment, kept to validate the hard binding of manifests retrieved through
    /// `manifestUri`.
    #[cfg(feature = "fetch_remote_manifests")]
    init_segment_data: Option<Vec<u8>>,
    previous_segment: Option<SegmentState>,
    session_keys: Vec<TrustedSessionKey>,
    session_key_manifest_state: Option<crate::ValidationState>,
    /// The track timescale (`moov/trak/mdia/mdhd`), captured by [`validate_init_segment`].
    /// Needed to turn a media segment's `tfdt` into a presentation time.
    ///
    /// [`validate_init_segment`]: LiveVideoValidator::validate_init_segment
    track_timescale: Option<u32>,
    /// Wall-clock time of media time 0, set by [`set_media_time_origin`].
    ///
    /// [`set_media_time_origin`]: LiveVideoValidator::set_media_time_origin
    media_time_origin: Option<chrono::DateTime<chrono::Utc>>,
}

impl LiveVideoValidator {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "fetch_remote_manifests")]
            init_segment_data: None,
            previous_segment: None,
            session_keys: Vec::new(),
            session_key_manifest_state: None,
            track_timescale: None,
            media_time_origin: None,
        }
    }

    /// Validates an initialization segment ([§19.7.1]), and records its track timescale for
    /// presentation-time checks of the media segments that follow. When remote fetching is
    /// enabled, also retains its bytes to validate the hard binding of manifests retrieved
    /// through `manifestUri`.
    ///
    /// [§19.7.1]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_live_video_validation_process
    pub fn validate_init_segment(
        &mut self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if segment_manifest_validation::segment_contains_box_type(segment_data, MDAT_BOX_TYPE) {
            return fail_validation(
                "initialization segment must not contain an mdat box",
                LIVEVIDEO_INIT_INVALID,
                tracker,
            );
        }
        if let Some(timescale) = vsi_signing::parse_first_mdhd_timescale(segment_data) {
            self.track_timescale = Some(timescale);
        }
        #[cfg(feature = "fetch_remote_manifests")]
        {
            self.init_segment_data = Some(segment_data.to_vec());
        }
        Ok(())
    }

    /// Sets the wall-clock time that corresponds to media time 0 of the stream, so a
    /// media segment's presentation time can be checked against its session key's validity
    /// period (C2PA 2.5, Verifiable Segment Info Validation).
    ///
    /// For DASH this is `MPD@availabilityStartTime + Period@start`, less
    /// `presentationTimeOffset / timescale`. For a stream whose `tfdt` counts from the Unix
    /// epoch (as DASH-IF livesim2 does), it's the Unix epoch.
    ///
    /// Without an origin, a segment's `prft` box is used to map its media time to wall-clock
    /// time; without either, the key's validity period is checked against the segment's
    /// claimed signing time (`iat`), or the current time.
    pub fn set_media_time_origin(&mut self, origin: chrono::DateTime<chrono::Utc>) {
        self.media_time_origin = Some(origin);
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
    /// `manifest_id` is the label of that same validated manifest. Keys remain associated
    /// with this manifest; adding keys from another manifest preserves earlier keys.
    /// Repeated announcements of the same keys are idempotent. For an update carried in a
    /// media segment, use [`Self::validate_session_key_update`] to enforce its sequence bound.
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
        let mut seen_kids = Vec::new();
        for key in &assertion.keys {
            let kid = kid_from_cose_key(&key.key);
            if kid.as_ref().is_none_or(|kid| kid.is_empty()) {
                return fail_validation(
                    "session key COSE_Key must include a kid (key identifier)",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }

            if seen_kids.contains(&kid) {
                return fail_validation(
                    "session key identifiers must be unique",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
            seen_kids.push(kid);

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

        let mut additions = Vec::new();
        for key in verified_keys {
            let known = self
                .session_keys
                .iter()
                .any(|old| old.manifest_id == manifest_id && old.key == key);
            if known {
                continue;
            }
            if self.session_keys.iter().any(|old| {
                old.manifest_id == manifest_id
                    && kid_from_cose_key(&old.key.key) == kid_from_cose_key(&key.key)
            }) || additions.iter().any(|old: &TrustedSessionKey| {
                kid_from_cose_key(&old.key.key) == kid_from_cose_key(&key.key)
            }) {
                return fail_validation(
                    "duplicate session key kid in a manifest",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
            let known_key = self.session_keys.iter().any(|old| old.key == key);
            if !known_key
                && self
                    .previous_segment
                    .as_ref()
                    .is_some_and(|previous| key.min_sequence_number <= previous.sequence_number)
            {
                return fail_validation(
                    "new session key minSequenceNumber is below the next sequence number",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
            additions.push(TrustedSessionKey {
                key,
                manifest_id: manifest_id.to_string(),
                manifest_state: None,
            });
        }
        self.session_keys.extend(additions);
        Ok(())
    }

    /// Validates a manifest containing additional session keys for the current segment.
    /// The caller must first validate the manifest and supply its signing certificate.
    /// Earlier keys remain available for overlapping rotation windows.
    pub fn validate_session_key_update(
        &mut self,
        assertion: &SessionKeys,
        manifest_id: &str,
        ee_cert_der: Option<&[u8]>,
        current_sequence_number: u64,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        for key in &assertion.keys {
            let known = self.session_keys.iter().any(|old| &old.key == key);
            if !known && key.min_sequence_number < current_sequence_number {
                return fail_validation(
                    "new session key minSequenceNumber is below the current sequence number",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
            }
        }
        self.validate_session_keys(assertion, manifest_id, ee_cert_der, tracker)
    }

    /// Loads verified session keys directly from a reader's native CBOR assertion.
    /// The caller must apply its manifest trust policy to this reader first. JSON-facing
    /// manifest APIs do not preserve the CBOR tags required by `signerBinding`.
    /// Set `current_sequence_number` for a manifest announced in a media segment.
    pub fn validate_session_keys_from_reader(
        &mut self,
        reader: &crate::Reader,
        current_sequence_number: Option<u64>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        use crate::assertion::AssertionBase;
        if reader.validation_state() == crate::ValidationState::Invalid {
            return fail_validation(
                "session-key manifest failed validation",
                LIVEVIDEO_MANIFEST_INVALID,
                tracker,
            );
        }
        let Some(manifest_id) = reader
            .active_manifest()
            .and_then(|manifest| manifest.label())
        else {
            return fail_validation(
                "session-key manifest has no active manifest",
                LIVEVIDEO_MANIFEST_INVALID,
                tracker,
            );
        };
        let claim = reader.store.get_claim(manifest_id).ok_or(Error::NotFound)?;
        if claim
            .claim_assertion_store()
            .iter()
            .filter(|assertion| assertion.label_raw() == SessionKeys::LABEL)
            .count()
            != 1
        {
            return fail_validation(
                "manifest must contain exactly one session-keys assertion",
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        }
        let Some(assertion) = claim.get_assertion(SessionKeys::LABEL, 0) else {
            return fail_validation(
                "manifest has no session-keys assertion",
                LIVEVIDEO_SESSIONKEY_INVALID,
                tracker,
            );
        };
        let keys = match SessionKeys::from_assertion(assertion) {
            Ok(keys) => keys,
            Err(_) => {
                return fail_validation(
                    "invalid session-keys assertion",
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                )
            }
        };
        let certs = claim
            .cose_sign1()
            .ok()
            .and_then(|sign1| crate::crypto::cose::cert_chain_from_sign1(&sign1).ok());
        let cert = certs
            .as_ref()
            .and_then(|certs| certs.first())
            .map(Vec::as_slice);
        let failures_before = tracker.filter_errors().count();
        match current_sequence_number {
            Some(sequence) => {
                self.validate_session_key_update(&keys, manifest_id, cert, sequence, tracker)?
            }
            None => self.validate_session_keys(&keys, manifest_id, cert, tracker)?,
        }
        if tracker.filter_errors().count() == failures_before {
            for entry in &mut self.session_keys {
                if entry.manifest_id == manifest_id {
                    entry.manifest_state = Some(reader.validation_state());
                }
            }
        }
        Ok(())
    }

    fn read_segment_session_keys(
        &mut self,
        segment_data: &[u8],
        manifest_id: &str,
        sequence_number: u64,
        context: &std::sync::Arc<crate::Context>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.session_key_manifest_state = None;
        let contains_manifest = box_walk::top_level_boxes(segment_data).any(|(kind, bytes)| {
            kind == b"uuid"
                && box_walk::box_payload(bytes)
                    .is_some_and(|payload| payload.starts_with(&C2PA_UUID))
        });
        if !contains_manifest {
            return Ok(());
        }
        let reader = match crate::Reader::from_shared_context(context)
            .with_stream("video/mp4", std::io::Cursor::new(segment_data))
        {
            Ok(reader) if reader.validation_state() != crate::ValidationState::Invalid => reader,
            Ok(reader) => {
                return fail_validation(
                    format!(
                        "embedded session-key manifest failed validation: {:?}",
                        reader.validation_status()
                    ),
                    LIVEVIDEO_MANIFEST_INVALID,
                    tracker,
                )
            }
            Err(error) => {
                return fail_validation(
                    format!("embedded session-key manifest could not be read: {error}"),
                    LIVEVIDEO_MANIFEST_INVALID,
                    tracker,
                )
            }
        };
        let trust_configured = matches!(context.settings().get_value::<Option<Vec<crate::settings::TrustAnchor>>>("trust.anchors"),
            Ok(Some(anchors)) if !anchors.is_empty());
        if trust_configured
            && context.settings().verify.verify_trust
            && reader.validation_state() != crate::ValidationState::Trusted
        {
            return fail_validation(
                "embedded session-key manifest signer is not trusted",
                LIVEVIDEO_MANIFEST_INVALID,
                tracker,
            );
        }
        self.session_key_manifest_state = Some(reader.validation_state());
        let Some(manifest) = reader.active_manifest() else {
            return fail_validation(
                "embedded session-key manifest has no active manifest",
                LIVEVIDEO_MANIFEST_INVALID,
                tracker,
            );
        };
        if manifest.label() != Some(manifest_id) {
            return fail_validation(
                "embedded manifest identifier does not match VSI manifestId",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        self.validate_session_keys_from_reader(&reader, Some(sequence_number), tracker)
    }

    /// Validates a media segment using the Verifiable Segment Info method ([§19.4]).
    ///
    /// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
    pub fn validate_verifiable_segment_info(
        &mut self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        self.validate_verifiable_segment_info_with_context(
            segment_data,
            &std::sync::Arc::new(context_from_thread_local_settings()?),
            tracker,
        )
    }

    /// Validation state of the manifest authorizing the last resolved VSI session key.
    pub fn session_key_manifest_state(&self) -> Option<crate::ValidationState> {
        self.session_key_manifest_state
    }

    /// Validates VSI and embedded key updates using the caller's trust and I/O settings.
    /// An unknown key may be retrieved through `manifestUri` when remote fetching is enabled;
    /// call [`Self::validate_init_segment`] first to allow init-bound remote manifests.
    pub fn validate_verifiable_segment_info_with_context(
        &mut self,
        segment_data: &[u8],
        context: &std::sync::Arc<crate::Context>,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        let failures_before = tracker.filter_errors().count();
        let parsed = self.extract_and_parse_vsi(segment_data, tracker)?;
        self.read_segment_session_keys(
            segment_data,
            &parsed.segment_info_map.manifest_id,
            parsed.segment_info_map.sequence_number,
            context,
            tracker,
        )?;
        if tracker.filter_errors().count() > failures_before {
            return Ok(());
        }
        // With no embedded manifest, an unknown key may be retrieved through `manifestUri`.
        self.resolve_manifest_uri(segment_data, &parsed, context, tracker)?;
        if tracker.filter_errors().count() > failures_before {
            return Ok(());
        }
        self.require_session_keys(tracker)?;
        let session_key =
            self.resolve_session_key(&parsed.sign1, &parsed.segment_info_map.manifest_id, tracker)?;
        self.session_key_manifest_state = self
            .session_keys
            .iter()
            .find(|entry| entry.manifest_id == parsed.segment_info_map.manifest_id)
            .and_then(|entry| entry.manifest_state);
        let seq_num = parsed.segment_info_map.sequence_number;

        // See the comment in `validate_media_segment`: `fail_validation` logs a failure but
        // still returns `Ok(())` under the default tracker, so these `?` calls do not
        // short-circuit on failure. Snapshot the failure count so a failed segment doesn't
        // become the trusted continuity baseline for the next one.
        let failures_before = tracker.filter_errors().count();

        self.validate_vsi_emsg_timing(segment_data, tracker)?;
        self.validate_vsi_sequence_bounds(seq_num, &session_key, tracker)?;
        self.validate_vsi_key_validity(&session_key, &parsed.sign1, segment_data, tracker)?;
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
