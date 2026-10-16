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

//! Offline interop with unmodified DASH-IF livesim2 v1.14.0 output, clear and encrypted.
//! Capture provenance and licenses: tests/fixtures/live_video/livesim2/README.md and
//! tests/fixtures/live_video/livesim2_eccp/README.md.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use chrono::{TimeZone, Utc};

use super::*;
use crate::{
    assertion::AssertionBase,
    live_video::{
        box_walk::{box_payload, top_level_boxes},
        verifiable_segment_info::{extract_vsi_payload_from_segment, parse_vsi},
        LiveVideoValidator,
    },
    status_tracker::StatusTracker,
    utils::ephemeral_signer::EphemeralSigner,
    validation_results::validation_codes::LIVEVIDEO_SEGMENT_INVALID,
};

const INIT: &[u8] = include_bytes!("../../tests/fixtures/live_video/livesim2/init.mp4");
const MEDIA: [&[u8]; 3] = [
    include_bytes!("../../tests/fixtures/live_video/livesim2/880000021.m4s"),
    include_bytes!("../../tests/fixtures/live_video/livesim2/880000022.m4s"),
    include_bytes!("../../tests/fixtures/live_video/livesim2/880000023.m4s"),
];
const FIRST_SEQUENCE: u64 = 880_000_021;
const FIRST_PRESENTATION_SECONDS: i64 = 1_760_000_042;
const TIMESCALE: u64 = 90_000;
const SCTE35_URI: &[u8] = b"urn:scte:scte35:2013:bin\0";

/// An encrypted capture: protection scheme, init segment and media segments.
type EccpCapture = (&'static str, &'static [u8], [&'static [u8]; 3]);

/// The same stream encrypted by livesim2's ECCP option.
const ECCP: [EccpCapture; 2] = [
    (
        "cenc",
        include_bytes!("../../tests/fixtures/live_video/livesim2_eccp/cenc/init.mp4"),
        [
            include_bytes!("../../tests/fixtures/live_video/livesim2_eccp/cenc/880000021.m4s"),
            include_bytes!("../../tests/fixtures/live_video/livesim2_eccp/cenc/880000022.m4s"),
            include_bytes!("../../tests/fixtures/live_video/livesim2_eccp/cenc/880000023.m4s"),
        ],
    ),
    (
        "cbcs",
        include_bytes!("../../tests/fixtures/live_video/livesim2_eccp/cbcs/init.mp4"),
        [
            include_bytes!("../../tests/fixtures/live_video/livesim2_eccp/cbcs/880000021.m4s"),
            include_bytes!("../../tests/fixtures/live_video/livesim2_eccp/cbcs/880000022.m4s"),
            include_bytes!("../../tests/fixtures/live_video/livesim2_eccp/cbcs/880000023.m4s"),
        ],
    ),
];

/// The signer currently reads thread-local settings. Restore the prior trust setting,
/// including when a test unwinds, so a worker thread cannot contaminate another test.
struct TrustGuard(bool);

impl TrustGuard {
    fn new() -> Self {
        let previous = crate::settings::get_thread_local_settings()
            .verify
            .verify_trust;
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();
        Self(previous)
    }
}

impl Drop for TrustGuard {
    fn drop(&mut self) {
        crate::settings::set_settings_value("verify.verify_trust", self.0).unwrap();
    }
}

struct SignedCapture {
    init: Vec<u8>,
    media: Vec<Vec<u8>>,
    context: Arc<crate::Context>,
}

impl SignedCapture {
    /// Signs the clear SCTE-35 capture.
    fn new(validity_period: u64) -> Self {
        Self::sign(INIT, &MEDIA, validity_period)
    }

    fn sign(source_init: &[u8], source_media: &[&[u8]], validity_period: u64) -> Self {
        let _trust = TrustGuard::new();
        let manifest_signer = EphemeralSigner::new("livesim2-interop.test").unwrap();
        let mut signer = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://c2pa.org/digitalsourcetype/empty"}]}}]}"#,
            &manifest_signer,
            SigningKey::from_bytes(&[0x42; 32]),
            b"livesim2-session".to_vec(),
            FIRST_SEQUENCE,
            validity_period,
        ).unwrap();
        // These are archived captures. Model the session key existing when the media was
        // presented, while signing the C2PA manifest now with a currently valid certificate.
        // This private test setup avoids adding an unrelated public createdAt override.
        signer.session_keys[0].created_at = Utc
            .timestamp_opt(FIRST_PRESENTATION_SECONDS, 0)
            .single()
            .unwrap()
            .to_rfc3339();
        let init = signer
            .sign_init_segment(source_init, "video/mp4", &manifest_signer)
            .unwrap();
        let media = source_media
            .iter()
            .map(|segment| signer.sign_media_segment(segment).unwrap())
            .collect();
        let context = Arc::new(
            crate::Context::new()
                .with_settings(
                    crate::settings::Settings::new()
                        .with_json(r#"{"verify":{"verify_trust":false}}"#)
                        .unwrap(),
                )
                .unwrap(),
        );
        Self {
            init,
            media,
            context,
        }
    }

    fn validator(&self) -> LiveVideoValidator {
        // Read the assertion and certificate actually carried in the signed init, preserving
        // native CBOR signerBinding tags rather than using the JSON-facing manifest API.
        let reader = Reader::from_shared_context(&self.context)
            .with_stream("video/mp4", std::io::Cursor::new(&self.init))
            .unwrap();
        assert_ne!(reader.validation_state(), crate::ValidationState::Invalid);
        let id = reader.active_manifest().unwrap().label().unwrap();
        let claim = reader.store.get_claim(id).unwrap();
        let keys = SessionKeys::from_assertion(claim.get_assertion(SessionKeys::LABEL, 0).unwrap())
            .unwrap();
        let certs =
            crate::crypto::cose::cert_chain_from_sign1(&claim.cose_sign1().unwrap()).unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&self.init, &mut tracker)
            .unwrap();
        validator.set_media_time_origin(chrono::DateTime::<Utc>::UNIX_EPOCH);
        validator
            .validate_session_keys(&keys, id, Some(&certs[0]), &mut tracker)
            .unwrap();
        assert_no_failures(&tracker);
        validator
    }
}

fn assert_no_failures(tracker: &StatusTracker) {
    let failures: Vec<_> = tracker.filter_errors().collect();
    assert!(
        failures.is_empty(),
        "unexpected validation failures: {failures:?}"
    );
}

fn scte35_emsg(segment: &[u8]) -> Option<&[u8]> {
    top_level_boxes(segment).find_map(|(kind, bytes)| {
        let body = box_payload(bytes)?;
        // SCTE-35 uses emsg v1: scheme_id_uri follows version/flags and 20 timing bytes.
        (kind == b"emsg" && body.first() == Some(&1) && body.get(24..)?.starts_with(SCTE35_URI))
            .then_some(bytes)
    })
}

fn assert_media_hash_failure(segment: &[u8], capture: &SignedCapture) {
    let mut validator = capture.validator();
    let mut tracker = StatusTracker::default();
    validator
        .validate_verifiable_segment_info(segment, &mut tracker)
        .unwrap();
    assert!(
        tracker
            .filter_errors()
            .any(
                |item| item.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
                    && item.description.contains("bmffHash verification failed")
            ),
        "expected media binding failure: {:?}",
        tracker.logged_items()
    );
    assert!(validator.previous_segment.is_none());
}

#[test]
fn livesim2_captured_dash_segments_round_trip_with_epoch_timing() {
    let capture = SignedCapture::new(10);
    let mut validator = capture.validator();
    let mut tracker = StatusTracker::default();
    assert_eq!(parse_first_mdhd_timescale(INIT), Some(TIMESCALE as u32));
    assert!(scte35_emsg(MEDIA[0]).is_some());
    assert!(scte35_emsg(MEDIA[1]).is_none());
    for (index, (source, signed)) in MEDIA.iter().zip(&capture.media).enumerate() {
        let expected_sequence = FIRST_SEQUENCE + index as u64;
        assert_eq!(top_level_boxes(source).next().unwrap().0, b"styp");
        assert_eq!(
            moof_sequence_number(source).map(u64::from),
            Some(expected_sequence)
        );
        let expected_ticks = (FIRST_PRESENTATION_SECONDS as u64 + 2 * index as u64) * TIMESCALE;
        assert!(expected_ticks > u64::from(u32::MAX));
        assert_eq!(parse_first_tfdt(source), Some(expected_ticks));
        assert_eq!(parse_segment_duration_ticks(source), Some(180_000));
        let vsi = parse_vsi(&extract_vsi_payload_from_segment(signed).unwrap()).unwrap();
        assert_eq!(vsi.segment_info_map.sequence_number, expected_sequence);
        // Insertion placement can change with #2864; every original box must remain intact.
        let retained: Vec<u8> = top_level_boxes(signed)
            .filter(|(kind, bytes)| {
                !(**kind == *b"emsg"
                    && box_payload(bytes)
                        .and_then(|body| body.get(4..))
                        .is_some_and(|body| body.starts_with(VSI_SCHEME_ID_URI.as_bytes())))
            })
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect();
        assert_eq!(retained, *source);
        validator
            .validate_verifiable_segment_info(signed, &mut tracker)
            .unwrap();
        assert_no_failures(&tracker);
    }
    assert_eq!(
        validator.previous_segment.as_ref().unwrap().sequence_number,
        FIRST_SEQUENCE + 2
    );
}

#[test]
fn livesim2_tampered_scte35_cue_fails_the_media_hash() {
    let capture = SignedCapture::new(10);
    let mut segment = capture.media[0].clone();
    let cue = scte35_emsg(&segment).unwrap();
    assert_eq!(cue, scte35_emsg(MEDIA[0]).unwrap());
    let last_byte = cue.as_ptr() as usize - segment.as_ptr() as usize + cue.len() - 1;
    segment[last_byte] ^= 1;
    assert_media_hash_failure(&segment, &capture);
}

#[test]
fn livesim2_removed_scte35_cue_fails_the_media_hash() {
    let capture = SignedCapture::new(10);
    let mut segment = capture.media[0].clone();
    let cue = scte35_emsg(&segment).unwrap();
    let start = cue.as_ptr() as usize - segment.as_ptr() as usize;
    let end = start + cue.len();
    segment.drain(start..end);
    assert_media_hash_failure(&segment, &capture);
}

#[test]
fn livesim2_tampered_media_payload_fails_the_media_hash() {
    let capture = SignedCapture::new(10);
    let mut segment = capture.media[0].clone();
    let mdat = find_box(&segment, b"mdat").unwrap();
    let last_byte = mdat.as_ptr() as usize - segment.as_ptr() as usize + mdat.len() - 1;
    segment[last_byte] ^= 1;
    assert_media_hash_failure(&segment, &capture);
}

#[test]
fn livesim2_key_expiry_uses_captured_presentation_time() {
    let capture = SignedCapture::new(3);
    let mut validator = capture.validator();
    let mut tracker = StatusTracker::default();
    for segment in &capture.media[..2] {
        validator
            .validate_verifiable_segment_info(segment, &mut tracker)
            .unwrap();
        assert_no_failures(&tracker);
    }
    validator
        .validate_verifiable_segment_info(&capture.media[2], &mut tracker)
        .unwrap();
    assert!(tracker
        .filter_errors()
        .any(
            |item| item.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
                && item.description.contains("expired")
                && item.description.contains("presentation time")
        ));
    assert_eq!(
        validator.previous_segment.as_ref().unwrap().sequence_number,
        FIRST_SEQUENCE + 1
    );
}

#[test]
fn livesim2_wrong_epoch_origin_fails_key_validity() {
    let capture = SignedCapture::new(10);
    let mut validator = capture.validator();
    validator.set_media_time_origin(Utc.timestamp_opt(3600, 0).single().unwrap());
    let mut tracker = StatusTracker::default();
    validator
        .validate_verifiable_segment_info(&capture.media[0], &mut tracker)
        .unwrap();
    assert!(tracker
        .filter_errors()
        .any(
            |item| item.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID)
                && item.description.contains("expired")
                && item.description.contains("presentation time")
        ));
    assert!(validator.previous_segment.is_none());
}

// ── encrypted (ECCP) captures ───────────────────────────────────────────────────

/// Byte offset of `inner`, a subslice of `outer`, within `outer`.
fn offset_in(outer: &[u8], inner: &[u8]) -> usize {
    inner.as_ptr() as usize - outer.as_ptr() as usize
}

/// Checks that the moof-relative offsets of an encrypted segment hit their targets: the
/// `saio` offset (`tfhd` default-base-is-moof) lands on the `senc` initialization vectors,
/// and the `trun` data offset on the `mdat` payload.
fn assert_offsets_hit_their_targets(segment: &[u8]) {
    let moof = find_box(segment, b"moof").unwrap();
    let mdat = find_box(segment, b"mdat").unwrap();
    let traf = box_payload(find_box(box_payload(moof).unwrap(), b"traf").unwrap()).unwrap();
    let tfhd = box_payload(find_box(traf, b"tfhd").unwrap()).unwrap();
    assert_eq!(tfhd[1..4], [0x02, 0x00, 0x00], "default-base-is-moof only");

    // saio v0 without aux_info_type: entry_count(4), then one 32-bit offset.
    let saio = box_payload(find_box(traf, b"saio").unwrap()).unwrap();
    assert_eq!(saio[..4], [0, 0, 0, 0]);
    assert_eq!(u32::from_be_bytes(saio[4..8].try_into().unwrap()), 1);
    let saio_offset = u32::from_be_bytes(saio[8..12].try_into().unwrap()) as usize;
    // senc: box header(8), version/flags(4), sample_count(4), then the IVs.
    let senc = find_box(traf, b"senc").unwrap();
    assert_eq!(
        offset_in(segment, moof) + saio_offset,
        offset_in(segment, senc) + 16
    );

    // trun with data-offset-present: data_offset follows sample_count.
    let trun = box_payload(find_box(traf, b"trun").unwrap()).unwrap();
    assert_ne!(trun[3] & 0x01, 0);
    let data_offset = i32::from_be_bytes(trun[8..12].try_into().unwrap()) as usize;
    assert_eq!(
        offset_in(segment, moof) + data_offset,
        offset_in(segment, mdat) + 8
    );
}

/// Encrypted segments sign and validate like clear ones: the VSI covers `senc`, `saiz`,
/// `saio` and the encrypted `mdat`, the init keeps its protection boxes, and inserting the
/// VSI `emsg` leaves every moof-relative offset pointing at its data.
#[test]
fn livesim2_encrypted_segments_round_trip() {
    for (scheme, init, media) in ECCP {
        let capture = SignedCapture::sign(init, &media, 10);
        assert_eq!(
            find_box(&capture.init, b"moov"),
            find_box(init, b"moov"),
            "{scheme}: the moov with encv/sinf/tenc is unchanged"
        );
        let mut validator = capture.validator();
        let mut tracker = StatusTracker::default();
        for (index, (source, signed)) in media.iter().zip(&capture.media).enumerate() {
            assert_offsets_hit_their_targets(source);
            assert_offsets_hit_their_targets(signed);
            let vsi = parse_vsi(&extract_vsi_payload_from_segment(signed).unwrap()).unwrap();
            assert_eq!(
                vsi.segment_info_map.sequence_number,
                FIRST_SEQUENCE + index as u64
            );
            let retained: Vec<u8> = top_level_boxes(signed)
                .filter(|(kind, bytes)| {
                    !(**kind == *b"emsg"
                        && box_payload(bytes)
                            .and_then(|body| body.get(4..))
                            .is_some_and(|body| body.starts_with(VSI_SCHEME_ID_URI.as_bytes())))
                })
                .flat_map(|(_, bytes)| bytes.iter().copied())
                .collect();
            assert_eq!(retained, *source, "{scheme}: every original box is kept");
            validator
                .validate_verifiable_segment_info(signed, &mut tracker)
                .unwrap();
            assert_no_failures(&tracker);
        }
    }
}

/// The `senc` initialization vectors are covered by the segment hash.
#[test]
fn livesim2_tampered_senc_fails_the_media_hash() {
    for (_, init, media) in ECCP {
        let capture = SignedCapture::sign(init, &media, 10);
        let mut segment = capture.media[0].clone();
        let moof = find_box(&segment, b"moof").unwrap();
        let traf = box_payload(find_box(box_payload(moof).unwrap(), b"traf").unwrap()).unwrap();
        let first_iv = offset_in(&segment, find_box(traf, b"senc").unwrap()) + 16;
        segment[first_iv] ^= 1;
        assert_media_hash_failure(&segment, &capture);
    }
}

/// So is the encrypted media.
#[test]
fn livesim2_tampered_encrypted_media_fails_the_media_hash() {
    for (_, init, media) in ECCP {
        let capture = SignedCapture::sign(init, &media, 10);
        let mut segment = capture.media[0].clone();
        let mdat = find_box(&segment, b"mdat").unwrap();
        let last_byte = offset_in(&segment, mdat) + mdat.len() - 1;
        segment[last_byte] ^= 1;
        assert_media_hash_failure(&segment, &capture);
    }
}
