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

//! Verifiable Segment Info (VSI) signing for live video (C2PA section 19.4).
//!
//! Each media segment carries a COSE_Sign1 inside an `emsg` box, signed by an
//! Ed25519 session key provided by the caller.  The init segment carries the
//! session key in a `c2pa.session-keys` assertion; the session key's
//! `signerBinding` is a detached COSE_Sign1 where the session key signs the
//! signer's end-entity certificate, proving the key is associated with the
//! manifest signer (§18.25.2).

use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};

use super::{
    box_walk::{box_payload, find_box},
    cose_key::build_ed25519_cose_key,
    verifiable_segment_info::{VSI_SCHEME_ID_URI, VSI_URI_OFFSET_IN_EMSG},
};
use crate::{
    assertions::{BmffHash, DataMap, ExclusionsMap, SessionKey, SessionKeys},
    builder::Builder,
    error::{Error, Result},
    live_video::verifiable_segment_info::SegmentInfoMap,
    Reader, Signer,
};

const VSI_VALUE_FSEG: &str = "fseg";

/// Signs live video segments using the Verifiable Segment Info method (§19.4).
///
/// The caller provides an Ed25519 session key via [`from_signing_key`].  The
/// init segment is signed with the manifest [`Signer`] and carries a
/// `c2pa.session-keys` assertion that includes the session public key and a
/// `signerBinding` COSE_Sign1 proving the key is associated with the manifest
/// signer.
///
/// Each media segment receives a COSE_Sign1 `emsg` box signed by the session
/// key; the box is prepended to the segment bytes.
///
/// [`from_signing_key`]: LiveVideoVsiSigner::from_signing_key
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
pub struct LiveVideoVsiSigner {
    session_signing_key: SigningKey,
    session_cose_key: c2pa_cbor::Value,
    kid: Vec<u8>,
    signer_binding: c2pa_cbor::Value,
    min_sequence_number: u64,
    created_at: String,
    validity_period: u64,
    next_sequence_number: u64,
    base_manifest_json: String,
    /// Instance ID of the active manifest from the signed init segment.
    /// Populated by `sign_init_segment` and embedded in every media segment's
    /// `segment-info-map` as `manifestId` per §19.4.
    active_manifest_id: Option<String>,
    /// Track timescale read from the init segment's `mdhd`, used for the
    /// `emsg` box's `timescale`/`event_duration` fields (§19.4.2). Falls back
    /// to `1` (i.e. seconds) if `sign_init_segment` was never called or the
    /// init segment has no parseable `mdhd`.
    track_timescale: Option<u32>,
}

impl LiveVideoVsiSigner {
    /// Creates a VSI signer from a caller-provided Ed25519 session key.
    ///
    /// Builds the `signerBinding` COSE_Sign1 per §18.25.2: the session key
    /// signs the manifest signer's end-entity certificate (detached payload).
    ///
    /// # Arguments
    ///
    /// * `manifest_json` — base manifest JSON (without a `c2pa.session-keys`
    ///   assertion; one is added automatically when signing the init segment).
    /// * `manifest_signer` — the C2PA [`Signer`] whose end-entity certificate
    ///   is bound to the session key via `signerBinding`.
    /// * `signing_key` — Ed25519 session private key.
    /// * `kid` — key identifier for the session key (e.g. `b"session-key-1"`).
    /// * `min_sequence_number` — first sequence number valid for this key.
    /// * `validity_period_secs` — how long (in seconds) the session key is valid.
    pub fn from_signing_key(
        manifest_json: impl Into<String>,
        manifest_signer: &dyn Signer,
        signing_key: SigningKey,
        kid: impl Into<Vec<u8>>,
        min_sequence_number: u64,
        validity_period_secs: u64,
    ) -> Result<Self> {
        let base_manifest_json = manifest_json.into();
        let kid = kid.into();

        let session_cose_key = build_ed25519_cose_key(&signing_key.verifying_key(), &kid);

        let ee_cert_der = manifest_signer
            .certs()
            .map_err(|e| Error::OtherError(Box::new(e)))?
            .into_iter()
            .next()
            .ok_or_else(|| Error::BadParam("manifest signer has no certificates".into()))?;

        let signer_binding = build_signer_binding(&ee_cert_der, &signing_key)?;

        let created_at = chrono::Utc::now().to_rfc3339();

        Ok(Self {
            session_signing_key: signing_key,
            session_cose_key,
            kid,
            signer_binding,
            min_sequence_number,
            created_at,
            validity_period: validity_period_secs,
            next_sequence_number: min_sequence_number,
            base_manifest_json,
            active_manifest_id: None,
            track_timescale: None,
        })
    }

    /// Signs an init segment, embedding a `c2pa.session-keys` assertion.
    ///
    /// Captures the manifest label from the signed output so that
    /// subsequent calls to [`sign_media_segment`] can embed it as `manifestId`
    /// per §19.4.
    ///
    /// Per §19.2.3, the init segment SHOULD NOT contain media data (`mdat`).
    ///
    /// [`sign_media_segment`]: LiveVideoVsiSigner::sign_media_segment
    pub fn sign_init_segment(
        &mut self,
        segment_data: &[u8],
        format: &str,
        manifest_signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        self.track_timescale = parse_first_mdhd_timescale(segment_data);

        let session_keys = self.build_session_keys_assertion();
        let mut builder = Builder::from_context(super::context_from_thread_local_settings()?)
            .with_definition(self.base_manifest_json.as_str())?;
        builder.add_assertion_cbor(SessionKeys::LABEL, &session_keys)?;

        let mut source = std::io::Cursor::new(segment_data);
        let mut dest = std::io::Cursor::new(Vec::new());
        builder.sign(manifest_signer, format, &mut source, &mut dest)?;
        let signed_bytes = dest.into_inner();

        self.capture_manifest_id(&signed_bytes, format)?;

        Ok(signed_bytes)
    }

    /// Signs a media segment by prepending a COSE_Sign1 `emsg` box.
    ///
    /// The COSE_Sign1 payload is a CBOR `SegmentInfoMap` with the current
    /// sequence number, a `bmffHash` covering the segment data excluding VSI
    /// `emsg` boxes, and the `manifestId` from the signed init segment per §19.4.
    pub fn sign_media_segment(&mut self, segment_data: &[u8]) -> Result<Vec<u8>> {
        let manifest_id = match self.active_manifest_id.as_deref() {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => {
                return Err(Error::BadParam(
                    "no manifestId available to sign into the segment; call sign_init_segment \
                     (or resume_from_segment/restore_manifest_id) before sign_media_segment"
                        .to_string(),
                ));
            }
        };
        let sequence_number = self.next_sequence_number;

        // Per §19.4.1, sequenceNumber "shall either match the mfhd.sequence_number field ...
        // or shall follow the segment-indexing rules defined in ISO/IEC 23009-9". This signer
        // uses an internal counter (needed to resume across process invocations), so cross-check
        // it against the segment's own mfhd whenever one is present, rather than silently
        // signing a sequenceNumber that has drifted from the segment actually being signed
        // (e.g. because a segment was skipped, reordered, or duplicated upstream).
        if let Some(mfhd_sequence_number) = moof_sequence_number(segment_data) {
            if u64::from(mfhd_sequence_number) != sequence_number {
                return Err(Error::BadParam(format!(
                    "VSI sequenceNumber ({sequence_number}) does not match the segment's own \
                     moof/mfhd.sequence_number ({mfhd_sequence_number}); the signer's \
                     sequence counter has drifted from the segment being signed"
                )));
            }
        }

        let timescale = self.track_timescale.unwrap_or(1);
        let event_duration = parse_first_moof_duration_ticks(segment_data).unwrap_or(0);
        // Truncation is safe: a live session realistically never reaches u32::MAX segments,
        // and the id only needs to be unique within the session (§19.4.2), not globally.
        let id = sequence_number as u32;

        // Two passes: the offset-prefix (§18.6.2) must reflect each box's absolute offset
        // in the final segment (emsg + segment_data), which requires knowing emsg's size
        // before its own contents (the hash) can be computed. Pass 1 hashes against a
        // same-size draft emsg (placeholder digest) to get real offsets; pass 2 rebuilds
        // emsg with the real hash, which only changes opaque digest/signature bytes, not
        // their lengths.
        let build_emsg = |bmff_hash: c2pa_cbor::Value| -> Result<Vec<u8>> {
            let segment_info_map = SegmentInfoMap {
                sequence_number,
                bmff_hash,
                manifest_id: manifest_id.clone(),
                manifest_uri: None,
            };
            let cose_sign1_bytes =
                build_vsi_cose_sign1(&segment_info_map, &self.session_signing_key, &self.kid)?;
            Ok(build_emsg_box(
                &cose_sign1_bytes,
                timescale,
                event_duration,
                id,
            ))
        };

        let draft_emsg_box = build_emsg(build_segment_bmff_hash_placeholder()?)?;
        let mut draft_segment = draft_emsg_box.clone();
        draft_segment.extend_from_slice(segment_data);
        let bmff_hash = build_segment_bmff_hash(&draft_segment)?;

        let emsg_box = build_emsg(bmff_hash)?;
        if draft_emsg_box.len() != emsg_box.len() {
            return Err(Error::BadParam(
                "draft and final VSI emsg boxes differ in size; the c2pa.hash.bmff.v3 \
                 offset-prefix scheme would be computed against the wrong box offsets"
                    .to_string(),
            ));
        }

        let mut signed_segment = emsg_box;
        signed_segment.extend_from_slice(segment_data);

        self.next_sequence_number += 1;
        Ok(signed_segment)
    }

    /// Returns the sequence number assigned to the next media segment.
    pub fn next_sequence_number(&self) -> u64 {
        self.next_sequence_number
    }

    /// Restores the active manifest ID from a previously signed init segment.
    ///
    /// Used when resuming a live session across process invocations.  Re-signing
    /// the init would produce a different UUID, breaking `manifestId` continuity
    /// across segments.  Instead, call this method with the already-signed init
    /// from the output directory to restore the session's `manifestId`.
    pub fn restore_manifest_id_from_signed_init(
        &mut self,
        signed_init_data: &[u8],
        format: &str,
    ) -> Result<()> {
        self.track_timescale = parse_first_mdhd_timescale(signed_init_data);
        self.capture_manifest_id(signed_init_data, format)
    }

    /// Resumes from a previously signed VSI segment.
    ///
    /// Extracts the `sequenceNumber` from the segment's `emsg` box and sets
    /// `next_sequence_number` to `sequenceNumber + 1`. Also restores `manifestId` from that
    /// same segment (unless it's empty, i.e. the original session never signed an init
    /// segment either) — the segment being resumed from already carries the session's
    /// `manifestId`, so callers resuming a session don't also need to separately call
    /// [`restore_manifest_id_from_signed_init`] just to avoid silently signing subsequent
    /// segments with an empty `manifestId`.
    ///
    /// [`restore_manifest_id_from_signed_init`]: LiveVideoVsiSigner::restore_manifest_id_from_signed_init
    pub fn resume_from_segment(&mut self, segment_data: &[u8]) -> Result<()> {
        use crate::live_video::verifiable_segment_info::{
            extract_vsi_payload_from_segment, parse_vsi,
        };

        let vsi_bytes = extract_vsi_payload_from_segment(segment_data).ok_or_else(|| {
            Error::BadParam("previous segment does not contain a VSI emsg box".into())
        })?;

        let parsed = parse_vsi(&vsi_bytes)?;
        self.next_sequence_number = parsed.segment_info_map.sequence_number + 1;
        if !parsed.segment_info_map.manifest_id.is_empty() {
            self.active_manifest_id = Some(parsed.segment_info_map.manifest_id);
        }
        Ok(())
    }

    /// Reads back `signed_data`'s active manifest and, if it has a label, stores it as
    /// `active_manifest_id` (its c2pa URN label per §8.1). Used after signing an init segment
    /// and when restoring state from a previously-signed one.
    fn capture_manifest_id(&mut self, signed_data: &[u8], format: &str) -> Result<()> {
        let reader = Reader::from_context(super::context_from_thread_local_settings()?)
            .with_stream(format, std::io::Cursor::new(signed_data))?;
        if let Some(label) = reader.active_manifest().and_then(|m| m.label()) {
            self.active_manifest_id = Some(label.to_string());
        }
        Ok(())
    }

    fn build_session_keys_assertion(&self) -> SessionKeys {
        SessionKeys {
            keys: vec![SessionKey {
                key: self.session_cose_key.clone(),
                min_sequence_number: self.min_sequence_number,
                created_at: self.created_at.clone(),
                validity_period: self.validity_period,
                signer_binding: self.signer_binding.clone(),
            }],
        }
    }
}

// ── BMFF hash helper ─────────────────────────────────────────────────────────

fn vsi_emsg_exclusion() -> ExclusionsMap {
    let mut exclusion = ExclusionsMap::new("/emsg".to_string());
    exclusion.data = Some(vec![DataMap {
        offset: VSI_URI_OFFSET_IN_EMSG,
        value: VSI_SCHEME_ID_URI.as_bytes().to_vec(),
    }]);
    exclusion
}

/// A `bmff-hash-map` scoped to exclude the VSI `emsg` box, per §19.4.1. Defaults to
/// `bmff_version` 3, which per §18.6.2 hashes each included root box as `offset || data`
/// (8-byte big-endian file offset prefix).
fn new_vsi_bmff_hash() -> BmffHash {
    let mut bmff_hash = BmffHash::new("jumbf manifest", "sha256", None);
    bmff_hash.add_exclusions(&mut vec![vsi_emsg_exclusion()]);
    bmff_hash
}

/// A same-shape `bmff-hash-map` with a zero-filled placeholder digest, used to size
/// the draft `emsg` box in [`LiveVideoVsiSigner::sign_media_segment`]'s first pass.
pub(super) fn build_segment_bmff_hash_placeholder() -> Result<c2pa_cbor::Value> {
    let mut bmff_hash = new_vsi_bmff_hash();
    bmff_hash.set_hash(vec![0u8; 32]); // sha256 digest size; value is irrelevant, only length matters
    c2pa_cbor::value::to_value(&bmff_hash)
        .map_err(|e| Error::BadParam(format!("failed to serialize placeholder bmffHash: {e}")))
}

/// Computes the `bmff-hash-map` for a media segment per §19.4.1.
///
/// `full_segment` must be the complete bytes that will be delivered — i.e. the
/// (draft or real) `emsg` box followed by the raw segment data — so that the
/// `c2pa.hash.bmff.v3` offset-prefix (§18.6.2) reflects each box's real final
/// position. The hash excludes the VSI `emsg` box itself, identified by its
/// `scheme_id_uri` field ("urn:c2pa:verifiable-segment-info").
pub(super) fn build_segment_bmff_hash(full_segment: &[u8]) -> Result<c2pa_cbor::Value> {
    let mut bmff_hash = new_vsi_bmff_hash();

    let mut cursor = std::io::Cursor::new(full_segment);
    bmff_hash
        .gen_hash_from_stream(&mut cursor)
        .map_err(|e| Error::BadParam(format!("failed to compute segment bmffHash: {e}")))?;

    c2pa_cbor::value::to_value(&bmff_hash)
        .map_err(|e| Error::BadParam(format!("failed to serialize bmffHash to CBOR: {e}")))
}

// ── Signer binding (§18.25.2) ────────────────────────────────────────────────
//
// Per the spec the `signerBinding` is a **detached** COSE_Sign1 where:
//   - the **session key** signs (EdDSA since we use Ed25519),
//   - the **payload** is the signer's end-entity certificate encoded as a CBOR
//     byte string (used in Sig_structure but NOT carried in the COSE_Sign1).

fn build_signer_binding(
    ee_cert_der: &[u8],
    session_signing_key: &SigningKey,
) -> Result<c2pa_cbor::Value> {
    let external_payload = c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec()))
        .map_err(|e| Error::BadParam(format!("failed to CBOR-encode EE certificate: {e}")))?;

    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .build();

    let mut sign1 = CoseSign1Builder::new().protected(protected).build();

    // signerBinding is a detached-payload COSE_Sign1: the cert bytes are the
    // external payload, not AAD. Use tbs_detached_data per RFC 9052 §4.4.
    let tbs = sign1.tbs_detached_data(&external_payload, b"");
    let signature: ed25519_dalek::Signature = Ed25519Signer::sign(session_signing_key, &tbs);
    sign1.signature = signature.to_bytes().to_vec();

    let binding_bytes = sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode signer binding: {e}")))?;

    // Deserialize back to a Value so the COSE_Sign1 is embedded as a tagged
    // CBOR structure (tag 18) rather than an opaque bstr.
    c2pa_cbor::from_slice(&binding_bytes).map_err(|e| {
        Error::BadParam(format!(
            "failed to decode signer binding as CBOR Value: {e}"
        ))
    })
}

// ── VSI COSE_Sign1 construction ──────────────────────────────────────────────

fn build_vsi_cose_sign1(
    segment_info_map: &SegmentInfoMap,
    signing_key: &SigningKey,
    kid: &[u8],
) -> Result<Vec<u8>> {
    let payload = c2pa_cbor::to_vec(segment_info_map)
        .map_err(|e| Error::BadParam(format!("failed to encode SegmentInfoMap: {e}")))?;

    // Per §19.4.1, the protected header may carry an `iat` field: a `NumericDate` (RFC 8392)
    // giving the "claimed time of signing". Populating it lets a validator check the segment
    // against the session key's validity period using this claimed time rather than its own
    // wall-clock time, which matters for any validation run after the fact (e.g. archival/VOD
    // validation of a recording), since the key's validity window is anchored to createdAt.
    let iat = chrono::Utc::now().timestamp();
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .text_value("iat".to_string(), coset::cbor::value::Value::from(iat))
        .build();
    let unprotected = HeaderBuilder::new().key_id(kid.to_vec()).build();

    let mut sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload)
        .build();

    let tbs = sign1.tbs_data(b"");
    let signature: ed25519_dalek::Signature = signing_key.sign(&tbs);
    sign1.signature = signature.to_bytes().to_vec();

    sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode COSE_Sign1: {e}")))
}

// ── emsg box construction ────────────────────────────────────────────────────

/// Builds a `emsg` v0 box carrying the VSI COSE_Sign1.
///
/// Per §19.4.2: `timescale` and `event_duration` shall cover the whole
/// segment, and `id` shall be a session-unique value.
fn build_emsg_box(
    cose_sign1_bytes: &[u8],
    timescale: u32,
    event_duration: u32,
    id: u32,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(VSI_SCHEME_ID_URI.as_bytes());
    body.push(0); // null terminator
    body.extend_from_slice(VSI_VALUE_FSEG.as_bytes());
    body.push(0); // null terminator
    body.extend_from_slice(&timescale.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // presentation_time_delta, shall be 0
    body.extend_from_slice(&event_duration.to_be_bytes());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(cose_sign1_bytes);

    // 8 bytes header + 4 bytes version/flags + body
    let total_size = (8u32 + 4 + body.len() as u32).to_be_bytes();

    let mut emsg = Vec::new();
    emsg.extend_from_slice(&total_size);
    emsg.extend_from_slice(b"emsg");
    emsg.push(0); // version 0
    emsg.extend_from_slice(&[0u8; 3]); // flags
    emsg.extend_from_slice(&body);
    emsg
}

// ── minimal BMFF box lookups for emsg timing fields ──────────────────────────
//
// `timescale`/`event_duration` in the emsg box must reflect the segment's
// real timing (§19.4.2). `timescale` is a track-level property declared once
// in the init segment's `mdhd`; `event_duration` is derived per-segment from
// the media segment's own `moof/traf/tfhd`+`trun` sample durations, which are
// always expressed in that same track timescale regardless of whether the
// caller supplies the init segment.

/// Parses `moov/trak/mdia/mdhd`'s `timescale` field from an init segment.
fn parse_first_mdhd_timescale(init_data: &[u8]) -> Option<u32> {
    let moov = box_payload(find_box(init_data, b"moov")?)?;
    let trak = box_payload(find_box(moov, b"trak")?)?;
    let mdia = box_payload(find_box(trak, b"mdia")?)?;
    let mdhd = box_payload(find_box(mdia, b"mdhd")?)?;

    let version = *mdhd.first()?;
    let fields = mdhd.get(4..)?; // skip FullBox version(1)+flags(3)
    let timescale_bytes = if version == 1 {
        fields.get(16..20)? // creation_time(8) + modification_time(8) + timescale(4)
    } else {
        fields.get(8..12)? // creation_time(4) + modification_time(4) + timescale(4)
    };
    Some(u32::from_be_bytes(timescale_bytes.try_into().ok()?))
}

/// Sums the `moof/traf/tfhd`+`trun` sample durations of a media segment, in
/// the track's timescale ticks (per ISO/IEC 14496-12 §8.8.7–8.8.8). Falls
/// back to `tfhd`'s `default_sample_duration * sample_count` when `trun`
/// doesn't carry per-sample durations.
fn parse_first_moof_duration_ticks(segment_data: &[u8]) -> Option<u32> {
    let moof = box_payload(find_box(segment_data, b"moof")?)?;
    let traf = box_payload(find_box(moof, b"traf")?)?;

    let tfhd = box_payload(find_box(traf, b"tfhd")?)?;
    let tfhd_flags = u32::from_be_bytes([0, *tfhd.get(1)?, *tfhd.get(2)?, *tfhd.get(3)?]);
    let mut pos = 4 + 4; // FullBox header + track_ID
    if tfhd_flags & 0x000001 != 0 {
        pos += 8; // base_data_offset
    }
    if tfhd_flags & 0x000002 != 0 {
        pos += 4; // sample_description_index
    }
    let default_sample_duration = if tfhd_flags & 0x000008 != 0 {
        Some(u32::from_be_bytes(tfhd.get(pos..pos + 4)?.try_into().ok()?))
    } else {
        None
    };

    let trun = box_payload(find_box(traf, b"trun")?)?;
    let trun_flags = u32::from_be_bytes([0, *trun.get(1)?, *trun.get(2)?, *trun.get(3)?]);
    let sample_count = u32::from_be_bytes(trun.get(4..8)?.try_into().ok()?);
    let mut tpos = 8;
    if trun_flags & 0x000001 != 0 {
        tpos += 4; // data_offset
    }
    if trun_flags & 0x000004 != 0 {
        tpos += 4; // first_sample_flags
    }

    let sample_duration_present = trun_flags & 0x000100 != 0;
    let sample_size_present = trun_flags & 0x000200 != 0;
    let sample_flags_present = trun_flags & 0x000400 != 0;
    let sample_cto_present = trun_flags & 0x000800 != 0;

    if sample_duration_present {
        let mut total: u64 = 0;
        for _ in 0..sample_count {
            let dur = u32::from_be_bytes(trun.get(tpos..tpos + 4)?.try_into().ok()?);
            total += u64::from(dur);
            tpos += 4;
            if sample_size_present {
                tpos += 4;
            }
            if sample_flags_present {
                tpos += 4;
            }
            if sample_cto_present {
                tpos += 4;
            }
        }
        Some(total.min(u64::from(u32::MAX)) as u32)
    } else {
        default_sample_duration
            .map(|d| (u64::from(d) * u64::from(sample_count)).min(u64::from(u32::MAX)) as u32)
    }
}

/// Parses `moof/mfhd`'s `sequence_number` field from a media segment, per ISO/IEC 14496-12
/// §8.8.5. Used to cross-check the signer's own sequence counter (§19.4.1).
///
/// Public so callers can infer a VSI session's starting `minSequenceNumber` from a live
/// stream's first segment, rather than assuming the packager starts at 1 (it commonly
/// doesn't). Returns `None` if the segment has no `moof` box, or `mfhd` is missing/malformed.
///
/// <div class="warning">
///
/// **Experimental.** This function is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
pub fn moof_sequence_number(segment_data: &[u8]) -> Option<u32> {
    let moof = box_payload(find_box(segment_data, b"moof")?)?;
    let mfhd = box_payload(find_box(moof, b"mfhd")?)?;
    Some(u32::from_be_bytes(mfhd.get(4..8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{
        live_video::{
            verifiable_segment_info::extract_vsi_payload_from_segment, LiveVideoValidator,
        },
        status_tracker::StatusTracker,
        utils::ephemeral_signer::EphemeralSigner,
    };

    fn make_test_segment() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&8u32.to_be_bytes());
        data.extend_from_slice(b"mdat");
        data
    }

    fn make_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        b.extend_from_slice(fourcc);
        b.extend_from_slice(payload);
        b
    }

    fn make_fullbox(fourcc: &[u8; 4], version: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(version);
        body.extend_from_slice(&flags.to_be_bytes()[1..]);
        body.extend_from_slice(payload);
        make_box(fourcc, &body)
    }

    fn make_test_init_segment(timescale: u32) -> Vec<u8> {
        let mut mdhd_payload = Vec::new();
        mdhd_payload.extend_from_slice(&0u32.to_be_bytes()); // creation_time
        mdhd_payload.extend_from_slice(&0u32.to_be_bytes()); // modification_time
        mdhd_payload.extend_from_slice(&timescale.to_be_bytes());
        mdhd_payload.extend_from_slice(&0u32.to_be_bytes()); // duration
        mdhd_payload.extend_from_slice(&0u16.to_be_bytes()); // language
        mdhd_payload.extend_from_slice(&0u16.to_be_bytes()); // pre_defined
        let mdhd = make_fullbox(b"mdhd", 0, 0, &mdhd_payload);
        let mdia = make_box(b"mdia", &mdhd);
        let trak = make_box(b"trak", &mdia);
        make_box(b"moov", &trak)
    }

    /// Builds a `moof/traf/tfhd+trun` segment with the given per-sample
    /// durations (`trun`'s sample-duration-present flag set), plus a trailing
    /// `mdat`.
    fn make_test_media_segment_with_moof(sample_durations: &[u32]) -> Vec<u8> {
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&1u32.to_be_bytes()); // track_ID
        let tfhd = make_fullbox(b"tfhd", 0, 0, &tfhd_payload);

        let mut trun_payload = Vec::new();
        trun_payload.extend_from_slice(&(sample_durations.len() as u32).to_be_bytes());
        for d in sample_durations {
            trun_payload.extend_from_slice(&d.to_be_bytes());
        }
        let trun = make_fullbox(b"trun", 0, 0x000100, &trun_payload); // sample-duration-present

        let traf = make_box(b"traf", &[tfhd, trun].concat());
        let moof = make_box(b"moof", &traf);
        let mdat = make_box(b"mdat", &[0u8; 4]);
        [moof, mdat].concat()
    }

    #[test]
    fn parses_mdhd_timescale_from_init_segment() {
        let init = make_test_init_segment(48_000);
        assert_eq!(parse_first_mdhd_timescale(&init), Some(48_000));
    }

    #[test]
    fn parses_moof_duration_from_trun_sample_durations() {
        let seg = make_test_media_segment_with_moof(&[1000, 1000, 1000]);
        assert_eq!(parse_first_moof_duration_ticks(&seg), Some(3000));
    }

    #[test]
    fn falls_back_to_tfhd_default_sample_duration_when_trun_omits_durations() {
        let mut tfhd_payload = Vec::new();
        tfhd_payload.extend_from_slice(&1u32.to_be_bytes()); // track_ID
        tfhd_payload.extend_from_slice(&2000u32.to_be_bytes()); // default_sample_duration
        let tfhd = make_fullbox(b"tfhd", 0, 0x000008, &tfhd_payload); // default-sample-duration-present

        let mut trun_payload = Vec::new();
        trun_payload.extend_from_slice(&4u32.to_be_bytes()); // sample_count, no per-sample durations
        let trun = make_fullbox(b"trun", 0, 0, &trun_payload);

        let traf = make_box(b"traf", &[tfhd, trun].concat());
        let moof = make_box(b"moof", &traf);

        assert_eq!(parse_first_moof_duration_ticks(&moof), Some(8000));
    }

    #[test]
    fn parsers_return_none_for_segments_without_the_relevant_boxes() {
        let plain_segment = make_test_segment();
        assert_eq!(parse_first_mdhd_timescale(&plain_segment), None);
        assert_eq!(parse_first_moof_duration_ticks(&plain_segment), None);
    }

    /// Regression test: a `tfhd`/`trun` box truncated shorter than its own fixed fields must
    /// return `None`, not panic, since these parsers run on attacker-controlled segment bytes.
    #[test]
    fn parsers_return_none_for_truncated_boxes_instead_of_panicking() {
        // `tfhd` with no payload at all (not even the FullBox version/flags bytes).
        let empty_tfhd = make_box(b"tfhd", &[]);
        let traf = make_box(b"traf", &empty_tfhd);
        let moof = make_box(b"moof", &traf);
        assert_eq!(parse_first_moof_duration_ticks(&moof), None);

        // `tfhd` present and well-formed, but `trun` truncated to nothing.
        let tfhd_payload = 1u32.to_be_bytes();
        let tfhd = make_fullbox(b"tfhd", 0, 0, &tfhd_payload);
        let empty_trun = make_box(b"trun", &[]);
        let traf = make_box(b"traf", &[tfhd, empty_trun].concat());
        let moof = make_box(b"moof", &traf);
        assert_eq!(parse_first_moof_duration_ticks(&moof), None);

        // A zero-length box (just an 8-byte header, no payload at all) as the outermost box.
        let empty_box = make_box(b"moof", &[]);
        assert_eq!(box_payload(&empty_box), Some(&[][..]));

        // A box shorter than its own 8-byte header.
        assert_eq!(box_payload(&[0, 0, 0, 4]), None);
    }

    #[test]
    fn signed_segments_have_real_emsg_timing_fields() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 1);
        // Bypass sign_init_segment (which round-trips through the full BMFF
        // asset-signing pipeline, requiring a complete valid MP4 structure
        // beyond the scope of this unit test) and set the field it would
        // have populated directly, since it's private to this module.
        vsi_signer.track_timescale = Some(48_000);

        let seg1 = vsi_signer
            .sign_media_segment(&make_test_media_segment_with_moof(&[1000, 1000]))
            .unwrap();
        let seg2 = vsi_signer
            .sign_media_segment(&make_test_media_segment_with_moof(&[1000, 1000]))
            .unwrap();

        let (timescale1, duration1, id1) = read_emsg_timing_fields(&seg1);
        let (timescale2, duration2, id2) = read_emsg_timing_fields(&seg2);

        assert_eq!(
            timescale1, 48_000,
            "emsg timescale must reflect the track's mdhd timescale"
        );
        assert_eq!(timescale2, 48_000);
        assert_eq!(
            duration1, 2000,
            "emsg event_duration must cover the whole segment"
        );
        assert_eq!(duration2, 2000);
        assert_ne!(
            id1, 0,
            "emsg id must not be the spec-prohibited placeholder 0"
        );
        assert_ne!(id2, 0);
        assert_ne!(id1, id2, "emsg id must be session-unique across segments");
    }

    fn make_test_media_segment_with_mfhd(sequence_number: u32) -> Vec<u8> {
        let mfhd = make_fullbox(b"mfhd", 0, 0, &sequence_number.to_be_bytes());
        let tfhd = make_fullbox(b"tfhd", 0, 0, &1u32.to_be_bytes()); // track_ID
        let traf = make_box(b"traf", &tfhd);
        let moof = make_box(b"moof", &[mfhd, traf].concat());
        let mdat = make_box(b"mdat", &[0u8; 4]);
        [moof, mdat].concat()
    }

    /// Regression test: per §19.4.1, sequenceNumber must match the segment's own
    /// `moof/mfhd.sequence_number` when present. If the signer's internal counter has
    /// drifted from the segment actually being signed (e.g. a skipped/reordered segment),
    /// signing must fail loudly rather than silently embed a mismatched sequenceNumber.
    #[test]
    fn sign_media_segment_rejects_mfhd_sequence_number_mismatch() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 1); // starts at sequenceNumber 1

        let err = vsi_signer
            .sign_media_segment(&make_test_media_segment_with_mfhd(5))
            .unwrap_err();
        assert!(
            format!("{err}").contains("sequenceNumber"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sign_media_segment_accepts_matching_mfhd_sequence_number() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 1); // starts at sequenceNumber 1

        vsi_signer
            .sign_media_segment(&make_test_media_segment_with_mfhd(1))
            .unwrap();
    }

    /// Test-only: reads back `(timescale, event_duration, id)` from a signed
    /// segment's `emsg` box, to assert on what [`build_emsg_box`] actually wrote.
    fn read_emsg_timing_fields(signed_segment: &[u8]) -> (u32, u32, u32) {
        let emsg = find_box(signed_segment, b"emsg").unwrap();
        let body = box_payload(emsg).unwrap();
        let fields = &body[4..]; // skip FullBox version+flags
        let mut pos = fields.iter().position(|&b| b == 0).unwrap() + 1; // scheme_id_uri\0
        pos += fields[pos..].iter().position(|&b| b == 0).unwrap() + 1; // value\0
        let timescale = u32::from_be_bytes(fields[pos..pos + 4].try_into().unwrap());
        let event_duration = u32::from_be_bytes(fields[pos + 8..pos + 12].try_into().unwrap());
        let id = u32::from_be_bytes(fields[pos + 12..pos + 16].try_into().unwrap());
        (timescale, event_duration, id)
    }

    fn make_test_signer() -> EphemeralSigner {
        EphemeralSigner::new("test-vsi.local").unwrap()
    }

    fn make_test_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    /// A manifest with a `c2pa.created` action, required for `sign_init_segment`'s internal
    /// read-back (via `Reader`) to pass full manifest validation.
    fn test_manifest_json_with_actions() -> &'static str {
        r#"{"assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"}]}}]}"#
    }

    fn make_vsi_signer(signer: &EphemeralSigner, kid: &[u8], min_seq: u64) -> LiveVideoVsiSigner {
        LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            signer,
            make_test_signing_key(),
            kid.to_vec(),
            min_seq,
            3600,
        )
        .unwrap()
    }

    /// A stand-in for the manifest label that `sign_init_segment` would normally capture.
    /// Tests that only exercise `sign_media_segment` in isolation (without round-tripping a
    /// full init segment through the signing pipeline) use this to satisfy
    /// `sign_media_segment`'s now-mandatory manifestId requirement.
    const TEST_MANIFEST_ID: &str = "urn:c2pa:test-manifest";

    /// Like [`make_vsi_signer`], but with `active_manifest_id` already set to
    /// [`TEST_MANIFEST_ID`], bypassing the need to sign a real init segment first.
    fn make_vsi_signer_with_manifest_id(
        signer: &EphemeralSigner,
        kid: &[u8],
        min_seq: u64,
    ) -> LiveVideoVsiSigner {
        let mut vsi_signer = make_vsi_signer(signer, kid, min_seq);
        vsi_signer.active_manifest_id = Some(TEST_MANIFEST_ID.to_string());
        vsi_signer
    }

    #[test]
    fn sign_media_segment_prepends_emsg_box() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);

        let segment = make_test_segment();
        let signed = vsi_signer.sign_media_segment(&segment).unwrap();

        assert!(signed.len() > segment.len());

        let vsi_payload = extract_vsi_payload_from_segment(&signed);
        assert!(
            vsi_payload.is_some(),
            "VSI emsg payload not found in signed segment"
        );
    }

    #[test]
    fn sequence_numbers_advance_per_segment() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 1);

        assert_eq!(vsi_signer.next_sequence_number(), 1);

        vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 2);

        vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 3);
    }

    #[test]
    fn signed_segment_passes_vsi_validation() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);

        let session_keys = vsi_signer.build_session_keys_assertion();
        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        validator
            .validate_session_keys(
                &session_keys,
                TEST_MANIFEST_ID,
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();

        let segment = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();

        validator
            .validate_verifiable_segment_info(&segment, &mut tracker)
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
        assert!(
            failures.is_empty(),
            "unexpected validation failures: {failures:?}"
        );
    }

    #[test]
    fn vsi_payload_contains_correct_sequence_number() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 5);

        let signed = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert_eq!(info_map.sequence_number, 5);
    }

    #[test]
    fn signer_binding_roundtrip_validates() {
        let signer = make_test_signer();
        let vsi_signer = make_vsi_signer(&signer, b"key-1", 1);

        let session_keys = vsi_signer.build_session_keys_assertion();
        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();

        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        validator
            .validate_session_keys(&session_keys, "", Some(&ee_cert_der), &mut tracker)
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
        assert!(
            failures.is_empty(),
            "signerBinding validation failures: {failures:?}"
        );
    }

    #[test]
    fn second_segment_has_next_sequence_number() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 1);

        let seg1 = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let seg2 = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();

        let map1 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();
        let map2 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();

        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);
    }

    #[test]
    fn resume_from_segment_advances_sequence_number() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 1);

        let seg1 = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 2);

        let mut resumed_signer = make_vsi_signer(&signer, b"k", 1);
        resumed_signer.resume_from_segment(&seg1).unwrap();
        assert_eq!(resumed_signer.next_sequence_number(), 2);
    }

    #[test]
    fn sign_media_segment_bmff_hash_is_not_null() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 1);

        let signed = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert!(
            !info_map.bmff_hash.is_null(),
            "bmffHash must not be null per §19.4 — regression guard"
        );
    }

    #[test]
    fn sign_media_segment_fails_without_manifest_id() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer(&signer, b"k", 1);

        // Neither sign_init_segment nor resume_from_segment/restore_manifest_id has been
        // called, so there's no manifestId to sign into the segment — must fail rather than
        // silently sign an empty (spec-non-conformant) manifestId.
        let result = vsi_signer.sign_media_segment(&make_test_segment());

        assert!(result.is_err());
    }

    #[test]
    fn sign_media_segment_manifest_id_populated_after_signing_init() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        // Init-segment read-back does full manifest validation; EphemeralSigner certs are
        // intentionally untrusted (see ephemeral_signer.rs), so disable trust checking here.
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        // Use a real DASH init segment so Builder::sign can embed the manifest.
        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");

        let signer = make_test_signer();
        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &signer,
            make_test_signing_key(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();

        vsi_signer
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();

        let signed = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let vsi_bytes = extract_vsi_payload_from_segment(&signed).unwrap();
        let info_map = parse_segment_info_map(&vsi_bytes).unwrap();

        assert!(
            !info_map.manifest_id.is_empty(),
            "manifestId must be populated from the signed init segment per §19.4"
        );
    }

    #[test]
    fn resume_from_segment_enables_continued_signing() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        let signer = make_test_signer();
        let session_key = make_test_signing_key();

        let mut signer1 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer1.active_manifest_id = Some(TEST_MANIFEST_ID.to_string());
        let seg1 = signer1.sign_media_segment(&make_test_segment()).unwrap();

        let mut signer2 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer2.resume_from_segment(&seg1).unwrap();
        let seg2 = signer2.sign_media_segment(&make_test_segment()).unwrap();

        let map1 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();
        let map2 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();
        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);

        let session_keys = signer2.build_session_keys_assertion();
        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_session_keys(
                &session_keys,
                TEST_MANIFEST_ID,
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();

        validator
            .validate_verifiable_segment_info(&seg1, &mut tracker)
            .unwrap();
        validator
            .validate_verifiable_segment_info(&seg2, &mut tracker)
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
        assert!(failures.is_empty(), "validation failures: {failures:?}");
    }

    /// Regression test: `resume_from_segment` alone (without also calling
    /// `restore_manifest_id_from_signed_init`) must restore `manifestId` from the resumed
    /// segment, not leave it empty. A caller following only the `resume_from_segment` doc
    /// comment — reasonably assuming symmetry with the non-VSI `LiveVideoSigner`, whose
    /// `resume_from_segment` restores full continuity state in one call — must not silently
    /// sign subsequent segments with an empty `manifestId`.
    #[test]
    fn resume_from_segment_alone_restores_manifest_id() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");

        let signer = make_test_signer();
        let session_key = make_test_signing_key();

        let mut signer1 = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer1
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();
        let seg1 = signer1.sign_media_segment(&make_test_segment()).unwrap();

        let mut signer2 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key,
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer2.resume_from_segment(&seg1).unwrap();
        let seg2 = signer2.sign_media_segment(&make_test_segment()).unwrap();

        let map1 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();
        let map2 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();

        assert!(!map1.manifest_id.is_empty());
        assert_eq!(
            map1.manifest_id, map2.manifest_id,
            "resume_from_segment alone must restore manifestId from the resumed segment"
        );
    }

    /// Regression test for the dynamic-manifestId bug: when the CLI is invoked once per
    /// segment (live session), `sign_init_segment` must not be called again.
    /// Instead, `restore_manifest_id_from_signed_init` must produce the same `manifestId`
    /// as the original `sign_init_segment` call.
    #[test]
    fn restore_manifest_id_from_signed_init_matches_original_manifest_id() {
        use crate::live_video::verifiable_segment_info::parse_segment_info_map;

        // Init-segment read-back does full manifest validation; EphemeralSigner certs are
        // intentionally untrusted (see ephemeral_signer.rs), so disable trust checking here.
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");

        let signer = make_test_signer();
        let session_key = make_test_signing_key();

        // Simulate first CLI invocation: sign init + seg_001.
        let mut signer_call1 = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        let signed_init = signer_call1
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();
        let seg1 = signer_call1
            .sign_media_segment(&make_test_segment())
            .unwrap();
        let map1 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg1).unwrap()).unwrap();

        // Simulate second CLI invocation: new signer process, restore state.
        let mut signer_call2 = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer_call2.resume_from_segment(&seg1).unwrap();
        signer_call2
            .restore_manifest_id_from_signed_init(&signed_init, "video/mp4")
            .unwrap();
        let seg2 = signer_call2
            .sign_media_segment(&make_test_segment())
            .unwrap();
        let map2 =
            parse_segment_info_map(&extract_vsi_payload_from_segment(&seg2).unwrap()).unwrap();

        // Both segments must reference the same manifestId.
        assert_eq!(
            map1.manifest_id, map2.manifest_id,
            "manifestId must be identical across per-segment invocations (§19.4)"
        );
        assert!(
            map2.manifest_id.starts_with("urn:c2pa:"),
            "manifestId must be the manifest's c2pa URN label (§8.1), got: {}",
            map2.manifest_id
        );
        assert_eq!(map1.sequence_number, 1);
        assert_eq!(map2.sequence_number, 2);
    }
}
