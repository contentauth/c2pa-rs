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

use c2pa_raw_crypto::validator_for_signing_alg;
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};

use super::{
    box_walk::{box_payload, find_box, top_level_boxes},
    cose_key::{build_ed25519_cose_key, cose_key_to_der, signing_alg_from_cose_key},
    verifiable_segment_info::{VSI_SCHEME_ID_URI, VSI_URI_OFFSET_IN_EMSG},
};
use crate::{
    assertions::{BmffHash, DataMap, ExclusionsMap, SessionKey, SessionKeys},
    builder::Builder,
    crypto::cose::signing_alg_from_sign1,
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
/// key; the box is inserted after any leading `styp`/`sidx`/`prft` boxes.
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
    session_keys: Vec<SessionSigningMaterial>,
    manifest_signer_cert: Vec<u8>,
    keys_need_announcement: bool,
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

struct SessionSigningMaterial {
    session_signing_key: SigningKey,
    session_cose_key: c2pa_cbor::Value,
    kid: Vec<u8>,
    /// COSE_Sign1_Tagged (`18([...])`) bytes of the detached signer binding.
    signer_binding: Vec<u8>,
    min_sequence_number: u64,
    created_at: String,
    validity_period: u64,
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
        if kid.is_empty() || validity_period_secs == 0 {
            return Err(Error::BadParam(
                "session key requires a nonempty kid and positive validity period".into(),
            ));
        }

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
            session_keys: vec![SessionSigningMaterial {
                session_signing_key: signing_key,
                session_cose_key,
                kid,
                signer_binding,
                min_sequence_number,
                created_at,
                validity_period: validity_period_secs,
            }],
            manifest_signer_cert: ee_cert_der,
            keys_need_announcement: false,
            next_sequence_number: min_sequence_number,
            base_manifest_json,
            active_manifest_id: None,
            track_timescale: None,
        })
    }

    /// Adds an Ed25519 key to announce in the next signed initialization segment.
    /// Keys are selected automatically by greatest eligible `minSequenceNumber`.
    /// Add scheduled keys before signing the init segment so receivers learn them first.
    /// To announce keys added later, deliver an updated initialization segment or call
    /// [`Self::sign_media_segment_with_manifest`]. All keys must bind the same manifest signer.
    pub fn add_session_key(
        &mut self,
        manifest_signer: &dyn Signer,
        signing_key: SigningKey,
        kid: impl Into<Vec<u8>>,
        min_sequence_number: u64,
        validity_period_secs: u64,
    ) -> Result<()> {
        self.check_manifest_signer(manifest_signer)?;
        let kid = kid.into();
        if kid.is_empty() || self.session_keys.iter().any(|key| key.kid == kid) {
            return Err(Error::BadParam(
                "session key kid must be nonempty and unique".into(),
            ));
        }
        if min_sequence_number < self.next_sequence_number {
            return Err(Error::BadParam(
                "new session key minSequenceNumber is below the current sequence number".into(),
            ));
        }
        let mut other = Self::from_signing_key(
            self.base_manifest_json.clone(),
            manifest_signer,
            signing_key,
            kid,
            min_sequence_number,
            validity_period_secs,
        )?;
        self.session_keys.append(&mut other.session_keys);
        // New keys must be announced before any further segment can reference them.
        self.active_manifest_id = None;
        self.keys_need_announcement = true;
        Ok(())
    }

    fn check_manifest_signer(&self, signer: &dyn Signer) -> Result<()> {
        if signer.certs()?.first() != Some(&self.manifest_signer_cert) {
            return Err(Error::BadParam(
                "manifest signer differs from the session keys' signerBinding certificate".into(),
            ));
        }
        Ok(())
    }

    fn key_for_sequence(&self, sequence: u64) -> Result<&SessionSigningMaterial> {
        self.session_keys
            .iter()
            .filter(|key| key.min_sequence_number <= sequence)
            .max_by_key(|key| key.min_sequence_number)
            .ok_or_else(|| {
                Error::BadParam("no session key is valid for this sequence number".into())
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
        self.check_manifest_signer(manifest_signer)?;
        self.track_timescale = parse_first_mdhd_timescale(segment_data);

        let session_keys = self.build_session_keys_assertion()?;
        let mut builder = Builder::from_context(super::context_from_thread_local_settings()?)
            .with_definition(self.base_manifest_json.as_str())?;
        builder.add_assertion(SessionKeys::LABEL, &session_keys)?;

        let mut source = std::io::Cursor::new(segment_data);
        let mut dest = std::io::Cursor::new(Vec::new());
        builder.sign(manifest_signer, format, &mut source, &mut dest)?;
        let signed_bytes = dest.into_inner();

        self.capture_manifest_id(&signed_bytes, format)?;
        self.keys_need_announcement = false;

        Ok(signed_bytes)
    }

    /// Signs a media segment by inserting a COSE_Sign1 `emsg` box.
    ///
    /// The box goes after any leading `styp`, `sidx` and `prft` boxes and before the
    /// first `moof` (ISO/IEC 23009-1 and CMAF require `styp`, when present, to be the
    /// first box of a media segment). A single-level `sidx` has its first
    /// `referenced_size` grown by the size of the `emsg`, which becomes part of the
    /// first subsegment. Segments with an `ssix`, more than one `sidx`, or a `sidx`
    /// that references another `sidx` are rejected.
    ///
    /// The COSE_Sign1 payload is a CBOR `SegmentInfoMap` with the current
    /// sequence number, a `bmffHash` covering the segment data excluding VSI
    /// `emsg` boxes, and the `manifestId` from the signed init segment per §19.4.
    pub fn sign_media_segment(&mut self, segment_data: &[u8]) -> Result<Vec<u8>> {
        if self.keys_need_announcement {
            return Err(Error::BadParam(
                "announce added session keys before signing media segments".into(),
            ));
        }
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
        let key = self.key_for_sequence(sequence_number)?;

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
        let event_duration = parse_segment_duration_ticks(segment_data).unwrap_or(0);
        // Truncation is safe: a live session realistically never reaches u32::MAX segments,
        // and the id only needs to be unique within the session (§19.4.2), not globally.
        let id = sequence_number as u32;

        // Two passes: the offset-prefix (§18.6.2) must reflect each box's absolute offset
        // in the final segment (segment_data with emsg inserted), which requires knowing emsg's size
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
                build_vsi_cose_sign1(&segment_info_map, &key.session_signing_key, &key.kid)?;
            build_emsg_box(&cose_sign1_bytes, timescale, event_duration, id)
        };

        let insert_at = vsi_emsg_insertion_point(segment_data)?;
        let draft_emsg_box = build_emsg(build_segment_bmff_hash_placeholder()?)?;
        let draft_segment = insert_emsg_box(segment_data, insert_at, &draft_emsg_box)?;
        let bmff_hash = build_segment_bmff_hash(&draft_segment)?;

        let emsg_box = build_emsg(bmff_hash)?;
        if draft_emsg_box.len() != emsg_box.len() {
            return Err(Error::BadParam(
                "draft and final VSI emsg boxes differ in size; the c2pa.hash.bmff.v3 \
                 offset-prefix scheme would be computed against the wrong box offsets"
                    .to_string(),
            ));
        }

        let signed_segment = insert_emsg_box(segment_data, insert_at, &emsg_box)?;

        self.next_sequence_number += 1;
        Ok(signed_segment)
    }

    /// Signs a media segment carrying a manifest that announces the current keys.
    ///
    /// Use this after adding a key during a running session. The context must contain
    /// the manifest signer used to bind those keys. Both the manifest hard binding and
    /// the VSI hash are computed over their final box offsets. The input must start
    /// with `styp` or `ftyp`; indexed segments (`sidx`/`ssix`) are not supported.
    pub fn sign_media_segment_with_manifest(
        &mut self,
        segment_data: &[u8],
        context: std::sync::Arc<crate::Context>,
    ) -> Result<Vec<u8>> {
        self.check_manifest_signer(context.signer()?)?;
        let sequence = self.next_sequence_number;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| Error::BadParam("VSI sequence number overflow".into()))?;
        let key = self.key_for_sequence(sequence)?;
        if find_box(segment_data, b"sidx").is_some() || find_box(segment_data, b"ssix").is_some() {
            return Err(Error::BadParam(
                "indexed media segments are not supported when announcing session keys".into(),
            ));
        }
        if !super::box_walk::top_level_boxes(segment_data)
            .next()
            .is_some_and(|(kind, _)| kind == b"styp" || kind == b"ftyp")
        {
            return Err(Error::BadParam(
                "session-key update segment must start with styp or ftyp".into(),
            ));
        }
        if let Some(number) = moof_sequence_number(segment_data) {
            if u64::from(number) != sequence {
                return Err(Error::BadParam(
                    "segment sequence number does not match signer counter".into(),
                ));
            }
        }
        let mut builder = Builder::from_shared_context(&context)
            .with_definition(self.base_manifest_json.as_str())?;
        let label = crate::claim::Claim::new("", None, 2).label().to_string();
        builder.definition.label = Some(label.clone());
        builder.add_assertion(SessionKeys::LABEL, &self.build_session_keys_assertion()?)?;
        let mut hash = BmffHash::new("jumbf manifest", "sha256", None);
        hash.set_default_exclusions_with_options(context.settings());
        hash.add_exclusions(&mut vec![vsi_emsg_exclusion()]);
        hash.set_hash(vec![0; 32]);
        builder.add_assertion("c2pa.hash.bmff.v3", &hash)?;
        let placeholder = builder.placeholder("video/mp4")?;
        let timescale = self.track_timescale.unwrap_or(1);
        let duration = parse_segment_duration_ticks(segment_data).unwrap_or(0);
        let make_emsg = |bmff_hash| -> Result<Vec<u8>> {
            let map = SegmentInfoMap {
                sequence_number: sequence,
                bmff_hash,
                manifest_id: label.clone(),
                manifest_uri: None,
            };
            build_emsg_box(
                &build_vsi_cose_sign1(&map, &key.session_signing_key, &key.kid)?,
                timescale,
                duration,
                sequence as u32,
            )
        };
        let draft_emsg = make_emsg(build_segment_bmff_hash_placeholder()?)?;
        // Preserve a leading styp/ftyp; put the manifest and VSI before remaining boxes.
        let insertion = super::box_walk::top_level_boxes(segment_data)
            .next()
            .filter(|(kind, _)| *kind == b"styp" || *kind == b"ftyp")
            .map_or(0, |(_, bytes)| bytes.len());
        let mut output = segment_data[..insertion].to_vec();
        output.extend_from_slice(&placeholder);
        let emsg_offset = output.len();
        output.extend_from_slice(&draft_emsg);
        output.extend_from_slice(&segment_data[insertion..]);
        builder.update_hash_from_stream("video/mp4", &mut std::io::Cursor::new(&output))?;
        let manifest = builder.sign_embeddable("video/mp4")?;
        if manifest.len() != placeholder.len() {
            return Err(Error::BadParam(
                "signed manifest does not fit its placeholder".into(),
            ));
        }
        output[insertion..emsg_offset].copy_from_slice(&manifest);
        let emsg = make_emsg(build_segment_bmff_hash(&output)?)?;
        if emsg.len() != draft_emsg.len() {
            return Err(Error::BadParam(
                "signed VSI does not fit its placeholder".into(),
            ));
        }
        output[emsg_offset..emsg_offset + emsg.len()].copy_from_slice(&emsg);
        self.active_manifest_id = Some(label);
        self.keys_need_announcement = false;
        self.next_sequence_number = next_sequence;
        Ok(output)
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
        use crate::assertion::AssertionBase;
        let reader = Reader::from_context(super::context_from_thread_local_settings()?)
            .with_stream(format, std::io::Cursor::new(signed_init_data))?;
        let manifest_id = reader
            .active_manifest()
            .and_then(|manifest| manifest.label())
            .ok_or_else(|| Error::BadParam("signed init has no manifest label".into()))?;
        let claim = reader.store.get_claim(manifest_id).ok_or(Error::NotFound)?;
        let keys = SessionKeys::from_assertion(
            claim
                .get_assertion(SessionKeys::LABEL, 0)
                .ok_or(Error::NotFound)?,
        )?;
        // A resumed schedule must contain only keys authorized by the restored manifest.
        let authorized = self
            .session_keys
            .iter()
            .map(|key| {
                keys.keys
                    .iter()
                    .find(|announced| announced.key == key.session_cose_key)
                    .ok_or_else(|| {
                        Error::BadParam(
                            "configured session key was not announced in the signed init".into(),
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        for (key, announced) in self.session_keys.iter_mut().zip(authorized) {
            key.min_sequence_number = announced.min_sequence_number;
            key.created_at = announced.created_at.to_string();
            key.validity_period = announced.validity_period;
        }
        self.active_manifest_id = Some(manifest_id.to_string());
        self.keys_need_announcement = false;
        self.track_timescale = parse_first_mdhd_timescale(signed_init_data);
        Ok(())
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

        // Verify the COSE_Sign1 signature before trusting the deserialized sequence
        // number. An attacker with write access to the output directory could otherwise
        // inject a tampered sequence number to cause subsequent segments to be signed
        // with an attacker-chosen value.
        self.verify_vsi_sign1(&parsed.sign1)?;

        self.next_sequence_number = parsed.segment_info_map.sequence_number + 1;
        if !parsed.segment_info_map.manifest_id.is_empty() {
            self.active_manifest_id = Some(parsed.segment_info_map.manifest_id);
        }
        Ok(())
    }

    /// Verifies a VSI COSE_Sign1 against the signer's own session public key.
    fn verify_vsi_sign1(&self, sign1: &coset::CoseSign1) -> Result<()> {
        let key = self
            .session_keys
            .iter()
            .find(|key| key.kid == sign1.unprotected.key_id)
            .ok_or_else(|| {
                Error::BadParam("previous segment uses an unknown session key".into())
            })?;
        let key_alg = signing_alg_from_cose_key(&key.session_cose_key)
            .ok_or_else(|| Error::BadParam("unsupported session key algorithm".into()))?;

        let header_alg = signing_alg_from_sign1(sign1)
            .map_err(|_| Error::BadParam("VSI COSE_Sign1 protected header missing `alg`".into()))?;

        if header_alg != key_alg {
            return Err(Error::BadParam(format!(
                "VSI COSE_Sign1 `alg` ({header_alg:?}) does not match session key ({key_alg:?})"
            )));
        }

        let public_key_der = cose_key_to_der(&key.session_cose_key)
            .ok_or_else(|| Error::BadParam("failed to convert session key to DER".into()))?;

        let validator = validator_for_signing_alg(key_alg)
            .ok_or_else(|| Error::BadParam(format!("no validator for {key_alg:?}")))?;

        let tbs = sign1.tbs_data(b"");

        validator
            .validate(&sign1.signature, &tbs, &public_key_der)
            .map_err(|e| Error::BadParam(format!("VSI signature verification failed: {e}")))
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

    fn build_session_keys_assertion(&self) -> Result<SessionKeys> {
        Ok(SessionKeys {
            keys: self
                .session_keys
                .iter()
                .map(|key| {
                    SessionKey::new(
                        key.session_cose_key.clone(),
                        key.min_sequence_number,
                        key.created_at.clone(),
                        key.validity_period,
                        &key.signer_binding,
                    )
                })
                .collect::<Result<Vec<_>>>()?,
        })
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
/// raw segment data with the (draft or real) `emsg` box inserted — so that the
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

fn build_signer_binding(ee_cert_der: &[u8], session_signing_key: &SigningKey) -> Result<Vec<u8>> {
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

    // The COSE_Sign1_Tagged (`18([...])`) bytes; `SessionKey::new` decodes these into the
    // native tagged CBOR value stored in the assertion per §18.25.
    sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode signer binding: {e}")))
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
    //
    // The label uses the text form `"iat"` rather than an integer because integer labels 1-7
    // in a COSE protected header are reserved for core COSE parameters (RFC 9052 §3.1) and
    // coset enforces this at runtime. Integer 6 in COSE is `partial_iv`, not `iat`.
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
) -> Result<Vec<u8>> {
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

    // 8 bytes header + 4 bytes version/flags + body.
    // Use checked arithmetic so an unexpectedly large COSE payload is caught
    // rather than silently truncating the size field (which the two-pass
    // draft/final guard would not catch, since both passes share the same
    // computation).
    let body_len =
        u32::try_from(body.len()).map_err(|_| Error::BadParam("emsg body too large".into()))?;

    let total_size = 8u32
        .checked_add(4)
        .and_then(|n| n.checked_add(body_len))
        .ok_or_else(|| Error::BadParam("emsg box size overflows u32".into()))?
        .to_be_bytes();

    let mut emsg = Vec::new();
    emsg.extend_from_slice(&total_size);
    emsg.extend_from_slice(b"emsg");
    emsg.push(0); // version 0
    emsg.extend_from_slice(&[0u8; 3]); // flags
    emsg.extend_from_slice(&body);
    Ok(emsg)
}

// ── emsg placement ───────────────────────────────────────────────────────────
//
// ISO/IEC 23009-1 (§6.3.4.2) and CMAF require `styp`, when present, to be the first
// box of a media segment, followed by any `sidx`/`prft` boxes, then `emsg` boxes,
// then the first `moof`.

/// Returns the byte offset at which the VSI `emsg` box is inserted: after the leading
/// `styp`, `sidx` and `prft` boxes, before anything else (normally the first `moof`
/// or an existing `emsg`).
fn vsi_emsg_insertion_point(segment_data: &[u8]) -> Result<usize> {
    let mut insert_at = 0;
    let mut sidx_count = 0;
    for (fourcc, box_bytes) in top_level_boxes(segment_data) {
        match fourcc {
            b"styp" | b"prft" => {}
            b"sidx" => sidx_count += 1,
            b"ssix" => {
                return Err(Error::BadParam(
                    "VSI signing does not support media segments with an ssix box".into(),
                ))
            }
            _ => break,
        }
        insert_at += box_bytes.len();
    }
    if sidx_count > 1 {
        return Err(Error::BadParam(
            "VSI signing does not support media segments with more than one sidx box".into(),
        ));
    }
    Ok(insert_at)
}

/// Returns `segment_data` with `emsg_box` inserted at `insert_at` (from
/// [`vsi_emsg_insertion_point`]), growing a leading `sidx`'s first reference to cover it.
fn insert_emsg_box(segment_data: &[u8], insert_at: usize, emsg_box: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(segment_data.len() + emsg_box.len());
    out.extend_from_slice(&segment_data[..insert_at]);
    out.extend_from_slice(emsg_box);
    out.extend_from_slice(&segment_data[insert_at..]);
    grow_first_sidx_reference(&mut out[..insert_at], emsg_box.len())?;
    Ok(out)
}

/// The `emsg` box sits between the `sidx` and the first `moof`, so it belongs to the
/// first subsegment: grow that reference's `referenced_size` (ISO/IEC 14496-12 §8.16.3)
/// by `by` bytes. Does nothing when `leading` has no `sidx` or the `sidx` has no references.
fn grow_first_sidx_reference(leading: &mut [u8], by: usize) -> Result<()> {
    let mut sidx_start = None;
    let mut pos = 0;
    for (fourcc, box_bytes) in top_level_boxes(leading) {
        if fourcc == b"sidx" {
            sidx_start = Some(pos);
            break;
        }
        pos += box_bytes.len();
    }
    let Some(sidx_start) = sidx_start else {
        return Ok(());
    };

    let sidx = &mut leading[sidx_start..];
    let read_be = |sidx: &[u8], at: usize, len: usize| -> Result<u32> {
        let bytes = sidx
            .get(at..at + len)
            .ok_or_else(|| Error::BadParam("malformed sidx box".into()))?;
        Ok(bytes.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)))
    };
    let header_len = if read_be(sidx, 0, 4)? == 1 { 16 } else { 8 };
    let version = read_be(sidx, header_len, 1)?;
    // FullBox header(4) + reference_ID(4) + timescale(4)
    // + earliest_presentation_time and first_offset (4 + 4 for version 0, 8 + 8 otherwise)
    // + reserved(2)
    let reference_count_at = header_len + 12 + if version == 0 { 8 } else { 16 } + 2;
    if read_be(sidx, reference_count_at, 2)? == 0 {
        return Ok(());
    }

    let first_ref_at = reference_count_at + 2;
    let value = read_be(sidx, first_ref_at, 4)?;
    if value & 0x8000_0000 != 0 {
        return Err(Error::BadParam(
            "VSI signing does not support a sidx that references another sidx".into(),
        ));
    }
    let referenced_size = u32::try_from(by)
        .ok()
        .and_then(|by| (value & 0x7fff_ffff).checked_add(by))
        .filter(|size| *size <= 0x7fff_ffff)
        .ok_or_else(|| Error::BadParam("sidx referenced_size overflows".into()))?;
    sidx[first_ref_at..first_ref_at + 4].copy_from_slice(&referenced_size.to_be_bytes());
    Ok(())
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
pub(super) fn parse_first_mdhd_timescale(init_data: &[u8]) -> Option<u32> {
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

/// Sums the `moof/traf/tfhd`+`trun` sample durations of every `moof` in a media
/// segment (a CMAF segment can hold several chunks), in the track's timescale
/// ticks (per ISO/IEC 14496-12 §8.8.7–8.8.8). Returns `None` when the segment
/// has no `moof`, or any `moof`'s duration can't be determined.
pub(super) fn parse_segment_duration_ticks(segment_data: &[u8]) -> Option<u32> {
    let mut total: u64 = 0;
    let mut found_moof = false;
    for (fourcc, moof_box) in top_level_boxes(segment_data) {
        if fourcc == b"moof" {
            total += u64::from(moof_duration_ticks(box_payload(moof_box)?)?);
            found_moof = true;
        }
    }
    found_moof.then(|| total.min(u64::from(u32::MAX)) as u32)
}

/// Parses `moof/traf/tfdt`'s `baseMediaDecodeTime` (ISO/IEC 14496-12 §8.8.12) of the
/// first `moof` in a media segment: the segment's earliest decode time, in track
/// timescale ticks.
pub(super) fn parse_first_tfdt(segment_data: &[u8]) -> Option<u64> {
    let moof = box_payload(find_box(segment_data, b"moof")?)?;
    let traf = box_payload(find_box(moof, b"traf")?)?;
    let tfdt = box_payload(find_box(traf, b"tfdt")?)?;
    if *tfdt.first()? == 1 {
        Some(u64::from_be_bytes(tfdt.get(4..12)?.try_into().ok()?))
    } else {
        Some(u64::from(u32::from_be_bytes(
            tfdt.get(4..8)?.try_into().ok()?,
        )))
    }
}

/// Parses a top-level `prft` box (ISO/IEC 14496-12 §8.16.5) into its
/// `(ntp_timestamp, media_time)` pair: the 64-bit NTP wall-clock time at which the
/// sample with `media_time` (in track timescale ticks) was produced.
pub(super) fn parse_prft(segment_data: &[u8]) -> Option<(u64, u64)> {
    let prft = box_payload(find_box(segment_data, b"prft")?)?;
    // FullBox header(4) + reference_track_ID(4)
    let ntp_timestamp = u64::from_be_bytes(prft.get(8..16)?.try_into().ok()?);
    let media_time = if *prft.first()? == 0 {
        u64::from(u32::from_be_bytes(prft.get(16..20)?.try_into().ok()?))
    } else {
        u64::from_be_bytes(prft.get(16..24)?.try_into().ok()?)
    };
    Some((ntp_timestamp, media_time))
}

/// Duration of one `moof`'s first `traf`. Falls back to `tfhd`'s
/// `default_sample_duration * sample_count` when `trun` doesn't carry
/// per-sample durations.
fn moof_duration_ticks(moof: &[u8]) -> Option<u32> {
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
    use crate::live_video::verifiable_segment_info::parse_vsi;
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
        assert_eq!(parse_segment_duration_ticks(&seg), Some(3000));
    }

    /// A CMAF segment made of several chunks: the duration covers every `moof`.
    #[test]
    fn segment_duration_sums_every_moof() {
        let seg = [
            make_test_media_segment_with_moof(&[1000, 1000]),
            make_test_media_segment_with_moof(&[500]),
        ]
        .concat();
        assert_eq!(parse_segment_duration_ticks(&seg), Some(2500));
    }

    /// A segment signed with the track timescale from the init segment passes the
    /// validator's `emsg` timing checks once it has seen the same init segment.
    #[test]
    fn signed_segment_passes_emsg_timing_validation() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);
        let init = make_test_init_segment(1000);
        vsi_signer.track_timescale = parse_first_mdhd_timescale(&init);

        let segment = [
            make_test_media_segment_with_moof(&[1000, 1000]),
            make_test_media_segment_with_moof(&[1000]),
        ]
        .concat();
        let signed = vsi_signer.sign_media_segment(&segment).unwrap();

        let session_keys = vsi_signer.build_session_keys_assertion().unwrap();
        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .unwrap();
        validator
            .validate_session_keys(
                &session_keys,
                TEST_MANIFEST_ID,
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();
        validator
            .validate_verifiable_segment_info(&signed, &mut tracker)
            .unwrap();

        let failures: Vec<_> = tracker
            .logged_items()
            .iter()
            .filter_map(|i| i.validation_status.as_deref())
            .filter(|s| s.starts_with("livevideo"))
            .collect();
        assert!(failures.is_empty(), "unexpected failures: {failures:?}");
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

        assert_eq!(parse_segment_duration_ticks(&moof), Some(8000));
    }

    #[test]
    fn parsers_return_none_for_segments_without_the_relevant_boxes() {
        let plain_segment = make_test_segment();
        assert_eq!(parse_first_mdhd_timescale(&plain_segment), None);
        assert_eq!(parse_segment_duration_ticks(&plain_segment), None);
    }

    /// Regression test: a `tfhd`/`trun` box truncated shorter than its own fixed fields must
    /// return `None`, not panic, since these parsers run on attacker-controlled segment bytes.
    #[test]
    fn parsers_return_none_for_truncated_boxes_instead_of_panicking() {
        // `tfhd` with no payload at all (not even the FullBox version/flags bytes).
        let empty_tfhd = make_box(b"tfhd", &[]);
        let traf = make_box(b"traf", &empty_tfhd);
        let moof = make_box(b"moof", &traf);
        assert_eq!(parse_segment_duration_ticks(&moof), None);

        // `tfhd` present and well-formed, but `trun` truncated to nothing.
        let tfhd_payload = 1u32.to_be_bytes();
        let tfhd = make_fullbox(b"tfhd", 0, 0, &tfhd_payload);
        let empty_trun = make_box(b"trun", &[]);
        let traf = make_box(b"traf", &[tfhd, empty_trun].concat());
        let moof = make_box(b"moof", &traf);
        assert_eq!(parse_segment_duration_ticks(&moof), None);

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

    fn top_level_types(data: &[u8]) -> Vec<[u8; 4]> {
        top_level_boxes(data).map(|(fourcc, _)| *fourcc).collect()
    }

    /// A version 0 `sidx` with one reference per `(reference_type, referenced_size)`.
    fn make_sidx(references: &[(bool, u32)]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_be_bytes()); // reference_ID
        payload.extend_from_slice(&1000u32.to_be_bytes()); // timescale
        payload.extend_from_slice(&0u32.to_be_bytes()); // earliest_presentation_time
        payload.extend_from_slice(&0u32.to_be_bytes()); // first_offset
        payload.extend_from_slice(&0u16.to_be_bytes()); // reserved
        payload.extend_from_slice(&(references.len() as u16).to_be_bytes());
        for (is_sidx, size) in references {
            let type_and_size = if *is_sidx { size | 0x8000_0000 } else { *size };
            payload.extend_from_slice(&type_and_size.to_be_bytes());
            payload.extend_from_slice(&1000u32.to_be_bytes()); // subsegment_duration
            payload.extend_from_slice(&0x9000_0000u32.to_be_bytes()); // starts_with_SAP, SAP_type 1
        }
        make_fullbox(b"sidx", 0, 0, &payload)
    }

    /// First reference's `referenced_size` of the first top-level `sidx` in `data`.
    fn first_sidx_referenced_size(data: &[u8]) -> u32 {
        let sidx = find_box(data, b"sidx").unwrap();
        // header(8) + FullBox(4) + reference_ID(4) + timescale(4) + ept(4) + first_offset(4)
        // + reserved(2) + reference_count(2)
        u32::from_be_bytes(sidx[32..36].try_into().unwrap()) & 0x7fff_ffff
    }

    fn make_scte35_emsg() -> Vec<u8> {
        let mut body = vec![0u8; 4]; // version 0, flags
        body.extend_from_slice(b"urn:scte:scte35:2013:bin\0\0");
        body.extend_from_slice(&[0u8; 16]); // timescale, presentation_time_delta, duration, id
        body.extend_from_slice(&[0xfc, 0x30]); // start of a splice_info_section
        make_box(b"emsg", &body)
    }

    /// Validates `signed` with the session keys of `vsi_signer` and returns the `livevideo.*`
    /// failure codes.
    fn vsi_validation_failures(
        signer: &EphemeralSigner,
        vsi_signer: &LiveVideoVsiSigner,
        signed: &[u8],
    ) -> Vec<String> {
        let session_keys = vsi_signer.build_session_keys_assertion().unwrap();
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
        let _ = validator.validate_verifiable_segment_info(signed, &mut tracker);
        tracker
            .logged_items()
            .iter()
            .filter_map(|i| i.validation_status.as_deref())
            .filter(|s| s.starts_with("livevideo"))
            .map(str::to_string)
            .collect()
    }

    fn rotation_media_segment() -> Vec<u8> {
        [
            make_box(b"styp", b"cmfs\0\0\0\0cmfs"),
            make_box(b"mdat", &[1, 2, 3, 4]),
        ]
        .concat()
    }

    fn rotation_context() -> std::sync::Arc<crate::Context> {
        std::sync::Arc::new(
            crate::Context::new()
                .with_settings(
                    crate::settings::Settings::new()
                        .with_json(r#"{"verify":{"verify_trust":false}}"#)
                        .unwrap(),
                )
                .unwrap()
                .with_signer(make_test_signer()),
        )
    }

    fn rotation_signer(context: &crate::Context) -> LiveVideoVsiSigner {
        let mut signer = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            context.signer().unwrap(),
            make_test_signing_key(),
            b"old".to_vec(),
            1,
            3600,
        )
        .unwrap();
        signer.active_manifest_id = Some(TEST_MANIFEST_ID.to_string());
        signer
    }

    fn register_keys(
        validator: &mut LiveVideoValidator,
        signer: &LiveVideoVsiSigner,
        context: &crate::Context,
        id: &str,
    ) {
        let cert = context.signer().unwrap().certs().unwrap().remove(0);
        let mut tracker = StatusTracker::default();
        validator
            .validate_session_keys(
                &signer.build_session_keys_assertion().unwrap(),
                id,
                Some(&cert),
                &mut tracker,
            )
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0);
    }

    #[test]
    fn scheduled_rotation_selects_key_at_boundary_and_resumes_with_either_key() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        signer
            .add_session_key(
                context.signer().unwrap(),
                make_test_signing_key(),
                b"new".to_vec(),
                2,
                3600,
            )
            .unwrap();
        signer.active_manifest_id = Some(TEST_MANIFEST_ID.to_string());
        signer.keys_need_announcement = false;
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        let first = signer.sign_media_segment(&make_test_segment()).unwrap();
        let second = signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(
            parse_vsi(&extract_vsi_payload_from_segment(&first).unwrap())
                .unwrap()
                .sign1
                .unprotected
                .key_id,
            b"old"
        );
        assert_eq!(
            parse_vsi(&extract_vsi_payload_from_segment(&second).unwrap())
                .unwrap()
                .sign1
                .unprotected
                .key_id,
            b"new"
        );
        for segment in [&first, &second] {
            let mut tracker = StatusTracker::default();
            validator
                .validate_verifiable_segment_info(segment, &mut tracker)
                .unwrap();
            assert_eq!(tracker.filter_errors().count(), 0);
            signer.resume_from_segment(segment).unwrap();
        }
        assert_eq!(signer.next_sequence_number(), 3);
    }

    #[test]
    fn embedded_manifest_announces_unknown_key_and_retains_previous_manifest() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        let first = signer.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info(&first, &mut StatusTracker::default())
            .unwrap();
        signer
            .add_session_key(
                context.signer().unwrap(),
                make_test_signing_key(),
                b"new".to_vec(),
                2,
                3600,
            )
            .unwrap();
        let update = signer
            .sign_media_segment_with_manifest(&rotation_media_segment(), context.clone())
            .unwrap();
        let mut tracker = StatusTracker::default();
        validator
            .validate_verifiable_segment_info_with_context(&update, &context, &mut tracker)
            .unwrap();
        assert_eq!(
            tracker.filter_errors().count(),
            0,
            "{:?}",
            tracker.logged_items()
        );
        assert_eq!(validator.session_keys.len(), 3); // old manifest + both keys in new manifest
        let id = signer.active_manifest_id.clone().unwrap();
        assert_ne!(id, TEST_MANIFEST_ID);
        let following = signer.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info_with_context(&following, &context, &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0);
        assert_eq!(
            validator.session_key_manifest_state(),
            Some(crate::ValidationState::Valid)
        );
        // Earlier keys still authorize later segments under their original manifest.
        signer.session_keys.pop();
        signer.active_manifest_id = Some(TEST_MANIFEST_ID.to_string());
        let old_key = signer.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info(&old_key, &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0);
    }

    #[test]
    fn embedded_manifest_tampering_does_not_install_keys() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        signer
            .add_session_key(
                context.signer().unwrap(),
                make_test_signing_key(),
                b"new".to_vec(),
                1,
                3600,
            )
            .unwrap();
        let mut update = signer
            .sign_media_segment_with_manifest(&rotation_media_segment(), context.clone())
            .unwrap();
        *update.last_mut().unwrap() ^= 1;
        let mut tracker = StatusTracker::default();
        validator
            .validate_verifiable_segment_info_with_context(&update, &context, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.validation_status.as_deref() == Some("livevideo.manifest.invalid")));
        assert_eq!(validator.session_keys.len(), 1);
        assert!(validator.previous_segment.is_none());
    }

    #[test]
    fn embedded_manifest_id_must_match_the_vsi_even_with_a_valid_signature() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        signer
            .add_session_key(
                context.signer().unwrap(),
                make_test_signing_key(),
                b"new".to_vec(),
                1,
                3600,
            )
            .unwrap();
        let mut update = signer
            .sign_media_segment_with_manifest(&rotation_media_segment(), context.clone())
            .unwrap();
        let parsed = parse_vsi(&extract_vsi_payload_from_segment(&update).unwrap()).unwrap();
        let mut map = parsed.segment_info_map;
        let last = map.manifest_id.pop().unwrap();
        map.manifest_id.push(if last == 'a' { 'b' } else { 'a' });
        let key = signer.key_for_sequence(1).unwrap();
        let emsg = build_emsg_box(
            &build_vsi_cose_sign1(&map, &key.session_signing_key, &key.kid).unwrap(),
            1,
            0,
            1,
        )
        .unwrap();
        let old_emsg = find_box(&update, b"emsg").unwrap();
        let offset = old_emsg.as_ptr() as usize - update.as_ptr() as usize;
        assert_eq!(emsg.len(), old_emsg.len());
        update[offset..offset + emsg.len()].copy_from_slice(&emsg);
        let mut tracker = StatusTracker::default();
        validator
            .validate_verifiable_segment_info_with_context(&update, &context, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.validation_status.as_deref() == Some("livevideo.segment.invalid")));
        assert_eq!(validator.session_keys.len(), 1);
    }

    #[test]
    fn embedded_manifest_uses_the_receivers_trust_policy() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        signer
            .add_session_key(
                context.signer().unwrap(),
                make_test_signing_key(),
                b"new".to_vec(),
                1,
                3600,
            )
            .unwrap();
        let update = signer
            .sign_media_segment_with_manifest(&rotation_media_segment(), context.clone())
            .unwrap();
        let receiver = std::sync::Arc::new(crate::Context::new());
        let mut tracker = StatusTracker::default();
        validator
            .validate_verifiable_segment_info_with_context(&update, &receiver, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.validation_status.as_deref() == Some("livevideo.manifest.invalid")));
        assert_eq!(validator.session_keys.len(), 1);
    }

    #[test]
    fn update_rejects_retroactive_keys_and_preserves_existing_keys() {
        let context = rotation_context();
        let signer = rotation_signer(&context);
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        let mut other = rotation_signer(&context);
        other.session_keys[0].kid = b"new".to_vec();
        other.session_keys[0].session_cose_key = build_ed25519_cose_key(
            &other.session_keys[0].session_signing_key.verifying_key(),
            b"new",
        );
        let cert = context.signer().unwrap().certs().unwrap().remove(0);
        let mut tracker = StatusTracker::default();
        validator
            .validate_session_key_update(
                &other.build_session_keys_assertion().unwrap(),
                "urn:c2pa:update",
                Some(&cert),
                2,
                &mut tracker,
            )
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 1);
        assert_eq!(validator.session_keys.len(), 1);
    }

    #[test]
    fn key_must_be_authorized_by_the_vsi_manifest() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        signer.active_manifest_id = Some("urn:c2pa:other".to_string());
        let segment = signer.sign_media_segment(&make_test_segment()).unwrap();
        let mut tracker = StatusTracker::default();
        assert!(validator
            .validate_verifiable_segment_info(&segment, &mut tracker)
            .is_err());
        assert_eq!(tracker.filter_errors().count(), 1);
    }

    #[test]
    fn restoring_init_rejects_a_key_added_after_that_init_was_signed() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        let init =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
        let signed_init = signer
            .sign_init_segment(init, "video/mp4", context.signer().unwrap())
            .unwrap();
        signer
            .add_session_key(
                context.signer().unwrap(),
                make_test_signing_key(),
                b"new".to_vec(),
                2,
                3600,
            )
            .unwrap();
        assert!(signer
            .restore_manifest_id_from_signed_init(&signed_init, "video/mp4")
            .is_err());
        assert!(signer.sign_media_segment(&make_test_segment()).is_err());
    }

    #[test]
    fn duplicate_key_ids_in_an_assertion_do_not_replace_cached_keys() {
        let context = rotation_context();
        let signer = rotation_signer(&context);
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        let mut keys = signer.build_session_keys_assertion().unwrap();
        keys.keys.push(keys.keys[0].clone());
        let cert = context.signer().unwrap().certs().unwrap().remove(0);
        let mut tracker = StatusTracker::default();
        validator
            .validate_session_keys(&keys, "urn:c2pa:update", Some(&cert), &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 1);
        assert_eq!(validator.session_keys.len(), 1);
    }

    #[test]
    fn adding_keys_rejects_duplicate_ids_and_requires_an_announcement() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        assert!(signer
            .add_session_key(
                context.signer().unwrap(),
                make_test_signing_key(),
                b"old".to_vec(),
                1,
                3600
            )
            .is_err());
        signer
            .add_session_key(
                context.signer().unwrap(),
                make_test_signing_key(),
                b"new".to_vec(),
                2,
                3600,
            )
            .unwrap();
        assert!(signer.sign_media_segment(&make_test_segment()).is_err());
        assert_eq!(signer.next_sequence_number(), 1);
    }

    #[test]
    fn sign_media_segment_puts_emsg_after_styp() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);

        let styp = make_box(b"styp", b"msdhmsdh");
        let segment = [styp.clone(), make_test_media_segment_with_moof(&[1000])].concat();
        let signed = vsi_signer.sign_media_segment(&segment).unwrap();

        assert_eq!(
            top_level_types(&signed),
            [*b"styp", *b"emsg", *b"moof", *b"mdat"]
        );
        assert_eq!(&signed[..styp.len()], styp.as_slice());
        assert!(vsi_validation_failures(&signer, &vsi_signer, &signed).is_empty());
    }

    #[test]
    fn sign_media_segment_puts_emsg_after_sidx_and_prft_and_grows_sidx() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);

        let media = [
            make_scte35_emsg(),
            make_test_media_segment_with_moof(&[1000]),
        ]
        .concat();
        let segment = [
            make_box(b"styp", b"msdhmsdh"),
            make_sidx(&[(false, media.len() as u32)]),
            make_fullbox(b"prft", 0, 0, &[0u8; 12]),
            media.clone(),
        ]
        .concat();
        let signed = vsi_signer.sign_media_segment(&segment).unwrap();

        assert_eq!(
            top_level_types(&signed),
            [*b"styp", *b"sidx", *b"prft", *b"emsg", *b"emsg", *b"moof", *b"mdat"]
        );
        // The VSI emsg comes first of the two; the SCTE-35 one is untouched.
        let vsi_emsg_len = signed.len() - segment.len();
        assert_eq!(
            first_sidx_referenced_size(&signed),
            (media.len() + vsi_emsg_len) as u32
        );
        assert!(vsi_validation_failures(&signer, &vsi_signer, &signed).is_empty());
    }

    #[test]
    fn sign_media_segment_rejects_unsupported_index_layouts() {
        let signer = make_test_signer();
        let media = make_test_media_segment_with_moof(&[1000]);
        let cases = [
            (
                "ssix",
                [
                    make_sidx(&[(false, 100)]),
                    make_fullbox(b"ssix", 0, 0, &0u32.to_be_bytes()),
                    media.clone(),
                ]
                .concat(),
            ),
            (
                "two sidx",
                [
                    make_sidx(&[(false, 100)]),
                    make_sidx(&[(false, 100)]),
                    media.clone(),
                ]
                .concat(),
            ),
            (
                "hierarchical sidx",
                [make_sidx(&[(true, 100)]), media.clone()].concat(),
            ),
        ];
        for (name, segment) in cases {
            let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);
            assert!(
                vsi_signer.sign_media_segment(&segment).is_err(),
                "{name} should be rejected"
            );
            assert_eq!(vsi_signer.next_sequence_number(), 1, "{name}");
        }
    }

    #[test]
    fn sign_media_segment_without_styp_starts_with_emsg() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);

        let segment = make_test_segment();
        let signed = vsi_signer.sign_media_segment(&segment).unwrap();

        assert!(signed.len() > segment.len());
        assert_eq!(top_level_types(&signed), [*b"emsg", *b"mdat"]);

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

        let session_keys = vsi_signer.build_session_keys_assertion().unwrap();
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

        let session_keys = vsi_signer.build_session_keys_assertion().unwrap();
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
        let session_key = make_test_signing_key();

        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key.clone(),
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
        vsi_signer.active_manifest_id = Some(TEST_MANIFEST_ID.to_string());

        let seg1 = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(vsi_signer.next_sequence_number(), 2);

        // Use the same session key — resume_from_segment now verifies the signature
        // on the resumed segment, which requires the same key that signed it.
        let mut resumed_signer = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            session_key,
            b"k".to_vec(),
            1,
            3600,
        )
        .unwrap();
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

        let session_keys = signer2.build_session_keys_assertion().unwrap();
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

    // ── VSI emsg exclusion alongside other emsg boxes (SCTE-35) ─────────────────

    fn make_emsg_v0(scheme_id_uri: &str, value: &str, message_data: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 4]; // version 0, flags
        body.extend_from_slice(scheme_id_uri.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
        body.extend_from_slice(&90_000u32.to_be_bytes()); // timescale
        body.extend_from_slice(&0u32.to_be_bytes()); // presentation_time_delta
        body.extend_from_slice(&0u32.to_be_bytes()); // event_duration
        body.extend_from_slice(&7u32.to_be_bytes()); // id
        body.extend_from_slice(message_data);
        make_box(b"emsg", &body)
    }

    /// Byte range of the `index`-th top-level box of type `fourcc` in `data`.
    fn box_range(data: &[u8], fourcc: &[u8; 4], index: usize) -> Option<std::ops::Range<usize>> {
        let mut pos = 0;
        let mut seen = 0;
        for (f, bytes) in crate::live_video::box_walk::top_level_boxes(data) {
            if f == fourcc {
                if seen == index {
                    return Some(pos..pos + bytes.len());
                }
                seen += 1;
            }
            pos += bytes.len();
        }
        None
    }

    /// Signs `segment`, then validates `mutate(signed)` and returns its `livevideo.*` codes.
    fn sign_mutate_and_validate(segment: &[u8], mutate: impl FnOnce(&mut Vec<u8>)) -> Vec<String> {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);
        let mut signed = vsi_signer.sign_media_segment(segment).unwrap();
        mutate(&mut signed);

        let session_keys = vsi_signer.build_session_keys_assertion().unwrap();
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
        let _ = validator.validate_verifiable_segment_info(&signed, &mut tracker);
        tracker
            .logged_items()
            .iter()
            .filter_map(|i| i.validation_status.as_deref())
            .filter(|s| s.starts_with("livevideo"))
            .map(str::to_string)
            .collect()
    }

    fn segment_with_scte35() -> Vec<u8> {
        [
            make_scte35_emsg(),
            make_test_media_segment_with_moof(&[1000]),
        ]
        .concat()
    }

    #[test]
    fn segment_with_scte35_emsg_passes_vsi_validation() {
        assert!(sign_mutate_and_validate(&segment_with_scte35(), |_| {}).is_empty());
    }

    /// The SCTE-35 `emsg` is not the VSI `emsg`, so `bmffHash` covers it: changing its
    /// payload invalidates the segment.
    #[test]
    fn tampered_scte35_emsg_fails_vsi_validation() {
        let codes = sign_mutate_and_validate(&segment_with_scte35(), |signed| {
            let scte35 = box_range(signed, b"emsg", 1).unwrap();
            signed[scte35.end - 1] ^= 0xff;
        });
        assert_eq!(codes, ["livevideo.segment.invalid"]);
    }

    /// Removing the SCTE-35 `emsg` also invalidates the segment.
    #[test]
    fn removed_scte35_emsg_fails_vsi_validation() {
        let codes = sign_mutate_and_validate(&segment_with_scte35(), |signed| {
            let scte35 = box_range(signed, b"emsg", 1).unwrap();
            signed.drain(scte35);
        });
        assert_eq!(codes, ["livevideo.segment.invalid"]);
    }

    /// The VSI `emsg` itself is excluded from `bmffHash`: its `id` field, which isn't
    /// covered by the signature either, can change without failing the hash check.
    #[test]
    fn vsi_emsg_is_excluded_from_the_hash() {
        let codes = sign_mutate_and_validate(&segment_with_scte35(), |signed| {
            let vsi = box_range(signed, b"emsg", 0).unwrap();
            // header(8) + FullBox(4) + scheme_id_uri + NUL + "fseg" + NUL
            // + timescale(4) + presentation_time_delta(4) + event_duration(4)
            let id_at = vsi.start + 12 + VSI_SCHEME_ID_URI.len() + 1 + 5 + 12;
            signed[id_at..id_at + 4].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        });
        assert!(codes.is_empty(), "unexpected failures: {codes:?}");
    }

    /// The `bmffHash` exclusion matches `emsg` boxes whose bytes at offset 12 *start with*
    /// `urn:c2pa:verifiable-segment-info`, so an `emsg` with a longer scheme (or a
    /// version 1 `emsg` laid out to match) would be left out of the hash without being the
    /// VSI `emsg`. Such a box must fail validation rather than ride along unhashed.
    #[test]
    fn emsg_matching_the_vsi_exclusion_but_not_vsi_fails() {
        let lookalike_v0 = make_emsg_v0(
            "urn:c2pa:verifiable-segment-info-extra",
            "fseg",
            b"unhashed",
        );
        let codes = sign_mutate_and_validate(&segment_with_scte35(), |signed| {
            signed.extend_from_slice(&lookalike_v0);
        });
        assert_eq!(codes, ["livevideo.segment.invalid"]);

        // A version 1 emsg whose timescale..id fields and the start of scheme_id_uri spell
        // out the VSI URI at offset 12.
        let mut body = vec![1u8, 0, 0, 0];
        body.extend_from_slice(VSI_SCHEME_ID_URI.as_bytes());
        body.extend_from_slice(b"\0fseg\0unhashed");
        let lookalike_v1 = make_box(b"emsg", &body);
        let codes = sign_mutate_and_validate(&segment_with_scte35(), |signed| {
            signed.extend_from_slice(&lookalike_v1);
        });
        assert_eq!(codes, ["livevideo.segment.invalid"]);
    }
}
