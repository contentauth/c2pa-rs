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

use c2pa_raw_crypto::{signer_from_private_key, validator_for_signing_alg, RawSigner};
use coset::{iana, iana::EnumI64, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};

use super::{
    box_walk::{box_payload, find_box, top_level_boxes},
    cose_key::{
        build_ed25519_cose_key, cose_alg_id, cose_key_from_spki, cose_key_to_der,
        signing_alg_from_cose_key,
    },
    verifiable_segment_info::{VSI_EXCLUSION_VALUE, VSI_SCHEME_ID_URI, VSI_URI_OFFSET_IN_EMSG},
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
/// The caller provides a session key via [`from_signing_key`]: an Ed25519 key, or any
/// [`SessionSigningKey`] (ES256/384/512, PS256/384/512 or Ed25519).  The
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
    manifest_uri: Option<crate::HashedUri>,
    manifest_store: Option<Vec<u8>>,
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
    /// Position of this signer's track among the tracks signed for the same presentation;
    /// see [`LiveVideoVsiSigner::set_event_ids`].
    event_id_index: u32,
    /// Number of tracks signed for the same presentation; see
    /// [`LiveVideoVsiSigner::set_event_ids`].
    event_id_count: u32,
}

struct SessionSigningMaterial {
    session_signing_key: SessionSigningKey,
    session_cose_key: c2pa_cbor::Value,
    kid: Vec<u8>,
    /// COSE_Sign1_Tagged (`18([...])`) bytes of the detached signer binding.
    signer_binding: Vec<u8>,
    min_sequence_number: u64,
    created_at: String,
    validity_period: u64,
}

/// A session private key and its public key, for signing VSI and `signerBinding`.
///
/// The Live Media specification allows session keys to use any algorithm allowed for
/// claim-signing certificates: ES256, ES384, ES512, PS256, PS384, PS512 and Ed25519. An
/// Ed25519 key converts directly (`From<Ed25519SessionKey>`); other keys are built with
/// [`SessionSigningKey::from_private_key_pem`].
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
pub struct SessionSigningKey {
    private_key: SessionPrivateKey,
    alg: crate::SigningAlg,
}

enum SessionPrivateKey {
    Ed25519(SigningKey),
    /// A raw signer and the DER SubjectPublicKeyInfo of its public key.
    Raw {
        signer: Box<dyn RawSigner + Send + Sync>,
        public_key_der: Vec<u8>,
    },
}

impl From<SigningKey> for SessionSigningKey {
    fn from(key: SigningKey) -> Self {
        Self {
            private_key: SessionPrivateKey::Ed25519(key),
            alg: crate::SigningAlg::Ed25519,
        }
    }
}

impl SessionSigningKey {
    /// Creates a session key from a PEM private key (PKCS #8), its public key as a DER
    /// SubjectPublicKeyInfo, and the algorithm to sign with.
    ///
    /// Fails if the algorithm isn't available, the public key doesn't fit the algorithm
    /// (for example, a P-384 key for ES256, or an RSA modulus under 2048 bits), or the
    /// public key doesn't belong to the private key.
    pub fn from_private_key_pem(
        private_key_pem: &[u8],
        public_key_der: &[u8],
        alg: crate::SigningAlg,
    ) -> Result<Self> {
        let signer = signer_from_private_key(private_key_pem, alg)
            .map_err(|e| Error::BadParam(format!("session private key: {e}")))?;
        let key = Self {
            private_key: SessionPrivateKey::Raw {
                signer,
                public_key_der: public_key_der.to_vec(),
            },
            alg,
        };
        // Check that the two halves belong together, through the COSE_Key a validator sees.
        let public_key = cose_key_to_der(&key.cose_key(b"probe")?).ok_or_else(|| {
            Error::BadParam(format!("session public key cannot be used for {alg:?}"))
        })?;
        let probe = b"c2pa live media session key";
        let validator = validator_for_signing_alg(alg)
            .ok_or_else(|| Error::BadParam(format!("no validator for {alg:?}")))?;
        validator
            .validate(&key.sign(probe)?, probe, &public_key)
            .map_err(|_| {
                Error::BadParam("session public key does not match the private key".into())
            })?;
        Ok(key)
    }

    /// The signing algorithm.
    pub fn alg(&self) -> crate::SigningAlg {
        self.alg
    }

    /// The COSE protected-header algorithm.
    fn cose_algorithm(&self) -> Result<iana::Algorithm> {
        cose_alg_id(self.alg)
            .and_then(|id| i64::try_from(id).ok())
            .and_then(iana::Algorithm::from_i64)
            .ok_or_else(|| {
                Error::BadParam(format!("unsupported session key algorithm {:?}", self.alg))
            })
    }

    /// The public key as a COSE_Key with `kid`.
    fn cose_key(&self, kid: &[u8]) -> Result<c2pa_cbor::Value> {
        match &self.private_key {
            SessionPrivateKey::Ed25519(key) => {
                Ok(build_ed25519_cose_key(&key.verifying_key(), kid))
            }
            SessionPrivateKey::Raw { public_key_der, .. } => {
                cose_key_from_spki(public_key_der, self.alg, kid).ok_or_else(|| {
                    Error::BadParam(format!(
                        "session public key is not a valid {:?} key",
                        self.alg
                    ))
                })
            }
        }
    }

    /// Signs `data`. EC signatures are in the IEEE P1363 `r|s` form COSE uses.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.private_key {
            SessionPrivateKey::Ed25519(key) => {
                let signature: ed25519_dalek::Signature = Ed25519Signer::sign(key, data);
                Ok(signature.to_bytes().to_vec())
            }
            SessionPrivateKey::Raw { signer, .. } => signer
                .sign(data)
                .map_err(|e| Error::BadParam(format!("session key signing failed: {e}"))),
        }
    }
}

impl LiveVideoVsiSigner {
    /// Creates a VSI signer from a caller-provided session key: an Ed25519 key, or any
    /// [`SessionSigningKey`].
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
    /// * `signing_key` — the session private key: an Ed25519 key or a [`SessionSigningKey`].
    /// * `kid` — key identifier for the session key (e.g. `b"session-key-1"`).
    /// * `min_sequence_number` — first sequence number valid for this key.
    /// * `validity_period_secs` — how long (in seconds) the session key is valid.
    pub fn from_signing_key(
        manifest_json: impl Into<String>,
        manifest_signer: &dyn Signer,
        signing_key: impl Into<SessionSigningKey>,
        kid: impl Into<Vec<u8>>,
        min_sequence_number: u64,
        validity_period_secs: u64,
    ) -> Result<Self> {
        let signing_key = signing_key.into();
        let base_manifest_json = manifest_json.into();
        let kid = kid.into();
        if kid.is_empty() || validity_period_secs == 0 {
            return Err(Error::BadParam(
                "session key requires a nonempty kid and positive validity period".into(),
            ));
        }

        let session_cose_key = signing_key.cose_key(&kid)?;

        let ee_cert_der = manifest_signer
            .certs()
            .map_err(|e| Error::OtherError(Box::new(e)))?
            .into_iter()
            .next()
            .ok_or_else(|| Error::BadParam("manifest signer has no certificates".into()))?;

        let signer_binding = build_signer_binding(&ee_cert_der, &signing_key)?;

        let created_at = chrono::Utc::now().to_rfc3339();

        Ok(Self {
            manifest_uri: None,
            manifest_store: None,
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
            event_id_index: 0,
            event_id_count: 1,
        })
    }

    /// Adds a session key (Ed25519 or any [`SessionSigningKey`]) to announce in the next
    /// signed initialization segment.
    /// Keys are selected automatically by greatest eligible `minSequenceNumber`.
    /// Add scheduled keys before signing the init segment so receivers learn them first.
    /// To announce keys added later, deliver an updated initialization segment or call
    /// [`Self::sign_media_segment_with_manifest`]. All keys must bind the same manifest signer.
    pub fn add_session_key(
        &mut self,
        manifest_signer: &dyn Signer,
        signing_key: impl Into<SessionSigningKey>,
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
        self.sign_media_segment_with_exclusion(segment_data, VSI_EXCLUSION_VALUE)
    }

    /// [`Self::sign_media_segment`] with a given `bmffHash` exclusion value; tests use it to
    /// sign with the legacy unterminated form.
    fn sign_media_segment_with_exclusion(
        &mut self,
        segment_data: &[u8],
        exclusion_value: &[u8],
    ) -> Result<Vec<u8>> {
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
        let id = self.event_id(sequence_number);

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
                manifest_uri: self.manifest_uri.clone(),
            };
            let cose_sign1_bytes =
                build_vsi_cose_sign1(&segment_info_map, &key.session_signing_key, &key.kid)?;
            build_emsg_box(&cose_sign1_bytes, timescale, event_duration, id)
        };

        check_relocatable(segment_data)?;
        let insert_at = vsi_emsg_insertion_point(segment_data)?;
        let draft_emsg_box =
            build_emsg(build_segment_bmff_hash_placeholder_with(exclusion_value)?)?;
        let draft_segment = insert_emsg_box(segment_data, insert_at, &draft_emsg_box)?;
        let bmff_hash = build_segment_bmff_hash_with(&draft_segment, exclusion_value)?;

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
        check_relocatable(segment_data)?;
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
                self.event_id(sequence),
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
        // The embedded manifest replaces the active one, so a reference to the previous
        // store would be stale.
        self.manifest_uri = None;
        self.manifest_store = None;
        self.active_manifest_id = Some(label);
        self.keys_need_announcement = false;
        self.next_sequence_number = next_sequence;
        Ok(output)
    }

    /// Makes this signer's VSI `emsg` ids distinct from those of other tracks signed for the
    /// same presentation.
    ///
    /// `index` is this track's position among `count` tracks (`index < count`). The `emsg` id
    /// becomes `sequence_number * count + index`, wrapping modulo 2^32. The default
    /// (`index` 0, `count` 1) uses the sequence number itself.
    ///
    /// ISO/IEC 23009-1 treats `emsg` boxes with the same `scheme_id_uri`, `value` and `id` as
    /// the same event, and players such as dash.js de-duplicate inband events per Period on
    /// those fields. Since every track carries a VSI for the same sequence number, equal ids
    /// make a player drop the other tracks' VSI events. This mirrors livesim2's
    /// `Signer.SetEventIDs`; see <https://github.com/c2pa-org/specs-core/issues/2628>.
    pub fn set_event_ids(&mut self, index: u32, count: u32) -> Result<()> {
        if index >= count {
            return Err(Error::BadParam(format!(
                "emsg id index ({index}) must be less than the track count ({count})"
            )));
        }
        self.event_id_index = index;
        self.event_id_count = count;
        Ok(())
    }

    /// The VSI `emsg` id for `sequence_number`. Truncation is safe: the id only needs to be
    /// unique within the session (§19.4.2), and a live session realistically never wraps it.
    fn event_id(&self, sequence_number: u64) -> u32 {
        (sequence_number as u32)
            .wrapping_mul(self.event_id_count)
            .wrapping_add(self.event_id_index)
    }

    /// Sets the optional hashed external manifest reference emitted in subsequent VSIs.
    /// `alg` is required for this external URI, despite being optional on [`crate::HashedUri`].
    /// The caller must host the exact referenced store for the stream's lifetime.
    /// Configure this after signing or restoring the init segment; those operations
    /// clear any previous reference.
    pub fn set_manifest_uri(&mut self, manifest_uri: Option<crate::HashedUri>) -> Result<()> {
        if let Some(uri) = &manifest_uri {
            super::manifest_uri::validate_reference(uri)?;
        }
        self.manifest_uri = manifest_uri;
        Ok(())
    }

    /// References the current init manifest store using SHA-256.
    /// Obtain the exact bytes to host using [`Self::manifest_store`].
    pub fn set_manifest_uri_for_current_manifest(&mut self, url: impl Into<String>) -> Result<()> {
        let bytes = self.manifest_store.as_deref().ok_or_else(|| {
            Error::BadParam(
                "sign or restore the initialization segment before setting manifestUri".into(),
            )
        })?;
        let hash = crate::utils::hash_utils::hash_by_alg("sha256", bytes, None);
        self.set_manifest_uri(Some(crate::HashedUri::new(
            url.into(),
            Some("sha256".into()),
            &hash,
        )))
    }

    /// Exact C2PA Manifest Store bytes from the last signed or restored init segment.
    pub fn manifest_store(&self) -> Option<&[u8]> {
        self.manifest_store.as_deref()
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
        self.manifest_store = Some(load_manifest_store(signed_init_data, format)?);
        // A restored init manifest invalidates any previously configured reference.
        self.manifest_uri = None;
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
            if self.active_manifest_id.as_deref() != Some(&parsed.segment_info_map.manifest_id) {
                self.manifest_uri = None;
                self.manifest_store = None;
            }
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
        let label = reader
            .active_manifest()
            .and_then(|manifest| manifest.label())
            .ok_or_else(|| Error::BadParam("signed init has no manifest label".into()))?;
        self.active_manifest_id = Some(label.to_string());
        self.manifest_store = Some(load_manifest_store(signed_data, format)?);
        // A new init manifest invalidates any previously configured reference.
        self.manifest_uri = None;
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

/// The exact C2PA Manifest Store bytes embedded in a signed init segment, for hosting
/// at a `manifestUri`.
fn load_manifest_store(signed_data: &[u8], format: &str) -> Result<Vec<u8>> {
    let context = super::context_from_thread_local_settings()?;
    Ok(crate::store::Store::load_jumbf_from_stream(
        format,
        &mut std::io::Cursor::new(signed_data),
        &context,
    )?
    .0)
}

// ── BMFF hash helper ─────────────────────────────────────────────────────────

/// The VSI `emsg` exclusion: xpath `/emsg` with the NUL-terminated `scheme_id_uri` at
/// offset 12 (c2pa-org/specs-core#2542).
fn vsi_emsg_exclusion() -> ExclusionsMap {
    vsi_emsg_exclusion_with(VSI_EXCLUSION_VALUE)
}

fn vsi_emsg_exclusion_with(value: &[u8]) -> ExclusionsMap {
    let mut exclusion = ExclusionsMap::new("/emsg".to_string());
    exclusion.data = Some(vec![DataMap {
        offset: VSI_URI_OFFSET_IN_EMSG,
        value: value.to_vec(),
    }]);
    exclusion
}

/// A `bmff-hash-map` scoped to exclude the VSI `emsg` box, per §19.4.1. Defaults to
/// `bmff_version` 3, which per §18.6.2 hashes each included root box as `offset || data`
/// (8-byte big-endian file offset prefix).
fn new_vsi_bmff_hash(exclusion_value: &[u8]) -> BmffHash {
    let mut bmff_hash = BmffHash::new("jumbf manifest", "sha256", None);
    bmff_hash.add_exclusions(&mut vec![vsi_emsg_exclusion_with(exclusion_value)]);
    bmff_hash
}

/// A same-shape `bmff-hash-map` with a zero-filled placeholder digest, used to size
/// the draft `emsg` box in [`LiveVideoVsiSigner::sign_media_segment`]'s first pass.
pub(super) fn build_segment_bmff_hash_placeholder() -> Result<c2pa_cbor::Value> {
    build_segment_bmff_hash_placeholder_with(VSI_EXCLUSION_VALUE)
}

pub(super) fn build_segment_bmff_hash_placeholder_with(
    exclusion_value: &[u8],
) -> Result<c2pa_cbor::Value> {
    let mut bmff_hash = new_vsi_bmff_hash(exclusion_value);
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
    build_segment_bmff_hash_with(full_segment, VSI_EXCLUSION_VALUE)
}

/// [`build_segment_bmff_hash`] with a given exclusion value; tests use it to produce the
/// legacy unterminated form.
pub(super) fn build_segment_bmff_hash_with(
    full_segment: &[u8],
    exclusion_value: &[u8],
) -> Result<c2pa_cbor::Value> {
    let mut bmff_hash = new_vsi_bmff_hash(exclusion_value);

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
//   - the **session key** signs, with its own algorithm,
//   - the **payload** is the signer's end-entity certificate encoded as a CBOR
//     byte string (used in Sig_structure but NOT carried in the COSE_Sign1).

fn build_signer_binding(
    ee_cert_der: &[u8],
    session_signing_key: &SessionSigningKey,
) -> Result<Vec<u8>> {
    let external_payload = c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec()))
        .map_err(|e| Error::BadParam(format!("failed to CBOR-encode EE certificate: {e}")))?;

    let protected = HeaderBuilder::new()
        .algorithm(session_signing_key.cose_algorithm()?)
        .build();

    let mut sign1 = CoseSign1Builder::new().protected(protected).build();

    // signerBinding is a detached-payload COSE_Sign1: the cert bytes are the
    // external payload, not AAD. Use tbs_detached_data per RFC 9052 §4.4.
    let tbs = sign1.tbs_detached_data(&external_payload, b"");
    sign1.signature = session_signing_key.sign(&tbs)?;

    // The COSE_Sign1_Tagged (`18([...])`) bytes; `SessionKey::new` decodes these into the
    // native tagged CBOR value stored in the assertion per §18.25.
    sign1
        .to_tagged_vec()
        .map_err(|e| Error::BadParam(format!("failed to encode signer binding: {e}")))
}

// ── VSI COSE_Sign1 construction ──────────────────────────────────────────────

fn build_vsi_cose_sign1(
    segment_info_map: &SegmentInfoMap,
    signing_key: &SessionSigningKey,
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
        .algorithm(signing_key.cose_algorithm()?)
        .text_value("iat".to_string(), coset::cbor::value::Value::from(iat))
        .build();
    let unprotected = HeaderBuilder::new().key_id(kid.to_vec()).build();

    let mut sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload)
        .build();

    let tbs = sign1.tbs_data(b"");
    sign1.signature = signing_key.sign(&tbs)?;

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

/// Checks that inserting boxes ahead of the first `moof` leaves the segment's media
/// addressable. That holds when every offset into the media is relative to its `moof`: a
/// `tfhd` without `base-data-offset-present` (flag 0x000001) puts the base of the `trun`
/// data offsets and of the `saio` offsets (ISO/IEC 14496-12 §8.8.7, §8.7.9) at the `moof`,
/// as CMAF requires. An explicit `base_data_offset` is an absolute file position, and so
/// are the `moof_offset`s in an `mfra`/`tfra` index; both would point at the wrong bytes
/// after the insertion, so such segments are rejected rather than silently corrupted.
fn check_relocatable(segment_data: &[u8]) -> Result<()> {
    for (fourcc, box_bytes) in top_level_boxes(segment_data) {
        match fourcc {
            b"mfra" => {
                return Err(Error::BadParam(
                    "VSI signing does not support media segments with an mfra box \
                     (absolute moof offsets)"
                        .into(),
                ))
            }
            b"moof" => {
                let Some(moof) = box_payload(box_bytes) else {
                    continue;
                };
                for (child, traf) in top_level_boxes(moof) {
                    if child != b"traf" {
                        continue;
                    }
                    let flags = box_payload(traf)
                        .and_then(|traf| find_box(traf, b"tfhd"))
                        .and_then(box_payload)
                        .and_then(|tfhd| tfhd.get(1..4))
                        .map(|f| u32::from_be_bytes([0, f[0], f[1], f[2]]));
                    if flags.is_some_and(|flags| flags & TFHD_BASE_DATA_OFFSET_PRESENT != 0) {
                        return Err(Error::BadParam(
                            "VSI signing does not support media segments whose tfhd has an \
                             explicit base_data_offset (absolute media offsets); use \
                             moof-relative offsets (default-base-is-moof)"
                                .into(),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// `tfhd` flag: `base_data_offset` is present (ISO/IEC 14496-12 §8.8.7).
const TFHD_BASE_DATA_OFFSET_PRESENT: u32 = 0x000001;

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
#[path = "livesim2_interop.rs"]
mod livesim2_interop;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::live_video::verifiable_segment_info::parse_vsi;
    use crate::live_video::verifiable_segment_info::VSI_LEGACY_EXCLUSION_VALUE;
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

    #[test]
    fn emsg_id_defaults_to_sequence_number() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 7);
        let signed = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(read_emsg_timing_fields(&signed).2, 7);
    }

    #[test]
    fn set_event_ids_offsets_emsg_id_per_track() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 7);
        vsi_signer.set_event_ids(2, 3).unwrap();
        let first = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        let second = vsi_signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(read_emsg_timing_fields(&first).2, 7 * 3 + 2);
        assert_eq!(read_emsg_timing_fields(&second).2, 8 * 3 + 2);
        // Wraps modulo 2^32 rather than failing.
        assert_eq!(
            vsi_signer.event_id(u64::from(u32::MAX)),
            u32::MAX.wrapping_mul(3) + 2
        );
    }

    #[test]
    fn set_event_ids_rejects_index_not_below_count() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"k", 1);
        assert!(vsi_signer.set_event_ids(2, 2).is_err());
        assert!(vsi_signer.set_event_ids(0, 0).is_err());
        // A rejected call leaves the previous configuration in place.
        assert_eq!(vsi_signer.event_id(5), 5);
    }

    #[test]
    fn tracks_signed_for_same_sequence_get_distinct_emsg_ids() {
        let signer = make_test_signer();
        let mut video = make_vsi_signer_with_manifest_id(&signer, b"video", 4);
        let mut audio = make_vsi_signer_with_manifest_id(&signer, b"audio", 4);
        video.set_event_ids(0, 2).unwrap();
        audio.set_event_ids(1, 2).unwrap();
        let video_id =
            read_emsg_timing_fields(&video.sign_media_segment(&make_test_segment()).unwrap()).2;
        let audio_id =
            read_emsg_timing_fields(&audio.sign_media_segment(&make_test_segment()).unwrap()).2;
        assert_ne!(video_id, audio_id);
    }

    #[test]
    fn segments_signed_with_event_ids_validate() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        signer.set_event_ids(1, 2).unwrap();
        let mut validator = LiveVideoValidator::new();
        register_keys(&mut validator, &signer, &context, TEST_MANIFEST_ID);
        let segment = signer.sign_media_segment(&make_test_segment()).unwrap();
        assert_eq!(read_emsg_timing_fields(&segment).2, 3);
        let mut tracker = StatusTracker::default();
        validator
            .validate_verifiable_segment_info(&segment, &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0);

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
        assert_eq!(read_emsg_timing_fields(&update).2, 5);
        validator
            .validate_verifiable_segment_info_with_context(&update, &context, &mut tracker)
            .unwrap();
        assert_eq!(
            tracker.filter_errors().count(),
            0,
            "{:?}",
            tracker.logged_items()
        );
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
        other.session_keys[0].session_cose_key = other.session_keys[0]
            .session_signing_key
            .cose_key(b"new")
            .unwrap();
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

        // Validate with the first signer's announcement: the resumed signer re-creates the
        // same key with a later `createdAt`, which a segment signed before it (with a
        // whole-second `iat`) can precede when a second boundary falls in between.
        let session_keys = signer1.build_session_keys_assertion().unwrap();
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
        sign_mutate_and_validate_with(segment, VSI_EXCLUSION_VALUE, mutate)
    }

    /// [`sign_mutate_and_validate`], signing with the given `bmffHash` exclusion value.
    fn sign_mutate_and_validate_with(
        segment: &[u8],
        exclusion_value: &[u8],
        mutate: impl FnOnce(&mut Vec<u8>),
    ) -> Vec<String> {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);
        let mut signed = vsi_signer
            .sign_media_segment_with_exclusion(segment, exclusion_value)
            .unwrap();
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

    /// An `emsg` that the `bmffHash` exclusion matches but that isn't the VSI `emsg` (a
    /// longer scheme under the legacy prefix match, or a version 1 `emsg` laid out to match)
    /// would be left out of the hash. Such a box must fail validation rather than ride along
    /// unhashed.
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

    /// The signer emits the NUL-terminated exclusion value (c2pa-org/specs-core#2542).
    #[test]
    fn signer_emits_nul_terminated_exclusion() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);
        let signed = vsi_signer
            .sign_media_segment(&make_test_media_segment_with_moof(&[1000]))
            .unwrap();
        let vsi = parse_vsi(&extract_vsi_payload_from_segment(&signed).unwrap()).unwrap();
        let bmff_hash: BmffHash =
            c2pa_cbor::value::from_value(vsi.segment_info_map.bmff_hash).unwrap();
        let values: Vec<_> = bmff_hash
            .exclusions()
            .iter()
            .flat_map(|e| e.data.iter().flatten())
            .map(|d| (d.offset, d.value.as_slice()))
            .collect();
        assert_eq!(values, [(VSI_URI_OFFSET_IN_EMSG, VSI_EXCLUSION_VALUE)]);
    }

    /// Segments signed with the earlier unterminated exclusion value still validate during
    /// the transition, and tampering with them is still detected.
    #[test]
    fn legacy_exclusion_value_still_validates() {
        let segment = segment_with_scte35();
        let codes = sign_mutate_and_validate_with(&segment, VSI_LEGACY_EXCLUSION_VALUE, |_| {});
        assert!(codes.is_empty(), "unexpected failures: {codes:?}");

        let codes = sign_mutate_and_validate_with(&segment, VSI_LEGACY_EXCLUSION_VALUE, |signed| {
            let scte35 = box_range(signed, b"emsg", 1).unwrap();
            signed[scte35.end - 1] ^= 0xff;
        });
        assert_eq!(codes, ["livevideo.segment.invalid"]);
    }

    /// An `emsg` whose scheme only starts with the VSI URI is hashed under the
    /// NUL-terminated exclusion, so a segment carrying one validates; under the legacy
    /// prefix match it would be excluded without being VSI, and is rejected.
    #[test]
    fn longer_scheme_emsg_is_hashed_with_nul_exclusion() {
        let segment = [
            make_emsg_v0("urn:c2pa:verifiable-segment-info-extra", "fseg", b"data"),
            make_test_media_segment_with_moof(&[1000]),
        ]
        .concat();
        assert!(sign_mutate_and_validate(&segment, |_| {}).is_empty());

        let codes = sign_mutate_and_validate(&segment, |signed| {
            let extra = box_range(signed, b"emsg", 1).unwrap();
            signed[extra.end - 1] ^= 0xff;
        });
        assert_eq!(codes, ["livevideo.segment.invalid"]);

        let codes = sign_mutate_and_validate_with(&segment, VSI_LEGACY_EXCLUSION_VALUE, |_| {});
        assert_eq!(codes, ["livevideo.segment.invalid"]);
    }

    // ── segments the emsg insertion would corrupt ───────────────────────────────

    /// A one-sample `moof`+`mdat` whose `tfhd` has the given flags, and an explicit
    /// `base_data_offset` (pointing at the `mdat` payload as laid out here) when
    /// `TFHD_BASE_DATA_OFFSET_PRESENT` is set.
    fn segment_with_tfhd_flags(flags: u32) -> Vec<u8> {
        let traf = |base_data_offset: u64| {
            let mut tfhd_payload = 1u32.to_be_bytes().to_vec(); // track_ID
            if flags & TFHD_BASE_DATA_OFFSET_PRESENT != 0 {
                tfhd_payload.extend_from_slice(&base_data_offset.to_be_bytes());
            }
            let tfhd = make_fullbox(b"tfhd", 0, flags, &tfhd_payload);
            let mut trun_payload = 1u32.to_be_bytes().to_vec(); // sample_count
            trun_payload.extend_from_slice(&1000u32.to_be_bytes()); // sample_duration
            let trun = make_fullbox(b"trun", 0, 0x000100, &trun_payload);
            make_box(b"traf", &[tfhd, trun].concat())
        };
        // The base offset is where the mdat payload starts: after the moof and the
        // mdat header.
        let moof_len = make_box(b"moof", &traf(0)).len() as u64;
        let moof = make_box(b"moof", &traf(moof_len + 8));
        [moof, make_box(b"mdat", &[1, 2, 3, 4])].concat()
    }

    /// An explicit `tfhd.base_data_offset` is an absolute file position: inserting the
    /// VSI `emsg` before the `moof` would leave it (and the `trun`/`saio` offsets based on
    /// it) pointing at the wrong bytes, so signing is refused and the counter is kept.
    #[test]
    fn absolute_base_data_offset_is_rejected() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);
        let err = vsi_signer
            .sign_media_segment(&segment_with_tfhd_flags(TFHD_BASE_DATA_OFFSET_PRESENT))
            .unwrap_err();
        assert!(err.to_string().contains("base_data_offset"), "{err}");
        assert_eq!(vsi_signer.next_sequence_number(), 1);
    }

    /// Any `traf` counts, not only the first one of the first `moof`.
    #[test]
    fn absolute_base_data_offset_in_a_later_moof_is_rejected() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);
        let segment = [
            segment_with_tfhd_flags(0),
            segment_with_tfhd_flags(TFHD_BASE_DATA_OFFSET_PRESENT),
        ]
        .concat();
        assert!(vsi_signer.sign_media_segment(&segment).is_err());
    }

    /// Moof-relative addressing, explicit (`default-base-is-moof`) or implicit, is
    /// unaffected by the insertion and still signs and validates.
    #[test]
    fn moof_relative_offsets_still_sign() {
        const TFHD_DEFAULT_BASE_IS_MOOF: u32 = 0x020000;
        for flags in [0, TFHD_DEFAULT_BASE_IS_MOOF] {
            let codes = sign_mutate_and_validate(&segment_with_tfhd_flags(flags), |_| {});
            assert!(codes.is_empty(), "flags {flags:#x}: {codes:?}");
        }
    }

    /// `tfra` entries in an `mfra` hold absolute `moof` offsets.
    #[test]
    fn mfra_is_rejected() {
        let signer = make_test_signer();
        let mut vsi_signer = make_vsi_signer_with_manifest_id(&signer, b"key-1", 1);
        let segment = [
            make_test_media_segment_with_moof(&[1000]),
            make_box(b"mfra", &make_fullbox(b"mfro", 0, 0, &16u32.to_be_bytes())),
        ]
        .concat();
        let err = vsi_signer.sign_media_segment(&segment).unwrap_err();
        assert!(err.to_string().contains("mfra"), "{err}");
    }

    /// Announcing keys inserts a manifest box ahead of the media too.
    #[test]
    fn announcement_rejects_absolute_base_data_offset() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        let segment = [
            make_box(b"styp", b"cmfs\0\0\0\0cmfs"),
            segment_with_tfhd_flags(TFHD_BASE_DATA_OFFSET_PRESENT),
        ]
        .concat();
        let err = signer
            .sign_media_segment_with_manifest(&segment, context.clone())
            .unwrap_err();
        assert!(err.to_string().contains("base_data_offset"), "{err}");
    }

    // ── session keys with other algorithms ──────────────────────────────────────

    /// The PEM private key and the end-entity certificate chain of a key fixture.
    fn fixture_key(alg: crate::SigningAlg) -> (&'static [u8], &'static [u8]) {
        use crate::SigningAlg::*;
        match alg {
            Es256 => (
                include_bytes!("../../tests/fixtures/certs/es256.pem"),
                include_bytes!("../../tests/fixtures/certs/es256.pub"),
            ),
            Es384 => (
                include_bytes!("../../tests/fixtures/certs/es384.pem"),
                include_bytes!("../../tests/fixtures/certs/es384.pub"),
            ),
            Es512 => (
                include_bytes!("../../tests/fixtures/certs/es512.pem"),
                include_bytes!("../../tests/fixtures/certs/es512.pub"),
            ),
            Ps256 => (
                include_bytes!("../../tests/fixtures/certs/ps256.pem"),
                include_bytes!("../../tests/fixtures/certs/ps256.pub"),
            ),
            Ps384 => (
                include_bytes!("../../tests/fixtures/certs/ps384.pem"),
                include_bytes!("../../tests/fixtures/certs/ps384.pub"),
            ),
            Ps512 => (
                include_bytes!("../../tests/fixtures/certs/ps512.pem"),
                include_bytes!("../../tests/fixtures/certs/ps512.pub"),
            ),
            _ => (
                include_bytes!("../../tests/fixtures/certs/ed25519.pem"),
                include_bytes!("../../tests/fixtures/certs/ed25519.pub"),
            ),
        }
    }

    /// The DER SubjectPublicKeyInfo of the `index`-th certificate in a PEM chain.
    fn chain_spki(chain_pem: &[u8], index: usize) -> Vec<u8> {
        let pem = x509_parser::pem::Pem::iter_from_buffer(chain_pem)
            .nth(index)
            .unwrap()
            .unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
        cert.tbs_certificate.subject_pki.raw.to_vec()
    }

    fn fixture_session_key(alg: crate::SigningAlg) -> SessionSigningKey {
        let (private_key, chain) = fixture_key(alg);
        SessionSigningKey::from_private_key_pem(private_key, &chain_spki(chain, 0), alg).unwrap()
    }

    const ALL_SESSION_KEY_ALGS: [crate::SigningAlg; 7] = [
        crate::SigningAlg::Es256,
        crate::SigningAlg::Es384,
        crate::SigningAlg::Es512,
        crate::SigningAlg::Ps256,
        crate::SigningAlg::Ps384,
        crate::SigningAlg::Ps512,
        crate::SigningAlg::Ed25519,
    ];

    /// Signs `segment` with `key`, then validates `mutate(signed)` and returns the signed
    /// segment and its `livevideo.*` codes.
    fn sign_and_validate_with_key(
        key: SessionSigningKey,
        segment: &[u8],
        mutate: impl FnOnce(&mut Vec<u8>),
    ) -> (Vec<u8>, Vec<String>) {
        let signer = make_test_signer();
        let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
            r#"{"assertions": []}"#,
            &signer,
            key,
            b"key-1".to_vec(),
            1,
            3600,
        )
        .unwrap();
        vsi_signer.active_manifest_id = Some(TEST_MANIFEST_ID.to_string());
        let mut signed = vsi_signer.sign_media_segment(segment).unwrap();
        mutate(&mut signed);

        let ee_cert_der = signer.certs().unwrap().into_iter().next().unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_session_keys(
                &vsi_signer.build_session_keys_assertion().unwrap(),
                TEST_MANIFEST_ID,
                Some(&ee_cert_der),
                &mut tracker,
            )
            .unwrap();
        let _ = validator.validate_verifiable_segment_info(&signed, &mut tracker);
        let codes = tracker
            .logged_items()
            .iter()
            .filter_map(|i| i.validation_status.as_deref())
            .filter(|s| s.starts_with("livevideo"))
            .map(str::to_string)
            .collect();
        (signed, codes)
    }

    /// Session keys may use any algorithm allowed for claim-signing certificates (Live Media,
    /// "Session Keys"): each signs a VSI and a signerBinding that validate, with the matching
    /// COSE `alg` and COSE_Key.
    #[test]
    fn every_allowed_session_key_algorithm_signs_and_validates() {
        for alg in ALL_SESSION_KEY_ALGS {
            let key = fixture_session_key(alg);
            assert_eq!(key.alg(), alg);
            let cose_key = key.cose_key(b"key-1").unwrap();
            assert_eq!(signing_alg_from_cose_key(&cose_key), Some(alg));

            let (signed, codes) = sign_and_validate_with_key(
                key,
                &make_test_media_segment_with_moof(&[1000]),
                |_| {},
            );
            assert!(codes.is_empty(), "{alg:?}: {codes:?}");
            let sign1 = coset::CoseSign1::from_tagged_slice(
                &extract_vsi_payload_from_segment(&signed).unwrap(),
            )
            .unwrap();
            assert_eq!(signing_alg_from_sign1(&sign1).unwrap(), alg);
        }
    }

    #[test]
    fn tampering_fails_with_ecdsa_and_rsa_session_keys() {
        for alg in [crate::SigningAlg::Es256, crate::SigningAlg::Ps256] {
            let (_, codes) = sign_and_validate_with_key(
                fixture_session_key(alg),
                &make_test_media_segment_with_moof(&[1000]),
                |signed| {
                    let last = signed.len() - 1;
                    signed[last] ^= 0xff; // mdat payload
                },
            );
            assert_eq!(codes, ["livevideo.segment.invalid"], "{alg:?}");
        }
    }

    /// The public key must fit the algorithm and belong to the private key.
    #[test]
    fn session_key_rejects_mismatched_public_key() {
        use crate::SigningAlg::*;
        let (es256_private, es256_chain) = fixture_key(Es256);
        let (_, es384_chain) = fixture_key(Es384);
        let (_, ps256_chain) = fixture_key(Ps256);
        // Wrong curve, wrong key type, then the right curve but another key (the issuer's).
        for public_key in [
            chain_spki(es384_chain, 0),
            chain_spki(ps256_chain, 0),
            chain_spki(es256_chain, 1),
        ] {
            assert!(
                SessionSigningKey::from_private_key_pem(es256_private, &public_key, Es256).is_err()
            );
        }
        // A private key for another algorithm.
        assert!(SessionSigningKey::from_private_key_pem(
            es256_private,
            &chain_spki(es256_chain, 0),
            Ps256
        )
        .is_err());
    }

    /// Keys added during a session can use another algorithm than the first key.
    #[test]
    fn added_session_key_can_use_another_algorithm() {
        let context = rotation_context();
        let mut signer = rotation_signer(&context);
        signer
            .add_session_key(
                context.signer().unwrap(),
                fixture_session_key(crate::SigningAlg::Es256),
                b"es256".to_vec(),
                2,
                3600,
            )
            .unwrap();
        let assertion = signer.build_session_keys_assertion().unwrap();
        let algs: Vec<_> = assertion
            .keys
            .iter()
            .map(|k| signing_alg_from_cose_key(&k.key))
            .collect();
        assert_eq!(
            algs,
            [
                Some(crate::SigningAlg::Ed25519),
                Some(crate::SigningAlg::Es256)
            ]
        );
    }

    struct ManifestResolver {
        body: Vec<u8>,
        status: u16,
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::http::SyncHttpResolver for ManifestResolver {
        fn http_resolve(
            &self,
            request: http::Request<Vec<u8>>,
        ) -> std::result::Result<
            http::Response<Box<dyn std::io::Read>>,
            crate::http::HttpResolverError,
        > {
            assert_eq!(
                request.uri().to_string(),
                "https://live.example/manifest.c2pa"
            );
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(http::Response::builder()
                .status(self.status)
                .body(Box::new(std::io::Cursor::new(self.body.clone())) as Box<dyn std::io::Read>)
                .unwrap())
        }
    }

    fn remote_manifest_fixture() -> (EphemeralSigner, LiveVideoVsiSigner, Vec<u8>) {
        let signer = make_test_signer();
        let mut vsi = LiveVideoVsiSigner::from_signing_key(
            test_manifest_json_with_actions(),
            &signer,
            make_test_signing_key(),
            b"remote-key".to_vec(),
            1,
            3600,
        )
        .unwrap();
        let init =
            include_bytes!("../../tests/fixtures/bunny/bunny_595491bps/BigBuckBunny_2s_init.mp4");
        let signed_init = vsi.sign_init_segment(init, "video/mp4", &signer).unwrap();
        vsi.set_manifest_uri_for_current_manifest("https://live.example/manifest.c2pa")
            .unwrap();
        (signer, vsi, signed_init)
    }

    fn remote_context(
        body: Vec<u8>,
        status: u16,
        fetch: bool,
    ) -> (
        std::sync::Arc<crate::Context>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let settings = crate::settings::Settings::new()
            .with_json(&format!(
                r#"{{"verify":{{"verify_trust":false,"remote_manifest_fetch":{fetch}}}}}"#
            ))
            .unwrap();
        let mut context = crate::Context::new().with_settings(settings).unwrap();
        context
            .set_resolver(ManifestResolver {
                body,
                status,
                calls: calls.clone(),
            })
            .unwrap();
        (std::sync::Arc::new(context), calls)
    }

    #[test]
    fn manifest_uri_is_optional_and_emits_the_exact_init_store_digest() {
        use crate::live_video::verifiable_segment_info::parse_vsi;
        let (_signer, mut vsi, init) = remote_manifest_fixture();
        let store = vsi.manifest_store().unwrap().to_vec();
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        let reference = parse_vsi(&extract_vsi_payload_from_segment(&segment).unwrap())
            .unwrap()
            .segment_info_map
            .manifest_uri
            .unwrap();
        assert_eq!(reference.alg().as_deref(), Some("sha256"));
        assert_eq!(
            reference.hash(),
            crate::utils::hash_utils::hash_by_alg("sha256", &store, None)
        );
        assert_eq!(reference.url(), "https://live.example/manifest.c2pa");
        vsi.set_manifest_uri(None).unwrap();
        let plain = vsi.sign_media_segment(&make_test_segment()).unwrap();
        assert!(
            parse_vsi(&extract_vsi_payload_from_segment(&plain).unwrap())
                .unwrap()
                .segment_info_map
                .manifest_uri
                .is_none()
        );
        vsi.restore_manifest_id_from_signed_init(&init, "video/mp4")
            .unwrap();
        assert_eq!(vsi.manifest_store().unwrap(), store);
    }

    #[test]
    fn manifest_uri_rejects_missing_algorithm_bad_digest_and_non_http_urls() {
        let signer = make_test_signer();
        let mut vsi = make_vsi_signer(&signer, b"key", 1);
        assert!(vsi
            .set_manifest_uri_for_current_manifest("https://live.example/manifest.c2pa")
            .is_err());
        for uri in [
            crate::HashedUri::new("https://live.example/manifest.c2pa".into(), None, &[0; 32]),
            crate::HashedUri::new(
                "https://live.example/manifest.c2pa".into(),
                Some("sha1".into()),
                &[0; 20],
            ),
            crate::HashedUri::new(
                "https://live.example/manifest.c2pa".into(),
                Some("sha256".into()),
                &[0; 31],
            ),
            crate::HashedUri::new(
                "file:///tmp/manifest.c2pa".into(),
                Some("sha256".into()),
                &[0; 32],
            ),
        ] {
            assert!(vsi.set_manifest_uri(Some(uri)).is_err());
        }
    }

    #[test]
    fn known_manifest_uri_key_never_fetches_even_when_remote_fetch_is_disabled() {
        let (_signer, mut vsi, init) = remote_manifest_fixture();
        let (context, calls) = remote_context(vsi.manifest_store().unwrap().to_vec(), 500, false);
        let reader = Reader::from_shared_context(&context)
            .with_stream("video/mp4", std::io::Cursor::new(&init))
            .unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_session_keys_from_reader(&reader, None, &mut tracker)
            .unwrap();
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn unknown_manifest_uri_key_obeys_runtime_fetch_switch() {
        let (_signer, mut vsi, _init) = remote_manifest_fixture();
        let (context, calls) = remote_context(vsi.manifest_store().unwrap().to_vec(), 200, false);
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert!(tracker.filter_errors().count() > 0);
        assert!(validator.session_keys.is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn embedded_manifest_prevents_manifest_uri_fetch() {
        let (_signer, mut vsi, _init) = remote_manifest_fixture();
        let (context, calls) = remote_context(vsi.manifest_store().unwrap().to_vec(), 200, true);
        let mut segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        segment.extend_from_slice(&crate::live_video::test_helpers::make_uuid_box(true));
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        let _ = validator.validate_verifiable_segment_info_with_context(
            &segment,
            &context,
            &mut tracker,
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(validator.session_keys.is_empty());
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_discovers_unknown_key_checks_init_binding_and_caches_it() {
        let (signer, mut vsi, init) = remote_manifest_fixture();
        let (context, calls) = remote_context(vsi.manifest_store().unwrap().to_vec(), 200, true);
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .unwrap();
        let old = make_vsi_signer(&signer, b"old", 1);
        let cert = signer.certs().unwrap().remove(0);
        validator
            .validate_session_keys(
                &old.build_session_keys_assertion().unwrap(),
                "urn:c2pa:old",
                Some(&cert),
                &mut tracker,
            )
            .unwrap();
        for _ in 0..2 {
            let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
            validator
                .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
                .unwrap();
        }
        assert_eq!(
            tracker.filter_errors().count(),
            0,
            "{:?}",
            tracker.logged_items()
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            validator.previous_segment.as_ref().unwrap().sequence_number,
            2
        );
        assert_eq!(
            validator.session_key_manifest_state(),
            Some(crate::ValidationState::Valid)
        );
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_can_validate_a_store_bound_to_the_current_media_segment() {
        let signer = make_test_signer();
        let vsi = make_vsi_signer(&signer, b"media-key", 1);
        let label = crate::claim::Claim::new("", None, 2).label().to_string();
        let reference = crate::HashedUri::new(
            "https://live.example/manifest.c2pa".into(),
            Some("sha256".into()),
            &[0; 32],
        );
        let assemble = |reference: crate::HashedUri| {
            let map = SegmentInfoMap {
                sequence_number: 1,
                manifest_id: label.clone(),
                bmff_hash: build_segment_bmff_hash_placeholder().unwrap(),
                manifest_uri: Some(reference),
            };
            let emsg = build_emsg_box(
                &build_vsi_cose_sign1(
                    &map,
                    &vsi.session_keys[0].session_signing_key,
                    &vsi.session_keys[0].kid,
                )
                .unwrap(),
                1,
                0,
                1,
            )
            .unwrap();
            [
                make_box(b"styp", b"cmfs\0\0\0\0cmfs"),
                emsg,
                make_box(b"mdat", &[1, 2, 3, 4]),
            ]
            .concat()
        };
        let draft = assemble(reference.clone());
        let mut builder = Builder::from_context(
            crate::Context::new()
                .with_settings(
                    crate::settings::Settings::new()
                        .with_json(r#"{"verify":{"verify_trust":false}}"#)
                        .unwrap(),
                )
                .unwrap(),
        )
        .with_definition(test_manifest_json_with_actions())
        .unwrap();
        builder.definition.label = Some(label.clone());
        builder.set_no_embed(true);
        builder
            .add_assertion(
                SessionKeys::LABEL,
                &vsi.build_session_keys_assertion().unwrap(),
            )
            .unwrap();
        let mut hash = new_vsi_bmff_hash(VSI_EXCLUSION_VALUE);
        hash.set_hash(vec![0; 32]);
        builder.add_assertion("c2pa.hash.bmff.v3", &hash).unwrap();
        builder
            .update_hash_from_stream("video/mp4", &mut std::io::Cursor::new(&draft))
            .unwrap();
        let mut signed_asset = std::io::Cursor::new(Vec::new());
        let store = builder
            .sign(
                &signer,
                "video/mp4",
                &mut std::io::Cursor::new(&draft),
                &mut signed_asset,
            )
            .unwrap();
        let digest = crate::utils::hash_utils::hash_by_alg("sha256", &store, None);
        let reference = crate::HashedUri::new(reference.url(), Some("sha256".into()), &digest);
        let provisional = assemble(reference.clone());
        assert_eq!(provisional.len(), draft.len());
        let map = SegmentInfoMap {
            sequence_number: 1,
            manifest_id: label,
            bmff_hash: build_segment_bmff_hash(&provisional).unwrap(),
            manifest_uri: Some(reference),
        };
        let emsg = build_emsg_box(
            &build_vsi_cose_sign1(
                &map,
                &vsi.session_keys[0].session_signing_key,
                &vsi.session_keys[0].kid,
            )
            .unwrap(),
            1,
            0,
            1,
        )
        .unwrap();
        let segment = [
            make_box(b"styp", b"cmfs\0\0\0\0cmfs"),
            emsg,
            make_box(b"mdat", &[1, 2, 3, 4]),
        ]
        .concat();
        assert_eq!(segment.len(), draft.len());
        let (context, calls) = remote_context(store, 200, true);
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert_eq!(
            tracker.filter_errors().count(),
            0,
            "{:?}",
            tracker.logged_items()
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_bad_store_hash_never_installs_keys() {
        let (_signer, mut vsi, init) = remote_manifest_fixture();
        let mut bytes = vsi.manifest_store().unwrap().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        let (context, calls) = remote_context(bytes, 200, true);
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .unwrap();
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.description.contains("hash does not match")));
        assert!(validator.session_keys.is_empty());
        assert!(validator.previous_segment.is_none());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_wrong_manifest_id_is_rejected() {
        let (_signer, mut vsi, init) = remote_manifest_fixture();
        let (context, _calls) = remote_context(vsi.manifest_store().unwrap().to_vec(), 200, true);
        vsi.active_manifest_id = Some("urn:c2pa:wrong".into());
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .unwrap();
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.description.contains("identifier does not match")));
        assert!(validator.session_keys.is_empty());
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_without_the_requested_kid_preserves_cached_keys() {
        let (signer, mut vsi, init) = remote_manifest_fixture();
        let (context, calls) = remote_context(vsi.manifest_store().unwrap().to_vec(), 200, true);
        vsi.session_keys[0].kid = b"not-in-store".to_vec();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .unwrap();
        let old = make_vsi_signer(&signer, b"old", 1);
        let cert = signer.certs().unwrap().remove(0);
        validator
            .validate_session_keys(
                &old.build_session_keys_assertion().unwrap(),
                "urn:c2pa:old",
                Some(&cert),
                &mut tracker,
            )
            .unwrap();
        let original = validator.session_keys.clone();
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.validation_status.as_deref() == Some("livevideo.segment.invalid")));
        assert_eq!(validator.session_keys, original);
        assert!(validator.previous_segment.is_none());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_http_error_and_wrong_asset_binding_are_rejected() {
        let (_signer, mut vsi, _init) = remote_manifest_fixture();
        let store = vsi.manifest_store().unwrap().to_vec();
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        for status in [404, 200] {
            let (context, calls) = remote_context(store.clone(), status, true);
            let mut validator = LiveVideoValidator::new();
            let mut tracker = StatusTracker::default();
            // No init asset is supplied, so the init manifest cannot validate its binding.
            validator
                .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
                .unwrap();
            assert!(tracker.filter_errors().count() > 0);
            assert!(validator.session_keys.is_empty());
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_supports_sha384_and_sha512() {
        let (_signer, mut vsi, init) = remote_manifest_fixture();
        let store = vsi.manifest_store().unwrap().to_vec();
        for alg in ["sha384", "sha512"] {
            // Start a fresh first-segment announcement for each algorithm.
            vsi.next_sequence_number = 1;
            let digest = crate::utils::hash_utils::hash_by_alg(alg, &store, None);
            vsi.set_manifest_uri(Some(crate::HashedUri::new(
                "https://live.example/manifest.c2pa".into(),
                Some(alg.into()),
                &digest,
            )))
            .unwrap();
            let (context, calls) = remote_context(store.clone(), 200, true);
            let mut validator = LiveVideoValidator::new();
            let mut tracker = StatusTracker::default();
            validator
                .validate_init_segment(&init, &mut tracker)
                .unwrap();
            let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
            validator
                .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
                .unwrap();
            assert_eq!(tracker.filter_errors().count(), 0);
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_rejects_malformed_store_even_when_its_digest_matches() {
        let (_signer, mut vsi, init) = remote_manifest_fixture();
        let body = b"not a C2PA manifest store".to_vec();
        let digest = crate::utils::hash_utils::hash_by_alg("sha256", &body, None);
        vsi.set_manifest_uri(Some(crate::HashedUri::new(
            "https://live.example/manifest.c2pa".into(),
            Some("sha256".into()),
            &digest,
        )))
        .unwrap();
        let (context, calls) = remote_context(body, 200, true);
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .unwrap();
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.description.contains("failed validation")));
        assert!(validator.session_keys.is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_obeys_receivers_trust_policy() {
        let (_signer, mut vsi, init) = remote_manifest_fixture();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut context = crate::Context::new();
        context
            .set_resolver(ManifestResolver {
                body: vsi.manifest_store().unwrap().to_vec(),
                status: 200,
                calls: calls.clone(),
            })
            .unwrap();
        let context = std::sync::Arc::new(context);
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .unwrap();
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.validation_status.as_deref() == Some("livevideo.manifest.invalid")));
        assert!(validator.session_keys.is_empty());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn manifest_uri_accepts_previously_published_keys_when_retrieved_later() {
        let (_signer, mut vsi, init) = remote_manifest_fixture();
        let (context, calls) = remote_context(vsi.manifest_store().unwrap().to_vec(), 200, true);
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_init_segment(&init, &mut tracker)
            .unwrap();
        vsi.next_sequence_number = 2; // key was configured with minimum 1
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        validator
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert_eq!(tracker.filter_errors().count(), 0);
        assert_eq!(validator.session_keys.len(), 1);
        assert_eq!(
            validator.previous_segment.as_ref().unwrap().sequence_number,
            2
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(not(feature = "fetch_remote_manifests"))]
    fn manifest_uri_never_fetches_without_the_compile_time_feature() {
        let (_signer, mut vsi, _init) = remote_manifest_fixture();
        let (context, calls) = remote_context(vsi.manifest_store().unwrap().to_vec(), 200, true);
        let segment = vsi.sign_media_segment(&make_test_segment()).unwrap();
        let mut tracker = StatusTracker::default();
        LiveVideoValidator::new()
            .validate_verifiable_segment_info_with_context(&segment, &context, &mut tracker)
            .unwrap();
        assert!(tracker
            .filter_errors()
            .any(|item| item.description.contains("enable fetch_remote_manifests")));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
