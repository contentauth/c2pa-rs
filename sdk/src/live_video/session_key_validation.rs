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

use c2pa_raw_crypto::validator_for_signing_alg;
use coset::TaggedCborSerializable;

use super::{
    cose_key::{cose_key_to_der, kid_from_cose_key, signing_alg_from_cose_key},
    fail_validation,
    verifiable_segment_info::{extract_vsi_payload_from_segment, parse_vsi, ParsedVsi},
    LiveVideoValidator,
};
use crate::{
    assertions::SessionKey,
    error::{Error, Result},
    status_tracker::StatusTracker,
    validation_results::validation_codes::{
        LIVEVIDEO_ASSERTION_INVALID, LIVEVIDEO_SEGMENT_INVALID, LIVEVIDEO_SESSIONKEY_INVALID,
    },
};

impl LiveVideoValidator {
    pub(super) fn require_session_keys(&self, tracker: &mut StatusTracker) -> Result<()> {
        if self.session_keys.is_empty() {
            return fail_validation(
                "no session keys available; validate_session_keys must be called first",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        Ok(())
    }

    pub(super) fn extract_and_parse_vsi(
        &self,
        segment_data: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<ParsedVsi> {
        let vsi_bytes = match extract_vsi_payload_from_segment(segment_data) {
            Some(bytes) => bytes,
            None => {
                fail_validation(
                    "segment must contain a VSI emsg box (urn:c2pa:verifiable-segment-info)",
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                )?;
                return Err(Error::BadParam("livevideo.segment.invalid".into()));
            }
        };

        parse_vsi(&vsi_bytes).map_err(|_| {
            let _ = fail_validation(
                "failed to parse SegmentInfoMap from VSI COSE_Sign1 payload",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
            Error::BadParam("livevideo.segment.invalid".into())
        })
    }

    pub(super) fn resolve_session_key(
        &self,
        sign1: &coset::CoseSign1,
        tracker: &mut StatusTracker,
    ) -> Result<SessionKey> {
        let kid = &sign1.unprotected.key_id;
        if kid.is_empty() {
            fail_validation(
                "COSE_Sign1 unprotected header must contain a kid identifying the session key",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            )?;
            return Err(Error::BadParam("livevideo.segment.invalid".into()));
        }

        match self.find_session_key_by_kid(kid) {
            Some(sk) => Ok(sk),
            None => {
                // Per §19.7.3: "Validation fails if the key cannot be found ... and shall
                // fail with a failure code of livevideo.segment.invalid."
                fail_validation(
                    "no session key matches the kid in the COSE_Sign1 unprotected header",
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                )?;
                Err(Error::BadParam("livevideo.segment.invalid".into()))
            }
        }
    }

    /// Verifies the segment-info-map's `manifestId` matches the trusted manifest that carried
    /// the `c2pa.session-keys` assertion ([§19.4.4]).
    ///
    /// [§19.4.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_manifest_retrieval_from_the_manifestid_field
    pub(super) fn validate_vsi_manifest_id(
        &self,
        manifest_id: &str,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Some(expected) = &self.expected_manifest_id {
            if manifest_id != expected {
                return fail_validation(
                    format!(
                        "segment-info-map manifestId ({manifest_id:?}) does not match the \
                         verified manifest that carried the session keys ({expected:?})"
                    ),
                    LIVEVIDEO_SEGMENT_INVALID,
                    tracker,
                );
            }
        }
        Ok(())
    }

    pub(super) fn validate_vsi_sequence_bounds(
        &self,
        seq_num: u64,
        session_key: &SessionKey,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if seq_num < session_key.min_sequence_number {
            return fail_validation(
                "sequenceNumber is below the session key's minSequenceNumber",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }
        Ok(())
    }

    pub(super) fn validate_vsi_key_validity(
        &self,
        session_key: &SessionKey,
        sign1: &coset::CoseSign1,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        // Per §19.7.3, "the segment's presentation time is outside the key's validity period"
        // is a segment-info-map parsing error, coded livevideo.segment.invalid (not
        // livevideo.sessionkey.invalid, which is reserved for signerBinding/shape failures).
        if let Err(msg) = self.check_key_validity_period(session_key, sign1) {
            return fail_validation(msg, LIVEVIDEO_SEGMENT_INVALID, tracker);
        }
        Ok(())
    }

    pub(super) fn validate_vsi_signature(
        &self,
        sign1: &coset::CoseSign1,
        session_key: &SessionKey,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Err(msg) = self.verify_cose_sign1(sign1, session_key) {
            return fail_validation(msg, LIVEVIDEO_SEGMENT_INVALID, tracker);
        }
        Ok(())
    }

    pub(super) fn validate_vsi_sequence_continuity(
        &self,
        seq_num: u64,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if let Some(previous) = &self.previous_segment {
            if seq_num <= previous.sequence_number {
                return fail_validation(
                    "VSI sequenceNumber must be strictly greater than the previous segment's",
                    LIVEVIDEO_ASSERTION_INVALID,
                    tracker,
                );
            }
        }
        Ok(())
    }

    /// Verifies the segment's BMFF hash against the `bmffHash` in the segment-info-map (§19.7.3).
    ///
    /// `bmffHash` is a mandatory field of the segment-info-map (§19.4.1); a missing or `Null`
    /// value is rejected rather than treated as "nothing to verify", since that would let a
    /// signed COSE_Sign1 bind only `sequenceNumber`/`manifestId` while leaving the actual
    /// segment media completely unverified.
    pub(super) fn validate_vsi_bmff_hash(
        &self,
        segment_data: &[u8],
        bmff_hash_value: &c2pa_cbor::Value,
        tracker: &mut StatusTracker,
    ) -> Result<()> {
        if bmff_hash_value.is_null() {
            return fail_validation(
                "segment-info-map bmffHash is missing; VSI requires a hash binding the \
                 segment's media bytes",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        let mut bmff_hash: crate::assertions::BmffHash =
            match c2pa_cbor::value::from_value(bmff_hash_value.clone()) {
                Ok(h) => h,
                Err(e) => {
                    return fail_validation(
                        format!("failed to deserialize bmffHash from segment-info-map: {e}"),
                        LIVEVIDEO_SEGMENT_INVALID,
                        tracker,
                    );
                }
            };

        // Per §19.4.1, the `merkle` field shall be absent from a VSI bmffHash.
        if bmff_hash.merkle().is_some() {
            return fail_validation(
                "segment-info-map bmffHash must not contain a merkle field",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        // Per §19.4.1, bmffHash shall contain at least one exclusion-map scoped to the VSI
        // `emsg` box specifically (xpath "/emsg" with a `data` sub-field matching the VSI
        // scheme_id_uri) — not just any "/emsg" exclusion, which could also exclude an
        // unrelated (e.g. SCTE-35) emsg box coexisting in the same segment from the hash.
        let has_vsi_emsg_exclusion = bmff_hash.exclusions().iter().any(|excl| {
            excl.xpath == "/emsg"
                && excl.data.as_deref().is_some_and(|data| {
                    data.iter().any(|d| {
                        d.offset == super::verifiable_segment_info::VSI_URI_OFFSET_IN_EMSG
                            && d.value
                                == super::verifiable_segment_info::VSI_SCHEME_ID_URI.as_bytes()
                    })
                })
        });
        if !has_vsi_emsg_exclusion {
            return fail_validation(
                "segment-info-map bmffHash must contain an exclusion-map for xpath \"/emsg\" \
                 scoped to the VSI scheme_id_uri",
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        // bmff_version is `#[serde(skip)]` and doesn't survive the wire; the VSI CDDL
        // fixes this field to `c2pa.hash.bmff.v3` (§19.4.1).
        bmff_hash.set_bmff_version(3);

        if let Err(e) = bmff_hash.verify_in_memory_hash(segment_data, None) {
            return fail_validation(
                format!("segment bmffHash verification failed: {e}"),
                LIVEVIDEO_SEGMENT_INVALID,
                tracker,
            );
        }

        Ok(())
    }

    fn find_session_key_by_kid(&self, kid: &[u8]) -> Option<SessionKey> {
        self.session_keys
            .iter()
            .find(|sk| {
                kid_from_cose_key(&sk.key)
                    .map(|k| k == kid)
                    .unwrap_or(false)
            })
            .cloned()
    }

    fn check_key_validity_period(
        &self,
        key: &SessionKey,
        sign1: &coset::CoseSign1,
    ) -> std::result::Result<(), String> {
        use chrono::{DateTime, Duration, TimeZone, Utc};

        let created_at: DateTime<Utc> = key
            .created_at
            .parse()
            .map_err(|_| "session key createdAt is not a valid RFC 3339 datetime".to_string())?;

        let validity_seconds = i64::try_from(key.validity_period)
            .map_err(|_| "validityPeriod overflow".to_string())?;

        let expires_at = created_at + Duration::seconds(validity_seconds);

        // Per §19.4.1, the protected header's `iat` claims the segment's actual time of
        // signing. Prefer it over wall-clock time so validation done after the fact (e.g.
        // archival/VOD validation of a recorded live stream) checks the segment against the
        // time it was actually produced, not the time it happens to be validated.
        let claimed_time = extract_iat(sign1).and_then(|secs| Utc.timestamp_opt(secs, 0).single());
        let now = claimed_time.unwrap_or_else(Utc::now);

        // §19.4.1's validity window is [createdAt, createdAt + validityPeriod]. Only the upper
        // bound was checked before; a claimed `iat` (or, in principle, a clock skew on `now`)
        // before the key was even created must be rejected too, not just the expiry.
        //
        // `iat` (RFC 8392 NumericDate) is whole-seconds, while `createdAt` may carry sub-second
        // precision — comparing them directly would spuriously reject a segment signed in the
        // same wall-clock second the key was created, since flooring `iat` down can put it just
        // under a sub-second `createdAt`. Floor `created_at` to match `iat`'s granularity.
        let created_at_floor = Utc
            .timestamp_opt(created_at.timestamp(), 0)
            .single()
            .unwrap_or(created_at);
        if now < created_at_floor {
            return Err(format!(
                "session key not yet valid: createdAt={}, {}={now}",
                key.created_at,
                if claimed_time.is_some() { "iat" } else { "now" },
            ));
        }

        if now > expires_at {
            return Err(format!(
                "session key expired: createdAt={}, validityPeriod={}s, {}={now}",
                key.created_at,
                key.validity_period,
                if claimed_time.is_some() { "iat" } else { "now" },
            ));
        }

        Ok(())
    }

    fn verify_cose_sign1(
        &self,
        sign1: &coset::CoseSign1,
        session_key: &SessionKey,
    ) -> std::result::Result<(), String> {
        let alg = signing_alg_from_cose_key(&session_key.key)
            .ok_or_else(|| "unsupported key type/curve in session key".to_string())?;

        let public_key_der = cose_key_to_der(&session_key.key)
            .ok_or_else(|| "failed to convert session key to DER".to_string())?;

        let validator = validator_for_signing_alg(alg)
            .ok_or_else(|| format!("no validator available for {alg:?}"))?;

        let tbs = sign1.tbs_data(b"");

        validator
            .validate(&sign1.signature, &tbs, &public_key_der)
            .map_err(|e| format!("COSE_Sign1 signature verification failed: {e}"))
    }

    /// Verifies the `signerBinding` detached COSE_Sign1 on a session key (§18.25.2).
    ///
    /// Per the spec the `signerBinding` is signed by the **session key** and the
    /// detached payload is the signer's end-entity certificate encoded as a CBOR
    /// byte string.  Verification uses the session key's public key (from the
    /// `key` field of the session-key object).
    /// Returns `Ok(true)` if the key's `signerBinding` verifies against `ee_cert_der`,
    /// `Ok(false)` if it does not (a `livevideo.sessionkey.invalid` failure is recorded on
    /// `tracker` in that case), or `Err` for an unexpected internal error unrelated to the
    /// binding's validity.
    ///
    /// Per §19.7.3, a key whose `signerBinding` does not verify shall not be used to validate
    /// any media segment — callers must not treat this key as trusted when this returns `false`.
    pub(super) fn verify_signer_binding(
        &self,
        key: &SessionKey,
        ee_cert_der: &[u8],
        tracker: &mut StatusTracker,
    ) -> Result<bool> {
        let binding_bytes = extract_signer_binding_bytes(&key.signer_binding);
        let binding_bytes = match &binding_bytes {
            Some(b) if !b.is_empty() => b,
            _ => {
                return reject_signer_binding(
                    "session key signerBinding must be a non-empty COSE_Sign1_Tagged byte string",
                    tracker,
                );
            }
        };

        let sign1 = match coset::CoseSign1::from_tagged_slice(binding_bytes) {
            Ok(s) => s,
            Err(e) => {
                return reject_signer_binding(
                    format!("failed to parse signerBinding as COSE_Sign1: {e}"),
                    tracker,
                )
            }
        };

        let Some(alg) = signing_alg_from_cose_key(&key.key) else {
            return reject_signer_binding(
                "signerBinding: unsupported or missing algorithm in session COSE_Key",
                tracker,
            );
        };

        let Some(session_public_key_der) = cose_key_to_der(&key.key) else {
            return reject_signer_binding(
                "failed to convert session COSE_Key to DER for signerBinding verification",
                tracker,
            );
        };

        let Some(validator) = validator_for_signing_alg(alg) else {
            return reject_signer_binding(
                format!("no signature validator available for {alg:?}"),
                tracker,
            );
        };

        let external_payload = c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec()))
            .map_err(|e| {
                let _ = fail_validation(
                    format!("failed to CBOR-encode EE certificate for signerBinding: {e}"),
                    LIVEVIDEO_SESSIONKEY_INVALID,
                    tracker,
                );
                Error::BadParam("livevideo.sessionkey.invalid".into())
            })?;

        // signerBinding is a detached-payload COSE_Sign1: the cert bytes are the
        // external payload, not AAD. Use tbs_detached_data per RFC 9052 §4.4.
        let tbs = sign1.tbs_detached_data(&external_payload, b"");
        if let Err(e) = validator.validate(&sign1.signature, &tbs, &session_public_key_der) {
            return reject_signer_binding(
                format!("signerBinding signature verification failed: {e}"),
                tracker,
            );
        }

        Ok(true)
    }
}

/// Records a `livevideo.sessionkey.invalid` failure and returns `Ok(false)`, the shared shape
/// of every rejection branch in [`LiveVideoValidator::verify_signer_binding`].
fn reject_signer_binding(msg: impl Into<String>, tracker: &mut StatusTracker) -> Result<bool> {
    fail_validation(msg, LIVEVIDEO_SESSIONKEY_INVALID, tracker)?;
    Ok(false)
}

/// Extracts the `iat` ("claimed time of signing", §19.4.1/RFC 8392) protected header field, if
/// present, as a Unix timestamp in seconds.
fn extract_iat(sign1: &coset::CoseSign1) -> Option<i64> {
    sign1
        .protected
        .header
        .rest
        .iter()
        .find_map(|(label, value)| match label {
            coset::Label::Text(s) if s == "iat" => {
                value.as_integer().and_then(|i| i64::try_from(i).ok())
            }
            _ => None,
        })
}

/// Extracts raw COSE_Sign1_Tagged bytes from a `signerBinding` CBOR value.
///
/// The value may appear in different forms depending on the serialization roundtrip:
/// - `Value::Array` with 4 elements — COSE_Sign1 inner content, possibly from JSON roundtrip
///   where byte strings become integer arrays. Re-serialized with tag 18.
/// - `Value::Array` of integers — legacy: flat byte representation of tagged COSE_Sign1 bytes
/// - `Value::Bytes` — direct CBOR byte string (ideal CBOR-only case)
/// - `Value::Text` — base64-encoded string (serde_json with base64 for bytes)
fn extract_signer_binding_bytes(value: &c2pa_cbor::Value) -> Option<Vec<u8>> {
    match value {
        c2pa_cbor::Value::Array(items) if is_cose_sign1_array(items) => {
            // COSE_Sign1 inner array [protected, unprotected, payload, signature].
            // After a JSON roundtrip, bstr elements become integer arrays — coerce
            // them back to Bytes so that the CBOR re-serialization is spec-correct.
            let fixed =
                c2pa_cbor::Value::Array(items.iter().map(coerce_int_array_to_bytes).collect());
            let mut buf = Vec::new();
            c2pa_cbor::tags::encode_tagged(&mut buf, 18, &fixed).ok()?;
            Some(buf)
        }
        // Legacy: flat array of integers (Value::Bytes after JSON roundtrip)
        c2pa_cbor::Value::Array(items) => items
            .iter()
            .map(|v| match v {
                c2pa_cbor::Value::Integer(i) => u8::try_from(*i).ok(),
                _ => None,
            })
            .collect(),
        c2pa_cbor::Value::Bytes(bytes) => Some(bytes.clone()),
        c2pa_cbor::Value::Text(text) => {
            use base64::{engine::general_purpose, Engine};
            general_purpose::STANDARD
                .decode(text)
                .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(text))
                .ok()
        }
        _ => None,
    }
}

/// Returns true if the array looks like a COSE_Sign1 structure (4 elements
/// where not all are plain integers).
fn is_cose_sign1_array(items: &[c2pa_cbor::Value]) -> bool {
    items.len() == 4
        && items
            .iter()
            .any(|v| !matches!(v, c2pa_cbor::Value::Integer(_)))
}

/// If the value is an array of integers (from a JSON roundtrip of a CBOR bstr),
/// convert it back to `Value::Bytes`. Otherwise return the value unchanged.
fn coerce_int_array_to_bytes(value: &c2pa_cbor::Value) -> c2pa_cbor::Value {
    if let c2pa_cbor::Value::Array(items) = value {
        if let Some(bytes) = items
            .iter()
            .map(|v| match v {
                c2pa_cbor::Value::Integer(i) => u8::try_from(*i).ok(),
                _ => None,
            })
            .collect::<Option<Vec<u8>>>()
        {
            return c2pa_cbor::Value::Bytes(bytes);
        }
    }
    value.clone()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use coset::TaggedCborSerializable;

    use super::super::{test_helpers::*, LiveVideoValidator};
    use crate::{
        assertions::{SessionKey, SessionKeys},
        status_tracker::StatusTracker,
        validation_results::validation_codes::{
            LIVEVIDEO_SEGMENT_INVALID, LIVEVIDEO_SESSIONKEY_INVALID,
        },
    };

    fn cbor_int(val: i64) -> c2pa_cbor::Value {
        c2pa_cbor::Value::Integer(val)
    }

    fn minimal_session_keys() -> SessionKeys {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(1), cbor_int(2)); // kty: EC2
        map.insert(cbor_int(2), c2pa_cbor::Value::Bytes(b"k".to_vec())); // kid
        map.insert(cbor_int(-1), cbor_int(1)); // crv: P-256
        map.insert(cbor_int(-2), c2pa_cbor::Value::Bytes(vec![0; 32]));
        map.insert(cbor_int(-3), c2pa_cbor::Value::Bytes(vec![0; 32]));

        SessionKeys {
            keys: vec![SessionKey {
                key: c2pa_cbor::Value::Map(map),
                min_sequence_number: 0,
                created_at: chrono::Utc::now().to_rfc3339(),
                validity_period: 3600,
                signer_binding: c2pa_cbor::Value::Bytes(vec![]),
            }],
        }
    }

    /// Builds an `emsg` version 0 box with C2PA VSI scheme carrying `message_data`.
    fn make_vsi_emsg_box(message_data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(b"urn:c2pa:verifiable-segment-info\0");
        body.extend_from_slice(b"fseg\0");
        body.extend_from_slice(&[0u8; 16]); // timescale + pts_delta + duration + id
        body.extend_from_slice(message_data);

        let total_size = (8u32 + 4 + body.len() as u32).to_be_bytes();
        let mut emsg = Vec::new();
        emsg.extend_from_slice(&total_size);
        emsg.extend_from_slice(b"emsg");
        emsg.push(0); // version 0
        emsg.extend_from_slice(&[0u8; 3]); // flags
        emsg.extend_from_slice(&body);
        emsg
    }

    mod vsi_crypto_helpers {
        use super::*;
        use crate::{
            live_video::verifiable_segment_info::SegmentInfoMap, status_tracker::StatusTracker,
        };

        pub const TEST_KID: &[u8] = b"test-key-1";
        /// A stand-in for the label of the manifest that carried the session-keys assertion.
        /// Kept constant across a test's segments since `validate_vsi_manifest_id` now checks
        /// every VSI segment's `manifestId` against the trusted manifest captured at
        /// `validate_session_keys` time (§19.4.4).
        pub const TEST_MANIFEST_ID: &str = "urn:c2pa:test-manifest";

        pub fn test_ee_cert_der() -> Vec<u8> {
            let signer =
                crate::utils::ephemeral_signer::EphemeralSigner::new("test-vsi-validation.local")
                    .unwrap();
            signer.cert_chain_der[0].clone()
        }

        /// Generates an Ed25519 session key pair, matching what `LiveVideoVsiSigner` actually
        /// produces in production (session keys are always Ed25519; see `vsi_signing.rs`).
        pub fn generate_test_key_pair() -> (ed25519_dalek::SigningKey, c2pa_cbor::Value) {
            let signing_key = generate_ed25519_session_key();
            let cose_key = build_ed25519_cose_key_value(&signing_key.verifying_key(), TEST_KID);
            (signing_key, cose_key)
        }

        /// Builds a `SessionKeys` assertion with a real `signerBinding` over `ee_cert_der`, so
        /// `validate_session_keys`'s now-mandatory signerBinding check succeeds.
        pub fn session_keys_with_cose_key(
            cose_key: c2pa_cbor::Value,
            signing_key: &ed25519_dalek::SigningKey,
            ee_cert_der: &[u8],
        ) -> SessionKeys {
            let binding = make_signer_binding_for_ee_cert(signing_key, ee_cert_der);
            session_key_with_ed25519_binding(cose_key, binding)
        }

        pub fn make_signed_cose_sign1_bytes(
            segment_info_map: &SegmentInfoMap,
            signing_key: &ed25519_dalek::SigningKey,
        ) -> Vec<u8> {
            use coset::{iana, HeaderBuilder, TaggedCborSerializable};
            use ed25519_dalek::Signer;

            let payload = c2pa_cbor::to_vec(segment_info_map).unwrap();

            let protected = HeaderBuilder::new()
                .algorithm(iana::Algorithm::EdDSA)
                .build();

            let unprotected = HeaderBuilder::new().key_id(TEST_KID.to_vec()).build();

            let mut sign1 = coset::CoseSign1Builder::new()
                .protected(protected)
                .unprotected(unprotected)
                .payload(payload)
                .build();

            let tbs = sign1.tbs_data(b"");
            let sig: ed25519_dalek::Signature = signing_key.sign(&tbs);
            sign1.signature = sig.to_bytes().to_vec();

            sign1.to_tagged_vec().unwrap()
        }

        /// Builds a fully VSI-conformant signed media segment: a real, two-pass
        /// `c2pa.hash.bmff.v3` `bmffHash` (matching production's
        /// `LiveVideoVsiSigner::sign_media_segment`) over the `emsg` box plus a trailing
        /// `mdat` box, so `validate_vsi_bmff_hash`'s now-mandatory hash check succeeds.
        pub fn make_signed_vsi_segment(
            sequence_number: u64,
            manifest_id: &str,
            signing_key: &ed25519_dalek::SigningKey,
        ) -> Vec<u8> {
            let trailer = make_mdat_box();
            let build = |bmff_hash: c2pa_cbor::Value| -> Vec<u8> {
                let map = SegmentInfoMap {
                    sequence_number,
                    bmff_hash,
                    manifest_id: manifest_id.to_string(),
                    manifest_uri: None,
                };
                let mut seg =
                    super::make_vsi_emsg_box(&make_signed_cose_sign1_bytes(&map, signing_key));
                seg.extend_from_slice(&trailer);
                seg
            };

            let draft = build(
                crate::live_video::vsi_signing::build_segment_bmff_hash_placeholder().unwrap(),
            );
            let real_hash =
                crate::live_video::vsi_signing::build_segment_bmff_hash(&draft).unwrap();
            let signed = build(real_hash);
            assert_eq!(
                draft.len(),
                signed.len(),
                "draft/final VSI test segment size mismatch"
            );
            signed
        }

        pub fn setup_vsi_validator() -> (LiveVideoValidator, ed25519_dalek::SigningKey) {
            let (signing_key, cose_key) = generate_test_key_pair();
            let ee_cert_der = test_ee_cert_der();
            let mut validator = LiveVideoValidator::new();
            let mut tracker = StatusTracker::default();
            let keys = session_keys_with_cose_key(cose_key, &signing_key, &ee_cert_der);
            validator
                .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
                .unwrap();
            (validator, signing_key)
        }
    }

    // ── validate_session_keys ─────────────────────────────────────────────────

    #[test]
    fn session_keys_empty_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let _ =
            validator.validate_session_keys(&SessionKeys { keys: vec![] }, "", None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    #[test]
    fn session_keys_zero_validity_period_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                validity_period: 0,
                ..minimal_session_keys().keys.remove(0)
            }],
        };
        let _ = validator.validate_session_keys(&keys, "", None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    #[test]
    fn session_keys_missing_kid_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let mut key_map = std::collections::BTreeMap::new();
        key_map.insert(
            c2pa_cbor::Value::Integer(1),
            c2pa_cbor::Value::Integer(2), // kty: EC2
        );
        let keys = SessionKeys {
            keys: vec![SessionKey {
                key: c2pa_cbor::Value::Map(key_map),
                ..minimal_session_keys().keys.remove(0)
            }],
        };
        let _ = validator.validate_session_keys(&keys, "", None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    /// Per §19.7.3, a key whose `signerBinding` cannot be verified shall not be used. Without a
    /// manifest signer certificate to verify against, no key in the assertion can be verified,
    /// so `validate_session_keys` must fail closed (reject all keys) rather than accept them
    /// unchecked.
    #[test]
    fn session_keys_none_cert_fails_closed() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let _ = validator.validate_session_keys(&minimal_session_keys(), "", None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
        assert!(
            validator.session_keys.is_empty(),
            "no key should be trusted when its signerBinding could not be verified"
        );
    }

    // ── validate_verifiable_segment_info ───────────────────────────────────────

    #[test]
    fn vsi_without_session_keys_fails() {
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let _ = validator.validate_verifiable_segment_info(&make_mdat_box(), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[test]
    fn vsi_segment_without_emsg_fails() {
        let (mut validator, _) = vsi_crypto_helpers::setup_vsi_validator();
        let mut tracker = StatusTracker::default();

        let _ = validator.validate_verifiable_segment_info(&make_mdat_box(), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[test]
    fn vsi_segment_with_invalid_cose_fails() {
        let (mut validator, _) = vsi_crypto_helpers::setup_vsi_validator();
        let mut tracker = StatusTracker::default();

        let segment = make_vsi_emsg_box(b"not-a-cose-sign1");
        let _ = validator.validate_verifiable_segment_info(&segment, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[test]
    fn vsi_valid_sequence_advances_state() {
        use vsi_crypto_helpers::*;
        let (mut validator, signing_key) = setup_vsi_validator();
        let mut tracker = StatusTracker::default();

        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key),
                &mut tracker,
            )
            .unwrap();

        validator
            .validate_verifiable_segment_info(
                &make_signed_vsi_segment(2, TEST_MANIFEST_ID, &signing_key),
                &mut tracker,
            )
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn vsi_regressed_sequence_number_fails() {
        use vsi_crypto_helpers::*;

        use crate::validation_results::validation_codes::LIVEVIDEO_ASSERTION_INVALID;
        let (mut validator, signing_key) = setup_vsi_validator();
        let mut tracker = StatusTracker::default();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(5, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );
        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(4, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_ASSERTION_INVALID) }));
    }

    #[test]
    fn vsi_min_sequence_number_enforced() {
        use vsi_crypto_helpers::*;
        let (signing_key, cose_key) = generate_test_key_pair();
        let ee_cert_der = test_ee_cert_der();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                min_sequence_number: 10,
                ..session_keys_with_cose_key(cose_key, &signing_key, &ee_cert_der)
                    .keys
                    .remove(0)
            }],
        };
        validator
            .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
            .unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(5, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[test]
    fn vsi_expired_key_fails() {
        use vsi_crypto_helpers::*;
        let (signing_key, cose_key) = generate_test_key_pair();
        let ee_cert_der = test_ee_cert_der();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                created_at: "2020-01-01T00:00:00Z".to_string(),
                validity_period: 1,
                ..session_keys_with_cose_key(cose_key, &signing_key, &ee_cert_der)
                    .keys
                    .remove(0)
            }],
        };
        validator
            .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
            .unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );

        // Per §19.7.3, "the segment's presentation time is outside the key's validity
        // period" is coded livevideo.segment.invalid.
        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    /// Regression test: the validity window is [createdAt, createdAt + validityPeriod], not
    /// just an upper (expiry) bound. A segment claiming to be signed before its own session
    /// key's createdAt must be rejected too.
    #[test]
    fn vsi_key_not_yet_valid_fails() {
        use vsi_crypto_helpers::*;
        let (signing_key, cose_key) = generate_test_key_pair();
        let ee_cert_der = test_ee_cert_der();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let keys = SessionKeys {
            keys: vec![SessionKey {
                created_at: "2099-01-01T00:00:00Z".to_string(),
                validity_period: 3600,
                ..session_keys_with_cose_key(cose_key, &signing_key, &ee_cert_der)
                    .keys
                    .remove(0)
            }],
        };
        validator
            .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
            .unwrap();

        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &signing_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    #[test]
    fn vsi_bad_signature_fails() {
        use vsi_crypto_helpers::*;
        let (correct_signing_key, cose_key) = generate_test_key_pair();
        let ee_cert_der = test_ee_cert_der();
        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();

        let keys = session_keys_with_cose_key(cose_key, &correct_signing_key, &ee_cert_der);
        validator
            .validate_session_keys(&keys, TEST_MANIFEST_ID, Some(&ee_cert_der), &mut tracker)
            .unwrap();

        let (other_key, _) = generate_test_key_pair();
        let _ = validator.validate_verifiable_segment_info(
            &make_signed_vsi_segment(1, TEST_MANIFEST_ID, &other_key),
            &mut tracker,
        );

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SEGMENT_INVALID) }));
    }

    // ── signer_binding verification (§18.25.2) ─────────────────────────────────
    //
    // Per the spec, signerBinding is a **detached** COSE_Sign1 where the session
    // key signs the signer's EE certificate (as CBOR byte string).

    fn generate_ed25519_session_key() -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    fn build_ed25519_cose_key_value(
        verifying_key: &ed25519_dalek::VerifyingKey,
        kid: &[u8],
    ) -> c2pa_cbor::Value {
        let mut map = std::collections::BTreeMap::new();
        map.insert(cbor_int(1), cbor_int(1)); // kty: OKP
        map.insert(cbor_int(2), c2pa_cbor::Value::Bytes(kid.to_vec())); // kid
        map.insert(cbor_int(-1), cbor_int(6)); // crv: Ed25519
        map.insert(
            cbor_int(-2),
            c2pa_cbor::Value::Bytes(verifying_key.as_bytes().to_vec()),
        ); // x
        c2pa_cbor::Value::Map(map)
    }

    fn make_signer_binding_for_ee_cert(
        session_signing_key: &ed25519_dalek::SigningKey,
        ee_cert_der: &[u8],
    ) -> Vec<u8> {
        use coset::{iana, HeaderBuilder, TaggedCborSerializable};
        use ed25519_dalek::Signer;

        let external_payload =
            c2pa_cbor::to_vec(&c2pa_cbor::Value::Bytes(ee_cert_der.to_vec())).unwrap();

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        let mut sign1 = coset::CoseSign1Builder::new().protected(protected).build();

        let tbs = sign1.tbs_detached_data(&external_payload, b"");
        let sig: ed25519_dalek::Signature = session_signing_key.sign(&tbs);
        sign1.signature = sig.to_bytes().to_vec();
        sign1.to_tagged_vec().unwrap()
    }

    fn session_key_with_ed25519_binding(
        cose_key: c2pa_cbor::Value,
        binding_bytes: Vec<u8>,
    ) -> SessionKeys {
        SessionKeys {
            keys: vec![SessionKey {
                key: cose_key,
                min_sequence_number: 0,
                created_at: chrono::Utc::now().to_rfc3339(),
                validity_period: 3600,
                signer_binding: c2pa_cbor::Value::Bytes(binding_bytes),
            }],
        }
    }

    #[test]
    fn signer_binding_valid_passes() {
        let signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("test-binding.local").unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");
        let binding = make_signer_binding_for_ee_cert(&session_key, &ee_cert_der);
        let keys = session_key_with_ed25519_binding(cose_key, binding);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        validator
            .validate_session_keys(&keys, "", Some(&ee_cert_der), &mut tracker)
            .unwrap();

        assert!(!tracker.logged_items().iter().any(|i| {
            i.validation_status
                .as_deref()
                .map(|s| s.starts_with("livevideo"))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn signer_binding_bad_signature_fails() {
        let signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("test-binding.local").unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");

        // Sign with a *different* session key — binding won't match the `key` field
        let other_session_key = generate_ed25519_session_key();
        let binding = make_signer_binding_for_ee_cert(&other_session_key, &ee_cert_der);
        let keys = session_key_with_ed25519_binding(cose_key, binding);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        let _ = validator.validate_session_keys(&keys, "", Some(&ee_cert_der), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    /// Per §19.7.3, a key whose `signerBinding` cannot be verified shall not be used. Without a
    /// manifest signer certificate, `validate_session_keys` must fail closed rather than accept
    /// the key unchecked (this used to silently skip the check and accept the key).
    #[test]
    fn signer_binding_none_cert_fails_closed() {
        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");
        let keys = session_key_with_ed25519_binding(cose_key, vec![0xde, 0xad]);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        let _ = validator.validate_session_keys(&keys, "", None, &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
        assert!(
            validator.session_keys.is_empty(),
            "no key should be trusted when its signerBinding could not be verified"
        );
    }

    #[test]
    fn signer_binding_wrong_ee_cert_fails() {
        let signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("test-binding.local").unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");
        let binding = make_signer_binding_for_ee_cert(&session_key, &ee_cert_der);
        let keys = session_key_with_ed25519_binding(cose_key, binding);

        // Validate with a different EE cert — signerBinding should fail
        let other_signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("other-cert.local").unwrap();
        let other_ee_cert = other_signer.cert_chain_der[0].clone();

        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        let _ = validator.validate_session_keys(&keys, "", Some(&other_ee_cert), &mut tracker);

        assert!(tracker
            .logged_items()
            .iter()
            .any(|i| { i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID) }));
    }

    /// Regression test: per §19.7.3, a key whose `signerBinding` fails to verify shall not be
    /// used to validate any media segment. Verifies the key is dropped from the validator's
    /// trusted key set entirely, not merely flagged in the tracker while still being usable.
    #[test]
    fn signer_binding_bad_signature_key_is_not_retained() {
        let signer =
            crate::utils::ephemeral_signer::EphemeralSigner::new("test-binding.local").unwrap();
        let ee_cert_der = signer.cert_chain_der[0].clone();

        let session_key = generate_ed25519_session_key();
        let cose_key = build_ed25519_cose_key_value(&session_key.verifying_key(), b"k");

        // Sign with a *different* session key — binding won't match the `key` field.
        let other_session_key = generate_ed25519_session_key();
        let binding = make_signer_binding_for_ee_cert(&other_session_key, &ee_cert_der);
        let keys = session_key_with_ed25519_binding(cose_key, binding);

        let mut validator = LiveVideoValidator::new();
        let mut tracker = StatusTracker::default();
        let _ = validator.validate_session_keys(&keys, "", Some(&ee_cert_der), &mut tracker);

        assert!(
            validator.session_keys.is_empty(),
            "a key with a failed signerBinding must not be retained for segment validation"
        );
    }

    // ── COSE_Sign1 wire format tests (§18.25.2) ─────────────────────────────────

    #[test]
    fn signer_binding_is_cose_sign1_tagged() {
        // Verify the COSE_Sign1 starts with CBOR tag 18 (0xD2)
        let session_key = generate_ed25519_session_key();
        let ee_cert_der = b"fake-cert-for-tag-test";
        let binding_bytes = make_signer_binding_for_ee_cert(&session_key, ee_cert_der);

        assert!(
            !binding_bytes.is_empty(),
            "binding bytes should not be empty"
        );
        assert_eq!(
            binding_bytes[0], 0xd2,
            "signerBinding must start with CBOR tag 18 (0xD2), got 0x{:02X}",
            binding_bytes[0]
        );
    }

    #[test]
    fn signer_binding_payload_is_detached() {
        // Per §18.25.2, the COSE_Sign1 payload must be null (detached)
        let session_key = generate_ed25519_session_key();
        let binding_bytes = make_signer_binding_for_ee_cert(&session_key, b"cert");

        let sign1 = coset::CoseSign1::from_tagged_slice(&binding_bytes).unwrap();
        assert!(
            sign1.payload.is_none(),
            "signerBinding payload must be None (detached), got {:?}",
            sign1.payload
        );
    }

    #[test]
    fn signer_binding_protected_header_contains_algorithm() {
        let session_key = generate_ed25519_session_key();
        let binding_bytes = make_signer_binding_for_ee_cert(&session_key, b"cert");

        let sign1 = coset::CoseSign1::from_tagged_slice(&binding_bytes).unwrap();
        let alg = sign1.protected.header.alg;
        assert_eq!(
            alg,
            Some(coset::RegisteredLabelWithPrivate::Assigned(
                coset::iana::Algorithm::EdDSA
            )),
            "signerBinding protected header must contain alg = EdDSA"
        );
    }

    #[test]
    fn cose_key_contains_alg_field() {
        // build_ed25519_cose_key must include field 3 (alg = -8 EdDSA) per RFC 9052
        let session_key = generate_ed25519_session_key();
        let key = super::super::cose_key::build_ed25519_cose_key(
            &session_key.verifying_key(),
            b"test-kid",
        );

        if let c2pa_cbor::Value::Map(map) = &key {
            let alg_value = map.get(&c2pa_cbor::Value::Integer(3));
            assert_eq!(
                alg_value,
                Some(&c2pa_cbor::Value::Integer(-8)),
                "COSE_Key must contain field 3 (alg) = -8 (EdDSA)"
            );
        } else {
            panic!("COSE_Key must be a CBOR map");
        }
    }

    // ── extract_signer_binding_bytes shape-sniffing ──────────────────────────────
    //
    // `signerBinding` normally round-trips as `Value::Bytes` (a tagged COSE_Sign1_Tagged
    // bstr), but callers that pass a `SessionKeys` assertion through a JSON intermediate
    // representation (or a hand-authored one) can produce three other shapes that must still
    // be accepted.

    #[test]
    fn extract_signer_binding_bytes_from_native_bytes() {
        let raw = vec![0xd2, 0x01, 0x02, 0x03];
        let value = c2pa_cbor::Value::Bytes(raw.clone());

        assert_eq!(super::extract_signer_binding_bytes(&value), Some(raw));
    }

    #[test]
    fn extract_signer_binding_bytes_from_base64_text() {
        use base64::{engine::general_purpose, Engine};

        let raw = vec![0xd2, 0xaa, 0xbb, 0xcc];
        let value = c2pa_cbor::Value::Text(general_purpose::STANDARD.encode(&raw));

        assert_eq!(super::extract_signer_binding_bytes(&value), Some(raw));
    }

    #[test]
    fn extract_signer_binding_bytes_from_unpadded_base64_text() {
        use base64::{engine::general_purpose, Engine};

        let raw = vec![0xd2, 0x01, 0x02];
        let value = c2pa_cbor::Value::Text(general_purpose::STANDARD_NO_PAD.encode(&raw));

        assert_eq!(super::extract_signer_binding_bytes(&value), Some(raw));
    }

    #[test]
    fn extract_signer_binding_bytes_from_legacy_flat_integer_array() {
        // A `Value::Bytes` that went through a JSON roundtrip comes back as a flat array of
        // integers (all elements, so `is_cose_sign1_array` doesn't misidentify it).
        let raw = vec![0xd2u8, 0x01, 0x02, 0x03];
        let value = c2pa_cbor::Value::Array(
            raw.iter()
                .map(|&b| c2pa_cbor::Value::Integer(b as i64))
                .collect(),
        );

        assert_eq!(super::extract_signer_binding_bytes(&value), Some(raw));
    }

    #[test]
    fn extract_signer_binding_bytes_from_cose_sign1_shaped_array() {
        // A 4-element [protected, unprotected, payload, signature] array with at least one
        // non-integer element (here, the bstr protected header) — as COSE_Sign1 would look
        // after being decoded into a generic `Value` and losing its CBOR tag 18.
        let value = c2pa_cbor::Value::Array(vec![
            c2pa_cbor::Value::Bytes(vec![0xa1, 0x01, 0x27]), // protected header bstr
            c2pa_cbor::Value::Map(std::collections::BTreeMap::new()), // unprotected header
            c2pa_cbor::Value::Null,                          // detached payload
            c2pa_cbor::Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]), // signature
        ]);

        let extracted = super::extract_signer_binding_bytes(&value).unwrap();

        // Re-encoded as a tagged (tag 18) COSE_Sign1: starts with the tag-18 prefix.
        assert_eq!(extracted[0], 0xd2, "must be CBOR-tagged (tag 18)");
        let decoded: c2pa_cbor::Value = c2pa_cbor::from_slice(&extracted).unwrap();
        match decoded {
            c2pa_cbor::Value::Array(items) => assert_eq!(items.len(), 4),
            other => panic!("expected a 4-element array, got {other:?}"),
        }
    }

    #[test]
    fn extract_signer_binding_bytes_returns_none_for_unsupported_shape() {
        let value = c2pa_cbor::Value::Integer(42);
        assert_eq!(super::extract_signer_binding_bytes(&value), None);
    }
}
