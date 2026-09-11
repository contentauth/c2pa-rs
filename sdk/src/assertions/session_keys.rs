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

//! Defines the `c2pa.session-keys` assertion ([§18.25]) for live video streams.
//!
//! [§18.25]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_session_keys

use serde::{Deserialize, Serialize};

use super::labels;
use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    cbor_types::DateT,
    Error, Result,
};

/// A single session key used to verify VSI signatures ([§18.25]).
///
/// [§18.25]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_session_keys
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionKey {
    /// COSE_Key (RFC 9052) with mandatory `kid`, stored as raw CBOR.
    pub key: c2pa_cbor::Value,
    /// First `sequenceNumber` this key is valid for ([§18.25.2]).
    ///
    /// [§18.25.2]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_session_keys
    pub min_sequence_number: u64,
    /// Key creation time, an RFC 3339 date-time string serialized as a CBOR tag 0
    /// date-time string on the wire, per §18.25.
    pub created_at: DateT,
    /// Seconds from `created_at` for which this key is valid.
    pub validity_period: u64,
    /// COSE_Sign1_Tagged binding this key to the signer's certificate, held as a native
    /// tagged CBOR value (`18([...])`) per §18.25.
    pub signer_binding: c2pa_cbor::Value,
}

impl SessionKey {
    /// Constructs a session key from ergonomic inputs, mapping them to the CBOR-native field
    /// types: `created_at` (an RFC 3339 string) becomes a tag 0 [`DateT`], and
    /// `signer_binding_tagged` — the COSE_Sign1_Tagged (`18([...])`) bytes of the detached
    /// binding — is decoded into a native tagged [`c2pa_cbor::Value`].
    pub fn new(
        key: c2pa_cbor::Value,
        min_sequence_number: u64,
        created_at: impl Into<String>,
        validity_period: u64,
        signer_binding_tagged: &[u8],
    ) -> Result<Self> {
        let signer_binding = c2pa_cbor::from_slice::<c2pa_cbor::Value>(signer_binding_tagged)
            .map_err(|e| Error::AssertionEncoding(format!("invalid signerBinding CBOR: {e}")))?;
        // Reject anything that isn't a COSE_Sign1_Tagged value up front, rather than deferring
        // the mismatch to signerBinding verification (§18.25 requires the `18([...])` tag).
        if !matches!(signer_binding, c2pa_cbor::Value::Tag(18, _)) {
            return Err(Error::AssertionEncoding(
                "signerBinding must be a COSE_Sign1_Tagged value (CBOR tag 18)".to_string(),
            ));
        }
        Ok(Self {
            key,
            min_sequence_number,
            created_at: DateT(created_at.into()),
            validity_period,
            signer_binding,
        })
    }
}

/// The `c2pa.session-keys` assertion embedded in a live video init segment manifest ([§18.25]).
///
/// [§18.25]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_session_keys
///
/// <div class="warning">
///
/// **Experimental.** This type is available only with the `unstable_live_video` feature
/// enabled. It is exempt from this crate's usual semantic-versioning stability guarantees and
/// may change in a backward-incompatible way, or be removed entirely, in any release.
///
/// </div>
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SessionKeys {
    /// The session keys published by this assertion. At least one per [§18.25].
    pub keys: Vec<SessionKey>,
}

impl SessionKeys {
    pub const LABEL: &'static str = labels::SESSION_KEYS;
}

impl AssertionBase for SessionKeys {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

impl AssertionCbor for SessionKeys {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::labels;

    fn minimal_session_key() -> SessionKey {
        // Minimal COSE_Key map: {1: 2} — kty: EC2
        let mut key_map = std::collections::BTreeMap::new();
        key_map.insert(
            c2pa_cbor::Value::Integer(1.into()),
            c2pa_cbor::Value::Integer(2.into()),
        );
        SessionKey {
            key: c2pa_cbor::Value::Map(key_map),
            min_sequence_number: 0,
            created_at: DateT("2026-01-01T00:00:00Z".to_string()),
            validity_period: 3600,
            // COSE_Sign1_Tagged shape: 18([protected, unprotected, payload, signature]).
            signer_binding: c2pa_cbor::Value::Tag(
                18,
                Box::new(c2pa_cbor::Value::Array(vec![
                    c2pa_cbor::Value::Bytes(vec![]),
                    c2pa_cbor::Value::Map(std::collections::BTreeMap::new()),
                    c2pa_cbor::Value::Bytes(vec![]),
                    c2pa_cbor::Value::Bytes(vec![]),
                ])),
            ),
        }
    }

    #[test]
    fn label_matches_spec() {
        assert_eq!(SessionKeys::LABEL, labels::SESSION_KEYS);
        assert_eq!(SessionKeys::LABEL, "c2pa.session-keys");
    }

    #[test]
    fn round_trip_cbor_single_key() {
        let original = SessionKeys {
            keys: vec![minimal_session_key()],
        };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn round_trip_cbor_multiple_keys() {
        let original = SessionKeys {
            keys: vec![minimal_session_key(), minimal_session_key()],
        };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn new_accepts_tag18_binding() {
        // 18([ h'a10127', {}, null, h'deadbeef' ]) — a well-formed COSE_Sign1_Tagged.
        let binding = c2pa_cbor::to_vec(&c2pa_cbor::Value::Tag(
            18,
            Box::new(c2pa_cbor::Value::Array(vec![
                c2pa_cbor::Value::Bytes(vec![0xa1, 0x01, 0x27]),
                c2pa_cbor::Value::Map(std::collections::BTreeMap::new()),
                c2pa_cbor::Value::Null,
                c2pa_cbor::Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
            ])),
        ))
        .unwrap();

        let key = SessionKey::new(
            c2pa_cbor::Value::Map(std::collections::BTreeMap::new()),
            0,
            "2026-01-01T00:00:00Z",
            3600,
            &binding,
        )
        .unwrap();
        assert!(matches!(key.signer_binding, c2pa_cbor::Value::Tag(18, _)));
    }

    #[test]
    fn new_rejects_untagged_binding() {
        // A bare (untagged) array decodes fine but is not a COSE_Sign1_Tagged value.
        let untagged = c2pa_cbor::to_vec(&c2pa_cbor::Value::Array(vec![
            c2pa_cbor::Value::Bytes(vec![0xa1, 0x01, 0x27]),
            c2pa_cbor::Value::Map(std::collections::BTreeMap::new()),
            c2pa_cbor::Value::Null,
            c2pa_cbor::Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        ]))
        .unwrap();

        let err = SessionKey::new(
            c2pa_cbor::Value::Map(std::collections::BTreeMap::new()),
            0,
            "2026-01-01T00:00:00Z",
            3600,
            &untagged,
        );
        assert!(err.is_err());
    }

    /// Per §18.25, `createdAt` is a CBOR tag 0 (standard date-time string) value. Guards the
    /// tag against being dropped on the wire.
    #[test]
    fn created_at_serializes_as_cbor_tag_0() {
        let keys = SessionKeys {
            keys: vec![minimal_session_key()],
        };
        let encoded = c2pa_cbor::to_vec(&keys).unwrap();

        // CBOR tag 0 is major type 6, value 0 => 0xc0; the tagged item that follows is the
        // RFC 3339 text string.
        let date = b"2026-01-01T00:00:00Z";
        let tag_then_date = encoded
            .windows(date.len() + 2)
            .any(|w| w[0] == 0xc0 && w[2..] == date[..]);
        assert!(
            tag_then_date,
            "createdAt must be encoded as CBOR tag 0 immediately followed by the date string"
        );
    }

    /// The spec requires tag 0, but a JSON round-trip strips CBOR tags, so an untagged string
    /// must still deserialize (matching `DateT`'s own long-standing behavior).
    #[test]
    fn created_at_accepts_untagged_string() {
        let keys = SessionKeys {
            keys: vec![minimal_session_key()],
        };
        let mut encoded = c2pa_cbor::to_vec(&keys).unwrap();

        let date = b"2026-01-01T00:00:00Z";
        let pos = encoded
            .windows(date.len() + 2)
            .position(|w| w[0] == 0xc0 && w[2..] == date[..])
            .unwrap();
        encoded.remove(pos); // drop the 0xc0 tag byte, leaving a bare text string

        let restored: SessionKeys = c2pa_cbor::from_slice(&encoded).unwrap();
        assert_eq!(restored.keys[0].created_at.0, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn round_trip_preserves_validity_period() {
        let key = SessionKey {
            validity_period: 86400,
            ..minimal_session_key()
        };
        let original = SessionKeys { keys: vec![key] };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(restored.keys[0].validity_period, 86400);
    }

    /// Per §18.25, `signerBinding` is a native COSE_Sign1_Tagged value (`18([...])`). Guards the
    /// tag against being dropped on the wire (it must not collapse to an opaque bstr).
    #[test]
    fn signer_binding_serializes_as_cbor_tag_18() {
        let keys = SessionKeys {
            keys: vec![minimal_session_key()],
        };
        let encoded = c2pa_cbor::to_vec(&keys).unwrap();

        // Tag 18 encodes as 0xd2; the tagged item that follows is the 4-element COSE_Sign1 array
        // (0x84). Guards against the binding collapsing to a bstr (major type 2).
        let tag18_then_array = encoded.windows(2).any(|w| w == [0xd2, 0x84]);
        assert!(
            tag18_then_array,
            "signerBinding must be encoded as CBOR tag 18 wrapping a 4-element array"
        );
    }

    /// The whole point of holding `SessionKey`'s CBOR-typed fields natively: the
    /// `Builder::add_assertion` path serializes via `to_value` and signs `to_vec` of that. This
    /// must preserve every field, including the tag 0 / tag 18 tags, so `SessionKeys` no longer
    /// needs a `cbor_override`. (The bytes differ from a direct `to_vec` of the struct only in
    /// map-key ordering — `to_value` collects into a sorted map — which is immaterial.)
    #[test]
    fn add_assertion_path_round_trips_with_tags() {
        let keys = SessionKeys {
            keys: vec![minimal_session_key()],
        };

        // Mirror Builder::add_assertion + sign: struct -> Value -> signed CBOR bytes.
        let value = c2pa_cbor::value::to_value(&keys).unwrap();
        let signed_bytes = c2pa_cbor::to_vec(&value).unwrap();

        // Tags survive the to_value hop.
        assert!(
            signed_bytes.windows(2).any(|w| w == [0xd2, 0x84]),
            "signerBinding tag 18 must survive the to_value path"
        );
        assert!(
            signed_bytes.windows(2).any(|w| w == [0xc0, 0x74]),
            "createdAt tag 0 must survive the to_value path"
        );

        let restored: SessionKeys = c2pa_cbor::from_slice(&signed_bytes).unwrap();
        assert_eq!(restored, keys);
    }
}
