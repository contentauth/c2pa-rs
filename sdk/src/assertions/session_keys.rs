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
    Result,
};

/// Serialize the `signer_binding` field as COSE_Sign1_Tagged (CBOR tag 18 + content).
///
/// The c2pa_cbor encoder recognizes `__cbor_tag_18__` in `serialize_newtype_struct`
/// and writes the proper CBOR tag 18 prefix before the inner value.
fn serialize_cose_sign1_tagged<S>(
    value: &c2pa_cbor::Value,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_newtype_struct("__cbor_tag_18__", value)
}

/// Deserialize the `signer_binding` field.
///
/// The c2pa_cbor decoder transparently strips CBOR tags, so whether the wire
/// format contains tag 18 (spec-compliant) or a raw bstr (legacy), the inner
/// value is returned as-is.
fn deserialize_cose_sign1_tagged<'de, D>(
    deserializer: D,
) -> std::result::Result<c2pa_cbor::Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    c2pa_cbor::Value::deserialize(deserializer)
}

/// Serialize the `created_at` field as a CBOR tag 0 date-time string, per §18.25.
///
/// The field is a plain `String` rather than [`DateT`] so that `SessionKey` is nameable and
/// constructible from outside the crate: `DateT` lives in a `pub(crate)` module, so a public
/// field of that type would be visible in the docs but impossible for a caller to write.
fn serialize_date_tagged<S>(value: &str, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    DateT(value.to_string()).serialize(serializer)
}

/// Deserialize the `created_at` field, accepting the spec's CBOR tag 0 date-time string (and,
/// like [`DateT`], an untagged string so the assertion survives a JSON round-trip).
fn deserialize_date_tagged<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    DateT::deserialize(deserializer).map(|d| d.0)
}

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
    /// Key creation time, an RFC 3339 date-time string.
    ///
    /// Serialized as a CBOR tag 0 date-time string on the wire, per §18.25.
    #[serde(
        serialize_with = "serialize_date_tagged",
        deserialize_with = "deserialize_date_tagged"
    )]
    pub created_at: String,
    /// Seconds from `created_at` for which this key is valid.
    pub validity_period: u64,
    /// COSE_Sign1_Tagged binding this key to the signer's certificate.
    ///
    /// Stored internally as the inner COSE_Sign1 content (without tag 18).
    /// The CBOR tag 18 is added/stripped transparently during serialization/deserialization.
    #[serde(
        serialize_with = "serialize_cose_sign1_tagged",
        deserialize_with = "deserialize_cose_sign1_tagged"
    )]
    pub signer_binding: c2pa_cbor::Value,
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
            created_at: "2026-01-01T00:00:00Z".to_string(),
            validity_period: 3600,
            signer_binding: c2pa_cbor::Value::Bytes(vec![]),
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

    /// Per §18.25, `createdAt` is a CBOR tag 0 (standard date-time string) value. The field is
    /// a plain `String` in Rust, so this guards the tag against being dropped on the wire.
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
        assert_eq!(restored.keys[0].created_at, "2026-01-01T00:00:00Z");
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
}
