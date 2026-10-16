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

//! Verifiable Segment Info (VSI) support for live video (C2PA section 19.4).
//!
//! VSI is a `COSE_Sign1_Tagged` structure carried in an ISO BMFF `emsg` box with
//! `scheme_id_uri = "urn:c2pa:verifiable-segment-info"` and `value = "fseg"`.
//! The COSE_Sign1 payload is a CBOR-encoded [`SegmentInfoMap`].
//!
//! See [C2PA Technical Specification section 19.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info).

use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

use crate::{Error, HashedUri, Result};

pub(super) const VSI_SCHEME_ID_URI: &str = "urn:c2pa:verifiable-segment-info";
const VSI_VALUE_FSEG: &str = "fseg";

/// Byte offset of the `scheme_id_uri` field from the start of an ISO BMFF `emsg`
/// box (8-byte BMFF header + 4-byte FullBox version/flags header).
pub(super) const VSI_URI_OFFSET_IN_EMSG: u64 = 12;

/// The `value` of the VSI `bmffHash` exclusion's data match: the `scheme_id_uri` bytes
/// including its NUL terminator (c2pa-org/specs-core#2542). Matching the terminator means
/// the exclusion applies only to `emsg` boxes whose scheme is exactly the VSI URI.
pub(super) const VSI_EXCLUSION_VALUE: &[u8] = b"urn:c2pa:verifiable-segment-info\0";

/// The earlier exclusion value, without the NUL terminator, still accepted on validation
/// during the transition. As a prefix it also matches longer schemes that start with the
/// VSI URI, which the lookalike check ([`has_vsi_excluded_non_vsi_emsg`]) rejects.
pub(super) const VSI_LEGACY_EXCLUSION_VALUE: &[u8] = VSI_SCHEME_ID_URI.as_bytes();

/// CBOR `segment-info-map` payload of the COSE_Sign1 in a VSI `emsg` box ([§19.4]).
///
/// [§19.4]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#verifiable_segment_info
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SegmentInfoMap {
    pub sequence_number: u64,
    pub bmff_hash: c2pa_cbor::Value,
    pub manifest_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_uri: Option<HashedUri>,
}

/// Returns the `COSE_Sign1_Tagged` bytes from the VSI `emsg` box in `segment_data`, if present.
pub fn extract_vsi_payload_from_segment(segment_data: &[u8]) -> Option<Vec<u8>> {
    extract_vsi_emsg(segment_data).map(|emsg| emsg.message_data)
}

/// The fields of a VSI `emsg` box (§19.4.2). Only `message_data` is covered by the
/// session key's signature; the timing fields are outside it and outside `bmffHash`.
pub(super) struct VsiEmsg {
    pub timescale: u32,
    pub presentation_time_delta: u32,
    pub event_duration: u32,
    pub message_data: Vec<u8>,
}

/// Returns the first VSI `emsg` box in `segment_data`, if present.
pub(super) fn extract_vsi_emsg(segment_data: &[u8]) -> Option<VsiEmsg> {
    find_emsg_boxes(segment_data)
        .into_iter()
        .find_map(|emsg_box| extract_vsi_from_emsg_box(&emsg_box))
}

/// Result of parsing a VSI COSE_Sign1_Tagged: the decoded map and the raw COSE structure.
pub struct ParsedVsi {
    pub segment_info_map: SegmentInfoMap,
    pub sign1: coset::CoseSign1,
}

/// Parses a [`SegmentInfoMap`] and the raw [`coset::CoseSign1`] from a `COSE_Sign1_Tagged` byte
/// slice. The caller can use `sign1` to verify the signature against a session key.
pub fn parse_vsi(cose_sign1_bytes: &[u8]) -> Result<ParsedVsi> {
    use coset::TaggedCborSerializable;

    let sign1 = coset::CoseSign1::from_tagged_slice(cose_sign1_bytes)
        .map_err(|e| Error::BadParam(format!("invalid COSE_Sign1 in VSI emsg: {e}")))?;

    let payload = sign1
        .payload
        .as_ref()
        .ok_or_else(|| Error::BadParam("COSE_Sign1 VSI payload is absent (detached)".into()))?;

    let segment_info_map: SegmentInfoMap = c2pa_cbor::from_slice(payload)
        .map_err(|e| Error::BadParam(format!("invalid SegmentInfoMap CBOR: {e}")))?;

    Ok(ParsedVsi {
        segment_info_map,
        sign1,
    })
}

/// Parses a [`SegmentInfoMap`] from a `COSE_Sign1_Tagged` byte slice.
///
/// Test-only: production code uses [`parse_vsi`], which also returns the raw `CoseSign1` needed
/// to verify the segment's signature; this discards it, so it's only a convenience for tests
/// that just want to inspect the decoded fields.
#[cfg(test)]
pub(crate) fn parse_segment_info_map(cose_sign1_bytes: &[u8]) -> Result<SegmentInfoMap> {
    parse_vsi(cose_sign1_bytes).map(|p| p.segment_info_map)
}

/// Returns `true` if `segment_data` has a top-level `emsg` box that a VSI `bmffHash`
/// exclusion (§19.4.1: xpath `/emsg`, `exclusion_value` at offset 12) matches but that
/// isn't a VSI `emsg` box: for example a version 1 `emsg` whose fields spell out the value
/// at that offset, or, with the legacy value, a longer `scheme_id_uri`.
pub(super) fn has_vsi_excluded_non_vsi_emsg(segment_data: &[u8], exclusion_value: &[u8]) -> bool {
    let uri_at = VSI_URI_OFFSET_IN_EMSG as usize;
    find_emsg_boxes(segment_data).iter().any(|emsg_box| {
        emsg_box.get(uri_at..uri_at + exclusion_value.len()) == Some(exclusion_value)
            && extract_vsi_from_emsg_box(emsg_box).is_none()
    })
}

fn find_emsg_boxes(segment_data: &[u8]) -> Vec<Vec<u8>> {
    super::box_walk::top_level_boxes(segment_data)
        .filter(|(fourcc, _)| **fourcc == *b"emsg")
        .map(|(_, box_bytes)| box_bytes.to_vec())
        .collect()
}

fn extract_vsi_from_emsg_box(emsg_box: &[u8]) -> Option<VsiEmsg> {
    let mut cursor = Cursor::new(emsg_box);

    // Skip box header (8 bytes: size + type).
    cursor.set_position(8);

    // version (1 byte) + flags (3 bytes).
    let mut version_flags = [0u8; 4];
    cursor.read_exact(&mut version_flags).ok()?;
    let version = version_flags[0];

    // C2PA spec requires emsg version 0 (SHALL be version 0).
    if version != 0 {
        return None;
    }

    let (scheme_id_uri, value, emsg) = parse_emsg_v0_body(&mut cursor)?;

    if scheme_id_uri != VSI_SCHEME_ID_URI || value != VSI_VALUE_FSEG {
        return None;
    }

    Some(emsg)
}

fn parse_emsg_v0_body(cursor: &mut Cursor<&[u8]>) -> Option<(String, String, VsiEmsg)> {
    let scheme_id_uri = read_null_terminated_string(cursor)?;
    let value = read_null_terminated_string(cursor)?;
    let timescale = read_u32(cursor)?;
    let presentation_time_delta = read_u32(cursor)?;
    let event_duration = read_u32(cursor)?;
    let _id = read_u32(cursor)?;
    let emsg = VsiEmsg {
        timescale,
        presentation_time_delta,
        event_duration,
        message_data: read_remaining(cursor),
    };
    Some((scheme_id_uri, value, emsg))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Option<u32> {
    let mut bytes = [0u8; 4];
    cursor.read_exact(&mut bytes).ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn read_null_terminated_string(cursor: &mut Cursor<&[u8]>) -> Option<String> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        cursor.read_exact(&mut byte).ok()?;
        if byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).ok()
}

fn read_remaining(cursor: &mut Cursor<&[u8]>) -> Vec<u8> {
    let mut data = Vec::new();
    let _ = cursor.read_to_end(&mut data);
    data
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn make_emsg_v0(scheme_id_uri: &str, value: &str, message_data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(scheme_id_uri.as_bytes());
        body.push(0); // null terminator
        body.extend_from_slice(value.as_bytes());
        body.push(0); // null terminator
        body.extend_from_slice(&[0u8; 16]); // timescale + presentation_time_delta + event_duration + id
        body.extend_from_slice(message_data);

        let total_size = 8u32 + 4 + body.len() as u32; // header + version/flags + body
        let mut emsg = Vec::new();
        emsg.extend_from_slice(&total_size.to_be_bytes());
        emsg.extend_from_slice(b"emsg");
        emsg.push(0); // version 0
        emsg.extend_from_slice(&[0u8; 3]); // flags
        emsg.extend_from_slice(&body);
        emsg
    }

    fn make_emsg_v1(scheme_id_uri: &str, value: &str, message_data: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8; 20]); // timescale + presentation_time + event_duration + id
        body.extend_from_slice(scheme_id_uri.as_bytes());
        body.push(0); // null terminator
        body.extend_from_slice(value.as_bytes());
        body.push(0); // null terminator
        body.extend_from_slice(message_data);

        let total_size = 8u32 + 4 + body.len() as u32;
        let mut emsg = Vec::new();
        emsg.extend_from_slice(&total_size.to_be_bytes());
        emsg.extend_from_slice(b"emsg");
        emsg.push(1); // version 1
        emsg.extend_from_slice(&[0u8; 3]); // flags
        emsg.extend_from_slice(&body);
        emsg
    }

    #[test]
    fn extracts_vsi_payload_from_v0_emsg() {
        let payload = b"cose_sign1_placeholder";
        let segment = make_emsg_v0(VSI_SCHEME_ID_URI, VSI_VALUE_FSEG, payload);
        let extracted = extract_vsi_payload_from_segment(&segment).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn rejects_vsi_from_v1_emsg() {
        let payload = b"cose_sign1_v1_placeholder";
        let segment = make_emsg_v1(VSI_SCHEME_ID_URI, VSI_VALUE_FSEG, payload);
        assert!(
            extract_vsi_payload_from_segment(&segment).is_none(),
            "emsg version 1 must be rejected per spec (SHALL be version 0)"
        );
    }

    #[test]
    fn ignores_emsg_with_wrong_scheme_id() {
        let payload = b"should_be_ignored";
        let segment = make_emsg_v0("urn:other:scheme", VSI_VALUE_FSEG, payload);
        assert!(extract_vsi_payload_from_segment(&segment).is_none());
    }

    #[test]
    fn ignores_emsg_with_wrong_value() {
        let payload = b"should_be_ignored";
        let segment = make_emsg_v0(VSI_SCHEME_ID_URI, "iseg", payload);
        assert!(extract_vsi_payload_from_segment(&segment).is_none());
    }

    /// Regression test: an `emsg` box truncated inside the fixed
    /// timescale/presentation_time_delta/event_duration/id fields (16 bytes per §19.4.2) must be
    /// rejected, not silently parsed with an empty `message_data`.
    #[test]
    fn rejects_emsg_truncated_in_fixed_fields() {
        let mut body = Vec::new();
        body.extend_from_slice(VSI_SCHEME_ID_URI.as_bytes());
        body.push(0);
        body.extend_from_slice(VSI_VALUE_FSEG.as_bytes());
        body.push(0);
        body.extend_from_slice(&[0u8; 10]); // 10 of the required 16 fixed-field bytes

        let total_size = 8u32 + 4 + body.len() as u32;
        let mut emsg = Vec::new();
        emsg.extend_from_slice(&total_size.to_be_bytes());
        emsg.extend_from_slice(b"emsg");
        emsg.push(0); // version 0
        emsg.extend_from_slice(&[0u8; 3]); // flags
        emsg.extend_from_slice(&body);

        assert!(extract_vsi_payload_from_segment(&emsg).is_none());
    }

    #[test]
    fn returns_none_for_segment_without_emsg() {
        let mut mdat = Vec::new();
        let size: u32 = 8;
        mdat.extend_from_slice(&size.to_be_bytes());
        mdat.extend_from_slice(b"mdat");
        assert!(extract_vsi_payload_from_segment(&mdat).is_none());
    }

    #[test]
    fn finds_vsi_emsg_among_multiple_boxes() {
        let payload = b"the_vsi_payload";
        let mut segment = Vec::new();

        // Non-VSI emsg box first
        segment.extend(make_emsg_v0("urn:other:scheme", "other", b"ignored"));
        // VSI emsg box second
        segment.extend(make_emsg_v0(VSI_SCHEME_ID_URI, VSI_VALUE_FSEG, payload));

        let extracted = extract_vsi_payload_from_segment(&segment).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn only_lookalike_emsg_boxes_count_as_excluded_but_not_vsi() {
        let vsi = make_emsg_v0(VSI_SCHEME_ID_URI, VSI_VALUE_FSEG, b"cose");
        let scte35 = make_emsg_v0("urn:scte:scte35:2013:bin", "1", b"\xfc\x30");
        let longer_scheme = make_emsg_v0(
            "urn:c2pa:verifiable-segment-info-extra",
            VSI_VALUE_FSEG,
            b"x",
        );
        let wrong_value = make_emsg_v0(VSI_SCHEME_ID_URI, "other", b"x");

        for value in [VSI_EXCLUSION_VALUE, VSI_LEGACY_EXCLUSION_VALUE] {
            assert!(!has_vsi_excluded_non_vsi_emsg(
                &[vsi.clone(), scte35.clone()].concat(),
                value
            ));
            // The exact scheme with another `value` is excluded by either form, so it has to
            // be rejected (c2pa-org/specs-core#2619).
            assert!(has_vsi_excluded_non_vsi_emsg(
                &[vsi.clone(), wrong_value.clone()].concat(),
                value
            ));
        }

        // Only the legacy prefix match excludes a longer scheme; with the NUL terminator it
        // stays in the hash.
        let with_longer = [vsi, longer_scheme].concat();
        assert!(has_vsi_excluded_non_vsi_emsg(
            &with_longer,
            VSI_LEGACY_EXCLUSION_VALUE
        ));
        assert!(!has_vsi_excluded_non_vsi_emsg(
            &with_longer,
            VSI_EXCLUSION_VALUE
        ));
    }

    #[test]
    fn exclusion_value_is_nul_terminated_scheme() {
        assert_eq!(
            VSI_EXCLUSION_VALUE,
            [VSI_SCHEME_ID_URI.as_bytes(), b"\0"].concat().as_slice()
        );
        assert_eq!(VSI_LEGACY_EXCLUSION_VALUE, VSI_SCHEME_ID_URI.as_bytes());
    }
}
