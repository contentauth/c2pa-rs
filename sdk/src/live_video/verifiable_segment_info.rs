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

fn find_emsg_boxes(segment_data: &[u8]) -> Vec<Vec<u8>> {
    super::box_walk::top_level_boxes(segment_data)
        .filter(|(fourcc, _)| **fourcc == *b"emsg")
        .map(|(_, box_bytes)| box_bytes.to_vec())
        .collect()
}

fn extract_vsi_from_emsg_box(emsg_box: &[u8]) -> Option<Vec<u8>> {
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

    let (scheme_id_uri, value, message_data) = parse_emsg_v0_body(&mut cursor)?;

    if scheme_id_uri != VSI_SCHEME_ID_URI || value != VSI_VALUE_FSEG {
        return None;
    }

    Some(message_data)
}

fn parse_emsg_v0_body(cursor: &mut Cursor<&[u8]>) -> Option<(String, String, Vec<u8>)> {
    let scheme_id_uri = read_null_terminated_string(cursor)?;
    let value = read_null_terminated_string(cursor)?;
    skip_bytes(cursor, 16)?; // timescale + presentation_time_delta + event_duration + id
    let message_data = read_remaining(cursor);
    Some((scheme_id_uri, value, message_data))
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

fn skip_bytes(cursor: &mut Cursor<&[u8]>, count: u64) -> Option<()> {
    let new_pos = cursor.position().checked_add(count)?;
    if new_pos > cursor.get_ref().len() as u64 {
        return None;
    }
    cursor.set_position(new_pos);
    Some(())
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
}
