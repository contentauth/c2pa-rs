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

//! Shared ISO BMFF top-level box walker for live_video's small (KB-to-low-MB) in-memory init
//! and media segment buffers.
//!
//! Handles the 32-bit and 64-bit (`size == 1`) box-size forms, and `size == 0` (box extends to
//! the end of `data`). Stops silently (as if `data` ended) at the first malformed or truncated
//! box header, since every caller in this module treats a malformed remainder as "no more boxes
//! to examine" rather than a hard parse error — segment/init data here is attacker-controlled,
//! and none of these callers need to distinguish "well-formed but absent" from "truncated".
//!
//! Deliberately does not build on [`crate::asset_handlers::bmff_io::BMFFArena`]: that type does
//! a full recursive parse of the entire box tree into a heap-allocated arena (with a
//! path-indexed map and an 80-entry FullBox lookup table) in order to answer general
//! C2PA-manifest queries. That's substantially more work than a single-pass top-level scan
//! needs for the narrow "does this box exist" / "give me this one child box's bytes" queries
//! this module makes.

/// Iterates over the top-level boxes in `data`, yielding `(fourcc, box_bytes)` — `box_bytes`
/// includes the box's own header.
pub(super) fn top_level_boxes(data: &[u8]) -> impl Iterator<Item = (&[u8; 4], &[u8])> {
    TopLevelBoxes { data, pos: 0 }
}

/// Returns the first top-level box in `data` matching `fourcc`, full bytes (header included).
pub(super) fn find_box<'a>(data: &'a [u8], fourcc: &[u8; 4]) -> Option<&'a [u8]> {
    top_level_boxes(data)
        .find(|(f, _)| *f == fourcc)
        .map(|(_, bytes)| bytes)
}

/// Returns `true` if `data` contains a top-level box matching `fourcc`.
pub(super) fn contains_box_type(data: &[u8], fourcc: &[u8; 4]) -> bool {
    top_level_boxes(data).any(|(f, _)| f == fourcc)
}

/// Returns the payload of a box (its bytes after the size/type header), or `None` if the box
/// is truncated shorter than its own header.
pub(super) fn box_payload(box_bytes: &[u8]) -> Option<&[u8]> {
    let size = u32::from_be_bytes(box_bytes.get(0..4)?.try_into().ok()?);
    if size == 1 {
        box_bytes.get(16..)
    } else {
        box_bytes.get(8..)
    }
}

struct TopLevelBoxes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for TopLevelBoxes<'a> {
    type Item = (&'a [u8; 4], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos.checked_add(8)? > self.data.len() {
            return None;
        }

        let size = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().ok()?);
        let fourcc: &[u8; 4] = self.data[self.pos + 4..self.pos + 8].try_into().ok()?;

        let (header_len, box_size) = if size == 1 {
            let largesize = u64::from_be_bytes(
                self.data
                    .get(self.pos + 8..self.pos + 16)?
                    .try_into()
                    .ok()?,
            );
            (16usize, usize::try_from(largesize).ok()?)
        } else if size == 0 {
            (8usize, self.data.len() - self.pos)
        } else {
            (8usize, size as usize)
        };

        if box_size < header_len {
            return None;
        }
        let box_end = self.pos.checked_add(box_size)?;
        if box_end > self.data.len() {
            return None;
        }

        let box_bytes = &self.data[self.pos..box_end];
        self.pos = box_end;
        Some((fourcc, box_bytes))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn make_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        b.extend_from_slice(fourcc);
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn finds_first_matching_box() {
        let data = [make_box(b"ftyp", &[]), make_box(b"moov", b"abc")].concat();
        let found = find_box(&data, b"moov").unwrap();
        assert_eq!(box_payload(found).unwrap(), b"abc");
    }

    #[test]
    fn returns_none_when_box_absent() {
        let data = make_box(b"ftyp", &[]);
        assert!(find_box(&data, b"moov").is_none());
        assert!(!contains_box_type(&data, b"moov"));
    }

    #[test]
    fn top_level_boxes_yields_all_siblings_in_order() {
        let data = [
            make_box(b"ftyp", &[]),
            make_box(b"moov", &[]),
            make_box(b"mdat", &[]),
        ]
        .concat();
        let fourccs: Vec<[u8; 4]> = top_level_boxes(&data).map(|(f, _)| *f).collect();
        assert_eq!(fourccs, [*b"ftyp", *b"moov", *b"mdat"]);
    }

    #[test]
    fn handles_size_zero_as_extends_to_end() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_be_bytes()); // size == 0
        data.extend_from_slice(b"mdat");
        data.extend_from_slice(b"trailing-payload");
        let found = find_box(&data, b"mdat").unwrap();
        assert_eq!(found.len(), data.len());
    }

    #[test]
    fn handles_64_bit_largesize() {
        let payload = b"abc";
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_be_bytes()); // size == 1: largesize follows
        data.extend_from_slice(b"mdat");
        data.extend_from_slice(&((16 + payload.len()) as u64).to_be_bytes());
        data.extend_from_slice(payload);
        let found = find_box(&data, b"mdat").unwrap();
        assert_eq!(box_payload(found).unwrap(), payload);
    }

    /// Regression test: a box shorter than its own declared header (`size` between 1 and 7)
    /// must stop the scan, not advance by less than a header and byte-crawl through the rest.
    #[test]
    fn rejects_box_size_shorter_than_header() {
        let mut data = Vec::new();
        data.extend_from_slice(&4u32.to_be_bytes()); // size == 4, shorter than the 8-byte header
        data.extend_from_slice(b"junk");
        assert!(top_level_boxes(&data).next().is_none());
    }

    #[test]
    fn stops_at_truncated_header_instead_of_panicking() {
        let data = [0u8, 0, 0, 20, b'm', b'o', b'o']; // declares 20 bytes but only 7 present, no full fourcc
        assert_eq!(top_level_boxes(&data).count(), 0);
    }
}
