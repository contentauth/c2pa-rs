// Copyright 2023 Adobe. All rights reserved.
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

use std::{
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    path::*,
};

use extfmt::Hexlify;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor, AssertionJson},
    assertions::labels,
    asset_io::{AssetBoxHash, CAIRead},
    error::{Error, Result},
    hash_utils::hash_by_alg,
    maybe_send_sync::MaybeSend,
    utils::{
        hash_utils::{hash_stream_by_alg_with_progress, vec_compare, HashRange},
        io_utils::ReaderUtils,
    },
    validation_results::validation_codes::{
        ASSERTION_BOXESHASH_MALFORMED, ASSERTION_BOXHASH_UNKNOWN_BOX,
    },
};

const ASSERTION_CREATION_VERSION: usize = 1;

pub const C2PA_BOXHASH: &str = "C2PA";

/// A byte range within one of a [`BoxMap`]'s named boxes, excluded from that
/// entry's hash. See the `box-exclusions-map` CDDL rule for this assertion.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BoxExclusion {
    /// Offset from the start of the referenced box.
    pub start: u64,
    pub length: u64,

    /// 0-based index into [`BoxMap::names`]. Omittable only when `names`
    /// has one entry. Signed (per CDDL `int`) so a negative wire value is a
    /// validation error, not a deserialize failure.
    #[serde(rename = "boxIndex", skip_serializing_if = "Option::is_none")]
    pub box_index: Option<i64>,
}

/// A caller-specified byte range to exclude when generating a [`BoxHash`],
/// targeting the box at `source_box_index` in [`AssetBoxHash::get_box_map`]'s
/// output (0-based, file order).
#[derive(Clone, Debug)]
pub struct BoxHashExclusionRequest {
    pub source_box_index: usize,
    pub start: u64,
    pub length: u64,
}

/// What a box's content represents, for spec §15.12.3's exclusion-content
/// validation: only `C2pa` and `Metadata` boxes may be excluded. Always
/// derived by the format-specific [`AssetBoxHash::get_box_map`] from the
/// *live* asset being verified - never trusted from the assertion itself,
/// so [`BoxMap::kind`] is never serialized (like `range_start`/`range_len`).
#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub enum BoxKind {
    /// Ordinary structural/payload content. Exclusions are not permitted.
    #[default]
    Content,
    /// A box this format's classifier has no specific rule for. Treated
    /// identically to `Content` (exclusions not permitted) - kept distinct
    /// only so classifiers stay exhaustive instead of silently folding
    /// unrecognized boxes into a name that implies positive identification.
    Unknown,
    /// The C2PA Manifest Store box itself.
    C2pa,
    /// Asset metadata (EXIF/XMP/IPTC-equivalent) per spec §9.2.6. May be
    /// excluded.
    Metadata,
}

#[derive(Serialize, Default, Deserialize, Debug, PartialEq, Eq)]
pub struct BoxMap {
    pub names: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    pub hash: ByteBuf,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusions: Option<Vec<BoxExclusion>>,

    pub pad: ByteBuf,

    #[serde(skip)]
    pub range_start: u64,

    #[serde(skip)]
    pub range_len: u64,

    #[serde(skip)]
    pub kind: BoxKind,
}

impl BoxMap {
    // diagnostic tool to show hashes for boxes
    pub fn dump_box(&self, mut reader: &mut dyn CAIRead, alg: &str) -> Result<()> {
        print!("box names: ");
        for name in &self.names {
            print!("{name}, ");
        }

        // get the hash
        reader.seek(SeekFrom::Start(self.range_start))?;
        let to_be_hashed = reader.read_to_vec(self.range_len)?;
        let (hash, len) = (hash_by_alg(alg, &to_be_hashed, None), to_be_hashed.len());

        println!("data len: {}, hash: {}", len, Hexlify(&hash));
        Ok(())
    }
}

/// Resolves `exclusions`' `boxIndex`-relative ranges against `box_ranges`/
/// `box_kinds` (the absolute range and [`BoxKind`] of each name in a
/// box-hash-map entry, in order). Rejects any exclusion targeting a
/// `Content`/`Unknown` box (spec §15.12.3: only the C2PA store or asset
/// metadata may be excluded). Returns the ordered sub-ranges of
/// `[entry_start, entry_start + entry_len)` left to hash once the exclusions
/// are punched out, plus whether any referenced box was `Metadata` (for the
/// informational `additionalExclusionsPresent` status).
fn split_exclusions(
    box_ranges: &[(u64, u64)],
    box_kinds: &[BoxKind],
    entry_start: u64,
    entry_len: u64,
    exclusions: &[BoxExclusion],
) -> Result<(Vec<HashRange>, bool)> {
    // `box_kinds` is meant to be parallel to `box_ranges` (every call site
    // pushes to both together); the lookup below degrades safely rather than
    // panicking if that invariant is ever broken, but assert it explicitly
    // so a caller mistake fails a debug/test build instead of silently
    // falling back to always-reject.
    debug_assert_eq!(box_ranges.len(), box_kinds.len());

    // Structural problems with the exclusions array itself (bad/missing
    // boxIndex, overflow, unordered ranges) are spec §15.12.3's
    // `assertion.boxesHash.malformed`, not a hash/content mismatch.
    let malformed = || Error::C2PAValidation(ASSERTION_BOXESHASH_MALFORMED.to_string());

    let entry_end = entry_start.checked_add(entry_len).ok_or_else(malformed)?;

    let mut abs_ranges: Vec<(u64, u64)> = Vec::with_capacity(exclusions.len());
    let mut metadata_used = false;
    for excl in exclusions {
        let box_index = match excl.box_index {
            Some(idx) if idx >= 0 => usize::try_from(idx).map_err(|_| malformed())?,
            Some(_) => return Err(malformed()),
            None if box_ranges.len() == 1 => 0,
            None => return Err(malformed()),
        };

        let (box_start, box_len) = box_ranges.get(box_index).ok_or_else(malformed)?;

        match box_kinds.get(box_index).copied().unwrap_or_default() {
            BoxKind::Content | BoxKind::Unknown => {
                return Err(Error::HashMismatch(
                    "box hash exclusion targets content that is not the C2PA store or asset metadata"
                        .to_string(),
                ));
            }
            BoxKind::Metadata => metadata_used = true,
            BoxKind::C2pa => {}
        }

        let excl_end = excl.start.checked_add(excl.length).ok_or_else(malformed)?;

        // Spec: an exclusion range ending past the end of its own box is a
        // content mismatch, not a structural malformation.
        if excl_end > *box_len {
            return Err(Error::HashMismatch(
                "box hash exclusion range extends beyond the end of its box".to_string(),
            ));
        }

        let abs_start = box_start.checked_add(excl.start).ok_or_else(malformed)?;
        let abs_end = box_start.checked_add(excl_end).ok_or_else(malformed)?;

        abs_ranges.push((abs_start, abs_end));
    }

    // Validate the sequence as given (not sorted) - the spec requires
    // exclusions to already be in increasing, non-overlapping order.
    for i in 1..abs_ranges.len() {
        if abs_ranges[i - 1].1 > abs_ranges[i].0 {
            return Err(malformed());
        }
    }

    let mut ranges = Vec::new();
    let mut cursor = entry_start;
    for (abs_start, abs_end) in abs_ranges {
        if abs_start > cursor {
            ranges.push(HashRange::new(cursor, abs_start - cursor));
        }
        cursor = abs_end.max(cursor);
    }
    if cursor < entry_end {
        ranges.push(HashRange::new(cursor, entry_end - cursor));
    }

    // An empty Vec (the whole entry excluded) would make
    // `hash_stream_by_alg_with_progress` fall back to hashing the entire
    // stream, so keep an explicit zero-length range instead.
    if ranges.is_empty() {
        ranges.push(HashRange::new(entry_start, 0));
    }

    Ok((ranges, metadata_used))
}

/// Helper class to create BoxHash assertion
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct BoxHash {
    pub boxes: Vec<BoxMap>,
}

impl BoxHash {
    pub const LABEL: &'static str = labels::BOX_HASH;

    pub fn verify_hash(
        &self,
        asset_path: &Path,
        alg: Option<&str>,
        bhp: &dyn AssetBoxHash,
    ) -> Result<()> {
        let mut file = File::open(asset_path)?;

        self.verify_stream_hash(&mut file, alg, bhp)
    }

    pub fn verify_in_memory_hash(
        &self,
        data: &[u8],
        alg: Option<&str>,
        bhp: &dyn AssetBoxHash,
    ) -> Result<()> {
        let mut reader = Cursor::new(data);

        self.verify_stream_hash(&mut reader, alg, bhp)
    }

    pub fn verify_stream_hash(
        &self,
        reader: &mut dyn CAIRead,
        alg: Option<&str>,
        bhp: &dyn AssetBoxHash,
    ) -> Result<()> {
        self.verify_stream_hash_with_progress(reader, alg, bhp, &mut |_, _| Ok(()))
            .map(|_metadata_exclusion_used| ())
    }

    /// Like [`verify_stream_hash`] but fires `progress(step, total)` once per hashed
    /// box so callers with a [`Context`] can report `ProgressPhase::VerifyingAssetHash`
    /// ticks and support cancellation.
    ///
    /// Returns whether any `exclusions` entry referenced a `BoxKind::Metadata`
    /// box, for the informational `assertion.boxesHash.additionalExclusionsPresent`
    /// status.
    pub(crate) fn verify_stream_hash_with_progress<F>(
        &self,
        reader: &mut dyn CAIRead,
        alg: Option<&str>,
        bhp: &dyn AssetBoxHash,
        progress: &mut F,
    ) -> Result<bool>
    where
        F: FnMut(u32, u32) -> Result<()>,
    {
        if self.boxes.is_empty() {
            return Err(Error::HashMismatch("No box hash found".to_string()));
        }

        let source_bms = bhp.get_box_map(reader)?;
        let mut source_index = 0;

        if let Some(first_expected_bms) = source_bms.get(source_index) {
            if first_expected_bms
                .names
                .first()
                .is_some_and(|name| name == "PNGh")
                && self.boxes[0]
                    .names
                    .first()
                    .is_some_and(|name| name != "PNGh")
            {
                source_index += 1;
            }
        } else {
            return Err(Error::HashMismatch("No data boxes found".to_string()));
        };

        let mut metadata_exclusion_used = false;

        for bm in &self.boxes {
            let mut skip_c2pa = false;
            let mut inclusion = HashRange::new(0u64, 0u64);
            let mut box_ranges: Vec<(u64, u64)> = Vec::with_capacity(bm.names.len());
            let mut box_kinds: Vec<BoxKind> = Vec::with_capacity(bm.names.len());
            for name in &bm.names {
                match source_bms.get(source_index) {
                    Some(next_source_bm) if name == &next_source_bm.names[0] => {
                        box_ranges.push((next_source_bm.range_start, next_source_bm.range_len));
                        box_kinds.push(next_source_bm.kind);

                        if inclusion.length() == 0 {
                            inclusion.set_start(next_source_bm.range_start);
                            inclusion.set_length(next_source_bm.range_len);

                            if name == C2PA_BOXHASH {
                                if bm.names.len() != 1 {
                                    return Err(Error::HashMismatch(
                                        "Malformed C2PA box hash".to_owned(),
                                    ));
                                }
                                skip_c2pa = true;
                            }
                        } else {
                            let len_to_this_seg = next_source_bm.range_start - inclusion.start();
                            inclusion.set_length(len_to_this_seg + next_source_bm.range_len);
                        }
                    }
                    Some(_) => {
                        return Err(Error::HashMismatch(
                            ASSERTION_BOXHASH_UNKNOWN_BOX.to_owned(),
                        ));
                    }
                    None => {
                        return Err(Error::HashMismatch(
                            ASSERTION_BOXHASH_UNKNOWN_BOX.to_owned(),
                        ))
                    }
                }
                source_index += 1;
            }

            let exclude = bm.excluded.unwrap_or(false);
            if skip_c2pa || exclude {
                continue;
            }

            let inclusions = match &bm.exclusions {
                Some(excl) if !excl.is_empty() => {
                    let (ranges, metadata_used) = split_exclusions(
                        &box_ranges,
                        &box_kinds,
                        inclusion.start(),
                        inclusion.length(),
                        excl,
                    )?;
                    metadata_exclusion_used |= metadata_used;
                    ranges
                }
                _ => vec![inclusion],
            };

            let curr_alg = match &bm.alg {
                Some(a) => a.clone(),
                None => match alg {
                    Some(a) => a.to_owned(),
                    None => return Err(Error::HashMismatch("No algorithm specified".to_string())),
                },
            };

            let computed = hash_stream_by_alg_with_progress(
                &curr_alg,
                reader,
                Some(inclusions),
                false,
                progress,
            )?;

            if !vec_compare(&bm.hash, &computed) {
                return Err(Error::HashMismatch("Hashes do not match".to_owned()));
            }
        }

        Ok(metadata_exclusion_used)
    }

    pub fn generate_box_hash_from_stream<R>(
        &mut self,
        reader: &mut R,
        alg: &str,
        bhp: &dyn AssetBoxHash,
        minimal_form: bool,
    ) -> Result<()>
    where
        R: Read + Seek + MaybeSend,
    {
        self.generate_box_hash_from_stream_with_progress(reader, alg, bhp, minimal_form, |_, _| {
            Ok(())
        })
    }

    /// Like [`generate_box_hash_from_stream`] but fires `progress(step, total)` once
    /// per hashed box so callers with a [`Context`] can report `ProgressPhase::Hashing`
    /// ticks and support cancellation.
    pub(crate) fn generate_box_hash_from_stream_with_progress<R, F>(
        &mut self,
        reader: &mut R,
        alg: &str,
        bhp: &dyn AssetBoxHash,
        minimal_form: bool,
        progress: F,
    ) -> Result<()>
    where
        R: Read + Seek + MaybeSend,
        F: FnMut(u32, u32) -> Result<()>,
    {
        self.generate_box_hash_from_stream_with_progress_and_exclusions(
            reader,
            alg,
            bhp,
            minimal_form,
            &[],
            progress,
        )
    }

    /// Like [`generate_box_hash_from_stream`], but `exclusion_requests` carves byte
    /// ranges out of specific source boxes' hashes, producing a spec-conformant
    /// `exclusions` field (see [`BoxExclusion`]) on the resulting entries.
    pub fn generate_box_hash_from_stream_with_exclusions<R>(
        &mut self,
        reader: &mut R,
        alg: &str,
        bhp: &dyn AssetBoxHash,
        minimal_form: bool,
        exclusion_requests: &[BoxHashExclusionRequest],
    ) -> Result<()>
    where
        R: Read + Seek + MaybeSend,
    {
        self.generate_box_hash_from_stream_with_progress_and_exclusions(
            reader,
            alg,
            bhp,
            minimal_form,
            exclusion_requests,
            |_, _| Ok(()),
        )
    }

    /// Like [`generate_box_hash_from_stream_with_exclusions`] but fires
    /// `progress(step, total)` once per hashed box.
    pub(crate) fn generate_box_hash_from_stream_with_progress_and_exclusions<R, F>(
        &mut self,
        reader: &mut R,
        alg: &str,
        bhp: &dyn AssetBoxHash,
        minimal_form: bool,
        exclusion_requests: &[BoxHashExclusionRequest],
        mut progress: F,
    ) -> Result<()>
    where
        R: Read + Seek + MaybeSend,
        F: FnMut(u32, u32) -> Result<()>,
    {
        // get source box list
        let source_bms = bhp.get_box_map(reader)?;

        if minimal_form {
            let mut before_c2pa = BoxMap {
                names: Vec::new(),
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                excluded: None,
                exclusions: None,
                kind: BoxKind::Content,
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 0,
            };
            let mut before_c2pa_ranges: Vec<(u64, u64)> = Vec::new();
            let mut before_c2pa_kinds: Vec<BoxKind> = Vec::new();
            let mut before_c2pa_exclusions: Vec<BoxExclusion> = Vec::new();

            let mut c2pa_box = BoxMap {
                names: Vec::new(),
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                excluded: None,
                exclusions: None,
                kind: BoxKind::Content,
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 0,
            };

            let mut after_c2pa = BoxMap {
                names: Vec::new(),
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                excluded: None,
                exclusions: None,
                kind: BoxKind::Content,
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 0,
            };
            let mut after_c2pa_ranges: Vec<(u64, u64)> = Vec::new();
            let mut after_c2pa_kinds: Vec<BoxKind> = Vec::new();
            let mut after_c2pa_exclusions: Vec<BoxExclusion> = Vec::new();

            let mut is_before_c2pa = true;

            // collapse map list to minimal set
            for (source_index, bm) in source_bms.into_iter().enumerate() {
                if bm.names[0] == "C2PA" {
                    // there should only be 1 collapsed C2PA range
                    if bm.names.len() != 1 {
                        return Err(Error::HashMismatch("Malformed C2PA box hash".to_owned()));
                    }

                    c2pa_box = bm;
                    is_before_c2pa = false;
                    continue;
                }

                let (group, group_ranges, group_kinds, group_exclusions) = if is_before_c2pa {
                    (
                        &mut before_c2pa,
                        &mut before_c2pa_ranges,
                        &mut before_c2pa_kinds,
                        &mut before_c2pa_exclusions,
                    )
                } else {
                    (
                        &mut after_c2pa,
                        &mut after_c2pa_ranges,
                        &mut after_c2pa_kinds,
                        &mut after_c2pa_exclusions,
                    )
                };

                // `names` and `group_ranges` grow in lockstep, so this box's
                // position in `group_ranges` (before pushing) is also its
                // future position in `group.names` - i.e. its `boxIndex`.
                let box_index_in_group = group_ranges.len();
                group_ranges.push((bm.range_start, bm.range_len));
                group_kinds.push(bm.kind);
                for req in exclusion_requests {
                    if req.source_box_index == source_index {
                        group_exclusions.push(BoxExclusion {
                            start: req.start,
                            length: req.length,
                            box_index: Some(box_index_in_group as i64),
                        });
                    }
                }

                if group.range_len == 0 {
                    group.range_start = bm.range_start;
                    group.range_len = bm.range_len;
                } else {
                    group.range_len += bm.range_len;
                }
                group.names.extend(bm.names);
            }

            if !before_c2pa_exclusions.is_empty() {
                before_c2pa.exclusions = Some(before_c2pa_exclusions);
            }
            if !after_c2pa_exclusions.is_empty() {
                after_c2pa.exclusions = Some(after_c2pa_exclusions);
            }

            // Instead of assuming we can combine all of the different ranges of
            // box hashes, we will check the bounds of each one
            let mut boxes = Vec::<BoxMap>::new();
            let mut boxes_ranges = Vec::<Vec<(u64, u64)>>::new();
            let mut boxes_kinds = Vec::<Vec<BoxKind>>::new();
            // Only add if we have some before the C2PA box
            if before_c2pa.range_len > 0 {
                boxes_ranges.push(before_c2pa_ranges);
                boxes_kinds.push(before_c2pa_kinds);
                boxes.push(before_c2pa);
            }
            // Do the same for the actual C2PA box
            if c2pa_box.range_len > 0 {
                boxes_ranges.push(vec![(c2pa_box.range_start, c2pa_box.range_len)]);
                boxes_kinds.push(vec![c2pa_box.kind]);
                boxes.push(c2pa_box);
            }
            // And finally, add the boxes after the C2PA box
            if after_c2pa.range_len > 0 {
                boxes_ranges.push(after_c2pa_ranges);
                boxes_kinds.push(after_c2pa_kinds);
                boxes.push(after_c2pa);
            }
            self.boxes = boxes;

            // compute the hashes
            for ((bm, box_ranges), box_kinds) in self
                .boxes
                .iter_mut()
                .zip(boxes_ranges.iter())
                .zip(boxes_kinds.iter())
            {
                // skip c2pa box
                if bm.names[0] == C2PA_BOXHASH {
                    continue;
                }

                let inclusions = match &bm.exclusions {
                    Some(excl) if !excl.is_empty() => {
                        split_exclusions(box_ranges, box_kinds, bm.range_start, bm.range_len, excl)?
                            .0
                    }
                    _ => vec![HashRange::new(bm.range_start, bm.range_len)],
                };
                bm.hash = ByteBuf::from(hash_stream_by_alg_with_progress(
                    alg,
                    reader,
                    Some(inclusions),
                    false,
                    &mut progress,
                )?);
            }
        } else {
            for (source_index, mut bm) in source_bms.into_iter().enumerate() {
                if bm.names[0] == "C2PA" {
                    // there should only be 1 collapsed C2PA range
                    if bm.names.len() != 1 {
                        return Err(Error::HashMismatch("Malformed C2PA box hash".to_owned()));
                    }
                    bm.hash = ByteBuf::from(vec![0]);
                    bm.pad = ByteBuf::from(vec![]);
                    self.boxes.push(bm);
                    continue;
                }

                let box_ranges = [(bm.range_start, bm.range_len)];
                let box_kinds = [bm.kind];
                let exclusions: Vec<BoxExclusion> = exclusion_requests
                    .iter()
                    .filter(|req| req.source_box_index == source_index)
                    .map(|req| BoxExclusion {
                        start: req.start,
                        length: req.length,
                        box_index: None,
                    })
                    .collect();

                let inclusions = if exclusions.is_empty() {
                    vec![HashRange::new(bm.range_start, bm.range_len)]
                } else {
                    split_exclusions(
                        &box_ranges,
                        &box_kinds,
                        bm.range_start,
                        bm.range_len,
                        &exclusions,
                    )?
                    .0
                };

                bm.alg = Some(alg.to_string());
                bm.hash = ByteBuf::from(hash_stream_by_alg_with_progress(
                    alg,
                    reader,
                    Some(inclusions),
                    false,
                    &mut progress,
                )?);
                bm.pad = ByteBuf::from(vec![]);
                bm.exclusions = if exclusions.is_empty() {
                    None
                } else {
                    Some(exclusions)
                };
                self.boxes.push(bm);
            }
        }

        Ok(())
    }
}

impl AssertionCbor for BoxHash {}

impl AssertionJson for BoxHash {}

impl AssertionBase for BoxHash {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn to_assertion(&self) -> crate::error::Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> crate::error::Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

#[cfg(feature = "file_io")]
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    #[cfg(test)]
    use crate::{jumbf_io::get_assetio_handler_from_path, utils::test::fixture_path};

    #[test]
    fn test_hash_verify_jpg() {
        let ap = fixture_path("CA.jpg");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, false)
            .unwrap();

        // see if they match reading
        bh.verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_hash_verify_jpg_reduced() {
        let ap = fixture_path("CA.jpg");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, true)
            .unwrap();

        // see if they match reading
        bh.verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_hash_verify_png() {
        let ap = fixture_path("libpng-test.png");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, false)
            .unwrap();

        // see if they match reading
        bh.verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_hash_verify_no_pngh() {
        let ap = fixture_path("libpng-test.png");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, false)
            .unwrap();

        bh.boxes.remove(0); // remove PNGh

        // see if they match reading
        bh.verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_json_round_trop() {
        let ap = fixture_path("CA.jpg");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, true)
            .unwrap();

        // save and reload JSON
        let bh_json_assertion = bh.to_json_assertion().unwrap();
        println!("Box hash json: {:?}", bh_json_assertion.decode_data());

        let reloaded_bh = BoxHash::from_json_assertion(&bh_json_assertion).unwrap();

        // see if they match reading
        reloaded_bh
            .verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_cbor_round_trop() {
        let ap = fixture_path("CA.jpg");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, true)
            .unwrap();

        // save and reload CBOR
        let bh_cbor_assertion = bh.to_cbor_assertion().unwrap();
        println!("Box hash cbor: {:?}", bh_cbor_assertion.decode_data());

        let reloaded_bh = BoxHash::from_cbor_assertion(&bh_cbor_assertion).unwrap();

        // see if they match reading
        reloaded_bh
            .verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    // Setup a mock for the AssetBoxHash trait
    mockall::mock! {
        pub MABH { }
        impl AssetBoxHash for MABH {
            fn get_box_map(&self, reader: &mut dyn CAIRead) -> Result<Vec<BoxMap>>;
        }
    }

    #[test]
    fn test_with_no_box_hashes_after_c2pa() {
        // Algorithm to use
        let alg = "sha256";
        // Create a mock object
        let mut mock = MockMABH::new();
        // Setup the expectation when asked for the box map
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![
                // Make sure the first one is the C2PA box
                BoxMap {
                    names: vec!["C2PA".to_string()],
                    alg: Some(alg.to_string()),
                    hash: ByteBuf::from(vec![0]),
                    excluded: None,
                    exclusions: None,
                    kind: BoxKind::C2pa,
                    pad: ByteBuf::from(vec![]),
                    range_start: 0,
                    range_len: 10,
                },
                // And follow with
                BoxMap {
                    names: vec!["test".to_string()],
                    alg: Some(alg.to_string()),
                    hash: ByteBuf::from(vec![0]),
                    excluded: None,
                    exclusions: None,
                    kind: BoxKind::Content,
                    pad: ByteBuf::from(vec![]),
                    range_start: 10,
                    range_len: 10,
                },
            ])
        });
        // The data size must match what we return in the expectation
        let data = vec![0u8; 20];
        // And create a reader on that data, for the API call
        let mut reader = Cursor::new(data);
        // Create the BoxHash object
        let mut bh = BoxHash { boxes: Vec::new() };
        // And generate the box hashes
        let result = bh.generate_box_hash_from_stream(&mut reader, alg, &mock, true);
        // We should expect an OK result
        assert!(result.is_ok());
        // With a total of 2 boxes
        assert_eq!(bh.boxes.len(), 2);
        assert_eq!(bh.boxes[0].names[0], "C2PA");
        assert_eq!(bh.boxes[1].names[0], "test");
    }

    #[test]
    fn test_with_no_box_hashes_before_c2pa() {
        // Algorithm to use
        let alg = "sha256";
        // Create a mock object
        let mut mock = MockMABH::new();
        // Setup the expectation when asked for the box map
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![
                // And follow with
                BoxMap {
                    names: vec!["test".to_string()],
                    alg: Some(alg.to_string()),
                    hash: ByteBuf::from(vec![0]),
                    excluded: None,
                    exclusions: None,
                    kind: BoxKind::Content,
                    pad: ByteBuf::from(vec![]),
                    range_start: 0,
                    range_len: 10,
                },
                // Make sure the first one is the C2PA box
                BoxMap {
                    names: vec!["C2PA".to_string()],
                    alg: Some(alg.to_string()),
                    hash: ByteBuf::from(vec![0]),
                    excluded: None,
                    exclusions: None,
                    kind: BoxKind::C2pa,
                    pad: ByteBuf::from(vec![]),
                    range_start: 10,
                    range_len: 10,
                },
            ])
        });
        // The data size must match what we return in the expectation
        let data = vec![0u8; 20];
        // And create a reader on that data, for the API call
        let mut reader = Cursor::new(data);
        // Create the BoxHash object
        let mut bh = BoxHash { boxes: Vec::new() };
        // And generate the box hashes
        let result = bh.generate_box_hash_from_stream(&mut reader, alg, &mock, true);
        // We should expect an OK result
        assert!(result.is_ok());
        // With a total of 2 boxes
        assert_eq!(bh.boxes.len(), 2);
        assert_eq!(bh.boxes[0].names[0], "test");
        assert_eq!(bh.boxes[1].names[0], "C2PA");
    }

    #[test]
    fn test_with_no_box_hashes_before_and_after_c2pa() {
        // Algorithm to use
        let alg = "sha256";
        // Create a mock object
        let mut mock = MockMABH::new();
        // Setup the expectation when asked for the box map
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![
                // And follow with
                BoxMap {
                    names: vec!["test".to_string()],
                    alg: Some(alg.to_string()),
                    hash: ByteBuf::from(vec![0]),
                    excluded: None,
                    exclusions: None,
                    kind: BoxKind::Content,
                    pad: ByteBuf::from(vec![]),
                    range_start: 0,
                    range_len: 10,
                },
                // Make sure the first one is the C2PA box
                BoxMap {
                    names: vec!["C2PA".to_string()],
                    alg: Some(alg.to_string()),
                    hash: ByteBuf::from(vec![0]),
                    excluded: None,
                    exclusions: None,
                    kind: BoxKind::C2pa,
                    pad: ByteBuf::from(vec![]),
                    range_start: 10,
                    range_len: 10,
                },
                BoxMap {
                    names: vec!["test1".to_string()],
                    alg: Some(alg.to_string()),
                    hash: ByteBuf::from(vec![0]),
                    excluded: None,
                    exclusions: None,
                    kind: BoxKind::Content,
                    pad: ByteBuf::from(vec![]),
                    range_start: 20,
                    range_len: 10,
                },
            ])
        });
        // The data size must match what we return in the expectation
        let data = vec![0u8; 30];
        // And create a reader on that data, for the API call
        let mut reader = Cursor::new(data);
        // Create the BoxHash object
        let mut bh = BoxHash { boxes: Vec::new() };
        // And generate the box hashes
        let result = bh.generate_box_hash_from_stream(&mut reader, alg, &mock, true);
        // We should expect an OK result
        assert!(result.is_ok());
        // With a total of 2 boxes
        assert_eq!(bh.boxes.len(), 3);
        assert_eq!(bh.boxes[0].names[0], "test");
        assert_eq!(bh.boxes[1].names[0], "C2PA");
        assert_eq!(bh.boxes[2].names[0], "test1");
    }

    #[test]
    fn test_verify_stream_hash_with_empty_names() {
        let ap = fixture_path("libpng-test.png");
        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();
        let mut input = File::open(&ap).unwrap();

        let malicious_bh = BoxHash {
            boxes: vec![BoxMap {
                names: vec![],
                alg: Some("sha256".to_string()),
                hash: ByteBuf::from(vec![0]),
                excluded: None,
                exclusions: None,
                kind: BoxKind::Content,
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 0,
            }],
        };

        // This shouldn't crash.
        let _ = malicious_bh.verify_stream_hash(&mut input, Some("sha256"), bhp);
    }

    #[test]
    fn test_exclusions_round_trip() {
        let bm = BoxMap {
            names: vec!["AAAA".to_string(), "BBBB".to_string()],
            alg: Some("sha256".to_string()),
            hash: ByteBuf::from(vec![1, 2, 3]),
            excluded: None,
            exclusions: Some(vec![
                BoxExclusion {
                    start: 3,
                    length: 2,
                    box_index: Some(0),
                },
                BoxExclusion {
                    start: 2,
                    length: 3,
                    box_index: Some(1),
                },
            ]),
            kind: BoxKind::Content,
            pad: ByteBuf::from(vec![]),
            range_start: 0,
            range_len: 20,
        };
        let bh = BoxHash { boxes: vec![bm] };

        let json_assertion = bh.to_json_assertion().unwrap();
        let from_json = BoxHash::from_json_assertion(&json_assertion).unwrap();
        assert_eq!(from_json.boxes[0].exclusions, bh.boxes[0].exclusions);

        let cbor_assertion = bh.to_cbor_assertion().unwrap();
        let from_cbor = BoxHash::from_cbor_assertion(&cbor_assertion).unwrap();
        assert_eq!(from_cbor.boxes[0].exclusions, bh.boxes[0].exclusions);
    }

    #[test]
    fn test_split_exclusions_basic_example() {
        // box 0: [100, 150), box 1: [150, 230); exclude [110,115) in box 0
        // and [170,180) in box 1.
        let box_ranges = [(100u64, 50u64), (150u64, 80u64)];
        let box_kinds = [BoxKind::Metadata, BoxKind::Metadata];
        let exclusions = vec![
            BoxExclusion {
                start: 10,
                length: 5,
                box_index: Some(0),
            },
            BoxExclusion {
                start: 20,
                length: 10,
                box_index: Some(1),
            },
        ];
        let (ranges, metadata_used) =
            split_exclusions(&box_ranges, &box_kinds, 100, 130, &exclusions).unwrap();
        let simplified: Vec<(u64, u64)> = ranges.iter().map(|r| (r.start(), r.length())).collect();
        assert_eq!(simplified, vec![(100, 10), (115, 55), (180, 50)]);
        assert!(metadata_used);
    }

    #[test]
    fn test_split_exclusions_fully_excluded_entry_does_not_fall_back_to_full_range() {
        let box_ranges = [(5u64, 10u64)];
        let box_kinds = [BoxKind::Metadata];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 10,
            box_index: None,
        }];
        let (ranges, _metadata_used) =
            split_exclusions(&box_ranges, &box_kinds, 5, 10, &exclusions).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].length(), 0);
    }

    #[test]
    fn test_split_exclusions_missing_box_index_with_multiple_boxes() {
        let box_ranges = [(0u64, 10u64), (10u64, 10u64)];
        let box_kinds = [BoxKind::Metadata, BoxKind::Metadata];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, &box_kinds, 0, 20, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_out_of_range_box_index() {
        let box_ranges = [(0u64, 10u64)];
        let box_kinds = [BoxKind::Metadata];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: Some(5),
        }];
        let result = split_exclusions(&box_ranges, &box_kinds, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_negative_box_index() {
        let box_ranges = [(0u64, 10u64)];
        let box_kinds = [BoxKind::Metadata];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: Some(-1),
        }];
        let result = split_exclusions(&box_ranges, &box_kinds, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_range_past_end_of_box() {
        let box_ranges = [(0u64, 10u64)];
        let box_kinds = [BoxKind::Metadata];
        let exclusions = vec![BoxExclusion {
            start: 8,
            length: 5,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, &box_kinds, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("extends beyond the end of its box")),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_overlapping_ranges() {
        let box_ranges = [(0u64, 20u64)];
        let box_kinds = [BoxKind::Metadata];
        let exclusions = vec![
            BoxExclusion {
                start: 0,
                length: 10,
                box_index: None,
            },
            BoxExclusion {
                start: 5,
                length: 5,
                box_index: None,
            },
        ];
        let result = split_exclusions(&box_ranges, &box_kinds, 0, 20, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    // Spec §15.12.3 requires exclusion ranges to be given in increasing order;
    // an out-of-order but non-overlapping array must still be rejected, not
    // silently sorted into a valid-looking sequence.
    #[test]
    fn test_split_exclusions_out_of_order_ranges_are_rejected_not_reordered() {
        let box_ranges = [(0u64, 20u64)];
        let box_kinds = [BoxKind::Metadata];
        let exclusions = vec![
            BoxExclusion {
                start: 10,
                length: 1,
                box_index: None,
            },
            BoxExclusion {
                start: 0,
                length: 1,
                box_index: None,
            },
        ];
        let result = split_exclusions(&box_ranges, &box_kinds, 0, 20, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_rejects_content_kind() {
        let box_ranges = [(0u64, 10u64)];
        let box_kinds = [BoxKind::Content];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, &box_kinds, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("not the C2PA store or asset metadata")),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_rejects_unknown_kind() {
        let box_ranges = [(0u64, 10u64)];
        let box_kinds = [BoxKind::Unknown];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, &box_kinds, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("not the C2PA store or asset metadata")),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_allows_c2pa_kind_without_metadata_signal() {
        let box_ranges = [(0u64, 10u64)];
        let box_kinds = [BoxKind::C2pa];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: None,
        }];
        let (_ranges, metadata_used) =
            split_exclusions(&box_ranges, &box_kinds, 0, 10, &exclusions).unwrap();
        assert!(!metadata_used);
    }

    #[test]
    fn test_generate_box_hash_from_stream_with_exclusions_rejects_content_kind_request() {
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![BoxMap {
                names: vec!["AAAA".to_string()],
                alg: None,
                hash: ByteBuf::from(vec![]),
                excluded: None,
                exclusions: None,
                kind: BoxKind::Content,
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 10,
            }])
        });

        let data: Vec<u8> = (0..10).collect();
        let mut reader = Cursor::new(data);
        let exclusion_requests = vec![BoxHashExclusionRequest {
            source_box_index: 0,
            start: 0,
            length: 1,
        }];

        let mut bh = BoxHash { boxes: Vec::new() };
        let result = bh.generate_box_hash_from_stream_with_exclusions(
            &mut reader,
            alg,
            &mock,
            false,
            &exclusion_requests,
        );
        assert!(
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("not the C2PA store or asset metadata")),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_generate_and_verify_with_exclusions() {
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![
                BoxMap {
                    names: vec!["AAAA".to_string()],
                    alg: None,
                    hash: ByteBuf::from(vec![]),
                    excluded: None,
                    exclusions: None,
                    // Only Metadata/C2pa boxes may carry an exclusion (spec §15.12.3).
                    kind: BoxKind::Metadata,
                    pad: ByteBuf::from(vec![]),
                    range_start: 0,
                    range_len: 10,
                },
                BoxMap {
                    names: vec!["BBBB".to_string()],
                    alg: None,
                    hash: ByteBuf::from(vec![]),
                    excluded: None,
                    exclusions: None,
                    kind: BoxKind::Metadata,
                    pad: ByteBuf::from(vec![]),
                    range_start: 10,
                    range_len: 10,
                },
            ])
        });

        let data: Vec<u8> = (0..20).collect();
        let mut reader = Cursor::new(data.clone());

        // Exclude AAAA's bytes [3,5) and BBBB's bytes [2,5) (absolute [12,15)).
        let exclusion_requests = vec![
            BoxHashExclusionRequest {
                source_box_index: 0,
                start: 3,
                length: 2,
            },
            BoxHashExclusionRequest {
                source_box_index: 1,
                start: 2,
                length: 3,
            },
        ];

        let mut bh = BoxHash { boxes: Vec::new() };
        bh.generate_box_hash_from_stream_with_exclusions(
            &mut reader,
            alg,
            &mock,
            false,
            &exclusion_requests,
        )
        .unwrap();

        // Unmodified data verifies.
        bh.verify_stream_hash(&mut reader, Some(alg), &mock)
            .unwrap();

        // A change inside an excluded range still verifies.
        let mut inside = data.clone();
        inside[3] ^= 0xff;
        let mut inside_reader = Cursor::new(inside);
        bh.verify_stream_hash(&mut inside_reader, Some(alg), &mock)
            .unwrap();

        // A change outside any excluded range invalidates the hash.
        let mut outside = data.clone();
        outside[0] ^= 0xff;
        let mut outside_reader = Cursor::new(outside);
        assert!(bh
            .verify_stream_hash(&mut outside_reader, Some(alg), &mock)
            .is_err());
    }
}
