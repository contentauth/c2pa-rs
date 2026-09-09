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
    asset_io::{
        AllowedExclusion, AssetBoxHash, BoxMap as AssetBoxMap, ExclusionKind, ReadSeek,
        C2PA_BOXHASH,
    },
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
/// targeting the box at `source_box_index` in `AssetBoxHash::get_box_map`'s
/// output (0-based, file order).
#[derive(Clone, Debug)]
pub struct BoxHashExclusionRequest {
    pub source_box_index: usize,
    pub start: u64,
    pub length: u64,
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
}

impl BoxMap {
    // diagnostic tool to show hashes for boxes
    pub fn dump_box(&self, mut reader: &mut dyn ReadSeek, alg: &str) -> Result<()> {
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

    /// Builds a spec `BoxMap` (hash-bearing) from an [`AssetBoxHash::get_box_map`]
    /// entry (region-only), attaching the hash produced for that region and
    /// any spec-conformant `exclusions` computed for it (see [`BoxExclusion`]).
    fn from_asset_box_map(
        bm: AssetBoxMap,
        hash: Vec<u8>,
        alg: Option<String>,
        exclusions: Option<Vec<BoxExclusion>>,
    ) -> Self {
        BoxMap {
            names: bm.names,
            alg,
            hash: ByteBuf::from(hash),
            excluded: bm.excluded,
            exclusions,
            pad: ByteBuf::from(vec![]),
            range_start: bm.range_start,
            range_len: bm.range_len,
        }
    }
}

/// A named box's absolute range plus the permitted exclusion sub-ranges
/// measured for it from the live asset. Keeping these together (rather than
/// as two parallel vectors) makes it impossible for a caller to push one
/// without the other, and naming the fields (rather than a positional tuple)
/// rules out transposing `start`/`len` at a construction or destructuring
/// site.
struct BoxRangeInfo {
    start: u64,
    len: u64,
    allowed_exclusions: Vec<AllowedExclusion>,
}

/// Resolves `exclusions`' `boxIndex`-relative ranges against `box_ranges`
/// (the absolute range and permitted sub-ranges of each name in a
/// box-hash-map entry, in order). Rejects any exclusion not fully contained
/// within one single permitted sub-range for its box (spec §15.12.3: only
/// the C2PA store or asset metadata may be excluded, and only the actual
/// payload - not header/length fields around it), and rejects a permitted
/// sub-range that would itself reach past its box's real length (a defensive
/// check against a buggy or malicious `AssetBoxHash` implementor, since
/// `AllowedExclusion` is otherwise trusted as already self-bounded). Returns
/// the ordered sub-ranges of `[entry_start, entry_start + entry_len)` left to
/// hash once the exclusions are punched out, plus whether any referenced
/// range was `AssetMetadata` (for the informational
/// `additionalExclusionsPresent` status).
fn split_exclusions(
    box_ranges: &[BoxRangeInfo],
    entry_start: u64,
    entry_len: u64,
    exclusions: &[BoxExclusion],
) -> Result<(Vec<HashRange>, bool)> {
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

        let range_info = box_ranges.get(box_index).ok_or_else(malformed)?;
        let box_start = range_info.start;

        let excl_end = excl.start.checked_add(excl.length).ok_or_else(malformed)?;

        let permitting_range = range_info
            .allowed_exclusions
            .iter()
            .filter(|a| a.is_bounded_by(range_info.len))
            .find(|a| a.contains(excl.start, excl_end));

        match permitting_range {
            None => {
                return Err(Error::HashMismatch(
                    "box hash exclusion is not contained within any permitted range for its box"
                        .to_string(),
                ));
            }
            Some(a) if a.kind == ExclusionKind::AssetMetadata => metadata_used = true,
            Some(_) => {}
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

    /// Builds an unhashed placeholder [`BoxHash`] straight from
    /// `AssetBoxHash::get_box_map`'s output, with every entry's `hash` left
    /// empty and `alg` unset.
    ///
    /// Used to size and reserve space for a `c2pa.hash.boxes` assertion before
    /// the asset (and its real box hashes) exist — e.g. an archived working
    /// store signed over an empty asset. Call
    /// [`generate_box_hash_from_stream`](Self::generate_box_hash_from_stream)
    /// separately to fill in real hashes once the asset is available.
    pub(crate) fn from_box_map(boxes: Vec<AssetBoxMap>) -> Self {
        BoxHash {
            boxes: boxes
                .into_iter()
                .map(|bm| BoxMap::from_asset_box_map(bm, vec![], None, None))
                .collect(),
        }
    }

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
        reader: &mut dyn ReadSeek,
        alg: Option<&str>,
        bhp: &dyn AssetBoxHash,
    ) -> Result<()> {
        self.verify_stream_hash_with_progress(reader, alg, bhp, &mut |_, _| Ok(()))
            .map(|_metadata_exclusion_used| ())
    }

    /// Like [`Self::verify_stream_hash`] but fires `progress(step, total)` once per hashed
    /// box so callers with a [`Context`] can report `ProgressPhase::VerifyingAssetHash`
    /// ticks and support cancellation.
    ///
    /// Returns whether any exclusion beyond the C2PA store itself was used -
    /// either an `exclusions` entry referencing an `AssetMetadata` range, or
    /// a whole non-C2PA box skipped via `excluded: true` - for the
    /// informational `assertion.boxesHash.additionalExclusionsPresent`
    /// status.
    pub(crate) fn verify_stream_hash_with_progress<F>(
        &self,
        reader: &mut dyn ReadSeek,
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
            let mut box_ranges: Vec<BoxRangeInfo> = Vec::with_capacity(bm.names.len());
            for name in &bm.names {
                match source_bms.get(source_index) {
                    Some(next_source_bm) if name == &next_source_bm.names[0] => {
                        box_ranges.push(BoxRangeInfo {
                            start: next_source_bm.range_start,
                            len: next_source_bm.range_len,
                            allowed_exclusions: next_source_bm.allowed_exclusions.clone(),
                        });

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

            // CDDL: `"exclusions": [1* box-exclusions-map]` - an empty array is
            // structurally invalid, not equivalent to the key being absent.
            // This must be checked regardless of `excluded`/being the C2PA
            // box below: `excluded` only says the box's hash is skipped, it
            // doesn't excuse an otherwise-present `exclusions` value from
            // still satisfying the CDDL shape.
            if matches!(&bm.exclusions, Some(excl) if excl.is_empty()) {
                return Err(Error::C2PAValidation(
                    ASSERTION_BOXESHASH_MALFORMED.to_string(),
                ));
            }

            let exclude = bm.excluded.unwrap_or(false);
            if skip_c2pa || exclude {
                // A box excluded in its entirety via `excluded: true` that
                // isn't the C2PA store itself is an exclusion beyond the
                // C2PA-store-only baseline, so it counts toward the
                // informational signal - regardless of the excluded box's
                // content, which this path doesn't classify (unlike the
                // `exclusions` sub-range case below).
                if exclude && !skip_c2pa {
                    metadata_exclusion_used = true;
                }
                continue;
            }

            let inclusions = match &bm.exclusions {
                None => vec![inclusion],
                Some(excl) => {
                    let (ranges, metadata_used) =
                        split_exclusions(&box_ranges, inclusion.start(), inclusion.length(), excl)?;
                    metadata_exclusion_used |= metadata_used;
                    ranges
                }
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

    /// Like [`Self::generate_box_hash_from_stream`] but fires `progress(step, total)` once
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

    /// Like [`Self::generate_box_hash_from_stream`], but `exclusion_requests` carves byte
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

    /// Like [`Self::generate_box_hash_from_stream_with_exclusions`] but fires
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
                alg: Some(alg.to_string()),
                ..Default::default()
            };
            let mut before_c2pa_ranges: Vec<BoxRangeInfo> = Vec::new();
            let mut before_c2pa_exclusions: Vec<BoxExclusion> = Vec::new();

            let mut c2pa_box = BoxMap {
                alg: Some(alg.to_string()),
                ..Default::default()
            };

            let mut after_c2pa = BoxMap {
                alg: Some(alg.to_string()),
                ..Default::default()
            };
            let mut after_c2pa_ranges: Vec<BoxRangeInfo> = Vec::new();
            let mut after_c2pa_exclusions: Vec<BoxExclusion> = Vec::new();

            let mut is_before_c2pa = true;

            // collapse map list to minimal set
            for (source_index, bm) in source_bms.into_iter().enumerate() {
                if bm.names[0] == "C2PA" {
                    // there should only be 1 collapsed C2PA range
                    if bm.names.len() != 1 {
                        return Err(Error::HashMismatch("Malformed C2PA box hash".to_owned()));
                    }

                    c2pa_box = BoxMap::from_asset_box_map(bm, vec![], None, None);
                    is_before_c2pa = false;
                    continue;
                }

                let (group, group_ranges, group_exclusions) = if is_before_c2pa {
                    (
                        &mut before_c2pa,
                        &mut before_c2pa_ranges,
                        &mut before_c2pa_exclusions,
                    )
                } else {
                    (
                        &mut after_c2pa,
                        &mut after_c2pa_ranges,
                        &mut after_c2pa_exclusions,
                    )
                };

                // `names` and `group_ranges` grow in lockstep, so this box's
                // position in `group_ranges` (before pushing) is also its
                // future position in `group.names` - i.e. its `boxIndex`.
                let box_index_in_group = group_ranges.len();
                group_ranges.push(BoxRangeInfo {
                    start: bm.range_start,
                    len: bm.range_len,
                    allowed_exclusions: bm.allowed_exclusions.clone(),
                });
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
            let mut boxes_ranges = Vec::<Vec<BoxRangeInfo>>::new();
            // Only add if we have some before the C2PA box
            if before_c2pa.range_len > 0 {
                boxes_ranges.push(before_c2pa_ranges);
                boxes.push(before_c2pa);
            }
            // Do the same for the actual C2PA box. Its `allowed_exclusions`
            // is never read - the hash loop below always skips the C2PA
            // box's own entry before `box_ranges` would be consulted - this
            // is only here to keep `boxes_ranges` zipped with `boxes`.
            if c2pa_box.range_len > 0 {
                boxes_ranges.push(vec![BoxRangeInfo {
                    start: c2pa_box.range_start,
                    len: c2pa_box.range_len,
                    allowed_exclusions: vec![],
                }]);
                boxes.push(c2pa_box);
            }
            // And finally, add the boxes after the C2PA box
            if after_c2pa.range_len > 0 {
                boxes_ranges.push(after_c2pa_ranges);
                boxes.push(after_c2pa);
            }
            self.boxes = boxes;

            // compute the hashes
            for (bm, box_ranges) in self.boxes.iter_mut().zip(boxes_ranges.iter()) {
                // skip c2pa box
                if bm.names[0] == C2PA_BOXHASH {
                    continue;
                }

                let inclusions = match &bm.exclusions {
                    Some(excl) if !excl.is_empty() => {
                        split_exclusions(box_ranges, bm.range_start, bm.range_len, excl)?.0
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
            for (source_index, bm) in source_bms.into_iter().enumerate() {
                if bm.names[0] == "C2PA" {
                    // there should only be 1 collapsed C2PA range
                    if bm.names.len() != 1 {
                        return Err(Error::HashMismatch("Malformed C2PA box hash".to_owned()));
                    }
                    self.boxes
                        .push(BoxMap::from_asset_box_map(bm, vec![0], None, None));
                    continue;
                }

                let box_ranges = [BoxRangeInfo {
                    start: bm.range_start,
                    len: bm.range_len,
                    allowed_exclusions: bm.allowed_exclusions.clone(),
                }];
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
                    split_exclusions(&box_ranges, bm.range_start, bm.range_len, &exclusions)?.0
                };

                let hash = hash_stream_by_alg_with_progress(
                    alg,
                    reader,
                    Some(inclusions),
                    false,
                    &mut progress,
                )?;

                self.boxes.push(BoxMap::from_asset_box_map(
                    bm,
                    hash,
                    Some(alg.to_string()),
                    if exclusions.is_empty() {
                        None
                    } else {
                        Some(exclusions)
                    },
                ));
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
            fn get_box_map(&self, reader: &mut dyn ReadSeek) -> Result<Vec<AssetBoxMap>>;
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
                AssetBoxMap::new(vec!["C2PA".to_string()], 0, 10).with_allowed_exclusions(vec![
                    AllowedExclusion {
                        start: 0,
                        length: 10,
                        kind: ExclusionKind::ManifestOrPadding,
                    },
                ]),
                // And follow with
                AssetBoxMap::new(vec!["test".to_string()], 10, 10),
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
                AssetBoxMap::new(vec!["test".to_string()], 0, 10),
                // Make sure the first one is the C2PA box
                AssetBoxMap::new(vec!["C2PA".to_string()], 10, 10).with_allowed_exclusions(vec![
                    AllowedExclusion {
                        start: 0,
                        length: 10,
                        kind: ExclusionKind::ManifestOrPadding,
                    },
                ]),
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
                AssetBoxMap::new(vec!["test".to_string()], 0, 10),
                // Make sure the first one is the C2PA box
                AssetBoxMap::new(vec!["C2PA".to_string()], 10, 10).with_allowed_exclusions(vec![
                    AllowedExclusion {
                        start: 0,
                        length: 10,
                        kind: ExclusionKind::ManifestOrPadding,
                    },
                ]),
                AssetBoxMap::new(vec!["test1".to_string()], 20, 10),
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
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 0,
            }],
        };

        // This shouldn't crash.
        let _ = malicious_bh.verify_stream_hash(&mut input, Some("sha256"), bhp);
    }

    #[test]
    fn test_verify_stream_hash_rejects_empty_exclusions_array() {
        // CDDL: `"exclusions": [1* box-exclusions-map]` - an empty array is
        // structurally invalid, not equivalent to the key being absent.
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![AssetBoxMap {
                names: vec!["AAAA".to_string()],
                excluded: None,
                range_start: 0,
                range_len: 10,
                allowed_exclusions: vec![AllowedExclusion {
                    start: 0,
                    length: 10,
                    kind: ExclusionKind::AssetMetadata,
                }],
            }])
        });

        let data: Vec<u8> = (0..10).collect();
        let mut reader = Cursor::new(data);

        let bh = BoxHash {
            boxes: vec![BoxMap {
                names: vec!["AAAA".to_string()],
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![0; 32]),
                excluded: None,
                exclusions: Some(vec![]),
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 10,
            }],
        };

        let result =
            bh.verify_stream_hash_with_progress(&mut reader, Some(alg), &mock, &mut |_, _| Ok(()));
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_verify_stream_hash_rejects_empty_exclusions_array_on_excluded_box() {
        // `excluded: true` skips the box's hash, but doesn't excuse an
        // otherwise-present `exclusions` value from still satisfying the
        // CDDL `[1* box-exclusions-map]` shape.
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![AssetBoxMap {
                names: vec!["AAAA".to_string()],
                excluded: None,
                range_start: 0,
                range_len: 10,
                allowed_exclusions: vec![],
            }])
        });

        let data: Vec<u8> = (0..10).collect();
        let mut reader = Cursor::new(data);

        let bh = BoxHash {
            boxes: vec![BoxMap {
                names: vec!["AAAA".to_string()],
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                excluded: Some(true),
                exclusions: Some(vec![]),
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 10,
            }],
        };

        let result =
            bh.verify_stream_hash_with_progress(&mut reader, Some(alg), &mock, &mut |_, _| Ok(()));
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_verify_stream_hash_rejects_empty_exclusions_array_on_c2pa_box() {
        // Same as above, but for the C2PA store's own box (`skip_c2pa`)
        // rather than an `excluded: true` box.
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![AssetBoxMap {
                names: vec![C2PA_BOXHASH.to_string()],
                excluded: None,
                range_start: 0,
                range_len: 10,
                allowed_exclusions: vec![AllowedExclusion {
                    start: 0,
                    length: 10,
                    kind: ExclusionKind::ManifestOrPadding,
                }],
            }])
        });

        let data: Vec<u8> = (0..10).collect();
        let mut reader = Cursor::new(data);

        let bh = BoxHash {
            boxes: vec![BoxMap {
                names: vec![C2PA_BOXHASH.to_string()],
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                excluded: None,
                exclusions: Some(vec![]),
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 10,
            }],
        };

        let result =
            bh.verify_stream_hash_with_progress(&mut reader, Some(alg), &mock, &mut |_, _| Ok(()));
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_verify_stream_hash_flags_excluded_non_c2pa_box() {
        // A whole box skipped via `excluded: true` that isn't the C2PA store
        // itself (e.g. the spec's PNG iTXt example) is an exclusion beyond
        // the C2PA-store-only baseline, so it must surface the informational
        // `additionalExclusionsPresent` signal - even though this path never
        // classifies the excluded box's content.
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![AssetBoxMap {
                names: vec!["AAAA".to_string()],
                excluded: None,
                range_start: 0,
                range_len: 10,
                allowed_exclusions: vec![],
            }])
        });

        let data: Vec<u8> = (0..10).collect();
        let mut reader = Cursor::new(data);

        let bh = BoxHash {
            boxes: vec![BoxMap {
                names: vec!["AAAA".to_string()],
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                excluded: Some(true),
                exclusions: None,
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 10,
            }],
        };

        let result =
            bh.verify_stream_hash_with_progress(&mut reader, Some(alg), &mock, &mut |_, _| Ok(()));
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_stream_hash_does_not_flag_excluded_c2pa_box() {
        // The C2PA store's own box is the baseline exclusion, not an
        // "additional" one - even if it's also marked `excluded: true`.
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![AssetBoxMap {
                names: vec![C2PA_BOXHASH.to_string()],
                excluded: None,
                range_start: 0,
                range_len: 10,
                allowed_exclusions: vec![AllowedExclusion {
                    start: 0,
                    length: 10,
                    kind: ExclusionKind::ManifestOrPadding,
                }],
            }])
        });

        let data: Vec<u8> = (0..10).collect();
        let mut reader = Cursor::new(data);

        let bh = BoxHash {
            boxes: vec![BoxMap {
                names: vec![C2PA_BOXHASH.to_string()],
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                excluded: Some(true),
                exclusions: None,
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 10,
            }],
        };

        let result =
            bh.verify_stream_hash_with_progress(&mut reader, Some(alg), &mock, &mut |_, _| Ok(()));
        assert!(!result.unwrap());
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
        let box_ranges: [BoxRangeInfo; 2] = [
            BoxRangeInfo {
                start: 100,
                len: 50,
                allowed_exclusions: vec![AllowedExclusion {
                    start: 0,
                    length: 50,
                    kind: ExclusionKind::AssetMetadata,
                }],
            },
            BoxRangeInfo {
                start: 150,
                len: 80,
                allowed_exclusions: vec![AllowedExclusion {
                    start: 0,
                    length: 80,
                    kind: ExclusionKind::AssetMetadata,
                }],
            },
        ];
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
        let (ranges, metadata_used) = split_exclusions(&box_ranges, 100, 130, &exclusions).unwrap();
        let simplified: Vec<(u64, u64)> = ranges.iter().map(|r| (r.start(), r.length())).collect();
        assert_eq!(simplified, vec![(100, 10), (115, 55), (180, 50)]);
        assert!(metadata_used);
    }

    #[test]
    fn test_split_exclusions_fully_excluded_entry_does_not_fall_back_to_full_range() {
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 5,
            len: 10,
            allowed_exclusions: vec![AllowedExclusion {
                start: 0,
                length: 10,
                kind: ExclusionKind::AssetMetadata,
            }],
        }];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 10,
            box_index: None,
        }];
        let (ranges, _metadata_used) = split_exclusions(&box_ranges, 5, 10, &exclusions).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].length(), 0);
    }

    #[test]
    fn test_split_exclusions_missing_box_index_with_multiple_boxes() {
        let box_ranges: [BoxRangeInfo; 2] = [
            BoxRangeInfo {
                start: 0,
                len: 10,
                allowed_exclusions: vec![AllowedExclusion {
                    start: 0,
                    length: 10,
                    kind: ExclusionKind::AssetMetadata,
                }],
            },
            BoxRangeInfo {
                start: 10,
                len: 10,
                allowed_exclusions: vec![AllowedExclusion {
                    start: 0,
                    length: 10,
                    kind: ExclusionKind::AssetMetadata,
                }],
            },
        ];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, 0, 20, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_out_of_range_box_index() {
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 10,
            allowed_exclusions: vec![AllowedExclusion {
                start: 0,
                length: 10,
                kind: ExclusionKind::AssetMetadata,
            }],
        }];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: Some(5),
        }];
        let result = split_exclusions(&box_ranges, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_negative_box_index() {
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 10,
            allowed_exclusions: vec![AllowedExclusion {
                start: 0,
                length: 10,
                kind: ExclusionKind::AssetMetadata,
            }],
        }];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: Some(-1),
        }];
        let result = split_exclusions(&box_ranges, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_rejects_range_extending_past_box_end() {
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 10,
            allowed_exclusions: vec![AllowedExclusion {
                start: 0,
                length: 10,
                kind: ExclusionKind::AssetMetadata,
            }],
        }];
        let exclusions = vec![BoxExclusion {
            start: 8,
            length: 5,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("not contained within any permitted range")),
            "unexpected result: {result:?}"
        );
    }

    // A malicious/buggy `AssetBoxHash` implementor could report an
    // `AllowedExclusion` that itself reaches past the box's real length.
    // Even though the requested exclusion is fully contained *within* that
    // over-wide permitted range, it must still be rejected - the permitted
    // range's own bound against the box's live length is not optional.
    #[test]
    fn test_split_exclusions_rejects_allowed_exclusion_wider_than_box() {
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 10,
            allowed_exclusions: vec![AllowedExclusion {
                start: 0,
                length: 15,
                kind: ExclusionKind::AssetMetadata,
            }],
        }];
        let exclusions = vec![BoxExclusion {
            start: 11,
            length: 2,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("not contained within any permitted range")),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_overlapping_ranges() {
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 20,
            allowed_exclusions: vec![AllowedExclusion {
                start: 0,
                length: 20,
                kind: ExclusionKind::AssetMetadata,
            }],
        }];
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
        let result = split_exclusions(&box_ranges, 0, 20, &exclusions);
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
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 20,
            allowed_exclusions: vec![AllowedExclusion {
                start: 0,
                length: 20,
                kind: ExclusionKind::AssetMetadata,
            }],
        }];
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
        let result = split_exclusions(&box_ranges, 0, 20, &exclusions);
        assert!(
            matches!(&result, Err(Error::C2PAValidation(s)) if s == ASSERTION_BOXESHASH_MALFORMED),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_rejects_box_with_no_allowed_exclusions() {
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 10,
            allowed_exclusions: vec![],
        }];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("not contained within any permitted range")),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_rejects_range_outside_allowed_exclusion() {
        // The box has a permitted range, but the requested exclusion falls
        // outside it - e.g. covering a PNG chunk's length/type header
        // instead of its data.
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 10,
            allowed_exclusions: vec![AllowedExclusion {
                start: 5,
                length: 5,
                kind: ExclusionKind::AssetMetadata,
            }],
        }];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: None,
        }];
        let result = split_exclusions(&box_ranges, 0, 10, &exclusions);
        assert!(
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("not contained within any permitted range")),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_split_exclusions_allows_manifest_or_padding_without_metadata_signal() {
        let box_ranges: [BoxRangeInfo; 1] = [BoxRangeInfo {
            start: 0,
            len: 10,
            allowed_exclusions: vec![AllowedExclusion {
                start: 0,
                length: 10,
                kind: ExclusionKind::ManifestOrPadding,
            }],
        }];
        let exclusions = vec![BoxExclusion {
            start: 0,
            length: 1,
            box_index: None,
        }];
        let (_ranges, metadata_used) = split_exclusions(&box_ranges, 0, 10, &exclusions).unwrap();
        assert!(!metadata_used);
    }

    #[test]
    fn test_generate_box_hash_from_stream_with_exclusions_rejects_disallowed_request() {
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![AssetBoxMap {
                names: vec!["AAAA".to_string()],
                excluded: None,
                range_start: 0,
                range_len: 10,
                allowed_exclusions: vec![],
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
            matches!(&result, Err(Error::HashMismatch(msg)) if msg.contains("not contained within any permitted range")),
            "unexpected result: {result:?}"
        );
    }

    #[test]
    fn test_generate_and_verify_with_exclusions() {
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![
                AssetBoxMap {
                    names: vec!["AAAA".to_string()],
                    excluded: None,
                    range_start: 0,
                    range_len: 10,
                    // Only ranges within an AssetMetadata/ManifestOrPadding
                    // range may be excluded (spec §15.12.3).
                    allowed_exclusions: vec![AllowedExclusion {
                        start: 0,
                        length: 10,
                        kind: ExclusionKind::AssetMetadata,
                    }],
                },
                AssetBoxMap {
                    names: vec!["BBBB".to_string()],
                    excluded: None,
                    range_start: 10,
                    range_len: 10,
                    allowed_exclusions: vec![AllowedExclusion {
                        start: 0,
                        length: 10,
                        kind: ExclusionKind::AssetMetadata,
                    }],
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

    #[test]
    fn test_generate_and_verify_with_exclusions_minimal_form() {
        // `minimal_form` folds every non-C2PA box before/after the C2PA box
        // into one merged `before_c2pa`/`after_c2pa` entry each. Exclusion
        // requests must still land on the right source box once its bytes
        // are folded into one of those merged entries, with `boxIndex`
        // translated to the box's position within the merged entry's
        // `names` list (not its position in the original source box list).
        let alg = "sha256";
        let mut mock = MockMABH::new();
        mock.expect_get_box_map().returning(|_| {
            Ok(vec![
                AssetBoxMap {
                    names: vec!["AAAA".to_string()],
                    excluded: None,
                    range_start: 0,
                    range_len: 10,
                    allowed_exclusions: vec![AllowedExclusion {
                        start: 0,
                        length: 10,
                        kind: ExclusionKind::AssetMetadata,
                    }],
                },
                AssetBoxMap {
                    names: vec![C2PA_BOXHASH.to_string()],
                    excluded: None,
                    range_start: 10,
                    range_len: 5,
                    allowed_exclusions: vec![AllowedExclusion {
                        start: 0,
                        length: 5,
                        kind: ExclusionKind::ManifestOrPadding,
                    }],
                },
                AssetBoxMap {
                    names: vec!["BBBB".to_string()],
                    excluded: None,
                    range_start: 15,
                    range_len: 10,
                    allowed_exclusions: vec![AllowedExclusion {
                        start: 0,
                        length: 10,
                        kind: ExclusionKind::AssetMetadata,
                    }],
                },
            ])
        });

        let data: Vec<u8> = (0..25).collect();
        let mut reader = Cursor::new(data.clone());

        // Exclude AAAA's bytes [3,5) (absolute [3,5), in the before_c2pa
        // group) and BBBB's bytes [2,5) (absolute [17,20), in the
        // after_c2pa group). Source indices are positions in
        // `get_box_map`'s output: 0 = AAAA, 1 = C2PA, 2 = BBBB.
        let exclusion_requests = vec![
            BoxHashExclusionRequest {
                source_box_index: 0,
                start: 3,
                length: 2,
            },
            BoxHashExclusionRequest {
                source_box_index: 2,
                start: 2,
                length: 3,
            },
        ];

        let mut bh = BoxHash { boxes: Vec::new() };
        bh.generate_box_hash_from_stream_with_exclusions(
            &mut reader,
            alg,
            &mock,
            true,
            &exclusion_requests,
        )
        .unwrap();

        // Folded into 3 entries: before_c2pa (AAAA), the C2PA box itself,
        // and after_c2pa (BBBB).
        assert_eq!(bh.boxes.len(), 3);
        assert_eq!(bh.boxes[0].names, vec!["AAAA".to_string()]);
        assert_eq!(bh.boxes[1].names, vec![C2PA_BOXHASH.to_string()]);
        assert_eq!(bh.boxes[2].names, vec!["BBBB".to_string()]);

        // Unmodified data verifies.
        bh.verify_stream_hash(&mut reader, Some(alg), &mock)
            .unwrap();

        // A change inside AAAA's excluded range still verifies.
        let mut inside_before = data.clone();
        inside_before[3] ^= 0xff;
        let mut inside_before_reader = Cursor::new(inside_before);
        bh.verify_stream_hash(&mut inside_before_reader, Some(alg), &mock)
            .unwrap();

        // A change inside BBBB's excluded range still verifies.
        let mut inside_after = data.clone();
        inside_after[18] ^= 0xff;
        let mut inside_after_reader = Cursor::new(inside_after);
        bh.verify_stream_hash(&mut inside_after_reader, Some(alg), &mock)
            .unwrap();

        // A change outside any excluded range (but still within AAAA)
        // invalidates the hash.
        let mut outside = data.clone();
        outside[0] ^= 0xff;
        let mut outside_reader = Cursor::new(outside);
        assert!(bh
            .verify_stream_hash(&mut outside_reader, Some(alg), &mock)
            .is_err());
    }
}
