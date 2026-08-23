// Copyright 2022 Adobe. All rights reserved.
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
    num::NonZeroUsize,
    ops::RangeInclusive,
    path::Path,
};

use range_set::RangeSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
// direct sha functions
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{crypto::base64::encode, utils::io_utils::stream_len, Error, Result};

const MAX_HASH_BUF: usize = 256 * 1024 * 1024; // cap memory usage to 256MB

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
/// Defines a hash range to be used with `hash_stream_by_alg`
pub struct HashRange {
    start: u64,
    length: u64,

    #[serde(skip)]
    bmff_offset: Option<u64>, /* optional tracking of offset positions to include in BMFF_V2 hashes in BE format */
}

impl HashRange {
    pub fn new(start: u64, length: u64) -> Self {
        HashRange {
            start,
            length,
            bmff_offset: None,
        }
    }

    /// update the start value
    #[allow(dead_code)]
    pub fn set_start(&mut self, start: u64) {
        self.start = start;
    }

    /// return start as usize
    pub fn start(&self) -> u64 {
        self.start
    }

    /// return length as usize
    pub fn length(&self) -> u64 {
        self.length
    }

    pub fn set_length(&mut self, length: u64) {
        self.length = length;
    }

    // set offset for BMFF_V2 to be hashed in addition to data
    pub fn set_bmff_offset(&mut self, offset: u64) {
        self.bmff_offset = Some(offset);
    }

    // get option offset for BMFF_V2 hash
    pub fn bmff_offset(&self) -> Option<u64> {
        self.bmff_offset
    }
}

/// Compare two byte vectors return true if match, false otherwise
pub fn vec_compare(va: &[u8], vb: &[u8]) -> bool {
    (va.len() == vb.len()) &&  // zip stops at the shortest
     va.iter()
       .zip(vb)
       .all(|(a,b)| a == b)
}

#[derive(Clone, Debug)]
pub enum Hasher {
    SHA256(Sha256),
    SHA384(Sha384),
    SHA512(Sha512),
}

impl Default for Hasher {
    fn default() -> Self {
        Hasher::SHA256(Sha256::new())
    }
}

impl Hasher {
    // update hash value with new data
    pub fn update(&mut self, data: &[u8]) {
        use Hasher::*;
        // update the hash
        match self {
            SHA256(ref mut d) => d.update(data),
            SHA384(ref mut d) => d.update(data),
            SHA512(ref mut d) => d.update(data),
        }
    }

    // consume hasher and return the final digest
    pub fn finalize(hasher_enum: Hasher) -> Vec<u8> {
        use Hasher::*;
        // return the hash
        match hasher_enum {
            SHA256(d) => d.finalize().to_vec(),
            SHA384(d) => d.finalize().to_vec(),
            SHA512(d) => d.finalize().to_vec(),
        }
    }

    pub fn finalize_reset(&mut self) -> Vec<u8> {
        use Hasher::*;

        // return the hash and leave the Hasher open and reset
        match self {
            SHA256(ref mut d) => d.finalize_reset().to_vec(),
            SHA384(ref mut d) => d.finalize_reset().to_vec(),
            SHA512(ref mut d) => d.finalize_reset().to_vec(),
        }
    }

    pub fn new(alg: &str) -> Result<Hasher> {
        match alg {
            "sha256" => Ok(Hasher::SHA256(Sha256::new())),
            "sha384" => Ok(Hasher::SHA384(Sha384::new())),
            "sha512" => Ok(Hasher::SHA512(Sha512::new())),
            _ => Err(Error::UnsupportedType),
        }
    }
}

// Return hash bytes for desired hashing algorithm.
pub fn hash_by_alg(alg: &str, data: &[u8], exclusions: Option<Vec<HashRange>>) -> Vec<u8> {
    let mut reader = Cursor::new(data);

    hash_stream_by_alg(alg, &mut reader, exclusions, true).unwrap_or_default()
}

// Return hash inclusive bytes for desired hashing algorithm.
pub fn hash_by_alg_with_inclusions(alg: &str, data: &[u8], inclusions: Vec<HashRange>) -> Vec<u8> {
    let mut reader = Cursor::new(data);

    hash_stream_by_alg(alg, &mut reader, Some(inclusions), false).unwrap_or_default()
}

// Return hash bytes for asset using desired hashing algorithm.
pub fn hash_asset_by_alg(
    alg: &str,
    asset_path: &Path,
    exclusions: Option<Vec<HashRange>>,
) -> Result<Vec<u8>> {
    let mut file = File::open(asset_path)?;
    hash_stream_by_alg(alg, &mut file, exclusions, true)
}

// Return hash inclusive bytes for asset using desired hashing algorithm.
pub fn hash_asset_by_alg_with_inclusions(
    alg: &str,
    asset_path: &Path,
    inclusions: Vec<HashRange>,
) -> Result<Vec<u8>> {
    let mut file = File::open(asset_path)?;
    hash_stream_by_alg(alg, &mut file, Some(inclusions), false)
}

/*  Returns hash bytes for a stream using desired hashing algorithm.  The function handles the many
    possible hash requirements of C2PA.  The function accepts a source stream 'data', an optional
    set of hash ranges 'hash_range' and a boolean to indicate whether the hash range is an exclusion
    or inclusion set of hash ranges.

    The basic case is to hash a stream without hash ranges:
    The data represents a single contiguous stream of bytes to be hash where D are data bytes

    to_be_hashed: [DDDDDDDDD...DDDDDDDDDD]

    The data is then chunked and hashed in groups to reduce memory
    footprint and increase performance.

    The most common case for C2PA is the use of an exclusion hash.  In this case the 'hash_range' indicate
    which byte ranges should be excluded shown here depicted with I for included bytes and  X for excluded bytes

    to_be_hashed: [IIIIXXXIIIIXXXXXIIIXXIII...IIII]

    In this case the data is split into a set of ranges covering the included bytes.  The set of ranged bytes
    are then chunked and hashed just like the default case.

    The opposite of this is when 'is_exclusion' is set to false indicating the 'hash_ranges' represent the bytes
    to include in the hash. Here are the bytes in 'data' are excluded except those explicitly referenced.

    to_be_hashed: [XXXXXXIIIIXXXXXIIXXXX...XXXX]

    Again a set of ranged bytes are created and hashed as described above.

    The last case is a special requirement for BMFF based assets (exclusion hashes only).  For this case we not
    only hash the data but also the location where the data was found in the asset.  To do this we add a special
    HashRange object to the hash ranges to indicate which locations in the stream require this special offset
    hash.  To make processing efficient we again split the data into ranges at not just the exclusion
    points but also for these markers.  The hashing loop knows to pause at these special marker ranges to insert
    the hash of the offset.  The stream sent to the hashing loop logically looks like this where M is the marker.
    to_be_hashed: [IIIIIXXXXXMIIIIIMXXXXXMXXXXIII...III]

    The data is again split into range sets breaking at the exclusion points and now also the markers.
*/
/// Internal implementation of [`hash_stream_by_alg`] with an optional per-range
/// progress/cancellation callback.  SDK internals that have a [`Context`] available
/// pass a closure that calls [`Context::check_progress`]; the public wrapper supplies
/// `None` so external callers are unaffected.
pub(crate) fn hash_stream_by_alg_with_progress<R, F>(
    alg: &str,
    data: &mut R,
    hash_range: Option<Vec<HashRange>>,
    is_exclusion: bool,
    progress: &mut F,
) -> Result<Vec<u8>>
where
    R: Read + Seek + ?Sized,
    F: FnMut(u32, u32) -> Result<()>,
{
    let max_hash_buf = NonZeroUsize::new(MAX_HASH_BUF)
        .ok_or(Error::BadParam("invalid max_hash_buf".to_string()))?;
    hash_stream_by_alg_with_progress_impl(
        alg,
        data,
        hash_range,
        is_exclusion,
        progress,
        max_hash_buf,
    )
}

/// Builds the ordered list of byte ranges to hash,
/// resolving `hash_range` against an asset of `data_len` bytes.
///
/// Returns the ranges sorted ascending by start, plus the BMFF V2 offsets whose
/// value (rather than whose bytes) is folded into the hash.
pub(crate) fn build_hash_ranges(
    hash_range: Option<Vec<HashRange>>,
    is_exclusion: bool,
    data_len: u64,
) -> Result<(Vec<RangeInclusive<u64>>, Vec<u64>)> {
    let mut bmff_v2_starts: Vec<u64> = Vec::new();

    if data_len < 1 {
        return Err(Error::OtherError("no data to hash".into()));
    }

    let ranges = match hash_range {
        Some(mut hr) if !hr.is_empty() => {
            // hash data skipping excluded regions
            // sort the exclusions
            hr.sort_by_key(|a| a.start());

            // verify structure of blocks
            let num_blocks = hr.len();
            let range_end = hr[num_blocks - 1]
                .start()
                .checked_add(hr[num_blocks - 1].length())
                .ok_or(Error::BadParam("hash range overflow".to_string()))?;
            let data_end = data_len - 1;

            // range extends past end of file so fail
            if data_len < range_end {
                return Err(Error::BadParam(
                    "The exclusion range exceed the data length".to_string(),
                ));
            }

            if is_exclusion {
                //build final ranges
                let mut ranges_vec: Vec<RangeInclusive<u64>> = Vec::new();
                let mut ranges = RangeSet::<[RangeInclusive<u64>; 1]>::from(0..=data_end);
                for exclusion in hr {
                    // add new BMFF V2 offset as a new range to be included so that we can
                    // pause to add the offset hash
                    if let Some(offset) = exclusion.bmff_offset() {
                        bmff_v2_starts.push(offset);
                        continue;
                    }

                    if exclusion.length() == 0 {
                        continue;
                    }

                    let end = exclusion
                        .start()
                        .checked_add(exclusion.length())
                        .ok_or(Error::BadParam("No exclusion range".to_string()))?
                        .checked_sub(1)
                        .ok_or(Error::BadParam("No exclusion range".to_string()))?;
                    let exclusion_start = exclusion.start();
                    ranges.remove_range(exclusion_start..=end);
                }

                // merge standard ranges and BMFF V2 ranges into single list
                if !bmff_v2_starts.is_empty() {
                    bmff_v2_starts.sort();

                    // split ranges at BMFF V2 offsets and insert offset value
                    for r in ranges.into_smallvec() {
                        // if bmff_v2 offset is within the range then split the range at the off set and both side to ranges_vec
                        let mut current_range = r;
                        for os in &bmff_v2_starts {
                            if current_range.contains(os) {
                                if *current_range.start() == *os {
                                    ranges_vec.push(RangeInclusive::new(*os, *os));
                                // offset
                                } else {
                                    ranges_vec
                                        .push(RangeInclusive::new(*current_range.start(), *os - 1)); // left side
                                    ranges_vec.push(RangeInclusive::new(*os, *os)); // offset
                                    current_range = RangeInclusive::new(*os, *current_range.end());
                                    // right side
                                }
                            }
                        }
                        ranges_vec.push(current_range);
                    }

                    // add in remaining BMFF V2 offsets that were not included in the ranges because of subsets
                    let range_start = RangeInclusive::new(0, 0);
                    let range_end = RangeInclusive::new(data_end, data_end);
                    let before_any_range = *ranges_vec.first().unwrap_or(&range_start).start();
                    let after_any_range = *ranges_vec.last().unwrap_or(&range_end).end();

                    for os in &bmff_v2_starts {
                        if !ranges_vec.iter().any(|r| r.contains(os))
                            && *os > before_any_range
                            && *os < after_any_range
                        {
                            ranges_vec.push(RangeInclusive::new(*os, *os));
                        }
                    }

                    // sort by start position
                    ranges_vec.sort_by(|a, b| {
                        let a_start = a.start();
                        let b_start = b.start();
                        a_start.cmp(b_start)
                    });

                    ranges_vec
                } else {
                    for r in ranges.into_smallvec() {
                        ranges_vec.push(r);
                    }
                    ranges_vec
                }
            } else {
                //build final ranges
                let mut ranges_vec: Vec<RangeInclusive<u64>> = Vec::new();
                for inclusion in hr {
                    if inclusion.length() == 0 {
                        continue;
                    }

                    let end = inclusion
                        .start()
                        .checked_add(inclusion.length())
                        .ok_or(Error::BadParam("inclusion range overflow".to_string()))?
                        - 1;
                    let inclusion_start = inclusion.start();

                    // add new BMFF V2 offset as a new range to be included so that we can
                    // pause to add the offset hash
                    if let Some(offset) = inclusion.bmff_offset() {
                        ranges_vec.push(RangeInclusive::new(offset, offset));
                        bmff_v2_starts.push(offset);
                    }

                    // add inclusion
                    ranges_vec.push(RangeInclusive::new(inclusion_start, end));
                }
                ranges_vec
            }
        }
        _ => {
            let mut ranges_vec: Vec<RangeInclusive<u64>> = Vec::new();
            let data_end = data_len - 1;
            ranges_vec.push(RangeInclusive::new(0_u64, data_end));

            ranges_vec
        }
    };

    Ok((ranges, bmff_v2_starts))
}

/// Counts progress callbacks: one per `max_hash_buf` chunk across all ranges.
fn progress_total(ranges: &[RangeInclusive<u64>], max_hash_buf: usize) -> u32 {
    ranges
        .iter()
        .map(|r| {
            let len = r.end() - r.start() + 1;
            (len as usize).div_ceil(max_hash_buf) as u32
        })
        .sum()
}

/// Selects the hasher for `alg`.
fn hasher_for_alg(alg: &str) -> Result<Hasher> {
    use Hasher::*;
    match alg {
        "sha256" => Ok(SHA256(Sha256::new())),
        "sha384" => Ok(SHA384(Sha384::new())),
        "sha512" => Ok(SHA512(Sha512::new())),
        _ => Err(Error::UnsupportedType),
    }
}

/// Make `hash_stream_by_alg_with_progress` configurable with `max_hash_buf`.
fn hash_stream_by_alg_with_progress_impl<R, F>(
    alg: &str,
    data: &mut R,
    hash_range: Option<Vec<HashRange>>,
    is_exclusion: bool,
    progress: &mut F,
    max_hash_buf: NonZeroUsize,
) -> Result<Vec<u8>>
where
    R: Read + Seek + ?Sized,
    F: FnMut(u32, u32) -> Result<()>,
{
    let max_hash_buf = max_hash_buf.get();

    let mut hasher_enum = hasher_for_alg(alg)?;

    let data_len = stream_len(data)?;
    data.rewind()?;

    let (ranges, bmff_v2_starts) = build_hash_ranges(hash_range, is_exclusion, data_len)?;

    let total: u32 = progress_total(&ranges, max_hash_buf);
    let mut step: u32 = 0;

    if cfg!(target_arch = "wasm32") {
        // hash the data for ranges
        for r in ranges {
            step += 1;
            progress(step, total)?;

            let start = r.start();
            let end = r.end();
            let mut chunk_left = end - start + 1;

            // check to see if this range is an BMFF V2 offset to include in the hash
            if bmff_v2_starts.contains(start) && end == start {
                hasher_enum.update(&start.to_be_bytes());
                continue;
            }

            // move to start of range
            data.seek(SeekFrom::Start(*start))?;

            loop {
                let mut chunk = vec![0u8; std::cmp::min(chunk_left as usize, max_hash_buf)];

                data.read_exact(&mut chunk)?;

                hasher_enum.update(&chunk);

                chunk_left -= chunk.len() as u64;
                if chunk_left == 0 {
                    break;
                }

                // fire after each non-final chunk so large ranges report sub-range progress
                step += 1;
                progress(step, total)?;
            }
        }
    } else {
        // hash the data for ranges, reading the next chunk on this thread while
        // the current one hashes on a worker (hash is still moving ahead sequentially).
        for r in ranges {
            step += 1;
            progress(step, total)?;

            let start = r.start();
            let end = r.end();
            let mut chunk_left = end - start + 1;

            // check to see if this range is an BMFF V2 offset to include in the hash
            if bmff_v2_starts.contains(start) && end == start {
                hasher_enum.update(&start.to_be_bytes());
                continue;
            }

            // move to start of range
            data.seek(SeekFrom::Start(*start))?;

            let mut chunk = vec![0u8; std::cmp::min(chunk_left as usize, max_hash_buf)];
            data.read_exact(&mut chunk)?;

            loop {
                chunk_left -= chunk.len() as u64;

                // with no next chunk to read there is nothing to overlap, so hash inline.
                if chunk_left == 0 {
                    hasher_enum.update(&chunk);
                    break;
                }

                let (tx, rx) = std::sync::mpsc::channel();

                std::thread::Builder::new()
                    .name("c2pa-hash".to_string())
                    .spawn(move || {
                        hasher_enum.update(&chunk);
                        tx.send(hasher_enum).unwrap_or_default();
                    })?;

                // read next chunk while we wait for hash
                let mut next_chunk = vec![0u8; std::cmp::min(chunk_left as usize, max_hash_buf)];
                data.read_exact(&mut next_chunk)?;

                hasher_enum = match rx.recv() {
                    Ok(hasher) => hasher,
                    Err(_) => return Err(Error::ThreadReceiveError),
                };

                // fire after each completed pipeline stage so large ranges report sub-range progress
                step += 1;
                progress(step, total)?;

                chunk = next_chunk;
            }
        }
    }

    // return the hash
    Ok(Hasher::finalize(hasher_enum))
}

/// May be used to generate hashes in combination with embeddable APIs.
pub fn hash_stream_by_alg<R>(
    alg: &str,
    data: &mut R,
    hash_range: Option<Vec<HashRange>>,
    is_exclusion: bool,
) -> Result<Vec<u8>>
where
    R: Read + Seek + ?Sized,
{
    hash_stream_by_alg_with_progress(alg, data, hash_range, is_exclusion, &mut |_, _| Ok(()))
}

/// The object a hash pass reads from: the source, its length, and the version every
/// fetch must come from.
///
/// Grouped so the version travels with the reader it belongs to and cannot be
/// forgotten at a call site.
pub(crate) struct AsyncHashSource<'a> {
    pub reader: &'a dyn crate::asset_source::range::AsyncRangeReader,
    pub data_len: u64,
    pub expect_version: Option<&'a crate::asset_source::range::ObjectVersion>,
}

/// Hashes an asset read through an asynchronous range source,
/// holding at most `chunk_size` bytes at a time.
///
/// The ranges come from [`build_hash_ranges`], so exclusions resolve exactly as they
/// do for [`hash_stream_by_alg`]. They are sorted ascending and walked in order, so
/// this needs only a forward sequence of chunk fetches and no random access and no
/// blocking read. Each chunk is hashed and dropped before the next is requested.
///
/// A range shorter than `chunk_size` is still fetched in one request; a longer one
/// is split. Because `read_range_async` may return fewer bytes than asked for, each
/// chunk accumulates until it is full, and a fetch yielding nothing is a short read
/// rather than end-of-file.
pub(crate) async fn hash_ranges_by_alg_async<F>(
    alg: &str,
    source: AsyncHashSource<'_>,
    hash_range: Option<Vec<HashRange>>,
    is_exclusion: bool,
    chunk_size: NonZeroUsize,
    progress: &mut F,
) -> Result<Vec<u8>>
where
    F: FnMut(u32, u32) -> Result<()>,
{
    let AsyncHashSource {
        reader,
        data_len,
        expect_version,
    } = source;
    let chunk_size = chunk_size.get();
    let mut hasher_enum = hasher_for_alg(alg)?;

    let (ranges, bmff_v2_starts) = build_hash_ranges(hash_range, is_exclusion, data_len)?;

    let total = progress_total(&ranges, chunk_size);
    let mut step: u32 = 0;

    for r in &ranges {
        step += 1;
        progress(step, total)?;

        let start = *r.start();
        let end = *r.end();

        // a BMFF V2 offset contributes its value to the hash, not the bytes there
        if bmff_v2_starts.contains(&start) && end == start {
            hasher_enum.update(&start.to_be_bytes());
            continue;
        }

        let mut offset = start;
        let mut range_left = end - start + 1;

        while range_left > 0 {
            let want = std::cmp::min(range_left, chunk_size as u64);
            let mut chunk = Vec::with_capacity(want as usize);

            // one logical chunk may take several fetches if the source short-reads
            while (chunk.len() as u64) < want {
                let still_want = want - chunk.len() as u64;
                let data = crate::asset_source::range::fetch_versioned_async(
                    reader,
                    offset,
                    still_want,
                    expect_version,
                )
                .await?;
                if data.is_empty() {
                    return Err(crate::asset_source::AssetSourceError::ShortRead {
                        offset,
                        expected: still_want,
                        got: 0,
                    }
                    .into());
                }
                // a source may also overshoot; take only what this chunk needs
                let take = std::cmp::min(data.len() as u64, still_want) as usize;
                chunk.extend_from_slice(&data[..take]);
                offset += take as u64;
            }

            hasher_enum.update(&chunk);
            range_left -= want;

            if range_left > 0 {
                // fire after each non-final chunk so large ranges report sub-range progress
                step += 1;
                progress(step, total)?;
            }
        }
    }

    Ok(Hasher::finalize(hasher_enum))
}

// verify the hash using the specified algorithm
pub fn verify_by_alg(
    alg: &str,
    hash: &[u8],
    data: &[u8],
    exclusions: Option<Vec<HashRange>>,
) -> bool {
    // hash with the same algorithm as target
    let data_hash = hash_by_alg(alg, data, exclusions);
    vec_compare(hash, &data_hash)
}

// verify the hash using the specified algorithm
pub fn verify_asset_by_alg(
    alg: &str,
    hash: &[u8],
    asset_path: &Path,
    exclusions: Option<Vec<HashRange>>,
) -> bool {
    // hash with the same algorithm as target
    if let Ok(data_hash) = hash_asset_by_alg(alg, asset_path, exclusions) {
        vec_compare(hash, &data_hash)
    } else {
        false
    }
}

pub fn verify_stream_by_alg<R>(
    alg: &str,
    hash: &[u8],
    reader: &mut R,
    hash_range: Option<Vec<HashRange>>,
    is_exclusion: bool,
) -> bool
where
    R: Read + Seek + ?Sized,
{
    if let Ok(data_hash) = hash_stream_by_alg(alg, reader, hash_range, is_exclusion) {
        vec_compare(hash, &data_hash)
    } else {
        false
    }
}

// Used by Merkle tree calculations to generate the pair wise hash
pub fn concat_and_hash(alg: &str, left: &[u8], right: Option<&[u8]>) -> Vec<u8> {
    let mut temp = left.to_vec();

    if let Some(r) = right {
        temp.append(&mut r.to_vec())
    }

    hash_by_alg(alg, &temp, None)
}

/// replace byte arrays with base64 encoded strings
pub fn hash_to_b64(mut value: Value) -> Value {
    use std::collections::VecDeque;

    let mut queue = VecDeque::new();
    queue.push_back(&mut value);

    while let Some(current) = queue.pop_front() {
        match current {
            Value::Object(obj) => {
                for (_, v) in obj.iter_mut() {
                    if let Value::Array(hash_arr) = v {
                        if !hash_arr.is_empty() && hash_arr.iter().all(|x| x.is_number()) {
                            // Pre-allocate with capacity to avoid reallocations
                            let mut hash_bytes = Vec::with_capacity(hash_arr.len());
                            // Convert numbers to bytes safely
                            for n in hash_arr.iter() {
                                if let Some(num) = n.as_u64() {
                                    hash_bytes.push(num as u8);
                                }
                            }
                            *v = Value::String(encode(&hash_bytes));
                        }
                    }
                    queue.push_back(v);
                }
            }
            Value::Array(arr) => {
                for v in arr.iter_mut() {
                    queue.push_back(v);
                }
            }
            _ => {}
        }
    }
    value
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use hex_literal::hex;

    use super::*;

    // Small enough that a few KB of test data spans multiple chunks.
    fn test_hash_buf() -> NonZeroUsize {
        NonZeroUsize::new(1024).unwrap()
    }

    // Attacker-controlled HashRange with start+length > u64::MAX must return Err,
    // not panic, in both the exclusion and inclusion paths.
    #[test]
    fn test_exclusion_range_overflow_returns_error() {
        let data = vec![0u8; 64];
        let mut reader = Cursor::new(&data);
        let hr = vec![HashRange::new(u64::MAX - 10, 20)]; // start + length overflows u64
        let result = hash_stream_by_alg("sha256", &mut reader, Some(hr), true);
        assert!(
            result.is_err(),
            "exclusion range overflow must return Err, not panic"
        );
    }

    #[test]
    fn test_inclusion_range_overflow_returns_error() {
        let data = vec![0u8; 64];
        let mut reader = Cursor::new(&data);
        let hr = vec![HashRange::new(u64::MAX, 1)]; // start + length overflows u64
        let result = hash_stream_by_alg("sha256", &mut reader, Some(hr), false);
        assert!(
            result.is_err(),
            "inclusion range overflow must return Err, not panic"
        );
    }

    #[test]
    fn progress_callback_is_called() {
        let data = vec![0u8; 64];
        let mut called = false;
        let mut reader = Cursor::new(&data);
        let mut cb = |_step, _total| {
            called = true;
            Ok(())
        };
        hash_stream_by_alg_with_progress("sha256", &mut reader, None, true, &mut cb).unwrap();
        assert!(called, "progress callback should have been invoked");
    }

    #[test]
    fn progress_callback_can_cancel() {
        let data = vec![0u8; 64];
        let mut reader = Cursor::new(&data);
        let mut cb = |_step, _total| Err(Error::OperationCancelled);
        let result = hash_stream_by_alg_with_progress("sha256", &mut reader, None, true, &mut cb);
        assert!(
            matches!(result, Err(Error::OperationCancelled)),
            "expected OperationCancelled, got {result:?}"
        );
    }

    // One tick per range before any read, one after each non-final chunk,
    // none for the final chunk regardless of whether it hashed inline.
    #[test]
    fn progress_sequence_multi_chunk() {
        let data = vec![0u8; 3 * 1024]; // 3 chunks at the 1024 buffer size below
        let mut reader = Cursor::new(&data);
        let mut seen: Vec<(u32, u32)> = Vec::new();
        let mut cb = |step, total| {
            seen.push((step, total));
            Ok(())
        };
        hash_stream_by_alg_with_progress_impl(
            "sha256",
            &mut reader,
            None,
            true,
            &mut cb,
            test_hash_buf(),
        )
        .unwrap();
        assert_eq!(seen, vec![(1, 3), (2, 3), (3, 3)]);
    }

    // 3 chunks at the 1024 buffer size passed below, non-uniform.
    // A reordered or dropped chunk changes the hash.
    // Expected value computed with:
    //   python3 -c "import hashlib
    //   d = bytes((i % 251) for i in range(3*1024))
    //   print(hashlib.sha256(d).hexdigest())"
    #[test]
    fn multi_chunk_digest_matches_known_value() {
        let data: Vec<u8> = (0..3 * 1024).map(|i| (i % 251) as u8).collect();
        let mut reader = Cursor::new(&data);
        let hash = hash_stream_by_alg_with_progress_impl(
            "sha256",
            &mut reader,
            None,
            true,
            &mut |_, _| Ok(()),
            test_hash_buf(),
        )
        .unwrap();

        assert_eq!(
            hash,
            hex!("5f24b2f16026ec7d0450a5a08283d3cfd47302fe859f579ed79fe7d2663b73f9")
        );
    }

    // Exclusion splits this into a 1-chunk range and a 2-chunk range.
    // Expected value computed with:
    //   python3 -c "import hashlib
    //   d = bytes((i % 251) for i in range(3*1024))
    //   print(hashlib.sha256(d[:1000] + d[1100:]).hexdigest())"
    #[test]
    fn multi_chunk_digest_survives_range_splits() {
        let data: Vec<u8> = (0..3 * 1024).map(|i| (i % 251) as u8).collect();
        let mut reader = Cursor::new(&data);
        let hr = vec![HashRange::new(1000, 100)];
        let hash = hash_stream_by_alg_with_progress_impl(
            "sha256",
            &mut reader,
            Some(hr),
            true,
            &mut |_, _| Ok(()),
            test_hash_buf(),
        )
        .unwrap();

        assert_eq!(
            hash,
            hex!("e3301ce38a42503098530b98cd1b652a10c5caf890735017dd0012ec319f04e5")
        );
    }

    // The async loop must agree with the synchronous one on every exclusion shape;
    // a drift between the two produces a wrong digest, which surfaces as a hash
    // mismatch on a valid asset.
    #[tokio::test]
    async fn async_digest_matches_sync_digest_with_exclusions() {
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        };

        use crate::asset_source::{
            range::{AsyncRangeReader, ObjectVersion, RangeChunk, RangeInfo},
            AssetSourceError,
        };

        struct AsyncMem {
            data: Vec<u8>,
            largest: Arc<AtomicU64>,
        }

        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        impl AsyncRangeReader for AsyncMem {
            async fn info_async(&self) -> std::result::Result<RangeInfo, AssetSourceError> {
                Ok(RangeInfo::new(self.data.len() as u64))
            }
            async fn read_range_async(
                &self,
                offset: u64,
                len: u64,
                expect: Option<&ObjectVersion>,
            ) -> std::result::Result<RangeChunk, AssetSourceError> {
                let _ = expect;
                self.largest.fetch_max(len, Ordering::SeqCst);
                let start = offset as usize;
                let end = (offset + len).min(self.data.len() as u64) as usize;
                Ok(RangeChunk::new(self.data[start..end].to_vec()))
            }
        }

        let data: Vec<u8> = (0..8 * 1024).map(|i| (i % 251) as u8).collect();

        // several exclusions, including one at the very start and one running to the
        // end, so the range list has gaps at both edges and in the middle
        let exclusions = vec![
            HashRange::new(0, 64),
            HashRange::new(1000, 100),
            HashRange::new(5000, 33),
            HashRange::new(8 * 1024 - 16, 16),
        ];

        let mut cursor = Cursor::new(&data);
        let sync_hash = hash_stream_by_alg_with_progress_impl(
            "sha256",
            &mut cursor,
            Some(exclusions.clone()),
            true,
            &mut |_, _| Ok(()),
            test_hash_buf(),
        )
        .unwrap();

        let largest = Arc::new(AtomicU64::new(0));
        let reader = AsyncMem {
            data: data.clone(),
            largest: largest.clone(),
        };
        let async_hash = hash_ranges_by_alg_async(
            "sha256",
            AsyncHashSource {
                reader: &reader,
                data_len: data.len() as u64,
                expect_version: None,
            },
            Some(exclusions),
            true,
            test_hash_buf(),
            &mut |_, _| Ok(()),
        )
        .await
        .unwrap();

        assert_eq!(sync_hash, async_hash);

        // peak memory is the point of the streaming design: no single fetch may
        // exceed the configured chunk size, whatever the asset size
        assert!(
            largest.load(Ordering::SeqCst) <= test_hash_buf().get() as u64,
            "requested {} bytes in one fetch, chunk size is {}",
            largest.load(Ordering::SeqCst),
            test_hash_buf().get()
        );
    }

    // A range source may legally return fewer bytes than requested; the digest must
    // still be correct, and a source returning nothing must error rather than spin.
    #[tokio::test]
    async fn async_digest_survives_short_reads() {
        use crate::asset_source::{
            range::{AsyncRangeReader, ObjectVersion, RangeChunk, RangeInfo},
            AssetSourceError,
        };

        struct Dribble {
            data: Vec<u8>,
            per_read: usize,
        }

        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        impl AsyncRangeReader for Dribble {
            async fn info_async(&self) -> std::result::Result<RangeInfo, AssetSourceError> {
                Ok(RangeInfo::new(self.data.len() as u64))
            }
            async fn read_range_async(
                &self,
                offset: u64,
                len: u64,
                expect: Option<&ObjectVersion>,
            ) -> std::result::Result<RangeChunk, AssetSourceError> {
                let _ = expect;
                let start = offset as usize;
                let capped = (len as usize).min(self.per_read);
                let end = (start + capped).min(self.data.len());
                Ok(RangeChunk::new(self.data[start..end].to_vec()))
            }
        }

        let data: Vec<u8> = (0..4 * 1024).map(|i| (i % 251) as u8).collect();
        let exclusions = vec![HashRange::new(500, 50)];

        let mut cursor = Cursor::new(&data);
        let expected = hash_stream_by_alg_with_progress_impl(
            "sha256",
            &mut cursor,
            Some(exclusions.clone()),
            true,
            &mut |_, _| Ok(()),
            test_hash_buf(),
        )
        .unwrap();

        // 7 bytes per fetch, so every chunk needs many round trips to fill
        let reader = Dribble {
            data: data.clone(),
            per_read: 7,
        };
        let got = hash_ranges_by_alg_async(
            "sha256",
            AsyncHashSource {
                reader: &reader,
                data_len: data.len() as u64,
                expect_version: None,
            },
            Some(exclusions.clone()),
            true,
            test_hash_buf(),
            &mut |_, _| Ok(()),
        )
        .await
        .unwrap();

        assert_eq!(expected, got);

        // a source that yields nothing at all is a short read, not end-of-file
        let stalled = Dribble {
            data: data.clone(),
            per_read: 0,
        };
        let err = hash_ranges_by_alg_async(
            "sha256",
            AsyncHashSource {
                reader: &stalled,
                data_len: data.len() as u64,
                expect_version: None,
            },
            Some(exclusions),
            true,
            test_hash_buf(),
            &mut |_, _| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::AssetSource(crate::asset_source::AssetSourceError::ShortRead { .. })
            ),
            "expected a short-read error, got {err:?}"
        );
    }
}
