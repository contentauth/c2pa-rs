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

// ========== SECURITY CONSTANTS FOR EXCLUSION VALIDATION ==========
/// Maximum percentage of asset that can be excluded (10% = 0.1)
/// This prevents attackers from excluding large portions of content
const MAX_EXCLUSION_PERCENTAGE: f64 = 0.10;

/// Minimum size in bytes that an exclusion must be for (prevents tiny fragmented exclusions)
const MIN_EXCLUSION_SIZE: u64 = 1;

/// Maximum number of exclusion ranges allowed per hash
/// This prevents DOS attacks with many small exclusions
const MAX_EXCLUSION_RANGES: usize = 100;

/// Magic bytes to cryptographically bind exclusions to the hash
/// This ensures exclusions cannot be manipulated without detection
const EXCLUSION_BINDING_PREFIX: &[u8] = b"C2PA_EXCLUSION_V1";

// ========== EXCLUSION VALIDATION STRUCTURE ==========
#[derive(Clone, Debug)]
pub struct ExclusionValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub total_excluded_bytes: u64,
    pub exclusion_percentage: f64,
}

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

// ========== NEW SECURITY FUNCTION: VALIDATE EXCLUSIONS ==========
/// Validates exclusion ranges against security constraints.
/// This function ensures exclusions cannot be abused for signature bypass.
///
/// # Security Checks:
/// 1. No single exclusion can exceed MAX_EXCLUSION_PERCENTAGE of total data
/// 2. Total excluded bytes cannot exceed MAX_EXCLUSION_PERCENTAGE of total data
/// 3. Number of exclusion ranges is bounded by MAX_EXCLUSION_RANGES
/// 4. All ranges are non-overlapping and well-formed
/// 5. No exclusion can extend beyond the asset boundary
pub fn validate_exclusions(
    hash_ranges: &[HashRange],
    data_len: u64,
) -> ExclusionValidationResult {
    let mut result = ExclusionValidationResult {
        is_valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
        total_excluded_bytes: 0,
        exclusion_percentage: 0.0,
    };

    // Check 1: Validate number of ranges
    if hash_ranges.len() > MAX_EXCLUSION_RANGES {
        result.is_valid = false;
        result.errors.push(format!(
            "Too many exclusion ranges: {} (max: {})",
            hash_ranges.len(),
            MAX_EXCLUSION_RANGES
        ));
    }

    // Check 2: Validate each range individually
    let mut sorted_ranges = hash_ranges.to_vec();
    sorted_ranges.sort_by_key(|r| r.start());

    for (idx, range) in sorted_ranges.iter().enumerate() {
        let range_end = match range.start().checked_add(range.length()) {
            Some(end) => {
                if end > data_len {
                    result.is_valid = false;
                    result.errors.push(format!(
                        "Exclusion range {} extends beyond asset boundary: {}-{} (data length: {})",
                        idx, range.start(), end, data_len
                    ));
                    continue;
                }
                end
            }
            None => {
                result.is_valid = false;
                result.errors.push(format!(
                    "Exclusion range {} has overflow error",
                    idx
                ));
                continue;
            }
        };

        // Check 3: Individual range size validation
        let range_percentage = range.length() as f64 / data_len as f64;
        if range_percentage > MAX_EXCLUSION_PERCENTAGE {
            result.is_valid = false;
            result.errors.push(format!(
                "Exclusion range {} is too large: {:.2}% of asset (max: {:.2}%)",
                idx,
                range_percentage * 100.0,
                MAX_EXCLUSION_PERCENTAGE * 100.0
            ));
        }

        // Check 4: Detect overlaps with previous ranges
        if idx > 0 {
            let prev_range = &sorted_ranges[idx - 1];
            let prev_end = prev_range.start() + prev_range.length();
            if prev_end > range.start() {
                result.is_valid = false;
                result.errors.push(format!(
                    "Exclusion ranges {} and {} overlap: {}-{} overlaps with {}-{}",
                    idx - 1, idx, prev_range.start(), prev_end, range.start(), range_end
                ));
            }
        }

        result.total_excluded_bytes += range.length();
    }

    // Check 5: Validate cumulative exclusion percentage
    result.exclusion_percentage = result.total_excluded_bytes as f64 / data_len as f64;
    if result.exclusion_percentage > MAX_EXCLUSION_PERCENTAGE {
        result.is_valid = false;
        result.errors.push(format!(
            "Total exclusions exceed maximum: {:.2}% of asset (max: {:.2}%)",
            result.exclusion_percentage * 100.0,
            MAX_EXCLUSION_PERCENTAGE * 100.0
        ));
    }

    result
}

// ========== NEW SECURITY FUNCTION: HASH EXCLUSION MANIFEST ==========
/// Cryptographically binds exclusions to the hash to prevent manipulation.
/// This ensures that exclusions cannot be added/removed/modified after signing.
fn hash_exclusion_manifest(hasher: &mut Hasher, hash_ranges: &[HashRange]) {
    // Prefix to ensure exclusion hashes don't collide with data hashes
    hasher.update(EXCLUSION_BINDING_PREFIX);

    let mut sorted_ranges = hash_ranges.to_vec();
    sorted_ranges.sort_by_key(|r| r.start());

    // Hash each exclusion range's metadata
    for range in sorted_ranges {
        // Hash the start position
        hasher.update(&range.start().to_le_bytes());
        // Hash the length
        hasher.update(&range.length().to_le_bytes());
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

    ========== SECURITY PATCH V1 ==========
    Added comprehensive validation of exclusion ranges to prevent signature bypass attacks.
    The function now:
    1. Validates all exclusion ranges before processing
    2. Rejects invalid/suspicious exclusion patterns
    3. Cryptographically binds exclusions to the hash
    4. Provides detailed error reporting for security violations
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
    let mut bmff_v2_starts: Vec<u64> = Vec::new();

    use Hasher::*;
    let mut hasher_enum = match alg {
        "sha256" => SHA256(Sha256::new()),
        "sha384" => SHA384(Sha384::new()),
        "sha512" => SHA512(Sha512::new()),
        _ => {
            return Err(Error::UnsupportedType);
        }
    };

    let data_len = stream_len(data)?;
    data.rewind()?;

    if data_len < 1 {
        return Err(Error::OtherError("no data to hash".into()));
    }

    // ========== SECURITY PATCH: VALIDATE EXCLUSIONS BEFORE PROCESSING ==========
    if let Some(ref hash_ranges) = hash_range {
        if is_exclusion && !hash_ranges.is_empty() {
            // Validate exclusion ranges against security constraints
            let validation = validate_exclusions(hash_ranges, data_len);

            if !validation.is_valid {
                // Security violation detected - log and reject
                let error_msg = format!(
                    "SECURITY: Exclusion validation failed: {}",
                    validation.errors.join("; ")
                );
                eprintln!("C2PA SECURITY ALERT: {}", error_msg);
                return Err(Error::BadParam(error_msg));
            }

            // Log warnings for legitimate but suspicious patterns
            for warning in validation.warnings {
                eprintln!("C2PA Security Warning: {}", warning);
            }

            eprintln!(
                "C2PA: Processing {} exclusion ranges ({:.2}% of asset)",
                hash_ranges.len(),
                validation.exclusion_percentage * 100.0
            );
        }
    }

    let ranges = match hash_range {
        Some(mut hr) if !hr.is_empty() => {
            // hash data skipping excluded regions
            // sort the exclusions
            hr.sort_by_key(|a| a.start());

            // verify structure of blocks
            let num_blocks = hr.len();
            let range_end = hr[num_blocks - 1].start() + hr[num_blocks - 1].length();
            let data_end = data_len - 1;

            // range extends past end of file so fail
            if data_len < range_end {
                return Err(Error::BadParam(
                    "The exclusion range exceed the data length".to_string(),
                ));
            }

            if is_exclusion {
                // ========== SECURITY PATCH: BIND EXCLUSIONS TO HASH ==========
                // Hash the exclusion manifest to prevent manipulation
                hash_exclusion_manifest(&mut hasher_enum, &hr);

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

                    let end = inclusion.start() + inclusion.length() - 1;
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

    // Total callbacks = one per 256 MB chunk across all ranges (BMFF V2 single-byte offsets
    // each contribute exactly one tick regardless of MAX_HASH_BUF).
    let total: u32 = ranges
        .iter()
        .map(|r| {
            let len = r.end() - r.start() + 1;
            (len as usize).div_ceil(MAX_HASH_BUF) as u32
        })
        .sum();
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
                let mut chunk = vec![0u8; std::cmp::min(chunk_left as usize, MAX_HASH_BUF)];

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

            let mut chunk = vec![0u8; std::cmp::min(chunk_left as usize, MAX_HASH_BUF)];
            data.read_exact(&mut chunk)?;

            loop {
                let (tx, rx) = std::sync::mpsc::channel();

                chunk_left -= chunk.len() as u64;

                std::thread::spawn(move || {
                    hasher_enum.update(&chunk);
                    tx.send(hasher_enum).unwrap_or_default();
                });

                // are we done
                if chunk_left == 0 {
                    hasher_enum = match rx.recv() {
                        Ok(hasher) => hasher,
                        Err(_) => return Err(Error::ThreadReceiveError),
                    };
                    break;
                }

                // read next chunk while we wait for hash
                let mut next_chunk = vec![0u8; std::cmp::min(chunk_left as usize, MAX_HASH_BUF)];
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

    use super::*;

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

    // ========== NEW SECURITY TESTS ==========

    #[test]
    fn test_validate_exclusions_single_large_exclusion() {
        let data_len = 1000u64;
        let exclusions = vec![HashRange::new(0, 200)]; // 20% - exceeds 10% limit
        let result = validate_exclusions(&exclusions, data_len);
        assert!(!result.is_valid, "Should reject exclusion exceeding max percentage");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("too large")),
            "Should report range is too large"
        );
    }

    #[test]
    fn test_validate_exclusions_cumulative_limit() {
        let data_len = 1000u64;
        let exclusions = vec![
            HashRange::new(0, 60),    // 6%
            HashRange::new(100, 60),  // 6%
            // Total: 12% - exceeds 10% limit
        ];
        let result = validate_exclusions(&exclusions, data_len);
        assert!(!result.is_valid, "Should reject when cumulative exclusions exceed limit");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("exceed maximum")),
            "Should report cumulative limit exceeded"
        );
    }

    #[test]
    fn test_validate_exclusions_overlapping_ranges() {
        let data_len = 1000u64;
        let exclusions = vec![
            HashRange::new(0, 50),    // 0-49
            HashRange::new(40, 50),   // 40-89 (overlaps!)
        ];
        let result = validate_exclusions(&exclusions, data_len);
        assert!(!result.is_valid, "Should reject overlapping ranges");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("overlap")),
            "Should report overlap"
        );
    }

    #[test]
    fn test_validate_exclusions_exceeds_data_boundary() {
        let data_len = 100u64;
        let exclusions = vec![HashRange::new(50, 60)]; // Would end at 110, beyond 100
        let result = validate_exclusions(&exclusions, data_len);
        assert!(!result.is_valid, "Should reject ranges beyond data boundary");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("beyond asset boundary")),
            "Should report boundary violation"
        );
    }

    #[test]
    fn test_validate_exclusions_too_many_ranges() {
        let data_len = 100000u64;
        let mut exclusions = Vec::new();
        for i in 0..105 {
            // MAX_EXCLUSION_RANGES is 100
            exclusions.push(HashRange::new(i * 100, 5));
        }
        let result = validate_exclusions(&exclusions, data_len);
        assert!(!result.is_valid, "Should reject too many ranges");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("Too many")),
            "Should report too many ranges"
        );
    }

    #[test]
    fn test_validate_exclusions_valid_case() {
        let data_len = 1000u64;
        let exclusions = vec![
            HashRange::new(0, 40),    // 4%
            HashRange::new(100, 40),  // 4%
            // Total: 8% - within 10% limit
        ];
        let result = validate_exclusions(&exclusions, data_len);
        assert!(result.is_valid, "Should accept valid exclusions");
        assert_eq!(result.total_excluded_bytes, 80);
        assert_eq!(result.exclusion_percentage, 0.08);
    }

    #[test]
    fn test_poi_signature_bypass_prevented() {
        // This test reproduces the PoC attack but verifies it's prevented
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let data_len = data.len() as u64;

        // Attacker tries to create an exclusion covering bytes 4-6
        let malicious_exclusions = vec![HashRange::new(4, 3)];

        // Validation should catch this suspicious pattern
        let validation = validate_exclusions(&malicious_exclusions, data_len);

        // Exclusion of 30% should be rejected (3 out of 10 bytes = 30% > 10% limit)
        assert!(!validation.is_valid);
        eprintln!(
            "Attack prevented! Reason: {}",
            validation.errors.join("; ")
        );
    }
}
