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

//use conv::ValueFrom;
use log::warn;
// multihash versions
use multibase::{decode, encode};
use multihash::{wrap, Code, Multihash, Sha2_256, Sha2_512, Sha3_256, Sha3_384, Sha3_512};
use range_set::RangeSet;
use serde::{Deserialize, Serialize};
// direct sha functions
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{Error, Result};

const MAX_HASH_BUF: usize = 256 * 1024 * 1024; // cap memory usage to 256MB

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct HashRange {
    start: usize,
    length: usize,

    #[serde(skip)]
    bmff_offset: Option<u64>, /* optional tracking of offset positions to include in BMFF_V2 hashes in BE format */
}

impl HashRange {
    pub fn new(start: usize, length: usize) -> Self {
        HashRange {
            start,
            length,
            bmff_offset: None,
        }
    }

    /// update the start value
    #[allow(dead_code)]
    pub fn set_start(&mut self, start: usize) {
        self.start = start;
    }

    /// return start as usize
    pub fn start(&self) -> usize {
        self.start
    }

    /// return length as usize
    pub fn length(&self) -> usize {
        self.length
    }

    pub fn set_length(&mut self, length: usize) {
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

/// Generate hash of type hash_type for supplied data array.  The
/// hash_type are those specified in the multihash specification.  Currently
/// we only support Sha2-256/512 or Sha2-256/512.
/// Returns hash or None if incomptible type
pub fn hash_by_type(hash_type: u8, data: &[u8]) -> Option<Multihash> {
    match hash_type {
        0x12 => Some(Sha2_256::digest(data)),
        0x13 => Some(Sha2_512::digest(data)),
        0x14 => Some(Sha3_512::digest(data)),
        0x15 => Some(Sha3_384::digest(data)),
        0x16 => Some(Sha3_256::digest(data)),
        _ => None,
    }
}

#[derive(Clone)]
pub enum Hasher {
    SHA256(Sha256),
    SHA384(Sha384),
    SHA512(Sha512),
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

    // comsume hasher and return the final digest
    pub fn finalize(hasher_enum: Hasher) -> Vec<u8> {
        use Hasher::*;
        // return the hash
        match hasher_enum {
            SHA256(d) => d.finalize().to_vec(),
            SHA384(d) => d.finalize().to_vec(),
            SHA512(d) => d.finalize().to_vec(),
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
pub fn hash_stream_by_alg<R>(
    alg: &str,
    data: &mut R,
    hash_range: Option<Vec<HashRange>>,
    is_exclusion: bool,
) -> Result<Vec<u8>>
where
    R: Read + Seek + ?Sized,
{
    let mut bmff_v2_starts: Vec<u64> = Vec::new();

    use Hasher::*;
    let mut hasher_enum = match alg {
        "sha256" => SHA256(Sha256::new()),
        "sha384" => SHA384(Sha384::new()),
        "sha512" => SHA512(Sha512::new()),
        _ => {
            warn!(
                "Unsupported hashing algorithm: {}, substituting sha256",
                alg
            );
            SHA256(Sha256::new())
        }
    };

    let data_len = data.seek(SeekFrom::End(0))?;
    data.rewind()?;

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
            if data_len < range_end as u64 {
                return Err(Error::BadParam(
                    "The exclusion range exceed the data length".to_string(),
                ));
            }

            if is_exclusion {
                //build final ranges
                let mut ranges_vec: Vec<RangeInclusive<u64>> = Vec::new();
                let mut ranges = RangeSet::<[RangeInclusive<u64>; 1]>::from(0..=data_end);
                for exclusion in hr {
                    let end = (exclusion.start() + exclusion.length() - 1) as u64;
                    let exclusion_start = exclusion.start() as u64;
                    ranges.remove_range(exclusion_start..=end);

                    // add new BMFF V2 offset as a new range to be included so that we can
                    // pause to add the offset hash
                    if let Some(offset) = exclusion.bmff_offset() {
                        bmff_v2_starts.push(offset);
                    }
                }

                // merge standard ranges and BMFF V2 ranges into single list
                if !bmff_v2_starts.is_empty() {
                    // remove any offset hashes that would be excluded
                    let test_ranges = ranges.clone().into_smallvec();
                    bmff_v2_starts.retain(|o| test_ranges.iter().any(|r| r.contains(&(*o + 1))));

                    // add in remaining BMFF V2 offsets
                    for os in bmff_v2_starts.iter() {
                        ranges_vec.push(RangeInclusive::new(*os, *os));
                    }

                    // add regularly included ranges
                    for r in ranges.into_smallvec() {
                        ranges_vec.push(r);
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
                    let end = (inclusion.start() + inclusion.length() - 1) as u64;
                    let inclusion_start = inclusion.start() as u64;

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

    if cfg!(feature = "no_interleaved_io") || cfg!(target_arch = "wasm32") {
        // hash the data for ranges
        for r in ranges {
            let start = r.start();
            let end = r.end();
            let mut chunk_left = end - start + 1;

            // move to start of range
            data.seek(SeekFrom::Start(*start))?;

            // check to see if this range is an BMFF V2 offset to include in the hash
            if bmff_v2_starts.contains(start) && (end - start) == 0 {
                hasher_enum.update(&start.to_be_bytes());
            }

            loop {
                let mut chunk = vec![0u8; std::cmp::min(chunk_left as usize, MAX_HASH_BUF)];

                data.read_exact(&mut chunk)?;

                hasher_enum.update(&chunk);

                chunk_left -= chunk.len() as u64;
                if chunk_left == 0 {
                    break;
                }
            }
        }
    } else {
        // hash the data for ranges
        for r in ranges {
            let start = r.start();
            let end = r.end();
            let mut chunk_left = end - start + 1;

            // move to start of range
            data.seek(SeekFrom::Start(*start))?;

            // check to see if this range is an BMFF V2 offset to include in the hash
            if bmff_v2_starts.contains(start) && (end - start) == 0 {
                hasher_enum.update(&start.to_be_bytes());
            }

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

                chunk = next_chunk;
            }
        }
    }

    // return the hash
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

// verify the hash using the specified alogrithm
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

/// Return a multihash (Sha256) of array of bytes
#[allow(dead_code)]
pub fn hash256(data: &[u8]) -> String {
    let mh = Sha2_256::digest(data);
    let digest = mh.digest();
    let wrapped: Multihash = wrap(Code::Sha2_256, digest);

    // Return Base-64 encoded hash.
    encode(multibase::Base::Base64, wrapped.as_bytes())
}

/// Verify muiltihash against input data.  True if match,
/// false if no match or unsupported.  The hash value should be
/// be multibase encoded string.
pub fn verify_hash(hash: &str, data: &[u8]) -> bool {
    match decode(hash) {
        Ok((_code, mh)) => {
            if mh.len() < 2 {
                return false;
            }

            // multihash lead bytes
            let hash_type = mh[0]; // hash type
            let _hash_len = mh[1]; // hash data length

            // hash with the same algorithm as target
            if let Some(data_hash) = hash_by_type(hash_type, data) {
                vec_compare(data_hash.digest(), &mh.as_slice()[2..])
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

// Fast implementation for Blake3 hashing that can handle large assets
pub fn blake3_from_asset(path: &Path) -> Result<String> {
    let mut data = File::open(path)?;
    data.rewind()?;
    let data_len = data.seek(SeekFrom::End(0))?;
    data.rewind()?;

    let mut hasher = blake3::Hasher::new();

    let mut chunk_left = data_len;

    if cfg!(feature = "no_interleaved_io") {
        loop {
            let mut chunk = vec![0u8; std::cmp::min(chunk_left as usize, MAX_HASH_BUF)];

            data.read_exact(&mut chunk)?;

            hasher.update(&chunk);

            chunk_left -= chunk.len() as u64;
            if chunk_left == 0 {
                break;
            }
        }
    } else {
        let mut chunk = vec![0u8; std::cmp::min(chunk_left as usize, MAX_HASH_BUF)];
        data.read_exact(&mut chunk)?;

        loop {
            let (tx, rx) = std::sync::mpsc::channel();

            chunk_left -= chunk.len() as u64;

            std::thread::spawn(move || {
                hasher.update(&chunk);
                tx.send(hasher).unwrap_or_default();
            });

            // are we done
            if chunk_left == 0 {
                hasher = match rx.recv() {
                    Ok(hasher) => hasher,
                    Err(_) => return Err(Error::ThreadReceiveError),
                };
                break;
            }

            // read next chunk while we wait for hash
            let mut next_chunk = vec![0u8; std::cmp::min(chunk_left as usize, MAX_HASH_BUF)];
            data.read_exact(&mut next_chunk)?;

            hasher = match rx.recv() {
                Ok(hasher) => hasher,
                Err(_) => return Err(Error::ThreadReceiveError),
            };

            chunk = next_chunk;
        }
    }

    let hash = hasher.finalize();

    Ok(hash.to_hex().as_str().to_owned())
}

/// Return the hash of data in the same hash format in_hash
pub fn hash_as_source(in_hash: &str, data: &[u8]) -> Option<String> {
    match decode(in_hash) {
        Ok((code, mh)) => {
            if mh.len() < 2 {
                return None;
            }

            // multihash lead bytes
            let hash_type = mh[0]; // hash type

            // hash with the same algorithm as target
            match hash_by_type(hash_type, data) {
                Some(hash) => {
                    let digest = hash.digest();

                    let wrapped = match hash_type {
                        0x12 => wrap(Code::Sha2_256, digest),
                        0x13 => wrap(Code::Sha2_512, digest),
                        0x14 => wrap(Code::Sha3_512, digest),
                        0x15 => wrap(Code::Sha3_384, digest),
                        0x16 => wrap(Code::Sha3_256, digest),
                        _ => return None,
                    };

                    // Return encoded hash.
                    Some(encode(code, wrapped.as_bytes()))
                }
                None => None,
            }
        }
        Err(_) => None,
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
