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
    io::{Read, Seek, SeekFrom},
    ops::RangeInclusive,
    path::Path,
};

use log::{debug, warn};
// multihash versions
use multibase::{decode, encode};
use multihash::{wrap, Code, Multihash, Sha2_256, Sha2_512, Sha3_256, Sha3_384, Sha3_512};
use range_set::RangeSet;
use serde::{Deserialize, Serialize};
// direct sha functions
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{asset_io::CAIReadWrite, Error, Result};

const MAX_HASH_BUF: usize = 256 * 1024 * 1024; // cap memory usage to 256MB

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Exclusion {
    start: usize,
    length: usize,
}

impl Exclusion {
    pub fn new(start: usize, length: usize) -> Self {
        Exclusion { start, length }
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
enum Hasher {
    SHA256(Sha256),
    SHA384(Sha384),
    SHA512(Sha512),
}

impl Hasher {
    // update hash value with new data
    fn update(&mut self, data: &[u8]) {
        use Hasher::*;
        // update the hash
        match self {
            SHA256(ref mut d) => d.update(data),
            SHA384(ref mut d) => d.update(data),
            SHA512(ref mut d) => d.update(data),
        }
    }

    // comsume hasher and return the final digest
    fn finalize(hasher_enum: Hasher) -> Vec<u8> {
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
pub fn hash_by_alg(alg: &str, data: &[u8], exclusions: Option<Vec<Exclusion>>) -> Vec<u8> {
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

    match exclusions {
        Some(mut e) if !e.is_empty() => {
            // hash data skipping excluded regions
            // sort the exclusions
            e.sort_by_key(|a| a.start());

            // verify structure of blocks
            let num_blocks = e.len();
            let exclusion_end = e[num_blocks - 1].start() + e[num_blocks - 1].length();
            let data_len = data.len();
            let data_end = data_len - 1;

            // if not enough range we will just calc to the end
            if data_len < exclusion_end {
                debug!("the exclusion range exceed the data length");
                return Vec::new();
            }

            //build final ranges
            let mut ranges = RangeSet::<[RangeInclusive<usize>; 1]>::from(0..=data_end);
            for exclusion in e {
                let end = exclusion.start() + exclusion.length() - 1;
                ranges.remove_range(exclusion.start()..=end);
            }

            // hash the data for ranges
            for r in ranges.into_smallvec() {
                hasher_enum.update(&data[r]);
            }

            // return the hash
            Hasher::finalize(hasher_enum)
        }
        _ => {
            // add the data
            hasher_enum.update(data);

            // return the hash
            Hasher::finalize(hasher_enum)
        }
    }
}

// Return hash bytes for asset using desired hashing algorithm.
pub fn hash_asset_by_alg(
    alg: &str,
    asset_path: &Path,
    exclusions: Option<Vec<Exclusion>>,
) -> Result<Vec<u8>> {
    let mut file = File::open(asset_path)?;
    hash_stream_by_alg(alg, &mut file, exclusions)
}

// Return hash bytes for stream using desired hashing algorithm.
pub fn hash_stream_by_alg(
    alg: &str,
    data: &mut dyn CAIReadWrite,
    exclusions: Option<Vec<Exclusion>>,
) -> Result<Vec<u8>> {
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
    data.seek(SeekFrom::Start(0))?;

    let ranges = match exclusions {
        Some(mut e) if !e.is_empty() => {
            // hash data skipping excluded regions
            // sort the exclusions
            e.sort_by_key(|a| a.start());

            // verify structure of blocks
            let num_blocks = e.len();
            let exclusion_end = e[num_blocks - 1].start() + e[num_blocks - 1].length();
            let data_end = data_len - 1;

            // if not enough range we will just calc to the end
            if data_len < exclusion_end as u64 {
                return Err(Error::BadParam(
                    "The exclusion range exceed the data length".to_string(),
                ));
            }

            //build final ranges
            let mut ranges = RangeSet::<[RangeInclusive<u64>; 1]>::from(0..=data_end);
            for exclusion in e {
                let end = (exclusion.start() + exclusion.length() - 1) as u64;
                let exclusion_start = exclusion.start() as u64;
                ranges.remove_range(exclusion_start..=end);
            }

            ranges
        }
        _ => {
            let data_end = data_len - 1;
            RangeSet::<[RangeInclusive<u64>; 1]>::from(0..=data_end)
        }
    };

    if cfg!(feature = "no_interleaved_io") {
        // hash the data for ranges
        for r in ranges.into_smallvec() {
            let start = r.start();
            let end = r.end();
            let mut chunk_left = end - start + 1;

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
            }
        }
    } else {
        // hash the data for ranges
        for r in ranges.into_smallvec() {
            let start = r.start();
            let end = r.end();
            let mut chunk_left = end - start + 1;

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
    exclusions: Option<Vec<Exclusion>>,
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
    exclusions: Option<Vec<Exclusion>>,
) -> bool {
    // hash with the same algorithm as target
    if let Ok(data_hash) = hash_asset_by_alg(alg, asset_path, exclusions) {
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
    data.seek(SeekFrom::Start(0))?;
    let data_len = data.seek(SeekFrom::End(0))?;
    data.seek(SeekFrom::Start(0))?;

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
