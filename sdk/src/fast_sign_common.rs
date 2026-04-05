// Copyright 2024 Adobe. All rights reserved.
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
//
// Common types and utilities shared by the fast-sign modules
// (fast_sign, fast_sign_riff, fast_sign_tiff).

use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    error::{Error, Result},
    utils::hash_utils::HashRange,
};

/// Placeholder offset used to seed the first JUMBF layout pass.
pub(crate) const PLACEHOLDER_OFFSET: u64 = 0xFFFF_FFFF;

/// Standard name used for the JUMBF manifest assertion.
pub(crate) const JUMBF_MANIFEST_NAME: &str = "jumbf manifest";

/// Copy buffer size used by the streaming copy functions.
pub(crate) const COPY_BUF_SIZE: usize = 256 * 1024; // 256KB

// --- Dynamic Hasher Wrapper ------------------------------------------------

/// Trait-object wrapper that dispatches to Sha256, Sha384, or Sha512 at
/// runtime, allowing StreamingHasher to work with any supported algorithm.
enum DynHasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl DynHasher {
    fn new(alg: &str) -> Result<Self> {
        match alg {
            "sha256" => Ok(DynHasher::Sha256(Sha256::new())),
            "sha384" => Ok(DynHasher::Sha384(Sha384::new())),
            "sha512" => Ok(DynHasher::Sha512(Sha512::new())),
            _ => Err(Error::UnsupportedType),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            DynHasher::Sha256(h) => h.update(data),
            DynHasher::Sha384(h) => h.update(data),
            DynHasher::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            DynHasher::Sha256(h) => h.finalize().to_vec(),
            DynHasher::Sha384(h) => h.finalize().to_vec(),
            DynHasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

// --- Streaming Hasher -------------------------------------------------------

/// Streaming hasher that accepts bytes at sequential output positions and
/// computes a hash (SHA-256, SHA-384, or SHA-512), skipping excluded regions
/// and inserting BMFF v2 offset values at marker positions.
///
/// Used by the BMFF and RIFF fast-sign modules to compute the content hash
/// simultaneously with writing the output stream.
pub(crate) struct StreamingHasher {
    hasher: DynHasher,
    pub(crate) actions: Vec<HashAction>,
    action_idx: usize,
    output_offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum HashAction {
    /// Hash file bytes in range [start, end] inclusive.
    HashRange { start: u64, end: u64 },
    /// Hash the big-endian u64 offset value (not file content) at this position.
    BmffOffset { position: u64, value: u64 },
}

impl StreamingHasher {
    /// Create a new streaming hasher for a file of `output_size` bytes, with
    /// the given exclusion ranges. Exclusions may include BMFF v2 offset markers.
    /// `alg` selects the hash algorithm: "sha256", "sha384", or "sha512".
    pub(crate) fn new(alg: &str, output_size: u64, exclusions: Vec<HashRange>) -> Result<Self> {
        let mut real_exclusions: Vec<(u64, u64)> = Vec::new();
        let mut bmff_offsets: Vec<(u64, u64)> = Vec::new();

        for exc in &exclusions {
            if let Some(offset_val) = exc.bmff_offset() {
                bmff_offsets.push((exc.start(), offset_val));
            } else {
                real_exclusions.push((exc.start(), exc.length()));
            }
        }

        real_exclusions.sort_by_key(|e| e.0);

        debug_assert!(
            real_exclusions.windows(2).all(|w| w[0].0 + w[0].1 <= w[1].0),
            "StreamingHasher: exclusion ranges must not overlap"
        );

        bmff_offsets.sort_by_key(|o| o.0);

        // Build inclusion ranges by inverting exclusions
        if output_size == 0 {
            return Ok(StreamingHasher {
                hasher: DynHasher::new(alg)?,
                actions: Vec::new(),
                action_idx: 0,
                output_offset: 0,
            });
        }
        let data_end = output_size - 1;
        let mut inclusions: Vec<(u64, u64)> = Vec::new();
        let mut pos = 0u64;
        for (exc_start, exc_len) in &real_exclusions {
            if *exc_start > pos {
                inclusions.push((pos, *exc_start - 1));
            }
            pos = *exc_start + *exc_len;
        }
        if pos <= data_end {
            inclusions.push((pos, data_end));
        }

        // Split inclusion ranges at bmff_offset positions
        let mut actions: Vec<HashAction> = Vec::new();
        for (inc_start, inc_end) in &inclusions {
            let mut current_start = *inc_start;
            for (bmff_pos, bmff_val) in &bmff_offsets {
                if *bmff_pos >= current_start && *bmff_pos <= *inc_end {
                    if *bmff_pos > current_start {
                        actions.push(HashAction::HashRange {
                            start: current_start,
                            end: *bmff_pos - 1,
                        });
                    }
                    actions.push(HashAction::BmffOffset {
                        position: *bmff_pos,
                        value: *bmff_val,
                    });
                    current_start = *bmff_pos;
                }
            }
            if current_start <= *inc_end {
                actions.push(HashAction::HashRange {
                    start: current_start,
                    end: *inc_end,
                });
            }
        }

        Ok(StreamingHasher {
            hasher: DynHasher::new(alg)?,
            actions,
            action_idx: 0,
            output_offset: 0,
        })
    }

    /// Create a simple streaming hasher from start/end exclusion pairs
    /// (no BMFF offset markers). Used by the RIFF fast-sign module.
    /// `alg` selects the hash algorithm: "sha256", "sha384", or "sha512".
    pub(crate) fn from_exclusion_pairs(alg: &str, exclusion_pairs: Vec<(u64, u64)>) -> Result<Self> {
        let mut excl = exclusion_pairs;
        excl.sort_by_key(|&(start, _)| start);

        // Convert (start, end) pairs to HashAction::HashRange by building
        // inclusion ranges from the gaps between exclusions.
        // We don't know the total output size upfront, so we use u64::MAX
        // as a sentinel for the last inclusion range.
        let mut actions: Vec<HashAction> = Vec::new();
        let mut pos = 0u64;
        for (exc_start, exc_end) in &excl {
            if *exc_start > pos {
                actions.push(HashAction::HashRange {
                    start: pos,
                    end: *exc_start - 1,
                });
            }
            pos = *exc_end;
        }
        // sentinel: hash to end-of-stream
        actions.push(HashAction::HashRange {
            start: pos,
            end: u64::MAX,
        });

        Ok(StreamingHasher {
            hasher: DynHasher::new(alg)?,
            actions,
            action_idx: 0,
            output_offset: 0,
        })
    }

    /// Feed bytes at the current output offset to the hasher.
    pub(crate) fn feed(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let data_start = self.output_offset;
        let data_end = self.output_offset + data.len() as u64; // exclusive

        while self.action_idx < self.actions.len() {
            let action = &self.actions[self.action_idx];
            match action {
                HashAction::BmffOffset { position, value } => {
                    if *position >= data_end {
                        break;
                    }
                    if *position >= data_start {
                        self.hasher.update(&value.to_be_bytes());
                    }
                    self.action_idx += 1;
                }
                HashAction::HashRange { start, end } => {
                    if *start >= data_end {
                        break;
                    }
                    let overlap_start = std::cmp::max(data_start, *start);
                    let overlap_end = std::cmp::min(data_end - 1, *end);
                    if overlap_start <= overlap_end {
                        let buf_start = (overlap_start - data_start) as usize;
                        let buf_end = (overlap_end - data_start + 1) as usize;
                        self.hasher.update(&data[buf_start..buf_end]);
                    }
                    if *end < data_end {
                        self.action_idx += 1;
                    } else {
                        break;
                    }
                }
            }
        }
        self.output_offset += data.len() as u64;
    }

    /// Finalize the hash computation, returning the digest.
    pub(crate) fn finalize(self) -> Vec<u8> {
        self.hasher.finalize()
    }
}

// --- Source Patch -----------------------------------------------------------

/// A byte-level patch to apply during the streaming copy. Positions are in the
/// SOURCE file. During the copy pass, when we copy bytes that include these
/// positions, we modify the value in the buffer before writing and hashing.
#[derive(Debug, Clone)]
pub(crate) struct SourcePatch {
    /// Byte offset in the SOURCE file where the value lives.
    pub(crate) source_offset: u64,
    /// Size of the field (4 or 8 bytes).
    pub(crate) field_size: u8,
    /// The signed adjustment to add to the current big-endian integer value.
    pub(crate) adjust: i64,
}

/// Copy a range from source to dest, applying byte-level offset patches
/// in-flight. Feeds the bytes (with patches applied) to the hasher.
///
/// Patches must be sorted by `source_offset`. Uses a sliding window
/// (`patch_start_idx`) so each chunk only inspects the patches that could
/// overlap it -- O(total_patches) across all chunks.
pub(crate) fn copy_with_patches<R: Read + Seek, W: Write>(
    source: &mut R,
    dest: &mut W,
    hasher: &mut StreamingHasher,
    src_offset: u64,
    length: u64,
    patches: &[SourcePatch],
) -> Result<()> {
    source.seek(SeekFrom::Start(src_offset))?;

    let mut buf = vec![0u8; COPY_BUF_SIZE];
    let mut remaining = length;
    let mut current_src = src_offset;

    let mut patch_start_idx: usize = 0;

    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, buf.len());
        source.read_exact(&mut buf[..to_read])?;

        let chunk_start = current_src;
        let chunk_end = current_src + to_read as u64;

        // Advance past patches that end before this chunk.
        while patch_start_idx < patches.len() {
            let p = &patches[patch_start_idx];
            if p.source_offset + p.field_size as u64 <= chunk_start {
                patch_start_idx += 1;
            } else {
                break;
            }
        }

        let mut pi = patch_start_idx;
        while pi < patches.len() {
            let patch = &patches[pi];
            let p_start = patch.source_offset;

            if p_start >= chunk_end {
                break;
            }

            let p_end = p_start + patch.field_size as u64;

            if p_end <= chunk_start {
                pi += 1;
                continue;
            }

            // The patch field must be entirely within this chunk.
            if p_start < chunk_start || p_end > chunk_end {
                log::error!(
                    "[c2pa-fast-sign-common] patch at offset {} (size {}) spans chunk boundary [{}, {})",
                    p_start, patch.field_size, chunk_start, chunk_end
                );
                return Err(Error::InvalidAsset(
                    "patch spans chunk boundary".to_string(),
                ));
            }

            let buf_offset = (p_start - chunk_start) as usize;
            match patch.field_size {
                4 => {
                    let val = u32::from_be_bytes([
                        buf[buf_offset],
                        buf[buf_offset + 1],
                        buf[buf_offset + 2],
                        buf[buf_offset + 3],
                    ]);
                    let adjusted = val as i64 + patch.adjust;
                    let new_val = u32::try_from(adjusted).map_err(|_| {
                        Error::InvalidAsset("offset patch overflow".to_string())
                    })?;
                    buf[buf_offset..buf_offset + 4]
                        .copy_from_slice(&new_val.to_be_bytes());
                }
                8 => {
                    let val = u64::from_be_bytes([
                        buf[buf_offset],
                        buf[buf_offset + 1],
                        buf[buf_offset + 2],
                        buf[buf_offset + 3],
                        buf[buf_offset + 4],
                        buf[buf_offset + 5],
                        buf[buf_offset + 6],
                        buf[buf_offset + 7],
                    ]);
                    let adjusted = val as i128 + patch.adjust as i128;
                    let new_val = u64::try_from(adjusted).map_err(|_| {
                        Error::InvalidAsset("offset patch overflow".to_string())
                    })?;
                    buf[buf_offset..buf_offset + 8]
                        .copy_from_slice(&new_val.to_be_bytes());
                }
                _ => {
                    return Err(Error::InvalidAsset(format!(
                        "unexpected patch field_size: {}",
                        patch.field_size
                    )));
                }
            }
            pi += 1;
        }

        hasher.feed(&buf[..to_read]);
        dest.write_all(&buf[..to_read])?;
        remaining -= to_read as u64;
        current_src += to_read as u64;
    }

    Ok(())
}

/// Return the hash digest size for the given algorithm name.
pub(crate) fn placeholder_hash_size(alg: &str) -> Result<usize> {
    match alg {
        "sha256" => Ok(32),
        "sha384" => Ok(48),
        "sha512" => Ok(64),
        _ => Err(Error::UnsupportedType),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hash_utils::HashRange;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_streaming_hasher_no_exclusions() {
        let data: Vec<u8> = (0..=255).collect();
        let mut hasher = StreamingHasher::new("sha256", data.len() as u64, vec![]).unwrap();
        hasher.feed(&data);
        let result = hasher.finalize();

        let expected = Sha256::digest(&data).to_vec();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_streaming_hasher_no_exclusions_chunked() {
        let data: Vec<u8> = (0..200).map(|i| (i % 256) as u8).collect();
        let mut hasher = StreamingHasher::new("sha256", data.len() as u64, vec![]).unwrap();
        for chunk in data.chunks(17) {
            hasher.feed(chunk);
        }
        let result = hasher.finalize();

        let expected = Sha256::digest(&data).to_vec();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_streaming_hasher_with_exclusions() {
        let data: Vec<u8> = (0..100).collect();
        let exclusions = vec![
            HashRange::new(10, 10),
            HashRange::new(50, 10),
        ];
        let mut hasher = StreamingHasher::new("sha256", 100, exclusions).unwrap();
        hasher.feed(&data);
        let result = hasher.finalize();

        let mut manual_hasher = Sha256::new();
        manual_hasher.update(&data[0..10]);
        manual_hasher.update(&data[20..50]);
        manual_hasher.update(&data[60..100]);
        let expected = manual_hasher.finalize().to_vec();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_streaming_hasher_with_exclusions_chunked() {
        let data: Vec<u8> = (0..100).collect();
        let exclusions = vec![
            HashRange::new(10, 10),
            HashRange::new(50, 10),
        ];
        let mut hasher = StreamingHasher::new("sha256", 100, exclusions).unwrap();
        for chunk in data.chunks(7) {
            hasher.feed(chunk);
        }
        let result = hasher.finalize();

        let mut manual_hasher = Sha256::new();
        manual_hasher.update(&data[0..10]);
        manual_hasher.update(&data[20..50]);
        manual_hasher.update(&data[60..100]);
        let expected = manual_hasher.finalize().to_vec();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_streaming_hasher_bmff_offsets() {
        let data: Vec<u8> = (0..50).collect();

        let mut bmff_marker = HashRange::new(20, 1);
        bmff_marker.set_bmff_offset(0x1234);

        let exclusions = vec![bmff_marker];
        let mut hasher = StreamingHasher::new("sha256", 50, exclusions).unwrap();
        hasher.feed(&data);
        let result = hasher.finalize();

        let mut manual_hasher = Sha256::new();
        manual_hasher.update(&data[0..20]);
        manual_hasher.update(&0x1234u64.to_be_bytes());
        manual_hasher.update(&data[20..50]);
        let expected = manual_hasher.finalize().to_vec();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_streaming_hasher_from_exclusion_pairs() {
        // "hello world" but exclude "lo wo" (bytes 3..8)
        let mut hasher = StreamingHasher::from_exclusion_pairs("sha256", vec![(3, 8)]).unwrap();
        hasher.feed(b"hello world");
        let hash = hasher.finalize();

        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"hel");
        expected_hasher.update(b"rld");
        let expected = expected_hasher.finalize().to_vec();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_placeholder_hash_size() {
        assert_eq!(placeholder_hash_size("sha256").unwrap(), 32);
        assert_eq!(placeholder_hash_size("sha384").unwrap(), 48);
        assert_eq!(placeholder_hash_size("sha512").unwrap(), 64);
        assert!(placeholder_hash_size("unknown").is_err());
    }

    #[test]
    fn test_copy_with_patches_single_u32_patch() {
        // Source data: 16 bytes with a known u32 at offset 4
        let source_data: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x03, // bytes 0-3
            0x00, 0x00, 0x00, 0x0A, // bytes 4-7: u32 big-endian = 10
            0x08, 0x09, 0x0A, 0x0B, // bytes 8-11
            0x0C, 0x0D, 0x0E, 0x0F, // bytes 12-15
        ];
        let mut source = std::io::Cursor::new(&source_data);
        let mut dest = Vec::new();
        let mut hasher = StreamingHasher::new("sha256", 16, vec![]).unwrap();

        let patches = vec![SourcePatch {
            source_offset: 4,
            field_size: 4,
            adjust: 5, // 10 + 5 = 15
        }];

        copy_with_patches(&mut source, &mut dest, &mut hasher, 0, 16, &patches).unwrap();

        // Check that the patch was applied
        let patched_val = u32::from_be_bytes([dest[4], dest[5], dest[6], dest[7]]);
        assert_eq!(patched_val, 15);

        // Non-patched bytes should be unchanged
        assert_eq!(&dest[0..4], &source_data[0..4]);
        assert_eq!(&dest[8..16], &source_data[8..16]);
    }

    #[test]
    fn test_copy_with_patches_no_patches() {
        let source_data: Vec<u8> = (0..64).collect();
        let mut source = std::io::Cursor::new(&source_data);
        let mut dest = Vec::new();
        let mut hasher = StreamingHasher::new("sha256", 64, vec![]).unwrap();

        copy_with_patches(&mut source, &mut dest, &mut hasher, 0, 64, &[]).unwrap();

        // Output should be identical to source
        assert_eq!(dest, source_data);
    }

    #[test]
    fn test_copy_with_patches_u64_happy_path() {
        // Source data: 16 bytes with a known u64 at offset 0
        let source_data: Vec<u8> = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, // u64 big-endian = 10
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let mut source = std::io::Cursor::new(&source_data);
        let mut dest = Vec::new();
        let mut hasher = StreamingHasher::new("sha256", 16, vec![]).unwrap();

        let patches = vec![SourcePatch {
            source_offset: 0,
            field_size: 8,
            adjust: 100,
        }];

        copy_with_patches(&mut source, &mut dest, &mut hasher, 0, 16, &patches).unwrap();

        let patched_val = u64::from_be_bytes(dest[0..8].try_into().unwrap());
        assert_eq!(patched_val, 110);
    }

    #[test]
    fn test_copy_with_patches_overflow_u32() {
        let val = u32::MAX - 1;
        let mut source_data = vec![0u8; 8];
        source_data[0..4].copy_from_slice(&val.to_be_bytes());
        let mut source = std::io::Cursor::new(&source_data);
        let mut dest = Vec::new();
        let mut hasher = StreamingHasher::new("sha256", 8, vec![]).unwrap();

        let patches = vec![SourcePatch {
            source_offset: 0,
            field_size: 4,
            adjust: 10, // would overflow u32
        }];

        let result = copy_with_patches(&mut source, &mut dest, &mut hasher, 0, 8, &patches);
        assert!(result.is_err(), "Expected overflow error for u32 patch");
    }

    #[test]
    fn test_copy_with_patches_overflow_u64() {
        let val = u64::MAX - 1;
        let mut source_data = vec![0u8; 16];
        source_data[0..8].copy_from_slice(&val.to_be_bytes());
        let mut source = std::io::Cursor::new(&source_data);
        let mut dest = Vec::new();
        let mut hasher = StreamingHasher::new("sha256", 16, vec![]).unwrap();

        let patches = vec![SourcePatch {
            source_offset: 0,
            field_size: 8,
            adjust: 10, // would overflow u64
        }];

        let result = copy_with_patches(&mut source, &mut dest, &mut hasher, 0, 16, &patches);
        assert!(result.is_err(), "Expected overflow error for u64 patch");
    }

    #[test]
    fn test_copy_with_patches_unexpected_field_size() {
        let source_data = vec![0u8; 8];
        let mut source = std::io::Cursor::new(&source_data);
        let mut dest = Vec::new();
        let mut hasher = StreamingHasher::new("sha256", 8, vec![]).unwrap();

        let patches = vec![SourcePatch {
            source_offset: 0,
            field_size: 3,
            adjust: 1,
        }];

        let result = copy_with_patches(&mut source, &mut dest, &mut hasher, 0, 8, &patches);
        assert!(result.is_err(), "Expected error for unexpected field_size");
    }

    #[test]
    fn test_copy_with_patches_span_chunk_boundary() {
        // Create source data larger than COPY_BUF_SIZE so the patch would span a boundary.
        // We put a patch at byte COPY_BUF_SIZE - 2 with field_size 4.
        let buf_sz = COPY_BUF_SIZE;
        let source_data = vec![0u8; buf_sz + 16];
        let mut source = std::io::Cursor::new(&source_data);
        let mut dest = Vec::new();
        let mut hasher = StreamingHasher::new("sha256", source_data.len() as u64, vec![]).unwrap();

        let patches = vec![SourcePatch {
            source_offset: (buf_sz - 2) as u64,
            field_size: 4,
            adjust: 1,
        }];

        let result = copy_with_patches(
            &mut source,
            &mut dest,
            &mut hasher,
            0,
            source_data.len() as u64,
            &patches,
        );
        assert!(
            result.is_err(),
            "Expected error for patch spanning chunk boundary"
        );
    }
}
