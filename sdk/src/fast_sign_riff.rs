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

//! Single-pass fast signer for RIFF-based formats (WAV, WebP, AVI).
//!
//! Achieves significant speedup over the standard multi-pass flow by:
//! 1. Parsing container structure (headers only, no data reads)
//! 2. Pre-computing output layout (where C2PA chunk goes, what shifts)
//! 3. Streaming source->dest in ONE pass, applying patches in-flight,
//!    computing SHA-256 hash over non-excluded regions simultaneously
//! 4. Seek-patching the signed JUMBF at the end

use std::io::{Read, Seek, SeekFrom, Write};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::{
    assertions::DataHash,
    error::{Error, Result},
    fast_sign_common::{placeholder_hash_size, StreamingHasher, COPY_BUF_SIZE, JUMBF_MANIFEST_NAME, PLACEHOLDER_OFFSET},
    store::Store,
    utils::{hash_utils::HashRange, patch::patch_bytes},
    Builder, Signer,
};

/// Four-byte chunk identifier.
type FourCC = [u8; 4];

const RIFF_ID: FourCC = *b"RIFF";
const LIST_ID: FourCC = *b"LIST";
const C2PA_ID: FourCC = *b"C2PA";

/// Maximum nesting depth for RIFF chunk parsing to prevent stack overflow.
const MAX_CHUNK_DEPTH: usize = 32;

/// Parsed RIFF chunk header -- position and size only, no data.
#[derive(Debug, Clone)]
struct ChunkInfo {
    /// FourCC identifier
    id: FourCC,
    /// Offset of the chunk in the source stream (points to the FourCC)
    offset: u64,
    /// Data size as declared in the chunk header (excludes 8-byte header)
    data_size: u32,
    /// For RIFF/LIST containers: the form type (4 bytes after size)
    form_type: Option<FourCC>,
    /// Child chunks (only for RIFF/LIST containers)
    children: Vec<ChunkInfo>,
}

impl ChunkInfo {
    /// Total size of this chunk on disk, including the 8-byte header.
    /// RIFF chunks are padded to even boundaries.
    fn total_size(&self) -> u64 {
        let raw = 8 + self.data_size as u64;
        if raw % 2 != 0 {
            raw + 1
        } else {
            raw
        }
    }
}

/// Parse the top-level RIFF chunk structure from a stream.
/// Only reads headers; does not read chunk payload data.
fn parse_riff_structure<R: Read + Seek>(reader: &mut R) -> Result<Vec<ChunkInfo>> {
    reader.rewind()?;
    let file_len = reader.seek(SeekFrom::End(0))?;
    reader.rewind()?;

    let mut chunks = Vec::new();
    while reader.stream_position()? < file_len {
        if let Some(chunk) = parse_chunk(reader, file_len, 0)? {
            chunks.push(chunk);
        } else {
            break;
        }
    }
    Ok(chunks)
}

/// Parse a single chunk at the current stream position.
fn parse_chunk<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    depth: usize,
) -> Result<Option<ChunkInfo>> {
    if depth > MAX_CHUNK_DEPTH {
        return Err(Error::InvalidAsset(
            "RIFF chunk nesting too deep".to_string(),
        ));
    }

    let offset = reader.stream_position()?;
    if offset + 8 > file_len {
        return Ok(None);
    }

    let mut id = [0u8; 4];
    if reader.read_exact(&mut id).is_err() {
        return Ok(None);
    }

    let data_size = match reader.read_u32::<LittleEndian>() {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    let is_container = id == RIFF_ID || id == LIST_ID;

    let mut form_type = None;
    let mut children = Vec::new();

    if is_container && data_size >= 4 {
        let mut ft = [0u8; 4];
        reader.read_exact(&mut ft)?;
        form_type = Some(ft);

        let container_end = offset + 8 + data_size as u64;
        let bounded_end = container_end.min(file_len);

        while reader.stream_position()? + 8 <= bounded_end {
            if let Some(child) = parse_chunk(reader, bounded_end, depth + 1)? {
                children.push(child);
            } else {
                break;
            }
        }

        let padded_end = if (offset + 8 + data_size as u64) % 2 != 0 {
            offset + 8 + data_size as u64 + 1
        } else {
            offset + 8 + data_size as u64
        };
        let seek_to = padded_end.min(file_len);
        reader.seek(SeekFrom::Start(seek_to))?;
    } else {
        let padded_size = if data_size % 2 != 0 {
            data_size as u64 + 1
        } else {
            data_size as u64
        };
        let skip_to = (offset + 8 + padded_size).min(file_len);
        reader.seek(SeekFrom::Start(skip_to))?;
    }

    Ok(Some(ChunkInfo {
        id,
        offset,
        data_size,
        form_type,
        children,
    }))
}

/// A segment of the RIFF output stream.
#[derive(Debug)]
enum RiffOutputSegment {
    /// Copy bytes from source at (source_offset, length)
    CopyFromSource { src_offset: u64, length: u64 },
    /// Write literal bytes (e.g., patched headers, C2PA chunk)
    Literal(Vec<u8>),
}

/// Describes the complete RIFF output layout.
struct RiffOutputPlan {
    segments: Vec<RiffOutputSegment>,
    /// Position of the C2PA chunk data in the output (after the 8-byte chunk header)
    c2pa_data_offset: u64,
    /// Position of the C2PA chunk (including header) in the output
    c2pa_chunk_offset: u64,
    /// Total length of the C2PA chunk including header
    c2pa_chunk_total_len: u64,
}

/// Build the output plan for inserting/replacing a C2PA chunk.
///
/// Strategy: The C2PA chunk is appended as the last child of the first RIFF chunk,
/// matching the behavior of `inject_c2pa` in `riff_io.rs`.
fn build_output_plan(
    chunks: &[ChunkInfo],
    c2pa_data: &[u8],
) -> Result<RiffOutputPlan> {
    if chunks.is_empty() {
        return Err(Error::InvalidAsset("No RIFF chunks found".to_string()));
    }

    let riff_chunk = &chunks[0];
    if riff_chunk.id != RIFF_ID {
        return Err(Error::InvalidAsset(
            "First chunk is not RIFF".to_string(),
        ));
    }

    let c2pa_data_len = u32::try_from(c2pa_data.len())
        .map_err(|_| Error::InvalidAsset("JUMBF too large for RIFF".to_string()))?;
    let c2pa_chunk_total = 8 + c2pa_data_len as u64;
    let c2pa_chunk_padded = if c2pa_chunk_total % 2 != 0 {
        c2pa_chunk_total + 1
    } else {
        c2pa_chunk_total
    };

    let form_type_bytes = 4u64;

    let mut segments = Vec::new();
    let mut out_pos: u64 = 0;

    let mut new_riff_data_size: u64 = form_type_bytes;
    for child in &riff_chunk.children {
        if child.id != C2PA_ID {
            new_riff_data_size += child.total_size();
        }
    }
    new_riff_data_size += c2pa_chunk_padded;

    // Emit the RIFF header with updated size
    let mut riff_header = Vec::with_capacity(12);
    riff_header.extend_from_slice(&RIFF_ID);
    let riff_size_u32 = u32::try_from(new_riff_data_size)
        .map_err(|_| Error::InvalidAsset("RIFF too large".to_string()))?;
    riff_header.extend_from_slice(&riff_size_u32.to_le_bytes());
    riff_header.extend_from_slice(riff_chunk.form_type.as_ref().unwrap_or(&[0u8; 4]));
    segments.push(RiffOutputSegment::Literal(riff_header));
    out_pos += 12;

    // Copy each non-C2PA child from source
    for child in &riff_chunk.children {
        if child.id == C2PA_ID {
            continue;
        }
        let child_total = child.total_size();
        segments.push(RiffOutputSegment::CopyFromSource {
            src_offset: child.offset,
            length: child_total,
        });
        out_pos += child_total;
    }

    // Append the C2PA chunk
    let c2pa_chunk_offset = out_pos;
    let mut c2pa_header = Vec::with_capacity(8);
    c2pa_header.extend_from_slice(&C2PA_ID);
    c2pa_header.extend_from_slice(&c2pa_data_len.to_le_bytes());
    segments.push(RiffOutputSegment::Literal(c2pa_header));
    out_pos += 8;

    let c2pa_data_offset = out_pos;
    segments.push(RiffOutputSegment::Literal(c2pa_data.to_vec()));
    out_pos += c2pa_data_len as u64;

    // Add padding byte if needed
    if c2pa_data_len % 2 != 0 {
        segments.push(RiffOutputSegment::Literal(vec![0u8]));
        out_pos += 1;
    }

    // Copy any additional RIFF/AVIX chunks (for large AVI files)
    for chunk in chunks.iter().skip(1) {
        let chunk_total = chunk.total_size();
        segments.push(RiffOutputSegment::CopyFromSource {
            src_offset: chunk.offset,
            length: chunk_total,
        });
        out_pos += chunk_total;
    }

    Ok(RiffOutputPlan {
        segments,
        c2pa_data_offset,
        c2pa_chunk_offset,
        c2pa_chunk_total_len: c2pa_chunk_padded,
    })
}

/// Execute the output plan: stream source to dest, computing hash simultaneously.
fn execute_plan<R, W>(
    plan: &RiffOutputPlan,
    source: &mut R,
    dest: &mut W,
    hasher: &mut StreamingHasher,
) -> Result<()>
where
    R: Read + Seek,
    W: Write,
{
    let mut buf = vec![0u8; COPY_BUF_SIZE];

    for segment in &plan.segments {
        match segment {
            RiffOutputSegment::Literal(data) => {
                dest.write_all(data)?;
                hasher.feed(data);
            }
            RiffOutputSegment::CopyFromSource { src_offset, length } => {
                source.seek(SeekFrom::Start(*src_offset))?;
                let mut remaining = *length;
                while remaining > 0 {
                    let to_read = remaining.min(COPY_BUF_SIZE as u64) as usize;
                    source.read_exact(&mut buf[..to_read])?;
                    dest.write_all(&buf[..to_read])?;
                    hasher.feed(&buf[..to_read]);
                    remaining -= to_read as u64;
                }
            }
        }
    }

    Ok(())
}

/// Sign a RIFF-based asset (WAV, WebP, AVI) using the fast single-pass method.
///
/// This function performs the complete signing workflow:
/// 1. Parse RIFF structure (headers only)
/// 2. Build a preliminary JUMBF with placeholder signature and hash
/// 3. Pre-compute output layout
/// 4. Stream source->dest in one pass, computing SHA-256 simultaneously
/// 5. Update hash in JUMBF, sign, seek-patch the final JUMBF
pub fn sign_riff_fast<R, W>(
    builder: &mut Builder,
    signer: &dyn Signer,
    format: &str,
    source: &mut R,
    dest: &mut W,
) -> Result<Vec<u8>>
where
    R: Read + Seek + Send,
    W: Write + Read + Seek + Send,
{
    let start = std::time::Instant::now();
    let settings = crate::settings::Settings::default();
    let reserve_size = signer.reserve_size();

    // --- Phase 0: Build Store ---
    let mime_format = crate::utils::mime::format_to_mime(format);
    builder.definition.format.clone_from(&mime_format);
    if !builder.deterministic {
        builder.definition.instance_id = format!("xmp:iid:{}", uuid::Uuid::new_v4());
    }
    let deterministic = builder.deterministic;

    let mut store = builder.to_store()?;

    // --- Phase 1: Parse RIFF structure ---
    source.rewind()?;
    let chunks = parse_riff_structure(source)?;

    // --- Phase 2: Create placeholder JUMBF ---
    let alg = {
        let pc = store.provenance_claim().ok_or(Error::ClaimEncoding)?;
        pc.alg().to_string()
    };
    let hash_size = placeholder_hash_size(&alg)?;

    {
        let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        let mut dh = DataHash::new(JUMBF_MANIFEST_NAME, &alg);
        dh.set_hash(vec![0u8; hash_size]);
        dh.add_exclusion(HashRange::new(PLACEHOLDER_OFFSET, PLACEHOLDER_OFFSET));
        if deterministic {
            pc.add_assertion_with_salt(&dh, &crate::salt::NoSalt)?;
        } else {
            pc.add_assertion(&dh)?;
        }
    }

    let initial_jumbf = store.to_jumbf_internal(reserve_size)?;
    let initial_jumbf_size = initial_jumbf.len();
    log::debug!("[c2pa-fast-sign-riff] initial JUMBF size={}", initial_jumbf_size);

    // --- Phase 3: Compute output layout and update exclusion with real values ---
    let plan = build_output_plan(&chunks, &initial_jumbf)?;

    {
        let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        let mut dh = DataHash::new(JUMBF_MANIFEST_NAME, &alg);
        dh.set_hash(vec![0u8; hash_size]);
        dh.add_exclusion(HashRange::new(
            plan.c2pa_chunk_offset,
            plan.c2pa_chunk_total_len,
        ));
        pc.update_data_hash(dh)?;
    }

    // Regenerate JUMBF with real exclusion values
    let placeholder_jumbf = store.to_jumbf_internal(reserve_size)?;
    let jumbf_size = placeholder_jumbf.len();

    // If the size changed (unlikely with 0xFFFF_FFFF seeding), recompute once
    let (plan, _placeholder_jumbf, jumbf_size) = if jumbf_size != initial_jumbf_size {
        log::debug!(
            "[c2pa-fast-sign-riff] JUMBF size changed {} -> {}, recomputing",
            initial_jumbf_size,
            jumbf_size
        );
        let plan2 = build_output_plan(&chunks, &placeholder_jumbf)?;

        {
            let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
            let mut dh = DataHash::new(JUMBF_MANIFEST_NAME, &alg);
            dh.set_hash(vec![0u8; hash_size]);
            dh.add_exclusion(HashRange::new(
                plan2.c2pa_chunk_offset,
                plan2.c2pa_chunk_total_len,
            ));
            pc.update_data_hash(dh)?;
        }

        let pj = store.to_jumbf_internal(reserve_size)?;
        let js = pj.len();
        if js != jumbf_size {
            log::error!(
                "[c2pa-fast-sign-riff] JUMBF size mismatch after recompute: expected {}, got {}",
                jumbf_size,
                js
            );
            return Err(Error::JumbfCreationError);
        }
        (plan2, pj, js)
    } else {
        (plan, placeholder_jumbf, jumbf_size)
    };

    // --- Phase 4: Single-pass stream with simultaneous hashing ---
    let exclusions = vec![(
        plan.c2pa_chunk_offset,
        plan.c2pa_chunk_offset + plan.c2pa_chunk_total_len,
    )];
    let mut hasher = StreamingHasher::from_exclusion_pairs(&alg, exclusions)?;

    dest.rewind()?;
    execute_plan(&plan, source, dest, &mut hasher)?;
    dest.flush()?;

    let hash = hasher.finalize();

    // --- Phase 5: Update hash in claim, regenerate JUMBF ---
    {
        let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        let mut final_dh = DataHash::new(JUMBF_MANIFEST_NAME, &alg);
        final_dh.add_exclusion(HashRange::new(
            plan.c2pa_chunk_offset,
            plan.c2pa_chunk_total_len,
        ));
        final_dh.set_hash(hash);
        pc.update_data_hash(final_dh)?;
    }

    let mut jumbf_bytes = store.to_jumbf_internal(reserve_size)?;
    if jumbf_bytes.len() != jumbf_size {
        log::error!(
            "[c2pa-fast-sign-riff] JUMBF size mismatch: expected {}, got {}",
            jumbf_size,
            jumbf_bytes.len()
        );
        return Err(Error::JumbfCreationError);
    }

    // --- Phase 6: Sign and patch ---
    let (sig, sig_placeholder) = {
        let pc = store.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let s = store.sign_claim(pc, signer, reserve_size, &settings)?;
        let sp = Store::sign_claim_placeholder(pc, reserve_size);
        (s, sp)
    };

    if sig.len() != sig_placeholder.len() {
        return Err(Error::CoseSigboxTooSmall);
    }

    patch_bytes(&mut jumbf_bytes, &sig_placeholder, &sig)
        .map_err(|_| Error::JumbfCreationError)?;

    // Seek-patch the C2PA data in the output
    dest.seek(SeekFrom::Start(plan.c2pa_data_offset))?;
    dest.write_all(&jumbf_bytes)?;
    dest.flush()?;

    log::debug!(
        "[c2pa-fast-sign-riff] total: {}ms, format={}, jumbf_size={}",
        start.elapsed().as_millis(),
        format,
        jumbf_size
    );

    Ok(jumbf_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_riff_wav() {
        let fixture = crate::utils::test::fixture_path("sample1.wav");
        let mut f = std::fs::File::open(fixture).unwrap();
        let chunks = parse_riff_structure(&mut f).unwrap();

        assert!(!chunks.is_empty());
        assert_eq!(&chunks[0].id, b"RIFF");
        assert!(chunks[0].form_type.is_some());
    }

    #[test]
    fn test_parse_riff_webp() {
        let fixture = crate::utils::test::fixture_path("test.webp");
        let mut f = std::fs::File::open(fixture).unwrap();
        let chunks = parse_riff_structure(&mut f).unwrap();

        assert!(!chunks.is_empty());
        assert_eq!(&chunks[0].id, b"RIFF");
    }

    #[test]
    fn test_parse_riff_avi() {
        let fixture = crate::utils::test::fixture_path("test.avi");
        let mut f = std::fs::File::open(fixture).unwrap();
        let chunks = parse_riff_structure(&mut f).unwrap();

        assert!(!chunks.is_empty());
        assert_eq!(&chunks[0].id, b"RIFF");
    }

    #[test]
    fn test_output_plan_basic() {
        let fixture = crate::utils::test::fixture_path("sample1.wav");
        let mut f = std::fs::File::open(fixture).unwrap();
        let chunks = parse_riff_structure(&mut f).unwrap();

        let dummy_data = vec![0u8; 100];
        let plan = build_output_plan(&chunks, &dummy_data).unwrap();

        assert!(plan.c2pa_chunk_offset > 0);
        assert!(plan.c2pa_data_offset == plan.c2pa_chunk_offset + 8);
    }
}
