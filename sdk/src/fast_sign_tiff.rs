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
// Single-pass TIFF/DNG C2PA signing.
//
// Strategy: append-only. We copy the entire source file to the output,
// then append the JUMBF data. We either:
//   (a) Update an existing C2PA IFD entry's count + data offset, or
//   (b) Create a new single-entry IFD (tag 0xCD41) at the end and
//       chain the last IFD's next-pointer to it.
//
// This avoids re-laying-out strip/tile offsets entirely.
//
// Steps:
//   1. Parse source TIFF structure (IFDs only)
//   2. Build Store with DataHash placeholder (with exclusion ranges)
//   3. Pre-compute output layout
//   4. Write output in one pass: source bytes + appended IFD + JUMBF
//   5. Compute SHA-256 hash over the output with exclusions
//   6. Update hash, re-sign, seek-patch JUMBF

use std::io::{Read, Seek, SeekFrom, Write};

use byteordered::{ByteOrdered, Endianness};
use uuid::Uuid;

use crate::{
    assertions::DataHash,
    asset_handlers::tiff_io::{self, IfdType, TiffStructure},
    error::{Error, Result},
    fast_sign_common::{placeholder_hash_size, COPY_BUF_SIZE, JUMBF_MANIFEST_NAME, PLACEHOLDER_OFFSET},
    store::Store,
    utils::{
        hash_utils::HashRange,
        io_utils::stream_len,
        mime::format_to_mime,
        patch::patch_bytes,
    },
    Builder, Signer,
};

const C2PA_TAG: u16 = 0xcd41;
const C2PA_FIELD_TYPE: u16 = 7; // UNDEFINED

/// Maximum number of IFDs to traverse before assuming a circular chain.
const MAX_IFD_COUNT: usize = 10_000;

static TIFF_TYPES: &[&str] = &[
    "tif",
    "tiff",
    "image/tiff",
    "dng",
    "image/dng",
    "image/x-adobe-dng",
];

fn is_tiff_format(format: &str) -> bool {
    TIFF_TYPES.contains(&format)
}

/// Information about the C2PA IFD/entry in the source file.
struct ExistingC2pa {
    /// File offset of the C2PA IFD (the IFD that contains only the C2PA tag).
    _ifd_offset: u64,
    /// Byte offset (decoded, in native order) of the C2PA data in the source.
    _data_offset: u64,
    /// Size of the existing C2PA data.
    _data_size: u64,
    /// File offset of the "next IFD" pointer in the *previous* IFD that points
    /// to the C2PA IFD. We patch this if we need to rewrite the chain.
    _prev_next_ptr_offset: u64,
}

/// Parsed TIFF header info we need for writing.
struct TiffHeader {
    endianness: Endianness,
    big_tiff: bool,
    /// File offset where the "first IFD offset" field lives in the header.
    first_ifd_ptr_offset: u64,
}

/// Pre-computed output layout.
struct OutputLayout {
    /// The source file is copied verbatim up to `source_copy_len` bytes.
    source_copy_len: u64,
    /// Absolute offset in output where the C2PA IFD starts.
    c2pa_ifd_offset: u64,
    /// Absolute offset in output where the JUMBF data starts.
    jumbf_data_offset: u64,
    /// Absolute offset in output where the C2PA count field is.
    count_field_offset: u64,
    /// Size of the count field (4 for regular TIFF, 8 for BigTIFF).
    count_field_size: u64,
    /// File offset of the "next IFD" pointer in the last page IFD that we
    /// need to patch to point to our new C2PA IFD. `None` if we are updating
    /// an existing C2PA IFD in-place.
    patch_next_ifd_ptr: Option<u64>,
    /// The pre-built IFD bytes (entry count + single C2PA entry + next=0).
    ifd_bytes: Vec<u8>,
}

/// Read the TIFF header and return parsed info.
fn read_tiff_header<R: Read + Seek>(reader: &mut R) -> Result<TiffHeader> {
    reader.rewind()?;
    let mut sig = [0u8; 2];
    reader.read_exact(&mut sig)?;
    let endianness = match sig {
        [0x49, 0x49] => Endianness::Little,
        [0x4d, 0x4d] => Endianness::Big,
        _ => return Err(Error::InvalidAsset("Not a TIFF file".to_string())),
    };

    let mut br = ByteOrdered::runtime(reader, endianness);
    let magic = br.read_u16()?;
    let big_tiff = match magic {
        42 => false,
        43 => {
            let offset_size = br.read_u16()?;
            if offset_size != 8 {
                return Err(Error::InvalidAsset("Invalid BigTIFF".to_string()));
            }
            let _reserved = br.read_u16()?;
            true
        }
        _ => return Err(Error::InvalidAsset("Invalid TIFF magic".to_string())),
    };

    let first_ifd_ptr_offset = if big_tiff { 8u64 } else { 4u64 };

    Ok(TiffHeader {
        endianness,
        big_tiff,
        first_ifd_ptr_offset,
    })
}

/// Walk the IFD chain and find the existing C2PA IFD (if any), plus return
/// the last page IFD's "next" pointer location.
fn find_c2pa_and_last_ifd<R: Read + Seek>(
    reader: &mut R,
    header: &TiffHeader,
) -> Result<(Option<ExistingC2pa>, u64)> {
    reader.seek(SeekFrom::Start(header.first_ifd_ptr_offset))?;
    let mut br = ByteOrdered::runtime(&mut *reader, header.endianness);
    let first_ifd_offset = if header.big_tiff {
        br.read_u64()?
    } else {
        br.read_u32()? as u64
    };

    let mut prev_next_ptr_offset = header.first_ifd_ptr_offset;
    let mut current_offset = first_ifd_offset;
    let mut existing_c2pa: Option<ExistingC2pa> = None;
    let mut ifd_count: usize = 0;

    loop {
        ifd_count += 1;
        if ifd_count > MAX_IFD_COUNT {
            return Err(Error::InvalidAsset(
                "IFD chain too long or circular".to_string(),
            ));
        }
        reader.seek(SeekFrom::Start(current_offset))?;
        let ifd = TiffStructure::read_ifd(
            reader,
            header.endianness,
            header.big_tiff,
            IfdType::Page,
        )?;

        // Check if this IFD contains the C2PA tag
        if let Some(c2pa_entry) = ifd.get_tag(C2PA_TAG) {
            let data_offset = tiff_io::decode_offset(
                c2pa_entry.value_offset,
                header.endianness,
                header.big_tiff,
            )?;
            existing_c2pa = Some(ExistingC2pa {
                _ifd_offset: ifd.offset,
                _data_offset: data_offset,
                _data_size: c2pa_entry.value_count,
                _prev_next_ptr_offset: prev_next_ptr_offset,
            });
        }

        let next_ptr_location = ifd.next_idf_offset_location;

        match ifd.next_ifd_offset {
            Some(next_offset) if next_offset != 0 => {
                prev_next_ptr_offset = next_ptr_location;
                current_offset = next_offset;
            }
            _ => {
                return Ok((existing_c2pa, next_ptr_location));
            }
        }
    }
}

/// Build the IFD bytes for a single-entry C2PA IFD.
/// Returns (ifd_bytes, count_field_offset_within_ifd).
fn build_c2pa_ifd(
    endianness: Endianness,
    big_tiff: bool,
    jumbf_size: u64,
    jumbf_data_offset: u64,
) -> Result<(Vec<u8>, u64)> {
    let mut buf = Vec::new();
    {
        let mut bw = ByteOrdered::runtime(&mut buf, endianness);

        // Entry count
        if big_tiff {
            bw.write_u64(1)?;
        } else {
            bw.write_u16(1)?;
        }

        // Tag
        bw.write_u16(C2PA_TAG)?;
        // Type (UNDEFINED = 7)
        bw.write_u16(C2PA_FIELD_TYPE)?;

        // Count (value_count = jumbf_size)
        if big_tiff {
            bw.write_u64(jumbf_size)?;
        } else {
            let sz = u32::try_from(jumbf_size)
                .map_err(|_| Error::InvalidAsset("JUMBF too large for TIFF".to_string()))?;
            bw.write_u32(sz)?;
        }

        // Value/Offset field: pointer to JUMBF data
        if big_tiff {
            bw.write_u64(jumbf_data_offset)?;
        } else {
            let off = u32::try_from(jumbf_data_offset)
                .map_err(|_| Error::InvalidAsset("JUMBF offset too large for TIFF".to_string()))?;
            bw.write_u32(off)?;
        }

        // Next IFD = 0 (no more IFDs)
        if big_tiff {
            bw.write_u64(0)?;
        } else {
            bw.write_u32(0)?;
        }
    }

    let count_field_rel = if big_tiff {
        8 + 2 + 2 // entry_count(8) + tag(2) + type(2)
    } else {
        2 + 2 + 2 // entry_count(2) + tag(2) + type(2)
    };

    Ok((buf, count_field_rel))
}

/// Compute the output layout for appending C2PA to the TIFF.
fn compute_layout<R: Read + Seek>(
    source: &mut R,
    header: &TiffHeader,
    _existing: &Option<ExistingC2pa>,
    last_ifd_next_ptr: u64,
    jumbf_size: u64,
) -> Result<OutputLayout> {
    let source_size = stream_len(source)?;

    // Always append: copy the entire source, then append a fresh C2PA IFD + JUMBF.
    // This avoids bugs with in-place IFD reuse when re-signing.
    let source_copy_len = source_size;
    let patch_next_ifd_ptr = Some(last_ifd_next_ptr);

    // Align to DWORD (4-byte) boundary
    const DWORD_ALIGN: u64 = 4;
    let padded_copy_len = (source_copy_len + DWORD_ALIGN - 1) & !(DWORD_ALIGN - 1);

    let c2pa_ifd_offset = padded_copy_len;
    let ifd_size = ifd_total_size(header.big_tiff, 1);
    let jumbf_data_offset = c2pa_ifd_offset + ifd_size;

    let (ifd_bytes, count_field_rel) = build_c2pa_ifd(
        header.endianness,
        header.big_tiff,
        jumbf_size,
        jumbf_data_offset,
    )?;

    let count_field_offset = c2pa_ifd_offset + count_field_rel;

    Ok(OutputLayout {
        source_copy_len,
        c2pa_ifd_offset,
        jumbf_data_offset,
        count_field_offset,
        count_field_size: if header.big_tiff { 8 } else { 4 },
        patch_next_ifd_ptr,
        ifd_bytes,
    })
}

/// Total byte size of a single-entry IFD.
fn ifd_total_size(big_tiff: bool, entry_count: u64) -> u64 {
    if big_tiff {
        8 + entry_count * 20 + 8 // entry_count(8) + entries * entry_size(20) + next_ifd_ptr(8)
    } else {
        2 + entry_count * 12 + 4 // entry_count(2) + entries * entry_size(12) + next_ifd_ptr(4)
    }
}

/// Single-pass TIFF/DNG signing.
///
/// Reads the source TIFF once, writes the output with embedded C2PA manifest,
/// computes the hash, signs, and seek-patches the signed JUMBF.
///
/// For non-TIFF formats, falls back to `Builder.sign()`.
pub fn sign_tiff_fast<R, W>(
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
    let mime_format = format_to_mime(format);
    if !is_tiff_format(&mime_format) {
        return builder.sign(signer, format, source, dest);
    }

    let t_total = std::time::Instant::now();
    let settings = crate::settings::Settings::default();

    // -- Prepare builder + store --
    builder.definition.format.clone_from(&mime_format);
    if !builder.deterministic {
        builder.definition.instance_id = format!("xmp:iid:{}", Uuid::new_v4());
    }
    let deterministic = builder.deterministic;

    let mut store = builder.to_store()?;

    // -- Step 1: Parse source TIFF structure --
    let t0 = std::time::Instant::now();
    source.rewind()?;
    let header = read_tiff_header(source)?;
    let (existing_c2pa, last_ifd_next_ptr) = find_c2pa_and_last_ifd(source, &header)?;
    log::debug!(
        "[c2pa-fast-sign-tiff] parse: {}ms",
        t0.elapsed().as_millis()
    );

    // -- Step 2: Build DataHash assertion with placeholder hash --
    let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
    let alg = pc.alg().to_string();

    let hash_size = placeholder_hash_size(&alg)?;
    {
        let mut data_hash = DataHash::new(JUMBF_MANIFEST_NAME, &alg);
        data_hash.set_hash(vec![0u8; hash_size]);
        data_hash.add_exclusion(HashRange::new(PLACEHOLDER_OFFSET, PLACEHOLDER_OFFSET));
        data_hash.add_exclusion(HashRange::new(PLACEHOLDER_OFFSET, PLACEHOLDER_OFFSET));
        if deterministic {
            pc.add_assertion_with_salt(&data_hash, &crate::salt::NoSalt)?;
        } else {
            pc.add_assertion(&data_hash)?;
        }
    }

    let initial_jumbf = store.to_jumbf_internal(signer.reserve_size())?;
    let initial_jumbf_size = initial_jumbf.len() as u64;

    // -- Step 3: Compute output layout with initial JUMBF size --
    let layout = compute_layout(source, &header, &existing_c2pa, last_ifd_next_ptr, initial_jumbf_size)?;

    // -- Step 4: Update DataHash with correct exclusion ranges --
    {
        let mut real_data_hash = DataHash::new(JUMBF_MANIFEST_NAME, &alg);
        real_data_hash.set_hash(vec![0u8; hash_size]);
        real_data_hash.add_exclusion(HashRange::new(layout.jumbf_data_offset, initial_jumbf_size));
        real_data_hash.add_exclusion(HashRange::new(
            layout.count_field_offset,
            layout.count_field_size,
        ));

        let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.update_data_hash(real_data_hash)?;
    }

    // Regenerate JUMBF with real exclusion values
    let placeholder_jumbf = store.to_jumbf_internal(signer.reserve_size())?;
    let jumbf_size = placeholder_jumbf.len() as u64;

    // If the size changed (different CBOR encoding width), recompute layout
    let (layout, placeholder_jumbf, jumbf_size) = if jumbf_size != initial_jumbf_size {
        let layout2 = compute_layout(source, &header, &existing_c2pa, last_ifd_next_ptr, jumbf_size)?;

        {
            let mut dh = DataHash::new(JUMBF_MANIFEST_NAME, &alg);
            dh.set_hash(vec![0u8; hash_size]);
            dh.add_exclusion(HashRange::new(layout2.jumbf_data_offset, jumbf_size));
            dh.add_exclusion(HashRange::new(layout2.count_field_offset, layout2.count_field_size));
            let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
            pc.update_data_hash(dh)?;
        }

        let pj = store.to_jumbf_internal(signer.reserve_size())?;
        let js = pj.len() as u64;
        if js != jumbf_size {
            log::error!(
                "[c2pa-fast-sign-tiff] JUMBF size mismatch after recompute: expected {}, got {}",
                jumbf_size,
                js
            );
            return Err(Error::JumbfCreationError);
        }
        (layout2, pj, js)
    } else {
        (layout, placeholder_jumbf, jumbf_size)
    };

    // -- Step 5: Write output --
    source.rewind()?;

    // Copy source bytes up to source_copy_len
    copy_bytes(source, dest, layout.source_copy_len)?;

    // Pad to word boundary if needed
    let padding = layout.c2pa_ifd_offset - layout.source_copy_len;
    if padding > 0 {
        let zeros = vec![0u8; padding as usize];
        dest.write_all(&zeros)?;
    }

    // Write C2PA IFD
    dest.write_all(&layout.ifd_bytes)?;

    // Write placeholder JUMBF
    dest.write_all(&placeholder_jumbf)?;
    dest.flush()?;

    // Patch the "next IFD" pointer in the last page IFD to point to our new IFD
    if let Some(ptr_offset) = layout.patch_next_ifd_ptr {
        dest.seek(SeekFrom::Start(ptr_offset))?;
        let mut bw = ByteOrdered::runtime(&mut *dest, header.endianness);
        if header.big_tiff {
            bw.write_u64(layout.c2pa_ifd_offset)?;
        } else {
            let off = u32::try_from(layout.c2pa_ifd_offset)
                .map_err(|_| Error::InvalidAsset("IFD offset too large".to_string()))?;
            bw.write_u32(off)?;
        }
    }

    dest.flush()?;

    // -- Step 6: Compute hash over the output with exclusions --
    let t_hash = std::time::Instant::now();
    dest.rewind()?;
    let hash_value = compute_hash_with_exclusions(
        dest,
        &[
            (layout.jumbf_data_offset, jumbf_size),
            (layout.count_field_offset, layout.count_field_size),
        ],
        &alg,
    )?;
    log::debug!(
        "[c2pa-fast-sign-tiff] hash: {}ms",
        t_hash.elapsed().as_millis()
    );

    // -- Step 7: Update DataHash with real hash, regenerate JUMBF --
    let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
    let mut final_data_hash = DataHash::from_assertion(
        pc.data_hash_assertions()
            .first()
            .ok_or(Error::ClaimEncoding)?
            .assertion(),
    )?;
    final_data_hash.set_hash(hash_value);
    pc.update_data_hash(final_data_hash)?;

    let final_jumbf_unsigned = store.to_jumbf_internal(signer.reserve_size())?;
    if final_jumbf_unsigned.len() as u64 != jumbf_size {
        log::error!(
            "[c2pa-fast-sign-tiff] JUMBF size mismatch: expected {}, got {}",
            jumbf_size,
            final_jumbf_unsigned.len()
        );
        return Err(Error::JumbfCreationError);
    }

    // -- Step 8: Sign the claim --
    let t_sign = std::time::Instant::now();
    let (sig, sig_placeholder) = {
        let pc = store.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let s = store.sign_claim(pc, signer, signer.reserve_size(), &settings)?;
        let sp = Store::sign_claim_placeholder(pc, signer.reserve_size());
        (s, sp)
    };

    // -- Step 9: Patch signature into JUMBF, seek-patch output --
    let mut final_jumbf = final_jumbf_unsigned;
    if sig_placeholder.len() != sig.len() {
        return Err(Error::CoseSigboxTooSmall);
    }
    patch_bytes(&mut final_jumbf, &sig_placeholder, &sig)
        .map_err(|_| Error::JumbfCreationError)?;
    if final_jumbf.len() as u64 != jumbf_size {
        log::error!(
            "[c2pa-fast-sign-tiff] JUMBF size mismatch after signing: expected {}, got {}",
            jumbf_size,
            final_jumbf.len()
        );
        return Err(Error::JumbfCreationError);
    }

    dest.seek(SeekFrom::Start(layout.jumbf_data_offset))?;
    dest.write_all(&final_jumbf)?;
    dest.flush()?;

    log::debug!(
        "[c2pa-fast-sign-tiff] sign: {}ms",
        t_sign.elapsed().as_millis()
    );

    if let Some(pc_mut) = store.provenance_claim_mut() {
        pc_mut.set_signature_val(sig);
    }

    log::debug!(
        "[c2pa-fast-sign-tiff] total: {}ms, format={}",
        t_total.elapsed().as_millis(),
        format,
    );

    Ok(final_jumbf)
}

/// Copy exactly `len` bytes from `src` to `dst`.
fn copy_bytes<R: Read, W: Write>(src: &mut R, dst: &mut W, len: u64) -> Result<()> {
    let mut remaining = len;
    let mut buf = vec![0u8; COPY_BUF_SIZE];
    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, buf.len());
        src.read_exact(&mut buf[..to_read])?;
        dst.write_all(&buf[..to_read])?;
        remaining -= to_read as u64;
    }
    Ok(())
}

/// Compute SHA-256 (or other algorithm) hash over a stream, excluding given ranges.
fn compute_hash_with_exclusions<R: Read + Seek>(
    reader: &mut R,
    exclusions: &[(u64, u64)], // (offset, length)
    alg: &str,
) -> Result<Vec<u8>> {
    let mut sorted_exc: Vec<(u64, u64)> = exclusions.to_vec();
    sorted_exc.sort_by_key(|e| e.0);

    let hash_ranges: Vec<HashRange> = sorted_exc
        .iter()
        .map(|(start, len)| HashRange::new(*start, *len))
        .collect();

    reader.rewind()?;
    crate::hash_utils::hash_stream_by_alg(alg, reader, Some(hash_ranges), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tiff_format() {
        assert!(is_tiff_format("image/tiff"));
        assert!(is_tiff_format("tiff"));
        assert!(is_tiff_format("tif"));
        assert!(is_tiff_format("dng"));
        assert!(is_tiff_format("image/dng"));
        assert!(!is_tiff_format("image/jpeg"));
        assert!(!is_tiff_format("video/mp4"));
    }

    #[test]
    fn test_ifd_total_size() {
        assert_eq!(ifd_total_size(false, 1), 18);
        assert_eq!(ifd_total_size(true, 1), 36);
    }
}
