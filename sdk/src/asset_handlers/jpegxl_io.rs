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

//! JPEG XL (ISO/IEC 18181-2:2024) asset handler for C2PA embedding.
//!
//! Implements C2PA Specification v2.3, Section A.3.9 - "Embedding manifests into JPEG XL".
//!
//! Key spec requirements:
//! - Only the ISOBMFF-based container form (not naked codestream) can embed C2PA.
//! - The C2PA Manifest Store (the entire JUMBF superbox with label `"c2pa"`) is embedded
//!   in its own `jumb` BMFF box at the top level of the container.
//! - Multiple top-level `jumb` boxes are permitted (e.g. one for EXIF, one for C2PA).
//!   All top-level `jumb` boxes are scanned; the one whose first inner box is a `jumd`
//!   description box with label `"c2pa"` is the manifest store. At most one such box
//!   is allowed.
//! - Uses general box hash (`c2pa.hash.boxes`) for hard binding (non-BMFF classification).
//! - Supports `brob` (Brotli-compressed) boxes for reading XMP metadata.
//!
//! NOTE: Brotli decompression is intentionally NOT supported for C2PA JUMBF (`jumb`) boxes.
//! Per C2PA Implementation Guidance §3.2.4, compressed manifests are not compatible with
//! box-based hashing. A `brob`-wrapped `jumb` would break the hashing model because the
//! compressed bytes are non-deterministic and the write path always produces uncompressed
//! `jumb` boxes. Only `brob`-wrapped `xml` (XMP) boxes are decompressed, as XMP is treated
//! as opaque metadata.

use std::{
    fs::File,
    io::{Cursor, SeekFrom},
    path::Path,
};

use byteorder::{BigEndian, ReadBytesExt};
use serde_bytes::ByteBuf;

use crate::{
    assertions::{BoxMap, C2PA_BOXHASH},
    asset_io::{
        rename_or_move, AssetBoxHash, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        ComposedManifestRef, HashBlockObjectType, HashObjectPositions, RemoteRefEmbed,
        RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::{
        io_utils::{safe_vec, tempfile_builder},
        xmp_inmemory_utils::{add_provenance, MIN_XMP},
    },
};

// JPEG XL container signature (ISO/IEC 18181-2:2024, Clause 4.1)
// This is itself a box: size=12, type='JXL ' (0x4A584C20), payload=0x0D0A870A
const JXL_CONTAINER_MAGIC: [u8; 12] = [
    0x00, 0x00, 0x00, 0x0c, // size = 12
    0x4a, 0x58, 0x4c, 0x20, // type = 'JXL '
    0x0d, 0x0a, 0x87, 0x0a, // magic payload
];

const JXL_CONTAINER_MAGIC_LEN: u64 = 12;

// Naked codestream signature - cannot embed C2PA manifests
const JXL_CODESTREAM_SIG: [u8; 2] = [0xff, 0x0a];

// Box type FourCCs (big-endian u32)
const BOX_JUMB: [u8; 4] = *b"jumb"; // JUMBF box
const BOX_XML: [u8; 4] = *b"xml "; // XMP metadata (note trailing space)
const BOX_BROB: [u8; 4] = *b"brob"; // Brotli-compressed metadata box
const BOX_FTYP: [u8; 4] = *b"ftyp"; // File type box
const BOX_JXLC: [u8; 4] = *b"jxlc"; // JPEG XL codestream
const BOX_JXLP: [u8; 4] = *b"jxlp"; // JPEG XL partial codestream
#[cfg(test)]
const BOX_EXIF: [u8; 4] = *b"Exif"; // Exif metadata

const BOX_HEADER_SIZE: u64 = 8; // 4-byte size + 4-byte type
const BOX_HEADER_SIZE_LARGE: u64 = 16; // + 8-byte extended size when size field == 1

/// Maximum number of top-level boxes allowed in a JPEG XL container.
/// Prevents memory exhaustion from files crafted with thousands of tiny boxes.
const MAX_JXL_BOX_COUNT: usize = 1024;

/// Bytes to peek from a `jumb` payload to determine whether it is the C2PA manifest
/// store via [`jumb_data_has_c2pa_label`]. The `jumd` description box layout is:
/// 4 (inner size) + 4 (type `"jumd"`) + 16 (UUID) + 1 (toggles) = 25 header bytes,
/// followed by the null-terminated label `"c2pa\0"` (5 bytes) = 30 bytes total.
const JUMD_C2PA_LABEL_PEEK: u64 = 30;

static SUPPORTED_TYPES: [&str; 2] = ["jxl", "image/jxl"];

/// Positional information for a single top-level ISOBMFF box in a JPEG XL container.
#[derive(Clone, Debug)]
struct JxlBoxInfo {
    box_type: [u8; 4],
    offset: u64,
    header_size: u64,
    total_size: u64, // 0 means "extends to end of file"
}

impl JxlBoxInfo {
    fn type_str(&self) -> String {
        String::from_utf8_lossy(&self.box_type).to_string()
    }

    fn data_offset(&self) -> u64 {
        self.offset + self.header_size
    }

    fn data_size(&self, file_len: u64) -> u64 {
        let total = if self.total_size == 0 {
            file_len - self.offset
        } else {
            self.total_size
        };
        total.saturating_sub(self.header_size)
    }

    fn end(&self, file_len: u64) -> u64 {
        if self.total_size == 0 {
            file_len
        } else {
            self.offset.saturating_add(self.total_size)
        }
    }
}

/// Validates that the stream starts with the JPEG XL container signature.
fn is_jxl_container(reader: &mut dyn CAIRead) -> Result<bool> {
    reader.rewind()?;
    let mut magic = [0u8; 12];
    match reader.read_exact(&mut magic) {
        Ok(()) => Ok(magic == JXL_CONTAINER_MAGIC),
        Err(_) => Ok(false),
    }
}

/// Checks if the stream starts with the naked codestream signature.
fn is_naked_codestream(reader: &mut dyn CAIRead) -> Result<bool> {
    reader.rewind()?;
    let mut sig = [0u8; 2];
    match reader.read_exact(&mut sig) {
        Ok(()) => Ok(sig == JXL_CODESTREAM_SIG),
        Err(_) => Ok(false),
    }
}

/// Reads a single box header from the current stream position.
/// Returns None at EOF.
fn read_box_header(reader: &mut dyn CAIRead) -> Result<Option<JxlBoxInfo>> {
    let offset = reader.stream_position()?;

    let size32 = match reader.read_u32::<BigEndian>() {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::IoError(e)),
    };

    let mut box_type = [0u8; 4];
    reader.read_exact(&mut box_type).map_err(Error::IoError)?;

    let (header_size, total_size) = match size32 {
        0 => (BOX_HEADER_SIZE, 0u64), // box extends to EOF
        1 => {
            let large_size = reader.read_u64::<BigEndian>().map_err(Error::IoError)?;
            (BOX_HEADER_SIZE_LARGE, large_size)
        }
        s => (BOX_HEADER_SIZE, s as u64),
    };

    Ok(Some(JxlBoxInfo {
        box_type,
        offset,
        header_size,
        total_size,
    }))
}

/// Parses all top-level boxes in a JPEG XL container.
/// The reader must be positioned at the start of the file.
fn parse_all_boxes(reader: &mut dyn CAIRead) -> Result<Vec<JxlBoxInfo>> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    reader.rewind()?;

    let mut boxes = Vec::new();
    loop {
        let pos = reader.stream_position()?;
        if pos >= file_len {
            break;
        }

        match read_box_header(reader)? {
            Some(info) => {
                let next_pos = if info.total_size == 0 {
                    file_len
                } else {
                    info.offset.saturating_add(info.total_size)
                };

                if boxes.len() >= MAX_JXL_BOX_COUNT {
                    return Err(Error::InvalidAsset(
                        "Too many boxes in JPEG XL container".to_string(),
                    ));
                }
                boxes.push(info);

                if next_pos >= file_len {
                    break;
                }
                reader.seek(SeekFrom::Start(next_pos))?;
            }
            None => break,
        }
    }

    Ok(boxes)
}

/// If a `brob` box wraps content of the given target type, decompress and return it.
/// The reader should be positioned at the start of the brob box's data area.
fn decompress_brob(reader: &mut dyn CAIRead, data_size: u64) -> Result<([u8; 4], Vec<u8>)> {
    let mut original_type = [0u8; 4];
    reader
        .read_exact(&mut original_type)
        .map_err(Error::IoError)?;

    let compressed_size = data_size.saturating_sub(4);
    let mut compressed = safe_vec(compressed_size, Some(0u8))?;
    reader.read_exact(&mut compressed).map_err(Error::IoError)?;

    let mut decompressed = Vec::new();
    brotli::BrotliDecompress(&mut Cursor::new(compressed), &mut decompressed)
        .map_err(|_| Error::InvalidAsset("Failed to decompress brob box".to_string()))?;

    Ok((original_type, decompressed))
}

/// Returns `true` if the given `jumb` box payload contains a JUMBF description box (`jumd`)
/// whose label is `"c2pa"`, identifying this as the C2PA manifest store.
///
/// A JPEG XL container may have multiple top-level `jumb` boxes (e.g. one for EXIF metadata
/// and a separate one for the C2PA manifest store). This function distinguishes them by
/// inspecting the label in the first inner `jumd` box of the payload.
///
/// The `jumd` payload layout is derived from [`jumbf::boxes::BoxReader::read_desc_box`]:
/// - bytes 0..4:  BMFF inner box size (big-endian u32, includes the 8-byte header)
/// - bytes 4..8:  BMFF box type = `b"jumd"`
/// - bytes 8..24: 16-byte UUID
/// - byte 24:     toggles bitfield (`toggles & 0x03 == 0x03` means requestable + label present)
/// - bytes 25..:  null-terminated label string
fn jumb_data_has_c2pa_label(data: &[u8]) -> bool {
    // Minimum viable jumd: 4 (size) + 4 (type) + 16 (UUID) + 1 (toggles) = 25 bytes
    if data.len() < 25 {
        return false;
    }

    // First inner box must be a jumd description box
    if &data[4..8] != b"jumd" {
        return false;
    }

    // toggles byte is at offset 24; bits 0+1 must both be set for a label to be present
    let toggles = data[24];
    if toggles & 0x03 != 0x03 {
        return false;
    }

    // Label starts at offset 25, null-terminated
    let label_bytes = &data[25..];
    let label_end = label_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(label_bytes.len());

    &label_bytes[..label_end] == b"c2pa"
}

/// Brotli-compresses `data` and wraps it in an ISOBMFF `brob` box with the given inner type.
fn compress_brob_box(inner_type: &[u8; 4], data: &[u8]) -> Result<Vec<u8>> {
    let params = brotli::enc::BrotliEncoderParams::default();
    let mut compressed = Vec::new();
    brotli::BrotliCompress(&mut Cursor::new(data), &mut compressed, &params)
        .map_err(|_| Error::InvalidAsset("Failed to compress brob box".to_string()))?;
    let mut brob_payload = Vec::with_capacity(4 + compressed.len());
    brob_payload.extend_from_slice(inner_type);
    brob_payload.extend_from_slice(&compressed);
    // build_box already handles the largesize case (ISO/IEC 14496-12): if the total
    // box size exceeds u32::MAX it emits a size=1 header followed by a 64-bit largesize
    // field, so payloads larger than 4 GiB are handled correctly here.
    Ok(build_box(&BOX_BROB, &brob_payload))
}

/// Finds the C2PA manifest store in a JPEG XL container.
///
/// Scans all top-level `jumb` BMFF boxes and returns the **complete** `jumb` BMFF box
/// (header + payload) for the one that contains a `jumd` description box with label
/// `"c2pa"`. The complete box is returned so that `Store::from_jumbf` (which calls
/// `BoxReader::read_super_box` and expects a `"jumb"` BMFF header) can parse it.
/// Multiple `jumb` boxes are permitted (e.g. one for EXIF, one for C2PA); only the
/// C2PA one is returned.
fn find_jumb_data(reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
    let file_len = reader.seek(SeekFrom::End(0))?;

    if !is_jxl_container(reader)? {
        if is_naked_codestream(reader)? {
            return Err(Error::InvalidAsset(
                "JPEG XL naked codestream cannot contain C2PA manifests".to_string(),
            ));
        }
        return Err(Error::InvalidAsset(
            "Not a valid JPEG XL container".to_string(),
        ));
    }

    let boxes = parse_all_boxes(reader)?;

    let mut c2pa_jumb: Option<Vec<u8>> = None;

    for b in &boxes {
        if b.box_type == BOX_JUMB {
            // Peek only the bytes needed by jumb_data_has_c2pa_label to check
            // the C2PA label; no need to read the entire payload.
            let peek = b.data_size(file_len).min(JUMD_C2PA_LABEL_PEEK);
            reader.seek(SeekFrom::Start(b.data_offset()))?;
            let mut header_peek = safe_vec(peek, Some(0u8))?;
            reader
                .read_exact(&mut header_peek)
                .map_err(Error::IoError)?;
            if jumb_data_has_c2pa_label(&header_peek) {
                if c2pa_jumb.is_some() {
                    return Err(Error::TooManyManifestStores);
                }
                // Return the complete jumb BMFF box (header + payload) so that
                // Store::from_jumbf (which calls BoxReader::read_super_box and
                // expects a "jumb" box header) can parse it correctly.
                let box_size = b.end(file_len).saturating_sub(b.offset);
                reader.seek(SeekFrom::Start(b.offset))?;
                let mut complete_box = safe_vec(box_size, Some(0u8))?;
                reader
                    .read_exact(&mut complete_box)
                    .map_err(Error::IoError)?;
                c2pa_jumb = Some(complete_box);
            }
        }
    }

    c2pa_jumb.ok_or(Error::JumbfNotFound)
}

/// Reads XMP data from the JPEG XL container (from `xml ` or `brob`-wrapped `xml ` boxes).
fn find_xmp_data(reader: &mut dyn CAIRead) -> Option<String> {
    let file_len = reader.seek(SeekFrom::End(0)).ok()?;

    if !is_jxl_container(reader).ok()? {
        return None;
    }

    let boxes = parse_all_boxes(reader).ok()?;

    for b in &boxes {
        if b.box_type == BOX_XML {
            let ds = b.data_size(file_len);
            reader.seek(SeekFrom::Start(b.data_offset())).ok()?;
            let mut data = safe_vec(ds, Some(0u8)).ok()?;
            reader.read_exact(&mut data).ok()?;
            return String::from_utf8(data).ok();
        } else if b.box_type == BOX_BROB {
            reader.seek(SeekFrom::Start(b.data_offset())).ok()?;
            let ds = b.data_size(file_len);
            if ds >= 4 {
                if let Ok((orig_type, decompressed)) = decompress_brob(reader, ds) {
                    if orig_type == BOX_XML {
                        return String::from_utf8(decompressed).ok();
                    }
                }
            }
        }
    }

    None
}

/// Determines the insertion point for a new `jumb` box.
/// Per the spec, it should be placed after `ftyp` and before codestream data.
fn find_jumb_insertion_offset(boxes: &[JxlBoxInfo]) -> u64 {
    // After ftyp, before first codestream box (jxlc/jxlp)
    for (i, b) in boxes.iter().enumerate() {
        if b.box_type == BOX_JXLC || b.box_type == BOX_JXLP {
            return b.offset;
        }
        if b.box_type == BOX_FTYP {
            if let Some(next) = boxes.get(i + 1) {
                return next.offset;
            }
        }
    }

    // Fallback: after the file signature box (first 12 bytes)
    if !boxes.is_empty() {
        let first = &boxes[0];
        if first.total_size > 0 {
            return first.offset + first.total_size;
        }
    }
    JXL_CONTAINER_MAGIC_LEN
}

/// Builds a JPEG XL ISOBMFF box with the given type and data payload.
fn build_box(box_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let total_size = BOX_HEADER_SIZE as usize + data.len();
    if total_size <= u32::MAX as usize {
        let mut buf = Vec::with_capacity(total_size);
        buf.extend_from_slice(&(total_size as u32).to_be_bytes()); // big-endian size
        buf.extend_from_slice(box_type);
        buf.extend_from_slice(data);
        buf
    } else {
        // Use large box format (ISO/IEC 14496-12: size=1 signals an 8-byte largesize field)
        let total_large = BOX_HEADER_SIZE_LARGE as usize + data.len();
        let mut buf = Vec::with_capacity(total_large);
        buf.extend_from_slice(&1u32.to_be_bytes()); // size=1 signals extended size
        buf.extend_from_slice(box_type);
        buf.extend_from_slice(&(total_large as u64).to_be_bytes()); // big-endian largesize
        buf.extend_from_slice(data);
        buf
    }
}

/// Rewrites the container, omitting only the C2PA manifest store `jumb` box.
/// Other `jumb` boxes (e.g. EXIF) and all non-`jumb` boxes are preserved.
fn remove_c2pa_jumb_box(reader: &mut dyn CAIRead, writer: &mut dyn CAIReadWrite) -> Result<()> {
    let file_len = reader.seek(SeekFrom::End(0))?;

    if !is_jxl_container(reader)? {
        return Err(Error::InvalidAsset(
            "Not a valid JPEG XL container".to_string(),
        ));
    }

    let boxes = parse_all_boxes(reader)?;

    writer.rewind()?;

    for b in &boxes {
        // Only skip the C2PA jumb box; other jumb boxes (e.g. EXIF) are preserved.
        // brob-wrapped jumb is always kept as opaque data since compressed manifests
        // are not supported (see module-level doc comment).
        let should_skip = if b.box_type == BOX_JUMB {
            let ds = b.data_size(file_len);
            reader.seek(SeekFrom::Start(b.data_offset()))?;
            let mut data = safe_vec(ds, Some(0u8))?;
            reader.read_exact(&mut data).map_err(Error::IoError)?;
            // Reset so the copy below can read from the box start
            reader.seek(SeekFrom::Start(b.offset))?;
            jumb_data_has_c2pa_label(&data)
        } else {
            false
        };

        if !should_skip {
            let box_end = b.end(file_len);
            let box_len = box_end.saturating_sub(b.offset);
            reader.seek(SeekFrom::Start(b.offset))?;
            let mut box_data = safe_vec(box_len, Some(0u8))?;
            reader.read_exact(&mut box_data).map_err(Error::IoError)?;
            writer.write_all(&box_data).map_err(Error::IoError)?;
        }
    }

    Ok(())
}

/// Determines the XMP insertion point and whether the existing XMP is Brotli-compressed.
///
/// Returns `(offset, len, was_compressed)`:
/// - `offset` — byte offset of the existing XMP box to replace, or the insertion point
///   when no XMP box is present.
/// - `len` — byte length of the existing XMP box (0 when inserting a new box).
/// - `was_compressed` — `true` when the existing XMP resides in a `brob`-wrapped `xml `
///   box, so that the write path can preserve the original compression state.
fn find_xmp_box_info(boxes: &[JxlBoxInfo], file_len: u64, data: &[u8]) -> (u64, u64, bool) {
    for b in boxes {
        if b.box_type == BOX_XML {
            return (b.offset, b.end(file_len) - b.offset, false);
        } else if b.box_type == BOX_BROB {
            let data_start = b.data_offset() as usize;
            if data.len() >= data_start + 4 {
                let orig_type: [u8; 4] = data[data_start..data_start + 4]
                    .try_into()
                    .unwrap_or([0u8; 4]);
                if orig_type == BOX_XML {
                    return (b.offset, b.end(file_len) - b.offset, true);
                }
            }
        }
    }
    // No existing XMP box — insert after ftyp, before codestream
    (find_jumb_insertion_offset(boxes), 0, false)
}

pub struct JpegXlIO {}

impl CAIReader for JpegXlIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        find_jumb_data(asset_reader)
    }

    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        find_xmp_data(asset_reader)
    }
}

impl CAIWriter for JpegXlIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let file_len = input_stream.seek(SeekFrom::End(0))?;

        if !is_jxl_container(input_stream)? {
            return Err(Error::InvalidAsset(
                "Not a valid JPEG XL container".to_string(),
            ));
        }

        // Read entire input
        input_stream.rewind()?;
        let mut buf = Vec::new();
        input_stream.read_to_end(&mut buf).map_err(Error::IoError)?;

        // Parse boxes to find and remove existing jumb
        let mut cursor = Cursor::new(&buf);
        let boxes = parse_all_boxes(&mut cursor)?;

        // Find the existing C2PA jumb box to remove, if any. The spec allows at most one,
        // so this is an Option rather than a Vec. Other jumb boxes (e.g. EXIF) and
        // brob-wrapped jumb boxes are left untouched.
        let existing_c2pa_jumb: Option<(usize, usize)> = boxes.iter().find_map(|b| {
            if b.box_type != BOX_JUMB {
                return None;
            }
            let data_start = b.data_offset() as usize;
            let data_end = b.end(file_len) as usize;
            if data_end <= buf.len() && jumb_data_has_c2pa_label(&buf[data_start..data_end]) {
                Some((b.offset as usize, data_end))
            } else {
                None
            }
        });

        if let Some((start, end)) = existing_c2pa_jumb {
            buf.drain(start..end);
        }

        // Only re-parse when an existing C2PA jumb box was removed, because draining
        // bytes invalidates the offsets captured in the first parse. When nothing
        // was removed the original parse results are still accurate.
        let insert_offset = if existing_c2pa_jumb.is_none() {
            find_jumb_insertion_offset(&boxes) as usize
        } else {
            let mut cursor = Cursor::new(&buf);
            let boxes = parse_all_boxes(&mut cursor)?;
            find_jumb_insertion_offset(&boxes) as usize
        };

        // store_bytes is already a complete `jumb` BMFF box produced by the C2PA SDK
        // (Store::to_jumbf). Do NOT wrap it in another jumb box.
        let jumb_box = store_bytes.to_vec();

        // Insert
        buf.splice(insert_offset..insert_offset, jumb_box.iter().cloned());

        output_stream.rewind()?;
        output_stream.write_all(&buf).map_err(Error::IoError)?;

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        // Ensure there is a jumb placeholder
        let output_vec: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_vec);
        add_required_jumb_to_stream(input_stream, &mut output_stream)?;

        let buf = output_stream.into_inner();
        let file_len = buf.len() as u64;
        let mut cursor = Cursor::new(&buf);
        let boxes = parse_all_boxes(&mut cursor)?;

        let positions: Vec<HashObjectPositions> = boxes
            .iter()
            .map(|b| {
                let length = if b.total_size == 0 {
                    (file_len - b.offset) as usize
                } else {
                    b.total_size as usize
                };
                let htype = if b.box_type == BOX_JUMB {
                    // Only mark as CAI if this is the C2PA manifest store (identified by
                    // its "c2pa" jumd label). The placeholder inserted by
                    // add_required_jumb_to_stream also carries this label, so no special
                    // empty-payload handling is needed.
                    let data_start = b.data_offset() as usize;
                    let data_end = b.end(file_len) as usize;
                    let data = if data_end <= buf.len() {
                        &buf[data_start..data_end]
                    } else {
                        &[]
                    };
                    if jumb_data_has_c2pa_label(data) {
                        HashBlockObjectType::Cai
                    } else {
                        HashBlockObjectType::Other
                    }
                } else if b.box_type == BOX_XML {
                    HashBlockObjectType::Xmp
                } else {
                    HashBlockObjectType::Other
                };
                HashObjectPositions {
                    offset: b.offset as usize,
                    length,
                    htype,
                }
            })
            .collect();

        Ok(positions)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        remove_c2pa_jumb_box(input_stream, output_stream)
    }
}

/// Builds a minimal C2PA manifest store placeholder payload.
///
/// The placeholder is a bare `jumd` description box with label `"c2pa"` and no additional
/// content. It is used by `add_required_jumb_to_stream` to insert a correctly-labelled
/// `jumb` slot when no C2PA manifest store exists yet, so that hashing can compute the
/// correct byte-range offset before the real manifest is written.  Using a labelled
/// placeholder (rather than an empty one) ensures `jumb_data_has_c2pa_label` can
/// unambiguously identify it and avoids false-positive matches on other empty `jumb` boxes.
fn build_c2pa_jumd_placeholder() -> Vec<u8> {
    let mut jumd_payload = Vec::new();
    jumd_payload.extend_from_slice(&[0u8; 16]); // UUID — all zeros for placeholder
    jumd_payload.push(0x03); // toggles: requestable (bit 0) + label present (bit 1)
    jumd_payload.extend_from_slice(b"c2pa\0"); // null-terminated label
    let jumd = build_box(b"jumd", &jumd_payload);
    // Wrap in a complete jumb BMFF box. write_cai no longer wraps store_bytes, so
    // the placeholder must already be the complete top-level jumb box.
    build_box(b"jumb", &jumd)
}

/// Ensures the JPEG XL container has a jumb box placeholder for hashing.
fn add_required_jumb_to_stream(
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    input_stream.rewind()?;

    let mut buf = Vec::new();
    input_stream.read_to_end(&mut buf).map_err(Error::IoError)?;
    input_stream.rewind()?;

    let mut cursor = Cursor::new(&buf);
    let boxes = parse_all_boxes(&mut cursor)?;

    // Check specifically for a C2PA jumb box (not just any jumb box), so that a file
    // with only non-C2PA jumb boxes (e.g. EXIF) still gets a C2PA placeholder inserted.
    let has_c2pa_jumb = boxes.iter().any(|b| {
        if b.box_type != BOX_JUMB {
            return false;
        }
        let data_start = b.data_offset() as usize;
        let data_end = b.end(buf.len() as u64) as usize;
        data_end <= buf.len() && jumb_data_has_c2pa_label(&buf[data_start..data_end])
    });

    if !has_c2pa_jumb {
        // Use a minimal valid jumd "c2pa" payload so the placeholder is identifiable
        // by jumb_data_has_c2pa_label and cannot be confused with any other jumb box.
        let placeholder = build_c2pa_jumd_placeholder();
        let jpegxl_io = JpegXlIO {};
        let mut input = Cursor::new(buf);
        jpegxl_io.write_cai(&mut input, output_stream, &placeholder)?;
    } else {
        output_stream.rewind()?;
        output_stream.write_all(&buf).map_err(Error::IoError)?;
    }

    Ok(())
}

impl AssetIO for JpegXlIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        JpegXlIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(JpegXlIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(JpegXlIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = std::fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        self.get_object_locations_from_stream(&mut file)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut input_stream = File::open(asset_path).map_err(Error::IoError)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        remove_c2pa_jumb_box(&mut input_stream, &mut temp_file)?;

        rename_or_move(temp_file, asset_path)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        Some(self)
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }
}

impl RemoteRefEmbed for JpegXlIO {
    #[allow(unused_variables)]
    fn embed_reference(&self, asset_path: &Path, embed_ref: RemoteRefEmbedType) -> Result<()> {
        match &embed_ref {
            RemoteRefEmbedType::Xmp(_) => {
                let mut file = File::open(asset_path)?;
                let mut temp = Cursor::new(Vec::new());
                self.embed_reference_to_stream(&mut file, &mut temp, embed_ref)?;
                std::fs::write(asset_path, temp.into_inner()).map_err(Error::IoError)?;
                Ok(())
            }
            RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }

    fn embed_reference_to_stream(
        &self,
        source_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            RemoteRefEmbedType::Xmp(manifest_uri) => {
                let file_len = source_stream.seek(SeekFrom::End(0))?;

                if !is_jxl_container(source_stream)? {
                    return Err(Error::InvalidAsset(
                        "Not a valid JPEG XL container".to_string(),
                    ));
                }

                source_stream.rewind()?;
                let mut buf = Vec::new();
                source_stream
                    .read_to_end(&mut buf)
                    .map_err(Error::IoError)?;

                let xmp = match find_xmp_data(source_stream) {
                    Some(s) => s,
                    None => MIN_XMP.to_string(),
                };

                let updated_xmp = add_provenance(&xmp, &manifest_uri)?;

                let mut cursor = Cursor::new(&buf);
                let boxes = parse_all_boxes(&mut cursor)?;

                let (xmp_offset, xmp_len, was_compressed) =
                    find_xmp_box_info(&boxes, file_len, &buf);

                // Preserve the source file's compression state: if the original XMP
                // was Brotli-compressed (brob-wrapped), write it back compressed.
                let xmp_box = if was_compressed {
                    compress_brob_box(&BOX_XML, updated_xmp.as_bytes())?
                } else {
                    build_box(&BOX_XML, updated_xmp.as_bytes())
                };

                let xmp_offset = xmp_offset as usize;
                let xmp_len = xmp_len as usize;

                buf.splice(xmp_offset..xmp_offset + xmp_len, xmp_box.iter().cloned());

                output_stream.rewind()?;
                output_stream.write_all(&buf).map_err(Error::IoError)?;

                Ok(())
            }
            RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }
}

impl AssetBoxHash for JpegXlIO {
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>> {
        let file_len = input_stream.seek(SeekFrom::End(0))?;

        if !is_jxl_container(input_stream)? {
            return Err(Error::InvalidAsset(
                "Not a valid JPEG XL container".to_string(),
            ));
        }

        let boxes = parse_all_boxes(input_stream)?;
        let mut box_maps = Vec::new();

        for b in &boxes {
            let total = if b.total_size == 0 {
                file_len - b.offset
            } else {
                b.total_size
            };

            // Only plain jumb boxes are marked as C2PA; brob boxes (including those
            // wrapping jumb) are treated as opaque data for hashing purposes, since
            // compressed manifests are incompatible with box-based hashing.
            let name = if b.box_type == BOX_JUMB {
                C2PA_BOXHASH.to_string()
            } else {
                b.type_str()
            };

            box_maps.push(BoxMap {
                names: vec![name],
                alg: None,
                hash: ByteBuf::from(Vec::new()),
                excluded: None,
                pad: ByteBuf::from(Vec::new()),
                range_start: b.offset,
                range_len: total,
            });
        }

        Ok(box_maps)
    }
}

impl ComposedManifestRef for JpegXlIO {
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        Ok(build_box(&BOX_JUMB, manifest_data))
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum JpegXlError {
    #[error("invalid file signature: {reason}")]
    InvalidFileSignature { reason: String },

    #[error("naked codestream cannot embed C2PA manifests")]
    NakedCodestream,
}

// ─── Test helpers: construct minimal JPEG XL containers ───

/// Builds a minimal valid JPEG XL container with just the signature and ftyp boxes.
#[cfg(test)]
fn build_minimal_jxl_container() -> Vec<u8> {
    let ftyp_data = b"jxl \0\0\0\0jxl ";
    let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

    let jxlc_data = &[0xff, 0x0a, 0x00]; // minimal codestream stub
    let jxlc_box = build_box(&BOX_JXLC, jxlc_data);

    let mut container = Vec::new();
    container.extend_from_slice(&JXL_CONTAINER_MAGIC);
    container.extend_from_slice(&ftyp_box);
    container.extend_from_slice(&jxlc_box);
    container
}

/// Builds a JPEG XL container with an embedded `xml ` (XMP) box.
#[cfg(test)]
fn build_jxl_with_xmp(xmp_data: &str) -> Vec<u8> {
    let ftyp_data = b"jxl \0\0\0\0jxl ";
    let ftyp_box = build_box(&BOX_FTYP, ftyp_data);
    let xml_box = build_box(&BOX_XML, xmp_data.as_bytes());

    let jxlc_data = &[0xff, 0x0a, 0x00];
    let jxlc_box = build_box(&BOX_JXLC, jxlc_data);

    let mut container = Vec::new();
    container.extend_from_slice(&JXL_CONTAINER_MAGIC);
    container.extend_from_slice(&ftyp_box);
    container.extend_from_slice(&xml_box);
    container.extend_from_slice(&jxlc_box);
    container
}

/// Builds a JPEG XL container with a `brob`-wrapped `jumb` box.
#[cfg(test)]
fn build_jxl_with_brob_jumb(manifest_data: &[u8]) -> Result<Vec<u8>> {
    let ftyp_data = b"jxl \0\0\0\0jxl ";
    let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

    // Brotli-compress the manifest data
    let mut compressed = Vec::new();
    {
        let params = brotli::enc::BrotliEncoderParams::default();
        brotli::BrotliCompress(&mut Cursor::new(manifest_data), &mut compressed, &params)
            .map_err(Error::IoError)?;
    }

    // brob payload = original_type(4) + compressed_data
    let mut brob_payload = Vec::new();
    brob_payload.extend_from_slice(&BOX_JUMB);
    brob_payload.extend_from_slice(&compressed);
    let brob_box = build_box(&BOX_BROB, &brob_payload);

    let jxlc_data = &[0xff, 0x0a, 0x00];
    let jxlc_box = build_box(&BOX_JXLC, jxlc_data);

    let mut container = Vec::new();
    container.extend_from_slice(&JXL_CONTAINER_MAGIC);
    container.extend_from_slice(&ftyp_box);
    container.extend_from_slice(&brob_box);
    container.extend_from_slice(&jxlc_box);
    Ok(container)
}

/// Builds a JPEG XL container with a `brob`-wrapped `xml ` box.
#[cfg(test)]
fn build_jxl_with_brob_xmp(xmp_data: &str) -> Result<Vec<u8>> {
    let ftyp_data = b"jxl \0\0\0\0jxl ";
    let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

    let mut compressed = Vec::new();
    {
        let params = brotli::enc::BrotliEncoderParams::default();
        brotli::BrotliCompress(
            &mut Cursor::new(xmp_data.as_bytes()),
            &mut compressed,
            &params,
        )
        .map_err(Error::IoError)?;
    }

    let mut brob_payload = Vec::new();
    brob_payload.extend_from_slice(&BOX_XML);
    brob_payload.extend_from_slice(&compressed);
    let brob_box = build_box(&BOX_BROB, &brob_payload);

    let jxlc_data = &[0xff, 0x0a, 0x00];
    let jxlc_box = build_box(&BOX_JXLC, jxlc_data);

    let mut container = Vec::new();
    container.extend_from_slice(&JXL_CONTAINER_MAGIC);
    container.extend_from_slice(&ftyp_box);
    container.extend_from_slice(&brob_box);
    container.extend_from_slice(&jxlc_box);
    Ok(container)
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Read, Seek};

    use byteorder::WriteBytesExt;

    use super::*;
    use crate::utils::io_utils::tempdirectory;

    /// Public test helper: builds a minimal JPEG XL container for use in integration tests.
    pub fn build_test_jxl_container() -> Vec<u8> {
        build_minimal_jxl_container()
    }

    /// Builds a minimal valid C2PA manifest store payload for use as `store_bytes` in
    /// `write_cai` / `save_cai_store` calls.
    ///
    /// Real C2PA manifest stores start with a `jumd` description box whose label is `"c2pa"`.
    /// Tests that verify write→read roundtrips must use this helper so that
    /// `jumb_data_has_c2pa_label` can identify the box.
    fn c2pa_store(extra: &[u8]) -> Vec<u8> {
        // Build a complete jumb BMFF box (as Store::to_jumbf produces) so that
        // write_cai (which no longer wraps store_bytes) and find_jumb_data
        // (which returns the complete jumb box) behave consistently in tests.
        let mut jumb_payload = build_jumd_box(b"c2pa\0");
        jumb_payload.extend_from_slice(extra);
        build_box(&BOX_JUMB, &jumb_payload)
    }

    // ─── Spec compliance: Section A.3.9 - JPEG XL container validation ───

    #[test]
    fn test_jxl_container_magic_validation() {
        let container = build_minimal_jxl_container();
        let mut cursor = Cursor::new(&container);
        assert!(is_jxl_container(&mut cursor).unwrap());
    }

    #[test]
    fn test_reject_invalid_magic() {
        let bad_data = vec![0x00; 20];
        let mut cursor = Cursor::new(&bad_data);
        assert!(!is_jxl_container(&mut cursor).unwrap());
    }

    #[test]
    fn test_detect_naked_codestream() {
        let naked = vec![0xff, 0x0a, 0x00, 0x00, 0x00];
        let mut cursor = Cursor::new(&naked);
        assert!(is_naked_codestream(&mut cursor).unwrap());
    }

    #[test]
    fn test_reject_naked_codestream_for_c2pa() {
        let naked = vec![0xff, 0x0a, 0x00, 0x00, 0x00];
        let mut cursor = Cursor::new(&naked);
        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.read_cai(&mut cursor);
        assert!(matches!(result, Err(Error::InvalidAsset(_))));
    }

    // ─── Spec compliance: multiple jumb boxes / label-based identification ───

    /// Builds a minimal `jumd` description box payload for use inside a `jumb` box.
    /// `label` must be a null-terminated ASCII string, e.g. `b"c2pa\0"`.
    fn build_jumd_box(label: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 16]); // UUID (all-zeros for test purposes)
        payload.push(0x03); // toggles: requestable (bit 0) + label present (bit 1)
        payload.extend_from_slice(label); // null-terminated label
        build_box(b"jumd", &payload)
    }

    /// Builds a `jumb` BMFF box whose first inner box is a `jumd` with the given label.
    fn build_labeled_jumb(label: &[u8]) -> Vec<u8> {
        build_box(&BOX_JUMB, &build_jumd_box(label))
    }

    /// Two `jumb` boxes with non-C2PA payloads → no C2PA manifest store found.
    #[test]
    fn test_multiple_non_c2pa_jumb_boxes_returns_not_found() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);
        let jumb_box1 = build_box(&BOX_JUMB, b"raw_payload_1");
        let jumb_box2 = build_box(&BOX_JUMB, b"raw_payload_2");
        let jxlc_box = build_box(&BOX_JXLC, &[0xff, 0x0a, 0x00]);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&jumb_box1);
        container.extend_from_slice(&jumb_box2);
        container.extend_from_slice(&jxlc_box);

        let mut cursor = Cursor::new(&container);
        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.read_cai(&mut cursor);
        assert!(matches!(result, Err(Error::JumbfNotFound)));
    }

    /// Two `jumb` boxes both labelled `"c2pa"` → TooManyManifestStores.
    #[test]
    fn test_reject_two_c2pa_jumb_boxes() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);
        let jumb_box1 = build_labeled_jumb(b"c2pa\0");
        let jumb_box2 = build_labeled_jumb(b"c2pa\0");
        let jxlc_box = build_box(&BOX_JXLC, &[0xff, 0x0a, 0x00]);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&jumb_box1);
        container.extend_from_slice(&jumb_box2);
        container.extend_from_slice(&jxlc_box);

        let mut cursor = Cursor::new(&container);
        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.read_cai(&mut cursor);
        assert!(matches!(result, Err(Error::TooManyManifestStores)));
    }

    /// A non-C2PA `jumb` box (e.g. EXIF) alongside a C2PA `jumb` box → the C2PA
    /// box is returned and the non-C2PA box is preserved through write/remove cycles.
    #[test]
    fn test_read_c2pa_jumb_alongside_non_c2pa_jumb() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

        // Non-C2PA jumb (EXIF label) — content after the jumd is opaque test data
        let exif_jumb = build_labeled_jumb(b"EXIF\0");

        // C2PA jumb: jumd + some fake manifest bytes appended as payload
        let mut c2pa_payload = build_jumd_box(b"c2pa\0");
        c2pa_payload.extend_from_slice(b"fake_manifest_bytes");
        let c2pa_jumb = build_box(&BOX_JUMB, &c2pa_payload);

        let jxlc_box = build_box(&BOX_JXLC, &[0xff, 0x0a, 0x00]);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&exif_jumb);
        container.extend_from_slice(&c2pa_jumb);
        container.extend_from_slice(&jxlc_box);

        // read_cai should return the complete C2PA jumb box
        let mut cursor = Cursor::new(&container);
        let jpegxl_io = JpegXlIO {};
        let data = jpegxl_io.read_cai(&mut cursor).unwrap();
        assert_eq!(data, c2pa_jumb);

        // remove_cai_store_from_stream should preserve the EXIF jumb
        let mut input = Cursor::new(container.clone());
        let mut output = Cursor::new(Vec::new());
        jpegxl_io
            .remove_cai_store_from_stream(&mut input, &mut output)
            .unwrap();
        output.rewind().unwrap();
        let out_boxes = parse_all_boxes(&mut output).unwrap();
        let jumb_count = out_boxes.iter().filter(|b| b.box_type == BOX_JUMB).count();
        assert_eq!(
            jumb_count, 1,
            "EXIF jumb should be preserved after C2PA removal"
        );
    }

    /// write_cai on a file with a non-C2PA `jumb` box preserves that box and
    /// inserts a new C2PA `jumb` box alongside it.
    #[test]
    fn test_write_cai_preserves_non_c2pa_jumb() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);
        let exif_jumb = build_labeled_jumb(b"EXIF\0");
        let jxlc_box = build_box(&BOX_JXLC, &[0xff, 0x0a, 0x00]);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&exif_jumb);
        container.extend_from_slice(&jxlc_box);

        // Build a complete C2PA jumb box as write_cai expects
        let c2pa_payload = c2pa_store(b"stub_c2pa_data");

        let jpegxl_io = JpegXlIO {};
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_payload)
            .unwrap();

        output.rewind().unwrap();
        let out_boxes = parse_all_boxes(&mut output).unwrap();
        let jumb_count = out_boxes.iter().filter(|b| b.box_type == BOX_JUMB).count();
        assert_eq!(
            jumb_count, 2,
            "both EXIF and C2PA jumb boxes should be present"
        );
    }

    // ─── Box parsing tests ───

    #[test]
    fn test_parse_minimal_container_boxes() {
        let container = build_minimal_jxl_container();
        let mut cursor = Cursor::new(&container);
        let boxes = parse_all_boxes(&mut cursor).unwrap();

        // Should have: JXL signature, ftyp, jxlc
        assert_eq!(boxes.len(), 3);
        assert_eq!(boxes[0].box_type, *b"JXL ");
        assert_eq!(boxes[1].box_type, BOX_FTYP);
        assert_eq!(boxes[2].box_type, BOX_JXLC);
    }

    #[test]
    fn test_parse_box_offsets_and_sizes() {
        let container = build_minimal_jxl_container();
        let mut cursor = Cursor::new(&container);
        let boxes = parse_all_boxes(&mut cursor).unwrap();

        // First box is always at offset 0 with size 12 (JXL signature)
        assert_eq!(boxes[0].offset, 0);
        assert_eq!(boxes[0].total_size, 12);
        assert_eq!(boxes[0].header_size, BOX_HEADER_SIZE);

        // ftyp follows at offset 12
        assert_eq!(boxes[1].offset, 12);
    }

    #[test]
    fn test_last_box_extends_to_eof() {
        // Build a container where the last box has size=0 (extends to EOF)
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);

        // Manually add a box with size=0 (extends to EOF)
        container.write_u32::<BigEndian>(0).unwrap(); // size = 0
        container.extend_from_slice(&BOX_JXLC);
        container.extend_from_slice(&[0xff, 0x0a, 0x00, 0x01, 0x02]);

        let file_len = container.len() as u64;
        let mut cursor = Cursor::new(&container);
        let boxes = parse_all_boxes(&mut cursor).unwrap();

        let last = boxes.last().unwrap();
        assert_eq!(last.box_type, BOX_JXLC);
        assert_eq!(last.total_size, 0); // signals extends-to-EOF
        assert_eq!(last.end(file_len), file_len);
    }

    #[test]
    fn test_large_box_header() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);

        // Add a box with extended size (size field = 1)
        let payload = vec![0xaa; 10];
        let large_total: u64 = BOX_HEADER_SIZE_LARGE + payload.len() as u64;
        container.write_u32::<BigEndian>(1).unwrap();
        container.extend_from_slice(&BOX_JXLC);
        container.write_u64::<BigEndian>(large_total).unwrap();
        container.extend_from_slice(&payload);

        let mut cursor = Cursor::new(&container);
        let boxes = parse_all_boxes(&mut cursor).unwrap();

        let jxlc = boxes.iter().find(|b| b.box_type == BOX_JXLC).unwrap();
        assert_eq!(jxlc.header_size, BOX_HEADER_SIZE_LARGE);
        assert_eq!(jxlc.total_size, large_total);
    }

    // ─── Read/Write C2PA store tests ───

    #[test]
    fn test_write_and_read_cai_roundtrip() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let store_bytes = c2pa_store(b"test_c2pa_manifest_store_data");

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &store_bytes)
            .unwrap();

        // Read back
        output.rewind().unwrap();
        let read_back = jpegxl_io.read_cai(&mut output).unwrap();
        assert_eq!(read_back, store_bytes);
    }

    #[test]
    fn test_write_cai_replaces_existing() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut intermediate = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};

        // Write first manifest
        let store1 = c2pa_store(b"first_manifest_store");
        jpegxl_io
            .write_cai(&mut input, &mut intermediate, &store1)
            .unwrap();

        // Write second manifest (should replace)
        intermediate.rewind().unwrap();
        let mut final_output = Cursor::new(Vec::new());
        let store2 = c2pa_store(b"second_manifest_store_replaced");
        jpegxl_io
            .write_cai(&mut intermediate, &mut final_output, &store2)
            .unwrap();

        // Read back - should only get the second manifest
        final_output.rewind().unwrap();
        let read_back = jpegxl_io.read_cai(&mut final_output).unwrap();
        assert_eq!(read_back, store2);
    }

    #[test]
    fn test_write_cai_maintains_container_validity() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b""))
            .unwrap();

        // Verify output is still a valid JXL container
        output.rewind().unwrap();
        assert!(is_jxl_container(&mut output).unwrap());

        // Verify all expected boxes are present
        output.rewind().unwrap();
        let boxes = parse_all_boxes(&mut output).unwrap();
        let types: Vec<[u8; 4]> = boxes.iter().map(|b| b.box_type).collect();

        assert!(types.contains(b"JXL "));
        assert!(types.contains(&BOX_FTYP));
        assert!(types.contains(&BOX_JUMB));
        assert!(types.contains(&BOX_JXLC));
    }

    #[test]
    fn test_jumb_placement_before_codestream() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b""))
            .unwrap();

        output.rewind().unwrap();
        let boxes = parse_all_boxes(&mut output).unwrap();

        let jumb_idx = boxes.iter().position(|b| b.box_type == BOX_JUMB).unwrap();
        let jxlc_idx = boxes.iter().position(|b| b.box_type == BOX_JXLC).unwrap();
        let ftyp_idx = boxes.iter().position(|b| b.box_type == BOX_FTYP).unwrap();

        // jumb should be after ftyp and before jxlc
        assert!(jumb_idx > ftyp_idx, "jumb must come after ftyp");
        assert!(jumb_idx < jxlc_idx, "jumb must come before jxlc");
    }

    // ─── Remove C2PA store tests ───

    #[test]
    fn test_remove_cai_store() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut with_manifest = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};

        // Add manifest
        jpegxl_io
            .write_cai(&mut input, &mut with_manifest, &c2pa_store(b""))
            .unwrap();

        // Remove it
        with_manifest.rewind().unwrap();
        let mut without_manifest = Cursor::new(Vec::new());
        jpegxl_io
            .remove_cai_store_from_stream(&mut with_manifest, &mut without_manifest)
            .unwrap();

        // Verify it's gone
        without_manifest.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut without_manifest);
        assert!(matches!(result, Err(Error::JumbfNotFound)));

        // Verify the container is still valid
        without_manifest.rewind().unwrap();
        assert!(is_jxl_container(&mut without_manifest).unwrap());
    }

    #[test]
    fn test_remove_cai_from_container_without_manifest() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container.clone());
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .remove_cai_store_from_stream(&mut input, &mut output)
            .unwrap();

        // Output should still be a valid container
        output.rewind().unwrap();
        assert!(is_jxl_container(&mut output).unwrap());
    }

    // ─── XMP (xml box) tests ───

    #[test]
    fn test_read_xmp_from_xml_box() {
        let xmp_content = "<x:xmpmeta>test xmp content</x:xmpmeta>";
        let container = build_jxl_with_xmp(xmp_content);
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let xmp = jpegxl_io.read_xmp(&mut cursor);
        assert_eq!(xmp.unwrap(), xmp_content);
    }

    #[test]
    fn test_read_xmp_none_when_missing() {
        let container = build_minimal_jxl_container();
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let xmp = jpegxl_io.read_xmp(&mut cursor);
        assert!(xmp.is_none());
    }

    #[test]
    fn test_read_xmp_from_brob_wrapped_xml() -> Result<()> {
        let xmp_content = "<x:xmpmeta>brob-wrapped xmp content</x:xmpmeta>";
        let container = build_jxl_with_brob_xmp(xmp_content)?;
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let xmp = jpegxl_io.read_xmp(&mut cursor);
        assert_eq!(xmp.unwrap(), xmp_content);
        Ok(())
    }

    // ─── brob (Brotli-compressed) box tests ───

    #[test]
    fn test_brob_wrapped_jumb_not_supported() -> Result<()> {
        // brob-wrapped jumb is intentionally not supported because compressed
        // manifests are incompatible with box-based hashing (C2PA Guidance §3.2.4).
        let manifest_data = b"brob_compressed_manifest_store";
        let container = build_jxl_with_brob_jumb(manifest_data)?;
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.read_cai(&mut cursor);
        assert!(
            matches!(result, Err(Error::JumbfNotFound)),
            "brob-wrapped jumb should not be read as a C2PA manifest"
        );
        Ok(())
    }

    #[test]
    fn test_brob_decompression_basic() {
        let original_data = b"Hello, JPEG XL Brotli world!";
        let mut compressed = Vec::new();
        let params = brotli::enc::BrotliEncoderParams::default();
        brotli::BrotliCompress(
            &mut Cursor::new(original_data.as_ref()),
            &mut compressed,
            &params,
        )
        .unwrap();

        // Build brob payload: original_type + compressed_data
        let mut brob_payload = Vec::new();
        brob_payload.extend_from_slice(&BOX_XML);
        brob_payload.extend_from_slice(&compressed);

        let mut cursor = Cursor::new(&brob_payload);
        let (orig_type, decompressed) =
            decompress_brob(&mut cursor, brob_payload.len() as u64).unwrap();

        assert_eq!(orig_type, BOX_XML);
        assert_eq!(decompressed, original_data);
    }

    #[test]
    fn test_remove_preserves_brob_wrapped_jumb() -> Result<()> {
        // brob-wrapped jumb is treated as opaque data, so remove_cai_store
        // should NOT remove it (it's not recognized as a C2PA manifest).
        let manifest_data = b"manifest_to_remove";
        let container = build_jxl_with_brob_jumb(manifest_data)?;
        let original_len = container.len();
        let mut input = Cursor::new(&container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .remove_cai_store_from_stream(&mut input, &mut output)
            .unwrap();

        // The brob box should still be present (not removed)
        output.rewind().unwrap();
        let boxes = parse_all_boxes(&mut output).unwrap();
        assert!(
            boxes.iter().any(|b| b.box_type == BOX_BROB),
            "brob box should be preserved as opaque data"
        );
        assert_eq!(
            output.get_ref().len(),
            original_len,
            "output should be same size since nothing was removed"
        );
        Ok(())
    }

    // ─── Object locations (hash positions) tests ───

    #[test]
    fn test_object_locations_include_cai() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b""))
            .unwrap();

        output.rewind().unwrap();
        let locations = jpegxl_io
            .get_object_locations_from_stream(&mut output)
            .unwrap();

        let cai_loc = locations
            .iter()
            .find(|l| l.htype == HashBlockObjectType::Cai);
        assert!(cai_loc.is_some(), "Should have a Cai hash object");
        assert!(cai_loc.unwrap().length > 0);
    }

    #[test]
    fn test_object_locations_non_overlapping() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b""))
            .unwrap();

        output.rewind().unwrap();
        let locations = jpegxl_io
            .get_object_locations_from_stream(&mut output)
            .unwrap();

        // Verify no overlapping ranges
        for (i, loc_a) in locations.iter().enumerate() {
            for loc_b in locations.iter().skip(i + 1) {
                let a_end = loc_a.offset + loc_a.length;
                let b_end = loc_b.offset + loc_b.length;
                assert!(
                    a_end <= loc_b.offset || b_end <= loc_a.offset,
                    "Hash object locations should not overlap: [{}, {}) vs [{}, {})",
                    loc_a.offset,
                    a_end,
                    loc_b.offset,
                    b_end
                );
            }
        }
    }

    // ─── Box hash (AssetBoxHash) tests ───

    #[test]
    fn test_box_map_contains_c2pa_entry() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b""))
            .unwrap();

        output.rewind().unwrap();
        let box_map = jpegxl_io.get_box_map(&mut output).unwrap();

        let c2pa_entry = box_map.iter().find(|bm| bm.names[0] == C2PA_BOXHASH);
        assert!(c2pa_entry.is_some(), "Box map must contain C2PA entry");
        assert!(c2pa_entry.unwrap().range_len > 0);
    }

    #[test]
    fn test_box_map_covers_entire_file() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b""))
            .unwrap();

        let file_len = output.get_ref().len() as u64;
        output.rewind().unwrap();
        let box_map = jpegxl_io.get_box_map(&mut output).unwrap();

        // Sum of all box ranges should equal file length
        let total_coverage: u64 = box_map.iter().map(|bm| bm.range_len).sum();
        assert_eq!(
            total_coverage, file_len,
            "Box map should cover the entire file"
        );
    }

    #[test]
    fn test_box_map_ordered_by_offset() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b""))
            .unwrap();

        output.rewind().unwrap();
        let box_map = jpegxl_io.get_box_map(&mut output).unwrap();

        for i in 1..box_map.len() {
            assert!(
                box_map[i].range_start >= box_map[i - 1].range_start + box_map[i - 1].range_len,
                "Box map entries must be ordered by offset and non-overlapping"
            );
        }
    }

    #[test]
    fn test_box_map_brob_jumb_not_marked_as_c2pa() -> Result<()> {
        // brob-wrapped jumb is treated as opaque data for hashing, so it should
        // NOT be marked as C2PA_BOXHASH in the box map.
        let manifest_data = b"brob_wrapped_manifest";
        let container = build_jxl_with_brob_jumb(manifest_data)?;
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let box_map = jpegxl_io.get_box_map(&mut cursor).unwrap();

        let c2pa_entries: Vec<_> = box_map
            .iter()
            .filter(|bm| bm.names[0] == C2PA_BOXHASH)
            .collect();
        assert_eq!(
            c2pa_entries.len(),
            0,
            "brob-wrapped jumb should NOT be identified as C2PA"
        );

        // The brob box should appear as a regular "brob" entry
        let brob_entries: Vec<_> = box_map.iter().filter(|bm| bm.names[0] == "brob").collect();
        assert_eq!(
            brob_entries.len(),
            1,
            "brob box should appear as opaque data"
        );
        Ok(())
    }

    // ─── Remote reference (XMP embedding) tests ───

    #[test]
    fn test_embed_xmp_reference_to_stream() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .embed_reference_to_stream(
                &mut input,
                &mut output,
                RemoteRefEmbedType::Xmp("https://example.com/manifest".to_string()),
            )
            .unwrap();

        // Read back XMP
        output.rewind().unwrap();
        let xmp = jpegxl_io.read_xmp(&mut output).unwrap();
        assert!(xmp.contains("https://example.com/manifest"));
    }

    #[test]
    fn test_embed_xmp_reference_updates_existing() {
        let xmp_content = MIN_XMP;
        let container = build_jxl_with_xmp(xmp_content);
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .embed_reference_to_stream(
                &mut input,
                &mut output,
                RemoteRefEmbedType::Xmp("https://example.com/updated".to_string()),
            )
            .unwrap();

        output.rewind().unwrap();
        let xmp = jpegxl_io.read_xmp(&mut output).unwrap();
        assert!(xmp.contains("https://example.com/updated"));
    }

    #[test]
    fn test_embed_xmp_preserves_compression() -> Result<()> {
        // Source file has brob-compressed XMP; the write path must write it back
        // compressed so the file format is round-tripped faithfully.
        let original_xmp = MIN_XMP;
        let container = build_jxl_with_brob_xmp(original_xmp)?;
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .embed_reference_to_stream(
                &mut input,
                &mut output,
                RemoteRefEmbedType::Xmp("https://example.com/brob-preserved".to_string()),
            )
            .unwrap();

        // Verify the output still uses a brob box (not a plain xml box)
        output.rewind().unwrap();
        let out_buf = output.get_ref();
        let boxes = parse_all_boxes(&mut Cursor::new(out_buf)).unwrap();
        assert!(
            !boxes.iter().any(|b| b.box_type == BOX_XML),
            "output should not contain a plain xml box when source was compressed"
        );
        assert!(
            boxes.iter().any(|b| b.box_type == BOX_BROB),
            "output should contain a brob box preserving the original compression"
        );

        // Verify the XMP content was correctly updated
        output.rewind().unwrap();
        let xmp = jpegxl_io.read_xmp(&mut output).unwrap();
        assert!(
            xmp.contains("https://example.com/brob-preserved"),
            "updated provenance URI should be readable from the compressed box"
        );
        Ok(())
    }

    #[test]
    fn test_embed_stego_unsupported() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.embed_reference_to_stream(
            &mut input,
            &mut output,
            RemoteRefEmbedType::StegoS("test".to_string()),
        );
        assert!(matches!(result, Err(Error::UnsupportedType)));
    }

    // ─── Composed manifest tests ───

    #[test]
    fn test_composed_manifest() {
        let manifest_data = b"test_manifest_for_composition";
        let jpegxl_io = JpegXlIO {};
        let composed = jpegxl_io.compose_manifest(manifest_data, "jxl").unwrap();

        // Verify it's a properly formatted ISOBMFF box
        let mut cursor = Cursor::new(&composed);
        let size = cursor.read_u32::<BigEndian>().unwrap();
        let mut box_type = [0u8; 4];
        cursor.read_exact(&mut box_type).unwrap();

        assert_eq!(size as usize, composed.len());
        assert_eq!(box_type, BOX_JUMB);

        // Payload should be the manifest data
        let mut payload = vec![0u8; manifest_data.len()];
        cursor.read_exact(&mut payload).unwrap();
        assert_eq!(payload, manifest_data);
    }

    #[test]
    fn test_composed_manifest_roundtrip() {
        let container = build_minimal_jxl_container();

        let jpegxl_io = JpegXlIO {};

        // First, write a manifest
        let original_manifest = c2pa_store(b"roundtrip_manifest_data");
        let mut input = Cursor::new(container);
        let mut with_manifest = Cursor::new(Vec::new());
        jpegxl_io
            .write_cai(&mut input, &mut with_manifest, &original_manifest)
            .unwrap();

        // Read it back
        with_manifest.rewind().unwrap();
        let curr_manifest = jpegxl_io.read_cai(&mut with_manifest).unwrap();
        assert_eq!(curr_manifest, original_manifest);

        // Compose it
        let composed = jpegxl_io.compose_manifest(&curr_manifest, "jxl").unwrap();

        // Verify the composed data can be parsed as a valid jumb box
        let mut c = Cursor::new(&composed);
        let header = read_box_header(&mut c).unwrap().unwrap();
        assert_eq!(header.box_type, BOX_JUMB);
        assert_eq!(header.total_size as usize, composed.len());
    }

    // ─── Supported types tests ───

    #[test]
    fn test_supported_types() {
        let jpegxl_io = JpegXlIO {};
        let types = jpegxl_io.supported_types();
        assert!(types.contains(&"jxl"));
        assert!(types.contains(&"image/jxl"));
    }

    #[test]
    fn test_handler_provides_writer() {
        let jpegxl_io = JpegXlIO {};
        assert!(jpegxl_io.get_writer("jxl").is_some());
        assert!(jpegxl_io.get_writer("image/jxl").is_some());
    }

    #[test]
    fn test_handler_provides_box_hash() {
        let jpegxl_io = JpegXlIO {};
        assert!(jpegxl_io.asset_box_hash_ref().is_some());
    }

    #[test]
    fn test_handler_provides_remote_ref() {
        let jpegxl_io = JpegXlIO {};
        assert!(jpegxl_io.remote_ref_writer_ref().is_some());
    }

    #[test]
    fn test_handler_provides_composed_data() {
        let jpegxl_io = JpegXlIO {};
        assert!(jpegxl_io.composed_data_ref().is_some());
    }

    // ─── Edge cases ───

    #[test]
    fn test_minimal_manifest_store() {
        // A store with only a jumd "c2pa" box and no additional content is the smallest
        // valid C2PA manifest store that can be identified by jumb_data_has_c2pa_label.
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let minimal_store = c2pa_store(&[]);
        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &minimal_store)
            .unwrap();

        output.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut output).unwrap();
        assert_eq!(result, minimal_store);
    }

    #[test]
    fn test_read_from_container_without_manifest() {
        let container = build_minimal_jxl_container();
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.read_cai(&mut cursor);
        assert!(matches!(result, Err(Error::JumbfNotFound)));
    }

    #[test]
    fn test_write_cai_to_invalid_data() {
        let bad_data = vec![0x00; 20];
        let mut input = Cursor::new(bad_data);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.write_cai(&mut input, &mut output, b"test");
        assert!(matches!(result, Err(Error::InvalidAsset(_))));
    }

    #[test]
    fn test_container_with_exif_box() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);
        let exif_box = build_box(&BOX_EXIF, b"exif_data_here");
        let jxlc_box = build_box(&BOX_JXLC, &[0xff, 0x0a, 0x00]);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&exif_box);
        container.extend_from_slice(&jxlc_box);

        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let store = c2pa_store(b"manifest_with_exif");
        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &store)
            .unwrap();

        output.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut output).unwrap();
        assert_eq!(result, store);

        // Exif box should still be present
        output.rewind().unwrap();
        let boxes = parse_all_boxes(&mut output).unwrap();
        assert!(boxes.iter().any(|b| b.box_type == BOX_EXIF));
    }

    #[test]
    fn test_container_with_multiple_metadata_boxes() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);
        let exif_box = build_box(&BOX_EXIF, b"exif_data");
        let xml_box = build_box(&BOX_XML, b"<xmp>data</xmp>");
        let jxlc_box = build_box(&BOX_JXLC, &[0xff, 0x0a, 0x00]);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&exif_box);
        container.extend_from_slice(&xml_box);
        container.extend_from_slice(&jxlc_box);

        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b""))
            .unwrap();

        output.rewind().unwrap();
        let boxes = parse_all_boxes(&mut output).unwrap();

        // All boxes should be preserved
        assert!(boxes.iter().any(|b| b.box_type == BOX_EXIF));
        assert!(boxes.iter().any(|b| b.box_type == BOX_XML));
        assert!(boxes.iter().any(|b| b.box_type == BOX_JUMB));
        assert!(boxes.iter().any(|b| b.box_type == BOX_JXLC));
    }

    #[test]
    fn test_large_manifest_store() {
        let container = build_minimal_jxl_container();
        let large_manifest = c2pa_store(&vec![0xab; 256 * 1024]); // 256 KB payload

        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &large_manifest)
            .unwrap();

        output.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut output).unwrap();
        assert_eq!(result, large_manifest);
    }

    // ─── File-based tests (gated on file_io) ───

    #[test]
    fn test_file_save_and_read() {
        let container = build_minimal_jxl_container();
        let temp_dir = tempdirectory().unwrap();
        let test_path = temp_dir.path().join("test.jxl");

        std::fs::write(&test_path, &container).unwrap();

        let jpegxl_io = JpegXlIO {};
        let store_bytes = c2pa_store(b"file_based_manifest_store");
        jpegxl_io.save_cai_store(&test_path, &store_bytes).unwrap();

        let read_back = jpegxl_io.read_cai_store(&test_path).unwrap();
        assert_eq!(read_back, store_bytes);
    }

    #[test]
    fn test_file_remove_cai_store() {
        let container = build_minimal_jxl_container();
        let temp_dir = tempdirectory().unwrap();
        let test_path = temp_dir.path().join("test_remove.jxl");

        std::fs::write(&test_path, &container).unwrap();

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .save_cai_store(&test_path, &c2pa_store(b"to_be_removed"))
            .unwrap();

        jpegxl_io.remove_cai_store(&test_path).unwrap();

        let result = jpegxl_io.read_cai_store(&test_path);
        assert!(matches!(result, Err(Error::JumbfNotFound)));
    }

    #[test]
    fn test_file_object_locations() {
        let container = build_minimal_jxl_container();
        let temp_dir = tempdirectory().unwrap();
        let test_path = temp_dir.path().join("test_locations.jxl");

        std::fs::write(&test_path, &container).unwrap();

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .save_cai_store(&test_path, &c2pa_store(b"manifest_for_locations"))
            .unwrap();

        let locations = jpegxl_io.get_object_locations(&test_path).unwrap();
        assert!(locations
            .iter()
            .any(|l| l.htype == HashBlockObjectType::Cai));
    }

    // ─── Spec compliance: container with jxlp (partial codestream) ───

    #[test]
    fn test_container_with_jxlp_boxes() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

        // Partial codestream boxes (jxlp has a 4-byte counter prefix)
        let mut jxlp1_data = Vec::new();
        jxlp1_data.write_u32::<BigEndian>(0).unwrap(); // counter = 0
        jxlp1_data.extend_from_slice(&[0xff, 0x0a]);
        let jxlp1_box = build_box(&BOX_JXLP, &jxlp1_data);

        let mut jxlp2_data = Vec::new();
        jxlp2_data.write_u32::<BigEndian>(0x80000001).unwrap(); // counter with last-box bit
        jxlp2_data.extend_from_slice(&[0x00, 0x01]);
        let jxlp2_box = build_box(&BOX_JXLP, &jxlp2_data);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&jxlp1_box);
        container.extend_from_slice(&jxlp2_box);

        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &c2pa_store(b"manifest_with_jxlp"))
            .unwrap();

        // jumb should be inserted before the first jxlp
        output.rewind().unwrap();
        let boxes = parse_all_boxes(&mut output).unwrap();
        let jumb_idx = boxes.iter().position(|b| b.box_type == BOX_JUMB).unwrap();
        let jxlp_idx = boxes.iter().position(|b| b.box_type == BOX_JXLP).unwrap();
        assert!(jumb_idx < jxlp_idx);

        output.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut output).unwrap();
        assert_eq!(result, c2pa_store(b"manifest_with_jxlp"));
    }

    // ─── End-to-end integration test: sign → read → validate hash layout ───

    /// Full end-to-end integration test using a real JPEG XL asset.
    ///
    /// Covers three independent validation phases:
    ///
    /// 1. **Write** — A C2PA manifest with multiple assertions (action + metadata) is
    ///    embedded in `sample1.jxl` using the standard `Builder` signing pipeline
    ///    and an Ed25519 `CallbackSigner`.
    ///
    /// 2. **Read & claim validation** — The signed bytes are parsed with `Reader`.
    ///    The test asserts that:
    ///    - The active manifest carries the expected title and format.
    ///    - Both the `c2pa.actions` and `c2pa.hash` assertions are present.
    ///    - No hard validation failures exist (only `signingCredential.untrusted`
    ///      is accepted, because the test CA is self-signed).
    ///    - Claim-signature validation succeeded (signature is cryptographically
    ///      valid even though the cert is not in a production trust store).
    ///
    /// 3. **Hash location consistency** — The test calls both
    ///    `get_object_locations_from_stream` and `get_box_map` on the signed
    ///    bytes and verifies:
    ///    - `get_object_locations_from_stream`: every byte of the file is
    ///      assigned to exactly one hash object (full coverage, no gaps, no
    ///      overlaps); exactly one object is tagged `HashBlockObjectType::Cai`.
    ///    - `get_box_map`: the box map covers the entire file; entries are
    ///      ordered and non-overlapping; exactly one entry carries the
    ///      `C2PA_BOXHASH` label; all non-excluded, non-CAI boxes carry a
    ///      non-empty hash.
    #[test]
    fn test_e2e_jpegxl_sign_read_validate() -> crate::error::Result<()> {
        // ── Test fixtures ────────────────────────────────────────────────────────
        static SAMPLE_JXL: &[u8] = include_bytes!("../../tests/fixtures/sample1.jxl");
        static CERTS: &[u8] = include_bytes!("../../tests/fixtures/certs/ed25519.pub");
        static PRIVATE_KEY: &[u8] = include_bytes!("../../tests/fixtures/certs/ed25519.pem");

        // Ed25519 signing helper (same pattern used in v2_api_integration.rs)
        fn ed_sign(data: &[u8], private_key: &[u8]) -> crate::error::Result<Vec<u8>> {
            use ed25519_dalek::{Signature, Signer, SigningKey};
            use pem::parse;
            let pem = parse(private_key).map_err(|e| crate::Error::OtherError(Box::new(e)))?;
            // Ed25519 PKCS#8 private key: skip the 16-byte ASN.1 prefix.
            let key_bytes = &pem.contents()[16..];
            let signing_key = SigningKey::try_from(key_bytes)
                .map_err(|e| crate::Error::OtherError(Box::new(e)))?;
            let signature: Signature = signing_key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }

        // ── Phase 1: Write a C2PA manifest into a real JPEG XL asset ────────────

        // Load the test trust anchors and verification settings so that the
        // Ed25519 test certificate is trusted during read-back.
        crate::Settings::from_toml(include_str!("../../tests/fixtures/test_settings.toml"))?;

        let signer_fn = |_ctx: *const (), data: &[u8]| ed_sign(data, PRIVATE_KEY);
        let signer = crate::CallbackSigner::new(signer_fn, crate::SigningAlg::Ed25519, CERTS);

        let manifest_json = serde_json::json!({
            "title": "E2E JPEG XL Integration Test",
            "format": "image/jxl",
            "claim_generator_info": [
                { "name": "jpegxl_e2e_test", "version": "0.1.0" }
            ],
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "digitalSourceType":
                                    "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
                                "softwareAgent": {
                                    "name": "jpegxl_e2e_test",
                                    "version": "0.1.0"
                                }
                            }
                        ]
                    }
                },
                {
                    "label": "c2pa.metadata",
                    "data": {
                        "@context": {
                            "exif": "http://ns.adobe.com/exif/1.0/"
                        },
                        "exif:GPSLatitude": "48,51.5N",
                        "exif:GPSLongitude": "2,17.8E"
                    },
                    "kind": "Json"
                }
            ]
        });

        let mut builder = crate::Builder::from_json(&manifest_json.to_string())?;

        let mut source = Cursor::new(SAMPLE_JXL);
        let mut signed = Cursor::new(Vec::new());
        builder.sign(&signer, "image/jxl", &mut source, &mut signed)?;

        // ── Phase 2: Read back and validate manifest claims ──────────────────────

        signed.rewind().unwrap();
        let reader = crate::Reader::from_stream("image/jxl", &mut signed)?;

        // Active manifest must be present.
        let manifest = reader
            .active_manifest()
            .ok_or_else(|| crate::Error::ClaimEncoding)?;

        assert_eq!(
            manifest.title().unwrap_or_default(),
            "E2E JPEG XL Integration Test",
            "manifest title must round-trip correctly"
        );
        // Both the action assertion and the hash assertion must be present.
        let assertions = manifest.assertions();
        assert!(
            assertions
                .iter()
                .any(|a| a.label().starts_with("c2pa.actions")),
            "manifest must contain a c2pa.actions assertion; got: {:?}",
            assertions.iter().map(|a| a.label()).collect::<Vec<_>>()
        );
        // Check validation results: only `signingCredential.untrusted` is
        // acceptable as a failure (test CA is not in the production trust store).
        // All other failure codes indicate a real problem in the signing or
        // embedding pipeline.
        if let Some(results) = reader.validation_results() {
            if let Some(active) = results.active_manifest() {
                let hard_failures: Vec<_> = active
                    .failure()
                    .iter()
                    .filter(|f| f.code() != "signingCredential.untrusted")
                    .collect();
                assert!(
                    hard_failures.is_empty(),
                    "unexpected hard validation failures: {:?}",
                    hard_failures.iter().map(|f| f.code()).collect::<Vec<_>>()
                );

                // Claim signature must be cryptographically valid.
                let sig_validated = active
                    .success()
                    .iter()
                    .any(|s| s.code() == "claimSignature.validated");
                assert!(
                    sig_validated,
                    "claimSignature.validated must be present in success codes"
                );
            }
        }

        // ── Phase 3: Hash location and box-map consistency ───────────────────────

        let signed_bytes = signed.into_inner();
        let file_len = signed_bytes.len() as u64;
        let mut cursor = Cursor::new(&signed_bytes);

        let jpegxl_io = JpegXlIO {};

        // ── 3a. get_object_locations_from_stream ─────────────────────────────────
        //
        // Every byte of the final file must be assigned to exactly one hash
        // object (no gaps, no overlaps).  Exactly one object must carry the
        // `Cai` type (the embedded manifest store).
        let locations = jpegxl_io.get_object_locations_from_stream(&mut cursor)?;

        let mut sorted_locs: Vec<_> = locations.iter().collect();
        sorted_locs.sort_by_key(|l| l.offset);

        // Full coverage: sum of all lengths == file size.
        let total_covered: usize = sorted_locs.iter().map(|l| l.length).sum();
        assert_eq!(
            total_covered, file_len as usize,
            "object locations must cover the entire file ({file_len} bytes total); \
             got {total_covered} bytes covered"
        );

        // No overlaps between adjacent (sorted) ranges.
        for window in sorted_locs.windows(2) {
            let a_end = window[0].offset + window[0].length;
            assert!(
                a_end <= window[1].offset,
                "hash object ranges must not overlap: [{}, {}) and [{}, {})",
                window[0].offset,
                a_end,
                window[1].offset,
                window[1].offset + window[1].length
            );
        }

        // Exactly one CAI slot (the manifest store jumb box).
        let cai_count = sorted_locs
            .iter()
            .filter(|l| l.htype == HashBlockObjectType::Cai)
            .count();
        assert_eq!(
            cai_count, 1,
            "exactly one CAI hash object must be present; found {cai_count}"
        );

        // Every object must carry a recognised hash type.
        for loc in &sorted_locs {
            assert!(
                matches!(
                    loc.htype,
                    HashBlockObjectType::Cai
                        | HashBlockObjectType::Xmp
                        | HashBlockObjectType::Other
                        | HashBlockObjectType::OtherExclusion
                ),
                "unrecognised HashBlockObjectType {:?} at offset {}",
                loc.htype,
                loc.offset
            );
        }

        // ── 3b. get_box_map ──────────────────────────────────────────────────────
        //
        // The box map produced by `AssetBoxHash::get_box_map` must:
        //   - Cover the entire file without gaps or overlaps.
        //   - Contain exactly one entry labelled C2PA_BOXHASH.
        //   - Have non-empty hash bytes for every non-excluded, non-CAI entry.
        cursor.rewind().unwrap();
        let box_map = jpegxl_io.get_box_map(&mut cursor)?;

        // Full file coverage.
        let total_bm: u64 = box_map.iter().map(|bm| bm.range_len).sum();
        assert_eq!(
            total_bm, file_len,
            "box map must cover entire file ({file_len} bytes); got {total_bm} bytes"
        );

        // Entries are ordered (range_start is non-decreasing) and non-overlapping.
        for window in box_map.windows(2) {
            assert!(
                window[0].range_start + window[0].range_len <= window[1].range_start,
                "box map entries must be ordered and non-overlapping: \
                 {:?} [{}, {}) vs {:?} [{}, {})",
                window[0].names,
                window[0].range_start,
                window[0].range_start + window[0].range_len,
                window[1].names,
                window[1].range_start,
                window[1].range_start + window[1].range_len,
            );
        }

        // Exactly one C2PA_BOXHASH entry with a non-zero range.
        let c2pa_entries: Vec<_> = box_map
            .iter()
            .filter(|bm| bm.names.first().is_some_and(|n| n == C2PA_BOXHASH))
            .collect();
        assert_eq!(
            c2pa_entries.len(),
            1,
            "box map must contain exactly one {C2PA_BOXHASH} entry; \
             found {}",
            c2pa_entries.len()
        );
        assert!(
            c2pa_entries[0].range_len > 0,
            "C2PA box map entry must have a non-zero range length"
        );

        Ok(())
    }

    // ── Security tests ────────────────────────────────────────────────────────

    /// A `jumb` box whose declared size is near u64::MAX must be rejected with
    /// `InsufficientMemory` rather than panicking or allocating gigabytes.
    #[test]
    fn test_find_jumb_data_rejects_oversized_box() {
        // Craft a JPEG XL container with a `jumb` box claiming a size of u32::MAX
        // (largest value representable in a standard 4-byte size field).
        let ftyp_box = build_box(&BOX_FTYP, b"jxl \0\0\0\0jxl ");
        let jxlc_box = build_box(&BOX_JXLC, &[0xff, 0x0a, 0x00]);

        // Hand-craft a jumb box with size = u32::MAX (0xFFFFFFFF).
        // Layout: [size:4][type:4] — data payload is "missing" (file is truncated).
        let mut jumb_header = Vec::new();
        jumb_header.extend_from_slice(&u32::MAX.to_be_bytes()); // size = 0xFFFF_FFFF
        jumb_header.extend_from_slice(&BOX_JUMB);
        // No actual data follows — the file is shorter than the declared size.

        let mut container = JXL_CONTAINER_MAGIC.to_vec();
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&jumb_header);
        container.extend_from_slice(&jxlc_box);

        let mut reader = Cursor::new(container);
        let result = find_jumb_data(&mut reader);
        // Must NOT panic; must return an error (InsufficientMemory or IoError).
        assert!(
            result.is_err(),
            "oversized jumb box must be rejected, not cause OOM"
        );
    }

    /// An ISOBMFF box with a crafted `total_size` that would overflow `offset +
    /// total_size` must not cause `parse_all_boxes` to loop or panic.
    #[test]
    fn test_parse_all_boxes_overflow_safe() {
        // Build a container where the first real box (ftyp, at offset 12) carries
        // total_size = u64::MAX - 11. In release mode `12 + (u64::MAX - 11)` wraps to
        // u64::MAX, which is treated as >= file_len and terminates the loop.
        // In debug mode saturating_add prevents the panic entirely.
        let ftyp_data = b"jxl \0\0\0\0jxl ";

        // Hand-craft a ftyp box with size=1 (large-box format) and largesize = u64::MAX.
        let mut overflow_box = Vec::new();
        overflow_box.extend_from_slice(&1u32.to_be_bytes()); // size=1 → large-size form
        overflow_box.extend_from_slice(&BOX_FTYP); // box type
        overflow_box.extend_from_slice(&u64::MAX.to_be_bytes()); // largesize = u64::MAX
        overflow_box.extend_from_slice(ftyp_data); // payload (irrelevant)

        let mut container = JXL_CONTAINER_MAGIC.to_vec();
        container.extend_from_slice(&overflow_box);

        let mut reader = Cursor::new(container);
        // Must terminate without panic or infinite loop; result may be Ok or Err.
        let result = parse_all_boxes(&mut reader);
        // The box is parsed and next_pos = saturating_add(12, u64::MAX) = u64::MAX
        // which is >= file_len, so the loop breaks after one box.
        assert!(
            result.is_ok(),
            "parse_all_boxes should handle overflow-sized box gracefully: {result:?}"
        );
    }

    /// A container with more than MAX_JXL_BOX_COUNT boxes must be rejected.
    #[test]
    fn test_parse_all_boxes_count_limit() {
        // Build a container with MAX_JXL_BOX_COUNT + 1 minimal (8-byte) boxes.
        let mut container = JXL_CONTAINER_MAGIC.to_vec();
        // Each empty box: 4-byte size + 4-byte type = 8 bytes, size = 8.
        let empty_box = build_box(&BOX_FTYP, &[]);
        for _ in 0..=MAX_JXL_BOX_COUNT {
            container.extend_from_slice(&empty_box);
        }

        let mut reader = Cursor::new(container);
        let result = parse_all_boxes(&mut reader);
        assert!(
            matches!(result, Err(Error::InvalidAsset(_))),
            "container with > {MAX_JXL_BOX_COUNT} boxes must be rejected: {result:?}"
        );
    }
}
