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

//! JPEG XL (ISO/IEC 18181-2:2024) asset handler for C2PA embedding.
//!
//! Implements C2PA Specification v2.3, Section A.3.9 - "Embedding manifests into JPEG XL".
//!
//! Key spec requirements:
//! - Only the ISOBMFF-based container form (not naked codestream) can embed C2PA.
//! - The C2PA Manifest Store is embedded as a native `jumb` superbox at the top level.
//! - A JPEG XL file SHALL contain at most one JUMBF superbox.
//! - Uses general box hash (`c2pa.hash.boxes`) for hard binding (non-BMFF classification).
//! - Supports `brob` (Brotli-compressed) boxes for reading metadata.

use std::{
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
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
        io_utils::tempfile_builder,
        xmp_inmemory_utils::{add_provenance, MIN_XMP},
    },
};

// JPEG XL container signature (ISO/IEC 18181-2:2024, Clause 4.1)
// This is itself a box: size=12, type='JXL ' (0x4A584C20), payload=0x0D0A870A
const JXL_CONTAINER_MAGIC: [u8; 12] = [
    0x00, 0x00, 0x00, 0x0C, // size = 12
    0x4A, 0x58, 0x4C, 0x20, // type = 'JXL '
    0x0D, 0x0A, 0x87, 0x0A, // magic payload
];

const JXL_CONTAINER_MAGIC_LEN: u64 = 12;

// Naked codestream signature - cannot embed C2PA manifests
const JXL_CODESTREAM_SIG: [u8; 2] = [0xFF, 0x0A];

// Box type FourCCs (big-endian u32)
const BOX_JUMB: [u8; 4] = *b"jumb"; // JUMBF superbox (C2PA manifest store)
const BOX_XML: [u8; 4] = *b"xml "; // XMP metadata (note trailing space)
const BOX_BROB: [u8; 4] = *b"brob"; // Brotli-compressed metadata box
const BOX_FTYP: [u8; 4] = *b"ftyp"; // File type box
const BOX_JXLC: [u8; 4] = *b"jxlc"; // JPEG XL codestream
const BOX_JXLP: [u8; 4] = *b"jxlp"; // JPEG XL partial codestream
#[cfg(test)]
const BOX_EXIF: [u8; 4] = *b"Exif"; // Exif metadata

const BOX_HEADER_SIZE: u64 = 8; // 4-byte size + 4-byte type
const BOX_HEADER_SIZE_LARGE: u64 = 16; // + 8-byte extended size when size field == 1

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
            self.offset + self.total_size
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
                    info.offset + info.total_size
                };

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
    reader.read_exact(&mut original_type).map_err(Error::IoError)?;

    let compressed_size = data_size.saturating_sub(4);
    let mut compressed = vec![0u8; compressed_size as usize];
    reader.read_exact(&mut compressed).map_err(Error::IoError)?;

    let mut decompressed = Vec::new();
    brotli::BrotliDecompress(&mut Cursor::new(compressed), &mut decompressed)
        .map_err(|_| Error::InvalidAsset("Failed to decompress brob box".to_string()))?;

    Ok((original_type, decompressed))
}

/// Finds the JUMBF data in a JPEG XL container, handling both direct `jumb` boxes
/// and `brob`-compressed `jumb` boxes.
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

    let mut jumb_count = 0u32;
    let mut jumb_data: Option<Vec<u8>> = None;

    for b in &boxes {
        if b.box_type == BOX_JUMB {
            jumb_count += 1;
            if jumb_count > 1 {
                return Err(Error::TooManyManifestStores);
            }
            let ds = b.data_size(file_len);
            reader.seek(SeekFrom::Start(b.data_offset()))?;
            let mut data = vec![0u8; ds as usize];
            reader.read_exact(&mut data).map_err(Error::IoError)?;
            jumb_data = Some(data);
        } else if b.box_type == BOX_BROB {
            reader.seek(SeekFrom::Start(b.data_offset()))?;
            let ds = b.data_size(file_len);
            if ds >= 4 {
                let (orig_type, decompressed) = decompress_brob(reader, ds)?;
                if orig_type == BOX_JUMB {
                    jumb_count += 1;
                    if jumb_count > 1 {
                        return Err(Error::TooManyManifestStores);
                    }
                    jumb_data = Some(decompressed);
                }
            }
        }
    }

    jumb_data.ok_or(Error::JumbfNotFound)
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
            let mut data = vec![0u8; ds as usize];
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
        buf.write_u32::<BigEndian>(total_size as u32).unwrap();
        buf.write_all(box_type).unwrap();
        buf.write_all(data).unwrap();
        buf
    } else {
        // Use large box format
        let total_large = BOX_HEADER_SIZE_LARGE as usize + data.len();
        let mut buf = Vec::with_capacity(total_large);
        buf.write_u32::<BigEndian>(1).unwrap(); // size=1 signals extended size
        buf.write_all(box_type).unwrap();
        buf.write_u64::<BigEndian>(total_large as u64).unwrap();
        buf.write_all(data).unwrap();
        buf
    }
}

/// Rewrites the container, excluding any `jumb` (or `brob`-wrapped `jumb`) boxes.
fn remove_jumb_boxes(reader: &mut dyn CAIRead, writer: &mut dyn CAIReadWrite) -> Result<()> {
    let file_len = reader.seek(SeekFrom::End(0))?;

    if !is_jxl_container(reader)? {
        return Err(Error::InvalidAsset("Not a valid JPEG XL container".to_string()));
    }

    let boxes = parse_all_boxes(reader)?;

    writer.rewind()?;

    for b in &boxes {
        let should_skip = if b.box_type == BOX_JUMB {
            true
        } else if b.box_type == BOX_BROB {
            reader.seek(SeekFrom::Start(b.data_offset()))?;
            let mut orig_type = [0u8; 4];
            reader.read_exact(&mut orig_type).ok().is_some() && orig_type == BOX_JUMB
        } else {
            false
        };

        if !should_skip {
            let box_end = b.end(file_len);
            let box_len = box_end - b.offset;
            reader.seek(SeekFrom::Start(b.offset))?;
            let mut box_data = vec![0u8; box_len as usize];
            reader.read_exact(&mut box_data).map_err(Error::IoError)?;
            writer.write_all(&box_data).map_err(Error::IoError)?;
        }
    }

    Ok(())
}

/// Determines the XMP insertion point (returns offset and length of existing xml box, or
/// offset for insertion if no xml box exists).
fn find_xmp_box_info(boxes: &[JxlBoxInfo], file_len: u64) -> (u64, u64) {
    for b in boxes {
        if b.box_type == BOX_XML {
            return (b.offset, b.end(file_len) - b.offset);
        }
    }
    // Insert after ftyp, before codestream
    (find_jumb_insertion_offset(boxes), 0)
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

        // Collect ranges to remove (jumb boxes and brob-wrapped jumb boxes)
        let mut remove_ranges: Vec<(usize, usize)> = Vec::new();
        for b in &boxes {
            if b.box_type == BOX_JUMB {
                let end = b.end(file_len) as usize;
                remove_ranges.push((b.offset as usize, end));
            } else if b.box_type == BOX_BROB {
                let mut c = Cursor::new(&buf);
                c.seek(SeekFrom::Start(b.data_offset())).ok();
                let mut orig_type = [0u8; 4];
                if c.read_exact(&mut orig_type).is_ok() && orig_type == BOX_JUMB {
                    let end = b.end(file_len) as usize;
                    remove_ranges.push((b.offset as usize, end));
                }
            }
        }

        // Remove in reverse order to preserve indices
        remove_ranges.sort_by(|a, b| b.0.cmp(&a.0));
        for (start, end) in &remove_ranges {
            buf.drain(*start..*end);
        }

        // Re-parse to find insertion point
        let mut cursor = Cursor::new(&buf);
        let boxes = parse_all_boxes(&mut cursor)?;
        let insert_offset = find_jumb_insertion_offset(&boxes) as usize;

        // Build the jumb box
        let jumb_box = build_box(&BOX_JUMB, store_bytes);

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

        let mut positions: Vec<HashObjectPositions> = Vec::new();

        for b in &boxes {
            if b.box_type == BOX_JUMB {
                let total = if b.total_size == 0 {
                    file_len - b.offset
                } else {
                    b.total_size
                };
                positions.push(HashObjectPositions {
                    offset: b.offset as usize,
                    length: total as usize,
                    htype: HashBlockObjectType::Cai,
                });
            } else if b.box_type == BOX_XML {
                let total = if b.total_size == 0 {
                    file_len - b.offset
                } else {
                    b.total_size
                };
                positions.push(HashObjectPositions {
                    offset: b.offset as usize,
                    length: total as usize,
                    htype: HashBlockObjectType::Xmp,
                });
            } else {
                let total = if b.total_size == 0 {
                    file_len - b.offset
                } else {
                    b.total_size
                };
                positions.push(HashObjectPositions {
                    offset: b.offset as usize,
                    length: total as usize,
                    htype: HashBlockObjectType::Other,
                });
            }
        }

        Ok(positions)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        remove_jumb_boxes(input_stream, output_stream)
    }
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

    let has_jumb = boxes.iter().any(|b| b.box_type == BOX_JUMB);

    if !has_jumb {
        let jpegxl_io = JpegXlIO {};
        let no_bytes: Vec<u8> = Vec::new();
        let mut input = Cursor::new(buf);
        jpegxl_io.write_cai(&mut input, output_stream, &no_bytes)?;
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

        remove_jumb_boxes(&mut input_stream, &mut temp_file)?;

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
    fn embed_reference(
        &self,
        asset_path: &Path,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
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
                source_stream.read_to_end(&mut buf).map_err(Error::IoError)?;

                let xmp = match find_xmp_data(source_stream) {
                    Some(s) => s,
                    None => MIN_XMP.to_string(),
                };

                let updated_xmp = add_provenance(&xmp, &manifest_uri)?;
                let xmp_box = build_box(&BOX_XML, updated_xmp.as_bytes());

                let mut cursor = Cursor::new(&buf);
                let boxes = parse_all_boxes(&mut cursor)?;

                let (xmp_offset, xmp_len) = find_xmp_box_info(&boxes, file_len);
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
            return Err(Error::InvalidAsset("Not a valid JPEG XL container".to_string()));
        }

        let boxes = parse_all_boxes(input_stream)?;
        let mut box_maps = Vec::new();

        for b in &boxes {
            let total = if b.total_size == 0 {
                file_len - b.offset
            } else {
                b.total_size
            };

            let name = if b.box_type == BOX_JUMB {
                C2PA_BOXHASH.to_string()
            } else if b.box_type == BOX_BROB {
                // Check if this brob wraps a jumb
                input_stream.seek(SeekFrom::Start(b.data_offset()))?;
                let mut orig_type = [0u8; 4];
                if input_stream.read_exact(&mut orig_type).is_ok() && orig_type == BOX_JUMB {
                    C2PA_BOXHASH.to_string()
                } else {
                    b.type_str()
                }
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

    let jxlc_data = &[0xFF, 0x0A, 0x00]; // minimal codestream stub
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

    let jxlc_data = &[0xFF, 0x0A, 0x00];
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
fn build_jxl_with_brob_jumb(manifest_data: &[u8]) -> Vec<u8> {
    let ftyp_data = b"jxl \0\0\0\0jxl ";
    let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

    // Brotli-compress the manifest data
    let mut compressed = Vec::new();
    {
        let params = brotli::enc::BrotliEncoderParams::default();
        brotli::BrotliCompress(&mut Cursor::new(manifest_data), &mut compressed, &params).unwrap();
    }

    // brob payload = original_type(4) + compressed_data
    let mut brob_payload = Vec::new();
    brob_payload.extend_from_slice(&BOX_JUMB);
    brob_payload.extend_from_slice(&compressed);
    let brob_box = build_box(&BOX_BROB, &brob_payload);

    let jxlc_data = &[0xFF, 0x0A, 0x00];
    let jxlc_box = build_box(&BOX_JXLC, jxlc_data);

    let mut container = Vec::new();
    container.extend_from_slice(&JXL_CONTAINER_MAGIC);
    container.extend_from_slice(&ftyp_box);
    container.extend_from_slice(&brob_box);
    container.extend_from_slice(&jxlc_box);
    container
}

/// Builds a JPEG XL container with a `brob`-wrapped `xml ` box.
#[cfg(test)]
fn build_jxl_with_brob_xmp(xmp_data: &str) -> Vec<u8> {
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
        .unwrap();
    }

    let mut brob_payload = Vec::new();
    brob_payload.extend_from_slice(&BOX_XML);
    brob_payload.extend_from_slice(&compressed);
    let brob_box = build_box(&BOX_BROB, &brob_payload);

    let jxlc_data = &[0xFF, 0x0A, 0x00];
    let jxlc_box = build_box(&BOX_JXLC, jxlc_data);

    let mut container = Vec::new();
    container.extend_from_slice(&JXL_CONTAINER_MAGIC);
    container.extend_from_slice(&ftyp_box);
    container.extend_from_slice(&brob_box);
    container.extend_from_slice(&jxlc_box);
    container
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Read, Seek};

    use super::*;
    use crate::utils::io_utils::tempdirectory;

    /// Public test helper: builds a minimal JPEG XL container for use in integration tests.
    pub fn build_test_jxl_container() -> Vec<u8> {
        build_minimal_jxl_container()
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
        let naked = vec![0xFF, 0x0A, 0x00, 0x00, 0x00];
        let mut cursor = Cursor::new(&naked);
        assert!(is_naked_codestream(&mut cursor).unwrap());
    }

    #[test]
    fn test_reject_naked_codestream_for_c2pa() {
        let naked = vec![0xFF, 0x0A, 0x00, 0x00, 0x00];
        let mut cursor = Cursor::new(&naked);
        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.read_cai(&mut cursor);
        assert!(matches!(result, Err(Error::InvalidAsset(_))));
    }

    // ─── Spec compliance: at most one JUMBF superbox ───

    #[test]
    fn test_reject_multiple_jumb_boxes() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

        let manifest1 = b"manifest_data_1";
        let jumb_box1 = build_box(&BOX_JUMB, manifest1);
        let manifest2 = b"manifest_data_2";
        let jumb_box2 = build_box(&BOX_JUMB, manifest2);

        let jxlc_box = build_box(&BOX_JXLC, &[0xFF, 0x0A, 0x00]);

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
        container.extend_from_slice(&[0xFF, 0x0A, 0x00, 0x01, 0x02]);

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
        let payload = vec![0xAA; 10];
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

        let store_bytes = b"test_c2pa_manifest_store_data";

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, store_bytes)
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
        let store1 = b"first_manifest_store";
        jpegxl_io
            .write_cai(&mut input, &mut intermediate, store1)
            .unwrap();

        // Write second manifest (should replace)
        intermediate.rewind().unwrap();
        let mut final_output = Cursor::new(Vec::new());
        let store2 = b"second_manifest_store_replaced";
        jpegxl_io
            .write_cai(&mut intermediate, &mut final_output, store2)
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
            .write_cai(&mut input, &mut output, b"manifest_data")
            .unwrap();

        // Verify output is still a valid JXL container
        output.rewind().unwrap();
        assert!(is_jxl_container(&mut output).unwrap());

        // Verify all expected boxes are present
        output.rewind().unwrap();
        let boxes = parse_all_boxes(&mut output).unwrap();
        let types: Vec<[u8; 4]> = boxes.iter().map(|b| b.box_type).collect();

        assert!(types.contains(&*b"JXL "));
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
            .write_cai(&mut input, &mut output, b"manifest")
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
            .write_cai(&mut input, &mut with_manifest, b"test_data")
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
    fn test_read_xmp_from_brob_wrapped_xml() {
        let xmp_content = "<x:xmpmeta>brob-wrapped xmp content</x:xmpmeta>";
        let container = build_jxl_with_brob_xmp(xmp_content);
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let xmp = jpegxl_io.read_xmp(&mut cursor);
        assert_eq!(xmp.unwrap(), xmp_content);
    }

    // ─── brob (Brotli-compressed) box tests ───

    #[test]
    fn test_read_cai_from_brob_wrapped_jumb() {
        let manifest_data = b"brob_compressed_manifest_store";
        let container = build_jxl_with_brob_jumb(manifest_data);
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let result = jpegxl_io.read_cai(&mut cursor).unwrap();
        assert_eq!(result, manifest_data);
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
    fn test_remove_brob_wrapped_jumb() {
        let manifest_data = b"manifest_to_remove";
        let container = build_jxl_with_brob_jumb(manifest_data);
        let mut input = Cursor::new(&container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .remove_cai_store_from_stream(&mut input, &mut output)
            .unwrap();

        output.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut output);
        assert!(matches!(result, Err(Error::JumbfNotFound)));
    }

    // ─── Object locations (hash positions) tests ───

    #[test]
    fn test_object_locations_include_cai() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, b"test_manifest")
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
            .write_cai(&mut input, &mut output, b"manifest_data")
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
            .write_cai(&mut input, &mut output, b"box_hash_test_manifest")
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
            .write_cai(&mut input, &mut output, b"manifest")
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
            .write_cai(&mut input, &mut output, b"manifest")
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
    fn test_box_map_brob_jumb_marked_as_c2pa() {
        let manifest_data = b"brob_wrapped_manifest";
        let container = build_jxl_with_brob_jumb(manifest_data);
        let mut cursor = Cursor::new(&container);

        let jpegxl_io = JpegXlIO {};
        let box_map = jpegxl_io.get_box_map(&mut cursor).unwrap();

        let c2pa_entries: Vec<_> = box_map
            .iter()
            .filter(|bm| bm.names[0] == C2PA_BOXHASH)
            .collect();
        assert_eq!(
            c2pa_entries.len(),
            1,
            "brob-wrapped jumb should be identified as C2PA"
        );
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
        let composed = jpegxl_io
            .compose_manifest(manifest_data, "jxl")
            .unwrap();

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
        let original_manifest = b"roundtrip_manifest_data";
        let mut input = Cursor::new(container);
        let mut with_manifest = Cursor::new(Vec::new());
        jpegxl_io
            .write_cai(&mut input, &mut with_manifest, original_manifest)
            .unwrap();

        // Read it back
        with_manifest.rewind().unwrap();
        let curr_manifest = jpegxl_io.read_cai(&mut with_manifest).unwrap();
        assert_eq!(curr_manifest, original_manifest);

        // Compose it
        let composed = jpegxl_io
            .compose_manifest(&curr_manifest, "jxl")
            .unwrap();

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
    fn test_empty_manifest_store() {
        let container = build_minimal_jxl_container();
        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, &[])
            .unwrap();

        // Should still be readable (empty jumb box)
        output.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut output).unwrap();
        assert!(result.is_empty());
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
        let jxlc_box = build_box(&BOX_JXLC, &[0xFF, 0x0A, 0x00]);

        let mut container = Vec::new();
        container.extend_from_slice(&JXL_CONTAINER_MAGIC);
        container.extend_from_slice(&ftyp_box);
        container.extend_from_slice(&exif_box);
        container.extend_from_slice(&jxlc_box);

        let mut input = Cursor::new(container);
        let mut output = Cursor::new(Vec::new());

        let jpegxl_io = JpegXlIO {};
        jpegxl_io
            .write_cai(&mut input, &mut output, b"manifest_with_exif")
            .unwrap();

        output.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut output).unwrap();
        assert_eq!(result, b"manifest_with_exif");

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
        let jxlc_box = build_box(&BOX_JXLC, &[0xFF, 0x0A, 0x00]);

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
            .write_cai(&mut input, &mut output, b"manifest")
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
        let large_manifest = vec![0xAB; 256 * 1024]; // 256 KB

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
        let store_bytes = b"file_based_manifest_store";
        jpegxl_io.save_cai_store(&test_path, store_bytes).unwrap();

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
            .save_cai_store(&test_path, b"to_be_removed")
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
            .save_cai_store(&test_path, b"manifest_for_locations")
            .unwrap();

        let locations = jpegxl_io.get_object_locations(&test_path).unwrap();
        assert!(
            locations
                .iter()
                .any(|l| l.htype == HashBlockObjectType::Cai)
        );
    }

    // ─── Spec compliance: container with jxlp (partial codestream) ───

    #[test]
    fn test_container_with_jxlp_boxes() {
        let ftyp_data = b"jxl \0\0\0\0jxl ";
        let ftyp_box = build_box(&BOX_FTYP, ftyp_data);

        // Partial codestream boxes (jxlp has a 4-byte counter prefix)
        let mut jxlp1_data = Vec::new();
        jxlp1_data.write_u32::<BigEndian>(0).unwrap(); // counter = 0
        jxlp1_data.extend_from_slice(&[0xFF, 0x0A]);
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
            .write_cai(&mut input, &mut output, b"manifest_with_jxlp")
            .unwrap();

        // jumb should be inserted before the first jxlp
        output.rewind().unwrap();
        let boxes = parse_all_boxes(&mut output).unwrap();
        let jumb_idx = boxes.iter().position(|b| b.box_type == BOX_JUMB).unwrap();
        let jxlp_idx = boxes.iter().position(|b| b.box_type == BOX_JXLP).unwrap();
        assert!(jumb_idx < jxlp_idx);

        output.rewind().unwrap();
        let result = jpegxl_io.read_cai(&mut output).unwrap();
        assert_eq!(result, b"manifest_with_jxlp");
    }
}
