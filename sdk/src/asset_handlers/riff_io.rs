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
    fs::{File, OpenOptions},
    io::{Cursor, Seek, SeekFrom},
    path::Path,
    result,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use riff::*;

use crate::{
    asset_io::{
        rename_or_move, AssetIO, AssetPatch, CAIRead, CAIReadWrapper, CAIReadWrite,
        CAIReadWriteWrapper, CAIReader, CAIWriter, HashBlockObjectType, HashObjectPositions,
        RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::{
        io_utils::{stream_len, tempfile_builder},
        xmp_inmemory_utils::{add_provenance, MIN_XMP},
    },
};

static SUPPORTED_TYPES: [&str; 12] = [
    "avi",
    "wav",
    "webp",
    "image/webp",
    "audio/wav",
    "audio/wave",
    "audio/x-wav",
    "audio/vnd.wave",
    "application/x-troff-msvideo",
    "video/avi",
    "video/msvideo",
    "video/x-msvideo",
];

pub struct RiffIO {
    #[allow(dead_code)]
    riff_format: String, // can be used for specialized RIFF cases
}

const C2PA_CHUNK_ID: ChunkId = ChunkId {
    value: [0x43, 0x32, 0x50, 0x41],
}; // C2PA

const VP8X_ID: ChunkId = ChunkId {
    value: [0x56, 0x50, 0x38, 0x58],
}; // VP8X  chunk to hold auxiliary info

const VP8_ID: ChunkId = ChunkId {
    value: [0x56, 0x50, 0x38, 0x20],
}; // VP8 chunk

const VP8L_ID: ChunkId = ChunkId {
    value: [0x56, 0x50, 0x38, 0x4c],
}; // VP8L chunk

const XMP_CHUNK_ID: ChunkId = ChunkId {
    value: [0x58, 0x4d, 0x50, 0x20],
}; // XMP

const AVIX_ID: ChunkId = ChunkId {
    value: [0x41, 0x56, 0x49, 0x58],
}; // AVIX - AVI extended for files > 1GB

const XMP_FLAG: u32 = 4;

fn get_height_and_width(chunk_contents: &[ChunkContents]) -> Result<(u16, u16)> {
    if let Some(ChunkContents::Data(_id, chunk_data)) = chunk_contents.iter().find(|c| match c {
        ChunkContents::Data(id, _) => *id == VP8L_ID,
        _ => false,
    }) {
        let mut chunk_stream = Cursor::new(chunk_data);
        chunk_stream.seek(SeekFrom::Start(1))?; // skip signature byte

        // width and length are 12 bits packed together
        let first_bytes = chunk_stream.read_u16::<LittleEndian>()?;
        let width = 1 + (first_bytes & 0x3fff); // add 1 for VP8L
        let last_two = (first_bytes & 0xc000) >> 14; // last two bits of first bytes are first 2 of height
        let height = 1 + (((chunk_stream.read_u16::<LittleEndian>()? & 0xfff) << 2) | last_two);

        return Ok((height, width));
    }

    if let Some(ChunkContents::Data(_id, chunk_data)) = chunk_contents.iter().find(|c| match c {
        ChunkContents::Data(id, _) => *id == VP8_ID,
        _ => false,
    }) {
        let mut chunk_stream = Cursor::new(chunk_data);
        chunk_stream.seek(SeekFrom::Start(6))?; // skip frame tag and start code

        let width = chunk_stream.read_u16::<LittleEndian>()? & 0x3fff;
        let height = chunk_stream.read_u16::<LittleEndian>()? & 0x3fff;

        return Ok((height, width));
    }

    Err(Error::InvalidAsset(
        "WEBP missing VP8 or VP8L segment".to_string(),
    ))
}

fn inject_c2pa<T>(
    chunk: &Chunk,
    stream: &mut T,
    data: &[u8],
    xmp_data: Option<&[u8]>,
    format: &str,
) -> Result<ChunkContents>
where
    T: Seek + std::io::Read,
{
    let id = chunk.id();
    let is_riff_chunk: bool = id == RIFF_ID;
    stream.rewind()?;

    if is_riff_chunk || id == LIST_ID {
        let chunk_type = chunk.read_type(stream).map_err(|_| {
            Error::InvalidAsset("RIFF handler could not parse file format {format}".to_string())
        })?;
        let mut children = chunk
            .iter(stream)
            .collect::<result::Result<Vec<Chunk>, _>>()?;

        let mut children_contents: Vec<ChunkContents> = Vec::new();

        if is_riff_chunk && !data.is_empty() {
            // remove c2pa manifest store in RIFF chunk
            children.retain(|c| c.id() != C2PA_CHUNK_ID);
        }

        if is_riff_chunk && xmp_data.is_some() {
            // remove XMP in RIFF chunk so we can replace
            children.retain(|c| c.id() != XMP_CHUNK_ID);
        }

        // duplicate all top level children
        for child in children {
            children_contents.push(inject_c2pa(&child, stream, data, xmp_data, format)?);
        }

        // add XMP if needed
        if let Some(xmp) = xmp_data {
            if is_riff_chunk && !xmp.is_empty() {
                // if this is a webp doc we must also update VP8X
                if format == "webp" {
                    // if already present we can patch otherwise add
                    if let Some(ChunkContents::Data(_id, chunk_data)) =
                        children_contents.iter_mut().find(|c| match c {
                            ChunkContents::Data(id, _) => *id == VP8X_ID,
                            _ => false,
                        })
                    {
                        let mut chunk_stream = Cursor::new(chunk_data);

                        let mut flags = chunk_stream.read_u32::<LittleEndian>()?;

                        // add in XMP flag
                        flags |= XMP_FLAG;

                        chunk_stream.rewind()?;

                        // write back changes
                        chunk_stream.write_u32::<LittleEndian>(flags)?;
                    } else {
                        // add new VP8X

                        // get height and width from VBL
                        if let Ok((height, width)) = get_height_and_width(&children_contents) {
                            let data: Vec<u8> = Vec::new();
                            let mut chunk_writer = Cursor::new(data);

                            let flags: u32 = XMP_FLAG;
                            let vp8x_height = height as u32 - 1;
                            let vp8x_width = width as u32 - 1;

                            // write flags
                            chunk_writer.write_u32::<LittleEndian>(flags)?;

                            // write width then height
                            chunk_writer.write_u24::<LittleEndian>(vp8x_width)?;
                            chunk_writer.write_u24::<LittleEndian>(vp8x_height)?;

                            // make new VP8X chunk and prepend to children list
                            let mut tmp_vec: Vec<ChunkContents> = Vec::new();
                            tmp_vec.push(ChunkContents::Data(VP8X_ID, chunk_writer.into_inner()));
                            tmp_vec.extend(children_contents);
                            children_contents = tmp_vec;
                        } else {
                            return Err(Error::InvalidAsset(
                                "Could not parse VP8 or VP8L".to_string(),
                            ));
                        }
                    }
                }

                children_contents.push(ChunkContents::Data(XMP_CHUNK_ID, xmp.to_vec()));
            }
        }

        // place at the end for maximum compatibility
        if is_riff_chunk && !data.is_empty() {
            children_contents.push(ChunkContents::Data(C2PA_CHUNK_ID, data.to_vec()));
        }

        Ok(ChunkContents::Children(id, chunk_type, children_contents))
    } else if id == SEQT_ID {
        let children = chunk
            .iter(stream)
            .collect::<result::Result<Vec<Chunk>, _>>()?;

        let mut children_contents: Vec<ChunkContents> = Vec::new();

        for child in children {
            children_contents.push(inject_c2pa(&child, stream, data, xmp_data, format)?);
        }

        Ok(ChunkContents::ChildrenNoType(id, children_contents))
    } else {
        let contents = chunk
            .read_contents(stream)
            .map_err(|_| Error::InvalidAsset("RIFF handler could not parse file".to_string()))?;
        Ok(ChunkContents::Data(id, contents))
    }
}

fn get_manifest_pos(reader: &mut dyn CAIRead) -> Option<(u64, u32)> {
    let mut asset: Vec<u8> = Vec::new();
    reader.rewind().ok()?;
    reader.read_to_end(&mut asset).ok()?;

    let mut chunk_reader = Cursor::new(asset);

    let top_level_chunks = Chunk::read(&mut chunk_reader, 0).ok()?;

    if top_level_chunks.id() == RIFF_ID {
        for chunk in top_level_chunks.iter(&mut chunk_reader) {
            let chunk = chunk.ok()?;
            if chunk.id() == C2PA_CHUNK_ID {
                return Some((chunk.offset(), chunk.len() + 8)); // 8 is len of data chunk header
            }
        }
    }
    None
}

/// Scan RIFF chunk headers to find the C2PA chunk without reading any chunk data.
///
/// Returns `Some((block_start, total_size))` where `total_size` includes the 8-byte
/// chunk header.  Returns `None` when no C2PA chunk is present at the top level.
///
/// Handles null-byte padding (`0x00000000`) that some encoders (e.g. VLC) insert
/// between top-level chunks for DWORD alignment — those 4 bytes are skipped
/// transparently.
///
/// Complexity: O(number of top-level chunks) — for a 1 GB AVI with a handful of
/// top-level chunks this reads fewer than 100 bytes, vs. the 1 GB needed by
/// `add_required_chunks`.
fn scan_riff_c2pa_region(reader: &mut dyn CAIRead) -> Option<(u64, u64)> {
    reader.rewind().ok()?;

    // RIFF outer header: 4-byte FourCC + 4-byte size + 4-byte form type
    let mut header = [0u8; 12];
    reader.read_exact(&mut header).ok()?;
    if &header[0..4] != b"RIFF" {
        return None;
    }

    let riff_data_size = u32::from_le_bytes(header[4..8].try_into().ok()?) as u64;
    let riff_content_end = 8 + riff_data_size; // byte past the first RIFF chunk

    // Walk top-level chunks inside the RIFF by reading only their 8-byte headers.
    let mut offset = 12u64;
    loop {
        if offset >= riff_content_end {
            break;
        }

        reader.seek(SeekFrom::Start(offset)).ok()?;
        let mut chunk_header = [0u8; 8];
        if reader.read_exact(&mut chunk_header).is_err() {
            break;
        }

        // Some encoders (e.g. VLC) insert 4 null bytes between chunks for DWORD
        // alignment.  Skip them and re-read the next real chunk header.
        if chunk_header[0..4] == [0u8; 4] {
            offset = offset.checked_add(4)?;
            continue;
        }

        let id = &chunk_header[0..4];
        let size = u32::from_le_bytes(chunk_header[4..8].try_into().ok()?) as u64;

        if id == C2PA_CHUNK_ID.value.as_slice() {
            return Some((offset, 8 + size));
        }

        // RIFF chunk data is padded to an even byte boundary.
        let padded_size = size + (size & 1);
        offset = offset.checked_add(8 + padded_size)?;
    }

    None
}

/// Copy exactly `count` bytes from `reader` to `writer` using a 1 MB stack buffer.
fn copy_n(
    reader: &mut dyn CAIRead,
    writer: &mut dyn CAIReadWrite,
    mut count: u64,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; (count.min(1024 * 1024)) as usize];
    while count > 0 {
        let to_read = count.min(buf.len() as u64) as usize;
        reader.read_exact(&mut buf[..to_read])?;
        writer.write_all(&buf[..to_read])?;
        count -= to_read as u64;
    }
    Ok(())
}

/// Streaming RIFF C2PA writer.
///
/// Copies the first RIFF chunk of `input` to `output`, replacing any existing
/// C2PA chunk and appending `store_bytes` as a new top-level `C2PA` chunk at the
/// end.  If `store_bytes` is empty the old C2PA chunk is simply removed.
///
/// Key properties:
/// - O(file_size) I/O but O(1) RAM: chunks are stream-copied with a 1 MB buffer.
/// - Null-byte padding (`0x00000000`) inserted by some encoders (e.g. VLC) between
///   chunks is skipped, fixing the parse failure described in issue #1910.
/// - Does **not** modify nested chunk contents, so it is correct for formats where
///   C2PA lives at the top level (AVI, WAV, WebP).
///
/// For large AVI files the caller is responsible for copying any trailing AVIX
/// chunks after the first RIFF chunk.
fn write_riff_cai_streaming(
    input: &mut dyn CAIRead,
    output: &mut dyn CAIReadWrite,
    store_bytes: &[u8],
) -> Result<u64> {
    input.rewind()?;
    output.rewind()?;

    // Read and validate the outer RIFF header (12 bytes).
    let mut outer = [0u8; 12];
    input.read_exact(&mut outer)?;
    if &outer[0..4] != b"RIFF" {
        return Err(Error::InvalidAsset("Invalid RIFF format".to_string()));
    }
    let orig_riff_data_size = u32::from_le_bytes(
        outer[4..8]
            .try_into()
            .map_err(|_| Error::InvalidAsset("Invalid RIFF size field".to_string()))?,
    ) as u64;
    let riff_content_end = 8 + orig_riff_data_size;

    // Write "RIFF" FourCC, placeholder size (patched at the end), then form type.
    output.write_all(&outer[0..4])?; // "RIFF"
    let size_patch_offset = output.stream_position()?; // offset 4
    output.write_all(&[0u8; 4])?; // placeholder size
    output.write_all(&outer[8..12])?; // form type (e.g., "AVI ")

    // Stream-copy top-level chunks, skipping null padding and any C2PA chunk.
    let mut in_pos = 12u64;
    loop {
        if in_pos >= riff_content_end {
            break;
        }

        input.seek(SeekFrom::Start(in_pos))?;
        let mut hdr = [0u8; 8];
        if input.read_exact(&mut hdr).is_err() {
            break; // EOF inside RIFF content — treat as end
        }

        // Skip null-byte DWORD padding (issue #1910: VLC-encoded AVIs).
        if hdr[0..4] == [0u8; 4] {
            in_pos += 4;
            continue;
        }

        let chunk_size = u32::from_le_bytes(
            hdr[4..8]
                .try_into()
                .map_err(|_| Error::InvalidAsset("Invalid RIFF chunk size".to_string()))?,
        ) as u64;
        let padded_size = chunk_size + (chunk_size & 1);

        if &hdr[0..4] == C2PA_CHUNK_ID.value.as_slice() {
            // Skip the existing C2PA chunk — we'll append a fresh one at the end.
            in_pos += 8 + padded_size;
            continue;
        }

        // Stream-copy this chunk verbatim (header + data).
        output.write_all(&hdr)?;
        input.seek(SeekFrom::Start(in_pos + 8))?;
        copy_n(input, output, padded_size)?;
        in_pos += 8 + padded_size;
    }

    // Append the new C2PA chunk (if any).
    if !store_bytes.is_empty() {
        let c2pa_data_size = store_bytes.len() as u32;
        output.write_all(&C2PA_CHUNK_ID.value)?;
        output.write_all(&c2pa_data_size.to_le_bytes())?;
        output.write_all(store_bytes)?;
        if c2pa_data_size & 1 != 0 {
            output.write_all(&[0u8])?; // RIFF even-size padding
        }
    }

    // Patch the RIFF outer size field (= total output size − 8-byte outer header).
    let output_end = output.stream_position()?;
    let new_riff_data_size = (output_end - 8) as u32;
    output.seek(SeekFrom::Start(size_patch_offset))?;
    output.write_all(&new_riff_data_size.to_le_bytes())?;

    // Return the end of the first RIFF chunk in the input so the caller can
    // handle any trailing AVIX chunks.
    Ok(riff_content_end)
}

impl CAIReader for RiffIO {
    fn read_cai(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        // Use the manual scanner so null-byte padding (issue #1910) is handled
        // transparently and we never try to parse chunk contents via the riff crate.
        let (block_start, total_size) =
            scan_riff_c2pa_region(input_stream).ok_or(Error::JumbfNotFound)?;

        let data_offset = block_start + 8; // skip the 8-byte chunk header
        let data_len = total_size - 8;

        input_stream.seek(SeekFrom::Start(data_offset))?;
        let mut data = vec![0u8; data_len as usize];
        input_stream.read_exact(&mut data)?;

        Ok(data)
    }

    // Get XMP block
    fn read_xmp(&self, input_stream: &mut dyn CAIRead) -> Option<String> {
        let top_level_chunks = {
            let mut reader = CAIReadWrapper {
                reader: input_stream,
            };
            Chunk::read(&mut reader, 0).ok()?
        };

        if top_level_chunks.id() != RIFF_ID {
            return None;
        }

        let mut chunk_reader = CAIReadWrapper {
            reader: input_stream,
        };

        for chunk in top_level_chunks.iter(&mut chunk_reader) {
            let chunk = chunk.ok()?;
            if chunk.id() == XMP_CHUNK_ID {
                let output = chunk.read_contents(&mut chunk_reader).ok()?;
                return Some(String::from_utf8_lossy(&output).to_string());
            }
        }

        None
    }
}

fn add_required_chunks(
    asset_type: &str,
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    let aio = RiffIO::new(asset_type);

    match aio.read_cai(input_stream) {
        Ok(_) => {
            // just clone
            input_stream.rewind()?;
            output_stream.rewind()?;
            std::io::copy(input_stream, output_stream)?;
            Ok(())
        }
        Err(_) => {
            input_stream.rewind()?;
            aio.write_cai(input_stream, output_stream, &[1, 2, 3, 4]) // save arbitrary data
        }
    }
}

impl AssetIO for RiffIO {
    fn new(riff_format: &str) -> Self {
        RiffIO {
            riff_format: riff_format.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(RiffIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(RiffIO::new(asset_type)))
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = File::open(asset_path)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        // copy temp file to asset
        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut f = File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;

        self.get_object_locations_from_stream(&mut f)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        self.save_cai_store(asset_path, &[])
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

impl CAIWriter for RiffIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        // Stream the first RIFF chunk to output, inserting/replacing the C2PA chunk.
        // Returns the byte offset in `input_stream` just past the first RIFF chunk,
        // needed so we can copy any trailing AVIX extension chunks below.
        let first_chunk_end = write_riff_cai_streaming(input_stream, output_stream, store_bytes)?;

        // Copy additional RIFF/AVIX chunks for large AVI files (OpenDML extension).
        if self.riff_format == "avi" || self.riff_format == "video/avi" {
            input_stream.seek(SeekFrom::Start(first_chunk_end))?;

            loop {
                let current_pos = input_stream.stream_position()?;
                let file_size = input_stream.seek(SeekFrom::End(0))?;
                input_stream.seek(SeekFrom::Start(current_pos))?;

                if current_pos >= file_size {
                    break;
                }

                let mut chunk_header = [0u8; 8];
                if input_stream.read_exact(&mut chunk_header).is_err() {
                    break;
                }

                let chunk_id = ChunkId {
                    value: chunk_header[0..4]
                        .try_into()
                        .map_err(|_e| Error::EmbeddingError)?,
                };
                let chunk_size = u32::from_le_bytes(
                    chunk_header[4..8]
                        .try_into()
                        .map_err(|_e| Error::EmbeddingError)?,
                ) as u64;

                if chunk_id != RIFF_ID && chunk_id != AVIX_ID {
                    break;
                }

                output_stream.write_all(&chunk_id.value)?;
                output_stream.write_all(&(chunk_size as u32).to_le_bytes())?;

                copy_n(input_stream, output_stream, chunk_size)?;
            }
        }

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        // Fast path: scan only chunk headers (8 bytes each) to find the C2PA chunk.
        // This avoids loading the entire file into RAM when the C2PA chunk already
        // exists (re-signing, or when called on the output stream after JUMBF write).
        if let Some((manifest_pos, manifest_len)) = scan_riff_c2pa_region(input_stream) {
            let file_end = stream_len(input_stream)?;
            let end = manifest_pos
                .checked_add(manifest_len)
                .ok_or_else(|| Error::InvalidAsset("value out of range".to_string()))?;

            return Ok(vec![
                HashObjectPositions {
                    offset: usize::try_from(manifest_pos)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
                    length: usize::try_from(manifest_len)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
                    htype: HashBlockObjectType::Cai,
                },
                HashObjectPositions {
                    offset: 0,
                    length: usize::try_from(manifest_pos)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
                    htype: HashBlockObjectType::Other,
                },
                HashObjectPositions {
                    offset: usize::try_from(end)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
                    length: usize::try_from(file_end - end)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
                    htype: HashBlockObjectType::Other,
                },
            ]);
        }

        // Slow path: no C2PA chunk yet (fresh signing).  Use add_required_chunks to
        // insert a placeholder and find the insertion point.
        let output_buf: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_buf);

        add_required_chunks(&self.riff_format, input_stream, &mut output_stream)?;

        let mut positions: Vec<HashObjectPositions> = Vec::new();

        let (manifest_pos, manifest_len) =
            get_manifest_pos(&mut output_stream).ok_or(Error::EmbeddingError)?;

        positions.push(HashObjectPositions {
            offset: usize::try_from(manifest_pos)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
            length: usize::try_from(manifest_len)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
            htype: HashBlockObjectType::Cai,
        });

        // add hash of chunks before cai
        positions.push(HashObjectPositions {
            offset: 0,
            length: usize::try_from(manifest_pos)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
            htype: HashBlockObjectType::Other,
        });

        // add position from cai to end
        let Some(end) = u64::checked_add(manifest_pos, manifest_len as u64) else {
            return Err(Error::InvalidAsset("value out of range".to_string()));
        };

        let file_end = stream_len(&mut output_stream)?;
        positions.push(HashObjectPositions {
            offset: usize::try_from(end)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?, // len of cai
            length: usize::try_from(file_end - end)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
            htype: HashBlockObjectType::Other,
        });

        Ok(positions)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        self.write_cai(input_stream, output_stream, &[])
    }
}

impl AssetPatch for RiffIO {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut asset = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(asset_path)?;
        self.patch_cai_store_from_stream(&mut asset, store_bytes)
    }

    fn patch_from_stream_supported(&self) -> bool {
        true
    }

    fn patch_cai_store_from_stream(
        &self,
        stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        // Use the lean O(metadata) scanner — reads only chunk headers, not data.
        let (block_start, total_size) =
            scan_riff_c2pa_region(stream).ok_or(Error::EmbeddingError)?;
        let data_offset = block_start + 8; // skip 8-byte chunk header
        let data_len = (total_size - 8) as usize;

        if store_bytes.len() == data_len {
            stream.seek(SeekFrom::Start(data_offset))?;
            stream.write_all(store_bytes)?;
            Ok(())
        } else {
            Err(Error::InvalidAsset(
                "patch_cai_store store size mismatch.".to_string(),
            ))
        }
    }
}

impl RemoteRefEmbed for RiffIO {
    #[allow(unused_variables)]
    fn embed_reference(&self, asset_path: &Path, embed_ref: RemoteRefEmbedType) -> Result<()> {
        let mut input_stream = File::open(asset_path)?;

        let mut output_stream = OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        self.embed_reference_to_stream(&mut input_stream, &mut output_stream, embed_ref)
    }

    fn embed_reference_to_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            RemoteRefEmbedType::Xmp(manifest_uri) => {
                if let Some(curr_xmp) = self.read_xmp(input_stream) {
                    let mut new_xmp = add_provenance(&curr_xmp, &manifest_uri)?;
                    if new_xmp.len() % 2 == 1 {
                        // pad if needed to even length
                        new_xmp.push(' ');
                    }

                    let top_level_chunks = {
                        let mut reader = CAIReadWrapper {
                            reader: input_stream,
                        };
                        Chunk::read(&mut reader, 0)?
                    };

                    if top_level_chunks.id() != RIFF_ID {
                        return Err(Error::InvalidAsset("Invalid RIFF format".to_string()));
                    }

                    let mut reader = CAIReadWrapper {
                        reader: input_stream,
                    };

                    // replace/add manifest in memory
                    let new_contents = inject_c2pa(
                        &top_level_chunks,
                        &mut reader,
                        &[],
                        Some(new_xmp.as_bytes()),
                        &self.riff_format,
                    )?;

                    // save contents
                    let mut writer = CAIReadWriteWrapper {
                        reader_writer: output_stream,
                    };
                    new_contents
                        .write(&mut writer)
                        .map_err(|_e| Error::EmbeddingError)?;
                    Ok(())
                } else {
                    let mut new_xmp = add_provenance(MIN_XMP, &manifest_uri)?;

                    if new_xmp.len() % 2 == 1 {
                        // pad if needed to even length
                        new_xmp.push(' ');
                    }

                    let top_level_chunks = {
                        let mut reader = CAIReadWrapper {
                            reader: input_stream,
                        };
                        Chunk::read(&mut reader, 0)?
                    };

                    if top_level_chunks.id() != RIFF_ID {
                        return Err(Error::InvalidAsset("Invalid RIFF format".to_string()));
                    }

                    let mut reader = CAIReadWrapper {
                        reader: input_stream,
                    };

                    // replace/add manifest in memory
                    let new_contents = inject_c2pa(
                        &top_level_chunks,
                        &mut reader,
                        &[],
                        Some(new_xmp.as_bytes()),
                        &self.riff_format,
                    )?;

                    // save contents
                    let mut writer = CAIReadWriteWrapper {
                        reader_writer: output_stream,
                    };
                    new_contents
                        .write(&mut writer)
                        .map_err(|_e| Error::EmbeddingError)?;
                    Ok(())
                }
            }
            RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RiffError {
    #[error("invalid file signature: {reason}")]
    InvalidFileSignature { reason: String },
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::panic;

    use super::*;
    use crate::utils::{
        hash_utils::vec_compare,
        io_utils::tempdirectory,
        test::{fixture_path, temp_dir_path},
        xmp_inmemory_utils::extract_provenance,
    };

    #[test]
    fn test_write_wav() {
        let more_data = "some more test data".as_bytes();
        let source = fixture_path("sample1.wav");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let riff_io = RiffIO::new("wav");

                if let Ok(()) = riff_io.save_cai_store(&output, more_data) {
                    if let Ok(read_test_data) = riff_io.read_cai_store(&output) {
                        assert!(vec_compare(more_data, &read_test_data));
                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_read_cai_with_incorrect_header_size_does_not_panic() {
        let riff_io = RiffIO::new("wav");

        let panic_result = panic::catch_unwind(|| {
            let mut source = File::open(fixture_path("sample3.invalid.wav")).unwrap();
            // The invalid file has no C2PA chunk — we expect any Err, not a panic.
            assert!(riff_io.read_cai(&mut source).is_err());
        });

        assert!(panic_result.is_ok());
    }

    #[test]
    fn test_write_wav_stream() {
        let more_data = "some more test data".as_bytes();
        let mut source = File::open(fixture_path("sample1.wav")).unwrap();

        let riff_io = RiffIO::new("wav");
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

            let mut output_stream = File::create(&output).unwrap();

            riff_io
                .write_cai(&mut source, &mut output_stream, more_data)
                .unwrap();

            let mut source = File::open(output).unwrap();
            let read_test_data = riff_io.read_cai(&mut source).unwrap();
            assert!(vec_compare(more_data, &read_test_data));
        }
    }

    #[test]
    fn test_patch_write_wav() {
        let test_data = "some test data".as_bytes();
        let source = fixture_path("sample1.wav");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let riff_io = RiffIO::new("wav");

                if let Ok(()) = riff_io.save_cai_store(&output, test_data) {
                    if let Ok(source_data) = riff_io.read_cai_store(&output) {
                        // create replacement data of same size
                        let mut new_data = vec![0u8; source_data.len()];
                        new_data[..test_data.len()].copy_from_slice(test_data);
                        riff_io.patch_cai_store(&output, &new_data).unwrap();

                        let replaced = riff_io.read_cai_store(&output).unwrap();

                        assert_eq!(new_data, replaced);

                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_remove_c2pa() {
        let source = fixture_path("sample1.wav");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

        std::fs::copy(source, &output).unwrap();
        let riff_io = RiffIO::new("wav");

        riff_io.remove_cai_store(&output).unwrap();

        // read back in asset, JumbfNotFound is expected since it was removed
        match riff_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_read_xmp() {
        let source = fixture_path("test_xmp.webp");
        let mut reader = File::open(source).unwrap();

        let riff_io = RiffIO::new("webp");

        let xmp = riff_io.read_xmp(&mut reader).unwrap();
        println!("XMP: {xmp}");
    }

    #[test]
    fn test_write_xmp() {
        let more_data = "some more test data";
        let source = fixture_path("test_xmp.webp");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "test_xmp.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_ref_writer_ref() {
                if let Ok(()) = embed_handler.embed_reference(
                    output.as_path(),
                    RemoteRefEmbedType::Xmp(more_data.to_string()),
                ) {
                    let mut output_stream = File::open(&output).unwrap();

                    // check the xmp
                    if let Some(xmp) = riff_io.read_xmp(&mut output_stream) {
                        println!("XMP: {xmp}");

                        if let Some(xmp_val) = extract_provenance(&xmp) {
                            if xmp_val == more_data {
                                success = true;
                            }
                        }
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_insert_xmp() {
        let more_data = "some more test data";
        let source = fixture_path("test.webp");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "test.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_ref_writer_ref() {
                if let Ok(()) = embed_handler.embed_reference(
                    output.as_path(),
                    RemoteRefEmbedType::Xmp(more_data.to_string()),
                ) {
                    let mut output_stream = File::open(&output).unwrap();

                    // check the xmp
                    if let Some(xmp) = riff_io.read_xmp(&mut output_stream) {
                        println!("XMP: {xmp}");

                        if let Some(xmp_val) = extract_provenance(&xmp) {
                            if xmp_val == more_data {
                                success = true;
                            }
                        }
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_insert_xmp_lossless() {
        let more_data = "some more test data";
        let source = fixture_path("test_lossless.webp");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "test_lossless.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_ref_writer_ref() {
                if let Ok(()) = embed_handler.embed_reference(
                    output.as_path(),
                    RemoteRefEmbedType::Xmp(more_data.to_string()),
                ) {
                    let mut output_stream = File::open(&output).unwrap();

                    // check the xmp
                    if let Some(xmp) = riff_io.read_xmp(&mut output_stream) {
                        println!("XMP: {xmp}");

                        if let Some(xmp_val) = extract_provenance(&xmp) {
                            if xmp_val == more_data {
                                success = true;
                            }
                        }
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_avi_support() {
        // Test basic AVI file support
        let source = fixture_path("test.avi");
        let mut f = File::open(source).unwrap();
        let riff_io = RiffIO::new("avi");

        // Should work even though file doesn't have C2PA yet
        assert!(matches!(
            riff_io.read_cai(&mut f),
            Err(Error::JumbfNotFound)
        ));
    }

    #[test]
    #[ignore] // Large file test - requires ~4.4GB AVI file
    fn test_large_avi_avix_support() {
        // This test verifies that large AVI files with AVIX chunks work correctly
        // Run with: cargo test test_large_avi_avix_support -- --ignored --nocapture

        use std::{
            io::{BufReader, Write},
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            thread,
            time::Duration,
        };

        use tempfile::NamedTempFile;

        let test_file = "tests/fixtures/bigbunny-3.avi";
        let source_size = std::fs::metadata(test_file).unwrap().len();

        let mut source = File::open(test_file).unwrap();
        let mut dest = NamedTempFile::new().unwrap();

        let riff_io = RiffIO::new("avi");
        let test_data = b"C2PA test data for large AVIX file";

        eprintln!("Writing C2PA data to large AVI...");
        let start = std::time::Instant::now();

        // Set up timeout - fail if write takes more than 15 seconds
        let timeout_flag = Arc::new(AtomicBool::new(false));
        let timeout_flag_clone = timeout_flag.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(15));
            timeout_flag_clone.store(true, Ordering::SeqCst);
        });

        let write_result = riff_io.write_cai(&mut source, &mut dest, test_data);
        let write_duration = start.elapsed();

        assert!(
            !timeout_flag.load(Ordering::SeqCst),
            "Test timed out after 15 seconds"
        );

        if let Err(e) = write_result {
            panic!("write_cai failed: {e:?}");
        }

        eprintln!("Write completed in {write_duration:?}");

        // Verify output size
        dest.flush().unwrap();
        let dest_size = dest.as_file().metadata().unwrap().len();

        // Output should be similar size to input (plus C2PA data)
        assert!(
            dest_size > source_size,
            "Output should be larger than source"
        );
        assert!(
            dest_size < source_size + 1_000_000,
            "Output shouldn't be much larger than source"
        );

        // Read back the C2PA data
        eprintln!("Reading C2PA data back...");
        dest.rewind().unwrap();
        let mut buffered_dest = BufReader::new(dest.as_file());
        let read_data = riff_io.read_cai(&mut buffered_dest).unwrap();
        assert_eq!(read_data, test_data);
        eprintln!("✓ Successfully read C2PA data from large AVI file");
    }

    #[test]
    #[ignore] // Large file test - run manually
    fn test_large_avi_write_cai() {
        // This test requires a large AVI file (>1GB with AVIX chunks)
        // Run with: cargo test test_large_avi_write_cai -- --ignored
        use std::io::Cursor;

        let test_file = "tests/fixtures/large_test.avi";
        if !std::path::Path::new(test_file).exists() {
            println!("Skipping test - {test_file} not found");
            return;
        }

        let mut source = File::open(test_file).unwrap();
        let mut dest = Cursor::new(Vec::new());

        let riff_io = RiffIO::new("avi");
        let test_data = b"test C2PA data for large AVI";

        // Write C2PA data
        riff_io
            .write_cai(&mut source, &mut dest, test_data)
            .unwrap();

        // Verify output size is reasonable (should be close to source + C2PA data)
        let source_size = std::fs::metadata(test_file).unwrap().len();
        let dest_size = dest.get_ref().len() as u64;

        println!("Source: {source_size} bytes, Dest: {dest_size} bytes");
        assert!(dest_size > source_size); // Should be larger with C2PA
        assert!(dest_size < source_size + 100_000); // But not too much larger

        // Try to read it back
        dest.set_position(0);
        let read_data = riff_io.read_cai(&mut dest).unwrap();
        assert_eq!(read_data, test_data);
    }

    #[test]
    #[ignore] // Large file test - run manually
    fn test_large_avi_builder_sign() {
        // Test Builder.sign() with large AVI file
        // Run with: cargo test test_large_avi_builder_sign -- --ignored
        use std::io::Cursor;

        use crate::{utils::test_signer::test_signer, Builder, SigningAlg};

        let test_file = "tests/fixtures/bigbunny-3.avi";

        let manifest_json = r#"{
            "claim_generator": "test_app/1.0",
            "title": "Large AVI Test"
        }"#;

        let mut builder = Builder::from_json(manifest_json).unwrap();
        let mut source = File::open(test_file).unwrap();
        let mut dest = Cursor::new(Vec::new());

        let signer = test_signer(SigningAlg::Ps256);

        // This should complete without hanging
        let start = std::time::Instant::now();
        builder
            .sign(signer.as_ref(), "video/avi", &mut source, &mut dest)
            .unwrap();
        let duration = start.elapsed();

        println!("Signing took {duration:?}");

        // Verify we got output
        assert!(!dest.get_ref().is_empty());

        // Verify the output size
        let source_size = std::fs::metadata(test_file).unwrap().len();
        let dest_size = dest.get_ref().len() as u64;
        println!("Source: {source_size} bytes, Dest: {dest_size} bytes");
        assert!(dest_size > source_size); // Should be larger with C2PA
        assert!(dest_size < source_size + 100_000); // But not too much larger
    }
}
