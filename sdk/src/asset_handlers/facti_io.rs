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

//! Asset handler for BlockFact .facti/.facta/.factv container formats.
//!
//! These formats share an identical binary structure:
//! - 4-byte magic (FA 49 41 00 for .facti, FA 41 41 00 for .facta, FA 56 41 00 for .factv)
//! - 4-byte metadata length (big-endian u32)
//! - N bytes JSON metadata (contains `image_length` for v2 files)
//! - M bytes media payload (JPEG/PNG for .facti, audio for .facta, video for .factv)
//! - [v2 only] 2-byte extension block count (big-endian u16)
//! - [v2 only] For each block: 4-byte ASCII type + 4-byte length + data
//!
//! The C2PA JUMBF manifest is stored in an extension block with type "C2PA".

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use crate::{
    asset_io::{
        AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, ComposedManifestRef,
        HashBlockObjectType, HashObjectPositions,
    },
    error::{Error, Result},
};

static SUPPORTED_TYPES: [&str; 6] = [
    "facti",
    "facta",
    "factv",
    "image/vnd.blockfact.facti",
    "audio/vnd.blockfact.facta",
    "video/vnd.blockfact.factv",
];

// Magic bytes for each format variant (first 2 bytes differ, last 2 are always 41 00)
const MAGIC_FACTI: [u8; 4] = [0xFA, 0x49, 0x41, 0x00];
const MAGIC_FACTA: [u8; 4] = [0xFA, 0x41, 0x41, 0x00];
const MAGIC_FACTV: [u8; 4] = [0xFA, 0x56, 0x41, 0x00];

const C2PA_BLOCK_TYPE: &[u8; 4] = b"C2PA";

/// Handler for BlockFact .facti, .facta, and .factv container formats.
pub struct FactiIO {}

/// Parsed structure of a .fact* file's header and extension blocks.
struct FactiLayout {
    /// Offset where extension blocks start (after media payload)
    ext_start: u64,
    /// The C2PA block data if found
    c2pa_data: Option<Vec<u8>>,
    /// Offset of the C2PA block's data (after type+len headers)
    c2pa_offset: Option<u64>,
    /// Length of the C2PA block data
    c2pa_len: Option<u64>,
}

fn is_valid_magic(magic: &[u8; 4]) -> bool {
    *magic == MAGIC_FACTI || *magic == MAGIC_FACTA || *magic == MAGIC_FACTV
}

/// Parse the .fact* file layout to locate extension blocks.
fn parse_layout(reader: &mut dyn CAIRead) -> Result<FactiLayout> {
    reader.rewind()?;

    // Read and validate magic
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|_| Error::InvalidAsset("Too short for .fact* magic".to_string()))?;
    if !is_valid_magic(&magic) {
        return Err(Error::InvalidAsset("Invalid .fact* magic bytes".to_string()));
    }

    // Read metadata length
    let mut meta_len_buf = [0u8; 4];
    reader.read_exact(&mut meta_len_buf).map_err(|_| {
        Error::InvalidAsset("Too short for metadata length".to_string())
    })?;
    let meta_len = u32::from_be_bytes(meta_len_buf) as u64;

    // Read JSON metadata to find image_length (v2 indicator)
    let mut meta_bytes = vec![0u8; meta_len as usize];
    reader.read_exact(&mut meta_bytes).map_err(|_| {
        Error::InvalidAsset("Metadata truncated".to_string())
    })?;

    // Parse image_length from JSON to determine v2 format
    let media_length = extract_media_length(&meta_bytes);

    let media_start = 4 + 4 + meta_len; // magic + meta_len_field + metadata

    let ext_start = match media_length {
        Some(len) => media_start + len,
        None => {
            // v1 file — no extension blocks, media goes to EOF
            let end = reader.seek(SeekFrom::End(0))?;
            return Ok(FactiLayout {
                ext_start: end,
                c2pa_data: None,
                c2pa_offset: None,
                c2pa_len: None,
            });
        }
    };

    // Seek to extension block area
    reader.seek(SeekFrom::Start(ext_start))?;

    // Read block count
    let mut block_count_buf = [0u8; 2];
    if reader.read_exact(&mut block_count_buf).is_err() {
        // No extension blocks present (valid v2 with 0 blocks)
        return Ok(FactiLayout {
            ext_start,
            c2pa_data: None,
            c2pa_offset: None,
            c2pa_len: None,
        });
    }
    let block_count = u16::from_be_bytes(block_count_buf);

    // Scan extension blocks for C2PA
    let mut c2pa_data = None;
    let mut c2pa_offset = None;
    let mut c2pa_len = None;

    for _ in 0..block_count {
        let mut block_type = [0u8; 4];
        let mut block_len_buf = [0u8; 4];
        if reader.read_exact(&mut block_type).is_err()
            || reader.read_exact(&mut block_len_buf).is_err()
        {
            break;
        }
        let block_len = u32::from_be_bytes(block_len_buf) as u64;
        let data_offset = reader.stream_position()?;

        if &block_type == C2PA_BLOCK_TYPE {
            let mut data = vec![0u8; block_len as usize];
            reader.read_exact(&mut data).map_err(|_| {
                Error::InvalidAsset("C2PA block data truncated".to_string())
            })?;
            c2pa_data = Some(data);
            c2pa_offset = Some(data_offset);
            c2pa_len = Some(block_len);
        } else {
            reader.seek(SeekFrom::Current(block_len as i64))?;
        }
    }

    Ok(FactiLayout {
        ext_start,
        c2pa_data,
        c2pa_offset,
        c2pa_len,
    })
}

/// Extract `image_length` (or `media_length`) from JSON metadata bytes.
fn extract_media_length(meta_bytes: &[u8]) -> Option<u64> {
    // Simple JSON key extraction without pulling in serde_json as a dependency.
    // Looks for "image_length": <number> or "media_length": <number>
    let s = std::str::from_utf8(meta_bytes).ok()?;
    for key in &["image_length", "media_length"] {
        if let Some(pos) = s.find(key) {
            let after_key = &s[pos + key.len()..];
            // Skip past `": ` to find the number
            let colon_pos = after_key.find(':')?;
            let after_colon = after_key[colon_pos + 1..].trim_start();
            // Parse digits
            let num_str: String = after_colon.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !num_str.is_empty() {
                return num_str.parse::<u64>().ok();
            }
        }
    }
    None
}

/// Write a complete .fact* v2 file: copy everything up to ext_start from input,
/// then write new extension blocks with the provided C2PA store.
fn write_with_c2pa(
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
    store_bytes: &[u8],
    ext_start: u64,
) -> Result<()> {
    input_stream.rewind()?;

    // Copy everything up to the extension block area
    let mut pre_ext = vec![0u8; ext_start as usize];
    input_stream.read_exact(&mut pre_ext).map_err(|_| {
        Error::InvalidAsset("Failed to read pre-extension data".to_string())
    })?;
    output_stream.write_all(&pre_ext)?;

    // Write extension blocks: 1 block (C2PA)
    let block_count: u16 = 1;
    output_stream.write_all(&block_count.to_be_bytes())?;

    // C2PA block: type + length + data
    output_stream.write_all(C2PA_BLOCK_TYPE)?;
    let store_len = store_bytes.len() as u32;
    output_stream.write_all(&store_len.to_be_bytes())?;
    output_stream.write_all(store_bytes)?;

    Ok(())
}

impl CAIReader for FactiIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let layout = parse_layout(asset_reader)?;
        match layout.c2pa_data {
            Some(data) => Ok(data),
            None => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        // .fact* formats do not contain XMP metadata
        None
    }
}

impl CAIWriter for FactiIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let layout = parse_layout(input_stream)?;
        write_with_c2pa(input_stream, output_stream, store_bytes, layout.ext_start)
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let layout = parse_layout(input_stream)?;

        match (layout.c2pa_offset, layout.c2pa_len) {
            (Some(offset), Some(len)) => Ok(vec![HashObjectPositions {
                offset: offset as usize,
                length: len as usize,
                htype: HashBlockObjectType::Cai,
            }]),
            _ => {
                // No C2PA block yet — report where it would go
                // (after ext_start + 2 bytes block count + 4 type + 4 len)
                Ok(vec![HashObjectPositions {
                    offset: (layout.ext_start + 2 + 4 + 4) as usize,
                    length: 0,
                    htype: HashBlockObjectType::Cai,
                }])
            }
        }
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let layout = parse_layout(input_stream)?;

        // Copy everything up to extension blocks, write 0 blocks
        input_stream.rewind()?;
        let mut pre_ext = vec![0u8; layout.ext_start as usize];
        input_stream.read_exact(&mut pre_ext)?;
        output_stream.write_all(&pre_ext)?;

        // Write zero extension blocks
        let block_count: u16 = 0;
        output_stream.write_all(&block_count.to_be_bytes())?;

        Ok(())
    }
}

impl AssetIO for FactiIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        FactiIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(FactiIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, _asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(FactiIO {}))
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut input = File::open(asset_path)?;
        let layout = parse_layout(&mut input)?;

        let temp_path = asset_path.with_extension("tmp");
        {
            let mut output = File::create(&temp_path)?;
            input.rewind()?;

            let mut pre_ext = vec![0u8; layout.ext_start as usize];
            input.read_exact(&mut pre_ext)?;
            output.write_all(&pre_ext)?;

            let block_count: u16 = 1;
            output.write_all(&block_count.to_be_bytes())?;
            output.write_all(C2PA_BLOCK_TYPE)?;
            let store_len = store_bytes.len() as u32;
            output.write_all(&store_len.to_be_bytes())?;
            output.write_all(store_bytes)?;
        }

        std::fs::rename(&temp_path, asset_path)?;
        Ok(())
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut f = File::open(asset_path)?;
        CAIWriter::get_object_locations_from_stream(self, &mut f)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut input = File::open(asset_path)?;
        let layout = parse_layout(&mut input)?;

        let temp_path = asset_path.with_extension("tmp");
        {
            let mut output = File::create(&temp_path)?;
            input.rewind()?;
            let mut pre_ext = vec![0u8; layout.ext_start as usize];
            input.read_exact(&mut pre_ext)?;
            output.write_all(&pre_ext)?;
            let block_count: u16 = 0;
            output.write_all(&block_count.to_be_bytes())?;
        }

        std::fs::rename(&temp_path, asset_path)?;
        Ok(())
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }
}

impl ComposedManifestRef for FactiIO {
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        // The C2PA JUMBF is stored directly in the extension block — no additional wrapping needed
        Ok(manifest_data.to_vec())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    /// Build a minimal .facti v2 container for testing.
    /// Contains a small JPEG payload and space for extension blocks.
    pub fn build_test_facti_container() -> Vec<u8> {
        let metadata = br#"{"format_version":2,"image_length":2,"creator":"test"}"#;
        let media = [0xFF, 0xD8]; // minimal JPEG SOI marker
        let meta_len = metadata.len() as u32;

        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC_FACTI);
        buf.extend_from_slice(&meta_len.to_be_bytes());
        buf.extend_from_slice(metadata);
        buf.extend_from_slice(&media);
        // Extension blocks: 0 blocks initially
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf
    }

    /// Build a minimal .facta v2 container for testing.
    pub fn build_test_facta_container() -> Vec<u8> {
        let metadata = br#"{"format_version":2,"media_length":4,"creator":"test"}"#;
        let media = [0x00, 0x00, 0x00, 0x00]; // placeholder audio
        let meta_len = metadata.len() as u32;

        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC_FACTA);
        buf.extend_from_slice(&meta_len.to_be_bytes());
        buf.extend_from_slice(metadata);
        buf.extend_from_slice(&media);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf
    }

    /// Build a minimal .factv v2 container for testing.
    pub fn build_test_factv_container() -> Vec<u8> {
        let metadata = br#"{"format_version":2,"media_length":4,"creator":"test"}"#;
        let media = [0x00, 0x00, 0x00, 0x00]; // placeholder video
        let meta_len = metadata.len() as u32;

        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC_FACTV);
        buf.extend_from_slice(&meta_len.to_be_bytes());
        buf.extend_from_slice(metadata);
        buf.extend_from_slice(&media);
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf
    }

    #[test]
    fn test_roundtrip_facti() {
        let container = build_test_facti_container();
        let handler = FactiIO::new("facti");
        let store_bytes = b"fake_jumbf_manifest_data";

        // Write C2PA store
        let mut reader = Cursor::new(container);
        let mut writer = Cursor::new(Vec::new());
        handler
            .write_cai(&mut reader, &mut writer, store_bytes)
            .unwrap();

        // Read it back
        writer.set_position(0);
        let read_back = handler.read_cai(&mut writer).unwrap();
        assert_eq!(read_back, store_bytes);
    }

    #[test]
    fn test_roundtrip_facta() {
        let container = build_test_facta_container();
        let handler = FactiIO::new("facta");
        let store_bytes = b"fake_audio_manifest";

        let mut reader = Cursor::new(container);
        let mut writer = Cursor::new(Vec::new());
        handler
            .write_cai(&mut reader, &mut writer, store_bytes)
            .unwrap();

        writer.set_position(0);
        let read_back = handler.read_cai(&mut writer).unwrap();
        assert_eq!(read_back, store_bytes);
    }

    #[test]
    fn test_roundtrip_factv() {
        let container = build_test_factv_container();
        let handler = FactiIO::new("factv");
        let store_bytes = b"fake_video_manifest";

        let mut reader = Cursor::new(container);
        let mut writer = Cursor::new(Vec::new());
        handler
            .write_cai(&mut reader, &mut writer, store_bytes)
            .unwrap();

        writer.set_position(0);
        let read_back = handler.read_cai(&mut writer).unwrap();
        assert_eq!(read_back, store_bytes);
    }

    #[test]
    fn test_no_manifest_returns_not_found() {
        let container = build_test_facti_container();
        let handler = FactiIO::new("facti");
        let mut reader = Cursor::new(container);
        let result = handler.read_cai(&mut reader);
        assert!(matches!(result, Err(Error::JumbfNotFound)));
    }

    #[test]
    fn test_remove_cai_store() {
        let container = build_test_facti_container();
        let handler = FactiIO::new("facti");
        let store_bytes = b"manifest_to_remove";

        // Write then remove
        let mut reader = Cursor::new(container);
        let mut with_manifest = Cursor::new(Vec::new());
        handler
            .write_cai(&mut reader, &mut with_manifest, store_bytes)
            .unwrap();

        with_manifest.set_position(0);
        let mut removed = Cursor::new(Vec::new());
        handler
            .remove_cai_store_from_stream(&mut with_manifest, &mut removed)
            .unwrap();

        removed.set_position(0);
        let result = handler.read_cai(&mut removed);
        assert!(matches!(result, Err(Error::JumbfNotFound)));
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let bad_data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let handler = FactiIO::new("facti");
        let mut reader = Cursor::new(bad_data);
        let result = handler.read_cai(&mut reader);
        assert!(matches!(result, Err(Error::InvalidAsset(_))));
    }

    #[test]
    fn test_object_locations() {
        let container = build_test_facti_container();
        let handler = FactiIO::new("facti");
        let store_bytes = b"test_store";

        let mut reader = Cursor::new(container);
        let mut writer = Cursor::new(Vec::new());
        handler
            .write_cai(&mut reader, &mut writer, store_bytes)
            .unwrap();

        writer.set_position(0);
        let locations = handler
            .get_object_locations_from_stream(&mut writer)
            .unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].htype, HashBlockObjectType::Cai);
        assert_eq!(locations[0].length, store_bytes.len());
    }

    #[test]
    fn test_supported_types() {
        let handler = FactiIO::new("");
        let types = handler.supported_types();
        assert!(types.contains(&"facti"));
        assert!(types.contains(&"facta"));
        assert!(types.contains(&"factv"));
        assert!(types.contains(&"image/vnd.blockfact.facti"));
        assert!(types.contains(&"audio/vnd.blockfact.facta"));
        assert!(types.contains(&"video/vnd.blockfact.factv"));
    }
}
