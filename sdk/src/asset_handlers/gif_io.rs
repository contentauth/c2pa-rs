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

// TODO: temp
#![allow(dead_code)]

use std::{
    fs::{self, File},
    io::{self, Read, SeekFrom},
    path::Path,
    str,
};

use byteorder::ReadBytesExt;
use tempfile::Builder;

use crate::{
    asset_io::{self, AssetIO, CAIReader, CAIWriter, HashObjectPositions},
    error::Result,
    CAIRead, CAIReadWrite, Error,
};

// https://www.w3.org/Graphics/GIF/spec-gif89a.txt
pub struct GifIO {}

impl CAIReader for GifIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        self.find_app_block(asset_reader, AppBlockExtKind::C2pa)?
            // TODO: don't like having to do this, we know it's a c2pa block
            .map(|c2pa_block| match c2pa_block.kind {
                BlockExtension::Application(app_block_ext) => app_block_ext.bytes,
                _ => unreachable!(),
            })
            .ok_or(Error::JumbfNotFound)
    }

    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        self.parse_preamble(asset_reader).ok()?;

        // TODO: find_app_block only checks for block extensions before image data (corresponding to c2pa spec)
        //       xmp doesn't specify if it's before or after, so we need to check both
        let mut bytes = self
            .find_app_block(asset_reader, AppBlockExtKind::Xmp)
            .ok()?
            // TODO: same here
            .map(|c2pa_block| match c2pa_block.kind {
                BlockExtension::Application(app_block_ext) => app_block_ext.bytes,
                _ => unreachable!(),
            })?;

        // Validate the 258-byte XMP magic trailer.
        if let Some(byte) = bytes.get(bytes.len() - 258) {
            if *byte != 1 {
                return None;
            }
        }
        for (i, byte) in bytes.iter().rev().take(258).enumerate() {
            if *byte != i as u8 {
                return None;
            }
        }

        bytes.truncate(bytes.len() - 258);
        String::from_utf8(bytes).ok()
    }
}

impl CAIWriter for GifIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let old_block = self.find_app_block(input_stream, AppBlockExtKind::C2pa)?;

        let new_block = BlockExtension::Application(AppBlockExtension {
            identifier: String::from("C2PA_GIF"),
            authentication_code: [0x01, 0x00, 0x00],
            // TODO: don't clone here, we can store bytes as a Cow,
            //       but that significantly increases code complexity
            //       best choice is probably to create a separate struct
            //       that takes borrowed bytes for the sole purpose of
            //       writing
            bytes: store_bytes.to_owned(),
        });

        // TODO: add with_premable functions so we don't have to parse it again
        match old_block {
            Some(old_block) => {
                self.replace_block_extension(input_stream, output_stream, &old_block, &new_block)
            }
            None => self.insert_block_extension(input_stream, output_stream, &new_block),
        }
    }

    fn get_object_locations_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        todo!()
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        match self.find_app_block(input_stream, AppBlockExtKind::C2pa)? {
            Some(c2pa_block) => {
                self.remove_block_extension(input_stream, output_stream, &c2pa_block)
            }
            None => Err(Error::JumbfNotFound),
        }
    }
}

impl AssetIO for GifIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        GifIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(GifIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn read_cai_store(&self, asset_path: &Path) -> crate::Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> crate::Result<()> {
        let mut stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.write_cai(&mut stream, &mut temp_file, store_bytes)?;

        asset_io::rename_or_copy(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut f = std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;
        self.get_object_locations_from_stream(&mut f)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> crate::Result<()> {
        let mut stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.remove_cai_store_from_stream(&mut stream, &mut temp_file)?;

        asset_io::rename_or_copy(temp_file, asset_path)
    }

    fn supported_types(&self) -> &[&str] {
        &["gif", "image/gif"]
    }
}

impl GifIO {
    fn parse_preamble(
        &self,
        mut stream: &mut dyn CAIRead,
    ) -> Result<(Header, LogicalScreenDescriptor, Option<GlobalColorTable>)> {
        stream.rewind()?;

        let header = Header::new(&mut stream)?;
        let logical_screen_descriptor = LogicalScreenDescriptor::new(&mut stream)?;
        let global_color_table = if logical_screen_descriptor.color_table_flag {
            Some(GlobalColorTable::new(
                &logical_screen_descriptor,
                &mut stream,
            )?)
        } else {
            None
        };

        Ok((header, logical_screen_descriptor, global_color_table))
    }

    // TODO: create an iterator over block extensions so we don't need to parse them all
    // Block extensions can be located before the image data or after. The C2PA manifest will
    // always be before, so we don't worry about other cases.
    fn parse_start_block_extensions(
        &self,
        stream: &mut dyn CAIRead,
    ) -> Result<Vec<BlockExtensionMeta>> {
        let mut blocks = Vec::new();
        loop {
            let extension_introducer = stream.read_u8()?;
            match extension_introducer {
                // If it's a block extension, parse it.
                0x21 => {
                    blocks.push(BlockExtensionMeta::new(stream)?);
                }
                // If it's the start of an image descriptor, there's no C2PA manifest.
                // According to the C2PA spec, it must be before the first image descriptor.
                0x2c => break,
                // If it's not a image descriptor or an extension then it's an invalid GIF.
                _ => break,
            }
        }

        Ok(blocks)
    }

    fn find_app_block(
        &self,
        stream: &mut dyn CAIRead,
        kind: AppBlockExtKind,
    ) -> Result<Option<BlockExtensionMeta>> {
        self.parse_preamble(stream)?;

        Ok(self
            .parse_start_block_extensions(stream)?
            .into_iter()
            .find(|block| {
                matches!(&block.kind, BlockExtension::Application(app_block_ext) if app_block_ext.kind() == kind)
            }))
    }

    fn remove_block_extension(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        block_meta: &BlockExtensionMeta,
    ) -> Result<()> {
        self.parse_preamble(input_stream)?;

        input_stream.rewind()?;
        output_stream.rewind()?;

        // TODO: same here
        let mut start_stream = input_stream.take(block_meta.start_pos - 1);
        io::copy(&mut start_stream, output_stream)?;

        let input_stream = start_stream.into_inner();
        input_stream.seek(SeekFrom::Current(i64::try_from(block_meta.length)?))?;
        io::copy(input_stream, output_stream)?;

        Ok(())
    }

    fn replace_block_extension(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        old_block_meta: &BlockExtensionMeta,
        new_block: &BlockExtension,
    ) -> Result<()> {
        self.parse_preamble(input_stream)?;

        input_stream.rewind()?;
        output_stream.rewind()?;

        // TODO: we shouldn't need to read from the stream again, we already read it
        //       from parse_preamble
        // Write everything before the replacement block.
        let mut start_stream = input_stream.take(old_block_meta.start_pos - 1);
        io::copy(&mut start_stream, output_stream)?;

        output_stream.write_all(&new_block.to_bytes()?)?;

        // Write everything after the replacement block.
        let input_stream = start_stream.into_inner();
        input_stream.seek(SeekFrom::Current(i64::try_from(old_block_meta.length)?))?;
        io::copy(input_stream, output_stream)?;

        Ok(())
    }

    fn insert_block_extension(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        block: &BlockExtension,
    ) -> Result<()> {
        self.parse_preamble(input_stream)?;

        // Position before any blocks start.
        let end_preamble_pos = input_stream.stream_position()?;

        input_stream.rewind()?;
        output_stream.rewind()?;

        // TODO: same here
        let mut start_stream = input_stream.take(end_preamble_pos);
        io::copy(&mut start_stream, output_stream)?;

        output_stream.write_all(&block.to_bytes()?)?;

        let input_stream = start_stream.into_inner();
        io::copy(input_stream, output_stream)?;

        Ok(())
    }
}

struct Header {}

impl Header {
    fn new(stream: &mut dyn CAIRead) -> Result<Header> {
        // We don't really care about the header so skip it for now.
        stream.seek(SeekFrom::Current(6))?;
        Ok(Header {})
    }
}

#[derive(Debug)]
struct LogicalScreenDescriptor {
    color_table_flag: bool,
    color_resolution: u8,
}

impl LogicalScreenDescriptor {
    fn new(stream: &mut dyn CAIRead) -> Result<LogicalScreenDescriptor> {
        // Don't need this info.
        stream.seek(SeekFrom::Current(4))?;

        let packed = stream.read_u8()?;
        let color_table_flag = (packed >> 7) & 1;
        let color_resolution = (packed >> 4) & 0b111;

        // We got everything we need, skip the rest.
        stream.seek(SeekFrom::Current(2))?;

        Ok(LogicalScreenDescriptor {
            color_table_flag: color_table_flag != 0,
            color_resolution,
        })
    }
}

struct GlobalColorTable {}

impl GlobalColorTable {
    fn new(lsd: &LogicalScreenDescriptor, stream: &mut dyn CAIRead) -> Result<GlobalColorTable> {
        // Just need to skip it.
        stream.seek(SeekFrom::Current(
            3 * (2_i64.pow(lsd.color_resolution as u32 + 1)),
        ))?;

        Ok(GlobalColorTable {})
    }
}

#[derive(Debug, PartialEq)]
enum AppBlockExtKind {
    C2pa,
    Xmp,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
struct AppBlockExtension {
    identifier: String,
    authentication_code: [u8; 3],
    bytes: Vec<u8>,
}

impl AppBlockExtension {
    fn kind(&self) -> AppBlockExtKind {
        match (self.identifier.as_str(), self.authentication_code) {
            ("C2PA_GIF", [0x01, 0x00, 0x00]) => AppBlockExtKind::C2pa,
            ("XMP Data", [0x58, 0x4d, 0x50]) => AppBlockExtKind::Xmp,
            (_, _) => AppBlockExtKind::Unknown,
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        // Get the amount of byte length markers plus one for terminator, the amount of bytes stored,
        // and the size of the header.
        let mut header = Vec::with_capacity((self.bytes.len() / 255) + 1 + self.bytes.len() + 14);
        header.push(0x21);
        header.push(0xff);
        header.push(0x0b);
        // TODO: if identifier <8 bytes pad it, if it's >8 bytes error
        header.extend_from_slice(self.identifier.as_bytes());
        header.extend_from_slice(&self.authentication_code);

        let data_sub_blocks = bytes_to_data_sub_blocks(&self.bytes)?;
        header.extend_from_slice(&data_sub_blocks);

        Ok(header)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum BlockExtension {
    Application(AppBlockExtension),
    PlainText,
    GraphicControl,
    Comment,
}

impl BlockExtension {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            BlockExtension::Application(app_block_ext) => app_block_ext.to_bytes(),
            // We only care about app block extensions.
            _ => Err(Error::UnsupportedType),
        }
    }
}

#[derive(Debug, PartialEq)]
struct BlockExtensionMeta {
    start_pos: u64,
    length: u64,
    kind: BlockExtension,
}

impl BlockExtensionMeta {
    fn new(stream: &mut dyn CAIRead) -> Result<BlockExtensionMeta> {
        // TODO: pass in extension introducer (seek -1 stream), it is part of the block.
        // Subtracted by 1 to account for extension introducer.
        let start_pos = stream.stream_position()?;

        let extension_label = stream.read_u8()?;

        // Next we check if the extension is an application data block.
        match extension_label {
            // Application Extension
            0xff => {
                let app_block_size = stream.read_u8()?;
                // App block size is a fixed value.
                if app_block_size == 0x0b {
                    // First 8 bytes is the app identifier.
                    let mut app_id = [0u8; 8];
                    stream.read_exact(&mut app_id)?;
                    let app_id = str::from_utf8(&app_id)?;

                    // First 3 bytes is the app auth code.
                    let mut app_auth_code = [0u8; 3];
                    stream.read_exact(&mut app_auth_code)?;

                    let mut app_block_ext = AppBlockExtension {
                        identifier: app_id.to_owned(),
                        authentication_code: app_auth_code,
                        bytes: Vec::new(),
                    };

                    // Ignore caching unknown app blocks as we don't need it.
                    let (bytes, data_len) = match app_block_ext.kind() {
                        AppBlockExtKind::C2pa | AppBlockExtKind::Xmp => {
                            let bytes = data_sub_block_bytes(stream)?;

                            // Amount of bytes needed for the data sub block length markers.
                            let length_marker_bytes = bytes.len().div_ceil(255);
                            // Add one for terminator.
                            let data_len = length_marker_bytes + bytes.len() + 1;

                            (bytes, data_len as u64)
                        }
                        AppBlockExtKind::Unknown => {
                            (app_block_ext.bytes, data_sub_block_length(stream)?)
                        }
                    };
                    app_block_ext.bytes = bytes;

                    Ok(BlockExtensionMeta {
                        start_pos,
                        length: data_len + 14,
                        kind: BlockExtension::Application(app_block_ext),
                    })
                } else {
                    Err(Error::UnsupportedType)
                }
            }
            // Plain Text Extension
            0x01 => {
                // 13 bytes for the header (excluding ext introducer and label).
                stream.seek(SeekFrom::Current(11))?;

                Ok(BlockExtensionMeta {
                    start_pos,
                    length: data_sub_block_length(stream)? + 13,
                    kind: BlockExtension::PlainText,
                })
            }
            // Comment Extension
            0xfe => {
                // 2 bytes for the header (excluding ext introducer and label).
                // stream.seek(SeekFrom::Current(0))?;

                Ok(BlockExtensionMeta {
                    start_pos,
                    length: data_sub_block_length(stream)? + 2,
                    kind: BlockExtension::Comment,
                })
            }
            // Graphics Control Extension
            0xf9 => {
                // 8 bytes for everything (excluding ext introducer and label).
                stream.seek(SeekFrom::Current(6))?;

                Ok(BlockExtensionMeta {
                    start_pos,
                    length: 8,
                    kind: BlockExtension::GraphicControl,
                })
            }
            _ => Err(Error::UnsupportedType),
        }
    }
}

fn bytes_to_data_sub_blocks(bytes: &[u8]) -> Result<Vec<u8>> {
    // The amount of length marker bytes + amount of bytes + terminator byte.
    let mut data_sub_blocks = Vec::with_capacity(bytes.len().div_ceil(255) + bytes.len() + 1);
    for chunk in bytes.chunks(255) {
        data_sub_blocks.push(chunk.len() as u8);
        data_sub_blocks.extend_from_slice(chunk);
    }

    // Add terminator.
    data_sub_blocks.push(0);

    Ok(data_sub_blocks)
}

fn data_sub_block_bytes(stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
    let mut data = Vec::new();

    let mut sub_block = [0u8; 255];
    loop {
        // First byte is the sub block size.
        let sub_block_size = stream.read_u8()? as usize;

        // If we are at the last block.
        if sub_block_size == 0 {
            break;
        }

        // Read sub_block_size bytes then insert it into data vec.
        let mut bytes_read = 0;
        while bytes_read < sub_block_size {
            bytes_read += stream.read(&mut sub_block[bytes_read..sub_block_size])?;
        }

        data.extend_from_slice(&sub_block[..bytes_read]);
    }

    Ok(data)
}

fn data_sub_block_length(stream: &mut dyn CAIRead) -> Result<u64> {
    let mut length = 0;
    loop {
        let sub_block_size = stream.read_u8()?;
        // Add one to account for the block size byte.
        length += 1;

        if sub_block_size == 0 {
            break;
        } else {
            length += sub_block_size as u64;
            stream.seek(SeekFrom::Current(sub_block_size as i64))?;
        }
    }

    Ok(length)
}

#[cfg(test)]
mod tests {
    use io::Cursor;

    use super::*;

    const SAMPLE1: &[u8] = include_bytes!("../../tests/fixtures/sample1.gif");

    #[test]
    fn test_read_start_blocks() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let gif_io = GifIO {};
        gif_io.parse_preamble(&mut stream)?;

        let blocks = gif_io.parse_start_block_extensions(&mut stream)?;
        assert_eq!(
            blocks[0],
            BlockExtensionMeta {
                start_pos: 782,
                length: 19,
                kind: BlockExtension::Application(AppBlockExtension {
                    identifier: String::from("NETSCAPE"),
                    authentication_code: [50, 46, 48],
                    bytes: Vec::new()
                })
            }
        );
        assert_eq!(
            blocks[1],
            BlockExtensionMeta {
                start_pos: 801,
                length: 8,
                kind: BlockExtension::GraphicControl
            }
        );
        assert_eq!(
            blocks[2],
            BlockExtensionMeta {
                start_pos: 809,
                length: 52,
                kind: BlockExtension::Comment
            }
        );

        Ok(())
    }

    #[test]
    fn test_write_remove_block() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let gif_io = GifIO {};

        assert!(matches!(
            gif_io.read_cai(&mut stream),
            Err(Error::JumbfNotFound)
        ));

        let mut output_stream1 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 7));
        let random_bytes = [1, 2, 3, 4, 3, 2, 1];
        gif_io.write_cai(&mut stream, &mut output_stream1, &random_bytes)?;

        let data_written = gif_io.read_cai(&mut output_stream1)?;
        assert_eq!(data_written, random_bytes);

        let mut output_stream2 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        gif_io.remove_cai_store_from_stream(&mut output_stream1, &mut output_stream2)?;

        assert!(matches!(
            gif_io.read_cai(&mut stream),
            Err(Error::JumbfNotFound)
        ));

        Ok(())
    }

    #[test]
    fn test_write_insert_two_blocks() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);
        let mut output_stream1 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));

        let gif_io = GifIO {};

        let test_block = BlockExtension::Application(AppBlockExtension {
            identifier: String::from("12345678"),
            authentication_code: [0, 0, 0],
            bytes: Vec::new(),
        });
        gif_io.insert_block_extension(&mut stream, &mut output_stream1, &test_block)?;
        let mut output_stream2 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        gif_io.insert_block_extension(&mut output_stream1, &mut output_stream2, &test_block)?;

        gif_io.parse_preamble(&mut output_stream2)?;
        let blocks = gif_io.parse_start_block_extensions(&mut output_stream2)?;
        assert_eq!(
            blocks[0],
            BlockExtensionMeta {
                start_pos: 782,
                length: 15,
                kind: test_block.clone()
            }
        );
        assert_eq!(
            blocks[1],
            BlockExtensionMeta {
                start_pos: 797,
                length: 15,
                kind: test_block
            }
        );

        Ok(())
    }

    #[test]
    fn test_write_bytes() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let gif_io = GifIO {};

        assert!(matches!(
            gif_io.read_cai(&mut stream),
            Err(Error::JumbfNotFound)
        ));

        let mut output_stream = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 7));
        let random_bytes = [1, 2, 3, 4, 3, 2, 1];
        gif_io.write_cai(&mut stream, &mut output_stream, &random_bytes)?;

        let data_written = gif_io.read_cai(&mut output_stream)?;
        assert_eq!(data_written, random_bytes);

        Ok(())
    }

    #[test]
    fn test_write_bytes_at_existing_block() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let gif_io = GifIO {};

        assert!(matches!(
            gif_io.read_cai(&mut stream),
            Err(Error::JumbfNotFound)
        ));

        let mut output_stream1 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 7));
        let random_bytes = [1, 2, 3, 4, 3, 2, 1];
        gif_io.write_cai(&mut stream, &mut output_stream1, &random_bytes)?;

        let data_written = gif_io.read_cai(&mut output_stream1)?;
        assert_eq!(data_written, random_bytes);

        let mut output_stream2 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 3));
        let random_bytes = [1, 2, 1];
        gif_io.write_cai(&mut output_stream1, &mut output_stream2, &random_bytes)?;

        let data_written = gif_io.read_cai(&mut output_stream2)?;
        assert_eq!(data_written, random_bytes);

        Ok(())
    }
}
