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
    fs::File,
    io::{self, Read, SeekFrom},
    path::Path,
    str,
};

use byteorder::ReadBytesExt;
use tempfile::Builder;

use crate::{
    asset_io::{rename_or_copy, AssetIO, CAIReader, CAIWriter, HashObjectPositions},
    error::Result,
    CAIRead, CAIReadWrite, Error,
};

// https://www.w3.org/Graphics/GIF/spec-gif89a.txt
pub struct GifIO {}

impl CAIReader for GifIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        self.parse_preamble(asset_reader)?;

        self.start_block_extensions(asset_reader)?
            .into_iter()
            .find_map(|block| match block.kind {
                BlockExtensionKind::Application {
                    content: AppBlockExtContent::C2pa(content),
                    ..
                } => Some(content),
                _ => None,
            })
            .ok_or(Error::JumbfNotFound)
    }

    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        // TODO: gif is supported by xmp, need to find xmp block
        None
    }
}

impl CAIWriter for GifIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        self.parse_preamble(input_stream)?;

        // Cache the start pos here before we start reading any blocks.
        let start_pos = input_stream.stream_position()?;

        let c2pa_block = self
            .start_block_extensions(input_stream)?
            .into_iter()
            .find(|block| {
                matches!(
                    block.kind,
                    BlockExtensionKind::Application {
                        content: AppBlockExtContent::C2pa(_),
                        ..
                    }
                )
            });
        let data_sub_blocks = bytes_to_data_sub_blocks(store_bytes)?;
        match c2pa_block {
            Some(block) => {
                let start_pos = block.start_pos;

                // TODO: we shouldn't need to read from the stream again, we already read it
                //       from parse_preamble
                input_stream.seek(SeekFrom::Start(0))?;
                let mut start_stream = input_stream.take(start_pos);
                io::copy(&mut start_stream, output_stream)?;

                let input_stream = start_stream.into_inner();
                output_stream.write_all(&data_sub_blocks)?;
                // Move the rest of the data from the gif.
                io::copy(input_stream, output_stream)?;
            }
            None => {
                // TODO: same here
                input_stream.seek(SeekFrom::Start(0))?;
                let mut start_stream = input_stream.take(start_pos);
                io::copy(&mut start_stream, output_stream)?;

                output_stream.write_all(&data_sub_blocks)?;
            }
        }

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        todo!()
    }

    fn remove_cai_store_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
        _output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        todo!()
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
        let mut stream = std::fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.write_cai(&mut stream, &mut temp_file, store_bytes)?;

        // copy temp file to asset
        rename_or_copy(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut f = std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;
        self.get_object_locations_from_stream(&mut f)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> crate::Result<()> {
        self.save_cai_store(asset_path, &[])
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
    // Block extensions can be located before the image data or afater. The C2PA manifest will
    // always be before, so we don't worry about other cases.
    fn start_block_extensions(&self, stream: &mut dyn CAIRead) -> Result<Vec<BlockExtension>> {
        let mut blocks = Vec::new();
        loop {
            let extension_introducer = stream.read_u8()?;
            match extension_introducer {
                // If it's a block extension, parse it.
                0x21 => {
                    blocks.push(BlockExtension::new(stream)?);
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
}

struct Header {}

impl Header {
    fn new(stream: &mut dyn CAIRead) -> Result<Header> {
        // We don't really care about the header so skip it for now.
        stream.seek(SeekFrom::Current(6))?;
        Ok(Header {})
    }
}

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
            3 * (2 ^ (lsd.color_resolution as i64 + 1)),
        ))?;

        Ok(GlobalColorTable {})
    }
}

enum AppBlockExtContent {
    C2pa(Vec<u8>),
    Xmp(String),
    Unknown,
}

enum BlockExtensionKind {
    Application {
        identifier: String,
        authentication_code: [u8; 3],
        content: AppBlockExtContent,
    },
    PlainText,
    GraphicsControl,
    Comment,
}

struct BlockExtension {
    start_pos: u64,
    length: u64,
    kind: BlockExtensionKind,
}

impl BlockExtension {
    pub fn new(stream: &mut dyn CAIRead) -> Result<BlockExtension> {
        let start_pos = stream.stream_position()?;

        let extension_label = stream.read_u8()?;
        // Next we check if the extension is an application data block.
        match extension_label {
            // Application Extension
            0xff => {
                let app_block_size = stream.read_u8()?;
                // App block size is a fixed value.
                if app_block_size == 0xb {
                    // First 8 bytes is the app identifier.
                    let mut app_id = [0u8; 8];
                    stream.read_exact(&mut app_id)?;
                    let app_id = str::from_utf8(&app_id)?;

                    // First 3 bytes is the app auth code.
                    let mut app_auth_code = [0u8; 3];
                    stream.read_exact(&mut app_auth_code)?;

                    match (app_id, app_auth_code) {
                        // C2PA app block
                        ("C2PA_GIF", [0x01, 0x00, 0x00]) => {
                            let bytes = data_sub_block_bytes(stream)?;
                            // First calculate how many bytes we need to represent each sub block length,
                            // then add one to account for terminator, then add the total amount of bytes.
                            let data_sub_block_total_length =
                                ((bytes.len() / 255) + 1) + bytes.len();
                            return Ok(BlockExtension {
                                start_pos,
                                // 21 is size of header
                                length: (data_sub_block_total_length + 21) as u64,
                                kind: BlockExtensionKind::Application {
                                    identifier: app_id.to_owned(),
                                    authentication_code: app_auth_code,
                                    content: AppBlockExtContent::C2pa(bytes),
                                },
                            });
                        }
                        // TODO: XMP app block
                        // Unknown app block
                        (_, _) => {
                            return Ok(BlockExtension {
                                start_pos,
                                length: data_sub_block_length(stream)? + 21,
                                kind: BlockExtensionKind::Application {
                                    identifier: app_id.to_owned(),
                                    authentication_code: app_auth_code,
                                    content: AppBlockExtContent::Unknown,
                                },
                            });
                        }
                    }
                }

                Err(Error::UnsupportedType)
            }
            // Plain Text Extension
            0x01 => {
                // 13 bytes for the header
                stream.seek(SeekFrom::Current(13))?;
                Ok(BlockExtension {
                    start_pos,
                    length: data_sub_block_length(stream)? + 12,
                    kind: BlockExtensionKind::PlainText,
                })
            }
            // Comment Extension
            0xfe => {
                // 2 bytes for the header
                stream.seek(SeekFrom::Current(2))?;

                Ok(BlockExtension {
                    start_pos,
                    length: data_sub_block_length(stream)? + 2,
                    kind: BlockExtensionKind::Comment,
                })
            }
            // Graphics Control Extension
            0xf9 => Ok(BlockExtension {
                start_pos,
                length: 8,
                kind: BlockExtensionKind::GraphicsControl,
            }),
            _ => Err(Error::UnsupportedType),
        }
    }
}

fn bytes_to_data_sub_blocks(bytes: &[u8]) -> Result<Vec<u8>> {
    // The amount of bytes + the amount of byte length bytes + terminator byte.
    let mut data_sub_blocks = Vec::with_capacity(bytes.len() + (bytes.len() / 255) + 1);
    for chunk in bytes.chunks(255) {
        data_sub_blocks.push(chunk.len() as u8);
        data_sub_blocks.extend_from_slice(chunk);
    }

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
