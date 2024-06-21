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
    io::{self, Cursor, Read, SeekFrom},
    path::Path,
    str,
};

use byteorder::ReadBytesExt;
use tempfile::Builder;

use crate::{
    asset_io::{
        self, AssetIO, AssetPatch, CAIReader, CAIWriter, ComposedManifestRef, HashObjectPositions,
        RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::Result,
    utils::xmp_inmemory_utils::{self, MIN_XMP},
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

        let new_block = BlockExtension::Application(AppBlockExtension::new(
            AppBlockExtKind::C2pa,
            // TODO: don't clone here, we can store bytes as a Cow,
            //       but that significantly increases code complexity
            //       best choice is probably to create a separate struct
            //       that takes borrowed bytes for the sole purpose of
            //       writing
            store_bytes.to_owned(),
        )?);

        // TODO: add with_premable functions so we don't have to parse it again
        match old_block {
            Some(old_block) => {
                self.replace_block_ext(input_stream, output_stream, &old_block, &new_block)
            }
            None => self.insert_block_ext(input_stream, output_stream, &new_block),
        }
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        // TODO: add xmp block hash pos
        let c2pa_block = self.find_app_block(input_stream, AppBlockExtKind::C2pa)?;
        match c2pa_block {
            Some(c2pa_block) => Ok(vec![
                HashObjectPositions {
                    offset: 0,
                    length: usize::try_from(c2pa_block.start_pos - 1)?,
                    htype: asset_io::HashBlockObjectType::Other,
                },
                HashObjectPositions {
                    offset: usize::try_from(c2pa_block.start_pos)?,
                    length: usize::try_from(c2pa_block.length)?,
                    htype: asset_io::HashBlockObjectType::Cai,
                },
                HashObjectPositions {
                    offset: usize::try_from(c2pa_block.start_pos + c2pa_block.length)?,
                    length: usize::try_from(input_stream.seek(SeekFrom::End(0))?)?,
                    htype: asset_io::HashBlockObjectType::Other,
                },
            ]),
            None => Err(Error::JumbfNotFound),
        }
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        match self.find_app_block(input_stream, AppBlockExtKind::C2pa)? {
            Some(c2pa_block) => self.remove_block_ext(input_stream, output_stream, &c2pa_block),
            None => Err(Error::JumbfNotFound),
        }
    }
}

impl AssetPatch for GifIO {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let old_block = match self.find_app_block(&mut stream, AppBlockExtKind::C2pa)? {
            Some(old_block) => old_block,
            None => return Err(Error::JumbfNotFound),
        };

        let new_block = BlockExtension::Application(AppBlockExtension::new(
            AppBlockExtKind::C2pa,
            // TODO: don't clone here as well
            store_bytes.to_owned(),
        )?);

        self.replace_block_ext_in_place(&mut stream, &old_block, &new_block)
    }
}

impl RemoteRefEmbed for GifIO {
    fn embed_reference(&self, asset_path: &Path, embed_ref: RemoteRefEmbedType) -> Result<()> {
        match &embed_ref {
            RemoteRefEmbedType::Xmp(_) => {
                let mut input_stream = File::open(asset_path)?;
                let mut output_stream = Cursor::new(Vec::new());
                self.embed_reference_to_stream(&mut input_stream, &mut output_stream, embed_ref)?;
                fs::write(asset_path, output_stream.into_inner())?;
                Ok(())
            }
            _ => Err(Error::UnsupportedType),
        }
    }

    fn embed_reference_to_stream(
        &self,
        source_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            RemoteRefEmbedType::Xmp(url) => {
                let xmp = xmp_inmemory_utils::add_provenance(
                    // TODO: we read xmp here, then search for it again after, we can cache it
                    &self
                        .read_xmp(source_stream)
                        .unwrap_or_else(|| format!("http://ns.adobe.com/xap/1.0/\0 {}", MIN_XMP)),
                    &url,
                )?;

                // TODO: same problem here as in read_xmp (we need to search after image descs)
                let old_block = self.find_app_block(source_stream, AppBlockExtKind::Xmp)?;

                let new_block = BlockExtension::Application(AppBlockExtension::new(
                    AppBlockExtKind::C2pa,
                    // TODO: avoid cloning
                    xmp.as_bytes().to_owned(),
                )?);

                match old_block {
                    Some(old_block) => {
                        self.replace_block_ext(source_stream, output_stream, &old_block, &new_block)
                    }
                    None => self.insert_block_ext(source_stream, output_stream, &new_block),
                }
            }
            _ => Err(Error::UnsupportedType),
        }
    }
}

impl ComposedManifestRef for GifIO {
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        BlockExtension::Application(AppBlockExtension::new(
            AppBlockExtKind::C2pa,
            // TODO: don't clone here
            manifest_data.to_owned(),
        )?)
        .to_bytes()
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

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(GifIO::new(asset_type)))
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
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
    fn parse_preamble(&self, mut stream: &mut dyn CAIRead) -> Result<Preamble> {
        stream.rewind()?;

        let header = Header::new(&mut stream)?;
        let logical_screen_descriptor = LogicalScreenDescriptor::new(&mut stream)?;
        let global_color_table = if logical_screen_descriptor.color_table_flag {
            Some(GlobalColorTable::new(
                &mut stream,
                &logical_screen_descriptor,
            )?)
        } else {
            None
        };

        Ok(Preamble {
            header,
            logical_screen_descriptor,
            global_color_table,
        })
    }

    // TODO: create an iterator over block extensions so we don't need to parse them all
    // Block extensions can be located before the image data or after. The C2PA manifest will
    // always be before, so we don't worry about other cases.
    fn parse_start_block_exts(&self, stream: &mut dyn CAIRead) -> Result<Vec<BlockExtensionMeta>> {
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

    fn parse_end_block_exts(&self, _stream: &mut dyn CAIRead) -> Result<Vec<BlockExtensionMeta>> {
        // TODO: same as parse_start_block_exts but ends at trailer
        todo!()
    }

    fn parse_images(&self, _stream: &mut dyn CAIRead) -> Result<()> {
        // TODO:
        // * starts at image descriptor
        // * optionally proceeded by graphic control block
        // * optionally proceeded by local color table
        // * proceeded by table based image data
        todo!()
    }

    fn block_extensions(&self, stream: &mut dyn CAIRead) -> Result<Vec<BlockExtensionMeta>> {
        self.parse_preamble(stream)?;
        let _start_block_exts = self.parse_start_block_exts(stream)?;
        self.parse_images(stream)?;
        let _end_block_exts = self.parse_end_block_exts(stream)?;

        // TODO: combine start + end
        // TODO: also make sure when parsing c2pa data it only checks start blocks, xmp checks both
        todo!()
    }

    fn find_app_block(
        &self,
        stream: &mut dyn CAIRead,
        kind: AppBlockExtKind,
    ) -> Result<Option<BlockExtensionMeta>> {
        self.parse_preamble(stream)?;

        Ok(self
            .parse_start_block_exts(stream)?
            .into_iter()
            .find(|block| {
                matches!(&block.kind, BlockExtension::Application(app_block_ext) if app_block_ext.kind() == kind)
            }))
    }

    fn remove_block_ext(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        block_meta: &BlockExtensionMeta,
    ) -> Result<()> {
        self.parse_preamble(input_stream)?;

        input_stream.rewind()?;
        output_stream.rewind()?;

        let mut start_stream = input_stream.take(block_meta.start_pos - 1);
        io::copy(&mut start_stream, output_stream)?;

        let input_stream = start_stream.into_inner();
        input_stream.seek(SeekFrom::Current(i64::try_from(block_meta.length)?))?;
        io::copy(input_stream, output_stream)?;

        Ok(())
    }

    fn replace_block_ext(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        old_block_meta: &BlockExtensionMeta,
        new_block: &BlockExtension,
    ) -> Result<()> {
        self.parse_preamble(input_stream)?;

        input_stream.rewind()?;
        output_stream.rewind()?;

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

    fn replace_block_ext_in_place(
        &self,
        mut stream: &mut dyn CAIReadWrite,
        old_block_meta: &BlockExtensionMeta,
        new_block: &BlockExtension,
    ) -> Result<()> {
        // TODO: if new_block len < old_block len, pad the new block?
        let new_bytes = new_block.to_bytes()?;
        if new_bytes.len() as u64 != old_block_meta.length {
            return Err(Error::EmbeddingError);
        }

        self.parse_preamble(&mut stream)?;

        stream.seek(SeekFrom::Start(old_block_meta.start_pos))?;
        stream.write_all(&new_bytes)?;

        Ok(())
    }

    fn insert_block_ext(
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

        let mut start_stream = input_stream.take(end_preamble_pos);
        io::copy(&mut start_stream, output_stream)?;

        output_stream.write_all(&block.to_bytes()?)?;

        let input_stream = start_stream.into_inner();
        io::copy(input_stream, output_stream)?;

        Ok(())
    }
}

#[derive(Debug)]
struct Preamble {
    header: Header,
    logical_screen_descriptor: LogicalScreenDescriptor,
    global_color_table: Option<GlobalColorTable>,
}

#[derive(Debug)]
struct Header {}

impl Header {
    fn new(stream: &mut dyn CAIRead) -> Result<Header> {
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
        stream.seek(SeekFrom::Current(4))?;

        let packed = stream.read_u8()?;
        let color_table_flag = (packed >> 7) & 1;
        let color_resolution = (packed >> 4) & 0b111;

        stream.seek(SeekFrom::Current(2))?;

        Ok(LogicalScreenDescriptor {
            color_table_flag: color_table_flag != 0,
            color_resolution,
        })
    }
}

#[derive(Debug)]
struct GlobalColorTable {}

impl GlobalColorTable {
    fn new(
        stream: &mut dyn CAIRead,
        logical_screen_descriptor: &LogicalScreenDescriptor,
    ) -> Result<GlobalColorTable> {
        stream.seek(SeekFrom::Current(
            3 * (2_i64.pow(logical_screen_descriptor.color_resolution as u32 + 1)),
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
    fn new(kind: AppBlockExtKind, bytes: Vec<u8>) -> Result<AppBlockExtension> {
        match kind {
            AppBlockExtKind::C2pa => Ok(AppBlockExtension {
                // TODO: add consts for this info
                identifier: String::from("C2PA_GIF"),
                authentication_code: [0x01, 0x00, 0x00],
                bytes,
            }),
            AppBlockExtKind::Xmp => Ok(AppBlockExtension {
                identifier: String::from("XMP_Data"),
                authentication_code: [0x58, 0x4d, 0x50],
                bytes,
            }),
            AppBlockExtKind::Unknown => Err(Error::UnsupportedType),
        }
    }

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
    // TODO: pass in extension introducer (seek -1 stream), it is part of the block.
    fn new(stream: &mut dyn CAIRead) -> Result<BlockExtensionMeta> {
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

#[derive(Debug)]
struct ImageDescriptor {
    local_color_table_flag: bool,
    local_color_table_size: u8,
}

impl ImageDescriptor {
    fn new(stream: &mut dyn CAIRead) -> Result<ImageDescriptor> {
        stream.seek(SeekFrom::Current(9))?;

        let packed = stream.read_u8()?;
        let local_color_table_flag = (packed >> 7) & 1;
        let local_color_table_size = packed & 0b111;

        Ok(ImageDescriptor {
            local_color_table_flag: local_color_table_flag != 0,
            local_color_table_size,
        })
    }
}

#[derive(Debug)]
struct LocalColorTable {}

impl LocalColorTable {
    fn new(
        stream: &mut dyn CAIRead,
        image_descriptor: &ImageDescriptor,
    ) -> Result<LocalColorTable> {
        stream.seek(SeekFrom::Current(
            3 * (2_i64.pow(image_descriptor.local_color_table_size as u32 + 1)),
        ))?;

        Ok(LocalColorTable {})
    }
}

#[derive(Debug)]
struct TableBasedImageData {}

impl TableBasedImageData {
    fn new(stream: &mut dyn CAIRead) -> Result<TableBasedImageData> {
        stream.seek(SeekFrom::Current(1))?;
        data_sub_block_length(stream)?;
        Ok(TableBasedImageData {})
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

        let blocks = gif_io.parse_start_block_exts(&mut stream)?;
        assert_eq!(
            blocks.first(),
            Some(&BlockExtensionMeta {
                start_pos: 782,
                length: 19,
                kind: BlockExtension::Application(AppBlockExtension {
                    identifier: String::from("NETSCAPE"),
                    authentication_code: [50, 46, 48],
                    bytes: Vec::new()
                })
            })
        );
        assert_eq!(
            blocks.get(1),
            Some(&BlockExtensionMeta {
                start_pos: 801,
                length: 8,
                kind: BlockExtension::GraphicControl
            })
        );
        assert_eq!(
            blocks.get(2),
            Some(&BlockExtensionMeta {
                start_pos: 809,
                length: 52,
                kind: BlockExtension::Comment
            })
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
        gif_io.insert_block_ext(&mut stream, &mut output_stream1, &test_block)?;
        let mut output_stream2 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        gif_io.insert_block_ext(&mut output_stream1, &mut output_stream2, &test_block)?;

        gif_io.parse_preamble(&mut output_stream2)?;
        let blocks = gif_io.parse_start_block_exts(&mut output_stream2)?;
        assert_eq!(
            blocks.first(),
            Some(&BlockExtensionMeta {
                start_pos: 782,
                length: 15,
                kind: test_block.clone()
            })
        );
        assert_eq!(
            blocks.get(1),
            Some(&BlockExtensionMeta {
                start_pos: 797,
                length: 15,
                kind: test_block
            })
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

    #[test]
    fn test_write_bytes_in_place() -> Result<()> {
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
        let random_bytes = [4, 3, 2, 1, 2, 3, 4];
        gif_io.write_cai(&mut output_stream1, &mut output_stream2, &random_bytes)?;

        let data_written = gif_io.read_cai(&mut output_stream2)?;
        assert_eq!(data_written, random_bytes);

        Ok(())
    }
}
