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
    fs::{self, File},
    io::{self, Cursor, Read, SeekFrom},
    path::Path,
    str,
};

use byteorder::{ReadBytesExt, WriteBytesExt};
use serde_bytes::ByteBuf;
use tempfile::Builder;

use crate::{
    assertions::{BoxMap, C2PA_BOXHASH},
    asset_io::{
        self, AssetBoxHash, AssetIO, AssetPatch, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        ComposedManifestRef, HashBlockObjectType, HashObjectPositions, RemoteRefEmbed,
        RemoteRefEmbedType,
    },
    error::Result,
    utils::{
        io_utils::stream_len,
        xmp_inmemory_utils::{self, MIN_XMP},
    },
    Error,
};

// https://www.w3.org/Graphics/GIF/spec-gif89a.txt
pub struct GifIO {}

impl CAIReader for GifIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        self.find_c2pa_block(asset_reader)?
            .map(|marker| marker.block.data_sub_blocks.to_decoded_bytes())
            .ok_or(Error::JumbfNotFound)
    }

    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        let mut bytes = self
            .find_xmp_block(asset_reader)
            .ok()?
            .map(|marker| marker.block.data_sub_blocks.to_decoded_bytes())?;

        // TODO: this should be validated on construction
        // Validate the 258-byte XMP magic trailer (excluding terminator).
        if let Some(byte) = bytes.get(bytes.len() - 257) {
            if *byte != 1 {
                return None;
            }
        }
        for (i, byte) in bytes.iter().rev().take(256).enumerate() {
            if *byte != i as u8 {
                return None;
            }
        }

        bytes.truncate(bytes.len() - 257);
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
        let old_block_marker = self.find_c2pa_block(input_stream)?;
        let new_block = ApplicationExtension::new_c2pa(store_bytes)?;

        match old_block_marker {
            Some(old_block_marker) => self.replace_block(
                input_stream,
                output_stream,
                &old_block_marker.into(),
                &new_block.into(),
            ),
            None => self.insert_block(input_stream, output_stream, &new_block.into()),
        }
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let c2pa_block = self.find_c2pa_block(input_stream)?;
        match c2pa_block {
            Some(c2pa_block) => Ok(vec![
                HashObjectPositions {
                    offset: 0,
                    length: usize::try_from(c2pa_block.start() - 1)?,
                    htype: HashBlockObjectType::Other,
                },
                HashObjectPositions {
                    offset: usize::try_from(c2pa_block.start())?,
                    length: usize::try_from(c2pa_block.len())?,
                    htype: HashBlockObjectType::Cai,
                },
                HashObjectPositions {
                    offset: usize::try_from(c2pa_block.end())?,
                    length: usize::try_from(stream_len(input_stream)? - c2pa_block.end())?,
                    htype: HashBlockObjectType::Other,
                },
            ]),
            None => {
                self.skip_preamble(input_stream)?;

                let end_preamble_pos = usize::try_from(input_stream.stream_position()?)?;
                Ok(vec![
                    HashObjectPositions {
                        offset: 0,
                        length: end_preamble_pos - 1,
                        htype: HashBlockObjectType::Other,
                    },
                    HashObjectPositions {
                        offset: end_preamble_pos,
                        length: 1, // Need at least size 1.
                        htype: HashBlockObjectType::Cai,
                    },
                    HashObjectPositions {
                        offset: end_preamble_pos + 1,
                        length: usize::try_from(stream_len(input_stream)?)? - end_preamble_pos,
                        htype: HashBlockObjectType::Other,
                    },
                ])
            }
        }
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        match self.find_c2pa_block(input_stream)? {
            Some(block_marker) => {
                self.remove_block(input_stream, output_stream, &block_marker.into())
            }
            None => {
                input_stream.rewind()?;
                io::copy(input_stream, output_stream)?;
                Ok(())
            }
        }
    }
}

impl AssetPatch for GifIO {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut stream = fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let old_block_marker = match self.find_c2pa_block(&mut stream)? {
            Some(old_block_marker) => old_block_marker,
            None => return Err(Error::JumbfNotFound),
        };

        let new_block = ApplicationExtension::new_c2pa(store_bytes)?;

        self.replace_block_in_place(&mut stream, &old_block_marker.into(), &new_block.into())
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
                        .unwrap_or_else(|| MIN_XMP.to_string()),
                    &url,
                )?;

                let old_block_marker = self.find_xmp_block(source_stream)?;
                let new_block = ApplicationExtension::new_xmp(xmp.into_bytes())?;

                match old_block_marker {
                    Some(old_block_marker) => self.replace_block(
                        source_stream,
                        output_stream,
                        &old_block_marker.into(),
                        &new_block.into(),
                    ),
                    None => self.insert_block(source_stream, output_stream, &new_block.into()),
                }
            }
            _ => Err(Error::UnsupportedType),
        }
    }
}

impl ComposedManifestRef for GifIO {
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        ApplicationExtension::new_c2pa(manifest_data)?.to_bytes()
    }
}

impl AssetBoxHash for GifIO {
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>> {
        let c2pa_block_exists = self.find_c2pa_block(input_stream)?.is_some();

        Blocks::new(input_stream)?
            .try_fold(
                (Vec::new(), None, 0),
                |(mut box_maps, last_marker, mut offset),
                 marker|
                 -> Result<(Vec<_>, Option<BlockMarker<Block>>, usize)> {
                    let marker = marker?;

                    // If the C2PA block doesn't exist, we need to insert a placeholder after the global color table
                    // if it exists, or otherwise after the logical screen descriptor.
                    if !c2pa_block_exists {
                        if let Some(last_marker) = last_marker.as_ref() {
                            let should_insert_placeholder = match last_marker.block {
                                Block::GlobalColorTable(_) => true,
                                // If the current block is a global color table, then wait til the next iteration to insert.
                                Block::LogicalScreenDescriptor(_)
                                    if !matches!(marker.block, Block::GlobalColorTable(_)) =>
                                {
                                    true
                                }
                                _ => false,
                            };
                            if should_insert_placeholder {
                                offset += 1;
                                box_maps.push(
                                    BlockMarker {
                                        block: Block::ApplicationExtension(
                                            ApplicationExtension::new_c2pa(&[])?,
                                        ),
                                        start: marker.start,
                                        len: 1,
                                    }
                                    .to_box_map()?,
                                );
                            }
                        }
                    }

                    // According to C2PA spec, these blocks must be grouped into the same box map.
                    match marker.block {
                        // If it's a local color table, then an image descriptor MUST have come before it.
                        // If it's a global color table, then a logical screen descriptor MUST have come before it.
                        Block::LocalColorTable(_) | Block::GlobalColorTable(_) => {
                            match box_maps.last_mut() {
                                Some(last_box_map) => {
                                    last_box_map.range_len += usize::try_from(marker.len())?
                                }
                                // Realistically, this case is unreachable, but to play it safe, we error.
                                None => return Err(Error::NotFound),
                            }
                        }
                        _ => {
                            let mut box_map = marker.to_box_map()?;
                            box_map.range_start += offset;
                            box_maps.push(box_map);
                        }
                    }
                    Ok((box_maps, Some(marker), offset))
                },
            )
            .map(|(box_maps, _, _)| box_maps)
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

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
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

        asset_io::rename_or_move(temp_file, asset_path)
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

        asset_io::rename_or_move(temp_file, asset_path)
    }

    fn supported_types(&self) -> &[&str] {
        &["gif", "image/gif"]
    }
}

impl GifIO {
    fn skip_preamble(&self, stream: &mut dyn CAIRead) -> Result<()> {
        stream.rewind()?;

        Header::from_stream(stream)?;
        let logical_screen_descriptor = LogicalScreenDescriptor::from_stream(stream)?;
        if logical_screen_descriptor.color_table_flag {
            GlobalColorTable::from_stream(stream, logical_screen_descriptor.color_resolution)?;
        }

        Ok(())
    }

    // According to spec, C2PA blocks must come before the first image descriptor.
    fn find_c2pa_block(
        &self,
        stream: &mut dyn CAIRead,
    ) -> Result<Option<BlockMarker<ApplicationExtension>>> {
        self.find_app_block_from_iterator(
            ApplicationExtensionKind::C2pa,
            Blocks::new(stream)?.take_while(|marker| {
                !matches!(
                    marker,
                    Ok(BlockMarker {
                        block: Block::ImageDescriptor(_),
                        ..
                    })
                )
            }),
        )
    }

    fn find_xmp_block(
        &self,
        stream: &mut dyn CAIRead,
    ) -> Result<Option<BlockMarker<ApplicationExtension>>> {
        self.find_app_block_from_iterator(ApplicationExtensionKind::Xmp, Blocks::new(stream)?)
    }

    fn find_app_block_from_iterator(
        &self,
        kind: ApplicationExtensionKind,
        mut iterator: impl Iterator<Item = Result<BlockMarker<Block>>>,
    ) -> Result<Option<BlockMarker<ApplicationExtension>>> {
        iterator
            .find_map(|marker| match marker {
                Ok(marker) => match marker.block {
                    Block::ApplicationExtension(app_ext) if app_ext.kind() == kind => {
                        Some(Ok(BlockMarker {
                            start: marker.start,
                            len: marker.len,
                            block: app_ext,
                        }))
                    }
                    _ => None,
                },
                Err(err) => Some(Err(err)),
            })
            .transpose()
    }

    // TODO: the methods below can be implemented much more conveniently within impl BlockMarker<Block>

    fn remove_block(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        block_meta: &BlockMarker<Block>,
    ) -> Result<()> {
        input_stream.rewind()?;
        output_stream.rewind()?;

        let mut start_stream = input_stream.take(block_meta.start());
        io::copy(&mut start_stream, output_stream)?;

        let input_stream = start_stream.into_inner();
        input_stream.seek(SeekFrom::Current(i64::try_from(block_meta.len())?))?;
        io::copy(input_stream, output_stream)?;

        Ok(())
    }

    fn replace_block(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        old_block_marker: &BlockMarker<Block>,
        new_block: &Block,
    ) -> Result<()> {
        input_stream.rewind()?;
        output_stream.rewind()?;

        // Write everything before the replacement block.
        let mut start_stream = input_stream.take(old_block_marker.start());
        io::copy(&mut start_stream, output_stream)?;

        output_stream.write_all(&new_block.to_bytes()?)?;

        // Write everything after the replacement block.
        let input_stream = start_stream.into_inner();
        input_stream.seek(SeekFrom::Current(i64::try_from(old_block_marker.len())?))?;
        io::copy(input_stream, output_stream)?;

        Ok(())
    }

    fn replace_block_in_place(
        &self,
        stream: &mut dyn CAIReadWrite,
        old_block_marker: &BlockMarker<Block>,
        new_block: &Block,
    ) -> Result<()> {
        // TODO: if new_block len < old_block len, pad the new block
        let new_bytes = new_block.to_bytes()?;
        if new_bytes.len() as u64 != old_block_marker.len() {
            return Err(Error::EmbeddingError);
        }

        stream.seek(SeekFrom::Start(old_block_marker.start()))?;
        stream.write_all(&new_bytes)?;

        Ok(())
    }

    fn insert_block(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        block: &Block,
    ) -> Result<()> {
        self.skip_preamble(input_stream)?;

        // Position before any blocks start.
        let end_preamble_pos = input_stream.stream_position()?;

        input_stream.rewind()?;
        output_stream.rewind()?;

        let mut start_stream = input_stream.take(end_preamble_pos);
        io::copy(&mut start_stream, output_stream)?;

        output_stream.write_all(&block.to_bytes()?)?;

        let input_stream = start_stream.into_inner();
        io::copy(input_stream, output_stream)?;

        self.update_to_89a(output_stream)
    }

    // GIF has two versions: 87a and 89a. 87a doesn't support block extensions, so if the input stream is
    // 87a we need to update it to 89a.
    fn update_to_89a(&self, stream: &mut dyn CAIReadWrite) -> Result<()> {
        stream.seek(SeekFrom::Start(4))?;
        // 0x39 is 9 in ASCII.
        stream.write_u8(0x39)?;
        Ok(())
    }
}

struct Blocks<'a> {
    next: Option<BlockMarker<Block>>,
    stream: &'a mut dyn CAIRead,
    reached_trailer: bool,
}

impl<'a> Blocks<'a> {
    fn new(stream: &'a mut dyn CAIRead) -> Result<Blocks<'a>> {
        stream.rewind()?;

        let start = stream.stream_position()?;
        let block = Block::Header(Header::from_stream(stream)?);
        let end = stream.stream_position()?;

        Ok(Blocks {
            next: Some(BlockMarker {
                len: end - start,
                start,
                block,
            }),
            stream,
            reached_trailer: false,
        })
    }

    fn parse_next(&mut self) -> Result<BlockMarker<Block>> {
        match self.next.take() {
            Some(marker) => {
                self.next = marker.block.next_block_hint(self.stream)?;
                Ok(marker)
            }
            None => {
                let marker = Block::from_stream(self.stream)?;
                self.next = marker.block.next_block_hint(self.stream)?;

                if let Block::Trailer = marker.block {
                    self.reached_trailer = true;
                }

                Ok(marker)
            }
        }
    }
}

impl Iterator for Blocks<'_> {
    type Item = Result<BlockMarker<Block>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reached_trailer {
            true => None,
            false => match self.parse_next() {
                Ok(marker) => Some(Ok(marker)),
                Err(err) => Some(Err(err)),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct BlockMarker<T> {
    start: u64,
    len: u64,
    block: T,
}

impl<T> BlockMarker<T> {
    fn len(&self) -> u64 {
        self.len
    }

    fn start(&self) -> u64 {
        self.start
    }

    fn end(&self) -> u64 {
        self.start + self.len
    }
}

impl BlockMarker<Block> {
    fn to_box_map(&self) -> Result<BoxMap> {
        let mut names = Vec::new();
        if let Some(name) = self.block.box_id() {
            names.push(name.to_owned());
        }

        Ok(BoxMap {
            names,
            alg: None,
            hash: ByteBuf::from(Vec::new()),
            pad: ByteBuf::from(Vec::new()),
            range_start: usize::try_from(self.start())?,
            range_len: usize::try_from(self.len())?,
        })
    }
}

impl From<BlockMarker<ApplicationExtension>> for BlockMarker<Block> {
    fn from(value: BlockMarker<ApplicationExtension>) -> Self {
        BlockMarker {
            start: value.start,
            len: value.len,
            block: Block::ApplicationExtension(value.block),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Block {
    Header(Header),
    LogicalScreenDescriptor(LogicalScreenDescriptor),
    GlobalColorTable(GlobalColorTable),
    GraphicControlExtension(GraphicControlExtension),
    PlainTextExtension(PlainTextExtension),
    ApplicationExtension(ApplicationExtension),
    CommentExtension(CommentExtension),
    ImageDescriptor(ImageDescriptor),
    LocalColorTable(LocalColorTable),
    ImageData(ImageData),
    Trailer,
}

impl Block {
    fn from_stream(stream: &mut dyn CAIRead) -> Result<BlockMarker<Block>> {
        let start = stream.stream_position()?;

        let ext_introducer = stream.read_u8()?;
        let block = match ext_introducer {
            0x21 => {
                let ext_label = stream.read_u8()?;
                match ext_label {
                    0xff => Ok(Block::ApplicationExtension(
                        ApplicationExtension::from_stream(stream)?,
                    )),
                    0xfe => Ok(Block::CommentExtension(CommentExtension::from_stream(
                        stream,
                    )?)),
                    0xf9 => Ok(Block::GraphicControlExtension(
                        GraphicControlExtension::from_stream(stream)?,
                    )),
                    0x01 => Ok(Block::PlainTextExtension(PlainTextExtension::from_stream(
                        stream,
                    )?)),
                    ext_label => Err(Error::InvalidAsset(format!(
                        "Invalid block extension label: {ext_label}"
                    ))),
                }
            }
            0x2c => Ok(Block::ImageDescriptor(ImageDescriptor::from_stream(
                stream,
            )?)),
            0x3b => Ok(Block::Trailer),
            ext_introducer => Err(Error::InvalidAsset(format!(
                "Invalid block id: {ext_introducer}"
            ))),
        }?;

        let end = stream.stream_position()?;
        Ok(BlockMarker {
            start,
            len: end - start,
            block,
        })
    }

    // Some blocks MUST come after other blocks, this function ensures that.
    fn next_block_hint(&self, stream: &mut dyn CAIRead) -> Result<Option<BlockMarker<Block>>> {
        let start = stream.stream_position()?;
        let next_block = match self {
            Block::Header(_) => Some(Block::LogicalScreenDescriptor(
                LogicalScreenDescriptor::from_stream(stream)?,
            )),
            Block::LogicalScreenDescriptor(logical_screen_descriptor) => {
                match logical_screen_descriptor.color_table_flag {
                    true => Some(Block::GlobalColorTable(GlobalColorTable::from_stream(
                        stream,
                        logical_screen_descriptor.color_resolution,
                    )?)),
                    false => None,
                }
            }
            Block::GlobalColorTable(_) => None,
            // Block::GraphicControlExtension(_) => match stream.read_u8()? {
            //     0x21 => match stream.read_u8()? {
            //         0x01 => Some(Block::PlainTextExtension(PlainTextExtension::from_stream(
            //             stream,
            //         )?)),
            //         ext_label => {
            //             return Err(Error::InvalidAsset(format!(
            //             "Block extension `{ext_label}` cannot come after graphic control extension"
            //         )))
            //         }
            //     },
            //     0x2c => Some(Block::ImageDescriptor(ImageDescriptor::from_stream(
            //         stream,
            //     )?)),
            //     ext_introducer => {
            //         return Err(Error::InvalidAsset(format!(
            //             "Block id `{ext_introducer}` cannot come after graphic control extension"
            //         )))
            //     }
            // },
            // In a valid GIF, a plain text extension or image descriptor MUST come after a graphic control extension.
            // However, it turns out not even our sample GIF follows this restriction! Since we don't really care about
            // the correctness of the GIF (more so that our modifications are correct), we ignore this restriction.
            Block::GraphicControlExtension(_) => None,
            Block::PlainTextExtension(_) => None,
            Block::ApplicationExtension(_) => None,
            Block::CommentExtension(_) => None,
            Block::ImageDescriptor(image_descriptor) => {
                match image_descriptor.local_color_table_flag {
                    true => Some(Block::LocalColorTable(LocalColorTable::from_stream(
                        stream,
                        image_descriptor.local_color_table_size,
                    )?)),
                    false => Some(Block::ImageData(ImageData::from_stream(stream)?)),
                }
            }
            Block::LocalColorTable(_) => Some(Block::ImageData(ImageData::from_stream(stream)?)),
            Block::ImageData(_) => None,
            Block::Trailer => None,
        };

        let end = stream.stream_position()?;
        Ok(next_block.map(|block| BlockMarker {
            len: end - start,
            start,
            block,
        }))
    }

    fn box_id(&self) -> Option<&'static str> {
        match self {
            Block::Header(_) => Some("GIF89a"),
            Block::LogicalScreenDescriptor(_) => Some("LSD"),
            Block::GlobalColorTable(_) => None,
            Block::GraphicControlExtension(_) => Some("21F9"),
            Block::PlainTextExtension(_) => Some("2101"),
            Block::ApplicationExtension(application_extension) => {
                match ApplicationExtensionKind::C2pa == application_extension.kind() {
                    true => Some(C2PA_BOXHASH),
                    false => Some("21FF"),
                }
            }
            Block::CommentExtension(_) => Some("21FE"),
            Block::ImageDescriptor(_) => Some("2C"),
            Block::LocalColorTable(_) => None,
            Block::ImageData(_) => Some("TBID"),
            Block::Trailer => Some("3B"),
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Block::ApplicationExtension(app_ext) => app_ext.to_bytes(),
            // We only care about app extensions.
            _ => Err(Error::UnsupportedType),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Header {
    // version: [u8; 3],
}

impl Header {
    fn from_stream(stream: &mut dyn CAIRead) -> Result<Header> {
        let mut signature = [0u8; 3];
        stream.read_exact(&mut signature)?;
        if signature != *b"GIF" {
            return Err(Error::InvalidAsset("GIF signature invalid".to_owned()));
        }

        let mut version = [0u8; 3];
        stream.read_exact(&mut version)?;

        Ok(Header {
            // version
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct LogicalScreenDescriptor {
    color_table_flag: bool,
    color_resolution: u8,
}

impl LogicalScreenDescriptor {
    fn from_stream(stream: &mut dyn CAIRead) -> Result<LogicalScreenDescriptor> {
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

#[derive(Debug, Clone, PartialEq)]
struct GlobalColorTable {}

impl GlobalColorTable {
    fn from_stream(stream: &mut dyn CAIRead, color_resolution: u8) -> Result<GlobalColorTable> {
        stream.seek(SeekFrom::Current(
            3 * (2_i64.pow(color_resolution as u32 + 1)),
        ))?;

        Ok(GlobalColorTable {})
    }
}

#[derive(Debug, PartialEq)]
enum ApplicationExtensionKind {
    C2pa,
    Xmp,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
struct ApplicationExtension {
    identifier: [u8; 8],
    authentication_code: [u8; 3],
    data_sub_blocks: DataSubBlocks,
}

impl ApplicationExtension {
    fn new_c2pa(bytes: &[u8]) -> Result<ApplicationExtension> {
        Ok(ApplicationExtension {
            identifier: *b"C2PA_GIF",
            authentication_code: [0x01, 0x00, 0x00],
            data_sub_blocks: DataSubBlocks::from_decoded_bytes(bytes)?,
        })
    }

    fn new_xmp(mut bytes: Vec<u8>) -> Result<ApplicationExtension> {
        // Add XMP magic trailer.
        bytes.reserve(257);
        bytes.push(1);
        for byte in (0..=255).rev() {
            bytes.push(byte);
        }

        Ok(ApplicationExtension {
            identifier: *b"XMP Data",
            authentication_code: [0x58, 0x4d, 0x50],
            data_sub_blocks: DataSubBlocks::from_decoded_bytes(&bytes)?,
        })
    }

    fn from_stream(stream: &mut dyn CAIRead) -> Result<ApplicationExtension> {
        let app_block_size = stream.read_u8()?;
        // App block size is a fixed value.
        if app_block_size != 0x0b {
            return Err(Error::InvalidAsset(format!(
                "Invalid block size for app block extension {app_block_size}!=11"
            )));
        }

        let mut app_id = [0u8; 8];
        stream.read_exact(&mut app_id)?;

        let mut app_auth_code = [0u8; 3];
        stream.read_exact(&mut app_auth_code)?;

        let mut app_block_ext = ApplicationExtension {
            identifier: app_id,
            authentication_code: app_auth_code,
            data_sub_blocks: DataSubBlocks::empty(),
        };

        match app_block_ext.kind() {
            ApplicationExtensionKind::C2pa | ApplicationExtensionKind::Xmp => {
                app_block_ext.data_sub_blocks = DataSubBlocks::from_encoded_stream(stream)?;
            }
            // Ignore caching unknown app blocks as we don't need it.
            ApplicationExtensionKind::Unknown => {
                DataSubBlocks::from_encoded_stream_and_skip(stream)?;
            }
        };

        Ok(app_block_ext)
    }

    fn kind(&self) -> ApplicationExtensionKind {
        match (&self.identifier, self.authentication_code) {
            (b"C2PA_GIF", [0x01, 0x00, 0x00]) => ApplicationExtensionKind::C2pa,
            (b"XMP Data", [0x58, 0x4d, 0x50]) => ApplicationExtensionKind::Xmp,
            (_, _) => ApplicationExtensionKind::Unknown,
        }
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = self.data_sub_blocks.to_encoded_bytes();
        // The header size + the amount of byte length markers + the amount of bytes stored + terminator.
        let mut header = Vec::with_capacity(14 + bytes.len().div_ceil(255) + bytes.len() + 1);
        header.push(0x21);
        header.push(0xff);
        header.push(0x0b);
        header.extend_from_slice(&self.identifier);
        header.extend_from_slice(&self.authentication_code);
        header.extend_from_slice(bytes);
        Ok(header)
    }
}

impl From<ApplicationExtension> for Block {
    fn from(value: ApplicationExtension) -> Self {
        Block::ApplicationExtension(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct PlainTextExtension {}

impl PlainTextExtension {
    fn from_stream(stream: &mut dyn CAIRead) -> Result<PlainTextExtension> {
        stream.seek(SeekFrom::Current(11))?;
        DataSubBlocks::from_encoded_stream_and_skip(stream)?;
        Ok(PlainTextExtension {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CommentExtension {}

impl CommentExtension {
    fn from_stream(stream: &mut dyn CAIRead) -> Result<CommentExtension> {
        // stream.seek(SeekFrom::Current(0))?;
        DataSubBlocks::from_encoded_stream_and_skip(stream)?;
        Ok(CommentExtension {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct GraphicControlExtension {}

impl GraphicControlExtension {
    // TODO: validate ext introducer and label, and do that for other extensions?
    fn from_stream(stream: &mut dyn CAIRead) -> Result<GraphicControlExtension> {
        stream.seek(SeekFrom::Current(6))?;
        Ok(GraphicControlExtension {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ImageDescriptor {
    local_color_table_flag: bool,
    local_color_table_size: u8,
}

impl ImageDescriptor {
    fn from_stream(stream: &mut dyn CAIRead) -> Result<ImageDescriptor> {
        stream.seek(SeekFrom::Current(8))?;

        let packed = stream.read_u8()?;
        let local_color_table_flag = (packed >> 7) & 1;
        let local_color_table_size = packed & 0b111;

        Ok(ImageDescriptor {
            local_color_table_flag: local_color_table_flag != 0,
            local_color_table_size,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct LocalColorTable {}

impl LocalColorTable {
    fn from_stream(
        stream: &mut dyn CAIRead,
        local_color_table_size: u8,
    ) -> Result<LocalColorTable> {
        stream.seek(SeekFrom::Current(
            3 * (2_i64.pow(local_color_table_size as u32 + 1)),
        ))?;
        Ok(LocalColorTable {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ImageData {}

impl ImageData {
    fn from_stream(stream: &mut dyn CAIRead) -> Result<ImageData> {
        stream.seek(SeekFrom::Current(1))?;
        DataSubBlocks::from_encoded_stream_and_skip(stream)?;
        Ok(ImageData {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct DataSubBlocks {
    bytes: Vec<u8>,
}

impl DataSubBlocks {
    fn empty() -> DataSubBlocks {
        // Terminator byte.
        DataSubBlocks { bytes: vec![0] }
    }

    // fn from_encoded_bytes(bytes: Vec<u8>) -> DataSubBlocks {
    //     DataSubBlocks { bytes }
    // }

    fn from_decoded_bytes(bytes: &[u8]) -> Result<DataSubBlocks> {
        // The amount of length marker bytes + amount of bytes + terminator byte.
        let mut data_sub_blocks = Vec::with_capacity(bytes.len().div_ceil(255) + bytes.len() + 1);
        for chunk in bytes.chunks(255) {
            data_sub_blocks.push(chunk.len() as u8);
            data_sub_blocks.extend_from_slice(chunk);
        }

        // Add terminator.
        data_sub_blocks.push(0);

        Ok(DataSubBlocks {
            bytes: data_sub_blocks,
        })
    }

    fn from_encoded_stream(stream: &mut dyn CAIRead) -> Result<DataSubBlocks> {
        let mut data_sub_blocks = Vec::new();
        loop {
            let sub_block_size = stream.read_u8()?;
            if sub_block_size == 0 {
                break;
            }

            data_sub_blocks.push(sub_block_size);

            let start = data_sub_blocks.len();
            let end = start + sub_block_size as usize;
            data_sub_blocks.resize(end, 0);

            stream.read_exact(&mut data_sub_blocks[start..end])?;
        }

        data_sub_blocks.push(0);

        Ok(DataSubBlocks {
            bytes: data_sub_blocks,
        })
    }

    fn from_encoded_stream_and_skip(stream: &mut dyn CAIRead) -> Result<u64> {
        let mut length = 0;
        loop {
            let sub_block_size = stream.read_u8()?;
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

    fn to_encoded_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_decoded_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(gif_chunks(&self.bytes).map(|c| c.len()).sum());
        for chunk in gif_chunks(&self.bytes) {
            bytes.extend_from_slice(chunk);
        }
        bytes
    }
}

fn gif_chunks(mut encoded_bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let (&len, rest) = encoded_bytes.split_first()?;
        if len == 0 {
            return None;
        }
        let (chunk, rest) = rest.split_at_checked(len.into())?;
        encoded_bytes = rest;
        Some(chunk)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use io::{Cursor, Seek};
    use xmp_inmemory_utils::extract_provenance;

    use super::*;

    const SAMPLE1: &[u8] = include_bytes!("../../tests/fixtures/sample1.gif");

    #[test]
    fn test_read_blocks() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let blocks: Vec<_> = Blocks::new(&mut stream)?.collect::<Result<_>>()?;
        assert_eq!(
            blocks.first(),
            Some(&BlockMarker {
                start: 0,
                len: 6,
                block: Block::Header(Header {})
            })
        );
        assert_eq!(
            blocks.get(1),
            Some(&BlockMarker {
                start: 6,
                len: 7,
                block: Block::LogicalScreenDescriptor(LogicalScreenDescriptor {
                    color_table_flag: true,
                    color_resolution: 7
                })
            })
        );
        assert_eq!(
            blocks.get(2),
            Some(&BlockMarker {
                start: 13,
                len: 768,
                block: Block::GlobalColorTable(GlobalColorTable {})
            })
        );
        assert_eq!(
            blocks.get(3),
            Some(&BlockMarker {
                start: 781,
                len: 19,
                block: Block::ApplicationExtension(ApplicationExtension {
                    identifier: *b"NETSCAPE",
                    authentication_code: [50, 46, 48],
                    data_sub_blocks: DataSubBlocks::empty(),
                })
            })
        );
        assert_eq!(
            blocks.get(4),
            Some(&BlockMarker {
                start: 800,
                len: 8,
                block: Block::GraphicControlExtension(GraphicControlExtension {})
            })
        );
        assert_eq!(
            blocks.get(5),
            Some(&BlockMarker {
                start: 808,
                len: 52,
                block: Block::CommentExtension(CommentExtension {})
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

        let mut output_stream1 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 7));
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

        let mut bytes = Vec::new();
        output_stream2.rewind()?;
        output_stream2.read_to_end(&mut bytes)?;
        assert_eq!(SAMPLE1, bytes);

        Ok(())
    }

    #[test]
    fn test_write_insert_two_blocks() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);
        let mut output_stream1 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));

        let gif_io = GifIO {};

        let test_block = Block::ApplicationExtension(ApplicationExtension {
            identifier: *b"12345678",
            authentication_code: [0, 0, 0],
            data_sub_blocks: DataSubBlocks::empty(),
        });
        gif_io.insert_block(&mut stream, &mut output_stream1, &test_block)?;
        let mut output_stream2 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        gif_io.insert_block(&mut output_stream1, &mut output_stream2, &test_block)?;

        let blocks: Vec<_> = Blocks::new(&mut output_stream2)?.collect::<Result<_>>()?;
        assert_eq!(
            blocks.get(3),
            Some(&BlockMarker {
                start: 781,
                len: 15,
                block: test_block.clone()
            })
        );
        assert_eq!(
            blocks.get(4),
            Some(&BlockMarker {
                start: 796,
                len: 15,
                block: test_block
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

        let mut output_stream = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 7));
        let random_bytes = [1, 2, 3, 4, 3, 2, 1];
        gif_io.write_cai(&mut stream, &mut output_stream, &random_bytes)?;

        let data_written = gif_io.read_cai(&mut output_stream)?;
        assert_eq!(data_written, random_bytes);

        Ok(())
    }

    #[test]
    fn test_write_bytes_replace() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let gif_io = GifIO {};

        assert!(matches!(
            gif_io.read_cai(&mut stream),
            Err(Error::JumbfNotFound)
        ));

        let mut output_stream1 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 7));
        let random_bytes = [1, 2, 3, 4, 3, 2, 1];
        gif_io.write_cai(&mut stream, &mut output_stream1, &random_bytes)?;

        let data_written = gif_io.read_cai(&mut output_stream1)?;
        assert_eq!(data_written, random_bytes);

        let mut output_stream2 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 5));
        let random_bytes = [3, 2, 1, 2, 3];
        gif_io.write_cai(&mut output_stream1, &mut output_stream2, &random_bytes)?;

        let data_written = gif_io.read_cai(&mut output_stream2)?;
        assert_eq!(data_written, random_bytes);

        let mut bytes = Vec::new();
        stream.rewind()?;
        stream.read_to_end(&mut bytes)?;
        assert_eq!(SAMPLE1, bytes);

        Ok(())
    }

    #[test]
    fn test_data_hash_locations() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let gif_io = GifIO {};

        let obj_locations = gif_io.get_object_locations_from_stream(&mut stream)?;
        assert_eq!(
            obj_locations.first(),
            Some(&HashObjectPositions {
                offset: 0,
                length: 780,
                htype: HashBlockObjectType::Other,
            })
        );
        assert_eq!(
            obj_locations.get(1),
            Some(&HashObjectPositions {
                offset: 781,
                length: 1,
                htype: HashBlockObjectType::Cai,
            })
        );
        assert_eq!(
            obj_locations.get(2),
            Some(&HashObjectPositions {
                offset: 782,
                length: SAMPLE1.len() - 781,
                htype: HashBlockObjectType::Other,
            })
        );
        assert_eq!(obj_locations.len(), 3);

        let mut output_stream1 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 4));
        gif_io.write_cai(&mut stream, &mut output_stream1, &[1, 2, 3, 4])?;

        let mut obj_locations = gif_io.get_object_locations_from_stream(&mut output_stream1)?;
        obj_locations.sort_by_key(|pos| pos.offset);

        assert_eq!(
            obj_locations.first(),
            Some(&HashObjectPositions {
                offset: 0,
                length: 780,
                htype: HashBlockObjectType::Other,
            })
        );
        assert_eq!(
            obj_locations.get(1),
            Some(&HashObjectPositions {
                offset: 781,
                length: 20,
                htype: HashBlockObjectType::Cai,
            })
        );
        assert_eq!(
            obj_locations.get(2),
            Some(&HashObjectPositions {
                offset: 801,
                length: SAMPLE1.len() - 781,
                htype: HashBlockObjectType::Other,
            })
        );
        assert_eq!(obj_locations.len(), 3);

        Ok(())
    }

    #[test]
    fn test_box_hash_locations() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let gif_io = GifIO {};

        let box_map = gif_io.get_box_map(&mut stream)?;
        assert_eq!(
            box_map.first(),
            Some(&BoxMap {
                names: vec!["GIF89a".to_owned()],
                alg: None,
                hash: ByteBuf::from(Vec::new()),
                pad: ByteBuf::from(Vec::new()),
                range_start: 0,
                range_len: 6
            })
        );
        assert_eq!(
            box_map.get(box_map.len() / 2),
            Some(&BoxMap {
                names: vec!["2C".to_owned()],
                alg: None,
                hash: ByteBuf::from(Vec::new()),
                pad: ByteBuf::from(Vec::new()),
                range_start: 368495,
                range_len: 778
            })
        );
        assert_eq!(
            box_map.last(),
            Some(&BoxMap {
                names: vec!["3B".to_owned()],
                alg: None,
                hash: ByteBuf::from(Vec::new()),
                pad: ByteBuf::from(Vec::new()),
                range_start: SAMPLE1.len(),
                range_len: 1
            })
        );
        assert_eq!(box_map.len(), 276);

        Ok(())
    }

    #[test]
    fn test_composed_manifest() -> Result<()> {
        let gif_io = GifIO {};

        let block = gif_io.compose_manifest(&[1, 2, 3], "")?;
        assert_eq!(
            block,
            vec![33, 255, 11, 67, 50, 80, 65, 95, 71, 73, 70, 1, 0, 0, 3, 1, 2, 3, 0]
        );

        Ok(())
    }

    #[test]
    fn test_remote_ref() -> Result<()> {
        let mut stream = Cursor::new(SAMPLE1);

        let gif_io = GifIO {};

        assert_eq!(gif_io.read_xmp(&mut stream), None);

        let mut output_stream1 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        gif_io.embed_reference_to_stream(
            &mut stream,
            &mut output_stream1,
            RemoteRefEmbedType::Xmp("Test".to_owned()),
        )?;

        let xmp = gif_io.read_xmp(&mut output_stream1).unwrap();
        let p = extract_provenance(&xmp).unwrap();
        assert_eq!(&p, "Test");

        Ok(())
    }
}
