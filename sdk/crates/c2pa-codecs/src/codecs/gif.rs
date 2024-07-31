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
    io::{self, Read, Seek, SeekFrom, Write},
    str,
};

use byteorder::{ReadBytesExt, WriteBytesExt};

use crate::{
    xmp::{self, MIN_XMP},
    BoxHash, ByteSpan, DataHash, Decoder, Encoder, Hash, Hasher, NamedByteSpan, ParseError,
    Supporter,
};

// https://www.w3.org/Graphics/GIF/spec-gif89a.txt
#[derive(Debug)]
pub struct GifCodec<R> {
    src: R,
}

impl<R> GifCodec<R> {
    pub fn new(src: R) -> Self {
        Self { src }
    }
}

impl Supporter for GifCodec<()> {
    fn supports_signature(signature: &[u8]) -> bool {
        signature.len() >= 3 && signature == *b"GIF"
    }

    fn supports_extension(ext: &str) -> bool {
        match ext {
            "gif" => true,
            _ => false,
        }
    }

    fn supports_mime(mime: &str) -> bool {
        match mime {
            "image/gif" => true,
            _ => false,
        }
    }
}

impl<R: Read + Seek> Encoder for GifCodec<R> {
    fn write_c2pa(&mut self, mut dst: impl Write, c2pa: &[u8]) -> Result<(), ParseError> {
        let old_block_marker = self.find_c2pa_block()?;
        let new_block = ApplicationExtension::new_c2pa(c2pa)?;

        match old_block_marker {
            Some(old_block_marker) => {
                self.replace_block(&mut dst, &old_block_marker.into(), &new_block.into())
            }
            None => self.insert_block(&mut dst, &new_block.into()),
        }
    }

    fn remove_c2pa(&mut self, mut dst: impl Write) -> Result<bool, ParseError> {
        match self.find_c2pa_block()? {
            Some(block_marker) => {
                self.remove_block(&mut dst, &block_marker.into())?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn patch_c2pa(&self, mut dst: impl Read + Write + Seek, c2pa: &[u8]) -> Result<(), ParseError> {
        let mut codec = GifCodec::new(&mut dst);
        let old_block_marker = match codec.find_c2pa_block()? {
            Some(old_block_marker) => old_block_marker,
            None => return Err(ParseError::NothingToPatch),
        };

        let new_block = ApplicationExtension::new_c2pa(c2pa)?;

        Self::replace_block_in_place(&mut dst, &old_block_marker.into(), &new_block.into())
    }

    fn write_xmp(&mut self, mut dst: impl Write, xmp: &str) -> Result<(), ParseError> {
        let xmp = xmp::add_provenance(
            // TODO: we read xmp here, then search for it again after, we can cache it
            &self
                .read_xmp()?
                .unwrap_or_else(|| format!("http://ns.adobe.com/xap/1.0/\0 {}", MIN_XMP)),
            xmp,
        )?;

        let old_block_marker = self.find_xmp_block()?;
        let new_block = ApplicationExtension::new_xmp(xmp.into_bytes())?;

        match old_block_marker {
            Some(old_block_marker) => {
                self.replace_block(&mut dst, &old_block_marker.into(), &new_block.into())
            }
            None => self.insert_block(&mut dst, &new_block.into()),
        }
    }
}

// TODO: the methods below can be implemented much more conveniently within impl BlockMarker<Block>
impl<R: Read + Seek> GifCodec<R> {
    fn remove_block(
        &mut self,
        mut dst: impl Write,
        block_meta: &BlockMarker<Block>,
    ) -> Result<(), ParseError> {
        self.src.rewind()?;

        let mut start_stream = self.src.by_ref().take(block_meta.start());
        io::copy(&mut start_stream, &mut dst)?;

        self.src.seek(SeekFrom::Current(
            i64::try_from(block_meta.len()).map_err(ParseError::SeekOutOfBounds)?,
        ))?;
        io::copy(&mut self.src, &mut dst)?;

        Ok(())
    }

    fn replace_block(
        &mut self,
        mut dst: impl Write,
        old_block_marker: &BlockMarker<Block>,
        new_block: &Block,
    ) -> Result<(), ParseError> {
        self.src.rewind()?;

        // Write everything before the replacement block.
        let mut start_stream = self.src.by_ref().take(old_block_marker.start());
        io::copy(&mut start_stream, &mut dst)?;

        dst.write_all(&new_block.to_bytes()?)?;

        // Write everything after the replacement block.
        self.src.seek(SeekFrom::Current(
            i64::try_from(old_block_marker.len()).map_err(ParseError::SeekOutOfBounds)?,
        ))?;
        io::copy(&mut self.src, &mut dst)?;

        Ok(())
    }

    fn insert_block(&mut self, mut dst: impl Write, block: &Block) -> Result<(), ParseError> {
        self.skip_preamble()?;

        // Position before any blocks start.
        let end_preamble_pos = self.src.stream_position()?;
        self.update_to_89a(&mut dst)?;
        let after_update_pos = self.src.stream_position()?;

        let mut start_stream = self.src.by_ref().take(end_preamble_pos - after_update_pos);
        io::copy(&mut start_stream, &mut dst)?;

        dst.write_all(&block.to_bytes()?)?;

        io::copy(&mut self.src, &mut dst)?;

        Ok(())
    }

    fn replace_block_in_place(
        mut dst: impl Write + Seek,
        old_block_marker: &BlockMarker<Block>,
        new_block: &Block,
    ) -> Result<(), ParseError> {
        // TODO: if new_block len < old_block len, pad the new block
        let new_bytes = new_block.to_bytes()?;
        if new_bytes.len() as u64 != old_block_marker.len() {
            return Err(ParseError::InvalidPatchSize {
                expected: old_block_marker.len(),
                actually: new_bytes.len() as u64,
            });
        }

        dst.seek(SeekFrom::Start(old_block_marker.start()))?;
        dst.write_all(&new_bytes)?;

        Ok(())
    }

    // GIF has two versions: 87a and 89a. 87a doesn't support block extensions, so if the input stream is
    // 87a we need to update it to 89a.
    fn update_to_89a(&mut self, mut dst: impl Write) -> Result<(), ParseError> {
        self.src.rewind()?;

        let mut before = [0; 4];
        self.src.read_exact(&mut before)?;
        dst.write_all(&before)?;

        // 0x39 is 9 in ASCII.
        dst.write_u8(0x39)?;
        Ok(())
    }
}

impl<R: Read + Seek> Decoder for GifCodec<R> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, ParseError> {
        Ok(self
            .find_c2pa_block()?
            .map(|marker| marker.block.data_sub_blocks.to_decoded_bytes()))
    }

    fn read_xmp(&mut self) -> Result<Option<String>, ParseError> {
        let bytes = self
            .find_xmp_block()?
            .map(|marker| marker.block.data_sub_blocks.to_decoded_bytes());
        match bytes {
            Some(mut bytes) => {
                // TODO: this should be validated on construction
                // Validate the 258-byte XMP magic trailer (excluding terminator).
                if let Some(byte) = bytes.get(bytes.len() - 257) {
                    if *byte != 1 {
                        return Err(ParseError::InvalidXmpBlock);
                    }
                }
                for (i, byte) in bytes.iter().rev().take(256).enumerate() {
                    if *byte != i as u8 {
                        return Err(ParseError::InvalidXmpBlock);
                    }
                }

                bytes.truncate(bytes.len() - 258);
                String::from_utf8(bytes)
                    .map(Some)
                    .map_err(|_| ParseError::InvalidXmpBlock)
            }
            None => Ok(None),
        }
    }
}

impl<R: Read + Seek> Hasher for GifCodec<R> {
    fn hash(&mut self) -> Result<Hash, ParseError> {
        Ok(Hash::Data(self.data_hash()?))
    }

    fn data_hash(&mut self) -> Result<DataHash, ParseError> {
        let c2pa_block = self.find_c2pa_block()?;
        match c2pa_block {
            Some(c2pa_block) => Ok(DataHash {
                spans: vec![ByteSpan {
                    start: c2pa_block.start(),
                    len: c2pa_block.len(),
                }],
            }),
            None => {
                self.skip_preamble()?;

                let end_preamble_pos = self.src.stream_position()?;
                Ok(DataHash {
                    spans: vec![ByteSpan {
                        start: end_preamble_pos,
                        len: 1, // Need at least size 1.
                    }],
                })
            }
        }
    }

    fn box_hash(&mut self) -> Result<BoxHash, ParseError> {
        let c2pa_block_exists = self.find_c2pa_block()?.is_some();

        Blocks::new(&mut self.src)?
            .try_fold(
                (Vec::new(), None, 0),
                |(mut named_spans, last_marker, mut offset),
                 marker|
                 -> Result<(Vec<_>, Option<BlockMarker<Block>>, u64), ParseError> {
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
                                named_spans.push(
                                    BlockMarker {
                                        block: Block::ApplicationExtension(
                                            ApplicationExtension::new_c2pa(&[])?,
                                        ),
                                        start: marker.start,
                                        len: 1,
                                    }
                                    .to_named_byte_span()?,
                                );
                            }
                        }
                    }

                    // According to C2PA spec, these blocks must be grouped into the same box map.
                    match marker.block {
                        // If it's a local color table, then an image descriptor MUST have come before it.
                        // If it's a global color table, then a logical screen descriptor MUST have come before it.
                        Block::LocalColorTable(_) | Block::GlobalColorTable(_) => {
                            match named_spans.last_mut() {
                                Some(last_named_span) => last_named_span.span.len += marker.len(),
                                // Realistically, this case is unreachable, but to play it safe, we error.
                                None => {
                                    return Err(ParseError::InvalidAsset {
                                        reason: "TODO".to_string(),
                                    })
                                }
                            }
                        }
                        _ => {
                            let mut named_span = marker.to_named_byte_span()?;
                            named_span.span.start += offset;
                            named_spans.push(named_span);
                        }
                    }
                    Ok((named_spans, Some(marker), offset))
                },
            )
            .map(|(named_spans, _, _)| BoxHash { spans: named_spans })
    }
}

impl<R: Read + Seek> GifCodec<R> {
    fn skip_preamble(&mut self) -> Result<(), ParseError> {
        self.src.rewind()?;

        Header::from_stream(&mut self.src)?;
        let logical_screen_descriptor = LogicalScreenDescriptor::from_stream(&mut self.src)?;
        if logical_screen_descriptor.color_table_flag {
            GlobalColorTable::from_stream(
                &mut self.src,
                logical_screen_descriptor.color_resolution,
            )?;
        }

        Ok(())
    }

    // According to spec, C2PA blocks must come before the first image descriptor.
    fn find_c2pa_block(&mut self) -> Result<Option<BlockMarker<ApplicationExtension>>, ParseError> {
        Self::find_app_block_from_iterator(
            ApplicationExtensionKind::C2pa,
            Blocks::new(&mut self.src)?.take_while(|marker| {
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

    fn find_xmp_block(&mut self) -> Result<Option<BlockMarker<ApplicationExtension>>, ParseError> {
        Self::find_app_block_from_iterator(
            ApplicationExtensionKind::Xmp,
            Blocks::new(&mut self.src)?,
        )
    }

    fn find_app_block_from_iterator(
        kind: ApplicationExtensionKind,
        mut iterator: impl Iterator<Item = Result<BlockMarker<Block>, ParseError>>,
    ) -> Result<Option<BlockMarker<ApplicationExtension>>, ParseError> {
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
}

struct Blocks<R> {
    next: Option<BlockMarker<Block>>,
    stream: R,
    reached_trailer: bool,
}

impl<R: Read + Seek> Blocks<R> {
    fn new(mut stream: R) -> Result<Blocks<R>, ParseError> {
        stream.rewind()?;

        let start = stream.stream_position()?;
        let block = Block::Header(Header::from_stream(&mut stream)?);
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

    fn parse_next(&mut self) -> Result<BlockMarker<Block>, ParseError> {
        match self.next.take() {
            Some(marker) => {
                self.next = marker.block.next_block_hint(&mut self.stream)?;
                Ok(marker)
            }
            None => {
                let marker = Block::from_stream(&mut self.stream)?;
                self.next = marker.block.next_block_hint(&mut self.stream)?;

                if let Block::Trailer = marker.block {
                    self.reached_trailer = true;
                }

                Ok(marker)
            }
        }
    }
}

impl<R: Read + Seek> Iterator for Blocks<R> {
    type Item = Result<BlockMarker<Block>, ParseError>;

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
}

impl BlockMarker<Block> {
    fn to_named_byte_span(&self) -> Result<NamedByteSpan, ParseError> {
        let mut names = Vec::new();
        if let Some(name) = self.block.box_id() {
            names.push(name.to_owned());
        }

        Ok(NamedByteSpan {
            names,
            span: ByteSpan {
                start: self.start(),
                len: self.len(),
            },
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
    fn from_stream(mut stream: impl Read + Seek) -> Result<BlockMarker<Block>, ParseError> {
        let start = stream.stream_position()?;

        let ext_introducer = stream.read_u8()?;
        let block = match ext_introducer {
            0x21 => {
                let ext_label = stream.read_u8()?;
                match ext_label {
                    0xff => Ok(Block::ApplicationExtension(
                        ApplicationExtension::from_stream(&mut stream)?,
                    )),
                    0xfe => Ok(Block::CommentExtension(CommentExtension::from_stream(
                        &mut stream,
                    )?)),
                    0xf9 => Ok(Block::GraphicControlExtension(
                        GraphicControlExtension::from_stream(&mut stream)?,
                    )),
                    0x21 => Ok(Block::PlainTextExtension(PlainTextExtension::from_stream(
                        &mut stream,
                    )?)),
                    ext_label => Err(ParseError::InvalidAsset {
                        reason: format!("Invalid block extension label: {ext_label}"),
                    }),
                }
            }
            0x2c => Ok(Block::ImageDescriptor(ImageDescriptor::from_stream(
                &mut stream,
            )?)),
            0x3b => Ok(Block::Trailer),
            ext_introducer => Err(ParseError::InvalidAsset {
                reason: format!("Invalid block id: {ext_introducer}"),
            }),
        }?;

        let end = stream.stream_position()?;
        Ok(BlockMarker {
            start,
            len: end - start,
            block,
        })
    }

    // Some blocks MUST come after other blocks, this function ensures that.
    fn next_block_hint(
        &self,
        mut stream: impl Read + Seek,
    ) -> Result<Option<BlockMarker<Block>>, ParseError> {
        let start = stream.stream_position()?;
        let next_block = match self {
            Block::Header(_) => Some(Block::LogicalScreenDescriptor(
                LogicalScreenDescriptor::from_stream(&mut stream)?,
            )),
            Block::LogicalScreenDescriptor(logical_screen_descriptor) => {
                match logical_screen_descriptor.color_table_flag {
                    true => Some(Block::GlobalColorTable(GlobalColorTable::from_stream(
                        &mut stream,
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
                        &mut stream,
                        image_descriptor.local_color_table_size,
                    )?)),
                    false => Some(Block::ImageData(ImageData::from_stream(&mut stream)?)),
                }
            }
            Block::LocalColorTable(_) => {
                Some(Block::ImageData(ImageData::from_stream(&mut stream)?))
            }
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
                    true => Some("C2PA"),
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

    fn to_bytes(&self) -> Result<Vec<u8>, ParseError> {
        match self {
            Block::ApplicationExtension(app_ext) => app_ext.to_bytes(),
            // We only care about app extensions.
            _ => Err(ParseError::Unsupported),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Header {}

impl Header {
    fn from_stream(mut stream: impl Read + Seek) -> Result<Header, ParseError> {
        stream.seek(SeekFrom::Current(6))?;

        Ok(Header {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct LogicalScreenDescriptor {
    color_table_flag: bool,
    color_resolution: u8,
}

impl LogicalScreenDescriptor {
    fn from_stream(mut stream: impl Read + Seek) -> Result<LogicalScreenDescriptor, ParseError> {
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
    fn from_stream(
        mut stream: impl Read + Seek,
        color_resolution: u8,
    ) -> Result<GlobalColorTable, ParseError> {
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
    fn new_c2pa(bytes: &[u8]) -> Result<ApplicationExtension, ParseError> {
        Ok(ApplicationExtension {
            identifier: *b"C2PA_GIF",
            authentication_code: [0x01, 0x00, 0x00],
            data_sub_blocks: DataSubBlocks::from_decoded_bytes(bytes)?,
        })
    }

    fn new_xmp(mut bytes: Vec<u8>) -> Result<ApplicationExtension, ParseError> {
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

    fn from_stream(mut stream: impl Read + Seek) -> Result<ApplicationExtension, ParseError> {
        let app_block_size = stream.read_u8()?;
        // App block size is a fixed value.
        if app_block_size != 0x0b {
            return Err(ParseError::InvalidAsset {
                reason: format!(
                    "Invalid block size for app block extension {}!=11",
                    app_block_size
                ),
            });
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

    fn to_bytes(&self) -> Result<Vec<u8>, ParseError> {
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
    fn from_stream(mut stream: impl Read + Seek) -> Result<PlainTextExtension, ParseError> {
        stream.seek(SeekFrom::Current(11))?;
        DataSubBlocks::from_encoded_stream_and_skip(&mut stream)?;
        Ok(PlainTextExtension {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CommentExtension {}

impl CommentExtension {
    fn from_stream(stream: impl Read + Seek) -> Result<CommentExtension, ParseError> {
        // stream.seek(SeekFrom::Current(0))?;
        DataSubBlocks::from_encoded_stream_and_skip(stream)?;
        Ok(CommentExtension {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct GraphicControlExtension {}

impl GraphicControlExtension {
    // TODO: validate ext introducer and label, and do that for other extensions?
    fn from_stream(mut stream: impl Read + Seek) -> Result<GraphicControlExtension, ParseError> {
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
    fn from_stream(mut stream: impl Read + Seek) -> Result<ImageDescriptor, ParseError> {
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
        mut stream: impl Read + Seek,
        local_color_table_size: u8,
    ) -> Result<LocalColorTable, ParseError> {
        stream.seek(SeekFrom::Current(
            3 * (2_i64.pow(local_color_table_size as u32 + 1)),
        ))?;
        Ok(LocalColorTable {})
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ImageData {}

impl ImageData {
    fn from_stream(mut stream: impl Read + Seek) -> Result<ImageData, ParseError> {
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

    fn from_decoded_bytes(bytes: &[u8]) -> Result<DataSubBlocks, ParseError> {
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

    fn from_encoded_stream(mut stream: impl Read + Seek) -> Result<DataSubBlocks, ParseError> {
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

    fn from_encoded_stream_and_skip(mut stream: impl Read + Seek) -> Result<u64, ParseError> {
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
        // Amount of bytes - (length markers + terminator).
        let mut bytes = Vec::with_capacity(self.bytes.len() - (self.bytes.len().div_ceil(255) + 1));
        for chunk in self.bytes.chunks(256) {
            bytes.extend_from_slice(&chunk[1..]);
        }

        // Remove terminator.
        bytes.truncate(bytes.len() - 1);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use io::{Cursor, Seek};

    use super::*;

    const SAMPLE1: &[u8] = include_bytes!("../../../../tests/fixtures/sample1.gif");

    #[test]
    fn test_read_blocks() -> Result<(), ParseError> {
        let mut src = Cursor::new(SAMPLE1);

        let blocks: Vec<_> = Blocks::new(&mut src)?.collect::<Result<_, _>>()?;
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
    fn test_write_remove_block() -> Result<(), ParseError> {
        let src = Cursor::new(SAMPLE1);

        let mut codec1 = GifCodec::new(src);

        assert!(matches!(codec1.read_c2pa(), Ok(None)));

        let mut dst1 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 7));
        let random_bytes = [1, 2, 3, 4, 3, 2, 1];
        codec1.write_c2pa(&mut dst1, &random_bytes)?;

        let mut codec2 = GifCodec::new(dst1);
        let data_written = codec2.read_c2pa()?;
        assert_eq!(data_written.as_deref(), Some(random_bytes.as_slice()));

        let mut dst2 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        codec2.remove_c2pa(&mut dst2)?;

        let mut codec3 = GifCodec::new(&mut dst2);
        assert!(matches!(codec3.read_c2pa(), Ok(None)));

        let mut bytes = Vec::new();
        dst2.rewind()?;
        dst2.read_to_end(&mut bytes)?;
        assert_eq!(SAMPLE1, bytes);

        Ok(())
    }

    #[test]
    fn test_write_insert_two_blocks() -> Result<(), ParseError> {
        let src = Cursor::new(SAMPLE1);

        let mut codec = GifCodec::new(src);

        let mut dst1 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        let test_block = Block::ApplicationExtension(ApplicationExtension {
            identifier: *b"12345678",
            authentication_code: [0, 0, 0],
            data_sub_blocks: DataSubBlocks::empty(),
        });
        codec.insert_block(&mut dst1, &test_block)?;
        let mut dst2 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        codec.insert_block(&mut dst2, &test_block)?;

        let blocks: Vec<_> = Blocks::new(&mut dst2)?.collect::<Result<_, _>>()?;
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
    fn test_write_bytes() -> Result<(), ParseError> {
        let src = Cursor::new(SAMPLE1);

        let mut codec1 = GifCodec::new(src);

        assert!(matches!(codec1.read_c2pa(), Ok(None)));

        let mut dst = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 7));
        let random_bytes = [1, 2, 3, 4, 3, 2, 1];
        codec1.write_c2pa(&mut dst, &random_bytes)?;

        let mut codec2 = GifCodec::new(dst);
        let data_written = codec2.read_c2pa()?;
        assert_eq!(data_written.as_deref(), Some(random_bytes.as_slice()));

        Ok(())
    }

    #[test]
    fn test_write_bytes_replace() -> Result<(), ParseError> {
        let mut src = Cursor::new(SAMPLE1);

        let mut codec = GifCodec::new(&mut src);

        assert!(matches!(codec.read_c2pa(), Ok(None)));

        let mut dst1 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 7));
        let random_bytes = [1, 2, 3, 4, 3, 2, 1];
        codec.write_c2pa(&mut dst1, &random_bytes)?;

        let mut codec = GifCodec::new(dst1);
        let data_written = codec.read_c2pa()?;
        assert_eq!(data_written.as_deref(), Some(random_bytes.as_slice()));

        let mut dst2 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 5));
        let random_bytes = [3, 2, 1, 2, 3];
        codec.write_c2pa(&mut dst2, &random_bytes)?;

        let mut codec = GifCodec::new(dst2);
        let data_written = codec.read_c2pa()?;
        assert_eq!(data_written.as_deref(), Some(random_bytes.as_slice()));

        let mut bytes = Vec::new();
        src.rewind()?;
        src.read_to_end(&mut bytes)?;
        assert_eq!(SAMPLE1, bytes);

        Ok(())
    }

    #[test]
    fn test_data_hash() -> Result<(), ParseError> {
        let src = Cursor::new(SAMPLE1);

        let mut codec1 = GifCodec::new(src);

        assert_eq!(
            codec1.data_hash()?,
            DataHash {
                spans: vec![ByteSpan { start: 781, len: 1 }]
            }
        );

        let mut dst1 = Cursor::new(Vec::with_capacity(SAMPLE1.len() + 15 + 4));
        codec1.write_c2pa(&mut dst1, &[1, 2, 3, 4])?;

        let mut codec2 = GifCodec::new(dst1);
        assert_eq!(
            codec2.data_hash()?,
            DataHash {
                spans: vec![ByteSpan {
                    start: 781,
                    len: 20
                }]
            }
        );

        Ok(())
    }

    #[test]
    fn test_box_hash() -> Result<(), ParseError> {
        let src = Cursor::new(SAMPLE1);

        let mut codec = GifCodec::new(src);
        let box_hash = codec.box_hash()?;
        assert_eq!(
            box_hash.spans.first(),
            Some(&NamedByteSpan {
                names: vec!["GIF89a".to_owned()],
                span: ByteSpan { start: 0, len: 6 }
            })
        );
        assert_eq!(
            box_hash.spans.get(box_hash.spans.len() / 2),
            Some(&NamedByteSpan {
                names: vec!["2C".to_owned()],
                span: ByteSpan {
                    start: 368495,
                    len: 778
                }
            })
        );
        assert_eq!(
            box_hash.spans.last(),
            Some(&NamedByteSpan {
                names: vec!["3B".to_owned()],
                span: ByteSpan {
                    start: SAMPLE1.len() as u64,
                    len: 1
                }
            })
        );
        assert_eq!(box_hash.spans.len(), 276);

        Ok(())
    }

    // #[test]
    // fn test_composed_manifest() -> Result<(), ParseError> {
    //     let encoder = GifEncoder {};

    //     let block = encoder.compose_manifest(&[1, 2, 3], "")?;
    //     assert_eq!(
    //         block,
    //         vec![33, 255, 11, 67, 50, 80, 65, 95, 71, 73, 70, 1, 0, 0, 3, 1, 2, 3, 0]
    //     );

    //     Ok(())
    // }

    #[test]
    fn test_remote_ref() -> Result<(), ParseError> {
        let src = Cursor::new(SAMPLE1);

        let mut codec1 = GifCodec::new(src);

        codec1.read_xmp()?;

        let mut dst1 = Cursor::new(Vec::with_capacity(SAMPLE1.len()));
        codec1.write_xmp(&mut dst1, "Test")?;

        let mut codec2 = GifCodec::new(dst1);
        assert_eq!(codec2.read_xmp()?, Some("http://ns.adobe.com/xap/1.0/\0<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"XMP Core 6.0.0\">\n  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n    <rdf:Description rdf:about=\"\" xmlns:dcterms=\"http://purl.org/dc/terms/\" dcterms:provenance=\"Test\">\n    </rdf:Description>\n  </rdf:RDF>\n</x:xmpmeta".to_string()));

        Ok(())
    }
}
