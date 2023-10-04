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
    io::{Cursor, Seek, SeekFrom, Write},
    path::Path,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use conv::ValueFrom;
use riff::*;
use tempfile::Builder;

use crate::{
    asset_io::{
        AssetIO, AssetPatch, CAIRead, CAIReadWrapper, CAIReadWrite, CAIReadWriteWrapper, CAIReader,
        CAIWriter, HashBlockObjectType, HashObjectPositions, RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::xmp_inmemory_utils::{add_provenance, MIN_XMP},
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

const XMP_FLAG: u32 = 4;

fn read_items<T>(iter: &mut T) -> Vec<T::Item>
where
    T: Iterator,
{
    let mut vec: Vec<T::Item> = Vec::new();
    for item in iter {
        vec.push(item);
    }
    vec
}

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
    T: std::io::Seek + std::io::Read,
{
    let id = chunk.id();
    let is_riff_chunk: bool = id == riff::RIFF_ID;
    stream.rewind()?;

    if is_riff_chunk || id == riff::LIST_ID {
        let chunk_type = chunk.read_type(stream).map_err(|_| {
            Error::InvalidAsset("RIFF handler could not parse file format {format}".to_string())
        })?;
        let mut children = read_items(&mut chunk.iter(stream));
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
    } else if id == riff::SEQT_ID {
        let children = read_items(&mut chunk.iter_no_type(stream));
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

    let top_level_chunks = riff::Chunk::read(&mut chunk_reader, 0).ok()?;

    if top_level_chunks.id() == RIFF_ID {
        for c in top_level_chunks.iter(&mut chunk_reader) {
            if c.id() == C2PA_CHUNK_ID {
                return Some((c.offset(), c.len() + 8)); // 8 is len of data chunk header
            }
        }
    }
    None
}

impl CAIReader for RiffIO {
    fn read_cai(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let mut chunk_reader = CAIReadWrapper {
            reader: input_stream,
        };

        let top_level_chunks = riff::Chunk::read(&mut chunk_reader, 0)?;

        if top_level_chunks.id() != RIFF_ID {
            return Err(Error::InvalidAsset("Invalid RIFF format".to_string()));
        }

        for c in top_level_chunks.iter(&mut chunk_reader) {
            if c.id() == C2PA_CHUNK_ID {
                return Ok(c.read_contents(&mut chunk_reader)?);
            }
        }

        Err(Error::JumbfNotFound)
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

        for c in top_level_chunks.iter(&mut chunk_reader) {
            if c.id() == XMP_CHUNK_ID {
                let output = c.read_contents(&mut chunk_reader).ok()?;
                let output_string = String::from_utf8_lossy(&output);

                return Some(output_string.to_string());
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

    fn save_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = File::open(asset_path)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        // copy temp file to asset
        std::fs::rename(temp_file.path(), asset_path)
            // if rename fails, try to copy in case we are on different volumes
            .or_else(|_| std::fs::copy(temp_file.path(), asset_path).and(Ok(())))
            .map_err(Error::IoError)
    }

    fn get_object_locations(
        &self,
        asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        let mut f = std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;

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
            store_bytes,
            None,
            &self.riff_format,
        )?;

        let mut writer = CAIReadWriteWrapper {
            reader_writer: output_stream,
        };

        // save contents
        new_contents
            .write(&mut writer)
            .map_err(|_e| Error::EmbeddingError)?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let output_buf: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_buf);

        add_required_chunks(&self.riff_format, input_stream, &mut output_stream)?;

        let mut positions: Vec<HashObjectPositions> = Vec::new();

        let (manifest_pos, manifest_len) =
            get_manifest_pos(&mut output_stream).ok_or(Error::EmbeddingError)?;

        positions.push(HashObjectPositions {
            offset: usize::value_from(manifest_pos)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
            length: usize::value_from(manifest_len)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
            htype: HashBlockObjectType::Cai,
        });

        // add hash of chunks before cai
        positions.push(HashObjectPositions {
            offset: 0,
            length: usize::value_from(manifest_pos)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
            htype: HashBlockObjectType::Other,
        });

        // add position from cai to end
        let end = u64::value_from(manifest_pos)
            .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?
            + u64::value_from(manifest_len)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;
        let file_end = output_stream.seek(SeekFrom::End(0))?;
        positions.push(HashObjectPositions {
            offset: usize::value_from(end)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?, // len of cai
            length: usize::value_from(file_end - end)
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
    fn patch_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut asset = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(asset_path)?;

        let (manifest_pos, manifest_len) =
            get_manifest_pos(&mut asset).ok_or(Error::EmbeddingError)?;

        if store_bytes.len() + 8 == manifest_len as usize {
            asset.seek(SeekFrom::Start(manifest_pos + 8))?; // skip 8 byte chunk data header
            asset.write_all(store_bytes)?;
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
    fn embed_reference(
        &self,
        asset_path: &Path,
        embed_ref: crate::asset_io::RemoteRefEmbedType,
    ) -> Result<()> {
        let mut input_stream = File::open(asset_path)?;

        let mut output_stream = std::fs::OpenOptions::new()
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
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                match self.riff_format.as_ref() {
                    "avi" | "wav" | "webp" => {
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
                    _ => Err(Error::UnsupportedType),
                }
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use tempfile::tempdir;

    use super::*;
    use crate::utils::{
        hash_utils::vec_compare,
        test::{fixture_path, temp_dir_path},
        xmp_inmemory_utils::extract_provenance,
    };

    #[test]
    fn test_write_wav() {
        let more_data = "some more test data".as_bytes();
        let source = fixture_path("sample1.wav");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
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
    fn test_patch_write_wav() {
        let test_data = "some test data".as_bytes();
        let source = fixture_path("sample1.wav");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
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

        let temp_dir = tempdir().unwrap();
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
        let mut reader = std::fs::File::open(source).unwrap();

        let riff_io = RiffIO::new("webp");

        let xmp = riff_io.read_xmp(&mut reader).unwrap();
        println!("XMP: {xmp}");
    }

    #[test]
    fn test_write_xmp() {
        let more_data = "some more test data";
        let source = fixture_path("test_xmp.webp");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "test_xmp.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_ref_writer_ref() {
                if let Ok(()) = embed_handler.embed_reference(
                    output.as_path(),
                    RemoteRefEmbedType::Xmp(more_data.to_string()),
                ) {
                    let mut output_stream = std::fs::File::open(&output).unwrap();

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
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "test.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_ref_writer_ref() {
                if let Ok(()) = embed_handler.embed_reference(
                    output.as_path(),
                    RemoteRefEmbedType::Xmp(more_data.to_string()),
                ) {
                    let mut output_stream = std::fs::File::open(&output).unwrap();

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
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "test_lossless.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_ref_writer_ref() {
                if let Ok(()) = embed_handler.embed_reference(
                    output.as_path(),
                    RemoteRefEmbedType::Xmp(more_data.to_string()),
                ) {
                    let mut output_stream = std::fs::File::open(&output).unwrap();

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
}
