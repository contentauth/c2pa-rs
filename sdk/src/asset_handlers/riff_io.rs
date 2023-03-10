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

use conv::ValueFrom;
use riff::*;

use crate::{
    asset_io::{
        AssetIO, AssetPatch, CAIRead, CAIReader, HashBlockObjectType, HashObjectPositions,
        RemoteRefEmbed,
    },
    error::{Error, Result},
    jumbf_io::get_file_extension,
};

static SUPPORTED_TYPES: [&str; 9] = [
    "avi",
    "wav",
    "webp",
    "image/webp",
    "audio/x-wav",
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

fn inject_c2pa<T>(chunk: &Chunk, file: &mut T, data: &[u8], format: &str) -> Result<ChunkContents>
where
    T: std::io::Seek + std::io::Read,
{
    let id = chunk.id();
    let is_riff_chunk: bool = id == riff::RIFF_ID;

    if is_riff_chunk || id == riff::LIST_ID {
        let chunk_type = chunk.read_type(file).map_err(|_| {
            Error::InvalidAsset("RIFF handler could not parse file format {format}".to_string())
        })?;
        let mut children = read_items(&mut chunk.iter(file));
        let mut children_contents: Vec<ChunkContents> = Vec::new();

        if is_riff_chunk {
            // remove c2pa manifest store in RIFF chunk
            children.retain(|c| c.id() != C2PA_CHUNK_ID);
        }

        // for non webp we can place at the front
        // add c2pa manifest
        if is_riff_chunk && !data.is_empty() && !format.contains("webp") {
            children_contents.push(ChunkContents::Data(C2PA_CHUNK_ID, data.to_vec()));
        }

        for child in children {
            children_contents.push(inject_c2pa(&child, file, data, format)?);
        }

        // for non webp we can place at the front
        // add c2pa manifest
        if is_riff_chunk && !data.is_empty() && format.contains("webp") {
            children_contents.push(ChunkContents::Data(C2PA_CHUNK_ID, data.to_vec()));
        }

        Ok(ChunkContents::Children(id, chunk_type, children_contents))
    } else if id == riff::SEQT_ID {
        let children = read_items(&mut chunk.iter_no_type(file));
        let mut children_contents: Vec<ChunkContents> = Vec::new();

        for child in children {
            children_contents.push(inject_c2pa(&child, file, data, format)?);
        }

        Ok(ChunkContents::ChildrenNoType(id, children_contents))
    } else {
        let contents = chunk
            .read_contents(file)
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
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let mut asset: Vec<u8> = Vec::new();
        reader.rewind()?;
        reader.read_to_end(&mut asset)?;

        let mut chunk_reader = Cursor::new(asset);

        let top_level_chunks = riff::Chunk::read(&mut chunk_reader, 0)?;

        if top_level_chunks.id() != RIFF_ID {
            return Err(Error::InvalidAsset("Invalid RIFF format".to_string()));
        }

        for c in top_level_chunks.iter(&mut chunk_reader) {
            if c.id() == C2PA_CHUNK_ID {
                let output = c.read_contents(&mut chunk_reader)?;
                return Ok(output);
            }
        }

        Err(Error::JumbfNotFound)
    }

    // Get XMP block
    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None // todo: figure out where XMP is stored for supported formats
    }
}

fn add_required_chunks(asset_path: &std::path::Path) -> Result<()> {
    let mut f = File::open(asset_path)?;
    let aio = RiffIO::new(&get_file_extension(asset_path).ok_or(Error::UnsupportedType)?);

    match aio.read_cai(&mut f) {
        Ok(_) => Ok(()),
        Err(_) => aio.save_cai_store(asset_path, &[1, 2, 3, 4]), // save arbitrary data
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

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }
    fn save_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let asset = std::fs::read(asset_path)?;
        let mut chunk_reader = Cursor::new(asset);

        let top_level_chunks = Chunk::read(&mut chunk_reader, 0)?;

        if top_level_chunks.id() != RIFF_ID {
            return Err(Error::InvalidAsset("Invalid RIFF format".to_string()));
        }

        // replace/add manifest in memory
        let new_contents = inject_c2pa(
            &top_level_chunks,
            &mut chunk_reader,
            store_bytes,
            &self.riff_format,
        )?;

        // save contents
        let mut output = OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;
        match new_contents.write(&mut output) {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::IoError(e)),
        }
    }

    fn get_object_locations(
        &self,
        asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        add_required_chunks(asset_path)?;

        let mut f = std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;

        let mut positions: Vec<HashObjectPositions> = Vec::new();

        let (manifest_pos, manifest_len) = get_manifest_pos(&mut f).ok_or(Error::EmbeddingError)?;

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
        let file_end = f.metadata()?.len();
        positions.push(HashObjectPositions {
            offset: usize::value_from(end)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?, // len of cai
            length: usize::value_from(file_end - end)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?,
            htype: HashBlockObjectType::Other,
        });

        Ok(positions)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        self.save_cai_store(asset_path, &[])
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        match self.riff_format.as_ref() {
            "avi" | "wav" => Some(self),
            _ => None,
        }
    }
    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
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
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                #[cfg(feature = "xmp_write")]
                {
                    crate::embedded_xmp::add_manifest_uri_to_file(asset_path, &manifest_uri)
                }

                #[cfg(not(feature = "xmp_write"))]
                {
                    Err(crate::error::Error::MissingFeature("xmp_write".to_string()))
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
}
