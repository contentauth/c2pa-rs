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

use byteorder::{BigEndian, ReadBytesExt};
use conv::ValueFrom;
use id3::{frame::EncapsulatedObject, *};
use tempfile::Builder;
use twoway::find_bytes;

use crate::{
    asset_io::{
        AssetIO, AssetPatch, CAIRead, CAIReadWrapper, CAIReadWrite, CAIReadWriteWrapper, CAIReader,
        CAIWriter, HashBlockObjectType, HashObjectPositions, RemoteRefEmbed,
    },
    error::{Error, Result},
};

static SUPPORTED_TYPES: [&str; 2] = ["mp3", "audio/mpeg"];

const GEOB_FRAME_MIME_TYPE: &str = "application/x-c2pa-manifest-store";
const GEOB_FRAME_FILE_NAME: &str = "c2pa";
const GEOB_FRAME_DESCRIPTION: &str = "c2pa manifest store";

struct ID3V2Header {
    _version_major: u8,
    _version_minor: u8,
    _flags: u8,
    tag_size: u32,
}

impl ID3V2Header {
    pub fn read_header(reader: &mut dyn CAIRead) -> Result<ID3V2Header> {
        let mut header = [0; 10];
        reader.read_exact(&mut header).map_err(Error::IoError)?;

        if &header[0..3] != b"ID3" {
            return Err(Error::UnsupportedType);
        }

        let (version_major, version_minor) = (header[3], header[4]);
        if !(2..=4).contains(&version_major) {
            return Err(Error::UnsupportedType);
        }

        let flags = header[5];

        let mut size_reader = Cursor::new(&header[6..10]);
        let encoded_tag_size = size_reader
            .read_u32::<BigEndian>()
            .map_err(|_err| Error::InvalidAsset("could not read mp3 tag size".to_string()))?;
        let tag_size = ID3V2Header::decode_tag_size(encoded_tag_size);

        Ok(ID3V2Header {
            _version_major: version_major,
            _version_minor: version_minor,
            _flags: flags,
            tag_size,
        })
    }

    pub fn get_size(&self) -> u32 {
        self.tag_size + 10
    }

    fn decode_tag_size(n: u32) -> u32 {
        n & 0xff | (n & 0xff00) >> 1 | (n & 0xff0000) >> 2 | (n & 0xff000000) >> 3
    }
}

fn get_manifest_pos(input_stream: &mut dyn CAIRead) -> Option<(u64, u32)> {
    input_stream.rewind().ok()?;
    let header = ID3V2Header::read_header(input_stream).ok()?;
    input_stream.rewind().ok()?;

    let reader = CAIReadWrapper {
        reader: input_stream,
    };

    if let Ok(tag) = Tag::read_from(reader) {
        let mut manifests = Vec::new();

        for eo in tag.encapsulated_objects() {
            if eo.mime_type == GEOB_FRAME_MIME_TYPE {
                manifests.push(eo.data.clone());
            }
        }

        if manifests.len() == 1 {
            input_stream.rewind().ok()?;

            let mut tag_bytes = vec![0u8; header.get_size() as usize];
            input_stream.read_exact(tag_bytes.as_mut_slice()).ok()?;

            let pos = find_bytes(&tag_bytes, &manifests[0])?;

            return Some((pos as u64, manifests[0].len() as u32));
        }
    }
    None
}

pub struct Mp3IO {
    _mp3_format: String,
}

impl CAIReader for Mp3IO {
    fn read_cai(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let mut manifest: Option<Vec<u8>> = None;

        if let Ok(tag) = Tag::read_from(input_stream) {
            for eo in tag.encapsulated_objects() {
                if eo.mime_type == GEOB_FRAME_MIME_TYPE {
                    match manifest {
                        Some(_) => {
                            return Err(Error::TooManyManifestStores);
                        }
                        None => manifest = Some(eo.data.clone()),
                    }
                }
            }
        }

        manifest.ok_or(Error::JumbfNotFound)
    }

    // Get XMP block
    fn read_xmp(&self, _input_stream: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

fn add_required_frame(
    asset_type: &str,
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    let mp3io = Mp3IO::new(asset_type);

    input_stream.rewind()?;

    match mp3io.read_cai(input_stream) {
        Ok(_) => {
            // just clone
            input_stream.rewind()?;
            output_stream.rewind()?;
            std::io::copy(input_stream, output_stream)?;
            Ok(())
        }
        Err(_) => {
            input_stream.rewind()?;
            mp3io.write_cai(input_stream, output_stream, &[1, 2, 3, 4]) // save arbitrary data
        }
    }
}

impl AssetIO for Mp3IO {
    fn new(mp3_format: &str) -> Self {
        Mp3IO {
            _mp3_format: mp3_format.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(Mp3IO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(Mp3IO::new(asset_type)))
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

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
        None
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

impl CAIWriter for Mp3IO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let header = ID3V2Header::read_header(input_stream)?;
        input_stream.rewind()?;

        let mut out_tag = Tag::new();

        // wrapper to protect imput stream from being gobbled
        let reader = CAIReadWrapper {
            reader: input_stream,
        };

        if let Ok(tag) = Tag::read_from(reader) {
            for f in tag.frames() {
                match f.content() {
                    // remove existing manifest keeping existing frames
                    Content::EncapsulatedObject(eo) => {
                        if eo.mime_type != "application/x-c2pa-manifest-store" {
                            out_tag.add_frame(f.clone());
                        }
                    }
                    _ => {
                        out_tag.add_frame(f.clone());
                    }
                }
            }
        }

        // only add new tags
        if !store_bytes.is_empty() {
            // Add new manifest store
            let frame = Frame::with_content(
                "GEOB",
                Content::EncapsulatedObject(EncapsulatedObject {
                    mime_type: GEOB_FRAME_MIME_TYPE.to_string(),
                    filename: GEOB_FRAME_FILE_NAME.to_string(),
                    description: GEOB_FRAME_DESCRIPTION.to_string(),
                    data: store_bytes.to_vec(),
                }),
            );

            out_tag.add_frame(frame);
        }

        // wrapper to protect output stream from being gobbled
        let writer = CAIReadWriteWrapper {
            reader_writer: output_stream,
        };

        // write new tag to output stream
        out_tag
            .write_to(writer, Version::Id3v24)
            .map_err(|_e| Error::EmbeddingError)?;

        // skip past old ID3V2
        input_stream.seek(SeekFrom::Start(header.get_size() as u64))?;

        // copy source data to output
        std::io::copy(input_stream, output_stream)?;

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let output_buf: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_buf);

        add_required_frame(&self._mp3_format, input_stream, &mut output_stream)?;

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

impl AssetPatch for Mp3IO {
    fn patch_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut asset = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(asset_path)?;

        let (manifest_pos, manifest_len) =
            get_manifest_pos(&mut asset).ok_or(Error::EmbeddingError)?;

        if store_bytes.len() == manifest_len as usize {
            asset.seek(SeekFrom::Start(manifest_pos))?;
            asset.write_all(store_bytes)?;
            Ok(())
        } else {
            Err(Error::InvalidAsset(
                "patch_cai_store store size mismatch.".to_string(),
            ))
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
    fn test_write_mp3() {
        let more_data = "some more test data".as_bytes();
        let source = fixture_path("sample1.mp3");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "sample1-mp3.mp3");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let mp3_io = Mp3IO::new("mp3");

                if let Ok(()) = mp3_io.save_cai_store(&output, more_data) {
                    if let Ok(read_test_data) = mp3_io.read_cai_store(&output) {
                        assert!(vec_compare(more_data, &read_test_data));
                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_patch_write_mp3() {
        let test_data = "some test data".as_bytes();
        let source = fixture_path("sample1.mp3");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "sample1-mp3.mp3");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let mp3_io = Mp3IO::new("mp3");

                if let Ok(()) = mp3_io.save_cai_store(&output, test_data) {
                    if let Ok(source_data) = mp3_io.read_cai_store(&output) {
                        // create replacement data of same size
                        let mut new_data = vec![0u8; source_data.len()];
                        new_data[..test_data.len()].copy_from_slice(test_data);
                        mp3_io.patch_cai_store(&output, &new_data).unwrap();

                        let replaced = mp3_io.read_cai_store(&output).unwrap();

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
        let source = fixture_path("sample1.mp3");

        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "sample1-mp3.mp3");

        std::fs::copy(source, &output).unwrap();
        let mp3_io = Mp3IO::new("wav");

        mp3_io.remove_cai_store(&output).unwrap();

        // read back in asset, JumbfNotFound is expected since it was removed
        match mp3_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => unreachable!(),
        }
    }
}
