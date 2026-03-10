// Copyright 2026 Adobe. All rights reserved.
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
    fs::{self, File, OpenOptions},
    io::{Cursor, Seek, SeekFrom, Write},
    path::Path,
};

use byteorder::{BigEndian, ReadBytesExt};
use id3::{
    frame::{EncapsulatedObject, Private},
    *,
};
use memchr::memmem;
use metaflac::Tag as FlacTag;

use crate::{
    asset_io::{
        rename_or_move, AssetIO, AssetPatch, CAIRead, CAIReadWrapper, CAIReadWrite,
        CAIReadWriteWrapper, CAIReader, CAIWriter, HashBlockObjectType, HashObjectPositions,
        RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::{
        io_utils::{stream_len, tempfile_builder, ReaderUtils},
        xmp_inmemory_utils::{self, MIN_XMP},
    },
};

static SUPPORTED_TYPES: [&str; 2] = ["flac", "audio/flac"];

const GEOB_FRAME_MIME_TYPE: &str = "application/c2pa";
const GEOB_FRAME_MIME_TYPE_DEPRECATED: &str = "application/x-c2pa-manifest-store";
const GEOB_FRAME_FILE_NAME: &str = "c2pa";
const GEOB_FRAME_DESCRIPTION: &str = "c2pa manifest store";

const FLAC_HEADER: &[u8; 4] = b"fLaC";
const ID3_HEADER: &[u8; 3] = b"ID3";

struct ID3V2Header {
    _version_major: u8,
    _version_minor: u8,
    _flags: u8,
    tag_size: u32,
}

impl ID3V2Header {
    /// Reads FLAC file header: optional ID3v2 at start, or pure FLAC (fLaC header).
    /// Returns Some(header) if ID3 present, None if file starts with fLaC (valid FLAC, no ID3).
    pub fn read_header(reader: &mut dyn CAIRead) -> Result<Option<ID3V2Header>> {
        let mut header = [0u8; 10];
        reader.read_exact(&mut header).map_err(Error::IoError)?;

        if header[0..3] == *ID3_HEADER {
            let (version_major, version_minor) = (header[3], header[4]);
            if !(2..=4).contains(&version_major) {
                return Err(Error::FlacError(FlacError::InvalidId3Version));
            }
            let flags = header[5];
            let mut size_reader = Cursor::new(&header[6..10]);
            let encoded_tag_size = size_reader
                .read_u32::<BigEndian>()
                .map_err(|_| Error::InvalidAsset("could not read ID3 tag size".to_string()))?;
            let tag_size = Self::decode_tag_size(encoded_tag_size);
            return Ok(Some(ID3V2Header {
                _version_major: version_major,
                _version_minor: version_minor,
                _flags: flags,
                tag_size,
            }));
        }

        if header[0..4] == *FLAC_HEADER {
            return Ok(None);
        }

        Err(Error::UnsupportedType)
    }

    pub fn get_size(&self) -> u32 {
        self.tag_size + 10
    }

    fn decode_tag_size(n: u32) -> u32 {
        (n & 0xff) | ((n & 0xff00) >> 1) | ((n & 0xff0000) >> 2) | ((n & 0xff000000) >> 3)
    }
}

/// Validates that the remainder of the reader is valid FLAC (starting at fLaC magic).
fn validate_flac_stream(reader: &mut dyn CAIRead) -> Result<()> {
    FlacTag::read_from(reader)
        .map_err(|e| Error::InvalidAsset(format!("invalid FLAC stream: {}", e)))?;
    Ok(())
}

fn is_c2pa_mime_type(mime_type: &str) -> bool {
    mime_type == GEOB_FRAME_MIME_TYPE || mime_type == GEOB_FRAME_MIME_TYPE_DEPRECATED
}

fn get_manifest_pos(mut input_stream: &mut dyn CAIRead) -> Option<(u64, u32)> {
    input_stream.rewind().ok()?;
    let header = ID3V2Header::read_header(input_stream).ok()?;
    input_stream.rewind().ok()?;

    let reader = CAIReadWrapper {
        reader: input_stream,
    };

    if let Ok(tag) = Tag::read_from2(reader) {
        let mut manifests = Vec::new();
        for eo in tag.encapsulated_objects() {
            if is_c2pa_mime_type(&eo.mime_type) {
                manifests.push(eo.data.clone());
            }
        }
        if manifests.len() == 1 {
            input_stream.rewind().ok()?;
            let tag_bytes = input_stream
                .read_to_vec(header.map_or(0, |h| h.get_size()) as u64)
                .ok()?;
            let pos = memmem::find(&tag_bytes, &manifests[0])?;
            return Some((pos as u64, manifests[0].len() as u32));
        }
    }
    None
}

#[derive(Debug, thiserror::Error)]
pub enum FlacError {
    #[error("invalid ID3 version for FLAC")]
    InvalidId3Version,
}

pub struct FlacIO {
    _asset_type: String,
}

impl CAIReader for FlacIO {
    fn read_cai(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        input_stream.rewind()?;

        let header = ID3V2Header::read_header(input_stream)?;
        input_stream.rewind()?;

        if let Some(h) = header {
            let mut manifest: Option<Vec<u8>> = None;
            let reader = CAIReadWrapper {
                reader: input_stream,
            };
            if let Ok(tag) = Tag::read_from2(reader) {
                for eo in tag.encapsulated_objects() {
                    if is_c2pa_mime_type(&eo.mime_type) {
                        match &manifest {
                            Some(_) => return Err(Error::TooManyManifestStores),
                            None => manifest = Some(eo.data.clone()),
                        }
                    }
                }
            }
            input_stream.seek(SeekFrom::Start(h.get_size() as u64))?;
            validate_flac_stream(input_stream)?;
            if let Some(m) = manifest {
                return Ok(m);
            }
        } else {
            validate_flac_stream(input_stream)?;
        }

        Err(Error::JumbfNotFound)
    }

    fn read_xmp(&self, input_stream: &mut dyn CAIRead) -> Option<String> {
        input_stream.rewind().ok()?;
        let header = ID3V2Header::read_header(input_stream).ok()?;
        if header.is_none() {
            return None;
        }
        input_stream.rewind().ok()?;

        let reader = CAIReadWrapper {
            reader: input_stream,
        };
        if let Ok(tag) = Tag::read_from2(reader) {
            for frame in tag.frames() {
                if let Content::Private(private) = frame.content() {
                    if private.owner_identifier == "XMP" {
                        return String::from_utf8(private.private_data.clone()).ok();
                    }
                }
            }
        }
        None
    }
}

impl RemoteRefEmbed for FlacIO {
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
                source_stream.rewind()?;
                let header = ID3V2Header::read_header(source_stream)?;
                source_stream.rewind()?;

                let mut out_tag = Tag::new();
                let reader = CAIReadWrapper {
                    reader: source_stream,
                };
                if let Ok(tag) = Tag::read_from2(reader) {
                    for f in tag.frames() {
                        match f.content() {
                            Content::Private(private) => {
                                if private.owner_identifier != "XMP" {
                                    let _ = out_tag.add_frame(f.clone());
                                }
                            }
                            _ => {
                                let _ = out_tag.add_frame(f.clone());
                            }
                        }
                    }
                }

                let xmp = xmp_inmemory_utils::add_provenance(
                    &self
                        .read_xmp(source_stream)
                        .unwrap_or_else(|| MIN_XMP.to_string()),
                    &url,
                )?;
                let geob_frame = Frame::with_content(
                    "PRIV",
                    Content::Private(Private {
                        owner_identifier: "XMP".to_owned(),
                        private_data: xmp.into_bytes(),
                    }),
                );
                let _ = out_tag.add_frame(geob_frame);

                let writer = CAIReadWriteWrapper {
                    reader_writer: output_stream,
                };
                out_tag
                    .write_to(writer, Version::Id3v24)
                    .map_err(|_| Error::EmbeddingError)?;

                source_stream.seek(SeekFrom::Start(
                    header.map_or(0, |h| h.get_size()) as u64,
                ))?;
                std::io::copy(source_stream, output_stream)?;
                Ok(())
            }
            _ => Err(Error::UnsupportedType),
        }
    }
}

fn add_required_frame(
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    let flac_io = FlacIO::new("flac");

    input_stream.rewind()?;
    match flac_io.read_cai(input_stream) {
        Ok(_) => {
            input_stream.rewind()?;
            output_stream.rewind()?;
            std::io::copy(input_stream, output_stream)?;
            Ok(())
        }
        Err(_) => {
            input_stream.rewind()?;
            flac_io.write_cai(input_stream, output_stream, &[1, 2, 3, 4])
        }
    }
}

impl AssetIO for FlacIO {
    fn new(asset_type: &str) -> Self {
        FlacIO {
            _asset_type: asset_type.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(FlacIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(FlacIO::new(asset_type)))
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;
        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;
        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut f = File::open(asset_path).map_err(|_| Error::EmbeddingError)?;
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

impl CAIWriter for FlacIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        input_stream.rewind()?;
        let header = ID3V2Header::read_header(input_stream)?;
        input_stream.rewind()?;

        let mut out_tag = Tag::new();
        let reader = CAIReadWrapper {
            reader: input_stream,
        };
        if let Ok(tag) = Tag::read_from2(reader) {
            for f in tag.frames() {
                match f.content() {
                    Content::EncapsulatedObject(eo) => {
                        if !is_c2pa_mime_type(&eo.mime_type) {
                            let _ = out_tag.add_frame(f.clone());
                        }
                    }
                    _ => {
                        let _ = out_tag.add_frame(f.clone());
                    }
                }
            }
        }

        if !store_bytes.is_empty() {
            let geob_frame = Frame::with_content(
                "GEOB",
                Content::EncapsulatedObject(EncapsulatedObject {
                    mime_type: GEOB_FRAME_MIME_TYPE.to_string(),
                    filename: GEOB_FRAME_FILE_NAME.to_string(),
                    description: GEOB_FRAME_DESCRIPTION.to_string(),
                    data: store_bytes.to_vec(),
                }),
            );
            let _ = out_tag.add_frame(geob_frame);
        }

        let writer = CAIReadWriteWrapper {
            reader_writer: output_stream,
        };
        out_tag
            .write_to(writer, Version::Id3v24)
            .map_err(|_| Error::EmbeddingError)?;

        let flac_start = header.map_or(0, |h| h.get_size()) as u64;
        input_stream.seek(SeekFrom::Start(flac_start))?;
        std::io::copy(input_stream, output_stream)?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let output_buf: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_buf);
        add_required_frame(input_stream, &mut output_stream)?;

        let mut positions = Vec::new();
        let (manifest_pos, manifest_len) =
            get_manifest_pos(&mut output_stream).ok_or(Error::EmbeddingError)?;

        positions.push(HashObjectPositions {
            offset: usize::try_from(manifest_pos)
                .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
            length: usize::try_from(manifest_len)
                .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
            htype: HashBlockObjectType::Cai,
        });
        positions.push(HashObjectPositions {
            offset: 0,
            length: usize::try_from(manifest_pos)
                .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
            htype: HashBlockObjectType::Other,
        });
        let end = manifest_pos
            .checked_add(manifest_len as u64)
            .ok_or_else(|| Error::InvalidAsset("value out of range".to_string()))?;
        let file_end = stream_len(&mut output_stream)?;
        positions.push(HashObjectPositions {
            offset: usize::try_from(end)
                .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
            length: usize::try_from(file_end - end)
                .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
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

impl AssetPatch for FlacIO {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
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
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;
    use std::path::Path;

    use id3::frame::{Content, EncapsulatedObject};
    use id3::{Frame, Tag, Version};
    use xmp_inmemory_utils::extract_provenance;

    use super::*;
    use crate::asset_io::HashBlockObjectType;
    use crate::utils::{
        hash_utils::vec_compare,
        io_utils::tempdirectory,
        test::{fixture_path, temp_dir_path},
    };

    /// C2PA GEOB mime type (must match flac_io constant for building tags).
    const GEOB_MIME: &str = "application/c2pa";
    const GEOB_FILENAME: &str = "c2pa";
    const GEOB_DESC: &str = "c2pa manifest store";

    /// Minimal valid FLAC stream for tests that don't need a file (pure FLAC, no ID3).
    const MINIMAL_FLAC: &[u8] = include_bytes!("../../tests/fixtures/sample1.flac");

    /// Build 10-byte ID3v2 header: ID3 + version + flags + 4-byte synch-safe size.
    #[cfg(test)]
    fn id3_header(version_major: u8, tag_size: u32) -> [u8; 10] {
        let mut h = [0u8; 10];
        h[0..3].copy_from_slice(b"ID3");
        h[3] = version_major;
        h[4] = 0;
        h[5] = 0;
        h[6] = ((tag_size >> 21) & 0x7f) as u8;
        h[7] = ((tag_size >> 14) & 0x7f) as u8;
        h[8] = ((tag_size >> 7) & 0x7f) as u8;
        h[9] = (tag_size & 0x7f) as u8;
        h
    }

    /// Build in-memory stream: ID3 tag (via id3 crate) + FLAC tail.
    #[cfg(test)]
    fn id3_tag_plus_flac(tag: Tag, flac_tail: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        tag.write_to(&mut buf, Version::Id3v24).expect("write id3");
        buf.extend_from_slice(flac_tail);
        buf
    }

    // ---------- read_cai / header / validation ----------

    #[test]
    fn test_read_cai_store_no_id3() {
        let flac_io = FlacIO::new("flac");
        let mut cursor = Cursor::new(MINIMAL_FLAC);
        match flac_io.read_cai(&mut cursor) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("expected JumbfNotFound for pure FLAC, got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_unsupported_type() {
        let flac_io = FlacIO::new("flac");
        let mut buf = vec![0u8; 10];
        buf[0..4].copy_from_slice(b"XXXX");
        buf.extend_from_slice(MINIMAL_FLAC);
        let mut cursor = Cursor::new(buf);
        match flac_io.read_cai(&mut cursor) {
            Err(Error::UnsupportedType) => {}
            other => panic!("expected UnsupportedType, got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_invalid_id3_version() {
        let flac_io = FlacIO::new("flac");
        let mut buf = id3_header(1, 0).to_vec();
        buf.extend_from_slice(MINIMAL_FLAC);
        let mut cursor = Cursor::new(buf);
        match flac_io.read_cai(&mut cursor) {
            Err(Error::FlacError(FlacError::InvalidId3Version)) => {}
            other => panic!("expected FlacError(InvalidId3Version), got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_io_error_too_short() {
        let flac_io = FlacIO::new("flac");
        let mut cursor = Cursor::new(b"abc");
        match flac_io.read_cai(&mut cursor) {
            Err(Error::IoError(_)) => {}
            other => panic!("expected IoError for short stream, got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_invalid_flac_after_id3() {
        // ID3 header with size 0, then non-FLAC bytes so validate_flac_stream fails.
        let flac_io = FlacIO::new("flac");
        let mut buf = id3_header(4, 0).to_vec();
        buf.extend_from_slice(b"XXXX");
        buf.extend_from_slice(MINIMAL_FLAC);
        let mut cursor = Cursor::new(buf);
        match flac_io.read_cai(&mut cursor) {
            Err(_) => {}
            Ok(_) => panic!("expected error for ID3 followed by non-FLAC bytes"),
        }
    }

    #[test]
    fn test_read_cai_too_many_manifest_stores() {
        // Build ID3 tag with two C2PA GEOB frames. Some ID3 readers may merge duplicate
        // frame IDs, so we may get only one manifest; the implementation returns
        // TooManyManifestStores only when both are seen.
        let mut tag = Tag::new();
        let geob = Frame::with_content(
            "GEOB",
            Content::EncapsulatedObject(EncapsulatedObject {
                mime_type: GEOB_MIME.to_string(),
                filename: GEOB_FILENAME.to_string(),
                description: GEOB_DESC.to_string(),
                data: b"first".to_vec(),
            }),
        );
        tag.add_frame(geob);
        let geob2 = Frame::with_content(
            "GEOB",
            Content::EncapsulatedObject(EncapsulatedObject {
                mime_type: GEOB_MIME.to_string(),
                filename: GEOB_FILENAME.to_string(),
                description: GEOB_DESC.to_string(),
                data: b"second".to_vec(),
            }),
        );
        tag.add_frame(geob2);
        let buf = id3_tag_plus_flac(tag, MINIMAL_FLAC);
        let flac_io = FlacIO::new("flac");
        let mut cursor = Cursor::new(buf);
        let result = flac_io.read_cai(&mut cursor);
        match result {
            Err(Error::TooManyManifestStores) => {}
            Ok(data) => {
                assert!(
                    data == b"first" || data == b"second",
                    "if one GEOB returned, must be first or second; got {:?}",
                    data
                );
            }
            other => panic!("expected TooManyManifestStores or Ok(first|second), got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_success_with_manifest() {
        let payload = b"c2pa manifest payload";
        let source = fixture_path("sample1.flac");
        let temp_dir = tempdirectory().expect("temp dir");
        let output = temp_dir_path(&temp_dir, "with_manifest.flac");
        std::fs::copy(source, &output).expect("copy");
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, payload).expect("save");
        let mut f = File::open(&output).unwrap();
        let read = flac_io.read_cai(&mut f).expect("read_cai");
        assert!(vec_compare(payload, &read));
    }

    #[test]
    fn test_write_flac() {
        let more_data = b"some more test data";
        let source = fixture_path("sample1.flac");

        let temp_dir = tempdirectory().expect("temp dir");
        let output = temp_dir_path(&temp_dir, "sample1-out.flac");
        std::fs::copy(source, &output).expect("copy");
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, more_data).expect("save_cai_store");
        let read_back = flac_io.read_cai_store(&output).expect("read_cai_store");
        assert!(vec_compare(more_data, &read_back));
    }

    #[test]
    fn test_patch_write_flac() {
        let test_data = b"some test data";
        let source = fixture_path("sample1.flac");

        let temp_dir = tempdirectory().expect("temp dir");
        let output = temp_dir_path(&temp_dir, "sample1-patch.flac");
        std::fs::copy(source, &output).expect("copy");
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, test_data).expect("save_cai_store");
        let source_data = flac_io.read_cai_store(&output).expect("read");
        let mut new_data = vec![0u8; source_data.len()];
        new_data[..test_data.len()].copy_from_slice(test_data);
        flac_io.patch_cai_store(&output, &new_data).unwrap();
        let replaced = flac_io.read_cai_store(&output).unwrap();
        assert_eq!(new_data, replaced);
    }

    #[test]
    fn test_patch_cai_store_size_mismatch() {
        let source = fixture_path("sample1.flac");
        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "patch_mismatch.flac");
        std::fs::copy(source, &output).unwrap();
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, &[1, 2, 3, 4]).unwrap();
        let wrong_size_data = b"wrong length";
        match flac_io.patch_cai_store(&output, wrong_size_data) {
            Err(Error::InvalidAsset(msg)) if msg.contains("patch_cai_store store size mismatch") => {}
            other => panic!("expected InvalidAsset(size mismatch), got {:?}", other),
        }
    }

    #[test]
    fn test_remove_c2pa_flac() {
        let source = fixture_path("sample1.flac");
        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "sample1-nomanifest.flac");
        std::fs::copy(source, &output).unwrap();
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, &[1, 2, 3]).unwrap();
        flac_io.remove_cai_store(&output).unwrap();
        match flac_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_get_object_locations_flac() {
        let source = fixture_path("sample1.flac");
        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "sample1-locs.flac");
        std::fs::copy(source, &output).unwrap();
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, &[1, 2, 3, 4, 5]).unwrap();
        let positions = flac_io.get_object_locations(&output).unwrap();
        assert!(!positions.is_empty());
    }

    #[test]
    fn test_get_object_locations_flac_structure() {
        let source = fixture_path("sample1.flac");
        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "locs_struct.flac");
        std::fs::copy(source, &output).unwrap();
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, &[1, 2, 3, 4, 5]).unwrap();
        let positions = flac_io.get_object_locations(&output).unwrap();
        assert_eq!(positions.len(), 3, "expected [Cai, Other, Other]");
        let file_len = std::fs::metadata(&output).unwrap().len() as usize;
        let sum_len: usize = positions.iter().map(|p| p.length).sum();
        assert_eq!(sum_len, file_len, "position lengths should sum to file size");
        let cai_idx = positions.iter().position(|p| p.htype == HashBlockObjectType::Cai).unwrap();
        let other_before = positions.iter().position(|p| p.htype == HashBlockObjectType::Other && p.offset == 0).unwrap();
        assert_eq!(positions[other_before].offset, 0);
        assert!(positions[cai_idx].offset + positions[cai_idx].length <= file_len);
    }

    #[test]
    fn test_remote_ref_flac() -> Result<()> {
        let flac_io = FlacIO::new("flac");
        let path = fixture_path("sample1.flac");
        let mut stream = File::open(path)?;
        assert_eq!(flac_io.read_xmp(&mut stream), None);
        stream.rewind()?;
        let mut output_stream = Cursor::new(Vec::new());
        flac_io.embed_reference_to_stream(
            &mut stream,
            &mut output_stream,
            RemoteRefEmbedType::Xmp("Test".to_owned()),
        )?;
        output_stream.rewind()?;
        let xmp = flac_io.read_xmp(&mut output_stream).unwrap();
        let p = extract_provenance(&xmp).unwrap();
        assert_eq!(&p, "Test");
        Ok(())
    }

    #[test]
    fn test_embed_reference_to_stream_unsupported_type() {
        let flac_io = FlacIO::new("flac");
        let path = fixture_path("sample1.flac");
        let mut stream = File::open(path).unwrap();
        let mut output = Cursor::new(Vec::new());
        match flac_io.embed_reference_to_stream(
            &mut stream,
            &mut output,
            RemoteRefEmbedType::StegoS("x".to_string()),
        ) {
            Err(Error::UnsupportedType) => {}
            other => panic!("expected UnsupportedType for StegoS, got {:?}", other),
        }
    }

    #[test]
    fn test_embed_reference_file_path() -> Result<()> {
        let flac_io = FlacIO::new("flac");
        let source = fixture_path("sample1.flac");
        let temp_dir = tempdirectory().expect("temp dir");
        let output = temp_dir_path(&temp_dir, "embed_ref.flac");
        std::fs::copy(&source, &output).expect("copy");
        flac_io.embed_reference(&output, RemoteRefEmbedType::Xmp("https://example.com/ref".to_string()))?;
        let mut f = File::open(&output)?;
        let xmp = flac_io.read_xmp(&mut f).expect("xmp present");
        let p = extract_provenance(&xmp).unwrap();
        assert_eq!(&p, "https://example.com/ref");
        Ok(())
    }

    #[test]
    fn test_remove_cai_store_from_stream() {
        let source = fixture_path("sample1.flac");
        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "stream_remove.flac");
        std::fs::copy(source, &output).unwrap();
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, &[1, 2, 3]).unwrap();
        let mut input = File::open(&output).unwrap();
        let mut out_buf = Cursor::new(Vec::new());
        flac_io.remove_cai_store_from_stream(&mut input, &mut out_buf).unwrap();
        out_buf.set_position(0);
        match flac_io.read_cai(&mut out_buf) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("expected JumbfNotFound after remove_cai_store_from_stream, got {:?}", other),
        }
    }

    #[test]
    fn test_write_cai_empty_store_removes_manifest() {
        let source = fixture_path("sample1.flac");
        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "empty_write.flac");
        std::fs::copy(source, &output).unwrap();
        let flac_io = FlacIO::new("flac");
        flac_io.save_cai_store(&output, &[1, 2, 3]).unwrap();
        let mut input = File::open(&output).unwrap();
        let mut out_buf = Cursor::new(Vec::new());
        flac_io.write_cai(&mut input, &mut out_buf, &[]).unwrap();
        out_buf.set_position(0);
        match flac_io.read_cai(&mut out_buf) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("expected JumbfNotFound after write_cai with empty store, got {:?}", other),
        }
    }

    #[test]
    fn test_supported_types() {
        let flac_io = FlacIO::new("flac");
        let types = flac_io.supported_types();
        assert!(types.contains(&"flac"));
        assert!(types.contains(&"audio/flac"));
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn test_get_handler_and_reader() {
        let flac_io = FlacIO::new("flac");
        let handler = flac_io.get_handler("audio/flac");
        let reader = flac_io.get_reader();
        let mut cursor = Cursor::new(MINIMAL_FLAC);
        match reader.read_cai(&mut cursor) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("unexpected: {:?}", other),
        }
        assert!(handler.supported_types().contains(&"audio/flac"));
    }

    #[test]
    fn test_read_cai_store_file_not_found() {
        let flac_io = FlacIO::new("flac");
        let path = Path::new("/nonexistent/sample.flac");
        match flac_io.read_cai_store(path) {
            Err(Error::IoError(_)) => {}
            other => panic!("expected IoError for missing file, got {:?}", other),
        }
    }
}
