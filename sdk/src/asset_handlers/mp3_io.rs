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

use std::{io::Cursor, path::Path};

use id3::Tag;

use crate::{
    asset_handlers::id3_helper::{self, ID3V2Header},
    asset_io::{
        AssetIO, AssetPatch, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions,
        RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
};

static SUPPORTED_TYPES: [&str; 2] = ["mp3", "audio/mpeg"];

// ── MP3-specific ID3 header reader ──────────────────────────────────────────

/// Reads the first 10 bytes and returns the ID3v2 header if present.
///
/// Falls back to checking for the MPEG audio frame sync word when the stream
/// does not start with `"ID3"`, in which case `Ok(None)` is returned.
fn read_header(reader: &mut dyn CAIRead) -> Result<Option<ID3V2Header>> {
    let mut buf = [0u8; 10];
    reader.read_exact(&mut buf)?;

    match ID3V2Header::parse_from_bytes(&buf)? {
        Some(h) => Ok(Some(h)),
        None => {
            // Check for MPEG audio frame sync word (first 11 bits set).
            if buf[0] == 0xff && (buf[1] & 0xe0 == 0xe0) {
                Ok(None)
            } else {
                Err(Error::UnsupportedType)
            }
        }
    }
}

// ── Helper ───────────────────────────────────────────────────────────────────

/// Ensures `output_stream` contains an ID3 tag with a C2PA GEOB frame,
/// writing a placeholder if none exists, so that manifest positions can be
/// computed.
fn add_required_frame(
    asset_type: &str,
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    let mp3io = Mp3IO::new(asset_type);
    input_stream.rewind()?;
    match mp3io.read_cai(input_stream) {
        Ok(_) => {
            input_stream.rewind()?;
            output_stream.rewind()?;
            std::io::copy(input_stream, output_stream)?;
            Ok(())
        }
        Err(Error::JumbfNotFound) => {
            input_stream.rewind()?;
            mp3io.write_cai(input_stream, output_stream, &[1, 2, 3, 4])
        }
        Err(Error::TooManyManifestStores) => Ok(()),
        Err(e) => Err(e),
    }
}

// ── Mp3IO ────────────────────────────────────────────────────────────────────

pub struct Mp3IO {
    _mp3_format: String,
}

impl CAIReader for Mp3IO {
    fn read_cai(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        input_stream.rewind()?;
        let mut manifest: Option<Vec<u8>> = None;
        if let Ok(tag) = Tag::read_from2(input_stream) {
            for eo in tag.encapsulated_objects() {
                if id3_helper::is_c2pa_mime_type(&eo.mime_type) {
                    match manifest {
                        Some(_) => return Err(Error::TooManyManifestStores),
                        None => manifest = Some(eo.data.clone()),
                    }
                }
            }
        }
        manifest.ok_or(Error::JumbfNotFound)
    }

    fn read_xmp(&self, input_stream: &mut dyn CAIRead) -> Option<String> {
        id3_helper::read_xmp_from_id3(input_stream).ok()?
    }
}

impl RemoteRefEmbed for Mp3IO {
    fn embed_reference(&self, asset_path: &Path, embed_ref: RemoteRefEmbedType) -> Result<()> {
        id3_helper::embed_xmp_reference(self, asset_path, embed_ref)
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
                let header = read_header(source_stream)?;
                let id3_end = header.map_or(0, |h| h.get_size()) as u64;
                let current_xmp = self.read_xmp(source_stream);
                id3_helper::embed_xmp_to_id3_stream(
                    source_stream,
                    output_stream,
                    url,
                    id3_end,
                    current_xmp,
                )
            }
            _ => Err(Error::UnsupportedType),
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
        id3_helper::read_cai_store_from_path(self, asset_path)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        id3_helper::save_cai_store_to_path(self, asset_path, store_bytes)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        id3_helper::get_object_locations_from_path(self, asset_path)
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

impl CAIWriter for Mp3IO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        input_stream.rewind()?;
        let header = read_header(input_stream)?;
        let id3_end = header.map_or(0, |h| h.get_size()) as u64;
        id3_helper::write_cai_with_id3(input_stream, output_stream, store_bytes, id3_end)
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let mut output_stream = Cursor::new(Vec::<u8>::new());
        add_required_frame(&self._mp3_format, input_stream, &mut output_stream)?;
        id3_helper::get_object_locations(&mut output_stream)
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
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        id3_helper::patch_cai_in_id3_asset(asset_path, store_bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Mp3Error {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::{io::Cursor, path::Path};

    use super::*;
    use crate::{
        asset_handlers::id3_helper::test_helpers,
        error::Error,
        utils::{io_utils::tempdirectory, test::fixture_path},
    };

    fn fixture() -> std::path::PathBuf {
        fixture_path("sample1.mp3")
    }

    // ── shared behavioral tests ──────────────────────────────────────────────

    #[test]
    fn test_write_mp3() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-mp3.mp3");
        test_helpers::run_write_read_roundtrip(&handler, &fixture(), &out);
    }

    #[test]
    fn test_patch_write_mp3() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-mp3.mp3");
        test_helpers::run_patch_same_size(&handler, &fixture(), &out);
    }

    #[test]
    fn test_patch_size_mismatch() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-mp3.mp3");
        test_helpers::run_patch_size_mismatch(&handler, &fixture(), &out);
    }

    #[test]
    fn test_remove_c2pa() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-mp3.mp3");
        test_helpers::run_remove_manifest(&handler, &fixture(), &out);
    }

    #[test]
    fn test_remote_ref() {
        let handler = Mp3IO::new("mp3");
        test_helpers::run_remote_ref_xmp(&handler, &handler, &fixture());
    }

    #[test]
    fn test_get_object_locations_structure() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-mp3.mp3");
        test_helpers::run_get_object_locations_structure(&handler, &fixture(), &out);
    }

    #[test]
    fn test_remove_from_stream() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-mp3.mp3");
        test_helpers::run_remove_from_stream(&handler, &fixture(), &out);
    }

    #[test]
    fn test_write_cai_empty_removes() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-mp3.mp3");
        test_helpers::run_write_cai_empty_removes(&handler, &fixture(), &out);
    }

    #[test]
    fn test_embed_reference_unsupported() {
        let handler = Mp3IO::new("mp3");
        test_helpers::run_embed_reference_unsupported(&handler, &fixture());
    }

    #[test]
    fn test_supported_types() {
        let handler = Mp3IO::new("mp3");
        test_helpers::run_supported_types(&handler, "mp3", "audio/mpeg");
    }

    #[test]
    fn test_embed_reference_file_path() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "embed_ref.mp3");
        test_helpers::run_embed_reference_file_path(&handler, &handler, &fixture(), &out);
    }

    #[test]
    fn test_read_cai_success_with_manifest() {
        let handler = Mp3IO::new("mp3");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "with_manifest.mp3");
        test_helpers::run_read_cai_success_with_manifest(&handler, &fixture(), &out);
    }

    #[test]
    fn test_read_cai_too_many_manifest_stores() {
        // MP3 does not validate the audio payload, so an empty slice is fine.
        test_helpers::run_read_cai_too_many_manifest_stores(&Mp3IO::new("mp3"), &[]);
    }

    #[test]
    fn test_get_handler_and_reader() {
        let mp3_io = Mp3IO::new("mp3");
        let handler = mp3_io.get_handler("audio/mpeg");
        let reader = mp3_io.get_reader();
        let mut f = std::fs::File::open(fixture()).unwrap();
        match reader.read_cai(&mut f) {
            Err(Error::JumbfNotFound) => {}
            other => panic!(
                "unexpected result for fixture without manifest: {:?}",
                other
            ),
        }
        assert!(handler.supported_types().contains(&"audio/mpeg"));
    }

    #[test]
    fn test_read_cai_store_file_not_found() {
        let mp3_io = Mp3IO::new("mp3");
        match mp3_io.read_cai_store(Path::new("/nonexistent/sample.mp3")) {
            Err(Error::IoError(_)) => {}
            other => panic!("expected IoError for missing file, got {:?}", other),
        }
    }

    // ── MP3-specific tests ───────────────────────────────────────────────────

    /// A bare MPEG stream (MPEG sync word, no ID3 tag) contains no C2PA manifest.
    #[test]
    fn test_read_cai_store_no_id3() {
        let mp3_io = Mp3IO::new("mp3");
        // Minimal MPEG frame sync: first 11 bits set (0xFF 0xE0 …).
        let mpeg_stream: Vec<u8> = std::iter::once(0xff_u8)
            .chain(std::iter::once(0xe0_u8))
            .chain(std::iter::repeat_n(0, 20))
            .collect();
        let mut cursor = Cursor::new(mpeg_stream);
        match mp3_io.read_cai(&mut cursor) {
            Err(Error::JumbfNotFound) => {}
            other => panic!(
                "expected JumbfNotFound for bare MPEG stream, got {:?}",
                other
            ),
        }
    }

    /// `write_cai` (via `read_header`) returns `UnsupportedType` for unknown magic.
    #[test]
    fn test_write_cai_unsupported_type() {
        let mp3_io = Mp3IO::new("mp3");
        let mut input = Cursor::new(b"XXXX\x00\x00\x00\x00\x00\x00".to_vec());
        let mut output = Cursor::new(Vec::new());
        match mp3_io.write_cai(&mut input, &mut output, &[1, 2, 3]) {
            Err(Error::UnsupportedType) => {}
            other => panic!(
                "expected UnsupportedType for unknown magic, got {:?}",
                other
            ),
        }
    }

    /// `write_cai` (via `read_header`) returns `IoError` when the stream is too short.
    #[test]
    fn test_write_cai_io_error_too_short() {
        let mp3_io = Mp3IO::new("mp3");
        let mut input = Cursor::new(b"abc".to_vec());
        let mut output = Cursor::new(Vec::new());
        match mp3_io.write_cai(&mut input, &mut output, &[1, 2, 3]) {
            Err(Error::IoError(_)) => {}
            other => panic!("expected IoError for short stream, got {:?}", other),
        }
    }

    /// `write_cai` (via `read_header`) returns `UnsupportedType` for ID3v1 headers
    /// (version < 2 is not a valid ID3v2 tag).
    #[test]
    fn test_write_cai_invalid_id3_version() {
        let mp3_io = Mp3IO::new("mp3");
        let mut input = Cursor::new(test_helpers::id3_header(1, 0).to_vec());
        let mut output = Cursor::new(Vec::new());
        match mp3_io.write_cai(&mut input, &mut output, &[1, 2, 3]) {
            Err(Error::UnsupportedType) => {}
            other => panic!("expected UnsupportedType for ID3v1 header, got {:?}", other),
        }
    }
}
