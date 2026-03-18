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
    io::{Cursor, SeekFrom},
    path::Path,
};

use id3::Tag;

use crate::{
    asset_handlers::id3_helper::{self, ID3V2Header},
    asset_io::{
        AssetIO, AssetPatch, CAIRead, CAIReadWrapper, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions, RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
};

static SUPPORTED_TYPES: [&str; 2] = ["flac", "audio/flac"];

const FLAC_HEADER: &[u8; 4] = b"fLaC";
const ID3_HEADER: &[u8; 3] = b"ID3";

// ── FLAC-specific ID3 header reader ─────────────────────────────────────────

/// Reads the first 10 bytes and returns the ID3v2 header if present.
///
/// * Returns `Ok(Some(h))` when the stream starts with a valid ID3v2 tag.
/// * Returns `Ok(None)` when the stream starts with the `fLaC` marker (pure
///   FLAC without an ID3 wrapper).
/// * Returns `Err` for an unsupported ID3 version (mapped to
///   [`FlacError::InvalidId3Version`]) or an unrecognised header.
fn read_header(reader: &mut dyn CAIRead) -> Result<Option<ID3V2Header>> {
    let mut buf = [0u8; 10];
    reader.read_exact(&mut buf).map_err(Error::IoError)?;

    if buf[0..3] == *ID3_HEADER {
        return ID3V2Header::parse_from_bytes(&buf)
            .map_err(|_| Error::FlacError(FlacError::InvalidId3Version));
    }

    if buf[0..4] == *FLAC_HEADER {
        return Ok(None);
    }

    Err(Error::UnsupportedType)
}

/// Validates that the reader's current position is the start of a valid FLAC
/// stream (i.e. starts with the `fLaC` marker).
fn validate_flac_stream(reader: &mut dyn CAIRead) -> Result<()> {
    let mut marker = [0u8; 4];
    reader.read_exact(&mut marker).map_err(Error::IoError)?;
    if &marker != b"fLaC" {
        return Err(Error::InvalidAsset("invalid FLAC stream: missing fLaC marker".to_string()));
    }
    Ok(())
}

// ── Helper ───────────────────────────────────────────────────────────────────

/// Ensures `output_stream` contains an ID3 tag with a C2PA GEOB frame,
/// writing a placeholder if none exists, so that manifest positions can be
/// computed.
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

// ── FlacError ────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum FlacError {
    #[error("invalid ID3 version for FLAC")]
    InvalidId3Version,
}

// ── FlacIO ───────────────────────────────────────────────────────────────────

pub struct FlacIO {
    _asset_type: String,
}

impl CAIReader for FlacIO {
    fn read_cai(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        input_stream.rewind()?;
        let header = read_header(input_stream)?;
        input_stream.rewind()?;

        if let Some(h) = header {
            let mut manifest: Option<Vec<u8>> = None;
            let reader = CAIReadWrapper {
                reader: input_stream,
            };
            if let Ok(tag) = Tag::read_from2(reader) {
                for eo in tag.encapsulated_objects() {
                    if id3_helper::is_c2pa_mime_type(&eo.mime_type) {
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
        // XMP is only present when there is an ID3 tag.
        input_stream.rewind().ok()?;
        let header = read_header(input_stream).ok()?;
        header.as_ref()?;
        id3_helper::read_xmp_from_id3(input_stream)
    }
}

impl RemoteRefEmbed for FlacIO {
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

impl CAIWriter for FlacIO {
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
        add_required_frame(input_stream, &mut output_stream)?;
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

impl AssetPatch for FlacIO {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        id3_helper::patch_cai_in_id3_asset(asset_path, store_bytes)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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

    /// Minimal valid FLAC stream (no ID3 prefix).
    const MINIMAL_FLAC: &[u8] = include_bytes!("../../tests/fixtures/sample1.flac");

    fn fixture() -> std::path::PathBuf {
        fixture_path("sample1.flac")
    }

    // ── shared behavioral tests ──────────────────────────────────────────────

    #[test]
    fn test_write_flac() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-out.flac");
        test_helpers::run_write_read_roundtrip(&handler, &fixture(), &out);
    }

    #[test]
    fn test_patch_write_flac() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-patch.flac");
        test_helpers::run_patch_same_size(&handler, &fixture(), &out);
    }

    #[test]
    fn test_patch_cai_store_size_mismatch() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "patch_mismatch.flac");
        test_helpers::run_patch_size_mismatch(&handler, &fixture(), &out);
    }

    #[test]
    fn test_remove_c2pa_flac() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "sample1-nomanifest.flac");
        test_helpers::run_remove_manifest(&handler, &fixture(), &out);
    }

    #[test]
    fn test_remote_ref_flac() {
        let handler = FlacIO::new("flac");
        test_helpers::run_remote_ref_xmp(&handler, &handler, &fixture());
    }

    #[test]
    fn test_get_object_locations_flac_structure() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "locs_struct.flac");
        test_helpers::run_get_object_locations_structure(&handler, &fixture(), &out);
    }

    #[test]
    fn test_remove_cai_store_from_stream() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "stream_remove.flac");
        test_helpers::run_remove_from_stream(&handler, &fixture(), &out);
    }

    #[test]
    fn test_write_cai_empty_store_removes_manifest() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "empty_write.flac");
        test_helpers::run_write_cai_empty_removes(&handler, &fixture(), &out);
    }

    #[test]
    fn test_embed_reference_to_stream_unsupported_type() {
        let handler = FlacIO::new("flac");
        test_helpers::run_embed_reference_unsupported(&handler, &fixture());
    }

    #[test]
    fn test_supported_types() {
        let handler = FlacIO::new("flac");
        test_helpers::run_supported_types(&handler, "flac", "audio/flac");
    }

    #[test]
    fn test_embed_reference_file_path() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "embed_ref.flac");
        test_helpers::run_embed_reference_file_path(&handler, &handler, &fixture(), &out);
    }

    #[test]
    fn test_read_cai_success_with_manifest() {
        let handler = FlacIO::new("flac");
        let temp = tempdirectory().unwrap();
        let out = crate::utils::test::temp_dir_path(&temp, "with_manifest.flac");
        test_helpers::run_read_cai_success_with_manifest(&handler, &fixture(), &out);
    }

    // ── FLAC-specific tests ──────────────────────────────────────────────────

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
        test_helpers::run_read_cai_unsupported_type(&FlacIO::new("flac"));
    }

    #[test]
    fn test_read_cai_invalid_id3_version() {
        let flac_io = FlacIO::new("flac");
        let mut buf = test_helpers::id3_header(1, 0).to_vec();
        buf.extend_from_slice(MINIMAL_FLAC);
        let mut cursor = Cursor::new(buf);
        match flac_io.read_cai(&mut cursor) {
            Err(Error::FlacError(FlacError::InvalidId3Version)) => {}
            other => panic!("expected FlacError(InvalidId3Version), got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_io_error_too_short() {
        test_helpers::run_read_cai_io_error_too_short(&FlacIO::new("flac"));
    }

    #[test]
    fn test_read_cai_invalid_flac_after_id3() {
        let flac_io = FlacIO::new("flac");
        let mut buf = test_helpers::id3_header(4, 0).to_vec();
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
        test_helpers::run_read_cai_too_many_manifest_stores(&FlacIO::new("flac"), MINIMAL_FLAC);
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
