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

use std::{fs::File, io::Cursor, path::Path};

use memchr::memmem;

use crate::{
    asset_handlers::pdf::{AnyPdf, C2paPdf},
    asset_io::{
        rename_or_move, AssetIO, AssetPatch, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        ComposedManifestRef, HashBlockObjectType, HashObjectPositions,
    },
    utils::{io_utils::tempfile_builder, patch::patch_bytes},
    Error::{self, JumbfNotFound, NotImplemented, PdfReadError},
};

static SUPPORTED_TYPES: [&str; 2] = ["pdf", "application/pdf"];

/// Selects which PDF backend implementation handles PDF assets.
///
/// Set via the `core.pdf_backend` settings value, e.g.
/// `Settings::new().with_json(r#"{"core": {"pdf_backend": "pdf_oxide"}}"#)` (see
/// [`crate::settings`]). Like the rest of the SDK's thread-local settings, `AssetIO`
/// implementations such as [`PdfIO`] read the thread-local settings directly (there is no
/// `Context` threaded down to this layer), so this is set via
/// [`crate::settings::Settings::set_thread_local_value`] rather than per-`Context`.
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfBackend {
    /// The default, stable backend, built on `lopdf`. Supports both reading and writing.
    #[default]
    Lopdf,
    /// Experimental backend built on `pdf_oxide` (feature `unstable_pdf_oxide`). Read-only: see
    /// `docs/experimental-features.md`.
    #[cfg(feature = "unstable_pdf_oxide")]
    PdfOxide,
}

/// Returns the currently-selected [`PdfBackend`] from the thread-local settings.
pub(crate) fn pdf_backend() -> PdfBackend {
    crate::settings::get_thread_local_settings().core.pdf_backend
}

pub struct PdfIO {}

impl CAIReader for PdfIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> crate::Result<Vec<u8>> {
        asset_reader.rewind()?;

        let pdf =
            AnyPdf::from_reader(asset_reader).map_err(|e| Error::InvalidAsset(e.to_string()))?;
        self.read_manifest_bytes(pdf)
    }

    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        if asset_reader.rewind().is_err() {
            return None;
        }

        let Ok(pdf) = AnyPdf::from_reader(asset_reader) else {
            return None;
        };

        self.read_xmp_from_pdf(pdf)
    }
}

impl PdfIO {
    fn read_manifest_bytes(&self, pdf: impl C2paPdf) -> crate::Result<Vec<u8>> {
        let Ok(result) = pdf.read_manifest_bytes() else {
            return Err(PdfReadError);
        };

        let Some(bytes) = result else {
            return Err(JumbfNotFound);
        };

        match bytes.as_slice() {
            [bytes] => Ok(bytes.to_vec()),
            _ => Err(NotImplemented(
                "c2pa-rs only supports reading PDFs with one manifest".into(),
            )),
        }
    }

    fn read_xmp_from_pdf(&self, pdf: impl C2paPdf) -> Option<String> {
        pdf.read_xmp()
    }

    /// Parses `raw` as a PDF and returns the bytes of its single embedded C2PA manifest.
    ///
    /// Returns `Err(JumbfNotFound)` if no manifest is present, or `Err(NotImplemented(_))`
    /// if more than one manifest is present (see [`Self::read_manifest_bytes`]).
    fn parse_single_manifest(&self, raw: &[u8]) -> crate::Result<Vec<u8>> {
        let mut reader = Cursor::new(raw);
        let pdf =
            AnyPdf::from_reader(&mut reader).map_err(|e| Error::InvalidAsset(e.to_string()))?;
        self.read_manifest_bytes(pdf)
    }
}

impl CAIWriter for PdfIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> crate::Result<()> {
        input_stream.rewind()?;
        let mut input_bytes = Vec::new();
        input_stream.read_to_end(&mut input_bytes)?;

        // Fast path: if a same-length manifest is already embedded, patch its bytes in
        // place instead of rebuilding the PDF's object graph. `Store` relies on this:
        // it first embeds a placeholder-signed manifest, computes a data hash over the
        // asset, then re-embeds the final signed manifest of identical length; any
        // shift in the surrounding bytes at that point would invalidate that hash.
        if let Ok(existing) = self.parse_single_manifest(&input_bytes) {
            if existing.len() == store_bytes.len()
                && patch_bytes(&mut input_bytes, &existing, store_bytes).is_ok()
            {
                output_stream.rewind()?;
                output_stream.write_all(&input_bytes)?;
                return Ok(());
            }
        }

        // Slow path: first embed, or replacing a manifest whose size changed. This
        // rebuilds the PDF's full object graph, so byte offsets elsewhere in the file
        // may shift.
        let mut reader = Cursor::new(&input_bytes);
        let mut pdf =
            AnyPdf::from_reader(&mut reader).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        if pdf.is_password_protected() {
            return Err(Error::InvalidAsset(
                "cannot embed a C2PA manifest into a password-protected PDF".to_string(),
            ));
        }

        if pdf.has_c2pa_manifest() {
            pdf.remove_manifest_bytes()
                .map_err(|e| Error::InvalidAsset(e.to_string()))?;
        }

        pdf.write_manifest_as_embedded_file(store_bytes.to_vec())
            .map_err(|e| Error::InvalidAsset(e.to_string()))?;

        let mut output_bytes = Vec::new();
        pdf.save_to(&mut output_bytes)?;

        output_stream.rewind()?;
        output_stream.write_all(&output_bytes)?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> crate::Result<Vec<HashObjectPositions>> {
        input_stream.rewind()?;
        let mut raw = Vec::new();
        input_stream.read_to_end(&mut raw)?;
        let file_len = raw.len();

        if let Ok(existing) = self.parse_single_manifest(&raw) {
            if let Some(offset) = memmem::find(&raw, &existing) {
                let length = existing.len();
                return Ok(vec![
                    HashObjectPositions {
                        offset: 0,
                        length: offset,
                        htype: HashBlockObjectType::Other,
                    },
                    HashObjectPositions {
                        offset,
                        length,
                        htype: HashBlockObjectType::Cai,
                    },
                    HashObjectPositions {
                        offset: offset + length,
                        length: file_len.saturating_sub(offset + length),
                        htype: HashBlockObjectType::Other,
                    },
                ]);
            }
        }

        // No manifest embedded yet: this is the pre-embed guess `Store` uses only to
        // size a placeholder data-hash assertion. The real positions are recomputed
        // once the manifest has actually been written (see `write_cai`).
        Ok(vec![
            HashObjectPositions {
                offset: 0,
                length: 0,
                htype: HashBlockObjectType::Other,
            },
            HashObjectPositions {
                offset: 0,
                length: file_len.min(1),
                htype: HashBlockObjectType::Cai,
            },
            HashObjectPositions {
                offset: file_len.min(1),
                length: file_len.saturating_sub(1),
                htype: HashBlockObjectType::Other,
            },
        ])
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> crate::Result<()> {
        input_stream.rewind()?;
        let mut raw = Vec::new();
        input_stream.read_to_end(&mut raw)?;

        let mut reader = Cursor::new(&raw);
        let mut pdf =
            AnyPdf::from_reader(&mut reader).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        if !pdf.has_c2pa_manifest() {
            output_stream.rewind()?;
            output_stream.write_all(&raw)?;
            return Ok(());
        }

        pdf.remove_manifest_bytes()
            .map_err(|e| Error::InvalidAsset(e.to_string()))?;

        let mut output_bytes = Vec::new();
        pdf.save_to(&mut output_bytes)?;

        output_stream.rewind()?;
        output_stream.write_all(&output_bytes)?;
        Ok(())
    }
}

impl AssetPatch for PdfIO {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> crate::Result<()> {
        let mut raw = std::fs::read(asset_path)?;

        let existing = self.parse_single_manifest(&raw)?;
        if existing.len() != store_bytes.len() {
            return Err(Error::NotFound);
        }

        patch_bytes(&mut raw, &existing, store_bytes)?;
        std::fs::write(asset_path, &raw)?;
        Ok(())
    }
}

impl AssetIO for PdfIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        Self {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(PdfIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(PdfIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> crate::Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> crate::Result<()> {
        let mut input_stream = File::open(asset_path)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> crate::Result<Vec<HashObjectPositions>> {
        let mut input_stream = File::open(asset_path)?;
        self.get_object_locations_from_stream(&mut input_stream)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> crate::Result<()> {
        let mut input_stream = File::open(asset_path)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.remove_cai_store_from_stream(&mut input_stream, &mut temp_file)?;

        rename_or_move(temp_file, asset_path)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }
}

impl ComposedManifestRef for PdfIO {
    // Return entire CAI block as Vec<u8>
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>, Error> {
        Ok(manifest_data.to_vec())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("invalid file signature: {reason}")]
    InvalidFileSignature { reason: String },
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use crate::{
        asset_handlers,
        asset_handlers::{pdf::MockC2paPdf, pdf_io::PdfIO},
        asset_io::{AssetIO, CAIReader},
    };

    static MANIFEST_BYTES: &[u8; 2] = &[10u8, 20u8];

    #[test]
    fn test_error_reading_manifest_fails() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_manifest_bytes().returning(|| {
            Err(asset_handlers::pdf::Error::UnableToReadPdf(
                lopdf::Error::ReferenceLimit,
            ))
        });

        let pdf_io = PdfIO::new("pdf");
        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::PdfReadError)
        ))
    }

    #[test]
    fn test_no_manifest_found_returns_no_jumbf_error() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_manifest_bytes().returning(|| Ok(None));
        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_one_manifest_found_returns_bytes() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf
            .expect_read_manifest_bytes()
            .returning(|| Ok(Some(vec![MANIFEST_BYTES])));

        let pdf_io = PdfIO::new("pdf");
        assert_eq!(
            pdf_io.read_manifest_bytes(mock_pdf).unwrap(),
            MANIFEST_BYTES.to_vec()
        );
    }

    #[test]
    fn test_multiple_manifest_fail_with_not_implemented_error() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf
            .expect_read_manifest_bytes()
            .returning(|| Ok(Some(vec![MANIFEST_BYTES, MANIFEST_BYTES, MANIFEST_BYTES])));

        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::NotImplemented(_))
        ));
    }

    #[test]
    fn test_returns_none_when_no_xmp() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_xmp().returning(|| None);

        let pdf_io = PdfIO::new("pdf");
        assert_eq!(pdf_io.read_xmp_from_pdf(mock_pdf), None);
    }

    #[test]
    fn test_returns_some_when_some_xmp() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_xmp().returning(|| Some("xmp".into()));

        let pdf_io = PdfIO::new("pdf");
        assert!(pdf_io.read_xmp_from_pdf(mock_pdf).is_some());
    }

    #[test]
    fn test_cai_read_finds_no_manifest() {
        let source = crate::utils::test::fixture_path("basic.pdf");
        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_cai_store(&source),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_cai_read_xmp_finds_xmp_data() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut stream = Cursor::new(source.to_vec());

        let pdf_io = PdfIO::new("pdf");
        assert!(pdf_io.read_xmp(&mut stream).is_some());
    }

    #[test]
    fn test_read_cai_express_pdf_finds_single_manifest_store() {
        let source = include_bytes!("../../tests/fixtures/express-signed.pdf");
        let pdf_io = PdfIO::new("pdf");
        let mut pdf_stream = Cursor::new(source.to_vec());
        assert!(pdf_io.read_cai(&mut pdf_stream).is_ok());
    }

    #[test]
    fn test_pdf_backend_defaults_to_lopdf() {
        assert_eq!(super::pdf_backend(), super::PdfBackend::Lopdf);
    }

    #[cfg(feature = "unstable_pdf_oxide")]
    #[test]
    fn test_set_pdf_backend_switches_backend() {
        crate::settings::set_settings_value("core.pdf_backend", "pdf_oxide").unwrap();
        assert_eq!(super::pdf_backend(), super::PdfBackend::PdfOxide);
    }

    #[cfg(feature = "unstable_pdf_oxide")]
    #[test]
    fn test_pdf_oxide_backend_cai_read_finds_no_manifest() {
        crate::settings::set_settings_value("core.pdf_backend", "pdf_oxide").unwrap();

        let source = crate::utils::test::fixture_path("basic.pdf");
        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_cai_store(&source),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[cfg(feature = "unstable_pdf_oxide")]
    #[test]
    fn test_pdf_oxide_backend_cai_read_xmp_finds_xmp_data() {
        crate::settings::set_settings_value("core.pdf_backend", "pdf_oxide").unwrap();

        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut stream = Cursor::new(source.to_vec());

        let pdf_io = PdfIO::new("pdf");
        assert!(pdf_io.read_xmp(&mut stream).is_some());
    }

    #[cfg(feature = "unstable_pdf_oxide")]
    #[test]
    fn test_pdf_oxide_backend_read_cai_express_pdf_finds_single_manifest_store() {
        crate::settings::set_settings_value("core.pdf_backend", "pdf_oxide").unwrap();

        let source = include_bytes!("../../tests/fixtures/express-signed.pdf");
        let pdf_io = PdfIO::new("pdf");
        let mut pdf_stream = Cursor::new(source.to_vec());
        assert!(pdf_io.read_cai(&mut pdf_stream).is_ok());
    }

    #[test]
    fn test_write_cai_embeds_manifest_into_pdf_without_manifest() {
        use crate::asset_io::CAIWriter;

        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut input_stream = Cursor::new(source.to_vec());
        let mut output_stream = Cursor::new(Vec::new());

        let pdf_io = PdfIO::new("pdf");
        let manifest_bytes = vec![1u8, 2, 3, 4, 5];
        pdf_io
            .write_cai(&mut input_stream, &mut output_stream, &manifest_bytes)
            .unwrap();

        output_stream.rewind().unwrap();
        assert_eq!(pdf_io.read_cai(&mut output_stream).unwrap(), manifest_bytes);
    }

    #[test]
    fn test_write_cai_replaces_same_length_manifest_without_shifting_other_bytes() {
        use crate::asset_io::CAIWriter;

        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut input_stream = Cursor::new(source.to_vec());
        let mut first_pass = Cursor::new(Vec::new());

        let pdf_io = PdfIO::new("pdf");
        let placeholder = vec![0u8; 32];
        pdf_io
            .write_cai(&mut input_stream, &mut first_pass, &placeholder)
            .unwrap();

        // Re-embed a different, but same-length, manifest -- this exercises the
        // "patch in place" fast path that `Store` relies on for hash stability:
        // everything but the manifest bytes themselves must stay byte-identical.
        first_pass.rewind().unwrap();
        let final_bytes: Vec<u8> = (0u8..32).collect();
        let mut second_pass = Cursor::new(Vec::new());
        pdf_io
            .write_cai(&mut first_pass, &mut second_pass, &final_bytes)
            .unwrap();

        let first_bytes = first_pass.into_inner();
        let second_bytes = second_pass.into_inner();

        assert_eq!(first_bytes.len(), second_bytes.len());

        let placeholder_pos = memchr::memmem::find(&first_bytes, &placeholder).unwrap();
        let mut expected = first_bytes.clone();
        expected[placeholder_pos..placeholder_pos + final_bytes.len()]
            .copy_from_slice(&final_bytes);
        assert_eq!(expected, second_bytes);

        let mut second_stream = Cursor::new(second_bytes);
        assert_eq!(pdf_io.read_cai(&mut second_stream).unwrap(), final_bytes);
    }

    #[test]
    fn test_get_object_locations_from_stream_finds_embedded_manifest() {
        use crate::asset_io::{CAIWriter, HashBlockObjectType};

        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut input_stream = Cursor::new(source.to_vec());
        let mut output_stream = Cursor::new(Vec::new());

        let pdf_io = PdfIO::new("pdf");
        let manifest_bytes = vec![9u8, 8, 7, 6, 5];
        pdf_io
            .write_cai(&mut input_stream, &mut output_stream, &manifest_bytes)
            .unwrap();

        output_stream.rewind().unwrap();
        let positions = pdf_io
            .get_object_locations_from_stream(&mut output_stream)
            .unwrap();

        let cai = positions
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Cai)
            .unwrap();
        assert_eq!(cai.length, manifest_bytes.len());

        let bytes = output_stream.into_inner();
        assert_eq!(
            &bytes[cai.offset..cai.offset + cai.length],
            &manifest_bytes[..]
        );
    }

    #[test]
    fn test_get_object_locations_from_stream_without_manifest_returns_placeholder() {
        use crate::asset_io::{CAIWriter, HashBlockObjectType};

        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut input_stream = Cursor::new(source.to_vec());

        let pdf_io = PdfIO::new("pdf");
        let positions = pdf_io
            .get_object_locations_from_stream(&mut input_stream)
            .unwrap();

        assert!(positions
            .iter()
            .any(|p| p.htype == HashBlockObjectType::Cai));
    }

    #[test]
    fn test_remove_cai_store_from_stream_removes_embedded_manifest() {
        use crate::asset_io::CAIWriter;

        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut input_stream = Cursor::new(source.to_vec());
        let mut embedded_stream = Cursor::new(Vec::new());

        let pdf_io = PdfIO::new("pdf");
        pdf_io
            .write_cai(&mut input_stream, &mut embedded_stream, &[1u8, 2, 3])
            .unwrap();

        embedded_stream.rewind().unwrap();
        let mut removed_stream = Cursor::new(Vec::new());
        pdf_io
            .remove_cai_store_from_stream(&mut embedded_stream, &mut removed_stream)
            .unwrap();

        removed_stream.rewind().unwrap();
        assert!(matches!(
            pdf_io.read_cai(&mut removed_stream),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_sign_and_verify_pdf_roundtrip() {
        use crate::{
            utils::test_signer::test_signer, Builder, BuilderIntent, Context, DigitalSourceType,
            Reader, SigningAlg,
        };

        let manifest_def = serde_json::json!({
            "claim_generator_info": [{ "name": "c2pa_test", "version": "1.0.0" }],
            "title": "pdf_write_test",
        })
        .to_string();

        let mut builder = Builder::from_context(Context::default())
            .with_definition(manifest_def)
            .unwrap();
        builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
        let signer = test_signer(SigningAlg::Ps256);

        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut source_stream = Cursor::new(source.to_vec());
        let mut signed_stream = Cursor::new(Vec::new());

        builder
            .sign(
                signer.as_ref(),
                "application/pdf",
                &mut source_stream,
                &mut signed_stream,
            )
            .unwrap();

        signed_stream.rewind().unwrap();
        let manifest_store = Reader::default()
            .with_stream("application/pdf", &mut signed_stream)
            .unwrap();

        println!("{manifest_store}");
        assert_ne!(
            manifest_store.validation_state(),
            crate::ValidationState::Invalid
        );
        assert!(manifest_store.active_manifest().is_some());
    }
}
