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

use crate::{
    asset_handlers::pdf::{C2paPdf, Pdf},
    asset_io::{
        AssetIO, C2paReader, C2paWriter, ComposedManifestRef, ObjectLocations, ObjectType,
        ReadSeek, ReadWriteSeek, RemoteManifestUrl, WriteXmp,
    },
    Error::{self, JumbfNotFound, NotImplemented, PdfReadError},
};

static SUPPORTED_TYPES: [&str; 2] = ["pdf", "application/pdf"];

/// Finds where a stream object's raw content begins, given the byte offset of its
/// `N G obj` declaration. Scans forward for the `stream` keyword and skips the EOL
/// marker that must immediately follow it (PDF spec §7.3.8.1: CRLF or bare LF).
///
/// The scan is bounded to `MAX_DICT_SCAN` bytes so a missing/corrupt `stream`
/// keyword can't turn this into an unbounded scan of the rest of the file. The
/// real defense against locking onto a `stream` substring inside unrelated
/// dict content (e.g. a crafted string value) is the content-equality check
/// the caller performs on the result, not this bound.
fn find_stream_content_start(bytes: &[u8], header_offset: usize) -> Option<usize> {
    const NEEDLE: &[u8] = b"stream";
    const MAX_DICT_SCAN: usize = 8192;

    let end = header_offset.saturating_add(MAX_DICT_SCAN).min(bytes.len());
    let search_region = bytes.get(header_offset..end)?;
    let rel = search_region
        .windows(NEEDLE.len())
        .position(|w| w == NEEDLE)?;
    let after_keyword = header_offset + rel + NEEDLE.len();

    match bytes.get(after_keyword..after_keyword + 2) {
        Some(b"\r\n") => Some(after_keyword + 2),
        _ => match bytes.get(after_keyword) {
            Some(b'\n') => Some(after_keyword + 1),
            _ => None,
        },
    }
}

/// Locates the raw byte range `(content_start, content_len)` of the C2PA manifest
/// already embedded in `bytes`, by re-parsing `bytes` and following its xref
/// table to the manifest stream's declaration.
///
/// Returns `Ok(None)` only when no manifest is present at all. Returns `Err`
/// if a manifest is present but its byte range can't be safely determined
/// this way (a compressed xref entry with no outer-file offset, or the
/// located bytes don't actually match the manifest's own content) — callers
/// must not treat that as "no manifest", since a manifest genuinely exists.
fn locate_manifest_content(bytes: &[u8]) -> crate::Result<Option<(u64, u64)>> {
    let pdf = Pdf::from_bytes(bytes).map_err(|e| Error::InvalidAsset(e.to_string()))?;

    let header_offset = match pdf.manifest_object_offset() {
        Ok(Some(offset)) => offset,
        Ok(None) => return Ok(None),
        Err(e) => return Err(unlocatable_manifest_error_from(e)),
    };

    let manifest_bytes = pdf
        .read_manifest_bytes()
        .map_err(unlocatable_manifest_error_from)?
        .ok_or_else(unlocatable_manifest_error)?;
    let [manifest_bytes] = manifest_bytes.as_slice() else {
        return Err(unlocatable_manifest_error());
    };

    let content_start = find_stream_content_start(bytes, header_offset as usize)
        .ok_or_else(unlocatable_manifest_error)?;
    let content_end = content_start
        .checked_add(manifest_bytes.len())
        .ok_or_else(unlocatable_manifest_error)?;

    // Verify the located range actually holds the manifest's own bytes before
    // trusting it, rather than any `stream` keyword occurrence the (possibly
    // externally-authored) dict happens to contain.
    if bytes.get(content_start..content_end) != Some(*manifest_bytes) {
        return Err(unlocatable_manifest_error());
    }

    Ok(Some((content_start as u64, manifest_bytes.len() as u64)))
}

fn unlocatable_manifest_error() -> Error {
    NotImplemented("PDF manifest is present but its byte range can't be located".into())
}

/// Same as [`unlocatable_manifest_error`], but preserves the underlying
/// `pdf::Error` (e.g. `ManifestObjectNotByteAddressable`) in the message
/// instead of discarding it, matching the `InvalidAsset` handling above.
fn unlocatable_manifest_error_from(cause: crate::asset_handlers::pdf::Error) -> Error {
    NotImplemented(format!(
        "PDF manifest is present but its byte range can't be located: {cause}"
    ))
}

pub struct PdfIO {}

impl C2paReader for PdfIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> crate::Result<Vec<u8>> {
        input_stream.rewind()?;

        let pdf = Pdf::from_reader(input_stream).map_err(|e| Error::InvalidAsset(e.to_string()))?;
        self.read_manifest_bytes(pdf)
    }

    fn read_xmp(&self, input_stream: &mut dyn ReadSeek) -> Option<String> {
        if input_stream.rewind().is_err() {
            return None;
        }

        let Ok(pdf) = Pdf::from_reader(input_stream) else {
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
}

impl C2paWriter for PdfIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> crate::Result<()> {
        input_stream.rewind()?;
        let mut bytes = Vec::new();
        input_stream.read_to_end(&mut bytes)?;

        // Fast path: the sign pipeline writes a placeholder manifest, then rewrites
        // it with the final, same-length manifest once the real hash is known. A
        // full rewrite would re-run the object graph through lopdf a second time,
        // which isn't guaranteed to reproduce the same byte layout (object ids
        // depend on prior edit history), shifting the manifest out from under the
        // hash exclusion already computed against the first write. Same-length
        // in-place substitution keeps that offset stable across both passes.
        //
        // If the existing manifest's byte range can't be safely determined (see
        // `locate_manifest_content`), fall through to the full-rewrite path below
        // instead of guessing — it's always correct, just not offset-stable.
        if let Ok(Some((content_start, content_len))) = locate_manifest_content(&bytes) {
            if content_len == store_bytes.len() as u64 {
                let start = content_start as usize;
                let end = start + store_bytes.len();
                output_stream.rewind()?;
                output_stream.write_all(&bytes[..start])?;
                output_stream.write_all(store_bytes)?;
                output_stream.write_all(&bytes[end..])?;
                return Ok(());
            }
        }

        let mut pdf = Pdf::from_bytes(&bytes).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        if pdf.has_c2pa_manifest() {
            pdf.remove_manifest_bytes()
                .map_err(|_| Error::EmbeddingError)?;
        }

        pdf.write_manifest_as_embedded_file(store_bytes.to_vec())
            .map_err(|_| Error::EmbeddingError)?;

        let mut out_bytes = Vec::new();
        pdf.save_to(&mut out_bytes).map_err(Error::IoError)?;
        output_stream.rewind()?;
        output_stream.write_all(&out_bytes)?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> crate::Result<Vec<ObjectLocations>> {
        input_stream.rewind()?;
        let mut bytes = Vec::new();
        input_stream.read_to_end(&mut bytes)?;
        let file_len = bytes.len() as u64;

        let Some((content_start, manifest_len)) = locate_manifest_content(&bytes)? else {
            // No manifest embedded yet: report a placeholder at the end of the file,
            // since a full rewrite always appends the new stream object last.
            return Ok(vec![
                ObjectLocations {
                    offset: 0,
                    length: file_len,
                    htype: ObjectType::Other,
                },
                ObjectLocations {
                    offset: file_len,
                    length: 1,
                    htype: ObjectType::C2pa,
                },
            ]);
        };

        let content_end = content_start + manifest_len;

        Ok(vec![
            ObjectLocations {
                offset: 0,
                length: content_start,
                htype: ObjectType::Other,
            },
            ObjectLocations {
                offset: content_start,
                length: manifest_len,
                htype: ObjectType::C2pa,
            },
            ObjectLocations {
                offset: content_end,
                length: file_len.saturating_sub(content_end),
                htype: ObjectType::Other,
            },
        ])
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> crate::Result<()> {
        input_stream.rewind()?;
        let mut pdf =
            Pdf::from_reader(input_stream).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        // A no-op, not an error, when there's nothing to remove: the remote/
        // sidecar save path always calls this first regardless of whether a
        // manifest is actually present, exactly as `write_c2pa` above already
        // guards its own call to `remove_manifest_bytes`.
        if pdf.has_c2pa_manifest() {
            pdf.remove_manifest_bytes()
                .map_err(|_| Error::EmbeddingError)?;
        }

        let mut bytes = Vec::new();
        pdf.save_to(&mut bytes).map_err(Error::IoError)?;
        output_stream.rewind()?;
        output_stream.write_all(&bytes)?;
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

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, _asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(PdfIO {}))
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }

    fn remote_manifest_url_ref(&self) -> Option<&dyn RemoteManifestUrl> {
        Some(self)
    }

    fn write_xmp_ref(&self) -> Option<&dyn WriteXmp> {
        Some(self)
    }
}

impl ComposedManifestRef for PdfIO {
    // Return entire CAI block as Vec<u8>
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>, Error> {
        Ok(manifest_data.to_vec())
    }
}

impl WriteXmp for PdfIO {
    fn write_xmp(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        xmp: &str,
    ) -> crate::Result<()> {
        input_stream.rewind()?;
        let mut bytes = Vec::new();
        input_stream.read_to_end(&mut bytes)?;

        let mut pdf = Pdf::from_bytes(&bytes).map_err(|e| Error::InvalidAsset(e.to_string()))?;
        pdf.write_xmp(xmp.to_string())
            .map_err(|_| Error::EmbeddingError)?;

        let mut out_bytes = Vec::new();
        pdf.save_to(&mut out_bytes).map_err(Error::IoError)?;
        output_stream.rewind()?;
        output_stream.write_all(&out_bytes)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::{find_stream_content_start, locate_manifest_content};
    use crate::{
        asset_handlers,
        asset_handlers::{pdf::MockC2paPdf, pdf_io::PdfIO},
        asset_io::{AssetIO, C2paReader},
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
    fn test_get_object_locations_matches_manifest_bytes() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let manifest_bytes = vec![10u8, 20u8, 30u8, 40u8, 50u8];
        let pdf_io = PdfIO::new("pdf");
        let writer = pdf_io.get_writer("pdf").unwrap();
        let mut input = Cursor::new(source.to_vec());
        let mut output = Cursor::new(Vec::new());
        writer
            .write_c2pa(&mut input, &mut output, &manifest_bytes)
            .unwrap();

        output.set_position(0);
        let locations = writer.get_object_locations(&mut output).unwrap();
        let c2pa_loc = locations
            .iter()
            .find(|l| l.htype == crate::asset_io::ObjectType::C2pa)
            .unwrap();

        let out_bytes = output.into_inner();
        let found =
            &out_bytes[c2pa_loc.offset as usize..(c2pa_loc.offset + c2pa_loc.length) as usize];
        assert_eq!(found, manifest_bytes.as_slice());
    }

    // `find_stream_content_start` trusts the first `stream` keyword it finds; a
    // dict value containing that literal text followed by an EOL is a decoy. The
    // scan must stay bounded rather than searching the rest of the file.
    #[test]
    fn test_find_stream_content_start_is_bounded() {
        let mut bytes = vec![b'x'; 10_000];
        // Place a real `stream\n` occurrence far past any reasonable dict size.
        bytes.extend_from_slice(b"stream\n");
        assert_eq!(find_stream_content_start(&bytes, 0), None);
    }

    #[test]
    fn test_find_stream_content_start_finds_first_match_within_bound() {
        let mut bytes = b"<< /Length 3 >>".to_vec();
        bytes.extend_from_slice(b"stream\n");
        bytes.extend_from_slice(b"abc");
        bytes.extend_from_slice(b"\nendstream");

        let start = find_stream_content_start(&bytes, 0).unwrap();
        assert_eq!(&bytes[start..start + 3], b"abc");
    }

    // A decoy `stream\n` occurrence inside the dict (e.g. an externally-crafted
    // PDF's string value) must not be trusted: the content-equality check should
    // reject it rather than returning a wrong-but-plausible byte range. Built by
    // hand via lopdf directly (rather than mutating a signed fixture's bytes) so
    // the rest of the file's structure/xref stays valid and the test doesn't
    // depend on byte-splicing arithmetic.
    #[test]
    fn test_locate_manifest_content_rejects_decoy_stream_keyword() {
        use lopdf::{dictionary, Document, Object, Stream};

        let manifest = vec![10u8, 20u8, 30u8, 40u8, 50u8];

        let mut doc = Document::with_version("1.7");

        let mut stream_dict = dictionary! {
            "F" => dictionary! {
                "Subtype" => Object::Name(b"application/x-c2pa-manifest-store".to_vec()),
                "Length" => Object::Integer(manifest.len() as i64),
            },
        };
        // `\r` gets escaped by lopdf's writer, but bare `\n` is written verbatim,
        // so this decoy survives as a real `stream` + LF sequence in the output.
        stream_dict.set("Decoy", Object::string_literal("noise stream\nmore noise"));
        let stream_id = doc.add_object(Stream::new(stream_dict, manifest.clone()));

        let file_spec_id = doc.add_object(dictionary! {
            "AFRelationship" => Object::Name(b"C2PA_Manifest".to_vec()),
            "Type" => Object::Name(b"FileSpec".to_vec()),
            "EF" => dictionary! { "F" => Object::Reference(stream_id) },
        });

        let catalog_id = doc.add_object(dictionary! {
            "Type" => Object::Name(b"Catalog".to_vec()),
            "AF" => Object::Array(vec![Object::Reference(file_spec_id)]),
        });
        doc.trailer.set("Root", Object::Reference(catalog_id));

        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();

        assert!(
            locate_manifest_content(&bytes).is_err(),
            "a decoy `stream` keyword inside the dict must not be trusted"
        );
    }

    // A truncated/corrupted file must never panic on an out-of-bounds slice,
    // regardless of what `find_stream_content_start` thinks it found.
    #[test]
    fn test_get_object_locations_truncated_pdf_does_not_panic() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let manifest_bytes = vec![10u8, 20u8, 30u8, 40u8, 50u8];
        let pdf_io = PdfIO::new("pdf");
        let writer = pdf_io.get_writer("pdf").unwrap();
        let mut input = Cursor::new(source.to_vec());
        let mut output = Cursor::new(Vec::new());
        writer
            .write_c2pa(&mut input, &mut output, &manifest_bytes)
            .unwrap();

        let mut truncated = output.into_inner();
        truncated.truncate(truncated.len() / 2);

        let mut stream = Cursor::new(truncated);
        // Must return an error, never panic.
        let _ = writer.get_object_locations(&mut stream);
    }

    // Regression test: the sign pipeline writes a placeholder manifest, computes
    // hash exclusions from its byte position, then rewrites the manifest in place
    // with a same-length, final manifest. The second write must land at the exact
    // same offset as the first, or the previously-computed exclusion is wrong.
    #[test]
    fn test_write_c2pa_same_length_rewrite_preserves_offset() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let placeholder = vec![0u8; 5];
        let pdf_io = PdfIO::new("pdf");
        let writer = pdf_io.get_writer("pdf").unwrap();

        let mut input = Cursor::new(source.to_vec());
        let mut first_pass = Cursor::new(Vec::new());
        writer
            .write_c2pa(&mut input, &mut first_pass, &placeholder)
            .unwrap();

        first_pass.set_position(0);
        let locations_before = writer.get_object_locations(&mut first_pass).unwrap();
        let c2pa_before = locations_before
            .iter()
            .find(|l| l.htype == crate::asset_io::ObjectType::C2pa)
            .unwrap()
            .clone();

        let final_manifest = vec![10u8, 20u8, 30u8, 40u8, 50u8];
        first_pass.set_position(0);
        let mut second_pass = Cursor::new(Vec::new());
        writer
            .write_c2pa(&mut first_pass, &mut second_pass, &final_manifest)
            .unwrap();

        second_pass.set_position(0);
        let locations_after = writer.get_object_locations(&mut second_pass).unwrap();
        let c2pa_after = locations_after
            .iter()
            .find(|l| l.htype == crate::asset_io::ObjectType::C2pa)
            .unwrap();

        assert_eq!(c2pa_after.offset, c2pa_before.offset);
        assert_eq!(c2pa_after.length, c2pa_before.length);

        let out_bytes = second_pass.into_inner();
        let found = &out_bytes
            [c2pa_after.offset as usize..(c2pa_after.offset + c2pa_after.length) as usize];
        assert_eq!(found, final_manifest.as_slice());
    }

    #[test]
    fn test_cai_read_finds_no_manifest() {
        let source = crate::utils::test::fixture_path("basic.pdf");
        let pdf_io = PdfIO::new("pdf");
        let mut f = std::fs::File::open(&source).unwrap();

        assert!(matches!(
            pdf_io.read_c2pa(&mut f),
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
    fn test_write_read_and_remove_manifest() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let manifest_bytes = vec![10u8, 20u8, 30u8];
        let pdf_io = PdfIO::new("pdf");
        let writer = pdf_io.get_writer("pdf").unwrap();
        let mut input = Cursor::new(source.to_vec());
        let mut output = Cursor::new(Vec::new());

        writer
            .write_c2pa(&mut input, &mut output, &manifest_bytes)
            .unwrap();

        output.set_position(0);
        assert_eq!(pdf_io.read_c2pa(&mut output).unwrap(), manifest_bytes);

        output.set_position(0);
        let mut removed = Cursor::new(Vec::new());
        writer.remove_c2pa(&mut output, &mut removed).unwrap();

        removed.set_position(0);
        assert!(matches!(
            pdf_io.read_c2pa(&mut removed),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    // `remove_c2pa` must no-op on a PDF with no manifest, not error: the
    // remote/sidecar save path in `Store::start_save_stream` always calls it
    // first regardless of whether a manifest is actually present.
    #[test]
    fn test_remove_c2pa_on_pdf_without_manifest_is_a_no_op() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let pdf_io = PdfIO::new("pdf");
        let writer = pdf_io.get_writer("pdf").unwrap();
        let mut input = Cursor::new(source.to_vec());
        let mut output = Cursor::new(Vec::new());

        writer.remove_c2pa(&mut input, &mut output).unwrap();

        output.set_position(0);
        assert!(matches!(
            pdf_io.read_c2pa(&mut output),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_read_cai_express_pdf_finds_single_manifest_store() {
        let source = include_bytes!("../../tests/fixtures/express-signed.pdf");
        let pdf_io = PdfIO::new("pdf");
        let mut pdf_stream = Cursor::new(source.to_vec());
        assert!(pdf_io.read_c2pa(&mut pdf_stream).is_ok());
    }

    #[test]
    fn test_write_remote_manifest_url_with_no_existing_xmp() {
        let source = include_bytes!("../../tests/fixtures/basic-no-xmp.pdf");
        let test_url = "https://example.com/manifest.c2pa";

        let pdf_io = PdfIO::new("pdf");
        let remote_ref_handler = pdf_io.remote_manifest_url_ref().unwrap();

        let mut input = Cursor::new(source.to_vec());
        let mut output = Cursor::new(Vec::new());
        remote_ref_handler
            .write_remote_manifest_url(&mut input, &mut output, test_url)
            .unwrap();

        output.set_position(0);
        let read_xmp = pdf_io.read_xmp(&mut output).unwrap();
        assert!(read_xmp.contains(test_url));

        output.set_position(0);
        assert_eq!(
            remote_ref_handler.read_manifest_url(&mut output),
            Some(test_url.to_string())
        );
    }

    #[test]
    fn test_write_remote_manifest_url_preserves_existing_xmp() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let test_url = "https://example.com/manifest.c2pa";

        let pdf_io = PdfIO::new("pdf");
        let mut input = Cursor::new(source.to_vec());
        let existing_xmp = pdf_io.read_xmp(&mut input).unwrap();
        // Sanity check on the fixture itself: the merge logic only adds a new
        // `rdf:Description` attribute and passes every other event through
        // unchanged, so an existing *child element* is the right thing to
        // assert survives (a byte-for-byte whole-packet comparison wouldn't,
        // since the `rdf:Description` tag itself gains a new attribute).
        assert!(existing_xmp.contains("<xmp:CreatorTool>"));
        input.set_position(0);

        let remote_ref_handler = pdf_io.remote_manifest_url_ref().unwrap();
        let mut output = Cursor::new(Vec::new());
        remote_ref_handler
            .write_remote_manifest_url(&mut input, &mut output, test_url)
            .unwrap();

        output.set_position(0);
        let read_xmp = pdf_io.read_xmp(&mut output).unwrap();
        assert!(read_xmp.contains(test_url));
        // The rest of the pre-existing XMP packet must survive the merge, not
        // just get clobbered by a fresh minimal packet.
        assert!(read_xmp.contains("<xmp:CreatorTool>Acrobat Pro 23.1.20143</xmp:CreatorTool>"));
    }

    #[test]
    fn test_read_manifest_url_none_when_absent() {
        let source = include_bytes!("../../tests/fixtures/basic-no-xmp.pdf");
        let pdf_io = PdfIO::new("pdf");
        let remote_ref_handler = pdf_io.remote_manifest_url_ref().unwrap();

        let mut input = Cursor::new(source.to_vec());
        assert_eq!(remote_ref_handler.read_manifest_url(&mut input), None);
    }
}
