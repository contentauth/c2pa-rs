// Copyright 2024 Encypher Corporation. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! C2PA HTML asset handler.
//!
//! Embeds and extracts C2PA manifests in HTML documents per C2PA 2.4 Appendix
//! A.7, using the `c2pa-text` crate. The Manifest Store (JUMBF) is Base64-encoded
//! into a `<script type="application/c2pa">` element placed in the document
//! `<head>`. External `<link rel="c2pa-manifest">` references are recognized on
//! read but are treated as an external (non-embedded) store.

use std::{fs::File, path::Path};

use c2pa_text::html::{embed_html_inline, extract_html, HtmlMethod};

use crate::{
    asset_io::{
        rename_or_move, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashBlockObjectType,
        HashObjectPositions,
    },
    error::{Error, Result},
    utils::io_utils::tempfile_builder,
};

static SUPPORTED_TYPES: [&str; 3] = ["html", "htm", "text/html"];

const SCRIPT_TYPE: &str = "type=\"application/c2pa\"";
const SCRIPT_CLOSE: &str = "</script>";

pub struct HtmlIO {}

/// Read the entire stream as a UTF-8 string.
fn stream_to_string(reader: &mut dyn CAIRead) -> Result<String> {
    reader.rewind()?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    String::from_utf8(buf)
        .map_err(|_| Error::InvalidAsset("HTML asset is not valid UTF-8".to_string()))
}

/// Byte span `(offset, length)` of the inline
/// `<script type="application/c2pa">…</script>` element, if present.
fn find_script_span(html: &str) -> Option<(usize, usize)> {
    let mut pos = 0;
    while let Some(rel_i) = html[pos..].find("<script") {
        let i = pos + rel_i;
        let gt = i + html[i..].find('>')?;
        let tag = &html[i..=gt];
        if tag.contains(SCRIPT_TYPE) {
            if let Some(rel_end) = html[gt + 1..].find(SCRIPT_CLOSE) {
                let end = gt + 1 + rel_end + SCRIPT_CLOSE.len();
                return Some((i, end - i));
            }
        }
        pos = gt + 1;
    }
    None
}

/// Return `html` with the inline C2PA `<script>` element removed (and one
/// immediately-following line terminator, if present).
fn strip_manifest_script(html: &str) -> String {
    match find_script_span(html) {
        Some((offset, length)) => {
            let mut end = offset + length;
            if html[end..].starts_with("\r\n") {
                end += 2;
            } else if html[end..].starts_with('\n') {
                end += 1;
            }
            let mut out = String::with_capacity(html.len() - (end - offset));
            out.push_str(&html[..offset]);
            out.push_str(&html[end..]);
            out
        }
        None => html.to_string(),
    }
}

impl CAIReader for HtmlIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let text = stream_to_string(reader)?;

        let extraction = extract_html(&text)
            .map_err(|e| Error::InvalidAsset(format!("HTML manifest extraction failed: {e}")))?;

        match extraction {
            Some(x) if x.method == HtmlMethod::Inline => x.manifest.ok_or(Error::JumbfNotFound),
            // No association, or an external <link> reference (not an embedded store).
            _ => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, _reader: &mut dyn CAIRead) -> Option<String> {
        // HTML manifests are carried in a <script>/<link> element, not XMP.
        None
    }
}

impl CAIWriter for HtmlIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let text = stream_to_string(input_stream)?;

        // Remove any existing inline manifest so writes are idempotent.
        let clean = strip_manifest_script(&text);

        let embed =
            embed_html_inline(&clean, store_bytes, "\n").map_err(|_| Error::EmbeddingError)?;

        output_stream.rewind()?;
        output_stream.write_all(embed.html.as_bytes())?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let text = stream_to_string(input_stream)?;

        let (offset, length) = find_script_span(&text).ok_or(Error::JumbfNotFound)?;
        let total = text.len();

        let mut positions = Vec::new();

        // Content before the manifest element.
        positions.push(HashObjectPositions {
            offset: 0,
            length: offset,
            htype: HashBlockObjectType::Other,
        });

        // The <script type="application/c2pa"> element (spec A.7.1.3 exclusion).
        positions.push(HashObjectPositions {
            offset,
            length,
            htype: HashBlockObjectType::Cai,
        });

        // Content after the manifest element.
        let end = offset + length;
        if end < total {
            positions.push(HashObjectPositions {
                offset: end,
                length: total - end,
                htype: HashBlockObjectType::Other,
            });
        }

        Ok(positions)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let text = stream_to_string(input_stream)?;
        let clean = strip_manifest_script(&text);

        output_stream.rewind()?;
        output_stream.write_all(clean.as_bytes())?;
        Ok(())
    }
}

impl AssetIO for HtmlIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        HtmlIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(HtmlIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(HtmlIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = File::open(asset_path).map_err(Error::IoError)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;
        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;
        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut input_stream = File::open(asset_path).map_err(|_| Error::EmbeddingError)?;
        self.get_object_locations_from_stream(&mut input_stream)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut input_file = File::open(asset_path)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;
        self.remove_cai_store_from_stream(&mut input_file, &mut temp_file)?;
        rename_or_move(temp_file, asset_path)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

#[cfg(test)]
#[cfg(feature = "file_io")]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    const HTML: &str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Example</title>\n</head>\n<body>\n<p>Hello.</p>\n</body>\n</html>\n";

    #[test]
    fn html_io_roundtrip() {
        let jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b'];
        let html_io = HtmlIO::new("html");

        let mut input = Cursor::new(HTML.as_bytes().to_vec());
        let mut output = Cursor::new(Vec::new());
        html_io
            .write_cai(&mut input, &mut output, &jumbf)
            .expect("write_cai");

        output.set_position(0);
        let extracted = html_io.read_cai(&mut output).expect("read_cai");
        assert_eq!(extracted, jumbf);
    }

    #[test]
    fn html_io_replace_then_remove() {
        let jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b'];
        let html_io = HtmlIO::new("html");

        let mut input = Cursor::new(HTML.as_bytes().to_vec());
        let mut signed = Cursor::new(Vec::new());
        html_io
            .write_cai(&mut input, &mut signed, &jumbf)
            .expect("write");

        // Replace the existing manifest (must remain a single element).
        let new_jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b', 0xAA];
        signed.set_position(0);
        let mut signed2 = Cursor::new(Vec::new());
        html_io
            .write_cai(&mut signed, &mut signed2, &new_jumbf)
            .expect("rewrite");

        signed2.set_position(0);
        assert_eq!(html_io.read_cai(&mut signed2).expect("read"), new_jumbf);

        // Remove restores clean HTML with no C2PA element.
        signed2.set_position(0);
        let mut cleaned = Cursor::new(Vec::new());
        html_io
            .remove_cai_store_from_stream(&mut signed2, &mut cleaned)
            .expect("remove");
        let clean = String::from_utf8(cleaned.into_inner()).unwrap();
        assert_eq!(clean.matches("application/c2pa").count(), 0);
    }

    #[test]
    fn html_io_object_locations() {
        let jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b'];
        let html_io = HtmlIO::new("html");

        let mut input = Cursor::new(HTML.as_bytes().to_vec());
        let mut signed = Cursor::new(Vec::new());
        html_io
            .write_cai(&mut input, &mut signed, &jumbf)
            .expect("write");
        let total = signed.get_ref().len();

        signed.set_position(0);
        let positions = html_io
            .get_object_locations_from_stream(&mut signed)
            .expect("locations");

        assert!(positions.len() >= 2);
        let cai = positions
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Cai)
            .expect("CAI block");
        assert!(cai.length > 0);

        let covered: usize = positions.iter().map(|p| p.length).sum();
        assert_eq!(covered, total);
    }

    #[test]
    fn html_io_no_manifest() {
        let html_io = HtmlIO::new("html");
        let mut reader = Cursor::new(HTML.as_bytes().to_vec());
        assert!(matches!(
            html_io.read_cai(&mut reader).unwrap_err(),
            Error::JumbfNotFound
        ));
    }
}
