// Copyright 2024 Encypher Corporation. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license,
// at your option.

//! C2PA structured-text asset handler.
//!
//! Embeds and extracts C2PA manifests in structured text formats (Markdown,
//! YAML, TOML, and similar comment-bearing formats) per C2PA 2.4 Appendix A.9,
//! using the [`c2pa-text`](https://crates.io/crates/c2pa-text) crate. The
//! Manifest Store is carried as a `data:application/c2pa;base64,...` reference
//! inside an ASCII-armour block
//! (`-----BEGIN C2PA MANIFEST----- ... -----END C2PA MANIFEST-----`) placed in a
//! host-format comment.
//!
//! XML media types (`text/xml`, `application/xml`, `application/xhtml+xml`) are
//! intentionally not claimed here pending resolution of the `SvgIO` handler
//! boundary; `image/svg+xml` is handled by `SvgIO` (Appendix A.3.3).
//!
//! This handler is gated behind the non-default `structured_text` feature and
//! is maintained by EncypherAI. Please report issues at
//! <https://github.com/encypherai/c2pa-text/issues>.

use std::{fs::File, path::Path};

use c2pa_text::structured::{
    build_manifest_block, embed_structured, encode_data_uri, extract_structured, Placement,
    BEGIN_DELIMITER, END_DELIMITER,
};

use crate::{
    asset_io::{
        rename_or_move, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashBlockObjectType,
        HashObjectPositions,
    },
    error::{Error, Result},
    utils::io_utils::{stream_len, tempfile_builder, ReaderUtils},
};

static SUPPORTED_TYPES: [&str; 8] = [
    "md",
    "markdown",
    "text/markdown",
    "yaml",
    "yml",
    "application/yaml",
    "text/yaml",
    "toml",
];

pub struct StructuredTextIO {
    asset_type: String,
}

/// Host-format comment delimiters `(prefix, suffix)` for the manifest block.
fn comment_style(asset_type: &str) -> (&'static str, &'static str) {
    match asset_type {
        // Markdown uses HTML comment syntax.
        "md" | "markdown" | "text/markdown" => ("<!--", "-->"),
        // YAML, TOML, INI and similar use a hash line comment.
        _ => ("#", ""),
    }
}

/// Read the entire stream as a UTF-8 string, bounding the allocation by the
/// stream length so an oversized asset fails cleanly instead of aborting.
fn stream_to_string(mut reader: &mut dyn CAIRead) -> Result<String> {
    reader.rewind()?;
    let len = stream_len(reader)?;
    let buf = reader.read_to_vec(len)?;
    String::from_utf8(buf)
        .map_err(|_| Error::InvalidAsset("structured text asset is not valid UTF-8".to_string()))
}

/// Byte span `(offset, length)` of the manifest block, the comment line that
/// contains the delimiters, including its trailing line terminator.
fn find_block_span(text: &str) -> Option<(usize, usize)> {
    let begin = text.find(BEGIN_DELIMITER)?;
    let end_delim = text.find(END_DELIMITER)?;
    if end_delim < begin {
        return None;
    }
    let line_start = text[..begin].rfind('\n').map(|n| n + 1).unwrap_or(0);
    let end_delim_end = end_delim + END_DELIMITER.len();
    let line_end = match text[end_delim_end..].find('\n') {
        Some(n) => end_delim_end + n + 1, // include the terminator
        None => text.len(),
    };
    Some((line_start, line_end - line_start))
}

/// Return `text` with the manifest block line removed, if present.
fn strip_block(text: &str) -> String {
    match find_block_span(text) {
        Some((offset, length)) => {
            let mut out = String::with_capacity(text.len() - length);
            out.push_str(&text[..offset]);
            out.push_str(&text[offset + length..]);
            out
        }
        None => text.to_string(),
    }
}

impl CAIReader for StructuredTextIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let text = stream_to_string(reader)?;

        match extract_structured(&text) {
            // A `data:` URI yields the embedded store; a URL reference does not.
            Ok(extraction) => extraction.manifest.ok_or(Error::JumbfNotFound),
            Err(c2pa_text::structured::StructuredError::NoManifest) => Err(Error::JumbfNotFound),
            Err(e) => Err(Error::InvalidAsset(format!(
                "structured text manifest extraction failed: {e}"
            ))),
        }
    }

    fn read_xmp(&self, _reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl CAIWriter for StructuredTextIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let text = stream_to_string(input_stream)?;

        let (prefix, suffix) = comment_style(&self.asset_type);
        let reference = encode_data_uri(store_bytes);

        let signed = match find_block_span(&text) {
            // An existing block line is replaced in place so the manifest
            // keeps its original position; update manifests require this. The
            // found span includes the trailing line terminator, which is
            // preserved as-is.
            Some((offset, length)) => {
                let block = build_manifest_block(&reference, prefix, suffix);
                let old = &text[offset..offset + length];
                let terminator = if old.ends_with("\r\n") {
                    "\r\n"
                } else if old.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                let mut out =
                    String::with_capacity(text.len() - length + block.len() + terminator.len());
                out.push_str(&text[..offset]);
                out.push_str(&block);
                out.push_str(terminator);
                out.push_str(&text[offset + length..]);
                out
            }
            // No existing manifest: insert at the start of the document
            // (spec A.9.3.1 single-line comment form).
            None => {
                embed_structured(&text, &reference, prefix, suffix, Placement::Start, "\n").text
            }
        };

        output_stream.rewind()?;
        output_stream.write_all(signed.as_bytes())?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let text = stream_to_string(input_stream)?;

        let (offset, length) = find_block_span(&text).ok_or(Error::JumbfNotFound)?;
        let total = text.len();

        let mut positions = Vec::new();

        positions.push(HashObjectPositions {
            offset: 0,
            length: offset,
            htype: HashBlockObjectType::Other,
        });

        // The manifest block (spec A.9.4 exclusion range).
        positions.push(HashObjectPositions {
            offset,
            length,
            htype: HashBlockObjectType::Cai,
        });

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
        let clean = strip_block(&text);

        output_stream.rewind()?;
        output_stream.write_all(clean.as_bytes())?;
        Ok(())
    }
}

impl AssetIO for StructuredTextIO {
    fn new(asset_type: &str) -> Self
    where
        Self: Sized,
    {
        StructuredTextIO {
            asset_type: asset_type.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(StructuredTextIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(StructuredTextIO::new(asset_type)))
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

    #[test]
    fn structured_markdown_roundtrip() {
        let jumbf: Vec<u8> = vec![0, 0, 0, 8, b'j', b'u', b'm', b'b'];
        let io = StructuredTextIO::new("text/markdown");

        let mut input = Cursor::new(b"# Title\n\nBody text.\n".to_vec());
        let mut output = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut output, &jumbf)
            .expect("write");

        output.set_position(0);
        let extracted = io.read_cai(&mut output).expect("read");
        assert_eq!(extracted, jumbf);

        // Markdown uses an HTML comment.
        let signed = String::from_utf8(output.into_inner()).unwrap();
        assert!(signed.contains("<!-- -----BEGIN C2PA MANIFEST-----"));
    }

    #[test]
    fn structured_yaml_uses_hash_comment() {
        let jumbf: Vec<u8> = vec![1, 2, 3, 4];
        let io = StructuredTextIO::new("yaml");

        let mut input = Cursor::new(b"key: value\n".to_vec());
        let mut output = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut output, &jumbf)
            .expect("write");
        let signed = String::from_utf8(output.into_inner()).unwrap();
        assert!(signed.starts_with("# -----BEGIN C2PA MANIFEST-----"));
    }

    #[test]
    fn structured_replace_then_remove() {
        let io = StructuredTextIO::new("text/markdown");
        let original = b"# Doc\n".to_vec();

        let mut input = Cursor::new(original.clone());
        let mut signed = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut signed, &[0xde, 0xad])
            .expect("write");

        // Replace.
        signed.set_position(0);
        let mut signed2 = Cursor::new(Vec::new());
        io.write_cai(&mut signed, &mut signed2, &[0xbe, 0xef])
            .expect("rewrite");
        signed2.set_position(0);
        assert_eq!(io.read_cai(&mut signed2).expect("read"), vec![0xbe, 0xef]);

        // Remove restores the original document.
        signed2.set_position(0);
        let mut cleaned = Cursor::new(Vec::new());
        io.remove_cai_store_from_stream(&mut signed2, &mut cleaned)
            .expect("remove");
        assert_eq!(cleaned.into_inner(), original);
    }

    /// Replacing a manifest keeps the block at its original position, even
    /// when the block is not on the first line, as required for update
    /// manifests.
    #[test]
    fn structured_write_preserves_block_position() {
        let io = StructuredTextIO::new("text/markdown");

        // Hand-place the block mid-document.
        let reference = encode_data_uri(&[0xde, 0xad]);
        let block = build_manifest_block(&reference, "<!--", "-->");
        let text = format!("# Title\n\n{block}\n\nBody.\n");
        let (original_offset, _) = find_block_span(&text).expect("span");

        // Replace with a different manifest through the handler.
        let mut input = Cursor::new(text.into_bytes());
        let mut output = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut output, &[0xbe, 0xef, 0x01, 0x02])
            .expect("rewrite");

        let rewritten = String::from_utf8(output.into_inner()).unwrap();
        let (new_offset, _) = find_block_span(&rewritten).expect("span after rewrite");
        assert_eq!(new_offset, original_offset);
        assert!(rewritten.starts_with("# Title\n\n"));
        assert!(rewritten.ends_with("\n\nBody.\n"));

        let mut reader = Cursor::new(rewritten.into_bytes());
        assert_eq!(
            io.read_cai(&mut reader).expect("read"),
            vec![0xbe, 0xef, 0x01, 0x02]
        );
    }

    #[test]
    fn structured_object_locations() {
        let io = StructuredTextIO::new("text/markdown");
        let mut input = Cursor::new(b"# Doc\nbody\n".to_vec());
        let mut signed = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut signed, &[0xde, 0xad, 0xbe, 0xef])
            .expect("write");
        let total = signed.get_ref().len();

        signed.set_position(0);
        let positions = io
            .get_object_locations_from_stream(&mut signed)
            .expect("locations");
        let cai = positions
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Cai)
            .expect("CAI block");
        assert!(cai.length > 0);
        let covered: usize = positions.iter().map(|p| p.length).sum();
        assert_eq!(covered, total);
    }

    #[test]
    fn structured_no_manifest() {
        let io = StructuredTextIO::new("text/markdown");
        let mut reader = Cursor::new(b"# Just a document.\n".to_vec());
        assert!(matches!(
            io.read_cai(&mut reader).unwrap_err(),
            Error::JumbfNotFound
        ));
    }
}
