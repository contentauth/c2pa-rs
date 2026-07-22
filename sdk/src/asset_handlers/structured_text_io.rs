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

//! Structured-text asset handler (C2PA spec A.9): embeds a Manifest Store in a
//! host-format comment line (`-----BEGIN/END C2PA MANIFEST-----`) as a URL
//! reference or `data:` URI. Hashed over raw bytes (no NFC).

use std::{fs::File, path::Path};

use crate::{
    asset_handlers::text_common::{
        self, encode_data_uri, parse_manifest_reference, ManifestReference, BEGIN_DELIMITER,
        END_DELIMITER,
    },
    asset_io::{
        rename_or_move, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashObjectPositions,
    },
    error::{Error, Result},
    utils::io_utils::tempfile_builder,
};

#[derive(Clone, Copy)]
enum CommentStyle {
    Line(&'static str),
    Block(&'static str, &'static str),
}

/// Types owned by a format-specific handler (HTML, SVG, generic XML) are excluded.
static SUPPORTED_TYPES: [&str; 28] = [
    "atom",
    "application/atom+xml",
    "css",
    "text/css",
    "ini",
    "js",
    "mjs",
    "text/javascript",
    "application/javascript",
    "md",
    "markdown",
    "text/markdown",
    "py",
    "text/x-python",
    "rss",
    "application/rss+xml",
    "sql",
    "application/sql",
    "tex",
    "application/x-tex",
    "toml",
    "application/toml",
    "vtt",
    "text/vtt",
    "yaml",
    "yml",
    "application/yaml",
    "text/yaml",
];

const PLACEHOLDER_STORE: &[u8] = b"placeholder manifest";

fn comment_style(asset_type: &str) -> Option<CommentStyle> {
    Some(match asset_type.to_lowercase().as_str() {
        "md"
        | "markdown"
        | "text/markdown"
        | "rss"
        | "application/rss+xml"
        | "atom"
        | "application/atom+xml" => CommentStyle::Block("<!--", "-->"),
        "yaml" | "yml" | "application/yaml" | "text/yaml" | "toml" | "application/toml" | "py"
        | "text/x-python" => CommentStyle::Line("#"),
        "ini" => CommentStyle::Line(";"),
        "js" | "mjs" | "text/javascript" | "application/javascript" => CommentStyle::Line("//"),
        "css" | "text/css" => CommentStyle::Block("/*", "*/"),
        "sql" | "application/sql" => CommentStyle::Line("--"),
        "tex" | "application/x-tex" => CommentStyle::Line("%"),
        "vtt" | "text/vtt" => CommentStyle::Line("NOTE"),
        _ => return None,
    })
}

pub struct StructuredTextIO {
    asset_type: String,
}

/// `[start, end)` is the block's line span (with terminator); `reference` is the
/// text between the delimiters.
struct BlockInfo {
    start: usize,
    end: usize,
    reference: String,
}

fn count_blocks(text: &str) -> usize {
    text.matches(BEGIN_DELIMITER).count()
}

fn locate_block(text: &str) -> Option<BlockInfo> {
    let begin = text.find(BEGIN_DELIMITER)?;
    let after_begin = begin + BEGIN_DELIMITER.len();
    let end_rel = text[after_begin..].find(END_DELIMITER)?;
    let end_delim_start = after_begin + end_rel;
    let reference = text[after_begin..end_delim_start].trim().to_string();

    let past_end = end_delim_start + END_DELIMITER.len();
    let line_start = text[..begin].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = text[past_end..]
        .find('\n')
        .map(|i| past_end + i + 1)
        .unwrap_or(text.len());

    Some(BlockInfo {
        start: line_start,
        end: line_end,
        reference,
    })
}

fn strip_blocks(text: &str) -> String {
    let mut current = text.to_string();
    while let Some(b) = locate_block(&current) {
        let mut next = String::with_capacity(current.len());
        next.push_str(&current[..b.start]);
        next.push_str(&current[b.end..]);
        current = next;
    }
    current
}

/// The A.9 exclusion span; an end-of-file block also excludes the preceding newline.
fn exclusion_span(text: &str, block: &BlockInfo) -> (usize, usize) {
    let mut start = block.start;
    if block.end == text.len() && start > 0 {
        let bytes = text.as_bytes();
        if bytes[start - 1] == b'\n' {
            start -= 1;
            if start > 0 && bytes[start - 1] == b'\r' {
                start -= 1;
            }
        }
    }
    (start, block.end - start)
}

fn build_block_line(style: CommentStyle, reference: &str) -> String {
    match style {
        CommentStyle::Line(prefix) => {
            format!("{prefix} {BEGIN_DELIMITER} {reference} {END_DELIMITER}")
        }
        CommentStyle::Block(prefix, suffix) => {
            format!("{prefix} {BEGIN_DELIMITER} {reference} {END_DELIMITER} {suffix}")
        }
    }
}

/// Inserts the block at the A.9 position: file start, end if the first line is
/// reserved (shebang / XML decl), or after the `WEBVTT` header.
fn insert_block(cleaned: &str, block_line: &str, asset_type: &str) -> String {
    let le = if cleaned.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let lower = asset_type.to_lowercase();

    if lower == "vtt" || lower == "text/vtt" || cleaned.starts_with("WEBVTT") {
        if let Some(nl) = cleaned.find('\n') {
            let (head, rest) = cleaned.split_at(nl + 1);
            let rest = rest.trim_start_matches(['\r', '\n']);
            return format!("{head}{le}{block_line}{le}{le}{rest}");
        }
    }

    let trimmed = cleaned.trim_start();
    if trimmed.starts_with("#!") || trimmed.starts_with("<?xml") {
        let base = cleaned.trim_end_matches(['\r', '\n']);
        return format!("{base}{le}{block_line}");
    }

    format!("{block_line}{le}{cleaned}")
}

impl CAIReader for StructuredTextIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let text = text_common::read_text_stream(reader)?;

        // More than one block ⇒ treat as no manifest (A.9).
        if count_blocks(&text) != 1 {
            return Err(Error::JumbfNotFound);
        }

        let block = locate_block(&text).ok_or(Error::JumbfNotFound)?;
        match parse_manifest_reference(&block.reference)? {
            ManifestReference::External => Err(Error::JumbfNotFound),
            ManifestReference::Embedded(bytes) if !bytes.is_empty() => Ok(bytes),
            ManifestReference::Embedded(_) => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
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
        let style = comment_style(&self.asset_type).ok_or(Error::UnsupportedType)?;

        let text = text_common::read_text_stream(input_stream)?;
        let reference = encode_data_uri(store_bytes);
        let block_line = build_block_line(style, &reference);

        // Replace an existing block in place (preserves offset for update
        // manifests); otherwise insert at the A.9 position.
        let result = if count_blocks(&text) == 1 {
            let b = locate_block(&text).ok_or(Error::EmbeddingError)?;
            let bytes = text.as_bytes();
            let terminator = if b.end >= 2 && &bytes[b.end - 2..b.end] == b"\r\n" {
                "\r\n"
            } else if b.end >= 1 && bytes[b.end - 1] == b'\n' {
                "\n"
            } else {
                ""
            };
            let mut out = String::with_capacity(text.len() + block_line.len());
            out.push_str(&text[..b.start]);
            out.push_str(&block_line);
            out.push_str(terminator);
            out.push_str(&text[b.end..]);
            out
        } else {
            insert_block(&strip_blocks(&text), &block_line, &self.asset_type)
        };

        output_stream.rewind()?;
        output_stream.write_all(result.as_bytes())?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let text = text_common::read_text_stream(input_stream)?;

        let (full_len, block_start, block_len) = match locate_block(&text) {
            Some(b) => {
                let (start, len) = exclusion_span(&text, &b);
                (text.len(), start, len)
            }
            None => {
                // No manifest yet: use a placeholder block for the exclusion.
                let style = comment_style(&self.asset_type).ok_or(Error::UnsupportedType)?;
                let reference = encode_data_uri(PLACEHOLDER_STORE);
                let block_line = build_block_line(style, &reference);
                let with_block = insert_block(&text, &block_line, &self.asset_type);
                let b = locate_block(&with_block).ok_or(Error::EmbeddingError)?;
                let (start, len) = exclusion_span(&with_block, &b);
                (with_block.len(), start, len)
            }
        };

        Ok(text_common::hash_positions(
            full_len,
            block_start,
            block_len,
        ))
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let text = text_common::read_text_stream(input_stream)?;
        let cleaned = strip_blocks(&text);
        output_stream.rewind()?;
        output_stream.write_all(cleaned.as_bytes())?;
        Ok(())
    }
}

impl AssetIO for StructuredTextIO {
    fn new(asset_type: &str) -> Self {
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
        let mut input_stream = File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;
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
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::asset_io::HashBlockObjectType;

    fn embed(asset_type: &str, source: &str, store: &[u8]) -> String {
        let io = StructuredTextIO::new(asset_type);
        let mut input = Cursor::new(source.as_bytes().to_vec());
        let mut output = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut output, store).unwrap();
        String::from_utf8(output.into_inner()).unwrap()
    }

    fn read_back(asset_type: &str, text: &str) -> Result<Vec<u8>> {
        let io = StructuredTextIO::new(asset_type);
        let mut input = Cursor::new(text.as_bytes().to_vec());
        io.read_cai(&mut input)
    }

    #[test]
    fn markdown_uses_html_comment_and_round_trips() {
        let store = b"markdown store bytes";
        let out = embed("md", "# Title\n\nBody text.\n", store);
        assert!(out.contains("<!-- -----BEGIN C2PA MANIFEST-----"));
        assert!(out.contains("-----END C2PA MANIFEST----- -->"));
        assert_eq!(read_back("md", &out).unwrap(), store);
    }

    #[test]
    fn yaml_uses_hash_comment() {
        let out = embed("yaml", "key: value\n", b"yaml store");
        assert!(out.starts_with("# -----BEGIN C2PA MANIFEST-----"));
        assert_eq!(read_back("yaml", &out).unwrap(), b"yaml store");
    }

    #[test]
    fn full_range_covers_more_than_md_yaml_toml() {
        for (t, needle) in [
            ("js", "// -----BEGIN"),
            ("css", "/* -----BEGIN"),
            ("sql", "-- -----BEGIN"),
            ("tex", "% -----BEGIN"),
            ("py", "# -----BEGIN"),
        ] {
            let out = embed(t, "content\n", b"store");
            assert!(out.contains(needle), "{t} should use {needle}");
            assert_eq!(read_back(t, &out).unwrap(), b"store");
        }
    }

    #[test]
    fn shebang_forces_block_to_end_of_file() {
        let out = embed("py", "#!/usr/bin/env python\nprint('hi')\n", b"store");
        assert!(out.starts_with("#!/usr/bin/env python"));
        assert!(out.trim_end().ends_with("-----END C2PA MANIFEST-----"));
        assert_eq!(read_back("py", &out).unwrap(), b"store");
    }

    #[test]
    fn end_placed_block_exclusion_starts_at_preceding_newline() {
        let out = embed("py", "#!/usr/bin/env python\nprint('hi')\n", b"store");
        let io = StructuredTextIO::new("py");
        let mut cursor = Cursor::new(out.clone().into_bytes());
        let locations = io.get_object_locations_from_stream(&mut cursor).unwrap();
        let cai = locations
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Cai)
            .unwrap();
        let excluded = &out.as_bytes()[cai.offset..cai.offset + cai.length];
        assert_eq!(
            excluded[0], b'\n',
            "exclusion must begin at the preceding newline"
        );
        assert_eq!(cai.offset + cai.length, out.len(), "exclusion runs to EOF");
        let excluded = std::str::from_utf8(excluded).unwrap();
        assert!(excluded.contains(BEGIN_DELIMITER) && excluded.contains(END_DELIMITER));
    }

    #[test]
    fn webvtt_block_follows_header() {
        let out = embed(
            "vtt",
            "WEBVTT\n\n00:00:00.000 --> 00:00:05.000\nHello.\n",
            b"vtt store",
        );
        assert!(out.starts_with("WEBVTT"));
        assert!(out.contains("NOTE -----BEGIN C2PA MANIFEST-----"));
        assert_eq!(read_back("vtt", &out).unwrap(), b"vtt store");
    }

    #[test]
    fn external_url_reference_is_not_an_embedded_store() {
        let text = "// -----BEGIN C2PA MANIFEST----- https://example.com/a.c2pa -----END C2PA MANIFEST-----\ncode\n";
        assert!(matches!(read_back("js", text), Err(Error::JumbfNotFound)));
    }

    #[test]
    fn multiple_blocks_treated_as_no_manifest() {
        let mut text = embed("yaml", "a: 1\n", b"first");
        text.push_str("# -----BEGIN C2PA MANIFEST----- data:application/c2pa;base64,AAAA -----END C2PA MANIFEST-----\n");
        assert!(matches!(
            read_back("yaml", &text),
            Err(Error::JumbfNotFound)
        ));
    }

    #[test]
    fn replace_and_remove() {
        let first = embed("toml", "a = 1\n", b"first store");
        // Replace.
        let io = StructuredTextIO::new("toml");
        let mut input = Cursor::new(first.into_bytes());
        let mut output = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut output, b"second").unwrap();
        let replaced = String::from_utf8(output.into_inner()).unwrap();
        assert_eq!(count_blocks(&replaced), 1);
        assert_eq!(read_back("toml", &replaced).unwrap(), b"second");

        // Remove.
        let mut input = Cursor::new(replaced.into_bytes());
        let mut output = Cursor::new(Vec::new());
        io.remove_cai_store_from_stream(&mut input, &mut output)
            .unwrap();
        let removed = String::from_utf8(output.into_inner()).unwrap();
        assert_eq!(removed, "a = 1\n");
    }

    #[test]
    fn replace_preserves_block_offset() {
        // Shebang forces the block to a non-zero end-of-file offset; a same-size
        // store must leave that offset byte-identical (update manifests).
        let first = embed("py", "#!/usr/bin/env python\nprint('x')\n", b"AAAA");
        let offset_before = first.find(BEGIN_DELIMITER).unwrap();

        let io = StructuredTextIO::new("py");
        let mut input = Cursor::new(first.into_bytes());
        let mut output = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut output, b"BBBB").unwrap();
        let replaced = String::from_utf8(output.into_inner()).unwrap();

        assert_eq!(count_blocks(&replaced), 1);
        assert_eq!(
            replaced.find(BEGIN_DELIMITER).unwrap(),
            offset_before,
            "block offset must be preserved on replace (update manifests)"
        );
        assert_eq!(read_back("py", &replaced).unwrap(), b"BBBB");
    }

    #[test]
    fn object_locations_exclude_exactly_the_block() {
        let out = embed("md", "# Doc\n", b"store bytes");
        let io = StructuredTextIO::new("md");
        let mut cursor = Cursor::new(out.clone().into_bytes());
        let locations = io.get_object_locations_from_stream(&mut cursor).unwrap();
        let cai = locations
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Cai)
            .unwrap();
        let excluded = &out.as_bytes()[cai.offset..cai.offset + cai.length];
        let excluded = std::str::from_utf8(excluded).unwrap();
        assert!(excluded.contains(BEGIN_DELIMITER) && excluded.contains(END_DELIMITER));
    }
}
