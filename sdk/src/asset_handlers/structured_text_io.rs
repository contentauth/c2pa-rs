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

use crate::{
    asset_handlers::text_common::{
        self, encode_data_uri, parse_manifest_reference, ManifestReference, BEGIN_DELIMITER,
        END_DELIMITER,
    },
    asset_io::{
        AssetIO, C2paReader, C2paWriter, ObjectLocations, ReadSeek, ReadWriteSeek,
        RemoteManifestUrl,
    },
    error::{Error, Result},
};

#[derive(Clone, Copy)]
enum CommentStyle {
    Line(&'static str),
    Block(&'static str, &'static str),
}

/// A.9.2 excludes `text/html` and `image/svg+xml`, which have their own embedding sections.
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
    /// Offset of the `BEGIN` delimiter, so the text before it on the line can be kept.
    begin: usize,
    /// Offset just past the `END` delimiter, so the text after it on the line can be kept.
    past_end: usize,
    reference: String,
    /// A.9.3.2 multi-line form (delimiters on separate lines), as used in front matter.
    multiline: bool,
}

/// Every manifest block in `text`, in order. A `BEGIN`/`END` pair only counts when the
/// text between the delimiters is a manifest reference (A.9.3): an unterminated `BEGIN`,
/// or a pair wrapping ordinary prose, is content and is skipped rather than treated as a
/// block to read, replace, or strip.
fn find_blocks(text: &str) -> Vec<BlockInfo> {
    let mut blocks = Vec::new();
    let mut search = 0;

    while let Some(rel) = text[search..].find(BEGIN_DELIMITER) {
        let begin = search + rel;
        let after_begin = begin + BEGIN_DELIMITER.len();
        let Some(end_rel) = text[after_begin..].find(END_DELIMITER) else {
            break;
        };
        let end_delim_start = after_begin + end_rel;
        let past_end = end_delim_start + END_DELIMITER.len();
        let reference = text[after_begin..end_delim_start].trim();

        let line_start = text[..begin].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = text[past_end..]
            .find('\n')
            .map(|i| past_end + i + 1)
            .unwrap_or(text.len());
        let multiline = text[after_begin..end_delim_start].contains('\n');
        let delimiters_on_own_lines = line_start == begin
            && text[past_end..line_end]
                .trim_end_matches(['\r', '\n'])
                .is_empty();

        if text_common::is_manifest_reference(reference) && (!multiline || delimiters_on_own_lines)
        {
            blocks.push(BlockInfo {
                start: line_start,
                end: line_end,
                begin,
                past_end,
                reference: reference.to_string(),
                multiline,
            });
        }

        search = past_end;
    }

    blocks
}

fn count_blocks(text: &str) -> usize {
    find_blocks(text).len()
}

fn locate_block(text: &str) -> Option<BlockInfo> {
    find_blocks(text).into_iter().next()
}

fn strip_blocks(text: &str) -> String {
    let blocks = find_blocks(text);
    if blocks.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for b in &blocks {
        out.push_str(&text[cursor..b.start]);
        cursor = b.end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// The hard binding exclusion: only the bytes from the `BEGIN` delimiter through the `END`
/// delimiter. Comment syntax and line terminators around them are hashed.
fn exclusion_span(block: &BlockInfo) -> (usize, usize) {
    (block.begin, block.past_end - block.begin)
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

/// The multi-line form, which validators still accept and replacement keeps: delimiters on their own lines,
/// with no comment prefix, and the reference between them.
fn build_multiline_block(reference: &str, le: &str) -> String {
    format!("{BEGIN_DELIMITER}{le}{reference}{le}{END_DELIMITER}")
}

/// Markdown is the format here with a front matter convention. A leading `---` in YAML or
/// TOML is document syntax rather than front matter, so those keep the comment form.
fn supports_front_matter(lower_asset_type: &str) -> bool {
    matches!(lower_asset_type, "md" | "markdown" | "text/markdown")
}

/// Byte offset just past the opening fence line of a leading front matter section, if the
/// file opens with one and a matching closing fence follows.
fn front_matter_insert_point(text: &str) -> Option<usize> {
    let fence = ["---", "+++"].into_iter().find(|f| text.starts_with(f))?;
    let first_nl = text.find('\n')?;
    if text[..first_nl].trim_end() != fence {
        return None;
    }
    let after_open = first_nl + 1;
    text[after_open..]
        .split_inclusive('\n')
        .any(|line| line.trim_end() == fence)
        .then_some(after_open)
}

/// Inserts the block at the A.9 position: inside leading front matter (A.9.3), else file
/// start, end if the first line is reserved (shebang / XML decl), or after the `WEBVTT`
/// header.
fn insert_block(cleaned: &str, reference: &str, style: CommentStyle, asset_type: &str) -> String {
    let le = if cleaned.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let lower = asset_type.to_lowercase();

    // YAML and TOML both use `#`, and a comment keeps the front matter parseable by its host format.
    if supports_front_matter(&lower) {
        if let Some(at) = front_matter_insert_point(cleaned) {
            let block = build_block_line(CommentStyle::Line("#"), reference);
            return format!("{}{block}{le}{}", &cleaned[..at], &cleaned[at..]);
        }
    }

    let block_line = build_block_line(style, reference);

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

/// Writes `reference` into `text`. An existing block is replaced in place, which preserves its
/// offset for update manifests and keeps the form the file already uses. Otherwise the block is
/// inserted at the A.9 position.
fn write_reference(
    text: &str,
    reference: &str,
    style: CommentStyle,
    asset_type: &str,
) -> Result<String> {
    if count_blocks(text) != 1 {
        return Ok(insert_block(
            &strip_blocks(text),
            reference,
            style,
            asset_type,
        ));
    }

    let b = locate_block(text).ok_or(Error::EmbeddingError)?;
    let bytes = text.as_bytes();
    let terminator = if b.end >= 2 && &bytes[b.end - 2..b.end] == b"\r\n" {
        "\r\n"
    } else if b.end >= 1 && bytes[b.end - 1] == b'\n' {
        "\n"
    } else {
        ""
    };
    let replacement = if b.multiline {
        let le = if terminator.is_empty() {
            "\n"
        } else {
            terminator
        };
        build_multiline_block(reference, le)
    } else {
        // Keep the line's own comment syntax. It isn't always the format's default: a `#` comment
        // inside Markdown's YAML front matter has to stay a `#` comment.
        let prefix = &text[b.start..b.begin];
        let suffix = &text[b.past_end..b.end - terminator.len()];
        format!("{prefix}{BEGIN_DELIMITER} {reference} {END_DELIMITER}{suffix}")
    };

    let mut out = String::with_capacity(text.len() + replacement.len());
    out.push_str(&text[..b.start]);
    out.push_str(&replacement);
    out.push_str(terminator);
    out.push_str(&text[b.end..]);
    Ok(out)
}

impl C2paReader for StructuredTextIO {
    fn read_c2pa(&self, reader: &mut dyn ReadSeek) -> Result<Vec<u8>> {
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

    fn read_xmp(&self, _asset_reader: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for StructuredTextIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let style = comment_style(&self.asset_type).ok_or(Error::UnsupportedType)?;

        let text = text_common::read_text_stream(input_stream)?;
        let reference = encode_data_uri(store_bytes);
        let result = write_reference(&text, &reference, style, &self.asset_type)?;

        output_stream.rewind()?;
        output_stream.write_all(result.as_bytes())?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let text = text_common::read_text_stream(input_stream)?;

        let (full_len, block_start, block_len) = match locate_block(&text) {
            Some(b) => {
                let (start, len) = exclusion_span(&b);
                (text.len(), start, len)
            }
            None => {
                // No manifest yet: use a placeholder block for the exclusion.
                let style = comment_style(&self.asset_type).ok_or(Error::UnsupportedType)?;
                let reference = encode_data_uri(PLACEHOLDER_STORE);
                let with_block = insert_block(&text, &reference, style, &self.asset_type);
                let b = locate_block(&with_block).ok_or(Error::EmbeddingError)?;
                let (start, len) = exclusion_span(&b);
                (with_block.len(), start, len)
            }
        };

        Ok(text_common::hash_positions(
            full_len,
            block_start,
            block_len,
        ))
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let text = text_common::read_text_stream(input_stream)?;
        let cleaned = strip_blocks(&text);
        output_stream.rewind()?;
        output_stream.write_all(cleaned.as_bytes())?;
        Ok(())
    }
}

impl RemoteManifestUrl for StructuredTextIO {
    fn write_remote_manifest_url(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        remote_manifest_url: &str,
    ) -> Result<()> {
        let style = comment_style(&self.asset_type).ok_or(Error::UnsupportedType)?;
        if !text_common::is_manifest_reference(remote_manifest_url)
            || !matches!(
                parse_manifest_reference(remote_manifest_url)?,
                ManifestReference::External
            )
        {
            return Err(Error::BadParam(format!(
                "not a remote manifest URL: {remote_manifest_url}"
            )));
        }

        let text = text_common::read_text_stream(input_stream)?;
        let result = write_reference(&text, remote_manifest_url, style, &self.asset_type)?;

        output_stream.rewind()?;
        output_stream.write_all(result.as_bytes())?;
        Ok(())
    }

    /// More than one block is treated as no manifest, and an embedded `data:` URI isn't a remote
    /// reference.
    fn read_manifest_url(&self, input_stream: &mut dyn ReadSeek) -> Option<String> {
        let text = text_common::read_text_stream(input_stream).ok()?;
        if count_blocks(&text) != 1 {
            return None;
        }
        let block = locate_block(&text)?;
        match parse_manifest_reference(&block.reference).ok()? {
            ManifestReference::External => Some(block.reference),
            ManifestReference::Embedded(_) => None,
        }
    }

    fn remove_remote_manifest_url(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let text = text_common::read_text_stream(input_stream)?;
        let has_url = find_blocks(&text).iter().any(|b| {
            matches!(
                parse_manifest_reference(&b.reference),
                Ok(ManifestReference::External)
            )
        });
        let result = if has_url { strip_blocks(&text) } else { text };

        output_stream.rewind()?;
        output_stream.write_all(result.as_bytes())?;
        Ok(())
    }

    fn url_shares_manifest_slot(&self) -> bool {
        true
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

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(StructuredTextIO::new(asset_type)))
    }

    fn remote_manifest_url_ref(&self) -> Option<&dyn RemoteManifestUrl> {
        Some(self)
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
    use crate::asset_io::ObjectType;

    fn embed(asset_type: &str, source: &str, store: &[u8]) -> String {
        let io = StructuredTextIO::new(asset_type);
        let mut input = Cursor::new(source.as_bytes().to_vec());
        let mut output = Cursor::new(Vec::new());
        io.write_c2pa(&mut input, &mut output, store).unwrap();
        String::from_utf8(output.into_inner()).unwrap()
    }

    fn read_back(asset_type: &str, text: &str) -> Result<Vec<u8>> {
        let io = StructuredTextIO::new(asset_type);
        let mut input = Cursor::new(text.as_bytes().to_vec());
        io.read_c2pa(&mut input)
    }

    fn write_url(asset_type: &str, source: &str, url: &str) -> String {
        let io = StructuredTextIO::new(asset_type);
        let mut input = Cursor::new(source.as_bytes().to_vec());
        let mut output = Cursor::new(Vec::new());
        io.write_remote_manifest_url(&mut input, &mut output, url)
            .unwrap();
        String::from_utf8(output.into_inner()).unwrap()
    }

    fn read_url(asset_type: &str, text: &str) -> Option<String> {
        StructuredTextIO::new(asset_type)
            .read_manifest_url(&mut Cursor::new(text.as_bytes().to_vec()))
    }

    const URL: &str = "https://example.com/manifests/a1b2c3.c2pa";

    #[test]
    fn remote_url_round_trips() {
        let out = write_url("md", "# Title\n", URL);
        assert_eq!(
            out,
            format!("<!-- {BEGIN_DELIMITER} {URL} {END_DELIMITER} -->\n# Title\n")
        );
        assert_eq!(read_url("md", &out).as_deref(), Some(URL));
        assert!(matches!(read_back("md", &out), Err(Error::JumbfNotFound)));
    }

    #[test]
    fn remote_url_uses_a_comment_line_in_new_front_matter_blocks() {
        let out = write_url("md", "---\ntitle: Doc\n---\nBody\n", URL);
        assert_eq!(
            out,
            format!("---\n# {BEGIN_DELIMITER} {URL} {END_DELIMITER}\ntitle: Doc\n---\nBody\n")
        );
        assert_eq!(read_url("md", &out).as_deref(), Some(URL));

        let toml = write_url("md", "+++\ntitle = \"Doc\"\n+++\nBody\n", URL);
        assert!(toml.starts_with(&format!("+++\n# {BEGIN_DELIMITER} {URL} {END_DELIMITER}\n")));
    }

    /// Validators still accept the multi-line form, and replacing a block keeps it.
    #[test]
    fn existing_multiline_block_is_read_and_kept() {
        let source =
            format!("---\n{BEGIN_DELIMITER}\n{URL}\n{END_DELIMITER}\ntitle: Doc\n---\nBody\n");
        assert_eq!(read_url("md", &source).as_deref(), Some(URL));

        let new_url = "https://new.example/m.c2pa";
        assert_eq!(
            write_url("md", &source, new_url),
            format!("---\n{BEGIN_DELIMITER}\n{new_url}\n{END_DELIMITER}\ntitle: Doc\n---\nBody\n")
        );
    }

    /// A line terminator between the delimiters is only allowed when each delimiter has its own
    /// line.
    #[test]
    fn multiline_reference_needs_delimiters_on_their_own_lines() {
        for text in [
            format!("# {BEGIN_DELIMITER}\n{URL}\n{END_DELIMITER}\nbody\n"),
            format!("{BEGIN_DELIMITER}\n{URL}\n# {END_DELIMITER}\nbody\n"),
            format!("{BEGIN_DELIMITER}\n{URL}\n{END_DELIMITER} # note\nbody\n"),
        ] {
            assert_eq!(count_blocks(&text), 0, "{text:?}");
            assert_eq!(read_url("md", &text), None);
        }

        let crlf = format!("{BEGIN_DELIMITER}\r\n{URL}\r\n{END_DELIMITER}\r\nbody\r\n");
        assert_eq!(read_url("md", &crlf).as_deref(), Some(URL));
    }

    #[test]
    fn a_reference_containing_whitespace_is_not_a_block() {
        let text = format!("# {BEGIN_DELIMITER} {URL} extra {END_DELIMITER}\nbody\n");
        assert_eq!(count_blocks(&text), 0);
    }

    /// A `#` line inside YAML front matter must stay a `#` line. The multi-line form and the
    /// Markdown `<!-- -->` form would both make the front matter invalid YAML.
    #[test]
    fn replacing_keeps_the_comment_syntax_of_the_existing_line() {
        let source = format!(
            "---\n# {BEGIN_DELIMITER} https://old.example/m.c2pa {END_DELIMITER}\nname: x\n---\nBody\n"
        );
        let expected =
            format!("---\n# {BEGIN_DELIMITER} {URL} {END_DELIMITER}\nname: x\n---\nBody\n");
        assert_eq!(write_url("md", &source, URL), expected);

        let embedded = embed("md", &source, b"store");
        assert!(embedded.starts_with(&format!("---\n# {BEGIN_DELIMITER} data:application/c2pa")));
        assert_eq!(read_back("md", &embedded).unwrap(), b"store");
    }

    #[test]
    fn replacing_keeps_a_comment_suffix_and_crlf() {
        let source = format!("/* {BEGIN_DELIMITER} {URL} {END_DELIMITER} */\r\nbody {{}}\r\n");
        let out = write_url("css", &source, "https://new.example/m.c2pa");
        assert_eq!(
            out,
            format!(
                "/* {BEGIN_DELIMITER} https://new.example/m.c2pa {END_DELIMITER} */\r\nbody {{}}\r\n"
            )
        );
    }

    #[test]
    fn reading_a_url_ignores_embedded_and_ambiguous_blocks() {
        assert_eq!(read_url("md", "# No block\n"), None);
        assert_eq!(read_url("md", &embed("md", "# Doc\n", b"store")), None);

        let line = format!("<!-- {BEGIN_DELIMITER} {URL} {END_DELIMITER} -->\n");
        assert_eq!(read_url("md", &format!("{line}{line}")), None);
    }

    #[test]
    fn writing_rejects_a_data_uri_or_non_url_as_the_remote_url() {
        let io = StructuredTextIO::new("md");
        for bad in ["data:application/c2pa;base64,AAAA", "not a url", ""] {
            let mut input = Cursor::new(b"# Doc\n".to_vec());
            let mut output = Cursor::new(Vec::new());
            assert!(matches!(
                io.write_remote_manifest_url(&mut input, &mut output, bad),
                Err(Error::BadParam(_))
            ));
        }
    }

    #[test]
    fn removing_a_url_leaves_an_embedded_manifest_alone() {
        let io = StructuredTextIO::new("md");
        let remove = |text: &str| {
            let mut input = Cursor::new(text.as_bytes().to_vec());
            let mut output = Cursor::new(Vec::new());
            io.remove_remote_manifest_url(&mut input, &mut output)
                .unwrap();
            String::from_utf8(output.into_inner()).unwrap()
        };

        assert_eq!(remove(&write_url("md", "# Doc\n", URL)), "# Doc\n");
        let embedded = embed("md", "# Doc\n", b"store");
        assert_eq!(remove(&embedded), embedded);
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
    fn end_placed_block_exclusion_covers_only_the_delimited_bytes() {
        let out = embed("py", "#!/usr/bin/env python\nprint('hi')\n", b"store");
        let io = StructuredTextIO::new("py");
        let mut cursor = Cursor::new(out.clone().into_bytes());
        let locations = io.get_object_locations(&mut cursor).unwrap();
        let cai = locations
            .iter()
            .find(|p| p.htype == ObjectType::C2pa)
            .unwrap();
        let excluded = &out[(cai.offset as usize)..(cai.offset as usize) + (cai.length as usize)];
        assert!(excluded.starts_with(BEGIN_DELIMITER) && excluded.ends_with(END_DELIMITER));
        assert!(
            out[..cai.offset as usize].ends_with("\n# "),
            "the newline and comment prefix are hashed"
        );
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
        io.write_c2pa(&mut input, &mut output, b"second").unwrap();
        let replaced = String::from_utf8(output.into_inner()).unwrap();
        assert_eq!(count_blocks(&replaced), 1);
        assert_eq!(read_back("toml", &replaced).unwrap(), b"second");

        // Remove.
        let mut input = Cursor::new(replaced.into_bytes());
        let mut output = Cursor::new(Vec::new());
        io.remove_c2pa(&mut input, &mut output).unwrap();
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
        io.write_c2pa(&mut input, &mut output, b"BBBB").unwrap();
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
        let locations = io.get_object_locations(&mut cursor).unwrap();
        let cai = locations
            .iter()
            .find(|p| p.htype == ObjectType::C2pa)
            .unwrap();
        let excluded = &out[(cai.offset as usize)..(cai.offset as usize) + (cai.length as usize)];
        assert!(excluded.starts_with(BEGIN_DELIMITER) && excluded.ends_with(END_DELIMITER));
        assert_eq!(&out[..cai.offset as usize], "<!-- ");
        assert!(out[(cai.offset as usize) + (cai.length as usize)..].starts_with(" -->\n"));
    }

    /// An unterminated `BEGIN` is not a block (A.9.5 step 4), so a file whose prose
    /// mentions the delimiter stays signable.
    #[test]
    fn unterminated_begin_is_content_not_a_block() {
        let src = format!("# Doc\n\nSee {BEGIN_DELIMITER} for the format.\n");
        let out = embed("md", &src, b"store");
        assert_eq!(read_back("md", &out).unwrap(), b"store");
        assert!(
            out.contains(&format!("See {BEGIN_DELIMITER} for the format.")),
            "the prose line must survive untouched"
        );
    }

    /// A stray `BEGIN` alongside a real block must not make the manifest unreadable.
    #[test]
    fn stray_begin_does_not_hide_the_manifest() {
        let signed = embed("md", "# Doc\n", b"first");
        let with_stray = format!("{signed}stray {BEGIN_DELIMITER} text\n");
        let out = embed("md", &with_stray, b"second");
        assert_eq!(count_blocks(&out), 1);
        assert_eq!(read_back("md", &out).unwrap(), b"second");
    }

    /// Delimiters wrapping prose are not a manifest reference (A.9.3), so embedding
    /// must not overwrite that line.
    #[test]
    fn prose_between_delimiters_is_preserved() {
        let src = format!("# Doc\n\n{BEGIN_DELIMITER} not a reference {END_DELIMITER}\n\ntail\n");
        let out = embed("md", &src, b"store");
        assert!(out.contains("not a reference"), "prose must be preserved");
        assert!(out.contains("tail"));
        assert_eq!(read_back("md", &out).unwrap(), b"store");
    }

    /// A.9.4 requires LF or CRLF preserved byte-exactly; the block must round-trip in a
    /// CRLF file and the exclusion range must cover it exactly.
    #[test]
    fn crlf_file_round_trips() {
        let out = embed("yaml", "a: 1\r\nb: 2\r\n", b"crlf store");
        assert!(out.contains("\r\n"), "CRLF must be preserved");
        assert_eq!(read_back("yaml", &out).unwrap(), b"crlf store");

        let io = StructuredTextIO::new("yaml");
        let mut cursor = Cursor::new(out.clone().into_bytes());
        let locations = io.get_object_locations(&mut cursor).unwrap();
        let cai = locations
            .iter()
            .find(|p| p.htype == ObjectType::C2pa)
            .unwrap();
        let excluded = &out[(cai.offset as usize)..(cai.offset as usize) + (cai.length as usize)];
        assert!(excluded.contains(BEGIN_DELIMITER) && excluded.contains(END_DELIMITER));
        assert!(
            !out[(cai.offset as usize) + (cai.length as usize)..].contains(BEGIN_DELIMITER),
            "exclusion must cover the whole block"
        );
    }

    #[test]
    fn markdown_front_matter_holds_the_block() {
        let src = "---\ntitle: My Document\n---\n\n# Body\n";
        let out = embed("md", src, b"front matter store");

        assert!(
            out.starts_with("---\n# "),
            "the block is the first front matter line"
        );
        assert!(out.contains("title: My Document"));
        assert!(out.contains("# Body"));
        assert_eq!(read_back("md", &out).unwrap(), b"front matter store");
        assert!(
            !out.contains("<!--"),
            "front matter uses its own comment syntax"
        );

        // The block must sit between the fences, not before the opening one.
        let block_at = out.find(BEGIN_DELIMITER).unwrap();
        let closing_fence = out[4..].find("\n---").unwrap() + 4;
        assert!(block_at > 3 && block_at < closing_fence);
    }

    #[test]
    fn front_matter_exclusion_omits_the_fences() {
        let out = embed("md", "---\ntitle: T\n---\n\nbody\n", b"store");
        let io = StructuredTextIO::new("md");
        let mut cursor = Cursor::new(out.clone().into_bytes());
        let locations = io.get_object_locations(&mut cursor).unwrap();
        let cai = locations
            .iter()
            .find(|p| p.htype == ObjectType::C2pa)
            .unwrap();

        let excluded = &out[(cai.offset as usize)..(cai.offset as usize) + (cai.length as usize)];
        assert!(excluded.starts_with(BEGIN_DELIMITER), "got {excluded:?}");
        assert!(excluded.ends_with(END_DELIMITER));
        assert_eq!(
            &out[..cai.offset as usize],
            "---\n# ",
            "the opening fence and comment prefix are hashed"
        );
        assert!(out[(cai.offset as usize) + (cai.length as usize)..].starts_with("\ntitle: T"));
    }

    #[test]
    fn front_matter_replace_keeps_form() {
        let first = embed("md", "---\ntitle: T\n---\n\nbody\n", b"AAAA");
        let io = StructuredTextIO::new("md");
        let mut input = Cursor::new(first.clone().into_bytes());
        let mut output = Cursor::new(Vec::new());
        io.write_c2pa(&mut input, &mut output, b"BBBB").unwrap();
        let replaced = String::from_utf8(output.into_inner()).unwrap();

        assert_eq!(count_blocks(&replaced), 1);
        assert_eq!(read_back("md", &replaced).unwrap(), b"BBBB");
        assert!(replaced.contains(&format!("\n# {BEGIN_DELIMITER} ")));
        assert!(!replaced.contains("<!--"));
        assert!(replaced.contains("title: T"));
        assert_eq!(
            replaced.find(BEGIN_DELIMITER),
            first.find(BEGIN_DELIMITER),
            "offset must be preserved on replace"
        );
    }

    /// Markdown without front matter keeps the comment form, and a YAML file's leading
    /// `---` is document syntax rather than front matter.
    #[test]
    fn leading_dashes_only_count_for_markdown_front_matter() {
        let md = embed("md", "# No front matter\n", b"store");
        assert!(md.starts_with("<!-- "), "got {md:?}");

        let yaml = embed("yaml", "---\nkey: value\n", b"store");
        assert!(
            yaml.starts_with("# "),
            "YAML keeps the comment form, got {yaml:?}"
        );
        assert_eq!(read_back("yaml", &yaml).unwrap(), b"store");
    }

    #[test]
    fn external_url_block_is_still_a_block() {
        let text =
            format!("// {BEGIN_DELIMITER} https://example.com/a.c2pa {END_DELIMITER}\ncode\n");
        assert_eq!(count_blocks(&text), 1);
        // Replacing it must not leave a second block behind.
        let out = embed("js", &text, b"store");
        assert_eq!(count_blocks(&out), 1);
        assert_eq!(read_back("js", &out).unwrap(), b"store");
    }
}
