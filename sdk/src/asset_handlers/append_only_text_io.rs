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

//! Append-only text files (C2PA "Embedding manifests into append-only text files"):
//! application logs and JSON Lines streams that carry a rolling chain of checkpoint
//! sentinel lines, each referencing the C2PA Manifest Store for the segment above it.
//!
//! This module locates sentinel lines and resolves their manifest references. The
//! `c2pa.hash.segment` binding itself is checked by
//! [`SegmentHash`](crate::assertions::SegmentHash), and the chain of earlier
//! checkpoints is walked by the store after the active manifest has been validated.

use std::io::SeekFrom;

use crate::{
    asset_io::{AssetIO, C2paReader, ReadSeek},
    crypto::base64,
    error::{Error, Result},
    utils::io_utils::stream_len,
    validation_status,
};

/// Delimiters for a plain-text sentinel line.
pub(crate) const BEGIN_CHECKPOINT: &str = "-----BEGIN C2PA CHECKPOINT-----";
pub(crate) const END_CHECKPOINT: &str = "-----END C2PA CHECKPOINT-----";
/// Member name for a JSONL sentinel line.
pub(crate) const JSONL_CHECKPOINT_KEY: &str = "c2pa:checkpoint";

const DATA_URI_PREFIX: &str = "data:application/c2pa;base64,";
const SCAN_CHUNK: u64 = 8 * 1024;

const JSONL_TYPES: [&str; 4] = [
    "jsonl",
    "application/jsonl",
    "application/x-ndjson",
    "application/jsonlines",
];
const PLAIN_TEXT_TYPES: [&str; 3] = ["txt", "text/plain", "log"];

/// Which sentinel syntax a file uses, decided by its format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SentinelForm {
    /// `-----BEGIN C2PA CHECKPOINT----- <ref> -----END C2PA CHECKPOINT-----`
    Armour,
    /// `{"c2pa:checkpoint":"<ref>"}`
    Json,
}

impl SentinelForm {
    pub(crate) fn for_format(format: &str) -> Self {
        if is_jsonl_format(format) {
            SentinelForm::Json
        } else {
            SentinelForm::Armour
        }
    }
}

fn is_jsonl_format(format: &str) -> bool {
    let format = format.to_ascii_lowercase();
    JSONL_TYPES.contains(&format.as_str())
}

/// Returns `true` for the formats this section applies to.
pub(crate) fn is_append_only_format(format: &str) -> bool {
    let format = format.to_ascii_lowercase();
    JSONL_TYPES.contains(&format.as_str()) || PLAIN_TEXT_TYPES.contains(&format.as_str())
}

/// Where a checkpoint's C2PA Manifest Store lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ManifestReference {
    /// Decoded from a `data:application/c2pa;base64,` URI on the sentinel line.
    Inline(Vec<u8>),
    /// A URI to an externally stored Manifest Store.
    External(String),
}

/// A complete, well-formed sentinel line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sentinel {
    /// Byte offset of the first byte of the line.
    pub(crate) start: u64,
    /// Byte length of the line, including its terminating line ending.
    pub(crate) len: u64,
    pub(crate) reference: ManifestReference,
}

enum Candidate {
    NotSentinel,
    Malformed,
    Sentinel(ManifestReference),
}

fn no_sentinel() -> Error {
    Error::C2PAValidation(validation_status::MANIFEST_APPEND_ONLY_TEXT_NO_SENTINEL.to_string())
}

/// Parses a manifest reference, trimming the whitespace the spec allows around it.
fn parse_reference(raw: &str) -> Option<ManifestReference> {
    let reference = raw.trim_matches([' ', '\t', '\n', '\r']);
    if reference.is_empty() {
        return None;
    }
    if let Some(rest) = reference.strip_prefix("data:") {
        // Only `application/c2pa` with base64 encoding is a valid inline store.
        let encoded = format!("data:{rest}");
        let encoded = encoded.strip_prefix(DATA_URI_PREFIX)?;
        return base64::decode(encoded)
            .ok()
            .filter(|bytes| !bytes.is_empty())
            .map(ManifestReference::Inline);
    }
    Some(ManifestReference::External(reference.to_string()))
}

/// Classifies one line, given without its line ending.
fn classify_line(line: &[u8], form: SentinelForm) -> Candidate {
    match form {
        SentinelForm::Armour => {
            if !line.starts_with(BEGIN_CHECKPOINT.as_bytes()) {
                return Candidate::NotSentinel;
            }
            let Ok(text) = std::str::from_utf8(line) else {
                return Candidate::Malformed;
            };
            let Some(inner) = text
                .strip_prefix(BEGIN_CHECKPOINT)
                .and_then(|t| t.strip_suffix(END_CHECKPOINT))
            else {
                return Candidate::Malformed;
            };
            parse_reference(inner).map_or(Candidate::Malformed, Candidate::Sentinel)
        }
        SentinelForm::Json => {
            // Cheap filter: most content lines never mention the key.
            let key = JSONL_CHECKPOINT_KEY.as_bytes();
            if !line.windows(key.len()).any(|w| w == key) {
                return Candidate::NotSentinel;
            }
            let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(line) else {
                return Candidate::NotSentinel;
            };
            match map.get(JSONL_CHECKPOINT_KEY) {
                None => Candidate::NotSentinel,
                Some(serde_json::Value::String(s)) => {
                    parse_reference(s).map_or(Candidate::Malformed, Candidate::Sentinel)
                }
                Some(_) => Candidate::Malformed,
            }
        }
    }
}

/// Formats a complete sentinel line for `reference`, terminated by `eol`.
pub(crate) fn sentinel_line(form: SentinelForm, reference: &str, eol: &str) -> Vec<u8> {
    match form {
        SentinelForm::Armour => format!("{BEGIN_CHECKPOINT} {reference} {END_CHECKPOINT}{eol}"),
        SentinelForm::Json => {
            let mut map = serde_json::Map::new();
            map.insert(
                JSONL_CHECKPOINT_KEY.to_string(),
                serde_json::Value::String(reference.to_string()),
            );
            format!("{}{eol}", serde_json::Value::Object(map))
        }
    }
    .into_bytes()
}

/// Splits a trailing `\n` or `\r\n` off a line, returning the content.
fn strip_line_ending(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Finds the active checkpoint: the last complete sentinel line in `[0, end)`.
///
/// Returns `Ok(None)` when the range contains no sentinel line, and an error carrying
/// `manifest.appendOnlyText.noSentinel` when the last candidate line is malformed or
/// incomplete. Content lines after the last sentinel are skipped here; coverage
/// validation reports them.
pub(crate) fn find_active_sentinel(
    stream: &mut dyn ReadSeek,
    form: SentinelForm,
    end: u64,
) -> Result<Option<Sentinel>> {
    let mut line_end = end;
    while line_end > 0 {
        let complete = read_range(stream, line_end - 1, 1)? == b"\n";
        // A complete line's own terminator is at `line_end - 1`; search before it.
        let search_before = if complete { line_end - 1 } else { line_end };
        let start = rfind_newline(stream, search_before)?.map_or(0, |i| i + 1);
        let line = read_range(stream, start, line_end - start)?;
        match classify_line(strip_line_ending(&line), form) {
            Candidate::NotSentinel => {}
            Candidate::Sentinel(reference) if complete => {
                return Ok(Some(Sentinel {
                    start,
                    len: line_end - start,
                    reference,
                }))
            }
            Candidate::Sentinel(_) | Candidate::Malformed => return Err(no_sentinel()),
        }
        line_end = start;
    }
    Ok(None)
}

fn read_range(stream: &mut dyn ReadSeek, start: u64, len: u64) -> Result<Vec<u8>> {
    let len = usize::try_from(len).map_err(|_| Error::InsufficientMemory)?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(len)
        .map_err(|_| Error::InsufficientMemory)?;
    buf.resize(len, 0);
    stream.seek(SeekFrom::Start(start))?;
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Offset of the last `\n` strictly before `before`, scanning backwards in chunks.
fn rfind_newline(stream: &mut dyn ReadSeek, before: u64) -> Result<Option<u64>> {
    let mut chunk_end = before;
    while chunk_end > 0 {
        let chunk_start = chunk_end.saturating_sub(SCAN_CHUNK);
        let chunk = read_range(stream, chunk_start, chunk_end - chunk_start)?;
        if let Some(i) = chunk.iter().rposition(|&b| b == b'\n') {
            return Ok(Some(chunk_start + i as u64));
        }
        chunk_end = chunk_start;
    }
    Ok(None)
}

/// Reads the sentinel line that starts at `start`, which must be complete and well formed.
/// Returns `Ok(None)` if the bytes at `start` are not a complete, well-formed sentinel.
pub(crate) fn read_sentinel_at(
    stream: &mut dyn ReadSeek,
    form: SentinelForm,
    start: u64,
) -> Result<Option<Sentinel>> {
    let len = stream_len(stream)?;
    if start >= len {
        return Ok(None);
    }
    stream.seek(SeekFrom::Start(start))?;
    let mut line = Vec::new();
    let mut buf = vec![0u8; SCAN_CHUNK as usize];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(None); // no line ending before EOF: incomplete
        }
        if let Some(i) = buf[..n].iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..=i]);
            break;
        }
        line.extend_from_slice(&buf[..n]);
    }
    match classify_line(strip_line_ending(&line), form) {
        Candidate::Sentinel(reference) => Ok(Some(Sentinel {
            start,
            len: line.len() as u64,
            reference,
        })),
        _ => Ok(None),
    }
}

/// Reads the active checkpoint's manifest reference, if `format` is append-only text.
pub(crate) fn active_reference(
    format: &str,
    stream: &mut dyn ReadSeek,
) -> Result<Option<ManifestReference>> {
    if !is_append_only_format(format) {
        return Ok(None);
    }
    let end = stream_len(stream)?;
    Ok(find_active_sentinel(stream, SentinelForm::for_format(format), end)?.map(|s| s.reference))
}

/// Reads append-only text files that carry checkpoint sentinels. Checkpoints with an
/// inline (`data:`) Manifest Store are returned directly; external URIs are resolved by
/// the store's remote manifest handling.
pub struct AppendOnlyTextIO {
    _asset_type: String,
}

/// Returns the active checkpoint's inline Manifest Store. `Ok(None)` means the file has
/// no checkpoint; `Err(Error::JumbfNotFound)` means the active checkpoint is external.
pub(crate) fn read_active_inline_store(
    reader: &mut dyn ReadSeek,
    form: SentinelForm,
) -> Result<Option<Vec<u8>>> {
    let end = stream_len(reader)?;
    match find_active_sentinel(reader, form, end)? {
        Some(Sentinel {
            reference: ManifestReference::Inline(bytes),
            ..
        }) => Ok(Some(bytes)),
        Some(_) => Err(Error::JumbfNotFound),
        None => Ok(None),
    }
}

impl C2paReader for AppendOnlyTextIO {
    fn read_c2pa(&self, reader: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        read_active_inline_store(reader, SentinelForm::for_format(&self._asset_type))?
            .ok_or(Error::JumbfNotFound)
    }

    fn read_xmp(&self, _asset_reader: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

// With `unstable_plain_text`, `PlainTextIO` owns `txt`/`text/plain` and defers to
// `read_active_inline_store` when a file carries checkpoints.
#[cfg(feature = "unstable_plain_text")]
const SUPPORTED_TYPES: &[&str] = &[
    "jsonl",
    "application/jsonl",
    "application/x-ndjson",
    "application/jsonlines",
    "log",
];
#[cfg(not(feature = "unstable_plain_text"))]
const SUPPORTED_TYPES: &[&str] = &[
    "jsonl",
    "application/jsonl",
    "application/x-ndjson",
    "application/jsonlines",
    "txt",
    "text/plain",
    "log",
];

impl AssetIO for AppendOnlyTextIO {
    fn new(asset_type: &str) -> Self {
        AppendOnlyTextIO {
            _asset_type: asset_type.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(AppendOnlyTextIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn supported_types(&self) -> &[&str] {
        SUPPORTED_TYPES
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    fn active(text: &str, form: SentinelForm) -> Result<Option<Sentinel>> {
        let mut c = Cursor::new(text.as_bytes().to_vec());
        find_active_sentinel(&mut c, form, text.len() as u64)
    }

    const URI: &str = "https://example.com/chk1.c2pa";

    fn armour(r: &str) -> String {
        format!("{BEGIN_CHECKPOINT} {r} {END_CHECKPOINT}")
    }

    #[test]
    fn finds_the_last_armour_sentinel() {
        let text = format!(
            "alpha\n{}\nbravo\n{}\n",
            armour("https://example.com/a"),
            armour(URI)
        );
        let s = active(&text, SentinelForm::Armour).unwrap().unwrap();
        assert_eq!(s.reference, ManifestReference::External(URI.into()));
        assert_eq!(s.start + s.len, text.len() as u64);
        assert_eq!(&text[s.start as usize..s.start as usize + 3], "---");
    }

    #[test]
    fn content_after_the_last_sentinel_is_skipped() {
        let text = format!("alpha\n{}\r\nlate line\npartial", armour(URI));
        let s = active(&text, SentinelForm::Armour).unwrap().unwrap();
        assert_eq!(s.start, 6);
        assert_eq!(s.len, armour(URI).len() as u64 + 2); // CRLF included
    }

    #[test]
    fn no_sentinel_is_none() {
        assert_eq!(
            active("alpha\nbravo\n", SentinelForm::Armour).unwrap(),
            None
        );
        assert_eq!(active("", SentinelForm::Armour).unwrap(), None);
        assert_eq!(active("{\"a\":1}\n", SentinelForm::Json).unwrap(), None);
    }

    #[test]
    fn malformed_or_incomplete_last_sentinel_is_no_sentinel() {
        let missing_end = format!("{}\nalpha\n{BEGIN_CHECKPOINT} {URI}\n", armour(URI));
        let incomplete = format!("alpha\n{}", armour(URI));
        let bad_data_uri = format!("alpha\n{}\n", armour("data:text/plain;base64,AAAA"));
        for text in [missing_end, incomplete, bad_data_uri] {
            let err = active(&text, SentinelForm::Armour).unwrap_err();
            assert!(
                matches!(&err, Error::C2PAValidation(c) if c == validation_status::MANIFEST_APPEND_ONLY_TEXT_NO_SENTINEL),
                "{text:?}: {err:?}"
            );
        }
    }

    #[test]
    fn jsonl_sentinels_and_lookalikes() {
        let text = format!(
            "{{\"msg\":\"mentions c2pa:checkpoint in a value\"}}\n{{\"{JSONL_CHECKPOINT_KEY}\":\"{URI}\"}}\n{{\"nested\":{{\"{JSONL_CHECKPOINT_KEY}\":\"x\"}}}}\n"
        );
        let s = active(&text, SentinelForm::Json).unwrap().unwrap();
        assert_eq!(s.reference, ManifestReference::External(URI.into()));

        let non_string = format!("{{\"{JSONL_CHECKPOINT_KEY}\":7}}\n");
        assert!(active(&non_string, SentinelForm::Json).is_err());

        // Armour delimiters mean nothing in a JSONL file, and vice versa.
        assert_eq!(
            active(&format!("{}\n", armour(URI)), SentinelForm::Json).unwrap(),
            None
        );
    }

    #[test]
    fn inline_reference_is_decoded() {
        let text = format!(
            "x\n{}\n",
            armour(&format!("{DATA_URI_PREFIX}{}", base64::encode(b"store")))
        );
        let s = active(&text, SentinelForm::Armour).unwrap().unwrap();
        assert_eq!(s.reference, ManifestReference::Inline(b"store".to_vec()));
    }

    #[test]
    fn sentinel_scan_crosses_chunk_boundaries() {
        let filler = "z".repeat(SCAN_CHUNK as usize * 2 + 17);
        let text = format!("{}\n{filler}\n{filler}\n", armour(URI));
        let s = active(&text, SentinelForm::Armour).unwrap().unwrap();
        assert_eq!(s.start, 0);
        let mut c = Cursor::new(text.as_bytes().to_vec());
        assert_eq!(
            read_sentinel_at(&mut c, SentinelForm::Armour, 0).unwrap(),
            Some(s)
        );
        assert_eq!(
            read_sentinel_at(&mut c, SentinelForm::Armour, 1).unwrap(),
            None
        );
    }
}
