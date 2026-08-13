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

//! Plain-text asset handler (C2PA spec A.8): embeds a Manifest Store in unstructured
//! `text/plain` content as a `C2PATextManifestWrapper`, a run of invisible Unicode
//! variation selectors appended after the visible text. Implemented in-tree from the
//! A.8 wire format directly (no third-party C2PA-text crate); the only dependency
//! this feature adds is `unicode-normalization` for NFC, the same class of generic
//! Unicode infrastructure already in this crate's dependency tree.
//!
//! # NFC normalization and the data hash
//!
//! A.8 requires the `c2pa.hash.data` hash to be computed over the NFC-normalized,
//! UTF-8 encoded visible text (with the wrapper excluded). [`AssetIO`] has no hook for
//! a format-specific hash transform: [`crate::utils::hash_utils::hash_stream_by_alg`]
//! hashes the raw bytes outside the reported exclusion, for every handler alike.
//!
//! [`write_cai`](CAIWriter::write_cai) closes that gap the only way available under
//! the current trait surface: it NFC-normalizes the visible text *before* embedding,
//! so the bytes this handler ever writes to disk are already canonical NFC. Raw-byte
//! hashing of a canonical-NFC file is exactly NFC-hashing, so the generic engine
//! produces the spec-correct hash without needing a transform hook.
//!
//! This guarantees correctness for anything this handler embeds. It does not — and,
//! absent a hash-transform hook in [`AssetIO`], cannot — repair a third-party `.txt`
//! asset that was produced non-NFC and never normalized before its hash was computed;
//! verifying such an asset falls back to raw-byte comparison like every other format.
//! That is a limitation of the current [`AssetIO`] surface, not of this handler.

use std::{fs::File, path::Path};

use unicode_normalization::UnicodeNormalization;

use crate::{
    asset_io::{
        rename_or_move, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, HashBlockObjectType,
        HashObjectPositions,
    },
    error::{Error, Result},
    utils::io_utils::{stream_len, tempfile_builder, ReaderUtils},
};

const SUPPORTED_TYPES: [&str; 2] = ["txt", "text/plain"];

/// Used only to size a wrapper before the real manifest is known, so
/// [`get_object_locations_from_stream`](CAIWriter::get_object_locations_from_stream) can report an
/// exclusion range on an asset that does not carry one yet. The real embed always uses the
/// caller's `store_bytes`, never this placeholder.
const PLACEHOLDER_STORE: &[u8] = b"placeholder manifest";

/// The A.8 `C2PATextManifestWrapper` wire format: a `U+FEFF` marker followed by the
/// variation-selector encoding of the frame `magic(8), version(1), big-endian length(4),
/// payload, optional padding`. Ported directly from the specification text (see
/// `embedding_manifests_into_unstructured_text` in the C2PA Technical Specification); no
/// third-party crate involved.
mod wrapper {
    use crate::error::{Error, Result};

    /// Wrapper identifier, `"C2PATXT\0"`.
    pub(super) const MAGIC: [u8; 8] = *b"C2PATXT\0";
    /// Frame version defined by A.8.
    pub(super) const VERSION: u8 = 1;
    /// Zero-Width No-Break Space marking the start of a wrapper.
    pub(super) const MARKER: char = '\u{FEFF}';
    /// `magic(8) + version(1) + length(4)`.
    pub(super) const HEADER_LEN: usize = 13;

    /// A located wrapper and the byte range it occupies in the host text.
    pub(super) struct Wrapper {
        /// The Manifest Store bytes, excluding any trailing padding.
        pub(super) payload: Vec<u8>,
        /// Byte offset of the `U+FEFF` marker in the host text.
        pub(super) start: usize,
        /// Byte length from the marker through the end of the selector run, including
        /// any trailing padding.
        pub(super) length: usize,
    }

    /// A.8's byte-to-variation-selector mapping: 0-15 to the base selectors
    /// (`U+FE00`-`U+FE0F`), 16-255 to the supplementary selectors (`U+E0100`-`U+E01EF`).
    pub(super) fn byte_to_vs(b: u8) -> char {
        let cp = if b <= 15 {
            0xFE00 + b as u32
        } else {
            0xE0100 + (b as u32 - 16)
        };
        // Both ranges (U+FE00-U+FE0F, U+E0100-U+E01EF) are valid, non-surrogate scalar
        // values for every input byte, so this fallback is unreachable; `unwrap_or` avoids
        // a `panic`/`unwrap`/`expect` in production code per this crate's lint policy.
        char::from_u32(cp).unwrap_or('\u{FFFD}')
    }

    /// The inverse of [`byte_to_vs`], or `None` if `c` is not a variation selector A.8 uses.
    fn vs_to_byte(c: char) -> Option<u8> {
        let cp = c as u32;
        if (0xFE00..=0xFE0F).contains(&cp) {
            Some((cp - 0xFE00) as u8)
        } else if (0xE0100..=0xE01EF).contains(&cp) {
            Some((cp - 0xE0100 + 16) as u8)
        } else {
            None
        }
    }

    /// Decodes the maximal run of variation selectors starting at the beginning of `s`,
    /// returning the decoded bytes and how many UTF-8 bytes of `s` they occupied.
    fn decode_run(s: &str) -> (Vec<u8>, usize) {
        let mut bytes = Vec::new();
        let mut consumed = 0;
        for c in s.chars() {
            match vs_to_byte(c) {
                Some(b) => {
                    bytes.push(b);
                    consumed += c.len_utf8();
                }
                None => break,
            }
        }
        (bytes, consumed)
    }

    fn carry(framed: &[u8]) -> String {
        let mut out = String::with_capacity(1 + framed.len() * 4);
        out.push(MARKER);
        out.extend(framed.iter().map(|&b| byte_to_vs(b)));
        out
    }

    fn encode_with_padding(payload: &[u8], padding: &[u8]) -> Result<String> {
        let len = u32::try_from(payload.len()).map_err(|_| Error::EmbeddingError)?;
        let mut framed = Vec::with_capacity(HEADER_LEN + payload.len() + padding.len());
        framed.extend_from_slice(&MAGIC);
        framed.push(VERSION);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(payload);
        framed.extend_from_slice(padding);
        Ok(carry(&framed))
    }

    /// The deterministic target UTF-8 byte length for a manifest of `manifest_len` bytes:
    /// `3 + (13 + M) * 4 + 6`. See A.8's "Deterministic Wrapper Padding".
    fn target_length(manifest_len: usize) -> usize {
        3 + (HEADER_LEN + manifest_len) * 4 + 6
    }

    /// Padding bytes whose selector encoding totals exactly `gap` UTF-8 bytes: `(gap - 4 *
    /// (gap mod 3)) / 3` bytes of `0x00`, then `gap mod 3` bytes of `0x10`, per the
    /// specification's fixed decomposition.
    fn padding(gap: usize) -> Result<Vec<u8>> {
        if gap == 0 {
            return Ok(Vec::new());
        }
        let b = gap % 3;
        if gap < 4 * b {
            // Only 1, 2 and 5 are not expressible as 3a + 4b; the +6 margin in
            // target_length keeps every real wrapper clear of these.
            return Err(Error::EmbeddingError);
        }
        let a = (gap - 4 * b) / 3;
        let mut out = vec![0x00u8; a];
        out.extend(std::iter::repeat_n(0x10u8, b));
        Ok(out)
    }

    /// Encodes `payload` as a v1 wrapper, padded to [`target_length`] so the wrapper's
    /// byte length depends only on the manifest size and not on its byte distribution.
    pub(super) fn encode_padded(payload: &[u8]) -> Result<String> {
        let target = target_length(payload.len());
        let base = encode_with_padding(payload, &[])?;
        let gap = target
            .checked_sub(base.len())
            .ok_or(Error::EmbeddingError)?;
        encode_with_padding(payload, &padding(gap)?)
    }

    /// Common header parse: the end of the declared body, and whether `run` is long
    /// enough to contain it.
    fn frame_bounds(run: &[u8]) -> Option<(usize, bool)> {
        if run.len() < HEADER_LEN || run[..MAGIC.len()] != MAGIC {
            return None;
        }
        let declared = u32::from_be_bytes([run[9], run[10], run[11], run[12]]) as usize;
        let body_end = HEADER_LEN.checked_add(declared)?;
        Some((body_end, run.len() >= body_end))
    }

    fn decode_frame(run: &[u8], start: usize, length: usize) -> Option<Wrapper> {
        let (body_end, declared_ok) = frame_bounds(run)?;
        if run[8] != VERSION || !declared_ok {
            return None;
        }
        Some(Wrapper {
            payload: run[HEADER_LEN..body_end].to_vec(),
            start,
            length,
        })
    }

    /// Visits every `U+FEFF`-prefixed selector run in `text` as `(run, start, length)`.
    fn scan(text: &str, mut visit: impl FnMut(&[u8], usize, usize)) {
        let mut from = 0;
        while let Some(rel) = text[from..].find(MARKER) {
            let start = from + rel;
            let run_start = start + MARKER.len_utf8();
            let (run, consumed) = decode_run(&text[run_start..]);
            let end = run_start + consumed;
            visit(&run, start, end - start);
            // Resume after the run (end >= run_start always, since consumed >= 0), so a
            // marker inside it is not rescanned.
            from = end;
        }
    }

    /// Every valid v1 wrapper in `text`, in order of appearance. A candidate whose magic
    /// matches but whose frame does not decode is skipped, so a mangled run beside a good
    /// one does not discard the asset.
    pub(super) fn locate_all(text: &str) -> Vec<Wrapper> {
        let mut found = Vec::new();
        scan(text, |run, start, length| {
            if let Some(w) = decode_frame(run, start, length) {
                found.push(w);
            }
        });
        found
    }

    /// The single wrapper in `text`, or `None` if there is not exactly one. A.8 leaves
    /// disambiguation among multiple wrappers to the `c2pa.hash.data` exclusions, which
    /// this handler does not attempt to resolve blind; treating "not exactly one" as no
    /// manifest mirrors `structured_text_io`'s handling of multiple A.9 blocks.
    pub(super) fn extract(text: &str) -> Option<Wrapper> {
        let mut found = locate_all(text);
        (found.len() == 1).then(|| found.remove(0))
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::expect_used)]

        use super::*;

        fn embed(text: &str, payload: &[u8]) -> String {
            format!("{text}{}", encode_padded(payload).unwrap())
        }

        #[test]
        fn byte_vs_round_trips_every_value() {
            for b in 0..=255u8 {
                assert_eq!(vs_to_byte(byte_to_vs(b)), Some(b), "byte {b}");
            }
        }

        #[test]
        fn round_trip_locates_the_payload() {
            let asset = embed("Host text.", b"payload-bytes");
            let w = extract(&asset).unwrap();
            assert_eq!(w.payload, b"payload-bytes");
            assert_eq!(w.start, "Host text.".len());
            assert_eq!(w.start + w.length, asset.len());
        }

        /// Fixture generated by `c2pa_text::embed_manifest("hello from c2pa-text ", &(0u8..16u8)
        /// .collect::<Vec<u8>>())` from the published `c2pa-text` 3.0.0 crate (the reference
        /// implementation used by contentauth/c2pa-rs#2117), NOT produced by this codebase.
        /// Confirms our decoder reads the same base wire format (magic, version, marker, VS
        /// ranges) an independent A.8 implementation writes.
        #[test]
        fn decodes_a_wrapper_produced_by_the_reference_implementation() {
            let asset = "hello from c2pa-text \u{feff}\u{e0133}\u{e0122}\u{e0140}\u{e0131}\u{e0144}\u{e0148}\u{e0144}\u{fe00}\u{fe01}\u{fe00}\u{fe00}\u{fe00}\u{e0100}\u{fe00}\u{fe01}\u{fe02}\u{fe03}\u{fe04}\u{fe05}\u{fe06}\u{fe07}\u{fe08}\u{fe09}\u{fe0a}\u{fe0b}\u{fe0c}\u{fe0d}\u{fe0e}\u{fe0f}";
            let w = extract(asset).unwrap();
            assert_eq!(w.payload, (0u8..16u8).collect::<Vec<u8>>());
        }

        #[test]
        fn padded_wrapper_hits_the_deterministic_target() {
            for m in [0usize, 1, 16, 200] {
                let payload = vec![0xABu8; m];
                let padded = encode_padded(&payload).unwrap();
                assert_eq!(padded.len(), target_length(m), "manifest of {m} bytes");
                let w = extract(&format!("host{padded}")).unwrap();
                assert_eq!(w.payload, payload);
            }
        }

        /// Not an externally-published conformance vector — a concrete worked case for the
        /// deterministic-padding formula, to pin the arithmetic against a hand-computed value
        /// rather than relying solely on the round-trip property tests above.
        #[test]
        fn deterministic_padding_matches_a_hand_computed_case() {
            // 16-byte payload: E_target 125, unpadded 114, gap 11 -> one 0x00, two 0x10.
            let payload = b"c2pa-manifest-01";
            let unpadded = encode_with_padding(payload, &[]).unwrap();
            assert_eq!(unpadded.len(), 114);
            assert_eq!(target_length(payload.len()), 125);
            assert_eq!(padding(125 - 114).unwrap(), vec![0x00, 0x10, 0x10]);
            assert_eq!(encode_padded(payload).unwrap().len(), 125);
        }

        #[test]
        fn no_wrapper_and_many_wrappers_both_extract_to_none() {
            assert!(extract("plain text, no wrapper").is_none());
            let one = embed("host", b"a");
            let two = embed(&one, b"b");
            assert_eq!(locate_all(&two).len(), 2);
            assert!(extract(&two).is_none());
        }

        #[test]
        fn a_mangled_candidate_beside_a_valid_one_is_ignored() {
            let mut framed = MAGIC.to_vec();
            framed.push(9); // wrong version
            framed.extend_from_slice(&16u32.to_be_bytes());
            framed.extend_from_slice(b"c2pa-manifest-01");
            let bad = carry(&framed);
            let good = encode_with_padding(b"payload", &[]).unwrap();
            let asset = format!("host{bad}{good}");
            let w = extract(&asset).expect("the valid wrapper is still located");
            assert_eq!(w.payload, b"payload");
            assert_eq!(locate_all(&asset).len(), 1);
        }

        #[test]
        fn legitimate_selectors_in_clean_text_are_not_payloads() {
            let clean = [
                "A perfectly ordinary paragraph with no hidden provenance whatsoever.",
                "Emoji carry legitimate variation selectors: a smiley \u{263A}\u{FE0F}.",
                "A stray zero-width joiner \u{200D} and no-break space \u{FEFF} alone.",
                "\u{FEFF}A leading byte-order mark followed by ordinary prose.",
                "",
            ];
            for s in clean {
                assert!(extract(s).is_none(), "hallucinated provenance in {s:?}");
                assert!(locate_all(s).is_empty());
            }
        }
    }
}

/// Reads a text asset into a `String`. The allocation is checked, so an oversized stream fails
/// with `Error::InsufficientMemory` rather than aborting.
fn read_text_stream(mut reader: &mut dyn CAIRead) -> Result<String> {
    reader.rewind()?;
    let len = stream_len(reader)?;
    let bytes = reader.read_to_vec(len)?;
    String::from_utf8(bytes)
        .map_err(|_| Error::InvalidAsset("text asset is not valid UTF-8".to_string()))
}

/// `c2pa.hash.data` layout: excluded wrapper region, plus content before/after.
fn hash_positions(
    full_len: usize,
    region_start: usize,
    region_len: usize,
) -> Vec<HashObjectPositions> {
    let region_end = region_start + region_len;
    vec![
        HashObjectPositions {
            offset: region_start,
            length: region_len,
            htype: HashBlockObjectType::Cai,
        },
        HashObjectPositions {
            offset: 0,
            length: region_start,
            htype: HashBlockObjectType::Other,
        },
        HashObjectPositions {
            offset: region_end,
            length: full_len.saturating_sub(region_end),
            htype: HashBlockObjectType::Other,
        },
    ]
}

/// Removes every valid wrapper from `text`, in order. `wrapper::locate_all` returns
/// non-overlapping wrappers in ascending `start` order (it scans strictly forward), so a single
/// left-to-right pass is sufficient. A candidate that matches the magic but does not fully decode
/// is left in place as ordinary content, the same treatment `structured_text_io` gives an
/// unterminated delimiter: only bytes that are a *valid* wrapper are ever removed.
fn strip_all_wrappers(text: &str) -> String {
    let wrappers = wrapper::locate_all(text);
    if wrappers.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for w in &wrappers {
        out.push_str(&text[cursor..w.start]);
        cursor = w.start + w.length;
    }
    out.push_str(&text[cursor..]);
    out
}

/// The visible text with every existing wrapper removed, normalized to NFC. Shared by the write
/// and object-locations paths so both always agree on what "clean" text is.
fn normalized_clean_text(text: &str) -> String {
    strip_all_wrappers(text).nfc().collect()
}

pub struct PlainTextIO {
    _asset_type: String,
}

impl CAIReader for PlainTextIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let text = read_text_stream(reader)?;
        let w = wrapper::extract(&text).ok_or(Error::JumbfNotFound)?;
        if w.payload.is_empty() {
            return Err(Error::JumbfNotFound);
        }
        Ok(w.payload)
    }

    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

impl CAIWriter for PlainTextIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let text = read_text_stream(input_stream)?;
        let normalized = normalized_clean_text(&text);
        let framed = wrapper::encode_padded(store_bytes)?;

        output_stream.rewind()?;
        output_stream.write_all(normalized.as_bytes())?;
        output_stream.write_all(framed.as_bytes())?;
        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let text = read_text_stream(input_stream)?;

        let (full_len, region_start, region_len) = match wrapper::extract(&text) {
            Some(w) => (text.len(), w.start, w.length),
            None => {
                // No manifest yet (or what is present is not a single valid wrapper): build on
                // the same normalized-clean-text basis write_cai will use, with a placeholder
                // wrapper standing in for the real one.
                let normalized = normalized_clean_text(&text);
                let framed = wrapper::encode_padded(PLACEHOLDER_STORE)?;
                let with_wrapper = format!("{normalized}{framed}");
                let w = wrapper::extract(&with_wrapper).ok_or(Error::EmbeddingError)?;
                (with_wrapper.len(), w.start, w.length)
            }
        };

        Ok(hash_positions(full_len, region_start, region_len))
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let text = read_text_stream(input_stream)?;
        let cleaned = strip_all_wrappers(&text);
        output_stream.rewind()?;
        output_stream.write_all(cleaned.as_bytes())?;
        Ok(())
    }
}

impl AssetIO for PlainTextIO {
    fn new(asset_type: &str) -> Self {
        PlainTextIO {
            _asset_type: asset_type.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(PlainTextIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(PlainTextIO::new(asset_type)))
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

    fn embed(source: &str, store: &[u8]) -> String {
        let io = PlainTextIO::new("txt");
        let mut input = Cursor::new(source.as_bytes().to_vec());
        let mut output = Cursor::new(Vec::new());
        io.write_cai(&mut input, &mut output, store).unwrap();
        String::from_utf8(output.into_inner()).unwrap()
    }

    fn read_back(text: &str) -> Result<Vec<u8>> {
        let io = PlainTextIO::new("txt");
        let mut input = Cursor::new(text.as_bytes().to_vec());
        io.read_cai(&mut input)
    }

    #[test]
    fn round_trips_a_plain_asset() {
        let out = embed("Hello, provenance.", b"manifest store bytes");
        assert_eq!(read_back(&out).unwrap(), b"manifest store bytes");
    }

    #[test]
    fn unsigned_text_has_no_manifest() {
        assert!(matches!(
            read_back("Just an ordinary sentence."),
            Err(Error::JumbfNotFound)
        ));
    }

    #[test]
    fn object_locations_exclude_exactly_the_wrapper() {
        let out = embed("Visible content.", b"store");
        let io = PlainTextIO::new("txt");
        let mut cursor = Cursor::new(out.clone().into_bytes());
        let locations = io.get_object_locations_from_stream(&mut cursor).unwrap();
        let cai = locations
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Cai)
            .unwrap();
        assert_eq!(cai.offset, "Visible content.".len());
        assert_eq!(cai.offset + cai.length, out.len());
        let other_before = locations
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Other && p.offset == 0)
            .unwrap();
        assert_eq!(other_before.length, "Visible content.".len());
    }

    #[test]
    fn object_locations_with_no_manifest_yet_still_report_a_cai_region() {
        let io = PlainTextIO::new("txt");
        let mut cursor = Cursor::new(b"No manifest here.".to_vec());
        let locations = io.get_object_locations_from_stream(&mut cursor).unwrap();
        let cai = locations
            .iter()
            .find(|p| p.htype == HashBlockObjectType::Cai)
            .unwrap();
        assert!(cai.length > 0);
        assert_eq!(cai.offset, "No manifest here.".len());
    }

    #[test]
    fn replace_strips_the_old_wrapper_and_embeds_the_new_one() {
        let first = embed("Body text.", b"first store");
        let second = embed(&first, b"second store");
        assert_eq!(read_back(&second).unwrap(), b"second store");
        // Exactly one wrapper survives; the first is gone, not just shadowed.
        assert_eq!(wrapper::locate_all(&second).len(), 1);
    }

    #[test]
    fn remove_strips_the_wrapper_and_leaves_visible_text_untouched() {
        let out = embed("Body text.", b"store");
        let io = PlainTextIO::new("txt");
        let mut input = Cursor::new(out.into_bytes());
        let mut output = Cursor::new(Vec::new());
        io.remove_cai_store_from_stream(&mut input, &mut output)
            .unwrap();
        assert_eq!(
            String::from_utf8(output.into_inner()).unwrap(),
            "Body text."
        );
    }

    /// The whole reason `write_cai` normalizes before embedding: two inputs that render
    /// identically but differ in normalization form (NFD vs NFC) must produce byte-identical
    /// visible text once embedded, so a generic raw-byte hash over the non-excluded range is the
    /// spec-mandated NFC hash.
    #[test]
    fn nfc_and_nfd_input_produce_the_same_stored_visible_bytes() {
        // "café résumé" written two ways: precomposed (NFC, U+00E9) and decomposed
        // (NFD, 'e' + U+0301 combining acute accent). Hand-built so the test needs no
        // normalization crate of its own.
        let nfc_host = "caf\u{00E9} r\u{00E9}sum\u{00E9}";
        let nfd_host = "cafe\u{0301} re\u{0301}sume\u{0301}";
        assert_ne!(
            nfc_host.as_bytes(),
            nfd_host.as_bytes(),
            "fixture must actually differ"
        );

        let out_from_nfc = embed(nfc_host, b"store");
        let out_from_nfd = embed(nfd_host, b"store");

        let visible = |asset: &str| {
            let w = wrapper::extract(asset).unwrap();
            asset[..w.start].to_string()
        };
        assert_eq!(visible(&out_from_nfc), visible(&out_from_nfd));
        assert_eq!(visible(&out_from_nfc), nfc_host);
    }

    #[test]
    fn a_lone_corrupted_candidate_is_left_as_ordinary_content_on_write() {
        // A magic-matching but truncated run: not a valid wrapper, so it is not stripped.
        let mut framed = wrapper::MAGIC.to_vec();
        framed.push(wrapper::VERSION);
        framed.extend_from_slice(&99u32.to_be_bytes()); // declares more than it carries
        framed.push(0x41);
        let junk = format!(
            "{}{}",
            wrapper::MARKER,
            framed
                .iter()
                .map(|&b| wrapper::byte_to_vs(b))
                .collect::<String>()
        );
        let src = format!("Body{junk}");
        let out = embed(&src, b"store");
        assert_eq!(read_back(&out).unwrap(), b"store");
        assert!(
            out.contains(&junk),
            "the corrupted candidate must survive untouched, not be silently dropped"
        );
    }

    #[test]
    fn wrong_extension_still_supports_plain_text_type() {
        let io = PlainTextIO::new("text/plain");
        assert!(io.supported_types().contains(&"text/plain"));
        assert!(io.supported_types().contains(&"txt"));
    }
}
