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

//! Shared ID3v2 utilities used by audio format handlers (MP3, FLAC, …).
//!
//! Both MP3 and FLAC embed C2PA manifests inside ID3v2 GEOB frames.  All of
//! the mechanics around reading, writing, locating, and patching those frames
//! live here so each format handler only needs format-specific logic (header
//! validation, FLAC stream verification, …).

use std::{
    fs::{File, OpenOptions},
    io::{Cursor, Seek, SeekFrom, Write},
    path::Path,
};

use byteorder::{BigEndian, ReadBytesExt};
use id3::{
    frame::{EncapsulatedObject, Private},
    Content, Frame, Tag, TagLike, Version,
};
use memchr::memmem;

use crate::{
    asset_io::{
        rename_or_move, CAIRead, CAIReadWrapper, CAIReadWrite, CAIReadWriteWrapper, CAIReader,
        CAIWriter, HashBlockObjectType, HashObjectPositions, RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::{
        io_utils::{stream_len, tempfile_builder, ReaderUtils},
        xmp_inmemory_utils::{self, MIN_XMP},
    },
};

// ── Constants ──────────────────────────────────────────────────────────────

pub(crate) const GEOB_FRAME_MIME_TYPE: &str = "application/c2pa";
pub(crate) const GEOB_FRAME_MIME_TYPE_DEPRECATED: &str = "application/x-c2pa-manifest-store";
pub(crate) const GEOB_FRAME_FILE_NAME: &str = "c2pa";
pub(crate) const GEOB_FRAME_DESCRIPTION: &str = "c2pa manifest store";

// ── ID3V2Header ─────────────────────────────────────────────────────────────

pub(crate) struct ID3V2Header {
    pub(crate) _version_major: u8,
    pub(crate) _version_minor: u8,
    pub(crate) _flags: u8,
    pub(crate) tag_size: u32,
}

impl ID3V2Header {
    /// Parses a 10-byte slice as an ID3v2 header.
    ///
    /// * Returns `Ok(Some(h))` when the slice starts with `"ID3"` and the
    ///   version is in the supported range (2–4).
    /// * Returns `Err(Error::UnsupportedType)` when it starts with `"ID3"` but
    ///   the version is unsupported.  Callers that need a different error
    ///   variant (e.g. `FlacError::InvalidId3Version`) should map this error.
    /// * Returns `Ok(None)` when the slice does **not** start with `"ID3"`.
    ///   Format-specific fallback (checking for `fLaC`, MPEG sync word, …)
    ///   remains the caller's responsibility.
    pub(crate) fn parse_from_bytes(header: &[u8]) -> Result<Option<ID3V2Header>> {
        if &header[0..3] != b"ID3" {
            return Ok(None);
        }
        let (version_major, version_minor) = (header[3], header[4]);
        if !(2..=4).contains(&version_major) {
            return Err(Error::UnsupportedType);
        }
        let flags = header[5];
        let mut size_reader = Cursor::new(&header[6..10]);
        let encoded_tag_size = size_reader
            .read_u32::<BigEndian>()
            .map_err(|_| Error::InvalidAsset("could not read ID3 tag size".to_string()))?;
        let tag_size = Self::decode_tag_size(encoded_tag_size);
        Ok(Some(ID3V2Header {
            _version_major: version_major,
            _version_minor: version_minor,
            _flags: flags,
            tag_size,
        }))
    }

    /// Returns the total byte count covered by this header (tag body + 10-byte
    /// header itself).
    pub(crate) fn get_size(&self) -> u32 {
        self.tag_size + 10
    }

    fn decode_tag_size(n: u32) -> u32 {
        (n & 0xff) | ((n & 0xff00) >> 1) | ((n & 0xff0000) >> 2) | ((n & 0xff000000) >> 3)
    }
}

// ── Free helpers ────────────────────────────────────────────────────────────

/// Returns `true` for both the current and the deprecated C2PA GEOB MIME type.
pub(crate) fn is_c2pa_mime_type(mime_type: &str) -> bool {
    mime_type == GEOB_FRAME_MIME_TYPE || mime_type == GEOB_FRAME_MIME_TYPE_DEPRECATED
}

/// Returns `(manifest_byte_offset, manifest_byte_length)` within the stream's
/// ID3 tag, or `None` when no single C2PA manifest GEOB frame is found.
pub(crate) fn get_manifest_pos(mut input_stream: &mut dyn CAIRead) -> Result<Option<(u64, u32)>> {
    input_stream.rewind()?;
    let mut buf = [0u8; 10];
    input_stream.read_exact(&mut buf)?;
    let header = ID3V2Header::parse_from_bytes(&buf)?;
    input_stream.rewind()?;

    let reader = CAIReadWrapper {
        reader: input_stream,
    };
    if let Ok(tag) = Tag::read_from2(reader) {
        let mut manifests = Vec::new();
        for eo in tag.encapsulated_objects() {
            if is_c2pa_mime_type(&eo.mime_type) {
                manifests.push(eo.data.clone());
            }
        }
        if manifests.len() == 1 {
            input_stream.rewind()?;
            let tag_bytes = input_stream.read_to_vec(header.map_or(0, |h| h.get_size()) as u64)?;
            if let Some(pos) = memmem::find(&tag_bytes, &manifests[0]) {
                return Ok(Some((pos as u64, manifests[0].len() as u32)));
            }
        }
    }
    Ok(None)
}

/// Reads the XMP string from the PRIV `"XMP"` frame in the ID3 tag, if any.
pub(crate) fn read_xmp_from_id3(input_stream: &mut dyn CAIRead) -> Result<Option<String>> {
    input_stream.rewind()?;
    let reader = CAIReadWrapper {
        reader: input_stream,
    };
    if let Ok(tag) = Tag::read_from2(reader) {
        for frame in tag.frames() {
            if let Content::Private(private) = frame.content() {
                if private.owner_identifier == "XMP" {
                    return Ok(String::from_utf8(private.private_data.clone()).ok());
                }
            }
        }
    }
    Ok(None)
}

/// Writes a new ID3v2.4 tag (with the C2PA manifest replaced or added) then
/// appends the non-ID3 payload from `input_stream` verbatim.
///
/// `id3_end` is the byte offset in `input_stream` at which the audio payload
/// begins — i.e. `header.get_size() as u64` when a pre-existing ID3 tag was
/// found, or `0` when there is none.
pub(crate) fn write_cai_with_id3(
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
    store_bytes: &[u8],
    id3_end: u64,
) -> Result<()> {
    input_stream.rewind()?;
    let mut out_tag = Tag::new();
    let reader = CAIReadWrapper {
        reader: input_stream,
    };
    if let Ok(tag) = Tag::read_from2(reader) {
        for f in tag.frames() {
            match f.content() {
                Content::EncapsulatedObject(eo) => {
                    if !is_c2pa_mime_type(&eo.mime_type) {
                        let _ = out_tag.add_frame(f.clone());
                    }
                }
                _ => {
                    let _ = out_tag.add_frame(f.clone());
                }
            }
        }
    }
    if !store_bytes.is_empty() {
        let frame = Frame::with_content(
            "GEOB",
            Content::EncapsulatedObject(EncapsulatedObject {
                mime_type: GEOB_FRAME_MIME_TYPE.to_string(),
                filename: GEOB_FRAME_FILE_NAME.to_string(),
                description: GEOB_FRAME_DESCRIPTION.to_string(),
                data: store_bytes.to_vec(),
            }),
        );
        let _ = out_tag.add_frame(frame);
    }
    let writer = CAIReadWriteWrapper {
        reader_writer: output_stream,
    };
    out_tag
        .write_to(writer, Version::Id3v24)
        .map_err(|_| Error::EmbeddingError)?;
    input_stream.seek(SeekFrom::Start(id3_end))?;
    std::io::copy(input_stream, output_stream)?;
    Ok(())
}

/// Embeds an XMP remote reference into the ID3 tag then copies the audio
/// payload unchanged.
///
/// `id3_end` — byte offset where the audio payload starts (see
/// [`write_cai_with_id3`]).
/// `current_xmp` — the existing XMP string, if any, used as the base for
/// [`xmp_inmemory_utils::add_provenance`].
pub(crate) fn embed_xmp_to_id3_stream(
    source_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
    url: String,
    id3_end: u64,
    current_xmp: Option<String>,
) -> Result<()> {
    source_stream.rewind()?;
    let mut out_tag = Tag::new();
    let reader = CAIReadWrapper {
        reader: source_stream,
    };
    if let Ok(tag) = Tag::read_from2(reader) {
        for f in tag.frames() {
            match f.content() {
                Content::Private(private) => {
                    if private.owner_identifier != "XMP" {
                        let _ = out_tag.add_frame(f.clone());
                    }
                }
                _ => {
                    let _ = out_tag.add_frame(f.clone());
                }
            }
        }
    }
    let xmp = xmp_inmemory_utils::add_provenance(
        &current_xmp.unwrap_or_else(|| MIN_XMP.to_string()),
        &url,
    )?;
    let frame = Frame::with_content(
        "PRIV",
        Content::Private(Private {
            owner_identifier: "XMP".to_owned(),
            private_data: xmp.into_bytes(),
        }),
    );
    let _ = out_tag.add_frame(frame);
    let writer = CAIReadWriteWrapper {
        reader_writer: output_stream,
    };
    out_tag
        .write_to(writer, Version::Id3v24)
        .map_err(|_| Error::EmbeddingError)?;
    source_stream.seek(SeekFrom::Start(id3_end))?;
    std::io::copy(source_stream, output_stream)?;
    Ok(())
}

/// Computes the three [`HashObjectPositions`] entries (CAI block, bytes before
/// it, bytes after it) from a stream that already contains an ID3 tag with a
/// C2PA manifest GEOB frame.
pub(crate) fn get_object_locations(
    output_stream: &mut dyn CAIRead,
) -> Result<Vec<HashObjectPositions>> {
    let mut positions: Vec<HashObjectPositions> = Vec::new();
    let (manifest_pos, manifest_len) =
        get_manifest_pos(output_stream)?.ok_or(Error::EmbeddingError)?;

    positions.push(HashObjectPositions {
        offset: usize::try_from(manifest_pos)
            .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
        length: usize::try_from(manifest_len)
            .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
        htype: HashBlockObjectType::Cai,
    });
    positions.push(HashObjectPositions {
        offset: 0,
        length: usize::try_from(manifest_pos)
            .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
        htype: HashBlockObjectType::Other,
    });
    let end = manifest_pos
        .checked_add(manifest_len as u64)
        .ok_or_else(|| Error::InvalidAsset("value out of range".to_string()))?;
    let file_end = stream_len(output_stream)?;
    positions.push(HashObjectPositions {
        offset: usize::try_from(end)
            .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
        length: usize::try_from(file_end - end)
            .map_err(|_| Error::InvalidAsset("value out of range".to_string()))?,
        htype: HashBlockObjectType::Other,
    });
    Ok(positions)
}

/// Patches the C2PA manifest in-place within an ID3-tagged asset file.
/// `store_bytes` **must** be the same length as the existing manifest.
#[allow(unused)]
pub(crate) fn patch_cai_in_id3_asset(asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
    let mut asset = OpenOptions::new()
        .write(true)
        .read(true)
        .create(false)
        .open(asset_path)?;
    let (manifest_pos, manifest_len) =
        get_manifest_pos(&mut asset)?.ok_or(Error::EmbeddingError)?;
    if store_bytes.len() == manifest_len as usize {
        asset.seek(SeekFrom::Start(manifest_pos))?;
        asset.write_all(store_bytes)?;
        Ok(())
    } else {
        Err(Error::InvalidAsset(
            "patch_cai_store store size mismatch.".to_string(),
        ))
    }
}

/// Embeds an XMP remote reference into an ID3-tagged asset file in place.
///
/// Opens the file at `asset_path`, delegates to
/// [`RemoteRefEmbed::embed_reference_to_stream`], then writes the result back.
/// Only [`RemoteRefEmbedType::Xmp`] is supported; all other variants return
/// [`Error::UnsupportedType`].
#[allow(unused)]
pub(crate) fn embed_xmp_reference(
    embed: &dyn RemoteRefEmbed,
    asset_path: &std::path::Path,
    embed_ref: RemoteRefEmbedType,
) -> Result<()> {
    match &embed_ref {
        RemoteRefEmbedType::Xmp(_) => {
            let mut input_stream = File::open(asset_path)?;
            let mut output_stream = Cursor::new(Vec::new());
            embed.embed_reference_to_stream(&mut input_stream, &mut output_stream, embed_ref)?;
            std::fs::write(asset_path, output_stream.into_inner())?;
            Ok(())
        }
        _ => Err(Error::UnsupportedType),
    }
}

/// Reads the CAI store from a file on disk via a [`CAIReader`].
pub(crate) fn read_cai_store_from_path(
    reader: &dyn CAIReader,
    asset_path: &Path,
) -> Result<Vec<u8>> {
    let mut f = File::open(asset_path)?;
    reader.read_cai(&mut f)
}

/// Writes `store_bytes` into an ID3-tagged asset file via a [`CAIWriter`],
/// replacing any existing C2PA manifest.
pub(crate) fn save_cai_store_to_path(
    writer: &dyn CAIWriter,
    asset_path: &Path,
    store_bytes: &[u8],
) -> Result<()> {
    let mut input_stream = OpenOptions::new()
        .read(true)
        .write(true)
        .open(asset_path)
        .map_err(Error::IoError)?;
    let mut temp_file = tempfile_builder("c2pa_temp")?;
    writer.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;
    rename_or_move(temp_file, asset_path)
}

/// Returns the [`HashObjectPositions`] for a file on disk via a [`CAIWriter`].
#[allow(unused)]
pub(crate) fn get_object_locations_from_path(
    writer: &dyn CAIWriter,
    asset_path: &Path,
) -> Result<Vec<HashObjectPositions>> {
    let mut f = File::open(asset_path).map_err(|_| Error::EmbeddingError)?;
    writer.get_object_locations_from_stream(&mut f)
}

// ── Shared test helpers ─────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod test_helpers {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::{
        io::{Cursor, Seek},
        path::Path,
    };

    use id3::{
        frame::{Content, EncapsulatedObject},
        Frame, Tag, TagLike, Version,
    };

    use crate::{
        asset_io::{AssetIO, HashBlockObjectType, RemoteRefEmbed, RemoteRefEmbedType},
        error::Error,
        utils::{hash_utils::vec_compare, xmp_inmemory_utils::extract_provenance},
    };

    // ── ID3 builder helpers ──────────────────────────────────────────────────

    /// Build a raw 10-byte ID3v2 header with a synch-safe encoded `tag_size`.
    pub(crate) fn id3_header(version_major: u8, tag_size: u32) -> [u8; 10] {
        let mut h = [0u8; 10];
        h[0..3].copy_from_slice(b"ID3");
        h[3] = version_major;
        h[4] = 0;
        h[5] = 0;
        h[6] = ((tag_size >> 21) & 0x7f) as u8;
        h[7] = ((tag_size >> 14) & 0x7f) as u8;
        h[8] = ((tag_size >> 7) & 0x7f) as u8;
        h[9] = (tag_size & 0x7f) as u8;
        h
    }

    /// Serialise `tag` using the `id3` crate then append `payload` verbatim.
    ///
    /// Used by both MP3 and FLAC tests to build in-memory streams for
    /// testing ID3 frame parsing without needing real audio files.
    pub(crate) fn id3_tag_with_payload(tag: Tag, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        tag.write_to(&mut buf, Version::Id3v24).expect("write id3");
        buf.extend_from_slice(payload);
        buf
    }

    // ── Shared ID3/CAI read_cai tests ────────────────────────────────────────

    /// Any bytes that are neither `"ID3"` nor a format-specific magic word must
    /// cause `read_cai` to return `Error::UnsupportedType`.
    pub(crate) fn run_read_cai_unsupported_type(handler: &dyn AssetIO) {
        let mut buf = [0u8; 10].to_vec();
        buf[0..4].copy_from_slice(b"XXXX");
        let mut cursor = Cursor::new(buf);
        match handler.get_reader().read_cai(&mut cursor) {
            Err(Error::UnsupportedType) => {}
            other => panic!(
                "expected UnsupportedType for unknown magic, got {:?}",
                other
            ),
        }
    }

    /// A stream that is too short to hold a 10-byte header must cause `read_cai`
    /// to return `Error::IoError`.
    pub(crate) fn run_read_cai_io_error_too_short(handler: &dyn AssetIO) {
        let mut cursor = Cursor::new(b"abc");
        match handler.get_reader().read_cai(&mut cursor) {
            Err(Error::IoError(_)) => {}
            other => panic!("expected IoError for short stream, got {:?}", other),
        }
    }

    /// An ID3 tag containing two C2PA GEOB frames must cause `read_cai` to
    /// return `TooManyManifestStores` (or `Ok` with one payload when the id3
    /// crate deduplicates frames with the same ID).
    ///
    /// `audio_payload` is appended after the ID3 tag so format-specific stream
    /// validation (e.g. the FLAC `fLaC` check) can be satisfied by the caller.
    pub(crate) fn run_read_cai_too_many_manifest_stores(
        handler: &dyn AssetIO,
        audio_payload: &[u8],
    ) {
        let mut tag = Tag::new();
        for data in [b"first".as_ref(), b"second".as_ref()] {
            let geob = Frame::with_content(
                "GEOB",
                Content::EncapsulatedObject(EncapsulatedObject {
                    mime_type: super::GEOB_FRAME_MIME_TYPE.to_string(),
                    filename: super::GEOB_FRAME_FILE_NAME.to_string(),
                    description: super::GEOB_FRAME_DESCRIPTION.to_string(),
                    data: data.to_vec(),
                }),
            );
            let _ = tag.add_frame(geob);
        }
        let buf = id3_tag_with_payload(tag, audio_payload);
        let mut cursor = Cursor::new(buf);
        match handler.get_reader().read_cai(&mut cursor) {
            Err(Error::TooManyManifestStores) => {}
            Ok(data) => {
                assert!(
                    data == b"first" || data == b"second",
                    "if one GEOB returned, must be first or second; got {:?}",
                    data
                );
            }
            other => panic!(
                "expected TooManyManifestStores or Ok(first|second), got {:?}",
                other
            ),
        }
    }

    /// Write arbitrary data then read it back and verify round-trip equality.
    pub(crate) fn run_write_read_roundtrip(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        let data = b"some more test data";
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_cai_store(tmp, data).unwrap();
        let read_back = handler.read_cai_store(tmp).unwrap();
        assert!(vec_compare(data, &read_back));
    }

    /// Save data, read back, then patch with a same-length replacement.
    pub(crate) fn run_patch_same_size(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        let test_data = b"some test data";
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_cai_store(tmp, test_data).unwrap();
        let source_data = handler.read_cai_store(tmp).unwrap();
        let mut new_data = vec![0u8; source_data.len()];
        new_data[..test_data.len()].copy_from_slice(test_data);
        handler
            .asset_patch_ref()
            .unwrap()
            .patch_cai_store(tmp, &new_data)
            .unwrap();
        let replaced = handler.read_cai_store(tmp).unwrap();
        assert_eq!(new_data, replaced);
    }

    /// Patching with a wrong-sized buffer must return `InvalidAsset`.
    pub(crate) fn run_patch_size_mismatch(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_cai_store(tmp, &[1, 2, 3, 4]).unwrap();
        match handler
            .asset_patch_ref()
            .unwrap()
            .patch_cai_store(tmp, b"wrong length")
        {
            Err(Error::InvalidAsset(msg))
                if msg.contains("patch_cai_store store size mismatch") => {}
            other => panic!("expected InvalidAsset(size mismatch), got {:?}", other),
        }
    }

    /// Save a manifest then remove it; reading back must yield `JumbfNotFound`.
    pub(crate) fn run_remove_manifest(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_cai_store(tmp, &[1, 2, 3]).unwrap();
        handler.remove_cai_store(tmp).unwrap();
        match handler.read_cai_store(tmp) {
            Err(Error::JumbfNotFound) => {}
            _ => unreachable!(),
        }
    }

    /// Embed an XMP URL, then verify it can be read back.
    pub(crate) fn run_remote_ref_xmp(
        handler: &dyn AssetIO,
        embed: &dyn RemoteRefEmbed,
        fixture: &Path,
    ) {
        let reader = handler.get_reader();
        let mut stream = std::fs::File::open(fixture).unwrap();
        assert_eq!(reader.read_xmp(&mut stream), None);
        stream.rewind().unwrap();

        let mut output = Cursor::new(Vec::new());
        embed
            .embed_reference_to_stream(
                &mut stream,
                &mut output,
                RemoteRefEmbedType::Xmp("Test".to_owned()),
            )
            .unwrap();
        output.rewind().unwrap();
        let xmp = reader.read_xmp(&mut output).unwrap();
        let p = extract_provenance(&xmp).unwrap();
        assert_eq!(&p, "Test");
    }

    /// `get_object_locations` must return exactly 3 entries that span the file.
    pub(crate) fn run_get_object_locations_structure(
        handler: &dyn AssetIO,
        fixture: &Path,
        tmp: &Path,
    ) {
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_cai_store(tmp, &[1, 2, 3, 4, 5]).unwrap();
        let positions = handler.get_object_locations(tmp).unwrap();
        assert_eq!(positions.len(), 3, "expected [Cai, Other, Other]");
        let file_len = std::fs::metadata(tmp).unwrap().len() as usize;
        let sum_len: usize = positions.iter().map(|p| p.length).sum();
        assert_eq!(
            sum_len, file_len,
            "position lengths should sum to file size"
        );
        assert!(positions
            .iter()
            .any(|p| p.htype == HashBlockObjectType::Cai));
        assert!(positions
            .iter()
            .any(|p| p.htype == HashBlockObjectType::Other && p.offset == 0));
    }

    /// `remove_cai_store_from_stream` must produce a stream without a manifest.
    pub(crate) fn run_remove_from_stream(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_cai_store(tmp, &[1, 2, 3]).unwrap();
        let mut input = std::fs::File::open(tmp).unwrap();
        let mut out_buf = Cursor::new(Vec::new());
        handler
            .get_writer("")
            .unwrap()
            .remove_cai_store_from_stream(&mut input, &mut out_buf)
            .unwrap();
        out_buf.set_position(0);
        match handler.get_reader().read_cai(&mut out_buf) {
            Err(Error::JumbfNotFound) => {}
            other => panic!(
                "expected JumbfNotFound after remove_cai_store_from_stream, got {:?}",
                other
            ),
        }
    }

    /// `write_cai` with empty `store_bytes` must remove the manifest.
    pub(crate) fn run_write_cai_empty_removes(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_cai_store(tmp, &[1, 2, 3]).unwrap();
        let mut input = std::fs::File::open(tmp).unwrap();
        let mut out_buf = Cursor::new(Vec::new());
        handler
            .get_writer("")
            .unwrap()
            .write_cai(&mut input, &mut out_buf, &[])
            .unwrap();
        out_buf.set_position(0);
        match handler.get_reader().read_cai(&mut out_buf) {
            Err(Error::JumbfNotFound) => {}
            other => panic!(
                "expected JumbfNotFound after write_cai with empty store, got {:?}",
                other
            ),
        }
    }

    /// Embedding an unsupported reference type must return `UnsupportedType`.
    pub(crate) fn run_embed_reference_unsupported(embed: &dyn RemoteRefEmbed, fixture: &Path) {
        let mut stream = std::fs::File::open(fixture).unwrap();
        let mut output = Cursor::new(Vec::new());
        match embed.embed_reference_to_stream(
            &mut stream,
            &mut output,
            RemoteRefEmbedType::StegoS("x".to_string()),
        ) {
            Err(Error::UnsupportedType) => {}
            other => panic!("expected UnsupportedType for StegoS, got {:?}", other),
        }
    }

    /// Save data, read back, verify.
    pub(crate) fn run_read_cai_success_with_manifest(
        handler: &dyn AssetIO,
        fixture: &Path,
        tmp: &Path,
    ) {
        let payload = b"c2pa manifest payload";
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_cai_store(tmp, payload).unwrap();
        let read = handler.read_cai_store(tmp).unwrap();
        assert!(vec_compare(payload, &read));
    }

    pub(crate) fn run_supported_types(
        handler: &dyn AssetIO,
        expected_ext: &str,
        expected_mime: &str,
    ) {
        let types = handler.supported_types();
        assert!(types.contains(&expected_ext));
        assert!(types.contains(&expected_mime));
        assert_eq!(types.len(), 2);
    }

    pub(crate) fn run_embed_reference_file_path(
        handler: &dyn AssetIO,
        embed: &dyn RemoteRefEmbed,
        fixture: &Path,
        tmp: &Path,
    ) {
        std::fs::copy(fixture, tmp).unwrap();
        embed
            .embed_reference(
                tmp,
                RemoteRefEmbedType::Xmp("https://example.com/ref".to_string()),
            )
            .unwrap();
        let mut f = std::fs::File::open(tmp).unwrap();
        let xmp = handler.get_reader().read_xmp(&mut f).expect("xmp present");
        let p = extract_provenance(&xmp).unwrap();
        assert_eq!(&p, "https://example.com/ref");
    }
}
