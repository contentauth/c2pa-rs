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

use std::io::{Cursor, Read, SeekFrom};

use byteorder::{BigEndian, ReadBytesExt};
use id3::{
    frame::{EncapsulatedObject, Private},
    Content, Frame, Tag, TagLike, Version,
};
use memchr::memmem;

use crate::{
    asset_io::{ObjectLocations, ObjectType, ReadSeek, ReadWriteSeek},
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
};

// ── Constants ──────────────────────────────────────────────────────────────

pub(crate) const GEOB_FRAME_MIME_TYPE: &str = "application/c2pa";
pub(crate) const GEOB_FRAME_MIME_TYPE_DEPRECATED: &str = "application/x-c2pa-manifest-store";
pub(crate) const GEOB_FRAME_FILE_NAME: &str = "c2pa";

// ── Reading tags safely ────────────────────────────────────────────────────

/// Reads the ID3v2 tag at the stream's current position, or `None` if there is no tag or it
/// can't be parsed. Use this rather than [`Tag::read_from2`] for untrusted input.
///
/// The `id3` crate allocates each frame's declared size before reading it, so a frame header
/// in a tiny file can claim gigabytes (32-bit sizes in ID3v2.3). Such a tag can never parse,
/// since the file doesn't hold that many bytes, so it is rejected before `id3` reads it.
pub(crate) fn read_id3_tag(input_stream: &mut dyn ReadSeek) -> Option<Tag> {
    let start = input_stream.stream_position().ok()?;
    let sizes_ok = frame_sizes_fit(input_stream, start);
    input_stream.seek(SeekFrom::Start(start)).ok()?;
    if !sizes_ok.unwrap_or(true) {
        return None;
    }
    Tag::read_from2(&mut *input_stream).ok()
}

/// Walks the frame headers of the ID3v2 tag at `start` the way the `id3` crate does, without
/// reading frame contents into memory. Returns `Ok(false)` if a frame declares more bytes than
/// remain in the stream, `Ok(true)` otherwise, including when there is no tag or it is
/// malformed in some other way, which `id3` reports itself.
fn frame_sizes_fit(input_stream: &mut dyn ReadSeek, start: u64) -> Result<bool> {
    Ok(walk_frames(input_stream, start, &mut |_, _, _| Ok(()))? != FrameWalk::Oversized)
}

/// How [`walk_frames`] ended.
#[derive(Debug, PartialEq)]
enum FrameWalk {
    /// The stream has no ID3v2 tag, or the tag is malformed in a way `id3` reports itself.
    NoTag,
    /// A frame declares more bytes than remain in the stream.
    Oversized,
    /// Every frame was visited.
    Done,
}

/// Called by [`walk_frames`] with the tag version, the raw frame header and the frame content.
type FrameVisitor<'a> = dyn FnMut(u8, &[u8], &mut dyn Read) -> Result<()> + 'a;

/// Walks the frames of the ID3v2 tag at `start` the way the `id3` crate does, calling
/// `visit(version, frame_header, content)` for each frame. `content` yields at most the
/// frame's declared size, after tag-level unsynchronisation is undone; whatever `visit`
/// leaves unread is skipped without being read into memory.
fn walk_frames(
    input_stream: &mut dyn ReadSeek,
    start: u64,
    visit: &mut FrameVisitor<'_>,
) -> Result<FrameWalk> {
    const UNSYNCHRONISATION: u8 = 0x80;
    const EXTENDED_HEADER: u8 = 0x40;

    let available = stream_len(input_stream)?.saturating_sub(start);
    let mut header = [0u8; 10];
    if input_stream.read_exact(&mut header).is_err() || &header[0..3] != b"ID3" {
        return Ok(FrameWalk::NoTag);
    }
    let (version, flags) = (header[3], header[5]);
    let syncsafe = |b: &[u8]| {
        b.iter()
            .fold(0u64, |size, byte| (size << 7) | u64::from(byte & 0x7f))
    };
    let tag_size = syncsafe(&header[6..10]);

    let mut reader = std::io::BufReader::new(&mut *input_stream);
    let mut ext_size = 0;
    if flags & EXTENDED_HEADER != 0 {
        let mut ext = [0u8; 6];
        if reader.read_exact(&mut ext).is_err() {
            return Ok(FrameWalk::NoTag);
        }
        ext_size = syncsafe(&ext[0..4]);
        if ext_size < 6 {
            return Ok(FrameWalk::NoTag);
        }
        std::io::copy(&mut (&mut reader).take(ext_size - 6), &mut std::io::sink())?;
    }
    let frame_bytes = tag_size.saturating_sub(ext_size);

    // ID3v2.2 is limited to the tag and ID3v2.3 is not, as in `id3`; both may be
    // unsynchronised as a whole. ID3v2.4 has no tag-level unsynchronisation.
    let unsync = flags & UNSYNCHRONISATION != 0 && version <= 3;
    let mut frames: Box<dyn Read + '_> = match (version, unsync) {
        (2, true) => Box::new(Unsynchronised::new(reader.take(frame_bytes))),
        (2, false) => Box::new(reader.take(frame_bytes)),
        (_, true) => Box::new(Unsynchronised::new(reader)),
        (_, false) => Box::new(reader),
    };

    let header_len = if version == 2 { 6 } else { 10 };
    let mut offset = 0u64;
    while offset < frame_bytes {
        let mut frame_header = [0u8; 10];
        if frames.read_exact(&mut frame_header[..header_len]).is_err() || frame_header[0] == 0 {
            break; // end of data, or padding
        }
        let size = match version {
            2 => u64::from(u32::from_be_bytes([
                0,
                frame_header[3],
                frame_header[4],
                frame_header[5],
            ])),
            3 => u64::from(u32::from_be_bytes([
                frame_header[4],
                frame_header[5],
                frame_header[6],
                frame_header[7],
            ])),
            _ => syncsafe(&frame_header[4..8]),
        };
        if size > available {
            return Ok(FrameWalk::Oversized);
        }
        let mut content = (&mut frames).take(size);
        visit(version, &frame_header[..header_len], &mut content)?;
        std::io::copy(&mut content, &mut std::io::sink())?;
        if content.limit() > 0 {
            break; // the frame runs past the end of the data
        }
        offset += header_len as u64 + size;
    }
    Ok(FrameWalk::Done)
}

/// Returns the data of every GEOB frame with a C2PA MIME type in the ID3v2 tag at the start
/// of the stream, in tag order, or `None` if the tag can't be walked.
///
/// The `id3` crate keeps only one GEOB frame per content description when it reads a tag, so
/// two C2PA GEOB frames that share a description look like one, and a later non-C2PA GEOB
/// frame with the same description hides a C2PA one. This visits every GEOB frame with
/// [`walk_frames`] and decodes each on its own, in a one-frame tag of the same version, so
/// `id3` still handles text encodings and frame flags.
fn c2pa_geob_payloads(input_stream: &mut dyn ReadSeek) -> Result<Option<Vec<Vec<u8>>>> {
    input_stream.rewind()?;
    let mut payloads = Vec::new();
    let mut decoded_all = true;
    let walk = walk_frames(input_stream, 0, &mut |version, frame_header, content| {
        let geob_id: &[u8] = if version == 2 { b"GEO" } else { b"GEOB" };
        if !frame_header.starts_with(geob_id) {
            return Ok(());
        }
        // The frame's size is bounded by the stream length, which `walk_frames` checked.
        let mut frame = frame_header.to_vec();
        content.read_to_end(&mut frame)?;
        let size = u32::try_from(frame.len())
            .map_err(|_| Error::InvalidAsset("ID3 frame too large".to_string()))?;
        let mut single = vec![b'I', b'D', b'3', version, 0, 0];
        single.extend_from_slice(&ID3V2Header::encode_tag_size(size).to_be_bytes());
        single.extend_from_slice(&frame);
        match Tag::read_from2(Cursor::new(single)) {
            Ok(tag) => payloads.extend(
                tag.encapsulated_objects()
                    .filter(|eo| is_c2pa_mime_type(&eo.mime_type))
                    .map(|eo| eo.data.clone()),
            ),
            Err(_) => decoded_all = false,
        }
        Ok(())
    })?;
    Ok((walk == FrameWalk::Done && decoded_all).then_some(payloads))
}

/// Reads the C2PA manifest store from the GEOB frame of an ID3v2-tagged stream.
///
/// Returns `Ok(None)` when there is no C2PA GEOB frame, and
/// `Err(Error::TooManyManifestStores)` when there is more than one, including frames that
/// share a content description.
pub(crate) fn read_manifest_from_id3(input_stream: &mut dyn ReadSeek) -> Result<Option<Vec<u8>>> {
    input_stream.rewind()?;
    let Some(tag) = read_id3_tag(&mut *input_stream) else {
        return Ok(None);
    };
    // Fall back to the frames the `id3` crate kept if the tag can't be walked.
    let mut payloads = match c2pa_geob_payloads(input_stream) {
        Ok(Some(payloads)) => payloads,
        _ => tag
            .encapsulated_objects()
            .filter(|eo| is_c2pa_mime_type(&eo.mime_type))
            .map(|eo| eo.data.clone())
            .collect(),
    };
    match payloads.len() {
        0 => Ok(None),
        1 => Ok(payloads.pop()),
        _ => Err(Error::TooManyManifestStores),
    }
}

/// Undoes ID3v2 unsynchronisation: drops each `0x00` that follows `0xFF`.
struct Unsynchronised<R> {
    inner: R,
    after_ff: bool,
}

impl<R: Read> Unsynchronised<R> {
    fn new(inner: R) -> Self {
        Unsynchronised {
            inner,
            after_ff: false,
        }
    }
}

impl<R: Read> Read for Unsynchronised<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut byte = [0u8; 1];
        let mut written = 0;
        while written < buf.len() {
            if self.inner.read(&mut byte)? == 0 {
                break;
            }
            if self.after_ff && byte[0] == 0 {
                self.after_ff = false;
                continue;
            }
            self.after_ff = byte[0] == 0xff;
            buf[written] = byte[0];
            written += 1;
        }
        Ok(written)
    }
}
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

    fn encode_tag_size(n: u32) -> u32 {
        (n & 0x7f) | ((n & 0x3f80) << 1) | ((n & 0x1f_c000) << 2) | ((n & 0x0fe0_0000) << 3)
    }
}

// ── Free helpers ────────────────────────────────────────────────────────────

/// Returns `true` for both the current and the deprecated C2PA GEOB MIME type.
pub(crate) fn is_c2pa_mime_type(mime_type: &str) -> bool {
    mime_type == GEOB_FRAME_MIME_TYPE || mime_type == GEOB_FRAME_MIME_TYPE_DEPRECATED
}

/// Returns `(manifest_byte_offset, manifest_byte_length)` within the stream's
/// ID3 tag, or `None` when no single C2PA manifest GEOB frame is found.
pub(crate) fn get_manifest_pos(mut input_stream: &mut dyn ReadSeek) -> Result<Option<(u64, u32)>> {
    input_stream.rewind()?;
    let mut buf = [0u8; 10];
    input_stream.read_exact(&mut buf)?;
    let header = ID3V2Header::parse_from_bytes(&buf)?;

    if let Ok(Some(manifest)) = read_manifest_from_id3(&mut *input_stream) {
        input_stream.rewind()?;
        let tag_bytes = input_stream.read_to_vec(header.map_or(0, |h| h.get_size()) as u64)?;
        if let Some(pos) = memmem::find(&tag_bytes, &manifest) {
            return Ok(Some((pos as u64, manifest.len() as u32)));
        }
    }
    Ok(None)
}

/// Reads the XMP string from the PRIV `"XMP"` frame in the ID3 tag, if any.
pub(crate) fn read_xmp_from_id3(input_stream: &mut dyn ReadSeek) -> Result<Option<String>> {
    input_stream.rewind()?;
    if let Some(tag) = read_id3_tag(&mut *input_stream) {
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
    input_stream: &mut dyn ReadSeek,
    output_stream: &mut dyn ReadWriteSeek,
    store_bytes: &[u8],
    id3_end: u64,
) -> Result<()> {
    input_stream.rewind()?;
    let mut out_tag = Tag::new();
    if let Some(tag) = read_id3_tag(&mut *input_stream) {
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
    out_tag
        .write_to(&mut *output_stream, Version::Id3v24)
        .map_err(|_| Error::EmbeddingError)?;
    input_stream.seek(SeekFrom::Start(id3_end))?;
    std::io::copy(input_stream, output_stream)?;
    Ok(())
}

/// Writes `xmp` (a complete XMP packet, already final) into a PRIV frame in the
/// ID3 tag, replacing any existing XMP PRIV frame, then appends the non-ID3
/// payload from `source_stream` verbatim.
///
/// `id3_end` — byte offset where the audio payload starts (see
/// [`write_cai_with_id3`]).
pub(crate) fn write_xmp_to_id3_stream(
    source_stream: &mut dyn ReadSeek,
    output_stream: &mut dyn ReadWriteSeek,
    xmp: &str,
    id3_end: u64,
) -> Result<()> {
    source_stream.rewind()?;
    let mut out_tag = Tag::new();
    if let Some(tag) = read_id3_tag(&mut *source_stream) {
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
    let frame = Frame::with_content(
        "PRIV",
        Content::Private(Private {
            owner_identifier: "XMP".to_owned(),
            private_data: xmp.as_bytes().to_vec(),
        }),
    );
    let _ = out_tag.add_frame(frame);
    out_tag
        .write_to(&mut *output_stream, Version::Id3v24)
        .map_err(|_| Error::EmbeddingError)?;
    source_stream.seek(SeekFrom::Start(id3_end))?;
    std::io::copy(source_stream, output_stream)?;
    Ok(())
}

/// Computes the three [`HashObjectPositions`] entries (CAI block, bytes before
/// it, bytes after it) from a stream that already contains an ID3 tag with a
/// C2PA manifest GEOB frame.
pub(crate) fn get_object_locations(
    output_stream: &mut dyn ReadSeek,
) -> Result<Vec<ObjectLocations>> {
    let mut positions: Vec<ObjectLocations> = Vec::new();
    let (manifest_pos, manifest_len) =
        get_manifest_pos(output_stream)?.ok_or(Error::EmbeddingError)?;

    positions.push(ObjectLocations {
        offset: manifest_pos,
        length: manifest_len as u64,
        htype: ObjectType::C2pa,
    });
    positions.push(ObjectLocations {
        offset: 0,
        length: manifest_pos,
        htype: ObjectType::Other,
    });
    let end = manifest_pos
        .checked_add(manifest_len as u64)
        .ok_or_else(|| Error::InvalidAsset("value out of range".to_string()))?;
    let file_end = stream_len(output_stream)?;
    positions.push(ObjectLocations {
        offset: end,
        length: file_end - end,
        htype: ObjectType::Other,
    });
    Ok(positions)
}

/// Patches the C2PA manifest in-place within an ID3-tagged asset file.
/// `store_bytes` **must** be the same length as the existing manifest.
#[allow(unused)]
pub(crate) fn patch_cai_in_id3_stream(
    stream: &mut dyn ReadWriteSeek,
    store_bytes: &[u8],
) -> Result<()> {
    let (manifest_pos, manifest_len) = get_manifest_pos(stream)?.ok_or(Error::EmbeddingError)?;
    if store_bytes.len() == manifest_len as usize {
        stream.seek(SeekFrom::Start(manifest_pos))?;
        stream.write_all(store_bytes)?;
        Ok(())
    } else {
        Err(Error::InvalidAsset(
            "patch_cai_store store size mismatch.".to_string(),
        ))
    }
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
        asset_io::{AssetIO, ObjectType, RemoteManifestUrl},
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

    // ── Shared ID3/CAI read_cai tests ────────────────────────────────────────

    /// Any bytes that are neither `"ID3"` nor a format-specific magic word must
    /// cause `read_cai` to return `Error::UnsupportedType`.
    pub(crate) fn run_read_cai_unsupported_type(handler: &dyn AssetIO) {
        let mut buf = [0u8; 10].to_vec();
        buf[0..4].copy_from_slice(b"XXXX");
        let mut cursor = Cursor::new(buf);
        match handler.get_reader().read_c2pa(&mut cursor) {
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
        match handler.get_reader().read_c2pa(&mut cursor) {
            Err(Error::IoError(_)) => {}
            other => panic!("expected IoError for short stream, got {:?}", other),
        }
    }

    /// Builds an ID3v2 tag holding exactly `frames`, in order, then appends
    /// `payload`.
    ///
    /// The `id3` crate replaces a frame that matches one already in a tag (for
    /// GEOB, one with the same content description), so each frame is encoded
    /// in a tag of its own and the encoded frames are joined by hand.
    pub(crate) fn id3_tag_with_frames(
        version: Version,
        frames: &[Frame],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        for frame in frames {
            let mut tag = Tag::new();
            tag.add_frame(frame.clone());
            let mut single = Vec::new();
            tag.write_to(&mut single, version).expect("write id3");
            let size = u32::from_be_bytes(single[14..18].try_into().unwrap());
            let size = match version {
                Version::Id3v24 => super::ID3V2Header::decode_tag_size(size),
                _ => size,
            } as usize;
            body.extend_from_slice(&single[10..20 + size]);
        }
        let major = match version {
            Version::Id3v22 => 2,
            Version::Id3v23 => 3,
            Version::Id3v24 => 4,
        };
        let mut buf = id3_header(major, body.len() as u32).to_vec();
        buf.extend_from_slice(&body);
        buf.extend_from_slice(payload);
        buf
    }

    /// A GEOB frame with the given MIME type, the C2PA file name and
    /// description, and `data`.
    pub(crate) fn geob(mime_type: &str, data: &[u8]) -> Frame {
        Frame::with_content(
            "GEOB",
            Content::EncapsulatedObject(EncapsulatedObject {
                mime_type: mime_type.to_string(),
                filename: super::GEOB_FRAME_FILE_NAME.to_string(),
                description: super::GEOB_FRAME_DESCRIPTION.to_string(),
                data: data.to_vec(),
            }),
        )
    }

    /// An ID3 tag containing two C2PA GEOB frames must cause `read_cai` to
    /// return `TooManyManifestStores`, including when the frames share a
    /// content description or are identical.
    ///
    /// `audio_payload` is appended after the ID3 tag so format-specific stream
    /// validation (e.g. the FLAC `fLaC` check) can be satisfied by the caller.
    pub(crate) fn run_read_cai_too_many_manifest_stores(
        handler: &dyn AssetIO,
        audio_payload: &[u8],
    ) {
        let mime = super::GEOB_FRAME_MIME_TYPE;
        let cases: [(&str, [Frame; 2]); 2] = [
            (
                "different data",
                [geob(mime, b"first"), geob(mime, b"second")],
            ),
            (
                "identical frames",
                [geob(mime, b"same"), geob(mime, b"same")],
            ),
        ];
        for version in [Version::Id3v23, Version::Id3v24] {
            for (name, frames) in &cases {
                let buf = id3_tag_with_frames(version, frames, audio_payload);
                match handler.get_reader().read_c2pa(&mut Cursor::new(buf)) {
                    Err(Error::TooManyManifestStores) => {}
                    other => {
                        panic!("{version:?}, {name}: expected TooManyManifestStores, got {other:?}")
                    }
                }
            }
        }
    }

    /// A non-C2PA GEOB frame with the same content description as the C2PA
    /// GEOB frame, placed after it, must not hide the manifest.
    pub(crate) fn run_read_cai_c2pa_geob_not_hidden(handler: &dyn AssetIO, audio_payload: &[u8]) {
        for version in [Version::Id3v23, Version::Id3v24] {
            let frames = [
                geob(super::GEOB_FRAME_MIME_TYPE, b"manifest"),
                geob("text/plain", b"not a manifest"),
            ];
            let buf = id3_tag_with_frames(version, &frames, audio_payload);
            match handler.get_reader().read_c2pa(&mut Cursor::new(buf)) {
                Ok(data) => assert_eq!(data, b"manifest", "{version:?}"),
                other => panic!("{version:?}: expected the manifest, got {other:?}"),
            }
        }
    }

    /// An ID3v2.4 extended header before the frames must not stop the reader
    /// from seeing both C2PA GEOB frames.
    pub(crate) fn run_read_cai_too_many_manifest_stores_extended_header(
        handler: &dyn AssetIO,
        audio_payload: &[u8],
    ) {
        let mime = super::GEOB_FRAME_MIME_TYPE;
        let mut buf = id3_tag_with_frames(
            Version::Id3v24,
            &[geob(mime, b"same"), geob(mime, b"same")],
            &[],
        );
        // Minimal v2.4 extended header: size 6 (synchsafe, includes itself),
        // one flag byte, no flags set.
        let ext = [0, 0, 0, 6, 1, 0];
        let tag_size =
            super::ID3V2Header::decode_tag_size(u32::from_be_bytes(buf[6..10].try_into().unwrap()))
                + ext.len() as u32;
        buf.splice(10..10, ext);
        buf[5] |= 0x40;
        buf[6..10].copy_from_slice(&id3_header(4, tag_size)[6..10]);
        buf.extend_from_slice(audio_payload);
        match handler.get_reader().read_c2pa(&mut Cursor::new(buf)) {
            Err(Error::TooManyManifestStores) => {}
            other => panic!("expected TooManyManifestStores, got {other:?}"),
        }
    }

    /// Regression test for CAI-13353 (VULN-38328): an ID3v2.4 frame using the
    /// COMPRESSION + DATA_LENGTH_INDICATOR flags could decompress to
    /// gigabytes from a tiny on-disk payload, OOM-killing the process.
    /// `id3` 1.17.2 caps decoded frame content at 256 MiB
    /// (`MAX_FRAME_CONTENT_SIZE` in `stream::frame::content`); this builds a
    /// frame that inflates just past that cap and asserts the read fails
    /// fast instead of exhausting memory.
    pub(crate) fn run_read_cai_zlib_bomb_rejected(handler: &dyn AssetIO, audio_payload: &[u8]) {
        use std::io::Write;

        use flate2::{write::ZlibEncoder, Compression};

        fn synchsafe(n: u32) -> [u8; 4] {
            [
                ((n >> 21) & 0x7f) as u8,
                ((n >> 14) & 0x7f) as u8,
                ((n >> 7) & 0x7f) as u8,
                (n & 0x7f) as u8,
            ]
        }

        // Highly-compressible payload that inflates to just past id3's 256
        // MiB cap while compressing down to a few hundred bytes on disk.
        const INFLATED_LEN: u64 = 256 * 1024 * 1024 + 1024 * 1024;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        let chunk = vec![0u8; 1024 * 1024];
        let mut written = 0u64;
        while written < INFLATED_LEN {
            let n = std::cmp::min(chunk.len() as u64, INFLATED_LEN - written) as usize;
            encoder.write_all(&chunk[..n]).expect("compress chunk");
            written += n as u64;
        }
        let compressed = encoder.finish().expect("finish zlib stream");

        // Frame content: 4-byte data-length-indicator (its value is ignored
        // by the reader, only its presence matters) + the compressed bytes.
        let mut frame_content = synchsafe(0).to_vec();
        frame_content.extend_from_slice(&compressed);

        let mut frame = Vec::new();
        frame.extend_from_slice(b"TXXX");
        frame.extend_from_slice(&synchsafe(frame_content.len() as u32));
        frame.extend_from_slice(&0x0009u16.to_be_bytes()); // COMPRESSION | DATA_LENGTH_INDICATOR
        frame.extend_from_slice(&frame_content);

        let mut buf = id3_header(4, frame.len() as u32).to_vec();
        buf.extend_from_slice(&frame);
        buf.extend_from_slice(audio_payload);
        let mut cursor = Cursor::new(buf);

        let start = std::time::Instant::now();
        let result = handler.get_reader().read_c2pa(&mut cursor);
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "zlib-bomb ID3 frame took too long to reject: {:?}",
            elapsed
        );
        match result {
            Err(_) => {}
            Ok(data) => panic!(
                "expected zlib-bomb ID3 frame to be rejected, got Ok({} bytes)",
                data.len()
            ),
        }
    }

    /// Write arbitrary data then read it back and verify round-trip equality.
    pub(crate) fn run_write_read_roundtrip(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        let data = b"some more test data";
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_c2pa_store(tmp, data).unwrap();
        let read_back = handler.read_cai_store(tmp).unwrap();
        assert!(vec_compare(data, &read_back));
    }

    /// Save data, read back, then patch with a same-length replacement.
    pub(crate) fn run_patch_same_size(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        let test_data = b"some test data";
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_c2pa_store(tmp, test_data).unwrap();
        let source_data = handler.read_cai_store(tmp).unwrap();
        let mut new_data = vec![0u8; source_data.len()];
        new_data[..test_data.len()].copy_from_slice(test_data);
        handler
            .asset_patch_ref()
            .unwrap()
            .patch_c2pa_file(tmp, &new_data)
            .unwrap();
        let replaced = handler.read_cai_store(tmp).unwrap();
        assert_eq!(new_data, replaced);
    }

    /// Patching with a wrong-sized buffer must return `InvalidAsset`.
    pub(crate) fn run_patch_size_mismatch(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_c2pa_store(tmp, &[1, 2, 3, 4]).unwrap();
        match handler
            .asset_patch_ref()
            .unwrap()
            .patch_c2pa_file(tmp, b"wrong length")
        {
            Err(Error::InvalidAsset(msg))
                if msg.contains("patch_cai_store store size mismatch") => {}
            other => panic!("expected InvalidAsset(size mismatch), got {:?}", other),
        }
    }

    /// Save a manifest then remove it; reading back must yield `JumbfNotFound`.
    pub(crate) fn run_remove_manifest(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_c2pa_store(tmp, &[1, 2, 3]).unwrap();
        handler.remove_c2pa_store(tmp).unwrap();
        match handler.read_cai_store(tmp) {
            Err(Error::JumbfNotFound) => {}
            _ => unreachable!(),
        }
    }

    /// Write a remote manifest URL, then verify it can be read back.
    pub(crate) fn run_remote_ref_xmp(
        handler: &dyn AssetIO,
        embed: &dyn RemoteManifestUrl,
        fixture: &Path,
    ) {
        let reader = handler.get_reader();
        let mut stream = std::fs::File::open(fixture).unwrap();
        assert_eq!(reader.read_xmp(&mut stream), None);
        stream.rewind().unwrap();

        let mut output = Cursor::new(Vec::new());
        embed
            .write_remote_manifest_url(&mut stream, &mut output, "Test")
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
        handler.save_c2pa_store(tmp, &[1, 2, 3, 4, 5]).unwrap();
        let mut f = std::fs::File::open(tmp).unwrap();
        let positions = handler
            .get_writer("")
            .unwrap()
            .get_object_locations(&mut f)
            .unwrap();
        assert_eq!(positions.len(), 3, "expected [Cai, Other, Other]");
        let file_len = std::fs::metadata(tmp).unwrap().len();
        let sum_len: u64 = positions.iter().map(|p| p.length).sum();
        assert_eq!(
            sum_len, file_len,
            "position lengths should sum to file size"
        );
        assert!(positions.iter().any(|p| p.htype == ObjectType::C2pa));
        assert!(positions
            .iter()
            .any(|p| p.htype == ObjectType::Other && p.offset == 0));
    }

    /// `remove_cai_store_from_stream` must produce a stream without a manifest.
    pub(crate) fn run_remove_from_stream(handler: &dyn AssetIO, fixture: &Path, tmp: &Path) {
        std::fs::copy(fixture, tmp).unwrap();
        handler.save_c2pa_store(tmp, &[1, 2, 3]).unwrap();
        let mut input = std::fs::File::open(tmp).unwrap();
        let mut out_buf = Cursor::new(Vec::new());
        handler
            .get_writer("")
            .unwrap()
            .remove_c2pa(&mut input, &mut out_buf)
            .unwrap();
        out_buf.set_position(0);
        match handler.get_reader().read_c2pa(&mut out_buf) {
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
        handler.save_c2pa_store(tmp, &[1, 2, 3]).unwrap();
        let mut input = std::fs::File::open(tmp).unwrap();
        let mut out_buf = Cursor::new(Vec::new());
        handler
            .get_writer("")
            .unwrap()
            .write_c2pa(&mut input, &mut out_buf, &[])
            .unwrap();
        out_buf.set_position(0);
        match handler.get_reader().read_c2pa(&mut out_buf) {
            Err(Error::JumbfNotFound) => {}
            other => panic!(
                "expected JumbfNotFound after write_cai with empty store, got {:?}",
                other
            ),
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
        handler.save_c2pa_store(tmp, payload).unwrap();
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
    }

    pub(crate) fn run_embed_reference_file_path(
        handler: &dyn AssetIO,
        embed: &dyn RemoteManifestUrl,
        fixture: &Path,
        tmp: &Path,
    ) {
        std::fs::copy(fixture, tmp).unwrap();
        let mut input_stream = std::fs::File::open(tmp).unwrap();
        let mut output_stream = Cursor::new(Vec::new());
        embed
            .write_remote_manifest_url(
                &mut input_stream,
                &mut output_stream,
                "https://example.com/ref",
            )
            .unwrap();
        std::fs::write(tmp, output_stream.into_inner()).unwrap();

        let mut f = std::fs::File::open(tmp).unwrap();
        let xmp = handler.get_reader().read_xmp(&mut f).expect("xmp present");
        let p = extract_provenance(&xmp).unwrap();
        assert_eq!(&p, "https://example.com/ref");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use id3::{Tag, TagLike, Version};

    use super::*;

    fn syncsafe(size: u32) -> [u8; 4] {
        [
            (size >> 21) as u8 & 0x7f,
            (size >> 14) as u8 & 0x7f,
            (size >> 7) as u8 & 0x7f,
            size as u8 & 0x7f,
        ]
    }

    /// An ID3v2 tag with one frame whose header declares `declared` bytes but which holds only
    /// 16, followed by some audio-like bytes.
    fn oversized_frame(version: u8, declared: u32) -> Vec<u8> {
        let mut frame = Vec::new();
        match version {
            2 => {
                frame.extend(b"TT2");
                frame.extend(&declared.to_be_bytes()[1..]);
            }
            3 => {
                frame.extend(b"TIT2");
                frame.extend(declared.to_be_bytes());
                frame.extend([0, 0]);
            }
            _ => {
                frame.extend(b"TIT2");
                frame.extend(syncsafe(declared));
                frame.extend([0, 0]);
            }
        }
        frame.extend([0u8; 16]);

        let mut tag = b"ID3".to_vec();
        tag.extend([version, 0, 0]);
        tag.extend(syncsafe(frame.len() as u32));
        tag.extend(frame);
        tag.extend([0xff, 0xfb, 0x90, 0x00]);
        tag.extend([0u8; 64]);
        tag
    }

    fn fits(data: &[u8]) -> bool {
        frame_sizes_fit(&mut Cursor::new(data), 0).unwrap()
    }

    #[test]
    fn test_rejects_frames_larger_than_the_file() {
        // Found by fuzzing: one flipped bit makes an ID3v2.3 TIT2 frame claim 0x40000003 bytes
        // in a 445-byte file, and `id3` allocated 1 GiB before failing.
        let bomb = include_bytes!("../../tests/fixtures/id3v23_frame_size_bomb.mp3");
        assert!(!fits(bomb));
        assert!(read_id3_tag(&mut Cursor::new(bomb)).is_none());

        for (version, declared) in [(2, 0x00ff_ffff), (3, 0x4000_0003), (4, 0x0fff_ffff)] {
            let data = oversized_frame(version, declared);
            assert!(!fits(&data), "ID3v2.{version}");
            assert!(read_id3_tag(&mut Cursor::new(&data)).is_none());
        }
    }

    #[test]
    fn test_accepts_valid_tags() {
        for version in [Version::Id3v23, Version::Id3v24] {
            let mut tag = Tag::new();
            tag.set_title("A title");
            tag.set_artist("An artist");
            let mut data = Vec::new();
            tag.write_to(&mut data, version).unwrap();
            data.extend([0xff, 0xfb, 0x90, 0x00]);

            assert!(fits(&data), "{version:?}");
            let read = read_id3_tag(&mut Cursor::new(&data)).unwrap();
            assert_eq!(read.title(), Some("A title"));
        }

        // A frame that fits exactly is not rejected.
        let mut exact = oversized_frame(3, 16);
        exact.truncate(10 + 10 + 16);
        assert!(fits(&exact));
    }

    #[test]
    fn test_unsynchronised_tag_is_walked_after_decoding() {
        // ID3v2.3 with tag-level unsynchronisation. The TIT2 frame's size is 0xFF, so its header
        // contains `FF 00 00`, written as `FF 00 00 00`: walking the raw bytes would misread the
        // frame, so the guard must undo the unsynchronisation as `id3` does.
        let mut frame = b"TIT2".to_vec();
        frame.extend(0xffu32.to_be_bytes());
        frame.extend([0, 0]);
        frame.push(0); // ISO-8859-1
        frame.extend(vec![b'x'; 0xfe]);

        let mut unsynchronised = Vec::new();
        for byte in frame {
            unsynchronised.push(byte);
            if byte == 0xff {
                unsynchronised.push(0);
            }
        }
        let mut data = b"ID3".to_vec();
        data.extend([3, 0, 0x80]);
        data.extend(syncsafe(unsynchronised.len() as u32));
        data.extend(unsynchronised);
        data.extend([0xff, 0xfb, 0x90, 0x00]);

        assert!(fits(&data));
        let read = read_id3_tag(&mut Cursor::new(&data)).unwrap();
        assert_eq!(read.title().map(str::len), Some(0xfe));
    }

    #[test]
    fn test_no_tag() {
        let data = [0xff, 0xfb, 0x90, 0x00, 1, 2, 3, 4];
        assert!(fits(&data));
        assert!(read_id3_tag(&mut Cursor::new(&data[..])).is_none());
    }

    #[test]
    fn test_reads_from_the_current_position() {
        // The guard walks the tag from where the stream is, then returns there for `id3`.
        let mut tag = Tag::new();
        tag.set_title("At offset 2");
        let mut data = vec![0xaa, 0xbb];
        tag.write_to(&mut data, Version::Id3v23).unwrap();

        let mut stream = Cursor::new(&data[..]);
        stream.set_position(2);
        let read = read_id3_tag(&mut stream).unwrap();
        assert_eq!(read.title(), Some("At offset 2"));
    }
}
