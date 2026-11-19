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

//! Support for embedding/extracting a C2PA Manifest Store in Standard MIDI
//! Files (SMF), per the "Embedding manifests into Standard MIDI Files"
//! section of the C2PA specification draft.
//!
//! The manifest is carried as a Sequencer-Specific Meta Event (`FF 7F`),
//! tagged with the 3-byte extended manufacturer identifier `00 43 32`
//! ("C2"), placed immediately before the End of Track event (`FF 2F`) of a
//! single designated `MTrk` chunk (sole track for Format 0, last track for
//! Format 1, first track for Format 2).
//!
//! Unlike [`crate::asset_handlers::riff_io`], the manifest is not a
//! top-level sibling chunk: it lives inside the event stream of one track,
//! so locating it requires walking MIDI events (delta-time VLQs, running
//! status, meta/sysex/channel messages) rather than a flat chunk list.

use std::io::{Cursor, SeekFrom};

use byteorder::{BigEndian, ReadBytesExt};

use crate::{
    asset_io::{
        AssetIO, AssetPatch, C2paReader, C2paWriter, ObjectLocations, ObjectType, ReadSeek,
        ReadWriteSeek,
    },
    error::{Error, Result},
};

static SUPPORTED_TYPES: [&str; 5] = ["mid", "midi", "audio/mid", "audio/midi", "audio/x-midi"];

const MTHD_ID: [u8; 4] = *b"MThd";
const MTRK_ID: [u8; 4] = *b"MTrk";

const META_EVENT: u8 = 0xFF;
const META_END_OF_TRACK: u8 = 0x2F;
const META_SEQUENCER_SPECIFIC: u8 = 0x7F;

/// The C2PA extended manufacturer identifier: `0x00` (extended-ID marker)
/// followed by the ASCII bytes "C2".
const C2PA_MANUFACTURER_ID: [u8; 3] = [0x00, 0x43, 0x32];

/// Standard MIDI File VLQ fields (delta-times, meta/sysex lengths) are
/// conventionally capped at 4 bytes (28 bits). Enforcing this bound also
/// guards the parser against unbounded loops on forged/malformed input.
const MAX_VLQ_BYTES: usize = 4;

pub struct MidiIO {
    #[allow(dead_code)]
    midi_format: String, // reserved for future format-specific handling
}

/// Reads a MIDI variable-length quantity starting at `data[pos]`.
/// Returns `(value, bytes_consumed)`.
fn read_vlq(data: &[u8], pos: usize) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut consumed = 0usize;

    loop {
        let idx = pos
            .checked_add(consumed)
            .ok_or_else(|| Error::InvalidAsset("MIDI VLQ offset overflow".to_string()))?;
        let byte = *data
            .get(idx)
            .ok_or_else(|| Error::InvalidAsset("MIDI VLQ truncated".to_string()))?;

        value = (value << 7) | u32::from(byte & 0x7f);
        consumed += 1;

        if byte & 0x80 == 0 {
            break;
        }
        if consumed >= MAX_VLQ_BYTES {
            return Err(Error::InvalidAsset(
                "MIDI VLQ exceeds maximum length".to_string(),
            ));
        }
    }

    Ok((value, consumed))
}

/// Encodes `value` as a MIDI variable-length quantity.
fn write_vlq(mut value: u32) -> Vec<u8> {
    let mut bytes = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        bytes.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    bytes
}

/// Span of a Sequencer-Specific Meta Event found while scanning a track,
/// tagged with the C2PA extended manufacturer identifier.
struct C2paEventSpan {
    // Byte range of the *entire* event (delta-time through event data),
    // relative to the start of the track's event data. Used to splice the
    // event out when replacing/removing the manifest.
    event_start: usize,
    event_end: usize,
    // Byte range of just the manifest payload (i.e. following the 3-byte
    // manufacturer id), relative to the start of the track's event data.
    manifest_start: usize,
    manifest_len: usize,
}

struct TrackScan {
    // Offset of the End of Track (FF 2F) event's delta-time byte, relative
    // to the start of the track's event data.
    eot_event_start: usize,
    // All C2PA-tagged Sequencer-Specific Meta Events found. Per spec, a
    // valid file has exactly one; zero or more than one are both treated
    // as "no manifest located" by the caller.
    c2pa_events: Vec<C2paEventSpan>,
}

/// Walks a track chunk's raw event data, tracking running status, until the
/// End of Track event is reached. Collects any C2PA-tagged
/// Sequencer-Specific Meta Events encountered along the way.
fn scan_track(data: &[u8]) -> Result<TrackScan> {
    let mut pos = 0usize;
    let mut running_status: Option<u8> = None;
    let mut c2pa_events = Vec::new();

    loop {
        let event_start = pos;

        let (_delta, n) = read_vlq(data, pos)?;
        pos += n;

        let status_byte = *data.get(pos).ok_or_else(|| {
            Error::InvalidAsset("MIDI track ended before End of Track event".to_string())
        })?;

        // Meta (0xFF) and sysex (0xF0/0xF7) events always carry an explicit
        // status byte and cancel any running status. Channel voice/mode
        // messages (0x80-0xEF) may omit the status byte and reuse the last
        // one seen.
        let status = if status_byte & 0x80 != 0 {
            pos += 1;
            running_status = if status_byte < 0xF0 {
                Some(status_byte)
            } else {
                None
            };
            status_byte
        } else {
            running_status.ok_or_else(|| {
                Error::InvalidAsset(
                    "MIDI event relies on running status with none active".to_string(),
                )
            })?
        };

        match status {
            META_EVENT => {
                let meta_type = *data
                    .get(pos)
                    .ok_or_else(|| Error::InvalidAsset("MIDI meta event truncated".to_string()))?;
                pos += 1;

                let (len, n) = read_vlq(data, pos)?;
                pos += n;
                let len = len as usize;

                let data_start = pos;
                let data_end = data_start.checked_add(len).ok_or_else(|| {
                    Error::InvalidAsset("MIDI meta event length overflow".to_string())
                })?;
                if data_end > data.len() {
                    return Err(Error::InvalidAsset(
                        "MIDI meta event length exceeds track data".to_string(),
                    ));
                }

                if meta_type == META_END_OF_TRACK {
                    return Ok(TrackScan {
                        eot_event_start: event_start,
                        c2pa_events,
                    });
                }

                if meta_type == META_SEQUENCER_SPECIFIC
                    && len >= C2PA_MANUFACTURER_ID.len()
                    && data[data_start..data_start + C2PA_MANUFACTURER_ID.len()]
                        == C2PA_MANUFACTURER_ID
                {
                    c2pa_events.push(C2paEventSpan {
                        event_start,
                        event_end: data_end,
                        manifest_start: data_start + C2PA_MANUFACTURER_ID.len(),
                        manifest_len: len - C2PA_MANUFACTURER_ID.len(),
                    });
                }

                pos = data_end;
            }
            0xF0 | 0xF7 => {
                let (len, n) = read_vlq(data, pos)?;
                pos += n;
                let len = len as usize;

                let data_end = pos.checked_add(len).ok_or_else(|| {
                    Error::InvalidAsset("MIDI sysex event length overflow".to_string())
                })?;
                if data_end > data.len() {
                    return Err(Error::InvalidAsset(
                        "MIDI sysex event length exceeds track data".to_string(),
                    ));
                }
                pos = data_end;
            }
            0x80..=0xEF => {
                let n_data_bytes = match status & 0xF0 {
                    0xC0 | 0xD0 => 1,
                    _ => 2,
                };
                let data_end = pos.checked_add(n_data_bytes).ok_or_else(|| {
                    Error::InvalidAsset("MIDI channel event overflow".to_string())
                })?;
                if data_end > data.len() {
                    return Err(Error::InvalidAsset(
                        "MIDI channel event exceeds track data".to_string(),
                    ));
                }
                pos = data_end;
            }
            other => {
                return Err(Error::InvalidAsset(format!(
                    "unsupported or unexpected MIDI status byte 0x{other:02X}"
                )));
            }
        }
    }
}

/// Parses the `MThd` header. Returns `(format, ntrks, end_offset)` where
/// `end_offset` is the byte offset immediately following the MThd chunk.
fn parse_mthd(data: &[u8]) -> Result<(u16, u16, usize)> {
    if data.len() < 8 || data[0..4] != MTHD_ID {
        return Err(Error::InvalidAsset(
            "not a Standard MIDI File (missing MThd header)".to_string(),
        ));
    }

    let len = Cursor::new(&data[4..8]).read_u32::<BigEndian>()? as usize;
    let header_end = 8usize
        .checked_add(len)
        .ok_or_else(|| Error::InvalidAsset("MThd declared length overflow".to_string()))?;
    if header_end > data.len() {
        return Err(Error::InvalidAsset(
            "MThd declared length exceeds file size".to_string(),
        ));
    }
    if len < 6 {
        return Err(Error::InvalidAsset("MThd chunk too short".to_string()));
    }

    let mut cur = Cursor::new(&data[8..14]);
    let format = cur.read_u16::<BigEndian>()?;
    let ntrks = cur.read_u16::<BigEndian>()?;

    Ok((format, ntrks, header_end))
}

/// A top-level SMF chunk: its 4-byte id and where its header and data are.
#[derive(Clone, Copy, Debug)]
struct Chunk {
    id: [u8; 4],
    header_offset: usize,
    data_offset: usize,
    data_len: usize,
}

/// Walks top-level chunks starting at `start`. Any chunk type is accepted and
/// skipped by its declared length, per SMF's forward-compat rule of tolerating
/// unrecognized chunks.
fn walk_chunks(data: &[u8], start: usize) -> Result<Vec<Chunk>> {
    let mut chunks = Vec::new();
    let mut pos = start;

    while pos.checked_add(8).is_some_and(|end| end <= data.len()) {
        let id: [u8; 4] = data[pos..pos + 4]
            .try_into()
            .map_err(|_| Error::InvalidAsset("MIDI chunk id read failure".to_string()))?;
        let len = Cursor::new(&data[pos + 4..pos + 8]).read_u32::<BigEndian>()? as usize;

        let data_offset = pos + 8;
        let data_end = data_offset.checked_add(len).ok_or_else(|| {
            Error::InvalidAsset("MIDI chunk declared length overflow".to_string())
        })?;
        if data_end > data.len() {
            return Err(Error::InvalidAsset(
                "MIDI chunk declared length exceeds file size".to_string(),
            ));
        }

        chunks.push(Chunk {
            id,
            header_offset: pos,
            data_offset,
            data_len: len,
        });
        pos = data_end;
    }

    Ok(chunks)
}

fn designated_track_index(format: u16, mtrk_count: usize) -> Result<usize> {
    if mtrk_count == 0 {
        return Err(Error::InvalidAsset(
            "MIDI file contains no MTrk chunks".to_string(),
        ));
    }
    match format {
        0 => {
            if mtrk_count != 1 {
                return Err(Error::InvalidAsset(
                    "Format 0 MIDI file must contain exactly one MTrk chunk".to_string(),
                ));
            }
            Ok(0)
        }
        1 => Ok(mtrk_count - 1),
        2 => Ok(0),
        other => Err(Error::InvalidAsset(format!(
            "unsupported Standard MIDI File format: {other}"
        ))),
    }
}

/// Locates the designated `MTrk` chunk (per file format) in `data`.
/// Returns `(header_offset, data_offset, data_len)`.
fn designated_track(data: &[u8]) -> Result<(usize, usize, usize)> {
    let (format, _ntrks, mthd_end) = parse_mthd(data)?;
    let chunks = walk_chunks(data, mthd_end)?;

    let mtrk_chunks: Vec<_> = chunks.into_iter().filter(|c| c.id == MTRK_ID).collect();
    let idx = designated_track_index(format, mtrk_chunks.len())?;

    let track = mtrk_chunks[idx];
    Ok((track.header_offset, track.data_offset, track.data_len))
}

/// Returns the absolute `(offset, length)` of the C2PA manifest payload in
/// `data`, or `None` if no manifest is present. Per spec, more than one
/// C2PA-tagged event in the designated track is also treated as "not
/// located" rather than an error.
fn locate_manifest_span(data: &[u8]) -> Result<Option<(usize, usize)>> {
    let (_header_offset, data_offset, data_len) = designated_track(data)?;
    let track_data = &data[data_offset..data_offset + data_len];
    let scan = scan_track(track_data)?;

    match scan.c2pa_events.as_slice() {
        [single] => Ok(Some((
            data_offset + single.manifest_start,
            single.manifest_len,
        ))),
        _ => Ok(None),
    }
}

/// Builds the bytes of a full Sequencer-Specific Meta Event carrying
/// `store_bytes` as the C2PA manifest payload, with a delta-time of 0.
fn build_c2pa_event(store_bytes: &[u8]) -> Result<Vec<u8>> {
    let payload_len = C2PA_MANUFACTURER_ID
        .len()
        .checked_add(store_bytes.len())
        .ok_or_else(|| Error::InvalidAsset("C2PA manifest too large for MIDI file".to_string()))?;
    let payload_len_u32 = u32::try_from(payload_len)
        .map_err(|_| Error::InvalidAsset("C2PA manifest too large for MIDI file".to_string()))?;

    let mut event = vec![0x00, META_EVENT, META_SEQUENCER_SPECIFIC];
    event.extend(write_vlq(payload_len_u32));
    event.extend_from_slice(&C2PA_MANUFACTURER_ID);
    event.extend_from_slice(store_bytes);
    Ok(event)
}

/// Returns a new copy of `data` with the designated track's C2PA
/// Sequencer-Specific Meta Event(s) replaced by one carrying `store_bytes`.
/// An empty `store_bytes` removes the manifest without inserting a new one.
fn write_cai_bytes(data: &[u8], store_bytes: &[u8]) -> Result<Vec<u8>> {
    let (header_offset, data_offset, data_len) = designated_track(data)?;
    let track_data = &data[data_offset..data_offset + data_len];
    let scan = scan_track(track_data)?;

    let mut spans: Vec<(usize, usize)> = scan
        .c2pa_events
        .iter()
        .map(|e| (e.event_start, e.event_end))
        .collect();
    spans.sort_by_key(|s| s.0);

    let mut new_track = Vec::with_capacity(track_data.len() + store_bytes.len() + 16);
    let mut cursor = 0usize;
    for (start, end) in &spans {
        new_track.extend_from_slice(&track_data[cursor..*start]);
        cursor = *end;
    }
    new_track.extend_from_slice(&track_data[cursor..scan.eot_event_start]);

    if !store_bytes.is_empty() {
        new_track.extend(build_c2pa_event(store_bytes)?);
    }

    // The End of Track event itself (and its original delta-time) is left
    // untouched: inserting the manifest event immediately before it with a
    // delta-time of 0 preserves total track duration without needing to
    // rewrite EOT's delta.
    new_track.extend_from_slice(&track_data[scan.eot_event_start..]);

    let new_len = u32::try_from(new_track.len())
        .map_err(|_| Error::InvalidAsset("MIDI track too large".to_string()))?;

    let mut out = Vec::with_capacity(data.len() + new_track.len());
    out.extend_from_slice(&data[..header_offset]);
    out.extend_from_slice(&MTRK_ID);
    out.extend_from_slice(&new_len.to_be_bytes());
    out.extend_from_slice(&new_track);
    out.extend_from_slice(&data[data_offset + data_len..]);

    Ok(out)
}

impl C2paReader for MidiIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        input_stream.rewind()?;
        let mut data = Vec::new();
        input_stream.read_to_end(&mut data)?;

        match locate_manifest_span(&data)? {
            Some((offset, len)) => Ok(data[offset..offset + len].to_vec()),
            None => Err(Error::JumbfNotFound),
        }
    }

    // MIDI has no native XMP-embedding convention.
    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl AssetIO for MidiIO {
    fn new(midi_format: &str) -> Self {
        MidiIO {
            midi_format: midi_format.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(MidiIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(MidiIO::new(asset_type)))
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

impl C2paWriter for MidiIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        input_stream.rewind()?;
        let mut data = Vec::new();
        input_stream.read_to_end(&mut data)?;

        let out = write_cai_bytes(&data, store_bytes)?;
        output_stream.write_all(&out)?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        input_stream.rewind()?;
        let mut data = Vec::new();
        input_stream.read_to_end(&mut data)?;

        let (manifest_offset, manifest_len, file_end) = match locate_manifest_span(&data)? {
            Some((offset, len)) => (offset, len, data.len()),
            None => {
                // No manifest present yet: do a dry-run write with a
                // placeholder payload to discover where it would land.
                let placeholder = write_cai_bytes(&data, &[1, 2, 3, 4])?;
                let (offset, len) =
                    locate_manifest_span(&placeholder)?.ok_or(Error::EmbeddingError)?;
                (offset, len, placeholder.len())
            }
        };

        let manifest_end = manifest_offset
            .checked_add(manifest_len)
            .ok_or_else(|| Error::InvalidAsset("value out of range".to_string()))?;

        Ok(vec![
            ObjectLocations {
                offset: 0,
                length: manifest_offset as u64,
                htype: ObjectType::Other,
            },
            ObjectLocations {
                offset: manifest_offset as u64,
                length: manifest_len as u64,
                htype: ObjectType::C2pa,
            },
            ObjectLocations {
                offset: manifest_end as u64,
                length: (file_end - manifest_end) as u64,
                htype: ObjectType::Other,
            },
        ])
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        self.write_c2pa(input_stream, output_stream, &[])
    }
}

impl AssetPatch for MidiIO {
    fn patch_c2pa(&self, stream: &mut dyn ReadWriteSeek, store_bytes: &[u8]) -> Result<()> {
        stream.rewind()?;
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;

        let (offset, len) = locate_manifest_span(&data)?.ok_or(Error::EmbeddingError)?;

        if store_bytes.len() != len {
            return Err(Error::InvalidAsset(
                "patch_c2pa store size mismatch.".to_string(),
            ));
        }

        stream.seek(SeekFrom::Start(offset as u64))?;
        stream.write_all(store_bytes)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::utils::hash_utils::vec_compare;

    fn minimal_mthd(format: u16, ntrks: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&MTHD_ID);
        v.extend_from_slice(&6u32.to_be_bytes());
        v.extend_from_slice(&format.to_be_bytes());
        v.extend_from_slice(&ntrks.to_be_bytes());
        v.extend_from_slice(&96u16.to_be_bytes()); // division: 96 ticks/quarter note
        v
    }

    fn mtrk_chunk(events: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&MTRK_ID);
        v.extend_from_slice(&(events.len() as u32).to_be_bytes());
        v.extend_from_slice(events);
        v
    }

    // A basic Note On / Note Off pair followed by End of Track.
    fn basic_track_events() -> Vec<u8> {
        let mut events = Vec::new();
        events.extend_from_slice(&[0x00, 0x90, 0x3C, 0x64]); // Note On, note 60, vel 100
        events.extend_from_slice(&[0x60, 0x80, 0x3C, 0x40]); // +0x60 ticks, Note Off
        events.extend_from_slice(&[0x00, 0xFF, 0x2F, 0x00]); // End of Track
        events
    }

    fn format0_test_file() -> Vec<u8> {
        let mut file = minimal_mthd(0, 1);
        file.extend(mtrk_chunk(&basic_track_events()));
        file
    }

    fn format1_test_file() -> Vec<u8> {
        let mut file = minimal_mthd(1, 2);
        // Track 0: a decoy event stream (should be left untouched).
        file.extend(mtrk_chunk(&basic_track_events()));
        // Track 1 (last track = designated track for Format 1).
        file.extend(mtrk_chunk(&basic_track_events()));
        file
    }

    #[test]
    fn test_write_and_read_cai() {
        let manifest = b"some test manifest bytes";
        let source = format0_test_file();

        let midi_io = MidiIO::new("mid");
        let mut input = Cursor::new(source);
        let mut output = Cursor::new(Vec::new());

        midi_io.write_c2pa(&mut input, &mut output, manifest).unwrap();

        output.set_position(0);
        let read_back = midi_io.read_c2pa(&mut output).unwrap();
        assert!(vec_compare(manifest, &read_back));
    }

    #[test]
    fn test_format1_uses_last_track() {
        let manifest = b"format1 manifest";
        let source = format1_test_file();

        let midi_io = MidiIO::new("mid");
        let mut input = Cursor::new(source.clone());
        let mut output = Cursor::new(Vec::new());
        midi_io.write_c2pa(&mut input, &mut output, manifest).unwrap();

        let out_data = output.into_inner();

        // First MTrk chunk (decoy track) must be byte-identical to the source.
        let (_, _, mthd_end) = parse_mthd(&source).unwrap();
        let source_chunks = walk_chunks(&source, mthd_end).unwrap();
        let out_chunks = walk_chunks(&out_data, mthd_end).unwrap();
        let (src, out) = (source_chunks[0], out_chunks[0]);
        assert_eq!(
            &source[src.data_offset..src.data_offset + src.data_len],
            &out_data[out.data_offset..out.data_offset + out.data_len]
        );

        let mut reader = Cursor::new(out_data);
        let read_back = midi_io.read_c2pa(&mut reader).unwrap();
        assert!(vec_compare(manifest, &read_back));
    }

    #[test]
    fn test_patch_c2pa() {
        let test_data = b"some test data";
        let midi_io = MidiIO::new("mid");

        let mut stream = Cursor::new(Vec::new());
        midi_io
            .write_c2pa(&mut Cursor::new(format0_test_file()), &mut stream, test_data)
            .unwrap();

        let stored = midi_io.read_c2pa(&mut stream).unwrap();
        let mut replacement = vec![0u8; stored.len()];
        replacement[..test_data.len()].copy_from_slice(test_data);

        midi_io
            .asset_patch_ref()
            .unwrap()
            .patch_c2pa(&mut stream, &replacement)
            .unwrap();

        let patched = midi_io.read_c2pa(&mut stream).unwrap();
        assert_eq!(replacement, patched);
    }

    #[test]
    fn test_remove_cai_store() {
        let manifest = b"to be removed";
        let source = format0_test_file();

        let midi_io = MidiIO::new("mid");
        let mut input = Cursor::new(source);
        let mut with_manifest = Cursor::new(Vec::new());
        midi_io
            .write_c2pa(&mut input, &mut with_manifest, manifest)
            .unwrap();

        with_manifest.set_position(0);
        let mut removed = Cursor::new(Vec::new());
        midi_io
            .remove_c2pa(&mut with_manifest, &mut removed)
            .unwrap();

        removed.set_position(0);
        assert!(matches!(
            midi_io.read_c2pa(&mut removed),
            Err(Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_multiple_c2pa_events_treated_as_not_found() {
        let mut events = Vec::new();
        // Two C2PA-tagged sequencer-specific events before EOT.
        events.extend(build_c2pa_event(b"first").unwrap());
        events.extend(build_c2pa_event(b"second").unwrap());
        events.extend_from_slice(&[0x00, 0xFF, 0x2F, 0x00]); // End of Track

        let mut file = minimal_mthd(0, 1);
        file.extend(mtrk_chunk(&events));

        let midi_io = MidiIO::new("mid");
        let mut reader = Cursor::new(file);
        assert!(matches!(
            midi_io.read_c2pa(&mut reader),
            Err(Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_forged_track_length_returns_error() {
        // MTrk declares far more data than actually follows it.
        let mut file = minimal_mthd(0, 1);
        file.extend_from_slice(&MTRK_ID);
        file.extend_from_slice(&u32::MAX.to_be_bytes());
        file.extend_from_slice(&basic_track_events());

        let midi_io = MidiIO::new("mid");
        let mut reader = Cursor::new(file);
        assert!(matches!(
            midi_io.read_c2pa(&mut reader),
            Err(Error::InvalidAsset(_))
        ));
    }

    #[test]
    fn test_missing_mthd_returns_error() {
        let midi_io = MidiIO::new("mid");
        let mut reader = Cursor::new(b"not a midi file".to_vec());
        assert!(matches!(
            midi_io.read_c2pa(&mut reader),
            Err(Error::InvalidAsset(_))
        ));
    }
}
