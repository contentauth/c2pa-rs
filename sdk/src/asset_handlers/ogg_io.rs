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

//! C2PA manifest embedding for OGG containers (Vorbis, Opus).
//!
//! Implements C2PA Technical Specification v2.3 Section A.3.5:
//! the manifest store is placed in a dedicated logical bitstream whose
//! first packet begins with the 5-byte identifier `\x00c2pa`.
//!
//! Hash binding follows Section 18.7.3.7: each logical bitstream is
//! treated as a single "box" named `Stream-{serial}` (decimal).  The
//! C2PA bitstream is named with the standard [`C2PA_BOXHASH`] label.

use std::{
    collections::HashMap,
    fs,
    io::{self, Cursor, Seek, SeekFrom, Write},
    path::Path,
};

use serde_bytes::ByteBuf;
use tempfile::Builder;

use crate::{
    assertions::{BoxMap, C2PA_BOXHASH},
    asset_io::{
        rename_or_move, AssetBoxHash, AssetIO, AssetPatch, CAIRead, CAIReadWrite, CAIReader,
        CAIWriter, HashBlockObjectType, HashObjectPositions, RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
};

// ── Constants ────────────────────────────────────────────────────────────────

/// Supported extensions and MIME types for OGG-based audio.
static SUPPORTED_TYPES: [&str; 4] = ["ogg", "audio/ogg", "opus", "audio/opus"];

/// OGG page capture pattern (RFC 3533 §6).
const OGG_CAPTURE: &[u8; 4] = b"OggS";

/// C2PA bitstream identification magic (C2PA spec §A.3.5).
const C2PA_MAGIC: &[u8; 5] = b"\x00c2pa";

/// Page header type flags (RFC 3533 §6).
const HEADER_TYPE_CONTINUED: u8 = 0x01;
const HEADER_TYPE_BOS: u8 = 0x02;
const HEADER_TYPE_EOS: u8 = 0x04;

/// Minimum OGG page header size: 27 fixed bytes + at least 0 segment entries.
const MIN_PAGE_HEADER: usize = 27;

/// Maximum number of segments per page (RFC 3533 §6).
const MAX_SEGMENTS_PER_PAGE: usize = 255;

/// Maximum single segment size.
const MAX_SEGMENT_SIZE: usize = 255;

// ── OGG CRC-32 ──────────────────────────────────────────────────────────────

/// Precomputed CRC-32 lookup table for the OGG polynomial 0x04c11db7
/// (direct / non-reflected, per RFC 3533 §6).
const CRC_TABLE: [u32; 256] = make_crc_table();

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut crc = i << 24;
        let mut j = 0;
        while j < 8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ 0x04c1_1db7;
            } else {
                crc <<= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

/// Compute the OGG CRC-32 checksum over `data`.
fn ogg_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0;
    for &byte in data {
        crc = (crc << 8) ^ CRC_TABLE[((crc >> 24) ^ byte as u32) as usize];
    }
    crc
}

// ── OGG Page ─────────────────────────────────────────────────────────────────

/// A parsed OGG page with positional metadata.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct OggPage {
    header_type: u8,
    granule_position: u64,
    serial_number: u32,
    page_sequence_number: u32,
    segment_table: Vec<u8>,
    body: Vec<u8>,
    /// Absolute byte offset where this page starts in the source stream.
    file_offset: u64,
}

impl OggPage {
    /// Total serialized size of this page (header + segment table + body).
    fn total_size(&self) -> usize {
        MIN_PAGE_HEADER + self.segment_table.len() + self.body.len()
    }

    fn is_bos(&self) -> bool {
        self.header_type & HEADER_TYPE_BOS != 0
    }

    /// Check whether this page's first packet begins with `C2PA_MAGIC`.
    fn is_c2pa_bos(&self) -> bool {
        self.is_bos() && self.body.starts_with(C2PA_MAGIC)
    }
}

/// Read a single OGG page from `reader` at the current position.
///
/// Returns `Ok(None)` on clean EOF (no bytes left).
fn read_page(reader: &mut dyn CAIRead) -> Result<Option<OggPage>> {
    let file_offset = reader.stream_position().map_err(Error::IoError)?;

    // Read capture pattern.
    let mut capture = [0u8; 4];
    match reader.read_exact(&mut capture) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Error::IoError(e)),
    }
    if &capture != OGG_CAPTURE {
        return Err(Error::OggError(OggError::InvalidCapture));
    }

    // Version (must be 0).
    let mut version = [0u8; 1];
    reader.read_exact(&mut version).map_err(Error::IoError)?;
    if version[0] != 0 {
        return Err(Error::OggError(OggError::UnsupportedVersion(version[0])));
    }

    // Header type.
    let mut header_type_buf = [0u8; 1];
    reader
        .read_exact(&mut header_type_buf)
        .map_err(Error::IoError)?;
    let header_type = header_type_buf[0];

    // Granule position (8 bytes LE).
    let mut gp_buf = [0u8; 8];
    reader.read_exact(&mut gp_buf).map_err(Error::IoError)?;
    let granule_position = u64::from_le_bytes(gp_buf);

    // Serial number (4 bytes LE).
    let mut sn_buf = [0u8; 4];
    reader.read_exact(&mut sn_buf).map_err(Error::IoError)?;
    let serial_number = u32::from_le_bytes(sn_buf);

    // Page sequence number (4 bytes LE).
    let mut psn_buf = [0u8; 4];
    reader.read_exact(&mut psn_buf).map_err(Error::IoError)?;
    let page_sequence_number = u32::from_le_bytes(psn_buf);

    // CRC (4 bytes LE) — read but verify after reading the whole page.
    let mut crc_buf = [0u8; 4];
    reader.read_exact(&mut crc_buf).map_err(Error::IoError)?;
    let stored_crc = u32::from_le_bytes(crc_buf);

    // Number of segments.
    let mut nseg_buf = [0u8; 1];
    reader.read_exact(&mut nseg_buf).map_err(Error::IoError)?;
    let num_segments = nseg_buf[0] as usize;

    // Segment table.
    let mut segment_table = vec![0u8; num_segments];
    reader
        .read_exact(&mut segment_table)
        .map_err(Error::IoError)?;

    // Body.
    let body_size: usize = segment_table.iter().map(|&s| s as usize).sum();
    let mut body = vec![0u8; body_size];
    reader.read_exact(&mut body).map_err(Error::IoError)?;

    // Verify CRC: reserialize the header with checksum = 0.
    let page = OggPage {
        header_type,
        granule_position,
        serial_number,
        page_sequence_number,
        segment_table,
        body,
        file_offset,
    };

    let computed_crc = compute_page_crc(&page);
    if computed_crc != stored_crc {
        return Err(Error::OggError(OggError::CrcMismatch {
            offset: file_offset,
        }));
    }

    Ok(Some(page))
}

/// Serialize an OGG page to `writer`, computing and embedding the CRC.
fn write_page(writer: &mut dyn Write, page: &OggPage) -> Result<()> {
    let serialized = serialize_page(page);
    writer.write_all(&serialized).map_err(Error::IoError)?;
    Ok(())
}

/// Serialize an OGG page to a `Vec<u8>` with a correct CRC.
fn serialize_page(page: &OggPage) -> Vec<u8> {
    let total = MIN_PAGE_HEADER + page.segment_table.len() + page.body.len();
    let mut buf = Vec::with_capacity(total);

    // Capture pattern.
    buf.extend_from_slice(OGG_CAPTURE);
    // Version.
    buf.push(0);
    // Header type.
    buf.push(page.header_type);
    // Granule position (LE).
    buf.extend_from_slice(&page.granule_position.to_le_bytes());
    // Serial number (LE).
    buf.extend_from_slice(&page.serial_number.to_le_bytes());
    // Page sequence number (LE).
    buf.extend_from_slice(&page.page_sequence_number.to_le_bytes());
    // CRC placeholder (zeroes for computation).
    buf.extend_from_slice(&[0u8; 4]);
    // Number of segments.
    buf.push(page.segment_table.len() as u8);
    // Segment table.
    buf.extend_from_slice(&page.segment_table);
    // Body.
    buf.extend_from_slice(&page.body);

    // Compute and patch CRC.
    let crc = ogg_crc32(&buf);
    buf[22..26].copy_from_slice(&crc.to_le_bytes());

    buf
}

/// Compute the CRC for a page (header with CRC field zeroed).
fn compute_page_crc(page: &OggPage) -> u32 {
    let total = MIN_PAGE_HEADER + page.segment_table.len() + page.body.len();
    let mut buf = Vec::with_capacity(total);

    buf.extend_from_slice(OGG_CAPTURE);
    buf.push(0); // version
    buf.push(page.header_type);
    buf.extend_from_slice(&page.granule_position.to_le_bytes());
    buf.extend_from_slice(&page.serial_number.to_le_bytes());
    buf.extend_from_slice(&page.page_sequence_number.to_le_bytes());
    buf.extend_from_slice(&[0u8; 4]); // CRC = 0 for computation
    buf.push(page.segment_table.len() as u8);
    buf.extend_from_slice(&page.segment_table);
    buf.extend_from_slice(&page.body);

    ogg_crc32(&buf)
}

/// Read all OGG pages from a stream.
fn read_all_pages(reader: &mut dyn CAIRead) -> Result<Vec<OggPage>> {
    reader.rewind()?;
    let mut pages = Vec::new();
    while let Some(page) = read_page(reader)? {
        pages.push(page);
    }
    if pages.is_empty() {
        return Err(Error::OggError(OggError::InvalidCapture));
    }
    Ok(pages)
}

// ── C2PA bitstream construction ──────────────────────────────────────────────

/// Build OGG pages for a C2PA manifest bitstream.
///
/// The single packet is `\x00c2pa` + `manifest_data`.  It is fragmented
/// across pages following OGG lacing rules.
fn build_c2pa_pages(manifest_data: &[u8], serial: u32) -> Vec<OggPage> {
    let mut packet = Vec::with_capacity(C2PA_MAGIC.len() + manifest_data.len());
    packet.extend_from_slice(C2PA_MAGIC);
    packet.extend_from_slice(manifest_data);

    let mut pages = Vec::new();
    let mut remaining = &packet[..];
    let mut page_seq: u32 = 0;

    while !remaining.is_empty() {
        let mut segment_table = Vec::new();
        let mut body = Vec::new();

        while segment_table.len() < MAX_SEGMENTS_PER_PAGE && !remaining.is_empty() {
            let chunk_size = remaining.len().min(MAX_SEGMENT_SIZE);
            segment_table.push(chunk_size as u8);
            body.extend_from_slice(&remaining[..chunk_size]);
            remaining = &remaining[chunk_size..];

            // A segment < 255 terminates the packet within this page.
            if chunk_size < MAX_SEGMENT_SIZE {
                break;
            }
        }

        let mut header_type = 0u8;
        if page_seq == 0 {
            header_type |= HEADER_TYPE_BOS;
        } else {
            // This page continues the packet from the previous page.
            header_type |= HEADER_TYPE_CONTINUED;
        }

        pages.push(OggPage {
            header_type,
            granule_position: 0,
            serial_number: serial,
            page_sequence_number: page_seq,
            segment_table,
            body,
            file_offset: 0,
        });

        page_seq += 1;
    }

    // Handle edge case: packet is exactly a multiple of 255 bytes.
    // The last segment value is 255, meaning "continues".  We need a
    // zero-length terminator segment.
    if let Some(last_page) = pages.last_mut() {
        if last_page.segment_table.last() == Some(&(MAX_SEGMENT_SIZE as u8)) {
            if last_page.segment_table.len() < MAX_SEGMENTS_PER_PAGE {
                last_page.segment_table.push(0);
            } else {
                // Need a new page for just the terminator.
                pages.push(OggPage {
                    header_type: HEADER_TYPE_CONTINUED,
                    granule_position: 0,
                    serial_number: serial,
                    page_sequence_number: page_seq,
                    segment_table: vec![0],
                    body: Vec::new(),
                    file_offset: 0,
                });
            }
        }
    }

    // Mark the last page as EOS.
    if let Some(last_page) = pages.last_mut() {
        last_page.header_type |= HEADER_TYPE_EOS;
    }

    pages
}

/// Choose a serial number not already in use.
fn pick_unused_serial(existing: &[u32]) -> u32 {
    // Start with "C2PA" in ASCII as a recognisable default.
    let mut candidate: u32 = 0x4332_5041;
    while existing.contains(&candidate) {
        candidate = candidate.wrapping_add(1);
    }
    candidate
}

/// Extract the first complete packet from a series of pages belonging to
/// the same logical bitstream.  Pages must be in sequence order.
fn extract_first_packet(pages: &[&OggPage]) -> Vec<u8> {
    let mut packet = Vec::new();
    for page in pages {
        let mut offset = 0usize;
        for &lacing in &page.segment_table {
            let seg_len = lacing as usize;
            if offset + seg_len <= page.body.len() {
                packet.extend_from_slice(&page.body[offset..offset + seg_len]);
            }
            offset += seg_len;
            if lacing < MAX_SEGMENT_SIZE as u8 {
                // Packet terminated.
                return packet;
            }
        }
    }
    packet
}

// ── OggError ─────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OggError {
    #[error("not a valid OGG file: missing OggS capture pattern")]
    InvalidCapture,

    #[error("unsupported OGG version: {0}")]
    UnsupportedVersion(u8),

    #[error("OGG CRC mismatch on page at offset {offset}")]
    CrcMismatch { offset: u64 },
}

// ── OggIO ────────────────────────────────────────────────────────────────────

pub struct OggIO {
    _asset_type: String,
}

impl CAIReader for OggIO {
    fn read_cai(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let pages = read_all_pages(input_stream)?;

        // Find C2PA BOS page(s).
        let c2pa_serials: Vec<u32> = pages
            .iter()
            .filter(|p| p.is_c2pa_bos())
            .map(|p| p.serial_number)
            .collect();

        if c2pa_serials.is_empty() {
            return Err(Error::JumbfNotFound);
        }
        if c2pa_serials.len() > 1 {
            return Err(Error::TooManyManifestStores);
        }

        let c2pa_serial = c2pa_serials[0];

        // Collect all pages for the C2PA bitstream, in order.
        let c2pa_pages: Vec<&OggPage> = pages
            .iter()
            .filter(|p| p.serial_number == c2pa_serial)
            .collect();

        // Extract the first (and only) packet.
        let packet = extract_first_packet(&c2pa_pages);
        if packet.len() < C2PA_MAGIC.len() || &packet[..C2PA_MAGIC.len()] != C2PA_MAGIC {
            return Err(Error::JumbfNotFound);
        }

        Ok(packet[C2PA_MAGIC.len()..].to_vec())
    }

    fn read_xmp(&self, _input_stream: &mut dyn CAIRead) -> Option<String> {
        // XMP embedding is not defined for OGG in the C2PA specification.
        None
    }
}

impl CAIWriter for OggIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let pages = read_all_pages(input_stream)?;

        // Identify existing C2PA bitstream serial (if any).
        let c2pa_serial: Option<u32> = pages.iter().find(|p| p.is_c2pa_bos()).map(|p| p.serial_number);

        // Collect non-C2PA pages.
        let non_c2pa_pages: Vec<&OggPage> = pages
            .iter()
            .filter(|p| c2pa_serial != Some(p.serial_number))
            .collect();

        // Separate BOS and non-BOS pages.
        let bos_pages: Vec<&OggPage> = non_c2pa_pages.iter().filter(|p| p.is_bos()).copied().collect();
        let data_pages: Vec<&OggPage> = non_c2pa_pages.iter().filter(|p| !p.is_bos()).copied().collect();

        // Build new C2PA pages (empty store_bytes means removal).
        let existing_serials: Vec<u32> = pages.iter().map(|p| p.serial_number).collect();
        let new_c2pa_serial = pick_unused_serial(&existing_serials);
        let c2pa_pages = if store_bytes.is_empty() {
            Vec::new()
        } else {
            build_c2pa_pages(store_bytes, new_c2pa_serial)
        };

        // Write output so that each bitstream's pages are contiguous,
        // which is required for BoxHash byte-range verification.
        //
        // Layout:
        //   1. C2PA BOS page
        //   2. C2PA continuation + EOS pages
        //   3. Audio BOS pages (one per non-C2PA bitstream)
        //   4. Audio data pages grouped by serial
        //
        // OGG spec requires all BOS pages before any data pages.  Here
        // the C2PA BOS comes first, followed by audio BOS pages, then
        // data pages.  This keeps each bitstream's pages contiguous:
        // C2PA occupies bytes [0..C2PA_total), audio occupies the rest.

        output_stream.rewind()?;

        // 1-2. All C2PA pages (BOS + continuation + EOS) — contiguous block.
        for page in &c2pa_pages {
            write_page(output_stream, page)?;
        }

        // 3. Audio BOS pages.
        for page in &bos_pages {
            write_page(output_stream, page)?;
        }

        // 4. Audio data pages grouped by serial.
        let mut seen_serials = Vec::new();
        for page in &data_pages {
            if !seen_serials.contains(&page.serial_number) {
                seen_serials.push(page.serial_number);
            }
        }
        for serial in &seen_serials {
            for page in &data_pages {
                if page.serial_number == *serial {
                    write_page(output_stream, page)?;
                }
            }
        }

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        // Write a temporary version with a placeholder manifest to find positions.
        let mut temp_output = Cursor::new(Vec::new());
        let has_c2pa = {
            input_stream.rewind()?;
            let pages = read_all_pages(input_stream)?;
            pages.iter().any(|p| p.is_c2pa_bos())
        };

        if has_c2pa {
            input_stream.rewind()?;
            io::copy(input_stream, &mut temp_output)?;
        } else {
            input_stream.rewind()?;
            self.write_cai(input_stream, &mut temp_output, &[1, 2, 3, 4])?;
        }

        temp_output.rewind()?;
        let pages = read_all_pages(&mut temp_output)?;

        let c2pa_serial = pages
            .iter()
            .find(|p| p.is_c2pa_bos())
            .map(|p| p.serial_number);

        let c2pa_serial = c2pa_serial.ok_or(Error::JumbfNotFound)?;

        // Re-read to compute actual offsets.
        temp_output.rewind()?;
        let pages = read_all_pages(&mut temp_output)?;

        // Compute output positions.
        let mut offset: usize = 0;
        let mut c2pa_start: Option<usize> = None;
        let mut c2pa_len: usize = 0;

        for page in &pages {
            let page_size = page.total_size();
            if page.serial_number == c2pa_serial {
                if c2pa_start.is_none() {
                    c2pa_start = Some(offset);
                }
                c2pa_len += page_size;
            }
            offset += page_size;
        }

        let total_len = offset;
        let c2pa_start = c2pa_start.unwrap_or(0);

        Ok(vec![
            HashObjectPositions {
                offset: 0,
                length: c2pa_start,
                htype: HashBlockObjectType::Other,
            },
            HashObjectPositions {
                offset: c2pa_start,
                length: c2pa_len,
                htype: HashBlockObjectType::Cai,
            },
            HashObjectPositions {
                offset: c2pa_start + c2pa_len,
                length: total_len - (c2pa_start + c2pa_len),
                htype: HashBlockObjectType::Other,
            },
        ])
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        self.write_cai(input_stream, output_stream, &[])
    }
}

impl AssetPatch for OggIO {
    fn patch_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut file = fs::File::open(asset_path).map_err(Error::IoError)?;
        let pages = read_all_pages(&mut file)?;

        let c2pa_serial = pages
            .iter()
            .find(|p| p.is_c2pa_bos())
            .map(|p| p.serial_number)
            .ok_or(Error::JumbfNotFound)?;

        let c2pa_pages: Vec<&OggPage> = pages
            .iter()
            .filter(|p| p.serial_number == c2pa_serial)
            .collect();

        let old_packet = extract_first_packet(&c2pa_pages);
        let old_manifest_len = old_packet.len().saturating_sub(C2PA_MAGIC.len());
        if store_bytes.len() != old_manifest_len {
            return Err(Error::InvalidAsset(
                "patch size mismatch: new manifest must be exactly the same size".to_string(),
            ));
        }

        // Rebuild with the same serial so page structure is identical.
        let new_pages = build_c2pa_pages(store_bytes, c2pa_serial);

        // Verify page count matches (same size should produce same page structure).
        if new_pages.len() != c2pa_pages.len() {
            return Err(Error::InvalidAsset(
                "patch produced different page count".to_string(),
            ));
        }

        // Overwrite each C2PA page in-place.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        for (old_page, new_page) in c2pa_pages.iter().zip(new_pages.iter()) {
            let serialized = serialize_page(new_page);
            file.seek(SeekFrom::Start(old_page.file_offset))
                .map_err(Error::IoError)?;
            file.write_all(&serialized).map_err(Error::IoError)?;
        }

        Ok(())
    }
}

impl RemoteRefEmbed for OggIO {
    fn embed_reference(&self, _asset_path: &Path, _embed_ref: RemoteRefEmbedType) -> Result<()> {
        // XMP/remote references are not defined for OGG in the C2PA spec.
        Err(Error::UnsupportedType)
    }

    fn embed_reference_to_stream(
        &self,
        _source_stream: &mut dyn CAIRead,
        _output_stream: &mut dyn CAIReadWrite,
        _embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        Err(Error::UnsupportedType)
    }
}

impl AssetBoxHash for OggIO {
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>> {
        // To get correct contiguous ranges, we write to a temporary buffer
        // first (which groups pages by serial).
        let has_c2pa = {
            input_stream.rewind()?;
            let pages = read_all_pages(input_stream)?;
            pages.iter().any(|p| p.is_c2pa_bos())
        };

        let mut temp_output = Cursor::new(Vec::new());
        if has_c2pa {
            input_stream.rewind()?;
            io::copy(input_stream, &mut temp_output)?;
        } else {
            input_stream.rewind()?;
            self.write_cai(input_stream, &mut temp_output, &[1, 2, 3, 4])?;
        }

        temp_output.rewind()?;
        let pages = read_all_pages(&mut temp_output)?;

        // Track byte ranges per serial, in the order pages appear.
        let mut serial_ranges: HashMap<u32, (u64, u64)> = HashMap::new(); // serial -> (start, end)
        let mut serial_order: Vec<u32> = Vec::new();
        let mut c2pa_serial: Option<u32> = None;
        let mut offset: u64 = 0;

        for page in &pages {
            let page_size = page.total_size() as u64;

            if page.is_c2pa_bos() {
                c2pa_serial = Some(page.serial_number);
            }

            let entry = serial_ranges
                .entry(page.serial_number)
                .or_insert((offset, offset));
            entry.1 = offset + page_size;

            if !serial_order.contains(&page.serial_number) {
                serial_order.push(page.serial_number);
            }

            offset += page_size;
        }

        let mut box_maps = Vec::new();

        for serial in &serial_order {
            let (start, end) = serial_ranges[serial];
            let is_c2pa = c2pa_serial == Some(*serial);

            let name = if is_c2pa {
                C2PA_BOXHASH.to_string()
            } else {
                format!("Stream-{serial}")
            };

            let excluded = if is_c2pa && !has_c2pa {
                Some(true)
            } else {
                None
            };

            box_maps.push(BoxMap {
                names: vec![name],
                alg: None,
                hash: ByteBuf::from(Vec::new()),
                excluded,
                pad: ByteBuf::from(Vec::new()),
                range_start: start,
                range_len: end - start,
            });
        }

        Ok(box_maps)
    }
}

impl AssetIO for OggIO {
    fn new(asset_type: &str) -> Self {
        OggIO {
            _asset_type: asset_type.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(OggIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(OggIO::new(asset_type)))
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        Some(self)
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = fs::File::open(asset_path).map_err(Error::IoError)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut reader = fs::File::open(asset_path).map_err(Error::IoError)?;

        let temp_file = Builder::new()
            .prefix("c2pa_ogg_")
            .suffix(
                Path::new(asset_path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| format!(".{e}"))
                    .as_deref()
                    .unwrap_or(".ogg"),
            )
            .tempfile_in(
                asset_path
                    .parent()
                    .unwrap_or_else(|| Path::new(".")),
            )
            .map_err(Error::IoError)?;

        let mut temp_writer = temp_file.reopen().map_err(Error::IoError)?;
        self.write_cai(&mut reader, &mut temp_writer, store_bytes)?;

        rename_or_move(temp_file, asset_path)?;
        Ok(())
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        let mut f = fs::File::open(asset_path).map_err(Error::IoError)?;
        self.get_object_locations_from_stream(&mut f)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        self.save_cai_store(asset_path, &[])
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::{
        asset_io::{HashBlockObjectType, RemoteRefEmbedType},
        error::Error,
    };

    /// Minimal valid OGG Vorbis file.
    const SAMPLE_OGG: &[u8] = include_bytes!("../../tests/fixtures/sample1.ogg");

    /// Minimal valid OGG Opus file.
    const SAMPLE_OPUS: &[u8] = include_bytes!("../../tests/fixtures/sample1.opus");

    const TEST_MANIFEST: &[u8] = b"test-c2pa-manifest-data-1234567890";

    // ── CRC tests ───────────────────────────────────────────────────────────

    #[test]
    fn test_crc32_known_values() {
        // The CRC of an empty input must be 0.
        assert_eq!(ogg_crc32(&[]), 0);

        // Verify against a real OGG page: parse the first page of our
        // fixture and confirm the stored CRC matches our computation.
        let mut cursor = Cursor::new(SAMPLE_OGG);
        let page = read_page(&mut cursor).unwrap().unwrap();
        // If read_page succeeded, the CRC was already verified internally.
        // Double-check by recomputing.
        let computed = compute_page_crc(&page);
        let serialized = serialize_page(&page);
        let stored = u32::from_le_bytes([
            serialized[22],
            serialized[23],
            serialized[24],
            serialized[25],
        ]);
        assert_eq!(computed, stored, "CRC mismatch on first fixture page");
    }

    // ── Page round-trip ─────────────────────────────────────────────────────

    #[test]
    fn test_page_roundtrip() {
        let mut cursor = Cursor::new(SAMPLE_OGG);
        let original = read_page(&mut cursor).unwrap().unwrap();

        let serialized = serialize_page(&original);
        let mut re_cursor = Cursor::new(serialized);
        let roundtripped = read_page(&mut re_cursor).unwrap().unwrap();

        assert_eq!(original.header_type, roundtripped.header_type);
        assert_eq!(original.granule_position, roundtripped.granule_position);
        assert_eq!(original.serial_number, roundtripped.serial_number);
        assert_eq!(original.segment_table, roundtripped.segment_table);
        assert_eq!(original.body, roundtripped.body);
    }

    // ── Read path ───────────────────────────────────────────────────────────

    #[test]
    fn test_read_cai_no_c2pa() {
        let handler = OggIO::new("ogg");
        let mut cursor = Cursor::new(SAMPLE_OGG);
        match handler.read_cai(&mut cursor) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("expected JumbfNotFound, got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_no_c2pa_opus() {
        let handler = OggIO::new("opus");
        let mut cursor = Cursor::new(SAMPLE_OPUS);
        match handler.read_cai(&mut cursor) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("expected JumbfNotFound for Opus, got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_invalid_header() {
        let handler = OggIO::new("ogg");
        let mut cursor = Cursor::new(b"not-an-ogg-file");
        match handler.read_cai(&mut cursor) {
            Err(Error::OggError(OggError::InvalidCapture)) => {}
            other => panic!("expected InvalidCapture, got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_too_short() {
        let handler = OggIO::new("ogg");
        let mut cursor = Cursor::new(&[0x4f, 0x67, 0x67]); // "Ogg" (missing S)
        match handler.read_cai(&mut cursor) {
            Err(_) => {} // either IoError or InvalidCapture
            Ok(_) => panic!("expected error for truncated stream"),
        }
    }

    // ── Write + read round-trip ─────────────────────────────────────────────

    #[test]
    fn test_write_read_roundtrip() {
        let handler = OggIO::new("ogg");
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut output, TEST_MANIFEST)
            .expect("write_cai failed");

        // Read it back.
        let read_back = handler
            .read_cai(&mut output)
            .expect("read_cai after write failed");

        assert_eq!(read_back, TEST_MANIFEST, "manifest round-trip mismatch");
    }

    #[test]
    fn test_write_read_roundtrip_opus() {
        let handler = OggIO::new("opus");
        let mut input = Cursor::new(SAMPLE_OPUS);
        let mut output = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut output, TEST_MANIFEST)
            .expect("write_cai failed for Opus");

        let read_back = handler
            .read_cai(&mut output)
            .expect("read_cai after write failed for Opus");

        assert_eq!(read_back, TEST_MANIFEST, "Opus manifest round-trip mismatch");
    }

    #[test]
    fn test_write_read_roundtrip_large_manifest() {
        // Test a manifest larger than one page (~65 KB).
        let handler = OggIO::new("ogg");
        let large_manifest = vec![0xAB; 100_000];
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut output, &large_manifest)
            .expect("write_cai failed for large manifest");

        let read_back = handler
            .read_cai(&mut output)
            .expect("read_cai failed for large manifest");

        assert_eq!(
            read_back, large_manifest,
            "large manifest round-trip mismatch"
        );
    }

    #[test]
    fn test_write_replaces_existing() {
        let handler = OggIO::new("ogg");
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output1 = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut output1, b"first-manifest")
            .unwrap();

        // Write again over the result.
        let mut output2 = Cursor::new(Vec::new());
        handler
            .write_cai(&mut output1, &mut output2, b"second-manifest")
            .unwrap();

        let read_back = handler.read_cai(&mut output2).unwrap();
        assert_eq!(read_back, b"second-manifest");
    }

    // ── Remove ──────────────────────────────────────────────────────────────

    #[test]
    fn test_remove_manifest() {
        let handler = OggIO::new("ogg");
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut with_manifest = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut with_manifest, TEST_MANIFEST)
            .unwrap();

        let mut removed = Cursor::new(Vec::new());
        handler
            .remove_cai_store_from_stream(&mut with_manifest, &mut removed)
            .unwrap();

        match handler.read_cai(&mut removed) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("expected JumbfNotFound after removal, got {:?}", other),
        }
    }

    #[test]
    fn test_write_empty_removes() {
        let handler = OggIO::new("ogg");
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut with_manifest = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut with_manifest, TEST_MANIFEST)
            .unwrap();

        let mut output = Cursor::new(Vec::new());
        handler
            .write_cai(&mut with_manifest, &mut output, &[])
            .unwrap();

        match handler.read_cai(&mut output) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("expected JumbfNotFound for empty write, got {:?}", other),
        }
    }

    // ── Patch ───────────────────────────────────────────────────────────────

    #[test]
    fn test_patch_same_size() {
        let handler = OggIO::new("ogg");

        // Create a temp file with a manifest.
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("patch_test.ogg");

        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output = Cursor::new(Vec::new());
        handler
            .write_cai(&mut input, &mut output, TEST_MANIFEST)
            .unwrap();
        fs::write(&temp_path, output.into_inner()).unwrap();

        // Patch with same-size data.
        let new_manifest = b"XXXX-c2pa-manifest-data-0987654321";
        assert_eq!(new_manifest.len(), TEST_MANIFEST.len());
        handler.patch_cai_store(&temp_path, new_manifest).unwrap();

        // Verify.
        let read_back = handler.read_cai_store(&temp_path).unwrap();
        assert_eq!(read_back, new_manifest);
    }

    #[test]
    fn test_patch_size_mismatch() {
        let handler = OggIO::new("ogg");

        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("patch_mismatch.ogg");

        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output = Cursor::new(Vec::new());
        handler
            .write_cai(&mut input, &mut output, TEST_MANIFEST)
            .unwrap();
        fs::write(&temp_path, output.into_inner()).unwrap();

        // Attempt patch with different size.
        let result = handler.patch_cai_store(&temp_path, b"short");
        assert!(result.is_err(), "patch with different size should fail");
    }

    // ── Object locations ────────────────────────────────────────────────────

    #[test]
    fn test_get_object_locations_structure() {
        let handler = OggIO::new("ogg");
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut output, TEST_MANIFEST)
            .unwrap();

        let locs = handler
            .get_object_locations_from_stream(&mut output)
            .unwrap();

        assert_eq!(locs.len(), 3, "expected 3 hash regions");

        // Regions must cover the entire file without overlap.
        let total_size = output.get_ref().len();
        let sum: usize = locs.iter().map(|l| l.length).sum();
        assert_eq!(sum, total_size, "regions must sum to file size");

        // Check types.
        assert_eq!(locs[0].htype, HashBlockObjectType::Other);
        assert_eq!(locs[1].htype, HashBlockObjectType::Cai);
        assert_eq!(locs[2].htype, HashBlockObjectType::Other);

        // Contiguous.
        assert_eq!(locs[0].offset, 0);
        assert_eq!(locs[1].offset, locs[0].length);
        assert_eq!(locs[2].offset, locs[1].offset + locs[1].length);
    }

    // ── BoxMap ──────────────────────────────────────────────────────────────

    #[test]
    fn test_get_box_map_with_c2pa() {
        let handler = OggIO::new("ogg");
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut output, TEST_MANIFEST)
            .unwrap();

        let box_map = handler.get_box_map(&mut output).unwrap();

        // Should have at least 2 entries: audio stream + C2PA.
        assert!(box_map.len() >= 2, "expected at least 2 BoxMap entries");

        let c2pa_entry = box_map
            .iter()
            .find(|bm| bm.names.contains(&C2PA_BOXHASH.to_string()));
        assert!(c2pa_entry.is_some(), "missing C2PA BoxMap entry");

        let audio_entry = box_map
            .iter()
            .find(|bm| bm.names.iter().any(|n| n.starts_with("Stream-")));
        assert!(audio_entry.is_some(), "missing Stream-N BoxMap entry");

        // Ranges must not overlap and should cover the file.
        let total: u64 = box_map.iter().map(|bm| bm.range_len).sum();
        let file_len = output.get_ref().len() as u64;
        assert_eq!(total, file_len, "BoxMap ranges must sum to file size");
    }

    #[test]
    fn test_get_box_map_no_c2pa() {
        let handler = OggIO::new("ogg");
        let mut cursor = Cursor::new(SAMPLE_OGG);

        let box_map = handler.get_box_map(&mut cursor).unwrap();

        // Should still have C2PA placeholder entry.
        let c2pa_entry = box_map
            .iter()
            .find(|bm| bm.names.contains(&C2PA_BOXHASH.to_string()));
        assert!(
            c2pa_entry.is_some(),
            "should have C2PA placeholder entry on unsigned file"
        );

        // Placeholder should be marked as excluded.
        let c2pa = c2pa_entry.unwrap();
        assert_eq!(c2pa.excluded, Some(true), "placeholder should be excluded");
    }

    // ── BOS grouping ────────────────────────────────────────────────────────

    #[test]
    fn test_bos_grouping() {
        let handler = OggIO::new("ogg");
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output = Cursor::new(Vec::new());

        handler
            .write_cai(&mut input, &mut output, TEST_MANIFEST)
            .unwrap();

        output.rewind().unwrap();
        let pages = read_all_pages(&mut output).unwrap();

        let mut seen_non_bos = false;
        for page in &pages {
            if page.is_bos() {
                assert!(
                    !seen_non_bos,
                    "BOS page found after non-BOS page: serial {}",
                    page.serial_number,
                );
            } else {
                seen_non_bos = true;
            }
        }
    }

    // ── Supported types ─────────────────────────────────────────────────────

    #[test]
    fn test_supported_types() {
        let handler = OggIO::new("ogg");
        let types = handler.supported_types();
        assert!(types.contains(&"ogg"), "missing ogg");
        assert!(types.contains(&"audio/ogg"), "missing audio/ogg");
        assert!(types.contains(&"opus"), "missing opus");
        assert!(types.contains(&"audio/opus"), "missing audio/opus");
    }

    // ── Handler construction ────────────────────────────────────────────────

    #[test]
    fn test_get_handler_and_reader() {
        let handler = OggIO::new("ogg");
        let new_handler = handler.get_handler("audio/ogg");
        let reader = handler.get_reader();

        let mut cursor = Cursor::new(SAMPLE_OGG);
        match reader.read_cai(&mut cursor) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("unexpected: {:?}", other),
        }
        assert!(new_handler.supported_types().contains(&"audio/ogg"));
    }

    // ── Remote ref unsupported ──────────────────────────────────────────────

    #[test]
    fn test_embed_reference_unsupported() {
        let handler = OggIO::new("ogg");
        let mut input = Cursor::new(SAMPLE_OGG);
        let mut output = Cursor::new(Vec::new());
        let result = handler.embed_reference_to_stream(
            &mut input,
            &mut output,
            RemoteRefEmbedType::Xmp("https://example.com".to_string()),
        );
        assert!(
            matches!(result, Err(Error::UnsupportedType)),
            "expected UnsupportedType for OGG remote ref"
        );
    }

    // ── File-based read/write ───────────────────────────────────────────────

    #[test]
    fn test_file_roundtrip() {
        let handler = OggIO::new("ogg");
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("file_roundtrip.ogg");

        fs::write(&temp_path, SAMPLE_OGG).unwrap();
        handler.save_cai_store(&temp_path, TEST_MANIFEST).unwrap();

        let read_back = handler.read_cai_store(&temp_path).unwrap();
        assert_eq!(read_back, TEST_MANIFEST);
    }

    #[test]
    fn test_file_remove() {
        let handler = OggIO::new("ogg");
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path().join("file_remove.ogg");

        fs::write(&temp_path, SAMPLE_OGG).unwrap();
        handler.save_cai_store(&temp_path, TEST_MANIFEST).unwrap();
        handler.remove_cai_store(&temp_path).unwrap();

        match handler.read_cai_store(&temp_path) {
            Err(Error::JumbfNotFound) => {}
            other => panic!("expected JumbfNotFound after file removal, got {:?}", other),
        }
    }

    #[test]
    fn test_read_cai_store_file_not_found() {
        let handler = OggIO::new("ogg");
        let path = Path::new("/nonexistent/sample.ogg");
        match handler.read_cai_store(path) {
            Err(Error::IoError(_)) => {}
            other => panic!("expected IoError for missing file, got {:?}", other),
        }
    }

}
