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

//! Locates the `C2PA` chunk of a RIFF-based asset (WAV, WebP, AVI) so data hash
//! exclusions can be checked against the RIFF-specific validation rules. This
//! reads the chunk structure directly, independent of the asset handler in use.

use std::io::SeekFrom;

use crate::{asset_io::ReadSeek, utils::io_utils::stream_len};

/// Formats (extensions and MIME types) whose manifest is embedded in a RIFF `C2PA` chunk.
const RIFF_FORMATS: [&str; 13] = [
    "avi",
    "wav",
    "webp",
    "image/webp",
    "image/x-webp",
    "audio/wav",
    "audio/wave",
    "audio/x-wav",
    "audio/vnd.wave",
    "application/x-troff-msvideo",
    "video/avi",
    "video/msvideo",
    "video/x-msvideo",
];

/// Layout of the embedded `C2PA` chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RiffC2paChunk {
    /// Offset of the `C2PA` chunk identifier.
    pub offset: u64,
    /// Value of the chunk size field: the length of the chunk data, not counting any pad byte.
    pub data_len: u64,
    /// Value of the pad byte that follows odd-length chunk data, if present.
    pub pad: Option<u8>,
    /// Length of the JUMBF superbox at the start of the chunk data.
    pub jumbf_len: u64,
    /// Value of the last byte of the chunk data.
    pub last_data_byte: u8,
    /// End of the first top-level `RIFF` chunk, according to its size field.
    pub riff_end: u64,
}

impl RiffC2paChunk {
    /// Offset of the C2PA Manifest Store (the chunk data).
    pub fn data_start(&self) -> u64 {
        self.offset + 8
    }

    /// Offset one past the end of the chunk data.
    pub fn data_end(&self) -> u64 {
        self.data_start() + self.data_len
    }

    /// Offset one past the end of the chunk data and its pad byte, if any.
    pub fn padded_end(&self) -> u64 {
        self.data_end() + u64::from(self.pad.is_some())
    }

    /// True if the size field counts a trailing zero alignment byte that is not
    /// part of the JUMBF superbox, as some older writers did.
    pub fn size_counts_pad(&self) -> bool {
        self.data_len.is_multiple_of(2)
            && self.jumbf_len + 1 == self.data_len
            && self.last_data_byte == 0
    }
}

/// Locates the `C2PA` chunk within the first top-level `RIFF` chunk, or returns
/// `None` if `format` is not RIFF-based or the asset has no well-formed `C2PA` chunk.
pub(crate) fn riff_c2pa_chunk(format: &str, reader: &mut dyn ReadSeek) -> Option<RiffC2paChunk> {
    if !RIFF_FORMATS.contains(&format.to_lowercase().as_str()) {
        return None;
    }
    let file_len = stream_len(reader).ok()?;

    let mut header = [0u8; 12];
    reader.seek(SeekFrom::Start(0)).ok()?;
    reader.read_exact(&mut header).ok()?;
    if &header[0..4] != b"RIFF" {
        return None;
    }
    let riff_end = 8 + u64::from(u32::from_le_bytes(header[4..8].try_into().ok()?));

    let mut offset = 12u64;
    while offset + 8 <= riff_end.min(file_len) {
        let mut chunk_header = [0u8; 8];
        reader.seek(SeekFrom::Start(offset)).ok()?;
        reader.read_exact(&mut chunk_header).ok()?;
        let data_len = u64::from(u32::from_le_bytes(chunk_header[4..8].try_into().ok()?));

        if &chunk_header[0..4] == b"C2PA" {
            if data_len < 4 || offset + 8 + data_len > file_len {
                return None;
            }
            let mut jumbf_len = [0u8; 4];
            reader.read_exact(&mut jumbf_len).ok()?;

            reader
                .seek(SeekFrom::Start(offset + 8 + data_len - 1))
                .ok()?;
            let mut last_data_byte = [0u8; 1];
            reader.read_exact(&mut last_data_byte).ok()?;
            let mut pad = [0u8; 1];
            let pad = (data_len % 2 == 1 && reader.read_exact(&mut pad).is_ok()).then_some(pad[0]);

            return Some(RiffC2paChunk {
                offset,
                data_len,
                pad,
                jumbf_len: u64::from(u32::from_be_bytes(jumbf_len)),
                last_data_byte: last_data_byte[0],
                riff_end,
            });
        }

        offset = offset.checked_add(8 + data_len + (data_len % 2))?;
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    /// A WebP-like RIFF file with one media chunk followed by a `C2PA` chunk
    /// holding `data` (whose first four bytes are the JUMBF superbox length).
    fn riff_with_c2pa(data: &[u8], pad: Option<u8>) -> Vec<u8> {
        let mut riff = b"RIFF\0\0\0\0WEBPVP8 \x03\0\0\0abc\0".to_vec();
        riff.extend_from_slice(b"C2PA");
        riff.extend_from_slice(&(data.len() as u32).to_le_bytes());
        riff.extend_from_slice(data);
        riff.extend(pad);
        let riff_size = (riff.len() - 8) as u32;
        riff[4..8].copy_from_slice(&riff_size.to_le_bytes());
        riff
    }

    #[test]
    fn locates_odd_length_c2pa_chunk_and_pad_byte() {
        let asset = riff_with_c2pa(&[0, 0, 0, 5, 9], Some(0));
        let chunk = riff_c2pa_chunk("image/webp", &mut Cursor::new(&asset)).unwrap();
        assert_eq!(
            chunk,
            RiffC2paChunk {
                offset: 24,
                data_len: 5,
                pad: Some(0),
                jumbf_len: 5,
                last_data_byte: 9,
                riff_end: asset.len() as u64,
            }
        );
        assert_eq!(chunk.data_end(), 37);
        assert_eq!(chunk.padded_end(), 38);
        assert!(!chunk.size_counts_pad());
    }

    #[test]
    fn detects_size_field_counting_pad_byte() {
        let asset = riff_with_c2pa(&[0, 0, 0, 5, 9, 0], None);
        let chunk = riff_c2pa_chunk("webp", &mut Cursor::new(&asset)).unwrap();
        assert_eq!(chunk.pad, None);
        assert!(chunk.size_counts_pad());
    }

    #[test]
    fn ignores_non_riff_formats_and_missing_chunks() {
        let asset = riff_with_c2pa(&[0, 0, 0, 4], None);
        assert!(riff_c2pa_chunk("image/jpeg", &mut Cursor::new(&asset)).is_none());

        let mut no_c2pa = asset.clone();
        no_c2pa[24..28].copy_from_slice(b"XMP ");
        assert!(riff_c2pa_chunk("image/webp", &mut Cursor::new(&no_c2pa)).is_none());

        // A size field running past the end of the file is not a usable chunk.
        let mut truncated = asset;
        truncated[28..32].copy_from_slice(&100u32.to_le_bytes());
        assert!(riff_c2pa_chunk("image/webp", &mut Cursor::new(&truncated)).is_none());
    }
}
