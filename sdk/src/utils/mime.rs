// Copyright 2022 Adobe. All rights reserved.
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

/// Converts a file extension to a MIME type
pub fn extension_to_mime(extension: &str) -> Option<&'static str> {
    Some(match extension.to_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "psd" => "image/vnd.adobe.photoshop",
        "tiff" | "tif" => "image/tiff",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "dng" => "image/x-adobe-dng",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "mp2" | "mpa" | "mpe" | "mpeg" | "mpg" | "mpv2" => "video/mpeg",
        "mp4" => "video/mp4",
        "avi" => "video/avi",
        "avif" => "image/avif",
        "mov" | "qt" => "video/quicktime",
        "m4a" => "audio/mp4",
        "mid" | "rmi" => "audio/mid",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "aif" | "aifc" | "aiff" => "audio/aiff",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "ai" => "application/postscript",
        "arw" => "image/x-sony-arw",
        "nef" => "image/x-nikon-nef",
        "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => "application/c2pa",
        _ => return None,
    })
}

/// Convert a format to a MIME type
/// formats can be passed in as extensions, e.g. "jpg" or "jpeg"
/// or as MIME types, e.g. "image/jpeg"
pub fn format_to_mime(format: &str) -> String {
    match extension_to_mime(format) {
        Some(mime) => mime,
        None => format,
    }
    .to_string()
}

/// Converts a format to a file extension
#[cfg(feature = "file_io")]
pub fn format_to_extension(format: &str) -> Option<&'static str> {
    Some(match format.to_lowercase().as_str() {
        "jpg" | "jpeg" | "image/jpeg" => "jpg",
        "png" | "image/png" => "png",
        "gif" | "image/gif" => "gif",
        "psd" | "image/vnd.adobe.photoshop" => "psd",
        "tiff" | "tif" | "image/tiff" => "tiff",
        "svg" | "image/svg+xml" => "svg",
        "ico" | "image/x-icon" => "ico",
        "bmp" | "image/bmp" => "bmp",
        "webp" | "image/webp" => "webp",
        "dng" | "image/dng" => "dng",
        "heic" | "image/heic" => "heic",
        "heif" | "image/heif" => "heif",
        "mp2" | "mpa" | "mpe" | "mpeg" | "mpg" | "mpv2" | "video/mpeg" => "mp2",
        "mp4" | "video/mp4" => "mp4",
        "avif" | "image/avif" => "avif",
        "avi" | "video/avi" => "avi",
        "mov" | "qt" | "video/quicktime" => "mov",
        "m4a" | "audio/mp4" => "m4a",
        "mid" | "rmi" | "audio/mid" => "mid",
        "mp3" | "audio/mpeg" => "mp3",
        "flac" | "audio/flac" => "flac",
        "wav" | "audio/wav" | "audio/wave" | "audio.vnd.wave" => "wav",
        "aif" | "aifc" | "aiff" | "audio/aiff" => "aif",
        "ogg" | "audio/ogg" => "ogg",
        "pdf" | "application/pdf" => "pdf",
        "ai" | "application/postscript" => "ai",
        "arw" | "image/x-sony-arw" => "arw",
        "nef" | "image/x-nikon-nef" => "nef",
        "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => "c2pa",
        _ => return None,
    })
}

/// Return a MIME type given a file path.
///
/// This function will use the file extension to determine the MIME type.
pub fn format_from_path<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    path.as_ref().extension().map(|ext| {
        crate::utils::mime::format_to_mime(ext.to_string_lossy().to_lowercase().as_ref())
    })
}

/// Detect the MIME type of a stream by inspecting its leading bytes.
///
/// Reads up to 16 bytes from the beginning of the stream, matches them
/// against well-known binary magic signatures, then rewinds the stream
/// before returning. Returns `None` when the format cannot be identified
/// from the leading bytes alone.
///
/// For streams carrying ID3-tagged audio the function decodes the ID3v2
/// sync-safe tag size and peeks past the tag header to determine whether
/// the payload is FLAC (`fLaC` marker) or MP3 (anything else).
pub fn format_from_stream<R: std::io::Read + std::io::Seek>(stream: &mut R) -> Option<String> {
    use std::io::SeekFrom;

    stream.rewind().ok()?;
    let mut buf = [0u8; 16];
    // `read` may return fewer bytes than requested for short streams.
    let n = stream.read(&mut buf).ok()?;
    stream.rewind().ok()?;

    if n < 2 {
        return None;
    }

    // JPEG: FF D8 FF
    if n >= 3 && buf[0] == 0xff && buf[1] == 0xd8 && buf[2] == 0xff {
        return Some("image/jpeg".to_string());
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if n >= 8 && buf[0..8] == [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] {
        return Some("image/png".to_string());
    }

    // GIF87a or GIF89a
    if n >= 6 && &buf[0..3] == b"GIF" && (&buf[3..6] == b"87a" || &buf[3..6] == b"89a") {
        return Some("image/gif".to_string());
    }

    // TIFF (standard and BigTIFF), both byte orders
    if n >= 4
        && (buf[0..4] == [0x49, 0x49, 0x2A, 0x00]   // TIFF little-endian
            || buf[0..4] == [0x4D, 0x4D, 0x00, 0x2A] // TIFF big-endian
            || buf[0..4] == [0x49, 0x49, 0x2B, 0x00] // BigTIFF little-endian
            || buf[0..4] == [0x4D, 0x4D, 0x00, 0x2B])
    // BigTIFF big-endian
    {
        return Some("image/tiff".to_string());
    }

    // JPEG XL container: 00 00 00 0C 4A 58 4C 20 0D 0A 87 0A
    if n >= 12
        && buf[0..12]
            == [
                0x00, 0x00, 0x00, 0x0c, 0x4a, 0x58, 0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a,
            ]
    {
        return Some("image/jxl".to_string());
    }

    // RIFF family: "RIFF" at bytes 0-3, four-CC format tag at bytes 8-11
    if n >= 12 && &buf[0..4] == b"RIFF" {
        return Some(
            match &buf[8..12] {
                b"WEBP" => "image/webp",
                b"AVI " => "video/avi",
                _ => "audio/wav", // WAVE and other unknown RIFF variants
            }
            .to_string(),
        );
    }

    // BMFF family: ISO 14496-12 box type "ftyp" at bytes 4-7.
    // Use the major brand at bytes 8-11 to pick the most specific MIME type.
    if n >= 12 && &buf[4..8] == b"ftyp" {
        return Some(
            match &buf[8..12] {
                b"heic" | b"heis" | b"heim" | b"heix" | b"hevc" | b"hevx" => "image/heic",
                b"mif1" | b"msf1" => "image/heif",
                b"avif" | b"avis" => "image/avif",
                b"qt  " => "video/quicktime",
                b"M4A " => "audio/mp4",
                _ => "video/mp4", // generic BMFF fallback (mp4, isom, m4v, …)
            }
            .to_string(),
        );
    }

    // FLAC: fLaC marker
    if n >= 4 && &buf[0..4] == b"fLaC" {
        return Some("audio/flac".to_string());
    }

    // ID3 header: may precede either MP3 or FLAC audio.
    // Decode the sync-safe 28-bit tag size at bytes 6-9 and peek past the
    // tag to see whether the payload starts with the fLaC marker.
    if n >= 10 && &buf[0..3] == b"ID3" {
        let tag_size = ((buf[6] as u64 & 0x7f) << 21)
            | ((buf[7] as u64 & 0x7f) << 14)
            | ((buf[8] as u64 & 0x7f) << 7)
            | (buf[9] as u64 & 0x7f);
        let flac_offset = 10 + tag_size;
        let mut marker = [0u8; 4];
        let is_flac = stream
            .seek(SeekFrom::Start(flac_offset))
            .and_then(|_| stream.read_exact(&mut marker))
            .map(|_| &marker == b"fLaC")
            .unwrap_or(false);
        let _ = stream.rewind();
        return Some(if is_flac { "audio/flac" } else { "audio/mpeg" }.to_string());
    }

    // MPEG audio frame sync: 0xFF followed by 0xE0–0xFF (11 high sync bits)
    if n >= 2 && buf[0] == 0xff && (buf[1] & 0xe0 == 0xe0) {
        return Some("audio/mpeg".to_string());
    }

    // PDF: %PDF
    if n >= 4 && &buf[0..4] == b"%PDF" {
        return Some("application/pdf".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::format_from_stream;

    fn detect(bytes: &[u8]) -> Option<String> {
        format_from_stream(&mut Cursor::new(bytes))
    }

    #[test]
    fn test_jpeg() {
        assert_eq!(
            detect(&[0xff, 0xd8, 0xff, 0xe0, 0, 0]),
            Some("image/jpeg".into())
        );
    }

    #[test]
    fn test_png() {
        assert_eq!(
            detect(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]),
            Some("image/png".into())
        );
    }

    #[test]
    fn test_gif() {
        assert_eq!(detect(b"GIF89a\x00\x00\x00\x00"), Some("image/gif".into()));
        assert_eq!(detect(b"GIF87a\x00\x00\x00\x00"), Some("image/gif".into()));
    }

    #[test]
    fn test_tiff_little_endian() {
        assert_eq!(
            detect(&[0x49, 0x49, 0x2a, 0x00, 0, 0, 0, 0]),
            Some("image/tiff".into())
        );
    }

    #[test]
    fn test_tiff_big_endian() {
        assert_eq!(
            detect(&[0x4d, 0x4d, 0x00, 0x2a, 0, 0, 0, 0]),
            Some("image/tiff".into())
        );
    }

    #[test]
    fn test_bigtiff() {
        assert_eq!(
            detect(&[0x49, 0x49, 0x2b, 0x00, 0, 0, 0, 0]),
            Some("image/tiff".into())
        );
    }

    #[test]
    fn test_jxl() {
        assert_eq!(
            detect(&[0x00, 0x00, 0x00, 0x0c, 0x4a, 0x58, 0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a]),
            Some("image/jxl".into())
        );
    }

    #[test]
    fn test_webp() {
        let mut bytes = *b"RIFF\x00\x00\x00\x00WEBP";
        assert_eq!(detect(&bytes), Some("image/webp".into()));
        // mutate brand bytes — should still be RIFF but fall through to wav
        bytes[8..12].copy_from_slice(b"WAVE");
        assert_eq!(detect(&bytes), Some("audio/wav".into()));
    }

    #[test]
    fn test_avi() {
        assert_eq!(
            detect(b"RIFF\x00\x00\x00\x00AVI "),
            Some("video/avi".into())
        );
    }

    #[test]
    fn test_mp4() {
        // ftypisom
        let mut b = [0u8; 12];
        b[4..8].copy_from_slice(b"ftyp");
        b[8..12].copy_from_slice(b"isom");
        assert_eq!(detect(&b), Some("video/mp4".into()));
    }

    #[test]
    fn test_heic() {
        let mut b = [0u8; 12];
        b[4..8].copy_from_slice(b"ftyp");
        b[8..12].copy_from_slice(b"heic");
        assert_eq!(detect(&b), Some("image/heic".into()));
    }

    #[test]
    fn test_heif() {
        let mut b = [0u8; 12];
        b[4..8].copy_from_slice(b"ftyp");
        b[8..12].copy_from_slice(b"mif1");
        assert_eq!(detect(&b), Some("image/heif".into()));
    }

    #[test]
    fn test_avif() {
        let mut b = [0u8; 12];
        b[4..8].copy_from_slice(b"ftyp");
        b[8..12].copy_from_slice(b"avif");
        assert_eq!(detect(&b), Some("image/avif".into()));
    }

    #[test]
    fn test_quicktime() {
        let mut b = [0u8; 12];
        b[4..8].copy_from_slice(b"ftyp");
        b[8..12].copy_from_slice(b"qt  ");
        assert_eq!(detect(&b), Some("video/quicktime".into()));
    }

    #[test]
    fn test_m4a() {
        let mut b = [0u8; 12];
        b[4..8].copy_from_slice(b"ftyp");
        b[8..12].copy_from_slice(b"M4A ");
        assert_eq!(detect(&b), Some("audio/mp4".into()));
    }

    #[test]
    fn test_flac() {
        assert_eq!(detect(b"fLaC\x00\x00\x00\x00"), Some("audio/flac".into()));
    }

    #[test]
    fn test_mp3_mpeg_sync() {
        // Plain MPEG frame sync header
        assert_eq!(detect(&[0xff, 0xfb, 0x90, 0x00]), Some("audio/mpeg".into()));
    }

    #[test]
    fn test_id3_mp3() {
        // ID3 tag with size=0 followed by non-fLaC bytes
        let mut bytes = vec![0u8; 20];
        bytes[0..3].copy_from_slice(b"ID3");
        bytes[3] = 3; // version
        bytes[4] = 0; // flags
                      // sync-safe size bytes 6-9, all 0 → tag_size = 0
                      // bytes 10+ = payload (not fLaC)
        bytes[10..14].copy_from_slice(b"XYZ!");
        assert_eq!(
            format_from_stream(&mut Cursor::new(&bytes)),
            Some("audio/mpeg".into())
        );
    }

    #[test]
    fn test_id3_flac() {
        // ID3 tag with size=0, payload is fLaC
        let mut bytes = vec![0u8; 20];
        bytes[0..3].copy_from_slice(b"ID3");
        // sync-safe size = 0 → payload at offset 10
        bytes[10..14].copy_from_slice(b"fLaC");
        assert_eq!(
            format_from_stream(&mut Cursor::new(&bytes)),
            Some("audio/flac".into())
        );
    }

    #[test]
    fn test_pdf() {
        assert_eq!(detect(b"%PDF-1.4\n"), Some("application/pdf".into()));
    }

    #[test]
    fn test_unknown_returns_none() {
        assert_eq!(detect(&[0x00u8; 16]), None);
    }

    #[test]
    fn test_stream_is_rewound_after_call() {
        use std::io::{Cursor, Seek as _};
        let mut cursor = Cursor::new(vec![0xff, 0xd8, 0xff, 0xe0, 0, 0]);
        let _ = format_from_stream(&mut cursor);
        assert_eq!(
            cursor.position(),
            0,
            "stream must be rewound after detection"
        );
    }
}
