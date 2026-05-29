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
        "jxl" => "image/jxl",
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
    use crate::utils::test::create_test_stream;

    fn detect_fixture(name: &str) {
        let (expected, mut stream) = create_test_stream(name);
        let detected = format_from_stream(&mut stream);
        assert_eq!(
            detected.as_deref(),
            Some(expected),
            "format_from_stream mismatch for {name}"
        );
    }

    #[test]
    fn test_jpeg() {
        detect_fixture("CA.jpg");
    }

    #[test]
    fn test_png() {
        detect_fixture("libpng-test.png");
    }

    #[test]
    fn test_gif() {
        detect_fixture("sample1.gif");
    }

    #[test]
    fn test_tiff() {
        detect_fixture("TUSCANY.TIF");
    }

    // BigTIFF has no fixture file; test the magic bytes directly.
    #[test]
    fn test_bigtiff() {
        let mut cursor = Cursor::new([0x49u8, 0x49, 0x2b, 0x00, 0, 0, 0, 0]);
        assert_eq!(format_from_stream(&mut cursor), Some("image/tiff".into()));
    }

    #[test]
    fn test_jxl() {
        detect_fixture("sample1.jxl");
    }

    #[test]
    fn test_webp() {
        detect_fixture("sample1.webp");
    }

    #[test]
    fn test_avi() {
        detect_fixture("test.avi");
    }

    #[test]
    fn test_mp4() {
        detect_fixture("video1.mp4");
    }

    #[test]
    fn test_heic() {
        detect_fixture("sample1.heic");
    }

    #[test]
    fn test_heif() {
        detect_fixture("sample1.heif");
    }

    #[test]
    fn test_avif() {
        detect_fixture("sample1.avif");
    }

    #[test]
    fn test_quicktime() {
        detect_fixture("c.mov");
    }

    #[test]
    fn test_m4a() {
        detect_fixture("sample1.m4a");
    }

    #[test]
    fn test_flac() {
        detect_fixture("sample1.flac");
    }

    #[test]
    fn test_mp3() {
        detect_fixture("sample1.mp3");
    }

    #[test]
    fn test_wav() {
        detect_fixture("sample1.wav");
    }

    /// Test that an ID3-tagged FLAC file is correctly identified as audio/flac, not audio/mpeg.
    /// we don't have a real FLAC fixture with an ID3 tag, so we construct a synthetic o
    #[test]
    fn test_id3_flac() {
        // ID3 tag with size=0, payload is fLaC → FLAC
        let mut bytes = vec![0u8; 20];
        bytes[0..3].copy_from_slice(b"ID3");
        bytes[10..14].copy_from_slice(b"fLaC");
        assert_eq!(
            format_from_stream(&mut Cursor::new(&bytes)),
            Some("audio/flac".into())
        );
    }

    #[test]
    fn test_pdf() {
        detect_fixture("basic.pdf");
    }

    #[test]
    fn test_unknown_returns_none() {
        let mut cursor = Cursor::new([0x00u8; 16]);
        assert_eq!(format_from_stream(&mut cursor), None);
    }

    #[test]
    fn test_stream_is_rewound_after_call() {
        let (_, mut stream) = create_test_stream("CA.jpg");
        let _ = format_from_stream(&mut stream);
        assert_eq!(
            stream.position(),
            0,
            "stream must be rewound after detection"
        );
    }
}
