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
        "wav" => "audio/wav",
        "aif" | "aifc" | "aiff" => "audio/aiff",
        "ogg" => "audio/ogg",
        "pdf" => "application/pdf",
        "ai" => "application/postscript",
        "arw" => "image/x-sony-arw",
        "nef" => "image/x-nikon-nef",
        "m4v" => "video/x-m4v",
        "3gp" => "video/3gpp",
        "3g2" => "video/3g2",
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
        "wav" | "audio/wav" | "audio/wave" | "audio.vnd.wave" => "wav",
        "aif" | "aifc" | "aiff" | "audio/aiff" => "aif",
        "ogg" | "audio/ogg" => "ogg",
        "pdf" | "application/pdf" => "pdf",
        "ai" | "application/postscript" => "ai",
        "arw" | "image/x-sony-arw" => "arw",
        "nef" | "image/x-nikon-nef" => "nef",
        "m4v" | "video/x-m4v" => "m4v",
        "3gp" | "video/3gpp" => "3gp",
        "3g2" | "video/3g2" => "3g2",
        "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => "c2pa",
        _ => return None,
    })
}

/// Return a MIME type given a file path.
///
/// This function will use the file content (magic bytes) to determine the MIME type.
/// If the format cannot be determined from content, it will fall back to using the file extension.
pub fn format_from_path<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    let path = path.as_ref();

    // try to detect from content first if we have file_io
    #[cfg(feature = "file_io")]
    if let Some(format) = detect_format_from_path(path) {
        return Some(format);
    }

    // fallback to extension
    path.extension()
        .and_then(|ext| extension_to_mime(ext.to_string_lossy().to_lowercase().as_ref()))
        .map(|m| m.to_owned())
}

/// Detect a MIME type from the content of a file.
#[cfg(feature = "file_io")]
pub fn detect_format_from_path<P: AsRef<std::path::Path>>(path: P) -> Option<String> {
    std::fs::File::open(path).ok().and_then(|mut file| {
        detect_format_from_stream(&mut file)
    })
}

/// Detect a MIME type from a stream of bytes.
pub fn detect_format_from_stream<R: std::io::Read + std::io::Seek + ?Sized>(stream: &mut R) -> Option<String> {
    let _ = stream.rewind();
    let mut buffer = [0u8; 512];
    let n = stream.read(&mut buffer).ok()?;
    let _ = stream.rewind(); // attempt to rewind, but don't fail if we can't
    crate::jumbf_io::format_from_bytes(&buffer[..n])
}

/// Returns a MIME type given a stream of bytes.
#[allow(dead_code)]
pub fn get_mime_from_bytes(data: &[u8]) -> Option<String> {
    crate::jumbf_io::format_from_bytes(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_mime_from_bytes() {
        assert_eq!(get_mime_from_bytes(&[0xff, 0xd8, 0xff, 0xe0]), Some("image/jpeg".to_string()));
        assert_eq!(get_mime_from_bytes(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Some("image/png".to_string()));
        assert_eq!(get_mime_from_bytes(b"GIF87a"), Some("image/gif".to_string()));
        assert_eq!(get_mime_from_bytes(b"GIF89a"), Some("image/gif".to_string()));
        assert_eq!(get_mime_from_bytes(&[0x49, 0x49, 0x2a, 0x00]), Some("image/tiff".to_string()));
        assert_eq!(get_mime_from_bytes(&[0x4d, 0x4d, 0x00, 0x2a]), Some("image/tiff".to_string()));
        // assert_eq!(get_mime_from_bytes(b"BM"), Some("image/bmp".to_string())); // BMP not currently in handlers list
        #[cfg(feature = "pdf")]
        assert_eq!(get_mime_from_bytes(b"%PDF-1.4"), Some("application/pdf".to_string()));
        assert_eq!(get_mime_from_bytes(b"RIFF\0\0\0\0WEBP"), Some("image/webp".to_string()));
        assert_eq!(get_mime_from_bytes(b"RIFF\0\0\0\0WAVE"), Some("audio/wav".to_string()));
        assert_eq!(get_mime_from_bytes(b"RIFF\0\0\0\0AVI "), Some("video/avi".to_string()));
        assert_eq!(get_mime_from_bytes(b"ID3\x03\0\0\0\0\0\0"), Some("audio/mpeg".to_string()));
        assert_eq!(get_mime_from_bytes(&[0x00, 0x00, 0x00, 0x18, b'f', b't', b'y', b'p', b'm', b'p', b'4', b'2']), Some("video/mp4".to_string()));
        assert_eq!(get_mime_from_bytes(&[0x00, 0x00, 0x00, 0x18, b'f', b't', b'y', b'p', b'h', b'e', b'i', b'c']), Some("image/heic".to_string()));
        assert_eq!(get_mime_from_bytes(b"<svg xmlns=\"http://www.w3.org/2000/svg\">"), Some("image/svg+xml".to_string()));
        assert_eq!(get_mime_from_bytes(b"<?xml version=\"1.0\"?><svg>"), Some("image/svg+xml".to_string()));
        assert_eq!(get_mime_from_bytes(&[0x00, 0x00, 0x00, 0x0c, b'j', b'u', b'm', b'b']), Some("application/c2pa".to_string()));
    }

    #[test]
    fn test_format_from_path() {
        use std::io::Write;
        let mut temp = tempfile::NamedTempFile::new().unwrap();
        temp.write_all(&[0xff, 0xd8, 0xff, 0xe0]).unwrap();
        let path = temp.path();
        
        // No extension, should detect from content
        assert_eq!(format_from_path(path), Some("image/jpeg".to_string()));
    }
}
