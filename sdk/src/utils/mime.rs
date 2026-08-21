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
        #[cfg(feature = "unstable_live_video")]
        "m4s" => "video/mp4",
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

/// Normalizes a format string (extension or MIME type) into a canonical
/// lookup key: surrounding whitespace is trimmed and the value is lowercased.
pub(crate) fn normalize_format(format: &str) -> String {
    format.trim().to_lowercase()
}

/// Convert a format to a MIME type
/// formats can be passed in as extensions, e.g. "jpg" or "jpeg"
/// or as MIME types, e.g. "image/jpeg"
/// MIME types are case-insensitive (RFC 2045 section 5.1), so the format is
/// trimmed to remove surrounding whitespaces and lowercased before matching.
pub fn format_to_mime(format: &str) -> String {
    let format = normalize_format(format);
    match extension_to_mime(&format) {
        Some(mime) => mime.to_string(),
        None => format,
    }
}

/// Converts a format to a file extension (not used anymore but maybe we want it later?)
#[allow(unused)]
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
        #[cfg(feature = "unstable_live_video")]
        "m4s" | "video/iso.segment" => "m4s",
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

#[cfg(test)]
mod tests {
    use super::*;

    /// MIME type and subtype are case-insensitive per RFC 2045 section 5.1.
    /// An uppercase spelling must normalize to the canonical lowercase form.
    #[test]
    fn test_format_to_mime_uppercase() {
        assert_eq!(format_to_mime("IMAGE/JPEG"), "image/jpeg");
        assert_eq!(format_to_mime("Image/Png"), "image/png");
        assert_eq!(format_to_mime("JPG"), "image/jpeg");
        assert_eq!(format_to_mime("PNG"), "image/png");
    }

    #[test]
    fn test_format_to_mime_lowercase_unchanged() {
        assert_eq!(format_to_mime("image/jpeg"), "image/jpeg");
        assert_eq!(format_to_mime("jpg"), "image/jpeg");
        assert_eq!(format_to_mime("image/svg+xml"), "image/svg+xml");
    }

    #[test]
    fn test_format_to_mime_trims_whitespace() {
        assert_eq!(format_to_mime("  image/jpeg  "), "image/jpeg");
        assert_eq!(format_to_mime("\timage/png\n"), "image/png");
        assert_eq!(format_to_mime("  JPG  "), "image/jpeg");
        assert_eq!(format_to_mime("  image/svg+xml  "), "image/svg+xml");
    }
}
