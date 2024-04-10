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
    Some(match extension {
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
    Some(match format {
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
        "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => "c2pa",
        _ => return None,
    })
}
