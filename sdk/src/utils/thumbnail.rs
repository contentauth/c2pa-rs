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

use crate::Result;
use image::ImageFormat;

///  utility to generate a thumbnail from a file at path
/// returns Result (format, image_bits) if successful, otherwise Error
pub fn make_thumbnail(path: &std::path::Path) -> Result<(String, Vec<u8>)> {
    let format = ImageFormat::from_path(path)?;

    // max edge size allowed in pixels for thumbnail creation
    const THUMBNAIL_LONGEST_EDGE: u32 = 1024;
    const THUMBNAIL_JPEG_QUALITY: u8 = 80; // JPEG quality 1-100

    let mut img = image::open(path)?;
    let longest_edge = THUMBNAIL_LONGEST_EDGE;

    // generate a thumbnail image scaled down and in jpeg format
    if img.width() > longest_edge || img.height() > longest_edge {
        img = img.thumbnail(longest_edge, longest_edge);
    }

    // for png files, use png thumbnails for transparency
    // for other supported types try a jpeg thumbnail
    let (output_format, content_type) = match format {
        ImageFormat::Png => (image::ImageOutputFormat::Png, "image/png"),
        _ => (
            image::ImageOutputFormat::Jpeg(THUMBNAIL_JPEG_QUALITY),
            "image/jpeg",
        ),
    };
    let thumbnail_bits = Vec::new();
    let mut cursor = std::io::Cursor::new(thumbnail_bits);
    img.write_to(&mut cursor, output_format)?;

    let format = content_type.to_owned();
    Ok((format, cursor.into_inner()))
}
