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

use std::io::{Read, Seek};

use anyhow::{Error, Result};
use image::{io::Reader, ImageFormat};

// max edge size allowed in pixels for thumbnail creation
const THUMBNAIL_LONGEST_EDGE: u32 = 1024;

///  utility to generate a thumbnail from a stream
/// returns Result (format, image_bits) if successful, otherwise Error
pub fn make_thumbnail_from_stream<R: Read + Seek + ?Sized>(
    format: &str,
    stream: &mut R,
) -> Result<(String, Vec<u8>)> {
    let format = ImageFormat::from_extension(format)
        .or_else(|| ImageFormat::from_mime_type(format))
        .ok_or(Error::msg(format!("format not supported {format}")))?;

    let reader = Reader::with_format(std::io::BufReader::new(stream), format);
    let mut img = reader.decode()?;

    let longest_edge = THUMBNAIL_LONGEST_EDGE;

    // generate a thumbnail image scaled down and in jpeg format
    if img.width() > longest_edge || img.height() > longest_edge {
        img = img.thumbnail(longest_edge, longest_edge);
    }

    // for png files, use png thumbnails for transparency
    // for other supported types try a jpeg thumbnail
    let (output_format, format) = match format {
        ImageFormat::Png => (ImageFormat::Png, "image/png"),
        _ => (ImageFormat::Jpeg, "image/jpeg"),
    };
    let thumbnail_bits = Vec::new();
    let mut cursor = std::io::Cursor::new(thumbnail_bits);
    img.write_to(&mut cursor, output_format)?;

    let format = format.to_owned();
    Ok((format, cursor.into_inner()))
}
