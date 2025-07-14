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

use image::{codecs::jpeg::JpegEncoder, DynamicImage, ImageDecoder, ImageFormat, ImageReader};

use crate::{Error, Result};

// max edge size allowed in pixels for thumbnail creation
const THUMBNAIL_LONGEST_EDGE: u32 = 1024;
const THUMBNAIL_JPEG_QUALITY: u8 = 80;

///  utility to generate a thumbnail from a file at path
/// returns Result (format, image_bits) if successful, otherwise Error
#[cfg(feature = "file_io")]
pub fn make_thumbnail(path: &std::path::Path) -> Result<(String, Vec<u8>)> {
    let format = ImageFormat::from_path(path)?;

    // Take the orientation from the EXIF data and manipulate the pixels to match
    let mut decoder = ImageReader::open(path)?.into_decoder()?;
    let orientation = decoder.orientation()?;
    let mut img = DynamicImage::from_decoder(decoder)?;
    img.apply_orientation(orientation);

    let longest_edge = THUMBNAIL_LONGEST_EDGE;

    // generate a thumbnail image scaled down and in jpeg format
    if img.width() > longest_edge || img.height() > longest_edge {
        img = img.thumbnail(longest_edge, longest_edge);
    }

    let thumbnail_bits = Vec::new();
    let mut cursor = std::io::Cursor::new(thumbnail_bits);
    // for png files, use png thumbnails if there is an alpha channel
    // for other supported types try a jpeg thumbnail
    let format = match format {
        ImageFormat::Png if img.color().has_alpha() => {
            img.write_to(&mut cursor, ImageFormat::Png)?;
            "image/png"
        }

        _ => {
            let mut encoder = JpegEncoder::new_with_quality(&mut cursor, THUMBNAIL_JPEG_QUALITY);
            encoder.encode_image(&img)?;
            "image/jpeg"
        }
    };

    let format = format.to_owned();
    Ok((format, cursor.into_inner()))
}

///  utility to generate a thumbnail from a file at path
/// returns Result (format, image_bits) if successful, otherwise Error
pub fn make_thumbnail_from_stream<R: Read + Seek + ?Sized>(
    format: &str,
    stream: &mut R,
) -> Result<(String, Vec<u8>)> {
    let format = ImageFormat::from_extension(format)
        .or_else(|| ImageFormat::from_mime_type(format))
        .ok_or(Error::UnsupportedType)?;

    // Take the orientation from the EXIF data and manipulate the pixels to match
    let mut decoder =
        ImageReader::with_format(std::io::BufReader::new(stream), format).into_decoder()?;
    let orientation = decoder.orientation()?;
    let mut img = DynamicImage::from_decoder(decoder)?;
    img.apply_orientation(orientation);

    let longest_edge = THUMBNAIL_LONGEST_EDGE;

    // generate a thumbnail image scaled down and in jpeg format
    if img.width() > longest_edge || img.height() > longest_edge {
        img = img.thumbnail(longest_edge, longest_edge);
    }

    let thumbnail_bits = Vec::new();
    let mut cursor = std::io::Cursor::new(thumbnail_bits);
    // for png files, use png thumbnails for transparency
    // for other supported types try a jpeg thumbnail
    let format = match format {
        ImageFormat::Png if img.color().has_alpha() => {
            img.write_to(&mut cursor, ImageFormat::Png)?;
            "image/png"
        }

        _ => {
            let mut encoder = JpegEncoder::new_with_quality(&mut cursor, THUMBNAIL_JPEG_QUALITY);
            encoder.encode_image(&img)?;
            "image/jpeg"
        }
    };

    let format = format.to_owned();
    Ok((format, cursor.into_inner()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use image::GenericImageView;

    use super::*;

    fn create_test_jpeg_with_orientation(orientation: u16) -> Vec<u8> {
        use image::{ImageBuffer, Rgb, RgbImage};
        let width = 200;
        let height = 100;
        let mut img: RgbImage = ImageBuffer::new(width, height);

        for y in 0..height {
            for x in 0..width {
                let pixel = if x < width / 2 {
                    Rgb([255, 0, 0]) // Red on left half
                } else {
                    Rgb([0, 0, 255]) // Blue on right half
                };
                img.put_pixel(x, y, pixel);
            }
        }

        // Encode image to JPEG
        let mut jpeg_data = Vec::new();
        {
            let mut encoder =
                image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg_data, 90);
            encoder.encode_image(&img).unwrap();
        }

        // Insert EXIF orientation if not 1
        if orientation != 1 {
            let exif_data = vec![
                0xff,
                0xe1, // APP1 marker
                0x00,
                0x2c, // Length (44 bytes)
                0x45,
                0x78,
                0x69,
                0x66,
                0x00,
                0x00, // "Exif\0\0"
                0x49,
                0x49, // Little endian
                0x2a,
                0x00, // TIFF identifier
                0x08,
                0x00,
                0x00,
                0x00, // Offset to IFD
                0x01,
                0x00, // Number of entries
                0x12,
                0x01, // Orientation tag
                0x03,
                0x00, // SHORT type
                0x01,
                0x00,
                0x00,
                0x00, // Count
                orientation as u8,
                (orientation >> 8) as u8,
                0x00,
                0x00, // Value
                0x00,
                0x00,
                0x00,
                0x00, // Next IFD offset
            ];
            // Insert EXIF after SOI marker
            jpeg_data.splice(2..2, exif_data);
        }

        jpeg_data
    }

    #[test]
    fn test_make_thumbnail_exif_orientation_issue() {
        // Create test JPEGs with different orientations
        for orientation in 1..=8 {
            let jpeg_data = create_test_jpeg_with_orientation(orientation);

            // Generate thumbnail from stream
            let mut cursor = std::io::Cursor::new(&jpeg_data);
            let result = make_thumbnail_from_stream("jpg", &mut cursor);
            assert!(
                result.is_ok(),
                "Thumbnail should be generated for orientation {}",
                orientation
            );

            let (format, thumbnail_data) = result.unwrap();
            assert_eq!(format, "image/jpeg");

            let thumb = image::load_from_memory(&thumbnail_data).unwrap();

            // Select pixels from the corners
            let top_left_pixel = thumb.get_pixel(0, 0);
            let bottom_right_pixel = thumb.get_pixel(thumb.width() - 1, thumb.height() - 1);

            match orientation {
                1 | 4 | 5 | 6 => {
                    // 1 Normal, 2 flipped vertically
                    // RB
                    // RB
                    // 5 Rotated 90 CW then flipped horizontally, 6 Rotated 90 CW
                    // RR
                    // BB
                    assert!(
                        top_left_pixel.0[0] >= 250,
                        "Top-left should be red for orientation {}",
                        orientation
                    );
                    assert!(
                        bottom_right_pixel.0[2] >= 250,
                        "Bottom-right should be blue for orientation {}",
                        orientation
                    );
                }
                2 | 3 | 7 | 8 => {
                    // 2 Flipped horizontally, 3 rotated 180
                    // BR
                    // BR
                    // 7 Rotated 90 CCW then flipped horizontally, 8 rotated 90 CCW
                    // BB
                    // RR
                    assert!(
                        top_left_pixel.0[2] >= 250,
                        "Top-left should be blue for orientation {}",
                        orientation
                    );
                    assert!(
                        bottom_right_pixel.0[0] >= 250,
                        "Bottom-right should be red for orientation {}",
                        orientation
                    );
                }
                _ => unreachable!("Unexpected orientation value: {}", orientation),
            }
        }
    }
}
