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

use std::{
    fmt,
    io::{BufRead, Cursor, Seek, Write},
};

use image::{
    codecs::{
        jpeg::JpegEncoder,
        png::{CompressionType, FilterType, PngEncoder},
    },
    DynamicImage, ImageDecoder, ImageFormat, ImageReader,
};

use crate::{
    settings::{
        builder::{ThumbnailFormat, ThumbnailQuality},
        Settings,
    },
    Error, Result,
};

impl ThumbnailFormat {
    /// Create a new [ThumbnailFormat] from the given format extension or mime type.
    ///
    /// If the format is unsupported, this function will return `None`.
    pub fn new(format: &str) -> Option<ThumbnailFormat> {
        ImageFormat::from_extension(format)
            .or_else(|| ImageFormat::from_mime_type(format))
            .and_then(|format| ThumbnailFormat::try_from(format).ok())
    }
}

impl From<ThumbnailFormat> for ImageFormat {
    fn from(format: ThumbnailFormat) -> Self {
        match format {
            ThumbnailFormat::Png => ImageFormat::Png,
            ThumbnailFormat::Jpeg => ImageFormat::Jpeg,
        }
    }
}

impl From<ThumbnailFormat> for config::ValueKind {
    fn from(value: ThumbnailFormat) -> Self {
        let variant = match value {
            ThumbnailFormat::Png => "png",
            ThumbnailFormat::Jpeg => "jpeg",
        };
        config::ValueKind::String(variant.to_owned())
    }
}

impl fmt::Display for ThumbnailFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ImageFormat::from(*self).to_mime_type())
    }
}

/// Make a thumbnail from an input stream and format and return the output format and new thumbnail bytes.
///
/// This function takes into account the [Settings][crate::Settings]:
/// * `builder.thumbnail.ignore_errors`
///
/// Read [make_thumbnail_from_stream] for more information.
pub fn make_thumbnail_bytes_from_stream<R>(
    format: &str,
    input: R,
    settings: &Settings,
) -> Result<Option<(ThumbnailFormat, Vec<u8>)>>
where
    R: BufRead + Seek,
{
    let result = {
        match ThumbnailFormat::new(format) {
            Some(input_format) => {
                let mut output = Cursor::new(Vec::new());
                make_thumbnail_from_stream(input_format, None, input, &mut output, settings)
                    .map(|output_format| (output_format, output.into_inner()))
            }
            None => Err(Error::UnsupportedThumbnailFormat(format.to_owned())),
        }
    };

    let ignore_errors = settings.builder.thumbnail.ignore_errors;
    match result {
        Ok(result) => Ok(Some(result)),
        Err(_) if ignore_errors => Ok(None),
        Err(err) => Err(err),
    }
}

/// Make a thumbnail from the input stream and write to the output stream.
///
/// This function takes into account two [Settings][crate::Settings]:
/// * `builder.thumbnail.long_edge`
/// * `builder.thumbnail.quality`
/// * `builder.thumbnail.format`
/// * `builder.thumbnail.prefer_smallest_format`
pub fn make_thumbnail_from_stream<R, W>(
    input_format: ThumbnailFormat,
    output_format: Option<ThumbnailFormat>,
    input: R,
    output: &mut W,
    settings: &Settings,
) -> Result<ThumbnailFormat>
where
    R: BufRead + Seek,
    W: Write + Seek,
{
    let mut decoder = ImageReader::with_format(input, input_format.into()).into_decoder()?;
    let orientation = decoder.orientation()?;

    let mut image = DynamicImage::from_decoder(decoder)?;
    image.apply_orientation(orientation);

    let output_format = match output_format {
        Some(output_format) => output_format,
        None => {
            match settings.builder.thumbnail.format {
                Some(global_format) => global_format,
                None => {
                    let prefer_smallest_format = settings.builder.thumbnail.prefer_smallest_format;
                    match prefer_smallest_format {
                        true => match input_format {
                            // TODO: investigate more formats
                            ThumbnailFormat::Png | ThumbnailFormat::Tiff
                                if !image.color().has_alpha() =>
                            {
                                ThumbnailFormat::Jpeg
                            }
                            _ => input_format,
                        },
                        false => input_format,
                    }
                }
            }
        }
    };

    let long_edge = settings.builder.thumbnail.long_edge;
    image = image.thumbnail(long_edge, long_edge);

    let quality = settings.builder.thumbnail.quality;
    // TODO: investigate more formats
    match output_format {
        ThumbnailFormat::Jpeg => match quality {
            ThumbnailQuality::Low => {
                image.write_with_encoder(JpegEncoder::new_with_quality(output, 38))?
            }
            ThumbnailQuality::Medium => {
                image.write_with_encoder(JpegEncoder::new_with_quality(output, 75))?
            }
            ThumbnailQuality::High => {
                image.write_with_encoder(JpegEncoder::new_with_quality(output, 100))?
            }
        },
        ThumbnailFormat::Png => match quality {
            ThumbnailQuality::Low => image.write_with_encoder(PngEncoder::new_with_quality(
                output,
                CompressionType::Fast,
                FilterType::default(),
            ))?,
            ThumbnailQuality::Medium => image.write_with_encoder(PngEncoder::new_with_quality(
                output,
                CompressionType::Default,
                FilterType::default(),
            ))?,
            ThumbnailQuality::High => image.write_with_encoder(PngEncoder::new_with_quality(
                output,
                CompressionType::Best,
                FilterType::default(),
            ))?,
        },
        _ => image.write_to(output, output_format.into())?,
    }

    Ok(output_format)
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use image::GenericImageView;

    use super::*;
    use crate::settings::Settings;

    const TEST_JPEG: &[u8] = include_bytes!("../../tests/fixtures/CA.jpg");
    const TEST_PNG: &[u8] = include_bytes!("../../tests/fixtures/sample1.png");

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
            let result = make_thumbnail_bytes_from_stream("jpg", &mut cursor, &Settings::default());
            assert!(
                result.is_ok(),
                "Thumbnail should be generated for orientation {orientation}"
            );

            let (format, thumbnail_data) = result.unwrap().unwrap();
            assert_eq!(format, ThumbnailFormat::Jpeg);

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
                        "Top-left should be red for orientation {orientation}"
                    );
                    assert!(
                        bottom_right_pixel.0[2] >= 250,
                        "Bottom-right should be blue for orientation {orientation}"
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
                        "Top-left should be blue for orientation {orientation}"
                    );
                    assert!(
                        bottom_right_pixel.0[0] >= 250,
                        "Bottom-right should be red for orientation {orientation}"
                    );
                }
                _ => unreachable!("Unexpected orientation value: {orientation}"),
            }
        }
    }

    #[test]
    fn test_make_thumbnail_from_stream() {
        let mut settings = Settings::default();
        settings.builder.thumbnail.prefer_smallest_format = false;
        settings.builder.thumbnail.ignore_errors = false;
        settings.builder.thumbnail.format = None;

        let mut output = Cursor::new(Vec::new());
        let format = make_thumbnail_from_stream(
            ThumbnailFormat::Jpeg,
            None,
            Cursor::new(TEST_JPEG),
            &mut output,
            &settings,
        )
        .unwrap();

        assert!(matches!(format, ThumbnailFormat::Jpeg));

        output.rewind().unwrap();
        ImageReader::with_format(output, format.into())
            .decode()
            .unwrap();
    }

    #[test]
    fn test_make_thumbnail_from_stream_with_output() {
        let mut settings = Settings::default();
        settings.builder.thumbnail.ignore_errors = false;

        let mut output = Cursor::new(Vec::new());
        let format = make_thumbnail_from_stream(
            ThumbnailFormat::Jpeg,
            Some(ThumbnailFormat::Png),
            Cursor::new(TEST_JPEG),
            &mut output,
            &settings,
        )
        .unwrap();

        assert!(matches!(format, ThumbnailFormat::Png));

        output.rewind().unwrap();
        ImageReader::with_format(output, format.into())
            .decode()
            .unwrap();
    }

    #[test]
    fn test_make_thumbnail_bytes_from_stream() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.thumbnail]
                prefer_smallest_format = false
                ignore_errors = false
            }
            .to_string(),
        )
        .unwrap();

        let (format, bytes) = make_thumbnail_bytes_from_stream(
            "image/jpeg",
            Cursor::new(TEST_JPEG),
            &Settings::default(),
        )
        .unwrap()
        .unwrap();

        assert!(matches!(format, ThumbnailFormat::Jpeg));

        ImageReader::with_format(Cursor::new(bytes), format.into())
            .decode()
            .unwrap();
    }

    #[test]
    fn test_make_thumbnail_with_prefer_smallest_format() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.thumbnail]
                prefer_smallest_format = true
                ignore_errors = false
            }
            .to_string(),
        )
        .unwrap();

        let (format, bytes) = make_thumbnail_bytes_from_stream(
            "image/png",
            Cursor::new(TEST_PNG),
            &Settings::default(),
        )
        .unwrap()
        .unwrap();

        assert!(matches!(format, ThumbnailFormat::Jpeg));

        ImageReader::with_format(Cursor::new(bytes), format.into())
            .decode()
            .unwrap();
    }

    #[test]
    fn test_make_thumbnail_with_forced_format() {
        let mut settings = Settings::default();
        settings.builder.thumbnail.format = Some(ThumbnailFormat::Png);
        settings.builder.thumbnail.ignore_errors = false;

        let (format, bytes) =
            make_thumbnail_bytes_from_stream("image/jpeg", Cursor::new(TEST_JPEG), &settings)
                .unwrap()
                .unwrap();

        assert!(matches!(format, ThumbnailFormat::Png));

        ImageReader::with_format(Cursor::new(bytes), format.into())
            .decode()
            .unwrap();
    }

    #[test]
    fn test_make_thumbnail_with_long_edge() {
        let mut settings = Settings::default();
        settings.builder.thumbnail.ignore_errors = false;
        settings.builder.thumbnail.long_edge = 100;

        let (format, bytes) =
            make_thumbnail_bytes_from_stream("image/jpeg", Cursor::new(TEST_JPEG), &settings)
                .unwrap()
                .unwrap();

        assert!(matches!(format, ThumbnailFormat::Jpeg));

        let image = ImageReader::with_format(Cursor::new(bytes), format.into())
            .decode()
            .unwrap();
        assert!(image.width() == 100 || image.height() == 100);
    }

    #[test]
    fn test_make_thumbnail_and_ignore_errors() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        Settings::from_toml(
            &toml::toml! {
                [builder.thumbnail]
                ignore_errors = true
            }
            .to_string(),
        )
        .unwrap();

        let thumbnail = make_thumbnail_bytes_from_stream(
            "image/png",
            Cursor::new(Vec::new()),
            &Settings::default(),
        )
        .unwrap();
        assert!(thumbnail.is_none());
    }
}
