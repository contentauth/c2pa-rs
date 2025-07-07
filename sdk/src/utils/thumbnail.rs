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
        // avif::AvifEncoder,
        jpeg::JpegEncoder,
        png::{CompressionType, FilterType, PngEncoder},
    },
    ImageFormat, ImageReader,
};
use serde_derive::{Deserialize, Serialize};

use crate::{
    settings::{self, ThumbnailQuality},
    Error, Result,
};

// TODO: thumbnails/previews for audio?
/// Possible output types for automatic thumbnail generation.
///
/// These formats are a combination of types supported in [image-rs](https://docs.rs/image/latest/image/enum.ImageFormat.html)
/// and types defined by the [IANA registry media type](https://www.iana.org/assignments/media-types/media-types.xhtml) (as defined in the spec).
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThumbnailFormat {
    /// An image in PNG format.
    Png,
    /// An image in JPEG format.
    Jpeg,
    /// An image in GIF format.
    Gif,
    /// An image in WEBP format.
    WebP,
    /// An image in TIFF format.
    Tiff,
    /// An image in BMP format.
    Bmp,
    /// An image in ICO format.
    Ico,
    // /// An image in AVIF format.
    // Avif,
}

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

impl TryFrom<ImageFormat> for ThumbnailFormat {
    type Error = Error;

    fn try_from(format: ImageFormat) -> Result<Self> {
        match format {
            ImageFormat::Png => Ok(ThumbnailFormat::Png),
            ImageFormat::Jpeg => Ok(ThumbnailFormat::Jpeg),
            ImageFormat::Gif => Ok(ThumbnailFormat::Gif),
            ImageFormat::WebP => Ok(ThumbnailFormat::WebP),
            ImageFormat::Tiff => Ok(ThumbnailFormat::Tiff),
            ImageFormat::Bmp => Ok(ThumbnailFormat::Bmp),
            ImageFormat::Ico => Ok(ThumbnailFormat::Ico),
            // ImageFormat::Avif => Ok(ThumbnailFormat::Avif),
            _ => Err(Error::UnsupportedThumbnailFormat(
                format.to_mime_type().to_owned(),
            )),
        }
    }
}

impl From<ThumbnailFormat> for ImageFormat {
    fn from(format: ThumbnailFormat) -> Self {
        match format {
            ThumbnailFormat::Png => ImageFormat::Png,
            ThumbnailFormat::Jpeg => ImageFormat::Jpeg,
            ThumbnailFormat::Gif => ImageFormat::Gif,
            ThumbnailFormat::WebP => ImageFormat::WebP,
            ThumbnailFormat::Tiff => ImageFormat::Tiff,
            ThumbnailFormat::Bmp => ImageFormat::Bmp,
            ThumbnailFormat::Ico => ImageFormat::Ico,
            // ThumbnailFormat::Avif => ImageFormat::Avif,
        }
    }
}

impl fmt::Display for ThumbnailFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", ImageFormat::from(*self).to_mime_type())
    }
}

/// Make a thumbnail from an input path and return the format and new thumbnail bytes.
///
/// If the output format is unsupported, this function will return [Error::UnsupportedThumbnailFormat][crate::Error::UnsupportedThumbnailFormat].
///
/// This function takes into account the [Settings][crate::Settings]:
/// * `builder.thumbnail.ignore_errors`
///
/// Read [make_thumbnail_from_stream] for more information.
#[cfg(feature = "file_io")]
pub fn make_thumbnail_bytes_from_path(
    path: &std::path::Path,
) -> Result<Option<(ThumbnailFormat, Vec<u8>)>> {
    use std::{fs::File, io::BufReader};

    let result = {
        match File::open(path) {
            Ok(file) => match crate::format_from_path(path) {
                Some(input_format) => {
                    make_thumbnail_bytes_from_stream(BufReader::new(file), &input_format)
                }
                None => Err(Error::UnsupportedType),
            },
            Err(err) => Err(err.into()),
        }
    };

    let ignore_errors =
        settings::get_profile_settings_value::<bool>("builder.thumbnail.ignore_errors")?;
    match result {
        Ok(result) => Ok(result),
        Err(_) if ignore_errors => Ok(None),
        Err(err) => Err(err),
    }
}

/// Make a thumbnail from an input stream and format and return the output format and new thumbnail bytes.
///
/// This function takes into account the [Settings][crate::Settings]:
/// * `builder.thumbnail.ignore_errors`
///
/// Read [make_thumbnail_from_stream] for more information.
pub fn make_thumbnail_bytes_from_stream<R>(
    input: R,
    format: &str,
) -> Result<Option<(ThumbnailFormat, Vec<u8>)>>
where
    R: BufRead + Seek,
{
    let result = {
        match ThumbnailFormat::new(format) {
            Some(input_format) => {
                let mut output = Cursor::new(Vec::new());
                make_thumbnail_from_stream(input, &mut output, input_format, None)
                    .map(|output_format| (output_format, output.into_inner()))
            }
            None => Err(Error::UnsupportedThumbnailFormat(format.to_owned())),
        }
    };

    let ignore_errors =
        settings::get_profile_settings_value::<bool>("builder.thumbnail.ignore_errors")?;
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
    input: R,
    output: &mut W,
    input_format: ThumbnailFormat,
    output_format: Option<ThumbnailFormat>,
) -> Result<ThumbnailFormat>
where
    R: BufRead + Seek,
    W: Write + Seek,
{
    let mut image = ImageReader::with_format(input, input_format.into()).decode()?;

    let output_format = match output_format {
        Some(output_format) => output_format,
        None => {
            let global_format = settings::get_profile_settings_value::<Option<ThumbnailFormat>>(
                "builder.thumbnail.format",
            )?;
            match global_format {
                Some(global_format) => global_format,
                None => {
                    let prefer_smallest_format = settings::get_profile_settings_value::<bool>(
                        "builder.thumbnail.prefer_smallest_format",
                    )?;
                    match prefer_smallest_format {
                        true => match input_format {
                            ThumbnailFormat::Png if !image.color().has_alpha() => {
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

    let long_edge = settings::get_profile_settings_value::<u32>("builder.thumbnail.long_edge")?;
    image = image.thumbnail(long_edge, long_edge);

    let quality =
        settings::get_profile_settings_value::<ThumbnailQuality>("builder.thumbnail.quality")?;
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
        // ThumbnailFormat::Avif => match quality {
        //     ThumbnailQuality::Low => {
        //         image.write_with_encoder(AvifEncoder::new_with_speed_quality(output, 10, 40))?
        //     }
        //     ThumbnailQuality::Medium => {
        //         image.write_with_encoder(AvifEncoder::new_with_speed_quality(output, 4, 80))?
        //     }
        //     ThumbnailQuality::High => {
        //         image.write_with_encoder(AvifEncoder::new_with_speed_quality(output, 1, 100))?
        //     }
        // },
        _ => image.write_to(output, output_format.into())?,
    }

    Ok(output_format)
}
