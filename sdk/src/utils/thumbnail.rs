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

use std::io::{BufRead, Cursor, Seek, Write};

use image::{
    codecs::{
        avif::AvifEncoder,
        jpeg::JpegEncoder,
        png::{CompressionType, FilterType, PngEncoder},
    },
    ImageReader,
};

use crate::{
    settings::{self, ThumbnailFormat, ThumbnailQuality},
    Error, Result,
};

/// Returns the output thumbnail format given the thumbnail input format taking the global
/// thumbnail preferences into account.
///
/// If the output format is unsupported, this function will return [Error::UnsupportedThumbnailVersion][crate::Error::UnsupportedThumbnailVersion].
///
/// This function takes into account the [Settings][crate::Settings]:
/// * `builder.thumbnail.format`
pub fn thumbnail_output_format(input_format: &str) -> Result<ThumbnailFormat> {
    let global_format =
        settings::get_settings_value::<Option<ThumbnailFormat>>("builder.thumbnail.format")?;
    match global_format {
        Some(global_format) => Ok(global_format),
        None => match ThumbnailFormat::new(input_format) {
            Some(format) => Ok(format),
            None => Err(Error::UnsupportedThumbnailFormat(input_format.to_owned())),
        },
    }
}

/// Make a thumbnail from an input path and return the format and new thumbnail bytes.
///
/// If the output format is unsupported, this function will return [Error::UnsupportedThumbnailVersion][crate::Error::UnsupportedThumbnailVersion].
///
/// This function takes into account the [Settings][crate::Settings]:
/// * `builder.thumbnail.ignore_errors`
/// * `builder.thumbnail.format`
/// * `builder.thumbnail.default_format`
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

    let ignore_errors = settings::get_settings_value::<bool>("builder.thumbnail.ignore_errors")?;
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
/// * `builder.thumbnail.format`
/// * `builder.thumbnail.default_format`
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
        let default_output_format = settings::get_settings_value::<Option<ThumbnailFormat>>(
            "builder.thumbnail.default_format",
        )?;
        let output_format = match thumbnail_output_format(format) {
            Ok(output_format) => Ok(output_format),
            Err(err) => match default_output_format {
                Some(output_format) => Ok(output_format),
                None => Err(err),
            },
        };

        match output_format {
            Ok(output_format) => match ThumbnailFormat::new(format) {
                Some(input_format) => {
                    let mut output = Cursor::new(Vec::new());
                    make_thumbnail_from_stream(input, &mut output, input_format, output_format)
                        .map(|_| (output_format, output.into_inner()))
                }
                None => Err(Error::UnsupportedThumbnailFormat(format.to_owned())),
            },
            Err(err) => Err(err),
        }
    };

    let ignore_errors = settings::get_settings_value::<bool>("builder.thumbnail.ignore_errors")?;
    match result {
        Ok(result) => Ok(Some(result)),
        Err(_) if ignore_errors => Ok(None),
        Err(err) => Err(err),
    }
}

/// Make a thumbnail from the input stream and write to the output stream.
///
/// This function takes into account two [Settings][crate::Settings]:
/// * `builder.thumbnail.size`
/// * `builder.thumbnail.quality`
pub fn make_thumbnail_from_stream<R, W>(
    input: R,
    output: &mut W,
    input_format: ThumbnailFormat,
    output_format: ThumbnailFormat,
) -> Result<()>
where
    R: BufRead + Seek,
    W: Write + Seek,
{
    // image-rs 0.25.6: doesn't support fixtures TUSCANY.TIF and sample1.avif
    let mut image = ImageReader::with_format(input, input_format.into()).decode()?;

    let size = settings::get_settings_value::<(u32, u32)>("builder.thumbnail.size")?;
    image = image.thumbnail(size.0, size.1);

    let quality = settings::get_settings_value::<ThumbnailQuality>("builder.thumbnail.quality")?;
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
        ThumbnailFormat::Avif => match quality {
            ThumbnailQuality::Low => {
                image.write_with_encoder(AvifEncoder::new_with_speed_quality(output, 10, 40))?
            }
            ThumbnailQuality::Medium => {
                image.write_with_encoder(AvifEncoder::new_with_speed_quality(output, 4, 80))?
            }
            ThumbnailQuality::High => {
                image.write_with_encoder(AvifEncoder::new_with_speed_quality(output, 1, 100))?
            }
        },
        _ => image.write_to(output, output_format.into())?,
    }

    Ok(())
}
