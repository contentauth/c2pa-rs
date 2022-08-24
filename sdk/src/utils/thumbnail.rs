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

use std::path::{PathBuf};

use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
extern crate ffmpeg_next as ffmpeg;

use ffmpeg::{
    format::{input, Pixel},
    media::Type,
    software::scaling::{context::Context, flag::Flags},
    util::frame::video::Video,
};

use crate::{jumbf_io::is_video_format, Error, Result};

// max edge size allowed in pixels for thumbnail creation
const THUMBNAIL_LONGEST_EDGE: u32 = 1024;
const THUMBNAIL_JPEG_QUALITY: u8 = 80; // JPEG quality 1-100

///  utility to generate a thumbnail from a file at path
/// returns Result (format, image_bits) if successful, otherwise Error
pub fn make_thumbnail(path: &std::path::Path) -> Result<(String, Vec<u8>)> {
    let ext = path
        .extension()
        .ok_or(Error::UnsupportedType)?
        .to_string_lossy();
    let (img, output_format, content_type) = if is_video_format(&ext) {
        let img = extract_frame_from_video(path.to_path_buf()).ok_or(Error::UnsupportedType)?;

        (
            DynamicImage::ImageRgb8(img),
            image::ImageOutputFormat::Jpeg(THUMBNAIL_JPEG_QUALITY),
            "image/jpeg",
        )
    } else {
        let format = ImageFormat::from_path(path)?;

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

        (img, output_format, content_type)
    };

    let thumbnail_bits = Vec::new();
    let mut cursor = std::io::Cursor::new(thumbnail_bits);
    img.write_to(&mut cursor, output_format)?;

    let format = content_type.to_owned();
    Ok((format, cursor.into_inner()))
}

fn extract_frame_from_video(path: PathBuf) -> Option<RgbImage> {
    ffmpeg::init().ok()?;

    if let Ok(mut ictx) = input(&path) {
        let input = ictx.streams().best(Type::Video)?;
        let video_stream_index = input.index();
        let context_decoder =
            ffmpeg::codec::context::Context::from_parameters(input.parameters()).ok()?;
        let mut decoder = context_decoder.decoder().video().ok()?;

        // set size of out
        let longest_edge = THUMBNAIL_LONGEST_EDGE;

        // generate a thumbnail image scaled down and in jpeg format
        let mut output_width = decoder.width();
        let mut output_height = decoder.height();
        let aspect_ratio = output_width as f32 / output_height as f32;

        // use longest edge or thumbnail max but keep aspect ratio
        if decoder.width() > longest_edge || decoder.height() > longest_edge {
            if output_height > output_width {
                output_width = (longest_edge as f32 * aspect_ratio) as u32;
                output_height = longest_edge;
            } else {
                output_height = (longest_edge as f32 * aspect_ratio) as u32;
                output_width = longest_edge;
            }
        }

        let mut scaler = Context::get(
            decoder.format(),
            decoder.width(),
            decoder.height(),
            Pixel::RGB24,
            output_width,
            output_height,
            Flags::BILINEAR,
        )
        .ok()?;

        let mut frame_index: i64 = 0;

        for (stream, packet) in ictx.packets() {
            if stream.index() == video_stream_index {
                let frames = stream.frames();
                let save_frame = frames / 2; // grab a frame in the middle of the stream

                decoder.send_packet(&packet).ok()?;

                let mut decoded = Video::empty();
                while decoder.receive_frame(&mut decoded).is_ok() {
                    if frame_index == save_frame {
                        let mut rgb_frame = Video::empty();
                        scaler.run(&decoded, &mut rgb_frame).ok()?;
                        return Some(frame_to_rgb(&rgb_frame));
                    }
                    frame_index += 1;
                }
            }
        }
        decoder.send_eof().ok()?;
    }
    None
}

fn frame_to_rgb(frame: &Video) -> RgbImage {
    let height = frame.height();
    let width = frame.width();
    let stride = frame.stride(0) as u32;
    let _planes = frame.planes();
    let source_data = frame.data(0);

    let mut img = RgbImage::new(width, height);

    for h in 0..height {
        for w in 0..width {
            let src_index = (h * stride + (w * 3)) as usize;
            let r = source_data[src_index];
            let g = source_data[src_index + 1];
            let b = source_data[src_index + 2];
            img.put_pixel(w, h, Rgb([r, g, b]));
        }
    }

    img
}
