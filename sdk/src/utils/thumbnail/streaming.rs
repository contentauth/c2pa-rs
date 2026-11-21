// Copyright 2026 Adobe. All rights reserved.
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

//! Thumbnails of large PNG and TIFF images without decoding them whole.
//!
//! Rows are decoded one at a time (TIFF: one strip or row of tiles at a time)
//! and reduced by an integer factor as they arrive, so memory is the reduced
//! image plus a few rows rather than the full-size image. The reduced image is
//! still at least `long_edge` on its long side; the caller resizes it to the
//! exact size as before.
//!
//! Images these functions don't handle (interlaced PNG, planar or CMYK TIFF,
//! images too small to be worth reducing, ...) return `Ok(None)` so the caller
//! can decode them in full.

use std::io::{BufRead, Read, Seek};

use image::{
    error::DecodingError, metadata::Orientation, DynamicImage, ImageBuffer, ImageError,
    ImageFormat,
};
use tiff::{
    decoder::{ChunkType, DecodingResult},
    tags::Tag,
};

use super::check_decoded_size;
use crate::{Error, Result};

/// A reduced image and the orientation still to be applied to it.
pub(super) struct Reduced {
    pub image: DynamicImage,
    pub orientation: Orientation,
}

/// The integer factor to reduce a `width` x `height` image by so its long side
/// stays at least `long_edge`, or `None` if reducing would save too little.
fn reduction_factor(width: u32, height: u32, long_edge: u32) -> Option<u32> {
    let factor = width.max(height) / long_edge.max(1);
    (factor >= 2).then_some(factor)
}

fn decode_error(
    format: ImageFormat,
    err: impl Into<Box<dyn std::error::Error + Send + Sync>>,
) -> Error {
    Error::ImageError(ImageError::Decoding(DecodingError::new(format.into(), err)))
}

fn invalid(msg: &str) -> Error {
    Error::InvalidAsset(format!("thumbnail: {msg}"))
}

fn u16_to_u8(v: u16) -> u8 {
    ((u32::from(v) * 255 + 32767) / 65535) as u8
}

/// Divide, rounding to nearest, saturating at 255.
fn div_round(sum: u64, n: u64) -> u8 {
    ((sum + n / 2) / n).min(255) as u8
}

/// Reduces rows of 8-bit pixels by an integer factor, averaging each
/// `factor` x `factor` block. Blocks at the right and bottom edges may be
/// smaller and are averaged over the pixels they have.
///
/// With alpha (the last channel), colors are weighted by alpha so fully
/// transparent pixels don't darken or tint the edges of opaque areas.
pub(super) struct BoxReducer {
    width: usize,
    height: usize,
    channels: usize,
    alpha: bool,
    factor: usize,
    out_width: usize,
    out_height: usize,
    /// Running sums for the output row being built, `channels` per column.
    sums: Vec<u64>,
    band_rows: usize,
    rows_seen: usize,
    out: Vec<u8>,
}

impl BoxReducer {
    /// The caller has checked `width * height * channels` against the decoded size limit.
    pub(super) fn new(width: u32, height: u32, channels: usize, alpha: bool, factor: u32) -> Self {
        let (width, height) = (width as usize, height as usize);
        let factor = (factor as usize).max(1);
        let out_width = width.div_ceil(factor);
        let out_height = height.div_ceil(factor);
        Self {
            width,
            height,
            channels,
            alpha,
            factor,
            out_width,
            out_height,
            sums: vec![0; out_width * channels],
            band_rows: 0,
            rows_seen: 0,
            out: Vec::with_capacity(out_width * out_height * channels),
        }
    }

    /// Add the next row of `width * channels` samples.
    pub(super) fn push_row(&mut self, row: &[u8]) -> Result<()> {
        if self.rows_seen >= self.height {
            return Err(invalid("more rows than the image height"));
        }
        let c = self.channels;
        let row = row
            .get(..self.width * c)
            .ok_or_else(|| invalid("row shorter than the image width"))?;
        for (sums, block) in self
            .sums
            .chunks_exact_mut(c)
            .zip(row.chunks(self.factor * c))
        {
            for px in block.chunks_exact(c) {
                if self.alpha {
                    let a = u64::from(px[c - 1]);
                    for (s, &v) in sums[..c - 1].iter_mut().zip(&px[..c - 1]) {
                        *s += u64::from(v) * a;
                    }
                    sums[c - 1] += a;
                } else {
                    for (s, &v) in sums.iter_mut().zip(px) {
                        *s += u64::from(v);
                    }
                }
            }
        }
        self.rows_seen += 1;
        self.band_rows += 1;
        if self.band_rows == self.factor || self.rows_seen == self.height {
            self.emit_row();
        }
        Ok(())
    }

    fn emit_row(&mut self) {
        let c = self.channels;
        for (x, sums) in self.sums.chunks_exact_mut(c).enumerate() {
            let cols = (self.width - x * self.factor).min(self.factor) as u64;
            let n = cols * self.band_rows as u64;
            if self.alpha {
                let a = sums[c - 1];
                for &s in &sums[..c - 1] {
                    self.out.push(if a == 0 { 0 } else { div_round(s, a) });
                }
                self.out.push(div_round(a, n));
            } else {
                for &s in sums.iter() {
                    self.out.push(div_round(s, n));
                }
            }
            sums.fill(0);
        }
        self.band_rows = 0;
    }

    /// The reduced image; fails if fewer rows than the image height were pushed.
    pub(super) fn finish(self) -> Result<DynamicImage> {
        if self.rows_seen != self.height {
            return Err(invalid("image data ended before the last row"));
        }
        let (w, h) = (self.out_width as u32, self.out_height as u32);
        let image = match self.channels {
            1 => ImageBuffer::from_raw(w, h, self.out).map(DynamicImage::ImageLuma8),
            2 => ImageBuffer::from_raw(w, h, self.out).map(DynamicImage::ImageLumaA8),
            3 => ImageBuffer::from_raw(w, h, self.out).map(DynamicImage::ImageRgb8),
            4 => ImageBuffer::from_raw(w, h, self.out).map(DynamicImage::ImageRgba8),
            _ => None,
        };
        image.ok_or_else(|| invalid("unexpected reduced image size"))
    }
}

/// Reduce a non-interlaced PNG row by row.
pub(super) fn reduce_png<R: BufRead + Seek>(input: R, long_edge: u32) -> Result<Option<Reduced>> {
    let png_error = |e: png::DecodingError| decode_error(ImageFormat::Png, e);

    let limits = png::Limits {
        bytes: usize::try_from(super::MAX_IMAGE_BYTES).unwrap_or(usize::MAX),
    };
    let mut decoder = png::Decoder::new_with_limits(input, limits);
    let info = decoder.read_header_info().map_err(png_error)?;
    let (width, height) = (info.width, info.height);
    // Adam7 delivers rows in seven passes, not top to bottom.
    if info.interlaced {
        return Ok(None);
    }
    let Some(factor) = reduction_factor(width, height, long_edge) else {
        return Ok(None);
    };

    // Expand palettes, transparency chunks and low bit depths to 8 bits, as
    // `image` does.
    decoder.set_transformations(png::Transformations::EXPAND);
    let mut reader = decoder.read_info().map_err(png_error)?;
    let (color, depth) = reader.output_color_type();
    let (channels, alpha) = match color {
        png::ColorType::Grayscale => (1, false),
        png::ColorType::GrayscaleAlpha => (2, true),
        png::ColorType::Rgb => (3, false),
        png::ColorType::Rgba => (4, true),
        png::ColorType::Indexed => return Ok(None),
    };
    let sample_bytes = match depth {
        png::BitDepth::Eight => 1,
        png::BitDepth::Sixteen => 2,
        _ => return Ok(None),
    };
    check_decoded_size(u64::from(width) * u64::from(height) * channels as u64 * sample_bytes)?;

    let orientation = reader
        .info()
        .exif_metadata
        .as_deref()
        .and_then(Orientation::from_exif_chunk)
        .unwrap_or(Orientation::NoTransforms);

    let mut reducer = BoxReducer::new(width, height, channels, alpha, factor);
    let mut row8 = Vec::new();
    while let Some(row) = reader.next_row().map_err(png_error)? {
        let data = row.data();
        if sample_bytes == 2 {
            row8.clear();
            row8.extend(
                data.chunks_exact(2)
                    .map(|b| u16_to_u8(u16::from_be_bytes([b[0], b[1]]))),
            );
            reducer.push_row(&row8)?;
        } else {
            reducer.push_row(data)?;
        }
    }
    Ok(Some(Reduced {
        image: reducer.finish()?,
        orientation,
    }))
}

/// 8-bit samples from a decoded TIFF chunk, or `None` for other sample types.
fn tiff_samples(chunk: DecodingResult) -> Option<Vec<u8>> {
    match chunk {
        DecodingResult::U8(v) => Some(v),
        DecodingResult::U16(v) => Some(v.into_iter().map(u16_to_u8).collect()),
        _ => None,
    }
}

/// Reduce the first image of a chunky (interleaved) TIFF one strip, or one row
/// of tiles, at a time.
pub(super) fn reduce_tiff<R: Read + Seek>(input: R, long_edge: u32) -> Result<Option<Reduced>> {
    let tiff_error = |e: tiff::TiffError| decode_error(ImageFormat::Tiff, e);

    let mut decoder = tiff::decoder::Decoder::new(input).map_err(tiff_error)?;
    let (width, height) = decoder.dimensions().map_err(tiff_error)?;
    let Some(factor) = reduction_factor(width, height, long_edge) else {
        return Ok(None);
    };
    let (channels, alpha, bits) = match decoder.colortype().map_err(tiff_error)? {
        tiff::ColorType::Gray(bits) => (1, false, bits),
        tiff::ColorType::GrayA(bits) => (2, true, bits),
        tiff::ColorType::RGB(bits) => (3, false, bits),
        tiff::ColorType::RGBA(bits) => (4, true, bits),
        _ => return Ok(None),
    };
    let sample_bytes = match bits {
        8 => 1,
        16 => 2,
        _ => return Ok(None),
    };
    // Planar images store each channel in its own chunks; signed and floating
    // point samples need conversions `image` makes. Leave both to it.
    let planar = decoder
        .find_tag_unsigned::<u16>(Tag::PlanarConfiguration)
        .map_err(tiff_error)?
        .unwrap_or(1);
    let unsigned = decoder
        .find_tag_unsigned_vec::<u16>(Tag::SampleFormat)
        .map_err(tiff_error)?
        .is_none_or(|formats| formats.iter().all(|&f| f == 1));
    if planar != 1 || !unsigned {
        return Ok(None);
    }
    check_decoded_size(u64::from(width) * u64::from(height) * channels as u64 * sample_bytes)?;

    let orientation = decoder
        .find_tag(Tag::Orientation)
        .map_err(tiff_error)?
        .and_then(|v| Orientation::from_exif(v.into_u16().ok()?.min(255) as u8))
        .unwrap_or(Orientation::NoTransforms);

    let mut reducer = BoxReducer::new(width, height, channels, alpha, factor);
    let row_len = width as usize * channels;
    match decoder.get_chunk_type() {
        ChunkType::Strip => {
            let strips = decoder.strip_count().map_err(tiff_error)?;
            for strip in 0..strips {
                let chunk = decoder.read_chunk(strip).map_err(tiff_error)?;
                let Some(data) = tiff_samples(chunk) else {
                    return Ok(None);
                };
                if data.len() % row_len != 0 {
                    return Err(invalid("TIFF strip is not a whole number of rows"));
                }
                for row in data.chunks_exact(row_len) {
                    reducer.push_row(row)?;
                }
            }
        }
        ChunkType::Tile => {
            let (tile_w, tile_h) = decoder.chunk_dimensions();
            if tile_w == 0 || tile_h == 0 {
                return Err(invalid("TIFF tile has no size"));
            }
            let across = width.div_ceil(tile_w);
            let down = height.div_ceil(tile_h);
            if u64::from(decoder.tile_count().map_err(tiff_error)?)
                != u64::from(across) * u64::from(down)
            {
                return Err(invalid("TIFF tile count does not match the image size"));
            }
            // One row of tiles at a time: at most `tile_h` full-width rows.
            let mut band = Vec::new();
            for ty in 0..down {
                let band_h = tile_h.min(height - ty * tile_h) as usize;
                band.clear();
                band.resize(row_len * band_h, 0);
                for tx in 0..across {
                    let chunk = decoder.read_chunk(ty * across + tx).map_err(tiff_error)?;
                    let Some(data) = tiff_samples(chunk) else {
                        return Ok(None);
                    };
                    let tile_row = tile_w.min(width - tx * tile_w) as usize * channels;
                    if data.len() != tile_row * band_h {
                        return Err(invalid("TIFF tile size does not match the image size"));
                    }
                    let x = (tx * tile_w) as usize * channels;
                    for (dst, src) in band
                        .chunks_exact_mut(row_len)
                        .zip(data.chunks_exact(tile_row))
                    {
                        dst[x..x + tile_row].copy_from_slice(src);
                    }
                }
                for row in band.chunks_exact(row_len) {
                    reducer.push_row(row)?;
                }
            }
        }
    }
    Ok(Some(Reduced {
        image: reducer.finish()?,
        orientation,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use image::{
        codecs::{png::PngEncoder, tiff::TiffEncoder},
        ImageEncoder, Rgb, Rgba,
    };

    use super::*;

    /// Reduce a decoded 8-bit image in memory, for comparison.
    fn reduce_in_memory(image: &DynamicImage, factor: u32) -> DynamicImage {
        let channels = image.color().channel_count() as usize;
        let alpha = image.color().has_alpha();
        let mut reducer = BoxReducer::new(image.width(), image.height(), channels, alpha, factor);
        for row in image.as_bytes().chunks_exact(image.width() as usize * channels) {
            reducer.push_row(row).unwrap();
        }
        reducer.finish().unwrap()
    }

    /// An RGBA image with gradients in every channel, including alpha.
    fn rgba(width: u32, height: u32) -> DynamicImage {
        DynamicImage::ImageRgba8(ImageBuffer::from_fn(width, height, |x, y| {
            Rgba([(x * 7) as u8, (y * 5) as u8, ((x + y) * 3) as u8, (x * 255 / width) as u8])
        }))
    }

    fn encode_png(image: &DynamicImage) -> Vec<u8> {
        let mut out = Vec::new();
        PngEncoder::new(&mut out)
            .write_image(
                image.as_bytes(),
                image.width(),
                image.height(),
                image.color().into(),
            )
            .unwrap();
        out
    }

    #[test]
    fn reducer_averages_blocks_including_partial_edges() {
        // 5 x 3 gray, factor 2: blocks are 2x2, 2x2, 1x2 then 2x1, 2x1, 1x1.
        let rows: [[u8; 5]; 3] = [[0, 2, 4, 6, 8], [2, 4, 6, 8, 10], [10, 20, 30, 40, 51]];
        let mut reducer = BoxReducer::new(5, 3, 1, false, 2);
        for row in &rows {
            reducer.push_row(row).unwrap();
        }
        let image = reducer.finish().unwrap();
        assert_eq!((image.width(), image.height()), (3, 2));
        assert_eq!(image.as_bytes(), &[2, 6, 9, 15, 35, 51]);
    }

    #[test]
    fn reducer_weights_color_by_alpha() {
        // Opaque red next to transparent blue: the result is half-transparent
        // red, not purple.
        let mut reducer = BoxReducer::new(2, 1, 4, true, 2);
        reducer.push_row(&[255, 0, 0, 255, 0, 0, 255, 0]).unwrap();
        assert_eq!(reducer.finish().unwrap().as_bytes(), &[255, 0, 0, 128]);
    }

    #[test]
    fn reducer_rejects_wrong_row_counts() {
        let mut reducer = BoxReducer::new(2, 1, 1, false, 2);
        assert!(reducer.push_row(&[1]).is_err());
        reducer.push_row(&[1, 2]).unwrap();
        assert!(reducer.push_row(&[1, 2]).is_err());

        let reducer = BoxReducer::new(2, 2, 1, false, 2);
        assert!(reducer.finish().is_err());
    }

    #[test]
    fn png_matches_reducing_the_full_image() {
        // Odd sizes leave partial blocks at the right and bottom.
        let image = rgba(203, 150);
        let reduced = reduce_png(Cursor::new(encode_png(&image)), 50)
            .unwrap()
            .unwrap();
        assert_eq!(reduced.image, reduce_in_memory(&image, 4));
        assert_eq!(reduced.orientation, Orientation::NoTransforms);
    }

    #[test]
    fn png_16_bit_is_reduced_to_8_bit() {
        let image8 = DynamicImage::ImageRgb8(ImageBuffer::from_fn(120, 90, |x, y| {
            Rgb([x as u8, y as u8, (x ^ y) as u8])
        }));
        // Every 16-bit sample is an exact 8-bit value times 257.
        let image16 = DynamicImage::ImageRgb16(image8.to_rgb16());
        let reduced = reduce_png(Cursor::new(encode_png(&image16)), 40)
            .unwrap()
            .unwrap();
        assert_eq!(reduced.image, reduce_in_memory(&image8, 3));
    }

    #[test]
    fn png_too_small_to_reduce_is_left_to_the_full_decoder() {
        let png = encode_png(&rgba(100, 80));
        assert!(reduce_png(Cursor::new(png), 60).unwrap().is_none());
    }

    #[test]
    fn truncated_png_is_an_error() {
        let png = encode_png(&rgba(203, 150));
        let truncated = &png[..png.len() / 2];
        assert!(reduce_png(Cursor::new(truncated), 50).is_err());
    }

    #[test]
    fn tiff_strips_match_reducing_the_full_image() {
        let image = rgba(203, 150);
        let mut tiff = Cursor::new(Vec::new());
        TiffEncoder::new(&mut tiff)
            .write_image(image.as_bytes(), 203, 150, image.color().into())
            .unwrap();
        tiff.set_position(0);
        let reduced = reduce_tiff(tiff, 50).unwrap().unwrap();
        assert_eq!(reduced.image, reduce_in_memory(&image, 4));
    }

    /// An uncompressed little-endian RGB TIFF made of 16 x 16 tiles. Tile
    /// padding beyond the image is filled with 0xff so it would show if used.
    fn tiled_tiff(image: &DynamicImage) -> Vec<u8> {
        const TILE: u32 = 16;
        let (width, height) = (image.width(), image.height());
        let (across, down) = (width.div_ceil(TILE), height.div_ceil(TILE));
        let tiles = across * down;
        let tile_bytes = TILE * TILE * 3;
        let rgb = image.to_rgb8();

        let entries: u32 = 11;
        let ifd_len = 2 + entries * 12 + 4;
        let bits_at = 8 + ifd_len;
        let offsets_at = bits_at + 6;
        let counts_at = offsets_at + tiles * 4;
        let data_at = counts_at + tiles * 4;

        let mut out = Vec::new();
        out.extend_from_slice(b"II*\0");
        out.extend_from_slice(&8u32.to_le_bytes());
        out.extend_from_slice(&(entries as u16).to_le_bytes());
        let mut entry = |tag: u16, kind: u16, count: u32, value: u32| {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
        };
        const SHORT: u16 = 3;
        const LONG: u16 = 4;
        entry(256, LONG, 1, width);
        entry(257, LONG, 1, height);
        entry(258, SHORT, 3, bits_at);
        entry(259, SHORT, 1, 1);
        entry(262, SHORT, 1, 2);
        entry(277, SHORT, 1, 3);
        entry(284, SHORT, 1, 1);
        entry(322, LONG, 1, TILE);
        entry(323, LONG, 1, TILE);
        entry(324, LONG, tiles, offsets_at);
        entry(325, LONG, tiles, counts_at);
        out.extend_from_slice(&0u32.to_le_bytes());
        for _ in 0..3 {
            out.extend_from_slice(&8u16.to_le_bytes());
        }
        for i in 0..tiles {
            out.extend_from_slice(&(data_at + i * tile_bytes).to_le_bytes());
        }
        for _ in 0..tiles {
            out.extend_from_slice(&tile_bytes.to_le_bytes());
        }
        for ty in 0..down {
            for tx in 0..across {
                for y in ty * TILE..(ty + 1) * TILE {
                    for x in tx * TILE..(tx + 1) * TILE {
                        match rgb.get_pixel_checked(x, y) {
                            Some(p) => out.extend_from_slice(&p.0),
                            None => out.extend_from_slice(&[0xff; 3]),
                        }
                    }
                }
            }
        }
        out
    }

    #[test]
    fn tiff_tiles_match_reducing_the_full_image() {
        // 3 x 2 tiles, with partial tiles at the right and bottom.
        let image = DynamicImage::ImageRgb8(rgba(40, 24).to_rgb8());
        let reduced = reduce_tiff(Cursor::new(tiled_tiff(&image)), 8)
            .unwrap()
            .unwrap();
        assert_eq!(reduced.image, reduce_in_memory(&image, 5));
    }
}
