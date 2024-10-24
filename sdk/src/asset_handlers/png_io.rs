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
    fs::File,
    io::{Cursor, Read, Seek, SeekFrom},
    path::Path,
};

use byteorder::{BigEndian, ReadBytesExt};
use conv::ValueFrom;
use png_pong::chunk::InternationalText;
use serde_bytes::ByteBuf;
use tempfile::Builder;

use crate::{
    assertions::{BoxMap, C2PA_BOXHASH},
    asset_io::{
        rename_or_move, AssetBoxHash, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        ComposedManifestRef, HashBlockObjectType, HashObjectPositions, RemoteRefEmbed,
        RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::{
        io_utils::ReaderUtils,
        xmp_inmemory_utils::{add_provenance, MIN_XMP},
    },
};

const PNG_ID: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
const CAI_CHUNK: [u8; 4] = *b"caBX";
const IMG_HDR: [u8; 4] = *b"IHDR";
const ITXT_CHUNK: [u8; 4] = *b"iTXt";
const XMP_KEY: &str = "XML:com.adobe.xmp";
const PNG_END: [u8; 4] = *b"IEND";
const PNG_HDR_LEN: u64 = 12;

static SUPPORTED_TYPES: [&str; 2] = ["png", "image/png"];

#[derive(Clone, Debug)]
struct PngChunkPos {
    pub start: u64,
    pub length: u32,
    pub name: [u8; 4],
    #[allow(dead_code)]
    pub name_str: String,
}

impl PngChunkPos {
    pub fn end(&self) -> u64 {
        self.start + self.length as u64 + PNG_HDR_LEN
    }
}

fn get_png_chunk_positions<R: Read + Seek + ?Sized>(f: &mut R) -> Result<Vec<PngChunkPos>> {
    let current_len = f.seek(SeekFrom::End(0))?;
    let mut chunk_positions: Vec<PngChunkPos> = Vec::new();

    // move to beginning of file
    f.rewind()?;

    let mut buf4 = [0; 4];
    let mut hdr = [0; 8];

    // check PNG signature
    f.read_exact(&mut hdr)
        .map_err(|_err| Error::InvalidAsset("PNG invalid".to_string()))?;
    if hdr != PNG_ID {
        return Err(Error::InvalidAsset("PNG invalid".to_string()));
    }

    loop {
        let current_pos = f.stream_position()?;

        // read the chunk length
        let length = f
            .read_u32::<BigEndian>()
            .map_err(|_err| Error::InvalidAsset("PNG out of range".to_string()))?;

        // read the chunk type
        f.read_exact(&mut buf4)
            .map_err(|_err| Error::InvalidAsset("PNG out of range".to_string()))?;
        let name = buf4;

        // seek past data
        f.seek(SeekFrom::Current(length as i64))
            .map_err(|_err| Error::InvalidAsset("PNG out of range".to_string()))?;

        // read crc
        f.read_exact(&mut buf4)
            .map_err(|_err| Error::InvalidAsset("PNG out of range".to_string()))?;

        let chunk_name = String::from_utf8(name.to_vec())
            .map_err(|_err| Error::InvalidAsset("PNG bad chunk name".to_string()))?;

        let pcp = PngChunkPos {
            start: current_pos,
            length,
            name,
            name_str: chunk_name,
        };

        // add to list
        chunk_positions.push(pcp);

        // should we break the loop
        if name == PNG_END || f.stream_position()? > current_len {
            break;
        }
    }

    Ok(chunk_positions)
}

fn get_cai_data<R: Read + Seek + ?Sized>(mut f: &mut R) -> Result<Vec<u8>> {
    let ps = get_png_chunk_positions(f)?;

    if ps
        .clone()
        .into_iter()
        .filter(|pcp| pcp.name == CAI_CHUNK)
        .count()
        > 1
    {
        return Err(Error::TooManyManifestStores);
    }

    let pcp = ps
        .into_iter()
        .find(|pcp| pcp.name == CAI_CHUNK)
        .ok_or(Error::JumbfNotFound)?;

    let length: usize = pcp.length as usize;

    f.seek(SeekFrom::Start(pcp.start + 8))?; // skip ahead from chunk start + length(4) + name(4)

    f.read_to_vec(length as u64)
}

fn add_required_chunks_to_stream(
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    input_stream.rewind()?;
    input_stream.read_to_end(&mut buf).map_err(Error::IoError)?;
    input_stream.rewind()?;

    let img_out = img_parts::DynImage::from_bytes(buf.into())
        .map_err(|_err| Error::InvalidAsset("Could not parse input PNG".to_owned()))?;

    if let Some(img_parts::DynImage::Png(png)) = img_out {
        if png.chunk_by_type(CAI_CHUNK).is_none() {
            let no_bytes: Vec<u8> = Vec::new();
            let aio = PngIO {};
            aio.write_cai(input_stream, output_stream, &no_bytes)?;
        } else {
            // just clone
            input_stream.rewind()?;
            output_stream.rewind()?;
            std::io::copy(input_stream, output_stream)?;
        }
    } else {
        return Err(Error::UnsupportedType);
    }

    Ok(())
}

fn read_string(asset_reader: &mut dyn CAIRead, max_read: u32) -> Result<String> {
    let mut bytes_read: u32 = 0;
    let mut s: Vec<u8> = Vec::with_capacity(80);

    loop {
        let c = asset_reader.read_u8()?;
        if c == 0 {
            break;
        }

        s.push(c);

        bytes_read += 1;

        if bytes_read == max_read {
            break;
        }
    }

    Ok(String::from_utf8_lossy(&s).to_string())
}
pub struct PngIO {}

impl CAIReader for PngIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let cai_data = get_cai_data(asset_reader)?;
        Ok(cai_data)
    }

    // Get XMP block
    fn read_xmp(&self, mut asset_reader: &mut dyn CAIRead) -> Option<String> {
        let ps = get_png_chunk_positions(asset_reader).ok()?;
        let mut xmp_str: Option<String> = None;

        ps.into_iter().find(|pcp| {
            if pcp.name == ITXT_CHUNK {
                // seek to start of chunk
                if asset_reader.seek(SeekFrom::Start(pcp.start + 8)).is_err() {
                    // move +8 to get past header
                    return false;
                }

                // parse the iTxt block
                if let Ok(key) = read_string(asset_reader, pcp.length) {
                    if key.is_empty() || key.len() > 79 {
                        return false;
                    }

                    // is this an XMP key
                    if key != XMP_KEY {
                        return false;
                    }

                    // parse rest of iTxt to get the xmp value
                    let compressed = match asset_reader.read_u8() {
                        Ok(c) => c != 0,
                        Err(_) => return false,
                    };

                    let _compression_method = match asset_reader.read_u8() {
                        Ok(c) => c != 0,
                        Err(_) => return false,
                    };

                    let _langtag = match read_string(asset_reader, pcp.length) {
                        Ok(s) => s,
                        Err(_) => return false,
                    };

                    let _transkey = match read_string(asset_reader, pcp.length) {
                        Ok(s) => s,
                        Err(_) => return false,
                    };

                    // read iTxt data
                    let data = match asset_reader.read_to_vec(
                        pcp.length as u64
                            - (key.len() + _langtag.len() + _transkey.len() + 5) as u64,
                    ) {
                        // data len - size of key - size of land - size of transkey - 3 "0" string terminators - compressed u8 - compression method u8
                        Ok(v) => v,
                        Err(_) => return false,
                    };

                    // convert to string, decompress if needed
                    let val = if compressed {
                        /*  should not be needed for current XMP
                        use flate2::read::GzDecoder;

                        let cursor = Cursor::new(data);

                        let mut d = GzDecoder::new(cursor);
                        let mut s = String::new();
                        if d.read_to_string(&mut s).is_err() {
                            return false;
                        }
                        s
                        */
                        return false;
                    } else {
                        String::from_utf8_lossy(&data).to_string()
                    };

                    xmp_str = Some(val);

                    true
                } else {
                    false
                }
            } else {
                false
            }
        });

        xmp_str
    }
}

impl CAIWriter for PngIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let mut cai_data = Vec::new();
        let mut cai_encoder = png_pong::Encoder::new(&mut cai_data).into_chunk_enc();

        let mut png_buf = Vec::new();
        input_stream.rewind()?;
        input_stream
            .read_to_end(&mut png_buf)
            .map_err(Error::IoError)?;

        let mut cursor = Cursor::new(png_buf);
        let mut ps = get_png_chunk_positions(&mut cursor)?;

        // get back buffer
        png_buf = cursor.into_inner();

        // create CAI store chunk
        let cai_unknown = png_pong::chunk::Unknown {
            name: CAI_CHUNK,
            data: store_bytes.to_vec(),
        };

        let mut cai_chunk = png_pong::chunk::Chunk::Unknown(cai_unknown);
        cai_encoder
            .encode(&mut cai_chunk)
            .map_err(|_| Error::EmbeddingError)?;

        /*  splice in new chunk.  Each PNG chunk has the following format:
                chunk data length (4 bytes big endian)
                chunk identifier (4 byte character sequence)
                chunk data (0 - n bytes of chunk data)
                chunk crc (4 bytes in crc in format defined in PNG spec)
        */

        // erase existing cai data
        let empty_buf = Vec::new();
        let mut iter = ps.into_iter();
        if let Some(existing_cai_data) = iter.find(|png_cp| png_cp.name == CAI_CHUNK) {
            // replace existing CAI data
            let cai_start = usize::value_from(existing_cai_data.start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_owned()))?; // get beginning of chunk which starts 4 bytes before label

            let cai_end = usize::value_from(existing_cai_data.end())
                .map_err(|_err| Error::InvalidAsset("value out of range".to_owned()))?;

            png_buf.splice(cai_start..cai_end, empty_buf.iter().cloned());
        };

        // update positions and reset png_buf
        cursor = Cursor::new(png_buf);
        ps = get_png_chunk_positions(&mut cursor)?;
        iter = ps.into_iter();
        png_buf = cursor.into_inner();

        // add new cai data after the image header chunk
        if let Some(img_hdr) = iter.find(|png_cp| png_cp.name == IMG_HDR) {
            let img_hdr_end = usize::value_from(img_hdr.end())
                .map_err(|_err| Error::InvalidAsset("value out of range".to_owned()))?;

            png_buf.splice(img_hdr_end..img_hdr_end, cai_data.iter().cloned());
        } else {
            return Err(Error::EmbeddingError);
        }

        output_stream.rewind()?;
        output_stream.write_all(&png_buf)?;

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let mut positions: Vec<HashObjectPositions> = Vec::new();

        // Ensure the stream has the required chunks so we can generate the required offsets.
        let output: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output);

        add_required_chunks_to_stream(input_stream, &mut output_stream)?;

        let mut png_buf: Vec<u8> = Vec::new();
        output_stream.rewind()?;
        output_stream
            .read_to_end(&mut png_buf)
            .map_err(Error::IoError)?;
        output_stream.rewind()?;

        let mut cursor = Cursor::new(png_buf);
        let ps = get_png_chunk_positions(&mut cursor)?;

        // get back buffer
        png_buf = cursor.into_inner();

        let pcp = ps
            .into_iter()
            .find(|pcp| pcp.name == CAI_CHUNK)
            .ok_or(Error::JumbfNotFound)?;

        positions.push(HashObjectPositions {
            offset: pcp.start as usize,
            length: pcp.length as usize + PNG_HDR_LEN as usize,
            htype: HashBlockObjectType::Cai,
        });

        // add hash of chunks before cai
        positions.push(HashObjectPositions {
            offset: 0,
            length: pcp.start as usize,
            htype: HashBlockObjectType::Other,
        });

        // add position from cai to end
        let end = pcp.end() as usize;
        let file_end = png_buf.len();
        positions.push(HashObjectPositions {
            offset: end, // len of cai
            length: file_end - end,
            htype: HashBlockObjectType::Other,
        });

        Ok(positions)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        // get png byte
        let ps = get_png_chunk_positions(input_stream)?;

        // get image bytes
        input_stream.rewind()?;
        let mut png_buf: Vec<u8> = Vec::new();
        input_stream.read_to_end(&mut png_buf)?;

        /*  splice in new chunk.  Each PNG chunk has the following format:
                chunk data length (4 bytes big endian)
                chunk identifier (4 byte character sequence)
                chunk data (0 - n bytes of chunk data)
                chunk crc (4 bytes in crc in format defined in PNG spec)
        */

        // erase existing
        let empty_buf = Vec::new();
        let mut iter = ps.into_iter();
        if let Some(existing_cai) = iter.find(|pcp| pcp.name == CAI_CHUNK) {
            // replace existing CAI
            let start = usize::value_from(existing_cai.start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            let end = usize::value_from(existing_cai.end())
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            png_buf.splice(start..end, empty_buf.iter().cloned());
        }

        // save png data
        output_stream.write_all(&png_buf)?;

        Ok(())
    }
}

impl AssetIO for PngIO {
    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        let mut stream = std::fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        self.write_cai(&mut stream, &mut temp_file, store_bytes)?;

        // copy temp file to asset
        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(
        &self,
        asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        self.get_object_locations_from_stream(&mut file)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        // get png byte
        let mut png_buf = std::fs::read(asset_path).map_err(|_err| Error::EmbeddingError)?;

        let mut cursor = Cursor::new(png_buf);
        let ps = get_png_chunk_positions(&mut cursor)?;

        // get back buffer
        png_buf = cursor.into_inner();

        /*  splice in new chunk.  Each PNG chunk has the following format:
                chunk data length (4 bytes big endian)
                chunk identifier (4 byte character sequence)
                chunk data (0 - n bytes of chunk data)
                chunk crc (4 bytes in crc in format defined in PNG spec)
        */

        // erase existing
        let empty_buf = Vec::new();
        let mut iter = ps.into_iter();
        if let Some(existing_cai) = iter.find(|pcp| pcp.name == CAI_CHUNK) {
            // replace existing CAI
            let start = usize::value_from(existing_cai.start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            let end = usize::value_from(existing_cai.end())
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            png_buf.splice(start..end, empty_buf.iter().cloned());
        }

        // save png data
        std::fs::write(asset_path, png_buf)?;

        Ok(())
    }

    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        PngIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(PngIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(PngIO::new(asset_type)))
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        Some(self)
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

fn get_xmp_insertion_point(asset_reader: &mut dyn CAIRead) -> Option<(u64, u32)> {
    let ps = get_png_chunk_positions(asset_reader).ok()?;

    let xmp_box = ps.iter().find(|pcp| {
        if pcp.name == ITXT_CHUNK {
            // seek to start of chunk
            if asset_reader.seek(SeekFrom::Start(pcp.start + 8)).is_err() {
                // move +8 to get past header
                return false;
            }

            // parse the iTxt block
            if let Ok(key) = read_string(asset_reader, pcp.length) {
                if key.is_empty() || key.len() > 79 {
                    return false;
                }

                // is this an XMP key
                if key == XMP_KEY {
                    return true;
                }
            }
            false
        } else {
            false
        }
    });

    if let Some(xmp) = xmp_box {
        // overwrite existing box
        Some((xmp.start, xmp.length + PNG_HDR_LEN as u32))
    } else {
        // insert after IHDR
        ps.iter()
            .find(|png_cp| png_cp.name == IMG_HDR)
            .map(|img_hdr| (img_hdr.end(), 0))
    }
}
impl RemoteRefEmbed for PngIO {
    #[allow(unused_variables)]
    fn embed_reference(&self, asset_path: &Path, embed_ref: RemoteRefEmbedType) -> Result<()> {
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                let output_buf = Vec::new();
                let mut output_stream = Cursor::new(output_buf);

                // do here so source file is closed after update
                {
                    let mut source_stream = std::fs::File::open(asset_path)?;
                    self.embed_reference_to_stream(
                        &mut source_stream,
                        &mut output_stream,
                        RemoteRefEmbedType::Xmp(manifest_uri),
                    )?;
                }

                std::fs::write(asset_path, output_stream.into_inner())?;

                Ok(())
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }

    fn embed_reference_to_stream(
        &self,
        source_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                source_stream.rewind()?;

                let xmp = match self.read_xmp(source_stream) {
                    Some(s) => s,
                    None => format!("http://ns.adobe.com/xap/1.0/\0 {}", MIN_XMP),
                };

                // update XMP
                let updated_xmp = add_provenance(&xmp, &manifest_uri)?;

                // make XMP chunk
                let mut xmp_data = Vec::new();
                let mut xmp_encoder = png_pong::Encoder::new(&mut xmp_data).into_chunk_enc();

                let mut xmp_chunk = png_pong::chunk::Chunk::InternationalText(InternationalText {
                    key: XMP_KEY.to_string(),
                    langtag: "".to_string(),
                    transkey: "".to_string(),
                    val: updated_xmp,
                    compressed: false,
                });
                xmp_encoder
                    .encode(&mut xmp_chunk)
                    .map_err(|_| Error::EmbeddingError)?;

                // patch output stream
                let mut png_buf = Vec::new();
                source_stream.rewind()?;
                source_stream
                    .read_to_end(&mut png_buf)
                    .map_err(Error::IoError)?;

                if let Some((start, xmp_len)) = get_xmp_insertion_point(source_stream) {
                    let mut png_buf = Vec::new();
                    source_stream.rewind()?;
                    source_stream
                        .read_to_end(&mut png_buf)
                        .map_err(Error::IoError)?;

                    // replace existing XMP
                    let xmp_start = usize::value_from(start)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_owned()))?; // get beginning of chunk which starts 4 bytes before label

                    let xmp_end = usize::value_from(start + xmp_len as u64)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_owned()))?;

                    png_buf.splice(xmp_start..xmp_end, xmp_data.iter().cloned());

                    output_stream.rewind()?;
                    output_stream.write_all(&png_buf)?;

                    Ok(())
                } else {
                    Err(Error::EmbeddingError)
                }
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }
}

impl AssetBoxHash for PngIO {
    fn get_box_map(&self, input_stream: &mut dyn CAIRead) -> Result<Vec<BoxMap>> {
        input_stream.rewind()?;

        let ps = get_png_chunk_positions(input_stream)?;

        let mut box_maps = Vec::new();

        // add PNGh header
        let pngh_bm = BoxMap {
            names: vec!["PNGh".to_string()],
            alg: None,
            hash: ByteBuf::from(Vec::new()),
            pad: ByteBuf::from(Vec::new()),
            range_start: 0,
            range_len: 8,
        };
        box_maps.push(pngh_bm);

        // add the other boxes
        for pc in ps.into_iter() {
            // add special C2PA box
            if pc.name == CAI_CHUNK {
                let c2pa_bm = BoxMap {
                    names: vec![C2PA_BOXHASH.to_string()],
                    alg: None,
                    hash: ByteBuf::from(Vec::new()),
                    pad: ByteBuf::from(Vec::new()),
                    range_start: pc.start as usize,
                    range_len: (pc.length + 12) as usize, // length(4) + name(4) + crc(4)
                };
                box_maps.push(c2pa_bm);
                continue;
            }

            // all other chunks
            let c2pa_bm = BoxMap {
                names: vec![pc.name_str],
                alg: None,
                hash: ByteBuf::from(Vec::new()),
                pad: ByteBuf::from(Vec::new()),
                range_start: pc.start as usize,
                range_len: (pc.length + 12) as usize, // length(4) + name(4) + crc(4)
            };
            box_maps.push(c2pa_bm);
        }

        Ok(box_maps)
    }
}

impl ComposedManifestRef for PngIO {
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        let mut cai_data = Vec::new();
        let mut cai_encoder = png_pong::Encoder::new(&mut cai_data).into_chunk_enc();

        // create CAI store chunk
        let cai_unknown = png_pong::chunk::Unknown {
            name: CAI_CHUNK,
            data: manifest_data.to_vec(),
        };

        let mut cai_chunk = png_pong::chunk::Chunk::Unknown(cai_unknown);
        cai_encoder
            .encode(&mut cai_chunk)
            .map_err(|_| Error::EmbeddingError)?;

        Ok(cai_data)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
pub mod tests {
    use std::io::Write;

    use memchr::memmem;

    use super::*;
    use crate::utils::test::{self, temp_dir_path};

    #[test]
    fn test_png_xmp() {
        let ap = test::fixture_path("libpng-test_with_url.png");

        let png_io = PngIO {};
        let xmp = png_io
            .read_xmp(&mut std::fs::File::open(ap).unwrap())
            .unwrap();

        // make sure we can parse it
        let provenance = crate::utils::xmp_inmemory_utils::extract_provenance(&xmp).unwrap();

        assert!(provenance.contains("libpng-test"));
    }

    #[test]
    fn test_png_xmp_write() {
        let ap = test::fixture_path("libpng-test.png");
        let mut source_stream = std::fs::File::open(ap).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "out.png");
        let mut output_stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output)
            .unwrap();

        let png_io = PngIO {};
        //let _orig_xmp = png_io
        //    .read_xmp(&mut source_stream )
        //    .unwrap();

        // change the xmp
        let eh = png_io.remote_ref_writer_ref().unwrap();
        eh.embed_reference_to_stream(
            &mut source_stream,
            &mut output_stream,
            RemoteRefEmbedType::Xmp("some test data".to_string()),
        )
        .unwrap();

        output_stream.rewind().unwrap();
        let new_xmp = png_io.read_xmp(&mut output_stream).unwrap();
        // make sure we can parse it
        let provenance = crate::utils::xmp_inmemory_utils::extract_provenance(&new_xmp).unwrap();

        assert!(provenance.contains("some test data"));
    }

    #[test]
    fn test_png_parse() {
        let ap = test::fixture_path("libpng-test.png");

        let png_bytes = std::fs::read(&ap).unwrap();

        // grab PNG chunks and positions
        let mut f = std::fs::File::open(ap).unwrap();
        let positions = get_png_chunk_positions(&mut f).unwrap();

        for hop in positions {
            if let Some(start) = memmem::find(&png_bytes, &hop.name) {
                if hop.start != (start - 4) as u64 {
                    panic!("find_bytes found the wrong position");
                    // assert!(true);
                }

                println!(
                    "Chunk {} position matches, start: {}, length: {} ",
                    hop.name_str, hop.start, hop.length
                );
            }
        }
    }

    #[test]
    fn test_write_cai_using_stream_existing_cai_data() {
        let source = include_bytes!("../../tests/fixtures/exp-test1.png");
        let mut stream = Cursor::new(source.to_vec());
        let png_io = PngIO {};

        // cai data already exists
        assert!(matches!(
            png_io.read_cai(&mut stream),
            Ok(data) if !data.is_empty(),
        ));

        // write new data
        let output: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output);

        let data_to_write: Vec<u8> = vec![0, 1, 1, 2, 3, 5, 8, 13, 21, 34];
        assert!(png_io
            .write_cai(&mut stream, &mut output_stream, &data_to_write)
            .is_ok());

        // new data replaces the existing cai data
        let data_written = png_io.read_cai(&mut output_stream).unwrap();
        assert_eq!(data_to_write, data_written);
    }

    #[test]
    fn test_write_cai_using_stream_no_cai_data() {
        let source = include_bytes!("../../tests/fixtures/libpng-test.png");
        let mut stream = Cursor::new(source.to_vec());
        let png_io = PngIO {};

        // no cai data present in stream.
        assert!(matches!(
            png_io.read_cai(&mut stream),
            Err(Error::JumbfNotFound)
        ));

        // write new data.
        let output: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output);

        let data_to_write: Vec<u8> = vec![0, 1, 1, 2, 3, 5, 8, 13, 21, 34];
        assert!(png_io
            .write_cai(&mut stream, &mut output_stream, &data_to_write)
            .is_ok());

        // assert new cai data is present.
        let data_written = png_io.read_cai(&mut output_stream).unwrap();
        assert_eq!(data_to_write, data_written);
    }

    #[test]
    fn test_write_cai_data_to_stream_wrong_format() {
        let source = include_bytes!("../../tests/fixtures/C.jpg");
        let mut stream = Cursor::new(source.to_vec());
        let png_io = PngIO {};

        let output: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output);
        assert!(matches!(
            png_io.write_cai(&mut stream, &mut output_stream, &[]),
            Err(Error::InvalidAsset(_),)
        ));
    }

    #[test]
    fn test_stream_object_locations() {
        let source = include_bytes!("../../tests/fixtures/exp-test1.png");
        let mut stream = Cursor::new(source.to_vec());
        let png_io = PngIO {};
        let cai_pos = png_io
            .get_object_locations_from_stream(&mut stream)
            .unwrap()
            .into_iter()
            .find(|pos| pos.htype == HashBlockObjectType::Cai)
            .unwrap();

        assert_eq!(cai_pos.offset, 33);
        assert_eq!(cai_pos.length, 3439701);
    }

    #[test]
    fn test_stream_object_locations_with_incorrect_file_type() {
        let source = include_bytes!("../../tests/fixtures/unsupported_type.txt");
        let mut stream = Cursor::new(source.to_vec());
        let png_io = PngIO {};
        assert!(matches!(
            png_io.get_object_locations_from_stream(&mut stream),
            Err(Error::UnsupportedType)
        ));
    }

    #[test]
    fn test_stream_object_locations_adds_offsets_to_file_without_claims() {
        let source = include_bytes!("../../tests/fixtures/libpng-test.png");
        let mut stream = Cursor::new(source.to_vec());

        let png_io = PngIO {};
        assert!(png_io
            .get_object_locations_from_stream(&mut stream)
            .unwrap()
            .into_iter()
            .any(|chunk| chunk.htype == HashBlockObjectType::Cai));
    }

    #[test]
    fn test_remove_c2pa() {
        let source = test::fixture_path("exp-test1.png");
        let temp_dir = tempfile::tempdir().unwrap();
        let output = test::temp_dir_path(&temp_dir, "exp-test1_tmp.png");
        std::fs::copy(source, &output).unwrap();

        let png_io = PngIO {};
        png_io.remove_cai_store(&output).unwrap();

        // read back in asset, JumbfNotFound is expected since it was removed
        match png_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_remove_c2pa_from_stream() {
        let source = crate::utils::test::fixture_path("exp-test1.png");

        let source_bytes = std::fs::read(source).unwrap();
        let mut source_stream = Cursor::new(source_bytes);

        let png_io = PngIO {};
        let png_writer = png_io.get_writer("png").unwrap();

        let output_bytes = Vec::new();
        let mut output_stream = Cursor::new(output_bytes);

        png_writer
            .remove_cai_store_from_stream(&mut source_stream, &mut output_stream)
            .unwrap();

        // read back in asset, JumbfNotFound is expected since it was removed
        let png_reader = png_io.get_reader();
        match png_reader.read_cai(&mut output_stream) {
            Err(Error::JumbfNotFound) => (),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_embeddable_manifest() {
        let png_io = PngIO {};

        let source = crate::utils::test::fixture_path("exp-test1.png");

        let ol = png_io.get_object_locations(&source).unwrap();

        let cai_loc = ol
            .iter()
            .find(|o| o.htype == HashBlockObjectType::Cai)
            .unwrap();
        let curr_manifest = png_io.read_cai_store(&source).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let output = crate::utils::test::temp_dir_path(&temp_dir, "exp-test1-out.png");

        std::fs::copy(source, &output).unwrap();

        // remove existing
        png_io.remove_cai_store(&output).unwrap();

        // generate new manifest data
        let em = png_io
            .composed_data_ref()
            .unwrap()
            .compose_manifest(&curr_manifest, "png")
            .unwrap();

        // insert new manifest
        let outbuf = Vec::new();
        let mut out_stream = Cursor::new(outbuf);

        let mut before = vec![0u8; cai_loc.offset];
        let mut in_file = std::fs::File::open(&output).unwrap();

        // write before
        in_file.read_exact(before.as_mut_slice()).unwrap();
        out_stream.write_all(&before).unwrap();

        // write composed bytes
        out_stream.write_all(&em).unwrap();

        // write bytes after
        let mut after_buf = Vec::new();
        in_file.read_to_end(&mut after_buf).unwrap();
        out_stream.write_all(&after_buf).unwrap();

        // read manifest back in from new in-memory PNG
        out_stream.rewind().unwrap();
        let restored_manifest = png_io.read_cai(&mut out_stream).unwrap();

        assert_eq!(&curr_manifest, &restored_manifest);
    }
}
