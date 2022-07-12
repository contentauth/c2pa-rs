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

use std::fs::File;
use std::io::{Cursor, SeekFrom};
use std::path::*;

use byteorder::{BigEndian, ReadBytesExt};
use conv::ValueFrom;

use crate::asset_io::{AssetIO, CAILoader, CAIRead, HashBlockObjectType, HashObjectPositions};
use crate::error::{Error, Result};

const PNG_ID: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
const CAI_CHUNK: [u8; 4] = *b"caBX";
const IMG_HDR: [u8; 4] = *b"IHDR";
const XMP_KEY: &str = "XML:com.adobe.xmp";
const PNG_END: [u8; 4] = *b"IEND";
const PNG_HDR_LEN: u64 = 12;

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

fn get_png_chunk_positions(f: &mut dyn CAIRead) -> Result<Vec<PngChunkPos>> {
    let current_len = f.seek(SeekFrom::End(0))?;
    let mut chunk_positions: Vec<PngChunkPos> = Vec::new();

    // move to beginning of file
    f.seek(SeekFrom::Start(0))?;

    let mut buf4 = [0; 4];
    let mut hdr = [0; 8];

    // check PNG signature
    f.read_exact(&mut hdr)
        .map_err(|_err| Error::BadParam("PNG invalid".to_string()))?;
    if hdr != PNG_ID {
        return Err(Error::BadParam("PNG invalid".to_string()));
    }

    loop {
        let current_pos = f.stream_position()?;

        // read the chunk length
        let length = f
            .read_u32::<BigEndian>()
            .map_err(|_err| Error::BadParam("PNG out of range".to_string()))?;

        // read the chunk type
        f.read_exact(&mut buf4)
            .map_err(|_err| Error::BadParam("PNG out of range".to_string()))?;
        let name = buf4;

        // seek past data
        f.seek(SeekFrom::Current(length as i64))
            .map_err(|_err| Error::BadParam("PNG out of range".to_string()))?;

        // read crc
        f.read_exact(&mut buf4)
            .map_err(|_err| Error::BadParam("PNG out of range".to_string()))?;

        let chunk_name = String::from_utf8(name.to_vec())
            .map_err(|_err| Error::BadParam("PNG bad chunk name".to_string()))?;

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

fn get_cai_data(f: &mut dyn CAIRead) -> Result<Vec<u8>> {
    let ps = get_png_chunk_positions(f)?;

    let pcp = ps
        .into_iter()
        .find(|pcp| pcp.name == CAI_CHUNK)
        .ok_or(Error::JumbfNotFound)?;

    let length: usize = pcp.length as usize;

    f.seek(SeekFrom::Start(pcp.start + 8))?; // skip ahead from chunk start + length(4) + name(4)

    let mut data: Vec<u8> = vec![0; length];
    f.read_exact(&mut data[..])
        .map_err(|_err| Error::BadParam("PNG out of range".to_string()))?;

    Ok(data)
}

fn add_required_chunks(asset_path: &std::path::Path) -> Result<()> {
    let mut f = File::open(asset_path)?;
    let aio = PngIO {};

    match aio.read_cai(&mut f) {
        Ok(_) => Ok(()),
        Err(_) => {
            let no_bytes: Vec<u8> = Vec::new();
            aio.save_cai_store(asset_path, &no_bytes)
        }
    }
}
pub struct PngIO {}

impl CAILoader for PngIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let cai_data = get_cai_data(asset_reader)?;
        Ok(cai_data)
    }

    // Get XMP block
    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        let chunks = png_pong::Decoder::new(asset_reader).ok()?.into_chunks();
        for chunk_r in chunks.flatten() {
            if let png_pong::chunk::Chunk::InternationalText(c) = chunk_r {
                if c.key == XMP_KEY {
                    return Some(c.val);
                }
            }
        }
        None
    }
}

impl AssetIO for PngIO {
    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut cai_data = Vec::new();
        let mut cai_encoder = png_pong::Encoder::new(&mut cai_data).into_chunk_enc();

        // get png byte
        let mut png_buf = std::fs::read(asset_path).map_err(|_err| Error::EmbeddingError)?;

        let mut cursor = Cursor::new(png_buf);
        let mut ps = get_png_chunk_positions(&mut cursor)?;

        // get back buffer
        png_buf = cursor.into_inner();

        // add CAI chunk
        let cai_unknown = png_pong::chunk::Unknown {
            name: CAI_CHUNK,
            data: store_bytes.to_vec(),
        };

        let mut cai_chunk = png_pong::chunk::Chunk::Unknown(cai_unknown);
        cai_encoder
            .encode(&mut cai_chunk)
            .map_err(|_err| Error::EmbeddingError)?;

        /*  splice in new chunk.  Each PNG chunk has the following format:
                chunk data length (4 bytes big endian)
                chunk identifier (4 byte character sequence)
                chunk data (0 - n bytes of chunck data)
                chunk crc (4 bytes in crc in format defined in PNG spec)
        */

        // erase existing
        let empty_buf = Vec::new();
        let mut iter = ps.into_iter();
        if let Some(existing_cai) = iter.find(|pcp| pcp.name == CAI_CHUNK) {
            // replace existing CAI
            let start = usize::value_from(existing_cai.start)
                .map_err(|_err| Error::BadParam("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            let end = usize::value_from(existing_cai.end())
                .map_err(|_err| Error::BadParam("value out of range".to_string()))?;

            png_buf.splice(start..end, empty_buf.iter().cloned());
        }

        // update positions and reset png_buf
        cursor = Cursor::new(png_buf);
        ps = get_png_chunk_positions(&mut cursor)?;
        iter = ps.into_iter();
        png_buf = cursor.into_inner();

        // add new cai data after image header chunk
        if let Some(img_hdr) = iter.find(|pcp| pcp.name == IMG_HDR) {
            let end = usize::value_from(img_hdr.end())
                .map_err(|_err| Error::BadParam("value out of range".to_string()))?;

            png_buf.splice(end..end, cai_data.iter().cloned());
        } else {
            return Err(Error::EmbeddingError);
        }

        // save png data
        std::fs::write(asset_path, png_buf)
            .map_err(|_err| Error::BadParam("PNG write error".to_owned()))?;

        Ok(())
    }

    fn get_object_locations(
        &self,
        asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        add_required_chunks(asset_path)?;

        let mut f = std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;
        let ps = get_png_chunk_positions(&mut f)?;

        let mut positions: Vec<HashObjectPositions> = Vec::new();

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
        let end = pcp.end();
        let file_end = f.metadata()?.len();
        positions.push(HashObjectPositions {
            offset: end as usize, // len of cai
            length: (file_end - end) as usize,
            htype: HashBlockObjectType::Other,
        });

        Ok(positions)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use twoway::find_bytes;

    use super::*;

    #[test]
    fn test_png_parse() {
        let ap = crate::utils::test::fixture_path("libpng-test.png");

        let png_bytes = std::fs::read(&ap).unwrap();

        // grab PNG chunks and positions
        let mut f = std::fs::File::open(ap).unwrap();
        let positions = get_png_chunk_positions(&mut f).unwrap();

        for hop in positions {
            if let Some(start) = find_bytes(&png_bytes, &hop.name) {
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
}
