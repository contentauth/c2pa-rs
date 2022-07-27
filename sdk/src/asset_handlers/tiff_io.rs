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

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use conv::*;

use std::collections::HashMap;
use std::io::SeekFrom;

use crate::asset_io::{CAILoader, CAIRead};
use crate::error::{Error, Result};

const C2PA_TAG: u16 = 0xCd41;
const C2PA_FIELD_TYPE: u16 = 7;

#[derive(Clone)]
pub(crate) enum Endianess {
    BigEndian,
    LittleEndian,
}

struct EndianReader {
    byte_order: Endianess,
}

impl EndianReader {
    pub fn new(endianess: Endianess) -> Self {
        EndianReader {
            byte_order: endianess,
        }
    }

    #[inline]
    pub fn read_u16(&self, r: &mut dyn CAIRead) -> Result<u16> {
        match self.byte_order {
            Endianess::BigEndian => r.read_u16::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_u16::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_u32(&self, r: &mut dyn CAIRead) -> Result<u32> {
        match self.byte_order {
            Endianess::BigEndian => r.read_u32::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_u32::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_u64(&self, r: &mut dyn CAIRead) -> Result<u64> {
        match self.byte_order {
            Endianess::BigEndian => r.read_u64::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_u64::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }
}

#[allow(dead_code)]
pub struct IfdEntry {
    entry_tag: u16,
    entry_type: u16,
    value_count: u64,
    value_offset: u64,
}
#[allow(dead_code)]
pub struct Ifd {
    offset: u64,
    entry_cnt: u64,
    entries: HashMap<u16, IfdEntry>,
    next_ifd_offset: Option<u64>,
}

impl Ifd {
    pub fn get_tag(&self, tag_id: u16) -> Option<&IfdEntry> {
        self.entries.get(&tag_id)
    }
}

#[allow(dead_code)]
pub(crate) struct TiffStructure {
    byte_order: Endianess,
    big_tiff: bool,
    first_ifd_offset: u64,
    first_ifd: Option<Ifd>,
}

const II: [u8; 2] = *b"II";
const MM: [u8; 2] = *b"MM";

impl TiffStructure {
    pub fn load(reader: &mut dyn CAIRead) -> Result<Self> {
        let mut endianess = [0u8, 2];
        reader.read_exact(&mut endianess)?;

        let byte_order = match endianess {
            II => Endianess::LittleEndian,
            MM => Endianess::BigEndian,
            _ => return Err(Error::BadParam("Could not parse input image".to_owned())),
        };

        let byte_reader = EndianReader::new(byte_order.clone());

        let big_tiff = match byte_reader.read_u16(reader) {
            Ok(42) => false,
            Ok(43) => {
                // read past big TIFF structs
                // Read bytesize of offsets, must be 8
                if byte_reader.read_u16(reader)? != 8 {
                    return Err(Error::BadParam("Could not parse input image".to_owned()));
                }
                // must currently be 0
                if byte_reader.read_u16(reader)? != 0 {
                    return Err(Error::BadParam("Could not parse input image".to_owned()));
                }
                true
            }
            _ => return Err(Error::BadParam("Could not parse input image".to_owned())),
        };

        let first_ifd_offset = if big_tiff {
            byte_reader.read_u64(reader)?
        } else {
            byte_reader.read_u32(reader)?.into()
        };

        // move read pointer to IFD
        reader.seek(SeekFrom::Start(first_ifd_offset))?;
        let first_ifd = TiffStructure::read_ifd(reader, byte_order.clone(), big_tiff)?;

        let ts = TiffStructure {
            byte_order: byte_order.clone(),
            big_tiff,
            first_ifd_offset,
            first_ifd: Some(first_ifd),
        };

        Ok(ts)
    }

    fn read_ifd(reader: &mut dyn CAIRead, byte_order: Endianess, big_tiff: bool) -> Result<Ifd> {
        let byte_reader = EndianReader::new(byte_order);

        let ifd_offset = reader.seek(SeekFrom::Current(0))?;

        let entry_cnt = if big_tiff {
            byte_reader.read_u64(reader)?
        } else {
            byte_reader.read_u16(reader)?.into()
        };

        let mut ifd = Ifd {
            offset: ifd_offset,
            entry_cnt,
            entries: HashMap::new(),
            next_ifd_offset: None,
        };

        for _ in 0..entry_cnt {
            let tag = byte_reader.read_u16(reader)?;
            let tag_type = byte_reader.read_u16(reader)?;

            let (count, data_offset) = if big_tiff {
                let count = byte_reader.read_u64(reader)?;
                let data_offset = byte_reader.read_u64(reader)?;
                (count, data_offset)
            } else {
                let count = byte_reader.read_u32(reader)?;
                let data_offset = byte_reader.read_u32(reader)?;
                (count.into(), data_offset.into())
            };

            let ifd_entry = IfdEntry {
                entry_tag: tag,
                entry_type: tag_type,
                value_count: count,
                value_offset: data_offset,
            };

            println!(
                "{}, {}, {}. {}",
                ifd_entry.entry_tag,
                ifd_entry.entry_type,
                ifd_entry.value_count,
                ifd_entry.value_offset
            );

            ifd.entries.insert(tag, ifd_entry);
        }

        let next_ifd = if big_tiff {
            byte_reader.read_u64(reader)?
        } else {
            byte_reader.read_u32(reader)?.into()
        };

        match next_ifd {
            0 => (),
            _ => ifd.next_ifd_offset = Some(next_ifd),
        };

        Ok(ifd)
    }
}

pub fn map_tiff(input: &mut dyn CAIRead) -> Result<Ifd> {
    let _size = input.seek(SeekFrom::End(0))?;
    input.seek(SeekFrom::Start(0))?;

    let ts = TiffStructure::load(input)?;

    ts.first_ifd
        .ok_or(Error::BadParam("Could not parse TIFF/DNG".to_string()))
}

pub struct TiffIO {}

fn get_cai_data(asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
    let first_idf = map_tiff(asset_reader)?;

    let cai_ifd_entry = first_idf.get_tag(C2PA_TAG).ok_or(Error::JumbfNotFound)?;

    // make sure data type is for unstructured data
    if cai_ifd_entry.entry_type != C2PA_FIELD_TYPE {
        return Err(Error::BadParam(
            "Ifd entry for C2PA must be type UNKNOWN(7)".to_string(),
        ));
    }

    // move read point to start of entry
    asset_reader.seek(SeekFrom::Start(cai_ifd_entry.value_offset))?;

    let manifest_len: usize = usize::value_from(cai_ifd_entry.value_count)
        .map_err(|_err| Error::BadParam("TIFF/DNG out of range".to_string()))?;

    let mut data = Vec::with_capacity(manifest_len);

    asset_reader
        .read_exact(&mut data[..])
        .map_err(|_err| Error::BadParam("TIFF/DNG out of range".to_string()))?;

    Ok(data)
}

impl CAILoader for TiffIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let cai_data = get_cai_data(asset_reader)?;
        Ok(cai_data)
    }

    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_dup_tiff() {
        let _data = "some data";

        let source = crate::utils::test::fixture_path("TUSCANY.TIF");

        let mut in_file = std::fs::File::open(&source).unwrap();

        map_tiff(&mut in_file).unwrap();
    }
}
