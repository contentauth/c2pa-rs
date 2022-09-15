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
use conv::ValueFrom;
use tiff::{encoder::*, TiffResult};
use tiff::tags::Tag;

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{SeekFrom, Write, Seek, Read};
use std::slice::from_ref;

use crate::asset_io::{CAILoader, CAIRead};
use crate::error::{Error, Result};

const C2PA_TAG: u16 = 0xCd41;
#[allow(dead_code)]
const C2PA_FIELD_TYPE: u16 = 1;

#[derive(Clone)]
pub(crate) enum Endianess {
    BigEndian,
    LittleEndian,
}

#[allow(dead_code)]
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
    pub fn read_u16<R: ?Sized>(&self, r: &mut R) -> Result<u16> 
    where
    R: Read + Seek
    {
        match self.byte_order {
            Endianess::BigEndian => r.read_u16::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_u16::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_i16<R: ?Sized>(&self, r: &mut R) -> Result<i16> 
    where
    R: Read + Seek
    {
        match self.byte_order {
            Endianess::BigEndian => r.read_i16::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_i16::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_u32<R: ?Sized>(&self, r: &mut R) -> Result<u32> 
    where
    R: Read + Seek
    {
        match self.byte_order {
            Endianess::BigEndian => r.read_u32::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_u32::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_i32<R: ?Sized>(&self, r: &mut R) -> Result<i32> 
    where
    R: Read + Seek
    {
        match self.byte_order {
            Endianess::BigEndian => r.read_i32::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_i32::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_u64<R: ?Sized>(&self, r: &mut R) -> Result<u64> 
    where
    R: Read + Seek
    {
        match self.byte_order {
            Endianess::BigEndian => r.read_u64::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_u64::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_i64<R: ?Sized>(&self, r: &mut R) -> Result<i64> 
    where
    R: Read + Seek
    {
        match self.byte_order {
            Endianess::BigEndian => r.read_i64::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_i64::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_f32<R: ?Sized>(&self, r: &mut R) -> Result<f32> 
    where
    R: Read + Seek
    {
        match self.byte_order {
            Endianess::BigEndian => r.read_f32::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_f32::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_f64<R: ?Sized>(&self, r: &mut R) -> Result<f64> 
    where
    R: Read + Seek
    {
        match self.byte_order {
            Endianess::BigEndian => r.read_f64::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianess::LittleEndian => r
                .read_f64::<LittleEndian>()
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
pub struct ImageFileDirectory {
    offset: u64,
    entry_cnt: u64,
    entries: HashMap<u16, IfdEntry>,
    next_ifd_offset: Option<u64>,
}

impl ImageFileDirectory {
    #[allow(dead_code)]
    pub fn get_tag(&self, tag_id: u16) -> Option<&IfdEntry> {
        self.entries.get(&tag_id)
    }
}

#[allow(dead_code)]
pub(crate) struct TiffStructure {
    byte_order: Endianess,
    big_tiff: bool,
    first_ifd_offset: u64,
    first_ifd: Option<ImageFileDirectory>,
}

#[allow(dead_code)]
const II: [u8; 2] = *b"II";
#[allow(dead_code)]
const MM: [u8; 2] = *b"MM";

impl TiffStructure {
    #[allow(dead_code)]
    pub fn load<R: ?Sized>(reader: &mut R) -> Result<Self> 
    where
        R: Read + Seek
    {
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

    #[allow(dead_code)]
    fn read_ifd<R: ?Sized>(reader: &mut R, byte_order: Endianess, big_tiff: bool) -> Result<ImageFileDirectory> 
    where
        R: Read + Seek
    {
        let byte_reader = EndianReader::new(byte_order);

        let ifd_offset = reader.seek(SeekFrom::Current(0))?;

        let entry_cnt = if big_tiff {
            byte_reader.read_u64(reader)?
        } else {
            byte_reader.read_u16(reader)?.into()
        };

        let mut ifd = ImageFileDirectory {
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


#[allow(dead_code)]
pub fn map_tiff<R: ?Sized>(input: &mut R) -> Result<(ImageFileDirectory, Endianess)> 
where
  R: Read + Seek
{
    let _size = input.seek(SeekFrom::End(0))?;
    input.seek(SeekFrom::Start(0))?;

    let ts = TiffStructure::load(input)?;

    Ok((ts.first_ifd
        .ok_or(Error::BadParam("Could not parse TIFF/DNG".to_string()))?, ts.byte_order))
}

fn get_cai_data<R: ?Sized>(asset_reader: &mut R) -> Result<Vec<u8>> 
where
  R: Read + Seek
{
    //let first_idf = map_tiff(asset_reader)?;

    //let cai_ifd_entry = first_idf.get_tag(C2PA_TAG).ok_or(Error::JumbfNotFound)?;

    //let e = tiff::decoder::ifd::Entry::new_u64(tiff::tags::Type::BYTE, 
    //    cai_ifd_entry.value_count, cai_ifd_entry.value_offset.to_ne_bytes());


    //let sr =  SmartReader::wrap(asset_reader, ByteOrder::LittleEndian);

    //let v = e.val(&tiff::decoder::Limits::unlimited(), false, asset_reader).unwrap();

    let mut d = tiff::decoder::Decoder::new(asset_reader).unwrap();

    let v = d.find_tag(tiff::tags::Tag::Unknown(C2PA_TAG)).unwrap();

    if let Some(val) = v {
        let output = val.into_u8_vec().unwrap();
        return Ok(output) 
    }

    /*
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
    */
    Err(Error::JumbfBoxNotFound)

    //Ok(data)
}


#[allow(dead_code)]
fn write_manifest<W>(w: &mut W, _assert_reader: &dyn CAIRead, data: &[u8]) -> Result<u64> 
where 
    W: Write + Seek, 
{
    use tiff::{encoder::*, tags::*};

    let mut image_data = Vec::new();
    for x in 0..100 {
        for y in 0..100u8 {
            let val = x + y;
            image_data.push(val);
            image_data.push(val);
            image_data.push(val);
        }
    }

    {
        let mut tiff = TiffEncoder::new(w).unwrap();

        let mut image = tiff.new_image::<colortype::RGB8>(100, 100).unwrap();
        image
            .encoder()
            .write_tag(Tag::Artist, "Image-tiff")
            .unwrap();
            image
            .encoder()
            .write_tag(Tag::Unknown(C2PA_TAG), data)
            .unwrap();
        image.write_data(&image_data).unwrap();
    }
    
    Ok(0)
}


/// Type to represent tiff values of type `IFD`
#[derive(Clone)]
struct Ifd(pub u32);

/// Type to represent tiff values of type `IFD8`
#[derive(Clone)]
struct Ifd8(pub u64);

/// Type to represent tiff values of type `RATIONAL`
#[derive(Clone)]
struct Rational {
    pub n: u32,
    pub d: u32,
}

/// Type to represent tiff values of type `SRATIONAL`
#[derive(Clone)]
struct SRational {
    pub n: i32,
    pub d: i32,
}
  
impl TiffValue for Rational {
    const BYTE_LEN: u8 = 8;
    const FIELD_TYPE: tiff::tags::Type = tiff::tags::Type::RATIONAL;

    fn count(&self) -> usize {
        1
    }

    fn write<W: Write>(&self, writer: &mut TiffWriter<W>) -> TiffResult<()> {
        writer.write_u32(self.n)?;
        writer.write_u32(self.d)?;
        Ok(())
    }

    fn data(&self) -> Cow<[u8]> {
        Cow::Owned({
            let first_dword = from_ref(&self.n);
            let second_dword = from_ref(&self.d);
            [first_dword, second_dword].concat()
        })
    }
}

impl TiffValue for SRational {
    const BYTE_LEN: u8 = 8;
    const FIELD_TYPE: tiff::tags::Type = tiff::tags::Type::SRATIONAL;

    fn count(&self) -> usize {
        1
    }

    fn write<W: Write>(&self, writer: &mut TiffWriter<W>) -> TiffResult<()> {
        writer.write_i32(self.n)?;
        writer.write_i32(self.d)?;
        Ok(())
    }

    fn data(&self) -> Cow<[u8]> {
        Cow::Owned({
            let first_dword = bytecast::i32_as_ne_bytes(from_ref(&self.n));
            let second_dword = bytecast::i32_as_ne_bytes(from_ref(&self.d));
            [first_dword, second_dword].concat()
        })
    }
}
fn clone_idf_entries< R: Read + Seek, W: Write + Seek>(entries: &HashMap<u16, IfdEntry>, asset_reader:  &mut R, writer: &mut W, endianess: Endianess) -> Result<()> 
{
    let mut tiff = TiffEncoder::new(writer).unwrap();
    let er = EndianReader::new(endianess);

    let mut new_ifd = tiff.new_directory().unwrap();

    for (tag, entry) in entries {
        // get bytes for tag
        let cnt = entry.value_count;
        let offset = entry.value_offset;
        let et = entry.entry_type;

        let entry_type = tiff::tags::Type::from_u16(et).ok_or(Error::UnsupportedType)?;

        // move to start of data 
        asset_reader.seek(SeekFrom::Start(offset))?;
    
        match entry_type {
            tiff::tags::Type::BYTE => {
                let num_bytes = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
    
                let mut data = vec![0u8; num_bytes];
                asset_reader.read_exact(&mut data)?;
                
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::ASCII => {
                let num_chars = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
    
                let mut data = vec![0u8; num_chars];
                asset_reader.read_exact(&mut data)?;
                
                let s = String::from_utf8_lossy(&data).to_string();

                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), s.as_str()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::SHORT => {
                let num_shorts = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data = vec![0u16; num_shorts];

                for i in 0..num_shorts {
                    let val = er.read_u16(asset_reader)?;
                    data.push(val);
                }
                
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::LONG => {
                let num_longs = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data = vec![0u32; num_longs];
               
                for i in 0..num_longs {
                    let val = er.read_u32(asset_reader)?;
                    data.push(val);
                }
                
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::RATIONAL => {
                let num_rationals = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data: Vec<Rational> = Vec::new();

                for i in 0..num_rationals {
                    let n = er.read_u32(asset_reader)?;
                    let d = er.read_u32(asset_reader)?;

                    let r = Rational { n, d };
                    
                    data.push(r);
                }
               
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::SBYTE => {
                let num_sbytes = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
    
                let mut data = vec![0i8; num_sbytes];
                asset_reader.read_exact(&mut data)?;
                
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::UNDEFINED => 
            {
                let num_undefined = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
    
                let mut data = vec![0u8; num_undefined];
                asset_reader.read_exact(&mut data)?;
                
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::SSHORT => {
                let num_sshorts = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data = vec![0i16; num_sshorts];

                for i in 0..num_sshorts {
                    let val = er.read_i16(asset_reader)?;
                    data.push(val);
                }

                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::SLONG => {
                let num_slongs = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data = vec![0i32; num_slongs];
                
                for i in 0..num_slongs {
                    let val = er.read_i32(asset_reader)?;
                    data.push(val);
                }

                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::SRATIONAL => {
                let num_srationals = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data: Vec<SRational> = Vec::new();

                for i in 0..num_srationals {
                    let n = er.read_i32(asset_reader)?;
                    let d = er.read_i32(asset_reader)?;

                    let s = SRational { n, d };
                    
                    data.push(s);
                }
               
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::FLOAT => {
                let num_floats = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data = vec![0f32; num_floats];

                for i in 0..num_floats {
                    let val = er.read_f32(asset_reader)?;
                    data.push(val);
                }

                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::DOUBLE => {
                let num_doubles = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data = vec![0f64; num_doubles];
                
                for i in 0..num_doubles {
                    let val = er.read_f64(asset_reader)?;
                    data.push(val);
                }
                
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::IFD => {
                let num_ifds = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data: Vec<Ifd> = Vec::with_capacity(num_ifds);

                for i in 0..num_ifds {
                    let ifd = asset_reader.read_u32()?;
                    data.push(Ifd(ifd));
                }
               
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::LONG8 => {
                let num_long8s = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data = vec![0u64; num_long8s];

                 for i in 0..num_long8s {
                    let val = er.read_u64(asset_reader)?;
                    data.push(val);
                }

                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::SLONG8 => {
                let num_slong8s = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data = vec![0i64; num_slong8s];

                 for i in 0..num_slong8s {
                    let val = er.read_i64(asset_reader)?;
                    data.push(val);
                }
                
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            tiff::tags::Type::IFD8 => {
                let num_ifd8s = usize::value_from(cnt).map_err(|_err| Error::BadParam("value out of range".to_string()))?; 
                let mut data: Vec<Ifd8> = Vec::new();

                for i in 0..num_ifd8s {
                    let ifd = asset_reader.read_u64()?;
                    data.push(Ifd8(ifd));
                }
               
                new_ifd.write_tag(Tag::from_u16_exhaustive(*tag), data.as_slice()).map_err(|_| Error::UnsupportedType)?;
            }
            _ => return Err(Error::UnsupportedType),
        }
    }
    new_ifd.finish().map_err(|_| Error::UnsupportedType)?;

    Ok(())
}

fn tiff_clone<R: Read + Seek, W: Write + Seek>(writer: &mut W, asset_reader: &mut R) -> Result<()> 
{
    let (ifd, endianess) =  map_tiff(&mut asset_reader)?;

    let mut tiff = TiffEncoder::new(writer).unwrap();

    clone_idf_entries(&ifd.entries, asset_reader, writer, endianess)?;

    Ok(())
   
}
pub struct TiffIO {}

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
    fn test_read_manifest() {
        let _data = "some data";

        let source = crate::utils::test::fixture_path("TUSCANY.TIF");

        let mut in_file = std::fs::File::open(&source).unwrap();

        let _ifd = map_tiff(&mut in_file).unwrap();


        // make a new tiff
        let data = "some test data".as_bytes();

        let output: Vec<u8> = Vec::new();
        let mut c = std::io::Cursor::new(output);

        write_manifest(&mut c, &mut in_file, data).unwrap();

        let data = "some test data".as_bytes();

        let tiff_io = TiffIO{};

        c.seek(SeekFrom::Start(0)).unwrap();
        let c2pa_data = tiff_io.read_cai(&mut c).unwrap();

        assert_eq!(&c2pa_data, data);

    }
}
