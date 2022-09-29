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

use byteorder::{BigEndian, LittleEndian, NativeEndian, ReadBytesExt};
use byteordered::{with_order, ByteOrdered, Endianness};
use conv::ValueFrom;
use tempfile::Builder;

//use std::borrow::Cow;
use std::io::{Read, Seek, SeekFrom, Write};
use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
};
//use std::slice::from_ref;

use crate::asset_io::{AssetIO, CAILoader, CAIRead, HashBlockObjectType, HashObjectPositions};
use crate::error::{Error, Result};

const C2PA_TAG: u16 = 0xCd41;
#[allow(dead_code)]
const C2PA_FIELD_TYPE: u16 = 1;

const STRIPBYTECOUNTS: u16 = 279;
const STRIPOFFSETS: u16 = 273;
const TILEBYTECOUNTS: u16 = 325;
const TILEOFFSETS: u16 = 324;

#[allow(dead_code)]
pub struct EndianIO {
    byte_order: Endianness,
}

#[allow(dead_code)]
impl EndianIO {
    pub fn new(endianness: Endianness) -> Self {
        EndianIO {
            byte_order: endianness,
        }
    }

    #[inline]
    pub fn read_u16<R: ?Sized>(&self, r: &mut R) -> Result<u16>
    where
        R: Read + Seek,
    {
        match self.byte_order {
            Endianness::Big => r.read_u16::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianness::Little => r
                .read_u16::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_i16<R: ?Sized>(&self, r: &mut R) -> Result<i16>
    where
        R: Read + Seek,
    {
        match self.byte_order {
            Endianness::Big => r.read_i16::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianness::Little => r
                .read_i16::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_u32<R: ?Sized>(&self, r: &mut R) -> Result<u32>
    where
        R: Read + Seek,
    {
        match self.byte_order {
            Endianness::Big => r.read_u32::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianness::Little => r
                .read_u32::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_i32<R: ?Sized>(&self, r: &mut R) -> Result<i32>
    where
        R: Read + Seek,
    {
        match self.byte_order {
            Endianness::Big => r.read_i32::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianness::Little => r
                .read_i32::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_u64<R: ?Sized>(&self, r: &mut R) -> Result<u64>
    where
        R: Read + Seek,
    {
        match self.byte_order {
            Endianness::Big => r.read_u64::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianness::Little => r
                .read_u64::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_i64<R: ?Sized>(&self, r: &mut R) -> Result<i64>
    where
        R: Read + Seek,
    {
        match self.byte_order {
            Endianness::Big => r.read_i64::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianness::Little => r
                .read_i64::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_f32<R: ?Sized>(&self, r: &mut R) -> Result<f32>
    where
        R: Read + Seek,
    {
        match self.byte_order {
            Endianness::Big => r.read_f32::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianness::Little => r
                .read_f32::<LittleEndian>()
                .map_err(crate::error::wrap_io_err),
        }
    }

    #[inline]
    pub fn read_f64<R: ?Sized>(&self, r: &mut R) -> Result<f64>
    where
        R: Read + Seek,
    {
        match self.byte_order {
            Endianness::Big => r.read_f64::<BigEndian>().map_err(crate::error::wrap_io_err),
            Endianness::Little => r
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
    byte_order: Endianness,
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
        R: Read + Seek,
    {
        let mut endianness = [0u8, 2];
        reader.read_exact(&mut endianness)?;

        let byte_order = match endianness {
            II => Endianness::Little,
            MM => Endianness::Big,
            _ => return Err(Error::BadParam("Could not parse input image".to_owned())),
        };

        let byte_reader = EndianIO::new(byte_order.clone());

        let big_tiff = match byte_reader.read_u16(reader) {
            Ok(42) => false,
            Ok(43) => {
                // read past Endianness::Big TIFF structs
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
    fn read_ifd<R: ?Sized>(
        reader: &mut R,
        byte_order: Endianness,
        big_tiff: bool,
    ) -> Result<ImageFileDirectory>
    where
        R: Read + Seek,
    {
        let byte_reader = EndianIO::new(byte_order);

        let ifd_offset = reader.seek(SeekFrom::Current(0))?;
        println!("IDF Offset: {:#x}", ifd_offset);

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
                "{}, {}, {}. {:?}",
                ifd_entry.entry_tag,
                ifd_entry.entry_type,
                ifd_entry.value_count,
                ifd_entry.value_offset.to_ne_bytes()
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
fn map_tiff<R: ?Sized>(input: &mut R) -> Result<(ImageFileDirectory, Endianness)>
where
    R: Read + Seek,
{
    let _size = input.seek(SeekFrom::End(0))?;
    input.seek(SeekFrom::Start(0))?;

    let ts = TiffStructure::load(input)?;

    Ok((
        ts.first_ifd
            .ok_or(Error::BadParam("Could not parse TIFF/DNG".to_string()))?,
        ts.byte_order,
    ))
}

fn get_cai_data<R: ?Sized>(asset_reader: &mut R) -> Result<Vec<u8>>
where
    R: Read + Seek,
{
    let (first_idf, _e) = map_tiff(asset_reader)?;

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

    let mut data = vec![0u8; manifest_len];

    asset_reader
        .read_exact(data.as_mut_slice())
        .map_err(|_err| Error::InvalidSourceAsset("TIFF/DNG out of range".to_string()))?;

    Ok(data)
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

#[derive(PartialEq, Clone)]
pub struct IfdClonedEntry {
    pub entry_tag: u16,
    pub entry_type: u16,
    pub value_count: u64,
    pub value_bytes: Vec<u8>,
}

pub struct TiffCloner<T>
where
    T: Write + Seek,
{
    endianness: Endianness,
    big_tiff: bool,
    first_idf_offset: u64,
    writer: ByteOrdered<T, Endianness>,
    target_ifd: BTreeMap<u16, IfdClonedEntry>,
}

impl<T: Write + Seek> TiffCloner<T> {
    pub fn new(endianness: Endianness, big_tiff: bool, writer: T) -> Result<TiffCloner<T>> {
        let bo = ByteOrdered::runtime(writer, endianness);

        let mut tc = TiffCloner {
            endianness,
            big_tiff,
            first_idf_offset: 0,
            writer: bo,
            target_ifd: BTreeMap::new(),
        };

        tc.write_header()?;

        Ok(tc)
    }

    fn offset(&mut self) -> Result<u64> {
        Ok(self.writer.seek(SeekFrom::Current(0))?)
    }

    fn pad_word_boundary(&mut self) -> Result<()> {
        let curr_offset = self.offset()?;
        if curr_offset % 4 != 0 {
            let padding = [0, 0, 0];
            let padd_len = 4 - (curr_offset % 4);
            self.writer.write_all(&padding[..padd_len as usize])?;
        }

        Ok(())
    }

    fn write_header(&mut self) -> Result<u64> {
        let boi = match self.endianness {
            Endianness::Big => 0x4d,
            Endianness::Little => 0x49,
        };
        let offset;

        if self.big_tiff {
            self.writer.write(&[boi, boi])?;
            self.writer.write_u16(43u16)?;
            self.writer.write_u16(8u16)?;
            self.writer.write_u16(0u16)?;
            offset = self.writer.seek(SeekFrom::Current(0))?; // first ifd offset

            self.writer.write_u64(0)?;
        } else {
            self.writer.write(&[boi, boi])?;
            self.writer.write_u16(42u16)?;
            offset = self.writer.seek(SeekFrom::Current(0))?; // first ifd offset

            self.writer.write_u32(0)?;
        }

        self.first_idf_offset = offset;
        Ok(offset)
    }

    fn write_entry_count(&mut self, count: usize) -> Result<()> {
        if self.big_tiff {
            let cnt = u64::value_from(count)
                .map_err(|_err| Error::BadParam("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            self.writer.write_u64(cnt)?;
        } else {
            let cnt = u16::value_from(count)
                .map_err(|_err| Error::BadParam("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            self.writer.write_u16(cnt)?;
        }

        Ok(())
    }

    pub fn add_target_tag(&mut self, entry: IfdClonedEntry) {
        self.target_ifd.insert(entry.entry_tag, entry);
    }

    pub fn clone_image_data<R: Read + Seek>(
        &mut self,
        _entries: &HashMap<u16, IfdEntry>,
        asset_reader: &mut R,
    ) -> Result<()> {
        match (
            self.target_ifd.contains_key(&STRIPBYTECOUNTS),
            self.target_ifd.contains_key(&STRIPOFFSETS),
            self.target_ifd.contains_key(&TILEBYTECOUNTS),
            self.target_ifd.contains_key(&TILEOFFSETS),
        ) {
            (true, true, false, false) => {
                let sbc_entry = self.target_ifd[&STRIPBYTECOUNTS].clone();
                let so_entry = self
                    .target_ifd
                    .get_mut(&STRIPOFFSETS)
                    .ok_or(Error::NotFound)?;

                // check for well formed TIFF
                if so_entry.value_count != sbc_entry.value_count {
                    return Err(Error::InvalidSourceAsset(
                        "TIFF strip count does not match strip offset count".to_string(),
                    ));
                }

                if so_entry.entry_type != 4 {
                    return Err(Error::InvalidSourceAsset(
                        "expected LONG TagStripOffests, found SHORT".to_string(),
                    ));
                }

                let mut sbcs = vec![0u64; sbc_entry.value_count as usize];
                let mut dest_offsets: Vec<u64> = Vec::new();

                // get the byte counts
                with_order!(sbc_entry.value_bytes.as_slice(), self.endianness, |src| {
                    for i in 0..sbcs.len() {
                        match sbc_entry.entry_type {
                            4u16 => {
                                let s = src.read_u32()?;
                                sbcs[i] = s.into();
                            }
                            3u16 => {
                                let s = src.read_u16()?;
                                sbcs[i] = s.into();
                            }
                            16u16 => {
                                let s = src.read_u64()?;
                                sbcs[i] = s;
                            }
                            _ => {
                                return Err(Error::InvalidSourceAsset(
                                    "invalid TIFF strip".to_string(),
                                ))
                            }
                        }
                    }
                });

                // seek to end of file
                self.writer.seek(SeekFrom::End(0))?;

                // copy the strips
                with_order!(so_entry.value_bytes.as_slice(), self.endianness, |src| {
                    for i in 0..so_entry.value_count as usize {
                        let cnt = usize::value_from(sbcs[i])
                            .map_err(|_err| Error::BadParam("value out of range".to_string()))?;

                        // get the offset
                        let so: u64 = match so_entry.entry_type {
                            4u16 => {
                                let s = src.read_u32()?;
                                s.into()
                            }
                            3u16 => {
                                let s = src.read_u16()?;
                                s.into()
                            }
                            16u16 => {
                                let s = src.read_u64()?;
                                s.into()
                            }
                            _ => {
                                return Err(Error::InvalidSourceAsset(
                                    "invalid TIFF strip".to_string(),
                                ))
                            }
                        };

                        let dest_offset = self.writer.seek(SeekFrom::Current(0))?;
                        dest_offsets.push(dest_offset);

                        // copy the strip to new file
                        let mut data = vec![0u8; cnt];
                        asset_reader.seek(SeekFrom::Start(so))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                        self.writer.write_all(data.as_slice())?;
                    }
                });

                // patch the offsets
                with_order!(
                    so_entry.value_bytes.as_mut_slice(),
                    self.endianness,
                    |dest| {
                        for i in 0..so_entry.value_count as usize {
                            // get the offset
                            match so_entry.entry_type {
                                4u16 => {
                                    let offset =
                                        u32::value_from(dest_offsets[i]).map_err(|_err| {
                                            Error::BadParam("value out of range".to_string())
                                        })?;
                                    dest.write_u32(offset)?;
                                }
                                3u16 => {
                                    let offset =
                                        u16::value_from(dest_offsets[i]).map_err(|_err| {
                                            Error::BadParam("value out of range".to_string())
                                        })?;
                                    dest.write_u16(offset)?;
                                }
                                16u16 => {
                                    let offset = dest_offsets[i];
                                    dest.write_u64(offset)?;
                                }
                                _ => {
                                    return Err(Error::InvalidSourceAsset(
                                        "invalid TIFF strip".to_string(),
                                    ))
                                }
                            }
                        }
                    }
                );
            }
            (false, false, true, true) => {
                /*
                chunk_type = ChunkType::Tile;

                let tile_width =
                    usize::try_from(tag_reader.require_tag(Tag::TileWidth)?.into_u32()?)?;
                let tile_length =
                    usize::try_from(tag_reader.require_tag(Tag::TileLength)?.into_u32()?)?;

                if tile_width == 0 {
                    return Err(TiffFormatError::InvalidTagValueType(Tag::TileWidth).into());
                } else if tile_length == 0 {
                    return Err(TiffFormatError::InvalidTagValueType(Tag::TileLength).into());
                }

                strip_decoder = None;
                tile_attributes = Some(TileAttributes {
                    image_width: usize::try_from(width)?,
                    image_height: usize::try_from(height)?,
                    tile_width,
                    tile_length,
                });
                chunk_offsets = tag_reader
                    .find_tag(Tag::TileOffsets)?
                    .unwrap()
                    .into_u64_vec()?;
                chunk_bytes = tag_reader
                    .find_tag(Tag::TileByteCounts)?
                    .unwrap()
                    .into_u64_vec()?;

                let tile = tile_attributes.as_ref().unwrap();
                if chunk_offsets.len() != chunk_bytes.len()
                    || chunk_offsets.len() != tile.tiles_down() * tile.tiles_across()
                {
                    return Err(TiffError::FormatError(
                        TiffFormatError::InconsistentSizesEncountered,
                    ));
                }

                */
            }
            (_, _, _, _) => {
                return Err(Error::InvalidSourceAsset(
                    "unknown TIFF image layout".to_string(),
                ))
            }
        };

        Ok(())
    }

    pub fn clone_tiff<R: Read + Seek>(
        &mut self,
        entries: &HashMap<u16, IfdEntry>,
        asset_reader: &mut R,
    ) -> Result<()> {
        // Clone IFD entries
        self.clone_idf_entries(entries, asset_reader)?;

        // Clone the image data
        self.clone_image_data(entries, asset_reader)?;

        // Write directory
        let ifd_offset = self.write_ifd()?;

        // Write final location info
        let curr_pos = self.offset()?;

        self.writer.seek(SeekFrom::Start(self.first_idf_offset))?;

        if self.big_tiff {
            self.writer.write_u64(ifd_offset)?;
            self.writer.seek(SeekFrom::Start(curr_pos))?;
            self.writer.write_u64(0)?;
        } else {
            let offset_u32 = u32::value_from(ifd_offset)
                .map_err(|_err| Error::BadParam("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            self.writer.write_u32(offset_u32)?;
            self.writer.seek(SeekFrom::Start(curr_pos))?;
            self.writer.write_u32(0)?;
        }

        Ok(())
    }

    fn write_ifd(&mut self) -> Result<u64> {
        // Start on a WORD boundary
        self.pad_word_boundary()?;

        // Write out all data and save the offsets
        for &mut IfdClonedEntry {
            value_bytes: ref mut value_bytes_ref,
            ..
        } in self.target_ifd.values_mut()
        {
            let data_bytes = if self.big_tiff { 8 } else { 4 };

            if value_bytes_ref.len() > data_bytes {
                let offset = self.writer.seek(SeekFrom::Current(0))?; // get location of entry data start

                self.writer.write_all(value_bytes_ref)?; // write out the data bytes

                // Set offset pointer in file source endian
                let mut offset_vec = vec![0; data_bytes];

                with_order!(offset_vec.as_mut_slice(), self.endianness, |ew| {
                    if self.big_tiff {
                        ew.write_u64(offset)?;
                    } else {
                        let offset_u32 = u32::value_from(offset)
                            .map_err(|_err| Error::BadParam("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

                        ew.write_u32(offset_u32)?;
                    }
                });

                *value_bytes_ref = offset_vec; // Set to new data offset position
            } else {
                while value_bytes_ref.len() < data_bytes {
                    value_bytes_ref.push(0); // is this need for clone
                }
            }
        }

        // Write out the IFD

        // Save location of start of IFD
        let ifd_offset = self.writer.seek(SeekFrom::Current(0))?;

        // Write out the entry count
        self.write_entry_count(self.target_ifd.len())?;

        // Write out the directory entries

        for (tag, entry) in self.target_ifd.iter() {
            self.writer.write_u16(*tag)?;
            self.writer.write_u16(entry.entry_type)?;

            if self.big_tiff {
                let cnt = u64::value_from(entry.value_count)
                    .map_err(|_err| Error::BadParam("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

                self.writer.write_u64(cnt)?;
            } else {
                let cnt = u32::value_from(entry.value_count)
                    .map_err(|_err| Error::BadParam("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

                self.writer.write_u32(cnt)?;
            }

            self.writer.write_all(&entry.value_bytes)?; // Write offset or data
        }

        Ok(ifd_offset)
    }

    fn clone_idf_entries<R: Read + Seek>(
        &mut self,
        entries: &HashMap<u16, IfdEntry>,
        asset_reader: &mut R,
    ) -> Result<()> {
        for (tag, entry) in entries {
            // skip if we already have a replacement tag
            if self.target_ifd.contains_key(tag) {
                continue;
            }

            // get bytes for tag
            let cnt = entry.value_count;
            let offset = entry.value_offset;
            let et = entry.entry_type;

            let target_endianness = self.writer.endianness();

            let entry_type = tiff::tags::Type::from_u16(et).ok_or(Error::UnsupportedType)?;

            // read IFD raw data in file native endian format
            let data = match entry_type {
                tiff::tags::Type::BYTE | tiff::tags::Type::SBYTE => {
                    let num_bytes = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;

                    let mut data = vec![0u8; num_bytes];

                    if num_bytes <= 4 || self.big_tiff && num_bytes <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        for i in 0..num_bytes {
                            data.push(offset_bytes[i]);
                        }
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(offset))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                tiff::tags::Type::ASCII => {
                    let num_chars = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;

                    let mut data = vec![0u8; num_chars];

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(offset))?;
                    asset_reader.read_exact(data.as_mut_slice())?;

                    if data.is_ascii() && data.ends_with(&[0]) {
                        data
                    } else {
                        return Err(Error::InvalidSourceAsset("invalid TIFF tag".to_string()));
                    }
                }
                tiff::tags::Type::SHORT => {
                    let num_shorts = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_shorts * 2];

                    if num_shorts * 2 <= 4 || self.big_tiff && num_shorts * 2 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        with_order!(data.as_mut_slice(), target_endianness, |dest| {
                            for _i in 0..num_shorts {
                                let s = offset_reader.read_u16::<NativeEndian>()?; // read a short from offset
                                dest.write_u16(s)?; // write a short in output endian
                            }
                        });
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(offset))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                tiff::tags::Type::LONG => {
                    let num_longs = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_longs * 4];

                    if num_longs * 4 <= 4 || self.big_tiff && num_longs * 4 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        with_order!(data.as_mut_slice(), target_endianness, |dest| {
                            for _i in 0..num_longs {
                                let s = offset_reader.read_u32::<NativeEndian>()?; // read a long from offset
                                dest.write_u32(s)?; // write a short in output endian
                            }
                        });
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(offset))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                tiff::tags::Type::RATIONAL => {
                    let num_rationals = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_rationals * 8];

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(offset))?;
                    asset_reader.read_exact(data.as_mut_slice())?;

                    data
                }
                tiff::tags::Type::UNDEFINED => {
                    let num_undefined = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_undefined];

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(offset))?;
                    asset_reader.read_exact(data.as_mut_slice())?;

                    data
                }
                tiff::tags::Type::SSHORT => {
                    let num_sshorts = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_sshorts * 2];

                    if num_sshorts * 2 <= 4 || self.big_tiff && num_sshorts * 2 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        with_order!(data.as_mut_slice(), target_endianness, |dest| {
                            for _i in 0..num_sshorts {
                                let s = offset_reader.read_i16::<NativeEndian>()?; // read a signed short from offset
                                dest.write_i16(s)?; // write a signed short in output endian
                            }
                        });
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(offset))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                tiff::tags::Type::SLONG => {
                    let num_slongs = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_slongs * 4];

                    if num_slongs * 4 <= 4 || self.big_tiff && num_slongs * 4 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        with_order!(data.as_mut_slice(), target_endianness, |dest| {
                            for _i in 0..num_slongs {
                                let s = offset_reader.read_i32::<NativeEndian>()?; // read a signed long from offset
                                dest.write_i32(s)?; // write a signed short in output endian
                            }
                        });
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(offset))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                tiff::tags::Type::SRATIONAL => {
                    let num_srationals = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_srationals * 8];

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(offset))?;
                    asset_reader.read_exact(data.as_mut_slice())?;

                    data
                }
                tiff::tags::Type::FLOAT => {
                    let num_floats = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_floats * 4];

                    if num_floats * 4 <= 4 || self.big_tiff && num_floats * 4 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        with_order!(data.as_mut_slice(), target_endianness, |dest| {
                            for _i in 0..num_floats {
                                let s = offset_reader.read_f32::<NativeEndian>()?; // read a float from offset
                                dest.write_f32(s)?; // write a float in output endian
                            }
                        });
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(offset))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                tiff::tags::Type::DOUBLE => {
                    let num_doubles = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_doubles * 8];

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(offset))?;
                    asset_reader.read_exact(data.as_mut_slice())?;

                    data
                }
                tiff::tags::Type::IFD => {
                    let num_ifds = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_ifds * 4];

                    if num_ifds * 4 <= 4 || self.big_tiff && num_ifds * 4 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        with_order!(data.as_mut_slice(), target_endianness, |dest| {
                            for _i in 0..num_ifds {
                                let s = offset_reader.read_u32::<NativeEndian>()?; // read a ifd from offset
                                dest.write_u32(s)?; // write a ifd in output endian
                            }
                        });
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(offset))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                tiff::tags::Type::LONG8 => {
                    let num_long8s = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_long8s * 8];

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(offset))?;
                    asset_reader.read_exact(data.as_mut_slice())?;

                    data
                }
                tiff::tags::Type::SLONG8 => {
                    let num_slong8s = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_slong8s * 8];

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(offset))?;
                    asset_reader.read_exact(data.as_mut_slice())?;

                    data
                }
                tiff::tags::Type::IFD8 => {
                    let num_ifd8s = usize::value_from(cnt)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;
                    let mut data = vec![0u8; num_ifd8s * 8];

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(offset))?;
                    asset_reader.read_exact(data.as_mut_slice())?;

                    data
                }
                _ => return Err(Error::UnsupportedType),
            };

            self.target_ifd.insert(
                *tag,
                IfdClonedEntry {
                    entry_tag: *tag,
                    entry_type: entry_type.to_u16(),
                    value_count: cnt,
                    value_bytes: data,
                },
            );
        }

        Ok(())
    }
}

fn tiff_clone_with_tags<R: Read + Seek, W: Write + Seek>(
    writer: &mut W,
    asset_reader: &mut R,
    tiff_tags: Vec<IfdClonedEntry>,
) -> Result<()> {
    let (ifd, endianess) = map_tiff(asset_reader)?;

    let mut bo = ByteOrdered::new(writer, endianess);

    let mut tc = TiffCloner::new(endianess, false, &mut bo)?;

    for e in tiff_tags {
        tc.add_target_tag(e);
    }

    tc.clone_tiff(&ifd.entries, asset_reader)?;

    Ok(())
}

fn add_required_tags(asset_path: &std::path::Path) -> Result<()> {
    let mut f = std::fs::File::open(asset_path)?;
    let tiff_io = TiffIO {};

    match tiff_io.read_cai(&mut f) {
        Ok(_) => Ok(()),
        Err(Error::JumbfNotFound) => {
            // allocate enough bytes to that value is not stored in offset field
            let some_bytes = vec![0u8; 10];
            tiff_io.save_cai_store(asset_path, &some_bytes)
        }
        Err(e) => Err(e),
    }
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

impl AssetIO for TiffIO {
    fn read_cai_store(&self, asset_path: &std::path::Path) -> Result<Vec<u8>> {
        let mut reader = std::fs::File::open(asset_path)?;

        self.read_cai(&mut reader)
    }

    fn save_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        let mut reader = std::fs::File::open(asset_path)?;

        let l = u64::value_from(store_bytes.len())
            .map_err(|_err| Error::BadParam("value out of range".to_string()))?;

        let entry = IfdClonedEntry {
            entry_tag: C2PA_TAG,
            entry_type: C2PA_FIELD_TYPE,
            value_count: l,
            value_bytes: store_bytes.to_vec(),
        };

        tiff_clone_with_tags(&mut temp_file, &mut reader, vec![entry])?;

        std::fs::copy(temp_file.path(), asset_path)?;

        Ok(())
    }

    fn get_object_locations(
        &self,
        asset_path: &std::path::Path,
    ) -> Result<Vec<crate::asset_io::HashObjectPositions>> {
        add_required_tags(asset_path)?;

        let mut asset_reader =
            std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;

        let (first_idf, _e) = map_tiff(&mut asset_reader)?;

        let cai_ifd_entry = match first_idf.get_tag(C2PA_TAG) {
            Some(ifd) => ifd,
            None => return Ok(Vec::new()),
        };

        // make sure data type is for unstructured data
        if cai_ifd_entry.entry_type != C2PA_FIELD_TYPE {
            return Err(Error::BadParam(
                "Ifd entry for C2PA must be type UNKNOWN(7)".to_string(),
            ));
        }

        let manifest_offset = usize::value_from(cai_ifd_entry.value_offset)
            .map_err(|_err| Error::BadParam("TIFF/DNG out of range".to_string()))?;
        let manifest_len = usize::value_from(cai_ifd_entry.value_count)
            .map_err(|_err| Error::BadParam("TIFF/DNG out of range".to_string()))?;

        Ok(vec![HashObjectPositions {
            offset: manifest_offset,
            length: manifest_len,
            htype: HashBlockObjectType::Cai,
        }])

    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use tempfile::tempdir;

    use crate::utils::test::temp_dir_path;

    use super::*;

    #[test]
    fn test_read_write_manifest() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("TUSCANY.TIF");

        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tif");

        std::fs::copy(&source, &output).unwrap();

        let tiff_io = TiffIO {};

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data.as_bytes());
    }
}
