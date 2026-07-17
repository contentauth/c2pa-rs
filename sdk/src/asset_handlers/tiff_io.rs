// Copyright 2023 Adobe. All rights reserved.
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

// The TiffCloner::clone_tiff path is no longer used in favor of append only changes to the TIFF file.  It is kept for reference and possible future use.
#![allow(dead_code, unused_variables)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::OpenOptions,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
    vec,
};

use atree::{Arena, Token};
use byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt};
use byteordered::{with_order, ByteOrdered, Endianness};

use crate::{
    asset_io::{
        rename_or_move, AssetIO, AssetPatch, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        ComposedManifestRef, HashBlockObjectType, HashObjectPositions, RemoteRefEmbed,
        RemoteRefEmbedType,
    },
    error::{Error, Result},
    utils::{
        io_utils::{safe_vec, stream_len, tempfile_builder, ReaderUtils},
        xmp_inmemory_utils::{add_provenance, MIN_XMP},
    },
};

const II: [u8; 2] = *b"II";
const MM: [u8; 2] = *b"MM";

const C2PA_TAG: u16 = 0xcd41;
const XMP_TAG: u16 = 0x02bc;
const SUBFILE_TAG: u16 = 0x014a;
const EXIFIFD_TAG: u16 = 0x8769;
const GPSIFD_TAG: u16 = 0x8825;
const INTEROPERABILITY_TAG: u16 = 40965;
const C2PA_FIELD_TYPE: u16 = 7;

const STRIPBYTECOUNTS: u16 = 279;
const STRIPOFFSETS: u16 = 273;
const TILEBYTECOUNTS: u16 = 325;
const TILEOFFSETS: u16 = 324;

const BIGTABLEDIGESTS: u16 = 52540;
const BIGTABLEOFFSETS: u16 = 52541;
const BIGTABLEBYTECOUNTS: u16 = 52542;

/* support when we find a use case
const FREEOFFSETS: u16 = 288;
const FREEBYTECOUNTS: u16 = 289;
*/

const MAX_PAGES: usize = 2000; // avoid arbitrary large allocations and possible DoS attacks.  This is a reasonable limit for TIFF files.
const MAX_SUBFILES: usize = 1000; // avoid arbitrary large allocations and possible DoS attacks.  This is a reasonable limit for TIFF files.

const SUBFILES: [u16; 4] = [SUBFILE_TAG, EXIFIFD_TAG, GPSIFD_TAG, INTEROPERABILITY_TAG];

static SUPPORTED_TYPES: [&str; 10] = [
    "tif",
    "tiff",
    "image/tiff",
    "dng",
    "image/dng",
    "image/x-adobe-dng",
    "arw",
    "image/x-sony-arw",
    "nef",
    "image/x-nikon-nef",
];

// Writing native formats is beyond the scope of the SDK.
static SUPPORTED_WRITER_TYPES: [&str; 6] = [
    "tif",
    "tiff",
    "image/tiff",
    "dng",
    "image/dng",
    "image/x-adobe-dng",
];

// The type of an IFD entry
#[derive(Debug, PartialEq)]
enum IFDEntryType {
    Byte = 1,       // 8-bit unsigned integer
    Ascii = 2,      // 8-bit byte that contains a 7-bit ASCII code; the last byte must be zero
    Short = 3,      // 16-bit unsigned integer
    Long = 4,       // 32-bit unsigned integer
    Rational = 5,   // Fraction stored as two 32-bit unsigned integers
    Sbyte = 6,      // 8-bit signed integer
    Undefined = 7,  // 8-bit byte that may contain anything, depending on the field
    Sshort = 8,     // 16-bit signed integer
    Slong = 9,      // 32-bit signed integer
    Srational = 10, // Fraction stored as two 32-bit signed integers
    Float = 11,     // 32-bit IEEE floating point
    Double = 12,    // 64-bit IEEE floating point
    Ifd = 13,       // 32-bit unsigned integer (offset)
    Long8 = 16,     // BigTIFF 64-bit unsigned integer
    Slong8 = 17,    // BigTIFF 64-bit unsigned integer (offset)
    Ifd8 = 18,      // 64-bit unsigned integer (offset)
}

impl IFDEntryType {
    pub fn from_u16(val: u16) -> Option<IFDEntryType> {
        match val {
            1 => Some(IFDEntryType::Byte),
            2 => Some(IFDEntryType::Ascii),
            3 => Some(IFDEntryType::Short),
            4 => Some(IFDEntryType::Long),
            5 => Some(IFDEntryType::Rational),
            6 => Some(IFDEntryType::Sbyte),
            7 => Some(IFDEntryType::Undefined),
            8 => Some(IFDEntryType::Sshort),
            9 => Some(IFDEntryType::Slong),
            10 => Some(IFDEntryType::Srational),
            11 => Some(IFDEntryType::Float),
            12 => Some(IFDEntryType::Double),
            13 => Some(IFDEntryType::Ifd),
            16 => Some(IFDEntryType::Long8),
            17 => Some(IFDEntryType::Slong8),
            18 => Some(IFDEntryType::Ifd8),
            _ => None,
        }
    }
}

// TIFF IFD Entry (value_offset is in target endian)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfdEntry {
    entry_tag: u16,
    entry_type: u16,
    value_count: u64,
    value_offset: u64,
}

// helper enum to know if the IFD requires special handling
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IfdType {
    Page,
    Subfile,
    Exif,
    Gps,
}

// TIFF IFD
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageFileDirectory {
    offset: u64,
    entry_cnt: u64,
    ifd_type: IfdType,
    entries: BTreeMap<u16, IfdEntry>,
    next_ifd_offset: Option<u64>,
    next_idf_offset_location: u64,
}

impl ImageFileDirectory {
    pub fn get_tag(&self, tag_id: u16) -> Option<&IfdEntry> {
        self.entries.get(&tag_id)
    }

    #[allow(dead_code)]
    pub fn get_tag_mut(&mut self, tag_id: u16) -> Option<&mut IfdEntry> {
        self.entries.get_mut(&tag_id)
    }
}

// Struct to map the contents of a TIFF file
pub(crate) struct TiffStructure {
    byte_order: Endianness,
    big_tiff: bool,
    #[allow(dead_code)]
    first_ifd_offset: u64,
    first_ifd: Option<ImageFileDirectory>,
}

impl TiffStructure {
    pub fn load<R>(reader: &mut R) -> Result<Self>
    where
        R: Read + Seek + ?Sized,
    {
        let mut endianness = [0u8, 2];
        reader.read_exact(&mut endianness)?;

        let byte_order = match endianness {
            II => Endianness::Little,
            MM => Endianness::Big,
            endianness => {
                return Err(TiffError::InvalidFileSignature {
                    reason: format!(
                    "invalid header signature: expected endianness \"II\" or \"MM\", found \"{}\"",
                    String::from_utf8_lossy(&endianness)
                ),
                }
                .into())
            }
        };

        let mut byte_reader = ByteOrdered::runtime(reader, byte_order);

        let big_tiff = match byte_reader.read_u16()? {
            42 => false,
            43 => {
                // read Big TIFF structs
                // Read byte size of offsets, must be 8
                let first_ifd_offset = byte_reader.read_u16()?;
                if first_ifd_offset != 8 {
                    return Err(TiffError::InvalidFileSignature {
                        reason: format!(
                            "invalid header signature: expected first IFD offset for BigTiff to be \"8\", found \"{first_ifd_offset}\""
                        ),
                    }.into());
                }
                // must currently be 0
                let reserved = byte_reader.read_u16()?;
                if reserved != 0 {
                    return Err(TiffError::InvalidFileSignature {
                        reason: format!(
                            "invalid header signature: expected bytes after first IFD offset for BigTiff to be \"0\", found \"{reserved}\""),
                    }.into());
                }
                true
            }
            magic => {
                return Err(TiffError::InvalidFileSignature {
                    reason: format!(
                        "invalid header signature: expected magic \"2A\" (TIFF) \"2B\" (BigTIFF), found \"{magic:02X}\""),
                }.into());
            }
        };

        let first_ifd_offset = if big_tiff {
            byte_reader.read_u64()?
        } else {
            byte_reader.read_u32()?.into()
        };

        // move read pointer to IFD
        byte_reader.seek(SeekFrom::Start(first_ifd_offset))?;
        let first_ifd = TiffStructure::read_ifd(
            byte_reader.into_inner(),
            byte_order,
            big_tiff,
            IfdType::Page,
        )?;

        let ts = TiffStructure {
            byte_order,
            big_tiff,
            first_ifd_offset,
            first_ifd: Some(first_ifd),
        };

        Ok(ts)
    }

    // read IFD entries, all value_offset are in source endianness
    pub fn read_ifd_entries<R>(
        byte_reader: &mut ByteOrdered<&mut R, Endianness>,
        big_tiff: bool,
        entry_cnt: u64,
        entries: &mut BTreeMap<u16, IfdEntry>,
    ) -> Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        for _ in 0..entry_cnt {
            let tag = byte_reader.read_u16()?;
            let tag_type = byte_reader.read_u16()?;

            let (count, data_offset) = if big_tiff {
                let count = byte_reader.read_u64()?;
                let mut buf = [0; 8];
                byte_reader.read_exact(&mut buf)?;

                let data_offset = buf
                    .as_slice()
                    .read_u64::<NativeEndian>()
                    .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;
                (count, data_offset)
            } else {
                let count = byte_reader.read_u32()?;
                let mut buf = [0; 4];
                byte_reader.read_exact(&mut buf)?;

                let data_offset = buf
                    .as_slice()
                    .read_u32::<NativeEndian>()
                    .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;
                (count.into(), data_offset.into())
            };

            let ifd_entry = IfdEntry {
                entry_tag: tag,
                entry_type: tag_type,
                value_count: count,
                value_offset: data_offset,
            };

            /*
            println!(
                "{}, {}, {}. {:?}",
                ifd_entry.entry_tag,
                ifd_entry.entry_type,
                ifd_entry.value_count,
                ifd_entry.value_offset.to_ne_bytes()
            );
            */

            entries.insert(tag, ifd_entry);
        }

        Ok(())
    }

    // read IFD from reader
    pub fn read_ifd<R>(
        reader: &mut R,
        byte_order: Endianness,
        big_tiff: bool,
        ifd_type: IfdType,
    ) -> Result<ImageFileDirectory>
    where
        R: Read + Seek + ReadBytesExt + ?Sized,
    {
        let mut byte_reader = ByteOrdered::runtime(reader, byte_order);

        let ifd_offset = byte_reader.stream_position()?;
        //println!("IFD Offset: {:#x}", ifd_offset);

        let entry_cnt = if big_tiff {
            byte_reader.read_u64()?
        } else {
            byte_reader.read_u16()?.into()
        };

        let mut ifd = ImageFileDirectory {
            offset: ifd_offset,
            entry_cnt,
            ifd_type,
            entries: BTreeMap::new(),
            next_ifd_offset: None,
            next_idf_offset_location: 0,
        };

        TiffStructure::read_ifd_entries(&mut byte_reader, big_tiff, entry_cnt, &mut ifd.entries)?;

        // save for easy patching
        ifd.next_idf_offset_location = byte_reader.stream_position()?;

        let next_ifd = if big_tiff {
            byte_reader.read_u64()?
        } else {
            byte_reader.read_u32()?.into()
        };

        match next_ifd {
            0 => (),
            _ => ifd.next_ifd_offset = Some(next_ifd),
        };

        Ok(ifd)
    }
}

// offset are stored in source endianness so to use offset value in Seek calls we must convert to native endianness
fn decode_offset(offset_file_native: u64, endianness: Endianness, big_tiff: bool) -> Result<u64> {
    let offset: u64;
    let offset_bytes = offset_file_native.to_ne_bytes();
    let offset_reader = Cursor::new(offset_bytes);

    with_order!(offset_reader, endianness, |src| {
        if big_tiff {
            let o = src.read_u64()?;
            offset = o;
        } else {
            let o = src.read_u32()?;
            offset = o.into();
        }
    });

    Ok(offset)
}

/// Reject forged IFD `value_count` fields whose claimed byte size exceeds the
/// actual file size. Used before every `safe_vec`/`read_to_vec` allocation
/// driven by attacker-controlled count fields, so a 52-byte BigTIFF can't
/// trigger a multi-GB allocation.
fn check_ifd_data_size(claimed_size: u64, file_size: u64) -> Result<()> {
    if claimed_size > file_size {
        return Err(Error::InvalidAsset(
            "IFD entry data size exceeds file size".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct MappedTiff {
    tiff_tree: Arena<ImageFileDirectory>,
    page_tokens: Vec<Token>,
    sub_files_map: HashMap<Token, Vec<ImageFileDirectory>>,
    endianness: Endianness,
    big_tiff: bool,
}

// create tree of TIFF structure IFDs and IFD entries.
fn map_tiff<R>(mut input: &mut R) -> Result<MappedTiff>
where
    R: Read + Seek + ?Sized,
{
    let file_size = stream_len(input)?;
    input.rewind()?;

    let mut tokens = Vec::new();
    let mut sub_files_map: HashMap<Token, Vec<ImageFileDirectory>> = HashMap::new();

    let ts = TiffStructure::load(input)?;

    let tiff_tree: Arena<ImageFileDirectory> =
        if let Some(ifd) = ts.first_ifd.clone() {
            let first_offset = ifd.offset;
            let (mut tiff_tree, page_0) = Arena::with_data(ifd);
            let mut current_token = page_0;
            let mut visited_offsets: HashSet<u64> = HashSet::new();
            visited_offsets.insert(first_offset);

            // get the pages
            loop {
                tokens.push(current_token);
                if tokens.len() > MAX_PAGES {
                    return Err(Error::InvalidAsset(
                        "TIFF file has too many pages".to_string(),
                    ));
                }

                // look for known special IFDs
                let page_subifd = tiff_tree[current_token].data.get_tag(SUBFILE_TAG).copied();

                // grab SubIFDs for page (DNG)
                if let Some(subifd) = page_subifd {
                    let decoded_offset =
                        decode_offset(subifd.value_offset, ts.byte_order, ts.big_tiff)?;
                    input.seek(SeekFrom::Start(decoded_offset))?;

                    let num_longs_x4 =
                        usize::try_from(subifd.value_count.checked_mul(4).ok_or_else(|| {
                            Error::InvalidAsset("value out of range".to_string())
                        })?)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    check_ifd_data_size(num_longs_x4 as u64, file_size)?;

                    let mut subfile_offsets = safe_vec(subifd.value_count, Some(0u32))?; // will contain offsets in native endianness

                    if num_longs_x4 <= 4 || ts.big_tiff && num_longs_x4 <= 8 {
                        let offset_bytes = subifd.value_offset.to_ne_bytes();
                        let offset_reader = Cursor::new(offset_bytes);

                        with_order!(offset_reader, ts.byte_order, |src| {
                            for item in subfile_offsets.iter_mut().take(num_longs_x4 / 4) {
                                let s = src.read_u32()?; // read a long from offset
                                *item = s; // write a long in output endian
                            }
                        });
                    } else {
                        let buf = input.read_to_vec(num_longs_x4 as u64)?;
                        let offsets_buf = Cursor::new(buf);

                        with_order!(offsets_buf, ts.byte_order, |src| {
                            for item in subfile_offsets.iter_mut().take(num_longs_x4 / 4) {
                                let s = src.read_u32()?; // read a long from offset
                                *item = s; // write a long in output endian
                            }
                        });
                    }

                    // make sure this is resonable number of subfiles, avoid arbitrary large allocations and possible DoS attacks
                    if subfile_offsets.len() > MAX_SUBFILES {
                        return Err(Error::InvalidAsset(
                            "TIFF file has too many subfiles".to_string(),
                        ));
                    }

                    // get all subfiles
                    for subfile_offset in subfile_offsets {
                        let u64_offset = subfile_offset as u64;
                        input.seek(SeekFrom::Start(u64_offset))?;

                        //println!("Reading SubIFD: {}", u64_offset);

                        let subfile_ifd = TiffStructure::read_ifd(
                            input,
                            ts.byte_order,
                            ts.big_tiff,
                            IfdType::Subfile,
                        )?;

                        sub_files_map
                            .entry(current_token)
                            .and_modify(|v| v.push(subfile_ifd.clone()))
                            .or_insert(vec![subfile_ifd]);
                    }
                }

                // grab EXIF IFD for page (DNG)
                if let Some(exififd) = tiff_tree[current_token].data.get_tag(EXIFIFD_TAG) {
                    let decoded_offset =
                        decode_offset(exififd.value_offset, ts.byte_order, ts.big_tiff)?;
                    input.seek(SeekFrom::Start(decoded_offset))?;

                    //println!("EXIF Reading SubIFD: {}", decoded_offset);

                    let exif_ifd =
                        TiffStructure::read_ifd(input, ts.byte_order, ts.big_tiff, IfdType::Exif)?;

                    sub_files_map
                        .entry(current_token)
                        .and_modify(|v| v.push(exif_ifd.clone()))
                        .or_insert(vec![exif_ifd]);
                }

                // grab GPS IFD for page (DNG)
                if let Some(gpsifd) = tiff_tree[current_token].data.get_tag(GPSIFD_TAG) {
                    let decoded_offset =
                        decode_offset(gpsifd.value_offset, ts.byte_order, ts.big_tiff)?;
                    input.seek(SeekFrom::Start(decoded_offset))?;

                    //println!("GPS Reading SubIFD: {}", decoded_offset);

                    let gps_ifd =
                        TiffStructure::read_ifd(input, ts.byte_order, ts.big_tiff, IfdType::Gps)?;

                    sub_files_map
                        .entry(current_token)
                        .and_modify(|v| v.push(gps_ifd.clone()))
                        .or_insert(vec![gps_ifd]);
                }

                // move to next page
                if let Some(next_ifd_offset) = tiff_tree[current_token].data.next_ifd_offset {
                    if !visited_offsets.insert(next_ifd_offset) {
                        return Err(Error::InvalidAsset("Cyclic IFD chain detected".to_string()));
                    }
                    input.seek(SeekFrom::Start(next_ifd_offset))?;
                    let next_ifd =
                        TiffStructure::read_ifd(input, ts.byte_order, ts.big_tiff, IfdType::Page)?;
                    current_token = current_token.insert_after(&mut tiff_tree, next_ifd);
                } else {
                    break;
                }
            }

            tiff_tree
        } else {
            return Err(Error::InvalidAsset("TIFF structure invalid".to_string()));
        };

    Ok(MappedTiff {
        tiff_tree,
        page_tokens: tokens,
        sub_files_map,
        endianness: ts.byte_order,
        big_tiff: ts.big_tiff,
    })
}

// struct used to clone source IFD entries. value_bytes are in target endianness
#[derive(Eq, PartialEq, Clone)]
pub(crate) struct IfdClonedEntry {
    pub entry_tag: u16,
    pub entry_type: u16,
    pub value_count: u64,
    pub value_bytes: Vec<u8>,
}

// struct to clone a TIFF/DNG and new tags if desired
pub(crate) struct TiffCloner<T>
where
    T: Read + Write + Seek,
{
    endianness: Endianness,
    big_tiff: bool,
    first_idf_offset: u64,
    writer: ByteOrdered<T, Endianness>,
    additional_ifds: BTreeMap<u16, IfdClonedEntry>,
    c2pa_mode: bool,
}

/// Accumulates one strip/tile/BigTable byte count into `copied` and rejects the
/// tag once the running total exceeds the source stream length.
///
/// TIFF strip/tile/BigTable data lives inside the source file, so a legitimate
/// `sum(byte_counts)` is at most the file size. A crafted file can instead list
/// many entries whose offsets all point at the same bytes and whose counts sum
/// to far more than the file, making the clone re-copy the input over and over
/// and grow the in-memory output to gigabytes (memory amplification → OOM
/// abort; ~4.9 GB from a 293 KB input in the reported PoC). Capping the
/// cumulative copy length at the source length stops that while leaving
/// well-formed files untouched.
///
/// `kind` labels the error ("strip", "tile", "BigTable"). The error is returned
/// via `Result` so the caller propagates it with `?`. Note that `with_order!`
/// inlines its body into a `match` arm — it is not a real closure — so that `?`
/// (like a bare `return`) exits `clone_image_data` directly, not just a closure.
fn accumulate_copy_len(copied: &mut u64, cnt: u64, source_len: u64, kind: &str) -> Result<()> {
    *copied = copied
        .checked_add(cnt)
        .ok_or_else(|| Error::InvalidAsset(format!("TIFF {kind} byte counts overflow")))?;
    if *copied > source_len {
        return Err(Error::InvalidAsset(format!(
            "TIFF {kind} byte counts exceed source length"
        )));
    }
    Ok(())
}

impl<T: Read + Write + Seek> TiffCloner<T> {
    pub fn new(endianness: Endianness, big_tiff: bool, writer: T) -> Result<TiffCloner<T>> {
        let bo = ByteOrdered::runtime(writer, endianness);

        let mut tc = TiffCloner {
            endianness,
            big_tiff,
            first_idf_offset: 0,
            writer: bo,
            additional_ifds: BTreeMap::new(),
            c2pa_mode: false,
        };

        tc.write_header()?;

        Ok(tc)
    }

    // Start with a copy of the source file to writer, then we will adjust the IFDs and add new tags as needed.
    // Use this constructor if you are cloning with C2PA mode
    pub fn new_from_source<R: Read + Seek + ?Sized>(
        endianness: Endianness,
        big_tiff: bool,
        writer: T,
        source: &mut R,
    ) -> Result<TiffCloner<T>> {
        let bo = ByteOrdered::runtime(writer, endianness);

        let mut tc = TiffCloner {
            endianness,
            big_tiff,
            first_idf_offset: 0,
            writer: bo,
            additional_ifds: BTreeMap::new(),
            c2pa_mode: true,
        };

        // start with copy of source file to writer, then we will adjust the IFDs and add new tags as needed
        source.rewind()?;
        std::io::copy(source, tc.writer.inner_mut())?;
        source.rewind()?;

        Ok(tc)
    }

    fn offset(&mut self) -> Result<u64> {
        Ok(self.writer.stream_position()?)
    }

    fn pad_word_boundary(&mut self) -> Result<()> {
        let curr_offset = self.offset()?;
        if curr_offset % 4 != 0 {
            let padding = [0, 0, 0];
            let pad_len = 4 - (curr_offset % 4);
            self.writer.write_all(&padding[..pad_len as usize])?;
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
            self.writer.write_all(&[boi, boi])?;
            self.writer.write_u16(43u16)?;
            self.writer.write_u16(8u16)?;
            self.writer.write_u16(0u16)?;
            offset = self.writer.stream_position()?; // first ifd offset

            self.writer.write_u64(0)?;
        } else {
            self.writer.write_all(&[boi, boi])?;
            self.writer.write_u16(42u16)?;
            offset = self.writer.stream_position()?; // first ifd offset

            self.writer.write_u32(0)?;
        }

        self.first_idf_offset = offset;
        Ok(offset)
    }

    fn adjust_header_ifd_offset(&mut self, offset: u64) -> Result<()> {
        if self.big_tiff {
            self.writer.seek(SeekFrom::Start(8))?;
            self.writer.write_u64(offset)?;
        } else {
            self.writer.seek(SeekFrom::Start(4))?;
            let offset_u32 = u32::try_from(offset)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            self.writer.write_u32(offset_u32)?;
        }

        Ok(())
    }

    fn write_entry_count(&mut self, count: usize) -> Result<()> {
        if self.big_tiff {
            let cnt = u64::try_from(count)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            self.writer.write_u64(cnt)?;
        } else {
            let cnt = u16::try_from(count)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            self.writer.write_u16(cnt)?;
        }

        Ok(())
    }

    fn write_ifd(&mut self, target_ifd: &mut BTreeMap<u16, IfdClonedEntry>) -> Result<u64> {
        let is_c2pa_idf = target_ifd.len() == 1 && target_ifd.contains_key(&C2PA_TAG);

        // Write out the data and IFD at end of file
        self.writer.seek(SeekFrom::End(0))?;

        if !is_c2pa_idf {
            // write out all data and save the offsets, skipping subfiles since the data is already written
            for &mut IfdClonedEntry {
                value_bytes: ref mut value_bytes_ref,
                ..
            } in target_ifd.values_mut()
            {
                let data_bytes = if self.big_tiff { 8 } else { 4 };

                if value_bytes_ref.len() > data_bytes {
                    // get location of entry data start
                    let offset = self.writer.stream_position()?;

                    // write out the data bytes
                    self.writer.write_all(value_bytes_ref)?;

                    // set offset pointer in file source endian
                    let mut offset_vec = vec![0; data_bytes];

                    with_order!(offset_vec.as_mut_slice(), self.endianness, |ew| {
                        if self.big_tiff {
                            ew.write_u64(offset)?;
                        } else {
                            let offset_u32 = u32::try_from(offset).map_err(|_err| {
                                Error::InvalidAsset("value out of range".to_string())
                            })?; // get beginning of chunk which starts 4 bytes before label

                            ew.write_u32(offset_u32)?;
                        }
                    });

                    // set to new data offset position
                    *value_bytes_ref = offset_vec;
                } else {
                    while value_bytes_ref.len() < data_bytes {
                        value_bytes_ref.push(0);
                    }
                }
            }
        }

        // start on a WORD boundary
        self.pad_word_boundary()?;

        // save location of start of IFD
        let ifd_offset = self.writer.stream_position()?;

        // write out the entry count
        self.write_entry_count(target_ifd.len())?;

        // save the bytes
        let mut c2pa_bytes = None;
        // write out the directory entries
        for (tag, entry) in target_ifd.iter() {
            self.writer.write_u16(*tag)?;
            self.writer.write_u16(entry.entry_type)?;

            if self.big_tiff {
                self.writer.write_u64(entry.value_count)?;
            } else {
                let cnt = u32::try_from(entry.value_count)
                    .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                self.writer.write_u32(cnt)?;
            }

            if *tag == C2PA_TAG && is_c2pa_idf {
                let data_bytes = if self.big_tiff { 8u64 } else { 4u64 };

                // does the data fit within size of value_bytes
                if entry.value_bytes.len() > data_bytes as usize {
                    c2pa_bytes = Some(entry.value_bytes.to_owned());
                    let c2pa_bytes_pos = self.writer.stream_position()?
                        + data_bytes // size of pointer
                        + data_bytes; // size of IFD terminator

                    if self.big_tiff {
                        self.writer.write_u64(c2pa_bytes_pos)?;
                    } else {
                        let offset32 = u32::try_from(c2pa_bytes_pos)?;
                        self.writer.write_u32(offset32)?;
                    }
                } else {
                    self.writer.write_all(&entry.value_bytes)?;
                }
            } else {
                self.writer.write_all(&entry.value_bytes)?;
            }
        }

        // terminate IFD
        if self.big_tiff {
            self.writer.write_u64(0)?;
        } else {
            self.writer.write_u32(0)?;
        }

        // write manifest after IFD if needed
        if let Some(c2pa_bytes) = c2pa_bytes {
            self.writer.write_all(&c2pa_bytes)?;
        }

        Ok(ifd_offset)
    }

    // add new TAG by supplying the IDF entry
    pub fn add_target_tag(&mut self, entry: IfdClonedEntry) {
        self.additional_ifds.insert(entry.entry_tag, entry);
    }

    // Writes a clone of the incoming IFD, only writing new data if it has changed to the end of the file, otherwise the
    // entries point to existing data.  If the entry contains C2PA data, it is written at the end of the file.
    // Returns location of start of IFD.
    fn write_adjusted_ifd(
        &mut self,
        target_ifd: &mut BTreeMap<u16, IfdClonedEntry>,
        adjust_tags: &[u16],
        next_ifd: u64,
        c2pa_buf: Option<Vec<u8>>,
    ) -> Result<u64> {
        let data_bytes = if self.big_tiff { 8 } else { 4 };

        // write new IFD data at the end
        self.writer.seek(SeekFrom::End(0))?;

        // Write out the IFD

        // start on a WORD boundary
        self.pad_word_boundary()?;

        // save location of start of IFD
        let ifd_offset = self.writer.stream_position()?;

        // write out the entry count
        self.write_entry_count(target_ifd.len())?;

        // write out the placeholder entries, all value_bytes are data_bytes in size
        let entry_array_offset = self.writer.stream_position()?;
        for (tag, entry) in target_ifd.iter() {
            self.writer.write_u16(*tag)?;
            self.writer.write_u16(entry.entry_type)?;

            if self.big_tiff {
                self.writer.write_u64(entry.value_count)?;
            } else {
                let cnt = u32::try_from(entry.value_count)
                    .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                self.writer.write_u32(cnt)?;
            }
            // just write out 0s for this placeholder pass
            let buf = vec![0u8; data_bytes];
            self.writer.write_all(&buf)?;
        }

        // terminate IFD
        if self.big_tiff {
            self.writer.write_u64(next_ifd)?;
        } else {
            let next_ifd32 = u32::try_from(next_ifd)?;
            self.writer.write_u32(next_ifd32)?;
        }

        // Update all changed data and save the offsets, existing tag pointers will be used for unchanged data.
        // C2PA data is written last per the spec.
        let mut adjust_c2pa_data = false;
        for &mut IfdClonedEntry {
            entry_tag,
            value_bytes: ref mut value_bytes_ref,
            ..
        } in target_ifd.values_mut()
        {
            if value_bytes_ref.len() > data_bytes {
                if entry_tag == C2PA_TAG {
                    // C2PA data must be written after all other data and is done after IFD write
                    continue;
                }

                // if this value should be adjusted write out the data bytes
                if adjust_tags.contains(&entry_tag) {
                    adjust_c2pa_data = true;

                    // get location of entry data start
                    let offset = self.writer.stream_position()?;

                    self.writer.write_all(value_bytes_ref)?;

                    // set offset pointer in file source endian
                    let mut offset_vec = vec![0; data_bytes];

                    with_order!(offset_vec.as_mut_slice(), self.endianness, |ew| {
                        if self.big_tiff {
                            ew.write_u64(offset)?;
                        } else {
                            let offset_u32 = u32::try_from(offset).map_err(|_err| {
                                Error::InvalidAsset("value out of range".to_string())
                            })?; // get beginning of chunk which starts 4 bytes before label

                            ew.write_u32(offset_u32)?;
                        }
                    });

                    // set value_buf new data offset position pointer
                    *value_bytes_ref = offset_vec;
                }
            }
        }

        // Write out the C2PA data if it is in the entry list, we will rewrite the C2PA manifest to
        // make sure it is last. If we have adjusted tags we need to move the C2PA manifest to the end
        let c2pa_data_changed = adjust_tags.contains(&C2PA_TAG);
        if adjust_c2pa_data || c2pa_data_changed {
            if let Some(c2pa_entry) = target_ifd.get_mut(&C2PA_TAG) {
                if c2pa_entry.value_bytes.len() > data_bytes {
                    // write data to output and make value_bytes its pointer
                    // get location of entry data start
                    let offset = self.writer.stream_position()?;
                    if c2pa_data_changed {
                        self.writer.write_all(&c2pa_entry.value_bytes)?;
                    } else {
                        // migrate existing manifest
                        if let Some(data) = c2pa_buf {
                            self.writer.write_all(&data)?;
                        } else {
                            return Err(Error::InternalError(
                                "could not relocate manifest".to_string(),
                            ));
                        }
                    }

                    // update the entry value_bytes to point to the new offset
                    let mut offset_vec = vec![0; data_bytes];
                    with_order!(offset_vec.as_mut_slice(), self.endianness, |ew| {
                        if self.big_tiff {
                            ew.write_u64(offset)?;
                        } else {
                            let offset_u32 = u32::try_from(offset).map_err(|_err| {
                                Error::InvalidAsset("value out of range".to_string())
                            })?;
                            ew.write_u32(offset_u32)?;
                        }
                    });
                    c2pa_entry.value_bytes = offset_vec;
                } else {
                    // since it fits set value_buf as the actual data
                    while c2pa_entry.value_bytes.len() < data_bytes {
                        c2pa_entry.value_bytes.push(0);
                    }
                }
            }
        }

        // seek to the start of the entries and write out again with the true offsets
        self.writer.seek(SeekFrom::Start(entry_array_offset))?;
        for (tag, entry) in target_ifd.iter() {
            self.writer.write_u16(*tag)?;
            self.writer.write_u16(entry.entry_type)?;

            if self.big_tiff {
                self.writer.write_u64(entry.value_count)?;
            } else {
                let cnt = u32::try_from(entry.value_count)
                    .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                self.writer.write_u32(cnt)?;
            }

            self.writer.write_all(&entry.value_bytes[0..data_bytes])?;
        }

        Ok(ifd_offset)
    }

    // Leave original content intact and replace first IDF with a new cloned IFD appended to the asset.
    // Any tag changes in the new IFD will be written to new data locations.  Existing data is preserved.
    // Since 2.4 now allows the C2PA tag to be in the first IFD for single page TIFF, and in its own last IFD for
    // the case of multi-page TIFF.
    pub fn clone_c2pa_mode<R: Read + Seek + ?Sized>(
        &mut self,
        mut asset_reader: &mut R,
        tiff_tree: &mut Arena<ImageFileDirectory>,
        page_tokens: &[Token],
        new_tiff_tags: Vec<IfdClonedEntry>,
        remove_tiff_tags: &[u16],
    ) -> Result<()> {
        if !self.c2pa_mode {
            return Err(Error::InternalError(
                "clone_c2pa_mode called without using new_from_source constructor".to_string(),
            ));
        }

        let first_page = page_tokens
            .first()
            .ok_or(Error::InvalidAsset("no IFD found".to_string()))?;

        let mut last_page = page_tokens
            .last()
            .ok_or(Error::InvalidAsset("no IFD found".to_string()))?;

        let mut last_page_ifd = tiff_tree
            .get(*last_page)
            .ok_or_else(|| Error::InvalidAsset("TIFF does not have IFD".to_string()))?;

        let first_page_ifd = tiff_tree
            .get(*first_page)
            .ok_or_else(|| Error::InvalidAsset("TIFF does not have IFD".to_string()))?;

        // separate out the C2PA entry since it may go into its own IFD
        let c2pa_entry = new_tiff_tags
            .iter()
            .find(|t| t.entry_tag == C2PA_TAG)
            .cloned();

        // if this is a single page TIFF then we can insert the C2PA tag into the first IFD, otherwise it must be in its own IFD
        let insert_to_first_page = *first_page == *last_page;

        // can we patch the existing C2PA tag in place
        // this case is required since we don't want to add a new IFD entry if we are replacing a placeholder C2PA manifest
        let try_patch = new_tiff_tags.len() == 1
            && c2pa_entry.is_some()
            && remove_tiff_tags.is_empty()
            && last_page_ifd.data.entries.contains_key(&C2PA_TAG);

        if try_patch {
            let cai_ifd_entry = last_page_ifd
                .data
                .entries
                .get(&C2PA_TAG)
                .ok_or(Error::JumbfNotFound)?;

            // make sure data type is for unstructured data
            if cai_ifd_entry.entry_type != C2PA_FIELD_TYPE {
                return Err(Error::InvalidAsset(
                    "Ifd entry for C2PA must be type UNKNOWN(7)".to_string(),
                ));
            }

            let manifest_len: usize = usize::try_from(cai_ifd_entry.value_count)
                .map_err(|_err| Error::InvalidAsset("TIFF/DNG out of range".to_string()))?;

            let store_bytes = c2pa_entry
                .as_ref()
                .ok_or(Error::JumbfNotFound)?
                .value_bytes
                .as_slice();

            // only patch if they are the same size
            if store_bytes.len() == manifest_len {
                // move read point to start of entry
                let decoded_offset =
                    decode_offset(cai_ifd_entry.value_offset, self.endianness, self.big_tiff)?;
                self.writer.seek(SeekFrom::Start(decoded_offset))?;

                self.writer.write_all(store_bytes)?;
                return Ok(());
            }
        }

        // find out if we need to replace first IFD if the first IFD contains the C2PA tag or if we have to add new tag or remove a tag that is in the first IFD.
        let needs_new_first_page_ifd = first_page_ifd.data.entries.contains_key(&C2PA_TAG)
            && !insert_to_first_page
            || (new_tiff_tags
                .iter()
                .find(|t| t.entry_tag == C2PA_TAG)
                .is_some()
                && insert_to_first_page)
            || new_tiff_tags.iter().any(|t| t.entry_tag != C2PA_TAG)
            || remove_tiff_tags
                .iter()
                .any(|t| first_page_ifd.data.entries.contains_key(t));

        let mut first_ifd_updated = false;
        if needs_new_first_page_ifd {
            let mut new_first_ifd_entries: BTreeMap<u16, IfdClonedEntry> = BTreeMap::new();

            // duplicate the first IFD entries but skip any tags in the remove list and add any new tags
            for (tag, entry) in &first_page_ifd.data.entries {
                if !remove_tiff_tags.contains(tag) {
                    new_first_ifd_entries.insert(
                        *tag,
                        IfdClonedEntry {
                            entry_tag: *tag,
                            entry_type: entry.entry_type,
                            value_count: entry.value_count,
                            value_bytes: entry.value_offset.to_ne_bytes().to_vec(), // note: this is in source byte order
                        },
                    );
                }
            }
            let had_removals = first_page_ifd.data.entries.len() > new_first_ifd_entries.len();

            // add in the new tags to the new first IFD
            let mut changed_ifd_tags: Vec<u16> = Vec::new();
            for new_tag in &new_tiff_tags {
                // C2PA will be added to its own tag for multi-page TIFF
                if new_tag.entry_tag == C2PA_TAG && !insert_to_first_page {
                    new_first_ifd_entries.remove(&C2PA_TAG);
                    continue;
                }
                changed_ifd_tags.push(new_tag.entry_tag);
                new_first_ifd_entries.insert(new_tag.entry_tag, new_tag.clone());
            }

            if !changed_ifd_tags.is_empty() || had_removals {
                // pass in existing manifest in case this is a manifest move only case
                // (i.e. no new manifest data but we need to move the manifest to the end of the file)
                let existing_c2pa_data = match last_page_ifd.data.get_tag(C2PA_TAG) {
                    Some(e) => {
                        // make sure data type is for unstructured data
                        if e.entry_type != C2PA_FIELD_TYPE {
                            return Err(Error::InvalidAsset(
                                "Ifd entry for C2PA must be type UNDEFINED(7)".to_string(),
                            ));
                        }

                        // move read point to start of entry
                        let decoded_offset =
                            decode_offset(e.value_offset, self.endianness, self.big_tiff)?;
                        asset_reader.seek(SeekFrom::Start(decoded_offset))?;

                        let data = asset_reader.read_to_vec(e.value_count).map_err(|_err| {
                            Error::InvalidAsset("TIFF/DNG out of range".to_string())
                        })?;
                        Some(data)
                    }
                    None => None,
                };

                // write out the new first IDF needed
                let second_ifd_offset = first_page_ifd.data.next_ifd_offset.unwrap_or(0);

                let new_ifd_offset = self.write_adjusted_ifd(
                    &mut new_first_ifd_entries,
                    &changed_ifd_tags,
                    second_ifd_offset,
                    existing_c2pa_data,
                )?;

                // patch the header first IFD pointer to point to second IFD if present
                self.adjust_header_ifd_offset(new_ifd_offset)?;

                first_ifd_updated = true;
            }
        }

        // if we updated the first IFD then we need to reread the current state so that
        // IFDs are accurate
        self.writer.rewind()?;
        let mapped = map_tiff(self.writer.inner_mut())?;
        let page_tokens = &mapped.page_tokens;
        if first_ifd_updated {
            last_page = page_tokens
                .last()
                .ok_or(Error::InvalidAsset("no IFD found".to_string()))?;

            last_page_ifd = mapped
                .tiff_tree
                .get(*last_page)
                .ok_or_else(|| Error::InvalidAsset("TIFF does not have IFD".to_string()))?;
        }

        // write out the new C2PA IFD if we have one and it was not added to the first IFD
        if let Some(c2pa_entry) = c2pa_entry {
            // C2PA manifest is in its own IFD
            if last_page_ifd.data.entries.contains_key(&C2PA_TAG) && !insert_to_first_page {
                let last_ifd_offset = last_page_ifd.data.offset;

                // we can just update the existing last page C2PA entry
                let existing_c2pa_entry = last_page_ifd
                    .data
                    .entries
                    .get(&C2PA_TAG)
                    .ok_or(Error::NotFound)?;
                let len_size = if self.big_tiff { 8 } else { 4 };

                let c2pa_offset = decode_offset(
                    existing_c2pa_entry.value_offset,
                    self.endianness,
                    self.big_tiff,
                )?;

                // if c2pa_offset is the last content in the file we can just overwrite the new C2PA data there
                let asset_len = stream_len(&mut self.writer)?;

                // if the manifest is at the end of the file and the new manifest is larger than the existing manifest
                // we can overwrite it and update the offset in the IFD entry
                if c2pa_offset + existing_c2pa_entry.value_count == asset_len
                    && c2pa_entry.value_count >= existing_c2pa_entry.value_count
                {
                    self.writer.seek(SeekFrom::Start(c2pa_offset))?;

                    // write the new C2PA data bytes in place
                    self.writer.write_all(&c2pa_entry.value_bytes)?;

                    // jump to location to write the updated offset
                    let entry_offset = last_ifd_offset
                        + if self.big_tiff { 8u64 } else { 2u64 } // entry count
                        + (if self.big_tiff { 16u64 } else { 12u64 } * last_page_ifd.data.entries.keys().position(|t| t == &C2PA_TAG).ok_or(Error::NotFound)? as u64); // offset of C2PA entry

                    // adjust the c2pa IFD entry count to the size of the new C2PA data
                    let new_c2pa_count = c2pa_entry.value_count;
                    self.writer.seek(SeekFrom::Start(entry_offset + 4))?;

                    if self.big_tiff {
                        self.writer.write_u64(new_c2pa_count)?;
                    } else {
                        let cnt = u32::try_from(new_c2pa_count).map_err(|_err| {
                            Error::InvalidAsset("value out of range".to_string())
                        })?;

                        self.writer.write_u32(cnt)?;
                    }
                } else {
                    // we have to write the new C2PA data at the end of the file and update the offset in the IFD entry
                    self.writer.seek(SeekFrom::End(0))?;
                    let new_c2pa_offset = self.offset()?;

                    // write the new C2PA data bytes at the end of the file
                    self.writer.write_all(&c2pa_entry.value_bytes)?;

                    // patch the IFD entry to point to the new C2PA data location
                    let mut new_offset_buf = vec![0; len_size];

                    with_order!(new_offset_buf.as_mut_slice(), self.endianness, |ew| {
                        if self.big_tiff {
                            ew.write_u64(new_c2pa_offset)?;
                        } else {
                            let offset_u32 = u32::try_from(new_c2pa_offset)?;
                            ew.write_u32(offset_u32)?;
                        }
                    });

                    // jump to location to write the updated offset
                    let entry_offset = last_ifd_offset
                        + if self.big_tiff { 8u64 } else { 2u64 } // entry count
                        + (if self.big_tiff { 16u64 } else { 12u64 } * last_page_ifd.data.entries.keys().position(|t| t == &C2PA_TAG).ok_or(Error::NotFound)? as u64); // offset of C2PA entry

                    self.writer.seek(SeekFrom::Start(
                        entry_offset + if self.big_tiff { 12u64 } else { 8u64 },
                    ))?;

                    // write the updated offset
                    self.writer.write_all(&new_offset_buf)?;

                    // adjust the c2pa IFD entry count to the size of the new C2PA data
                    let new_c2pa_count = c2pa_entry.value_count;
                    self.writer.seek(SeekFrom::Start(entry_offset + 4))?;

                    if self.big_tiff {
                        self.writer.write_u64(new_c2pa_count)?;
                    } else {
                        let cnt = u32::try_from(new_c2pa_count).map_err(|_err| {
                            Error::InvalidAsset("value out of range".to_string())
                        })?;

                        self.writer.write_u32(cnt)?;
                    }
                }
            } else {
                // write out the new C2PA IFD
                if !insert_to_first_page {
                    let last_ifd_offset = last_page_ifd.data.offset;

                    let mut c2pa_ifd_entries: BTreeMap<u16, IfdClonedEntry> = BTreeMap::new();
                    c2pa_ifd_entries.insert(c2pa_entry.entry_tag, c2pa_entry);

                    let new_c2pa_ifd_offset = self.write_ifd(&mut c2pa_ifd_entries)?;

                    // point last page IFD to the new C2PA IFD
                    self.writer.seek(SeekFrom::Start(last_ifd_offset))?;
                    let prior_ifd = TiffStructure::read_ifd(
                        &mut self.writer.inner_mut(),
                        self.endianness,
                        self.big_tiff,
                        IfdType::Page,
                    )?;

                    self.set_next_ifd_offset(&prior_ifd, new_c2pa_ifd_offset)?;
                }
            }
        } else {
            // is this a manifest removal?
            // remove the last IDF just by set a new last IFD if there is a C2PA tag in the remove list and we are not inserting to the first page
            if remove_tiff_tags.contains(&C2PA_TAG) && !insert_to_first_page {
                let second_to_last = &page_tokens[page_tokens.len() - 2];

                let second_to_last_ifd = tiff_tree
                    .get(*second_to_last)
                    .ok_or_else(|| Error::InvalidAsset("TIFF does not have IFD".to_string()))?;

                // make last page IFD to the prior IFD
                self.set_next_ifd_offset(&second_to_last_ifd.data, 0)?;

                return Ok(());
            }

            // wrote a new first IFD so we need to move C2PA data to end if there is a C2PA entry
            if first_ifd_updated && !insert_to_first_page {
                let last_ifd_offset = last_page_ifd.data.offset;

                // we can just update the existing last page C2PA entry
                if let Some(existing_c2pa_entry) = last_page_ifd.data.entries.get(&C2PA_TAG) {
                    let len_size = if self.big_tiff { 8 } else { 4 };

                    let c2pa_offset = decode_offset(
                        existing_c2pa_entry.value_offset,
                        self.endianness,
                        self.big_tiff,
                    )?;

                    // read old data
                    let mut c2pa_buf: Vec<u8> = safe_vec(existing_c2pa_entry.value_count, None)?;
                    self.writer.seek(SeekFrom::Start(c2pa_offset))?;
                    std::io::copy(&mut self.writer, &mut c2pa_buf)?;

                    // write manifest at the end of asset
                    let new_c2pa_offset = self.writer.seek(SeekFrom::End(0))?;
                    self.writer.write_all(&c2pa_buf)?;

                    let mut new_offset_buf = vec![0; len_size];
                    with_order!(new_offset_buf.as_mut_slice(), self.endianness, |ew| {
                        if self.big_tiff {
                            ew.write_u64(new_c2pa_offset)?;
                        } else {
                            let offset_u32 = u32::try_from(new_c2pa_offset)?;
                            ew.write_u32(offset_u32)?;
                        }
                    });

                    // fix up the location
                    // jump to location to write the updated offset
                    let entry_offset = last_ifd_offset
                        + if self.big_tiff { 8u64 } else { 2u64 } // entry count
                        + (if self.big_tiff { 16u64 } else { 12u64 } * last_page_ifd.data.entries.keys().position(|t| t == &C2PA_TAG).ok_or(Error::NotFound)? as u64); // offset of C2PA entry

                    self.writer.seek(SeekFrom::Start(
                        entry_offset + if self.big_tiff { 12u64 } else { 8u64 },
                    ))?;

                    // write the updated offset
                    self.writer.write_all(&new_offset_buf)?;
                }
            }
        }

        Ok(())
    }

    pub fn set_next_ifd_offset(&mut self, entry: &ImageFileDirectory, offset: u64) -> Result<()> {
        self.writer
            .seek(SeekFrom::Start(entry.next_idf_offset_location))?;

        // write 0s for next offset
        if self.big_tiff {
            self.writer.write_u64(offset)?;
        } else {
            let offset32 = u32::try_from(offset)?;
            self.writer.write_u32(offset32)?;
        }
        Ok(())
    }

    fn clone_image_data<R: Read + Seek + ?Sized>(
        &mut self,
        target_ifd: &mut BTreeMap<u16, IfdClonedEntry>,
        asset_reader: &mut R,
    ) -> Result<()> {
        match (
            target_ifd.contains_key(&STRIPBYTECOUNTS),
            target_ifd.contains_key(&STRIPOFFSETS),
            target_ifd.contains_key(&TILEBYTECOUNTS),
            target_ifd.contains_key(&TILEOFFSETS),
        ) {
            (true, true, false, false) => {
                // stripped image data
                let sbc_entry = target_ifd[&STRIPBYTECOUNTS].clone();
                let so_entry = target_ifd.get_mut(&STRIPOFFSETS).ok_or(Error::NotFound)?;

                // check for well formed TIFF
                if so_entry.value_count != sbc_entry.value_count {
                    return Err(Error::InvalidAsset(
                        "TIFF strip count does not match strip offset count".to_string(),
                    ));
                }

                let mut sbcs: Vec<u64> = safe_vec(sbc_entry.value_count, Some(0))?;
                let mut dest_offsets: Vec<u64> = Vec::new();

                // get the byte counts
                with_order!(sbc_entry.value_bytes.as_slice(), self.endianness, |src| {
                    for c in &mut sbcs {
                        match sbc_entry.entry_type {
                            4u16 => {
                                let s = src.read_u32()?;
                                *c = s.into();
                            }
                            3u16 => {
                                let s = src.read_u16()?;
                                *c = s.into();
                            }
                            16u16 => {
                                let s = src.read_u64()?;
                                *c = s;
                            }
                            _ => return Err(Error::InvalidAsset("invalid TIFF strip".to_string())),
                        }
                    }
                });

                // Seek to our tracked write position (not End(0) which could be wrong if stream has leftover data)
                let current_offset = self.offset()?;
                self.writer.seek(SeekFrom::Start(current_offset))?;

                // Cap cumulative copy bytes at the source stream length. Legit
                // TIFF strip data lives inside the file, so sum(byte_counts)
                // is at most the file size. A crafted file where 50 000 strip
                // offsets all point to byte 0 could otherwise cause each strip
                // to re-copy the whole file (~5 GiB output from a 293 KiB
                // input, OOM abort).
                let source_len = stream_len(asset_reader)?;
                let mut copied: u64 = 0;

                // copy the strips
                with_order!(so_entry.value_bytes.as_slice(), self.endianness, |src| {
                    for cnt in sbcs.iter() {
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
                            16u16 => src.read_u64()?,
                            _ => return Err(Error::InvalidAsset("invalid TIFF strip".to_string())),
                        };

                        accumulate_copy_len(&mut copied, *cnt, source_len, "strip")?;

                        let dest_offset = self.writer.stream_position()?;
                        dest_offsets.push(dest_offset);

                        // copy the strip to new file
                        asset_reader.seek(SeekFrom::Start(so))?;
                        let mut data_reader = asset_reader.take(*cnt);
                        std::io::copy(&mut data_reader, &mut self.writer)?; // copy the BigTable block to new file
                    }
                });

                // patch the offsets
                with_order!(
                    so_entry.value_bytes.as_mut_slice(),
                    self.endianness,
                    |dest| {
                        for o in dest_offsets.iter() {
                            // get the offset
                            match so_entry.entry_type {
                                4u16 => {
                                    let offset = u32::try_from(*o).map_err(|_err| {
                                        Error::InvalidAsset("value out of range".to_string())
                                    })?;
                                    dest.write_u32(offset)?;
                                }
                                3u16 => {
                                    let offset = u16::try_from(*o).map_err(|_err| {
                                        Error::InvalidAsset("value out of range".to_string())
                                    })?;
                                    dest.write_u16(offset)?;
                                }
                                16u16 => {
                                    let offset = *o;
                                    dest.write_u64(offset)?;
                                }
                                _ => {
                                    return Err(Error::InvalidAsset(
                                        "invalid TIFF strip".to_string(),
                                    ))
                                }
                            }
                        }
                    }
                );
            }
            (false, false, true, true) => {
                // tiled image data
                let tbc_entry = target_ifd[&TILEBYTECOUNTS].clone();
                let to_entry = target_ifd.get_mut(&TILEOFFSETS).ok_or(Error::NotFound)?;

                // check for well formed TIFF
                if to_entry.value_count != tbc_entry.value_count {
                    return Err(Error::InvalidAsset(
                        "TIFF tile count does not match tile offset count".to_string(),
                    ));
                }

                let mut tbcs: Vec<u64> = safe_vec(tbc_entry.value_count, Some(0u64))?;
                let mut dest_offsets: Vec<u64> = Vec::new();

                // get the byte counts
                with_order!(tbc_entry.value_bytes.as_slice(), self.endianness, |src| {
                    for val in &mut tbcs {
                        match tbc_entry.entry_type {
                            4u16 => {
                                let s = src.read_u32()?;
                                *val = s.into();
                            }
                            3u16 => {
                                let s = src.read_u16()?;
                                *val = s.into();
                            }
                            16u16 => {
                                let s = src.read_u64()?;
                                *val = s;
                            }
                            _ => return Err(Error::InvalidAsset("invalid TIFF tile".to_string())),
                        }
                    }
                });

                // Seek to our tracked write position (not End(0) which could be wrong if stream has leftover data)
                let current_offset = self.offset()?;
                self.writer.seek(SeekFrom::Start(current_offset))?;

                // Cap cumulative copy bytes at the source stream length (see
                // the strip path above for rationale).
                let source_len = stream_len(asset_reader)?;
                let mut copied: u64 = 0;

                // copy the tiles
                with_order!(to_entry.value_bytes.as_slice(), self.endianness, |src| {
                    for cnt in tbcs.iter() {
                        // get the offset
                        let to: u64 = match to_entry.entry_type {
                            4u16 => {
                                let s = src.read_u32()?;
                                s.into()
                            }
                            16u16 => src.read_u64()?,
                            _ => return Err(Error::InvalidAsset("invalid TIFF tile".to_string())),
                        };

                        accumulate_copy_len(&mut copied, *cnt, source_len, "tile")?;

                        let dest_offset = self.writer.stream_position()?;
                        dest_offsets.push(dest_offset);

                        // copy the tile to new file
                        asset_reader.seek(SeekFrom::Start(to))?;
                        let mut data_reader = asset_reader.take(*cnt);
                        std::io::copy(&mut data_reader, &mut self.writer)?; // copy the BigTable block to new file
                    }
                });

                // patch the offsets
                with_order!(
                    to_entry.value_bytes.as_mut_slice(),
                    self.endianness,
                    |dest| {
                        for v in dest_offsets.iter() {
                            // get the offset
                            match to_entry.entry_type {
                                4u16 => {
                                    let offset = u32::try_from(*v).map_err(|_err| {
                                        Error::InvalidAsset("value out of range".to_string())
                                    })?;
                                    dest.write_u32(offset)?;
                                }
                                3u16 => {
                                    let offset = u16::try_from(*v).map_err(|_err| {
                                        Error::InvalidAsset("value out of range".to_string())
                                    })?;
                                    dest.write_u16(offset)?;
                                }
                                16u16 => {
                                    let offset = *v;
                                    dest.write_u64(offset)?;
                                }
                                _ => {
                                    return Err(Error::InvalidAsset(
                                        "invalid TIFF tile".to_string(),
                                    ))
                                }
                            }
                        }
                    }
                );
            }
            (_, _, _, _) => (),
        };

        Ok(())
    }

    // Special DNG case - clone BigTable data if present. BigTable data is stored similarly
    // to strip/tile data but with three separate tags for offsets, byte counts, and digests.
    // We need to clone the data and patch the offsets to preserve the integrity of the DNG.
    // Note: this is not a general DNG feature. Converts the target_ifd to the final
    // IFD with the copied data and actual offsets.
    fn clone_dng_bigtable_data<R: Read + Seek + ?Sized>(
        &mut self,
        target_ifd: &mut BTreeMap<u16, IfdClonedEntry>,
        asset_reader: &mut R,
    ) -> Result<()> {
        // BigTable image data — only when all three BigTable tags are present.
        if target_ifd.contains_key(&BIGTABLEOFFSETS)
            && target_ifd.contains_key(&BIGTABLEDIGESTS)
            && target_ifd.contains_key(&BIGTABLEBYTECOUNTS)
        {
            let bbc_entry = target_ifd[&BIGTABLEBYTECOUNTS].clone();
            let bo_entry = target_ifd
                .get_mut(&BIGTABLEOFFSETS)
                .ok_or(Error::NotFound)?;

            if bo_entry.value_count != bbc_entry.value_count {
                return Err(Error::InvalidAsset(
                    "TIFF BigTable count does not match BigTable offset count".to_string(),
                ));
            }

            let mut bbcs: Vec<u64> = safe_vec(bbc_entry.value_count, Some(0u64))?;
            let mut dest_offsets: Vec<u64> = Vec::new();

            // get the byte counts
            with_order!(bbc_entry.value_bytes.as_slice(), self.endianness, |src| {
                for val in &mut bbcs {
                    match bbc_entry.entry_type {
                        4u16 => {
                            let s = src.read_u32()?;
                            *val = s.into();
                        }
                        3u16 => {
                            let s = src.read_u16()?;
                            *val = s.into();
                        }
                        16u16 => {
                            let s = src.read_u64()?;
                            *val = s;
                        }
                        _ => return Err(Error::InvalidAsset("invalid TIFF BigTable".to_string())),
                    }
                }
            });

            // Seek to our tracked write position (not End(0) which could be wrong if stream has leftover data)
            let current_offset = self.offset()?;
            self.writer.seek(SeekFrom::Start(current_offset))?;

            // Cap cumulative copy bytes at the source stream length (see
            // clone_image_data strip path for rationale).
            let source_len = stream_len(asset_reader)?;
            let mut copied: u64 = 0;

            // copy the BigTable blocks
            with_order!(bo_entry.value_bytes.as_slice(), self.endianness, |src| {
                for cnt in bbcs.iter() {
                    let bo: u64 = match bo_entry.entry_type {
                        4u16 => {
                            let s = src.read_u32()?;
                            s.into()
                        }
                        3u16 => {
                            let s = src.read_u16()?;
                            s.into()
                        }
                        16u16 => src.read_u64()?,
                        _ => return Err(Error::InvalidAsset("invalid TIFF BigTable".to_string())),
                    };

                    accumulate_copy_len(&mut copied, *cnt, source_len, "BigTable")?;

                    let dest_offset = self.writer.stream_position()?;
                    dest_offsets.push(dest_offset); // save offset where the new BigTable block is written for patching later

                    asset_reader.seek(SeekFrom::Start(bo))?;
                    let mut data_reader = asset_reader.take(*cnt);
                    std::io::copy(&mut data_reader, &mut self.writer)?; // copy the BigTable block to new file
                }
            });

            // patch with final offsets where the BigTable blocks were written in the new file
            with_order!(
                bo_entry.value_bytes.as_mut_slice(),
                self.endianness,
                |dest| {
                    for o in dest_offsets.iter() {
                        match bo_entry.entry_type {
                            4u16 => {
                                let offset = u32::try_from(*o).map_err(|_err| {
                                    Error::InvalidAsset("value out of range".to_string())
                                })?;
                                dest.write_u32(offset)?;
                            }
                            3u16 => {
                                let offset = u16::try_from(*o).map_err(|_err| {
                                    Error::InvalidAsset("value out of range".to_string())
                                })?;
                                dest.write_u16(offset)?;
                            }
                            16u16 => {
                                dest.write_u64(*o)?;
                            }
                            _ => {
                                return Err(Error::InvalidAsset(
                                    "invalid TIFF BigTable".to_string(),
                                ))
                            }
                        }
                    }
                }
            );
        }
        Ok(())
    }

    fn clone_sub_files<R: Read + Seek + ?Sized>(
        &mut self,
        tiff_tree: &Arena<ImageFileDirectory>,
        page_sub_files: &Vec<ImageFileDirectory>,
        asset_reader: &mut R,
    ) -> Result<BTreeMap<u16, Vec<u64>>> {
        // offset map
        let mut offset_map: BTreeMap<u16, Vec<u64>> = BTreeMap::new();

        let mut offsets_ifd: Vec<u64> = Vec::new();
        let mut offsets_exif: Vec<u64> = Vec::new();
        let mut offsets_gps: Vec<u64> = Vec::new();

        // clone the EXIF entry and DNG entries
        for ifd in page_sub_files {
            // clone IFD entries
            let mut cloned_ifd = self.clone_ifd_entries(&ifd.entries, asset_reader)?;

            // clone the image data
            self.clone_image_data(&mut cloned_ifd, asset_reader)?;

            // clone bigtable data if DNG
            self.clone_dng_bigtable_data(&mut cloned_ifd, asset_reader)?;

            // write directory
            let sub_ifd_offset = self.write_ifd(&mut cloned_ifd)?;

            // fix up offset in main page known IFDs
            match ifd.ifd_type {
                IfdType::Page => (),
                IfdType::Subfile => offsets_ifd.push(sub_ifd_offset),
                IfdType::Exif => offsets_exif.push(sub_ifd_offset),
                IfdType::Gps => offsets_gps.push(sub_ifd_offset),
            };
        }

        offset_map.insert(SUBFILE_TAG, offsets_ifd);
        offset_map.insert(EXIFIFD_TAG, offsets_exif);
        offset_map.insert(GPSIFD_TAG, offsets_gps);

        Ok(offset_map)
    }

    pub fn clone_tiff<R: Read + Seek + ?Sized>(
        &mut self,
        tiff_tree: &mut Arena<ImageFileDirectory>,
        tokens: &[Token],
        page_sub_files_map: &HashMap<Token, Vec<ImageFileDirectory>>,
        asset_reader: &mut R,
    ) -> Result<()> {
        let mut page_ifd_offsets = Vec::new();

        let first_page = tokens
            .first()
            .ok_or(Error::InvalidAsset("no IFD found".to_string()))?;

        let last_page = tokens
            .last()
            .ok_or(Error::InvalidAsset("no IFD found".to_string()))?;

        let last_page_ifd = tiff_tree
            .get(*last_page)
            .ok_or_else(|| Error::InvalidAsset("TIFF does not have IFD".to_string()))?;

        // separate out the C2PA entry since it goes in its own IFD
        let new_c2pa_entry = self.additional_ifds.remove(&C2PA_TAG);

        // is this an old manifest so we need to add a manifest or a
        // multipage tiff without a manifest
        let needs_end_ifd = last_page == first_page
            || !last_page_ifd.data.entries.contains_key(&C2PA_TAG) && new_c2pa_entry.is_some();

        // if multipage, make sure last page containing C2PA contains a single entry
        if last_page != first_page
            && last_page_ifd.data.entries.contains_key(&C2PA_TAG)
            && last_page_ifd.data.entries.len() > 1
        {
            return Err(Error::ValidationRule(
                "Last IDF with C2PA manifest contained additional tags, expected 1 tag".to_string(),
            ));
        }

        // is there and existing valid new end C2PA IFD
        let has_c2pa_ifd =
            last_page != first_page || last_page_ifd.data.entries.contains_key(&C2PA_TAG);

        for page_token in tokens {
            // clone the subfile entries (DNG)
            let page_subfiles = page_sub_files_map
                .get(page_token)
                .cloned()
                .unwrap_or_else(Vec::new);
            let subfile_offsets = self.clone_sub_files(tiff_tree, &page_subfiles, asset_reader)?;

            let page_ifd = tiff_tree
                .get(*page_token)
                .ok_or_else(|| Error::InvalidAsset("TIFF does not have IFD".to_string()))?;

            // clone IFD entries
            let mut cloned_ifd = self.clone_ifd_entries(&page_ifd.data.entries, asset_reader)?;

            // clone the image data
            self.clone_image_data(&mut cloned_ifd, asset_reader)?;

            // clone bigtable data if DNG
            self.clone_dng_bigtable_data(&mut cloned_ifd, asset_reader)?;

            // add in new Tags to first IFD (XMP for example)
            if page_token == first_page {
                for (tag, new_entry) in &self.additional_ifds {
                    cloned_ifd.insert(*tag, new_entry.clone());
                }
            }

            // replace C2PA content
            if page_token == last_page && has_c2pa_ifd {
                if let Some(new_entry) = &new_c2pa_entry {
                    cloned_ifd.insert(C2PA_TAG, new_entry.clone());
                }
            }

            // fix up subfile offsets
            for t in SUBFILES {
                if let Some(offsets) = subfile_offsets.get(&t) {
                    if offsets.is_empty() {
                        continue;
                    }

                    let e = cloned_ifd
                        .get_mut(&t)
                        .ok_or_else(|| Error::InvalidAsset("TIFF does not have IFD".to_string()))?;
                    let mut adjust_offsets: Vec<u8> = if self.big_tiff {
                        safe_vec(offsets.len() as u64 * 8, Some(0))?
                    } else {
                        safe_vec(offsets.len() as u64 * 4, Some(0))?
                    };

                    with_order!(adjust_offsets.as_mut_slice(), self.endianness, |dest| {
                        for o in offsets {
                            if self.big_tiff {
                                dest.write_u64(*o)?;
                            } else {
                                let offset_u32 = u32::try_from(*o).map_err(|_err| {
                                    Error::InvalidAsset("value out of range".to_string())
                                })?;

                                dest.write_u32(offset_u32)?;
                            }
                        }
                    });

                    e.value_bytes = adjust_offsets;
                }
            }

            // write directory
            let ifd_offset = self.write_ifd(&mut cloned_ifd)?;

            page_ifd_offsets.push((ifd_offset, self.offset()?));
        }

        // add new C2PA IFD if needed
        if needs_end_ifd {
            if let Some(new_entry) = &new_c2pa_entry {
                let mut cloned_entry = BTreeMap::new();
                cloned_entry.insert(C2PA_TAG, new_entry.clone());

                // write directory
                let ifd_offset = self.write_ifd(&mut cloned_entry)?;

                page_ifd_offsets.push((ifd_offset, self.offset()?));
            }
        }

        // link all IFDs
        let mut prior_ifd_start = 0u64;
        for (index, (offset, _write_point)) in page_ifd_offsets.iter().enumerate() {
            // if this is the first IFD we need to patch the TIFF header
            if index == 0 {
                self.writer.seek(SeekFrom::Start(4))?; // header first IDF offset location

                if self.big_tiff {
                    self.writer.write_u64(*offset)?;
                } else {
                    let offset_u32 = u32::try_from(*offset)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;
                    self.writer.write_u32(offset_u32)?;
                }
                prior_ifd_start = *offset;
            } else {
                // seek and patch the prior IFD next offset field
                self.writer.seek(SeekFrom::Start(prior_ifd_start))?;
                let prior_ifd = TiffStructure::read_ifd(
                    &mut self.writer.inner_mut(),
                    self.endianness,
                    self.big_tiff,
                    IfdType::Page,
                )?;

                self.set_next_ifd_offset(&prior_ifd, *offset)?;

                prior_ifd_start = *offset;
            }
        }

        self.writer.flush()?;

        Ok(())
    }

    fn clone_ifd_entries<R: Read + Seek + ?Sized>(
        &mut self,
        entries: &BTreeMap<u16, IfdEntry>,
        mut asset_reader: &mut R,
    ) -> Result<BTreeMap<u16, IfdClonedEntry>> {
        let file_size = stream_len(asset_reader)?;
        let mut target_ifd: BTreeMap<u16, IfdClonedEntry> = BTreeMap::new();

        for (tag, entry) in entries {
            let target_endianness = self.writer.endianness();

            // get bytes for tag
            let cnt = entry.value_count;
            let et = entry.entry_type;

            let entry_type = IFDEntryType::from_u16(et).ok_or(Error::UnsupportedType)?;

            // read IFD raw data in file native endian format
            let data = match entry_type {
                IFDEntryType::Byte
                | IFDEntryType::Sbyte
                | IFDEntryType::Undefined
                | IFDEntryType::Ascii => {
                    let num_bytes = usize::try_from(cnt)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    check_ifd_data_size(cnt, file_size)?;

                    let mut data = safe_vec(cnt, Some(0u8))?;

                    if num_bytes <= 4 || self.big_tiff && num_bytes <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        for (i, item) in offset_bytes.iter().take(num_bytes).enumerate() {
                            data[i] = *item;
                        }
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(decode_offset(
                            entry.value_offset,
                            target_endianness,
                            self.big_tiff,
                        )?))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                IFDEntryType::Short => {
                    let num_shorts_x2 =
                        usize::try_from(cnt.checked_mul(2).ok_or_else(|| {
                            Error::InvalidAsset("value out of range".to_string())
                        })?)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    check_ifd_data_size(num_shorts_x2 as u64, file_size)?;

                    let mut data = safe_vec(num_shorts_x2 as u64, Some(0u8))?;

                    if num_shorts_x2 <= 4 || self.big_tiff && num_shorts_x2 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        let mut w = Cursor::new(data.as_mut_slice());
                        for _i in 0..num_shorts_x2 / 2 {
                            let s = offset_reader.read_u16::<NativeEndian>()?; // read a short from offset
                            w.write_u16::<NativeEndian>(s)?; // write a short in output endian
                        }
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(decode_offset(
                            entry.value_offset,
                            target_endianness,
                            self.big_tiff,
                        )?))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                IFDEntryType::Long | IFDEntryType::Ifd => {
                    let num_longs_x4 =
                        usize::try_from(cnt.checked_mul(4).ok_or_else(|| {
                            Error::InvalidAsset("value out of range".to_string())
                        })?)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    check_ifd_data_size(num_longs_x4 as u64, file_size)?;

                    let mut data = safe_vec(num_longs_x4 as u64, Some(0u8))?;

                    if num_longs_x4 <= 4 || self.big_tiff && num_longs_x4 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        let mut w = Cursor::new(data.as_mut_slice());
                        for _i in 0..num_longs_x4 / 4 {
                            let s = offset_reader.read_u32::<NativeEndian>()?; // read a long from offset
                            w.write_u32::<NativeEndian>(s)?; // write a long in output endian
                        }
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(decode_offset(
                            entry.value_offset,
                            target_endianness,
                            self.big_tiff,
                        )?))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                IFDEntryType::Sshort => {
                    let num_sshorts_x2 =
                        usize::try_from(cnt.checked_mul(2).ok_or_else(|| {
                            Error::InvalidAsset("value out of range".to_string())
                        })?)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    check_ifd_data_size(num_sshorts_x2 as u64, file_size)?;

                    let mut data = safe_vec(num_sshorts_x2 as u64, Some(0u8))?;

                    if num_sshorts_x2 <= 4 || self.big_tiff && num_sshorts_x2 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        let mut w = Cursor::new(data.as_mut_slice());
                        for _i in 0..num_sshorts_x2 / 2 {
                            let s = offset_reader.read_i16::<NativeEndian>()?; // read a short from offset
                            w.write_i16::<NativeEndian>(s)?; // write a short in output endian
                        }
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(decode_offset(
                            entry.value_offset,
                            target_endianness,
                            self.big_tiff,
                        )?))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                IFDEntryType::Slong => {
                    let num_slongs_x4 =
                        usize::try_from(cnt.checked_mul(4).ok_or_else(|| {
                            Error::InvalidAsset("value out of range".to_string())
                        })?)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    check_ifd_data_size(num_slongs_x4 as u64, file_size)?;

                    let mut data = safe_vec(num_slongs_x4 as u64, Some(0u8))?;

                    if num_slongs_x4 <= 4 || self.big_tiff && num_slongs_x4 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        let mut w = Cursor::new(data.as_mut_slice());
                        for _i in 0..num_slongs_x4 / 4 {
                            let s = offset_reader.read_i32::<NativeEndian>()?; // read a slong from offset
                            w.write_i32::<NativeEndian>(s)?; // write a slong in output endian
                        }
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(decode_offset(
                            entry.value_offset,
                            target_endianness,
                            self.big_tiff,
                        )?))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                IFDEntryType::Float => {
                    let num_floats_x4 =
                        usize::try_from(cnt.checked_mul(4).ok_or_else(|| {
                            Error::InvalidAsset("value out of range".to_string())
                        })?)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    check_ifd_data_size(num_floats_x4 as u64, file_size)?;

                    let mut data = safe_vec(num_floats_x4 as u64, Some(0u8))?;

                    if num_floats_x4 <= 4 || self.big_tiff && num_floats_x4 <= 8 {
                        let offset_bytes = entry.value_offset.to_ne_bytes();
                        let mut offset_reader = Cursor::new(offset_bytes);

                        let mut w = Cursor::new(data.as_mut_slice());
                        for _i in 0..num_floats_x4 / 4 {
                            let s = offset_reader.read_f32::<NativeEndian>()?; // read a float from offset
                            w.write_f32::<NativeEndian>(s)?; // write a float in output endian
                        }
                    } else {
                        // move to start of data
                        asset_reader.seek(SeekFrom::Start(decode_offset(
                            entry.value_offset,
                            target_endianness,
                            self.big_tiff,
                        )?))?;
                        asset_reader.read_exact(data.as_mut_slice())?;
                    }

                    data
                }
                IFDEntryType::Rational
                | IFDEntryType::Srational
                | IFDEntryType::Slong8
                | IFDEntryType::Double
                | IFDEntryType::Long8
                | IFDEntryType::Ifd8 => {
                    // Each element is 8 bytes wide. Use checked_mul to prevent u64 overflow
                    // when a crafted BigTIFF supplies a malicious value_count (e.g.
                    // 0x2000000000000001 * 8 wraps past u64::MAX in release builds and
                    // panics in debug builds).
                    let num_bytes_8 = cnt
                        .checked_mul(8)
                        .ok_or_else(|| Error::InvalidAsset("value out of range".to_string()))?;

                    // move to start of data
                    asset_reader.seek(SeekFrom::Start(decode_offset(
                        entry.value_offset,
                        target_endianness,
                        self.big_tiff,
                    )?))?;

                    asset_reader.read_to_vec(num_bytes_8)?
                }
            };

            target_ifd.insert(
                *tag,
                IfdClonedEntry {
                    entry_tag: *tag,
                    entry_type: entry_type as u16,
                    value_count: cnt,
                    value_bytes: data,
                },
            );
        }

        Ok(target_ifd)
    }
}

fn tiff_clone_with_tags<R: Read + Seek + ?Sized, W: Read + Write + Seek + ?Sized>(
    asset_writer: &mut W,
    asset_reader: &mut R,
    tiff_tags: Vec<IfdClonedEntry>,
) -> Result<()> {
    let MappedTiff {
        mut tiff_tree,
        page_tokens,
        sub_files_map: _sub_files_map,
        endianness,
        big_tiff,
    } = map_tiff(asset_reader)?;

    let mut bo = ByteOrdered::new(asset_writer, endianness);
    let mut tc = TiffCloner::new_from_source(endianness, big_tiff, &mut bo, asset_reader)?;

    tc.clone_c2pa_mode(
        asset_reader,
        &mut tiff_tree,
        &page_tokens,
        tiff_tags.clone(),
        &[],
    )?;

    Ok(())
}
fn add_required_tags_to_stream(
    input_stream: &mut dyn CAIRead,
    output_stream: &mut dyn CAIReadWrite,
) -> Result<()> {
    let tiff_io = TiffIO {};

    match tiff_io.read_cai(input_stream) {
        Ok(_) => {
            // just clone
            input_stream.rewind()?;
            output_stream.rewind()?;
            std::io::copy(input_stream, output_stream)?;
            Ok(())
        }
        Err(Error::JumbfNotFound) => {
            // allocate enough bytes so that value is not stored in offset field
            let some_bytes = vec![0u8; 10];
            let tio = TiffIO {};
            tio.write_cai(input_stream, output_stream, &some_bytes)
        }
        Err(e) => Err(e),
    }
}

fn get_cai_data<R>(mut asset_reader: &mut R) -> Result<Vec<u8>>
where
    R: Read + Seek + ?Sized,
{
    let mapped = map_tiff(asset_reader)?;
    let tiff_tree = mapped.tiff_tree;
    let page_tokens = mapped.page_tokens;
    let e = mapped.endianness;
    let big_tiff = mapped.big_tiff;

    let first_page = page_tokens
        .first()
        .ok_or(Error::InvalidAsset("no IFD".to_string()))?;
    let last_page = page_tokens
        .last()
        .ok_or(Error::InvalidAsset("no IFD".to_string()))?;
    let last_ifd = &tiff_tree[*last_page].data;

    let cai_ifd_entry = match last_ifd.get_tag(C2PA_TAG) {
        Some(entry) => entry,
        None => {
            // if the last page doesn't have the C2PA tag, check the first page for backwards compatibility with older TIFFs
            let first_ifd = &tiff_tree[*first_page].data;
            first_ifd.get_tag(C2PA_TAG).ok_or(Error::JumbfNotFound)?
        }
    };

    // make sure data type is for unstructured data
    if cai_ifd_entry.entry_type != C2PA_FIELD_TYPE {
        return Err(Error::InvalidAsset(
            "Ifd entry for C2PA must be type UNDEFINED(7)".to_string(),
        ));
    }

    // move read point to start of entry
    let decoded_offset = decode_offset(cai_ifd_entry.value_offset, e, big_tiff)?;
    asset_reader.seek(SeekFrom::Start(decoded_offset))?;

    let data = asset_reader
        .read_to_vec(cai_ifd_entry.value_count)
        .map_err(|_err| Error::InvalidAsset("TIFF/DNG out of range".to_string()))?;

    Ok(data)
}

fn get_xmp_data<R>(mut asset_reader: &mut R) -> Option<Vec<u8>>
where
    R: Read + Seek + ?Sized,
{
    let mapped = map_tiff(asset_reader).ok()?;
    let tiff_tree = mapped.tiff_tree;
    let page_tokens = mapped.page_tokens;
    let e = mapped.endianness;
    let big_tiff = mapped.big_tiff;

    let first_page = page_tokens.first()?;
    let first_ifd = &tiff_tree[*first_page].data;

    let xmp_ifd_entry = first_ifd.get_tag(XMP_TAG)?;
    // make sure the tag type is correct
    if IFDEntryType::from_u16(xmp_ifd_entry.entry_type)? != IFDEntryType::Byte {
        return None;
    }

    // move read point to start of entry
    let decoded_offset = decode_offset(xmp_ifd_entry.value_offset, e, big_tiff).ok()?;
    asset_reader.seek(SeekFrom::Start(decoded_offset)).ok()?;

    asset_reader.read_to_vec(xmp_ifd_entry.value_count).ok()
}

pub struct TiffIO {}

impl CAIReader for TiffIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let cai_data = get_cai_data(asset_reader)?;
        Ok(cai_data)
    }

    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        let xmp_data = get_xmp_data(asset_reader)?;
        String::from_utf8(xmp_data).ok()
    }
}

impl AssetIO for TiffIO {
    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn read_cai_store(&self, asset_path: &std::path::Path) -> Result<Vec<u8>> {
        let mut reader = std::fs::File::open(asset_path)?;

        self.read_cai(&mut reader)
    }

    fn save_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut input_stream = std::fs::OpenOptions::new()
            .read(true)
            .open(asset_path)
            .map_err(Error::IoError)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;

        // copy temp file to asset
        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(
        &self,
        asset_path: &std::path::Path,
    ) -> Result<Vec<crate::asset_io::HashObjectPositions>> {
        let mut input_stream =
            std::fs::File::open(asset_path).map_err(|_err| Error::EmbeddingError)?;

        self.get_object_locations_from_stream(&mut input_stream)
    }

    fn remove_cai_store(&self, asset_path: &std::path::Path) -> Result<()> {
        let mut input_file = std::fs::File::open(asset_path)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.remove_cai_store_from_stream(&mut input_file, &mut temp_file)?;

        // copy temp file to asset
        rename_or_move(temp_file, asset_path)
    }

    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        TiffIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(TiffIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        if SUPPORTED_WRITER_TYPES.contains(&asset_type) {
            Some(Box::new(TiffIO::new(asset_type)))
        } else {
            None
        }
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

impl CAIWriter for TiffIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let l = u64::try_from(store_bytes.len())
            .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

        let entry = IfdClonedEntry {
            entry_tag: C2PA_TAG,
            entry_type: C2PA_FIELD_TYPE,
            value_count: l,
            value_bytes: store_bytes.to_vec(),
        };

        tiff_clone_with_tags(output_stream, input_stream, vec![entry])
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let len = stream_len(input_stream)?;
        let vec_cap = usize::try_from(len)
            .map_err(|_err| Error::InvalidAsset("value out of range".to_owned()))?;
        let output_buf: Vec<u8> = Vec::with_capacity(vec_cap + 100);

        let mut output_stream = Cursor::new(output_buf);

        add_required_tags_to_stream(input_stream, &mut output_stream)?;
        output_stream.rewind()?;

        let mapped = map_tiff(&mut output_stream)?;
        let tiff_tree = mapped.tiff_tree;
        let page_tokens = mapped.page_tokens;
        let e = mapped.endianness;
        let big_tiff = mapped.big_tiff;

        let first_page = page_tokens
            .first()
            .ok_or(Error::InvalidAsset("no IFD".to_string()))?;
        let last_page = page_tokens
            .last()
            .ok_or(Error::InvalidAsset("no IFD".to_string()))?;
        let last_page_ifd = &tiff_tree[*last_page].data;

        let cai_ifd_entry = match last_page_ifd.get_tag(C2PA_TAG) {
            Some(entry) => entry,
            None => {
                // if the last page doesn't have the C2PA tag, check the first page for backwards compatibility with older TIFFs
                let first_ifd = &tiff_tree[*first_page].data;
                first_ifd.get_tag(C2PA_TAG).ok_or(Error::JumbfNotFound)?
            }
        };

        // make sure data type is for unstructured data
        if cai_ifd_entry.entry_type != C2PA_FIELD_TYPE {
            return Err(Error::InvalidAsset(
                "Ifd entry for C2PA must be type UNDEFINED(7)".to_string(),
            ));
        }

        let decoded_offset = decode_offset(cai_ifd_entry.value_offset, e, big_tiff)?;
        let manifest_offset = usize::try_from(decoded_offset)
            .map_err(|_err| Error::InvalidAsset("TIFF/DNG out of range".to_string()))?;
        let manifest_len = usize::try_from(cai_ifd_entry.value_count)
            .map_err(|_err| Error::InvalidAsset("TIFF/DNG out of range".to_string()))?;

        // figure out count to exclude
        let c2p_entry_pos = last_page_ifd
            .entries
            .keys()
            .position(|t| t == &C2PA_TAG)
            .ok_or(Error::NotFound)?;
        let count_offset = last_page_ifd.offset
                        + if big_tiff { 8u64 } else { 2u64 } // entry count
                        + (if big_tiff { 16u64 } else { 12u64 } * c2p_entry_pos as u64) // offset of C2PA entry
                        + 4; // tag(2) + type(2)

        // size of the count field
        let count_size = if big_tiff { 8 } else { 4 };

        Ok(vec![
            HashObjectPositions {
                offset: manifest_offset,
                length: manifest_len,
                htype: HashBlockObjectType::Cai,
            },
            HashObjectPositions {
                offset: usize::try_from(count_offset)
                    .map_err(|_err| Error::InvalidAsset("TIFF/DNG out of range".to_string()))?,
                length: count_size,
                htype: HashBlockObjectType::OtherExclusion,
            },
        ])
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let mapped = map_tiff(input_stream)?;
        let mut tiff_tree = mapped.tiff_tree;
        let page_tokens = mapped.page_tokens;
        let e = mapped.endianness;
        let big_tiff = mapped.big_tiff;

        let last_page = page_tokens
            .last()
            .ok_or(Error::InvalidAsset("no IFD found".to_string()))?;

        // we remove tag if found and rewrite the file
        if tiff_tree[*last_page].data.entries.contains_key(&C2PA_TAG) {
            let mut bo = ByteOrdered::new(output_stream, e);
            let mut tc = TiffCloner::new_from_source(e, big_tiff, &mut bo, input_stream)?;

            tc.clone_c2pa_mode(
                input_stream,
                &mut tiff_tree,
                &page_tokens,
                Vec::new(),
                &[C2PA_TAG],
            )?;
        } else {
            // just copy if no changes made
            input_stream.rewind()?;
            std::io::copy(input_stream, output_stream)?;
        }

        Ok(())
    }
}

impl AssetPatch for TiffIO {
    fn patch_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut asset_io = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(asset_path)?;

        let mapped = map_tiff(&mut asset_io)?;
        let tiff_tree = mapped.tiff_tree;
        let page_tokens = mapped.page_tokens;
        let e = mapped.endianness;
        let big_tiff = mapped.big_tiff;

        let last_page = page_tokens
            .last()
            .ok_or(Error::InvalidAsset("no IFD".to_string()))?;
        let last_ifd = &tiff_tree[*last_page].data;

        let cai_ifd_entry = last_ifd.get_tag(C2PA_TAG).ok_or(Error::JumbfNotFound)?;

        // make sure data type is for unstructured data
        if cai_ifd_entry.entry_type != C2PA_FIELD_TYPE {
            return Err(Error::InvalidAsset(
                "Ifd entry for C2PA must be type UNKNOWN(7)".to_string(),
            ));
        }

        let manifest_len: usize = usize::try_from(cai_ifd_entry.value_count)
            .map_err(|_err| Error::InvalidAsset("TIFF/DNG out of range".to_string()))?;

        if store_bytes.len() == manifest_len {
            // move read point to start of entry
            let decoded_offset = decode_offset(cai_ifd_entry.value_offset, e, big_tiff)?;
            asset_io.seek(SeekFrom::Start(decoded_offset))?;

            asset_io.write_all(store_bytes)?;
            Ok(())
        } else {
            Err(Error::InvalidAsset(
                "patch_cai_store store size mismatch.".to_string(),
            ))
        }
    }
}

impl RemoteRefEmbed for TiffIO {
    #[allow(unused_variables)]
    fn embed_reference(
        &self,
        asset_path: &Path,
        embed_ref: crate::asset_io::RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                let output_buf = Vec::new();
                let mut output_stream = Cursor::new(output_buf);

                // block so that source file is closed after embed
                {
                    let mut source_stream = std::fs::File::open(asset_path)?;
                    self.embed_reference_to_stream(
                        &mut source_stream,
                        &mut output_stream,
                        RemoteRefEmbedType::Xmp(manifest_uri),
                    )?;
                }

                // write will replace exisiting contents
                output_stream.rewind()?;
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
                let xmp = match self.get_reader().read_xmp(source_stream) {
                    Some(xmp) => add_provenance(&xmp, &manifest_uri)?,
                    None => {
                        let xmp = MIN_XMP.to_string();
                        add_provenance(&xmp, &manifest_uri)?
                    }
                };

                let l = u64::try_from(xmp.len())
                    .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                let entry = IfdClonedEntry {
                    entry_tag: XMP_TAG,
                    entry_type: IFDEntryType::Byte as u16,
                    value_count: l,
                    value_bytes: xmp.as_bytes().to_vec(),
                };
                tiff_clone_with_tags(output_stream, source_stream, vec![entry])
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }
}

impl ComposedManifestRef for TiffIO {
    // Return entire CAI block as Vec<u8>
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        Ok(manifest_data.to_vec())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TiffError {
    #[error("invalid file signature: {reason}")]
    InvalidFileSignature { reason: String },
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use core::panic;

    use super::*;
    use crate::utils::{io_utils::tempdirectory, test::temp_dir_path};

    #[test]
    fn test_multipage_read_write_manifest() {
        let data = "some data";
        let data2 = "some different data";

        let source = crate::utils::test::fixture_path("MultiPage.tif");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tif");

        std::fs::copy(source, &output).unwrap();

        let tiff_io = TiffIO {};

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data.as_bytes());

        // test adding over existing
        tiff_io.save_cai_store(&output, data2.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data2.as_bytes());

        // let's remove the manifest
        tiff_io.remove_cai_store(&output).unwrap();

        // should not contain a manifest
        let result = tiff_io.read_cai_store(&output);
        assert!(result.is_err());
    }

    #[test]
    fn test_multipage_read_write_manifest_xmp() {
        let data = "some data";
        let data2 = "some xmp data";

        let source = crate::utils::test::fixture_path("MultiPage.tif");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tif");

        std::fs::copy(source, &output).unwrap();

        let tiff_io = TiffIO {};

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data.as_bytes());

        // test adding over existing
        tiff_io
            .remote_ref_writer_ref()
            .unwrap()
            .embed_reference(&output, RemoteRefEmbedType::Xmp(data2.to_string()))
            .unwrap();

        // read xmp data back
        let mut output_file = std::fs::File::open(&output).unwrap();
        let loaded = tiff_io.read_xmp(&mut output_file).unwrap();

        assert!(loaded.contains(data2));

        // make sure manifest was relocated correctly
        let loaded = tiff_io.read_cai_store(&output).unwrap();
        assert_eq!(&loaded, data.as_bytes());

        // now test shrinking the manifest at the end of the file
        let data3 = "short";
        tiff_io.save_cai_store(&output, data3.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();
        assert_eq!(&loaded, data3.as_bytes());
    }

    #[test]
    fn cyclic_ifd_self_loop_returns_error() {
        // 14-byte little-endian TIFF: IFD at offset 8 has next-offset = 8.
        // Chain: A → A
        #[rustfmt::skip]
        let crafted_tiff: &[u8] = &[
            0x49, 0x49, // byte order: little-endian
            0x2A, 0x00, // magic: 42
            0x08, 0x00, 0x00, 0x00, // first IFD at offset 8
            0x00, 0x00, // IFD entry count: 0
            0x08, 0x00, 0x00, 0x00, // next IFD offset: 8 (self-loop)
        ];
        let mut cursor = Cursor::new(crafted_tiff);
        let result = map_tiff(&mut cursor);
        assert!(result.is_err(), "self-loop IFD must return an error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Cyclic IFD chain"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn cyclic_ifd_two_node_cycle_returns_error() {
        // 20-byte little-endian TIFF with two IFDs forming a cycle.
        // Chain: A (offset 8) → B (offset 14) → A (offset 8)
        #[rustfmt::skip]
        let crafted_tiff: &[u8] = &[
            0x49, 0x49, // byte order: little-endian
            0x2A, 0x00, // magic: 42
            0x08, 0x00, 0x00, 0x00, // first IFD at offset 8
            // IFD A at offset 8
            0x00, 0x00, // entry count: 0
            0x0E, 0x00, 0x00, 0x00, // next IFD offset: 14 (IFD B)
            // IFD B at offset 14
            0x00, 0x00, // entry count: 0
            0x08, 0x00, 0x00, 0x00, // next IFD offset: 8 (back to IFD A)
        ];
        let mut cursor = Cursor::new(crafted_tiff);
        let result = map_tiff(&mut cursor);
        assert!(result.is_err(), "A→B→A IFD cycle must return an error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Cyclic IFD chain"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn test_read_write_manifest() {
        let data = "some data";
        let data2 = "some different data";

        let source = crate::utils::test::fixture_path("TUSCANY.TIF");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tif");

        std::fs::copy(source, &output).unwrap();

        let tiff_io = TiffIO {};

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();
        tiff_io.save_cai_store(&output, data2.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data2.as_bytes());
    }

    #[test]
    fn test_read_write_manifest_dng() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("subfiles.dng");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.dng");

        std::fs::copy(source, &output).unwrap();

        let tiff_io = TiffIO {};

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data.as_bytes());
    }

    #[test]
    fn test_read_write_manifest_dng_bigdata() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("Foo.dng");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.dng");

        std::fs::copy(source, &output).unwrap();

        let tiff_io = TiffIO {};

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data.as_bytes());
    }

    #[test]
    fn test_legacy_cloner_tiff_bomb() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("tiff_poc.tiff");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tiff");

        std::fs::copy(&source, &output).unwrap();
        let asset_writer = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(&output)
            .unwrap();

        let mut asset_reader = std::fs::OpenOptions::new()
            .write(false)
            .read(true)
            .create(false)
            .open(&source)
            .unwrap();

        let l = u64::try_from(data.len())
            .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))
            .unwrap();

        let entry = IfdClonedEntry {
            entry_tag: C2PA_TAG,
            entry_type: C2PA_FIELD_TYPE,
            value_count: l,
            value_bytes: data.as_bytes().to_vec(),
        };

        let result = map_tiff(&mut asset_reader);
        assert!(result.is_err(), "should not be able to map tiff bomb");
    }

    #[test]
    fn test_cloner_tiff_bomb() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("tiff_poc.tiff");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tif");

        std::fs::copy(source, &output).unwrap();
        let mut asset_writer = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(&output)
            .unwrap();

        let mut asset_reader = std::fs::OpenOptions::new()
            .write(false)
            .read(true)
            .create(false)
            .open(&output)
            .unwrap();

        let l = u64::try_from(data.len())
            .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))
            .unwrap();

        let entry = IfdClonedEntry {
            entry_tag: C2PA_TAG,
            entry_type: C2PA_FIELD_TYPE,
            value_count: l,
            value_bytes: data.as_bytes().to_vec(),
        };

        let result = tiff_clone_with_tags(&mut asset_writer, &mut asset_reader, vec![entry]);
        assert!(result.is_err(), "should not be able to clone tiff bomb");
    }

    #[test]
    fn test_write_xmp() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("TUSCANY.TIF");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tif");

        std::fs::copy(source, &output).unwrap();

        let tiff_io = TiffIO {};

        // add a manifest first to stress this case
        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // save data to tiff
        let eh = tiff_io.remote_ref_writer_ref().unwrap();
        eh.embed_reference(&output, RemoteRefEmbedType::Xmp(data.to_string()))
            .unwrap();

        // read data back
        let mut output_stream = std::fs::File::open(&output).unwrap();
        let xmp = tiff_io.read_xmp(&mut output_stream).unwrap();
        let loaded = crate::utils::xmp_inmemory_utils::extract_provenance(&xmp).unwrap();

        assert_eq!(&loaded, data);
    }

    #[test]
    fn test_remove_manifest() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("TUSCANY.TIF");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tif");

        std::fs::copy(source, &output).unwrap();

        let tiff_io = TiffIO {};

        // first make sure that calling this without a manifest does not error
        tiff_io.remove_cai_store(&output).unwrap();

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data.as_bytes());

        tiff_io.remove_cai_store(&output).unwrap();

        match tiff_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => panic!("should be no C2PA store"),
        }
    }

    #[test]
    fn test_get_object_location() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("TUSCANY.TIF");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.tif");

        std::fs::copy(source, &output).unwrap();

        let tiff_io = TiffIO {};

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // read data back
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data.as_bytes());

        let mut success = false;
        if let Ok(locations) = tiff_io.get_object_locations(&output) {
            for op in locations {
                if op.htype == HashBlockObjectType::Cai {
                    let mut of = std::fs::File::open(&output).unwrap();

                    let mut manifests_buf: Vec<u8> = vec![0u8; op.length];
                    of.seek(SeekFrom::Start(op.offset as u64)).unwrap();
                    of.read_exact(manifests_buf.as_mut_slice()).unwrap();
                    if crate::hash_utils::vec_compare(&manifests_buf, data.as_bytes()) {
                        success = true;
                    }
                }
            }
        }
        assert!(success);
    }

    #[test]
    #[ignore = "This code is no longer accessed.  We do not clone ifd entries."]
    fn test_overflow_clone_ifd_entries() {
        let data = [
            0x49, 0x49, 0x2b, 0x00, 0x08, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49,
            0x49, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xf9, 0x00,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            // entry
            //
            0x00, 0x00, // entry_tag
            0x04, 0x00, // entry_type
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // value_count (cnt)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value_offset
            //
            // entry
            //
            0x00, 0x00, // entry_tag
            0x04, 0x00, // entry_type
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // value_count (cnt)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value_offset
            //
            // ...
            //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];

        let mut stream = Cursor::new(&data);

        let tiff_io = TiffIO {};

        let locations = tiff_io.get_object_locations_from_stream(&mut stream);
        assert!(matches!(locations, Err(Error::InvalidAsset(_))));
    }

    /// Regression test for integer overflow in `clone_ifd_entries` for 8-byte element types.
    ///
    /// IFD entry types Rational, SRational, Double, Long8, SLong8, and Ifd8 are all 8 bytes
    /// wide per element. Before the fix, the byte count was computed as `cnt * 8` with no
    /// overflow guard. A crafted BigTIFF carrying `value_count = 0x2000000000000001` causes
    /// `0x2000000000000001 * 8 = 0x10000000000000008`, which wraps past u64::MAX:
    ///   - debug builds: immediate panic (exit code 101)
    ///   - release builds: silent truncation to 0x8, producing wrong results
    ///
    /// The fix adds `checked_mul(8)` — matching the pattern already used for every other
    /// multi-byte type — and returns `Error::InvalidAsset` instead of overflowing.
    ///
    /// The binary blob below is the same crafted BigTIFF as in `test_overflow_clone_ifd_entries`
    /// but with entry_type changed from 0x04 (Long, ×4) to 0x05 (Rational, ×8) and
    /// value_count set to 0x2000000000000001 (overflows ×8).
    #[test]
    #[ignore = "This code is no longer accessed.  We do not clone ifd entries."]
    fn test_overflow_clone_ifd_entries_rational_type() {
        let data = [
            0x49, 0x49, 0x2b, 0x00, 0x08, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49,
            0x49, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xf9, 0x00,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            // entry — type 0x05 (Rational, 8 bytes/element), count overflows × 8
            //
            0x00, 0x00, // entry_tag
            0x05, 0x00, // entry_type: Rational (was 0x04 Long)
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, // value_count = 0x2000000000000001
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value_offset
            //
            // entry
            //
            0x00, 0x00, // entry_tag
            0x05, 0x00, // entry_type: Rational (was 0x04 Long)
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, // value_count = 0x2000000000000001
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value_offset
            //
            // ...
            //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];

        let mut stream = Cursor::new(&data);
        let tiff_io = TiffIO {};

        // Before the fix: this would panic (exit 101) in debug or silently overflow in release.
        // After the fix: must return Err(Error::InvalidAsset) without any panic.
        let locations = tiff_io.get_object_locations_from_stream(&mut stream);
        assert!(matches!(locations, Err(Error::InvalidAsset(_))));
    }

    /// Regression test for OOM in `clone_ifd_entries` for Byte/1-byte element types.
    ///
    /// On Linux containers with memory overcommit (the default), `safe_vec` uses
    /// `try_reserve_exact` which succeeds for a 10 GB allocation because the OS commits
    /// virtual address space lazily. The subsequent `resize` then touches all 10 GB of
    /// pages, triggering the OOM killer (exit 137) in any 8 GB container.
    ///
    /// The fix validates `cnt <= file_size` before calling `safe_vec`, returning
    /// `Err(InvalidAsset)` for any count that exceeds the file's actual byte count.
    ///
    /// The binary blob is the same crafted BigTIFF as `test_overflow_clone_ifd_entries`
    /// but with entry_type changed from 0x04 (Long, ×4) to 0x01 (Byte, ×1) and
    /// value_count set to 10_000_000_000 (0x00000002540BE400 little-endian).
    #[test]
    #[ignore = "This code is no longer accessed.  We do not clone ifd entries."]
    fn test_oom_clone_ifd_entries_byte_type() {
        // Same BigTIFF blob as test_overflow_clone_ifd_entries, with entry_type changed from
        // 0x04 (Long, ×4) to 0x01 (Byte, ×1) and value_count changed from the overflow-inducing
        // 0x8000000000000003 to 10_000_000_000 (0x00000002540BE400 LE). The IFD offset (0x31 = 49)
        // and entry count (3) at that offset must stay identical to the original blob.
        let data = [
            0x49, 0x49, 0x2b, 0x00, 0x08, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49,
            0x49, 0x2a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xf9, 0x00,
            0x00, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            // entry — type 0x01 (Byte, 1 byte/element), value_count = 10_000_000_000
            //
            0x00, 0x00, // entry_tag
            0x01, 0x00, // entry_type: Byte (was 0x04 Long)
            0x00, 0xe4, 0x0b, 0x54, 0x02, 0x00, 0x00, 0x00, // value_count = 10_000_000_000 LE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value_offset
            //
            // entry
            //
            0x00, 0x00, // entry_tag
            0x01, 0x00, // entry_type: Byte (was 0x04 Long)
            0x00, 0xe4, 0x0b, 0x54, 0x02, 0x00, 0x00, 0x00, // value_count = 10_000_000_000 LE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value_offset
            //
            // ...
            //
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];

        let mut stream = Cursor::new(&data);
        let tiff_io = TiffIO {};

        // Before the fix: this would OOM-kill an 8 GB Linux container.
        // After the fix: must return Err(Error::InvalidAsset) without any allocation.
        let locations = tiff_io.get_object_locations_from_stream(&mut stream);
        assert!(matches!(locations, Err(Error::InvalidAsset(_))));
    }

    // Helper: build an IfdClonedEntry of LONG (u32) values in little-endian.
    fn u32_strip_entry(tag: u16, values: &[u32]) -> IfdClonedEntry {
        let mut value_bytes = Vec::with_capacity(values.len() * 4);
        for v in values {
            value_bytes.extend_from_slice(&v.to_le_bytes());
        }
        IfdClonedEntry {
            entry_tag: tag,
            entry_type: 4, // LONG
            value_count: values.len() as u64,
            value_bytes,
        }
    }

    // Regression: a TIFF whose strip byte counts sum to more than the actual
    // source stream length must be rejected. Pre-fix, `clone_image_data`
    // would honor an attacker-chosen sum (50 000 strips × source_len) and
    // grow the in-memory output to gigabytes, aborting with OOM (~4.9 GB
    // from a 293 KB input in the reported PoC).
    #[test]
    fn clone_image_data_rejects_strip_byte_count_amplification() {
        // 100-byte source; 10 strips claiming 200 bytes each → sum 2000 > 100.
        let mut asset_reader = Cursor::new(vec![0u8; 100]);

        let n = 10;
        let byte_counts: Vec<u32> = vec![200u32; n];
        let offsets: Vec<u32> = vec![0u32; n];

        let mut ifd: BTreeMap<u16, IfdClonedEntry> = BTreeMap::new();
        ifd.insert(
            STRIPBYTECOUNTS,
            u32_strip_entry(STRIPBYTECOUNTS, &byte_counts),
        );
        ifd.insert(STRIPOFFSETS, u32_strip_entry(STRIPOFFSETS, &offsets));

        let writer = Cursor::new(Vec::<u8>::new());
        let mut cloner = TiffCloner::new(Endianness::Little, false, writer).unwrap();
        let result = cloner.clone_image_data(&mut ifd, &mut asset_reader);

        assert!(
            matches!(&result, Err(Error::InvalidAsset(msg)) if msg.contains("exceed source length")),
            "expected InvalidAsset for over-cap strip byte counts, got {result:?}",
        );
    }

    // Regression: same amplification pattern in the tile branch of
    // `clone_image_data`. `sum(tile_byte_counts) > source_len` must be
    // rejected before any copy is performed.
    #[test]
    fn clone_image_data_rejects_tile_byte_count_amplification() {
        let mut asset_reader = Cursor::new(vec![0u8; 100]);

        let n = 8;
        let byte_counts: Vec<u32> = vec![u32::MAX / n as u32; n]; // huge sum
        let offsets: Vec<u32> = vec![0u32; n];

        let mut ifd: BTreeMap<u16, IfdClonedEntry> = BTreeMap::new();
        ifd.insert(
            TILEBYTECOUNTS,
            u32_strip_entry(TILEBYTECOUNTS, &byte_counts),
        );
        ifd.insert(TILEOFFSETS, u32_strip_entry(TILEOFFSETS, &offsets));

        let writer = Cursor::new(Vec::<u8>::new());
        let mut cloner = TiffCloner::new(Endianness::Little, false, writer).unwrap();
        let result = cloner.clone_image_data(&mut ifd, &mut asset_reader);

        assert!(
            matches!(&result, Err(Error::InvalidAsset(msg)) if msg.contains("exceed source length")),
            "expected InvalidAsset for over-cap tile byte counts, got {result:?}",
        );
    }

    // Happy path: strip byte counts that legitimately sum to <= source_len
    // must still copy successfully. Guards against a future refactor that
    // makes the cap too strict.
    #[test]
    fn clone_image_data_accepts_valid_strip_byte_counts() {
        let mut asset_reader = Cursor::new(vec![0xaau8; 100]);

        // 5 strips × 10 bytes = 50 bytes, well within 100.
        let byte_counts: Vec<u32> = vec![10u32; 5];
        let offsets: Vec<u32> = vec![0u32; 5];

        let mut ifd: BTreeMap<u16, IfdClonedEntry> = BTreeMap::new();
        ifd.insert(
            STRIPBYTECOUNTS,
            u32_strip_entry(STRIPBYTECOUNTS, &byte_counts),
        );
        ifd.insert(STRIPOFFSETS, u32_strip_entry(STRIPOFFSETS, &offsets));

        let writer = Cursor::new(Vec::<u8>::new());
        let mut cloner = TiffCloner::new(Endianness::Little, false, writer).unwrap();
        cloner
            .clone_image_data(&mut ifd, &mut asset_reader)
            .expect("valid strip byte counts should copy successfully");
    }

    // Unit test for the shared cap helper used by the strip, tile, and BigTable
    // copy loops. Covers the running-total accounting, the exceed-source-length
    // rejection (with the per-kind label), and the checked_add overflow guard.
    #[test]
    fn accumulate_copy_len_caps_and_labels() {
        // Accumulates within the cap.
        let mut copied = 0u64;
        accumulate_copy_len(&mut copied, 40, 100, "strip").expect("within cap");
        accumulate_copy_len(&mut copied, 60, 100, "strip").expect("exactly at cap");
        assert_eq!(copied, 100);

        // One more byte exceeds the source length and is rejected with the label.
        let err = accumulate_copy_len(&mut copied, 1, 100, "tile").unwrap_err();
        assert!(
            matches!(&err, Error::InvalidAsset(msg)
                if msg.contains("tile") && msg.contains("exceed source length")),
            "got {err:?}",
        );

        // A count that overflows the u64 running total is rejected too.
        let mut copied = u64::MAX;
        let err = accumulate_copy_len(&mut copied, 1, u64::MAX, "BigTable").unwrap_err();
        assert!(
            matches!(&err, Error::InvalidAsset(msg)
                if msg.contains("BigTable") && msg.contains("overflow")),
            "got {err:?}",
        );
    }

    /*  disable until I find smaller DNG
    #[test]
    fn test_read_write_dng_manifest() {
        let data = "some data";

        let source = crate::utils::test::fixture_path("test.DNG");
        //let source = crate::utils::test::fixture_path("sample1.dng");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "test.DNG");

        std::fs::copy(&source, &output).unwrap();

        let tiff_io = TiffIO {};

        // save data to tiff
        tiff_io.save_cai_store(&output, data.as_bytes()).unwrap();

        // read data back
        println!("Reading TIFF");
        let loaded = tiff_io.read_cai_store(&output).unwrap();

        assert_eq!(&loaded, data.as_bytes());
    }
    #[test]
    fn test_read_write_dng_parse() {
        //let data = "some data";

        let source = crate::utils::test::fixture_path("test.DNG");
        let mut f = std::fs::File::open(&source).unwrap();

        let (idfs, token, _endianness, _big_tiff) = map_tiff(&mut f).unwrap();

        println!("IFD {}", idfs[token].data.entry_cnt);
    }
    */
}
