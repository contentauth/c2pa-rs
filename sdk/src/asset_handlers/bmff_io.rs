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
    cmp::min,
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
};

use atree::{Arena, Token};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::{
    assertions::{BmffMerkleMap, ExclusionsMap},
    asset_io::{
        rename_or_move, AssetIO, AssetPatch, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        HashObjectPositions, RemoteRefEmbed, RemoteRefEmbedType,
    },
    error::{Error, Result},
    status_tracker::{ErrorBehavior, StatusTracker},
    store::Store,
    utils::{
        hash_utils::{vec_compare, HashRange},
        io_utils::{patch_stream, stream_len, tempfile_builder, ReaderUtils},
        patch::patch_bytes,
        xmp_inmemory_utils::{add_provenance, MIN_XMP},
    },
};

pub struct BmffIO {
    #[allow(dead_code)]
    bmff_format: String, // can be used for specialized BMFF cases
}

const MAX_BOX_DEPTH: usize = 32; // reasonable BMFF box depth, to prevent stack overflow

const HEADER_SIZE: u64 = 8; // 4 byte type + 4 byte size
const HEADER_SIZE_LARGE: u64 = 16; // 4 byte type + 4 byte size + 8 byte large size

const C2PA_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];
const XMP_UUID: [u8; 16] = [
    0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac,
];
pub(crate) const MANIFEST: &str = "manifest";
pub(crate) const MERKLE: &str = "merkle";
const ORIGINAL: &str = "original";
const UPDATE: &str = "update";

// ISO IEC 14496-12_2022 FullBoxes
const FULL_BOX_TYPES: &[&str; 80] = &[
    "pdin", "mvhd", "tkhd", "mdhd", "hdlr", "nmhd", "elng", "stsd", "stdp", "stts", "ctts", "cslg",
    "stss", "stsh", "stdp", "elst", "dref", "stsz", "stz2", "stsc", "stco", "co64", "padb", "subs",
    "saiz", "saio", "mehd", "trex", "mfhd", "tfhd", "trun", "tfra", "mfro", "tfdt", "leva", "trep",
    "assp", "sbgp", "sgpd", "csgp", "cprt", "tsel", "kind", "meta", "xml ", "bxml", "iloc", "pitm",
    "ipro", "infe", "iinf", "iref", "ipma", "schm", "fiin", "fpar", "fecr", "gitn", "fire", "stri",
    "stsg", "stvi", "csch", "sidx", "ssix", "prft", "srpp", "vmhd", "smhd", "srat", "chnl", "dmix",
    "txtC", "mime", "uri ", "uriI", "hmhd", "sthd", "vvhd", "medc",
];

static SUPPORTED_TYPES: [&str; 15] = [
    "avif",
    "heif",
    "heic",
    "mp4",
    "m4a",
    "mov",
    "m4v",
    "application/mp4",
    "audio/mp4",
    "image/avif",
    "image/heic",
    "image/heif",
    "video/mp4",
    "video/quicktime",
    "video/x-m4v",
];

macro_rules! boxtype {
    ($( $name:ident => $value:expr ),*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum BoxType {
            $( $name, )*
            UnknownBox(u32),
        }

        impl From<u32> for BoxType {
            fn from(t: u32) -> BoxType {
                match t {
                    $( $value => BoxType::$name, )*
                    _ => BoxType::UnknownBox(t),
                }
            }
        }

        impl From<BoxType> for u32 {
            fn from(t: BoxType) -> u32 {
                match t {
                    $( BoxType::$name => $value, )*
                    BoxType::UnknownBox(t) => t,
                }
            }
        }
    }
}

boxtype! {
    Empty => 0x0000_0000,
    UuidBox => 0x75756964,
    FtypBox => 0x66747970,
    MvhdBox => 0x6d766864,
    MfhdBox => 0x6d666864,
    FreeBox => 0x66726565,
    MdatBox => 0x6d646174,
    MoovBox => 0x6d6f6f76,
    MvexBox => 0x6d766578,
    MehdBox => 0x6d656864,
    TrexBox => 0x74726578,
    EmsgBox => 0x656d7367,
    MoofBox => 0x6d6f6f66,
    TkhdBox => 0x746b6864,
    TfhdBox => 0x74666864,
    EdtsBox => 0x65647473,
    MdiaBox => 0x6d646961,
    ElstBox => 0x656c7374,
    MfraBox => 0x6d667261,
    MdhdBox => 0x6d646864,
    HdlrBox => 0x68646c72,
    MinfBox => 0x6d696e66,
    VmhdBox => 0x766d6864,
    StblBox => 0x7374626c,
    StsdBox => 0x73747364,
    SttsBox => 0x73747473,
    CttsBox => 0x63747473,
    StssBox => 0x73747373,
    StscBox => 0x73747363,
    StszBox => 0x7374737A,
    StcoBox => 0x7374636F,
    Co64Box => 0x636F3634,
    TrakBox => 0x7472616b,
    TrafBox => 0x74726166,
    TrefBox => 0x74726566,
    TregBox => 0x74726567,
    TrunBox => 0x7472756E,
    UdtaBox => 0x75647461,
    DinfBox => 0x64696e66,
    DrefBox => 0x64726566,
    UrlBox  => 0x75726C20,
    SmhdBox => 0x736d6864,
    Avc1Box => 0x61766331,
    AvcCBox => 0x61766343,
    Hev1Box => 0x68657631,
    HvcCBox => 0x68766343,
    Mp4aBox => 0x6d703461,
    EsdsBox => 0x65736473,
    Tx3gBox => 0x74783367,
    VpccBox => 0x76706343,
    Vp09Box => 0x76703039,
    MetaBox => 0x6D657461,
    SchiBox => 0x73636869,
    IlocBox => 0x696C6F63,
    MfroBox => 0x6d66726f,
    TfraBox => 0x74667261,
    SaioBox => 0x7361696f
}

struct BoxHeaderLite {
    pub name: BoxType,
    pub size: u64,
    pub fourcc: String,
    pub large_size: bool,
}

impl BoxHeaderLite {
    pub fn new(name: BoxType, size: u64, fourcc: &str) -> Self {
        Self {
            name,
            size,
            fourcc: fourcc.to_string(),
            large_size: false,
        }
    }

    pub fn read<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<Self> {
        let box_start = reader.stream_position()?;

        // Create and read to buf.
        let mut buf = [0u8; 8]; // 8 bytes for box header.
        reader.read_exact(&mut buf)?;

        // Get size.
        let mut s = [0u8; 4];
        s.clone_from_slice(&buf[0..4]);
        let size = u32::from_be_bytes(s);

        // Get box type string.
        let mut t = [0u8; 4];
        t.clone_from_slice(&buf[4..8]);
        let fourcc = String::from_utf8_lossy(&buf[4..8]).to_string();
        let typ = u32::from_be_bytes(t);

        // Get largesize if size is 1
        if size == 1 {
            reader.read_exact(&mut buf)?;
            let largesize = u64::from_be_bytes(buf);

            Ok(BoxHeaderLite {
                name: BoxType::from(typ),
                size: largesize,
                fourcc,
                large_size: true,
            })
        } else if size == 0 {
            // special case to indicate the size goes to the end of the file
            let end_of_stream = stream_len(reader)?;
            let actual_size = end_of_stream - box_start;

            Ok(BoxHeaderLite {
                name: BoxType::from(typ),
                size: actual_size,
                fourcc,
                large_size: false,
            })
        } else {
            Ok(BoxHeaderLite {
                name: BoxType::from(typ),
                size: size as u64,
                fourcc,
                large_size: false,
            })
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> Result<u64> {
        if self.size > u32::MAX as u64 {
            writer.write_u32::<BigEndian>(1)?;
            writer.write_u32::<BigEndian>(self.name.into())?;
            writer.write_u64::<BigEndian>(self.size)?;
            Ok(16)
        } else {
            writer.write_u32::<BigEndian>(self.size as u32)?;
            writer.write_u32::<BigEndian>(self.name.into())?;
            Ok(8)
        }
    }
}

fn write_box_uuid_extension<W: Write>(w: &mut W, uuid: &[u8; 16]) -> Result<u64> {
    w.write_all(uuid)?;
    Ok(16)
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BoxInfo {
    path: String,
    parent: Option<Token>,
    pub offset: u64,
    pub size: u64,
    box_type: BoxType,
    user_type: Option<Vec<u8>>,
    version: Option<u8>,
    flags: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BoxInfoLite {
    pub path: String,
    pub offset: u64,
    pub size: u64,
}

impl BoxInfoLite {
    pub fn start(&self) -> u64 {
        self.offset
    }

    pub fn end(&self) -> u64 {
        self.offset + self.size
    }

    pub fn size(&self) -> u64 {
        self.size
    }
}

fn read_box_header_ext<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<(u8, u32)> {
    let version = reader.read_u8()?;
    let flags = reader.read_u24::<BigEndian>()?;
    Ok((version, flags))
}
fn write_box_header_ext<W: Write>(w: &mut W, v: u8, f: u32) -> Result<u64> {
    w.write_u8(v)?;
    w.write_u24::<BigEndian>(f)?;
    Ok(4)
}

/// Detect if a `meta` box uses FullBox format (ISO BMFF) or regular box format (QuickTime mov).
///
/// In ISO BMFF (ISO 14496-12), `meta` is a FullBox with 4 bytes of version/flags before its children. 
/// In Apple QuickTime MOV files, `meta` is a regular box where children start immediately after the 8-byte header.
///
/// THis tries to detect that by peeking at the 8 bytes right after the header:
/// - If they form a valid child box header it's a regular box (QuickTime style).
/// - Otherwise, the first 4 bytes are version/flags (ISO BMFF style).
fn is_meta_full_box<R: Read + Seek + ?Sized>(reader: &mut R, box_size: u64) -> Result<bool> {
    let pos = reader.stream_position()?;
    let mut buf = [0u8; 8];

    if reader.read_exact(&mut buf).is_err() {
        reader.seek(SeekFrom::Start(pos))?;
        return Ok(true); // fallback to FullBox if we can't read enough bytes
    }
    reader.seek(SeekFrom::Start(pos))?;

    // Interpret first 4 bytes as a potential child box size
    let potential_child_size = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
    // Interpret next 4 bytes as a potential child box fourcc
    let potential_child_type = &buf[4..8];

    // A valid fourcc consists of printable ASCII characters
    let is_valid_fourcc = potential_child_type
        .iter()
        .all(|&b| (0x20..=0x7E).contains(&b));

    // Check if this looks like a valid child box header (QuickTime style):
    // - size > 0 and fits within the remaining container space
    // - fourcc is printable ASCII
    if potential_child_size > 0 && potential_child_size <= box_size && is_valid_fourcc {
        Ok(false) // QuickTime style: children start right after the 8-byte header
    } else {
        Ok(true) // ISO BMFF style: 4 bytes of version/flags first
    }
}

fn box_start<R: Read + Seek + ?Sized>(reader: &mut R, is_large: bool) -> Result<u64> {
    if is_large {
        Ok(reader.stream_position()? - HEADER_SIZE_LARGE)
    } else {
        Ok(reader.stream_position()? - HEADER_SIZE)
    }
}

fn _skip_bytes<R: Read + Seek + ?Sized>(reader: &mut R, size: u64) -> Result<()> {
    reader.seek(SeekFrom::Current(size as i64))?;
    Ok(())
}

fn skip_bytes_to<R: Read + Seek + ?Sized>(reader: &mut R, pos: u64) -> Result<u64> {
    let pos = reader.seek(SeekFrom::Start(pos))?;
    Ok(pos)
}

pub(crate) fn write_c2pa_box<W: Write>(
    w: &mut W,
    data: &[u8],
    purpose: &str,
    merkle_data: &[u8],
    merkle_offset: u64,
) -> Result<()> {
    let purpose_size = purpose.len() + 1;

    let box_size = if purpose == MERKLE {
        merkle_data.len()
    } else {
        8
    };
    let size = 8 + 16 + 4 + purpose_size + box_size + data.len(); // header + UUID + version/flags + data + zero terminated purpose + merkle data
    let bh = BoxHeaderLite::new(BoxType::UuidBox, size as u64, "uuid");

    // write out header
    bh.write(w)?;

    // write out c2pa extension UUID
    write_box_uuid_extension(w, &C2PA_UUID)?;

    // write out version and flags
    let version: u8 = 0;
    let flags: u32 = 0;
    write_box_header_ext(w, version, flags)?;

    // write with appropriate purpose
    w.write_all(purpose.as_bytes())?;
    w.write_u8(0)?;
    if purpose == MERKLE {
        // write merkle cbor
        w.write_all(merkle_data)?;
    } else {
        // write merkle offset
        w.write_u64::<BigEndian>(merkle_offset)?;
    }

    // write out data
    w.write_all(data)?;

    Ok(())
}

fn write_xmp_box<W: Write>(w: &mut W, data: &[u8]) -> Result<()> {
    let size = 8 + 16 + data.len(); // header + UUID + data
    let bh = BoxHeaderLite::new(BoxType::UuidBox, size as u64, "uuid");

    // write out header
    bh.write(w)?;

    // write out XMP extension UUID
    write_box_uuid_extension(w, &XMP_UUID)?;

    // write out data
    w.write_all(data)?;

    Ok(())
}

fn _write_free_box<W: Write>(w: &mut W, size: usize) -> Result<()> {
    if size < 8 {
        return Err(Error::BadParam("cannot adjust free space".to_string()));
    }

    let zeros = vec![0u8; size - 8];
    let bh = BoxHeaderLite::new(BoxType::FreeBox, size as u64, "free");

    // write out header
    bh.write(w)?;

    // write out header
    w.write_all(&zeros)?;

    Ok(())
}

fn add_token_to_cache(bmff_path_map: &mut HashMap<String, Vec<Token>>, path: String, token: Token) {
    if let Some(token_list) = bmff_path_map.get_mut(&path) {
        token_list.push(token);
    } else {
        let token_list = vec![token];
        bmff_path_map.insert(path, token_list);
    }
}

fn path_from_token(bmff_tree: &Arena<BoxInfo>, current_node_token: &Token) -> Result<String> {
    let ancestors = current_node_token.ancestors(bmff_tree);
    let mut path = bmff_tree[*current_node_token].data.path.clone();

    for parent in ancestors {
        path = format!("{}/{}", parent.data.path, path);
    }

    if path.is_empty() {
        path = "/".to_string();
    }

    Ok(path)
}

fn get_top_level_box_offsets(
    bmff_tree: &Arena<BoxInfo>,
    bmff_path_map: &HashMap<String, Vec<Token>>,
) -> Vec<u64> {
    let mut tl_offsets = Vec::new();

    for (p, t) in bmff_path_map {
        // look for top level offsets
        if p.matches('/').count() == 1 {
            for token in t {
                if let Some(box_info) = bmff_tree.get(*token) {
                    tl_offsets.push(box_info.data.offset);
                }
            }
        }
    }

    tl_offsets
}

fn get_top_level_boxes(
    bmff_tree: &Arena<BoxInfo>,
    bmff_path_map: &HashMap<String, Vec<Token>>,
) -> Vec<BoxInfoLite> {
    let mut tl_boxes = Vec::new();

    for (p, t) in bmff_path_map {
        // look for top level offsets
        if p.matches('/').count() == 1 {
            for token in t {
                if let Some(box_info) = bmff_tree.get(*token) {
                    tl_boxes.push(BoxInfoLite {
                        path: box_info.data.path.clone(),
                        offset: box_info.data.offset,
                        size: box_info.data.size,
                    });
                }
            }
        }
    }

    tl_boxes
}

pub fn bmff_to_jumbf_exclusions<R>(
    mut reader: &mut R,
    bmff_exclusions: &[ExclusionsMap],
    bmff_v2: bool,
) -> Result<Vec<HashRange>>
where
    R: Read + Seek + ?Sized,
{
    let size = stream_len(reader)?;
    reader.rewind()?;

    // create root node
    let root_box = BoxInfo {
        path: "".to_string(),
        offset: 0,
        size,
        box_type: BoxType::Empty,
        parent: None,
        user_type: None,
        version: None,
        flags: None,
    };

    let (mut bmff_tree, root_token) = Arena::with_data(root_box);
    let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

    // build layout of the BMFF structure
    let mut rl = 0usize;
    build_bmff_tree(
        reader,
        size,
        &mut bmff_tree,
        &root_token,
        &mut bmff_map,
        &mut rl,
    )?;

    // get top level box offsets
    let mut tl_offsets = get_top_level_box_offsets(&bmff_tree, &bmff_map);
    tl_offsets.sort();

    let mut exclusions = Vec::new();

    for bmff_exclusion in bmff_exclusions {
        if let Some(box_token_list) = bmff_map.get(&bmff_exclusion.xpath) {
            for box_token in box_token_list {
                let box_info = &bmff_tree[*box_token].data;

                let box_start = box_info.offset;
                let box_length = box_info.size;

                let exclusion_start = box_start;
                let exclusion_length = box_length;

                // adjust exclusion bounds as needed

                // check the length
                if let Some(desired_length) = bmff_exclusion.length {
                    if desired_length != box_length {
                        continue;
                    }
                }

                // check the version
                if let Some(desired_version) = bmff_exclusion.version {
                    if let Some(box_version) = box_info.version {
                        if desired_version != box_version {
                            continue;
                        }
                    }
                }

                // check the flags
                if let Some(desired_flag_bytes) = &bmff_exclusion.flags {
                    let mut temp_bytes = [0u8; 4];
                    if desired_flag_bytes.len() >= 3 {
                        temp_bytes[0] = desired_flag_bytes[0];
                        temp_bytes[1] = desired_flag_bytes[1];
                        temp_bytes[2] = desired_flag_bytes[2];
                    }
                    let desired_flags = u32::from_be_bytes(temp_bytes);

                    if let Some(box_flags) = box_info.flags {
                        let exact = bmff_exclusion.exact.unwrap_or(true);

                        if exact {
                            if desired_flags != box_flags {
                                continue;
                            }
                        } else {
                            // bitwise match
                            if (desired_flags | box_flags) != desired_flags {
                                continue;
                            }
                        }
                    }
                }

                // check data match
                if let Some(data_map_vec) = &bmff_exclusion.data {
                    let mut should_add = true;

                    for data_map in data_map_vec {
                        // move to the start of exclusion
                        skip_bytes_to(reader, box_start + data_map.offset)?;

                        // match the data
                        let buf = reader.read_to_vec(data_map.value.len() as u64)?;

                        // does not match so skip
                        if !vec_compare(&data_map.value, &buf) {
                            should_add = false;
                            break;
                        }
                    }
                    if !should_add {
                        continue;
                    }
                }

                // reduce range if desired
                if let Some(subset_vec) = &bmff_exclusion.subset {
                    for subset in subset_vec {
                        // if the subset offset is past the end of the box, skip
                        if subset.offset > exclusion_length {
                            continue;
                        }

                        let new_start = exclusion_start + subset.offset;
                        let new_length = if subset.length == 0 {
                            exclusion_length - subset.offset
                        } else {
                            min(subset.length, exclusion_length - subset.offset)
                        };

                        let exclusion = HashRange::new(new_start, new_length);

                        exclusions.push(exclusion);
                    }
                } else {
                    // exclude box in its entirty
                    let exclusion = HashRange::new(exclusion_start, exclusion_length);

                    exclusions.push(exclusion);

                    // for BMFF V2 hashes we do not add hash offsets for top level boxes
                    // that are completely excluded, so remove from BMFF V2 hash offset calc
                    if let Some(pos) = tl_offsets.iter().position(|x| *x == exclusion_start) {
                        tl_offsets.remove(pos);
                    }
                }
            }
        }
    }

    // add remaining top level offsets to be included when generating BMFF V2 hashes
    // note: this is technically not an exclusion but a replacement with a new range of bytes to be hashed
    if bmff_v2 {
        for tl_start in tl_offsets {
            let mut exclusion = HashRange::new(tl_start, 1u64);
            exclusion.set_bmff_offset(tl_start);

            exclusions.push(exclusion);
        }
    }

    Ok(exclusions)
}

// `iloc`, `stco`, `co64`, `mfro`, `saio`, `sidx`, `tdhd`, and `tfra` elements contain absolute file offsets so they need to be adjusted based on whether content was added or removed.
fn adjust_known_offsets<W: Write + CAIRead + ?Sized>(
    mut output: &mut W,
    bmff_tree: &Arena<BoxInfo>,
    bmff_path_map: &HashMap<String, Vec<Token>>,
    adjust: i32,
) -> Result<()> {
    let start_pos = output.stream_position()?; // save starting point

    // handle 32 bit offsets
    if let Some(stco_list) = bmff_path_map.get("/moov/trak/mdia/minf/stbl/stco") {
        for stco_token in stco_list {
            let stco_box_info = &bmff_tree[*stco_token].data;
            if stco_box_info.box_type != BoxType::StcoBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read stco box and patch
            output.seek(SeekFrom::Start(stco_box_info.offset))?;

            // read header
            let header = BoxHeaderLite::read(output)
                .map_err(|_err| Error::InvalidAsset("Bad BMFF".to_string()))?;
            if header.name != BoxType::StcoBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read extended header
            let (_version, _flags) = read_box_header_ext(output)?; // box extensions

            // get count of offsets
            let entry_count = output.read_u32::<BigEndian>()?;

            // read and patch offsets
            let entry_start_pos = output.stream_position()?;
            let mut entries: Vec<u32> = Vec::new();
            for _e in 0..entry_count {
                let offset = output.read_u32::<BigEndian>()?;
                let new_offset = if adjust < 0 {
                    offset
                        - u32::try_from(adjust.abs()).map_err(|_| {
                            Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                        })?
                } else {
                    offset
                        + u32::try_from(adjust).map_err(|_| {
                            Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                        })?
                };
                entries.push(new_offset);
            }

            // write updated offsets
            output.seek(SeekFrom::Start(entry_start_pos))?;
            for e in entries {
                output.write_u32::<BigEndian>(e)?;
            }
        }
    }

    // handle 64 offsets
    if let Some(co64_list) = bmff_path_map.get("/moov/trak/mdia/minf/stbl/co64") {
        for co64_token in co64_list {
            let co64_box_info = &bmff_tree[*co64_token].data;
            if co64_box_info.box_type != BoxType::Co64Box {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read co64 box and patch
            output.seek(SeekFrom::Start(co64_box_info.offset))?;

            // read header
            let header = BoxHeaderLite::read(output)
                .map_err(|_err| Error::InvalidAsset("Bad BMFF".to_string()))?;
            if header.name != BoxType::Co64Box {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read extended header
            let (_version, _flags) = read_box_header_ext(output)?; // box extensions

            // get count of offsets
            let entry_count = output.read_u32::<BigEndian>()?;

            // read and patch offsets
            let entry_start_pos = output.stream_position()?;
            let mut entries: Vec<u64> = Vec::new();
            for _e in 0..entry_count {
                let offset = output.read_u64::<BigEndian>()?;
                let new_offset = if adjust < 0 {
                    offset
                        - u64::try_from(adjust.abs()).map_err(|_| {
                            Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                        })?
                } else {
                    offset
                        + u64::try_from(adjust).map_err(|_| {
                            Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                        })?
                };
                entries.push(new_offset);
            }

            // write updated offsets
            output.seek(SeekFrom::Start(entry_start_pos))?;
            for e in entries {
                output.write_u64::<BigEndian>(e)?;
            }
        }
    }

    // handle meta iloc
    if let Some(iloc_list) = bmff_path_map.get("/meta/iloc") {
        for iloc_token in iloc_list {
            let iloc_box_info = &bmff_tree[*iloc_token].data;
            if iloc_box_info.box_type != BoxType::IlocBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read iloc box and patch
            output.seek(SeekFrom::Start(iloc_box_info.offset))?;

            // read header
            let header = BoxHeaderLite::read(output)
                .map_err(|_err| Error::InvalidAsset("Bad BMFF".to_string()))?;
            if header.name != BoxType::IlocBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read extended header
            let (version, _flags) = read_box_header_ext(output)?; // box extensions

            // read next 16 bits (in file byte order)
            let mut iloc_header = [0u8, 2];
            output.read_exact(&mut iloc_header)?;

            // get offset size (high nibble)
            let offset_size: u8 = (iloc_header[0] & 0xf0) >> 4;

            // get length size (low nibble)
            let length_size: u8 = iloc_header[0] & 0x0f;

            // get box offset size (high nibble)
            let base_offset_size: u8 = (iloc_header[1] & 0xf0) >> 4;

            // get index size (low nibble)
            let index_size: u8 = iloc_header[1] & 0x0f;

            // get item count
            let item_count = match version {
                _v if version < 2 => output.read_u16::<BigEndian>()? as u32,
                _v if version == 2 => output.read_u32::<BigEndian>()?,
                _ => {
                    return Err(Error::InvalidAsset(
                        "Bad BMFF unknown iloc format".to_string(),
                    ))
                }
            };

            // walk the iloc items and patch
            for _i in 0..item_count {
                // read item id
                let _item_id = match version {
                    _v if version < 2 => output.read_u16::<BigEndian>()? as u32,
                    2 => output.read_u32::<BigEndian>()?,
                    _ => {
                        return Err(Error::InvalidAsset(
                            "Bad BMFF: unknown iloc item".to_string(),
                        ))
                    }
                };

                // read construction method
                let construction_method = if version == 1 || version == 2 {
                    let mut cm_bytes = [0u8, 2];
                    output.read_exact(&mut cm_bytes)?;

                    // lower nibble of 2nd byte
                    cm_bytes[1] & 0x0f
                } else {
                    0
                };

                // read data reference index
                let _data_reference_index = output.read_u16::<BigEndian>()?;

                let base_offset_file_pos = output.stream_position()?;
                let base_offset = match base_offset_size {
                    0 => 0_u64,
                    4 => output.read_u32::<BigEndian>()? as u64,
                    8 => output.read_u64::<BigEndian>()?,
                    _ => {
                        return Err(Error::InvalidAsset(
                            "Bad BMFF: unknown iloc offset size".to_string(),
                        ))
                    }
                };

                // patch the offsets if needed
                if construction_method == 0 {
                    // file offset construction method
                    if base_offset_size == 4 {
                        let new_offset = if adjust < 0 {
                            u32::try_from(base_offset).map_err(|_| {
                                Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                            })? - u32::try_from(adjust.abs()).map_err(|_| {
                                Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                            })?
                        } else {
                            u32::try_from(base_offset).map_err(|_| {
                                Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                            })? + u32::try_from(adjust).map_err(|_| {
                                Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                            })?
                        };

                        output.seek(SeekFrom::Start(base_offset_file_pos))?;
                        output.write_u32::<BigEndian>(new_offset)?;
                    }

                    if base_offset_size == 8 {
                        let new_offset = if adjust < 0 {
                            base_offset
                                - u64::try_from(adjust.abs()).map_err(|_| {
                                    Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                                })?
                        } else {
                            base_offset
                                + u64::try_from(adjust).map_err(|_| {
                                    Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                                })?
                        };

                        output.seek(SeekFrom::Start(base_offset_file_pos))?;
                        output.write_u64::<BigEndian>(new_offset)?;
                    }
                }

                // read extent count
                let extent_count = output.read_u16::<BigEndian>()?;

                // consume the extents
                for _e in 0..extent_count {
                    let _extent_index = if version == 1 || (version == 2 && index_size > 0) {
                        match base_offset_size {
                            4 => Some(output.read_u32::<BigEndian>()? as u64),
                            8 => Some(output.read_u64::<BigEndian>()?),
                            _ => None,
                        }
                    } else {
                        None
                    };

                    let extent_offset_file_pos = output.stream_position()?;
                    let extent_offset = match offset_size {
                        0 => 0_u64,
                        4 => output.read_u32::<BigEndian>()? as u64,
                        8 => output.read_u64::<BigEndian>()?,
                        _ => {
                            return Err(Error::InvalidAsset(
                                "Bad BMFF: unknown iloc extent_offset size".to_string(),
                            ))
                        }
                    };

                    // no base offset so just adjust the raw extent_offset value
                    if construction_method == 0 && base_offset == 0 && extent_offset != 0 {
                        output.seek(SeekFrom::Start(extent_offset_file_pos))?;
                        match offset_size {
                            4 => {
                                let new_offset = if adjust < 0 {
                                    extent_offset as u32
                                        - u32::try_from(adjust.abs()).map_err(|_| {
                                            Error::InvalidAsset(
                                                "Bad BMFF offset adjustment".to_string(),
                                            )
                                        })?
                                } else {
                                    extent_offset as u32
                                        + u32::try_from(adjust).map_err(|_| {
                                            Error::InvalidAsset(
                                                "Bad BMFF offset adjustment".to_string(),
                                            )
                                        })?
                                };
                                output.write_u32::<BigEndian>(new_offset)?;
                            }
                            8 => {
                                let new_offset = if adjust < 0 {
                                    extent_offset
                                        - u64::try_from(adjust.abs()).map_err(|_| {
                                            Error::InvalidAsset(
                                                "Bad BMFF offset adjustment".to_string(),
                                            )
                                        })?
                                } else {
                                    extent_offset
                                        + u64::try_from(adjust).map_err(|_| {
                                            Error::InvalidAsset(
                                                "Bad BMFF offset adjustment".to_string(),
                                            )
                                        })?
                                };
                                output.write_u64::<BigEndian>(new_offset)?;
                            }
                            _ => {
                                return Err(Error::InvalidAsset(
                                    "Bad BMFF: unknown extent_offset format".to_string(),
                                ))
                            }
                        }
                    }

                    let _extent_length = match length_size {
                        0 => 0_u64,
                        4 => output.read_u32::<BigEndian>()? as u64,
                        8 => output.read_u64::<BigEndian>()?,
                        _ => {
                            return Err(Error::InvalidAsset(
                                "Bad BMFF: unknown iloc offset size".to_string(),
                            ))
                        }
                    };
                }
            }
        }
    }

    // map to store track to moof mapping
    let mut track_id_to_moof_mapping = HashMap::new();

    // handle moof traf tfhd
    if let Some(tfhd_list) = bmff_path_map.get("/moof/traf/tfhd") {
        for tfhd_token in tfhd_list {
            let tfhd_box_info = &bmff_tree[*tfhd_token].data;
            if tfhd_box_info.box_type != BoxType::TfhdBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read box and patch
            output.seek(SeekFrom::Start(tfhd_box_info.offset))?;

            // read header
            let header = BoxHeaderLite::read(output)
                .map_err(|_err| Error::InvalidAsset("Bad BMFF".to_string()))?;
            if header.name != BoxType::TfhdBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read extended header
            let (_version, tf_flags) = read_box_header_ext(output)?; // box extensions

            // track ID
            let track_id = output.read_u32::<BigEndian>()?;

            // get to outter moof box
            let ancestors = tfhd_token.ancestors(bmff_tree);
            for ancestor in ancestors {
                if ancestor.data.path == "moof" {
                    track_id_to_moof_mapping.insert(track_id, ancestor.data.offset);
                }
            }

            // fix up base offset and write out if flags indicate to do so
            if tf_flags & 1 == 1 {
                let base_data_offset_pos = output.stream_position()?;
                let mut base_data_offset = output.read_u64::<BigEndian>()?;

                base_data_offset = if adjust < 0 {
                    base_data_offset
                        - u64::try_from(adjust.abs()).map_err(|_| {
                            Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                        })?
                } else {
                    base_data_offset
                        + u64::try_from(adjust).map_err(|_| {
                            Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                        })?
                };

                output.seek(SeekFrom::Start(base_data_offset_pos))?;
                output.write_u64::<BigEndian>(base_data_offset)?;
            }

            // ignore rest of fields
        }
    }

    // handle mfra tfra
    if let Some(tfra_list) = bmff_path_map.get("/mfra/tfra") {
        for tfra_token in tfra_list {
            let tfra_box_info = &bmff_tree[*tfra_token].data;
            if tfra_box_info.box_type != BoxType::TfraBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read iloc box and patch
            output.seek(SeekFrom::Start(tfra_box_info.offset))?;

            // read header
            let header = BoxHeaderLite::read(output)
                .map_err(|_err| Error::InvalidAsset("Bad BMFF".to_string()))?;
            if header.name != BoxType::TfraBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read extended header
            let (version, _flags) = read_box_header_ext(output)?; // box extensions

            // track ID
            let track_id = output.read_u32::<BigEndian>()?;

            // tfr flags
            let tfra_info = output.read_u32::<BigEndian>()?;
            let length_size_of_traf_num = (tfra_info >> 4) & 0x03;
            let length_size_of_trun_num = (tfra_info >> 2) & 0x03;
            let length_size_of_sample_num = tfra_info & 0x03;

            // num entries
            let num_entries = output.read_u32::<BigEndian>()?;

            // get the moof boxes
            // fix up the offsets in the entry list
            for _entries in 0..num_entries {
                if version == 1 {
                    let _time = output.read_u64::<BigEndian>()?;

                    // write out mapped value of the moof position for this track
                    let moof_offset = track_id_to_moof_mapping
                        .get(&track_id)
                        .ok_or(Error::InvalidAsset("Bad BMFF".to_string()))?;
                    output.write_u64::<BigEndian>(*moof_offset)?;
                } else {
                    let _time = output.read_u32::<BigEndian>()?;

                    // write out mapped value of the moof position for this track
                    let moof_offset_u64 = track_id_to_moof_mapping
                        .get(&track_id)
                        .ok_or(Error::InvalidAsset("Bad BMFF".to_string()))?;

                    let moof_offset = u32::try_from(*moof_offset_u64).map_err(|_e| {
                        Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                    })?;
                    output.write_u32::<BigEndian>(moof_offset)?;
                }

                // read extra stuff to move the position
                let traf_num_bytes = length_size_of_traf_num + 1;
                output.read_to_vec(traf_num_bytes as u64)?;
                let trun_num_bytes = length_size_of_trun_num + 1;
                output.read_to_vec(trun_num_bytes as u64)?;
                let sample_num_bytes = length_size_of_sample_num + 1;
                output.read_to_vec(sample_num_bytes as u64)?;
            }
        }
    }

    // handle moov trak mdia minf stbl saio
    if let Some(saio_list) = bmff_path_map.get("/moov/trak/mdia/minf/stbl/saio") {
        for saio_token in saio_list {
            let saio_box_info = &bmff_tree[*saio_token].data;
            if saio_box_info.box_type != BoxType::SaioBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read saio box and patch
            output.seek(SeekFrom::Start(saio_box_info.offset))?;

            // read header
            let header = BoxHeaderLite::read(output)
                .map_err(|_err| Error::InvalidAsset("Bad BMFF".to_string()))?;
            if header.name != BoxType::SaioBox {
                return Err(Error::InvalidAsset("Bad BMFF".to_string()));
            }

            // read extended header
            let (version, flags) = read_box_header_ext(output)?; // box extensions
            if (flags & 1) == 1 {
                let _aux_info_type = output.read_u32::<BigEndian>()?;
                let _aux_info_type_parameter = output.read_u32::<BigEndian>()?;
            }

            // get count of offsets
            let entry_count = output.read_u32::<BigEndian>()?;

            // read and patch offsets
            let entry_start_pos = output.stream_position()?;
            let mut entries: Vec<u64> = Vec::new();
            for _e in 0..entry_count {
                if version == 0 {
                    let offset = output.read_u32::<BigEndian>()?;
                    let new_offset = if adjust < 0 {
                        offset
                            - u32::try_from(adjust.abs()).map_err(|_| {
                                Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                            })?
                    } else {
                        offset
                            + u32::try_from(adjust).map_err(|_| {
                                Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                            })?
                    };
                    entries.push(new_offset as u64);
                } else {
                    let offset = output.read_u64::<BigEndian>()?;
                    let new_offset = if adjust < 0 {
                        offset
                            - u64::try_from(adjust.abs()).map_err(|_| {
                                Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                            })?
                    } else {
                        offset
                            + u64::try_from(adjust).map_err(|_| {
                                Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                            })?
                    };
                    entries.push(new_offset);
                }
            }

            // write updated offsets
            output.seek(SeekFrom::Start(entry_start_pos))?;
            for e in entries {
                if version == 0 {
                    let e32 = u32::try_from(e).map_err(|_| {
                        Error::InvalidAsset("Bad BMFF offset adjustment".to_string())
                    })?;
                    output.write_u32::<BigEndian>(e32)?;
                } else {
                    output.write_u64::<BigEndian>(e)?;
                }
            }
        }
    }

    // restore seek point
    output.seek(SeekFrom::Start(start_pos))?;
    output.flush()?;

    Ok(())
}

pub(crate) fn build_bmff_tree<R: Read + Seek + ?Sized>(
    reader: &mut R,
    end: u64,
    bmff_tree: &mut Arena<BoxInfo>,
    current_node: &Token,
    bmff_path_map: &mut HashMap<String, Vec<Token>>,
    recursion_level: &mut usize,
) -> Result<()> {
    *recursion_level += 1;
    if *recursion_level > MAX_BOX_DEPTH {
        return Err(Error::InvalidAsset(
            "Boxes are too deply nested, unsupported asset".to_string(),
        ));
    }

    let start = reader.stream_position()?;
    let mut current = start;
    while current < end {
        // Get box header.
        let header = BoxHeaderLite::read(reader)
            .map_err(|err| Error::InvalidAsset(format!("Bad BMFF {err}")))?;

        // Break if size zero BoxHeader
        let s = header.size;
        if s == 0 {
            break;
        }

        if current + s > end {
            return Err(Error::InvalidAsset(
                "Box size extends beyond asset bounds".to_string(),
            ));
        }

        // Match and parse the supported atom boxes.
        match header.name {
            BoxType::UuidBox => {
                let start = box_start(reader, header.large_size)?;

                let mut extended_type = [0u8; 16]; // 16 bytes of UUID
                reader.read_exact(&mut extended_type)?;

                // if this is a C2PA UUID box it is a FullBox it has version and flags
                // so read those too
                let (version, flags) = if extended_type == C2PA_UUID {
                    let (v, f) = read_box_header_ext(reader)?;
                    (Some(v), Some(f))
                } else {
                    (None, None)
                };

                let b = BoxInfo {
                    path: header.fourcc.clone(),
                    offset: start,
                    size: s,
                    box_type: BoxType::UuidBox,
                    parent: Some(*current_node),
                    user_type: Some(extended_type.to_vec()),
                    version,
                    flags,
                };

                let new_token = current_node.append(bmff_tree, b);

                let path = path_from_token(bmff_tree, &new_token)?;
                add_token_to_cache(bmff_path_map, path, new_token);

                // position seek pointer
                skip_bytes_to(reader, start + s)?;
            }
            // container box types
            BoxType::MoovBox
            | BoxType::TrakBox
            | BoxType::MdiaBox
            | BoxType::MinfBox
            | BoxType::StblBox
            | BoxType::MoofBox
            | BoxType::TrafBox
            | BoxType::EdtsBox
            | BoxType::UdtaBox
            | BoxType::DinfBox
            | BoxType::TrefBox
            | BoxType::TregBox
            | BoxType::MvexBox
            | BoxType::MfraBox
            | BoxType::MetaBox
            | BoxType::SchiBox => {
                let start = box_start(reader, header.large_size)?;

                // Determine if this is a FullBox. For 'meta' boxes (Quicktime style), we need to
                // detect the format because  MOV uses regular box while ISO BMFF uses FullBox (with version/flags).
                let is_full_box = if header.name == BoxType::MetaBox {
                    is_meta_full_box(reader, s)?
                } else {
                    FULL_BOX_TYPES.contains(&header.fourcc.as_str())
                };

                let b = if is_full_box {
                    let (version, flags) = read_box_header_ext(reader)?; // box extensions
                    BoxInfo {
                        path: header.fourcc.clone(),
                        offset: start,
                        size: s,
                        box_type: header.name,
                        parent: Some(*current_node),
                        user_type: None,
                        version: Some(version),
                        flags: Some(flags),
                    }
                } else {
                    BoxInfo {
                        path: header.fourcc.clone(),
                        offset: start,
                        size: s,
                        box_type: header.name,
                        parent: Some(*current_node),
                        user_type: None,
                        version: None,
                        flags: None,
                    }
                };

                let new_token = bmff_tree.new_node(b);
                current_node
                    .append_node(bmff_tree, new_token)
                    .map_err(|_err| Error::InvalidAsset("Bad BMFF Graph".to_string()))?;

                let path = path_from_token(bmff_tree, &new_token)?;
                add_token_to_cache(bmff_path_map, path, new_token);

                // consume all sub-boxes
                let mut current = reader.stream_position()?;
                let end = start + s;
                while current < end {
                    build_bmff_tree(
                        reader,
                        end,
                        bmff_tree,
                        &new_token,
                        bmff_path_map,
                        recursion_level,
                    )?;
                    current = reader.stream_position()?;
                }

                // position seek pointer
                skip_bytes_to(reader, start + s)?;
            }
            _ => {
                let start = box_start(reader, header.large_size)?;

                let b = if FULL_BOX_TYPES.contains(&header.fourcc.as_str()) {
                    let (version, flags) = read_box_header_ext(reader)?; // box extensions
                    BoxInfo {
                        path: header.fourcc.clone(),
                        offset: start,
                        size: s,
                        box_type: header.name,
                        parent: Some(*current_node),
                        user_type: None,
                        version: Some(version),
                        flags: Some(flags),
                    }
                } else {
                    BoxInfo {
                        path: header.fourcc.clone(),
                        offset: start,
                        size: s,
                        box_type: header.name,
                        parent: Some(*current_node),
                        user_type: None,
                        version: None,
                        flags: None,
                    }
                };

                let new_token = current_node.append(bmff_tree, b);

                let path = path_from_token(bmff_tree, &new_token)?;
                add_token_to_cache(bmff_path_map, path, new_token);

                // position seek pointer
                skip_bytes_to(reader, start + s)?;
            }
        }
        current = reader.stream_position()?;
    }

    *recursion_level -= 1;

    Ok(())
}

fn get_uuid_box_purpose<R: Read + Seek + ?Sized>(
    reader: &mut R,
    box_info: &atree::Node<BoxInfo>,
) -> Result<(String, u64)> {
    if box_info.data.box_type == BoxType::UuidBox {
        let mut data_len = box_info.data.size - HEADER_SIZE - 16 /*UUID*/;

        // set reader to start of box contents
        skip_bytes_to(reader, box_info.data.offset + HEADER_SIZE + 16)?;

        // Fullbox => 8 bits for version 24 bits for flags
        let (_version, _flags) = read_box_header_ext(reader)?;
        data_len -= 4;

        // get the purpose
        let mut purpose_bytes = Vec::with_capacity(64);
        loop {
            let mut buf = [0; 1];
            reader.read_exact(&mut buf)?;
            data_len -= 1;
            if buf[0] == 0x00 {
                break;
            } else {
                purpose_bytes.push(buf[0]);
            }
        }

        let purpose = String::from_utf8_lossy(&purpose_bytes);

        return Ok((purpose.to_string(), data_len));
    }

    Err(Error::C2PAValidation(
        "C2PA UUID box does not contain a purpose".to_string(),
    ))
}

fn get_uuid_token(
    reader: &mut dyn CAIRead,
    bmff_tree: &Arena<BoxInfo>,
    bmff_map: &HashMap<String, Vec<Token>>,
    uuid: &[u8; 16],
    purpose: Option<&[&str]>,
) -> Result<Token> {
    if let Some(uuid_list) = bmff_map.get("/uuid") {
        for uuid_token in uuid_list {
            let box_info = &bmff_tree[*uuid_token];

            // make sure it is UUID box
            if box_info.data.box_type == BoxType::UuidBox {
                if let Some(found_uuid) = &box_info.data.user_type {
                    // make sure uuids match
                    if vec_compare(uuid, found_uuid) {
                        // if C2PA_UUID also check against purpose if present
                        if vec_compare(&C2PA_UUID, uuid) {
                            let (box_purpose, _) = get_uuid_box_purpose(reader, box_info)?;

                            // if there is a purpose, match it
                            if let Some(target_purposes) = purpose {
                                for target_purpose in target_purposes {
                                    if box_purpose == *target_purpose {
                                        return Ok(*uuid_token);
                                    }
                                }
                                continue;
                            }
                        }
                        return Ok(*uuid_token);
                    }
                }
            }
        }
    }
    Err(Error::NotFound)
}

#[allow(dead_code)]
pub(crate) struct C2PABmffBoxes {
    pub manifest_bytes: Option<Vec<u8>>,
    pub original_bytes: Option<Vec<u8>>,
    pub update_bytes: Option<Vec<u8>>,
    pub manifest_box_bytes: Option<Vec<u8>>,
    pub update_box_bytes: Option<Vec<u8>>,
    pub bmff_merkle: Vec<BmffMerkleMap>,
    pub bmff_merkle_box_infos: Vec<BoxInfoLite>,
    pub box_infos: Vec<BoxInfoLite>,
    pub xmp: Option<String>,
    pub manifest_box_offset: Option<u64>,
    pub update_box_offset: Option<u64>,
    pub first_aux_uuid_offset: u64,
    pub xmp_box_offset: u64,
    pub xmp_box_size: u64,
}

fn c2pa_boxes_from_tree_and_map<R: Read + Seek + ?Sized>(
    mut reader: &mut R,
    bmff_tree: &Arena<BoxInfo>,
    bmff_map: &HashMap<String, Vec<Token>>,
) -> Result<C2PABmffBoxes> {
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut original_bytes: Option<Vec<u8>> = None;
    let mut update_bytes: Option<Vec<u8>> = None;
    let mut manifest_box_bytes: Option<Vec<u8>> = None;
    let mut update_box_bytes: Option<Vec<u8>> = None;
    let mut xmp: Option<String> = None;
    let mut manifest_box_offset = None;
    let mut update_box_offset = None;
    let mut first_aux_uuid_offset = 0u64;
    let mut merkle_boxes: Vec<BmffMerkleMap> = Vec::new();
    let mut merkle_box_infos: Vec<BoxInfoLite> = Vec::new();
    let mut xmp_box_offset = 0;
    let mut xmp_box_size = 0;

    // grab top level (for now) C2PA box
    if let Some(uuid_list) = bmff_map.get("/uuid") {
        let mut manifest_store_cnt = 0;
        let mut update_store_cnt = 0;

        for uuid_token in uuid_list {
            let box_info = &bmff_tree[*uuid_token];

            // make sure it is UUID box
            if box_info.data.box_type == BoxType::UuidBox {
                if let Some(uuid) = &box_info.data.user_type {
                    // make sure it is a C2PA ContentProvenanceBox box
                    if vec_compare(&C2PA_UUID, uuid) {
                        let (purpose, mut data_len) = get_uuid_box_purpose(reader, box_info)?;

                        // is the purpose manifest?
                        if purpose == MANIFEST || purpose == ORIGINAL || purpose == UPDATE {
                            // offset to first aux uuid with purpose merkle
                            let mut buf = [0u8; 8];
                            reader.read_exact(&mut buf)?;
                            data_len -= 8;

                            // read the manifest box contents
                            let manifest = reader.read_to_vec(data_len)?;

                            // read the entire manifest box
                            skip_bytes_to(reader, box_info.data.offset)?;
                            let box_bytes = Some(reader.read_to_vec(box_info.data.size)?);

                            if purpose == MANIFEST {
                                manifest_bytes = Some(manifest);
                                manifest_box_offset = Some(box_info.data.offset);
                                manifest_box_bytes = box_bytes;
                                manifest_store_cnt += 1;
                                // offset to first aux uuid
                                first_aux_uuid_offset = u64::from_be_bytes(buf);
                            } else if purpose == ORIGINAL {
                                original_bytes = Some(manifest);
                                manifest_box_offset = Some(box_info.data.offset);
                                manifest_box_bytes = box_bytes;
                                manifest_store_cnt += 1;
                                // offset to first aux uuid
                                first_aux_uuid_offset = u64::from_be_bytes(buf);
                            } else if purpose == UPDATE {
                                update_bytes = Some(manifest);
                                update_box_offset = Some(box_info.data.offset);
                                update_box_bytes = box_bytes;
                                update_store_cnt += 1;
                            }

                            if manifest_store_cnt > 1 || update_store_cnt > 1 {
                                return Err(Error::TooManyManifestStores);
                            }
                        } else if purpose == MERKLE {
                            let merkle = reader.read_to_vec(data_len)?;

                            // use this method since it will strip trailing zeros padding if there
                            let mut deserializer = c2pa_cbor::de::Deserializer::from_slice(&merkle);
                            let mm: BmffMerkleMap =
                                serde::Deserialize::deserialize(&mut deserializer)?;
                            merkle_boxes.push(mm);
                            merkle_box_infos.push(BoxInfoLite {
                                path: box_info.data.path.clone(),
                                offset: box_info.data.offset,
                                size: box_info.data.size,
                            });
                        }
                    } else if vec_compare(&XMP_UUID, uuid) {
                        let data_len = box_info.data.size - HEADER_SIZE - 16 /*UUID*/;

                        // set reader to start of box contents
                        skip_bytes_to(reader, box_info.data.offset + HEADER_SIZE + 16)?;

                        let xmp_vec = reader.read_to_vec(data_len)?;
                        if let Ok(xmp_string) = String::from_utf8(xmp_vec) {
                            xmp = Some(xmp_string);
                            xmp_box_offset = box_info.data.offset;
                            xmp_box_size = box_info.data.size;
                        }
                    }
                }
            }
        }
    }

    // get position ordered list of boxes
    let mut box_infos: Vec<BoxInfoLite> = get_top_level_boxes(bmff_tree, bmff_map);
    box_infos.sort_by(|a, b| a.offset.cmp(&b.offset));

    Ok(C2PABmffBoxes {
        manifest_bytes,
        original_bytes,
        update_bytes,
        manifest_box_bytes,
        update_box_bytes,
        bmff_merkle: merkle_boxes,
        bmff_merkle_box_infos: merkle_box_infos,
        box_infos,
        xmp,
        manifest_box_offset,
        update_box_offset,
        first_aux_uuid_offset,
        xmp_box_offset,
        xmp_box_size,
    })
}

pub(crate) fn read_bmff_c2pa_boxes(reader: &mut dyn CAIRead) -> Result<C2PABmffBoxes> {
    let size = stream_len(reader)?;
    reader.rewind()?;

    // create root node
    let root_box = BoxInfo {
        path: "".to_string(),
        offset: 0,
        size,
        box_type: BoxType::Empty,
        parent: None,
        user_type: None,
        version: None,
        flags: None,
    };

    let (mut bmff_tree, root_token) = Arena::with_data(root_box);
    let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

    // build layout of the BMFF structure
    let mut rl = 0usize;
    build_bmff_tree(
        reader,
        size,
        &mut bmff_tree,
        &root_token,
        &mut bmff_map,
        &mut rl,
    )?;
    c2pa_boxes_from_tree_and_map(reader, &bmff_tree, &bmff_map)
}

impl CAIReader for BmffIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        reader.seek(SeekFrom::Start(4))?;

        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;

        if header[..4] != *b"ftyp" {
            return Err(BmffError::InvalidFileSignature {
                reason: format!(
                    "invalid BMFF structure: expected box type \"ftyp\" at offset 4, found {}",
                    String::from_utf8_lossy(&header[..4])
                ),
            }
            .into());
        }

        let c2pa_boxes = read_bmff_c2pa_boxes(reader)?;

        // is this an update manifest?
        if let Some(original_bytes) = c2pa_boxes.original_bytes {
            if let Some(update_bytes) = c2pa_boxes.update_bytes {
                let mut validation_log = StatusTracker::default();

                // combine original Store and update Store to single logical manifest Store
                let mut original_store = Store::from_jumbf(&original_bytes, &mut validation_log)?;
                let update_store = Store::from_jumbf(&update_bytes, &mut validation_log)?;

                original_store.append_store(&update_store);

                return original_store.to_jumbf_internal(0);
            } else {
                return Err(Error::C2PAValidation(
                    "original manifest without update manifest".to_string(),
                ));
            }
        }

        c2pa_boxes.manifest_bytes.ok_or(Error::JumbfNotFound)
    }

    // Get XMP block
    fn read_xmp(&self, reader: &mut dyn CAIRead) -> Option<String> {
        let c2pa_boxes = read_bmff_c2pa_boxes(reader).ok()?;

        c2pa_boxes.xmp
    }
}

impl AssetIO for BmffIO {
    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
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
        _asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        let vec: Vec<HashObjectPositions> = Vec::new();
        Ok(vec)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut input_file = std::fs::File::open(asset_path)?;

        let mut temp_file = tempfile_builder("c2pa_temp")?;

        self.remove_cai_store_from_stream(&mut input_file, &mut temp_file)?;

        // copy temp file to asset
        rename_or_move(temp_file, asset_path)
    }

    fn new(asset_type: &str) -> Self
    where
        Self: Sized,
    {
        BmffIO {
            bmff_format: asset_type.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(BmffIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(BmffIO::new(asset_type)))
    }

    fn remote_ref_writer_ref(&self) -> Option<&dyn RemoteRefEmbed> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

impl CAIWriter for BmffIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        let size = stream_len(input_stream)?;
        input_stream.rewind()?;

        // create root node
        let root_box = BoxInfo {
            path: "".to_string(),
            offset: 0,
            size,
            box_type: BoxType::Empty,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };

        let (mut bmff_tree, root_token) = Arena::with_data(root_box);
        let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

        // build layout of the BMFF structure
        let mut rl = 0usize;
        build_bmff_tree(
            input_stream,
            size,
            &mut bmff_tree,
            &root_token,
            &mut bmff_map,
            &mut rl,
        )?;

        // figure out what state we are in
        let c2pa_boxes = c2pa_boxes_from_tree_and_map(input_stream, &bmff_tree, &bmff_map)?;
        let has_manifest = c2pa_boxes.manifest_bytes.is_some();
        let has_original = c2pa_boxes.original_bytes.is_some();
        let has_update = c2pa_boxes.update_bytes.is_some();
        // if the incoming Store has an update manifest we must split it into original and update stores
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
        let (pc, is_update) = if let Ok(store) = Store::from_jumbf(store_bytes, &mut validation_log)
        {
            let pc = store
                .provenance_claim()
                .ok_or(Error::BadParam("no provenance claim".to_string()))?;
            let is_update = pc.update_manifest();
            (Some(pc.clone()), is_update)
        } else {
            (None, false)
        };

        // "original" manifest store and "update" manifest store can only appear together
        if has_original && !has_update || !has_original && has_update {
            return Err(Error::BadParam(
                "BMFF save failure, found original manifest store without update manifest store"
                    .to_string(),
            ));
        }

        // if is an ordinary manifest store then it should not have an update manifest store
        if has_manifest && has_update {
            return Err(Error::BadParam(
                "BMFF save failure, found manifest store with update manifest store".to_string(),
            ));
        }

        // if we already have an "original" manifest store and an "update" manifest store
        // then we can just apppend to the update store
        if has_original && has_update && is_update {
            let update_manifest_bytes = &c2pa_boxes
                .update_bytes
                .ok_or(Error::BadParam("no update manifest".to_string()))?;
            let update_box_offset = c2pa_boxes
                .update_box_offset
                .ok_or(Error::BadParam("no update manifest".to_string()))?;
            let update_box_size = c2pa_boxes
                .update_box_bytes
                .ok_or(Error::BadParam("no update manifest".to_string()))?
                .len();
            let pc = pc.ok_or(Error::BadParam("no provenance manifest".to_string()))?;

            let mut update_store = Store::from_jumbf(update_manifest_bytes, &mut validation_log)?;
            // add new update manfiest or replace existing one if the is a finalization pass
            update_store.replace_claim_or_insert(pc.label().to_string(), pc);

            let new_update_bytes = update_store.to_jumbf_internal(0)?;
            let mut new_update_box = Vec::new();
            write_c2pa_box(&mut new_update_box, &new_update_bytes, UPDATE, &[], 0)?;

            patch_stream(
                input_stream,
                output_stream,
                update_box_offset,
                update_box_size as u64,
                &new_update_box,
            )?;

            return Ok(());
        }

        // if we have an ordinary manifest store and we are adding a new update manifest
        // then we need to split off incoming provenance claim into and add to update new update manifest
        if has_manifest && !has_update && is_update {
            let pc = pc.ok_or(Error::BadParam("no provenance manifest".to_string()))?;

            let mut update_store = Store::new();
            update_store.insert_restored_claim(pc.label().to_string(), pc);
            let new_update_bytes = update_store.to_jumbf_internal(0)?;

            // patch the purpose of the original manifest store
            let mut manifest_box_bytes = c2pa_boxes
                .manifest_box_bytes
                .ok_or(Error::BadParam("no original manifest".to_string()))?
                .clone();
            let manifest_box_offset = c2pa_boxes
                .manifest_box_offset
                .ok_or(Error::BadParam("no original manifest offset".to_string()))?;

            // update the manifest purpose
            patch_bytes(
                &mut manifest_box_bytes,
                MANIFEST.as_bytes(),
                ORIGINAL.as_bytes(),
            )?;

            // write the stream with manifest bytes containing updated manifest PURPOSE
            patch_stream(
                input_stream,
                output_stream,
                manifest_box_offset,
                manifest_box_bytes.len() as u64,
                &manifest_box_bytes,
            )?;

            // append new update manifest store to end of stream
            let mut update_manifest = Vec::new();
            write_c2pa_box(&mut update_manifest, &new_update_bytes, UPDATE, &[], 0)?;
            output_stream.seek(SeekFrom::End(0))?;
            output_stream.write_all(&update_manifest)?;

            return Ok(());
        }

        // since we reached this point we must have an ordinary manifest store so we may need to truncate off
        // the update manifest
        // get ftyp location
        // start after ftyp
        let ftyp_token = bmff_map.get("/ftyp").ok_or(Error::UnsupportedType)?; // todo check ftyps to make sure we support any special format requirements
        let ftyp_info = &bmff_tree[ftyp_token[0]].data;
        let ftyp_offset = ftyp_info.offset;
        let ftyp_size = ftyp_info.size;

        // get position to insert c2pa primary manifest store
        let (c2pa_start, c2pa_length) = match get_uuid_token(
            input_stream,
            &bmff_tree,
            &bmff_map,
            &C2PA_UUID,
            Some(&[MANIFEST, ORIGINAL]),
        ) {
            Ok(c2pa_token) => {
                let uuid_info = &bmff_tree[c2pa_token].data;

                (uuid_info.offset, Some(uuid_info.size))
            }
            Err(Error::NotFound) => ((ftyp_offset + ftyp_size), None),
            Err(e) => return Err(e),
        };

        let mut new_c2pa_box: Vec<u8> = Vec::with_capacity(store_bytes.len() * 2);
        let merkle_data: &[u8] = &[]; // not yet supported
        write_c2pa_box(&mut new_c2pa_box, store_bytes, MANIFEST, merkle_data, 0)?;
        let new_c2pa_box_size = new_c2pa_box.len();

        let (start, end) = if let Some(c2pa_length) = c2pa_length {
            let start = usize::try_from(c2pa_start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            let end = usize::try_from(c2pa_start + c2pa_length)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            (start, end)
        } else {
            // insert new c2pa
            let end = usize::try_from(c2pa_start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            (end, end)
        };

        // write content before ContentProvenanceBox
        input_stream.rewind()?;
        let mut before_manifest = input_stream.take(start as u64);
        std::io::copy(&mut before_manifest, output_stream)?;

        // write ContentProvenanceBox
        output_stream.write_all(&new_c2pa_box)?;

        // calc offset adjustments
        let offset_adjust: i32 = if end == 0 {
            new_c2pa_box_size as i32
        } else {
            // value could be negative if box is truncated
            let existing_c2pa_box_size = end - start;
            let pad_size: i32 = new_c2pa_box_size as i32 - existing_c2pa_box_size as i32;
            pad_size
        };

        // write content after ContentProvenanceBox
        // since we reached this point we must have an ordinary manifest store so we may need to truncate off
        // the update manifest
        input_stream.seek(SeekFrom::Start(end as u64))?;
        if has_update {
            let update_offset = c2pa_boxes
                .update_box_offset
                .ok_or(Error::BadParam("no update manifest".to_string()))?;
            let len_to_update = update_offset - end as u64;
            let mut truncating_reader = input_stream.take(len_to_update);
            std::io::copy(&mut truncating_reader, output_stream)?;
        } else {
            std::io::copy(input_stream, output_stream)?;
        }

        // Manipulating the UUID box means we may need some patch offsets if they are file absolute offsets.
        if offset_adjust != 0 {
            // create root node
            let root_box = BoxInfo {
                path: "".to_string(),
                offset: 0,
                size,
                box_type: BoxType::Empty,
                parent: None,
                user_type: None,
                version: None,
                flags: None,
            };

            // map box layout of current output file
            let (mut output_bmff_tree, root_token) = Arena::with_data(root_box);
            let mut output_bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

            let size = stream_len(output_stream)?;
            output_stream.rewind()?;
            let mut rl = 0usize;
            build_bmff_tree(
                output_stream,
                size,
                &mut output_bmff_tree,
                &root_token,
                &mut output_bmff_map,
                &mut rl,
            )?;

            // adjust offsets based on current layout
            output_stream.rewind()?;
            adjust_known_offsets(
                output_stream,
                &output_bmff_tree,
                &output_bmff_map,
                offset_adjust,
            )?;
        }

        Ok(())
    }

    fn get_object_locations_from_stream(
        &self,
        _input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        let vec: Vec<HashObjectPositions> = Vec::new();
        Ok(vec)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        let size = stream_len(input_stream)?;
        input_stream.rewind()?;

        // create root node
        let root_box = BoxInfo {
            path: "".to_string(),
            offset: 0,
            size,
            box_type: BoxType::Empty,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };

        let (mut bmff_tree, root_token) = Arena::with_data(root_box);
        let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

        // build layout of the BMFF structure
        let mut rl = 0usize;
        build_bmff_tree(
            input_stream,
            size,
            &mut bmff_tree,
            &root_token,
            &mut bmff_map,
            &mut rl,
        )?;

        // get position of c2pa manifest
        let (c2pa_start, c2pa_length) =
            match get_uuid_token(input_stream, &bmff_tree, &bmff_map, &C2PA_UUID, None) {
                Ok(c2pa_token) => {
                    let uuid_info = &bmff_tree[c2pa_token].data;

                    (uuid_info.offset, Some(uuid_info.size))
                }
                Err(Error::NotFound) => {
                    input_stream.rewind()?;
                    std::io::copy(input_stream, output_stream)?;
                    return Ok(()); // no box to remove, propagate source to output
                }
                Err(e) => return Err(e),
            };

        let (start, end) = if let Some(c2pa_length) = c2pa_length {
            let start = usize::try_from(c2pa_start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            let end = usize::try_from(c2pa_start + c2pa_length)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            (start, end)
        } else {
            return Err(Error::InvalidAsset("value out of range".to_string()));
        };

        // write content before ContentProvenanceBox
        input_stream.rewind()?;
        let mut before_manifest = input_stream.take(start as u64);
        std::io::copy(&mut before_manifest, output_stream)?;

        // calc offset adjustments
        // value will be negative since the box is truncated
        let new_c2pa_box_size: i32 = 0;
        let existing_c2pa_box_size = end - start;
        let offset_adjust = new_c2pa_box_size - existing_c2pa_box_size as i32;

        // write content after ContentProvenanceBox
        input_stream.seek(SeekFrom::Start(end as u64))?;
        std::io::copy(input_stream, output_stream)?;

        // Manipulating the UUID box means we may need some patch offsets if they are file absolute offsets.

        // create root node
        let root_box = BoxInfo {
            path: "".to_string(),
            offset: 0,
            size,
            box_type: BoxType::Empty,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };

        // map box layout of current output file
        let (mut output_bmff_tree, root_token) = Arena::with_data(root_box);
        let mut output_bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

        let size = stream_len(output_stream)?;
        output_stream.rewind()?;
        let mut rl = 0usize;
        build_bmff_tree(
            output_stream,
            size,
            &mut output_bmff_tree,
            &root_token,
            &mut output_bmff_map,
            &mut rl,
        )?;

        // adjust offsets based on current layout
        output_stream.rewind()?;
        adjust_known_offsets(
            output_stream,
            &output_bmff_tree,
            &output_bmff_map,
            offset_adjust,
        )
    }
}

impl AssetPatch for BmffIO {
    fn patch_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut asset = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(asset_path)?;
        let size = stream_len(&mut asset)?;
        asset.rewind()?;

        // create root node
        let root_box = BoxInfo {
            path: "".to_string(),
            offset: 0,
            size,
            box_type: BoxType::Empty,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };

        let (mut bmff_tree, root_token) = Arena::with_data(root_box);
        let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

        // build layout of the BMFF structure
        let mut rl = 0usize;
        build_bmff_tree(
            &mut asset,
            size,
            &mut bmff_tree,
            &root_token,
            &mut bmff_map,
            &mut rl,
        )?;

        // get position to insert c2pa
        let (c2pa_start, c2pa_length) = if let Some(uuid_tokens) = bmff_map.get("/uuid") {
            let uuid_info = &bmff_tree[uuid_tokens[0]].data;

            // is this a C2PA manifest
            let is_c2pa = if let Some(uuid) = &uuid_info.user_type {
                // make sure it is a C2PA box
                vec_compare(&C2PA_UUID, uuid)
            } else {
                false
            };

            if is_c2pa {
                (uuid_info.offset, Some(uuid_info.size))
            } else {
                (0, None)
            }
        } else {
            return Err(Error::InvalidAsset(
                "patch_cai_store found no manifest store to patch.".to_string(),
            ));
        };

        if let Some(manifest_length) = c2pa_length {
            let mut new_c2pa_box: Vec<u8> = Vec::with_capacity(store_bytes.len() * 2);
            let merkle_data: &[u8] = &[]; // not yet supported
            write_c2pa_box(&mut new_c2pa_box, store_bytes, MANIFEST, merkle_data, 0)?;
            let new_c2pa_box_size = new_c2pa_box.len();

            if new_c2pa_box_size as u64 == manifest_length {
                asset.seek(SeekFrom::Start(c2pa_start))?;
                asset.write_all(&new_c2pa_box)?;
                Ok(())
            } else {
                Err(Error::InvalidAsset(
                    "patch_cai_store store size mismatch.".to_string(),
                ))
            }
        } else {
            Err(Error::InvalidAsset(
                "patch_cai_store store size mismatch.".to_string(),
            ))
        }
    }
}

impl RemoteRefEmbed for BmffIO {
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
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        match embed_ref {
            crate::asset_io::RemoteRefEmbedType::Xmp(manifest_uri) => {
                let size = stream_len(input_stream)?;
                input_stream.rewind()?;

                // create root node
                let root_box = BoxInfo {
                    path: "".to_string(),
                    offset: 0,
                    size,
                    box_type: BoxType::Empty,
                    parent: None,
                    user_type: None,
                    version: None,
                    flags: None,
                };

                let (mut bmff_tree, root_token) = Arena::with_data(root_box);
                let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

                // build layout of the BMFF structure
                let mut rl = 0usize;
                build_bmff_tree(
                    input_stream,
                    size,
                    &mut bmff_tree,
                    &root_token,
                    &mut bmff_map,
                    &mut rl,
                )?;

                let c2pa_boxes = c2pa_boxes_from_tree_and_map(input_stream, &bmff_tree, &bmff_map)?;

                let xmp = match &c2pa_boxes.xmp {
                    Some(xmp) => add_provenance(xmp, &manifest_uri)?,
                    None => {
                        let xmp = MIN_XMP.to_string();
                        add_provenance(&xmp, &manifest_uri)?
                    }
                };

                // get position to insert xmp
                let (xmp_start, xmp_length) = match &c2pa_boxes.xmp {
                    Some(_xmp) => (c2pa_boxes.xmp_box_offset, Some(c2pa_boxes.xmp_box_size)),
                    None => {
                        // get ftyp location
                        // start after ftyp
                        let ftyp_token = bmff_map.get("/ftyp").ok_or(Error::UnsupportedType)?; // todo check ftyps to make sure we support any special format requirements
                        let ftyp_info = &bmff_tree[ftyp_token[0]].data;
                        let ftyp_offset = ftyp_info.offset;
                        let ftyp_size = ftyp_info.size;

                        ((ftyp_offset + ftyp_size), None)
                    }
                };

                let mut new_xmp_box: Vec<u8> = Vec::with_capacity(xmp.len() * 2);
                write_xmp_box(&mut new_xmp_box, xmp.as_bytes())?;
                let new_xmp_box_size = new_xmp_box.len();

                let (start, end) = if let Some(xmp_length) = xmp_length {
                    let start = usize::try_from(xmp_start)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

                    let end = usize::try_from(xmp_start + xmp_length)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    (start, end)
                } else {
                    // insert new c2pa
                    let end = usize::try_from(xmp_start)
                        .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

                    (end, end)
                };

                // write content before XMP box
                input_stream.rewind()?;
                let mut before_xmp = input_stream.take(start as u64);
                std::io::copy(&mut before_xmp, output_stream)?;

                // write ContentProvenanceBox
                output_stream.write_all(&new_xmp_box)?;

                // calc offset adjustments
                let offset_adjust: i32 = if end == 0 {
                    new_xmp_box_size as i32
                } else {
                    // value could be negative if box is truncated
                    let existing_xmp_box_size = end - start;
                    let pad_size: i32 = new_xmp_box_size as i32 - existing_xmp_box_size as i32;
                    pad_size
                };

                // write content after XMP box
                input_stream.seek(SeekFrom::Start(end as u64))?;
                std::io::copy(input_stream, output_stream)?;

                // Manipulating the UUID box means we may need some patch offsets if they are file absolute offsets.

                // create root node
                let root_box = BoxInfo {
                    path: "".to_string(),
                    offset: 0,
                    size,
                    box_type: BoxType::Empty,
                    parent: None,
                    user_type: None,
                    version: None,
                    flags: None,
                };

                // map box layout of current output file
                let (mut output_bmff_tree, root_token) = Arena::with_data(root_box);
                let mut output_bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

                let size = stream_len(output_stream)?;
                output_stream.rewind()?;
                let mut rl = 0usize;
                build_bmff_tree(
                    output_stream,
                    size,
                    &mut output_bmff_tree,
                    &root_token,
                    &mut output_bmff_map,
                    &mut rl,
                )?;

                // adjust offsets based on current layout
                output_stream.rewind()?;
                adjust_known_offsets(
                    output_stream,
                    &output_bmff_tree,
                    &output_bmff_map,
                    offset_adjust,
                )
            }
            crate::asset_io::RemoteRefEmbedType::StegoS(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::StegoB(_) => Err(Error::UnsupportedType),
            crate::asset_io::RemoteRefEmbedType::Watermark(_) => Err(Error::UnsupportedType),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BmffError {
    #[error("invalid file signature: {reason}")]
    InvalidFileSignature { reason: String },
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::utils::{
        io_utils::tempdirectory,
        test::{fixture_path, temp_dir_path},
    };

    #[test]
    fn test_read_deep_nesting() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let ap = fixture_path("nested_moov_1000.mp4");
        let mut input_stream = std::fs::File::open(&ap).unwrap();

        let bmff = BmffIO::new("mp4");
        let cai = bmff.read_cai(&mut input_stream);

        assert!(cai.is_err());
    }

    #[test]
    fn test_read_mp4() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let ap = fixture_path("video1.mp4");
        let mut input_stream = std::fs::File::open(&ap).unwrap();

        let bmff = BmffIO::new("mp4");
        let cai = bmff.read_cai(&mut input_stream).unwrap();

        assert!(!cai.is_empty());
    }

    #[test]
    fn test_xmp_write() {
        let data = "some test data";
        let source = fixture_path("video1.mp4");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "video1-out.mp4");

        std::fs::copy(source, &output).unwrap();

        let bmff = BmffIO::new("mp4");

        let eh = bmff.remote_ref_writer_ref().unwrap();

        eh.embed_reference(&output, RemoteRefEmbedType::Xmp(data.to_string()))
            .unwrap();

        let mut output_stream = std::fs::File::open(&output).unwrap();
        let xmp = bmff.get_reader().read_xmp(&mut output_stream).unwrap();

        let loaded = crate::utils::xmp_inmemory_utils::extract_provenance(&xmp).unwrap();

        assert_eq!(&loaded, data);
    }

    #[test]
    fn test_truncated_c2pa_write_mp4() {
        let test_data = "some test data".as_bytes();
        let source = fixture_path("video1.mp4");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "mp4_test.mp4");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let bmff = BmffIO::new("mp4");

                //let test_data =  bmff.read_cai_store(&source).unwrap();
                if let Ok(()) = bmff.save_cai_store(&output, test_data) {
                    if let Ok(read_test_data) = bmff.read_cai_store(&output) {
                        assert!(vec_compare(test_data, &read_test_data));
                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_expanded_c2pa_write_mp4() {
        let mut more_data = "some more test data".as_bytes().to_vec();
        let source = fixture_path("video1.mp4");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "mp4_test.mp4");

            if let Ok(_size) = std::fs::copy(&source, &output) {
                let bmff = BmffIO::new("mp4");

                if let Ok(mut test_data) = bmff.read_cai_store(&source) {
                    test_data.append(&mut more_data);
                    if let Ok(()) = bmff.save_cai_store(&output, &test_data) {
                        if let Ok(read_test_data) = bmff.read_cai_store(&output) {
                            assert!(vec_compare(&test_data, &read_test_data));
                            success = true;
                        }
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_patch_c2pa_write_mp4() {
        let test_data = "some test data".as_bytes();
        let source = fixture_path("video1.mp4");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "mp4_test.mp4");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let bmff = BmffIO::new("mp4");

                if let Ok(source_data) = bmff.read_cai_store(&output) {
                    // create replacement data of same size
                    let mut new_data = vec![0u8; source_data.len()];
                    new_data[..test_data.len()].copy_from_slice(test_data);
                    bmff.patch_cai_store(&output, &new_data).unwrap();

                    let replaced = bmff.read_cai_store(&output).unwrap();

                    assert_eq!(new_data, replaced);

                    success = true;
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_remove_c2pa() {
        let source = fixture_path("video1.mp4");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "mp4_test.mp4");

        std::fs::copy(source, &output).unwrap();
        let bmff_io = BmffIO::new("mp4");

        bmff_io.remove_cai_store(&output).unwrap();

        // read back in asset, JumbfNotFound is expected since it was removed
        match bmff_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => unreachable!(),
        }
    }
}
