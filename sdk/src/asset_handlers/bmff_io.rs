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
    collections::HashMap,
    convert::{From, TryFrom},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use atree::{Arena, Token};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use conv::ValueFrom;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tempfile::{Builder, NamedTempFile};

use crate::{
    assertions::ExclusionsMap,
    asset_io::{AssetIO, AssetPatch, CAILoader, CAIRead, HashObjectPositions},
    error::{Error, Result},
    utils::hash_utils::{vec_compare, Exclusion},
};

pub struct BmffIO {
    #[allow(dead_code)]
    bmff_format: String, // can be used for specialized BMFF cases
}
impl BmffIO {
    pub fn new(bmff_format: &str) -> Self {
        BmffIO {
            bmff_format: bmff_format.to_string(),
        }
    }
}

const HEADER_SIZE: u64 = 8;

const C2PA_UUID: [u8; 16] = [
    0xD8, 0xFE, 0xC3, 0xD6, 0x1B, 0x0E, 0x48, 0x3C, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7E, 0xC4, 0x81,
];
const MANIFEST: &str = "manifest";
const MERKLE: &str = "merkle";

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

// define CAIRead for tempfile
impl CAIRead for NamedTempFile {}

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
    SchiBox => 0x73636869
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct BmffMerkleMap {
    #[serde(rename = "uniqueId")]
    unique_id: u32,
    #[serde(rename = "localId")]
    local_id: u32,
    location: u32,
    hashes: Option<Vec<ByteBuf>>,
}

struct BoxHeaderLite {
    pub name: BoxType,
    pub size: u64,
    pub fourcc: String,
}

impl BoxHeaderLite {
    pub fn new(name: BoxType, size: u64, fourcc: &str) -> Self {
        Self {
            name,
            size,
            fourcc: fourcc.to_string(),
        }
    }
    pub fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self> {
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
                size: largesize - HEADER_SIZE,
                fourcc,
            })
        } else {
            Ok(BoxHeaderLite {
                name: BoxType::from(typ),
                size: size as u64,
                fourcc,
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

#[derive(Debug, PartialEq)]
pub(crate) struct BoxInfo {
    path: String,
    parent: Option<Token>,
    offset: u64,
    size: u64,
    box_type: BoxType,
    user_type: Option<Vec<u8>>,
    version: Option<u8>,
    flags: Option<u32>,
}

fn read_box_header_ext(reader: &mut dyn CAIRead) -> Result<(u8, u32)> {
    let version = reader.read_u8()?;
    let flags = reader.read_u24::<BigEndian>()?;
    Ok((version, flags))
}
fn write_box_header_ext<W: Write>(w: &mut W, v: u8, f: u32) -> Result<u64> {
    w.write_u8(v)?;
    w.write_u24::<BigEndian>(f)?;
    Ok(4)
}

fn box_start(reader: &mut dyn CAIRead) -> Result<u64> {
    Ok(reader.seek(SeekFrom::Current(0))? - HEADER_SIZE)
}

fn _skip_bytes(reader: &mut dyn CAIRead, size: u64) -> Result<()> {
    reader.seek(SeekFrom::Current(size as i64))?;
    Ok(())
}

fn skip_bytes_to(reader: &mut dyn CAIRead, pos: u64) -> Result<u64> {
    let pos = reader.seek(SeekFrom::Start(pos))?;
    Ok(pos)
}

fn _skip_box(reader: &mut dyn CAIRead, size: u64) -> Result<()> {
    let start = box_start(reader)?;
    skip_bytes_to(reader, start + size)?;
    Ok(())
}

fn write_c2pa_box<W: Write>(
    w: &mut W,
    data: &[u8],
    is_manifest: bool,
    merkle_data: &[u8],
) -> Result<()> {
    let purpose_size = if is_manifest {
        MANIFEST.len() + 1
    } else {
        MERKLE.len() + 1
    };
    let merkle_size = if is_manifest { 8 } else { merkle_data.len() };
    let size = 8 + 16 + 4 + purpose_size + merkle_size + data.len(); // header + UUID + version/flags + data + zero terminated purpose + merkle data
    let bh = BoxHeaderLite::new(BoxType::UuidBox, size as u64, "uuid");

    // write out header
    bh.write(w)?;

    // write out c2pa extension UUID
    write_box_uuid_extension(w, &C2PA_UUID)?;

    // write out version and flags
    let version: u8 = 0;
    let flags: u32 = 0;
    write_box_header_ext(w, version, flags)?;

    // write purpose
    if is_manifest {
        w.write_all(MANIFEST.as_bytes())?;
        w.write_u8(0)?;

        // write no merkle flag
        w.write_u64::<BigEndian>(0)?;
    } else {
        w.write_all(MERKLE.as_bytes())?;
        w.write_u8(0)?;

        // write merkle cbor
        w.write_all(merkle_data)?;
    }

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

fn path_from_token(bmff_tree: &mut Arena<BoxInfo>, current_node_token: &Token) -> Result<String> {
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

pub fn bmff_to_jumbf_exclusions(
    reader: &mut dyn CAIRead,
    bmff_exclusions: &[ExclusionsMap],
) -> Result<Vec<Exclusion>> {
    let start = reader.seek(SeekFrom::Current(0))?;
    let size = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(start))?;

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
    build_bmff_tree(reader, size, &mut bmff_tree, &root_token, &mut bmff_map)?;

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
                    if desired_length as u64 != box_length {
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
                        let exact = if let Some(is_exact) = bmff_exclusion.exact {
                            is_exact
                        } else {
                            true
                        };

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
                        skip_bytes_to(reader, box_start + data_map.offset as u64)?;

                        // match the data
                        let mut buf = vec![0u8; data_map.value.len()];
                        reader.read_exact(&mut buf)?;

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
                        let exclusion = Exclusion::new(
                            (exclusion_start + subset.offset as u64) as usize,
                            (if subset.length == 0 {
                                exclusion_length - subset.offset as u64
                            } else {
                                subset.length as u64
                            }) as usize,
                        );
                        exclusions.push(exclusion);
                    }
                } else {
                    let exclusion =
                        Exclusion::new(exclusion_start as usize, exclusion_length as usize);
                    exclusions.push(exclusion);
                }
            }
        }
    }

    Ok(exclusions)
}

// `stco` and `co64` elements contain absolute file offsets so they need to be adjusted based on whether content was added or removed.
fn adjust_stco_and_co64<W: Write + CAIRead>(
    output: &mut W,
    bmff_tree: &Arena<BoxInfo>,
    bmff_path_map: &HashMap<String, Vec<Token>>,
    adjust: i32,
) -> Result<()> {
    let start_pos = output.seek(SeekFrom::Current(0))?; // save starting point

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
            let entry_start_pos = output.seek(SeekFrom::Current(0))?;
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
            let entry_start_pos = output.seek(SeekFrom::Current(0))?;
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

    // restore seek point
    output.seek(SeekFrom::Start(start_pos))?;
    output.flush()?;

    Ok(())
}

pub(crate) fn build_bmff_tree(
    reader: &mut dyn CAIRead,
    end: u64,
    bmff_tree: &mut Arena<BoxInfo>,
    current_node: &Token,
    bmff_path_map: &mut HashMap<String, Vec<Token>>,
) -> Result<()> {
    let start = reader.seek(SeekFrom::Current(0))?;

    let mut current = start;
    while current < end {
        // Get box header.
        let header = BoxHeaderLite::read(reader)
            .map_err(|_err| Error::InvalidAsset("Bad BMFF".to_string()))?;

        // Break if size zero BoxHeader
        let s = header.size;
        if s == 0 {
            break;
        }

        // Match and parse the supported atom boxes.
        match header.name {
            BoxType::UuidBox => {
                let start = box_start(reader)?;

                let mut extended_type = [0u8; 16]; // 16 bytes of UUID
                reader.read_exact(&mut extended_type)?;

                let (version, flags) = read_box_header_ext(reader)?;

                let b = BoxInfo {
                    path: header.fourcc.clone(),
                    offset: start,
                    size: s,
                    box_type: BoxType::UuidBox,
                    parent: Some(*current_node),
                    user_type: Some(extended_type.to_vec()),
                    version: Some(version),
                    flags: Some(flags),
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
                let start = box_start(reader)?;

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

                let new_token = bmff_tree.new_node(b);
                current_node
                    .append_node(bmff_tree, new_token)
                    .map_err(|_err| Error::InvalidAsset("Bad BMFF Graph".to_string()))?;

                let path = path_from_token(bmff_tree, &new_token)?;
                add_token_to_cache(bmff_path_map, path, new_token);

                // consume all sub-boxes
                let mut current = reader.seek(SeekFrom::Current(0))?;
                let end = start + s;
                while current < end {
                    build_bmff_tree(reader, end, bmff_tree, &new_token, bmff_path_map)?;
                    current = reader.seek(SeekFrom::Current(0))?;
                }

                // position seek pointer
                skip_bytes_to(reader, start + s)?;
            }
            _ => {
                let start = reader.seek(SeekFrom::Current(0))? - HEADER_SIZE;

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
        current = reader.seek(SeekFrom::Current(0))?;
    }

    Ok(())
}

fn get_manifest_token(
    bmff_tree: &Arena<BoxInfo>,
    bmff_map: &HashMap<String, Vec<Token>>,
) -> Option<Token> {
    if let Some(uuid_list) = bmff_map.get("/uuid") {
        for uuid_token in uuid_list {
            let box_info = &bmff_tree[*uuid_token];

            // make sure it is UUID box
            if box_info.data.box_type == BoxType::UuidBox {
                if let Some(uuid) = &box_info.data.user_type {
                    // make sure it is a C2PA ContentProvenanceBox box
                    if vec_compare(&C2PA_UUID, uuid) {
                        return Some(*uuid_token);
                    }
                }
            }
        }
    }
    None
}

impl CAILoader for BmffIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        let start = reader.seek(SeekFrom::Current(0))?;
        let size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(start))?;

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
        build_bmff_tree(reader, size, &mut bmff_tree, &root_token, &mut bmff_map)?;

        let mut output: Option<Vec<u8>> = None;

        // grab top level (for now) C2PA box
        if let Some(uuid_list) = bmff_map.get("/uuid") {
            let mut manifest_store_cnt = 0;

            for uuid_token in uuid_list {
                let box_info = &bmff_tree[*uuid_token];

                // make sure it is UUID box
                if box_info.data.box_type == BoxType::UuidBox {
                    if let Some(uuid) = &box_info.data.user_type {
                        // make sure it is a C2PA ContentProvenanceBox box
                        if vec_compare(&C2PA_UUID, uuid) {
                            let mut data_len = box_info.data.size - HEADER_SIZE - 16 /*UUID*/;

                            // set reader to start of box contents
                            skip_bytes_to(reader, box_info.data.offset + HEADER_SIZE + 16)?;

                            // Fullbox => 8 bits for version 24 bits for flags
                            let (_version, _flags) = read_box_header_ext(reader)?;
                            data_len -= 4;

                            // get the purpose
                            let mut purpose = Vec::with_capacity(64);
                            loop {
                                let mut buf = [0; 1];
                                reader.read_exact(&mut buf)?;
                                data_len -= 1;
                                if buf[0] == 0x00 {
                                    break;
                                } else {
                                    purpose.push(buf[0]);
                                }
                            }

                            // is the purpose manifest?
                            if vec_compare(&purpose, MANIFEST.as_bytes()) {
                                // offset to first aux uuid with purpose merkle
                                let mut buf = [0u8; 8];
                                reader.read_exact(&mut buf)?;
                                data_len -= 8;

                                // offset to first aux uuid
                                let offset = u64::from_be_bytes(buf);

                                // if no offset this contains the manifest
                                if offset == 0 {
                                    if manifest_store_cnt == 0 {
                                        let mut manifest = vec![0u8; data_len as usize];
                                        reader.read_exact(&mut manifest)?;
                                        output = Some(manifest);

                                        manifest_store_cnt += 1;
                                    } else {
                                        return Err(Error::TooManyManifestStores);
                                    }
                                } else {
                                    // handle aux uuids
                                    let mut buf = vec![0u8; data_len as usize];
                                    reader.read_exact(&mut buf)?;

                                    let _mm: BmffMerkleMap = serde_cbor::from_slice(&buf)?;
                                }
                            } else if vec_compare(&purpose, MERKLE.as_bytes()) {
                                // handle merkle boxes not yet handled
                                return Err(Error::UnsupportedType);
                            }
                        }
                    }
                }
            }
        }

        output.ok_or(Error::JumbfNotFound)
    }

    // Get XMP block
    fn read_xmp(&self, _asset_reader: &mut dyn CAIRead) -> Option<String> {
        None
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
        let mut input = File::open(asset_path)?;
        let size = input.seek(SeekFrom::End(0))?;
        input.seek(SeekFrom::Start(0))?;

        // create root node
        let root_box = BoxInfo {
            path: "".to_string(),
            offset: 0,
            size: size as u64,
            box_type: BoxType::Empty,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };

        let (mut bmff_tree, root_token) = Arena::with_data(root_box);
        let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

        // build layout of the BMFF structure
        build_bmff_tree(
            &mut input,
            size as u64,
            &mut bmff_tree,
            &root_token,
            &mut bmff_map,
        )?;

        // get ftyp location
        // start after ftyp
        let ftyp_token = bmff_map.get("/ftyp").ok_or(Error::UnsupportedType)?; // todo check ftyps to make sure we supprt any special format requirements
        let ftyp_info = &bmff_tree[ftyp_token[0]].data;
        let ftyp_offset = ftyp_info.offset;
        let ftyp_size = ftyp_info.size;

        // get position to insert c2pa
        let (c2pa_start, c2pa_length) =
            if let Some(c2pa_token) = get_manifest_token(&bmff_tree, &bmff_map) {
                let uuid_info = &bmff_tree[c2pa_token].data;

                (uuid_info.offset, Some(uuid_info.size))
            } else {
                ((ftyp_offset + ftyp_size), None)
            };

        let mut new_c2pa_box: Vec<u8> = Vec::with_capacity(store_bytes.len() * 2);
        let merkle_data: &[u8] = &[]; // not yet supported
        write_c2pa_box(&mut new_c2pa_box, store_bytes, true, merkle_data)?;
        let new_c2pa_box_size = new_c2pa_box.len();

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        let (start, end) = if let Some(c2pa_length) = c2pa_length {
            let start = usize::value_from(c2pa_start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            let end = usize::value_from(c2pa_start + c2pa_length)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            (start, end)
        } else {
            // insert new c2pa
            let end = usize::value_from(c2pa_start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            (end, end)
        };

        // write content before ContentProvenanceBox
        input.seek(SeekFrom::Start(0))?;
        let mut b = vec![0u8; start];
        input.read_exact(&mut b)?;
        temp_file.write_all(&b)?;

        // write ContentProvenanceBox
        temp_file.write_all(&new_c2pa_box)?;

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
        input.seek(SeekFrom::Start(end as u64))?;
        let mut chunk = vec![0u8; 1024 * 1024];
        loop {
            let len = match input.read(&mut chunk) {
                Ok(0) => break,
                Ok(len) => len,
                Err(e) => return Err(Error::IoError(e)),
            };

            temp_file.write_all(&chunk[0..len])?;
        }
        temp_file.flush()?;

        // Manipulating the UUID box means we may need some patch offsets if they are file absolute offsets.
        match self.bmff_format.as_ref() {
            "m4a" | "mp4" | "mov" => {
                // create root node
                let root_box = BoxInfo {
                    path: "".to_string(),
                    offset: 0,
                    size: size as u64,
                    box_type: BoxType::Empty,
                    parent: None,
                    user_type: None,
                    version: None,
                    flags: None,
                };

                // rebuild box layout for output file
                let (mut output_bmff_tree, root_token) = Arena::with_data(root_box);
                let mut output_bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

                let size = temp_file.seek(SeekFrom::End(0))?;
                temp_file.seek(SeekFrom::Start(0))?;
                build_bmff_tree(
                    &mut temp_file,
                    size as u64,
                    &mut output_bmff_tree,
                    &root_token,
                    &mut output_bmff_map,
                )?;

                // adjust based on current layout
                adjust_stco_and_co64(
                    &mut temp_file,
                    &output_bmff_tree,
                    &output_bmff_map,
                    offset_adjust,
                )?;
            }
            _ => (), // todo: handle more patching cases as necessary
        }

        // copy temp file to asset
        std::fs::rename(&temp_file.path(), asset_path)
            // if rename fails, try to copy in case we are on different volumes
            .or_else(|_| std::fs::copy(&temp_file.path(), asset_path).and(Ok(())))
            .map_err(Error::IoError)
    }

    fn get_object_locations(
        &self,
        _asset_path: &std::path::Path,
    ) -> Result<Vec<HashObjectPositions>> {
        let vec: Vec<HashObjectPositions> = Vec::new();
        Ok(vec)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        let mut input = File::open(asset_path)?;
        let size = input.seek(SeekFrom::End(0))?;
        input.seek(SeekFrom::Start(0))?;

        // create root node
        let root_box = BoxInfo {
            path: "".to_string(),
            offset: 0,
            size: size as u64,
            box_type: BoxType::Empty,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };

        let (mut bmff_tree, root_token) = Arena::with_data(root_box);
        let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

        // build layout of the BMFF structure
        build_bmff_tree(
            &mut input,
            size as u64,
            &mut bmff_tree,
            &root_token,
            &mut bmff_map,
        )?;

        // get position of c2pa manifest
        let (c2pa_start, c2pa_length) =
            if let Some(c2pa_token) = get_manifest_token(&bmff_tree, &bmff_map) {
                let uuid_info = &bmff_tree[c2pa_token].data;

                (uuid_info.offset, Some(uuid_info.size))
            } else {
                return Ok(()); // no box to remove
            };

        let mut temp_file = Builder::new()
            .prefix("c2pa_temp")
            .rand_bytes(5)
            .tempfile()?;

        let (start, end) = if let Some(c2pa_length) = c2pa_length {
            let start = usize::value_from(c2pa_start)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?; // get beginning of chunk which starts 4 bytes before label

            let end = usize::value_from(c2pa_start + c2pa_length)
                .map_err(|_err| Error::InvalidAsset("value out of range".to_string()))?;

            (start, end)
        } else {
            return Err(Error::InvalidAsset("value out of range".to_string()));
        };

        // write content before ContentProvenanceBox
        input.seek(SeekFrom::Start(0))?;
        let mut b = vec![0u8; start];
        input.read_exact(&mut b)?;
        temp_file.write_all(&b)?;

        // calc offset adjustments
        // value will be negative since the box is truncated
        let new_c2pa_box_size: i32 = 0;
        let existing_c2pa_box_size = end - start;
        let offset_adjust = new_c2pa_box_size - existing_c2pa_box_size as i32;

        // write content after ContentProvenanceBox
        input.seek(SeekFrom::Start(end as u64))?;
        let mut chunk = vec![0u8; 1024 * 1024];
        loop {
            let len = match input.read(&mut chunk) {
                Ok(0) => break,
                Ok(len) => len,
                Err(e) => return Err(Error::IoError(e)),
            };

            temp_file.write_all(&chunk[0..len])?;
        }
        temp_file.flush()?;

        // Manipulating the UUID box means we may need some patch offsets if they are file absolute offsets.
        match self.bmff_format.as_ref() {
            "m4a" | "mp4" | "mov" => {
                // create root node
                let root_box = BoxInfo {
                    path: "".to_string(),
                    offset: 0,
                    size: size as u64,
                    box_type: BoxType::Empty,
                    parent: None,
                    user_type: None,
                    version: None,
                    flags: None,
                };

                // rebuild box layout for output file
                let (mut output_bmff_tree, root_token) = Arena::with_data(root_box);
                let mut output_bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

                let size = temp_file.seek(SeekFrom::End(0))?;
                temp_file.seek(SeekFrom::Start(0))?;
                build_bmff_tree(
                    &mut temp_file,
                    size as u64,
                    &mut output_bmff_tree,
                    &root_token,
                    &mut output_bmff_map,
                )?;

                // adjust based on current layout
                adjust_stco_and_co64(
                    &mut temp_file,
                    &output_bmff_tree,
                    &output_bmff_map,
                    offset_adjust,
                )?;
            }
            _ => (), // todo: handle more patching cases as necessary
        }

        // copy temp file to asset
        std::fs::rename(&temp_file.path(), asset_path)
            // if rename fails, try to copy in case we are on different volumes
            .or_else(|_| std::fs::copy(&temp_file.path(), asset_path).and(Ok(())))
            .map_err(Error::IoError)
    }
}

impl AssetPatch for BmffIO {
    fn patch_cai_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        let mut asset = OpenOptions::new()
            .write(true)
            .read(true)
            .create(false)
            .open(asset_path)?;
        let size = asset.seek(SeekFrom::End(0))?;
        asset.seek(SeekFrom::Start(0))?;

        // create root node
        let root_box = BoxInfo {
            path: "".to_string(),
            offset: 0,
            size: size as u64,
            box_type: BoxType::Empty,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };

        let (mut bmff_tree, root_token) = Arena::with_data(root_box);
        let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();

        // build layout of the BMFF structure
        build_bmff_tree(
            &mut asset,
            size as u64,
            &mut bmff_tree,
            &root_token,
            &mut bmff_map,
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
            write_c2pa_box(&mut new_c2pa_box, store_bytes, true, merkle_data)?;
            let new_c2pa_box_size = new_c2pa_box.len();

            if new_c2pa_box_size as u64 == manifest_length {
                asset.seek(SeekFrom::Start(c2pa_start as u64))?;
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

#[cfg(feature = "bmff")]
#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use tempfile::tempdir;

    use super::*;
    use crate::{
        status_tracker::{report_split_errors, DetailedStatusTracker, StatusTracker},
        store::Store,
        utils::test::{fixture_path, temp_dir_path},
    };

    #[test]
    fn test_read_mp4() {
        let ap = fixture_path("video1.mp4");

        let mut log = DetailedStatusTracker::default();
        let store = Store::load_from_asset(&ap, true, &mut log);

        let errors = report_split_errors(log.get_log_mut());
        assert!(errors.is_empty());

        if let Ok(s) = store {
            print!("Store: \n{}", s);
        }
    }

    #[test]
    fn test_truncated_c2pa_write_mp4() {
        let test_data = "some test data".as_bytes();
        let source = fixture_path("video1.mp4");

        let mut success = false;
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "mp4_test.mp4");

            if let Ok(_size) = std::fs::copy(&source, &output) {
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
        if let Ok(temp_dir) = tempdir() {
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
        if let Ok(temp_dir) = tempdir() {
            let output = temp_dir_path(&temp_dir, "mp4_test.mp4");

            if let Ok(_size) = std::fs::copy(&source, &output) {
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

        let temp_dir = tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "mp4_test.mp4");

        std::fs::copy(&source, &output).unwrap();
        let bmff_io = BmffIO::new("mp4");

        bmff_io.remove_cai_store(&output).unwrap();

        // read back in asset, JumbfNotFound is expected since it was removed
        match bmff_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => unreachable!(),
        }
    }
}
