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

//! Matroska and WebM asset handler.
//!
//! Implements the embedding described in the Matroska section of the C2PA
//! specification working draft (not yet in a published version, hence the
//! `unstable_matroska` feature):
//!
//! * The asset is one EBML Header followed by one `Segment` whose Element Data
//!   Size is encoded on 8 octets and reaches the end of the asset; no
//!   Top-Level Element has an unknown size, and `EBMLMaxSizeLength` is 8.
//! * The C2PA Manifest Store is the `FileData` of an `AttachedFile` whose
//!   `FileMediaType` is `application/c2pa` (the "C2PA `AttachedFile`", named
//!   `content_credential.c2pa`). It is the last child of the `Attachments`
//!   element, which is the last Top-Level Element, has an 8-octet Element
//!   Data Size, no `CRC-32`, and is referenced by a `Seek` of the first
//!   `SeekHead`. An `Attachments` element found elsewhere is relocated to the
//!   end byte for byte and replaced by a `Void` of the same size.
//! * The hard binding is `c2pa.hash.boxes`: the EBML Header (`1A45DFA3`), a
//!   12-byte `SEGh` box with its 8-octet size excluded, one box per
//!   Top-Level Element named by its Element ID in uppercase hex, and, in place
//!   of the `Attachments` element, a 12-byte `ATTh` box with its size excluded
//!   followed by one box per child, the C2PA `AttachedFile` being `C2PA`.
//!
//! The EBML reader and writer are minimal and in-tree: only Element IDs and
//! sizes are decoded, plus the few elements that carry Segment Positions
//! (`SeekHead`, `Cues`, `Cluster/Position`) when they have to be rewritten.

use std::io::{Cursor, Read, SeekFrom};

use crate::{
    asset_io::{
        AllowedExclusion, AssetBoxHash, AssetIO, AssetPatch, BoxMap, C2paReader, C2paWriter,
        ExclusionKind, ObjectLocations, ObjectType, ReadSeek, ReadWriteSeek, C2PA_BOXHASH,
    },
    error::{Error, Result},
    utils::io_utils::stream_len,
};

static SUPPORTED_TYPES: [&str; 11] = [
    "mkv",
    "mka",
    "mk3d",
    "webm",
    "video/matroska",
    "audio/matroska",
    "video/matroska-3d",
    "video/x-matroska",
    "audio/x-matroska",
    "video/webm",
    "audio/webm",
];

// Element IDs (RFC 8794, RFC 9559), including their VINT_MARKER bits.
const ID_EBML: u32 = 0x1a45_dfa3;
const ID_DOCTYPE: u32 = 0x4282;
const ID_EBML_MAX_SIZE_LENGTH: u32 = 0x42f3;
const ID_SEGMENT: u32 = 0x1853_8067;
const ID_SEEKHEAD: u32 = 0x114d_9b74;
const ID_SEEK: u32 = 0x4dbb;
const ID_SEEK_ID: u32 = 0x53ab;
const ID_SEEK_POSITION: u32 = 0x53ac;
const ID_INFO: u32 = 0x1549_a966;
const ID_TRACKS: u32 = 0x1654_ae6b;
const ID_CHAPTERS: u32 = 0x1043_a770;
const ID_TAGS: u32 = 0x1254_c367;
const ID_CLUSTER: u32 = 0x1f43_b675;
const ID_CLUSTER_POSITION: u32 = 0xa7;
const ID_SIMPLE_BLOCK: u32 = 0xa3;
const ID_BLOCK_GROUP: u32 = 0xa0;
const ID_ENCRYPTED_BLOCK: u32 = 0xaf;
const ID_CUES: u32 = 0x1c53_bb6b;
const ID_CUE_POINT: u32 = 0xbb;
const ID_CUE_TRACK_POSITIONS: u32 = 0xb7;
const ID_CUE_CLUSTER_POSITION: u32 = 0xf1;
const ID_CUE_CODEC_STATE: u32 = 0xea;
const ID_CUE_REFERENCE: u32 = 0xdb;
const ID_CUE_REF_CLUSTER: u32 = 0x97;
const ID_ATTACHMENTS: u32 = 0x1941_a469;
const ID_ATTACHED_FILE: u32 = 0x61a7;
const ID_FILE_DESCRIPTION: u32 = 0x467e;
const ID_FILE_NAME: u32 = 0x466e;
const ID_FILE_MEDIA_TYPE: u32 = 0x4660;
const ID_FILE_DATA: u32 = 0x465c;
const ID_FILE_UID: u32 = 0x46ae;
const ID_VOID: u32 = 0xec;
const ID_CRC32: u32 = 0xbf;

/// `FileName` of the C2PA `AttachedFile`.
pub(crate) const C2PA_FILE_NAME: &str = "content_credential.c2pa";
/// `FileMediaType` identifying the C2PA `AttachedFile`.
pub(crate) const C2PA_MEDIA_TYPE: &str = "application/c2pa";
/// Box name of the `Segment` header (ID + 8-octet size).
pub(crate) const SEGMENT_HEADER_BOX: &str = "SEGh";
/// Box name of the `Attachments` header (ID + 8-octet size).
pub(crate) const ATTACHMENTS_HEADER_BOX: &str = "ATTh";

/// Length of a 4-octet Element ID followed by an 8-octet Element Data Size.
const WIDE_HEADER_LEN: u64 = 12;
/// Offset of the Element Data Size within a `SEGh`/`ATTh` box.
const SIZE_FIELD_OFFSET: u64 = 4;
/// Required length of the `Segment` and `Attachments` Element Data Sizes, and
/// required `EBMLMaxSizeLength`.
const WIDE_SIZE_LEN: u8 = 8;
/// Upper bound for metadata elements decoded in memory (`SeekHead`, `Cues`,
/// EBML Header, `AttachedFile` metadata children).
const MAX_IN_MEMORY_ELEMENT: u64 = 64 * 1024 * 1024;
/// Nesting limit when decoding `SeekHead`/`Cues` trees.
const MAX_TREE_DEPTH: usize = 8;
/// Placeholder store written by [`AssetBoxHash::prepare_box_hash_stream`].
const PLACEHOLDER_STORE: &[u8] = b"c2pa manifest store placeholder";

fn invalid(msg: impl AsRef<str>) -> Error {
    Error::InvalidAsset(format!("Matroska: {}", msg.as_ref()))
}

// ---------------------------------------------------------------------------
// EBML primitives
// ---------------------------------------------------------------------------

/// Length of a VINT from its first octet (`None` for `0x00`).
fn vint_len(first: u8) -> Option<usize> {
    (first != 0).then(|| first.leading_zeros() as usize + 1)
}

/// Whether `value` can be stored as a known Element Data Size on `len` octets
/// (the all-ones value is reserved for the unknown size).
fn size_fits(value: u64, len: u8) -> bool {
    (1..=8).contains(&len) && value < (1u64 << (7 * len as u32)) - 1
}

fn min_size_len(value: u64) -> Result<u8> {
    (1..=8)
        .find(|&l| size_fits(value, l))
        .ok_or_else(|| invalid("element too large"))
}

fn encode_size(value: u64, len: u8) -> Result<Vec<u8>> {
    if !size_fits(value, len) {
        return Err(invalid("element size does not fit its size field"));
    }
    let len = len as usize;
    let mut out = value.to_be_bytes()[8 - len..].to_vec();
    out[0] |= 0x80 >> (len - 1);
    Ok(out)
}

/// The octets of an Element ID as stored (IDs keep their VINT_MARKER, so the
/// first stored octet is never zero).
fn id_bytes(id: u32) -> Vec<u8> {
    let b = id.to_be_bytes();
    b[(id.leading_zeros() / 8) as usize..].to_vec()
}

/// Box name of an element: its stored Element ID octets in uppercase hex.
pub(crate) fn element_box_name(id: u32) -> String {
    id_bytes(id).iter().map(|b| format!("{b:02X}")).collect()
}

fn decode_uint(b: &[u8]) -> Option<u64> {
    (b.len() <= 8).then(|| b.iter().fold(0u64, |a, &x| (a << 8) | x as u64))
}

/// Big-endian unsigned integer on at least `min_width` octets.
fn encode_uint(value: u64, min_width: usize) -> Vec<u8> {
    let needed = 8 - (value.leading_zeros() / 8) as usize;
    let w = needed.max(min_width).min(8);
    value.to_be_bytes()[8 - w..].to_vec()
}

/// An element with known size.
fn element(id: u32, data: &[u8]) -> Result<Vec<u8>> {
    element_with_size_len(id, data, min_size_len(data.len() as u64)?)
}

fn element_with_size_len(id: u32, data: &[u8], size_len: u8) -> Result<Vec<u8>> {
    let mut out = id_bytes(id);
    out.extend(encode_size(data.len() as u64, size_len)?);
    out.extend_from_slice(data);
    Ok(out)
}

/// CRC-32 as used by EBML `CRC-32` elements (IEEE 802.3, reflected).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// An EBML element header with known size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Elem {
    id: u32,
    /// Absolute offset of the Element ID.
    offset: u64,
    header_len: u64,
    size_len: u8,
    data_len: u64,
}

impl Elem {
    fn data_offset(&self) -> u64 {
        self.offset + self.header_len
    }

    fn end(&self) -> u64 {
        self.data_offset() + self.data_len
    }

    fn total_len(&self) -> u64 {
        self.header_len + self.data_len
    }

    fn id_len(&self) -> u64 {
        self.header_len - self.size_len as u64
    }
}

/// A raw element header: ID, ID length, size (`None` if unknown), size length.
struct RawHeader {
    id: u32,
    id_len: u8,
    size: Option<u64>,
    size_len: u8,
}

fn read_header_at(r: &mut dyn ReadSeek, pos: u64) -> Result<RawHeader> {
    r.seek(SeekFrom::Start(pos))?;
    let mut b = [0u8; 8];
    r.read_exact(&mut b[..1])?;
    let id_len = vint_len(b[0])
        .filter(|&l| l <= 4)
        .ok_or_else(|| invalid(format!("invalid Element ID at {pos}")))?;
    r.read_exact(&mut b[1..id_len])?;
    let id = b[..id_len].iter().fold(0u32, |a, &x| (a << 8) | x as u32);

    r.read_exact(&mut b[..1])?;
    let size_len =
        vint_len(b[0]).ok_or_else(|| invalid(format!("invalid Element Data Size at {pos}")))?;
    r.read_exact(&mut b[1..size_len])?;
    let mask = ((1u16 << (8 - size_len)) - 1) as u8;
    let value = b[1..size_len]
        .iter()
        .fold((b[0] & mask) as u64, |a, &x| (a << 8) | x as u64);
    let unknown = value == (1u64 << (7 * size_len as u32)) - 1;
    Ok(RawHeader {
        id,
        id_len: id_len as u8,
        size: (!unknown).then_some(value),
        size_len: size_len as u8,
    })
}

/// Reads the element at `pos`, which must end at or before `limit`.
fn read_elem(r: &mut dyn ReadSeek, pos: u64, limit: u64) -> Result<Elem> {
    let h = read_header_at(r, pos)?;
    let size = h.size.ok_or_else(|| {
        invalid(format!(
            "element {} at {pos} has an unknown size, which is not supported",
            element_box_name(h.id)
        ))
    })?;
    let e = Elem {
        id: h.id,
        offset: pos,
        header_len: (h.id_len + h.size_len) as u64,
        size_len: h.size_len,
        data_len: size,
    };
    if e.data_offset() > limit || size > limit - e.data_offset() {
        return Err(invalid(format!(
            "element {} at {pos} extends beyond its parent",
            element_box_name(h.id)
        )));
    }
    Ok(e)
}

/// Reads the child elements of `[start, end)`, which they must tile exactly.
fn read_children(r: &mut dyn ReadSeek, start: u64, end: u64) -> Result<Vec<Elem>> {
    let mut v = Vec::new();
    let mut pos = start;
    while pos < end {
        let e = read_elem(r, pos, end)?;
        pos = e.end();
        v.push(e);
    }
    Ok(v)
}

fn read_bytes(r: &mut dyn ReadSeek, pos: u64, len: u64) -> Result<Vec<u8>> {
    if len > MAX_IN_MEMORY_ELEMENT {
        return Err(invalid("metadata element too large"));
    }
    r.seek(SeekFrom::Start(pos))?;
    let mut v = vec![0u8; len as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn read_data(r: &mut dyn ReadSeek, e: &Elem) -> Result<Vec<u8>> {
    read_bytes(r, e.data_offset(), e.data_len)
}

/// Reads a short string element, without trailing NUL padding. Returns `None`
/// for implausibly long values.
fn read_short_string(r: &mut dyn ReadSeek, e: &Elem) -> Result<Option<String>> {
    if e.data_len > 256 {
        return Ok(None);
    }
    let mut b = read_data(r, e)?;
    while b.last() == Some(&0) {
        b.pop();
    }
    Ok(String::from_utf8(b).ok())
}

// ---------------------------------------------------------------------------
// In-memory element trees (SeekHead, Cues, EBML Header)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    id: u32,
    size_len: u8,
    body: Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Body {
    Leaf(Vec<u8>),
    Master(Vec<Node>),
}

fn is_master(id: u32) -> bool {
    matches!(
        id,
        ID_SEEK | ID_CUE_POINT | ID_CUE_TRACK_POSITIONS | ID_CUE_REFERENCE
    )
}

fn parse_nodes(data: &[u8], depth: usize) -> Result<Vec<Node>> {
    if depth > MAX_TREE_DEPTH {
        return Err(invalid("elements nested too deeply"));
    }
    let mut c = Cursor::new(data);
    let mut out = Vec::new();
    for e in read_children(&mut c, 0, data.len() as u64)? {
        let bytes = &data[e.data_offset() as usize..e.end() as usize];
        let body = if is_master(e.id) {
            Body::Master(parse_nodes(bytes, depth + 1)?)
        } else {
            Body::Leaf(bytes.to_vec())
        };
        out.push(Node {
            id: e.id,
            size_len: e.size_len,
            body,
        });
    }
    Ok(out)
}

/// Serializes child nodes, recomputing a leading `CRC-32` element over the
/// other children.
fn serialize_children(nodes: &[Node]) -> Result<Vec<u8>> {
    let mut parts = nodes
        .iter()
        .map(serialize_node)
        .collect::<Result<Vec<_>>>()?;
    if let Some(first) = nodes.first() {
        if first.id == ID_CRC32 && matches!(&first.body, Body::Leaf(b) if b.len() == 4) {
            let crc = crc32(&parts[1..].concat());
            parts[0] = element_with_size_len(ID_CRC32, &crc.to_le_bytes(), first.size_len)?;
        }
    }
    Ok(parts.concat())
}

fn serialize_node(n: &Node) -> Result<Vec<u8>> {
    let data = match &n.body {
        Body::Leaf(b) => b.clone(),
        Body::Master(children) => serialize_children(children)?,
    };
    let size_len = if size_fits(data.len() as u64, n.size_len) {
        n.size_len
    } else {
        min_size_len(data.len() as u64)?
    };
    element_with_size_len(n.id, &data, size_len)
}

fn is_position_leaf(id: u32) -> bool {
    matches!(
        id,
        ID_SEEK_POSITION | ID_CUE_CLUSTER_POSITION | ID_CUE_CODEC_STATE | ID_CUE_REF_CLUSTER
    )
}

/// Replaces an unsigned leaf value, keeping its width when the value fits.
fn set_uint(b: &mut Vec<u8>, value: u64) -> bool {
    if decode_uint(b) == Some(value) {
        return false;
    }
    *b = encode_uint(value, b.len());
    true
}

/// Maps every Segment Position stored in `nodes` through `map`.
fn remap_positions(nodes: &mut [Node], map: &dyn Fn(u64) -> u64) -> bool {
    let mut changed = false;
    for n in nodes {
        match &mut n.body {
            Body::Master(c) => changed |= remap_positions(c, map),
            Body::Leaf(b) if is_position_leaf(n.id) => {
                if let Some(old) = decode_uint(b) {
                    // A CueCodecState of 0 means "no codec state", not a position.
                    if n.id == ID_CUE_CODEC_STATE && old == 0 {
                        continue;
                    }
                    changed |= set_uint(b, map(old));
                }
            }
            Body::Leaf(_) => {}
        }
    }
    changed
}

fn seek_target(seek: &Node) -> Option<&[u8]> {
    match &seek.body {
        Body::Master(c) => c.iter().find_map(|n| match &n.body {
            Body::Leaf(b) if n.id == ID_SEEK_ID => Some(b.as_slice()),
            _ => None,
        }),
        Body::Leaf(_) => None,
    }
}

fn seek_node(target: u32, pos: u64) -> Node {
    Node {
        id: ID_SEEK,
        size_len: 1,
        body: Body::Master(vec![
            Node {
                id: ID_SEEK_ID,
                size_len: 1,
                body: Body::Leaf(id_bytes(target)),
            },
            Node {
                id: ID_SEEK_POSITION,
                size_len: 1,
                body: Body::Leaf(encode_uint(pos, 1)),
            },
        ]),
    }
}

/// Updates the `Seek` entries of a `SeekHead`: positions are mapped through
/// `map`, the `Attachments` entries are set to `att_pos` (or removed when there
/// is no `Attachments` element), and one is added when `ensure` is set.
fn rewrite_seekhead(
    nodes: &mut Vec<Node>,
    map: &dyn Fn(u64) -> u64,
    att_pos: Option<u64>,
    ensure: bool,
) -> bool {
    let att_id = id_bytes(ID_ATTACHMENTS);
    let mut changed = false;
    let mut found = false;
    nodes.retain_mut(|n| {
        if n.id != ID_SEEK {
            return true;
        }
        let is_att = seek_target(n) == Some(att_id.as_slice());
        let Body::Master(children) = &mut n.body else {
            return true;
        };
        if is_att {
            let Some(p) = att_pos else {
                changed = true;
                return false;
            };
            found = true;
            for c in children.iter_mut() {
                if let (ID_SEEK_POSITION, Body::Leaf(b)) = (c.id, &mut c.body) {
                    changed |= set_uint(b, p);
                }
            }
        } else {
            changed |= remap_positions(children, map);
        }
        true
    });
    if ensure && !found {
        if let Some(p) = att_pos {
            let at = nodes
                .iter()
                .rposition(|n| n.id == ID_SEEK)
                .map_or(nodes.len(), |i| i + 1);
            nodes.insert(at, seek_node(ID_ATTACHMENTS, p));
            changed = true;
        }
    }
    changed
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Parsed top-level structure of a Matroska/WebM file with known sizes.
#[derive(Debug)]
struct Layout {
    file_len: u64,
    ebml: Elem,
    segment: Elem,
    /// Top-Level Elements (children of the `Segment`), in file order.
    children: Vec<Elem>,
}

impl Layout {
    fn attachments(&self) -> Result<Option<(usize, Elem)>> {
        let mut it = self
            .children
            .iter()
            .enumerate()
            .filter(|(_, e)| e.id == ID_ATTACHMENTS);
        let first = it.next().map(|(i, e)| (i, *e));
        if it.next().is_some() {
            return Err(invalid("more than one Attachments element"));
        }
        Ok(first)
    }
}

/// Reads and checks the EBML Header (`DocType` `matroska` or `webm`).
fn parse_ebml_header(r: &mut dyn ReadSeek) -> Result<Elem> {
    let file_len = stream_len(r)?;
    let h = read_header_at(r, 0).map_err(|_| Error::UnsupportedType)?;
    if h.id != ID_EBML {
        return Err(Error::UnsupportedType);
    }
    let ebml = read_elem(r, 0, file_len)?;
    let mut doc_type = None;
    for c in read_children(r, ebml.data_offset(), ebml.end())? {
        if c.id == ID_DOCTYPE {
            doc_type = read_short_string(r, &c)?;
        }
    }
    match doc_type.as_deref() {
        Some("matroska") | Some("webm") => Ok(ebml),
        _ => Err(Error::UnsupportedType),
    }
}

/// Parses the EBML Header, the single `Segment` and its Top-Level Elements.
///
/// Rejects unknown sizes, elements overrunning their parent, more than one
/// `Segment` and data after the `Segment`.
fn parse_layout(r: &mut dyn ReadSeek) -> Result<Layout> {
    let file_len = stream_len(r)?;
    let ebml = parse_ebml_header(r)?;
    if ebml.end() >= file_len {
        return Err(invalid("no Segment element"));
    }
    let h = read_header_at(r, ebml.end())?;
    if h.id != ID_SEGMENT {
        return Err(invalid(
            "the EBML Header is not immediately followed by a Segment",
        ));
    }
    if h.size.is_none() {
        return Err(invalid(
            "the Segment has an unknown size, which is not supported",
        ));
    }
    let segment = read_elem(r, ebml.end(), file_len)
        .map_err(|_| invalid("the Segment extends beyond the end of the asset"))?;
    if segment.end() < file_len {
        let next = read_header_at(r, segment.end()).ok();
        return Err(if next.is_some_and(|h| h.id == ID_SEGMENT) {
            invalid("more than one Segment is not supported")
        } else {
            invalid("data follows the end of the Segment")
        });
    }
    let children = read_children(r, segment.data_offset(), segment.end())?;
    Ok(Layout {
        file_len,
        ebml,
        segment,
        children,
    })
}

#[derive(Debug, Clone)]
struct AttachedFileInfo {
    elem: Elem,
    children: Vec<Elem>,
    is_c2pa: bool,
}

impl AttachedFileInfo {
    fn file_data(&self) -> Option<Elem> {
        self.children.iter().find(|c| c.id == ID_FILE_DATA).copied()
    }
}

fn parse_attached_file(r: &mut dyn ReadSeek, e: &Elem) -> Result<AttachedFileInfo> {
    let children = read_children(r, e.data_offset(), e.end())?;
    let mut is_c2pa = false;
    for c in children.iter().filter(|c| c.id == ID_FILE_MEDIA_TYPE) {
        is_c2pa = read_short_string(r, c)?
            .is_some_and(|m| m.trim().eq_ignore_ascii_case(C2PA_MEDIA_TYPE));
    }
    Ok(AttachedFileInfo {
        elem: *e,
        children,
        is_c2pa,
    })
}

/// The children of an `Attachments` element, with the C2PA `AttachedFile`s
/// identified.
fn attachments_children(
    r: &mut dyn ReadSeek,
    att: &Elem,
) -> Result<Vec<(Elem, Option<AttachedFileInfo>)>> {
    read_children(r, att.data_offset(), att.end())?
        .into_iter()
        .map(|c| {
            let info = if c.id == ID_ATTACHED_FILE {
                Some(parse_attached_file(r, &c)?).filter(|i| i.is_c2pa)
            } else {
                None
            };
            Ok((c, info))
        })
        .collect()
}

/// The single C2PA `AttachedFile` of an `Attachments` element; `None` if there
/// is none or more than one.
fn single_c2pa_attached_file(r: &mut dyn ReadSeek, att: &Elem) -> Result<Option<AttachedFileInfo>> {
    let mut found: Vec<AttachedFileInfo> = attachments_children(r, att)?
        .into_iter()
        .filter_map(|(_, i)| i)
        .collect();
    Ok(if found.len() == 1 { found.pop() } else { None })
}

/// Locates the `Attachments` element as the specification's "Locating the
/// Manifest Store" procedure does: through the first `SeekHead`, falling back
/// to a scan of the Top-Level Elements. Tolerates an unknown-size `Segment`.
fn locate_attachments(r: &mut dyn ReadSeek) -> Result<Option<Elem>> {
    let file_len = stream_len(r)?;
    let ebml = parse_ebml_header(r)?;
    if ebml.end() >= file_len {
        return Ok(None);
    }
    let h = read_header_at(r, ebml.end())?;
    if h.id != ID_SEGMENT {
        return Ok(None);
    }
    let seg_data = ebml.end() + (h.id_len + h.size_len) as u64;
    let seg_end = h
        .size
        .and_then(|s| seg_data.checked_add(s))
        .map_or(file_len, |e| e.min(file_len));

    // Via the first SeekHead.
    let mut pos = seg_data;
    while pos < seg_end {
        let Ok(e) = read_elem(r, pos, seg_end) else {
            break;
        };
        if e.id == ID_CRC32 {
            pos = e.end();
            continue;
        }
        if e.id == ID_SEEKHEAD {
            let nodes = parse_nodes(&read_data(r, &e)?, 0)?;
            let att_id = id_bytes(ID_ATTACHMENTS);
            for seek in nodes.iter().filter(|n| n.id == ID_SEEK) {
                if seek_target(seek) != Some(att_id.as_slice()) {
                    continue;
                }
                let Body::Master(children) = &seek.body else {
                    continue;
                };
                for c in children.iter().filter(|c| c.id == ID_SEEK_POSITION) {
                    let Body::Leaf(b) = &c.body else { continue };
                    let Some(at) = decode_uint(b).and_then(|p| seg_data.checked_add(p)) else {
                        continue;
                    };
                    if at < seg_end {
                        if let Ok(att) = read_elem(r, at, seg_end) {
                            if att.id == ID_ATTACHMENTS {
                                return Ok(Some(att));
                            }
                        }
                    }
                }
            }
        }
        break;
    }

    // Fallback: scan the Top-Level Elements.
    let mut pos = seg_data;
    while pos < seg_end {
        let Ok(e) = read_elem(r, pos, seg_end) else {
            break;
        };
        if e.id == ID_ATTACHMENTS {
            return Ok(Some(e));
        }
        pos = e.end();
    }
    Ok(None)
}

/// The C2PA `AttachedFile` and its `FileData`, located per the specification.
fn locate_c2pa(r: &mut dyn ReadSeek) -> Result<Option<(AttachedFileInfo, Elem)>> {
    let Some(att) = locate_attachments(r)? else {
        return Ok(None);
    };
    let Some(af) = single_c2pa_attached_file(r, &att)? else {
        return Ok(None);
    };
    Ok(af.file_data().map(|fd| (af, fd)))
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Copy { start: u64, len: u64 },
    Bytes(Vec<u8>),
    Zeros(u64),
}

impl Piece {
    fn len(&self) -> u64 {
        match self {
            Piece::Copy { len, .. } => *len,
            Piece::Bytes(b) => b.len() as u64,
            Piece::Zeros(n) => *n,
        }
    }
}

fn pieces_len(p: &[Piece]) -> u64 {
    p.iter().map(Piece::len).sum()
}

/// A `Void` element of exactly `total` octets, preferring a size field of
/// `size_len_hint` octets. `None` for a single octet, which no element fits.
fn void_pieces(total: u64, size_len_hint: Option<u8>) -> Option<Vec<Piece>> {
    size_len_hint.into_iter().chain(1..=8).find_map(|k| {
        let data = total.checked_sub(1 + k as u64)?;
        let size = encode_size(data, k).ok()?;
        let mut header = id_bytes(ID_VOID);
        header.extend(size);
        Some(vec![Piece::Bytes(header), Piece::Zeros(data)])
    })
}

/// Encodes element `id` with `data` into exactly `budget` octets, followed by
/// a `Void` for any remaining space. Widens the size field when the remainder
/// is a single octet.
fn fit_with_void(
    id: u32,
    data: &[u8],
    size_len: u8,
    budget: u64,
    void_hint: Option<u8>,
) -> Option<Vec<Piece>> {
    for l in size_len.max(1)..=8 {
        if !size_fits(data.len() as u64, l) {
            continue;
        }
        let bytes = element_with_size_len(id, data, l).ok()?;
        let rest = budget.checked_sub(bytes.len() as u64)?;
        if rest == 0 {
            return Some(vec![Piece::Bytes(bytes)]);
        }
        if let Some(v) = void_pieces(rest, void_hint) {
            let mut p = vec![Piece::Bytes(bytes)];
            p.extend(v);
            return Some(p);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Plain,
    SeekHead { first: bool },
    NewSeekHead,
    Cues,
    Cluster,
    Void,
    Attachments,
}

#[derive(Debug, Clone)]
struct Item {
    pieces: Vec<Piece>,
    /// The source element (`None` for new items).
    elem: Option<Elem>,
    role: Role,
}

impl Item {
    fn len(&self) -> u64 {
        pieces_len(&self.pieces)
    }
}

/// The C2PA `AttachedFile` element for `store`. An existing C2PA
/// `AttachedFile` that already has the specified shape keeps its children (and
/// so its `FileUID`), with only its `FileData` replaced.
fn c2pa_attached_file(
    r: &mut dyn ReadSeek,
    store: &[u8],
    existing: Option<&AttachedFileInfo>,
) -> Result<Vec<u8>> {
    let mut file_data = id_bytes(ID_FILE_DATA);
    file_data.extend(encode_size(store.len() as u64, WIDE_SIZE_LEN)?);
    file_data.extend_from_slice(store);

    let reusable = existing.filter(|af| {
        let count = |id| af.children.iter().filter(|c| c.id == id).count();
        af.children.iter().all(|c| {
            matches!(
                c.id,
                ID_FILE_NAME
                    | ID_FILE_MEDIA_TYPE
                    | ID_FILE_UID
                    | ID_FILE_DATA
                    | ID_FILE_DESCRIPTION
            )
        }) && [ID_FILE_NAME, ID_FILE_MEDIA_TYPE, ID_FILE_UID, ID_FILE_DATA]
            .iter()
            .all(|&id| count(id) == 1)
            && count(ID_FILE_DESCRIPTION) <= 1
    });

    let mut data = Vec::new();
    match reusable {
        Some(af) => {
            for c in &af.children {
                if c.id == ID_FILE_DATA {
                    data.extend_from_slice(&file_data);
                } else {
                    data.extend(read_bytes(r, c.offset, c.total_len())?);
                }
            }
        }
        None => {
            let uid = loop {
                let (v, _) = uuid::Uuid::new_v4().as_u64_pair();
                if v != 0 {
                    break v;
                }
            };
            data.extend(element(ID_FILE_NAME, C2PA_FILE_NAME.as_bytes())?);
            data.extend(element(ID_FILE_MEDIA_TYPE, C2PA_MEDIA_TYPE.as_bytes())?);
            data.extend(element(ID_FILE_UID, &uid.to_be_bytes())?);
            data.extend_from_slice(&file_data);
        }
    }
    element_with_size_len(ID_ATTACHED_FILE, &data, WIDE_SIZE_LEN)
}

/// The EBML Header with `EBMLMaxSizeLength` set to 8 when it has another value.
fn normalized_ebml_header(r: &mut dyn ReadSeek, ebml: &Elem) -> Result<Vec<u8>> {
    let raw = read_bytes(r, ebml.offset, ebml.total_len())?;
    let mut nodes = parse_nodes(&raw[ebml.header_len as usize..], 0)?;
    let mut changed = false;
    for n in nodes.iter_mut().filter(|n| n.id == ID_EBML_MAX_SIZE_LENGTH) {
        if let Body::Leaf(b) = &mut n.body {
            changed |= set_uint(b, WIDE_SIZE_LEN as u64);
        }
    }
    if !changed {
        return Ok(raw);
    }
    serialize_node(&Node {
        id: ID_EBML,
        size_len: ebml.size_len,
        body: Body::Master(nodes),
    })
}

/// Position of the `Cluster/Position` child of a cluster, if it has one before
/// its first block.
fn cluster_position_child(r: &mut dyn ReadSeek, cluster: &Elem) -> Result<Option<Elem>> {
    let mut pos = cluster.data_offset();
    while pos < cluster.end() {
        let e = read_elem(r, pos, cluster.end())?;
        match e.id {
            ID_CLUSTER_POSITION => return Ok(Some(e)),
            ID_SIMPLE_BLOCK | ID_BLOCK_GROUP | ID_ENCRYPTED_BLOCK => return Ok(None),
            _ => pos = e.end(),
        }
    }
    Ok(None)
}

/// Computes the output of embedding `store` (or of removing the C2PA
/// `AttachedFile` when `store` is empty) as a list of pieces.
struct Plan {
    ebml_header: Vec<u8>,
    items: Vec<Item>,
}

fn plan_write(r: &mut dyn ReadSeek, layout: &Layout, store: &[u8]) -> Result<Plan> {
    let ebml_header = normalized_ebml_header(r, &layout.ebml)?;
    let seg_data = layout.segment.data_offset();
    let existing_att = layout.attachments()?;

    // Children of the new Attachments element, other than the C2PA AttachedFile.
    let mut att_children = Vec::new();
    let mut c2pa_files = Vec::new();
    if let Some((_, att)) = existing_att {
        for (c, info) in attachments_children(r, &att)? {
            if c.id == ID_CRC32 {
                continue;
            }
            match info {
                Some(i) => c2pa_files.push(i),
                None => att_children.push(Piece::Copy {
                    start: c.offset,
                    len: c.total_len(),
                }),
            }
        }
    }
    let c2pa = if store.is_empty() {
        None
    } else {
        let existing = (c2pa_files.len() == 1).then(|| &c2pa_files[0]);
        Some(c2pa_attached_file(r, store, existing)?)
    };
    let new_att = if att_children.is_empty() && c2pa.is_none() {
        None
    } else {
        let data_len = pieces_len(&att_children) + c2pa.as_ref().map_or(0, |c| c.len() as u64);
        let mut header = id_bytes(ID_ATTACHMENTS);
        header.extend(encode_size(data_len, WIDE_SIZE_LEN)?);
        let mut pieces = vec![Piece::Bytes(header)];
        pieces.extend(att_children);
        pieces.extend(c2pa.map(Piece::Bytes));
        Some(pieces)
    };

    // Top-Level Elements; an Attachments element that is not the last one is
    // replaced by a Void of the same size.
    let last = layout.children.len().saturating_sub(1);
    let first_non_crc = layout.children.iter().position(|e| e.id != ID_CRC32);
    let first_seekhead = first_non_crc.filter(|&i| layout.children[i].id == ID_SEEKHEAD);
    let mut base = Vec::new();
    for (i, e) in layout.children.iter().enumerate() {
        if e.id == ID_ATTACHMENTS {
            if i != last {
                base.push(Item {
                    pieces: void_pieces(e.total_len(), None)
                        .ok_or_else(|| invalid("cannot replace Attachments"))?,
                    elem: Some(*e),
                    role: Role::Void,
                });
            }
            continue;
        }
        let role = match e.id {
            ID_SEEKHEAD => Role::SeekHead {
                first: Some(i) == first_seekhead,
            },
            ID_CUES => Role::Cues,
            ID_CLUSTER => Role::Cluster,
            ID_VOID => Role::Void,
            _ => Role::Plain,
        };
        base.push(Item {
            pieces: vec![Piece::Copy {
                start: e.offset,
                len: e.total_len(),
            }],
            elem: Some(*e),
            role,
        });
    }
    if let Some(p) = new_att {
        base.push(Item {
            pieces: p,
            elem: None,
            role: Role::Attachments,
        });
    }

    if let Some(items) = plan_in_place(r, &base)? {
        return Ok(Plan { ebml_header, items });
    }
    let items = plan_shifted(r, base, seg_data, first_non_crc.unwrap_or(0))?;
    Ok(Plan { ebml_header, items })
}

fn starts(items: &[Item]) -> Vec<u64> {
    let mut pos = 0;
    items
        .iter()
        .map(|it| {
            let s = pos;
            pos += it.len();
            s
        })
        .collect()
}

fn attachments_pos(items: &[Item]) -> Option<u64> {
    let s = starts(items);
    items
        .iter()
        .position(|it| it.role == Role::Attachments)
        .map(|i| s[i])
}

/// Updates the `SeekHead` elements without moving any other Top-Level
/// Element: the first `SeekHead` may use the `Void` that follows it. Returns
/// `None` when there is not enough room.
fn plan_in_place(r: &mut dyn ReadSeek, base: &[Item]) -> Result<Option<Vec<Item>>> {
    let mut items = base.to_vec();
    let att_pos = attachments_pos(&items);
    let has_first = items
        .iter()
        .any(|it| it.role == Role::SeekHead { first: true });
    if att_pos.is_some() && !has_first {
        return Ok(None);
    }
    let identity = |p: u64| p;
    let mut i = 0;
    while i < items.len() {
        let Role::SeekHead { first } = items[i].role else {
            i += 1;
            continue;
        };
        let Some(elem) = items[i].elem else {
            i += 1;
            continue;
        };
        let mut nodes = parse_nodes(&read_data(r, &elem)?, 0)?;
        if !rewrite_seekhead(&mut nodes, &identity, att_pos, first) {
            i += 1;
            continue;
        }
        let data = serialize_children(&nodes)?;
        let next_void = items
            .get(i + 1)
            .filter(|it| first && it.role == Role::Void)
            .map(|it| {
                (
                    it.len(),
                    it.elem.filter(|e| e.id == ID_VOID).map(|e| e.size_len),
                )
            });
        let budget = elem.total_len() + next_void.map_or(0, |(l, _)| l);
        let hint = next_void.and_then(|(_, h)| h);
        let Some(pieces) = fit_with_void(ID_SEEKHEAD, &data, elem.size_len, budget, hint) else {
            return Ok(None);
        };
        items[i].pieces = pieces;
        if next_void.is_some() {
            items.remove(i + 1);
        }
        i += 1;
    }
    Ok(Some(items))
}

/// Rewrites every stored Segment Position for a layout in which Top-Level
/// Elements move (no room for the `Seek` entry, or no `SeekHead` at all).
fn plan_shifted(
    r: &mut dyn ReadSeek,
    mut items: Vec<Item>,
    seg_data: u64,
    new_seekhead_at: usize,
) -> Result<Vec<Item>> {
    let has_att = items.iter().any(|it| it.role == Role::Attachments);
    let has_first = items
        .iter()
        .any(|it| it.role == Role::SeekHead { first: true });
    if has_att && !has_first {
        items.insert(
            new_seekhead_at.min(items.len()),
            Item {
                pieces: vec![],
                elem: None,
                role: Role::NewSeekHead,
            },
        );
    }

    // Decoded trees and Cluster/Position children, computed once.
    let mut trees: Vec<Option<Vec<Node>>> = Vec::with_capacity(items.len());
    let mut cluster_pos: Vec<Option<Elem>> = Vec::with_capacity(items.len());
    for it in &items {
        let tree = match (it.role, it.elem) {
            (Role::SeekHead { .. } | Role::Cues, Some(e)) => {
                Some(parse_nodes(&read_data(r, &e)?, 0)?)
            }
            _ => None,
        };
        trees.push(tree);
        cluster_pos.push(match (it.role, it.elem) {
            (Role::Cluster, Some(e)) => cluster_position_child(r, &e)?,
            _ => None,
        });
    }

    for _ in 0..32 {
        let before: Vec<u64> = items.iter().map(Item::len).collect();
        let new_starts = starts(&items);
        // (old relative start, old length, new relative start), by old start.
        let mut moves: Vec<(u64, u64, u64)> = items
            .iter()
            .zip(&new_starts)
            .filter_map(|(it, &s)| it.elem.map(|e| (e.offset - seg_data, e.total_len(), s)))
            .collect();
        moves.sort_unstable();
        let map = |p: u64| -> u64 {
            let i = moves.partition_point(|m| m.0 <= p);
            match i.checked_sub(1).map(|i| moves[i]) {
                Some((old, len, new)) if p < old + len => new + (p - old),
                _ => p,
            }
        };
        let att_pos = items
            .iter()
            .position(|it| it.role == Role::Attachments)
            .map(|i| new_starts[i]);

        for (i, it) in items.iter_mut().enumerate() {
            match (it.role, it.elem) {
                (Role::SeekHead { first }, Some(e)) => {
                    let mut nodes = trees[i].clone().unwrap_or_default();
                    it.pieces = if rewrite_seekhead(&mut nodes, &map, att_pos, first) {
                        vec![Piece::Bytes(serialize_node(&Node {
                            id: ID_SEEKHEAD,
                            size_len: e.size_len,
                            body: Body::Master(nodes),
                        })?)]
                    } else {
                        vec![Piece::Copy {
                            start: e.offset,
                            len: e.total_len(),
                        }]
                    };
                }
                (Role::Cues, Some(e)) => {
                    let mut nodes = trees[i].clone().unwrap_or_default();
                    it.pieces = if remap_positions(&mut nodes, &map) {
                        vec![Piece::Bytes(serialize_node(&Node {
                            id: ID_CUES,
                            size_len: e.size_len,
                            body: Body::Master(nodes),
                        })?)]
                    } else {
                        vec![Piece::Copy {
                            start: e.offset,
                            len: e.total_len(),
                        }]
                    };
                }
                (Role::Cluster, Some(e)) => {
                    if let Some(pc) = cluster_pos[i] {
                        let mut v = read_data(r, &pc)?;
                        let width = v.len();
                        if set_uint(&mut v, new_starts[i]) {
                            if v.len() != width {
                                return Err(invalid(
                                    "cannot update a Cluster Position that does not fit its field",
                                ));
                            }
                            let first = read_elem(r, e.data_offset(), e.end())?;
                            if first.id == ID_CRC32 && first.data_len == 4 {
                                // Recompute the Cluster's CRC-32 over its patched data.
                                let mut data = read_data(r, &e)?;
                                let at = (pc.data_offset() - e.data_offset()) as usize;
                                data[at..at + width].copy_from_slice(&v);
                                let crc_end = (first.end() - e.data_offset()) as usize;
                                let crc = crc32(&data[crc_end..]);
                                data[crc_end - 4..crc_end].copy_from_slice(&crc.to_le_bytes());
                                let mut bytes = read_bytes(r, e.offset, e.header_len)?;
                                bytes.extend(data);
                                it.pieces = vec![Piece::Bytes(bytes)];
                                continue;
                            }
                            it.pieces = vec![
                                Piece::Copy {
                                    start: e.offset,
                                    len: pc.data_offset() - e.offset,
                                },
                                Piece::Bytes(v),
                                Piece::Copy {
                                    start: pc.end(),
                                    len: e.end() - pc.end(),
                                },
                            ];
                        }
                    }
                }
                _ => {}
            }
        }

        // A new SeekHead references the main Top-Level Elements.
        if let Some(i) = items.iter().position(|it| it.role == Role::NewSeekHead) {
            let mut seeks = Vec::new();
            for target in [ID_INFO, ID_TRACKS, ID_CHAPTERS, ID_TAGS, ID_CUES] {
                if let Some(j) = items
                    .iter()
                    .position(|it| it.elem.is_some_and(|e| e.id == target))
                {
                    seeks.push(seek_node(target, new_starts[j]));
                }
            }
            if let Some(p) = att_pos {
                seeks.push(seek_node(ID_ATTACHMENTS, p));
            }
            items[i].pieces = vec![Piece::Bytes(element(
                ID_SEEKHEAD,
                &serialize_children(&seeks)?,
            )?)];
        }

        let after: Vec<u64> = items.iter().map(Item::len).collect();
        if before == after {
            return Ok(items);
        }
    }
    Err(invalid("could not compute a stable layout"))
}

fn write_pieces(r: &mut dyn ReadSeek, w: &mut dyn ReadWriteSeek, pieces: &[Piece]) -> Result<()> {
    for p in pieces {
        match p {
            Piece::Copy { start, len } => {
                r.seek(SeekFrom::Start(*start))?;
                let copied = std::io::copy(&mut r.take(*len), w)?;
                if copied != *len {
                    return Err(invalid("unexpected end of stream"));
                }
            }
            Piece::Bytes(b) => w.write_all(b)?,
            Piece::Zeros(n) => {
                let zeros = [0u8; 4096];
                let mut left = *n;
                while left > 0 {
                    let k = left.min(zeros.len() as u64) as usize;
                    w.write_all(&zeros[..k])?;
                    left -= k as u64;
                }
            }
        }
    }
    Ok(())
}

fn write_plan(r: &mut dyn ReadSeek, w: &mut dyn ReadWriteSeek, plan: &Plan) -> Result<()> {
    let seg_len: u64 = plan.items.iter().map(Item::len).sum();
    w.rewind()?;
    w.write_all(&plan.ebml_header)?;
    w.write_all(&id_bytes(ID_SEGMENT))?;
    w.write_all(&encode_size(seg_len, WIDE_SIZE_LEN)?)?;
    for it in &plan.items {
        write_pieces(r, w, &it.pieces)?;
    }
    w.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

pub struct MatroskaIO {
    _asset_type: String,
}

impl C2paReader for MatroskaIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let (_, fd) = locate_c2pa(input_stream)?.ok_or(Error::JumbfNotFound)?;
        input_stream.seek(SeekFrom::Start(fd.data_offset()))?;
        let mut data = vec![0u8; fd.data_len as usize];
        input_stream.read_exact(&mut data)?;
        if data.is_empty() {
            return Err(Error::JumbfNotFound);
        }
        Ok(data)
    }

    /// Matroska carries metadata in `Tags`, not XMP; not supported.
    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for MatroskaIO {
    /// Embeds `store` as the C2PA `AttachedFile`, replacing an existing one.
    /// An empty `store` removes the C2PA `AttachedFile`.
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let layout = parse_layout(input_stream)?;
        if store_bytes.is_empty() {
            let has_c2pa = match layout.attachments()? {
                Some((_, att)) => attachments_children(input_stream, &att)?
                    .iter()
                    .any(|(_, i)| i.is_some()),
                None => false,
            };
            if !has_c2pa {
                input_stream.rewind()?;
                output_stream.rewind()?;
                std::io::copy(input_stream, output_stream)?;
                output_stream.flush()?;
                return Ok(());
            }
        }
        let plan = plan_write(input_stream, &layout, store_bytes)?;
        write_plan(input_stream, output_stream, &plan)
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let mut with_c2pa = Cursor::new(Vec::new());
        let (stream, file_len): (&mut dyn ReadSeek, u64) = if locate_c2pa(input_stream)?.is_some() {
            let len = stream_len(input_stream)?;
            (input_stream, len)
        } else {
            self.write_c2pa(input_stream, &mut with_c2pa, PLACEHOLDER_STORE)?;
            let len = with_c2pa.get_ref().len() as u64;
            (&mut with_c2pa, len)
        };
        let (af, _) = locate_c2pa(stream)?.ok_or(Error::JumbfNotFound)?;
        let e = af.elem;
        let mut locs = vec![
            ObjectLocations {
                offset: 0,
                length: e.offset,
                htype: ObjectType::Other,
            },
            ObjectLocations {
                offset: e.offset,
                length: e.total_len(),
                htype: ObjectType::C2pa,
            },
        ];
        if e.end() < file_len {
            locs.push(ObjectLocations {
                offset: e.end(),
                length: file_len - e.end(),
                htype: ObjectType::Other,
            });
        }
        Ok(locs)
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        self.write_c2pa(input_stream, output_stream, &[])
    }
}

impl AssetPatch for MatroskaIO {
    /// Overwrites the `FileData` of the C2PA `AttachedFile` in place when the
    /// store has the same size.
    fn patch_c2pa(&self, stream: &mut dyn ReadWriteSeek, store_bytes: &[u8]) -> Result<()> {
        let (_, fd) = locate_c2pa(stream)?.ok_or(Error::JumbfNotFound)?;
        if fd.data_len != store_bytes.len() as u64 {
            return Err(Error::InvalidAsset(
                "patch_c2pa: store size does not match existing Matroska C2PA AttachedFile".into(),
            ));
        }
        stream.seek(SeekFrom::Start(fd.data_offset()))?;
        stream.write_all(store_bytes)?;
        Ok(())
    }
}

fn container_length_exclusion() -> Vec<AllowedExclusion> {
    vec![AllowedExclusion {
        start: SIZE_FIELD_OFFSET,
        length: WIDE_SIZE_LEN as u64,
        kind: ExclusionKind::ContainerLength,
    }]
}

impl AssetBoxHash for MatroskaIO {
    /// Boxes per the Matroska-specific box hash handling: `1A45DFA3`, `SEGh`,
    /// each Top-Level Element by Element ID, and `ATTh` plus the children of
    /// the `Attachments` element (the C2PA `AttachedFile` as `C2PA`).
    ///
    /// Without a C2PA `AttachedFile`, `ATTh` (when the asset does not end with
    /// an `Attachments` element) and `C2PA` placeholders are appended at the
    /// end of the asset; the hashes are only meaningful for an asset already in
    /// its embedded layout (see [`AssetBoxHash::prepare_box_hash_stream`]).
    fn get_box_map(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
        let layout = parse_layout(input_stream)?;
        if layout.segment.size_len != WIDE_SIZE_LEN || layout.segment.id_len() != 4 {
            return Err(invalid(
                "the Segment Element Data Size is not encoded on 8 octets",
            ));
        }
        layout.attachments()?;

        let mut maps = vec![
            BoxMap::new(vec![element_box_name(ID_EBML)], 0, layout.ebml.total_len()),
            BoxMap::new(
                vec![SEGMENT_HEADER_BOX.to_string()],
                layout.segment.offset,
                WIDE_HEADER_LEN,
            )
            .with_allowed_exclusions(container_length_exclusion()),
        ];
        let mut c2pa_offset = None;
        for e in &layout.children {
            if e.id != ID_ATTACHMENTS {
                maps.push(BoxMap::new(
                    vec![element_box_name(e.id)],
                    e.offset,
                    e.total_len(),
                ));
                continue;
            }
            if e.size_len != WIDE_SIZE_LEN {
                return Err(invalid(
                    "the Attachments Element Data Size is not encoded on 8 octets",
                ));
            }
            maps.push(
                BoxMap::new(
                    vec![ATTACHMENTS_HEADER_BOX.to_string()],
                    e.offset,
                    WIDE_HEADER_LEN,
                )
                .with_allowed_exclusions(container_length_exclusion()),
            );
            for (c, info) in attachments_children(input_stream, e)? {
                if info.is_some() {
                    if c2pa_offset.is_some() {
                        return Err(Error::TooManyManifestStores);
                    }
                    c2pa_offset = Some(c.offset);
                    maps.push(
                        BoxMap::new(vec![C2PA_BOXHASH.to_string()], c.offset, c.total_len())
                            .with_allowed_exclusions(vec![AllowedExclusion::whole_box(
                                c.total_len(),
                            )]),
                    );
                } else {
                    maps.push(BoxMap::new(
                        vec![element_box_name(c.id)],
                        c.offset,
                        c.total_len(),
                    ));
                }
            }
        }

        if let Some(offset) = c2pa_offset {
            // The `C2PA` box shall be the AttachedFile from which the Manifest
            // Store is located.
            let located = locate_c2pa(input_stream)?.map(|(af, _)| af.elem.offset);
            if located != Some(offset) {
                return Err(invalid(
                    "the C2PA AttachedFile is not the one located through the SeekHead",
                ));
            }
        } else {
            let end = layout.file_len;
            if layout.children.last().map(|e| e.id) != Some(ID_ATTACHMENTS) {
                maps.push(BoxMap::new(
                    vec![ATTACHMENTS_HEADER_BOX.to_string()],
                    end,
                    0,
                ));
            }
            maps.push(
                BoxMap::new(vec![C2PA_BOXHASH.to_string()], end, 0)
                    .with_allowed_exclusions(vec![AllowedExclusion::whole_box(0)]),
            );
        }
        Ok(maps)
    }

    fn requires_box_hash(&self) -> bool {
        true
    }

    fn prepare_box_hash_stream(
        &self,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
    ) -> Result<bool> {
        self.write_c2pa(input, output, PLACEHOLDER_STORE)?;
        Ok(true)
    }
}

impl AssetIO for MatroskaIO {
    fn new(asset_type: &str) -> Self {
        MatroskaIO {
            _asset_type: asset_type.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(MatroskaIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(MatroskaIO::new(asset_type)))
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::{
        assertions::BoxHash,
        utils::{test::test_context, test_signer::test_signer},
        Builder, Reader, SigningAlg,
    };

    /// VP9 + Opus, written by ffmpeg (SeekHead + Void, Tags, Cues at the end).
    const VP9_OPUS: &[u8] = include_bytes!("../../tests/fixtures/sample_vp9_opus.webm");
    /// VP9 with alpha (BlockAdditions), written by ffmpeg.
    const VP9_ALPHA: &[u8] = include_bytes!("../../tests/fixtures/sample_vp9_alpha.webm");
    /// Opus only, written by ffmpeg.
    const OPUS: &[u8] = include_bytes!("../../tests/fixtures/sample_opus.webm");
    /// H.264 + AAC with a font attachment placed before the clusters, written
    /// by mkvmerge.
    const H264_FONT: &[u8] = include_bytes!("../../tests/fixtures/sample_h264_aac_font.mkv");
    /// H.264 + AAC written by ffmpeg, with CRC-32 elements in the Top-Level
    /// Elements.
    const H264_CRC: &[u8] = include_bytes!("../../tests/fixtures/sample_h264_aac_crc.mkv");

    const FIXTURES: [(&str, &[u8]); 5] = [
        ("video/webm", VP9_OPUS),
        ("video/webm", VP9_ALPHA),
        ("audio/webm", OPUS),
        ("video/matroska", H264_FONT),
        ("video/matroska", H264_CRC),
    ];

    fn io() -> MatroskaIO {
        MatroskaIO::new("webm")
    }

    /// Builds a JUMBF-shaped test store: big-endian LBox + `jumb` + payload.
    fn fake_store(payload: &[u8]) -> Vec<u8> {
        let mut v = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b"jumb");
        v.extend_from_slice(payload);
        v
    }

    fn write(src: &[u8], store: &[u8]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        io().write_c2pa(&mut Cursor::new(src), &mut out, store)
            .unwrap();
        out.into_inner()
    }

    fn try_write(src: &[u8], store: &[u8]) -> Result<Vec<u8>> {
        let mut out = Cursor::new(Vec::new());
        io().write_c2pa(&mut Cursor::new(src), &mut out, store)?;
        Ok(out.into_inner())
    }

    fn layout(b: &[u8]) -> Layout {
        parse_layout(&mut Cursor::new(b)).unwrap()
    }

    fn names(b: &[u8]) -> Vec<String> {
        io().get_box_map(&mut Cursor::new(b))
            .unwrap()
            .into_iter()
            .map(|m| m.names[0].clone())
            .collect()
    }

    fn top_level_ids(b: &[u8]) -> Vec<u32> {
        layout(b).children.iter().map(|e| e.id).collect()
    }

    /// Checks every stored Segment Position (SeekHead and Cues) points at an
    /// element with the expected ID.
    fn check_positions(b: &[u8]) {
        let l = layout(b);
        let seg = l.segment.data_offset();
        let mut c = Cursor::new(b);
        let id_at = |c: &mut Cursor<&[u8]>, p: u64| read_header_at(c, seg + p).unwrap().id;
        for e in &l.children {
            let data = &b[e.data_offset() as usize..e.end() as usize];
            if e.id == ID_SEEKHEAD {
                for s in parse_nodes(data, 0).unwrap() {
                    let Body::Master(ch) = &s.body else { continue };
                    let mut target = None;
                    let mut pos = None;
                    for n in ch {
                        match (&n.body, n.id) {
                            (Body::Leaf(v), ID_SEEK_ID) => target = decode_uint(v),
                            (Body::Leaf(v), ID_SEEK_POSITION) => pos = decode_uint(v),
                            _ => {}
                        }
                    }
                    assert_eq!(
                        id_at(&mut c, pos.unwrap()) as u64,
                        target.unwrap(),
                        "Seek entry does not point at its target"
                    );
                }
            }
            if e.id == ID_CUES {
                fn walk(nodes: &[Node], out: &mut Vec<u64>) {
                    for n in nodes {
                        match &n.body {
                            Body::Master(c) => walk(c, out),
                            Body::Leaf(v) if n.id == ID_CUE_CLUSTER_POSITION => {
                                out.push(decode_uint(v).unwrap())
                            }
                            _ => {}
                        }
                    }
                }
                let mut ps = Vec::new();
                walk(&parse_nodes(data, 0).unwrap(), &mut ps);
                assert!(!ps.is_empty());
                for p in ps {
                    assert_eq!(
                        id_at(&mut c, p),
                        ID_CLUSTER,
                        "Cue does not point at a Cluster"
                    );
                }
            }
        }
    }

    /// Checks the leading CRC-32 of every Top-Level Element that has one.
    fn check_crcs(b: &[u8]) -> usize {
        let l = layout(b);
        let mut checked = 0;
        for e in &l.children {
            let data = &b[e.data_offset() as usize..e.end() as usize];
            if data.first() == Some(&0xbf) {
                let stored = u32::from_le_bytes(data[2..6].try_into().unwrap());
                assert_eq!(stored, crc32(&data[6..]), "bad CRC-32 in {:X}", e.id);
                checked += 1;
            }
        }
        checked
    }

    fn c2pa_af(b: &[u8]) -> AttachedFileInfo {
        locate_c2pa(&mut Cursor::new(b)).unwrap().unwrap().0
    }

    fn child_bytes<'a>(b: &'a [u8], af: &AttachedFileInfo, id: u32) -> &'a [u8] {
        let c = af.children.iter().find(|c| c.id == id).unwrap();
        &b[c.data_offset() as usize..c.end() as usize]
    }

    #[test]
    fn test_ebml_primitives() {
        assert_eq!(encode_size(0, 1).unwrap(), [0x80]);
        assert_eq!(encode_size(126, 1).unwrap(), [0xfe]);
        assert!(encode_size(127, 1).is_err()); // reserved (unknown size)
        assert_eq!(encode_size(5, 8).unwrap(), [1, 0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(id_bytes(ID_ATTACHMENTS), [0x19, 0x41, 0xa4, 0x69]);
        assert_eq!(element_box_name(ID_CLUSTER), "1F43B675");
        assert_eq!(element_box_name(ID_VOID), "EC");
        assert_eq!(element_box_name(ID_ATTACHED_FILE), "61A7");
        assert_eq!(encode_uint(0x1234, 1), [0x12, 0x34]);
        assert_eq!(encode_uint(5, 2), [0, 5]);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        for total in 2..300u64 {
            let v = void_pieces(total, None).unwrap();
            assert_eq!(pieces_len(&v), total);
        }
        assert!(void_pieces(1, None).is_none());
    }

    #[test]
    fn test_parse_fixtures() {
        for (_, f) in FIXTURES {
            let l = layout(f);
            assert_eq!(l.segment.size_len, 8);
            assert_eq!(l.segment.end(), f.len() as u64);
            assert_eq!(l.children[0].id, ID_SEEKHEAD);
            assert!(l.children.iter().any(|e| e.id == ID_CLUSTER));
            assert!(matches!(
                io().read_c2pa(&mut Cursor::new(f)),
                Err(Error::JumbfNotFound)
            ));
        }
        assert_eq!(check_crcs(H264_CRC), 11);
    }

    #[test]
    fn test_write_read_roundtrip() {
        for (_, src) in FIXTURES {
            let store = fake_store(b"manifest store");
            let out = write(src, &store);
            let l = layout(&out);
            // Attachments is the last Top-Level Element, with an 8-octet size,
            // and the C2PA AttachedFile is its last child.
            let att = *l.children.last().unwrap();
            assert_eq!(att.id, ID_ATTACHMENTS);
            assert_eq!(att.size_len, 8);
            let kids = attachments_children(&mut Cursor::new(&out[..]), &att).unwrap();
            assert!(kids.last().unwrap().1.is_some());
            assert!(kids.iter().all(|(c, _)| c.id != ID_CRC32));
            let af = c2pa_af(&out);
            assert_eq!(
                child_bytes(&out, &af, ID_FILE_NAME),
                C2PA_FILE_NAME.as_bytes()
            );
            assert_eq!(
                child_bytes(&out, &af, ID_FILE_MEDIA_TYPE),
                C2PA_MEDIA_TYPE.as_bytes()
            );
            assert_ne!(decode_uint(child_bytes(&out, &af, ID_FILE_UID)), Some(0));
            assert_eq!(
                af.children.iter().map(|c| c.id).collect::<Vec<_>>(),
                [ID_FILE_NAME, ID_FILE_MEDIA_TYPE, ID_FILE_UID, ID_FILE_DATA]
            );
            assert_eq!(io().read_c2pa(&mut Cursor::new(&out)).unwrap(), store);
            check_positions(&out);
            check_crcs(&out);

            // No Top-Level Element other than SeekHead/Void (and a relocated
            // Attachments) moved: the Clusters are byte-identical in place.
            let before = layout(src);
            for e in before.children.iter().filter(|e| e.id == ID_CLUSTER) {
                let r = e.offset as usize..e.end() as usize;
                assert_eq!(&out[r.clone()], &src[r]);
            }
        }
    }

    #[test]
    fn test_seek_written_into_void() {
        let out = write(VP9_OPUS, &fake_store(b"x"));
        let (a, b) = (layout(VP9_OPUS), layout(&out));
        // SeekHead + Void keep their combined size.
        assert_eq!(
            a.children[0].total_len() + a.children[1].total_len(),
            b.children[0].total_len() + b.children[1].total_len()
        );
        assert!(b.children[0].total_len() > a.children[0].total_len());
        assert_eq!(b.children[1].id, ID_VOID);
        // The located Attachments comes from the Seek entry.
        let att = locate_attachments(&mut Cursor::new(&out[..]))
            .unwrap()
            .unwrap();
        assert_eq!(Some(att), b.children.last().copied());
        // Everything after the Void and before the Attachments is unchanged.
        let from = b.children[2].offset as usize;
        assert_eq!(&out[from..VP9_OPUS.len()], &VP9_OPUS[from..]);
    }

    #[test]
    fn test_seekhead_crc_recomputed() {
        let out = write(H264_CRC, &fake_store(b"crc"));
        assert_ne!(
            out[..layout(&out).children[0].end() as usize],
            H264_CRC[..layout(H264_CRC).children[0].end() as usize]
        );
        assert_eq!(check_crcs(&out), 11);
        check_positions(&out);
    }

    #[test]
    fn test_replace_only_changes_c2pa_attached_file() {
        for (_, src) in FIXTURES {
            let a = write(src, &fake_store(b"first manifest"));
            let b = write(&a, &fake_store(&[9u8; 3000]));
            let (la, lb) = (layout(&a), layout(&b));
            let (af_a, af_b) = (c2pa_af(&a), c2pa_af(&b));
            assert_eq!(af_a.elem.offset, af_b.elem.offset);
            // Same FileUID.
            assert_eq!(
                child_bytes(&a, &af_a, ID_FILE_UID),
                child_bytes(&b, &af_b, ID_FILE_UID)
            );
            // Identical bytes up to the C2PA AttachedFile, except the Segment
            // and Attachments sizes.
            let seg_size = la.segment.offset as usize + 4..la.segment.offset as usize + 12;
            let att = la.children.last().unwrap().offset as usize;
            let att_size = att + 4..att + 12;
            for i in 0..af_a.elem.offset as usize {
                if !seg_size.contains(&i) && !att_size.contains(&i) {
                    assert_eq!(a[i], b[i], "byte {i} changed");
                }
            }
            assert_eq!(lb.segment.end(), b.len() as u64);
            assert_eq!(
                io().read_c2pa(&mut Cursor::new(&b)).unwrap(),
                fake_store(&[9u8; 3000])
            );
        }
    }

    #[test]
    fn test_remove() {
        // ffmpeg layouts are restored byte for byte.
        for src in [VP9_OPUS, VP9_ALPHA, OPUS, H264_CRC] {
            let signed = write(src, &fake_store(b"x"));
            let mut out = Cursor::new(Vec::new());
            io().remove_c2pa(&mut Cursor::new(&signed), &mut out)
                .unwrap();
            assert_eq!(out.into_inner(), src);
        }
        // The relocated font stays (at the end), without the C2PA AttachedFile.
        let signed = write(H264_FONT, &fake_store(b"x"));
        let mut out = Cursor::new(Vec::new());
        io().remove_c2pa(&mut Cursor::new(&signed), &mut out)
            .unwrap();
        let out = out.into_inner();
        assert!(matches!(
            io().read_c2pa(&mut Cursor::new(&out)),
            Err(Error::JumbfNotFound)
        ));
        assert_eq!(*top_level_ids(&out).last().unwrap(), ID_ATTACHMENTS);
        check_positions(&out);
        // Removing from an asset without a manifest is a no-op.
        let mut out = Cursor::new(Vec::new());
        io().remove_c2pa(&mut Cursor::new(H264_FONT), &mut out)
            .unwrap();
        assert_eq!(out.into_inner(), H264_FONT);
    }

    #[test]
    fn test_patch_same_size() {
        let mut s = Cursor::new(write(OPUS, &fake_store(b"aaaa")));
        io().patch_c2pa(&mut s, &fake_store(b"bbbb")).unwrap();
        assert_eq!(io().read_c2pa(&mut s).unwrap(), fake_store(b"bbbb"));
        assert!(io()
            .patch_c2pa(&mut s, &fake_store(b"much longer store"))
            .is_err());
    }

    #[test]
    fn test_object_locations() {
        let signed = write(VP9_OPUS, &fake_store(b"abc"));
        let locs = io()
            .get_object_locations(&mut Cursor::new(&signed))
            .unwrap();
        assert_eq!(locs.len(), 2);
        assert_eq!(locs[1].htype, ObjectType::C2pa);
        assert_eq!(locs[1].offset + locs[1].length, signed.len() as u64);
        let locs = io()
            .get_object_locations(&mut Cursor::new(VP9_OPUS))
            .unwrap();
        assert_eq!(locs[1].htype, ObjectType::C2pa);
    }

    #[test]
    fn test_relocation_keeps_font_byte_identical() {
        let src = H264_FONT;
        let before = layout(src);
        let (ai, old_att) = before
            .children
            .iter()
            .enumerate()
            .find(|(_, e)| e.id == ID_ATTACHMENTS)
            .map(|(i, e)| (i, *e))
            .unwrap();
        assert!(ai < before.children.len() - 1);
        let font = attachments_children(&mut Cursor::new(src), &old_att).unwrap()[0].0;
        let font_bytes = &src[font.offset as usize..font.end() as usize];

        let out = write(src, &fake_store(b"m"));
        let after = layout(&out);
        // Same number of Top-Level Elements before the end; the old
        // Attachments is now a Void of the same size at the same offset.
        let void = after.children[ai];
        assert_eq!(
            (void.id, void.offset, void.total_len()),
            (ID_VOID, old_att.offset, old_att.total_len())
        );
        for (a, b) in before.children.iter().zip(&after.children).skip(1) {
            if a.id != ID_ATTACHMENTS && a.id != ID_VOID {
                assert_eq!(
                    (a.id, a.offset, a.total_len()),
                    (b.id, b.offset, b.total_len())
                );
            }
        }
        // The font is the first child of the new, last Attachments element.
        let att = *after.children.last().unwrap();
        assert_eq!(att.id, ID_ATTACHMENTS);
        let kids = attachments_children(&mut Cursor::new(&out[..]), &att).unwrap();
        assert_eq!(kids.len(), 2);
        let f = kids[0].0;
        assert_eq!(&out[f.offset as usize..f.end() as usize], font_bytes);
        check_positions(&out);

        assert_eq!(
            names(&out)[names(&out).len() - 3..],
            ["ATTh".to_string(), "61A7".to_string(), "C2PA".to_string()]
        );
        // The font is hashed: tampering with it breaks the box hash.
        let mut bh = BoxHash { boxes: Vec::new() };
        bh.generate_box_hash_from_stream(&mut Cursor::new(&out), "sha256", &io(), false)
            .unwrap();
        let mut tampered = out.clone();
        tampered[f.end() as usize - 1] ^= 1;
        assert!(bh
            .verify_in_memory_hash(&tampered, Some("sha256"), &io())
            .is_err());
        bh.verify_in_memory_hash(&out, Some("sha256"), &io())
            .unwrap();
    }

    #[test]
    fn test_box_map_matches_spec_example() {
        // The draft's example: SeekHead, Void, Info, Tracks, Clusters, Cues,
        // then ATTh and C2PA. ffmpeg also writes Tags (1254C367).
        let out = write(VP9_ALPHA, &fake_store(b"m"));
        let mut expected = vec![
            "1A45DFA3", "SEGh", "114D9B74", "EC", "1549A966", "1654AE6B", "1254C367",
        ];
        expected.extend(["1F43B675"; 4]);
        expected.extend(["1C53BB6B", "ATTh", "C2PA"]);
        assert_eq!(names(&out), expected);

        let maps = io().get_box_map(&mut Cursor::new(&out)).unwrap();
        // Boxes tile the whole file contiguously.
        let mut pos = 0;
        for m in &maps {
            assert_eq!(m.range_start, pos);
            pos += m.range_len;
        }
        assert_eq!(pos, out.len() as u64);
        assert_eq!(maps[1].range_len, 12);

        let mut bh = BoxHash { boxes: Vec::new() };
        bh.generate_box_hash_from_stream(&mut Cursor::new(&out), "sha256", &io(), false)
            .unwrap();
        let json = serde_json::to_value(&bh).unwrap();
        for (i, b) in bh.boxes.iter().enumerate() {
            let excl = b.exclusions.as_ref().map(|e| {
                e.iter()
                    .map(|x| (x.start, x.length, x.box_index))
                    .collect::<Vec<_>>()
            });
            match b.names[0].as_str() {
                "SEGh" | "ATTh" => assert_eq!(excl, Some(vec![(4, 8, None)]), "{json}"),
                _ => assert_eq!(excl, None, "box {i}"),
            }
        }
        let c2pa = bh.boxes.last().unwrap();
        assert_eq!(c2pa.names, ["C2PA"]);
        assert_eq!(c2pa.hash.as_ref(), [0]);
        // The example also hashes the four Clusters as one range: the
        // generated per-box form and the minimal form both verify.
        let mut minimal = BoxHash { boxes: Vec::new() };
        minimal
            .generate_box_hash_from_stream(&mut Cursor::new(&out), "sha256", &io(), true)
            .unwrap();
        minimal
            .verify_in_memory_hash(&out, Some("sha256"), &io())
            .unwrap();
    }

    #[test]
    fn test_box_map_placeholder_without_manifest() {
        let n = names(VP9_OPUS);
        assert_eq!(n[..2], ["1A45DFA3", "SEGh"]);
        assert_eq!(n[n.len() - 2..], ["ATTh", "C2PA"]);
        let maps = io().get_box_map(&mut Cursor::new(VP9_OPUS)).unwrap();
        assert_eq!(maps.last().unwrap().range_start, VP9_OPUS.len() as u64);
        assert_eq!(maps.last().unwrap().range_len, 0);
        // After removal of the manifest, an Attachments element at the end
        // only gets a C2PA placeholder.
        let signed = write(H264_FONT, &fake_store(b"x"));
        let mut out = Cursor::new(Vec::new());
        io().remove_c2pa(&mut Cursor::new(&signed), &mut out)
            .unwrap();
        let n = names(&out.into_inner());
        assert_eq!(n[n.len() - 3..], ["ATTh", "61A7", "C2PA"]);
    }

    #[test]
    fn test_exclusions_hold_as_manifest_grows() {
        for (_, src) in FIXTURES {
            let prepared = write(src, PLACEHOLDER_STORE);
            let mut bh = BoxHash { boxes: Vec::new() };
            bh.generate_box_hash_from_stream(&mut Cursor::new(&prepared), "sha256", &io(), false)
                .unwrap();
            for size in [1usize, 100, 5_000, 300_000] {
                let signed = write(&prepared, &fake_store(&vec![7u8; size]));
                bh.verify_in_memory_hash(&signed, Some("sha256"), &io())
                    .unwrap();
            }
        }
    }

    fn signed_layout_and_hash(src: &[u8]) -> (Vec<u8>, BoxHash) {
        let prepared = write(src, PLACEHOLDER_STORE);
        let mut bh = BoxHash { boxes: Vec::new() };
        bh.generate_box_hash_from_stream(&mut Cursor::new(&prepared), "sha256", &io(), false)
            .unwrap();
        (write(&prepared, &fake_store(b"final")), bh)
    }

    #[test]
    fn test_tamper_and_structure_violations_detected() {
        let (signed, bh) = signed_layout_and_hash(VP9_OPUS);
        bh.verify_in_memory_hash(&signed, Some("sha256"), &io())
            .unwrap();
        let l = layout(&signed);
        let verify = |b: &[u8]| bh.verify_in_memory_hash(b, Some("sha256"), &io());

        // A byte in a Cluster.
        let cluster = l.children.iter().find(|e| e.id == ID_CLUSTER).unwrap();
        let mut t = signed.clone();
        t[cluster.data_offset() as usize + 20] ^= 0x01;
        assert!(verify(&t).is_err());

        // An extra Top-Level Element after Attachments (Segment size updated).
        let mut extra = signed.clone();
        extra.extend([0xec, 0x81, 0x00]);
        let seg = l.segment.offset as usize;
        let new_size = l.segment.data_len + 3;
        extra[seg + 4..seg + 12].copy_from_slice(&encode_size(new_size, 8).unwrap());
        let err = verify(&extra).unwrap_err();
        assert!(format!("{err}").contains("unknownBox"), "{err}");

        // Trailing data after the Segment.
        let mut trailing = signed.clone();
        trailing.extend([0xec, 0x80]);
        assert!(verify(&trailing).is_err());

        // A Segment size that does not reach the end of the asset.
        let mut short = signed.clone();
        short[seg + 4..seg + 12].copy_from_slice(&encode_size(l.segment.data_len - 1, 8).unwrap());
        assert!(verify(&short).is_err());

        // An Attachments size that does not match its children.
        let att = l.children.last().unwrap().offset as usize;
        let mut bad_att = signed.clone();
        let v = l.children.last().unwrap().data_len + 2;
        bad_att[att + 4..att + 12].copy_from_slice(&encode_size(v, 8).unwrap());
        assert!(verify(&bad_att).is_err());

        // An element inserted before the Clusters (a Top-Level Element not
        // listed in the assertion).
        let tags = l.children.iter().find(|e| e.id == ID_TAGS).unwrap();
        let mut moved = signed[..tags.offset as usize].to_vec();
        moved.extend([0xec, 0x80]);
        moved.extend(&signed[tags.offset as usize..]);
        moved[seg + 4..seg + 12].copy_from_slice(&encode_size(l.segment.data_len + 2, 8).unwrap());
        assert!(verify(&moved).is_err());
    }

    #[test]
    fn test_rejected_inputs() {
        // Unknown-size Segment.
        let mut unknown_seg = VP9_OPUS.to_vec();
        let seg = layout(VP9_OPUS).segment.offset as usize;
        unknown_seg[seg + 4..seg + 12]
            .copy_from_slice(&[0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let err = try_write(&unknown_seg, &fake_store(b"x")).unwrap_err();
        assert!(
            matches!(err, Error::InvalidAsset(ref m) if m.contains("unknown size")),
            "{err}"
        );
        assert!(io().get_box_map(&mut Cursor::new(&unknown_seg)).is_err());
        // An unknown-size Segment can still be read (no manifest).
        assert!(matches!(
            io().read_c2pa(&mut Cursor::new(&unknown_seg)),
            Err(Error::JumbfNotFound)
        ));

        // Unknown-size Cluster.
        let mut unknown_cluster = VP9_OPUS.to_vec();
        let c = *layout(VP9_OPUS)
            .children
            .iter()
            .find(|e| e.id == ID_CLUSTER)
            .unwrap();
        let size_at = (c.offset + 4) as usize;
        let k = c.size_len as usize;
        let mut ones = vec![0xffu8; k];
        ones[0] = 0xff >> (k - 1);
        unknown_cluster[size_at..size_at + k].copy_from_slice(&ones);
        let err = try_write(&unknown_cluster, &fake_store(b"x")).unwrap_err();
        assert!(
            matches!(err, Error::InvalidAsset(ref m) if m.contains("unknown size")),
            "{err}"
        );

        // Two Segments.
        let l = layout(OPUS);
        let mut two = OPUS.to_vec();
        two.extend(&OPUS[l.segment.offset as usize..]);
        let err = try_write(&two, &fake_store(b"x")).unwrap_err();
        assert!(
            matches!(err, Error::InvalidAsset(ref m) if m.contains("more than one Segment")),
            "{err}"
        );

        // Not Matroska.
        assert!(matches!(
            try_write(b"RIFF....WEBPVP8 ", &fake_store(b"x")),
            Err(Error::UnsupportedType)
        ));
        let mut bad_doctype = OPUS.to_vec();
        let p = OPUS.windows(4).position(|w| w == b"webm").unwrap();
        bad_doctype[p..p + 4].copy_from_slice(b"xxxx");
        assert!(matches!(
            try_write(&bad_doctype, &fake_store(b"x")),
            Err(Error::UnsupportedType)
        ));
    }

    #[test]
    fn test_locate_and_multiple_c2pa_attached_files() {
        let signed = write(OPUS, &fake_store(b"m"));
        // Without the Seek entry, the scan of Top-Level Elements finds it.
        let mut no_seek = signed.clone();
        let p = no_seek
            .windows(6)
            .position(|w| w == [0x53, 0xab, 0x84, 0x19, 0x41, 0xa4])
            .unwrap();
        no_seek[p + 3] = 0x1a; // SeekID no longer Attachments
        assert_eq!(
            io().read_c2pa(&mut Cursor::new(&no_seek)).unwrap(),
            fake_store(b"m")
        );

        // Two C2PA AttachedFiles: treated as if no manifest were present.
        let l = layout(&signed);
        let af = c2pa_af(&signed);
        let af_bytes = signed[af.elem.offset as usize..af.elem.end() as usize].to_vec();
        let mut two = signed.clone();
        two.extend(&af_bytes);
        let att = l.children.last().unwrap().offset as usize;
        let seg = l.segment.offset as usize;
        let n = af_bytes.len() as u64;
        two[att + 4..att + 12]
            .copy_from_slice(&encode_size(l.children.last().unwrap().data_len + n, 8).unwrap());
        two[seg + 4..seg + 12].copy_from_slice(&encode_size(l.segment.data_len + n, 8).unwrap());
        assert!(matches!(
            io().read_c2pa(&mut Cursor::new(&two)),
            Err(Error::JumbfNotFound)
        ));
        assert!(io().get_box_map(&mut Cursor::new(&two)).is_err());
        // Writing replaces both with a single one.
        let fixed = write(&two, &fake_store(b"n"));
        assert_eq!(
            io().read_c2pa(&mut Cursor::new(&fixed)).unwrap(),
            fake_store(b"n")
        );
    }

    // -- Synthetic layouts -------------------------------------------------

    fn ebml_header(max_size_len: Option<u8>) -> Vec<u8> {
        let mut d = element(ID_DOCTYPE, b"webm").unwrap();
        if let Some(m) = max_size_len {
            d.extend(element(ID_EBML_MAX_SIZE_LENGTH, &[m]).unwrap());
        }
        element(ID_EBML, &d).unwrap()
    }

    /// A Cluster with a leading CRC-32 and a 3-octet `Position`.
    fn cluster(ts: u8, payload: usize, position: u64) -> Vec<u8> {
        let mut d = element(0xe7, &[ts]).unwrap();
        d.extend(element(ID_CLUSTER_POSITION, &encode_uint(position, 3)).unwrap());
        let mut block = vec![0x81, 0, 0, 0x80];
        block.extend(vec![0x55u8; payload]);
        d.extend(element(ID_SIMPLE_BLOCK, &block).unwrap());
        let mut with_crc = element(ID_CRC32, &crc32(&d).to_le_bytes()).unwrap();
        with_crc.extend(d);
        element(ID_CLUSTER, &with_crc).unwrap()
    }

    /// Checks each Cluster `Position` against the Cluster's Segment Position.
    fn check_cluster_positions(b: &[u8]) -> usize {
        let l = layout(b);
        let mut c = Cursor::new(b);
        let mut n = 0;
        for e in l.children.iter().filter(|e| e.id == ID_CLUSTER) {
            if let Some(p) = cluster_position_child(&mut c, e).unwrap() {
                let v = decode_uint(&b[p.data_offset() as usize..p.end() as usize]);
                assert_eq!(v, Some(e.offset - l.segment.data_offset()));
                n += 1;
            }
        }
        n
    }

    fn cues(positions: &[u64]) -> Vec<u8> {
        let mut d = Vec::new();
        for (i, p) in positions.iter().enumerate() {
            let tp = [
                element(0xf7, &[1]).unwrap(),
                element(ID_CUE_CLUSTER_POSITION, &encode_uint(*p, 2)).unwrap(),
            ]
            .concat();
            let cp = [
                element(0xb3, &[i as u8]).unwrap(),
                element(ID_CUE_TRACK_POSITIONS, &tp).unwrap(),
            ]
            .concat();
            d.extend(element(ID_CUE_POINT, &cp).unwrap());
        }
        element(ID_CUES, &d).unwrap()
    }

    fn seekhead(entries: &[(u32, u64)]) -> Vec<u8> {
        let d: Vec<u8> = entries
            .iter()
            .flat_map(|&(id, p)| {
                let s = [
                    element(ID_SEEK_ID, &id_bytes(id)).unwrap(),
                    element(ID_SEEK_POSITION, &encode_uint(p, 4)).unwrap(),
                ]
                .concat();
                element(ID_SEEK, &s).unwrap()
            })
            .collect();
        element(ID_SEEKHEAD, &d).unwrap()
    }

    /// EBML Header + Segment with `[SeekHead][Info][Cues][Cluster][Cluster]`
    /// (Cues before the Clusters, so that Cues growth moves the Clusters).
    fn synthetic(with_seekhead: bool, seg_size_len: u8, max_size_len: Option<u8>) -> Vec<u8> {
        let info = element(ID_INFO, &element(0x2ad7b1, &[0x0f, 0x42, 0x40]).unwrap()).unwrap();
        let clen = cluster(0, 65_415, 0).len() as u64;
        let sh_len = if with_seekhead {
            seekhead(&[(ID_INFO, 0), (ID_CUES, 0)]).len()
        } else {
            0
        } as u64;
        let cues_len = cues(&[0, 0]).len() as u64;
        let info_pos = sh_len;
        let cues_pos = info_pos + info.len() as u64;
        let c0_pos = cues_pos + cues_len;
        let c1_pos = c0_pos + clen;
        let c0 = cluster(0, 65_415, c0_pos);
        let c1 = cluster(1, 10, c1_pos);
        let mut seg = Vec::new();
        if with_seekhead {
            seg.extend(seekhead(&[(ID_INFO, info_pos), (ID_CUES, cues_pos)]));
        }
        seg.extend(&info);
        seg.extend(cues(&[c0_pos, c1_pos]));
        seg.extend(&c0);
        seg.extend(&c1);
        let mut out = ebml_header(max_size_len);
        out.extend(id_bytes(ID_SEGMENT));
        out.extend(encode_size(seg.len() as u64, seg_size_len).unwrap());
        out.extend(seg);
        out
    }

    #[test]
    fn test_shift_when_no_room_for_seek() {
        let src = synthetic(true, 8, None);
        check_positions(&src);
        assert_eq!(check_cluster_positions(&src), 2);
        assert_eq!(check_crcs(&src), 2);
        let out = write(&src, &fake_store(b"m"));
        check_positions(&out);
        // Cluster Positions were updated and the Clusters' CRC-32 recomputed.
        assert_eq!(check_cluster_positions(&out), 2);
        assert_eq!(check_crcs(&out), 2);
        assert_eq!(
            io().read_c2pa(&mut Cursor::new(&out)).unwrap(),
            fake_store(b"m")
        );
        // The second Cluster crossed the 2-octet boundary, so its Cue grew,
        // which moved both Clusters again.
        let rel = |b: &[u8]| {
            let l = layout(b);
            let seg = l.segment.data_offset();
            l.children
                .iter()
                .filter(|e| e.id == ID_CLUSTER)
                .map(|e| e.offset - seg)
                .collect::<Vec<_>>()
        };
        assert!(rel(&src)[1] < 0x1_0000, "{:?}", rel(&src));
        assert!(rel(&out)[1] >= 0x1_0000, "{:?}", rel(&out));
        let cues_len = |b: &[u8]| {
            layout(b)
                .children
                .iter()
                .find(|e| e.id == ID_CUES)
                .unwrap()
                .total_len()
        };
        assert!(cues_len(&out) > cues_len(&src));
        let l = layout(&out);
        assert_eq!(
            locate_attachments(&mut Cursor::new(&out[..])).unwrap(),
            l.children.last().copied()
        );
        // Box hash over the embedded layout.
        let (signed, bh) = signed_layout_and_hash(&src);
        bh.verify_in_memory_hash(&signed, Some("sha256"), &io())
            .unwrap();
    }

    #[test]
    fn test_new_seekhead_when_missing() {
        let src = synthetic(false, 8, None);
        let out = write(&src, &fake_store(b"m"));
        let ids = top_level_ids(&out);
        assert_eq!(ids[0], ID_SEEKHEAD);
        assert_eq!(*ids.last().unwrap(), ID_ATTACHMENTS);
        check_positions(&out);
        assert_eq!(
            locate_attachments(&mut Cursor::new(&out[..])).unwrap(),
            layout(&out).children.last().copied()
        );
    }

    #[test]
    fn test_normalizes_segment_size_and_max_size_length() {
        let src = synthetic(true, 4, Some(4));
        assert_eq!(layout(&src).segment.size_len, 4);
        let out = write(&src, &fake_store(b"m"));
        let l = layout(&out);
        assert_eq!(l.segment.size_len, 8);
        check_positions(&out);
        let mut c = Cursor::new(&out[..]);
        let max = read_children(&mut c, l.ebml.data_offset(), l.ebml.end())
            .unwrap()
            .into_iter()
            .find(|e| e.id == ID_EBML_MAX_SIZE_LENGTH)
            .unwrap();
        assert_eq!(out[max.data_offset() as usize], 8);
        // A 4-octet Segment size is rejected by the box map.
        assert!(io().get_box_map(&mut Cursor::new(&src)).is_err());
    }

    // -- End to end ----------------------------------------------------------

    fn sign(src: &[u8], format: &str) -> Vec<u8> {
        let context = test_context().into_shared();
        let signer = test_signer(SigningAlg::Ps256);
        let mut builder = Builder::from_shared_context(&context)
            .with_definition(
                serde_json::json!({
                    "title": "Matroska test",
                    "format": format,
                    "claim_generator_info": [{"name": "matroska_io test", "version": "0.1"}],
                    "assertions": [{
                        "label": "c2pa.actions",
                        "data": {"actions": [{
                            "action": "c2pa.created",
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
                        }]}
                    }]
                })
                .to_string(),
            )
            .unwrap();
        let mut out = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), format, &mut Cursor::new(src), &mut out)
            .unwrap();
        out.into_inner()
    }

    fn read_json(b: &[u8], format: &str) -> Result<String> {
        let context = test_context().into_shared();
        let reader = Reader::from_shared_context(&context).with_stream(format, Cursor::new(b))?;
        Ok(reader.json())
    }

    fn assert_valid(json: &str) {
        assert!(json.contains("c2pa.hash.boxes"), "{json}");
        assert!(json.contains("assertion.boxesHash.match"), "{json}");
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        let failures = &v["validation_results"]["activeManifest"]["failure"];
        assert!(
            failures.as_array().is_none_or(|a| a.is_empty()),
            "unexpected failures: {failures}"
        );
    }

    #[test]
    fn test_e2e_sign_and_verify() {
        for (format, src) in FIXTURES {
            let signed = sign(src, format);
            assert_valid(&read_json(&signed, format).unwrap());
            let l = layout(&signed);
            assert_eq!(l.segment.end(), signed.len() as u64);
            assert_eq!(*top_level_ids(&signed).last().unwrap(), ID_ATTACHMENTS);
            check_positions(&signed);
            check_crcs(&signed);
            // Clusters are untouched.
            for e in layout(src).children.iter().filter(|e| e.id == ID_CLUSTER) {
                let r = e.offset as usize..e.end() as usize;
                assert_eq!(&signed[r.clone()], &src[r]);
            }
            // Re-signing a signed asset replaces its manifest.
            let resigned = sign(&signed, format);
            assert_valid(&read_json(&resigned, format).unwrap());
            assert_eq!(top_level_ids(&resigned), top_level_ids(&signed));
        }
        // The synthetic layouts that need a shift or a new SeekHead.
        for src in [synthetic(true, 8, None), synthetic(false, 4, Some(4))] {
            let signed = sign(&src, "video/webm");
            assert_valid(&read_json(&signed, "video/webm").unwrap());
        }
    }

    #[test]
    fn test_e2e_tamper_cluster_fails() {
        let mut signed = sign(VP9_OPUS, "video/webm");
        let c = *layout(&signed)
            .children
            .iter()
            .find(|e| e.id == ID_CLUSTER)
            .unwrap();
        signed[c.data_offset() as usize + 40] ^= 0x01;
        let json = read_json(&signed, "video/webm").unwrap();
        assert!(json.contains("assertion.boxesHash.mismatch"), "{json}");
    }

    #[test]
    fn test_e2e_structure_change_fails() {
        // Data appended after the Segment: the manifest is still located, and
        // validation reports a mismatch.
        let mut signed = sign(OPUS, "audio/webm");
        signed.extend([0xec, 0x80]);
        let json = read_json(&signed, "audio/webm").unwrap();
        assert!(json.contains("assertion.boxesHash.mismatch"), "{json}");
    }

    /// Dev aid: signs every `.webm`/`.mkv`/`.mka` in `$MATROSKA_SAMPLES_IN`
    /// into `$MATROSKA_SAMPLES_DIR` (`<name>.signed.<ext>`), with the Reader
    /// JSON next to each. Run with
    /// `cargo test ... matroska_io::tests::write_samples -- --ignored`.
    #[test]
    #[ignore]
    fn write_samples() {
        let (Ok(input), Ok(dir)) = (
            std::env::var("MATROSKA_SAMPLES_IN"),
            std::env::var("MATROSKA_SAMPLES_DIR"),
        ) else {
            return;
        };
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).unwrap();
        let mut entries: Vec<_> = std::fs::read_dir(&input)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for p in entries {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or_default()
                .to_string();
            let format = match ext.as_str() {
                "webm" => "video/webm",
                "mkv" => "video/matroska",
                "mka" => "audio/matroska",
                _ => continue,
            };
            let stem = p.file_stem().unwrap().to_str().unwrap().to_string();
            let src = std::fs::read(&p).unwrap();
            let context = test_context().into_shared();
            let signer = test_signer(SigningAlg::Ps256);
            let mut builder = Builder::from_shared_context(&context)
                .with_definition(
                    serde_json::json!({
                        "title": format!("{stem}.{ext}"),
                        "format": format,
                        "claim_generator_info": [{"name": "matroska_io samples", "version": "0.1"}],
                        "assertions": [{
                            "label": "c2pa.actions",
                            "data": {"actions": [{"action": "c2pa.created",
                                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"}]}
                        }]
                    })
                    .to_string(),
                )
                .unwrap();
            let mut out = Cursor::new(Vec::new());
            let res = builder.sign(signer.as_ref(), format, &mut Cursor::new(&src), &mut out);
            let (signed_path, json) = match res {
                Ok(_) => {
                    let signed = out.into_inner();
                    let sp = dir.join(format!("{stem}.signed.{ext}"));
                    std::fs::write(&sp, &signed).unwrap();
                    let json = read_json(&signed, format).unwrap_or_else(|e| {
                        serde_json::json!({"error": format!("{e:?}")}).to_string()
                    });
                    (sp, json)
                }
                Err(e) => (
                    dir.join(format!("{stem}.{ext}")),
                    serde_json::json!({"sign_error": format!("{e:?}")}).to_string(),
                ),
            };
            std::fs::write(dir.join(format!("{stem}.validation.json")), json).unwrap();
            eprintln!("{}", signed_path.display());
        }
    }
}
