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

//! GLB (binary glTF 2.0) asset handler.
//!
//! Implements the embedding described in the GLB section of the C2PA
//! specification working draft (not yet in a published version, hence the
//! `unstable_glb` feature):
//!
//! * The C2PA Manifest Store is the `chunkData` of a chunk with
//!   `chunkType = 0x41503243` (`C`,`2`,`P`,`A` in file order), placed after all
//!   JSON and BIN chunks and zero-padded to a 4-byte boundary. There is at most
//!   one such chunk, and the header `length` (bytes 8-11) is updated to the new
//!   total file size.
//! * The hard binding is `c2pa.hash.boxes`: a `GLBh` box for the 12-byte header
//!   with the `length` field excluded, then one box per chunk (in file order)
//!   named after its `chunkType`, the C2PA chunk being named `C2PA`.

use std::io::{Cursor, Read, SeekFrom};

use crate::{
    asset_io::{
        AllowedExclusion, AssetBoxHash, AssetIO, AssetPatch, BoxMap, C2paReader, C2paWriter,
        ExclusionKind, ObjectLocations, ObjectType, ReadSeek, ReadWriteSeek, C2PA_BOXHASH,
    },
    error::{Error, Result},
    utils::io_utils::stream_len,
};

static SUPPORTED_TYPES: [&str; 2] = ["glb", "model/gltf-binary"];

/// `glTF` read as a little-endian u32.
const GLB_MAGIC: u32 = 0x4654_6c67;
const GLB_VERSION: u32 = 2;
const GLB_HEADER_LEN: u64 = 12;
const CHUNK_HEADER_LEN: u64 = 8;
/// Offset of the header `length` field (excluded from the `GLBh` box hash).
const GLB_LENGTH_FIELD_OFFSET: u64 = 8;

pub(crate) const CHUNK_JSON: u32 = 0x4e4f_534a;
pub(crate) const CHUNK_BIN: u32 = 0x004e_4942;
pub(crate) const CHUNK_C2PA: u32 = 0x4150_3243;

/// Box name for the GLB header.
pub(crate) const GLB_HEADER_BOX: &str = "GLBh";

/// One chunk in a GLB file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GlbChunk {
    /// Offset of the `chunkLength` field.
    offset: u64,
    /// Value of `chunkLength` (length of `chunkData`, padding included).
    data_len: u32,
    chunk_type: u32,
}

impl GlbChunk {
    fn total_len(&self) -> u64 {
        CHUNK_HEADER_LEN + self.data_len as u64
    }

    fn data_offset(&self) -> u64 {
        self.offset + CHUNK_HEADER_LEN
    }
}

/// Parsed, validated chunk layout of a GLB file.
#[derive(Debug)]
struct GlbLayout {
    file_len: u64,
    chunks: Vec<GlbChunk>,
}

impl GlbLayout {
    fn c2pa_chunk(&self) -> Option<&GlbChunk> {
        self.chunks.iter().find(|c| c.chunk_type == CHUNK_C2PA)
    }
}

fn invalid(msg: &str) -> Error {
    Error::InvalidAsset(format!("GLB: {msg}"))
}

fn read_u32_le(r: &mut dyn ReadSeek) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Parses and strictly validates the GLB container structure:
/// magic `glTF`, version 2, header `length` equal to the stream length,
/// 4-byte alignment of every chunk, JSON first, BIN (if present) second and
/// unique, and at most one C2PA chunk placed after the JSON and BIN chunks.
fn parse_glb(r: &mut dyn ReadSeek) -> Result<GlbLayout> {
    let file_len = stream_len(r)?;
    r.rewind()?;

    if file_len < GLB_HEADER_LEN {
        return Err(Error::UnsupportedType);
    }
    if read_u32_le(r)? != GLB_MAGIC {
        return Err(Error::UnsupportedType);
    }
    let version = read_u32_le(r)?;
    if version != GLB_VERSION {
        return Err(invalid(&format!("unsupported version {version}")));
    }
    let length = read_u32_le(r)? as u64;
    if length != file_len {
        return Err(invalid(&format!(
            "header length {length} does not match stream length {file_len}"
        )));
    }
    if file_len % 4 != 0 {
        return Err(invalid("file length is not a multiple of 4"));
    }

    let mut chunks = Vec::new();
    let mut pos = GLB_HEADER_LEN;
    while pos < file_len {
        if file_len - pos < CHUNK_HEADER_LEN {
            return Err(invalid("truncated chunk header"));
        }
        r.seek(SeekFrom::Start(pos))?;
        let data_len = read_u32_le(r)?;
        let chunk_type = read_u32_le(r)?;
        if data_len % 4 != 0 {
            return Err(invalid("chunkLength is not a multiple of 4"));
        }
        let chunk = GlbChunk {
            offset: pos,
            data_len,
            chunk_type,
        };
        let end = pos
            .checked_add(chunk.total_len())
            .ok_or_else(|| invalid("chunk length overflow"))?;
        if end > file_len {
            return Err(invalid("chunk extends past end of file"));
        }
        chunks.push(chunk);
        pos = end;
    }

    // JSON shall be the first chunk, and only the first.
    match chunks.first() {
        Some(c) if c.chunk_type == CHUNK_JSON => {}
        _ => return Err(invalid("first chunk is not JSON")),
    }
    let mut c2pa_count = 0;
    for (i, c) in chunks.iter().enumerate() {
        match c.chunk_type {
            CHUNK_JSON if i != 0 => return Err(invalid("JSON chunk is not the first chunk")),
            CHUNK_BIN if i != 1 => return Err(invalid("BIN chunk is not the second chunk")),
            CHUNK_C2PA => {
                c2pa_count += 1;
                // After JSON (index 0); BIN, if any, is at index 1 and checked above,
                // so a C2PA chunk at index 1 implies no BIN chunk exists.
                if i == 0 {
                    return Err(invalid("C2PA chunk precedes JSON chunk"));
                }
            }
            _ => {}
        }
    }
    if c2pa_count > 1 {
        return Err(Error::TooManyManifestStores);
    }

    Ok(GlbLayout { file_len, chunks })
}

/// Box name for a non-C2PA chunk per the draft GLB section: the chunkType's four
/// bytes in memory (little-endian) order as ASCII, or the lowercase hex of the
/// u32 value when any byte is outside 0x20-0x7E. `BIN` is special-cased to the
/// name the draft lists explicitly (its memory-order bytes are `BIN\0`).
pub(crate) fn chunk_box_name(chunk_type: u32) -> String {
    match chunk_type {
        CHUNK_C2PA => C2PA_BOXHASH.to_string(),
        CHUNK_BIN => "BIN".to_string(),
        t => {
            let bytes = t.to_le_bytes();
            if bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
                bytes.iter().map(|&b| b as char).collect()
            } else {
                format!("{t:08x}")
            }
        }
    }
}

/// Trims the zero padding after the JUMBF superbox, using its LBox/XLBox.
fn trim_jumbf_padding(mut data: Vec<u8>) -> Vec<u8> {
    if data.len() >= 8 {
        let lbox = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
        let box_len = if lbox == 1 && data.len() >= 16 {
            let mut x = [0u8; 8];
            x.copy_from_slice(&data[8..16]);
            u64::from_be_bytes(x)
        } else {
            lbox
        };
        if box_len >= 8 && box_len <= data.len() as u64 {
            data.truncate(box_len as usize);
        }
    }
    data
}

fn padded_len(len: usize) -> usize {
    len.div_ceil(4) * 4
}

fn copy_range(r: &mut dyn ReadSeek, w: &mut dyn ReadWriteSeek, start: u64, len: u64) -> Result<()> {
    r.seek(SeekFrom::Start(start))?;
    let copied = std::io::copy(&mut r.take(len), w)?;
    if copied != len {
        return Err(invalid("unexpected end of stream"));
    }
    Ok(())
}

fn write_c2pa_chunk(w: &mut dyn ReadWriteSeek, store_bytes: &[u8]) -> Result<()> {
    let plen = padded_len(store_bytes.len());
    let plen_u32 = u32::try_from(plen).map_err(|_| invalid("manifest store too large"))?;
    w.write_all(&plen_u32.to_le_bytes())?;
    w.write_all(&CHUNK_C2PA.to_le_bytes())?;
    w.write_all(store_bytes)?;
    w.write_all(&vec![0u8; plen - store_bytes.len()])?;
    Ok(())
}

pub struct GlbIO {
    _asset_type: String,
}

impl C2paReader for GlbIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let layout = parse_glb(input_stream)?;
        let chunk = layout.c2pa_chunk().ok_or(Error::JumbfNotFound)?;
        input_stream.seek(SeekFrom::Start(chunk.data_offset()))?;
        let mut data = vec![0u8; chunk.data_len as usize];
        input_stream.read_exact(&mut data)?;
        let data = trim_jumbf_padding(data);
        if data.is_empty() {
            return Err(Error::JumbfNotFound);
        }
        Ok(data)
    }

    /// GLB carries XMP only through the `KHR_xmp_json_ld` glTF extension,
    /// which the draft spec does not use; not supported.
    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for GlbIO {
    /// Replaces an existing C2PA chunk in place, or appends one after the last
    /// chunk. An empty `store_bytes` removes the C2PA chunk.
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let layout = parse_glb(input_stream)?;
        let existing = layout.c2pa_chunk().copied();

        let new_chunk_len = if store_bytes.is_empty() {
            0
        } else {
            CHUNK_HEADER_LEN + padded_len(store_bytes.len()) as u64
        };
        let new_len = layout.file_len - existing.map_or(0, |c| c.total_len()) + new_chunk_len;
        let new_len_u32 =
            u32::try_from(new_len).map_err(|_| invalid("output exceeds 4 GiB GLB limit"))?;

        output_stream.rewind()?;
        output_stream.write_all(&GLB_MAGIC.to_le_bytes())?;
        output_stream.write_all(&GLB_VERSION.to_le_bytes())?;
        output_stream.write_all(&new_len_u32.to_le_bytes())?;

        let mut wrote = false;
        for c in &layout.chunks {
            if c.chunk_type == CHUNK_C2PA {
                if !store_bytes.is_empty() {
                    write_c2pa_chunk(output_stream, store_bytes)?;
                    wrote = true;
                }
                continue;
            }
            copy_range(input_stream, output_stream, c.offset, c.total_len())?;
        }
        if !wrote && !store_bytes.is_empty() {
            write_c2pa_chunk(output_stream, store_bytes)?;
        }
        output_stream.flush()?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        // Ensure a C2PA chunk exists so its final position is known.
        let mut with_c2pa = Cursor::new(Vec::new());
        let layout = parse_glb(input_stream)?;
        let layout = if layout.c2pa_chunk().is_some() {
            layout
        } else {
            self.write_c2pa(input_stream, &mut with_c2pa, &[0u8; 4])?;
            parse_glb(&mut with_c2pa)?
        };
        let c = *layout.c2pa_chunk().ok_or(Error::JumbfNotFound)?;
        let mut locs = vec![
            ObjectLocations {
                offset: 0,
                length: c.offset,
                htype: ObjectType::Other,
            },
            ObjectLocations {
                offset: c.offset,
                length: c.total_len(),
                htype: ObjectType::C2pa,
            },
        ];
        let end = c.offset + c.total_len();
        if end < layout.file_len {
            locs.push(ObjectLocations {
                offset: end,
                length: layout.file_len - end,
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

impl AssetPatch for GlbIO {
    /// Overwrites the C2PA chunk data in place when the padded size is unchanged.
    fn patch_c2pa(&self, stream: &mut dyn ReadWriteSeek, store_bytes: &[u8]) -> Result<()> {
        let layout = parse_glb(stream)?;
        let c = *layout.c2pa_chunk().ok_or(Error::JumbfNotFound)?;
        if padded_len(store_bytes.len()) as u64 != c.data_len as u64 {
            return Err(Error::InvalidAsset(
                "patch_c2pa: store size does not match existing GLB C2PA chunk".into(),
            ));
        }
        stream.seek(SeekFrom::Start(c.data_offset()))?;
        stream.write_all(store_bytes)?;
        stream.write_all(&vec![0u8; c.data_len as usize - store_bytes.len()])?;
        Ok(())
    }
}

impl AssetBoxHash for GlbIO {
    fn get_box_map(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
        let layout = parse_glb(input_stream)?;

        let mut maps = vec![
            BoxMap::new(vec![GLB_HEADER_BOX.to_string()], 0, GLB_HEADER_LEN)
                .with_allowed_exclusions(vec![AllowedExclusion {
                    start: GLB_LENGTH_FIELD_OFFSET,
                    length: 4,
                    kind: ExclusionKind::ContainerLength,
                }]),
        ];

        for c in &layout.chunks {
            let name = chunk_box_name(c.chunk_type);
            let bm = BoxMap::new(vec![name], c.offset, c.total_len());
            maps.push(if c.chunk_type == CHUNK_C2PA {
                bm.with_allowed_exclusions(vec![AllowedExclusion::whole_box(c.total_len())])
            } else {
                bm
            });
        }

        // No manifest yet: placeholder where `write_c2pa` will append it. It is
        // not marked `excluded` (unlike PNG's placeholder) so the generated
        // assertion matches the draft's example: `C2PA` with hash `00` only.
        if layout.c2pa_chunk().is_none() {
            maps.push(
                BoxMap::new(vec![C2PA_BOXHASH.to_string()], layout.file_len, 0)
                    .with_allowed_exclusions(vec![AllowedExclusion::whole_box(0)]),
            );
        }
        Ok(maps)
    }

    fn requires_box_hash(&self) -> bool {
        true
    }
}

impl AssetIO for GlbIO {
    fn new(asset_type: &str) -> Self {
        GlbIO {
            _asset_type: asset_type.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(GlbIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(GlbIO::new(asset_type)))
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

    const TRIANGLE: &[u8] = include_bytes!("../../tests/fixtures/triangle.glb");
    const TEXTURED: &[u8] = include_bytes!("../../tests/fixtures/textured.glb");

    /// Builds a JUMBF-shaped test store: big-endian LBox + `jumb` + payload.
    fn fake_store(payload: &[u8]) -> Vec<u8> {
        let mut v = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b"jumb");
        v.extend_from_slice(payload);
        v
    }

    fn with_extra_chunk(src: &[u8], chunk_type: u32, data: &[u8]) -> Vec<u8> {
        let mut v = src.to_vec();
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&chunk_type.to_le_bytes());
        v.extend_from_slice(data);
        let len = v.len() as u32;
        v[8..12].copy_from_slice(&len.to_le_bytes());
        v
    }

    fn write(src: &[u8], store: &[u8]) -> Vec<u8> {
        let mut out = Cursor::new(Vec::new());
        GlbIO::new("glb")
            .write_c2pa(&mut Cursor::new(src), &mut out, store)
            .unwrap();
        out.into_inner()
    }

    fn header_len(b: &[u8]) -> u32 {
        u32::from_le_bytes(b[8..12].try_into().unwrap())
    }

    #[test]
    fn test_parse_fixtures() {
        for f in [TRIANGLE, TEXTURED] {
            let l = parse_glb(&mut Cursor::new(f)).unwrap();
            assert_eq!(l.chunks.len(), 2);
            assert_eq!(l.chunks[0].chunk_type, CHUNK_JSON);
            assert_eq!(l.chunks[1].chunk_type, CHUNK_BIN);
            assert!(l.c2pa_chunk().is_none());
        }
    }

    #[test]
    fn test_read_no_manifest() {
        let r = GlbIO::new("glb").read_c2pa(&mut Cursor::new(TRIANGLE));
        assert!(matches!(r, Err(Error::JumbfNotFound)));
    }

    #[test]
    fn test_write_read_roundtrip_and_padding() {
        let store = fake_store(b"abcde"); // 13 bytes -> padded to 16
        let out = write(TRIANGLE, &store);
        assert_eq!(out.len(), TRIANGLE.len() + 8 + 16);
        assert_eq!(header_len(&out) as usize, out.len());
        assert_eq!(&out[TRIANGLE.len() + 4..TRIANGLE.len() + 8], b"C2PA");
        assert_eq!(&out[out.len() - 3..], &[0, 0, 0]);
        let read = GlbIO::new("glb").read_c2pa(&mut Cursor::new(&out)).unwrap();
        assert_eq!(read, store);
    }

    #[test]
    fn test_replace_keeps_single_chunk() {
        let a = write(TRIANGLE, &fake_store(b"first manifest"));
        let b = write(&a, &fake_store(b"2nd"));
        let l = parse_glb(&mut Cursor::new(&b)).unwrap();
        assert_eq!(l.chunks.len(), 3);
        assert_eq!(header_len(&b) as usize, b.len());
        assert_eq!(
            GlbIO::new("glb").read_c2pa(&mut Cursor::new(&b)).unwrap(),
            fake_store(b"2nd")
        );
    }

    #[test]
    fn test_replace_in_place_before_extension_chunk() {
        let signed = write(TRIANGLE, &fake_store(b"m1"));
        let with_ext = with_extra_chunk(&signed, u32::from_le_bytes(*b"XTRA"), &[1, 2, 3, 4]);
        let out = write(&with_ext, &fake_store(b"m2-longer"));
        let l = parse_glb(&mut Cursor::new(&out)).unwrap();
        let types: Vec<_> = l
            .chunks
            .iter()
            .map(|c| chunk_box_name(c.chunk_type))
            .collect();
        assert_eq!(types, ["JSON", "BIN", "C2PA", "XTRA"]);
    }

    #[test]
    fn test_remove() {
        let signed = write(TEXTURED, &fake_store(b"x"));
        let mut out = Cursor::new(Vec::new());
        GlbIO::new("glb")
            .remove_c2pa(&mut Cursor::new(&signed), &mut out)
            .unwrap();
        assert_eq!(out.into_inner(), TEXTURED);
    }

    #[test]
    fn test_patch_same_size() {
        let signed = write(TRIANGLE, &fake_store(b"aaaa"));
        let mut s = Cursor::new(signed);
        GlbIO::new("glb")
            .patch_c2pa(&mut s, &fake_store(b"bbbb"))
            .unwrap();
        assert_eq!(
            GlbIO::new("glb").read_c2pa(&mut s).unwrap(),
            fake_store(b"bbbb")
        );
        assert!(GlbIO::new("glb")
            .patch_c2pa(&mut s, &fake_store(b"much longer store"))
            .is_err());
    }

    #[test]
    fn test_strict_validation() {
        let io = GlbIO::new("glb");
        let check = |b: Vec<u8>| io.read_c2pa(&mut Cursor::new(b));

        let mut bad_magic = TRIANGLE.to_vec();
        bad_magic[0] = b'x';
        assert!(matches!(check(bad_magic), Err(Error::UnsupportedType)));

        let mut v1 = TRIANGLE.to_vec();
        v1[4] = 1;
        assert!(matches!(check(v1), Err(Error::InvalidAsset(_))));

        let mut bad_len = TRIANGLE.to_vec();
        bad_len[8] ^= 4;
        assert!(matches!(check(bad_len), Err(Error::InvalidAsset(_))));

        let mut trailing = TRIANGLE.to_vec();
        trailing.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(check(trailing), Err(Error::InvalidAsset(_))));

        // Unaligned chunk (length 3).
        let unaligned = with_extra_chunk(TRIANGLE, u32::from_le_bytes(*b"XTRA"), &[1, 2, 3]);
        assert!(matches!(check(unaligned), Err(Error::InvalidAsset(_))));

        // Two C2PA chunks.
        let one = write(TRIANGLE, &fake_store(b"a"));
        let two = with_extra_chunk(&one, CHUNK_C2PA, &fake_store(b"bbbb"));
        assert!(matches!(check(two), Err(Error::TooManyManifestStores)));

        // A second BIN chunk after C2PA.
        let late_bin = with_extra_chunk(&one, CHUNK_BIN, &[0; 4]);
        assert!(matches!(check(late_bin), Err(Error::InvalidAsset(_))));

        // BIN first.
        let mut bin_first = TRIANGLE.to_vec();
        bin_first[16..20].copy_from_slice(&CHUNK_BIN.to_le_bytes());
        assert!(matches!(check(bin_first), Err(Error::InvalidAsset(_))));
    }

    #[test]
    fn test_chunk_box_names() {
        assert_eq!(chunk_box_name(CHUNK_JSON), "JSON");
        assert_eq!(chunk_box_name(CHUNK_BIN), "BIN");
        assert_eq!(chunk_box_name(CHUNK_C2PA), "C2PA");
        assert_eq!(chunk_box_name(u32::from_le_bytes(*b"XTRA")), "XTRA");
        // Normative text: lowercase hex of the u32 value.
        assert_eq!(chunk_box_name(0x4142_4300), "41424300");
    }

    #[test]
    fn test_box_map() {
        let io = GlbIO::new("glb");
        let unsigned = io.get_box_map(&mut Cursor::new(TRIANGLE)).unwrap();
        let names: Vec<_> = unsigned.iter().map(|b| b.names[0].as_str()).collect();
        assert_eq!(names, ["GLBh", "JSON", "BIN", "C2PA"]);
        assert_eq!((unsigned[0].range_start, unsigned[0].range_len), (0, 12));
        assert_eq!(unsigned[0].allowed_exclusions[0].start, 8);
        assert_eq!(unsigned[3].range_len, 0);
        assert_eq!(unsigned[3].range_start, TRIANGLE.len() as u64);

        let signed = write(TRIANGLE, &fake_store(b"abc"));
        let bm = io.get_box_map(&mut Cursor::new(&signed)).unwrap();
        // Boxes tile the whole file contiguously.
        let mut pos = 0;
        for b in &bm {
            assert_eq!(b.range_start, pos);
            pos += b.range_len;
        }
        assert_eq!(pos, signed.len() as u64);
        assert_eq!(bm[3].excluded, None);
    }

    #[test]
    fn test_box_hash_glbh_exclusion_survives_manifest_resize() {
        let io = GlbIO::new("glb");
        let mut bh = BoxHash { boxes: Vec::new() };
        bh.generate_box_hash_from_stream(&mut Cursor::new(TRIANGLE), "sha256", &io, false)
            .unwrap();
        let excl = bh.boxes[0].exclusions.as_ref().unwrap();
        assert_eq!(
            (excl[0].start, excl[0].length, excl[0].box_index),
            (8, 4, None)
        );

        for size in [1usize, 100, 5000] {
            let signed = write(TRIANGLE, &fake_store(&vec![7u8; size]));
            bh.verify_in_memory_hash(&signed, Some("sha256"), &io)
                .unwrap();
        }

        // Flip a byte inside the BIN chunk data.
        let mut tampered = write(TRIANGLE, &fake_store(b"m"));
        let bin = parse_glb(&mut Cursor::new(&tampered)).unwrap().chunks[1];
        tampered[bin.data_offset() as usize] ^= 0xff;
        assert!(bh
            .verify_in_memory_hash(&tampered, Some("sha256"), &io)
            .is_err());

        // An extra (unlisted) chunk is rejected.
        let signed = write(TRIANGLE, &fake_store(b"m"));
        let extra = with_extra_chunk(&signed, u32::from_le_bytes(*b"XTRA"), &[0; 4]);
        let err = bh
            .verify_in_memory_hash(&extra, Some("sha256"), &io)
            .unwrap_err();
        assert!(format!("{err}").contains("unknownBox"), "{err}");
    }

    fn sign(src: &[u8]) -> Vec<u8> {
        let context = test_context().into_shared();
        let signer = test_signer(SigningAlg::Ps256);
        let mut builder = Builder::from_shared_context(&context)
            .with_definition(
                serde_json::json!({
                    "title": "GLB test",
                    "format": "model/gltf-binary",
                    "claim_generator_info": [{"name": "glb_io test", "version": "0.1"}],
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
            .sign(
                signer.as_ref(),
                "model/gltf-binary",
                &mut Cursor::new(src),
                &mut out,
            )
            .unwrap();
        out.into_inner()
    }

    fn read_json(b: &[u8]) -> Result<String> {
        let context = test_context().into_shared();
        let reader = Reader::from_shared_context(&context)
            .with_stream("model/gltf-binary", Cursor::new(b))?;
        Ok(reader.json())
    }

    #[test]
    fn test_e2e_sign_and_verify() {
        for src in [TRIANGLE, TEXTURED] {
            let signed = sign(src);
            assert_eq!(header_len(&signed) as usize, signed.len());
            let json = read_json(&signed).unwrap();
            assert!(json.contains("c2pa.hash.boxes"), "{json}");
            assert!(json.contains("assertion.boxesHash.match"), "{json}");
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            let failures = &v["validation_results"]["activeManifest"]["failure"];
            assert!(
                failures.as_array().is_none_or(|a| a.is_empty()),
                "unexpected failures: {failures}"
            );

            // Unsigned payload preserved verbatim except header length.
            let l = parse_glb(&mut Cursor::new(&signed)).unwrap();
            assert_eq!(l.chunks.len(), 3);
            assert_eq!(&signed[12..src.len()], &src[12..]);
        }
    }

    #[test]
    fn test_e2e_tamper_bin_fails() {
        let mut signed = sign(TRIANGLE);
        let bin = parse_glb(&mut Cursor::new(&signed)).unwrap().chunks[1];
        signed[bin.data_offset() as usize + 1] ^= 0x01;
        let json = read_json(&signed).unwrap();
        assert!(json.contains("assertion.boxesHash.mismatch"), "{json}");
    }

    #[test]
    fn test_e2e_header_length_only_change() {
        let mut signed = sign(TRIANGLE);
        let bad = header_len(&signed) + 4;
        signed[8..12].copy_from_slice(&bad.to_le_bytes());
        // The GLBh hash excludes bytes 8-11, so detection relies on the strict
        // structural check (header length must equal stream length).
        let res = read_json(&signed);
        eprintln!("header-length-only change result: {res:?}");
        match res {
            Ok(json) => assert!(
                json.contains("assertion.boxesHash.mismatch") || json.contains("\"failure\""),
                "length change was not detected: {json}"
            ),
            Err(e) => assert!(matches!(e, Error::InvalidAsset(_)), "{e:?}"),
        }
    }

    /// Dev aid: writes sample files + Reader JSON to `$GLB_SAMPLES_DIR`.
    /// Run with `cargo test ... glb_io::tests::write_samples -- --ignored`.
    #[test]
    #[ignore]
    fn write_samples() {
        let Ok(dir) = std::env::var("GLB_SAMPLES_DIR") else {
            return;
        };
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).unwrap();
        let report = |b: &[u8]| match read_json(b) {
            Ok(j) => j,
            Err(e) => serde_json::json!({ "error": format!("{e:?}") }).to_string(),
        };
        let signed = sign(TRIANGLE);
        let mut tampered = signed.clone();
        let bin = parse_glb(&mut Cursor::new(&tampered)).unwrap().chunks[1];
        tampered[bin.data_offset() as usize + 1] ^= 0x01;
        let mut bad_len = signed.clone();
        let l = header_len(&bad_len) + 4;
        bad_len[8..12].copy_from_slice(&l.to_le_bytes());
        let textured = sign(TEXTURED);
        for (name, data) in [
            ("unsigned", TRIANGLE.to_vec()),
            ("signed", signed),
            ("tampered", tampered),
            ("header-length-changed", bad_len),
            ("textured-unsigned", TEXTURED.to_vec()),
            ("textured-signed", textured),
        ] {
            std::fs::write(dir.join(format!("{name}.glb")), &data).unwrap();
            std::fs::write(dir.join(format!("{name}.validation.json")), report(&data)).unwrap();
        }
    }
}
