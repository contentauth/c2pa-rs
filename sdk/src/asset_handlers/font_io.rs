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

//! OpenType / TrueType (SFNT) fonts, as described in "Embedding manifests into fonts".
//!
//! The C2PA Manifest Store lives in a `C2PA` table. The specification marks that table's
//! layout as preliminary. The hard binding is a general box hash in which each table is a
//! box, listed in table-directory order, with `head.checkSumAdjustment` hashed as zero.

use std::io::{self, SeekFrom};

use crate::{
    asset_io::{
        AssetBoxHash, AssetIO, BoxMap, C2paReader, C2paWriter, ObjectLocations, ReadSeek,
        ReadWriteSeek, C2PA_BOXHASH,
    },
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
};

/// SFNT version tags accepted as fonts: TrueType outlines, CFF outlines, and legacy Apple
/// TrueType. Collections (`ttcf`) and WOFF/WOFF2 are different containers.
const SFNT_VERSIONS: [[u8; 4]; 3] = [[0x00, 0x01, 0x00, 0x00], *b"OTTO", *b"true"];

const C2PA_TAG: [u8; 4] = *b"C2PA";
const HEAD_TAG: [u8; 4] = *b"head";

const SFNT_HEADER_LEN: u64 = 12;
const TABLE_RECORD_LEN: u64 = 16;

/// Offset of `checkSumAdjustment` within the `head` table.
const CHECKSUM_ADJUSTMENT_OFFSET: u64 = 8;
/// The whole-font checksum, including `checkSumAdjustment`, sums to this value.
const CHECKSUM_MAGIC: u32 = 0xb1b0_afba;

/// `C2PA` table version written by this handler. The specification does not assign one yet.
const C2PA_TABLE_MAJOR_VERSION: u16 = 0;
const C2PA_TABLE_MINOR_VERSION: u16 = 1;
/// `majorVersion`, `minorVersion`, `activeManifestUriOffset`, `activeManifestUriLength`,
/// `reserved`, `manifestStoreOffset` and `manifestStoreLength`.
const C2PA_TABLE_HEADER_LEN: usize = 20;

/// One entry of the table directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableRecord {
    tag: [u8; 4],
    offset: u32,
    length: u32,
}

impl TableRecord {
    fn name(&self) -> String {
        // Tags are padded with trailing spaces (`cvt `, `CFF `); box names are not.
        String::from_utf8_lossy(&self.tag).trim_end().to_string()
    }

    fn end(&self) -> u64 {
        self.offset as u64 + self.length as u64
    }
}

/// An SFNT font's header and table directory, in directory order.
struct Sfnt {
    version: [u8; 4],
    tables: Vec<TableRecord>,
}

impl Sfnt {
    fn read(mut stream: &mut dyn ReadSeek) -> Result<Self> {
        let len = stream_len(stream)?;
        stream.rewind()?;

        let mut header = [0u8; SFNT_HEADER_LEN as usize];
        stream
            .read_exact(&mut header)
            .map_err(|_| Error::InvalidAsset("font is too short".to_string()))?;
        let version: [u8; 4] = [header[0], header[1], header[2], header[3]];
        if !SFNT_VERSIONS.contains(&version) {
            return Err(Error::InvalidAsset(
                "not an OpenType or TrueType font".to_string(),
            ));
        }
        let num_tables = u16::from_be_bytes([header[4], header[5]]);

        let directory_len = num_tables as u64 * TABLE_RECORD_LEN;
        if SFNT_HEADER_LEN + directory_len > len {
            return Err(Error::InvalidAsset(
                "font table directory is truncated".to_string(),
            ));
        }
        let directory = stream.read_to_vec(directory_len)?;

        let mut tables: Vec<TableRecord> = Vec::with_capacity(num_tables as usize);
        for record in directory.chunks_exact(TABLE_RECORD_LEN as usize) {
            let word = |i: usize| {
                u32::from_be_bytes([record[i], record[i + 1], record[i + 2], record[i + 3]])
            };
            let table = TableRecord {
                tag: [record[0], record[1], record[2], record[3]],
                offset: word(8),
                length: word(12),
            };
            if table.end() > len {
                return Err(Error::InvalidAsset(format!(
                    "font table `{}` extends past the end of the font",
                    table.name()
                )));
            }
            if tables.iter().any(|t| t.tag == table.tag) {
                return Err(Error::InvalidAsset(format!(
                    "font has more than one `{}` table",
                    table.name()
                )));
            }
            tables.push(table);
        }

        Ok(Sfnt { version, tables })
    }

    fn table(&self, tag: [u8; 4]) -> Option<&TableRecord> {
        self.tables.iter().find(|t| t.tag == tag)
    }

    /// The directory index at which a `C2PA` table is, or would be inserted: before the
    /// first table whose tag sorts after it. OpenType requires a sorted directory, so in a
    /// conforming font this keeps it sorted.
    fn c2pa_index(&self) -> usize {
        self.tables
            .iter()
            .position(|t| t.tag >= C2PA_TAG)
            .unwrap_or(self.tables.len())
    }
}

/// The contents of a `C2PA` table.
#[derive(Debug, Default, PartialEq, Eq)]
struct C2paTable {
    active_manifest_uri: Option<Vec<u8>>,
    manifest_store: Option<Vec<u8>>,
}

impl C2paTable {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < C2PA_TABLE_HEADER_LEN {
            return Err(Error::InvalidAsset("`C2PA` table is truncated".to_string()));
        }
        let u16_at = |i: usize| u16::from_be_bytes([data[i], data[i + 1]]) as usize;
        let u32_at = |i: usize| {
            u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize
        };

        let section = |offset: usize, length: usize| -> Result<Option<Vec<u8>>> {
            if offset == 0 {
                return Ok(None);
            }
            offset
                .checked_add(length)
                .and_then(|end| data.get(offset..end))
                .map(|bytes| Some(bytes.to_vec()))
                .ok_or_else(|| {
                    Error::InvalidAsset("`C2PA` table section is out of bounds".to_string())
                })
        };

        Ok(C2paTable {
            active_manifest_uri: section(u32_at(4), u16_at(8))?,
            manifest_store: section(u32_at(12), u32_at(16))?,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let uri = self.active_manifest_uri.as_deref().unwrap_or_default();
        let store = self.manifest_store.as_deref().unwrap_or_default();
        let uri_len = u16::try_from(uri.len())
            .map_err(|_| Error::BadParam("manifest URI is too long for a font".to_string()))?;
        let store_len = u32::try_from(store.len())
            .map_err(|_| Error::BadParam("manifest is too large for a font".to_string()))?;

        let uri_offset = if uri.is_empty() {
            0
        } else {
            C2PA_TABLE_HEADER_LEN
        };
        let store_offset = if store.is_empty() {
            0
        } else {
            C2PA_TABLE_HEADER_LEN + uri.len()
        };

        let mut data = Vec::with_capacity(C2PA_TABLE_HEADER_LEN + uri.len() + store.len());
        data.extend_from_slice(&C2PA_TABLE_MAJOR_VERSION.to_be_bytes());
        data.extend_from_slice(&C2PA_TABLE_MINOR_VERSION.to_be_bytes());
        data.extend_from_slice(&(uri_offset as u32).to_be_bytes());
        data.extend_from_slice(&uri_len.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes()); // reserved
        data.extend_from_slice(&(store_offset as u32).to_be_bytes());
        data.extend_from_slice(&store_len.to_be_bytes());
        data.extend_from_slice(uri);
        data.extend_from_slice(store);
        Ok(data)
    }
}

/// The OpenType table checksum: the wrapping sum of big-endian `uint32`s, zero-padded.
fn table_checksum(data: &[u8]) -> u32 {
    data.chunks(4).fold(0u32, |sum, chunk| {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        sum.wrapping_add(u32::from_be_bytes(word))
    })
}

fn padding(len: u64) -> u64 {
    (4 - len % 4) % 4
}

fn read_table(mut stream: &mut dyn ReadSeek, table: &TableRecord) -> Result<Vec<u8>> {
    stream.seek(SeekFrom::Start(table.offset as u64))?;
    stream.read_to_vec(table.length as u64)
}

/// Writes `font` to `output_stream` with its `C2PA` table replaced by `c2pa_table`, or
/// removed when it is `None`.
///
/// Existing tables keep their bytes and their relative order in the file, and the `C2PA`
/// table goes last. The directory, offsets, table checksums and `head.checkSumAdjustment`
/// are recomputed, as font consumers expect.
fn write_font(
    input_stream: &mut dyn ReadSeek,
    output_stream: &mut dyn ReadWriteSeek,
    font: &Sfnt,
    c2pa_table: Option<&[u8]>,
) -> Result<()> {
    let mut directory: Vec<TableRecord> = font
        .tables
        .iter()
        .filter(|t| t.tag != C2PA_TAG)
        .copied()
        .collect();
    if c2pa_table.is_some() {
        let placeholder = TableRecord {
            tag: C2PA_TAG,
            offset: 0,
            length: 0,
        };
        let index = Sfnt {
            version: font.version,
            tables: directory.clone(),
        }
        .c2pa_index();
        directory.insert(index, placeholder);
    }
    let num_tables = u16::try_from(directory.len())
        .map_err(|_| Error::InvalidAsset("font has too many tables".to_string()))?;

    // Lay the tables out in their current file order, followed by the `C2PA` table.
    let mut file_order: Vec<usize> = (0..directory.len())
        .filter(|&i| directory[i].tag != C2PA_TAG)
        .collect();
    file_order.sort_by_key(|&i| directory[i].offset);
    if let Some(index) = directory.iter().position(|t| t.tag == C2PA_TAG) {
        file_order.push(index);
    }

    let header_len = SFNT_HEADER_LEN + num_tables as u64 * TABLE_RECORD_LEN;
    let mut offset = header_len;
    let mut new_offsets = vec![0u64; directory.len()];
    for &i in &file_order {
        let length = match (directory[i].tag, c2pa_table) {
            (C2PA_TAG, Some(table)) => table.len() as u64,
            _ => directory[i].length as u64,
        };
        new_offsets[i] = offset;
        offset += length + padding(length);
    }
    if offset > u32::MAX as u64 {
        return Err(Error::InvalidAsset("font is too large".to_string()));
    }

    // Write the tables, collecting their checksums. `head` is checksummed with
    // `checkSumAdjustment` zeroed, which is also how it is written for now.
    output_stream.rewind()?;
    output_stream.write_all(&vec![0u8; header_len as usize])?;
    let mut checksums = vec![0u32; directory.len()];
    let mut head_offset = None;
    for &i in &file_order {
        let mut data = match (directory[i].tag, c2pa_table) {
            (C2PA_TAG, Some(table)) => table.to_vec(),
            _ => read_table(input_stream, &directory[i])?,
        };
        if directory[i].tag == HEAD_TAG {
            let field =
                CHECKSUM_ADJUSTMENT_OFFSET as usize..CHECKSUM_ADJUSTMENT_OFFSET as usize + 4;
            if let Some(adjustment) = data.get_mut(field) {
                adjustment.fill(0);
                head_offset = Some(new_offsets[i]);
            }
        }
        checksums[i] = table_checksum(&data);
        directory[i].offset = new_offsets[i] as u32;
        directory[i].length = data.len() as u32;

        output_stream.write_all(&data)?;
        output_stream.write_all(&[0u8; 3][..padding(data.len() as u64) as usize])?;
    }

    // The header and table directory.
    let entry_selector = 15 - num_tables.max(1).leading_zeros() as u16;
    let search_range = (1u16 << entry_selector) * TABLE_RECORD_LEN as u16;
    let range_shift = num_tables * TABLE_RECORD_LEN as u16 - search_range;
    let mut header = Vec::with_capacity(header_len as usize);
    header.extend_from_slice(&font.version);
    header.extend_from_slice(&num_tables.to_be_bytes());
    header.extend_from_slice(&search_range.to_be_bytes());
    header.extend_from_slice(&entry_selector.to_be_bytes());
    header.extend_from_slice(&range_shift.to_be_bytes());
    for (table, checksum) in directory.iter().zip(&checksums) {
        header.extend_from_slice(&table.tag);
        header.extend_from_slice(&checksum.to_be_bytes());
        header.extend_from_slice(&table.offset.to_be_bytes());
        header.extend_from_slice(&table.length.to_be_bytes());
    }
    output_stream.rewind()?;
    output_stream.write_all(&header)?;

    // Every table is 4-byte aligned and zero-padded, so the whole-font checksum is the
    // header's checksum plus each table's.
    if let Some(head_offset) = head_offset {
        let font_checksum = checksums
            .iter()
            .fold(table_checksum(&header), |sum, c| sum.wrapping_add(*c));
        let adjustment = CHECKSUM_MAGIC.wrapping_sub(font_checksum);
        output_stream.seek(SeekFrom::Start(head_offset + CHECKSUM_ADJUSTMENT_OFFSET))?;
        output_stream.write_all(&adjustment.to_be_bytes())?;
    }

    output_stream.seek(SeekFrom::End(0))?;
    output_stream.flush()?;
    Ok(())
}

pub struct FontIO {}

impl C2paReader for FontIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let font = Sfnt::read(input_stream)?;
        let table = font.table(C2PA_TAG).ok_or(Error::JumbfNotFound)?;
        let data = read_table(input_stream, table)?;
        C2paTable::parse(&data)?
            .manifest_store
            .filter(|store| !store.is_empty())
            .ok_or(Error::JumbfNotFound)
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for FontIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let font = Sfnt::read(input_stream)?;

        // Keep an existing remote manifest URI; replace the embedded store.
        let mut table = match font.table(C2PA_TAG) {
            Some(existing) => C2paTable::parse(&read_table(input_stream, existing)?)?,
            None => C2paTable::default(),
        };
        table.manifest_store = Some(store_bytes.to_vec());

        write_font(input_stream, output_stream, &font, Some(&table.to_bytes()?))
    }

    fn get_object_locations(
        &self,
        _input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        Err(Error::NotImplemented(
            "data hashing is not supported for fonts, use a box hash instead".to_string(),
        ))
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let font = Sfnt::read(input_stream)?;
        if font.table(C2PA_TAG).is_none() {
            input_stream.rewind()?;
            io::copy(input_stream, output_stream)?;
            return Ok(());
        }
        write_font(input_stream, output_stream, &font, None)
    }
}

impl AssetBoxHash for FontIO {
    fn get_box_map(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
        let font = Sfnt::read(input_stream)?;

        let mut box_maps: Vec<BoxMap> = font
            .tables
            .iter()
            .map(|table| {
                let box_map =
                    BoxMap::new(vec![table.name()], table.offset as u64, table.length as u64);
                if table.tag == HEAD_TAG && table.length as u64 >= CHECKSUM_ADJUSTMENT_OFFSET + 4 {
                    box_map.with_hashed_as_zero(vec![(
                        table.offset as u64 + CHECKSUM_ADJUSTMENT_OFFSET,
                        4,
                    )])
                } else {
                    box_map
                }
            })
            .collect();

        // Before signing, the `C2PA` table does not exist yet. Report a placeholder where
        // `write_c2pa` will insert it in the directory.
        if font.table(C2PA_TAG).is_none() {
            box_maps.insert(
                font.c2pa_index(),
                BoxMap::new(vec![C2PA_BOXHASH.to_string()], 0, 0),
            );
        }

        Ok(box_maps)
    }

    fn requires_box_hash(&self) -> bool {
        true
    }
}

impl AssetIO for FontIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        FontIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(FontIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(FontIO::new(asset_type)))
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &["otf", "font/otf", "ttf", "font/ttf"]
    }

    fn mime_type_map(&self) -> Vec<(String, String)> {
        vec![
            ("otf".to_string(), "font/otf".to_string()),
            ("ttf".to_string(), "font/ttf".to_string()),
        ]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::assertions::BoxHash;

    const TTF: &[u8] = include_bytes!("../../tests/fixtures/sample1.ttf");
    const OTF: &[u8] = include_bytes!("../../tests/fixtures/sample1.otf");

    fn write(font: &[u8], store: &[u8]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        FontIO {}
            .write_c2pa(&mut Cursor::new(font), &mut output, store)
            .unwrap();
        output.into_inner()
    }

    fn tables(font: &[u8]) -> Vec<TableRecord> {
        Sfnt::read(&mut Cursor::new(font)).unwrap().tables
    }

    fn table_data<'a>(font: &'a [u8], tag: &[u8; 4]) -> &'a [u8] {
        let t = tables(font).into_iter().find(|t| &t.tag == tag).unwrap();
        &font[t.offset as usize..t.end() as usize]
    }

    /// Checks the directory checksums and `head.checkSumAdjustment` as font consumers do.
    fn assert_checksums_valid(font: &[u8]) {
        let num_tables = u16::from_be_bytes([font[4], font[5]]) as usize;
        for record in font[12..12 + num_tables * 16].chunks(16) {
            let tag = &record[0..4];
            let checksum = u32::from_be_bytes(record[4..8].try_into().unwrap());
            let offset = u32::from_be_bytes(record[8..12].try_into().unwrap()) as usize;
            let length = u32::from_be_bytes(record[12..16].try_into().unwrap()) as usize;
            assert_eq!(offset % 4, 0, "table {tag:?} is not 4-byte aligned");
            let mut data = font[offset..offset + length].to_vec();
            if tag == HEAD_TAG {
                data[8..12].fill(0);
            }
            assert_eq!(table_checksum(&data), checksum, "checksum of {tag:?}");
        }
        assert_eq!(table_checksum(font), CHECKSUM_MAGIC, "whole-font checksum");
    }

    #[test]
    fn test_read_unsigned() {
        for font in [TTF, OTF] {
            assert!(matches!(
                FontIO {}.read_c2pa(&mut Cursor::new(font)),
                Err(Error::JumbfNotFound)
            ));
        }
    }

    #[test]
    fn test_write_read_round_trip() {
        for font in [TTF, OTF] {
            let signed = write(font, b"manifest store");
            assert_eq!(
                FontIO {}.read_c2pa(&mut Cursor::new(&signed)).unwrap(),
                b"manifest store"
            );
            assert_checksums_valid(&signed);

            // Directory stays sorted, and every original table keeps its bytes (`head`
            // apart from `checkSumAdjustment`).
            let tags: Vec<_> = tables(&signed).iter().map(|t| t.tag).collect();
            assert!(tags.windows(2).all(|w| w[0] < w[1]), "{tags:?}");
            for t in tables(font) {
                let (old, new) = (table_data(font, &t.tag), table_data(&signed, &t.tag));
                if t.tag == HEAD_TAG {
                    assert_eq!(old[..8], new[..8]);
                    assert_eq!(old[12..], new[12..]);
                } else {
                    assert_eq!(old, new, "{}", t.name());
                }
            }
        }
    }

    #[test]
    fn test_replace_keeps_one_table_and_the_uri() {
        let with_uri = C2paTable {
            active_manifest_uri: Some(b"https://example.com/manifest.c2pa".to_vec()),
            manifest_store: Some(b"first".to_vec()),
        };
        let font = Sfnt::read(&mut Cursor::new(TTF)).unwrap();
        let mut signed = Cursor::new(Vec::new());
        write_font(
            &mut Cursor::new(TTF),
            &mut signed,
            &font,
            Some(&with_uri.to_bytes().unwrap()),
        )
        .unwrap();

        let resigned = write(signed.get_ref(), b"second, longer manifest store");
        assert_eq!(tables(&resigned).len(), tables(TTF).len() + 1);
        assert_checksums_valid(&resigned);
        assert_eq!(
            C2paTable::parse(table_data(&resigned, &C2PA_TAG)).unwrap(),
            C2paTable {
                active_manifest_uri: with_uri.active_manifest_uri,
                manifest_store: Some(b"second, longer manifest store".to_vec()),
            }
        );
    }

    #[test]
    fn test_remove() {
        for font in [TTF, OTF] {
            let mut removed = Cursor::new(Vec::new());
            FontIO {}
                .remove_c2pa(&mut Cursor::new(write(font, b"store")), &mut removed)
                .unwrap();
            let removed = removed.into_inner();

            assert_eq!(tables(&removed).len(), tables(font).len());
            assert_checksums_valid(&removed);
            assert!(matches!(
                FontIO {}.read_c2pa(&mut Cursor::new(&removed)),
                Err(Error::JumbfNotFound)
            ));
        }
    }

    #[test]
    fn test_box_map() {
        for font in [TTF, OTF] {
            let before = FontIO {}.get_box_map(&mut Cursor::new(font)).unwrap();
            let signed = write(font, b"store");
            let after = FontIO {}.get_box_map(&mut Cursor::new(&signed)).unwrap();

            // The placeholder is where the table is inserted, so the names line up.
            let names = |bms: &[BoxMap]| bms.iter().map(|b| b.names[0].clone()).collect::<Vec<_>>();
            assert_eq!(names(&before), names(&after));
            assert_eq!(names(&after)[0], C2PA_BOXHASH);
            assert!(names(&after)
                .iter()
                .all(|n| n.len() <= 4 && !n.ends_with(' ')));

            let head = after.iter().find(|b| b.names[0] == "head").unwrap();
            assert_eq!(head.hashed_as_zero, vec![(head.range_start + 8, 4)]);
        }
    }

    #[test]
    fn test_box_hash_ignores_checksum_adjustment() {
        let signed = write(TTF, b"store");
        let mut bh = BoxHash { boxes: Vec::new() };
        bh.generate_box_hash_from_stream(&mut Cursor::new(&signed), "sha256", &FontIO {}, false)
            .unwrap();

        // Changing `checkSumAdjustment` alone does not change the hash; changing a
        // glyph does.
        let head = tables(&signed)
            .into_iter()
            .find(|t| t.tag == HEAD_TAG)
            .unwrap();
        let mut adjusted = signed.clone();
        adjusted[head.offset as usize + 8] ^= 0xff;
        assert!(bh
            .verify_stream_hash(&mut Cursor::new(&adjusted), Some("sha256"), &FontIO {})
            .is_ok());

        let glyf = tables(&signed)
            .into_iter()
            .find(|t| &t.tag == b"glyf")
            .unwrap();
        let mut tampered = signed.clone();
        tampered[glyf.offset as usize] ^= 0xff;
        assert!(bh
            .verify_stream_hash(&mut Cursor::new(&tampered), Some("sha256"), &FontIO {})
            .is_err());
    }

    #[test]
    fn test_grouped_boxes_out_of_file_order_do_not_panic() {
        // `glyf` precedes `head` in the directory but follows it in the file. Grouping them
        // into one box must be reported as a mismatch rather than underflow.
        let signed = write(TTF, b"store");
        let mut bh = BoxHash { boxes: Vec::new() };
        bh.generate_box_hash_from_stream(&mut Cursor::new(&signed), "sha256", &FontIO {}, false)
            .unwrap();
        let glyf = bh.boxes.iter().position(|b| b.names == ["glyf"]).unwrap();
        assert_eq!(bh.boxes[glyf + 1].names, ["head"]);

        bh.boxes.remove(glyf + 1);
        bh.boxes[glyf].names.push("head".to_string());
        assert!(matches!(
            bh.verify_stream_hash(&mut Cursor::new(&signed), Some("sha256"), &FontIO {}),
            Err(Error::HashMismatch(_))
        ));
    }

    #[test]
    fn test_rejects_malformed_fonts() {
        let mut collection = TTF.to_vec();
        collection[0..4].copy_from_slice(b"ttcf");
        let mut woff = TTF.to_vec();
        woff[0..4].copy_from_slice(b"wOFF");
        let truncated = TTF[..20].to_vec();
        let mut past_end = TTF.to_vec();
        past_end[12 + 12..12 + 16].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut duplicate = TTF.to_vec();
        let second_tag = duplicate[12 + 16..12 + 20].to_vec();
        duplicate[12..16].copy_from_slice(&second_tag);

        for (name, font) in [
            ("collection", collection),
            ("woff", woff),
            ("truncated", truncated),
            ("table past end", past_end),
            ("duplicate tag", duplicate),
        ] {
            assert!(
                matches!(
                    FontIO {}.read_c2pa(&mut Cursor::new(&font)),
                    Err(Error::InvalidAsset(_))
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn test_c2pa_table_out_of_bounds() {
        let mut table = C2paTable {
            active_manifest_uri: None,
            manifest_store: Some(b"store".to_vec()),
        }
        .to_bytes()
        .unwrap();
        table[16..20].copy_from_slice(&1000u32.to_be_bytes()); // manifestStoreLength
        assert!(matches!(
            C2paTable::parse(&table),
            Err(Error::InvalidAsset(_))
        ));
    }
}
