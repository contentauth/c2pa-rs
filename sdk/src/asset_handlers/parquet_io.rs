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

//! Apache Parquet files, as described in "Embedding manifests into Parquet".
//!
//! A Parquet file is `PAR1`, the column data, a footer holding a Thrift compact-encoded
//! `FileMetaData`, the footer's 4-byte little-endian length, and `PAR1`. The C2PA Manifest
//! Store is Base64-encoded and stored as the value of a `key_value_metadata` entry whose key
//! is `c2pa:manifest`. The hard binding is a data hash that excludes exactly the
//! Base64-encoded value bytes.
//!
//! Only the footer is rewritten. Its fields keep their value bytes, existing
//! `key_value_metadata` entries keep their order and bytes, and the column data is copied
//! unchanged.

use std::{
    io::{self, Read, SeekFrom},
    ops::Range,
};

use crate::{
    asset_io::{
        AssetIO, C2paReader, C2paWriter, ObjectLocations, ObjectType, ReadSeek, ReadWriteSeek,
    },
    crypto::base64,
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
};

const MAGIC: &[u8; 4] = b"PAR1";
/// The trailing magic of a file whose footer is encrypted.
const ENCRYPTED_FOOTER_MAGIC: &[u8; 4] = b"PARE";
/// The leading magic and the trailing footer length and magic.
const MIN_FILE_LEN: u64 = 12;

/// `FileMetaData.key_value_metadata`, a `list<KeyValue>`.
const KEY_VALUE_METADATA_FIELD: i16 = 5;
/// `FileMetaData.encryption_algorithm`, present in files with encrypted columns.
const ENCRYPTION_ALGORITHM_FIELD: i16 = 8;
/// `KeyValue.key` and `.value`.
const KEY_FIELD: i16 = 1;
const VALUE_FIELD: i16 = 2;

// Thrift compact protocol types.
const STOP: u8 = 0;
const BOOL_TRUE: u8 = 1;
const BOOL_FALSE: u8 = 2;
const BYTE: u8 = 3;
const I16: u8 = 4;
const I32: u8 = 5;
const I64: u8 = 6;
const DOUBLE: u8 = 7;
const BINARY: u8 = 8;
const LIST: u8 = 9;
const SET: u8 = 10;
const MAP: u8 = 11;
const STRUCT: u8 = 12;
const UUID: u8 = 13;

/// Nesting deeper than this is not a real Parquet footer.
const MAX_DEPTH: usize = 64;

const MANIFEST_KEY: &str = "c2pa:manifest";

fn invalid(message: &str) -> Error {
    Error::InvalidAsset(format!("invalid Parquet file: {message}"))
}

fn varint_bytes(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            bytes.push(byte);
            return bytes;
        }
        bytes.push(byte | 0x80);
    }
}

/// A reader over Thrift compact-encoded bytes.
struct Thrift<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Thrift<'_> {
    fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or_else(|| invalid("footer is truncated"))?;
        self.pos += 1;
        Ok(byte)
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.byte()?;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte < 0x80 {
                return Ok(value);
            }
        }
        Err(invalid("varint is too long"))
    }

    fn skip(&mut self, len: u64) -> Result<()> {
        self.pos = usize::try_from(len)
            .ok()
            .and_then(|len| self.pos.checked_add(len))
            .filter(|&end| end <= self.data.len())
            .ok_or_else(|| invalid("footer is truncated"))?;
        Ok(())
    }

    fn binary(&mut self) -> Result<Range<usize>> {
        let len = self.varint()?;
        let start = self.pos;
        self.skip(len)?;
        Ok(start..self.pos)
    }

    /// Reads a field header, returning `None` at the end of a struct.
    fn field_header(&mut self, last_id: i16) -> Result<Option<(i16, u8)>> {
        let header = self.byte()?;
        let field_type = header & 0x0f;
        if field_type == STOP {
            return Ok(None);
        }
        let delta = (header >> 4) as i16;
        let id = if delta == 0 {
            let zigzag = self.varint()?;
            i16::try_from((zigzag >> 1) as i64 ^ -((zigzag & 1) as i64))
                .map_err(|_| invalid("field id is out of range"))?
        } else {
            last_id
                .checked_add(delta)
                .ok_or_else(|| invalid("field id is out of range"))?
        };
        Ok(Some((id, field_type)))
    }

    fn list_header(&mut self) -> Result<(u64, u8)> {
        let header = self.byte()?;
        let size = match header >> 4 {
            15 => self.varint()?,
            size => size as u64,
        };
        Ok((size, header & 0x0f))
    }

    /// Skips a value of `value_type`. `in_collection` distinguishes booleans, which are a
    /// byte in a collection but carried by the field header otherwise.
    fn skip_value(&mut self, value_type: u8, in_collection: bool, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(invalid("footer is nested too deeply"));
        }
        match value_type {
            BOOL_TRUE | BOOL_FALSE if !in_collection => {}
            BOOL_TRUE | BOOL_FALSE | BYTE => self.skip(1)?,
            I16 | I32 | I64 => {
                self.varint()?;
            }
            DOUBLE => self.skip(8)?,
            UUID => self.skip(16)?,
            BINARY => {
                self.binary()?;
            }
            LIST | SET => {
                let (size, element_type) = self.list_header()?;
                for _ in 0..size {
                    self.skip_value(element_type, true, depth + 1)?;
                }
            }
            MAP => {
                let size = self.varint()?;
                if size > 0 {
                    let types = self.byte()?;
                    for _ in 0..size {
                        self.skip_value(types >> 4, true, depth + 1)?;
                        self.skip_value(types & 0x0f, true, depth + 1)?;
                    }
                }
            }
            STRUCT => {
                let mut last_id = 0;
                while let Some((id, field_type)) = self.field_header(last_id)? {
                    self.skip_value(field_type, false, depth + 1)?;
                    last_id = id;
                }
            }
            _ => return Err(invalid("unknown Thrift type")),
        }
        Ok(())
    }
}

/// A top-level field of the `FileMetaData`.
struct Field {
    id: i16,
    field_type: u8,
    /// The value's bytes within the footer (empty for booleans).
    value: Range<usize>,
}

/// A `key_value_metadata` entry.
struct KeyValue {
    /// The serialized `KeyValue` struct within the footer.
    span: Range<usize>,
    key: Vec<u8>,
    /// The value's bytes within the footer.
    value: Option<Range<usize>>,
}

/// A parsed Parquet footer.
struct Footer {
    /// Where the footer starts in the file.
    start: u64,
    data: Vec<u8>,
    fields: Vec<Field>,
    key_values: Vec<KeyValue>,
}

impl Footer {
    fn read(mut stream: &mut dyn ReadSeek) -> Result<Self> {
        let len = stream_len(stream)?;
        if len < MIN_FILE_LEN {
            return Err(invalid("file is too short"));
        }
        stream.rewind()?;
        let mut magic = [0u8; 4];
        stream.read_exact(&mut magic)?;
        let mut trailer = [0u8; 8];
        stream.seek(SeekFrom::Start(len - 8))?;
        stream.read_exact(&mut trailer)?;
        if &trailer[4..] == ENCRYPTED_FOOTER_MAGIC {
            return Err(invalid("encrypted files are not supported"));
        }
        if &magic != MAGIC || &trailer[4..] != MAGIC {
            return Err(invalid("missing `PAR1` magic"));
        }

        let footer_len =
            u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]) as u64;
        if footer_len > len - MIN_FILE_LEN {
            return Err(invalid("footer length is out of range"));
        }
        let start = len - 8 - footer_len;
        stream.seek(SeekFrom::Start(start))?;
        let data = stream.read_to_vec(footer_len)?;

        let mut thrift = Thrift {
            data: &data,
            pos: 0,
        };
        let mut fields = Vec::new();
        let mut key_values = Vec::new();
        let mut last_id = 0;
        while let Some((id, field_type)) = thrift.field_header(last_id)? {
            let value_start = thrift.pos;
            if id == KEY_VALUE_METADATA_FIELD && field_type == LIST {
                let (size, element_type) = thrift.list_header()?;
                if element_type != STRUCT {
                    return Err(invalid("`key_value_metadata` is not a list of structs"));
                }
                for _ in 0..size {
                    key_values.push(read_key_value(&mut thrift)?);
                }
            } else {
                thrift.skip_value(field_type, false, 0)?;
            }
            if id == ENCRYPTION_ALGORITHM_FIELD {
                return Err(invalid("encrypted files are not supported"));
            }
            fields.push(Field {
                id,
                field_type,
                value: value_start..thrift.pos,
            });
            last_id = id;
        }
        if thrift.pos != data.len() {
            return Err(invalid("footer length does not match the footer"));
        }

        Ok(Footer {
            start,
            data,
            fields,
            key_values,
        })
    }

    /// The `c2pa:manifest` entry, if there is exactly one.
    fn manifest_entry(&self) -> Result<Option<&KeyValue>> {
        let mut entries = self
            .key_values
            .iter()
            .filter(|kv| kv.key == MANIFEST_KEY.as_bytes());
        match (entries.next(), entries.next()) {
            (None, _) => Ok(None),
            (Some(entry), None) => Ok(Some(entry)),
            (Some(_), Some(_)) => Err(Error::TooManyManifestStores),
        }
    }

    /// Serializes the footer with any `c2pa:manifest` entry removed and, if `encoded` is
    /// given, a new one appended to `key_value_metadata`. Returns the footer and the range
    /// of the new value within it.
    fn rewrite(&self, encoded: Option<&str>) -> Result<(Vec<u8>, Option<Range<usize>>)> {
        self.manifest_entry()?;
        let kept: Vec<&KeyValue> = self
            .key_values
            .iter()
            .filter(|kv| kv.key != MANIFEST_KEY.as_bytes())
            .collect();

        // The new `key_value_metadata` value, or `None` to leave the field out.
        let mut list = None;
        let mut value_in_list = None;
        let count = kept.len() + encoded.is_some() as usize;
        if count > 0 {
            let mut bytes = if count < 15 {
                vec![((count as u8) << 4) | STRUCT]
            } else {
                let mut header = vec![0xf0 | STRUCT];
                header.extend(varint_bytes(count as u64));
                header
            };
            for kv in &kept {
                bytes.extend_from_slice(&self.data[kv.span.clone()]);
            }
            if let Some(encoded) = encoded {
                bytes.push((1 << 4) | BINARY); // key: field 1
                bytes.extend(varint_bytes(MANIFEST_KEY.len() as u64));
                bytes.extend_from_slice(MANIFEST_KEY.as_bytes());
                bytes.push((1 << 4) | BINARY); // value: field 2
                bytes.extend(varint_bytes(encoded.len() as u64));
                let start = bytes.len();
                bytes.extend_from_slice(encoded.as_bytes());
                value_in_list = Some(start..bytes.len());
                bytes.push(STOP);
            }
            list = Some(bytes);
        }

        // Re-emit the fields in order with fresh headers, putting `key_value_metadata` where
        // it was, or before the first field numbered after it.
        let mut footer = Vec::with_capacity(self.data.len() + encoded.map_or(0, str::len) + 64);
        let mut last_id = 0i16;
        let mut value_range = None;
        let mut list_written = false;
        let mut write_list = |footer: &mut Vec<u8>, last_id: &mut i16| {
            if let Some(list) = &list {
                write_field_header(footer, *last_id, KEY_VALUE_METADATA_FIELD, LIST);
                let start = footer.len();
                footer.extend_from_slice(list);
                value_range = value_in_list
                    .clone()
                    .map(|r| start + r.start..start + r.end);
                *last_id = KEY_VALUE_METADATA_FIELD;
            }
        };
        for field in &self.fields {
            if field.id == KEY_VALUE_METADATA_FIELD
                || (!list_written && field.id > KEY_VALUE_METADATA_FIELD)
            {
                write_list(&mut footer, &mut last_id);
                list_written = true;
                if field.id == KEY_VALUE_METADATA_FIELD {
                    continue;
                }
            }
            write_field_header(&mut footer, last_id, field.id, field.field_type);
            footer.extend_from_slice(&self.data[field.value.clone()]);
            last_id = field.id;
        }
        if !list_written {
            write_list(&mut footer, &mut last_id);
        }
        footer.push(STOP);
        Ok((footer, value_range))
    }
}

fn write_field_header(out: &mut Vec<u8>, last_id: i16, id: i16, field_type: u8) {
    match id - last_id {
        delta @ 1..=15 => out.push(((delta as u8) << 4) | field_type),
        _ => {
            out.push(field_type);
            let zigzag = ((id as i64) << 1) ^ ((id as i64) >> 63);
            out.extend(varint_bytes(zigzag as u64));
        }
    }
}

/// Reads a `KeyValue` struct, recording its span and its key and value.
fn read_key_value(thrift: &mut Thrift<'_>) -> Result<KeyValue> {
    let start = thrift.pos;
    let (mut key, mut value) = (None, None);
    let mut last_id = 0;
    while let Some((id, field_type)) = thrift.field_header(last_id)? {
        match (id, field_type) {
            (KEY_FIELD, BINARY) => key = Some(thrift.data[thrift.binary()?].to_vec()),
            (VALUE_FIELD, BINARY) => value = Some(thrift.binary()?),
            _ => thrift.skip_value(field_type, false, 1)?,
        }
        last_id = id;
    }
    Ok(KeyValue {
        span: start..thrift.pos,
        key: key.ok_or_else(|| invalid("`KeyValue` has no key"))?,
        value,
    })
}

/// Writes the column data from `input_stream`, then `footer` and the trailer.
fn write_file(
    input_stream: &mut dyn ReadSeek,
    output_stream: &mut dyn ReadWriteSeek,
    data_len: u64,
    footer: &[u8],
) -> Result<()> {
    let footer_len = u32::try_from(footer.len()).map_err(|_| invalid("footer is too large"))?;
    input_stream.rewind()?;
    output_stream.rewind()?;
    let copied = io::copy(&mut input_stream.take(data_len), output_stream)?;
    if copied != data_len {
        return Err(invalid("file changed while being copied"));
    }
    output_stream.write_all(footer)?;
    output_stream.write_all(&footer_len.to_le_bytes())?;
    output_stream.write_all(MAGIC)?;
    output_stream.flush()?;
    Ok(())
}

pub struct ParquetIO {}

impl C2paReader for ParquetIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let footer = Footer::read(input_stream)?;
        let value = footer
            .manifest_entry()?
            .and_then(|entry| entry.value.clone())
            .ok_or(Error::JumbfNotFound)?;
        let encoded = std::str::from_utf8(&footer.data[value]).map_err(|_| Error::JumbfNotFound)?;
        base64::decode(encoded).map_err(|_| invalid("`c2pa:manifest` is not valid Base64"))
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for ParquetIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let footer = Footer::read(input_stream)?;
        let (new_footer, _) = footer.rewrite(Some(&base64::encode(store_bytes)))?;
        write_file(input_stream, output_stream, footer.start, &new_footer)
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let footer = Footer::read(input_stream)?;

        // Before signing there is no manifest yet. Report where one would be, in the file as
        // it would be with a short placeholder added. (A zero-length range would produce a
        // data hash with no exclusion, so it could not grow into the final one.)
        let (footer_len, value) = match footer.manifest_entry()? {
            Some(entry) => (
                footer.data.len(),
                entry.value.clone().ok_or(Error::JumbfNotFound)?,
            ),
            None => {
                let (new_footer, value) =
                    footer.rewrite(Some(&base64::encode(b"placeholder manifest")))?;
                (new_footer.len(), value.ok_or(Error::JumbfNotFound)?)
            }
        };
        let start = footer.start + value.start as u64;
        let end = footer.start + value.end as u64;
        let file_len = footer.start + footer_len as u64 + 8;

        Ok(vec![
            ObjectLocations {
                offset: start,
                length: end - start,
                htype: ObjectType::C2pa,
            },
            ObjectLocations {
                offset: 0,
                length: start,
                htype: ObjectType::Other,
            },
            ObjectLocations {
                offset: end,
                length: file_len - end,
                htype: ObjectType::Other,
            },
        ])
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let footer = Footer::read(input_stream)?;
        let (new_footer, _) = footer.rewrite(None)?;
        write_file(input_stream, output_stream, footer.start, &new_footer)
    }
}

impl AssetIO for ParquetIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        ParquetIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(ParquetIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(ParquetIO::new(asset_type)))
    }

    fn supported_types(&self) -> &[&str] {
        &["parquet", "application/vnd.apache.parquet"]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    /// Two row groups, with `key_value_metadata` (`ARROW:schema` plus two entries).
    const WITH_METADATA: &[u8] = include_bytes!("../../tests/fixtures/sample1.parquet");
    /// No `key_value_metadata`, so signing inserts the field before `created_by`.
    const WITHOUT_METADATA: &[u8] = include_bytes!("../../tests/fixtures/sample2_no_kv.parquet");

    fn write(input: &[u8], store: &[u8]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        ParquetIO {}
            .write_c2pa(&mut Cursor::new(input), &mut output, store)
            .unwrap();
        output.into_inner()
    }

    fn remove(input: &[u8]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        ParquetIO {}
            .remove_c2pa(&mut Cursor::new(input), &mut output)
            .unwrap();
        output.into_inner()
    }

    fn read(input: &[u8]) -> Result<Vec<u8>> {
        ParquetIO {}.read_c2pa(&mut Cursor::new(input))
    }

    fn footer(input: &[u8]) -> Footer {
        Footer::read(&mut Cursor::new(input)).unwrap()
    }

    /// Rebuilds `input` with its footer's fields followed by `extra` fields, each given as
    /// `(id, type, value bytes)`, in place of any `key_value_metadata`.
    fn with_fields(input: &[u8], extra: &[(i16, u8, Vec<u8>)]) -> Vec<u8> {
        let footer = footer(input);
        let mut fields: Vec<(i16, u8, Vec<u8>)> = footer
            .fields
            .iter()
            .filter(|f| f.id != KEY_VALUE_METADATA_FIELD)
            .map(|f| (f.id, f.field_type, footer.data[f.value.clone()].to_vec()))
            .collect();
        fields.extend(extra.iter().cloned());
        fields.sort_by_key(|f| f.0);

        let mut data = Vec::new();
        let mut last_id = 0;
        for (id, field_type, value) in fields {
            write_field_header(&mut data, last_id, id, field_type);
            data.extend(value);
            last_id = id;
        }
        data.push(STOP);

        let mut file = input[..footer.start as usize].to_vec();
        file.extend(&data);
        file.extend((data.len() as u32).to_le_bytes());
        file.extend(MAGIC);
        file
    }

    /// A `list<KeyValue>`. The key (field 1) and value (field 2) each use a delta-1 header.
    fn key_values(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut list = vec![((entries.len() as u8) << 4) | STRUCT];
        for (key, value) in entries {
            for text in [key, value] {
                list.push((1 << 4) | BINARY);
                list.extend(varint_bytes(text.len() as u64));
                list.extend(text.as_bytes());
            }
            list.push(STOP);
        }
        list
    }

    #[test]
    fn test_read_unsigned() {
        for input in [WITH_METADATA, WITHOUT_METADATA] {
            assert!(matches!(read(input), Err(Error::JumbfNotFound)));
        }
    }

    #[test]
    fn test_write_read_round_trip() {
        for input in [WITH_METADATA, WITHOUT_METADATA] {
            let signed = write(input, b"manifest store");
            assert_eq!(read(&signed).unwrap(), b"manifest store");

            // The column data is unchanged, existing entries keep their order, and the
            // manifest is appended.
            let (before, after) = (footer(input), footer(&signed));
            assert_eq!(
                signed[..after.start as usize],
                input[..before.start as usize]
            );
            let keys = |f: &Footer| {
                f.key_values
                    .iter()
                    .map(|kv| kv.key.clone())
                    .collect::<Vec<_>>()
            };
            let mut expected = keys(&before);
            expected.push(MANIFEST_KEY.as_bytes().to_vec());
            assert_eq!(keys(&after), expected);

            // Removing the manifest gives back the original bytes exactly.
            assert_eq!(remove(&signed), input);
        }
    }

    #[test]
    fn test_resign_replaces() {
        let signed = write(WITH_METADATA, b"first");
        let resigned = write(&signed, b"a second, longer manifest store");
        assert_eq!(read(&resigned).unwrap(), b"a second, longer manifest store");
        assert_eq!(
            footer(&resigned).key_values.len(),
            footer(&signed).key_values.len()
        );
        assert_eq!(remove(&resigned), WITH_METADATA);
    }

    #[test]
    fn test_object_locations_cover_exactly_the_value() {
        let signed = write(WITH_METADATA, b"manifest store");
        let locations = ParquetIO {}
            .get_object_locations(&mut Cursor::new(&signed))
            .unwrap();
        let c2pa = locations
            .iter()
            .find(|l| l.htype == ObjectType::C2pa)
            .unwrap();
        let range = c2pa.offset as usize..(c2pa.offset + c2pa.length) as usize;
        assert_eq!(&signed[range], base64::encode(b"manifest store").as_bytes());

        // Together the regions cover the whole file without overlapping.
        let mut regions: Vec<_> = locations.iter().map(|l| (l.offset, l.length)).collect();
        regions.sort();
        assert_eq!(regions[0].0, 0);
        assert!(regions.windows(2).all(|w| w[0].0 + w[0].1 == w[1].0));
        let last = regions.last().unwrap();
        assert_eq!(last.0 + last.1, signed.len() as u64);
    }

    #[test]
    fn test_object_locations_before_signing() {
        // Without a manifest, the locations describe the file with a placeholder entry.
        for input in [WITH_METADATA, WITHOUT_METADATA] {
            let locations = ParquetIO {}
                .get_object_locations(&mut Cursor::new(input))
                .unwrap();
            let c2pa = locations
                .iter()
                .find(|l| l.htype == ObjectType::C2pa)
                .unwrap();
            let signed = write(input, b"placeholder manifest");
            let range = c2pa.offset as usize..(c2pa.offset + c2pa.length) as usize;
            assert_eq!(
                &signed[range],
                base64::encode(b"placeholder manifest").as_bytes()
            );
            let total: u64 = locations.iter().map(|l| l.length).sum();
            assert_eq!(total, signed.len() as u64);
        }
    }

    #[test]
    fn test_duplicate_manifest_entries() {
        let input = with_fields(
            WITHOUT_METADATA,
            &[(
                KEY_VALUE_METADATA_FIELD,
                LIST,
                key_values(&[
                    (MANIFEST_KEY, "AAAA"),
                    ("other", "x"),
                    (MANIFEST_KEY, "AAAA"),
                ]),
            )],
        );
        assert_eq!(footer(&input).key_values.len(), 3);
        assert!(matches!(read(&input), Err(Error::TooManyManifestStores)));
        assert!(matches!(
            ParquetIO {}.write_c2pa(
                &mut Cursor::new(&input),
                &mut Cursor::new(Vec::new()),
                b"store"
            ),
            Err(Error::TooManyManifestStores)
        ));
    }

    #[test]
    fn test_rejects_encrypted_files() {
        let mut encrypted_footer = WITHOUT_METADATA.to_vec();
        let len = encrypted_footer.len();
        encrypted_footer[len - 4..].copy_from_slice(ENCRYPTED_FOOTER_MAGIC);
        // A plaintext footer that declares `encryption_algorithm` (an empty union).
        let encrypted_columns = with_fields(
            WITHOUT_METADATA,
            &[(ENCRYPTION_ALGORITHM_FIELD, STRUCT, vec![STOP])],
        );
        for input in [encrypted_footer, encrypted_columns] {
            assert!(matches!(read(&input), Err(Error::InvalidAsset(_))));
        }
    }

    #[test]
    fn test_rejects_malformed_files() {
        let len = WITHOUT_METADATA.len();
        let mut bad_leading_magic = WITHOUT_METADATA.to_vec();
        bad_leading_magic[0] = b'X';
        let mut footer_too_long = WITHOUT_METADATA.to_vec();
        footer_too_long[len - 8..len - 4].copy_from_slice(&(len as u32).to_le_bytes());
        let mut footer_too_short = WITHOUT_METADATA.to_vec();
        let footer_len = u32::from_le_bytes(footer_too_short[len - 8..len - 4].try_into().unwrap());
        footer_too_short[len - 8..len - 4].copy_from_slice(&(footer_len - 1).to_le_bytes());
        let deeply_nested = with_fields(WITHOUT_METADATA, &[(20, LIST, vec![0x19; MAX_DEPTH + 2])]);
        let unknown_type = with_fields(WITHOUT_METADATA, &[(20, 0x0e, vec![])]);

        for (name, input) in [
            ("too short", b"PAR1PAR1".to_vec()),
            ("bad leading magic", bad_leading_magic),
            ("footer length past start", footer_too_long),
            ("footer length mismatch", footer_too_short),
            ("nested too deeply", deeply_nested),
            ("unknown Thrift type", unknown_type),
        ] {
            assert!(
                matches!(read(&input), Err(Error::InvalidAsset(_))),
                "{name}: {:?}",
                read(&input)
            );
        }
    }
}
