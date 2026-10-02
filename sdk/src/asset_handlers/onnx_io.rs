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

//! ONNX models, as described in "Embedding manifests into ONNX".
//!
//! An ONNX file is a serialized protobuf `ModelProto`. The C2PA Manifest Store is
//! Base64-encoded and stored as the value of a `metadata_props` entry (a
//! `StringStringEntryProto`) whose key is `c2pa:manifest`. The hard binding is a data hash
//! that excludes exactly the Base64-encoded value bytes.
//!
//! Only the top-level fields of the `ModelProto` are scanned, and the rest of the file is
//! copied unchanged, so models of any size are handled without loading the graph.

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

/// `ModelProto.ir_version`, which every ONNX model has.
const IR_VERSION_FIELD: u64 = 1;
/// `ModelProto.metadata_props`, a repeated `StringStringEntryProto`.
const METADATA_PROPS_FIELD: u64 = 14;
/// `StringStringEntryProto.key` and `.value`.
const ENTRY_KEY_FIELD: u64 = 1;
const ENTRY_VALUE_FIELD: u64 = 2;

const WIRE_VARINT: u8 = 0;
const WIRE_FIXED64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_FIXED32: u8 = 5;

const MANIFEST_KEY: &str = "c2pa:manifest";
/// `metadata_props` entries are small; anything larger is not a key/value pair we read.
const MAX_ENTRY_LEN: u64 = 1 << 30;

fn invalid(message: &str) -> Error {
    Error::InvalidAsset(format!("invalid ONNX model: {message}"))
}

fn read_varint(stream: &mut dyn ReadSeek) -> Result<Option<u64>> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte)? == 0 {
            return if shift == 0 {
                Ok(None)
            } else {
                Err(invalid("truncated varint"))
            };
        }
        value |= ((byte[0] & 0x7f) as u64) << shift;
        if byte[0] < 0x80 {
            return Ok(Some(value));
        }
    }
    Err(invalid("varint is too long"))
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

/// A top-level field of the `ModelProto`.
struct Field {
    number: u64,
    /// The whole field: tag, length (if any) and value.
    span: Range<u64>,
}

/// A `metadata_props` entry.
struct Entry {
    field: usize,
    key: Vec<u8>,
    /// The value's bytes within the file.
    value: Range<u64>,
}

/// The top-level structure of a `ModelProto`.
struct Model {
    len: u64,
    fields: Vec<Field>,
    entries: Vec<Entry>,
}

impl Model {
    fn read(mut stream: &mut dyn ReadSeek) -> Result<Self> {
        let len = stream_len(stream)?;
        stream.rewind()?;

        let mut fields = Vec::new();
        let mut entries = Vec::new();
        loop {
            let start = stream.stream_position()?;
            let Some(tag) = read_varint(stream)? else {
                break;
            };
            let (number, wire_type) = (tag >> 3, (tag & 7) as u8);
            if number == 0 {
                return Err(invalid("field number 0"));
            }

            match wire_type {
                WIRE_VARINT => {
                    read_varint(stream)?.ok_or_else(|| invalid("truncated varint"))?;
                }
                WIRE_FIXED64 | WIRE_FIXED32 => {
                    let size = if wire_type == WIRE_FIXED64 { 8 } else { 4 };
                    stream.seek(SeekFrom::Current(size))?;
                }
                WIRE_LEN => {
                    let size = read_varint(stream)?.ok_or_else(|| invalid("truncated length"))?;
                    let value_start = stream.stream_position()?;
                    let value_end = value_start
                        .checked_add(size)
                        .filter(|&end| end <= len)
                        .ok_or_else(|| invalid("field extends past the end of the file"))?;
                    if number == METADATA_PROPS_FIELD {
                        if size > MAX_ENTRY_LEN {
                            return Err(invalid("metadata entry is too large"));
                        }
                        let data = stream.read_to_vec(size)?;
                        let (key, value) = parse_entry(&data)?;
                        entries.push(Entry {
                            field: fields.len(),
                            key,
                            value: value_start + value.start as u64..value_start + value.end as u64,
                        });
                    }
                    stream.seek(SeekFrom::Start(value_end))?;
                }
                _ => return Err(invalid("unsupported wire type")),
            }

            let end = stream.stream_position()?;
            if end > len {
                return Err(invalid("field extends past the end of the file"));
            }
            fields.push(Field {
                number,
                span: start..end,
            });
        }

        if !fields.iter().any(|f| f.number == IR_VERSION_FIELD) {
            return Err(invalid("no ir_version"));
        }
        Ok(Model {
            len,
            fields,
            entries,
        })
    }

    /// The `c2pa:manifest` entry, if there is exactly one.
    fn manifest_entry(&self) -> Result<Option<&Entry>> {
        let mut entries = self
            .entries
            .iter()
            .filter(|e| e.key == MANIFEST_KEY.as_bytes());
        match (entries.next(), entries.next()) {
            (None, _) => Ok(None),
            (Some(entry), None) => Ok(Some(entry)),
            (Some(_), Some(_)) => Err(Error::TooManyManifestStores),
        }
    }

    /// Where a new `metadata_props` entry goes: after the last field numbered up to
    /// `metadata_props`, ignoring `skip`, which is where a serializer would put it.
    fn insertion_point(&self, skip: Option<usize>) -> u64 {
        self.fields
            .iter()
            .enumerate()
            .filter(|(i, f)| Some(*i) != skip && f.number <= METADATA_PROPS_FIELD)
            .map(|(_, f)| f.span.end)
            .max()
            .unwrap_or(0)
    }
}

/// Parses a `StringStringEntryProto`, returning its key and the range of its value.
fn parse_entry(data: &[u8]) -> Result<(Vec<u8>, Range<usize>)> {
    let mut stream = io::Cursor::new(data);
    let (mut key, mut value) = (Vec::new(), 0..0);
    while let Some(tag) = read_varint(&mut stream)? {
        let size = match (tag & 7) as u8 {
            WIRE_LEN => read_varint(&mut stream)?.ok_or_else(|| invalid("truncated length"))?,
            WIRE_VARINT => {
                read_varint(&mut stream)?;
                continue;
            }
            WIRE_FIXED64 => 8,
            WIRE_FIXED32 => 4,
            _ => return Err(invalid("unsupported wire type in metadata entry")),
        };
        let start = stream.position() as usize;
        let end = start
            .checked_add(size as usize)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| invalid("metadata entry is truncated"))?;
        match (tag >> 3, (tag & 7) as u8) {
            (ENTRY_KEY_FIELD, WIRE_LEN) => key = data[start..end].to_vec(),
            (ENTRY_VALUE_FIELD, WIRE_LEN) => value = start..end,
            _ => {}
        }
        stream.set_position(end as u64);
    }
    Ok((key, value))
}

/// Serializes a `metadata_props` field holding `c2pa:manifest` = `encoded`. Returns the
/// bytes and the offset of the value within them.
fn manifest_field(encoded: &str) -> (Vec<u8>, usize) {
    let mut entry = vec![(ENTRY_KEY_FIELD << 3) as u8 | WIRE_LEN];
    entry.extend(varint_bytes(MANIFEST_KEY.len() as u64));
    entry.extend_from_slice(MANIFEST_KEY.as_bytes());
    entry.push((ENTRY_VALUE_FIELD << 3) as u8 | WIRE_LEN);
    entry.extend(varint_bytes(encoded.len() as u64));
    let value_offset = entry.len();
    entry.extend_from_slice(encoded.as_bytes());

    let mut field = vec![(METADATA_PROPS_FIELD << 3) as u8 | WIRE_LEN];
    field.extend(varint_bytes(entry.len() as u64));
    let value_offset = field.len() + value_offset;
    field.extend(entry);
    (field, value_offset)
}

/// The layout of the file once the existing `c2pa:manifest` field, if any, is removed and
/// `new_field` is inserted.
struct Layout {
    /// The existing `c2pa:manifest` field, which is dropped.
    removed: Option<Range<u64>>,
    /// Where `new_field` goes, in the input.
    insert_at: u64,
}

impl Layout {
    fn new(model: &Model) -> Result<Self> {
        let existing = model.manifest_entry()?.map(|e| e.field);
        Ok(Layout {
            removed: existing.map(|i| model.fields[i].span.clone()),
            insert_at: model.insertion_point(existing),
        })
    }

    /// The input's position in the output, for input positions outside the removed field.
    fn output_position(&self, input: u64, inserted_len: u64) -> u64 {
        let removed = match &self.removed {
            Some(r) if r.end <= input => r.end - r.start,
            _ => 0,
        };
        let inserted = if input >= self.insert_at {
            inserted_len
        } else {
            0
        };
        input - removed + inserted
    }
}

fn copy_range(
    input_stream: &mut dyn ReadSeek,
    output_stream: &mut dyn ReadWriteSeek,
    range: Range<u64>,
) -> Result<()> {
    input_stream.seek(SeekFrom::Start(range.start))?;
    let copied = io::copy(
        &mut input_stream.take(range.end - range.start),
        output_stream,
    )?;
    if copied != range.end - range.start {
        return Err(invalid("file changed while being copied"));
    }
    Ok(())
}

/// Writes the model with its `c2pa:manifest` field removed, and `new_field` inserted.
fn write_model(
    input_stream: &mut dyn ReadSeek,
    output_stream: &mut dyn ReadWriteSeek,
    model: &Model,
    layout: &Layout,
    new_field: &[u8],
) -> Result<()> {
    // Cut points in input order: the removed field, and the insertion point.
    let mut cuts = vec![0, model.len];
    if let Some(r) = &layout.removed {
        cuts.extend([r.start, r.end]);
    }
    cuts.push(layout.insert_at);
    cuts.sort_unstable();
    cuts.dedup();

    output_stream.rewind()?;
    for window in cuts.windows(2) {
        let (start, end) = (window[0], window[1]);
        if start == layout.insert_at {
            output_stream.write_all(new_field)?;
        }
        if layout.removed.as_ref().is_none_or(|r| r.start != start) {
            copy_range(input_stream, output_stream, start..end)?;
        }
    }
    if layout.insert_at == model.len {
        output_stream.write_all(new_field)?;
    }
    output_stream.flush()?;
    Ok(())
}

pub struct OnnxIO {}

impl C2paReader for OnnxIO {
    fn read_c2pa(&self, mut input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let model = Model::read(input_stream)?;
        let entry = model.manifest_entry()?.ok_or(Error::JumbfNotFound)?;
        input_stream.seek(SeekFrom::Start(entry.value.start))?;
        let encoded = input_stream.read_to_vec(entry.value.end - entry.value.start)?;
        let encoded = std::str::from_utf8(&encoded).map_err(|_| Error::JumbfNotFound)?;
        base64::decode(encoded).map_err(|_| invalid("`c2pa:manifest` is not valid Base64"))
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for OnnxIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let model = Model::read(input_stream)?;
        let layout = Layout::new(&model)?;
        let (field, _) = manifest_field(&base64::encode(store_bytes));
        write_model(input_stream, output_stream, &model, &layout, &field)
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let model = Model::read(input_stream)?;

        let (start, end, file_len) = match model.manifest_entry()? {
            Some(entry) => (entry.value.start, entry.value.end, model.len),
            // Before signing there is no manifest yet. Report where one would be, in the
            // file as it would be with a short placeholder added. (A zero-length range would
            // produce a data hash with no exclusion, so it could not grow into the final one.)
            None => {
                let layout = Layout::new(&model)?;
                let (field, value_offset) =
                    manifest_field(&base64::encode(b"placeholder manifest"));
                let field_start = layout.output_position(layout.insert_at, 0);
                let start = field_start + value_offset as u64;
                let end = field_start + field.len() as u64;
                (start, end, model.len + field.len() as u64)
            }
        };

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
        let model = Model::read(input_stream)?;
        let layout = Layout::new(&model)?;
        write_model(input_stream, output_stream, &model, &layout, &[])
    }
}

impl AssetIO for OnnxIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        OnnxIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(OnnxIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(OnnxIO::new(asset_type)))
    }

    /// ONNX has no IANA media type, so it is identified by its extension.
    fn supported_types(&self) -> &[&str] {
        &["onnx"]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    /// `y = x·W + b`, with two existing `metadata_props` entries.
    const WITH_METADATA: &[u8] = include_bytes!("../../tests/fixtures/sample1.onnx");
    /// No `metadata_props`, and a model-local function (field 25, after `metadata_props`).
    const WITH_FUNCTIONS: &[u8] = include_bytes!("../../tests/fixtures/sample2_functions.onnx");

    fn write(input: &[u8], store: &[u8]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        OnnxIO {}
            .write_c2pa(&mut Cursor::new(input), &mut output, store)
            .unwrap();
        output.into_inner()
    }

    fn remove(input: &[u8]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        OnnxIO {}
            .remove_c2pa(&mut Cursor::new(input), &mut output)
            .unwrap();
        output.into_inner()
    }

    fn read(input: &[u8]) -> Result<Vec<u8>> {
        OnnxIO {}.read_c2pa(&mut Cursor::new(input))
    }

    fn field_numbers(input: &[u8]) -> Vec<u64> {
        Model::read(&mut Cursor::new(input))
            .unwrap()
            .fields
            .iter()
            .map(|f| f.number)
            .collect()
    }

    fn entry(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut entry = vec![0x0a];
        entry.extend(varint_bytes(key.len() as u64));
        entry.extend_from_slice(key);
        entry.push(0x12);
        entry.extend(varint_bytes(value.len() as u64));
        entry.extend_from_slice(value);
        let mut field = vec![0x72];
        field.extend(varint_bytes(entry.len() as u64));
        field.extend(entry);
        field
    }

    #[test]
    fn test_read_unsigned() {
        for input in [WITH_METADATA, WITH_FUNCTIONS] {
            assert!(matches!(read(input), Err(Error::JumbfNotFound)));
        }
    }

    #[test]
    fn test_write_read_round_trip() {
        for input in [WITH_METADATA, WITH_FUNCTIONS] {
            let signed = write(input, b"manifest store");
            assert_eq!(read(&signed).unwrap(), b"manifest store");

            // Fields stay in field-number order: the entry goes after the last field
            // numbered up to `metadata_props`, and before later ones.
            let numbers = field_numbers(&signed);
            assert!(numbers.windows(2).all(|w| w[0] <= w[1]), "{numbers:?}");

            // Removing the manifest gives back the original bytes exactly.
            assert_eq!(remove(&signed), input);
        }
    }

    #[test]
    fn test_resign_replaces_in_place() {
        let signed = write(WITH_FUNCTIONS, b"first");
        let resigned = write(&signed, b"a second, longer manifest store");
        assert_eq!(read(&resigned).unwrap(), b"a second, longer manifest store");
        assert_eq!(field_numbers(&resigned), field_numbers(&signed));
        assert_eq!(remove(&resigned), WITH_FUNCTIONS);
    }

    #[test]
    fn test_remove_unsigned_is_a_copy() {
        for input in [WITH_METADATA, WITH_FUNCTIONS] {
            assert_eq!(remove(input), input);
        }
    }

    #[test]
    fn test_object_locations_cover_exactly_the_value() {
        let signed = write(WITH_METADATA, b"manifest store");
        let locations = OnnxIO {}
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
        for input in [WITH_METADATA, WITH_FUNCTIONS] {
            let locations = OnnxIO {}
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
        let mut input = WITH_FUNCTIONS.to_vec();
        input.extend(entry(MANIFEST_KEY.as_bytes(), b"AAAA"));
        input.extend(entry(MANIFEST_KEY.as_bytes(), b"AAAA"));
        assert!(matches!(read(&input), Err(Error::TooManyManifestStores)));
        assert!(matches!(
            OnnxIO {}.write_c2pa(
                &mut Cursor::new(&input),
                &mut Cursor::new(Vec::new()),
                b"store"
            ),
            Err(Error::TooManyManifestStores)
        ));

        // Other keys are not manifests.
        let mut other = WITH_FUNCTIONS.to_vec();
        other.extend(entry(b"c2pa:manifest2", b"AAAA"));
        assert!(matches!(read(&other), Err(Error::JumbfNotFound)));
    }

    #[test]
    fn test_rejects_malformed_models() {
        let mut past_end = WITH_FUNCTIONS.to_vec();
        past_end.extend([0x72, 0x7f, 0x00]); // a 127-byte field with 1 byte present
        let mut group = WITH_FUNCTIONS.to_vec();
        group.push(0x73); // field 14, wire type 3 (start group)
        let mut field_zero = WITH_FUNCTIONS.to_vec();
        field_zero.extend([0x02, 0x00]); // field 0
        let mut truncated_varint = WITH_FUNCTIONS.to_vec();
        truncated_varint.extend([0x08, 0x80]); // varint field missing its last byte
        let mut bad_entry = WITH_FUNCTIONS.to_vec();
        bad_entry.extend([0x72, 0x02, 0x0a, 0x05]); // key claims 5 bytes, has none

        for (name, input) in [
            ("empty", vec![]),
            ("no ir_version", vec![0x12, 0x01, b'x']),
            ("field past end", past_end),
            ("group wire type", group),
            ("field number 0", field_zero),
            ("truncated varint", truncated_varint),
            ("truncated metadata entry", bad_entry),
        ] {
            assert!(
                matches!(read(&input), Err(Error::InvalidAsset(_))),
                "{name}: {:?}",
                read(&input)
            );
        }
    }
}
