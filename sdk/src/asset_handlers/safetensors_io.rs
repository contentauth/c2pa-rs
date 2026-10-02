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

//! SafeTensors files, as described in "Embedding manifests into SafeTensors".
//!
//! A SafeTensors file is an 8-byte little-endian header length, a UTF-8 JSON header, and the
//! tensor data. The C2PA Manifest Store is Base64-encoded and stored as the `c2pa:manifest`
//! value in the header's `__metadata__` object. The hard binding is a data hash that excludes
//! exactly the Base64-encoded value bytes.
//!
//! The header is edited in place, so every other byte of it is preserved.

use std::{io, ops::Range};

use crate::{
    asset_io::{
        AssetIO, C2paReader, C2paWriter, ObjectLocations, ObjectType, ReadSeek, ReadWriteSeek,
    },
    crypto::base64,
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
};

const LENGTH_FIELD_LEN: u64 = 8;
/// The SafeTensors format limits the header to 100 MB.
const MAX_HEADER_LEN: u64 = 100_000_000;
/// Headers are padded with spaces so that tensor data starts 8-byte aligned.
const DATA_ALIGNMENT: usize = 8;

const METADATA_KEY: &str = "__metadata__";
const MANIFEST_KEY: &str = "c2pa:manifest";

fn invalid(message: &str) -> Error {
    Error::InvalidAsset(format!("invalid SafeTensors header: {message}"))
}

/// A `key: value` member of a JSON object, as byte ranges within the header.
struct Member {
    /// From the opening quote of the key to the end of the value.
    span: Range<usize>,
    key: String,
    value: Range<usize>,
}

/// A JSON object within the header: the position just after its `{`, and its members.
struct Object {
    open: usize,
    members: Vec<Member>,
}

/// A minimal scanner over the JSON header, reporting byte positions. It is only used on
/// headers that `serde_json` has already accepted, so it checks structure rather than
/// grammar. Unlike a JSON parser, it reports duplicate keys.
struct Scanner<'a> {
    json: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn skip_whitespace(&mut self) {
        while matches!(self.json.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<()> {
        self.skip_whitespace();
        if self.json.get(self.pos) != Some(&byte) {
            return Err(invalid(&format!("expected `{}`", byte as char)));
        }
        self.pos += 1;
        Ok(())
    }

    /// Skips a string, returning the range of its contents (between the quotes).
    fn string(&mut self) -> Result<Range<usize>> {
        self.expect(b'"')?;
        let start = self.pos;
        loop {
            match self.json.get(self.pos) {
                Some(b'"') => break,
                Some(b'\\') => self.pos += 2,
                Some(_) => self.pos += 1,
                None => return Err(invalid("unterminated string")),
            }
        }
        let contents = start..self.pos;
        self.pos += 1;
        Ok(contents)
    }

    fn value(&mut self) -> Result<Range<usize>> {
        self.skip_whitespace();
        let start = self.pos;
        match self.json.get(self.pos) {
            Some(b'"') => {
                self.string()?;
            }
            Some(b'{' | b'[') => {
                let mut depth = 0usize;
                loop {
                    match self.json.get(self.pos) {
                        Some(b'"') => {
                            self.string()?;
                            continue;
                        }
                        Some(b'{' | b'[') => depth += 1,
                        Some(b'}' | b']') => {
                            depth -= 1;
                            if depth == 0 {
                                self.pos += 1;
                                break;
                            }
                        }
                        Some(_) => {}
                        None => return Err(invalid("unterminated object or array")),
                    }
                    self.pos += 1;
                }
            }
            Some(_) => {
                while !matches!(
                    self.json.get(self.pos),
                    None | Some(b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
                ) {
                    self.pos += 1;
                }
            }
            None => return Err(invalid("missing value")),
        }
        Ok(start..self.pos)
    }

    fn object(&mut self) -> Result<Object> {
        self.expect(b'{')?;
        let open = self.pos;
        let mut members = Vec::new();

        self.skip_whitespace();
        if self.json.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Object { open, members });
        }
        loop {
            self.skip_whitespace();
            let member_start = self.pos;
            let key = self.string()?;
            let key: String = serde_json::from_slice(&self.json[key.start - 1..key.end + 1])
                .map_err(|_| invalid("invalid key"))?;
            self.expect(b':')?;
            let value = self.value()?;
            members.push(Member {
                span: member_start..value.end,
                key,
                value,
            });

            self.skip_whitespace();
            match self.json.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Object { open, members });
                }
                _ => return Err(invalid("expected `,` or `}`")),
            }
        }
    }
}

/// A parsed SafeTensors header.
struct Header {
    /// The JSON header, without the length field.
    json: Vec<u8>,
    top: Object,
    /// The `__metadata__` object, if present.
    metadata: Option<Object>,
}

impl Header {
    fn read(mut stream: &mut dyn ReadSeek) -> Result<Self> {
        let file_len = stream_len(stream)?;
        stream.rewind()?;

        let mut length = [0u8; LENGTH_FIELD_LEN as usize];
        stream
            .read_exact(&mut length)
            .map_err(|_| invalid("file is too short"))?;
        let header_len = u64::from_le_bytes(length);
        if header_len > MAX_HEADER_LEN || LENGTH_FIELD_LEN + header_len > file_len {
            return Err(invalid("header length is out of range"));
        }
        let json = stream.read_to_vec(header_len)?;

        // The header is a JSON object, optionally followed by padding spaces. Anything else
        // means the length field does not match the header.
        serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&json)
            .map_err(|_| invalid("header is not a JSON object of the stated length"))?;

        let mut scanner = Scanner {
            json: &json,
            pos: 0,
        };
        let top = scanner.object()?;
        let metadata = match top.members.iter().find(|m| m.key == METADATA_KEY) {
            Some(member) => {
                let mut scanner = Scanner {
                    json: &json,
                    pos: member.value.start,
                };
                Some(scanner.object()?)
            }
            None => None,
        };

        Ok(Header {
            json,
            top,
            metadata,
        })
    }

    fn data_start(&self) -> u64 {
        LENGTH_FIELD_LEN + self.json.len() as u64
    }

    /// The range of the Base64 `c2pa:manifest` value within the JSON (between the quotes),
    /// if there is exactly one.
    fn manifest_value(&self) -> Result<Option<Range<usize>>> {
        let mut entries = self
            .metadata
            .iter()
            .flat_map(|m| &m.members)
            .filter(|m| m.key == MANIFEST_KEY);
        match (entries.next(), entries.next()) {
            (None, _) => Ok(None),
            (Some(entry), None) => {
                if self.json.get(entry.value.start) != Some(&b'"') {
                    return Err(invalid("`c2pa:manifest` is not a string"));
                }
                Ok(Some(entry.value.start + 1..entry.value.end - 1))
            }
            (Some(_), Some(_)) => Err(Error::TooManyManifestStores),
        }
    }

    /// Returns the JSON header with `c2pa:manifest` set to `encoded`, or removed when it is
    /// `None`, padded with spaces so that the tensor data stays 8-byte aligned.
    fn with_manifest(&self, encoded: Option<&str>) -> Result<Vec<u8>> {
        let manifest_value = self.manifest_value()?;
        let json = &self.json;
        let mut out = Vec::with_capacity(json.len() + encoded.map_or(0, str::len) + 64);

        match (manifest_value, encoded, &self.metadata) {
            // Replace the existing value.
            (Some(value), Some(encoded), _) => {
                out.extend_from_slice(&json[..value.start]);
                out.extend_from_slice(encoded.as_bytes());
                out.extend_from_slice(&json[value.end..]);
            }
            // Remove the existing member and its separating comma.
            (Some(_), None, Some(metadata)) => {
                let index = metadata
                    .members
                    .iter()
                    .position(|m| m.key == MANIFEST_KEY)
                    .ok_or(Error::JumbfNotFound)?;
                let span = &metadata.members[index].span;
                let removed = match (metadata.members.get(index + 1), index.checked_sub(1)) {
                    (Some(next), _) => span.start..next.span.start,
                    (None, Some(previous)) => metadata.members[previous].span.end..span.end,
                    (None, None) => span.clone(),
                };
                out.extend_from_slice(&json[..removed.start]);
                out.extend_from_slice(&json[removed.end..]);
            }
            // Add the member as the first in `__metadata__`.
            (None, Some(encoded), Some(metadata)) => {
                let separator = if metadata.members.is_empty() { "" } else { "," };
                out.extend_from_slice(&json[..metadata.open]);
                out.extend_from_slice(
                    format!("\"{MANIFEST_KEY}\":\"{encoded}\"{separator}").as_bytes(),
                );
                out.extend_from_slice(&json[metadata.open..]);
            }
            // Add `__metadata__` as the first member of the header.
            (None, Some(encoded), None) => {
                let separator = if self.top.members.is_empty() { "" } else { "," };
                out.extend_from_slice(&json[..self.top.open]);
                out.extend_from_slice(
                    format!("\"{METADATA_KEY}\":{{\"{MANIFEST_KEY}\":\"{encoded}\"}}{separator}")
                        .as_bytes(),
                );
                out.extend_from_slice(&json[self.top.open..]);
            }
            (_, None, _) => out.extend_from_slice(json),
        }

        // Re-pad: drop trailing spaces, then align the start of the tensor data.
        while out.last() == Some(&b' ') {
            out.pop();
        }
        let padding = (DATA_ALIGNMENT - (LENGTH_FIELD_LEN as usize + out.len()) % DATA_ALIGNMENT)
            % DATA_ALIGNMENT;
        out.resize(out.len() + padding, b' ');
        Ok(out)
    }
}

/// Writes a SafeTensors file with the header `json` and the tensor data from `input_stream`.
fn write_file(
    input_stream: &mut dyn ReadSeek,
    output_stream: &mut dyn ReadWriteSeek,
    header: &Header,
    json: &[u8],
) -> Result<()> {
    output_stream.rewind()?;
    output_stream.write_all(&(json.len() as u64).to_le_bytes())?;
    output_stream.write_all(json)?;
    input_stream.seek(io::SeekFrom::Start(header.data_start()))?;
    io::copy(input_stream, output_stream)?;
    output_stream.flush()?;
    Ok(())
}

pub struct SafeTensorsIO {}

impl C2paReader for SafeTensorsIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let header = Header::read(input_stream)?;
        let value = header.manifest_value()?.ok_or(Error::JumbfNotFound)?;
        let encoded = std::str::from_utf8(&header.json[value]).map_err(|_| Error::JumbfNotFound)?;
        base64::decode(encoded).map_err(|_| invalid("`c2pa:manifest` is not valid Base64"))
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl C2paWriter for SafeTensorsIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let header = Header::read(input_stream)?;
        let json = header.with_manifest(Some(&base64::encode(store_bytes)))?;
        write_file(input_stream, output_stream, &header, &json)
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let mut header = Header::read(input_stream)?;
        let mut file_len = stream_len(input_stream)?;

        // Before signing there is no manifest yet. Report where one would be, in the file as
        // it would be with a short placeholder added. (A zero-length range would produce a
        // data hash with no exclusion, so it could not grow into the final one.)
        if header.manifest_value()?.is_none() {
            let json = header.with_manifest(Some(&base64::encode(b"placeholder manifest")))?;
            file_len = file_len - header.json.len() as u64 + json.len() as u64;
            let mut with_entry = Vec::with_capacity(LENGTH_FIELD_LEN as usize + json.len());
            with_entry.extend_from_slice(&(json.len() as u64).to_le_bytes());
            with_entry.extend_from_slice(&json);
            header = Header::read(&mut io::Cursor::new(with_entry))?;
        }
        let value = header.manifest_value()?.ok_or(Error::JumbfNotFound)?;

        let start = LENGTH_FIELD_LEN + value.start as u64;
        let end = LENGTH_FIELD_LEN + value.end as u64;
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
                length: file_len.saturating_sub(end),
                htype: ObjectType::Other,
            },
        ])
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let header = Header::read(input_stream)?;
        let json = header.with_manifest(None)?;
        write_file(input_stream, output_stream, &header, &json)
    }
}

impl AssetIO for SafeTensorsIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        SafeTensorsIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(SafeTensorsIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(SafeTensorsIO::new(asset_type)))
    }

    /// SafeTensors has no IANA media type, so it is identified by its extension.
    fn supported_types(&self) -> &[&str] {
        &["safetensors"]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;

    const WITH_METADATA: &[u8] = include_bytes!("../../tests/fixtures/sample1.safetensors");
    const WITHOUT_METADATA: &[u8] =
        include_bytes!("../../tests/fixtures/sample2_no_metadata.safetensors");

    fn file(json: &str, data: &[u8]) -> Vec<u8> {
        let mut file = (json.len() as u64).to_le_bytes().to_vec();
        file.extend_from_slice(json.as_bytes());
        file.extend_from_slice(data);
        file
    }

    fn write(input: &[u8], store: &[u8]) -> Vec<u8> {
        let mut output = Cursor::new(Vec::new());
        SafeTensorsIO {}
            .write_c2pa(&mut Cursor::new(input), &mut output, store)
            .unwrap();
        output.into_inner()
    }

    fn read(input: &[u8]) -> Result<Vec<u8>> {
        SafeTensorsIO {}.read_c2pa(&mut Cursor::new(input))
    }

    fn header_json(input: &[u8]) -> serde_json::Value {
        let len = u64::from_le_bytes(input[..8].try_into().unwrap()) as usize;
        serde_json::from_slice(&input[8..8 + len]).unwrap()
    }

    fn tensor_data(input: &[u8]) -> &[u8] {
        let len = u64::from_le_bytes(input[..8].try_into().unwrap()) as usize;
        &input[8 + len..]
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

            // Tensor data is untouched and stays 8-byte aligned; the rest of the header is
            // unchanged apart from the new entry.
            assert_eq!(tensor_data(&signed), tensor_data(input));
            assert_eq!((signed.len() - tensor_data(&signed).len()) % 8, 0);
            let original = header_json(input);
            let mut header = header_json(&signed);
            header["__metadata__"]
                .as_object_mut()
                .unwrap()
                .remove(MANIFEST_KEY);
            if original.get(METADATA_KEY).is_none() {
                header.as_object_mut().unwrap().remove(METADATA_KEY);
            }
            assert_eq!(header, original);
        }
    }

    #[test]
    fn test_replace_keeps_one_entry() {
        let signed = write(WITH_METADATA, b"first");
        let resigned = write(&signed, b"a second, longer manifest store");
        assert_eq!(read(&resigned).unwrap(), b"a second, longer manifest store");
        assert_eq!(header_json(&resigned)["__metadata__"]["format"], "np");
        assert_eq!(tensor_data(&resigned), tensor_data(WITH_METADATA));
    }

    #[test]
    fn test_remove() {
        for input in [WITH_METADATA, WITHOUT_METADATA] {
            let mut removed = Cursor::new(Vec::new());
            SafeTensorsIO {}
                .remove_c2pa(&mut Cursor::new(write(input, b"store")), &mut removed)
                .unwrap();
            let removed = removed.into_inner();

            assert!(matches!(read(&removed), Err(Error::JumbfNotFound)));
            assert_eq!(tensor_data(&removed), tensor_data(input));
            // `__metadata__` keeps its other entries; if signing created it, it stays, empty.
            let metadata = &header_json(&removed)["__metadata__"];
            let expected = header_json(input)
                .get(METADATA_KEY)
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            assert_eq!(metadata, &expected);
        }
    }

    #[test]
    fn test_object_locations_cover_exactly_the_value() {
        let signed = write(WITH_METADATA, b"manifest store");
        let locations = SafeTensorsIO {}
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
        let locations = SafeTensorsIO {}
            .get_object_locations(&mut Cursor::new(WITHOUT_METADATA))
            .unwrap();
        let c2pa = locations
            .iter()
            .find(|l| l.htype == ObjectType::C2pa)
            .unwrap();
        assert!(c2pa.length > 0);
        let signed = write(WITHOUT_METADATA, b"placeholder manifest");
        let range = c2pa.offset as usize..(c2pa.offset + c2pa.length) as usize;
        assert_eq!(
            &signed[range],
            base64::encode(b"placeholder manifest").as_bytes()
        );
    }

    #[test]
    fn test_duplicate_manifest_keys() {
        let input = file(
            r#"{"__metadata__":{"c2pa:manifest":"AAAA","c2pa:manifest":"AAAA"}}"#,
            b"",
        );
        assert!(matches!(read(&input), Err(Error::TooManyManifestStores)));
        assert!(matches!(
            SafeTensorsIO {}.write_c2pa(
                &mut Cursor::new(&input),
                &mut Cursor::new(Vec::new()),
                b"store"
            ),
            Err(Error::TooManyManifestStores)
        ));

        // An escaped spelling of the key is the same key.
        let escaped = file(
            r#"{"__metadata__":{"c2pa:manifest":"AAAA","c2pa:manifest":"AAAA"}}"#,
            b"",
        );
        assert!(matches!(read(&escaped), Err(Error::TooManyManifestStores)));
    }

    #[test]
    fn test_rejects_malformed_files() {
        let mut too_long = file(r#"{}"#, b"");
        too_long[..8].copy_from_slice(&1000u64.to_le_bytes());
        let mut huge = file(r#"{}"#, b"");
        huge[..8].copy_from_slice(&(MAX_HEADER_LEN + 1).to_le_bytes());

        for (name, input) in [
            ("too short", vec![1, 2, 3]),
            ("length past end of file", too_long),
            ("length over the limit", huge),
            ("not JSON", file("not json", b"")),
            ("not an object", file("[]", b"")),
            // The length field must match the header: only padding may follow the object.
            ("length field mismatch", file(r#"{}xx"#, b"")),
            (
                "manifest not a string",
                file(r#"{"__metadata__":{"c2pa:manifest":1}}"#, b""),
            ),
        ] {
            assert!(
                matches!(read(&input), Err(Error::InvalidAsset(_))),
                "{name}: {:?}",
                read(&input)
            );
        }

        // Padding spaces after the object are allowed.
        assert!(matches!(
            read(&file(r#"{}      "#, b"")),
            Err(Error::JumbfNotFound)
        ));
    }
}
