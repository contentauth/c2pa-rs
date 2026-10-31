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

//! WARC (ISO 28500, WARC 1.1) asset handler, per "Embedding manifests into WARC files" in the
//! C2PA 2.5 specification.
//!
//! The C2PA Manifest Store is the block of a record with `WARC-Type: c2pa-provenance` and
//! `Content-Type: application/c2pa`, which is always the last record of the file. Updating
//! the manifest removes that record and appends its replacement.
//!
//! The file is bound with a collection data hash: every record other than the C2PA record is
//! a member, whose `uri` is its `WARC-Record-ID` (without the angle brackets) and whose hash
//! covers its uncompressed bytes, from the version line through the two closing CRLFs. Since
//! the C2PA record isn't a member, adding or replacing it changes no member's hash.
//!
//! Plain WARC files and gzip-compressed ones (one gzip member per record, or several records
//! per member) are supported; a record is decompressed before it is hashed, so recompressing
//! it doesn't change its hash. In a compressed file the C2PA record is written as its own gzip
//! member. WARC-zstd files are not supported.

use std::io::{Read, Write};

use flate2::{bufread::GzDecoder, write::GzEncoder, Compression};

use crate::{
    asset_io::{
        AssetCollectionHash, AssetIO, C2paReader, C2paWriter, ObjectLocations, ObjectType,
        ReadSeek, ReadWriteSeek,
    },
    crypto::internal::time::utc_now,
    error::{Error, Result},
    utils::{
        hash_utils::Hasher,
        io_utils::{stream_len, ReaderUtils},
    },
};

static SUPPORTED_TYPES: [&str; 2] = ["warc", "application/warc"];

const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
const ZSTD_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
const C2PA_WARC_TYPE: &str = "c2pa-provenance";
const C2PA_CONTENT_TYPE: &str = "application/c2pa";

/// The largest a gzip member may decompress to. Bounds the work an untrusted file can force.
const MAX_MEMBER_SIZE: u64 = 1 << 30;

/// Aggregate limit for retained decompressed bytes across all gzip members.
const MAX_DECOMPRESSED_SIZE: u64 = 1 << 30;

/// Placeholder used to lay out the C2PA record before a manifest exists.
const PLACEHOLDER_STORE: &[u8] = b"placeholder manifest";

/// One WARC record.
struct Record {
    /// Index into `Warc::members` of the stored unit holding this record.
    member: usize,
    /// The record's uncompressed bytes within that member's data, from the version line
    /// through the closing CRLFs.
    start: usize,
    end: usize,
    /// The block's range within the member's data.
    block_start: usize,
    block_end: usize,
    version: String,
    record_id: Option<String>,
    is_c2pa: bool,
}

/// A stored unit of the file: a gzip member, or (for a plain file) the whole file.
struct Member {
    /// Byte range of the stored form in the file.
    start: usize,
    end: usize,
    /// The uncompressed data (empty for a plain file, whose data is the file itself).
    data: Vec<u8>,
    records: usize,
}

struct Warc {
    compressed: bool,
    members: Vec<Member>,
    records: Vec<Record>,
}

impl Warc {
    fn member_data<'a>(&'a self, file: &'a [u8], member: usize) -> &'a [u8] {
        if self.compressed {
            &self.members[member].data
        } else {
            file
        }
    }

    fn record_bytes<'a>(&'a self, file: &'a [u8], record: &Record) -> &'a [u8] {
        &self.member_data(file, record.member)[record.start..record.end]
    }

    fn c2pa_records(&self) -> Vec<&Record> {
        self.records.iter().filter(|r| r.is_c2pa).collect()
    }
}

fn invalid(msg: &str) -> Error {
    Error::InvalidAsset(format!("WARC: {msg}"))
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| from + i)
}

/// Parses the records in `data` (one gzip member's data, or a whole plain file).
fn parse_records(data: &[u8], member: usize, records: &mut Vec<Record>) -> Result<usize> {
    let mut pos = 0;
    let mut count = 0;
    while pos < data.len() {
        if !data[pos..].starts_with(b"WARC/") {
            return Err(invalid("record does not start with a WARC version line"));
        }
        let header_end =
            find(data, b"\r\n\r\n", pos).ok_or_else(|| invalid("unterminated header"))?;
        let header = std::str::from_utf8(&data[pos..header_end])
            .map_err(|_| invalid("header is not UTF-8"))?;
        let mut lines = header.split("\r\n");
        let version = lines.next().unwrap_or_default().trim().to_string();

        let mut fields: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.starts_with([' ', '\t']) {
                // A folded continuation of the previous field's value.
                if let Some(last) = fields.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(line.trim());
                }
            } else if let Some((name, value)) = line.split_once(':') {
                fields.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            } else {
                return Err(invalid("malformed header field"));
            }
        }
        let field = |name: &str| {
            fields
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };

        let content_length: usize = field("content-length")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| invalid("record has no valid Content-Length"))?;
        let block_start = header_end + 4;
        let block_end = block_start
            .checked_add(content_length)
            .filter(|&end| end <= data.len())
            .ok_or_else(|| invalid("block is shorter than its Content-Length"))?;
        if data.get(block_end..block_end + 4) != Some(b"\r\n\r\n") {
            return Err(invalid("block length does not match its Content-Length"));
        }
        let end = block_end + 4;

        let content_type = field("content-type").map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        });
        let is_c2pa = field("warc-type") == Some(C2PA_WARC_TYPE)
            && content_type.as_deref() == Some(C2PA_CONTENT_TYPE);
        let record_id = field("warc-record-id").map(|v| {
            v.strip_prefix('<')
                .and_then(|v| v.strip_suffix('>'))
                .unwrap_or(v)
                .to_string()
        });

        records.push(Record {
            member,
            start: pos,
            end,
            block_start,
            block_end,
            version,
            record_id,
            is_c2pa,
        });
        count += 1;
        pos = end;
    }
    Ok(count)
}

fn parse(file: &[u8]) -> Result<Warc> {
    parse_with_limit(file, MAX_DECOMPRESSED_SIZE)
}

fn parse_with_limit(file: &[u8], max_decompressed_size: u64) -> Result<Warc> {
    if file.starts_with(ZSTD_MAGIC) {
        return Err(Error::UnsupportedType);
    }
    let mut records = Vec::new();
    if file.starts_with(b"WARC/") {
        let count = parse_records(file, 0, &mut records)?;
        return Ok(Warc {
            compressed: false,
            members: vec![Member {
                start: 0,
                end: file.len(),
                data: Vec::new(),
                records: count,
            }],
            records,
        });
    }
    if !file.starts_with(GZIP_MAGIC) {
        return Err(Error::UnsupportedType);
    }

    let mut members = Vec::new();
    let mut pos = 0;
    let mut remaining = max_decompressed_size;
    while pos < file.len() {
        let mut decoder = GzDecoder::new(&file[pos..]);
        let mut data = Vec::new();
        (&mut decoder)
            .take(MAX_MEMBER_SIZE.min(remaining) + 1)
            .read_to_end(&mut data)
            .map_err(|_| invalid("bad gzip member"))?;
        if data.len() as u64 > MAX_MEMBER_SIZE {
            return Err(invalid("gzip member decompresses past the size limit"));
        }
        remaining = remaining
            .checked_sub(data.len() as u64)
            .ok_or_else(|| invalid("gzip members exceed the aggregate decompression limit"))?;
        let rest = decoder.into_inner();
        let end = file.len() - rest.len();
        if end == pos {
            return Err(invalid("empty gzip member"));
        }
        let index = members.len();
        let count = parse_records(&data, index, &mut records)?;
        members.push(Member {
            start: pos,
            end,
            data,
            records: count,
        });
        pos = end;
    }
    Ok(Warc {
        compressed: true,
        members,
        records,
    })
}

/// A new C2PA record holding `store_bytes`.
fn c2pa_record(version: &str, store_bytes: &[u8]) -> Vec<u8> {
    let date = utc_now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let id = uuid::Uuid::new_v4();
    let mut out = format!(
        "{version}\r\nWARC-Type: {C2PA_WARC_TYPE}\r\nWARC-Record-ID: <urn:uuid:{id}>\r\n\
         WARC-Date: {date}\r\nContent-Type: {C2PA_CONTENT_TYPE}\r\nContent-Length: {}\r\n\r\n",
        store_bytes.len()
    )
    .into_bytes();
    out.extend_from_slice(store_bytes);
    out.extend_from_slice(b"\r\n\r\n");
    out
}

/// The file without its C2PA records, and the version line to use for a new one.
fn without_c2pa(file: &[u8], warc: &Warc) -> Result<(Vec<u8>, String)> {
    let version = warc
        .records
        .iter()
        .find(|r| !r.is_c2pa)
        .map_or("WARC/1.1".to_string(), |r| r.version.clone());

    let mut out = Vec::with_capacity(file.len());
    if warc.compressed {
        for (index, member) in warc.members.iter().enumerate() {
            let c2pa = warc
                .records
                .iter()
                .filter(|r| r.member == index && r.is_c2pa)
                .count();
            if c2pa == 0 {
                out.extend_from_slice(&file[member.start..member.end]);
            } else if c2pa != member.records {
                return Err(invalid(
                    "the C2PA record shares a gzip member with other records",
                ));
            }
        }
    } else {
        let mut cursor = 0;
        for record in warc.c2pa_records() {
            out.extend_from_slice(&file[cursor..record.start]);
            cursor = record.end;
        }
        out.extend_from_slice(&file[cursor..]);
    }
    Ok((out, version))
}

/// Returns `file` with one C2PA record for `store_bytes`, appended as the last record, and
/// the byte range of its stored form.
fn embed(file: &[u8], store_bytes: &[u8]) -> Result<(Vec<u8>, (usize, usize))> {
    let warc = parse(file)?;
    let (mut out, version) = without_c2pa(file, &warc)?;
    let record = c2pa_record(&version, store_bytes);
    let start = out.len();
    if warc.compressed {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&record)?;
        out.extend_from_slice(&encoder.finish()?);
    } else {
        out.extend_from_slice(&record);
    }
    let end = out.len();
    Ok((out, (start, end)))
}

fn read_all(mut input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
    input_stream.rewind()?;
    let len = stream_len(input_stream)?;
    input_stream.read_to_vec(len)
}

pub struct WarcIO {}

impl C2paReader for WarcIO {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let file = read_all(input_stream)?;
        let warc = parse(&file)?;
        // More than one C2PA record is treated as no manifest.
        match warc.c2pa_records()[..] {
            [record] if record.block_end > record.block_start => Ok(warc
                .member_data(&file, record.member)[record.block_start..record.block_end]
                .to_vec()),
            _ => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, _input_stream: &mut dyn ReadSeek) -> Option<String> {
        None
    }
}

impl AssetCollectionHash for WarcIO {
    fn member_hashes(
        &self,
        input_stream: &mut dyn ReadSeek,
        alg: &str,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let file = read_all(input_stream)?;
        let warc = parse(&file)?;
        let mut members: Vec<(String, Vec<u8>)> = Vec::new();
        for record in warc.records.iter().filter(|r| !r.is_c2pa) {
            let uri = record
                .record_id
                .clone()
                .ok_or_else(|| Error::HashMismatch("WARC record has no WARC-Record-ID".into()))?;
            if members.iter().any(|(u, _)| *u == uri) {
                return Err(Error::HashMismatch(format!(
                    "two WARC records share the WARC-Record-ID {uri}"
                )));
            }
            let mut hasher = Hasher::new(alg)?;
            hasher.update(warc.record_bytes(&file, record));
            members.push((uri, Hasher::finalize(hasher)));
        }
        Ok(members)
    }
}

impl C2paWriter for WarcIO {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let file = read_all(input_stream)?;
        let (out, _) = embed(&file, store_bytes)?;
        output_stream.rewind()?;
        output_stream.write_all(&out)?;
        Ok(())
    }

    /// The stored form of the C2PA record, for callers that bind a WARC file with a data
    /// hash rather than the collection data hash the specification requires.
    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let file = read_all(input_stream)?;
        let warc = parse(&file)?;
        let (full_len, (start, end)) = match warc.c2pa_records()[..] {
            [record] if warc.compressed => {
                let member = &warc.members[record.member];
                (file.len(), (member.start, member.end))
            }
            [record] => (file.len(), (record.start, record.end)),
            [] => {
                let (out, range) = embed(&file, PLACEHOLDER_STORE)?;
                (out.len(), range)
            }
            _ => return Err(invalid("more than one C2PA record")),
        };
        Ok(vec![
            ObjectLocations {
                offset: start as u64,
                length: (end - start) as u64,
                htype: ObjectType::C2pa,
            },
            ObjectLocations {
                offset: 0,
                length: start as u64,
                htype: ObjectType::Other,
            },
            ObjectLocations {
                offset: end as u64,
                length: full_len.saturating_sub(end) as u64,
                htype: ObjectType::Other,
            },
        ])
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        let file = read_all(input_stream)?;
        let warc = parse(&file)?;
        let (out, _) = without_c2pa(&file, &warc)?;
        output_stream.rewind()?;
        output_stream.write_all(&out)?;
        Ok(())
    }
}

impl AssetIO for WarcIO {
    fn new(_asset_type: &str) -> Self {
        WarcIO {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(WarcIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(WarcIO::new(asset_type)))
    }

    fn asset_collection_hash_ref(&self) -> Option<&dyn AssetCollectionHash> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::assertions::CollectionHash;

    fn record(kind: &str, id: &str, content_type: &str, block: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "WARC/1.1\r\nWARC-Type: {kind}\r\nWARC-Record-ID: <{id}>\r\n\
             WARC-Date: 2026-10-29T00:00:00Z\r\nContent-Type: {content_type}\r\n\
             Content-Length: {}\r\n\r\n",
            block.len()
        )
        .into_bytes();
        out.extend_from_slice(block);
        out.extend_from_slice(b"\r\n\r\n");
        out
    }

    fn records() -> Vec<Vec<u8>> {
        vec![
            record(
                "warcinfo",
                "urn:uuid:00000000-0000-4000-8000-000000000001",
                "application/warc-fields",
                b"software: c2pa test\r\n",
            ),
            record(
                "response",
                "urn:uuid:00000000-0000-4000-8000-000000000002",
                "application/http;msgtype=response",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>C2PA test page.</p>",
            ),
            record(
                "request",
                "urn:uuid:00000000-0000-4000-8000-000000000003",
                "application/http;msgtype=request",
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ),
        ]
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn plain() -> Vec<u8> {
        records().concat()
    }

    fn per_record_gzip() -> Vec<u8> {
        records().iter().flat_map(|r| gzip(r)).collect()
    }

    fn write(source: &[u8], store: &[u8]) -> Result<Vec<u8>> {
        let mut output = Cursor::new(Vec::new());
        WarcIO {}.write_c2pa(&mut Cursor::new(source.to_vec()), &mut output, store)?;
        Ok(output.into_inner())
    }

    fn read(data: &[u8]) -> Result<Vec<u8>> {
        WarcIO {}.read_c2pa(&mut Cursor::new(data.to_vec()))
    }

    fn members(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
        WarcIO {}.member_hashes(&mut Cursor::new(data.to_vec()), "sha256")
    }

    #[test]
    fn aggregate_decompression_limit_covers_all_members() {
        let records = records();
        let total = records.iter().map(|r| r.len() as u64).sum::<u64>();
        let compressed: Vec<u8> = records.iter().flat_map(|r| gzip(r)).collect();
        assert!(parse_with_limit(&compressed, total).is_ok());
        assert!(matches!(
            parse_with_limit(&compressed, total - 1),
            Err(Error::InvalidAsset(message)) if message.contains("aggregate decompression limit")
        ));
        assert!(parse_with_limit(&compressed, 0).is_err());
        // The same boundary applies when all records share a single gzip member.
        let compressed = gzip(&records.concat());
        assert!(parse_with_limit(&compressed, total).is_ok());
        assert!(parse_with_limit(&compressed, total - 1).is_err());
    }

    #[test]
    fn appends_the_c2pa_record_last_and_round_trips() {
        let out = write(&plain(), b"store bytes").unwrap();
        assert!(out.starts_with(&plain()));
        assert_eq!(read(&out).unwrap(), b"store bytes");

        let warc = parse(&out).unwrap();
        let last = warc.records.last().unwrap();
        assert!(last.is_c2pa);
        let header = std::str::from_utf8(&out[last.start..last.block_start]).unwrap();
        assert!(header.contains("WARC-Type: c2pa-provenance\r\n"));
        assert!(header.contains("Content-Type: application/c2pa\r\n"));
        assert!(header.contains("Content-Length: 11\r\n"));
        assert!(!header.contains("WARC-Target-URI"));
    }

    #[test]
    fn members_are_every_record_but_the_c2pa_record() {
        let before = members(&plain()).unwrap();
        assert_eq!(before.len(), 3);
        assert_eq!(before[0].0, "urn:uuid:00000000-0000-4000-8000-000000000001");
        let mut hasher = Hasher::new("sha256").unwrap();
        hasher.update(&records()[1]);
        assert_eq!(before[1].1, Hasher::finalize(hasher));

        // Adding, then replacing, the C2PA record changes no member's hash.
        let signed = write(&plain(), b"first").unwrap();
        assert_eq!(members(&signed).unwrap(), before);
        let replaced = write(&signed, b"a longer second store").unwrap();
        assert_eq!(members(&replaced).unwrap(), before);
        assert_eq!(read(&replaced).unwrap(), b"a longer second store");
        assert_eq!(parse(&replaced).unwrap().c2pa_records().len(), 1);
    }

    #[test]
    fn compressed_records_hash_as_uncompressed() {
        assert_eq!(
            members(&per_record_gzip()).unwrap(),
            members(&plain()).unwrap()
        );
        // The whole file as one gzip member, too.
        assert_eq!(
            members(&gzip(&plain())).unwrap(),
            members(&plain()).unwrap()
        );

        let out = write(&per_record_gzip(), b"store").unwrap();
        assert!(out.starts_with(&per_record_gzip()));
        assert_eq!(read(&out).unwrap(), b"store");
        assert_eq!(members(&out).unwrap(), members(&plain()).unwrap());
        // The C2PA record is its own gzip member, so it can be replaced.
        assert_eq!(read(&write(&out, b"again").unwrap()).unwrap(), b"again");
    }

    #[test]
    fn collection_hash_generates_and_verifies() {
        let handler = WarcIO {};
        let mut collection = CollectionHash::new("sha256".to_string());
        collection
            .gen_hash_from_members(&mut Cursor::new(plain()), &handler)
            .unwrap();
        let signed = write(&plain(), b"store").unwrap();
        collection
            .verify_members_hash(&mut Cursor::new(signed.clone()), None, &handler)
            .unwrap();

        // A changed record fails.
        let mut changed = signed.clone();
        let at = find(&changed, b"C2PA test page", 0).unwrap();
        changed[at] = b'c';
        assert!(collection
            .verify_members_hash(&mut Cursor::new(changed), None, &handler)
            .is_err());

        // So does a record the collection doesn't list.
        let extra = record(
            "metadata",
            "urn:uuid:00000000-0000-4000-8000-000000000009",
            "application/warc-fields",
            b"x: y\r\n",
        );
        let added = [plain(), extra].concat();
        let added = write(&added, b"store").unwrap();
        assert!(collection
            .verify_members_hash(&mut Cursor::new(added), None, &handler)
            .is_err());
    }

    #[test]
    fn duplicate_record_ids_are_rejected() {
        let mut duplicated = plain();
        duplicated.extend_from_slice(&records()[1]);
        assert!(members(&duplicated).is_err());
        let mut collection = CollectionHash::new("sha256".to_string());
        assert!(collection
            .gen_hash_from_members(&mut Cursor::new(duplicated), &WarcIO {})
            .is_err());
    }

    #[test]
    fn two_c2pa_records_are_treated_as_no_manifest() {
        let doubled = [
            plain(),
            record(C2PA_WARC_TYPE, "urn:uuid:c1", C2PA_CONTENT_TYPE, b"one"),
            record(C2PA_WARC_TYPE, "urn:uuid:c2", C2PA_CONTENT_TYPE, b"two"),
        ]
        .concat();
        assert!(matches!(read(&doubled), Err(Error::JumbfNotFound)));
        // Both are left out of the collection.
        assert_eq!(members(&doubled).unwrap(), members(&plain()).unwrap());
    }

    #[test]
    fn content_length_mismatch_is_rejected() {
        let mut bad = plain();
        let at = find(&bad, b"Content-Length: 21", 0).unwrap();
        bad[at + 16..at + 18].copy_from_slice(b"20");
        assert!(members(&bad).is_err());
        let mut bad = per_record_gzip();
        bad.extend(gzip(
            &record("metadata", "urn:uuid:x", "text/plain", b"abc")[..60],
        ));
        assert!(members(&bad).is_err());
    }

    #[test]
    fn version_line_follows_the_file() {
        let v10 = String::from_utf8(plain())
            .unwrap()
            .replace("WARC/1.1", "WARC/1.0");
        let out = write(v10.as_bytes(), b"store").unwrap();
        let warc = parse(&out).unwrap();
        assert_eq!(warc.records.last().unwrap().version, "WARC/1.0");
    }

    #[test]
    fn remove_restores_the_original() {
        for source in [plain(), per_record_gzip()] {
            let out = write(&source, b"store").unwrap();
            let mut output = Cursor::new(Vec::new());
            WarcIO {}
                .remove_c2pa(&mut Cursor::new(out), &mut output)
                .unwrap();
            assert_eq!(output.into_inner(), source);
        }
    }

    #[test]
    fn zstd_and_foreign_files_are_unsupported() {
        assert!(matches!(
            read(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0]),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(read(b"%PDF-1.7"), Err(Error::UnsupportedType)));
    }
}
