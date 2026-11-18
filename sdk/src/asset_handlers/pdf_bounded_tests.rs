// Copyright 2026 Adobe. All rights reserved.
// This file is licensed under the Apache License, Version 2.0 or the MIT license.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::{
    collections::BTreeMap,
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use flate2::{write::ZlibEncoder, Compression};

use super::*;
use crate::{asset_handlers::pdf_io::PdfIO, asset_io::C2paReader, store::Store, Context};

const GIANT: u64 = 1_162_403_077;
const EMBEDDED: &[u8] = b"synthetic manifest";
const REMOTE: &str = "https://credentials.example.test/manifest.c2pa";

#[derive(Default)]
struct Sparse {
    length: u64,
    position: u64,
    segments: BTreeMap<u64, Vec<u8>>,
    reads: Vec<(u64, usize)>,
    fail: bool,
}

impl Sparse {
    fn insert(&mut self, offset: u64, bytes: Vec<u8>) {
        self.length = self.length.max(offset + bytes.len() as u64);
        self.segments.insert(offset, bytes);
    }

    fn total_read(&self) -> u64 {
        self.reads.iter().map(|(_, n)| *n as u64).sum()
    }
}

impl Read for Sparse {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.fail {
            return Err(io::Error::other("synthetic read failure"));
        }
        let count = output.len().min((self.length - self.position) as usize);
        let output = &mut output[..count];
        output.fill(0);
        for (offset, bytes) in &self.segments {
            let start = self.position.max(*offset);
            let end = (self.position + count as u64).min(*offset + bytes.len() as u64);
            if start < end {
                output[(start - self.position) as usize..(end - self.position) as usize]
                    .copy_from_slice(&bytes[(start - offset) as usize..(end - offset) as usize]);
            }
        }
        self.reads.push((self.position, count));
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Sparse {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(position) => position as i128,
            SeekFrom::Current(delta) => self.position as i128 + delta as i128,
            SeekFrom::End(delta) => self.length as i128 + delta as i128,
        };
        if position < 0 || position > self.length as i128 {
            return Err(io::Error::other("invalid synthetic seek"));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

fn stream(dict: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = format!("<< /Length {} {dict} >>\nstream\n", bytes.len()).into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\nendstream");
    body
}

fn flate(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn objects(manifest: Option<&[u8]>, xmp: Option<&str>) -> BTreeMap<u32, Vec<u8>> {
    let mut objects = BTreeMap::new();
    objects.insert(
        1,
        format!(
            "<< /Type /Catalog /Pages 6 0 R {} {} >>",
            if manifest.is_some() {
                "/AF [2 0 R]"
            } else {
                ""
            },
            if xmp.is_some() { "/Metadata 4 0 R" } else { "" },
        )
        .into_bytes(),
    );
    if let Some(bytes) = manifest {
        objects.insert(
            2,
            b"<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F 3 0 R >> >>".to_vec(),
        );
        objects.insert(3, stream("/Type /EmbeddedFile", bytes));
    }
    if let Some(xmp) = xmp {
        objects.insert(4, stream("/Type /Metadata /Subtype /XML", xmp.as_bytes()));
    }
    objects.insert(6, b"<< /Type /Pages /Count 1 /Kids [7 0 R] >>".to_vec());
    objects.insert(7, b"<< /Type /Page /Parent 6 0 R /MediaBox [0 0 10 10] /Resources << /XObject << /Im 9000 0 R >> >> >>".to_vec());
    objects
}

fn remote_xmp() -> String {
    format!(
        r#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dcterms="http://purl.org/dc/terms/" dcterms:provenance="{REMOTE}"/></rdf:RDF></x:xmpmeta>"#
    )
}

#[derive(Clone, Copy)]
enum Layout {
    Table,
    Stream(bool),
    Predictor,
    Hybrid,
}

struct Fixture {
    source: Sparse,
    xref: u64,
    offsets: BTreeMap<u32, u64>,
    unrelated: (u64, u64),
}

fn fixture(
    length: u64,
    objects: BTreeMap<u32, Vec<u8>>,
    layout: Layout,
    compressed: BTreeMap<u32, (u32, u32)>,
) -> Fixture {
    let mut source = Sparse::default();
    source.insert(0, b"%PDF-1.7\n".to_vec());
    let body_size = objects.values().map(|v| v.len() + 64).sum::<usize>();
    let base = length - (2 * WINDOW + body_size) as u64;
    let terminator = b"\nendstream\nendobj\n";
    let mut data_start = 0;
    for _ in 0..4 {
        let header = format!("9000 0 obj\n<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray /Filter /DCTDecode /Length {} >>\nstream\n",
            base - terminator.len() as u64 - data_start);
        data_start = 4096 + header.len() as u64;
        source.insert(4096, header.into_bytes());
    }
    source.insert(base - terminator.len() as u64, terminator.to_vec());
    let mut offsets = BTreeMap::from([(9000, 4096)]);
    let mut position = base;
    for (id, body) in objects {
        offsets.insert(id, position);
        let mut bytes = format!("{id} 0 obj\n").into_bytes();
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(b"\nendobj\n");
        position += bytes.len() as u64;
        source.insert(offsets[&id], bytes);
    }
    let mut entries = BTreeMap::from([(0, Xref::Free)]);
    for (id, offset) in &offsets {
        entries.insert(*id, Xref::Offset(*offset, 0));
    }
    for (id, (container, slot)) in compressed {
        entries.insert(id, Xref::Compressed(container, slot));
    }
    let xref = match layout {
        Layout::Table => {
            source.insert(position, table(&entries, "/Root 1 0 R"));
            position
        }
        Layout::Stream(_) | Layout::Predictor | Layout::Hybrid => {
            offsets.insert(100, position);
            entries.insert(100, Xref::Offset(position, 0));
            let mut data = Vec::new();
            let mut index = String::new();
            for (id, entry) in &entries {
                index.push_str(&format!("{id} 1 "));
                let (kind, field, generation) = match entry {
                    Xref::Free => (0u8, 0u64, 65535u16),
                    Xref::Offset(offset, generation) => (1, *offset, *generation),
                    Xref::Compressed(container, slot) => (2, *container as u64, *slot as u16),
                };
                data.push(kind);
                data.extend_from_slice(&field.to_be_bytes());
                data.extend_from_slice(&generation.to_be_bytes());
            }
            let data = if matches!(layout, Layout::Predictor) {
                let mut encoded = Vec::new();
                let mut previous = [0u8; 11];
                for row in data.as_chunks::<11>().0 {
                    encoded.push(2);
                    for (byte, previous) in row.iter().zip(previous) {
                        encoded.push(byte.wrapping_sub(previous));
                    }
                    previous.copy_from_slice(row);
                }
                flate(&encoded)
            } else if matches!(layout, Layout::Stream(true)) {
                flate(&data)
            } else {
                data
            };
            let dict = format!(
                "/Type /XRef /Size 9001 /Root 1 0 R /W [1 8 2] /Index [{index}] {}",
                if matches!(layout, Layout::Predictor) {
                    "/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 11 >>"
                } else if matches!(layout, Layout::Stream(true)) {
                    "/Filter /FlateDecode"
                } else {
                    ""
                }
            );
            let mut bytes = b"100 0 obj\n".to_vec();
            bytes.extend(stream(&dict, &data));
            bytes.extend_from_slice(b"\nendobj\n");
            let stream_offset = position;
            position += bytes.len() as u64;
            source.insert(stream_offset, bytes);
            if matches!(layout, Layout::Hybrid) {
                for entry in entries.values_mut() {
                    if matches!(entry, Xref::Compressed(..)) {
                        *entry = Xref::Free;
                    }
                }
                source.insert(
                    position,
                    table(&entries, &format!("/Root 1 0 R /XRefStm {stream_offset}")),
                );
                position
            } else {
                stream_offset
            }
        }
    };
    let end = format!("startxref\n{xref}\n%%EOF\n").into_bytes();
    source.insert(length - end.len() as u64, end);
    Fixture {
        source,
        xref,
        offsets,
        unrelated: (data_start, base - terminator.len() as u64),
    }
}

fn table(entries: &BTreeMap<u32, Xref>, trailer: &str) -> Vec<u8> {
    let mut text = "xref\n".to_string();
    for (id, entry) in entries {
        text.push_str(&format!("{id} 1\n"));
        match entry {
            Xref::Offset(offset, generation) => {
                text.push_str(&format!("{offset:010} {generation:05} n \n"))
            }
            Xref::Free => text.push_str("0000000000 65535 f \n"),
            Xref::Compressed(..) => panic!("table cannot encode compressed object"),
        }
    }
    text.push_str(&format!("trailer\n<< /Size 9001 {trailer} >>\n"));
    text.into_bytes()
}

fn incremental(fixture: &mut Fixture, objects: &[(u32, u16, &[u8])], free: &[u32], trailer: &str) {
    let mut position = fixture.source.length;
    let mut entries = BTreeMap::new();
    for (id, generation, body) in objects {
        let mut bytes = format!("{id} {generation} obj\n").into_bytes();
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(b"\nendobj\n");
        entries.insert(*id, Xref::Offset(position, *generation));
        fixture.source.insert(position, bytes.clone());
        position += bytes.len() as u64;
    }
    for id in free {
        entries.insert(*id, Xref::Free);
    }
    let bytes = table(&entries, &format!("/Prev {} {trailer}", fixture.xref));
    let next = position;
    position += bytes.len() as u64;
    fixture.source.insert(next, bytes);
    fixture
        .source
        .insert(position, format!("startxref\n{next}\n%%EOF\n").into_bytes());
    fixture.xref = next;
}

fn assert_bounded(fixture: &Fixture) {
    assert!(
        fixture.source.total_read() < 4 * 1024 * 1024,
        "{:?}",
        fixture.source.reads
    );
    for (offset, count) in &fixture.source.reads {
        assert!(*count <= WINDOW);
        assert!(
            *offset + *count as u64 <= fixture.unrelated.0 + WINDOW as u64
                || *offset >= fixture.unrelated.1 - WINDOW as u64,
            "read interior of unrelated giant stream: {offset} + {count}"
        );
    }
}

#[test]
fn bounded_giant_embedded_absent_remote_and_aliases() {
    for alias in ["pdf", "application/pdf"] {
        let context = Context::new()
            .with_settings(r#"{"verify":{"remote_manifest_fetch":false}}"#)
            .unwrap();
        let mut embedded = fixture(
            GIANT,
            objects(Some(EMBEDDED), Some("<broken")),
            Layout::Table,
            BTreeMap::new(),
        );
        assert_eq!(
            Store::load_jumbf_from_stream(alias, &mut embedded.source, &context)
                .unwrap()
                .0,
            EMBEDDED
        );
        assert_bounded(&embedded);
        let mut absent = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
        assert!(matches!(
            Store::load_jumbf_from_stream(alias, &mut absent.source, &context),
            Err(Error::JumbfNotFound)
        ));
        assert_bounded(&absent);
        let mut remote = fixture(
            GIANT,
            objects(None, Some(&remote_xmp())),
            Layout::Table,
            BTreeMap::new(),
        );
        assert!(
            matches!(Store::load_jumbf_from_stream(alias, &mut remote.source, &context), Err(Error::RemoteManifestUrl(url)) if url == REMOTE)
        );
        assert_bounded(&remote);
    }
}

#[test]
fn bounded_threshold_routing_exact_bytes() {
    let reader = PdfIO {};
    for length in [THRESHOLD - 1, THRESHOLD, THRESHOLD + 1] {
        let mut fixture = fixture(
            length,
            objects(Some(EMBEDDED), None),
            Layout::Table,
            BTreeMap::new(),
        );
        assert_eq!(fixture.source.length, length);
        assert_eq!(reader.read_c2pa(&mut fixture.source).unwrap(), EMBEDDED);
        if length <= THRESHOLD {
            assert!(fixture.source.total_read() >= length);
        } else {
            assert_bounded(&fixture);
        }
    }
}

#[test]
fn bounded_manifest_locations_for_hash_exclusions() {
    use crate::asset_io::{C2paWriter, ObjectType};

    for length in [THRESHOLD - 1, THRESHOLD, THRESHOLD + 1, GIANT] {
        let mut embedded = fixture(
            length,
            objects(Some(EMBEDDED), None),
            Layout::Table,
            BTreeMap::new(),
        );
        let locations = PdfIO {}.get_object_locations(&mut embedded.source).unwrap();
        assert_eq!(locations.len(), 3);
        let manifest = &locations[1];
        assert_eq!(manifest.htype, ObjectType::C2pa);
        assert_eq!(manifest.length, EMBEDDED.len() as u64);
        embedded
            .source
            .seek(SeekFrom::Start(manifest.offset))
            .unwrap();
        let mut bytes = vec![0; EMBEDDED.len()];
        embedded.source.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, EMBEDDED);
        assert_eq!(locations[2].offset + locations[2].length, length);
        if length > THRESHOLD {
            assert_bounded(&embedded);
        }
    }
    let mut absent = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
    let locations = PdfIO {}.get_object_locations(&mut absent.source).unwrap();
    assert_eq!(locations[1].offset, GIANT);
    assert_bounded(&absent);

    let mut data = objects(Some(EMBEDDED), None);
    data.insert(3, stream("/Filter /FlateDecode", &flate(EMBEDDED)));
    let mut filtered = fixture(GIANT, data, Layout::Table, BTreeMap::new());
    assert!(matches!(
        PdfIO {}.get_object_locations(&mut filtered.source),
        Err(Error::NotImplemented(_))
    ));
    assert_bounded(&filtered);
}

#[test]
fn bounded_xref_stream_filtered_and_hybrid_objstm() {
    for layout in [
        Layout::Stream(false),
        Layout::Stream(true),
        Layout::Predictor,
        Layout::Hybrid,
    ] {
        let mut data = objects(Some(EMBEDDED), None);
        let catalog = data.remove(&1).unwrap();
        let filespec = data.remove(&2).unwrap();
        let header = format!("1 0 2 {} ", catalog.len() + 1);
        let mut content = header.as_bytes().to_vec();
        content.extend_from_slice(&catalog);
        content.push(b' ');
        content.extend_from_slice(&filespec);
        let dict = format!(
            "/Type /ObjStm /N 2 /First {} /Filter /FlateDecode",
            header.len()
        );
        data.insert(10, stream(&dict, &flate(&content)));
        let mut fixture = fixture(
            GIANT,
            data,
            layout,
            BTreeMap::from([(1, (10, 0)), (2, (10, 1))]),
        );
        assert_eq!(PdfIO {}.read_c2pa(&mut fixture.source).unwrap(), EMBEDDED);
        assert_bounded(&fixture);
    }
}

#[test]
fn bounded_indirect_arrays_dicts_and_length() {
    let mut data = objects(Some(EMBEDDED), None);
    data.insert(1, b"<< /Type /Catalog /AF 11 0 R >>".to_vec());
    data.insert(2, b"<< /AFRelationship 12 0 R /EF 13 0 R >>".to_vec());
    data.insert(
        3,
        b"<< /Length 14 0 R >>\nstream\nsynthetic manifest\nendstream".to_vec(),
    );
    data.insert(11, b"[2 0 R]".to_vec());
    data.insert(12, b"/C2PA_Manifest".to_vec());
    data.insert(13, b"<< /F 3 0 R >>".to_vec());
    data.insert(14, EMBEDDED.len().to_string().into_bytes());
    let mut fixture = fixture(GIANT, data, Layout::Table, BTreeMap::new());
    assert_eq!(PdfIO {}.read_c2pa(&mut fixture.source).unwrap(), EMBEDDED);
    assert_bounded(&fixture);
}

#[test]
fn bounded_structural_xref_and_work_caps() {
    let bytes = vec![0u8; STRUCTURAL];
    let encoded = flate(&bytes);
    assert_eq!(
        decode(
            b"FlateDecode",
            &Dict::new(),
            &encoded,
            STRUCTURAL,
            &mut Budget::default()
        )
        .unwrap()
        .len(),
        STRUCTURAL
    );
    let mut fixture = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
    let mut pdf = Pdf::open(&mut fixture.source).unwrap();
    let mut index = BTreeMap::new();
    for id in 1..=ENTRIES as u32 {
        pdf.entry(&mut index, id, Xref::Free, false).unwrap();
    }
    assert!(matches!(
        pdf.entry(&mut index, ENTRIES as u32 + 1, Xref::Free, false),
        Err(Error::PdfResourceLimit(_))
    ));
    let mut byte = [0u8; 1];
    pdf.input.budget.operations = OPERATIONS - 1;
    pdf.input.read_at(0, &mut byte).unwrap();
    assert!(matches!(
        pdf.input.read_at(0, &mut byte),
        Err(Error::PdfResourceLimit(_))
    ));
    pdf.input.budget.operations = 0;
    pdf.input.budget.read_bytes = READ_BYTES - 1;
    pdf.input.read_at(0, &mut byte).unwrap();
    assert!(matches!(
        pdf.input.read_at(0, &mut byte),
        Err(Error::PdfResourceLimit(_))
    ));
    pdf.input.budget.read_bytes = 0;
    pdf.input.budget.objects = OBJECTS - 1;
    pdf.plain(Value::Reference(pdf.root)).unwrap();
    assert!(matches!(
        pdf.plain(Value::Reference(pdf.root)),
        Err(Error::PdfResourceLimit(_))
    ));
}

#[test]
fn bounded_revision_depth_and_object_cycles() {
    let mut chain = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
    for _ in 1..REVISIONS {
        incremental(&mut chain, &[], &[], "");
    }
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut chain.source),
        Err(Error::JumbfNotFound)
    ));
    incremental(&mut chain, &[], &[], "");
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut chain.source),
        Err(Error::PdfResourceLimit(_))
    ));
    for depth in [DEPTH, DEPTH + 1] {
        let text = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let mut cursor = std::io::Cursor::new(text.as_bytes());
        let mut input = Input::new(&mut cursor).unwrap();
        assert_eq!(parse(&mut input, 0).is_ok(), depth == DEPTH);
    }
    let mut data = objects(Some(EMBEDDED), None);
    data.insert(
        2,
        b"<< /AFRelationship /C2PA_Manifest /EF 10 0 R >>".to_vec(),
    );
    data.insert(10, b"11 0 R".to_vec());
    data.insert(11, b"10 0 R".to_vec());
    let mut cycle = fixture(GIANT, data, Layout::Table, BTreeMap::new());
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut cycle.source),
        Err(Error::InvalidAsset(_))
    ));
}

#[test]
fn bounded_truncation_overflow_and_objstm_boundaries() {
    for body in [
        b"<< /Length 1 >>\nstream\nabc\nendstream".as_slice(),
        b"<< /Length 9223372036854775808 >>\nstream\nabc\nendstream",
        b"<< /Length 18446744073709551616 >>\nstream\nabc\nendstream",
        b"<< /Length -1 >>\nstream\nabc\nendstream",
        b"<< /Length 20 >>\nstream\nabc\nendstream",
    ] {
        let mut data = objects(Some(EMBEDDED), None);
        data.insert(3, body.to_vec());
        let mut fixture = fixture(GIANT, data, Layout::Table, BTreeMap::new());
        assert!(matches!(
            PdfIO {}.read_c2pa(&mut fixture.source),
            Err(Error::InvalidAsset(_)) | Err(Error::PdfResourceLimit(_))
        ));
    }
    for (header, first, count) in [
        ("1 0 ", 1000, 1),
        ("1 0 1 5 ", 8, 2),
        ("1 10 2 0 ", 9, 2),
        ("2 0 ", 4, 1),
        ("1 18446744073709551615 ", 23, 1),
    ] {
        let mut data = objects(Some(EMBEDDED), None);
        let catalog = data.remove(&1).unwrap();
        let mut content = header.as_bytes().to_vec();
        content.extend(catalog);
        data.insert(
            10,
            stream(
                &format!("/Type /ObjStm /N {count} /First {first}"),
                &content,
            ),
        );
        let mut fixture = fixture(
            GIANT,
            data,
            Layout::Stream(true),
            BTreeMap::from([(1, (10, 0))]),
        );
        assert!(
            matches!(
                PdfIO {}.read_c2pa(&mut fixture.source),
                Err(Error::InvalidAsset(_))
            ),
            "{header}"
        );
    }
}

#[test]
fn bounded_linearized_forward_prev_navigation() {
    let mut fixture = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    // A linearized layout's first-page xref can link forward to the main xref.
    // No page or hint-table traversal is needed for catalog extraction.
    let first_xref = 512;
    let first = table(
        &BTreeMap::from([(20, Xref::Offset(9, 0))]),
        &format!("/Prev {}", fixture.xref),
    );
    fixture.source.insert(first_xref, first);
    fixture.source.insert(
        9,
        format!(
            "20 0 obj\n<< /Linearized 1 /L {GIANT} /H [0 0] /O 7 /E 1024 /N 1 /T {} >>\nendobj\n",
            fixture.xref
        )
        .into_bytes(),
    );
    let end = format!("startxref\n{first_xref}\n%%EOF\n");
    let previous_end = fixture.source.length;
    fixture.source.insert(previous_end, end.into_bytes());
    assert_eq!(PdfIO {}.read_c2pa(&mut fixture.source).unwrap(), EMBEDDED);
}

#[test]
fn bounded_incremental_replacement_removal_free_and_generation() {
    let mut replacement = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    let new_manifest = stream("", b"latest manifest");
    incremental(
        &mut replacement,
        &[
            (3, 1, &new_manifest),
            (
                2,
                0,
                b"<< /AFRelationship /C2PA_Manifest /EF << /F 3 1 R >> >>",
            ),
        ],
        &[],
        "",
    );
    assert_eq!(
        PdfIO {}.read_c2pa(&mut replacement.source).unwrap(),
        b"latest manifest"
    );
    let mut removal = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    incremental(
        &mut removal,
        &[(1, 0, b"<< /Type /Catalog >>")],
        &[2, 3],
        "/Root 1 0 R",
    );
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut removal.source),
        Err(Error::JumbfNotFound)
    ));
    let mut free = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    incremental(&mut free, &[], &[3], "");
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut free.source),
        Err(Error::InvalidAsset(_))
    ));
    let mut wrong_generation = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    incremental(&mut wrong_generation, &[(3, 1, &new_manifest)], &[], "");
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut wrong_generation.source),
        Err(Error::InvalidAsset(_))
    ));
}

#[test]
fn bounded_bad_offsets_encryption_cycles_and_repair_are_not_absence() {
    let reader = PdfIO {};
    for trailer in [
        "/Root 1 0 R /Encrypt << >>",
        "/Root 1 0 R /Prev 18446744073709551615",
        "/Root 1 0 R /Prev 0",
    ] {
        let mut fixture = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
        let entries = BTreeMap::from([(0, Xref::Free), (1, Xref::Offset(fixture.offsets[&1], 0))]);
        fixture
            .source
            .insert(fixture.xref, table(&entries, trailer));
        assert!(!matches!(
            reader.read_c2pa(&mut fixture.source),
            Ok(_) | Err(Error::JumbfNotFound)
        ));
    }
    let mut cycle = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
    let entries = BTreeMap::from([(0, Xref::Free), (1, Xref::Offset(cycle.offsets[&1], 0))]);
    cycle.source.insert(
        cycle.xref,
        table(&entries, &format!("/Root 1 0 R /Prev {}", cycle.xref)),
    );
    assert!(matches!(
        reader.read_c2pa(&mut cycle.source),
        Err(Error::InvalidAsset(_))
    ));
    let mut repair = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
    let end = repair.source.length;
    repair.source.insert(end, vec![b' '; WINDOW + 1]);
    assert!(matches!(
        reader.read_c2pa(&mut repair.source),
        Err(Error::InvalidAsset(_))
    ));
    let mut io = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
    io.source.fail = true;
    assert!(matches!(
        reader.read_c2pa(&mut io.source),
        Err(Error::IoError(_))
    ));
}

#[test]
fn bounded_filtered_manifest_and_unsupported_filter() {
    let mut data = objects(Some(EMBEDDED), None);
    data.insert(3, stream("/Filter /FlateDecode", &flate(EMBEDDED)));
    let mut filtered = fixture(GIANT, data, Layout::Stream(true), BTreeMap::new());
    assert_eq!(PdfIO {}.read_c2pa(&mut filtered.source).unwrap(), EMBEDDED);
    let mut data = objects(Some(EMBEDDED), None);
    data.insert(3, stream("/Filter /DCTDecode", b"not an image"));
    let mut unsupported = fixture(GIANT, data, Layout::Table, BTreeMap::new());
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut unsupported.source),
        Err(Error::NotImplemented(_))
    ));
}

#[test]
fn bounded_filter_arrays_and_lzw() {
    let encoded = format!("{}>", hex::encode(flate(EMBEDDED)));
    let mut data = objects(Some(EMBEDDED), None);
    data.insert(
        3,
        stream(
            "/Filter [/ASCIIHexDecode /FlateDecode] /DecodeParms [null << /Predictor 1 >>]",
            encoded.as_bytes(),
        ),
    );
    let mut fixture = fixture(GIANT, data, Layout::Table, BTreeMap::new());
    assert_eq!(PdfIO {}.read_c2pa(&mut fixture.source).unwrap(), EMBEDDED);
    for early in [0, 1] {
        let mut encoder = if early == 0 {
            weezl::encode::Encoder::new(BitOrder::Msb, 8)
        } else {
            weezl::encode::Encoder::with_tiff_size_switch(BitOrder::Msb, 8)
        };
        let encoded = encoder.encode(EMBEDDED).unwrap();
        let params = BTreeMap::from([(b"EarlyChange".to_vec(), Value::Integer(early))]);
        assert_eq!(
            decode(
                b"LZWDecode",
                &params,
                &encoded,
                EMBEDDED.len(),
                &mut Budget::default()
            )
            .unwrap(),
            EMBEDDED
        );
    }
}

#[test]
fn bounded_sparse_size_and_hostile_xref_declarations() {
    let mut sparse = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    let table = sparse.source.segments.get_mut(&sparse.xref).unwrap();
    *table = String::from_utf8(table.clone())
        .unwrap()
        .replace("/Size 9001", "/Size 4294967296")
        .into_bytes();
    assert_eq!(PdfIO {}.read_c2pa(&mut sparse.source).unwrap(), EMBEDDED);
    assert_bounded(&sparse);
    let mut invalid_size = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    let table = invalid_size
        .source
        .segments
        .get_mut(&invalid_size.xref)
        .unwrap();
    *table = String::from_utf8(table.clone())
        .unwrap()
        .replace("/Size 9001", "/Size 1   ")
        .into_bytes();
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut invalid_size.source),
        Err(Error::InvalidAsset(_))
    ));
    for (dict, resource) in [
        (
            "/Type /XRef /Size 4294967296 /Root 1 0 R /W [1 8 2] /Index [0 4294967296]",
            true,
        ),
        (
            "/Type /XRef /Size 9001 /Root 1 0 R /W [1 8 2] /Index [18446744073709551615 2]",
            false,
        ),
        (
            "/Type /XRef /Size 9001 /Root 1 0 R /W [9 8 2] /Index [0 1]",
            false,
        ),
        (
            "/Type /XRef /Size 9001 /Root 1 0 R /W [1 8 2] /Index [0 1 0 1]",
            false,
        ),
    ] {
        let mut fixture = fixture(
            GIANT,
            objects(None, None),
            Layout::Stream(false),
            BTreeMap::new(),
        );
        let mut object = b"100 0 obj\n".to_vec();
        object.extend(stream(dict, &[]));
        object.extend_from_slice(b"\nendobj\n");
        fixture.source.insert(fixture.xref, object);
        let result = PdfIO {}.read_c2pa(&mut fixture.source);
        assert!(!matches!(result, Ok(_) | Err(Error::JumbfNotFound)));
        assert_eq!(matches!(result, Err(Error::PdfResourceLimit(_))), resource);
    }
}

#[test]
fn bounded_malformed_xmp_propagates() {
    for xmp in [
        "<x>",
        "<x></y>",
        "<x a='&unknown;'/>",
        "<x/><y/>",
        "<x>&unknown;</x>",
    ] {
        let mut fixture = fixture(
            GIANT,
            objects(None, Some(xmp)),
            Layout::Table,
            BTreeMap::new(),
        );
        assert!(
            matches!(
                Store::load_jumbf_from_stream("pdf", &mut fixture.source, &Context::new()),
                Err(Error::InvalidAsset(_))
            ),
            "{xmp}"
        );
        assert_bounded(&fixture);
    }
}

#[test]
fn bounded_context_manifest_limit_before_read() {
    let context = Context::new()
        .with_settings(r#"{"core":{"max_decompressed_manifest_size_in_mb":0}}"#)
        .unwrap();
    let mut fixture = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    assert!(matches!(
        Store::load_jumbf_from_stream("pdf", &mut fixture.source, &context),
        Err(Error::PdfResourceLimit(_))
    ));
}

#[test]
fn bounded_stream_caps_and_bombs() {
    for (cap, subtype) in [(XMP, "/Subtype /XML"), (MANIFEST, "")] {
        for length in [cap, cap + 1] {
            let mut content = vec![b' '; length];
            if cap == XMP {
                content[..3].copy_from_slice(b"<m>");
                content[length - 4..].copy_from_slice(b"</m>");
            }
            let body = stream(subtype, &content);
            let mut data = objects(
                if cap == MANIFEST {
                    Some(EMBEDDED)
                } else {
                    None
                },
                None,
            );
            let id = if cap == MANIFEST { 3 } else { 4 };
            if id == 4 {
                data.insert(1, b"<< /Type /Catalog /Metadata 4 0 R >>".to_vec());
            }
            data.insert(id, body);
            let mut fixture = fixture(GIANT, data, Layout::Table, BTreeMap::new());
            let result = if id == 3 {
                PdfIO {}.read_c2pa(&mut fixture.source).map(|_| ())
            } else {
                PdfIO {}.read_xmp_result(&mut fixture.source).map(|_| ())
            };
            assert_eq!(result.is_ok(), length == cap, "{result:?}");
        }
    }
    let mut budget = Budget::default();
    let bomb = flate(&vec![0; STRUCTURAL + 1]);
    assert!(matches!(
        decode(b"FlateDecode", &Dict::new(), &bomb, STRUCTURAL, &mut budget),
        Err(Error::PdfResourceLimit(_))
    ));
    let mut budget = Budget::default();
    budget.allocate(ALLOCATION).unwrap();
    assert!(matches!(
        budget.allocate(1),
        Err(Error::PdfResourceLimit(_))
    ));
    for length in [STRUCTURAL, STRUCTURAL + 1] {
        let mut encoded = vec![b'0'; length - 2];
        encoded.extend_from_slice(b"> ");
        let mut data = objects(Some(EMBEDDED), None);
        data.insert(3, stream("/Filter /ASCIIHexDecode", &encoded));
        let mut fixture = fixture(GIANT, data, Layout::Table, BTreeMap::new());
        let result = PdfIO {}.read_c2pa(&mut fixture.source);
        if length == STRUCTURAL {
            assert_eq!(result.unwrap().len(), (length - 2) / 2);
        } else {
            assert!(matches!(result, Err(Error::PdfResourceLimit(_))));
        }
    }
}

#[test]
fn bounded_decoder_filters_predictors_and_corruption() {
    let cases: &[(&[u8], &[u8], &[u8])] = &[
        (b"ASCIIHexDecode", b"61 6263>", b"abc"),
        (b"ASCIIHexDecode", b"f>", &[240]),
        (b"ASCII85Decode", b"@:E^~>", b"abc"),
        (b"RunLengthDecode", &[2, b'a', b'b', b'c', 128], b"abc"),
    ];
    for (filter, input, expected) in cases {
        assert_eq!(
            decode(filter, &Dict::new(), input, 20, &mut Budget::default()).unwrap(),
            *expected
        );
    }
    let mut params = Dict::new();
    params.insert(b"Predictor".to_vec(), Value::Integer(12));
    params.insert(b"Columns".to_vec(), Value::Integer(3));
    assert_eq!(
        decode(
            b"FlateDecode",
            &params,
            &flate(&[2, 1, 2, 3, 2, 1, 1, 1]),
            20,
            &mut Budget::default()
        )
        .unwrap(),
        [1, 2, 3, 2, 3, 4]
    );
    for (filter, bytes) in [
        (b"FlateDecode".as_slice(), vec![1, 2, 3]),
        (b"ASCII85Decode", b"!!!!".to_vec()),
        (b"ASCIIHexDecode", b"ffff".to_vec()),
        (b"RunLengthDecode", vec![4, 1, 128]),
        (b"LZWDecode", vec![0]),
    ] {
        assert!(matches!(
            decode(filter, &Dict::new(), &bytes, 20, &mut Budget::default()),
            Err(Error::InvalidAsset(_))
        ));
    }
    let encoded = flate(b"valid output");
    let mut corrupt = encoded.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(decode(
        b"FlateDecode",
        &Dict::new(),
        &corrupt,
        100,
        &mut Budget::default()
    )
    .is_err());
    assert!(decode(
        b"FlateDecode",
        &Dict::new(),
        &encoded[..encoded.len() - 1],
        100,
        &mut Budget::default()
    )
    .is_err());
}

#[test]
fn bounded_synthetic_sparse_file_and_seek_callback() {
    let fixture = fixture(
        GIANT,
        objects(Some(EMBEDDED), None),
        Layout::Table,
        BTreeMap::new(),
    );
    let directory = crate::utils::io_utils::tempdirectory().unwrap();
    let mut file = tempfile::tempfile_in(directory.path()).unwrap();
    file.set_len(fixture.source.length).unwrap();
    for (offset, bytes) in fixture.source.segments {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&bytes).unwrap();
    }
    file.rewind().unwrap();
    assert_eq!(PdfIO {}.read_c2pa(&mut file).unwrap(), EMBEDDED);
}

#[derive(Clone, Default)]
struct MetadataOverride {
    reads: Arc<AtomicUsize>,
}

impl C2paReader for MetadataOverride {
    fn read_c2pa(&self, _: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        Err(Error::JumbfNotFound)
    }

    fn read_xmp(&self, _: &mut dyn ReadSeek) -> Option<String> {
        panic!("legacy/global metadata surface must not be used")
    }

    fn read_xmp_result(&self, _: &mut dyn ReadSeek) -> Result<Option<String>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(Some(remote_xmp()))
    }
}

impl crate::asset_io::AssetIO for MetadataOverride {
    fn new(_: &str) -> Self {
        Self::default()
    }

    fn get_handler(&self, _: &str) -> Box<dyn crate::asset_io::AssetIO> {
        Box::new(self.clone())
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn supported_types(&self) -> &[&str] {
        &["pdf", "application/pdf"]
    }

    fn save_c2pa_store(&self, _: &std::path::Path, _: &[u8]) -> Result<()> {
        Err(Error::PdfReadError)
    }

    fn remove_c2pa_store(&self, _: &std::path::Path) -> Result<()> {
        Err(Error::PdfReadError)
    }
}

#[test]
fn bounded_remote_fallback_uses_context_override() {
    let handler = MetadataOverride::default();
    let reads = handler.reads.clone();
    let context = Context::new()
        .with_settings(r#"{"verify":{"remote_manifest_fetch":false}}"#)
        .unwrap()
        .with_io_handler(handler);
    let mut fixture = fixture(GIANT, objects(None, None), Layout::Table, BTreeMap::new());
    assert!(
        matches!(Store::load_jumbf_from_stream("application/pdf", &mut fixture.source, &context),
            Err(Error::RemoteManifestUrl(url)) if url == REMOTE)
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(fixture.source.reads.is_empty());
}

#[test]
fn bounded_xmp_entities_and_invalid_remote_locator() {
    let context = Context::new()
        .with_settings(r#"{"verify":{"remote_manifest_fetch":false}}"#)
        .unwrap();
    let xmp = remote_xmp().replace(REMOTE, &format!("{REMOTE}?a=1&amp;b=2"));
    let mut escaped = fixture(
        GIANT,
        objects(None, Some(&xmp)),
        Layout::Table,
        BTreeMap::new(),
    );
    assert!(
        matches!(Store::load_jumbf_from_stream("pdf", &mut escaped.source, &context),
        Err(Error::RemoteManifestUrl(url)) if url == format!("{REMOTE}?a=1&b=2"))
    );
    let xmp = remote_xmp().replace(REMOTE, "file:///not-supported.c2pa");
    let mut invalid = fixture(
        GIANT,
        objects(None, Some(&xmp)),
        Layout::Table,
        BTreeMap::new(),
    );
    assert!(matches!(
        Store::load_jumbf_from_stream("pdf", &mut invalid.source, &context),
        Err(Error::NotImplemented(_))
    ));
}

#[test]
fn bounded_xmp_namespace_alias_text_and_resource_forms() {
    let context = Context::new()
        .with_settings(r#"{"verify":{"remote_manifest_fetch":false}}"#)
        .unwrap();
    let forms = [
        format!(
            r#"<m xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:d="http://purl.org/dc/terms/"><r:Description d:provenance="{REMOTE}"/></m>"#
        ),
        format!(
            r#"<m xmlns:d="http://purl.org/dc/terms/"><d:provenance>{REMOTE}</d:provenance></m>"#
        ),
        format!(
            r#"<m xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:d="http://purl.org/dc/terms/"><d:provenance r:resource="{REMOTE}"/></m>"#
        ),
        format!(
            r#"<m xmlns:d="http://purl.org/dc/terms/"><d:provenance><![CDATA[{REMOTE}]]></d:provenance></m>"#
        ),
        format!(
            r#"<m xmlns:d="http://purl.org/dc/terms/"><d:provenance>{}</d:provenance></m>"#,
            REMOTE.replace("example", "ex&#97;mple")
        ),
    ];
    for xmp in forms {
        let mut fixture = fixture(
            GIANT,
            objects(None, Some(&xmp)),
            Layout::Table,
            BTreeMap::new(),
        );
        assert!(
            matches!(Store::load_jumbf_from_stream("pdf", &mut fixture.source, &context),
            Err(Error::RemoteManifestUrl(url)) if url == REMOTE),
            "{xmp}"
        );
    }
    let xmp = r#"<m xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:mm="http://ns.adobe.com/xap/1.0/mm/"><r:Description mm:DocumentID="document" mm:InstanceID="instance"/></m>"#;
    let mut metadata = fixture(
        GIANT,
        objects(None, Some(xmp)),
        Layout::Table,
        BTreeMap::new(),
    );
    let info = crate::utils::xmp_inmemory_utils::XmpInfo::from_source_with_context(
        &mut metadata.source,
        "pdf",
        &context,
    )
    .unwrap();
    assert_eq!(info.document_id.as_deref(), Some("document"));
    assert_eq!(info.instance_id.as_deref(), Some("instance"));
    for xmp in [
        "<1/>",
        "<m>\u{0}</m>",
        "<m>&#0;</m>",
        "<?xml invalid?><m/>",
        "<m><unknown:provenance>https://example.test/</unknown:provenance></m>",
        "<m><d:provenance xmlns:d='http://purl.org/dc/terms/'>a</d:provenance><d:provenance xmlns:d='http://purl.org/dc/terms/'>b</d:provenance></m>",
    ] {
        let mut fixture = fixture(GIANT, objects(None, Some(xmp)), Layout::Table, BTreeMap::new());
        assert!(matches!(Store::load_jumbf_from_stream("pdf", &mut fixture.source, &context),
            Err(Error::InvalidAsset(_))), "{xmp}");
    }
}

#[test]
fn bounded_unrelated_attachment_and_multiple_manifests() {
    let mut data = objects(Some(EMBEDDED), None);
    data.insert(1, b"<< /Type /Catalog /AF [15 0 R 2 0 R] >>".to_vec());
    data.insert(
        15,
        b"<< /AFRelationship /Alternative /EF << /F 9000 0 R >> >>".to_vec(),
    );
    let mut unrelated = fixture(GIANT, data, Layout::Table, BTreeMap::new());
    assert_eq!(PdfIO {}.read_c2pa(&mut unrelated.source).unwrap(), EMBEDDED);
    assert_bounded(&unrelated);
    let mut data = objects(Some(EMBEDDED), None);
    data.insert(1, b"<< /Type /Catalog /AF [2 0 R 16 0 R] >>".to_vec());
    data.insert(
        16,
        b"<< /AFRelationship /C2PA_Manifest /EF << /F 3 0 R >> >>".to_vec(),
    );
    let mut multiple = fixture(GIANT, data, Layout::Table, BTreeMap::new());
    assert!(matches!(
        PdfIO {}.read_c2pa(&mut multiple.source),
        Err(Error::TooManyManifestStores)
    ));
}

#[cfg(feature = "fetch_remote_manifests")]
#[derive(Clone)]
struct Resolver {
    calls: Arc<AtomicUsize>,
}

#[cfg(feature = "fetch_remote_manifests")]
impl crate::http::SyncHttpResolver for Resolver {
    fn http_resolve(
        &self,
        request: http::Request<Vec<u8>>,
    ) -> std::result::Result<http::Response<Box<dyn Read>>, crate::http::HttpResolverError> {
        assert_eq!(request.uri().to_string(), REMOTE);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(http::Response::builder()
            .status(200)
            .header("Content-Length", EMBEDDED.len())
            .body(Box::new(std::io::Cursor::new(EMBEDDED)) as Box<dyn Read>)
            .unwrap())
    }
}

#[cfg(feature = "fetch_remote_manifests")]
#[test]
fn bounded_remote_resolver_allowlists_disabled_and_embedded_precedence() {
    let calls = Arc::new(AtomicUsize::new(0));
    for (settings, embedded, expected) in [
        (
            r#"{"core":{"allowed_network_hosts":["credentials.example.test"]}}"#,
            false,
            1,
        ),
        (
            r#"{"core":{"allowed_network_hosts":["other.example.test"]}}"#,
            false,
            0,
        ),
        (r#"{"verify":{"remote_manifest_fetch":false}}"#, false, 0),
        (
            r#"{"core":{"allowed_network_hosts":["other.example.test"]}}"#,
            true,
            0,
        ),
    ] {
        calls.store(0, Ordering::SeqCst);
        let mut context = Context::new().with_settings(settings).unwrap();
        // Custom resolvers replace the default policy stack in 0.91.0. Exercise
        // host denial through that default stack, not an unrestricted test stub.
        if !settings.contains("other.example.test") || embedded {
            context
                .set_resolver(Resolver {
                    calls: calls.clone(),
                })
                .unwrap();
        }
        let mut fixture = fixture(
            GIANT,
            objects(embedded.then_some(EMBEDDED), Some(&remote_xmp())),
            Layout::Table,
            BTreeMap::new(),
        );
        let result = Store::load_jumbf_from_stream("pdf", &mut fixture.source, &context);
        if expected == 1 || embedded {
            let (bytes, remote) = result.unwrap();
            assert_eq!(bytes, EMBEDDED);
            assert_eq!(remote.is_some(), !embedded);
        } else {
            assert!(result.is_err());
            assert!(!matches!(result, Err(Error::JumbfNotFound)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), expected);
        assert_bounded(&fixture);
    }
}

#[test]
fn bounded_full_reader_validates_signature_and_asset_hash() {
    use crate::{
        assertions::DataHash,
        utils::{hash_utils::HashRange, test::create_test_claim, test_signer::test_signer},
        Reader, SigningAlg, ValidationState,
    };

    let context = Arc::new(Context::new());
    assert!(context.settings().verify.verify_after_reading);
    let signer = test_signer(SigningAlg::Es256);
    let mut store = Store::from_context(&context);
    store.commit_claim(create_test_claim().unwrap()).unwrap();
    let placeholder = store
        .get_data_hashed_manifest_placeholder(signer.reserve_size(), "pdf", &context)
        .unwrap();
    let mut fixture = fixture(
        THRESHOLD + 1,
        objects(Some(&placeholder), None),
        Layout::Table,
        BTreeMap::new(),
    );
    let header = format!(
        "3 0 obj\n<< /Length {} /Type /EmbeddedFile >>\nstream\n",
        placeholder.len()
    );
    let offset = fixture.offsets[&3] + header.len() as u64;
    let mut dh = DataHash::new("PDF asset", "sha256");
    dh.add_exclusion(HashRange::new(offset, placeholder.len() as u64));
    let signed = store
        .get_data_hashed_embeddable_manifest(
            &dh,
            signer.as_ref(),
            "pdf",
            Some(&mut fixture.source),
            &context,
        )
        .unwrap();
    assert_eq!(signed.len(), placeholder.len());
    // Patch the generated fixture's manifest only; no production mutation path.
    let object = fixture
        .source
        .segments
        .get_mut(&fixture.offsets[&3])
        .unwrap();
    object[header.len()..header.len() + signed.len()].copy_from_slice(&signed);
    fixture.source.reads.clear();
    fixture.source.rewind().unwrap();
    let reader = Reader::from_shared_context(&context)
        .with_stream("application/pdf", &mut fixture.source)
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{}",
        reader.json()
    );
    let report = reader.json();
    assert!(report.contains("assertion.dataHash.match"), "{report}");
    assert!(report.contains("claimSignature.validated"), "{report}");
    // Verification legitimately traverses the asset; detection did not.
    assert!(fixture.source.total_read() >= THRESHOLD);
    assert!(fixture.source.total_read() < THRESHOLD + 4 * 1024 * 1024);
    fixture
        .source
        .insert(fixture.unrelated.0 + WINDOW as u64, vec![42]);
    fixture.source.rewind().unwrap();
    let reader = Reader::from_shared_context(&context)
        .with_stream("pdf", &mut fixture.source)
        .unwrap();
    assert_eq!(reader.validation_state(), ValidationState::Invalid);
    assert!(reader.json().contains("assertion.dataHash.mismatch"));
}
