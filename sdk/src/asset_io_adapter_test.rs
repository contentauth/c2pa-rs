// EXPERIMENT (local only, do not commit).
//
// The asset-io adapter against the handlers it replaces (`JpegIO`, `PngIO`), through the
// same traits the SDK uses, on every JPEG and PNG fixture.
//
// Run with: cargo test --features asset_io asset_io_adapter

#![cfg(all(test, feature = "asset_io"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{fs, io::Cursor, mem::discriminant, path::PathBuf};

use crate::{
    asset_handlers::{asset_io_adapter::AssetIoAdapter, jpeg_io::JpegIO, png_io::PngIO},
    asset_io::{AssetIO, ObjectType, C2PA_BOXHASH},
    Error,
};

fn fixtures() -> Vec<(String, Vec<u8>, Box<dyn AssetIO>, Box<dyn AssetIO>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut v = Vec::new();
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        let ext = p
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase);
        let (old, new): (Box<dyn AssetIO>, Box<dyn AssetIO>) = match ext.as_deref() {
            Some("jpg" | "jpeg") => (
                Box::new(JpegIO::new("jpg")),
                Box::new(AssetIoAdapter::new("jpg")),
            ),
            Some("png") => (
                Box::new(PngIO::new("png")),
                Box::new(AssetIoAdapter::new("png")),
            ),
            _ => continue,
        };
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        v.push((name, fs::read(&p).unwrap(), old, new));
    }
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

fn boxed(ty: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    v.extend_from_slice(ty);
    v.extend_from_slice(body);
    v
}

const C2PA_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// A `jumb` superbox of the given type with one child.
fn superbox(uuid: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut d = uuid.to_vec();
    d.push(3);
    d.extend_from_slice(b"c2pa\0");
    let mut body = boxed(b"jumd", &d);
    body.extend_from_slice(&boxed(b"json", payload));
    boxed(b"jumb", &body)
}

/// A minimal C2PA store.
fn store(payload: &[u8]) -> Vec<u8> {
    superbox(C2PA_UUID, payload)
}

/// Both Ok and equal, or both Err of the same kind.
fn same<T: PartialEq + std::fmt::Debug>(
    what: &str,
    old: crate::Result<T>,
    new: crate::Result<T>,
    problems: &mut Vec<String>,
) {
    let agree = match (&old, &new) {
        (Ok(a), Ok(b)) => a == b,
        (Err(a), Err(b)) => discriminant(a) == discriminant(b),
        _ => false,
    };
    if !agree {
        problems.push(format!(
            "{what}: old {:?}, new {:?}",
            old.map(|_| "Ok"),
            new.map(|_| "Ok")
        ));
    }
}

fn finish(problems: Vec<String>) {
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn reads_agree() {
    let mut problems = Vec::new();
    for (name, bytes, old, new) in fixtures() {
        same(
            &format!("{name} read_c2pa"),
            old.get_reader().read_c2pa(&mut Cursor::new(&bytes)),
            new.get_reader().read_c2pa(&mut Cursor::new(&bytes)),
            &mut problems,
        );
        let (ox, nx) = (
            old.get_reader().read_xmp(&mut Cursor::new(&bytes)),
            new.get_reader().read_xmp(&mut Cursor::new(&bytes)),
        );
        if ox != nx {
            problems.push(format!(
                "{name} read_xmp: old {:?}, new {:?}",
                ox.map(|s| s.len()),
                nx.map(|s| s.len())
            ));
        }
    }
    finish(problems);
}

#[test]
fn manifest_locations_agree() {
    let mut problems = Vec::new();
    let mut compared = 0;
    for (name, bytes, old, new) in fixtures() {
        let ol = old
            .get_writer("x")
            .unwrap()
            .get_object_locations(&mut Cursor::new(&bytes));
        let nl = new
            .get_writer("x")
            .unwrap()
            .get_object_locations(&mut Cursor::new(&bytes));
        let has_manifest = old.get_reader().read_c2pa(&mut Cursor::new(&bytes)).is_ok();
        match (ol, nl) {
            (Ok(o), Ok(n)) => {
                let find = |v: &[crate::asset_io::ObjectLocations]| {
                    v.iter()
                        .find(|l| l.htype == ObjectType::C2pa)
                        .map(|l| (l.offset, l.length))
                };
                // Without a manifest the two place the placeholder differently; only
                // that one exists is expected.
                if has_manifest {
                    if find(&o) != find(&n) {
                        problems.push(format!("{name}: C2pa {:?} vs {:?}", find(&o), find(&n)));
                    }
                    compared += 1;
                } else if find(&n).is_none() {
                    problems.push(format!("{name}: no placeholder location"));
                }
            }
            (Err(_), Err(_)) => {}
            (o, n) => problems.push(format!("{name}: old ok={} new ok={}", o.is_ok(), n.is_ok())),
        }
    }
    assert!(compared > 0, "no fixture with a manifest");
    finish(problems);
}

#[test]
fn written_manifests_read_back_with_either_reader() {
    let s = store(b"hello");
    let mut problems = Vec::new();
    let mut done = 0;
    for (name, bytes, old, new) in fixtures() {
        // Only assets the legacy writer accepts.
        let mut legacy = Cursor::new(Vec::new());
        if old
            .get_writer("x")
            .unwrap()
            .write_c2pa(&mut Cursor::new(&bytes), &mut legacy, &s)
            .is_err()
        {
            continue;
        }
        let mut out = Cursor::new(Vec::new());
        if let Err(e) =
            new.get_writer("x")
                .unwrap()
                .write_c2pa(&mut Cursor::new(&bytes), &mut out, &s)
        {
            problems.push(format!("{name}: write failed: {e}"));
            continue;
        }
        let out = out.into_inner();

        for (who, h) in [("old", &old), ("new", &new)] {
            match h.get_reader().read_c2pa(&mut Cursor::new(&out)) {
                Ok(got) if got == s => {}
                other => problems.push(format!(
                    "{name}: {who} reader of new output: {:?}",
                    other.map(|v| v.len())
                )),
            }
        }
        // And the other way: the new reader on the legacy writer's output.
        match new
            .get_reader()
            .read_c2pa(&mut Cursor::new(legacy.into_inner()))
        {
            Ok(got) if got == s => {}
            other => problems.push(format!(
                "{name}: new reader of old output: {:?}",
                other.map(|v| v.len())
            )),
        }

        // Replacing, then removing.
        let s2 = store(b"a different, longer payload");
        let mut replaced = Cursor::new(Vec::new());
        new.get_writer("x")
            .unwrap()
            .write_c2pa(&mut Cursor::new(&out), &mut replaced, &s2)
            .unwrap();
        let replaced = replaced.into_inner();
        match old.get_reader().read_c2pa(&mut Cursor::new(&replaced)) {
            Ok(got) if got == s2 => {}
            other => problems.push(format!("{name}: replace: {:?}", other.map(|v| v.len()))),
        }
        let mut removed = Cursor::new(Vec::new());
        new.get_writer("x")
            .unwrap()
            .remove_c2pa(&mut Cursor::new(&replaced), &mut removed)
            .unwrap();
        let removed = removed.into_inner();
        if !matches!(
            old.get_reader().read_c2pa(&mut Cursor::new(&removed)),
            Err(Error::JumbfNotFound)
        ) {
            problems.push(format!("{name}: manifest still present after remove_c2pa"));
        }
        done += 1;
    }
    assert!(done > 0);
    finish(problems);
}

/// JUMBF that is not a C2PA store survives writing and removing C2PA stores, and is
/// not mistaken for one.
#[test]
fn other_jumbf_is_left_alone() {
    let other = superbox([9; 16], b"not c2pa");
    let (name, bytes, _, new) = fixtures()
        .into_iter()
        .find(|f| f.0.ends_with(".jpg"))
        .expect("a JPEG fixture");
    let writer = new.get_writer("x").unwrap();
    let entities = |data: &[u8]| {
        let reg = ::asset_io::HandlerRegistry::builtin();
        let s = reg.parse("jpg", &mut Cursor::new(data.to_vec())).unwrap();
        s.entities(::asset_io::SegmentKind::Jumbf)
            .map(|e| {
                (
                    e.jumbf_type(),
                    s.read_entity(&mut Cursor::new(data.to_vec()), e).unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };

    // A clean asset, then the other JUMBF added through asset-io directly.
    let mut clean = Cursor::new(Vec::new());
    writer
        .remove_c2pa(&mut Cursor::new(&bytes), &mut clean)
        .unwrap();
    let clean = clean.into_inner();
    let reg = ::asset_io::HandlerRegistry::builtin();
    let s = reg.parse("jpg", &mut Cursor::new(clean.clone())).unwrap();
    let mut with_other = Cursor::new(Vec::new());
    s.write(
        &mut Cursor::new(clean.clone()),
        &mut with_other,
        &::asset_io::Updates::new().set_jumbf(other.clone()),
        &mut ::asset_io::NullSink,
    )
    .unwrap();
    let with_other = with_other.into_inner();
    assert_eq!(
        entities(&with_other),
        [(Some([9; 16]), other.clone())],
        "{name}"
    );
    // It is not a manifest.
    assert!(matches!(
        new.get_reader().read_c2pa(&mut Cursor::new(&with_other)),
        Err(Error::JumbfNotFound)
    ));

    // Adding a C2PA store keeps it, and the store reads back on its own.
    let c2pa = store(b"manifest");
    let mut both = Cursor::new(Vec::new());
    writer
        .write_c2pa(&mut Cursor::new(&with_other), &mut both, &c2pa)
        .unwrap();
    let both = both.into_inner();
    assert_eq!(
        new.get_reader().read_c2pa(&mut Cursor::new(&both)).unwrap(),
        c2pa
    );
    let found = entities(&both);
    assert_eq!(found.len(), 2, "{name}");
    assert!(found.contains(&(Some([9; 16]), other.clone())));

    // Replacing the store keeps it too.
    let c2pa2 = store(b"a second, longer manifest");
    let mut replaced = Cursor::new(Vec::new());
    writer
        .write_c2pa(&mut Cursor::new(&both), &mut replaced, &c2pa2)
        .unwrap();
    let replaced = replaced.into_inner();
    assert_eq!(
        new.get_reader()
            .read_c2pa(&mut Cursor::new(&replaced))
            .unwrap(),
        c2pa2
    );
    assert!(entities(&replaced).contains(&(Some([9; 16]), other.clone())));

    // Removing the store leaves only the other JUMBF.
    let mut removed = Cursor::new(Vec::new());
    writer
        .remove_c2pa(&mut Cursor::new(&replaced), &mut removed)
        .unwrap();
    assert_eq!(entities(&removed.into_inner()), [(Some([9; 16]), other)]);
}

#[test]
fn composed_manifests_agree() {
    let s = store(b"compose");
    let big = store(&vec![0x5au8; 200_000]);
    for ext in ["jpg", "png"] {
        let (old, new): (Box<dyn AssetIO>, Box<dyn AssetIO>) = if ext == "jpg" {
            (
                Box::new(JpegIO::new("jpg")),
                Box::new(AssetIoAdapter::new("jpg")),
            )
        } else {
            (
                Box::new(PngIO::new("png")),
                Box::new(AssetIoAdapter::new("png")),
            )
        };
        let compose = |io: &dyn AssetIO, data: &[u8]| {
            io.composed_data_ref()
                .unwrap()
                .compose_manifest(data, ext)
                .unwrap()
        };
        // A store that fits one segment composes identically.
        assert_eq!(compose(&*old, &s), compose(&*new, &s), "{ext}");

        // A store that spans segments is split at a different size (c2pa-rs keeps
        // JPEG segments to 64000 bytes, asset-io fills them), so compare the
        // payload they carry.
        let (o, n) = (compose(&*old, &big), compose(&*new, &big));
        if ext == "jpg" {
            assert_eq!(jpeg_xt_payload(&o), big, "old jpg");
            assert_eq!(jpeg_xt_payload(&n), big, "new jpg");
        } else {
            assert_eq!(o, n, "{ext}");
        }
    }
}

/// The JUMBF carried by a run of JPEG XT APP11 segments: the segment framing and
/// XT header removed, and the repeated LBox/TBox dropped from every later segment.
fn jpeg_xt_payload(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = true;
    while !b.is_empty() {
        assert_eq!(&b[..2], &[0xff, 0xeb], "APP11 marker");
        let len = u16::from_be_bytes([b[2], b[3]]) as usize;
        let seg = &b[4..2 + len];
        assert_eq!(&seg[..2], b"JP");
        // En (2) and Z (4) follow, then LBox/TBox repeated after the first segment.
        let skip = if first { 8 } else { 16 };
        out.extend_from_slice(&seg[skip..]);
        first = false;
        b = &b[2 + len..];
    }
    out
}

#[test]
fn box_maps_agree_apart_from_the_placeholder() {
    let mut problems = Vec::new();
    let mut compared = 0;
    for (name, bytes, old, new) in fixtures() {
        let (Some(o), Some(n)) = (old.asset_box_hash_ref(), new.asset_box_hash_ref()) else {
            problems.push(format!("{name}: box hash support differs"));
            continue;
        };
        let (Ok(ob), Ok(nb)) = (
            o.get_box_map(&mut Cursor::new(&bytes)),
            n.get_box_map(&mut Cursor::new(&bytes)),
        ) else {
            continue;
        };
        let has_manifest = old.get_reader().read_c2pa(&mut Cursor::new(&bytes)).is_ok();
        let key = |v: Vec<crate::asset_io::BoxMap>| -> Vec<(Vec<String>, u64, u64)> {
            v.into_iter()
                .filter(|b| has_manifest || !(b.names == [C2PA_BOXHASH] && b.range_len == 0))
                .map(|b| (b.names, b.range_start, b.range_len))
                .collect()
        };
        let (ko, kn) = (key(ob), key(nb));
        if ko != kn {
            let at = ko.iter().zip(&kn).position(|(a, b)| a != b).unwrap_or(0);
            problems.push(format!(
                "{name}: {} vs {} boxes; first difference at #{at}: {:?} vs {:?}",
                ko.len(),
                kn.len(),
                ko.get(at),
                kn.get(at)
            ));
        } else {
            compared += 1;
        }
    }
    assert!(compared > 0);
    finish(problems);
}

#[test]
fn the_registry_resolves_formats_to_the_adapter() {
    let ctx = crate::Context::new();
    for f in ["jpg", "jpeg", "image/jpeg", "png", "image/png"] {
        assert!(ctx.io().handler(f).is_some(), "{f}");
        assert!(ctx.io().writer(f).is_some(), "{f}");
    }
    assert_eq!(ctx.io().mime_for("jpg"), Some("image/jpeg"));
    assert_eq!(ctx.io().mime_for("png"), Some("image/png"));
    assert!(!ctx.io().is_bmff_format("jpg"));
}
