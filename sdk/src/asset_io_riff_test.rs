// EXPERIMENT (local only, do not commit).
//
// Differential test: asset-io's RIFF handler against the existing c2pa-rs
// `RiffIO` on every WebP, WAV and AVI fixture.
//
//   1. both sides agree on which files are errors;
//   2. the manifest and XMP read from each file are equal;
//   3. `write_c2pa` output is byte-identical to `set_jumbf`;
//   4. `get_object_locations` equals the locations derived from the layout;
//   5. `write_xmp` output matches `set_xmp` (byte-identical when the file had no XMP
//      to replace, where the two place the new chunk differently).

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{fs, io::Cursor, path::PathBuf};

use asset_io::{containers::riff, NullSink, SegmentKind, Structure, Updates};

use crate::{
    asset_handlers::riff_io::RiffIO,
    asset_io::{AssetIO, C2paWriter, ObjectLocations, ObjectType, WriteXmp},
};

fn fixtures() -> Vec<(PathBuf, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut v: Vec<(PathBuf, String)> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter_map(|p| {
            let ext = p.extension()?.to_str()?.to_ascii_lowercase();
            matches!(ext.as_str(), "webp" | "wav" | "avi").then_some((p, ext))
        })
        .collect();
    v.sort();
    v
}

fn entity(s: &Structure, bytes: &[u8], kind: SegmentKind) -> Option<Vec<u8>> {
    s.entities(kind)
        .next()
        .map(|e| s.read_entity(&mut Cursor::new(bytes), e).unwrap())
}

fn old_write(io: &RiffIO, bytes: &[u8], store: &[u8]) -> crate::Result<Vec<u8>> {
    let mut out = Cursor::new(Vec::new());
    io.write_c2pa(&mut Cursor::new(bytes), &mut out, store)?;
    Ok(out.into_inner())
}

fn new_write(bytes: &[u8], u: &Updates) -> asset_io::Result<Vec<u8>> {
    let s = riff::parse(&mut Cursor::new(bytes))?;
    let mut out = Cursor::new(Vec::new());
    s.write(&mut Cursor::new(bytes), &mut out, u, &mut NullSink)?;
    Ok(out.into_inner())
}

/// What the old handler's `get_object_locations` would say, from the layout of a
/// file that has a manifest chunk.
fn locations(s: &Structure, total: u64) -> Option<Vec<(u64, u64, ObjectType)>> {
    let e = s.entities(SegmentKind::Jumbf).next()?;
    let seg = s.segment(e.parts().next()?.segment()).ok()?;
    let (off, len) = (
        seg.extent().offset(),
        seg.header().len() + seg.payload().len(),
    );
    let end = off + len;
    Some(vec![
        (off, len, ObjectType::C2pa),
        (0, off, ObjectType::Other),
        (end, total - end, ObjectType::Other),
    ])
}

#[test]
fn riff_matches_existing_handler() {
    let mut problems = Vec::new();
    let mut checked = 0;
    for (path, ext) in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let bytes = fs::read(&path).unwrap();
        let io = RiffIO::new(&ext);

        let new = riff::parse(&mut Cursor::new(&bytes));
        let old_read = io.get_reader().read_c2pa(&mut Cursor::new(&bytes));

        // 1. Which files are errors. A parse error on the new side must be matched
        //    by some error on the old side.
        let s = match new {
            Ok(s) => s,
            Err(e) => {
                if old_read.is_ok() {
                    problems.push(format!("{name}: only asset-io refuses it ({e})"));
                }
                continue;
            }
        };
        checked += 1;

        // 2. Manifest and XMP.
        let new_store = entity(&s, &bytes, SegmentKind::Jumbf);
        match (&old_read, &new_store) {
            (Ok(a), Some(b)) if a == b => {}
            (Err(crate::Error::JumbfNotFound), None) => {}
            (a, b) => problems.push(format!(
                "{name}: manifest differs (old {:?}, new {:?})",
                a.as_ref().map(Vec::len),
                b.as_ref().map(Vec::len)
            )),
        }
        let old_xmp = io.get_reader().read_xmp(&mut Cursor::new(&bytes));
        let new_xmp =
            entity(&s, &bytes, SegmentKind::Xmp).map(|b| String::from_utf8_lossy(&b).to_string());
        if old_xmp != new_xmp {
            problems.push(format!("{name}: xmp differs"));
        }

        // 3. Writing a manifest.
        let store = vec![0x5au8; 1001];
        match (
            old_write(&io, &bytes, &store),
            new_write(&bytes, &Updates::new().set_jumbf(store.clone())),
        ) {
            (Ok(a), Ok(b)) if a == b => {}
            (Ok(a), Ok(b)) => problems.push(format!(
                "{name}: write_c2pa differs (old {} bytes, new {})",
                a.len(),
                b.len()
            )),
            (Err(_), Err(_)) => {}
            // The old handler recurses into LIST chunks and gives up past 32 levels;
            // asset-io copies them opaquely and has no depth to exceed.
            (Err(_), Ok(_)) if name.contains("bomb") => {}
            (a, b) => problems.push(format!(
                "{name}: write_c2pa result differs (old ok {}, new ok {})",
                a.is_ok(),
                b.is_ok()
            )),
        }

        // 4. Object locations. The old handler writes a dummy manifest to find
        //    where one would go; do the same on the new side.
        if let Ok(old) = io.get_object_locations(&mut Cursor::new(&bytes)) {
            let old: Vec<_> = old
                .iter()
                .map(
                    |ObjectLocations {
                         offset,
                         length,
                         htype,
                     }| (*offset, *length, *htype),
                )
                .collect();
            let probe = if new_store.is_some() {
                Some(bytes.clone())
            } else {
                new_write(&bytes, &Updates::new().set_jumbf(vec![1, 2, 3, 4])).ok()
            };
            match probe {
                Some(p) => {
                    let ps = riff::parse(&mut Cursor::new(&p)).unwrap();
                    let new = locations(&ps, p.len() as u64);
                    if new.as_ref() != Some(&old) {
                        problems.push(format!(
                            "{name}: object locations differ: old {old:?}, new {new:?}"
                        ));
                    }
                }
                None => problems.push(format!("{name}: asset-io cannot place a manifest")),
            }
        }

        // 5. Writing XMP (even length, so the old space padding does not apply).
        let mut xmp = String::from("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>");
        if xmp.len() % 2 == 1 {
            xmp.push(' ');
        }
        let xmp = xmp.as_str();
        let mut old_out = Cursor::new(Vec::new());
        let old_x = io.write_xmp(&mut Cursor::new(&bytes), &mut old_out, xmp);
        let new_x = new_write(&bytes, &Updates::new().set_xmp(xmp.as_bytes().to_vec()));
        match (old_x, new_x) {
            (Ok(()), Ok(b)) => {
                let a = old_out.into_inner();
                if old_xmp.is_none() && a != b {
                    problems.push(format!(
                        "{name}: write_xmp differs (old {} bytes, new {})",
                        a.len(),
                        b.len()
                    ));
                }
                // Either way, the old reader finds the XMP in what the new side wrote.
                let read = io.get_reader().read_xmp(&mut Cursor::new(&b));
                if read.as_deref() != Some(xmp) {
                    problems.push(format!("{name}: old reader cannot read new XMP: {read:?}"));
                }
            }
            (Err(_), Err(_)) => {}
            (Err(_), Ok(_)) if name.contains("bomb") => {}
            (a, b) => problems.push(format!(
                "{name}: write_xmp result differs (old ok {}, new ok {})",
                a.is_ok(),
                b.is_ok()
            )),
        }
    }
    assert!(checked > 0, "no RIFF fixtures parsed");
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}
