// EXPERIMENT (local only, do not commit).
//
// Differential test: asset-io's BMFF layout against the existing c2pa-rs BMFF
// handler on every BMFF fixture.
//
//   1. `walk` paths/offsets/sizes equal the BMFFArena path map;
//   2. manifest/original/update/merkle/XMP boxes found by asset-io equal what
//      `read_bmff_c2pa_boxes` reports;
//   3. both sides agree on which files are errors.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{collections::BTreeMap, fs, io::Cursor, path::PathBuf};

use asset_io::{containers::bmff, ItemKind, NullSink, Structure, Updates};

use crate::{
    asset_handlers::bmff_io::{read_bmff_c2pa_boxes, BMFFArena, BmffIO},
    asset_io::{AssetIO, C2paWriter},
};

fn fixtures() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(str::to_ascii_lowercase)
                    .as_deref(),
                Some("mp4" | "m4a" | "m4v" | "mov" | "heic" | "heif" | "avif")
            )
        })
        .collect();
    v.sort();
    v
}

type PathMap = BTreeMap<String, Vec<(u64, u64)>>;

fn new_tree(bytes: &[u8]) -> asset_io::Result<(Structure, PathMap)> {
    let s = bmff::parse(&mut Cursor::new(bytes))?;
    let mut m = PathMap::new();
    s.walk(&mut Cursor::new(bytes), |n| {
        m.entry(n.path.to_string())
            .or_default()
            .push((n.range.offset(), n.range.len()));
        Ok(())
    })?;
    Ok((s, m))
}

fn old_tree(bytes: &[u8]) -> crate::Result<PathMap> {
    let (arena, map) = BMFFArena::from_stream(&mut Cursor::new(bytes))?;
    let mut out = PathMap::new();
    for (path, tokens) in map {
        let v = tokens
            .iter()
            .map(|t| {
                let n = arena.get(*t).expect("token in arena");
                (n.data.offset, n.data.size)
            })
            .collect();
        out.insert(path, v);
    }
    Ok(out)
}

fn first_diff(a: &PathMap, b: &PathMap) -> Option<String> {
    for (k, va) in a {
        match b.get(k) {
            None => return Some(format!("{k} only in c2pa-rs: {va:?}")),
            Some(vb) if vb != va => {
                return Some(format!("{k}: c2pa-rs {va:?} vs asset-io {vb:?}"));
            }
            _ => {}
        }
    }
    b.keys()
        .find(|k| !a.contains_key(*k))
        .map(|k| format!("{k} only in asset-io: {:?}", b[k]))
}

#[test]
fn bmff_tree_matches_existing_handler() {
    let mut failures = Vec::new();
    let (mut both_ok, mut both_err) = (0, 0);
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        match (old_tree(&bytes), new_tree(&bytes)) {
            (Ok(old), Ok((_, new))) => {
                both_ok += 1;
                if let Some(d) = first_diff(&old, &new) {
                    failures.push(format!("{name}: {d}"));
                }
            }
            (Err(a), Err(b)) => {
                both_err += 1;
                println!("{name}: both reject (c2pa-rs: {a}; asset-io: {b})");
            }
            (Ok(_), Err(b)) => failures.push(format!("{name}: only asset-io rejects: {b}")),
            (Err(a), Ok(_)) => failures.push(format!("{name}: only c2pa-rs rejects: {a}")),
        }
    }
    println!("tree: {both_ok} agree, {both_err} rejected by both");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(both_ok > 0, "no fixture exercised");
}

// ---------------------------------------------------------------------------
// Hash equivalence.
//
// BmffHash exclusions are C2PA semantics (xpath, length, version, flags, data,
// subset), so they live here, not in asset-io. They are resolved over
// `Structure::walk`, and must give the ranges the existing xpath resolver gives.
// Separately, the default exclusions are derived from labelled entities and
// segment names alone and must reproduce stored hashes.
// ---------------------------------------------------------------------------

use std::collections::HashSet;

use asset_io::Name;
use serde_bytes::ByteBuf;

use crate::{
    assertion::AssertionBase,
    assertions::{BmffHash, DataMap, ExclusionsMap, SubsetMap},
    asset_handlers::bmff_io::bmff_to_jumbf_exclusions,
    hash_utils::{hash_stream_by_alg, HashRange},
    status_tracker::StatusTracker,
    store::Store,
    Context,
};

#[derive(Debug)]
struct N {
    path: String,
    offset: u64,
    size: u64,
    version: Option<u8>,
    flags: Option<u32>,
    depth: u32,
}

fn nodes(s: &Structure, bytes: &[u8]) -> asset_io::Result<Vec<N>> {
    let mut v = Vec::new();
    s.walk(&mut Cursor::new(bytes), |n| {
        v.push(N {
            path: n.path.to_string(),
            offset: n.range.offset(),
            size: n.range.len(),
            version: n.version,
            flags: n.flags,
            depth: n.depth,
        });
        Ok(())
    })?;
    Ok(v)
}

/// The semantics of `bmff_to_jumbf_exclusions`, over walked nodes.
fn exclusions_from_walk(
    nodes: &[N],
    bytes: &[u8],
    excl: &[ExclusionsMap],
    v2: bool,
) -> Result<Vec<HashRange>, String> {
    let mut tl: Vec<u64> = nodes
        .iter()
        .filter(|n| n.depth == 1)
        .map(|n| n.offset)
        .collect();
    tl.sort();
    let mut out = Vec::new();
    for ex in excl {
        let parts: Vec<&str> = ex.xpath.trim_start_matches('/').split('/').collect();
        if parts.iter().any(|p| p.len() < 4) {
            continue; // malformed xpath: skipped
        }
        if ex.xpath.contains('[') {
            return Err(format!(
                "indexed xpath not supported by this test: {}",
                ex.xpath
            ));
        }
        let want = format!("/{}", parts.join("/"));
        for n in nodes.iter().filter(|n| n.path == want) {
            if let Some(l) = ex.length {
                if l != n.size {
                    continue;
                }
            }
            if let (Some(v), Some(bv)) = (ex.version, n.version) {
                if v != bv {
                    continue;
                }
            }
            if let Some(fl) = &ex.flags {
                let mut t = [0u8; 4];
                if fl.len() >= 3 {
                    t[..3].copy_from_slice(&fl[..3]);
                }
                let desired = u32::from_be_bytes(t);
                if let Some(bf) = n.flags {
                    if ex.exact.unwrap_or(true) {
                        if desired != bf {
                            continue;
                        }
                    } else if (desired | bf) != desired {
                        continue;
                    }
                }
            }
            if let Some(dm) = &ex.data {
                let mut ok = true;
                for d in dm {
                    let at = (n.offset + d.offset) as usize;
                    match bytes.get(at..at + d.value.len()) {
                        Some(b) if b == &d.value[..] => {}
                        Some(_) => {
                            ok = false;
                            break;
                        }
                        None => return Err("data match past end of file".into()),
                    }
                }
                if !ok {
                    continue;
                }
            }
            if let Some(sub) = &ex.subset {
                for s in sub {
                    if s.offset > n.size {
                        continue;
                    }
                    let len = if s.length == 0 {
                        n.size - s.offset
                    } else {
                        s.length.min(n.size - s.offset)
                    };
                    out.push(HashRange::new(n.offset + s.offset, len));
                }
            } else {
                out.push(HashRange::new(n.offset, n.size));
                if let Some(pos) = tl.iter().position(|x| *x == n.offset) {
                    tl.remove(pos);
                }
            }
        }
    }
    if v2 {
        for start in tl {
            let mut r = HashRange::new(start, 1);
            r.set_bmff_offset(start);
            out.push(r);
        }
    }
    Ok(out)
}

/// Default BmffHash exclusions from entities and segment names only: every C2PA
/// box (manifest, original, update, merkle), `ftyp` and `mfra`. For version 2
/// hashes every other top-level box contributes its offset.
///
/// `free_skip` is the builder setting `bmff_hash_exclude_free_and_skip_boxes`.
fn exclusions_from_entities(s: &Structure, v2: bool, free_skip: bool) -> Vec<HashRange> {
    let mut whole: Vec<(u64, u64)> = Vec::new();
    for seg in s.segments() {
        let n = seg.name();
        let named = |t: &[u8; 4]| n == Name::FourCC(*t);
        if named(b"ftyp") || named(b"mfra") || (free_skip && (named(b"free") || named(b"skip"))) {
            whole.push((seg.range().offset(), seg.range().len()));
        }
    }
    for (kind, label) in [
        (ItemKind::Jumbf, "manifest"),
        (ItemKind::Jumbf, "original"),
        (ItemKind::Jumbf, "update"),
        (ItemKind::Other, "merkle"),
    ] {
        for e in s.items_labelled(kind, label) {
            for p in e.extents() {
                let ext = s.segment(p.segment()).unwrap().range();
                whole.push((ext.offset(), ext.len()));
            }
        }
    }
    whole.sort();
    let skipped: HashSet<u64> = whole.iter().map(|w| w.0).collect();
    let mut v: Vec<HashRange> = whole.iter().map(|(o, l)| HashRange::new(*o, *l)).collect();
    if v2 {
        for seg in s.segments() {
            let start = seg.range().offset();
            if !seg.name().is_none() && !skipped.contains(&start) {
                let mut r = HashRange::new(start, 1);
                r.set_bmff_offset(start);
                v.push(r);
            }
        }
    }
    v
}

fn normalized(mut v: Vec<HashRange>) -> Vec<(u64, u64, Option<u64>)> {
    let mut t: Vec<_> = v
        .drain(..)
        .map(|r| (r.start(), r.length(), r.bmff_offset()))
        .collect();
    t.sort();
    t
}

fn mime_for(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "m4a" => "audio/mp4",
        "m4v" => "video/x-m4v",
        "mov" => "video/quicktime",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "avif" => "image/avif",
        _ => "video/mp4",
    }
}

fn extra_exclusions() -> Vec<ExclusionsMap> {
    let mut v = Vec::new();
    let mut stco = ExclusionsMap::new("/moov/trak/mdia/minf/stbl/stco".into());
    stco.subset = Some(vec![SubsetMap {
        offset: 16,
        length: 0,
    }]);
    v.push(stco);
    v.push(ExclusionsMap::new("/meta/iloc".into()));
    v.push(ExclusionsMap::new("/mfra/tfra".into()));
    let mut tfhd = ExclusionsMap::new("/moof/traf/tfhd".into());
    tfhd.subset = Some(vec![SubsetMap {
        offset: 16,
        length: 8,
    }]);
    tfhd.flags = Some(ByteBuf::from([1, 0, 0]));
    v.push(tfhd);
    v.push(ExclusionsMap::new("/free".into()));
    v.push(ExclusionsMap::new("/skip".into()));
    v.push(ExclusionsMap::new("/xxx".into())); // matches nothing
    v.push(ExclusionsMap::new("/ab".into())); // malformed: skipped
    let mut len = ExclusionsMap::new("/mdat".into());
    len.length = Some(1); // matches nothing
    v.push(len);
    let mut ver = ExclusionsMap::new("/moov/mvhd".into());
    ver.version = Some(0);
    v.push(ver);
    let mut dm = ExclusionsMap::new("/ftyp".into());
    dm.data = Some(vec![DataMap {
        offset: 4,
        value: b"ftyp".to_vec(),
    }]);
    v.push(dm);
    v
}

#[test]
fn xpath_exclusions_over_walk_match_existing_resolver() {
    let mut defaults = BmffHash::new("a", "sha256", None);
    defaults.set_default_exclusions();
    let default_list = defaults.exclusions().to_vec();
    let mut extended = default_list.clone();
    extended.extend(extra_exclusions());

    let mut failures = Vec::new();
    let mut compared = 0;
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        let tree = bmff::parse(&mut Cursor::new(&bytes)).and_then(|s| nodes(&s, &bytes));
        for (label, list) in [("default", &default_list), ("extended", &extended)] {
            for v2 in [false, true] {
                let old = bmff_to_jumbf_exclusions(&mut Cursor::new(&bytes), list, v2);
                let new = match &tree {
                    Ok(n) => exclusions_from_walk(n, &bytes, list, v2),
                    Err(e) => Err(e.to_string()),
                };
                match (old, new) {
                    (Ok(o), Ok(n)) => {
                        compared += 1;
                        if normalized(o) != normalized(n) {
                            failures.push(format!("{name} [{label}, v2={v2}]: ranges differ"));
                        }
                    }
                    (Err(_), Err(_)) => {}
                    (Ok(_), Err(e)) => failures.push(format!(
                        "{name} [{label}, v2={v2}]: only asset-io fails: {e}"
                    )),
                    (Err(e), Ok(_)) => failures.push(format!(
                        "{name} [{label}, v2={v2}]: only c2pa-rs fails: {e}"
                    )),
                }
            }
        }
    }
    println!("exclusion lists compared: {compared}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(compared > 0);
}

#[test]
fn bmff_default_exclusions_from_entities_reproduce_stored_hashes() {
    let context = Context::new();
    let mut defaults = BmffHash::new("a", "sha256", None);
    defaults.set_default_exclusions();
    let default_list = defaults.exclusions().to_vec();

    let mut failures = Vec::new();
    let (mut checked, mut with_defaults) = (0, 0);
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        let Ok(store) = Store::from_stream(
            mime_for(&path),
            Cursor::new(bytes.clone()),
            &mut StatusTracker::default(),
            &context,
        ) else {
            println!("{name}: SKIP no readable store");
            continue;
        };
        let Some(claim) = store.provenance_claim() else {
            continue;
        };
        let Some(a) = claim
            .hash_assertions()
            .into_iter()
            .find(|a| a.label_raw().starts_with(BmffHash::LABEL))
        else {
            println!("{name}: SKIP no c2pa.hash.bmff");
            continue;
        };
        let bh = BmffHash::from_assertion(a.assertion()).unwrap();
        let Some(stored) = bh.hash().cloned() else {
            println!("{name}: SKIP merkle-only BmffHash");
            continue;
        };
        let alg = bh.alg().cloned().unwrap_or_else(|| "sha256".into());
        let v2 = bh.bmff_version() > 1;

        let old = bmff_to_jumbf_exclusions(&mut Cursor::new(&bytes), bh.exclusions(), v2).unwrap();
        let control = hash_stream_by_alg(&alg, &mut Cursor::new(&bytes), Some(old), true).unwrap();
        if control != stored {
            println!("{name}: stored hash does not match file under c2pa-rs; not counted");
            continue;
        }
        checked += 1;

        let s = bmff::parse(&mut Cursor::new(&bytes)).unwrap();
        let n = nodes(&s, &bytes).unwrap();
        let walked = exclusions_from_walk(&n, &bytes, bh.exclusions(), v2).unwrap();
        let h = hash_stream_by_alg(&alg, &mut Cursor::new(&bytes), Some(walked), true).unwrap();
        if h != stored {
            failures.push(format!(
                "{name}: walk-resolved exclusions do not reproduce the stored hash"
            ));
        }

        let uses_defaults = bh.exclusions() == &default_list[..];
        if uses_defaults {
            with_defaults += 1;
            let free_skip = default_list.iter().any(|e| e.xpath == "/free");
            let derived = exclusions_from_entities(&s, v2, free_skip);
            let h =
                hash_stream_by_alg(&alg, &mut Cursor::new(&bytes), Some(derived), true).unwrap();
            if h != stored {
                failures.push(format!(
                    "{name}: entity-derived exclusions do not reproduce the stored hash"
                ));
            }
        }
        println!(
            "{name}: v{} {} exclusions, default list: {uses_defaults}",
            bh.bmff_version(),
            bh.exclusions().len()
        );
    }
    println!("checked {checked}, of which {with_defaults} use the default exclusion list");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(checked > 0, "no signed BMFF fixture exercised");
}

#[test]
fn entity_exclusions_equal_default_xpath_exclusions() {
    let mut defaults = BmffHash::new("a", "sha256", None);
    defaults.set_default_exclusions();
    let list = defaults.exclusions().to_vec();
    let free_skip = list.iter().any(|e| e.xpath == "/free");
    println!(
        "default list: {:?} (free/skip: {free_skip})",
        list.iter().map(|e| &e.xpath).collect::<Vec<_>>()
    );
    let mut failures = Vec::new();
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        let Ok(s) = bmff::parse(&mut Cursor::new(&bytes)) else {
            continue;
        };
        for v2 in [false, true] {
            let Ok(old) = bmff_to_jumbf_exclusions(&mut Cursor::new(&bytes), &list, v2) else {
                continue;
            };
            if normalized(old) != normalized(exclusions_from_entities(&s, v2, free_skip)) {
                failures.push(format!(
                    "{name} v2={v2}: entity-derived ranges differ from xpath ranges"
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Sign a clean BMFF file with the manifest placed by asset-io and the hash
/// derived from asset-io's entities, then have c2pa-rs validate it:
///   placeholder -> asset-io Set -> entity-derived exclusions -> hash -> sign ->
///   asset-io patch -> Reader validates.
/// Also checks the hash equals the one c2pa-rs's own resolver computes, and that
/// asset-io's boxes equal c2pa-rs's composed manifest.
#[test]
fn bmff_sign_flow_through_asset_io_validates() {
    use crate::{utils::test::test_context, Builder, Reader, ValidationState};

    let mut done = 0;
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let src = fs::read(&path).unwrap();
        let mime = mime_for(&path);
        let Ok(s) = bmff::parse(&mut Cursor::new(&src)) else {
            continue;
        };
        if s.items_of(ItemKind::Jumbf).next().is_some() || nodes(&s, &src).is_err() {
            continue; // only clean, walkable assets
        }

        let mut builder = Builder::from_context(test_context())
            .with_definition(
                serde_json::json!({
                    "claim_generator_info": [{"name": "asset_io_flow", "version": "1.0.0"}],
                    "title": "asset-io bmff flow",
                    "assertions": [{
                        "label": "c2pa.actions",
                        "data": {"actions": [{
                            "action": "c2pa.created",
                            "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"
                        }]}
                    }]
                })
                .to_string()
                .as_str(),
            )
            .unwrap();
        let (composed_ph, raw_ph) = match builder.exp_placeholder(mime) {
            Ok(x) => x,
            Err(e) => {
                println!("{name}: SKIP placeholder: {e}");
                continue;
            }
        };

        let out = new_write(&src, &Updates::new().set_jumbf(raw_ph.clone())).unwrap();
        let dest = bmff::parse(&mut Cursor::new(&out)).unwrap();
        let item = dest
            .items_labelled(ItemKind::Jumbf, "manifest")
            .next()
            .unwrap();
        let ext = dest
            .segment(item.extents().next().unwrap().segment())
            .unwrap()
            .range();
        let at = ext.offset() as usize..ext.end() as usize;
        // `composed_ph` is from an earlier call whose JUMBF can differ in content
        // (generated ids); compare against the composition of the raw bytes we wrote.
        assert_eq!(
            composed_ph.len(),
            out[at.clone()].len(),
            "{name}: placeholder size differs"
        );
        let composed_raw = builder.exp_compose(&raw_ph, mime).unwrap();
        assert_eq!(
            &out[at.clone()],
            &composed_raw[..],
            "{name}: placeholder box differs"
        );

        // Hash from entities, against c2pa-rs's own resolver on the same bytes.
        let (alg, version, excl, c2pa_hash) =
            builder.exp_bmff_info(&mut Cursor::new(&out)).unwrap();
        let free_skip = excl.iter().any(|e| e.xpath == "/free");
        let derived = exclusions_from_entities(&dest, version > 1, free_skip);
        let mine = hash_stream_by_alg(&alg, &mut Cursor::new(&out), Some(derived), true).unwrap();
        assert_eq!(
            mine, c2pa_hash,
            "{name}: entity-derived hash != c2pa-rs hash (v{version})"
        );
        builder.exp_set_bmff_hash(mine).unwrap();

        let signed_raw = builder.exp_sign_raw().unwrap();
        assert_eq!(
            signed_raw.len(),
            raw_ph.len(),
            "{name}: signed != reserved size"
        );

        let mut cur = Cursor::new(out);
        dest.patch_exact(&mut cur, item, &signed_raw).unwrap();
        let out = cur.into_inner();
        assert_eq!(out.len() as u64, dest.total_size());
        let composed_signed = builder.exp_compose(&signed_raw, mime).unwrap();
        assert_eq!(
            &out[at],
            &composed_signed[..],
            "{name}: signed box differs from c2pa-rs"
        );

        let reader = Reader::from_context(test_context())
            .with_stream(mime, Cursor::new(out.clone()))
            .unwrap_or_else(|e| panic!("{name}: reader failed: {e}"));
        let state = reader.validation_state();
        println!(
            "{name}: signed via asset-io (v{version}), state {state:?}, status {:?}",
            reader.validation_status().map(|v| v.len())
        );
        assert_ne!(
            state,
            ValidationState::Invalid,
            "{name}: {:?}",
            reader.validation_status()
        );
        done += 1;
    }
    assert!(done > 0, "no clean BMFF fixture exercised");
}

fn new_write(bytes: &[u8], u: &Updates) -> asset_io::Result<Vec<u8>> {
    let s = bmff::parse(&mut Cursor::new(bytes))?;
    let mut out = Cursor::new(Vec::new());
    s.handler()
        .write(&s, &mut Cursor::new(bytes), &mut out, u, &mut NullSink)?;
    Ok(out.into_inner())
}

fn first_byte_diff(a: &[u8], b: &[u8]) -> String {
    match (0..a.len().min(b.len())).find(|&i| a[i] != b[i]) {
        Some(i) => format!(
            "first difference at {i} (lengths {} vs {})",
            a.len(),
            b.len()
        ),
        None => format!(
            "one is a prefix of the other (lengths {} vs {})",
            a.len(),
            b.len()
        ),
    }
}

// Writing a manifest with asset-io must produce the bytes c2pa-rs produces, on
// every fixture c2pa-rs can write.
#[test]
fn bmff_set_manifest_matches_existing_writer() {
    // Not a valid store: c2pa-rs treats it as an ordinary manifest.
    let store: Vec<u8> = (0..137u32).map(|i| (i * 7 + 3) as u8).collect();
    let mut failures = Vec::new();
    let (mut same, mut skipped) = (0, 0);
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        let ext = path.extension().unwrap().to_string_lossy().into_owned();

        let mut old_out = Cursor::new(Vec::new());
        let old = BmffIO::new(&ext).write_c2pa(&mut Cursor::new(&bytes), &mut old_out, &store);
        let new = new_write(&bytes, &Updates::new().set_jumbf(store.clone()));
        match (old, new) {
            (Ok(()), Ok(n)) => {
                let o = old_out.into_inner();
                if o == n {
                    same += 1;
                } else {
                    failures.push(format!("{name}: {}", first_byte_diff(&o, &n)));
                }
                if bmff::parse(&mut Cursor::new(&n)).is_err() {
                    failures.push(format!("{name}: asset-io output does not parse"));
                }
            }
            (Err(a), Err(b)) => {
                skipped += 1;
                println!("{name}: both refuse (c2pa-rs: {a}; asset-io: {b})");
            }
            (Ok(()), Err(b)) => failures.push(format!("{name}: only asset-io refuses: {b}")),
            (Err(a), Ok(n)) => {
                // c2pa-rs cannot adjust some fragmented files (a tfra entry with no
                // matching moof). asset-io must still produce a file that undoes
                // cleanly: removing the manifest restores the input exactly.
                // (Not remove: the input may carry a manifest of its own.)
                let other: Vec<u8> = (0..61u32).map(|i| (i * 5 + 1) as u8).collect();
                let u = Updates::new().set_jumbf(other);
                let direct = new_write(&bytes, &u);
                let via = new_write(&n, &u);
                if direct.is_ok() && direct.as_ref().ok() == via.as_ref().ok() {
                    println!("{name}: c2pa-rs refuses ({a}); asset-io round trips");
                } else {
                    failures.push(format!(
                        "{name}: c2pa-rs refuses ({a}); asset-io does not round trip"
                    ));
                }
            }
        }
    }
    println!("set manifest: {same} identical, {skipped} refused by both");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(same > 0);
}

fn payload(s: &Structure, bytes: &[u8], kind: ItemKind, label: &str) -> Option<Vec<u8>> {
    s.items_labelled(kind, label)
        .next()
        .map(|e| s.read_item(&mut Cursor::new(bytes), e).unwrap())
}

fn extent_of(s: &Structure, kind: ItemKind, label: &str) -> Option<(u64, u64)> {
    s.items_labelled(kind, label).next().map(|e| {
        let seg = s.segment(e.extents().next().unwrap().segment()).unwrap();
        (seg.range().offset(), seg.range().len())
    })
}

#[test]
fn bmff_c2pa_boxes_match_existing_handler() {
    let mut failures = Vec::new();
    let (mut checked, mut with_c2pa) = (0, 0);
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        let old = read_bmff_c2pa_boxes(&mut Cursor::new(&bytes));
        let new = bmff::parse(&mut Cursor::new(&bytes));
        let (o, s) = match (old, new) {
            (Ok(o), Ok(s)) => (o, s),
            (Err(_), Err(_)) => continue,
            (Ok(_), Err(b)) => {
                failures.push(format!("{name}: only asset-io rejects: {b}"));
                continue;
            }
            (Err(a), Ok(s)) => {
                // asset-io parses top-level boxes only; depth limits apply when
                // the tree is walked, so the walk must reject what c2pa-rs rejects.
                if s.walk(&mut Cursor::new(&bytes), |_| Ok(())).is_ok() {
                    failures.push(format!("{name}: only c2pa-rs rejects: {a}"));
                }
                continue;
            }
        };
        checked += 1;
        let j = ItemKind::Jumbf;
        let mut check = |what: &str, ok: bool| {
            if !ok {
                failures.push(format!("{name}: {what} differs"));
            }
        };
        check(
            "manifest bytes",
            payload(&s, &bytes, j, "manifest") == o.manifest_bytes,
        );
        check(
            "original bytes",
            payload(&s, &bytes, j, "original") == o.original_bytes,
        );
        check(
            "update bytes",
            payload(&s, &bytes, j, "update") == o.update_bytes,
        );
        check(
            "manifest box offset",
            extent_of(&s, j, "manifest").map(|e| e.0) == o.manifest_box_offset,
        );
        check(
            "update box offset",
            extent_of(&s, j, "update").map(|e| e.0) == o.update_box_offset,
        );

        let new_merkle: Vec<(u64, u64)> = s
            .items_labelled(ItemKind::Other, "merkle")
            .map(|e| {
                let seg = s.segment(e.extents().next().unwrap().segment()).unwrap();
                (seg.range().offset(), seg.range().len())
            })
            .collect();
        let old_merkle: Vec<(u64, u64)> = o
            .bmff_merkle_box_infos
            .iter()
            .map(|b| (b.offset, b.size))
            .collect();
        check("merkle boxes", new_merkle == old_merkle);

        // The XMP `uuid` box only: a HEIF `mime` XMP item (one with an item id) is
        // also an XMP item, but c2pa-rs's BMFF handler does not report it.
        let xmp_boxes: Vec<_> = s
            .items_of(ItemKind::Xmp)
            .filter(|e| e.native_id().is_none())
            .collect();
        assert!(xmp_boxes.len() <= 1, "{name}: several XMP boxes");
        let new_xmp = xmp_boxes
            .first()
            .map(|e| {
                let seg = s.segment(e.extents().next().unwrap().segment()).unwrap();
                (seg.range().offset(), seg.range().len())
            })
            .unwrap_or((0, 0));
        check("xmp box", new_xmp == (o.xmp_box_offset, o.xmp_box_size));

        let any_c2pa = s.items_of(ItemKind::Jumbf).next().is_some() || !new_merkle.is_empty();
        check("c2pa presence", any_c2pa == o.c2pa_box_present);
        if any_c2pa {
            with_c2pa += 1;
        }
    }
    println!("c2pa boxes: {checked} compared, {with_c2pa} with C2PA boxes");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(with_c2pa > 0, "no fixture carried C2PA boxes");
}
