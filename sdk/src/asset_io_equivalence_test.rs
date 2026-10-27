// EXPERIMENT (local only, do not commit).
//
// Can exclusions derived from asset-io's container-agnostic `Structure`
// reproduce the DataHash stored in real signed files?
//
// For every JPEG/PNG fixture whose active claim has a c2pa.hash.data assertion:
//   1. read the stored DataHash (alg, hash, exclusions) straight off the claim;
//   2. parse the same bytes with asset_io;
//   3. derive exclusions from the manifest item's segments under two policies
//      (whole segment extent / payload+trailer only);
//   4. hash with each and compare to the stored hash.
//
// The hash comparison is the pass criterion; exclusion-list equality is reported.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{fs, io::Cursor, path::PathBuf};

use asset_io::{containers, ByteRange, ItemKind, SegmentId, Structure, TransferEncoding};

use crate::{
    assertions::DataHash,
    hash_utils::{hash_stream_by_alg, HashRange},
    status_tracker::StatusTracker,
    store::Store,
    Context,
};

fn fixtures() -> Vec<(PathBuf, &'static str, bool)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut v = Vec::new();
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        match p
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("jpg" | "jpeg") => v.push((p, "image/jpeg", true)),
            Some("png") => v.push((p, "image/png", false)),
            _ => {}
        }
    }
    v.sort();
    v
}

/// Sort and merge touching ranges.
fn merge(mut v: Vec<ByteRange>) -> Vec<(u64, u64)> {
    v.sort_by_key(|r| r.offset());
    let mut out: Vec<(u64, u64)> = Vec::new();
    for r in v {
        match out.last_mut() {
            Some((s, l)) if *s + *l == r.offset() => *l += r.len(),
            _ => out.push((r.offset(), r.len())),
        }
    }
    out
}

fn manifest_ranges(s: &Structure, whole_extent: bool) -> Vec<(u64, u64)> {
    let mut v = Vec::new();
    for e in s.items_of(ItemKind::Jumbf) {
        for p in e.extents() {
            let seg = s.segment(p.segment()).unwrap();
            if whole_extent {
                v.push(seg.range());
            } else {
                v.push(seg.payload());
                if !seg.trailer().is_empty() {
                    v.push(seg.trailer());
                }
            }
        }
    }
    merge(v)
}

fn hash_with(alg: &str, bytes: &[u8], ranges: &[(u64, u64)]) -> Vec<u8> {
    let hr: Vec<HashRange> = ranges.iter().map(|(s, l)| HashRange::new(*s, *l)).collect();
    hash_stream_by_alg(alg, &mut Cursor::new(bytes), Some(hr), true).unwrap()
}

// ---------------------------------------------------------------------------
// Box hash: an AssetBoxHash built only from asset-io's Structure::elements().
// ---------------------------------------------------------------------------

use std::collections::HashSet;

use crate::{
    assertions::BoxHash,
    asset_io::{AllowedExclusion, AssetBoxHash, BoxMap, C2PA_BOXHASH},
    read_seek::ReadSeek,
    Error, Result,
};

/// JUMBF superbox type UUID of the C2PA Manifest Store ("c2pa"), spec 11.1.4.2.
const C2PA_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// Whether segment `id` holds XMP or EXIF stored as is (no transfer encoding).
fn holds_plain_metadata(s: &Structure, id: SegmentId) -> bool {
    s.items_in(id).any(|i| {
        matches!(i.kind(), ItemKind::Xmp | ItemKind::Exif)
            && *i.transfer() == TransferEncoding::Identity
    })
}

/// Box map from the layout model alone. The only format knowledge here is the
/// name table; the traversal is the same for every container.
fn box_map_from_layout(s: &Structure, mut src: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
    let io = |e: asset_io::Error| Error::InvalidAsset(e.to_string());

    // Which segments belong to the C2PA Manifest Store (not just any JUMBF).
    let mut store: HashSet<asset_io::SegmentId> = HashSet::new();
    for e in s.items_of(ItemKind::Jumbf) {
        if s.jumbf_type(&mut src, e).map_err(io)? == Some(C2PA_STORE_UUID) {
            store.extend(e.extents().map(|p| p.segment()));
        }
    }

    let mut out: Vec<BoxMap> = Vec::new();
    let mut c2pa: Option<usize> = None;
    let mut last_owner: Option<asset_io::SegmentId> = None;
    s.elements(&mut src, |id, e| {
        let mut ext = e.range();

        // Compatibility with the existing c2pa-rs box maps (see PR #612): when a
        // segment is expanded into parts, the first part is reported with the
        // whole segment's extent and each later part with only its own header
        // (e.g. a JPEG scan, then the 2-byte RSTn markers inside it). The boxes
        // therefore overlap, as they do today. asset-io itself never overlaps.
        let owner = s.segment(id)?.range();
        if ext != owner {
            ext = if last_owner != Some(id) {
                owner
            } else {
                ByteRange::new(ext.offset(), e.header().len())?
            };
        }
        last_owner = Some(id);
        if store.contains(&id) {
            match c2pa {
                // The store is one box even when it spans several segments.
                Some(i) => out[i].range_len = ext.end() - out[i].range_start,
                None => {
                    out.push(
                        BoxMap::new(vec![C2PA_BOXHASH.to_string()], ext.offset(), ext.len())
                            .with_allowed_exclusions(vec![AllowedExclusion::whole_box(ext.len())]),
                    );
                    c2pa = Some(out.len() - 1);
                }
            }
            return Ok(());
        }
        // Unnamed elements (fill bytes, trailing data) are not boxes.
        let Some(name) = s.box_name(e.name()) else {
            return Ok(());
        };
        let mut bm = BoxMap::new(vec![name.into_owned()], ext.offset(), ext.len());
        if holds_plain_metadata(s, id) {
            // Metadata may be excluded after its header; the trailer (e.g. a PNG
            // CRC) changes with the data, so it is excludable too.
            bm = bm.with_allowed_exclusions(vec![AllowedExclusion::after_header(
                e.header().len(),
                ext.len(),
            )]);
        }
        out.push(bm);
        Ok(())
    })
    .map_err(io)?;
    Ok(out)
}

struct LayoutBoxHash {
    jpeg: bool,
}

impl AssetBoxHash for LayoutBoxHash {
    fn get_box_map(&self, mut input: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
        let io = |e: asset_io::Error| Error::InvalidAsset(e.to_string());
        let s = if self.jpeg {
            containers::jpeg::parse(&mut input)
        } else {
            containers::png::parse(&mut input)
        }
        .map_err(io)?;
        box_map_from_layout(&s, input)
    }
}

fn old_box_hash(mime: &str) -> Option<&dyn AssetBoxHash> {
    crate::jumbf_io::get_assetio_handler(mime)?.asset_box_hash_ref()
}

/// Names, start and length of every box, from the existing handlers and from
/// the layout model, must agree on every fixture.
#[test]
fn box_maps_agree_with_existing_handlers() {
    let (mut compared, mut skipped) = (0, 0);
    let mut problems = Vec::new();
    for (path, mime, jpeg) in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        let Some(old_h) = old_box_hash(mime) else {
            continue;
        };

        let Ok(old) = old_h.get_box_map(&mut Cursor::new(bytes.clone())) else {
            skipped += 1;
            continue;
        };
        let Ok(new) = LayoutBoxHash { jpeg }.get_box_map(&mut Cursor::new(bytes.clone())) else {
            problems.push(format!("{name}: layout box map failed (old succeeded)"));
            continue;
        };

        // The old handlers synthesize an empty, excluded placeholder when the file
        // has no manifest. That is a signing-path artefact, not a box of the file.
        let old: Vec<_> = old
            .into_iter()
            .filter(|b| !(b.names == [C2PA_BOXHASH] && b.range_len == 0))
            .collect();

        let key = |v: &[BoxMap]| -> Vec<(Vec<String>, u64, u64)> {
            v.iter()
                .map(|b| (b.names.clone(), b.range_start, b.range_len))
                .collect()
        };
        let (ko, kn) = (key(&old), key(&new));
        if ko != kn {
            let first = ko
                .iter()
                .zip(&kn)
                .position(|(a, b)| a != b)
                .unwrap_or(ko.len().min(kn.len()));
            problems.push(format!(
                "{name}: old {} boxes, layout {} boxes; first difference at #{first}: old {:?} vs layout {:?}",
                ko.len(),
                kn.len(),
                ko.get(first),
                kn.get(first)
            ));
            continue;
        }

        // Allowed exclusions are informational: layout is deliberately tighter for
        // XMP/Exif (the signature stays in the header).
        let ao: Vec<_> = old.iter().map(|b| b.allowed_exclusions.clone()).collect();
        let an: Vec<_> = new.iter().map(|b| b.allowed_exclusions.clone()).collect();
        if ao != an {
            let diffs = ao.iter().zip(&an).filter(|(a, b)| a != b).count();
            println!("{name}: {diffs} box(es) differ in allowed_exclusions (informational)");
        }
        compared += 1;
    }
    println!("compared {compared} files, skipped {skipped}");
    assert!(compared > 0);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Generate a box hash with one implementation and verify it with the other,
/// using c2pa-rs's own `BoxHash` code in both directions.
#[test]
fn box_hash_cross_generate_and_verify() {
    let mut checked = 0;
    let mut problems = Vec::new();
    for (path, mime, jpeg) in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        let Some(old_h) = old_box_hash(mime) else {
            continue;
        };
        let new_h = LayoutBoxHash { jpeg };

        // Only assets that already carry a manifest: the C2PA box then has real
        // bytes in both implementations.
        let Ok(s) = (if jpeg {
            containers::jpeg::parse(&mut Cursor::new(bytes.clone()))
        } else {
            containers::png::parse(&mut Cursor::new(bytes.clone()))
        }) else {
            continue;
        };
        if s.items_of(ItemKind::Jumbf).next().is_none()
            || old_h.get_box_map(&mut Cursor::new(bytes.clone())).is_err()
        {
            continue;
        }

        for (gen_name, gen, ver_name, ver) in [
            ("layout", &new_h as &dyn AssetBoxHash, "existing", old_h),
            ("existing", old_h, "layout", &new_h as &dyn AssetBoxHash),
        ] {
            let mut bh = BoxHash { boxes: Vec::new() };
            if let Err(e) = bh.generate_box_hash_from_stream(
                &mut Cursor::new(bytes.clone()),
                "sha256",
                gen,
                false,
            ) {
                problems.push(format!("{name}: generate with {gen_name}: {e}"));
                continue;
            }
            if let Err(e) =
                bh.verify_stream_hash(&mut Cursor::new(bytes.clone()), Some("sha256"), ver)
            {
                problems.push(format!(
                    "{name}: generated by {gen_name}, verified by {ver_name}: {e}"
                ));
            }
        }
        checked += 1;
    }
    println!("cross-checked {checked} files");
    assert!(checked > 0);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Full embeddable flow with asset-io owning the container:
///   placeholder (raw JUMBF) -> asset-io Set -> exclusions from Structure ->
///   hash -> sign (raw) -> asset-io patch -> Reader validates.
/// Also checks asset-io's composition (APP11 / caBX framing, CRC) is
/// byte-identical to c2pa-rs's `get_composed_manifest`.
#[test]
fn sign_flow_through_asset_io_validates() {
    use asset_io::Updates;

    use crate::{utils::test::test_context, Builder, Reader, ValidationState};

    let mut done = 0;
    for (path, mime, jpeg) in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let src = fs::read(&path).unwrap();
        let parse = |b: &[u8]| {
            let mut c = Cursor::new(b.to_vec());
            if jpeg {
                containers::jpeg::parse(&mut c)
            } else {
                containers::png::parse(&mut c)
            }
        };
        let Ok(s) = parse(&src) else { continue };
        if s.items_of(ItemKind::Jumbf).next().is_some() {
            continue; // only clean assets
        }

        let mut builder = Builder::from_context(test_context())
            .with_definition(
                serde_json::json!({
                    "claim_generator_info": [{"name": "asset_io_flow", "version": "1.0.0"}],
                    "title": "asset-io flow",
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
        let (composed_ph, raw_ph) = builder.exp_placeholder(mime).unwrap();

        // asset-io inserts the raw placeholder JUMBF.
        let write = |s: &Structure, src: &[u8], u: &Updates| {
            let mut out = Cursor::new(Vec::new());
            let dest = s
                .write(
                    &mut Cursor::new(src.to_vec()),
                    &mut out,
                    u,
                    &mut asset_io::NullSink,
                )
                .unwrap();
            (out.into_inner(), dest)
        };
        let (mut out, dest) = write(&s, &src, &Updates::new().set_jumbf(raw_ph.clone()));

        // Composition equivalence for the placeholder: asset-io's manifest
        // segments, concatenated, equal c2pa-rs's composed placeholder.
        let ranges = manifest_ranges(&dest, true);
        assert_eq!(
            ranges.len(),
            1,
            "{name}: manifest extents should be contiguous"
        );
        let (start, len) = ranges[0];
        assert_eq!(
            len as usize,
            composed_ph.len(),
            "{name}: composed size differs"
        );

        // Exclusions from the structure; hash; sign.
        builder
            .set_data_hash_exclusions(vec![HashRange::new(start, len)])
            .unwrap();
        builder
            .update_hash_from_stream(mime, &mut Cursor::new(out.clone()))
            .unwrap();
        let signed_raw = builder.exp_sign_raw().unwrap();
        assert_eq!(
            signed_raw.len(),
            raw_ph.len(),
            "{name}: signed != reserved size"
        );

        // Patch in place.
        let item = dest.require_item(ItemKind::Jumbf).unwrap().clone();
        let mut cur = Cursor::new(std::mem::take(&mut out));
        dest.patch_exact(&mut cur, &item, &signed_raw).unwrap();
        let out = cur.into_inner();
        assert_eq!(out.len() as u64, dest.total_size());

        // asset-io's framing == c2pa-rs's framing of the same signed JUMBF.
        let composed_signed = builder.exp_compose(&signed_raw, mime).unwrap();
        assert!(
            out[start as usize..(start + len) as usize] == composed_signed[..],
            "{name}: asset-io composition differs from get_composed_manifest"
        );

        // Everything outside the manifest is the original asset's bytes.
        let reparsed = parse(&out).unwrap();
        let ex = manifest_ranges(&reparsed, true);
        assert_eq!(ex, ranges, "{name}: reparsed layout differs");

        // c2pa-rs validates the result.
        let reader = Reader::from_context(test_context())
            .with_stream(mime, Cursor::new(out.clone()))
            .unwrap_or_else(|e| panic!("{name}: reader failed: {e}"));
        let state = reader.validation_state();
        println!(
            "{name}: signed via asset-io, manifest {len} bytes at {start}, state {state:?}, status {:?}",
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
    assert!(done > 0, "no clean fixtures exercised");
}

#[test]
fn derived_exclusions_reproduce_stored_data_hash() {
    let context = Context::new();
    let (mut checked, mut skipped) = (0, 0);
    let mut failures = Vec::new();

    for (path, mime, jpeg) in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();

        let store = match Store::from_stream(
            mime,
            Cursor::new(bytes.clone()),
            &mut StatusTracker::default(),
            &context,
        ) {
            Ok(s) => s,
            Err(e) => {
                println!("{name}: SKIP store: {e}");
                skipped += 1;
                continue;
            }
        };
        let Some(claim) = store.provenance_claim() else {
            println!("{name}: SKIP no provenance claim");
            skipped += 1;
            continue;
        };
        let Some(dh_assertion) = claim
            .hash_assertions()
            .into_iter()
            .find(|a| a.label_raw().starts_with(DataHash::LABEL))
        else {
            println!("{name}: SKIP no c2pa.hash.data (box/bmff hash?)");
            skipped += 1;
            continue;
        };
        let dh = DataHash::from_assertion(dh_assertion.assertion()).unwrap();
        let alg = dh.alg.clone().unwrap_or_else(|| "sha256".to_owned());
        let stored: Vec<(u64, u64)> = dh
            .exclusions
            .as_ref()
            .map(|v| v.iter().map(|r| (r.start(), r.length())).collect())
            .unwrap_or_default();

        let mut cur = Cursor::new(bytes.clone());
        let s = if jpeg {
            containers::jpeg::parse(&mut cur)
        } else {
            containers::png::parse(&mut cur)
        }
        .unwrap();

        let whole = manifest_ranges(&s, true);
        let inner = manifest_ranges(&s, false);
        let h_whole = hash_with(&alg, &bytes, &whole);
        let h_inner = hash_with(&alg, &bytes, &inner);

        // Control: does the stored hash even match the file under the stored
        // exclusions? (Negative fixtures are built so that it does not.)
        let h_stored = hash_with(&alg, &bytes, &stored);
        let stored_valid = h_stored == dh.hash;

        println!(
            "{name}: stored={stored:?} whole={whole:?} payload+trailer={inner:?} \
             hash(whole)={} hash(inner)={} stored_hash_valid={stored_valid} excl_equal={}",
            h_whole == dh.hash,
            h_inner == dh.hash,
            whole == stored
        );
        checked += 1;
        if !stored_valid {
            println!("{name}: stored hash does not match file; negative fixture, not counted");
            continue;
        }
        if h_whole != dh.hash {
            failures.push(format!(
                "{name}: hash over whole-extent exclusions != stored \
                 (stored {stored:?}, derived {whole:?})"
            ));
        }
    }

    println!("checked {checked}, skipped {skipped}");
    assert!(checked > 0, "no fixture exercised the comparison");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
