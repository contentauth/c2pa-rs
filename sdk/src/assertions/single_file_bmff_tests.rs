// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Cursor, Seek};

use sha2::{Digest, Sha256};
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use super::BmffHash;
use crate::{
    asset_handlers::bmff_io::read_bmff_c2pa_boxes,
    dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
    utils::test_signer::{async_test_signer, test_signer},
    Builder, BuilderIntent, Context, Reader, Result, Settings, Signer, SigningAlg, ValidationState,
};

const RELATIVE: &[u8] = include_bytes!("../../tests/fixtures/single_file_fragments.mp4");
const ABSOLUTE: &[u8] = include_bytes!("../../tests/fixtures/single_file_fragments_absolute.mp4");
const DEFINITION: &str = r#"{"title":"single-file fragments","assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"}]}}]}"#;

fn builder() -> Builder {
    Builder::default().with_definition(DEFINITION).unwrap()
}

fn sign(input: &[u8]) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut output,
        )
        .unwrap();
    output.into_inner()
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap())
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().unwrap())
}

// Deliberately independent of the SDK's BMFF tree and offset/hash helpers.
#[derive(Clone, Copy, Debug)]
struct B {
    start: usize,
    payload: usize,
    end: usize,
    kind: [u8; 4],
}

fn boxes(data: &[u8], start: usize, end: usize) -> Vec<B> {
    let mut result = Vec::new();
    let mut at = start;
    while end - at >= 8 {
        let size = u32_at(data, at);
        let (size, header) = match size {
            0 => (end - at, 8),
            1 => (u64_at(data, at + 8) as usize, 16),
            _ => (size as usize, 8),
        };
        assert!(size >= header && at + size <= end);
        result.push(B {
            start: at,
            payload: at + header,
            end: at + size,
            kind: data[at + 4..at + 8].try_into().unwrap(),
        });
        at += size;
    }
    assert!(end - at < 8);
    result
}

fn roots(data: &[u8]) -> Vec<B> {
    boxes(data, 0, data.len())
}
fn children(data: &[u8], b: B) -> Vec<B> {
    boxes(data, b.payload, b.end)
}
fn named(list: &[B], kind: &[u8; 4]) -> B {
    *list.iter().find(|b| &b.kind == kind).unwrap()
}

fn binding(data: &[u8]) -> BmffHash {
    let reader = Reader::default()
        .with_stream("video/mp4", Cursor::new(data))
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
    let mut hash: BmffHash = reader
        .active_manifest()
        .unwrap()
        .find_assertion("c2pa.hash.bmff.v3")
        .unwrap();
    hash.set_bmff_version(3); // Deserializing assertion data alone does not carry its label version.
    hash.verify_stream_hash(&mut Cursor::new(data), None)
        .unwrap();
    hash
}

fn independent_hash(data: &[u8], start: usize, end: usize) -> Vec<u8> {
    let mut digest = Sha256::new();
    let parsed = roots(data);
    for b in parsed.iter().filter(|b| b.start >= start && b.end <= end) {
        if [*b"ftyp", *b"mfra", *b"free", *b"skip"].contains(&b.kind)
            || (b.kind == *b"uuid"
                && data[b.payload..b.payload + 16]
                    == [
                        0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28,
                        0x87, 0x7e, 0xc4, 0x81,
                    ])
        {
            continue;
        }
        digest.update((b.start as u64).to_be_bytes());
        digest.update(&data[b.start..b.end]);
    }
    let suffix_start = parsed.last().map_or(0, |b| b.end);
    if suffix_start >= start && suffix_start < end {
        digest.update(&data[suffix_start..end]);
    }
    digest.finalize().to_vec()
}

fn check_aux_locator(signed: &[u8]) {
    let root = roots(signed);
    let first_merkle = root
        .iter()
        .find(|b| {
            b.kind == *b"uuid" && signed.get(b.payload + 20..b.payload + 27) == Some(b"merkle\0")
        })
        .unwrap();
    let primary = root
        .iter()
        .find(|b| {
            b.kind == *b"uuid"
                && matches!(
                    signed.get(b.payload + 20..b.payload + 29),
                    Some(b"manifest\0" | b"original\0")
                )
        })
        .unwrap();
    assert_eq!(
        u64_at(signed, primary.payload + 29),
        first_merkle.start as u64
    );
}

fn check_output(original: &[u8], signed: &[u8]) {
    let hash = binding(signed);
    assert!(hash.hash().is_none());
    let maps = hash.merkle().unwrap();
    assert_eq!(maps.len(), 1);
    let map = &maps[0];
    let count = roots(original)
        .iter()
        .filter(|b| b.kind == *b"moof")
        .count();
    assert_eq!(map.count, count);
    let moov = named(&roots(original), b"moov");
    let trak = named(&children(original, moov), b"trak");
    let tkhd = named(&children(original, trak), b"tkhd");
    let track_id = u32_at(
        original,
        tkhd.payload + if original[tkhd.payload] == 1 { 20 } else { 12 },
    );
    assert_ne!(track_id, 0);
    assert_eq!(map.local_id, track_id as usize);
    check_aux_locator(signed);
    assert!(map.fixed_block_size.is_none() && map.variable_block_sizes.is_none());
    let root = roots(signed);
    let moofs: Vec<_> = root
        .iter()
        .filter(|b| b.kind == *b"moof")
        .copied()
        .collect();
    assert_eq!(moofs.len(), count);
    assert_eq!(
        map.init_hash.as_ref().unwrap().as_ref(),
        independent_hash(signed, 0, moofs[0].start)
    );
    let c2pa = read_bmff_c2pa_boxes(&mut Cursor::new(signed)).unwrap();
    assert_eq!(c2pa.bmff_merkle.len(), count);
    for (i, moof) in moofs.iter().enumerate() {
        let uuid = &c2pa.bmff_merkle_box_infos[i];
        assert_eq!(uuid.end(), moof.start as u64);
        assert_eq!(uuid.size(), c2pa.bmff_merkle_box_infos[0].size());
        assert_eq!(c2pa.bmff_merkle[i].location, i);
        assert_eq!(c2pa.bmff_merkle[i].unique_id, map.unique_id);
        assert_eq!(c2pa.bmff_merkle[i].local_id, map.local_id);
        let end = moofs.get(i + 1).map_or(signed.len(), |b| b.start);
        assert_eq!(
            map.hashes.0[i].as_ref(),
            independent_hash(signed, moof.start, end)
        );
    }
    // Every media payload and mfhd sequence is preserved; tfhd is the only moof
    // field that may change (when its base is absolute).
    let old_roots = roots(original);
    for (old, new) in old_roots
        .iter()
        .filter(|b| b.kind == *b"mdat")
        .zip(root.iter().filter(|b| b.kind == *b"mdat"))
    {
        assert_eq!(&original[old.start..old.end], &signed[new.start..new.end]);
    }
    for (old, new) in old_roots.iter().filter(|b| b.kind == *b"moof").zip(&moofs) {
        let mut expected = original[old.start..old.end].to_vec();
        let old_traf = named(&children(original, *old), b"traf");
        let old_tfhd = named(&children(original, old_traf), b"tfhd");
        let new_traf = named(&children(signed, *new), b"traf");
        let new_tfhd = named(&children(signed, new_traf), b"tfhd");
        if u32_at(original, old_tfhd.payload) & 1 != 0 {
            assert_eq!(u64_at(signed, new_tfhd.payload + 8), new.start as u64);
            let at = old_tfhd.payload + 8 - old.start;
            expected[at..at + 8].copy_from_slice(&(new.start as u64).to_be_bytes());
        } else {
            assert_ne!(u32_at(signed, new_tfhd.payload) & 0x020000, 0);
        }
        assert_eq!(expected, signed[new.start..new.end]);
        let trun = named(&children(signed, new_traf), b"trun");
        let offset = u32_at(signed, trun.payload + 8) as i32;
        assert_eq!((new.start as i64 + i64::from(offset)) as usize, new.end + 8);
    }
    // sidx must include the new UUID in each reference, not just move first_offset.
    if let Some(sidx) = root.iter().find(|b| b.kind == *b"sidx") {
        let wide = signed[sidx.payload] == 1;
        let first_at = sidx.payload + 12 + if wide { 8 } else { 4 };
        let first = if wide {
            u64_at(signed, first_at)
        } else {
            u64::from(u32_at(signed, first_at))
        };
        let mut start = sidx.end + first as usize;
        let entries = first_at + if wide { 8 } else { 4 } + 4;
        assert_eq!(
            u16::from_be_bytes(signed[entries - 2..entries].try_into().unwrap()),
            count as u16
        );
        for (i, moof) in moofs.iter().enumerate() {
            assert_eq!(start as u64, c2pa.bmff_merkle_box_infos[i].start());
            let length = u32_at(signed, entries + 12 * i);
            assert_eq!(length & 0x80000000, 0);
            start += length as usize;
            let mdat = root
                .iter()
                .find(|b| b.kind == *b"mdat" && b.start > moof.start)
                .unwrap();
            assert_eq!(start, mdat.end);
        }
    }
    // All tfra entries must address their own moof, not the last moof for a track.
    check_tfra(signed);
}

fn check_tfra(signed: &[u8]) {
    let root = roots(signed);
    let moofs: Vec<_> = root.iter().filter(|b| b.kind == *b"moof").collect();
    let count = moofs.len();
    if let Some(mfra) = root.iter().find(|b| b.kind == *b"mfra") {
        let tfra = named(&children(signed, *mfra), b"tfra");
        let wide = signed[tfra.payload] == 1;
        let widths = u32_at(signed, tfra.payload + 8);
        assert_eq!(u32_at(signed, tfra.payload + 12), count as u32);
        let mut at = tfra.payload + 16;
        for moof in moofs {
            at += if wide { 8 } else { 4 };
            let offset = if wide {
                u64_at(signed, at)
            } else {
                u64::from(u32_at(signed, at))
            };
            assert_eq!(offset, moof.start as u64);
            at += if wide { 8 } else { 4 };
            at += (((widths >> 4) & 3) + ((widths >> 2) & 3) + (widths & 3) + 3) as usize;
        }
    }
}

#[test]
fn single_file_stream_offsets_and_hashes() {
    for input in [RELATIVE, ABSOLUTE] {
        check_output(input, &sign(input));
    }
}

#[test]
#[cfg(feature = "file_io")]
fn single_file_sign_file() {
    let dir = tempfile::tempdir().unwrap();
    for (i, input) in [RELATIVE, ABSOLUTE].iter().enumerate() {
        let source = dir.path().join(format!("source{i}.mp4"));
        let dest = dir.path().join(format!("signed{i}.mp4"));
        std::fs::write(&source, input).unwrap();
        builder()
            .sign_file(test_signer(SigningAlg::Es256).as_ref(), &source, &dest)
            .unwrap();
        check_output(input, &std::fs::read(dest).unwrap());
    }
}

#[c2pa_macros::c2pa_test_async]
async fn single_file_async() {
    for input in [RELATIVE, ABSOLUTE] {
        let mut output = Cursor::new(Vec::new());
        builder()
            .sign_async(
                async_test_signer(SigningAlg::Es256).as_ref(),
                "video/mp4",
                &mut Cursor::new(input),
                &mut output,
            )
            .await
            .unwrap();
        check_output(input, output.get_ref());
    }
}

#[test]
fn single_file_tampering_and_resign() {
    let signed = sign(RELATIVE);
    let hash = binding(&signed);
    for kind in [b"moov", b"moof", b"mdat"] {
        let b = named(&roots(&signed), kind);
        let mut corrupted = signed.clone();
        let at = if kind == b"moof" {
            named(&children(&signed, b), b"mfhd").payload + 7
        } else {
            b.end - 1
        };
        corrupted[at] ^= 1;
        assert!(hash
            .verify_stream_hash(&mut Cursor::new(corrupted), None)
            .is_err());
    }
    let error = builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(&signed),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("existing Merkle boxes"),
        "{error}"
    );
}

#[test]
fn single_file_reject_cross_fragment_trun_and_limit() {
    let mut bad = RELATIVE.to_vec();
    let moof = named(&roots(&bad), b"moof");
    let traf = named(&children(&bad, moof), b"traf");
    let trun = named(&children(&bad, traf), b"trun");
    bad[trun.payload + 8..trun.payload + 12].copy_from_slice(&(-100i32).to_be_bytes());
    let err = builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(bad),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(err.to_string().contains("trun samples outside"), "{err}");
    let settings = Settings::new()
        .with_value("core.merkle_tree_max_leaves", 2)
        .unwrap();
    let err = Builder::from_context(Context::new().with_settings(settings).unwrap())
        .with_definition(DEFINITION)
        .unwrap()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(RELATIVE),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(err.to_string().contains("merkle_tree_max_leaves"), "{err}");
}

#[test]
fn single_file_reject_unsupported_addressing() {
    let moof = named(&roots(RELATIVE), b"moof");
    let traf = named(&children(RELATIVE, moof), b"traf");
    let tfhd = named(&children(RELATIVE, traf), b"tfhd");
    let trun = named(&children(RELATIVE, traf), b"trun");
    let sidx = named(&roots(RELATIVE), b"sidx");
    let mut variants = Vec::new();
    let mut implicit = RELATIVE.to_vec();
    let flags = u32_at(&implicit, tfhd.payload) & !0x020000;
    implicit[tfhd.payload..tfhd.payload + 4].copy_from_slice(&flags.to_be_bytes());
    variants.push((implicit, "implicit tfhd base"));
    let mut overrun = RELATIVE.to_vec();
    overrun[trun.payload + 8..trun.payload + 12].copy_from_slice(&(moof.end as i32).to_be_bytes());
    variants.push((overrun, "trun samples outside"));
    let mut auxiliary = RELATIVE.to_vec();
    auxiliary[trun.start + 4..trun.start + 8].copy_from_slice(b"saio");
    variants.push((auxiliary, "saio"));
    let mut hierarchical = RELATIVE.to_vec();
    let entry = sidx.payload + if RELATIVE[sidx.payload] == 1 { 32 } else { 24 };
    hierarchical[entry] |= 0x80;
    variants.push((hierarchical, "hierarchical sidx"));
    for (input, message) in variants {
        let err = builder()
            .sign(
                test_signer(SigningAlg::Es256).as_ref(),
                "video/mp4",
                &mut Cursor::new(input),
                &mut Cursor::new(Vec::new()),
            )
            .unwrap_err();
        assert!(err.to_string().contains(message), "{message}: {err}");
    }
}

#[test]
fn single_file_fragment_binding_overrides_mdat_chunk_setting() {
    let settings = Settings::new()
        .with_value("core.merkle_tree_chunk_size_in_kb", 1)
        .unwrap();
    let mut output = Cursor::new(Vec::new());
    Builder::from_context(Context::new().with_settings(settings).unwrap())
        .with_definition(DEFINITION)
        .unwrap()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(RELATIVE),
            &mut output,
        )
        .unwrap();
    check_output(RELATIVE, output.get_ref());
}

#[test]
#[ignore = "requires the ffmpeg executable; run explicitly for native release qualification"]
fn single_file_ffmpeg_decode_equivalence() {
    let dir = tempfile::tempdir().unwrap();
    for input in [RELATIVE, ABSOLUTE] {
        let source = dir.path().join("source.mp4");
        let dest = dir.path().join("signed.mp4");
        std::fs::write(&source, input).unwrap();
        std::fs::write(&dest, sign(input)).unwrap();
        let decode = |path: &std::path::Path| {
            let result = std::process::Command::new("ffmpeg")
                .args(["-v", "error", "-i"])
                .arg(path)
                .args(["-f", "framemd5", "-"])
                .output()
                .expect("ffmpeg is required for this explicitly selected test");
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(
                result.stderr.is_empty(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            result.stdout
        };
        let before = decode(&source);
        assert_eq!(
            String::from_utf8_lossy(&before)
                .lines()
                .filter(|l| l.starts_with("0,"))
                .count(),
            6
        );
        assert_eq!(before, decode(&dest));
    }
}

struct DynamicSigner(Box<dyn Signer>);
struct Dynamic;
impl DynamicAssertion for Dynamic {
    fn label(&self) -> String {
        "com.castlabs.fragment-test".into()
    }

    fn reserve_size(&self) -> Result<usize> {
        Ok(64)
    }

    fn content(
        &self,
        _: &str,
        size: Option<usize>,
        claim: &PartialClaim,
    ) -> Result<DynamicAssertionContent> {
        assert_eq!(size, Some(64));
        let binding = claim
            .assertions()
            .find(|a| a.url().contains("c2pa.hash.bmff.v3"))
            .unwrap();
        let mut content = vec![0xa2, 0x64, b'h', b'a', b's', b'h', 0x58, 0x20];
        content.extend(binding.hash());
        content.extend([0x63, b'p', b'a', b'd', 0x73]);
        content.extend([b'x'; 19]);
        Ok(DynamicAssertionContent::Cbor(content))
    }
}
impl Signer for DynamicSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.0.certs()
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        vec![Box::new(Dynamic)]
    }
}

#[test]
fn single_file_dynamic_assertion_and_update() {
    let signer = DynamicSigner(test_signer(SigningAlg::Es256));
    let mut signed = Cursor::new(Vec::new());
    builder()
        .sign(
            &signer,
            "video/mp4",
            &mut Cursor::new(RELATIVE),
            &mut signed,
        )
        .unwrap();
    check_output(RELATIVE, signed.get_ref());
    let reader = Reader::default()
        .with_stream("video/mp4", &mut signed)
        .unwrap();
    #[derive(serde::Deserialize)]
    struct Endorsement {
        hash: serde_bytes::ByteBuf,
    }
    let endorsement: Endorsement = reader
        .active_manifest()
        .unwrap()
        .find_assertion("com.castlabs.fragment-test")
        .unwrap();
    let boxes = read_bmff_c2pa_boxes(&mut signed).unwrap();
    let store = crate::store::Store::from_jumbf(
        &boxes.manifest_bytes.unwrap(),
        &mut crate::status_tracker::StatusTracker::default(),
    )
    .unwrap();
    let final_binding = store
        .provenance_claim()
        .unwrap()
        .assertions()
        .iter()
        .find(|a| a.url().contains("c2pa.hash.bmff.v3"))
        .unwrap();
    assert_eq!(endorsement.hash.as_ref(), final_binding.hash());
    let mut update = Builder::default();
    update.set_intent(BuilderIntent::Update);
    update
        .add_action(crate::assertions::Action::new("c2pa.published"))
        .unwrap();
    signed.rewind().unwrap();
    let mut output = Cursor::new(Vec::new());
    update
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut signed,
            &mut output,
        )
        .unwrap();
    let reader = Reader::default()
        .with_stream("video/mp4", &mut output)
        .unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
    binding(signed.get_ref())
        .verify_stream_hash(&mut output, None)
        .unwrap();
    check_aux_locator(output.get_ref());
}

fn historical_flat(input: &[u8]) -> Vec<u8> {
    // Reproduce the historical file-level binding using the caller-owned hash
    // API. The first pass fixes the layout; the second fills the same-size hash.
    let settings = Settings::new()
        .with_value("verify.verify_after_sign", false)
        .unwrap();
    let mut hash = BmffHash::new("historical flat fMP4", "sha256", None);
    hash.set_default_exclusions();
    hash.add_place_holder_hash().unwrap();
    let mut signed = Vec::new();
    for _ in 0..2 {
        let mut b = Builder::from_context(Context::new().with_settings(settings.clone()).unwrap())
            .with_definition(DEFINITION)
            .unwrap();
        b.add_assertion("c2pa.hash.bmff.v3", &hash).unwrap();
        let mut output = Cursor::new(Vec::new());
        b.sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut output,
        )
        .unwrap();
        signed = output.into_inner();
        hash.gen_hash_from_stream(&mut Cursor::new(&signed))
            .unwrap();
    }
    signed
}

#[test]
fn single_file_historical_flat_binding_still_verifies() {
    let signed = historical_flat(RELATIVE);
    let hash = binding(&signed);
    assert!(hash.hash().is_some() && hash.merkle().is_none());
    assert!(read_bmff_c2pa_boxes(&mut Cursor::new(&signed))
        .unwrap()
        .bmff_merkle
        .is_empty());
    // Re-signing legacy flat-bound fMP4 upgrades it to fragment Merkle binding.
    check_output(RELATIVE, &sign(&signed));
}

#[test]
fn single_file_trailing_bytes_are_bound_through_eof() {
    let clean = sign(RELATIVE);
    let clean_binding = binding(&clean);
    for len in 1..=7 {
        let mut appended = clean.clone();
        appended.extend(vec![0x51; len]);
        assert!(clean_binding
            .verify_stream_hash(&mut Cursor::new(appended), None)
            .is_err());
        let mut input = RELATIVE.to_vec();
        input.extend(vec![0x51; len]);
        let signed = sign(&input);
        check_output(&input, &signed);
        let hash = binding(&signed);
        let mut changed = signed.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(hash
            .verify_stream_hash(&mut Cursor::new(changed), None)
            .is_err());
        assert!(hash
            .verify_stream_hash(&mut Cursor::new(&signed[..signed.len() - 1]), None)
            .is_err());
    }
}

#[test]
fn single_file_track_id_and_changing_tracks() {
    assert_eq!(binding(&sign(RELATIVE)).merkle().unwrap()[0].local_id, 1);
    let mut input = RELATIVE.to_vec();
    let root = roots(&input);
    let moov = named(&root, b"moov");
    let trak = named(&children(&input, moov), b"trak");
    let tkhd = named(&children(&input, trak), b"tkhd");
    let trex = named(
        &children(&input, named(&children(&input, moov), b"mvex")),
        b"trex",
    );
    input[tkhd.payload + 12..tkhd.payload + 16].copy_from_slice(&137u32.to_be_bytes());
    input[trex.payload + 4..trex.payload + 8].copy_from_slice(&137u32.to_be_bytes());
    for moof in root.iter().filter(|b| b.kind == *b"moof") {
        let traf = named(&children(&input, *moof), b"traf");
        let tfhd = named(&children(&input, traf), b"tfhd");
        input[tfhd.payload + 4..tfhd.payload + 8].copy_from_slice(&137u32.to_be_bytes());
    }
    let sidx = named(&root, b"sidx");
    input[sidx.payload + 4..sidx.payload + 8].copy_from_slice(&137u32.to_be_bytes());
    let tfra = named(&children(&input, named(&root, b"mfra")), b"tfra");
    input[tfra.payload + 4..tfra.payload + 8].copy_from_slice(&137u32.to_be_bytes());
    let signed = sign(&input);
    check_output(&input, &signed);
    assert_eq!(binding(&signed).merkle().unwrap()[0].local_id, 137);
    let moof = named(&root, b"moof");
    let tfhd = named(
        &children(&input, named(&children(&input, moof), b"traf")),
        b"tfhd",
    );
    input[tfhd.payload + 4..tfhd.payload + 8].copy_from_slice(&138u32.to_be_bytes());
    let error = builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(error.to_string().contains("matching tfhd"), "{error}");
}

#[test]
fn single_file_uuid_size_at_cbor_integer_boundaries() {
    let root = roots(RELATIVE);
    let moofs: Vec<_> = root
        .iter()
        .filter(|b| b.kind == *b"moof")
        .copied()
        .collect();
    let first = moofs[0];
    let mdat = *root
        .iter()
        .find(|b| b.kind == *b"mdat" && b.start > first.start)
        .unwrap();
    let traf = named(&children(RELATIVE, first), b"traf");
    let tfdt = named(&children(RELATIVE, traf), b"tfdt");
    let next_tfdt = named(
        &children(RELATIVE, named(&children(RELATIVE, moofs[1]), b"traf")),
        b"tfdt",
    );
    assert_eq!(RELATIVE[tfdt.payload], 1);
    let duration = u64_at(RELATIVE, next_tfdt.payload + 4) - u64_at(RELATIVE, tfdt.payload + 4);
    let mfhd = named(&children(RELATIVE, first), b"mfhd");
    for count in [25, 257] {
        // Repeat real encoded fragments with advancing decode time/sequence.
        // Omit optional indexes so source offsets remain moof-relative.
        let mut input = RELATIVE[..named(&root, b"moov").end].to_vec();
        for index in 0..count {
            let mut fragment = RELATIVE[first.start..mdat.end].to_vec();
            let at = mfhd.payload + 4 - first.start;
            fragment[at..at + 4].copy_from_slice(&((index + 1) as u32).to_be_bytes());
            let at = tfdt.payload + 4 - first.start;
            fragment[at..at + 8].copy_from_slice(&(index as u64 * duration).to_be_bytes());
            input.extend(fragment);
        }
        let signed = sign(&input);
        check_output(&input, &signed);
        let parsed = read_bmff_c2pa_boxes(&mut Cursor::new(&signed)).unwrap();
        assert_eq!(parsed.bmff_merkle.len(), count);
        let size = parsed.bmff_merkle_box_infos.last().unwrap().size();
        assert!(parsed
            .bmff_merkle_box_infos
            .iter()
            .all(|b| b.size() == size));
    }
}

#[test]
fn single_file_preprocessing_xmp_and_manifest_removal() {
    for input in [RELATIVE, ABSOLUTE] {
        let legacy = historical_flat(input);
        let handler = crate::jumbf_io::get_assetio_handler("video/mp4").unwrap();
        let mut stripped = Cursor::new(Vec::new());
        handler
            .get_writer("video/mp4")
            .unwrap()
            .remove_c2pa(&mut Cursor::new(&legacy), &mut stripped)
            .unwrap();
        assert_eq!(stripped.get_ref(), input); // Includes every original tfra/tfhd/sidx field.
        let mut remote = builder();
        remote.set_remote_url("https://example.invalid/manifest.c2pa");
        let mut output = Cursor::new(Vec::new());
        remote
            .sign(
                test_signer(SigningAlg::Es256).as_ref(),
                "video/mp4",
                &mut Cursor::new(&legacy),
                &mut output,
            )
            .unwrap();
        check_output(input, output.get_ref());
        for remote_only in [false, true] {
            let mut sidecar = builder();
            sidecar.set_no_embed(true);
            if remote_only {
                sidecar.set_remote_url("https://example.invalid/detached.c2pa");
            }
            let mut output = Cursor::new(Vec::new());
            let error = sidecar
                .sign(
                    test_signer(SigningAlg::Es256).as_ref(),
                    "video/mp4",
                    &mut Cursor::new(&legacy),
                    &mut output,
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("requires an embedded manifest"),
                "{error}"
            );
            assert!(output.get_ref().is_empty());
        }
    }
}

#[test]
#[cfg(feature = "file_io")]
fn single_file_aux_locator_xmp_replacement_and_in_place_patch() {
    let signed = sign(ABSOLUTE);
    let handler = crate::jumbf_io::get_assetio_handler("video/mp4").unwrap();
    let manifest = read_bmff_c2pa_boxes(&mut Cursor::new(&signed))
        .unwrap()
        .manifest_bytes
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("patched.mp4");
    std::fs::write(&path, &signed).unwrap();
    handler
        .asset_patch_ref()
        .unwrap()
        .patch_c2pa_file(&path, &manifest)
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), signed);
    let mut source = signed;
    for url in [
        "https://example.invalid/long-manifest-name.c2pa",
        "https://example.invalid/x",
    ] {
        let mut output = Cursor::new(Vec::new());
        handler
            .remote_manifest_url_ref()
            .unwrap()
            .write_remote_manifest_url(&mut Cursor::new(&source), &mut output, url)
            .unwrap();
        // Modifying XMP requires re-signing the binding, but the media indexes
        // and the existing manifest's auxiliary locator must still be correct.
        check_aux_locator(output.get_ref());
        check_tfra(output.get_ref());
        source = output.into_inner();
    }
}

#[test]
fn single_file_rejects_multiple_initialization_tracks() {
    let root = roots(RELATIVE);
    let moov = named(&root, b"moov");
    let trak = named(&children(RELATIVE, moov), b"trak");
    let mut extra_track = RELATIVE[trak.start..trak.end].to_vec();
    let tkhd = named(&children(RELATIVE, trak), b"tkhd");
    let at = tkhd.payload + 12 - trak.start;
    extra_track[at..at + 4].copy_from_slice(&2u32.to_be_bytes());
    let mut input = RELATIVE.to_vec();
    input.splice(moov.end..moov.end, extra_track.iter().copied());
    input[moov.start..moov.start + 4]
        .copy_from_slice(&((moov.end - moov.start + extra_track.len()) as u32).to_be_bytes());
    let error = builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut Cursor::new(Vec::new()),
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("multiplexed/changing tracks"),
        "{error}"
    );
}

#[test]
fn single_file_updates_preserve_raw_suffix_and_reject_size_zero() {
    let update = |input: &[u8]| -> Result<Vec<u8>> {
        let mut builder = Builder::default();
        builder.set_intent(BuilderIntent::Update);
        builder.add_action(crate::assertions::Action::new("c2pa.published"))?;
        let mut output = Cursor::new(Vec::new());
        builder.sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(input),
            &mut output,
        )?;
        Ok(output.into_inner())
    };
    for len in 1..=7 {
        let mut input = RELATIVE.to_vec();
        input.extend(vec![0x51; len]);
        let signed = sign(&input);
        let hash = binding(&signed);
        let first = update(&signed).unwrap();
        let second = update(&first).unwrap();
        for output in [first, second] {
            assert!(output.ends_with(&vec![0x51; len]));
            hash.verify_stream_hash(&mut Cursor::new(&output), None)
                .unwrap();
            let reader = Reader::default()
                .with_stream("video/mp4", Cursor::new(&output))
                .unwrap();
            assert_ne!(
                reader.validation_state(),
                ValidationState::Invalid,
                "{reader}"
            );
            check_aux_locator(&output);
        }
    }
    let mdat = *roots(RELATIVE)
        .iter()
        .rfind(|b| b.kind == *b"mdat")
        .unwrap();
    let mut input = RELATIVE[..mdat.end].to_vec();
    input[mdat.start..mdat.start + 4].fill(0);
    let signed = sign(&input);
    let error = update(&signed).unwrap_err();
    assert!(
        error.to_string().contains("terminal size-zero box"),
        "{error}"
    );
}

#[test]
fn single_file_sign_with_trailing_xmp() {
    let handler = crate::jumbf_io::get_assetio_handler("video/mp4").unwrap();
    for input in [RELATIVE, ABSOLUTE] {
        // Obtain an XMP UUID through the public writer, then put it after all media.
        // Appending metadata does not change any original media/index offsets.
        let mut with_xmp = Cursor::new(Vec::new());
        handler
            .remote_manifest_url_ref()
            .unwrap()
            .write_remote_manifest_url(
                &mut Cursor::new(input),
                &mut with_xmp,
                "https://example.invalid/old",
            )
            .unwrap();
        let xmp = named(&roots(with_xmp.get_ref()), b"uuid");
        let mut input_with_tail = input.to_vec();
        input_with_tail.extend_from_slice(&with_xmp.get_ref()[xmp.start..xmp.end]);
        for length in [8192, 1] {
            let mut builder = builder();
            builder.set_remote_url(format!("https://example.invalid/{}", "x".repeat(length)));
            let mut output = Cursor::new(Vec::new());
            builder
                .sign(
                    test_signer(SigningAlg::Es256).as_ref(),
                    "video/mp4",
                    &mut Cursor::new(&input_with_tail),
                    &mut output,
                )
                .unwrap();
            check_output(&input_with_tail, output.get_ref());
        }
    }
}
