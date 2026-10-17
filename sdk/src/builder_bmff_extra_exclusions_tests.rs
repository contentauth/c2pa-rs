// Copyright 2026 Adobe. All rights reserved.
// This file is licensed under the Apache License, Version 2.0 or the MIT license.

#![allow(clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Seek, SeekFrom, Write};

use super::*;
use crate::{
    utils::{test::write_bmff_placeholder_stream, test_signer::test_signer},
    Settings, SigningAlg, ValidationState,
};

const EXTRAS: &str =
    r#"{"builder":{"bmff_hash_extra_exclusions":[{"xpath":"/sidx"},{"xpath":"/sidx"}]}}"#;
const DEFINITION: &str = r#"{"title":"extra exclusions","assertions":[{"label":"c2pa.actions","data":{"actions":[{"action":"c2pa.created","digitalSourceType":"http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"}]}}]}"#;
const FLAT: &[u8] = include_bytes!("../tests/fixtures/video1_no_manifest.mp4");

fn builder() -> Builder {
    let settings = Settings::new().with_json(EXTRAS).unwrap();
    Builder::from_context(Context::new().with_settings(settings).unwrap())
        .with_definition(DEFINITION)
        .unwrap()
}

fn caller_hash(matching: bool) -> BmffHash {
    let mut hash = BmffHash::new("caller hash", "sha256", None);
    hash.set_default_exclusions();
    hash.set_bmff_version(3);
    if matching {
        hash.add_extra_exclusions(
            &builder()
                .context
                .settings()
                .builder
                .bmff_hash_extra_exclusions,
        );
    }
    hash.gen_hash_from_stream(&mut Cursor::new(FLAT)).unwrap();
    hash
}

fn assert_settings_error<T>(result: Result<T>) {
    assert!(
        matches!(result, Err(Error::BadParam(ref message)) if message.contains("bmff_hash_extra_exclusions"))
    );
}

struct NeverSign;

impl Signer for NeverSign {
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>> {
        panic!("settings must be rejected before native signer invocation")
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        test_signer(self.alg()).certs()
    }

    fn reserve_size(&self) -> usize {
        10000
    }
}

#[test]
fn extra_exclusions_require_exact_descriptors_without_mutation() {
    let extra: crate::settings::builder::BmffHashExclusion = serde_json::from_str(
        r#"{"xpath":"/sidx","length":64,"data":[{"offset":8,"value":[0]}],"subset":[{"offset":20,"length":4}],"version":0,"flags":[0,0,1],"exact":true}"#,
    ).unwrap();
    let mut hash = caller_hash(false);
    hash.add_extra_exclusions(&[extra.clone(), extra.clone()]);
    let before = hash.to_assertion().unwrap();
    hash.check_extra_exclusions(&[extra.clone(), extra.clone()])
        .unwrap();
    assert_eq!(hash.to_assertion().unwrap().data(), before.data());
    assert_eq!(
        hash.exclusions()
            .iter()
            .filter(|e| e.xpath == "/sidx")
            .count(),
        1
    );
    for field in ["length", "data", "subset", "version", "flags", "exact"] {
        let mut different = serde_json::to_value(&extra).unwrap();
        different.as_object_mut().unwrap().remove(field);
        let different = serde_json::from_value(different).unwrap();
        assert_settings_error(hash.check_extra_exclusions(&[different]));
    }
}

#[test]
fn extra_exclusions_shared_claim_check_rejects_missing_descriptor() {
    let builder = builder();
    let mut claim = builder.to_claim().unwrap();
    claim.add_assertion(&caller_hash(false)).unwrap();
    assert_settings_error(builder.to_store_with_claim(claim));
}

#[test]
fn extra_exclusions_embeddable_rejects_missing_caller_hash_descriptor() {
    let mut builder = builder();
    builder.context = Arc::new(
        Context::new()
            .with_settings(Settings::new().with_json(EXTRAS).unwrap())
            .unwrap()
            .with_signer(NeverSign),
    );
    builder
        .add_assertion("c2pa.hash.bmff.v3", &caller_hash(false))
        .unwrap();
    assert_settings_error(builder.sign_embeddable("video/mp4"));
    assert_settings_error(builder.placeholder("video/mp4"));
    assert_settings_error(
        builder.update_hash_from_stream("video/mp4", &mut Cursor::new(Vec::<u8>::new())),
    );
}

#[test]
fn extra_exclusions_embeddable_allows_matching_precomputed_hash() {
    let mut builder = builder();
    let supplied = caller_hash(true);
    let before = supplied.to_assertion().unwrap();
    builder
        .add_assertion("c2pa.hash.bmff.v3", &supplied)
        .unwrap();
    assert!(!builder.sign_embeddable("video/mp4").unwrap().is_empty());
    let store = builder.to_store().unwrap();
    let assertion = store.provenance_claim().unwrap().bmff_hash_assertions()[0];
    assert_eq!(assertion.assertion().data(), before.data());
}

#[test]
fn extra_exclusions_matching_caller_hash_signs_unchanged() {
    let mut builder = builder();
    builder.set_no_embed(true);
    builder
        .add_assertion("c2pa.hash.bmff.v3", &caller_hash(true))
        .unwrap();
    let mut output = Cursor::new(Vec::new());
    builder
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "video/mp4",
            &mut Cursor::new(FLAT),
            &mut output,
        )
        .unwrap();
    assert_eq!(output.into_inner(), FLAT);
}

#[test]
fn extra_exclusions_generated_placeholder_embeddable_validates() {
    let mut builder = builder();
    let placeholder = builder.placeholder("video/mp4").unwrap();
    let mut asset = Cursor::new(Vec::new());
    let offset =
        write_bmff_placeholder_stream(&placeholder, &mut Cursor::new(FLAT), &mut asset).unwrap();
    builder
        .update_hash_from_stream("video/mp4", &mut asset)
        .unwrap();
    let signed = builder.sign_embeddable("video/mp4").unwrap();
    assert_eq!(signed.len(), placeholder.len());
    asset.seek(SeekFrom::Start(offset as u64)).unwrap();
    asset.write_all(&signed).unwrap();
    asset.rewind().unwrap();
    let reader = Reader::default().with_stream("video/mp4", asset).unwrap();
    assert_ne!(
        reader.validation_state(),
        ValidationState::Invalid,
        "{reader}"
    );
}

#[test]
fn extra_exclusions_update_rejects_before_signer_and_stream_writes() {
    let mut builder = builder();
    builder.set_intent(BuilderIntent::Update);
    let mut output = Cursor::new(b"untouched".to_vec());
    assert_settings_error(builder.sign(
        &NeverSign,
        "video/mp4",
        &mut Cursor::new(FLAT),
        &mut output,
    ));
    assert_eq!(output.into_inner(), b"untouched");
    assert_settings_error(builder.sign_embeddable("video/mp4"));
    builder.check_bmff_settings("image/jpeg").unwrap();
}

#[test]
fn extra_exclusions_store_update_rejects_before_signer_and_stream_writes() {
    let builder = builder();
    let mut store = builder.to_store().unwrap();
    store
        .provenance_claim_mut()
        .unwrap()
        .set_update_manifest(true);
    let mut output = Cursor::new(b"untouched".to_vec());
    assert_settings_error(store.save_to_stream(
        "video/mp4",
        &mut Cursor::new(FLAT),
        &mut output,
        &NeverSign,
        &builder.context,
    ));
    assert_eq!(output.into_inner(), b"untouched");
}

#[test]
fn extra_exclusions_do_not_reject_non_bmff_signing() {
    let mut output = Cursor::new(Vec::new());
    builder()
        .sign(
            test_signer(SigningAlg::Es256).as_ref(),
            "image/jpeg",
            &mut Cursor::new(include_bytes!("../tests/fixtures/earth_apollo17.jpg")),
            &mut output,
        )
        .unwrap();
    assert!(!output.into_inner().is_empty());
}

#[cfg(feature = "file_io")]
#[test]
fn extra_exclusions_update_and_missing_hash_preserve_output_files() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.mp4");
    let output = dir.path().join("output.mp4");
    std::fs::write(&input, FLAT).unwrap();
    for update in [false, true] {
        let mut builder = builder();
        if update {
            builder.set_intent(BuilderIntent::Update);
        } else {
            builder
                .add_assertion("c2pa.hash.bmff.v3", &caller_hash(false))
                .unwrap();
        }
        assert_settings_error(builder.save_to_file(&input, &output));
        assert!(!output.exists());
        assert_settings_error(builder.sign_file(&NeverSign, &input, &output));
        assert!(!output.exists());
        std::fs::write(&output, b"untouched").unwrap();
        assert!(builder.sign_file(&NeverSign, &input, &output).is_err());
        assert_eq!(std::fs::read(&output).unwrap(), b"untouched");
        std::fs::remove_file(&output).unwrap();
    }
}

#[cfg(feature = "file_io")]
#[test]
fn extra_exclusions_fragmented_rejects_missing_hash_before_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("absent");
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bunny/bunny_89283bps/BigBuckBunny_2s_init.mp4");
    let mut builder = builder();
    builder
        .add_assertion("c2pa.hash.bmff.v3", &caller_hash(false))
        .unwrap();
    assert_settings_error(builder.sign_fragmented_files(
        &NeverSign,
        input.as_path(),
        Path::new("BigBuckBunny_2s1*.m4s"),
        output.as_path(),
    ));
    assert!(!output.exists());
    // Direct Store callers must fail before even creating the output root.
    let mut store = Store::from_context(&builder.context);
    store.commit_claim(builder.to_claim().unwrap()).unwrap();
    assert_settings_error(store.save_to_bmff_fragmented(
        std::slice::from_ref(&input),
        Path::new("BigBuckBunny_2s1*.m4s"),
        output.as_path(),
        &NeverSign,
        &builder.context,
    ));
    assert!(!output.exists());
    store
        .provenance_claim_mut()
        .unwrap()
        .set_update_manifest(true);
    assert_settings_error(store.save_to_bmff_fragmented(
        &[input],
        Path::new("BigBuckBunny_2s1*.m4s"),
        output.as_path(),
        &NeverSign,
        &builder.context,
    ));
    assert!(!output.exists());
}

#[cfg(feature = "file_io")]
#[test]
fn extra_exclusions_fragmented_reuses_generated_assertion_across_renditions() {
    let dir = tempfile::tempdir().unwrap();
    let input = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bunny/*/BigBuckBunny_2s_init.mp4");
    builder()
        .sign_fragmented_files(
            test_signer(SigningAlg::Es256).as_ref(),
            input.as_path(),
            Path::new("BigBuckBunny_2s*.m4s"),
            dir.path(),
        )
        .unwrap();
    for rendition in ["bunny_89283bps", "bunny_595491bps", "bunny_791182bps"] {
        let init =
            std::fs::read(dir.path().join(rendition).join("BigBuckBunny_2s_init.mp4")).unwrap();
        let reader = Reader::default()
            .with_stream("video/mp4", Cursor::new(init))
            .unwrap();
        let hash: BmffHash = reader
            .active_manifest()
            .unwrap()
            .find_assertion("c2pa.hash.bmff.v3")
            .unwrap();
        assert_eq!(
            hash.exclusions()
                .iter()
                .filter(|e| e.xpath == "/sidx")
                .count(),
            1
        );
        assert_eq!(hash.merkle().unwrap().len(), 3);
    }
}
