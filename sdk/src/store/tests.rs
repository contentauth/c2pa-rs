#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "file_io")]
use std::fs;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use c2pa_macros::c2pa_test_async;
#[cfg(feature = "file_io")]
use memchr::memmem;
use serde::Serialize;
#[cfg(feature = "file_io")]
use sha2::Sha256;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use super::*;
#[cfg(feature = "file_io")]
use crate::{
    assertion::AssertionJson,
    assertions::{labels::BOX_HASH, BoxHash, DataHash},
    asset_io::HashBlockObjectType,
    hashed_uri::HashedUri,
    jumbf_io::{get_assetio_handler_from_path, load_jumbf_from_file, save_jumbf_to_file},
    utils::{
        hash_utils::Hasher,
        io_utils::tempdirectory,
        test::write_jpeg_placeholder_file,
        test::{temp_dir_path, TEST_USER_ASSERTION},
        test_signer::test_cawg_signer,
    },
};
use crate::{
    assertions::{Action, Actions, Uuid},
    asset_io::CAIReadWrite,
    claim::{AssertionStoreJsonFormat, ClaimAssetData},
    crypto::raw_signature::SigningAlg,
    jumbf_io::load_jumbf_from_stream,
    status_tracker::{LogItem, StatusTracker},
    utils::{
        patch::patch_bytes,
        test::{create_test_claim, create_test_streams, fixture_path},
        test_signer::{async_test_signer, test_signer},
    },
    ClaimGeneratorInfo, DigitalSourceType,
};

fn create_editing_claim(claim: &mut Claim) -> Result<&mut Claim> {
    let uuid_str = "deadbeefdeadbeefdeadbeefdeadbeef";

    // add a binary thumbnail assertion  ('deadbeefadbeadbe')
    let some_binary_data: Vec<u8> = vec![
        0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d, 0x0b,
        0x0e,
    ];

    let actions = Actions::new().add_action(Action::new("c2pa.created"));

    claim.add_assertion(&actions)?;

    let uuid_assertion = Uuid::new("test uuid", uuid_str.to_string(), some_binary_data);

    claim.add_assertion(&uuid_assertion)?;

    Ok(claim)
}

fn create_capture_claim(claim: &mut Claim) -> Result<&mut Claim> {
    let actions = Actions::new()
        .add_action(Action::new("c2pa.created").set_source_type(DigitalSourceType::Empty));

    claim.add_assertion(&actions)?;

    Ok(claim)
}

#[test]
fn test_jumbf_generation() {
    let context = Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v1_unit_test");

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
    create_capture_claim(&mut claim_capture).unwrap();
    claim_capture.add_claim_generator_info(cgi.clone());

    let signer = test_signer(SigningAlg::Ps256);

    store.commit_claim(claim_capture).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // should not have any
    assert!(!report.has_any_error());

    // dump store and compare to original
    for claim in new_store.claims() {
        let _restored_json = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();
        let _orig_json = store
            .get_claim(claim.label())
            .unwrap()
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();

        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim.get_claim_assertion(&label, instance).unwrap();
        }
    }
}

#[test]
fn test_claim_v2_generation() {
    let context = Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 2);
    create_capture_claim(&mut claim_capture).unwrap();
    claim_capture.add_claim_generator_info(cgi.clone());

    let signer = test_signer(SigningAlg::Ps256);

    store.commit_claim(claim_capture).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // should not have any
    assert!(!report.has_any_error());

    // dump store and compare to original
    for claim in new_store.claims() {
        let _restored_json = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();
        let _orig_json = store
            .get_claim(claim.label())
            .unwrap()
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();

        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim.get_claim_assertion(&label, instance).unwrap();
        }
    }
}

#[test]
fn test_bad_claim_v2_generation() {
    let mut context = Context::new();
    context.settings_mut().verify.verify_after_sign = false;

    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 2);
    create_capture_claim(&mut claim_capture).unwrap();
    claim_capture.add_claim_generator_info(cgi.clone());

    // add second action to claim which is not allowed
    let action = Actions::new().add_action(Action::new("c2pa.opened"));
    claim_capture.add_assertion(&action).unwrap();

    let signer = test_signer(SigningAlg::Ps256);

    store.commit_claim(claim_capture).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // read from new stream
    output_stream.rewind().unwrap();
    let _new_store = Store::from_stream(format, &mut output_stream, &mut report, &context);

    // should have action errors
    assert!(report.has_any_error());
    assert!(report.has_error(Error::ValidationRule(
        "only first action can be created or opened".to_string()
    )));
}

#[test]
#[cfg(feature = "file_io")]
#[ignore = "we need to make this work again"]
fn test_unknown_asset_type_generation() {
    let context = crate::context::Context::new();

    // test adding to actual image
    let (_format, mut input_stream, mut output_stream) =
        create_test_streams("unsupported_type.txt");
    let format = "text/plain";
    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Create a new claim.
    let mut claim2 = Claim::new("Photoshop", Some("Adobe"), 1);
    create_editing_claim(&mut claim2).unwrap();

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
    create_capture_claim(&mut claim_capture).unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(
        format,
        &mut output_stream,
        &mut StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError),
        &context,
    )
    .unwrap();

    // can  we get by the ingredient data back

    // dump store and compare to original
    for claim in new_store.claims() {
        let _restored_json = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();
        let _orig_json = store
            .get_claim(claim.label())
            .unwrap()
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();

        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim.get_claim_assertion(&label, instance).unwrap();
        }
    }
}

#[test]
#[cfg(feature = "file_io")]
fn test_detects_unverifiable_signature() {
    let context = crate::context::Context::new();

    struct BadSigner {}

    impl Signer for BadSigner {
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
            Ok(b"not a valid signature".to_vec())
        }

        fn alg(&self) -> SigningAlg {
            SigningAlg::Ps256
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }

        fn reserve_size(&self) -> usize {
            42
        }
    }

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    let mut store = Store::from_context(&context);

    let claim = create_test_claim().unwrap();

    let signer = BadSigner {};

    // JUMBF generation should fail because this signature won't validate.
    store.commit_claim(claim).unwrap();

    // TO DO: This generates a log spew when running this test.
    // I don't have time to fix this right now.
    // [(date) ERROR c2pa::store] Signature that was just generated does not validate: CoseCbor

    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            &signer,
            &context,
        )
        .unwrap_err();
}

#[test]
#[cfg(feature = "file_io")]
fn test_sign_with_expired_cert() {
    use crate::{create_signer, crypto::raw_signature::SigningAlg};

    let context = Context::new();

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    let mut store = Store::from_context(&context);

    let claim = create_test_claim().unwrap();

    let signcert_path = fixture_path("rsa-pss256_key-expired.pub");
    let pkey_path = fixture_path("rsa-pss256-expired.pem");
    let signer =
        create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None).unwrap();

    store.commit_claim(claim).unwrap();

    let r = store.save_to_stream(
        format,
        &mut input_stream,
        &mut output_stream,
        &signer,
        &context,
    );
    assert!(r.is_err());
    assert_eq!(
        r.err().unwrap().to_string(),
        "the certificate was not valid at time of signing"
    );
}

#[test]
#[cfg(feature = "file_io")]
fn test_jumbf_replacement_generation() {
    let context = Context::new();
    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();
    store.commit_claim(claim1).unwrap();

    // do we generate JUMBF
    let jumbf_bytes = store.to_jumbf_internal(512).unwrap();
    assert!(!jumbf_bytes.is_empty());

    // test adding to actual image
    let ap = fixture_path("prerelease.jpg");
    let temp_dir = tempdirectory().expect("temp dir");
    let op = temp_dir_path(&temp_dir, "replacement_test.jpg");

    // grab jumbf from original
    let original_jumbf = load_jumbf_from_file(&ap).unwrap();

    // replace with new jumbf
    save_jumbf_to_file(&jumbf_bytes, &ap, Some(&op)).unwrap();

    let saved_jumbf = load_jumbf_from_file(&op).unwrap();

    // saved data should be the new data
    assert_eq!(&jumbf_bytes, &saved_jumbf);

    // original data should not be in file anymore check for first 1k
    let buf = fs::read(&op).unwrap();
    assert_eq!(memmem::find(&buf, &original_jumbf[0..1024]), None);
}

#[c2pa_test_async]
//#[ignore] // this is not generating the expected error. Needs investigation.
async fn test_jumbf_generation_async() -> Result<()> {
    let context = crate::context::Context::new();

    // Verify after sign is causing UnreferencedManifest errors here, since the manifests don't reference each other.
    //no_verify_after_sign();

    let signer = async_test_signer(SigningAlg::Ps256);

    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = crate::utils::test::create_test_claim()?;

    // Create a new claim.
    let mut claim2 = Claim::new("Photoshop", Some("Adobe"), 1);
    create_editing_claim(&mut claim2)?;

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
    create_capture_claim(&mut claim_capture)?;

    // Test generate JUMBF
    // Get labels for label test
    let claim1_label = claim1.label().to_string();
    let capture = claim_capture.label().to_string();
    let claim2_label = claim2.label().to_string();

    store.commit_claim(claim1)?;
    store
        .save_to_stream_async(
            format,
            &mut input_stream,
            &mut output_stream,
            &signer,
            &context,
        )
        .await?;
    store.commit_claim(claim_capture)?;
    let mut temp_stream = Cursor::new(Vec::new());
    output_stream.rewind()?;
    store
        .save_to_stream_async(
            format,
            &mut output_stream,
            &mut temp_stream,
            &signer,
            &context,
        )
        .await?;
    store.commit_claim(claim2)?;
    temp_stream.rewind()?;
    output_stream.rewind()?;
    store
        .save_to_stream_async(
            format,
            &mut temp_stream,
            &mut output_stream,
            &signer,
            &context,
        )
        .await
        .unwrap();

    // test finding claims by label
    let c1 = store.get_claim(&claim1_label);
    let c2 = store.get_claim(&capture);
    let c3 = store.get_claim(&claim2_label);
    assert_eq!(&claim1_label, c1.unwrap().label());
    assert_eq!(&capture, c2.unwrap().label());
    assert_eq!(claim2_label, c3.unwrap().label());

    // Do we generate JUMBF
    let jumbf_bytes = store.to_jumbf_internal(signer.reserve_size())?;
    assert!(!jumbf_bytes.is_empty());

    // write to new file
    println!("Provenance: {}\n", store.provenance_path().unwrap());

    // make sure we can read from new file
    let mut report = StatusTracker::default();

    output_stream.rewind()?;
    let _new_store =
        Store::from_stream_async(format, &mut output_stream, &mut report, &context).await?;

    assert!(!report.has_any_error());
    Ok(())
}

#[test]
fn test_png_jumbf_generation() {
    let mut context = Context::new();
    context.settings_mut().verify.verify_after_sign = false;

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("libpng-test.png");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Create a new claim.
    let mut claim2 = Claim::new("Photoshop", Some("Adobe"), 1);
    create_editing_claim(&mut claim2).unwrap();

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
    create_capture_claim(&mut claim_capture).unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            &signer,
            &context,
        )
        .unwrap();

    store.commit_claim(claim_capture).unwrap();
    output_stream.rewind().unwrap();
    let mut temp_stream = Cursor::new(Vec::new());
    store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut temp_stream,
            &signer,
            &context,
        )
        .unwrap();

    store.commit_claim(claim2).unwrap();
    temp_stream.rewind().unwrap();
    output_stream.rewind().unwrap();
    store
        .save_to_stream(
            format,
            &mut temp_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // write to new file
    println!("Provenance: {}\n", store.provenance_path().unwrap());

    let mut report = StatusTracker::default();

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // can  we get by the ingredient data back
    let _some_binary_data: Vec<u8> = vec![
        0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d, 0x0b,
        0x0e,
    ];

    // dump store and compare to original
    for claim in new_store.claims() {
        let _restored_json = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();
        let _orig_json = store
            .get_claim(claim.label())
            .unwrap()
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();

        // println!(
        //     "Claim: {} \n{}",
        //     claim.label(),
        //     claim
        //         .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
        //         .expect("could not restore from json")
        // );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim
                .get_claim_assertion(&label, instance)
                .expect("Should find assertion");
        }
    }
}

#[test]
#[cfg(feature = "file_io")]
fn test_get_data_boxes() {
    // Create a new claim.
    use crate::jumbf::labels::to_relative_uri;
    let claim1 = create_test_claim().unwrap();

    for (uri, db) in claim1.databoxes() {
        // test full path
        assert!(claim1.get_databox(uri).is_some());

        // test with relative path
        let rel_path = to_relative_uri(&uri.url());
        let rel_hr = HashedUri::new(rel_path, uri.alg(), &uri.hash());
        assert!(claim1.get_databox(&rel_hr).is_some());

        // test values
        assert_eq!(db, claim1.get_databox(uri).unwrap());
    }
}

/*  reenable this test once we place for large test files
    #[test]
    #[cfg(feature = "file_io")]
    fn test_arw_jumbf_generation() {
        let ap = fixture_path("sample1.arw");
        let temp_dir = tempdirectory().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "ssample1.arw");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"), 1);
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = test_signer(SigningAlg::Ps256);

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commmits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

        // write to new file
        println!("Provenance: {}\n", store.provenance_path().unwrap());

        let mut report = StatusTracker::default();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // can  we get by the ingredient data back
        let _some_binary_data: Vec<u8> = vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ];

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }
    #[test]
    #[cfg(feature = "file_io")]
    fn test_nef_jumbf_generation() {
        let ap = fixture_path("sample1.nef");
        let temp_dir = tempdirectory().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "ssample1.nef");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"), 1);
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = test_signer(SigningAlg::Ps256);

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commmits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

        // write to new file
        println!("Provenance: {}\n", store.provenance_path().unwrap());

        let mut report = StatusTracker::default();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // can  we get by the ingredient data back
        let _some_binary_data: Vec<u8> = vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ];

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }
*/
#[test]
fn test_wav_jumbf_generation() {
    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("sample1.wav");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Create a new claim.
    let mut claim2 = Claim::new("Photoshop", Some("Adobe"), 1);
    create_editing_claim(&mut claim2).unwrap();

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
    create_capture_claim(&mut claim_capture).unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();
    store.commit_claim(claim_capture).unwrap();
    output_stream.rewind().unwrap();
    let mut temp_stream = Cursor::new(Vec::new());
    store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut temp_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();
    store.commit_claim(claim2).unwrap();
    output_stream.rewind().unwrap();
    store
        .save_to_stream(
            format,
            &mut temp_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // write to new file
    println!("Provenance: {}\n", store.provenance_path().unwrap());

    let mut report = StatusTracker::default();

    // can  we get by the ingredient data back
    let _some_binary_data: Vec<u8> = vec![
        0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d, 0x0b,
        0x0e,
    ];

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // dump store and compare to original
    for claim in new_store.claims() {
        let _restored_json = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();
        let _orig_json = store
            .get_claim(claim.label())
            .unwrap()
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();

        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim
                .get_claim_assertion(&label, instance)
                .expect("Should find assertion");
        }
    }
}

#[test]
fn test_avi_jumbf_generation() {
    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("test.avi");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Create a new claim.
    let mut claim2 = Claim::new("Photoshop", Some("Adobe"), 1);
    create_editing_claim(&mut claim2).unwrap();

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
    create_capture_claim(&mut claim_capture).unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            &signer,
            &context,
        )
        .unwrap();
    store.commit_claim(claim_capture).unwrap();
    output_stream.rewind().unwrap();
    let mut temp_stream = Cursor::new(Vec::new());
    store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut temp_stream,
            &signer,
            &context,
        )
        .unwrap();
    store.commit_claim(claim2).unwrap();
    temp_stream.rewind().unwrap();
    output_stream.rewind().unwrap();
    store
        .save_to_stream(
            format,
            &mut temp_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // write to new file
    println!("Provenance: {}\n", store.provenance_path().unwrap());

    let mut report = StatusTracker::default();

    // can  we get by the ingredient data back
    let _some_binary_data: Vec<u8> = vec![
        0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d, 0x0b,
        0x0e,
    ];

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // dump store and compare to original
    for claim in new_store.claims() {
        let _restored_json = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();
        let _orig_json = store
            .get_claim(claim.label())
            .unwrap()
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();

        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim
                .get_claim_assertion(&label, instance)
                .expect("Should find assertion");
        }
    }
}

#[test]
fn test_webp_jumbf_generation() {
    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("sample1.webp");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Create a new claim.
    let mut claim2 = Claim::new("Photoshop", Some("Adobe"), 1);
    create_editing_claim(&mut claim2).unwrap();

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
    create_capture_claim(&mut claim_capture).unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            &signer,
            &context,
        )
        .unwrap();
    store.commit_claim(claim_capture).unwrap();
    output_stream.rewind().unwrap();
    let mut temp_stream = Cursor::new(Vec::new());
    store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut temp_stream,
            &signer,
            &context,
        )
        .unwrap();
    store.commit_claim(claim2).unwrap();
    temp_stream.rewind().unwrap();
    output_stream.rewind().unwrap();
    store
        .save_to_stream(
            format,
            &mut temp_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // write to new file
    println!("Provenance: {}\n", store.provenance_path().unwrap());

    let mut report = StatusTracker::default();

    // can  we get by the ingredient data back
    let _some_binary_data: Vec<u8> = vec![
        0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d, 0x0b,
        0x0e,
    ];

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // dump store and compare to original
    for claim in new_store.claims() {
        let _restored_json = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();
        let _orig_json = store
            .get_claim(claim.label())
            .unwrap()
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();

        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim
                .get_claim_assertion(&label, instance)
                .expect("Should find assertion");
        }
    }
}

#[test]
fn test_heic() {
    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("sample1.heic");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // dump store and compare to original
    for claim in new_store.claims() {
        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim
                .get_claim_assertion(&label, instance)
                .expect("Should find assertion");
        }
    }
}

#[test]
fn test_avif() {
    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("sample1.avif");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // dump store and compare to original
    for claim in new_store.claims() {
        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim
                .get_claim_assertion(&label, instance)
                .expect("Should find assertion");
        }
    }
}

#[test]
fn test_heif() {
    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("sample1.heif");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // read from new stream
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    // dump store and compare to original
    for claim in new_store.claims() {
        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim
                .get_claim_assertion(&label, instance)
                .expect("Should find assertion");
        }
    }
}

/*  todo: disable until we can generate a valid file with no xmp
#[test]
fn test_manifest_no_xmp() {
    let ap = fixture_path("CAICAI_NO_XMP.jpg");
    assert!(Store::load_from_asset(&ap, true, None).is_ok());
}
*/

#[test]
#[ignore = "This is not generating the expected error. Needs investigation."]
fn test_manifest_bad_sig() {
    let context = Context::new();
    let (format, mut input_stream, _output_stream) = create_test_streams("CIE-sig-CA.jpg");
    let tracker = &mut StatusTracker::default();
    let result = Store::from_stream(format, &mut input_stream, tracker, &context);
    assert!(result.is_ok());
    println!("Error report: {tracker:?}");
    assert!(tracker.has_error(Error::AssertionInvalidRedaction));
}

#[test]
fn test_unsupported_type_without_external_manifest() {
    let context = Context::new();
    let (format, mut input_stream, _output_stream) = create_test_streams("unsupported_type.txt");
    let mut report = StatusTracker::default();
    let result = Store::from_stream(format, &mut input_stream, &mut report, &context);
    assert!(matches!(result, Err(Error::UnsupportedType)));
    println!("Error report: {report:?}");
    assert!(!report.logged_items().is_empty());

    assert!(report.has_error(Error::UnsupportedType));
}

#[test]
fn test_bad_jumbf() {
    // test bad jumbf
    let (format, mut input_stream, _output_stream) = create_test_streams("prerelease.jpg");
    let mut report = StatusTracker::default();
    let _r = Store::from_stream(format, &mut input_stream, &mut report, &Context::new());

    // error report
    println!("Error report: {report:?}");
    assert!(!report.logged_items().is_empty());

    assert!(report.has_error(Error::PrereleaseError));
}

#[test]
fn test_detect_byte_change() {
    // test bad jumbf
    let (format, mut input_stream, _output_stream) = create_test_streams("XCA.jpg");
    let mut report = StatusTracker::default();
    Store::from_stream(format, &mut input_stream, &mut report, &Context::new()).unwrap();

    // error report
    println!("Error report: {report:?}");
    assert!(!report.logged_items().is_empty());

    assert!(report.has_status(validation_status::ASSERTION_DATAHASH_MISMATCH));
}

// #[test]
// #[cfg(feature = "file_io")]
// fn test_file_not_found() {
//     let ap = fixture_path("this_does_not_exist.jpg");
//     let mut report = StatusTracker::default();
//     let _result = Store::load_from_asset(&ap, true, &mut report);

//     println!(
//         "Error report for {}: {:?}",
//         ap.display(),
//         report.logged_items()
//     );

//     assert!(!report.logged_items().is_empty());

//     let errors: Vec<&LogItem> = report.filter_errors().collect();
//     assert!(errors[0].err_val.as_ref().unwrap().starts_with("IoError"));
// }

#[test]
fn test_old_manifest() {
    let (format, mut input_stream, _output_stream) = create_test_streams("prerelease.jpg");
    let mut report = StatusTracker::default();
    let _r = Store::from_stream(format, &mut input_stream, &mut report, &Context::new());

    println!("Error report: {report:?}");

    assert!(!report.logged_items().is_empty());

    let errors: Vec<&LogItem> = report.filter_errors().collect();
    assert!(errors[0]
        .err_val
        .as_ref()
        .unwrap()
        .starts_with("Prerelease"));
}

#[test]
fn test_verifiable_credentials() {
    use crate::utils::test::create_test_store_v1;

    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    let signer = test_signer(SigningAlg::Ps256);

    // get default store with default claim
    let mut store = create_test_store_v1().unwrap();

    // save to output
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // read back in
    output_stream.rewind().unwrap();
    let restored_store = Store::from_stream(
        format,
        &mut output_stream,
        &mut StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError),
        &context,
    )
    .unwrap();

    let pc = restored_store.provenance_claim().unwrap();

    let vc = pc.get_verifiable_credentials();

    assert!(!vc.is_empty());
    match &vc[0] {
        AssertionData::Json(s) => {
            assert!(s.contains("did:nppa:eb1bb9934d9896a374c384521410c7f14"))
        }
        _ => panic!("expected JSON assertion data"),
    }
}

#[test]
fn test_data_box_creation() {
    use crate::utils::test::create_test_store_v1;

    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    let signer = test_signer(SigningAlg::Ps256);

    // get default store with default claim
    let mut store = create_test_store_v1().unwrap();

    // save to output
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // read back in
    output_stream.rewind().unwrap();
    let restored_store = Store::from_stream(
        format,
        &mut output_stream,
        &mut StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError),
        &context,
    )
    .unwrap();

    let pc = restored_store.provenance_claim().unwrap();

    let databoxes = pc.databoxes();

    assert!(!databoxes.is_empty());

    for (uri, db) in databoxes {
        println!(
            "URI: {}, data: {}",
            uri.url(),
            String::from_utf8_lossy(&db.data)
        );
    }
}

/// loads a fixture, replaces some bytes in memory and returns a validation report
fn patch_and_report(
    fixture_name: &str,
    search_bytes: &[u8],
    replace_bytes: &[u8],
) -> StatusTracker {
    // Create test streams from fixture
    let (format, input_stream, _output_stream) = create_test_streams(fixture_name);

    // Get the data from the input stream and patch it
    let mut data = input_stream.into_inner();
    patch_bytes(&mut data, search_bytes, replace_bytes).expect("patch_bytes");

    // Create new stream from patched data
    let mut patched_stream = std::io::Cursor::new(data);

    let mut report = StatusTracker::default();
    let _r = Store::from_stream(format, &mut patched_stream, &mut report, &Context::new()); // errs are in report
    println!("report: {report:?}");
    report
}

#[test]
fn test_update_manifest_v1() {
    use crate::{hashed_uri::HashedUri, utils::test::create_test_store_v1};

    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");
    let signer = test_signer(SigningAlg::Ps256);

    // get default store with default claim
    let mut store = create_test_store_v1().unwrap();

    // save to output
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    // read back in
    output_stream.rewind().unwrap();
    let restored_store =
        Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();
    let pc = restored_store.provenance_claim().unwrap();

    // should be a regular manifest
    assert!(!pc.update_manifest());

    // create a new update manifest
    let mut claim = Claim::new("adobe unit test", Some("update_manifest"), 1);
    output_stream.rewind().unwrap();
    let mut new_store = Store::load_ingredient_to_claim(
        &mut claim,
        &load_jumbf_from_stream(format, &mut output_stream).unwrap(),
        None,
        &context,
    )
    .unwrap();

    let ingredient_hashes = new_store.get_manifest_box_hashes(pc);
    let parent_hashed_uri = HashedUri::new(
        restored_store.provenance_path().unwrap(),
        Some(pc.alg().to_string()),
        &ingredient_hashes.manifest_box_hash,
    );

    let ingredient = Ingredient::new_v2("update_manifest.jpg", "image/jpeg")
        .set_parent()
        .set_c2pa_manifest_from_hashed_uri(Some(parent_hashed_uri));

    claim.add_assertion(&ingredient).unwrap();

    new_store.commit_update_manifest(claim).unwrap();
    output_stream.rewind().unwrap();
    let mut output_stream2 = std::io::Cursor::new(Vec::new());
    new_store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut output_stream2,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // read back in store with update manifest
    output_stream2.rewind().unwrap();
    let um_store = Store::from_stream(format, &mut output_stream2, &mut report, &context).unwrap();

    let um = um_store.provenance_claim().unwrap();

    // should be an update manifest
    assert!(um.update_manifest());

    // should not have any errors
    assert!(!report.has_any_error());
}

///Test for Update Manifest V2
#[test]
fn test_update_manifest_v2() {
    use crate::{
        hashed_uri::HashedUri, jumbf::labels::to_signature_uri, utils::test::create_test_store_v1,
        ClaimGeneratorInfo, ValidationResults,
    };

    let context = crate::context::Context::new();

    let signer = test_signer(SigningAlg::Ps256);

    // Create test streams from fixture
    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    // get default store with default claim
    let mut store = create_test_store_v1().unwrap();

    // save to output
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    // read back in
    output_stream.rewind().unwrap();
    let ingredient_vec = output_stream.get_ref().clone();
    let mut ingredient_stream = Cursor::new(ingredient_vec);
    let restored_store =
        Store::from_stream(format, &mut ingredient_stream, &mut report, &context).unwrap();
    let pc = restored_store.provenance_claim().unwrap();

    // should be a regular manifest
    assert!(!pc.update_manifest());

    // create a new update manifest
    let mut claim = Claim::new("adobe unit test", Some("update_manifest_vendor"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    claim.add_claim_generator_info(cgi);

    ingredient_stream.rewind().unwrap();
    let (manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut ingredient_stream, &context).unwrap();
    let mut new_store =
        Store::load_ingredient_to_claim(&mut claim, &manifest_bytes, None, &context).unwrap();

    let ingredient_hashes = new_store.get_manifest_box_hashes(pc);
    let parent_hashed_uri = HashedUri::new(
        restored_store.provenance_path().unwrap(),
        Some(pc.alg().to_string()),
        &ingredient_hashes.manifest_box_hash,
    );
    let signature_hashed_uri = HashedUri::new(
        to_signature_uri(pc.label()),
        Some(pc.alg().to_string()),
        &ingredient_hashes.signature_box_hash,
    );

    let validation_results = ValidationResults::from_store(&restored_store, &report);

    let ingredient = Ingredient::new_v3(Relationship::ParentOf)
        .set_active_manifests_and_signature_from_hashed_uri(
            Some(parent_hashed_uri),
            Some(signature_hashed_uri),
        ) // mandatory for v3
        .set_validation_results(Some(validation_results)); // mandatory for v3

    claim.add_assertion(&ingredient).unwrap();

    // create mandatory opened action (optional for update manifest)
    let ingredient = claim.ingredient_assertions()[0];
    let ingregient_uri = to_assertion_uri(claim.label(), &ingredient.label());
    let ingredient_hashed_uri = HashedUri::new(
        ingregient_uri,
        Some(claim.alg().to_owned()),
        ingredient.hash(),
    );

    let opened = Action::new("c2pa.opened")
        .set_parameter("ingredients", vec![ingredient_hashed_uri])
        .unwrap();
    let em = Action::new("c2pa.edited.metadata");
    let actions = Actions::new().add_action(opened).add_action(em);

    // add action (this is optional for update manifest)
    claim.add_assertion(&actions).unwrap();

    /* sample of adding timestamp assertion

    // lets add a timestamp for old manifest
    let timestamp = send_timestamp_request(pc.signature_val()).unwrap();
    crate::crypto::time_stamp::verify_time_stamp(&timestamp, pc.signature_val()).unwrap();
    let timestamp_assertion = crate::assertions::TimeStamp::new(pc.label(), &timestamp);
    claim.add_assertion(&timestamp_assertion).unwrap();
    */

    new_store.commit_update_manifest(claim).unwrap();
    output_stream.rewind().unwrap();
    let mut output_stream2 = std::io::Cursor::new(Vec::new());
    new_store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut output_stream2,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut um_report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    // read back in store with update manifest
    output_stream2.rewind().unwrap();
    let um_store =
        Store::from_stream(format, &mut output_stream2, &mut um_report, &context).unwrap();

    let um = um_store.provenance_claim().unwrap();

    // should be an update manifest
    assert!(um.update_manifest());

    // should not have any errors
    assert!(!um_report.has_any_error());
}

#[test]
#[cfg(feature = "file_io")]
fn test_update_manifest_v2_bmff() {
    use crate::{
        hashed_uri::HashedUri, jumbf::labels::to_signature_uri, ClaimGeneratorInfo,
        ValidationResults,
    };

    let context = crate::context::Context::new();

    let signer = test_signer(SigningAlg::Ps256);

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("video1.mp4");

    let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    // read in the store
    let mut store = Store::from_stream(format, &mut input_stream, &mut report, &context).unwrap();
    let pc = store.provenance_claim().unwrap();

    // create a new update manifest
    let mut claim = Claim::new("adobe unit test", Some("update_manifest_vendor"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    claim.add_claim_generator_info(cgi);

    let ingredient_hashes = store.get_manifest_box_hashes(pc);
    let parent_hashed_uri = HashedUri::new(
        store.provenance_path().unwrap(),
        Some(pc.alg().to_string()),
        &ingredient_hashes.manifest_box_hash,
    );
    let signature_hashed_uri = HashedUri::new(
        to_signature_uri(pc.label()),
        Some(pc.alg().to_string()),
        &ingredient_hashes.signature_box_hash,
    );

    let validation_results = ValidationResults::from_store(&store, &report);

    let ingredient = Ingredient::new_v3(Relationship::ParentOf)
        .set_active_manifests_and_signature_from_hashed_uri(
            Some(parent_hashed_uri),
            Some(signature_hashed_uri),
        ) // mandatory for v3
        .set_validation_results(Some(validation_results)); // mandatory for v3

    claim.add_assertion(&ingredient).unwrap();

    // create mandatory opened action (optional for update manifest)
    let ingredient = claim.ingredient_assertions()[0];
    let ingregient_uri = to_assertion_uri(claim.label(), &ingredient.label());
    let ingredient_hashed_uri = HashedUri::new(
        ingregient_uri,
        Some(claim.alg().to_owned()),
        ingredient.hash(),
    );

    let opened = Action::new("c2pa.opened")
        .set_parameter("ingredients", vec![ingredient_hashed_uri])
        .unwrap();
    let em = Action::new("c2pa.edited.metadata");
    let actions = Actions::new().add_action(opened).add_action(em);

    // add action (this is optional for update manifest)
    claim.add_assertion(&actions).unwrap();

    store.commit_update_manifest(claim).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut um_report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    // read back in store with update manifest
    output_stream.rewind().unwrap();
    let mut um_store =
        Store::from_stream(format, &mut output_stream, &mut um_report, &context).unwrap();

    let um = um_store.provenance_claim().unwrap();

    // should be an update manifest
    assert!(um.update_manifest());

    // should have valid bmff hash binding
    assert!(um_report.has_status(validation_status::ASSERTION_BMFFHASH_MATCH));

    // now add a new oridinary manifest to restore the original manifest (collapsed manifest)

    // create a new ordinary claim
    let mut claim2 = Claim::new("adobe unit test", Some("ordinary_manifest_vendor"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    claim2.add_claim_generator_info(cgi);

    // make update PC claim the parent of the ordinary claim
    let update_pc = um_store.provenance_claim().unwrap();
    let ingredient_hashes = um_store.get_manifest_box_hashes(update_pc);
    let parent_hashed_uri = HashedUri::new(
        um_store.provenance_path().unwrap(),
        Some(update_pc.alg().to_string()),
        &ingredient_hashes.manifest_box_hash,
    );
    let signature_hashed_uri = HashedUri::new(
        to_signature_uri(update_pc.label()),
        Some(update_pc.alg().to_string()),
        &ingredient_hashes.signature_box_hash,
    );

    let validation_results = ValidationResults::from_store(&um_store, &report);

    let ingredient = Ingredient::new_v3(Relationship::ParentOf)
        .set_active_manifests_and_signature_from_hashed_uri(
            Some(parent_hashed_uri),
            Some(signature_hashed_uri),
        ) // mandatory for v3
        .set_validation_results(Some(validation_results)); // mandatory for v3

    claim2.add_assertion(&ingredient).unwrap();

    // create mandatory opened action
    let ingredient = claim2.ingredient_assertions()[0];
    let ingregient_uri = to_assertion_uri(claim2.label(), &ingredient.label());
    let ingredient_hashed_uri = HashedUri::new(
        ingregient_uri,
        Some(claim2.alg().to_owned()),
        ingredient.hash(),
    );

    let opened = Action::new("c2pa.opened")
        .set_parameter("ingredients", vec![ingredient_hashed_uri])
        .unwrap();
    let editted = Action::new("c2pa.edited");
    let actions = Actions::new().add_action(opened).add_action(editted);

    // add action
    claim2.add_assertion(&actions).unwrap();

    um_store.commit_claim(claim2).unwrap();
    output_stream.rewind().unwrap();
    let mut output_stream2 = Cursor::new(Vec::new());
    um_store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut output_stream2,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut collapsed_report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    // read back in store with update manifest
    output_stream2.rewind().unwrap();
    let collapsed_store =
        Store::from_stream(format, &mut output_stream2, &mut collapsed_report, &context).unwrap();

    let cm = collapsed_store.provenance_claim().unwrap();
    assert!(!cm.update_manifest());

    // should have valid bmff hash binding
    assert!(collapsed_report.has_status(validation_status::ASSERTION_BMFFHASH_MATCH));
}

#[test]
#[cfg(feature = "file_io")]
fn test_update_manifest_with_timestamp_assertion() {
    // add timestamp assertion to update manifest
    let (format, mut input_stream, _output_stream) = create_test_streams("update_manifest.jpg");

    let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let restored_store =
        Store::from_stream(format, &mut input_stream, &mut report, &Context::new()).unwrap();
    let pc = restored_store.provenance_claim().unwrap();

    // should be an update manifest
    assert!(pc.update_manifest());
}

#[test]
fn test_ingredient_conflict_with_current_manifest() {
    use crate::{
        hashed_uri::HashedUri, jumbf::labels::to_signature_uri, utils::test::create_test_store_v1,
        ClaimGeneratorInfo, ValidationResults,
    };

    let context = crate::context::Context::new();

    let signer = test_signer(SigningAlg::Ps256);

    // Create test streams from fixture
    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    // get default store with default claim
    let mut store = create_test_store_v1().unwrap();

    // save to output
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    // read back in
    output_stream.rewind().unwrap();
    let ingredient_vec = output_stream.get_ref().clone();
    let mut ingredient_stream = Cursor::new(ingredient_vec.clone());
    let restored_store =
        Store::from_stream(format, &mut ingredient_stream, &mut report, &context).unwrap();
    let pc = restored_store.provenance_claim().unwrap();

    // should be a regular manifest
    assert!(!pc.update_manifest());

    // create a new update manifest
    let mut claim = Claim::new("adobe unit test", Some("update_manifest_1"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    claim.add_claim_generator_info(cgi);

    // created redacted uri
    let redacted_uri = to_assertion_uri(pc.label(), labels::SCHEMA_ORG);

    let (manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(ingredient_vec.clone()), &context)
            .unwrap();
    let mut redacted_store = Store::load_ingredient_to_claim(
        &mut claim,
        &manifest_bytes,
        Some(vec![redacted_uri]),
        &context,
    )
    .unwrap();

    let ingredient_hashes = restored_store.get_manifest_box_hashes(pc);
    let parent_hashed_uri = HashedUri::new(
        restored_store.provenance_path().unwrap(),
        Some(pc.alg().to_string()),
        &ingredient_hashes.manifest_box_hash,
    );
    let signature_hashed_uri = HashedUri::new(
        to_signature_uri(pc.label()),
        Some(pc.alg().to_string()),
        &ingredient_hashes.signature_box_hash,
    );

    let validation_results = ValidationResults::from_store(&restored_store, &report);

    let ingredient = Ingredient::new_v3(Relationship::ParentOf)
        .set_active_manifests_and_signature_from_hashed_uri(
            Some(parent_hashed_uri),
            Some(signature_hashed_uri),
        ) // mandatory for v3
        .set_validation_results(Some(validation_results)); // mandatory for v3

    claim.add_assertion(&ingredient).unwrap();

    // create mandatory opened action (optional for update manifest)
    let ingredient = claim.ingredient_assertions()[0];
    let ingregient_uri = to_assertion_uri(claim.label(), &ingredient.label());
    let ingredient_hashed_uri = HashedUri::new(
        ingregient_uri,
        Some(claim.alg().to_owned()),
        ingredient.hash(),
    );

    let opened = Action::new("c2pa.opened")
        .set_parameter("ingredients", vec![ingredient_hashed_uri])
        .unwrap();
    let em = Action::new("c2pa.edited.metadata");
    let actions = Actions::new().add_action(opened).add_action(em);

    // add action (this is optional for update manifest)
    claim.add_assertion(&actions).unwrap();

    redacted_store.commit_update_manifest(claim).unwrap();
    output_stream.rewind().unwrap();
    let mut output_stream2 = std::io::Cursor::new(Vec::new());
    redacted_store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut output_stream2,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut um_report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    // read back in store with update manifest
    output_stream2.rewind().unwrap();
    let um_store =
        Store::from_stream(format, &mut output_stream2, &mut um_report, &context).unwrap();

    let um = um_store.provenance_claim().unwrap();

    // should be an update manifest
    assert!(um.update_manifest());

    // should not have any errors
    assert!(!um_report.has_any_error());

    // add ingredient again without redaction to make sure conflict is resolved with current redaction
    let mut new_claim = Claim::new("adobe unit test", Some("update_manifest_2"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    new_claim.add_claim_generator_info(cgi);

    // load ingredient with redaction
    output_stream2.rewind().unwrap();
    let (redacted_manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut output_stream2, &context).unwrap();
    Store::load_ingredient_to_claim(&mut new_claim, &redacted_manifest_bytes, None, &context)
        .unwrap();

    // load original ingredient without redaction
    let (original_manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(ingredient_vec), &context).unwrap();
    let _conflict_store =
        Store::load_ingredient_to_claim(&mut new_claim, &original_manifest_bytes, None, &context)
            .unwrap();

    // the confict_store is adjusted to remove the conflicting claim
    let redacted_claim = new_claim.claim_ingredient(pc.label()).unwrap();
    assert!(redacted_claim
        .get_assertion(labels::SCHEMA_ORG, 0)
        .is_none());
}

#[test]
fn test_ingredient_conflict_with_incoming_manifest() {
    use crate::{
        hashed_uri::HashedUri, jumbf::labels::to_signature_uri, utils::test::create_test_store_v1,
        ClaimGeneratorInfo, ValidationResults,
    };

    let context = Context::new();

    let signer = test_signer(SigningAlg::Ps256);

    // Create test streams from fixture
    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    // get default store with default claim
    let mut store = create_test_store_v1().unwrap();

    // save to output
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    // read back in
    output_stream.rewind().unwrap();
    let ingredient_vec = output_stream.get_ref().clone();
    let mut ingredient_stream = Cursor::new(ingredient_vec.clone());
    let restored_store =
        Store::from_stream(format, &mut ingredient_stream, &mut report, &context).unwrap();

    let pc = restored_store.provenance_claim().unwrap();

    // should be a regular manifest
    assert!(!pc.update_manifest());

    // create a new update manifest
    let mut claim = Claim::new("adobe unit test", Some("update_manifest_1"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    claim.add_claim_generator_info(cgi);

    // created redacted uri
    let redacted_uri = to_assertion_uri(pc.label(), labels::SCHEMA_ORG);

    let (manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(ingredient_vec.clone()), &context)
            .unwrap();

    let mut redacted_store = Store::load_ingredient_to_claim(
        &mut claim,
        &manifest_bytes,
        Some(vec![redacted_uri]),
        &context,
    )
    .unwrap();

    let ingredient_hashes = restored_store.get_manifest_box_hashes(pc);
    let parent_hashed_uri = HashedUri::new(
        restored_store.provenance_path().unwrap(),
        Some(pc.alg().to_string()),
        &ingredient_hashes.manifest_box_hash,
    );
    let signature_hashed_uri = HashedUri::new(
        to_signature_uri(pc.label()),
        Some(pc.alg().to_string()),
        &ingredient_hashes.signature_box_hash,
    );

    let validation_results = ValidationResults::from_store(&restored_store, &report);

    let ingredient = Ingredient::new_v3(Relationship::ParentOf)
        .set_active_manifests_and_signature_from_hashed_uri(
            Some(parent_hashed_uri),
            Some(signature_hashed_uri),
        ) // mandatory for v3
        .set_validation_results(Some(validation_results)); // mandatory for v3

    claim.add_assertion(&ingredient).unwrap();

    // create mandatory opened action (optional for update manifest)
    let ingredient = claim.ingredient_assertions()[0];
    let ingregient_uri = to_assertion_uri(claim.label(), &ingredient.label());
    let ingredient_hashed_uri = HashedUri::new(
        ingregient_uri,
        Some(claim.alg().to_owned()),
        ingredient.hash(),
    );

    let opened = Action::new("c2pa.opened")
        .set_parameter("ingredients", vec![ingredient_hashed_uri])
        .unwrap();
    let em = Action::new("c2pa.edited.metadata");
    let actions = Actions::new().add_action(opened).add_action(em);

    // add action (this is optional for update manifest)
    claim.add_assertion(&actions).unwrap();

    redacted_store.commit_update_manifest(claim).unwrap();
    output_stream.rewind().unwrap();
    let mut output_stream2 = std::io::Cursor::new(Vec::new());
    redacted_store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut output_stream2,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut um_report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    // read back in store with update manifest
    output_stream2.rewind().unwrap();
    let um_store =
        Store::from_stream(format, &mut output_stream2, &mut um_report, &context).unwrap();

    let um = um_store.provenance_claim().unwrap();

    // should be an update manifest
    assert!(um.update_manifest());

    // should not have any errors
    assert!(!um_report.has_any_error());

    // add ingredient again without redaction to make sure conflict is resolved with current redaction
    let mut new_claim = Claim::new("adobe unit test", Some("update_manifest_2"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    new_claim.add_claim_generator_info(cgi);

    // load original ingredient without redaction
    let (original_manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(ingredient_vec), &context).unwrap();
    Store::load_ingredient_to_claim(&mut new_claim, &original_manifest_bytes, None, &context)
        .unwrap();

    // the confict_store is adjusted to remove the conflicting claim
    let not_redacted_claim = new_claim.claim_ingredient(pc.label()).unwrap();
    assert!(not_redacted_claim
        .get_assertion(labels::SCHEMA_ORG, 0)
        .is_some());

    // load ingredient with redaction
    output_stream2.rewind().unwrap();

    let (redacted_manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut output_stream2, &context).unwrap();
    Store::load_ingredient_to_claim(&mut new_claim, &redacted_manifest_bytes, None, &context)
        .unwrap();

    // the confict_store is adjusted to remove the conflicting claim
    let redacted_claim = new_claim.claim_ingredient(pc.label()).unwrap();
    assert!(redacted_claim
        .get_assertion(labels::SCHEMA_ORG, 0)
        .is_none());
}

#[test]
#[cfg(feature = "file_io")]
fn test_ingredient_conflicting_redactions_to_same_manifest() {
    use crate::{
        hashed_uri::HashedUri, jumbf::labels::to_signature_uri, utils::test::create_test_store_v1,
        ClaimGeneratorInfo, ValidationResults,
    };

    let context = Context::new();

    let signer = test_signer(SigningAlg::Ps256);

    // Create test streams from fixture
    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");

    // get default store with default claim
    let mut store = create_test_store_v1().unwrap();

    // save to output
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    // read back in
    output_stream.rewind().unwrap();
    let restored_store =
        Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();
    let pc = restored_store.provenance_claim().unwrap();

    // should be a regular manifest
    assert!(!pc.update_manifest());

    // create a new update manifest
    let mut claim = Claim::new("adobe unit test", Some("update_manifest_1"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    claim.add_claim_generator_info(cgi.clone());

    // created redacted uri
    let redacted_uri = to_assertion_uri(pc.label(), labels::SCHEMA_ORG);

    output_stream.rewind().unwrap();
    let ingredient_vec = load_jumbf_from_stream(format, &mut output_stream).unwrap();
    let mut redacted_store = Store::load_ingredient_to_claim(
        &mut claim,
        &ingredient_vec,
        Some(vec![redacted_uri]),
        &context,
    )
    .unwrap();

    let ingredient_hashes = restored_store.get_manifest_box_hashes(pc);
    let parent_hashed_uri = HashedUri::new(
        restored_store.provenance_path().unwrap(),
        Some(pc.alg().to_string()),
        &ingredient_hashes.manifest_box_hash,
    );
    let signature_hashed_uri = HashedUri::new(
        to_signature_uri(pc.label()),
        Some(pc.alg().to_string()),
        &ingredient_hashes.signature_box_hash,
    );

    let validation_results = ValidationResults::from_store(&restored_store, &report);

    let ingredient = Ingredient::new_v3(Relationship::ParentOf)
        .set_active_manifests_and_signature_from_hashed_uri(
            Some(parent_hashed_uri),
            Some(signature_hashed_uri),
        ) // mandatory for v3
        .set_validation_results(Some(validation_results)); // mandatory for v3

    claim.add_assertion(&ingredient).unwrap();

    // create mandatory opened action (optional for update manifest)
    let ingredient = claim.ingredient_assertions()[0];
    let ingregient_uri = to_assertion_uri(claim.label(), &ingredient.label());
    let ingredient_hashed_uri = HashedUri::new(
        ingregient_uri,
        Some(claim.alg().to_owned()),
        ingredient.hash(),
    );

    let opened = Action::new("c2pa.opened")
        .set_parameter("ingredients", vec![ingredient_hashed_uri])
        .unwrap();
    let em = Action::new("c2pa.edited.metadata");
    let actions = Actions::new().add_action(opened).add_action(em);

    // add action (this is optional for update manifest)
    claim.add_assertion(&actions).unwrap();

    redacted_store.commit_update_manifest(claim).unwrap();
    output_stream.rewind().unwrap();
    let mut op_output = std::io::Cursor::new(Vec::new());
    redacted_store
        .save_to_stream(
            format,
            &mut output_stream,
            &mut op_output,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut um_report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    // read back in store with update manifest
    op_output.rewind().unwrap();
    let um_store = Store::from_stream(format, &mut op_output, &mut um_report, &context).unwrap();

    let um = um_store.provenance_claim().unwrap();

    // should be an update manifest
    assert!(um.update_manifest());

    // should not have any errors
    assert!(!um_report.has_any_error());

    // save a different redaction to the same manifest
    let mut claim2 = Claim::new("adobe unit test", Some("update_manifest_1"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    claim2.add_claim_generator_info(cgi);

    // created redacted uri
    let redacted_uri2 = to_assertion_uri(pc.label(), TEST_USER_ASSERTION);

    let mut redacted_store2 = Store::load_ingredient_to_claim(
        &mut claim2,
        &ingredient_vec,
        Some(vec![redacted_uri2]),
        &context,
    )
    .unwrap();

    let ingredient_hashes2 = restored_store.get_manifest_box_hashes(pc);
    let parent_hashed_uri2 = HashedUri::new(
        restored_store.provenance_path().unwrap(),
        Some(pc.alg().to_string()),
        &ingredient_hashes2.manifest_box_hash,
    );
    let signature_hashed_uri2 = HashedUri::new(
        to_signature_uri(pc.label()),
        Some(pc.alg().to_string()),
        &ingredient_hashes2.signature_box_hash,
    );

    let validation_results2 = ValidationResults::from_store(&restored_store, &report);

    let ingredient2 = Ingredient::new_v3(Relationship::ParentOf)
        .set_active_manifests_and_signature_from_hashed_uri(
            Some(parent_hashed_uri2),
            Some(signature_hashed_uri2),
        ) // mandatory for v3
        .set_validation_results(Some(validation_results2)); // mandatory for v3

    claim2.add_assertion(&ingredient2).unwrap();

    // create mandatory opened action (optional for update manifest)
    let ingredient2 = claim2.ingredient_assertions()[0];
    let ingregient_uri2 = to_assertion_uri(claim2.label(), &ingredient2.label());
    let ingredient_hashed_uri2 = HashedUri::new(
        ingregient_uri2,
        Some(claim2.alg().to_owned()),
        ingredient2.hash(),
    );

    let opened2 = Action::new("c2pa.opened")
        .set_parameter("ingredients", vec![ingredient_hashed_uri2])
        .unwrap();
    let em2 = Action::new("c2pa.edited.metadata");
    let actions2 = Actions::new().add_action(opened2).add_action(em2);

    // add action (this is optional for update manifest)
    claim2.add_assertion(&actions2).unwrap();

    redacted_store2.commit_update_manifest(claim2).unwrap();
    output_stream.rewind().unwrap();
    let mut op2_output = std::io::Cursor::new(Vec::new());
    redacted_store2
        .save_to_stream(
            format,
            &mut output_stream,
            &mut op2_output,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // add ingredient again without redaction to make sure conflict is resolved with current redaction
    let mut new_claim = Claim::new("adobe unit test", Some("update_manifest_2"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    new_claim.add_claim_generator_info(cgi);

    // load ingredient with SCHEMA_ORG redaction
    op_output.rewind().unwrap();
    Store::load_ingredient_to_claim(
        &mut new_claim,
        &load_jumbf_from_stream(format, &mut op_output).unwrap(),
        None,
        &context,
    )
    .unwrap();

    // load original ingredient with TEST_USER_ASSERTION redaction
    op2_output.rewind().unwrap();
    Store::load_ingredient_to_claim(
        &mut new_claim,
        &load_jumbf_from_stream(format, &mut op2_output).unwrap(),
        None,
        &context,
    )
    .unwrap();

    // Check that both redactions are present
    let redacted_claim = new_claim.claim_ingredient(pc.label()).unwrap();
    assert!(redacted_claim
        .get_assertion(labels::SCHEMA_ORG, 0)
        .is_none());

    assert!(redacted_claim
        .get_assertion(TEST_USER_ASSERTION, 0)
        .is_none());
}

#[test]
fn test_claim_decoding() {
    // modify a required field label in the claim - causes failure to read claim from cbor
    let report = patch_and_report("C.jpg", b"claim_generator", b"claim_generatur");
    assert!(!report.logged_items().is_empty());
    assert!(report.logged_items()[0]
        .err_val
        .as_ref()
        .unwrap()
        .starts_with("ClaimDecoding"))
}

#[test]
fn test_claim_modified() {
    // replace the title that is inside the claim data - should cause signature to not match
    let report = patch_and_report("C.jpg", b"C.jpg", b"X.jpg");
    assert!(!report.logged_items().is_empty());
    // note in the older validation statuses, this was an error, but now it is informational
    assert!(report.has_status(validation_status::TIMESTAMP_MISMATCH));
}

#[test]
fn test_assertion_hash_mismatch() {
    // modifies content of an action assertion - causes an assertion hashuri mismatch
    let report = patch_and_report("CA.jpg", b"brightnesscontrast", b"brightnesscontraxx");
    let first_error = report.filter_errors().next().cloned().unwrap();

    assert_eq!(
        first_error.validation_status.as_deref(),
        Some(validation_status::ASSERTION_HASHEDURI_MISMATCH)
    );
}

#[test]
fn test_claim_missing() {
    // patch jumbf url from c2pa_manifest field in an ingredient to cause claim_missing
    // note this includes hex for Jumbf blocks, so may need some manual tweaking
    const SEARCH_BYTES: &[u8] =
        b"c2pa_manifest\xA3\x63url\x78\x4aself#jumbf=/c2pa/contentauth:urn:uuid:";
    const REPLACE_BYTES: &[u8] =
        b"c2pa_manifest\xA3\x63url\x78\x4aself#jumbf=/c2pa/contentauth:urn:uuix:";
    let report = patch_and_report("CIE-sig-CA.jpg", SEARCH_BYTES, REPLACE_BYTES);

    assert!(report.has_status(validation_status::ASSERTION_HASHEDURI_MISMATCH));
    assert!(report.has_status(validation_status::CLAIM_MISSING));
}

#[test]
fn test_display() {
    let context = Context::new();
    let (format, mut input_stream, _output_stream) = create_test_streams("CA.jpg");

    let mut report = StatusTracker::default();
    let store =
        Store::from_stream(format, &mut input_stream, &mut report, &context).expect("from_stream");

    assert!(!report.has_any_error());
    println!("store = {store}");
}

#[test]
fn test_no_alg() {
    let (format, mut input_stream, _output_stream) = create_test_streams("no_alg.jpg");
    let mut report = StatusTracker::default();
    let _store = Store::from_stream(format, &mut input_stream, &mut report, &Context::new());

    assert!(report.has_status(ALGORITHM_UNSUPPORTED));
}

/// sample of adding timestamp assertion
/*fn send_timestamp_request(message: &[u8]) -> Result<Vec<u8>> {
    let url = "http://timestamp.digicert.com";

    let body = crate::crypto::time_stamp::default_rfc3161_message(message)?;
    let headers = None;

    let bytes =
        crate::crypto::time_stamp::default_rfc3161_request(url, headers, &body, message)
            .map_err(|_e| Error::OtherError("timestamp token not found".into()))?;

    let token = crate::crypto::cose::timestamptoken_from_timestamprsp(&bytes)
        .ok_or(Error::OtherError("timestamp token not found".into()))?;

    Ok(token)
}*/

#[test]
fn test_legacy_ingredient_hash() {
    let context = Context::new();
    // test 1.0 ingredient hash
    let (format, input_stream, _output_stream) = create_test_streams("legacy_ingredient_hash.jpg");
    let mut report = StatusTracker::default();
    let store =
        Store::from_stream(format, input_stream, &mut report, &context).expect("from_stream");
    println!("store = {store}");
}

#[test]
#[ignore = "this test is not generating the expected errors - the test image cert has expired"]
fn test_bmff_legacy() {
    let mut context = Context::new();
    context.settings_mut().verify.verify_trust = false;

    let (format, mut input_stream, _output_stream) = create_test_streams("legacy.mp4");
    // test 1.0 bmff hash
    let mut report = StatusTracker::default();
    let store = Store::from_stream(format, &mut input_stream, &mut report, &context);
    println!("store = {report:#?}");
    // expect action error
    assert!(store.is_err());
    assert!(report.has_error(Error::ValidationRule(
        "opened, placed and removed items must have ingredient(s) parameters".into()
    )));
    assert!(report.filter_errors().count() == 2);
}

#[test]
fn test_bmff_fragments() {
    let context = Context::new();
    let init_stream_path = fixture_path("dashinit.mp4");
    let segment_stream_path = fixture_path("dash1.m4s");

    let init_stream = std::fs::File::open(init_stream_path).unwrap();
    let init_stream = std::io::BufReader::new(init_stream);
    let segment_stream = std::fs::File::open(segment_stream_path).unwrap();
    let segment_stream = std::io::BufReader::new(segment_stream);

    let mut report = StatusTracker::default();
    let store =
        Store::load_fragment_from_stream("mp4", init_stream, segment_stream, &mut report, &context)
            .expect("load_from_asset");
    println!("store = {store}");
}

#[test]
fn test_bmff_jumbf_generation() {
    let context = crate::context::Context::new();

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("video1.mp4");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list.
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // can we read back in
    output_stream.set_position(0);
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    assert!(!report.has_any_error());

    println!("store = {new_store}");
}

#[test]
fn test_bmff_jumbf_generation_qt() {
    let context = crate::context::Context::new();

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("c.mov");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list.
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // can we read back in
    output_stream.set_position(0);
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    assert!(!report.has_any_error());

    println!("store = {new_store}");
}

#[test]
fn test_bmff_jumbf_generation_claim_v1() {
    let context = crate::context::Context::new();

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("video1.mp4");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = crate::utils::test::create_test_claim_v1().unwrap();

    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list.
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // can we read back in
    output_stream.set_position(0);
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    assert!(!report.has_any_error());

    println!("store = {new_store}");
}

#[cfg(feature = "file_io")]
#[test]
fn test_jumbf_generation_with_bmffv3_fixed_block_size() {
    // use Merkle tree with 1024 byte chunks
    let context = crate::context::Context::new();

    // use Merkle tree with 1024 byte chunks
    crate::settings::set_settings_value("core.merkle_tree_chunk_size_in_kb", 1).unwrap();

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) =
        create_test_streams("BigBuckBunny_320x180.mp4");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list.
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // can we read back in
    output_stream.set_position(0);
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    assert!(!report.has_any_error());

    println!("store = {new_store}");
}

#[test]
fn test_jumbf_generation_with_bmffv3_fixed_block_size_no_proof() {
    let context = crate::context::Context::new();

    let (format, mut input_stream, mut output_stream) = create_test_streams("video1.mp4");

    // use Merkle tree with 1024 byte chunks an 0 proofs (no UUID boxes)
    crate::settings::set_settings_value("core.merkle_tree_chunk_size_in_kb", 1).unwrap();
    crate::settings::set_settings_value("core.merkle_tree_max_proofs", 0).unwrap();

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list.
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // can we read back in
    output_stream.set_position(0);
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    assert!(!report.has_any_error());

    println!("store = {new_store}");
}

#[test]
fn test_jumbf_generation_with_bmffv3_fixed_block_size_stream() {
    let context = crate::context::Context::new();

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("video1.mp4");

    // use Merkle tree with 1024 byte chunks
    crate::settings::set_settings_value("core.merkle_tree_chunk_size_in_kb", 1).unwrap();

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list.
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    // can we read back in
    output_stream.set_position(0);
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    assert!(!report.has_any_error());

    println!("store = {new_store}");
}

#[test]
fn test_bmff_jumbf_stream_generation() {
    let mut context = Context::new();
    context.settings_mut().verify.verify_after_reading = false;

    // test adding to actual image
    let (format, mut input_stream, mut output_stream) = create_test_streams("video1.mp4");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list.
    store.commit_claim(claim1).unwrap();

    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    let mut report = StatusTracker::default();

    output_stream.set_position(0);

    let (manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut input_stream, &context).unwrap();

    let _new_store = {
        Store::from_manifest_data_and_stream(
            &manifest_bytes,
            format,
            &mut output_stream,
            &mut report,
            &context,
        )
        .unwrap()
    };
    println!("report = {report:#?}");
    assert!(!report.has_any_error());
}

#[test]
fn test_removed_jumbf() {
    let context = Context::new();
    let (format, mut input_stream, _output_stream) = create_test_streams("no_manifest.jpg");

    let mut report = StatusTracker::default();

    // can we read back in
    let result = Store::from_stream(format, &mut input_stream, &mut report, &context);

    assert!(result.is_err());
    assert!(matches!(result, Err(Error::JumbfNotFound)));
    assert!(report.has_error(Error::JumbfNotFound));
}

// #[test]
// #[cfg(feature = "file_io")]
// fn test_external_manifest_sidecar() {
//     // test adding to actual image
//     let ap = fixture_path("libpng-test.png");
//     let temp_dir = tempdirectory().expect("temp dir");
//     let op = temp_dir_path(&temp_dir, "libpng-test-c2pa.png");

//     let sidecar = op.with_extension(MANIFEST_STORE_EXT);

//     // Create claims store.
//     let mut store = Store::new();

//     // Create a new claim.
//     let mut claim = create_test_claim().unwrap();

//     // set claim for side car generation
//     claim.set_external_manifest();

//     // Do we generate JUMBF?
//     let signer = test_signer(SigningAlg::Ps256);

//     store.commit_claim(claim).unwrap();

//     let saved_manifest = store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

//     assert!(sidecar.exists());

//     // load external manifest
//     let loaded_manifest = std::fs::read(sidecar).unwrap();

//     // compare returned to external
//     assert_eq!(saved_manifest, loaded_manifest);

//     // test auto loading of sidecar with validation
//     let mut validation_log =
//         StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
//     Store::load_from_asset(&op, true, &mut validation_log).unwrap();
// }

// generalize test for multipe file types
fn external_manifest_test(file_name: &str) {
    use crate::utils::test::{run_file_test, TestFileSetup};

    run_file_test(file_name, |setup: &TestFileSetup| {
        let context = crate::context::Context::new();

        // Create claims store.
        let mut store = Store::from_context(&context);

        // Create a new claim.
        let mut claim = create_test_claim().unwrap();

        // Do we generate JUMBF?
        let signer = test_signer(SigningAlg::Ps256);

        // set claim for side car with remote manifest embedding generation
        claim.set_remote_manifest(setup.sidecar_url()).unwrap();

        store.commit_claim(claim).unwrap();

        // Use streams from TestFileSetup - same pattern as create_test_streams
        let (format, mut input_stream, mut output_stream) = setup.create_streams();
        println!("format = {format}");
        let saved_manifest = store
            .save_to_stream(
                format,
                &mut input_stream,
                &mut output_stream,
                signer.as_ref(),
                &context,
            )
            .unwrap();

        // load the jumbf back into a store
        let mut asset_reader = std::fs::File::open(&setup.output_path).unwrap();
        let ext_ref = crate::utils::xmp_inmemory_utils::XmpInfo::from_source(
            &mut asset_reader,
            setup.extension(),
        )
        .provenance
        .unwrap();

        // cases might be different on different filesystems
        assert_eq!(ext_ref.to_lowercase(), setup.sidecar_url().to_lowercase());

        // make sure it validates using streams with external manifest data
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
        let mut validation_stream = std::fs::File::open(&setup.output_path).unwrap();
        Store::from_manifest_data_and_stream(
            &saved_manifest,
            format,
            &mut validation_stream,
            &mut validation_log,
            &context,
        )
        .unwrap();
    });
}

#[test]
fn test_external_manifest_embedded_png() {
    external_manifest_test("libpng-test.png");
}

#[test]
fn test_external_manifest_embedded_tiff() {
    external_manifest_test("TUSCANY.TIF");
}

#[test]
fn test_external_manifest_embedded_webp() {
    external_manifest_test("sample1.webp");
}

#[test]
fn test_user_guid_external_manifest_embedded() {
    let context = crate::context::Context::new();

    // Create test streams from fixture
    let (format, mut input_stream, mut output_stream) = create_test_streams("libpng-test.png");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let mut claim = create_test_claim().unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // start with base url
    let fp = format!("file:/{}", "temp_sidecar.c2pa");
    let url = url::Url::parse(&fp).unwrap();

    let url_string: String = url.into();

    // set claim for side car with remote manifest embedding generation
    claim.set_embed_remote_manifest(url_string.clone()).unwrap();

    store.commit_claim(claim).unwrap();

    let saved_manifest = store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // Get the data from output stream to check for external reference
    output_stream.rewind().unwrap();
    let output_data = output_stream.get_ref().clone();
    let mut output_reader = Cursor::new(output_data);

    let ext_ref =
        crate::utils::xmp_inmemory_utils::XmpInfo::from_source(&mut output_reader, format)
            .provenance
            .unwrap();

    assert_eq!(ext_ref, url_string);

    // make sure it validates using the manifest data and stream
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    output_stream.rewind().unwrap();
    Store::from_manifest_data_and_stream(
        &saved_manifest,
        format,
        &mut output_stream,
        &mut validation_log,
        &context,
    )
    .unwrap();
}

#[c2pa_test_async]
async fn test_jumbf_generation_stream() {
    let context = crate::context::Context::new();

    let file_buffer = include_bytes!("../../tests/fixtures/earth_apollo17.jpg").to_vec();
    // convert buffer to cursor with Read/Write/Seek capability
    let mut buf_io = Cursor::new(file_buffer);

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = async_test_signer(SigningAlg::Ps256);

    store.commit_claim(claim1).unwrap();

    let result: Vec<u8> = Vec::new();
    let mut result_stream = Cursor::new(result);

    store
        .save_to_stream_async(
            "image/jpeg",
            &mut buf_io,
            &mut result_stream,
            signer.as_ref(),
            &context,
        )
        .await
        .unwrap();

    // rewind the result stream to read from it
    result_stream.rewind().unwrap();

    // make sure we can read from new file
    let mut report = StatusTracker::default();
    let _new_store =
        Store::from_stream_async("image/jpeg", &mut result_stream, &mut report, &context)
            .await
            .unwrap();

    assert!(!report.has_any_error());
    // std::fs::write("target/test.jpg", result).unwrap();
}

#[test]
fn test_tiff_jumbf_generation() {
    let context = crate::context::Context::new();

    // Create test streams from fixture
    let (format, mut input_stream, mut output_stream) = create_test_streams("TUSCANY.TIF");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
    store.commit_claim(claim1).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    println!("Provenance: {}\n", store.provenance_path().unwrap());

    let mut report = StatusTracker::default();

    // read from new file
    output_stream.rewind().unwrap();
    let new_store = Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();

    assert!(!report.has_any_error());

    // dump store and compare to original
    for claim in new_store.claims() {
        let _restored_json = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();
        let _orig_json = store
            .get_claim(claim.label())
            .unwrap()
            .to_json(AssertionStoreJsonFormat::OrderedList, false)
            .unwrap();

        println!(
            "Claim: {} \n{}",
            claim.label(),
            claim
                .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                .expect("could not restore from json")
        );

        for hashed_uri in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
            claim
                .get_claim_assertion(&label, instance)
                .expect("Should find assertion");
        }
    }
}

#[c2pa_test_async]
#[cfg(feature = "file_io")]
async fn test_boxhash_embeddable_manifest_async() {
    let context = crate::context::Context::new();

    // test adding to actual image
    let ap = fixture_path("boxhash.jpg");
    let box_hash_path = fixture_path("boxhash.json");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let mut claim = create_test_claim().unwrap();

    // add box hash for CA.jpg
    let box_hash_data = std::fs::read(box_hash_path).unwrap();
    let assertion = Assertion::from_data_json(BOX_HASH, &box_hash_data).unwrap();
    let box_hash = BoxHash::from_json_assertion(&assertion).unwrap();
    claim.add_assertion(&box_hash).unwrap();

    store.commit_claim(claim).unwrap();

    // Do we generate JUMBF?
    let signer = async_test_signer(SigningAlg::Ps256);

    // get the embeddable manifest
    let em = store
        .get_box_hashed_embeddable_manifest_async(&signer, &context)
        .await
        .unwrap();

    // get composed version for embedding to JPEG
    let cm = Store::get_composed_manifest(&em, "image/jpeg").unwrap();

    // insert manifest into output asset
    let jpeg_io = get_assetio_handler_from_path(&ap).unwrap();
    let ol = jpeg_io.get_object_locations(&ap).unwrap();

    let cai_loc = ol
        .iter()
        .find(|o| o.htype == HashBlockObjectType::Cai)
        .unwrap();

    // remove any existing manifest
    jpeg_io.read_cai_store(&ap).unwrap();

    // build new asset in memory inserting new manifest
    let outbuf = Vec::new();
    let mut out_stream = Cursor::new(outbuf);
    let mut input_file = std::fs::File::open(&ap).unwrap();

    // write before
    let mut before = vec![0u8; cai_loc.offset];
    input_file.read_exact(before.as_mut_slice()).unwrap();
    out_stream.write_all(&before).unwrap();

    // write composed bytes
    out_stream.write_all(&cm).unwrap();

    // write bytes after
    let mut after_buf = Vec::new();
    input_file.read_to_end(&mut after_buf).unwrap();
    out_stream.write_all(&after_buf).unwrap();

    out_stream.rewind().unwrap();

    let mut report = StatusTracker::default();
    let _new_store = Store::from_stream_async("image/jpeg", &mut out_stream, &mut report, &context)
        .await
        .unwrap();

    assert!(!report.has_any_error());
}

#[test]
#[cfg(feature = "file_io")]
fn test_boxhash_embeddable_manifest() {
    let context = crate::context::Context::new();

    // test adding to actual image
    let ap = fixture_path("boxhash.jpg");
    let box_hash_path = fixture_path("boxhash.json");

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let mut claim = create_test_claim().unwrap();

    // add box hash for CA.jpg
    let box_hash_data = std::fs::read(box_hash_path).unwrap();
    let assertion = Assertion::from_data_json(BOX_HASH, &box_hash_data).unwrap();
    let box_hash = BoxHash::from_json_assertion(&assertion).unwrap();
    claim.add_assertion(&box_hash).unwrap();

    store.commit_claim(claim).unwrap();

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // get the embeddable manifest
    let em = store
        .get_box_hashed_embeddable_manifest(signer.as_ref(), &context)
        .unwrap();

    // get composed version for embedding to JPEG
    let cm = Store::get_composed_manifest(&em, "jpg").unwrap();

    // insert manifest into output asset
    let jpeg_io = get_assetio_handler_from_path(&ap).unwrap();
    let ol = jpeg_io.get_object_locations(&ap).unwrap();

    let cai_loc = ol
        .iter()
        .find(|o| o.htype == HashBlockObjectType::Cai)
        .unwrap();

    // remove any existing manifest
    jpeg_io.read_cai_store(&ap).unwrap();

    // build new asset in memory inserting new manifest
    let outbuf = Vec::new();
    let mut out_stream = Cursor::new(outbuf);
    let mut input_file = std::fs::File::open(&ap).unwrap();

    // write before
    let mut before = vec![0u8; cai_loc.offset];
    input_file.read_exact(before.as_mut_slice()).unwrap();
    out_stream.write_all(&before).unwrap();

    // write composed bytes
    out_stream.write_all(&cm).unwrap();

    // write bytes after
    let mut after_buf = Vec::new();
    input_file.read_to_end(&mut after_buf).unwrap();
    out_stream.write_all(&after_buf).unwrap();

    out_stream.rewind().unwrap();

    let mut report = StatusTracker::default();
    let _new_store =
        Store::from_stream("image/jpeg", &mut out_stream, &mut report, &context).unwrap();

    assert!(!report.has_any_error());
}

#[c2pa_test_async]
#[cfg(feature = "file_io")]
async fn test_datahash_embeddable_manifest_async() {
    let context = crate::context::Context::new();

    // test adding to actual image
    use std::io::SeekFrom;

    let ap = fixture_path("cloud.jpg");

    // Do we generate JUMBF?
    let signer = async_test_signer(SigningAlg::Ps256);

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim = create_test_claim().unwrap();

    store.commit_claim(claim).unwrap();

    // get a placeholder the manifest
    let placeholder = store
        .get_data_hashed_manifest_placeholder(signer.reserve_size(), "jpeg")
        .unwrap();

    let temp_dir = tempdirectory().unwrap();
    let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)
        .unwrap();

    // write a jpeg file with a placeholder for the manifest (returns offset of the placeholder)
    let offset = write_jpeg_placeholder_file(&placeholder, &ap, &mut output_file, None).unwrap();

    // build manifest to insert in the hole

    // create an hash exclusion for the manifest
    let exclusion = HashRange::new(offset as u64, placeholder.len() as u64);
    let exclusions = vec![exclusion];

    let mut dh = DataHash::new("source_hash", "sha256");
    dh.exclusions = Some(exclusions);

    // get the embeddable manifest, letting API do the hashing
    output_file.rewind().unwrap();
    let cm = store
        .get_data_hashed_embeddable_manifest_async(
            &dh,
            &signer,
            "jpeg",
            Some(&mut output_file),
            &context,
        )
        .await
        .unwrap();

    // path in new composed manifest
    output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
    output_file.write_all(&cm).unwrap();

    output_file.rewind().unwrap();
    let mut report = StatusTracker::default();
    let _new_store =
        Store::from_stream_async("image/jpeg", &mut output_file, &mut report, &context)
            .await
            .unwrap();

    assert!(!report.has_any_error());
}

#[test]
#[cfg(feature = "file_io")]
fn test_datahash_embeddable_manifest() {
    let context = crate::context::Context::new();

    // test adding to actual image

    use std::io::SeekFrom;
    let ap = fixture_path("cloud.jpg");

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim = create_test_claim().unwrap();

    store.commit_claim(claim).unwrap();

    // get a placeholder the manifest
    let placeholder = store
        .get_data_hashed_manifest_placeholder(Signer::reserve_size(&signer), "jpeg")
        .unwrap();

    let temp_dir = tempdirectory().unwrap();
    let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)
        .unwrap();

    // write a jpeg file with a placeholder for the manifest (returns offset of the placeholder)
    let offset = write_jpeg_placeholder_file(&placeholder, &ap, &mut output_file, None).unwrap();

    // build manifest to insert in the hole

    // create an hash exclusion for the manifest
    let exclusion = HashRange::new(offset as u64, placeholder.len() as u64);
    let exclusions = vec![exclusion];

    let mut dh = DataHash::new("source_hash", "sha256");
    dh.exclusions = Some(exclusions);

    // get the embeddable manifest, letting API do the hashing
    output_file.rewind().unwrap();
    let cm = store
        .get_data_hashed_embeddable_manifest(
            &dh,
            signer.as_ref(),
            "jpeg",
            Some(&mut output_file),
            &context,
        )
        .unwrap();

    // path in new composed manifest
    output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
    output_file.write_all(&cm).unwrap();

    output_file.rewind().unwrap();
    let mut report = StatusTracker::default();
    let _new_store =
        Store::from_stream("image/jpeg", &mut output_file, &mut report, &context).unwrap();

    assert!(!report.has_any_error());
}

#[test]
#[cfg(feature = "file_io")]
fn test_datahash_embeddable_manifest_user_hashed() {
    let context = crate::context::Context::new();

    use std::io::SeekFrom;

    use sha2::Digest;

    // test adding to actual image
    let ap = fixture_path("cloud.jpg");

    let mut hasher = Hasher::SHA256(Sha256::new());

    // Do we generate JUMBF?
    let signer = test_signer(SigningAlg::Ps256);

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim = create_test_claim().unwrap();

    store.commit_claim(claim).unwrap();

    // get a placeholder for the manifest
    let placeholder = store
        .get_data_hashed_manifest_placeholder(Signer::reserve_size(&signer), "jpeg")
        .unwrap();

    let temp_dir = tempdirectory().unwrap();
    let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
    let mut output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)
        .unwrap();

    // write a jpeg file with a placeholder for the manifest (returns offset of the placeholder)
    let offset =
        write_jpeg_placeholder_file(&placeholder, &ap, &mut output_file, Some(&mut hasher))
            .unwrap();

    // create target data hash
    // create an hash exclusion for the manifest
    let exclusion = HashRange::new(offset as u64, placeholder.len() as u64);
    let exclusions = vec![exclusion];

    //input_file.rewind().unwrap();
    let mut dh = DataHash::new("source_hash", "sha256");
    dh.hash = Hasher::finalize(hasher);
    dh.exclusions = Some(exclusions);

    // get the embeddable manifest, using user hashing
    let cm = store
        .get_data_hashed_embeddable_manifest(&dh, signer.as_ref(), "jpeg", None, &context)
        .unwrap();

    // path in new composed manifest
    output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
    output_file.write_all(&cm).unwrap();

    output_file.rewind().unwrap();
    let mut report = StatusTracker::default();
    let _new_store =
        Store::from_stream("image/jpeg", &mut output_file, &mut report, &context).unwrap();

    assert!(!report.has_any_error());
}

#[test]
fn test_dynamic_assertions() {
    let context = crate::context::Context::new();

    #[derive(Serialize)]
    struct TestAssertion {
        my_tag: String,
    }

    #[derive(Debug)]
    struct TestDynamicAssertion {}

    impl DynamicAssertion for TestDynamicAssertion {
        fn label(&self) -> String {
            "com.mycompany.myassertion".to_string()
        }

        fn reserve_size(&self) -> Result<usize> {
            let assertion = TestAssertion {
                my_tag: "some value I will replace".to_string(),
            };
            Ok(c2pa_cbor::to_vec(&assertion)?.len())
        }

        fn content(
            &self,
            _label: &str,
            _size: Option<usize>,
            claim: &PartialClaim,
        ) -> Result<DynamicAssertionContent> {
            assert!(claim
                .assertions()
                .inspect(|a| {
                    dbg!(a);
                })
                .any(|a| a.url().contains("c2pa.hash")));

            let assertion = TestAssertion {
                my_tag: "some value I will replace".to_string(),
            };

            Ok(DynamicAssertionContent::Cbor(
                c2pa_cbor::to_vec(&assertion).unwrap(),
            ))
        }
    }

    /// This is an signer wrapped around a local temp signer,
    /// that implements the dynamic assertion trait.
    struct DynamicSigner(Box<dyn Signer>);

    impl DynamicSigner {
        fn new() -> Self {
            Self(test_signer(SigningAlg::Ps256))
        }
    }

    impl crate::Signer for DynamicSigner {
        fn sign(&self, data: &[u8]) -> crate::error::Result<Vec<u8>> {
            self.0.sign(data)
        }

        fn alg(&self) -> SigningAlg {
            self.0.alg()
        }

        fn certs(&self) -> crate::Result<Vec<Vec<u8>>> {
            self.0.certs()
        }

        fn reserve_size(&self) -> usize {
            self.0.reserve_size()
        }

        fn time_authority_url(&self) -> Option<String> {
            self.0.time_authority_url()
        }

        fn ocsp_val(&self) -> Option<Vec<u8>> {
            self.0.ocsp_val()
        }

        // Returns our dynamic assertion here.
        fn dynamic_assertions(&self) -> Vec<Box<dyn crate::dynamic_assertion::DynamicAssertion>> {
            vec![Box::new(TestDynamicAssertion {})]
        }
    }

    let file_buffer = include_bytes!("../../tests/fixtures/earth_apollo17.jpg").to_vec();
    // convert buffer to cursor with Read/Write/Seek capability
    let mut buf_io = Cursor::new(file_buffer);

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = DynamicSigner::new();

    store.commit_claim(claim1).unwrap();

    let result: Vec<u8> = Vec::new();
    let mut result_stream = Cursor::new(result);

    store
        .save_to_stream("jpeg", &mut buf_io, &mut result_stream, &signer, &context)
        .unwrap();

    // rewind the result stream to read from it
    result_stream.rewind().unwrap();

    // make sure we can read from new file
    let mut report = StatusTracker::default();
    let new_store =
        Store::from_stream("image/jpeg", &mut result_stream, &mut report, &context).unwrap();

    println!("new_store: {new_store}");

    assert!(!report.has_any_error());
    // std::fs::write("target/test.jpg", result).unwrap();
}

#[c2pa_test_async]
async fn test_async_dynamic_assertions() {
    use async_trait::async_trait;

    let context = crate::context::Context::new();

    #[derive(Serialize)]
    struct TestAssertion {
        my_tag: String,
    }

    #[derive(Debug)]
    struct TestDynamicAssertion {}

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl AsyncDynamicAssertion for TestDynamicAssertion {
        fn label(&self) -> String {
            "com.mycompany.myassertion".to_string()
        }

        fn reserve_size(&self) -> Result<usize> {
            let assertion = TestAssertion {
                my_tag: "some value I will replace".to_string(),
            };
            Ok(c2pa_cbor::to_vec(&assertion)?.len())
        }

        async fn content(
            &self,
            _label: &str,
            _size: Option<usize>,
            claim: &PartialClaim,
        ) -> Result<DynamicAssertionContent> {
            assert!(claim
                .assertions()
                .inspect(|a| {
                    dbg!(a);
                })
                .any(|a| a.url().contains("c2pa.hash")));

            let assertion = TestAssertion {
                my_tag: "some value I will replace".to_string(),
            };

            Ok(DynamicAssertionContent::Cbor(
                c2pa_cbor::to_vec(&assertion).unwrap(),
            ))
        }
    }

    /// This is an async signer wrapped around a local temp signer,
    /// that implements the dynamic assertion trait.
    struct DynamicSigner(Box<dyn AsyncSigner>);

    impl DynamicSigner {
        fn new() -> Self {
            Self(async_test_signer(SigningAlg::Ps256))
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    impl crate::AsyncSigner for DynamicSigner {
        async fn sign(&self, data: Vec<u8>) -> crate::error::Result<Vec<u8>> {
            self.0.sign(data).await
        }

        fn alg(&self) -> SigningAlg {
            self.0.alg()
        }

        fn certs(&self) -> crate::Result<Vec<Vec<u8>>> {
            self.0.certs()
        }

        fn reserve_size(&self) -> usize {
            self.0.reserve_size()
        }

        fn time_authority_url(&self) -> Option<String> {
            self.0.time_authority_url()
        }

        async fn ocsp_val(&self) -> Option<Vec<u8>> {
            self.0.ocsp_val().await
        }

        // Returns our dynamic assertion here.
        fn dynamic_assertions(
            &self,
        ) -> Vec<Box<dyn crate::dynamic_assertion::AsyncDynamicAssertion>> {
            vec![Box::new(TestDynamicAssertion {})]
        }
    }

    let file_buffer = include_bytes!("../../tests/fixtures/earth_apollo17.jpg").to_vec();
    // convert buffer to cursor with Read/Write/Seek capability
    let mut buf_io = Cursor::new(file_buffer);

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim1 = create_test_claim().unwrap();

    let signer = DynamicSigner::new();

    store.commit_claim(claim1).unwrap();

    let result: Vec<u8> = Vec::new();
    let mut result_stream = Cursor::new(result);

    store
        .save_to_stream_async("jpeg", &mut buf_io, &mut result_stream, &signer, &context)
        .await
        .unwrap();

    result_stream.rewind().unwrap();

    // make sure we can read from new file
    let mut report = StatusTracker::default();
    let new_store = Store::from_stream_async("jpeg", &mut result_stream, &mut report, &context)
        .await
        .unwrap();

    println!("new_store: {new_store}");

    let result = result_stream.into_inner();

    Store::verify_store_async(
        &new_store,
        &mut ClaimAssetData::Bytes(&result, "jpg"),
        &mut report,
        &context,
    )
    .await
    .unwrap();

    assert!(!report.has_any_error());
    // std::fs::write("target/test.jpg", result).unwrap();
}

#[test]
#[cfg(feature = "file_io")]
fn test_fragmented_jumbf_generation() {
    let mut context = crate::context::Context::new();
    context.settings_mut().verify.verify_after_reading = false;

    // test adding to actual image

    let tempdir = tempdirectory().expect("temp dir");
    let output_path = tempdir.path();

    // search folders for init segments
    for init in glob::glob(
        fixture_path("bunny/**/BigBuckBunny_2s_init.mp4")
            .to_str()
            .unwrap(),
    )
    .unwrap()
    {
        match init {
            Ok(p) => {
                let mut fragments = Vec::new();
                let init_dir = p.parent().unwrap();
                let seg_glob = init_dir.join("BigBuckBunny_2s*.m4s"); // segment match pattern

                // grab the fragments that go with this init segment
                for seg in glob::glob(seg_glob.to_str().unwrap()).unwrap().flatten() {
                    fragments.push(seg);
                }

                // Create claims store.
                let mut store = Store::from_context(&context);

                // Create a new claim.
                let claim = create_test_claim().unwrap();
                store.commit_claim(claim).unwrap();

                // Do we generate JUMBF?
                let signer = test_cawg_signer(SigningAlg::Ps256, &[labels::SCHEMA_ORG]).unwrap();

                // Use Tempdir for automatic cleanup
                let new_subdir =
                    tempfile::TempDir::new_in(output_path).expect("Failed to create temp subdir");
                let new_output_path = new_subdir.path().join(init_dir.file_name().unwrap());
                store
                    .save_to_bmff_fragmented(
                        p.as_path(),
                        &fragments,
                        new_output_path.as_path(),
                        signer.as_ref(),
                        &context,
                    )
                    .unwrap();

                // verify the fragments
                let output_init = new_output_path.join(p.file_name().unwrap());
                let mut init_stream = std::fs::File::open(&output_init).unwrap();

                for entry in &fragments {
                    let file_path = new_output_path.join(entry.file_name().unwrap());

                    let mut validation_log = StatusTracker::default();

                    let mut fragment_stream = std::fs::File::open(&file_path).unwrap();
                    let _manifest = Store::load_fragment_from_stream(
                        "mp4",
                        &mut init_stream,
                        &mut fragment_stream,
                        &mut validation_log,
                        &context,
                    )
                    .unwrap();
                    init_stream.seek(std::io::SeekFrom::Start(0)).unwrap();
                    assert!(!validation_log.has_any_error());
                }

                // test verifying all at once
                let mut output_fragments = Vec::new();
                for entry in &fragments {
                    output_fragments.push(new_output_path.join(entry.file_name().unwrap()));
                }

                let mut validation_log = StatusTracker::default();
                let _manifest = Store::load_from_file_and_fragments(
                    "mp4",
                    &mut init_stream,
                    &output_fragments,
                    &mut validation_log,
                    &context,
                )
                .unwrap();

                assert!(!validation_log.has_any_error());
            }
            Err(_) => panic!("test misconfigures"),
        }
    }
}

#[test]
#[cfg(feature = "file_io")]
fn test_bogus_cert() {
    use crate::builder::{Builder, BuilderIntent};

    // bypass auto sig check
    crate::settings::set_settings_value("verify.verify_after_sign", false).unwrap();
    crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

    let png = include_bytes!("../../tests/fixtures/libpng-test.png"); // Randomly generated local Ed25519
    let ed25519 = include_bytes!("../../tests/fixtures/certs/ed25519.pem");
    let certs = include_bytes!("../../tests/fixtures/certs/es256.pub");

    let mut context = Context::new();
    // bypass auto signature checks
    context.settings_mut().verify.verify_after_sign = false;
    context.settings_mut().verify.verify_trust = false;

    let mut builder = Builder::from_context(context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));

    let signer =
        crate::create_signer::from_keys(certs, ed25519, SigningAlg::Ed25519, None).unwrap();
    let mut dst = Cursor::new(Vec::new());

    builder
        .sign(&signer, "image/png", &mut Cursor::new(png), &mut dst)
        .unwrap();

    let reader = crate::Reader::from_stream("image/png", &mut dst).unwrap();

    assert_eq!(reader.validation_state(), crate::ValidationState::Invalid);
}

#[test]
/// Test that we can we load a store from JUMBF and then convert it back to the identical JUMBF.
fn test_from_and_to_jumbf() {
    let context = crate::context::Context::new();

    // test adding to actual image
    let ap = fixture_path("C.jpg");

    let mut stream = std::fs::File::open(&ap).unwrap();
    let format = "image/jpeg";

    let (manifest_bytes, _remote_url) =
        Store::load_jumbf_from_stream(format, &mut stream, &context).unwrap();

    let store =
        Store::from_jumbf_with_context(&manifest_bytes, &mut StatusTracker::default(), &context)
            .unwrap();

    let jumbf = store
        .to_jumbf_internal(0)
        .expect("Failed to convert store to JUMBF");

    assert_eq!(jumbf, manifest_bytes);
}

#[c2pa_test_async]
async fn test_store_load_fragment_from_stream_async() {
    let context = crate::context::Context::new();
    // Use the dash fixtures that are known to work with fragment loading
    // These are the same files used in test_bmff_fragments
    let init_segment = include_bytes!("../../tests/fixtures/dashinit.mp4");
    let fragment = include_bytes!("../../tests/fixtures/dash1.m4s");

    let mut init_stream = Cursor::new(init_segment);
    let mut fragment_stream = Cursor::new(fragment);

    let format = "mp4";
    let mut validation_log = StatusTracker::default();

    // Test the async fragment loading (this is what we're actually testing)
    let result = Store::load_fragment_from_stream_async(
        format,
        &mut init_stream,
        &mut fragment_stream,
        &mut validation_log,
        &context,
    )
    .await;

    // Same validation as test_fragmented_jumbf_generation - but allow expected certificate trust errors
    match result {
        Ok(_manifest) => {
            // Verify that we successfully loaded a store from the fragment
            // The store should contain the manifest data from the fragment

            // Check for validation errors, but allow expected certificate trust errors
            if validation_log.has_any_error() {
                let errors: Vec<_> = validation_log.filter_errors().collect();
                let has_unexpected_errors = errors.iter().any(|item| {
                    // Allow certificate trust errors (these are expected for test fixtures)
                    // Check if the error is a CertificateTrustError
                    if let Some(err_val) = &item.err_val {
                        if err_val.contains("CertificateTrustError") {
                            return false; // This error is expected
                        }
                    }

                    // Any other errors are unexpected
                    true
                });

                if has_unexpected_errors {
                    panic!("Validation log contains unexpected errors: {validation_log:?}",);
                }
                // Certificate trust errors are OK for test fixtures
            }
        }
        Err(e) => {
            // Errors are NOT acceptable - this should work with fragments that contain manifest data
            panic!("Failed to load fragment from stream: {e:?}");
        }
    }
}

#[test]
fn test_stream_context_handling_for_c_ffi_layer() {
    // Building a stream wrapper that simulates C FFI behavior

    /// Stream wrapper that simulates the streams like it would be in C FFI layer.
    /// Needed to repro a use-after-free bug from the FFI layer.
    struct FlushTrackingStream<T: CAIReadWrite> {
        inner: T,
        buffer: Vec<u8>,
        flush_called: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl<T: CAIReadWrite> FlushTrackingStream<T> {
        fn new(inner: T, flush_called: Arc<AtomicBool>, dropped: Arc<AtomicBool>) -> Self {
            Self {
                inner,
                buffer: Vec::new(),
                flush_called,
                dropped,
            }
        }
    }

    impl<T: CAIReadWrite> Read for FlushTrackingStream<T> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl<T: CAIReadWrite> Write for FlushTrackingStream<T> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // Simulate buffering behavior
            if !self.buffer.is_empty() {
                // Write previous buffer first
                self.inner.write_all(&self.buffer)?;
            }
            // Keep the current write in the buffer
            self.buffer = buf.to_vec();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            // Mark that flush was called
            self.flush_called.store(true, Ordering::SeqCst);

            // Actually write the buffered data
            if !self.buffer.is_empty() {
                self.inner.write_all(&self.buffer)?;
                self.buffer.clear();
            }
            self.inner.flush()
        }
    }

    impl<T: CAIReadWrite> Seek for FlushTrackingStream<T> {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            // Check if we're trying to seek without flushing first
            // Simulates a crash scenario where the stream is accessed
            // after data should have been written but wasn't
            if !self.buffer.is_empty() && !self.flush_called.load(Ordering::SeqCst) {
                // This is a use-after-free error simulation for the way the FFI layer handles streams
                return Err(std::io::Error::other(
                    "Simulated use-after-free: attempting to seek with unflushed buffer (similar to accessing freed FFI context)",
                ));
            }
            self.inner.seek(pos)
        }

        fn rewind(&mut self) -> std::io::Result<()> {
            // Suffer the same troubles as seek
            if !self.buffer.is_empty() && !self.flush_called.load(Ordering::SeqCst) {
                return Err(std::io::Error::other(
                    "Simulated use-after-free: attempting to rewind with unflushed buffer (similar to accessing freed FFI context)",
                ));
            }
            self.inner.rewind()
        }

        fn stream_position(&mut self) -> std::io::Result<u64> {
            self.inner.stream_position()
        }
    }

    impl<T: CAIReadWrite> Drop for FlushTrackingStream<T> {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
            // Dropping without flush frees the context
        }
    }

    // The actual test starts here...
    let context = Context::new();

    let (format, mut input_stream, output_stream) = create_test_streams("earth_apollo17.jpg");

    let flush_called = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));

    let mut tracking_stream =
        FlushTrackingStream::new(output_stream, flush_called.clone(), dropped.clone());

    let mut store = Store::from_context(&context);

    let cgi = ClaimGeneratorInfo::new("flush_test");
    let mut claim = Claim::new("test", Some("flush_test"), 1);
    create_capture_claim(&mut claim).unwrap();
    claim.add_claim_generator_info(cgi);

    let signer = test_signer(SigningAlg::Ps256);

    store.commit_claim(claim).unwrap();

    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut tracking_stream,
            signer.as_ref(),
            &context,
        )
        .expect("save_to_stream should succeed and properly flush the stream");

    // Verify that flush was called: if not, we would have crashed on rewind
    // when used through the C FFI layers with streams
    assert!(
        flush_called.load(Ordering::SeqCst),
        "flush() must be called during save_to_stream to prevent use-after-free in FFI scenarios"
    );

    // Verify buffer is empty (data was actually written), nothing dangling
    assert!(
        tracking_stream.buffer.is_empty(),
        "buffer should be empty after flush"
    );
}

/// Another test for stream context issues, with unsafe pointers
#[test]
fn test_stream_context_handling_for_c_ffi_layer_no_use_after_free() {
    use std::io::Cursor;

    // This struct simulates an FFI stream context that could be freed any time
    #[repr(C)]
    struct StreamContext {
        data: Cursor<Vec<u8>>,
        // Used to detect if memory has been freed
        magic: u64,
    }

    impl StreamContext {
        fn new() -> Self {
            Self {
                data: Cursor::new(Vec::new()),
                // Magic number to detect valid context (not unintialized)
                magic: 0xdeadbeefcafebabe,
            }
        }

        fn mark_freed(&mut self) {
            // 0xCCCCCCCCCCCCCCCC is a value used by some compilers
            // to flag uninitialized memory, so we'll do the same here
            self.magic = 0xcccccccccccccccc;
        }

        fn check_valid(&self) -> std::io::Result<()> {
            if self.magic != 0xdeadbeefcafebabe {
                return Err(std::io::Error::other(
                    format!(
                        "Use-after-free detected: StreamContext magic is 0x{:X} (expected 0xDEADBEEFCAFEBABE)",
                        self.magic
                    ),
                ));
            }
            Ok(())
        }
    }

    struct UnsafeStream {
        context: *mut StreamContext,
        flush_called: Arc<AtomicBool>,
    }

    impl UnsafeStream {
        fn new(flush_called: Arc<AtomicBool>) -> Self {
            let context = Box::into_raw(Box::new(StreamContext::new()));
            Self {
                context,
                flush_called,
            }
        }

        unsafe fn context_ref(&self) -> &StreamContext {
            &*self.context
        }

        unsafe fn context_mut(&mut self) -> &mut StreamContext {
            &mut *self.context
        }
    }

    impl Read for UnsafeStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            unsafe {
                self.context_ref().check_valid()?;
                self.context_mut().data.read(buf)
            }
        }
    }

    impl Write for UnsafeStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            unsafe {
                self.context_ref().check_valid()?;
                self.context_mut().data.write(buf)
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            unsafe {
                self.context_ref().check_valid()?;
                self.flush_called.store(true, Ordering::SeqCst);
                self.context_mut().data.flush()
            }
        }
    }

    impl Seek for UnsafeStream {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            unsafe {
                // This is where the crash would happen in the FFI layer
                // if the context was freed before flush
                self.context_ref().check_valid()?;
                self.context_mut().data.seek(pos)
            }
        }

        fn rewind(&mut self) -> std::io::Result<()> {
            unsafe {
                self.context_ref().check_valid()?;
                self.context_mut().data.rewind()
            }
        }

        fn stream_position(&mut self) -> std::io::Result<u64> {
            unsafe {
                self.context_ref().check_valid()?;
                self.context_mut().data.stream_position()
            }
        }
    }

    impl Drop for UnsafeStream {
        fn drop(&mut self) {
            unsafe {
                if !self.context.is_null() {
                    // Simulate what happens in FFI: if flush wasn't called,
                    // mark the context as freed aka uninitialized memory
                    if !self.flush_called.load(Ordering::SeqCst) {
                        (*self.context).mark_freed();
                    }
                    // Clean up the context
                    drop(Box::from_raw(self.context));
                }
            }
        }
    }

    unsafe impl Send for UnsafeStream {}
    unsafe impl Sync for UnsafeStream {}

    let context = Context::new();

    let (format, mut input_stream, _) = create_test_streams("earth_apollo17.jpg");

    let flush_called = Arc::new(AtomicBool::new(false));
    let mut unsafe_stream = UnsafeStream::new(flush_called.clone());

    let mut store = Store::from_context(&context);

    let cgi = ClaimGeneratorInfo::new("unsafe_flush_test");
    let mut claim = Claim::new("test", Some("unsafe_flush_test"), 1);
    create_capture_claim(&mut claim).unwrap();
    claim.add_claim_generator_info(cgi);

    let signer = test_signer(SigningAlg::Ps256);

    store.commit_claim(claim).unwrap();

    // Save to stream: without the flush calls, this triggers
    // a use-after-free error when trying to rewind the stream,
    // because the stream context is freed before the flush is called
    let result = store.save_to_stream(
        format,
        &mut input_stream,
        &mut unsafe_stream,
        signer.as_ref(),
        &context,
    );

    // flushing should prevent the lifetimes issues at C FFI level
    assert!(
        result.is_ok(),
        "save_to_stream should succeed. Error: {:?}",
        result.err()
    );

    // Verify that flush was called
    assert!(flush_called.load(Ordering::SeqCst));
}
