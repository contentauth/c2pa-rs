// Copyright 2022 Adobe. All rights reserved.
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

#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "file_io")]
use std::fs;
#[cfg(feature = "file_io")]
use std::path::PathBuf;
use std::{
    collections::HashSet,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use c2pa_macros::c2pa_test_async;
#[cfg(feature = "file_io")]
use memchr::memmem;
use serde::Serialize;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use super::store_core::MAX_INGREDIENT_DEPTH;
#[cfg(feature = "file_io")]
use crate::{
    assertion::AssertionJson,
    assertions::{labels::BOX_HASH, BoxHash},
    asset_io::ObjectType,
    hashed_uri::HashedUri,
    jumbf_io::get_assetio_handler_from_path,
    utils::{
        io_utils::tempdirectory,
        test::{temp_dir_path, TEST_USER_ASSERTION},
        test_signer::test_cawg_signer,
    },
};
use crate::{
    assertion::{Assertion, AssertionData},
    assertions::{
        labels, Action, Actions, CollectionHash, DataHash, Ingredient, Relationship, Uuid,
    },
    asset_io::ReadWriteSeek,
    claim::{AssertionStoreJsonFormat, Claim, ClaimAssertion, ClaimAssetData},
    context::Context,
    dynamic_assertion::{
        AsyncDynamicAssertion, DynamicAssertion, DynamicAssertionContent, PartialClaim,
    },
    error::{Error, Result},
    jumbf::{boxes::C2PA_REDACTION_UUID, labels::to_assertion_uri},
    jumbf_io::load_jumbf_from_stream,
    settings::{Settings, SettingsValidate},
    status_tracker::{ErrorBehavior, LogItem, StatusTracker},
    store::{InvalidClaimError, Store, StoreValidationInfo},
    utils::{
        patch::patch_bytes,
        test::{create_test_claim, create_test_streams, fixture_path},
        test_signer::{async_test_signer, test_signer},
    },
    validation_status,
    validation_status::ALGORITHM_UNSUPPORTED,
    AsyncSigner, ClaimGeneratorInfo, DigitalSourceType, Signer, SigningAlg,
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

// Manifests signed before resource-reference icons were converted to hashed URIs (or by
// another producer that wrote them) remain readable, but report `hashedURI.missing` against
// the containing actions assertion and are therefore Invalid.
#[test]
fn test_legacy_resource_ref_icon_reads_as_invalid() {
    let mut context = Context::new();
    // Simulate an older SDK that did not reject these icons after signing.
    context.settings_mut().verify.verify_after_sign = false;

    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");
    let mut store = Store::from_context(&context);

    let mut claim = Claim::new("legacy", Some("legacy"), 2);
    claim.add_claim_generator_info(ClaimGeneratorInfo::new("legacy_icon_test"));

    let mut agent = ClaimGeneratorInfo::new("LegacyApp");
    agent.set_icon(crate::resource_store::ResourceRef::new(
        "image/png",
        "icon.png",
    ));
    let mut actions = Actions::new()
        .add_action(Action::new("c2pa.created").set_source_type(DigitalSourceType::Empty));
    actions.add_software_agent(agent);
    let actions_uri = claim.add_assertion(&actions).unwrap().url();

    store.commit_claim(claim).unwrap();
    store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            test_signer(SigningAlg::Ps256).as_ref(),
            &context,
        )
        .unwrap();

    output_stream.rewind().unwrap();
    let reader = crate::Reader::default()
        .with_stream(format, &mut output_stream)
        .unwrap();

    assert_eq!(reader.validation_state(), crate::ValidationState::Invalid);

    let failures = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .map(|status| status.failure().to_vec())
        .unwrap_or_default();
    let (actions_label, _) = Claim::assertion_label_from_link(&actions_uri);
    assert!(
        failures.iter().any(|status| {
            status.code() == validation_status::HASHED_URI_MISSING
                && status
                    .url()
                    .is_some_and(|url| url.ends_with(&format!("c2pa.assertions/{actions_label}")))
        }),
        "{failures:?}"
    );

    let actions: Actions = reader
        .active_manifest()
        .unwrap()
        .find_assertion(Actions::LABEL)
        .unwrap();
    assert_eq!(
        actions.software_agents().as_ref().unwrap()[0].name,
        "LegacyApp"
    );
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
    use crate::{create_signer, SigningAlg};

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
    let original_jumbf = context.io().read_c2pa_from_file(&ap).unwrap();

    // replace with new jumbf
    context
        .io()
        .write_c2pa_to_file(&jumbf_bytes, &ap, Some(&op))
        .unwrap();

    let saved_jumbf = context.io().read_c2pa_from_file(&op).unwrap();

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
fn test_png_compressed_jumbf_generation() {
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
    claim2.set_compressed_manifest(true);

    // Create a 3rd party claim
    let mut claim_capture = Claim::new("capture", Some("claim_capture"), 1);
    create_capture_claim(&mut claim_capture).unwrap();
    claim_capture.set_compressed_manifest(true);

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
    // `unsupported_type.txt` is `.txt`/`text/plain`: unsupported by default, but a real
    // (unsigned) type once the experimental plain-text handler registers that extension.
    if cfg!(feature = "unstable_plain_text") {
        assert!(matches!(result, Err(Error::JumbfNotFound)));
        assert!(report.has_error(Error::JumbfNotFound));
    } else {
        assert!(matches!(result, Err(Error::UnsupportedType)));
        assert!(report.has_error(Error::UnsupportedType));
    }
    println!("Error report: {report:?}");
    assert!(!report.logged_items().is_empty());
}

fn make_brotli_bomb_jumbf(decompressed_size: usize) -> Vec<u8> {
    use brotli::enc::BrotliEncoderParams;

    use crate::jumbf::boxes::{
        BMFFBox, Cai, JUMBFBrotliContentBox, JUMBFSuperBox, CAI_MANIFEST_UUID,
    };

    let payload = vec![0u8; decompressed_size];
    let mut compressed = Vec::new();
    brotli::BrotliCompress(
        &mut Cursor::new(payload.as_slice()),
        &mut compressed,
        &BrotliEncoderParams::default(),
    )
    .expect("brotli compress");

    let brotli_box = JUMBFBrotliContentBox::new(compressed);
    let mut manifest_sbox = JUMBFSuperBox::new("test.manifest", Some(CAI_MANIFEST_UUID));
    manifest_sbox.add_data_box(Box::new(brotli_box));

    let mut cai = Cai::new();
    cai.add_box(Box::new(manifest_sbox));

    let mut bytes = Vec::new();
    cai.super_box()
        .write_box(&mut bytes)
        .expect("serialize cai block");
    bytes
}

#[test]
fn test_from_jumbf_rejects_brotli_bomb_via_thread_local() {
    let settings = Settings::new()
        .with_value("core.max_decompressed_manifest_size_in_mb", 1usize)
        .unwrap();
    let context = Context::new().with_settings(settings).unwrap();
    let result = Store::from_jumbf_with_context(
        &make_brotli_bomb_jumbf(2 * 1024 * 1024),
        &mut StatusTracker::default(),
        &context,
    );
    assert!(result.is_err());
}

#[test]
fn test_from_jumbf_with_context_rejects_brotli_bomb() {
    let settings = Settings::default()
        .with_value("core.max_decompressed_manifest_size_in_mb", 1usize)
        .unwrap();
    let context = Context::new().with_settings(settings).unwrap();

    let result = Store::from_jumbf_with_context(
        &make_brotli_bomb_jumbf(2 * 1024 * 1024),
        &mut StatusTracker::default(),
        &context,
    );

    assert!(result.is_err());
}

#[test]
fn test_from_jumbf_reads_c2md_standard_manifest() {
    use crate::{
        jumbf::boxes::{CAI_MANIFEST_C2MD_UUID, CAI_MANIFEST_UUID},
        utils::test::create_test_store,
    };

    // Per C2PA spec 11.2.2, a manifest using the c2md JUMBF type UUID is a
    // standard manifest that consumers shall accept. Build a normal (c2ma)
    // manifest, rewrite its superbox type UUID to c2md, and confirm the
    // store still reads the manifest instead of silently skipping it.
    let store = create_test_store().unwrap();
    let jumbf = store.to_jumbf_internal(0).unwrap();

    // Flip the manifest superbox type UUID from c2ma to c2md in place.
    let c2ma = hex::decode(CAI_MANIFEST_UUID).unwrap();
    let c2md = hex::decode(CAI_MANIFEST_C2MD_UUID).unwrap();
    let pos = jumbf
        .windows(c2ma.len())
        .position(|w| w == c2ma.as_slice())
        .expect("manifest c2ma UUID present");
    let mut patched = jumbf.clone();
    patched[pos..pos + c2md.len()].copy_from_slice(&c2md);

    let mut log = StatusTracker::default();
    let restored = Store::from_jumbf_with_context(&patched, &mut log, &Context::new())
        .expect("c2md manifest should be read");
    assert_eq!(
        restored.claims().len(),
        store.claims().len(),
        "c2md manifest should be read as a standard manifest"
    );
}

#[test]
fn test_c2md_manifest_preserved_on_round_trip() {
    use crate::{
        jumbf::boxes::{CAI_MANIFEST_C2MD_UUID, CAI_MANIFEST_UUID},
        utils::test::create_test_store,
    };

    // A c2md manifest must keep its c2md tag if the store is
    // re-serialized (e.g. when it is copied as part of adding an update
    // manifest or embedding it as an ingredient's manifest store) -
    // claim generators must not synthesize new c2ma/c2um boxes for data
    // that was never theirs to retag.
    let store = create_test_store().unwrap();
    let jumbf = store.to_jumbf_internal(0).unwrap();

    let c2ma = hex::decode(CAI_MANIFEST_UUID).unwrap();
    let c2md = hex::decode(CAI_MANIFEST_C2MD_UUID).unwrap();
    let pos = jumbf
        .windows(c2ma.len())
        .position(|w| w == c2ma.as_slice())
        .expect("manifest c2ma UUID present");
    let mut patched = jumbf.clone();
    patched[pos..pos + c2md.len()].copy_from_slice(&c2md);

    let mut log = StatusTracker::default();
    let restored = Store::from_jumbf_with_context(&patched, &mut log, &Context::new())
        .expect("c2md manifest should be read");

    // Re-serialize the store that was read from a c2md-tagged manifest.
    let round_tripped = restored.to_jumbf_internal(0).unwrap();

    let c2md_count = round_tripped
        .windows(c2md.len())
        .filter(|w| *w == c2md.as_slice())
        .count();
    let c2ma_count = round_tripped
        .windows(c2ma.len())
        .filter(|w| *w == c2ma.as_slice())
        .count();

    assert_eq!(
        c2md_count, 1,
        "c2md tag should survive re-serialization of the store"
    );
    assert_eq!(
        c2ma_count, 0,
        "a c2md manifest must not be rewritten as c2ma on round-trip"
    );
}

#[test]
fn test_manifest_box_hash_uses_box_uuid_not_label() {
    use crate::utils::test::create_test_store;

    // Core boxes (claim, signature, assertion store) are located by their
    // JUMBF type UUID, so the manifest box hash must be regenerated from the
    // same UUIDs. Relabeling the signature box as `c2pa.databoxes` while
    // leaving its type UUID intact must not change the manifest box hash: if
    // the box order were derived from the label, the signature box would be
    // dropped from the regenerated manifest and byte-distinct parents could
    // collapse to the same hash, defeating ingredient validation
    // (vuln-37402).
    let store = create_test_store().unwrap();
    let jumbf = store.to_jumbf_internal(0).unwrap();

    // Baseline: load the untouched manifest and record its box hash.
    let mut log = StatusTracker::default();
    let baseline = Store::from_jumbf_with_context(&jumbf, &mut log, &Context::new()).unwrap();
    let baseline_pc = baseline.provenance_claim().unwrap();
    let baseline_hash = baseline
        .get_manifest_box_hashes(baseline_pc)
        .manifest_box_hash;
    assert!(!baseline_hash.is_empty());

    // Relabel the signature description box `c2pa.signature` ->
    // `c2pa.databoxes` (same byte length, null terminator preserved) while
    // leaving its type UUID unchanged. It is the last occurrence of the
    // label in the stream, after the claim and its placeholder signature.
    let old_label = b"c2pa.signature\0";
    let new_label = b"c2pa.databoxes";
    let pos = jumbf
        .windows(old_label.len())
        .rposition(|w| w == old_label)
        .expect("signature box label present");
    let mut patched = jumbf.clone();
    patched[pos..pos + new_label.len()].copy_from_slice(new_label);

    let mut log = StatusTracker::default();
    let tampered = Store::from_jumbf_with_context(&patched, &mut log, &Context::new()).unwrap();
    let tampered_pc = tampered.provenance_claim().unwrap();
    let tampered_hash = tampered
        .get_manifest_box_hashes(tampered_pc)
        .manifest_box_hash;

    assert_eq!(
        baseline_hash, tampered_hash,
        "manifest box hash must be derived from box UUIDs, not labels"
    );
}

#[test]
fn test_duplicate_assertion_store_box_is_rejected() {
    use crate::{
        jumbf::boxes::{CAI_ASSERTION_STORE_UUID, CAI_MANIFEST_UUID},
        utils::test::create_test_store,
    };

    // A manifest may contain only one of each core box. `manifest_map` is keyed by box
    // UUID (last-wins), so a second assertion store would be dropped from the map while
    // still counted in `box_order` and regenerated from the single surviving box. That
    // lets two byte-distinct manifests collapse to the same manifest box hash — the
    // vuln-37402 ingredient parent-swap primitive. Duplicating the assertion store box
    // (editing manifest-store bytes needs no key) must now be rejected at parse time.

    // Locate a JUMBF superbox by its description-box type UUID, returning its byte range.
    // Superbox layout: [size:4][b"jumb"][desc_size:4][b"jumd"][uuid:16]..., so the
    // 16-byte UUID sits 4 bytes after the `jumd` marker and the enclosing superbox
    // starts 12 bytes before it.
    fn superbox_range(jumbf: &[u8], uuid_hex: &str) -> (usize, usize) {
        let mut needle = b"jumd".to_vec();
        needle.extend_from_slice(&hex::decode(uuid_hex).unwrap());
        let jumd_pos = jumbf
            .windows(needle.len())
            .position(|w| w == needle.as_slice())
            .expect("superbox present");
        let start = jumd_pos - 12;
        let size = u32::from_be_bytes(jumbf[start..start + 4].try_into().unwrap()) as usize;
        (start, size)
    }

    fn add_u32(buf: &mut [u8], at: usize, delta: usize) {
        let v = u32::from_be_bytes(buf[at..at + 4].try_into().unwrap());
        buf[at..at + 4].copy_from_slice(&(v + delta as u32).to_be_bytes());
    }

    let store = create_test_store().unwrap();
    let jumbf = store.to_jumbf_internal(0).unwrap();

    // Sanity: the untouched manifest reads back fine.
    let mut log = StatusTracker::default();
    Store::from_jumbf_with_context(&jumbf, &mut log, &Context::new())
        .expect("baseline manifest should read");

    // Duplicate the assertion store superbox in place, right after the original.
    let (as_start, as_len) = superbox_range(&jumbf, CAI_ASSERTION_STORE_UUID);
    let as_end = as_start + as_len;
    let (manifest_start, _) = superbox_range(&jumbf, CAI_MANIFEST_UUID);

    let mut patched = Vec::with_capacity(jumbf.len() + as_len);
    patched.extend_from_slice(&jumbf[..as_end]);
    patched.extend_from_slice(&jumbf[as_start..as_end]);
    patched.extend_from_slice(&jumbf[as_end..]);

    // Grow the enclosing manifest superbox and the outer CAI block to cover the copy.
    add_u32(&mut patched, manifest_start, as_len);
    add_u32(&mut patched, 0, as_len);

    let mut log = StatusTracker::default();
    let result = Store::from_jumbf_with_context(&patched, &mut log, &Context::new());
    assert!(
        matches!(
            result,
            Err(Error::InvalidClaim(
                InvalidClaimError::C2paMultipleManifestBoxes
            ))
        ),
        "duplicate assertion store must be rejected, got {result:?}"
    );
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

#[test]
fn test_bad_update_manifest_v1() {
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

    // missing signature Hashed URI.  Should fail
    let ingredient = Ingredient::new_v3(Relationship::ParentOf)
        .set_parent()
        .set_c2pa_manifest_from_hashed_uri(Some(parent_hashed_uri));

    claim.add_assertion(&ingredient).unwrap();

    // won't serialize because it must have activeManifest
    assert!(new_store.commit_update_manifest(claim).is_err());
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
#[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
fn test_v1_timestamp_rejects_sha1_message_imprint() {
    use openssl::hash::MessageDigest;

    use crate::{
        crypto::{
            cose::CertificateTrustPolicy,
            time_stamp::verify::message_imprint_regression::{build_token, OID_SHA1, OID_SHA256},
        },
        utils::test::create_test_store_v1,
    };

    let context = Context::new();
    let (format, mut input_stream, mut output_stream) = create_test_streams("earth_apollo17.jpg");
    let signer = test_signer(SigningAlg::Ps256);

    let mut store = create_test_store_v1().unwrap();
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
    output_stream.rewind().unwrap();
    let restored_store =
        Store::from_stream(format, &mut output_stream, &mut report, &context).unwrap();
    let claim = restored_store.provenance_claim().unwrap();
    assert_eq!(claim.version(), 1);

    let signature = claim.cose_sign1().unwrap().signature;
    let ctp = CertificateTrustPolicy::default();

    // control: a SHA-256 imprint over the claim signature is accepted
    let sha256_token = build_token(OID_SHA256, MessageDigest::sha256(), &signature);
    assert!(Store::verified_timestamp_for_claim(claim, &sha256_token, &ctp).is_some());

    // same signature and a matching imprint, but SHA-1 must be ignored
    let sha1_token = build_token(OID_SHA1, MessageDigest::sha1(), &signature);
    assert!(Store::verified_timestamp_for_claim(claim, &sha1_token, &ctp).is_none());
}

fn add_ingredient_assertion_to_claim(
    store: &Store,
    claim: &mut Claim,
    action: &str,
    relationship: Relationship,
    instance: Option<usize>,
) -> Result<()> {
    use crate::{hashed_uri::HashedUri, jumbf::labels::to_signature_uri, ValidationResults};

    let report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    let pc = store.provenance_claim().unwrap();

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

    let validation_results = ValidationResults::from_store(store, &report);

    let ingredient = Ingredient::new_v3(relationship)
        .set_active_manifests_and_signature_from_hashed_uri(
            Some(parent_hashed_uri),
            Some(signature_hashed_uri),
        ) // mandatory for v3
        .set_validation_results(Some(validation_results)); // mandatory for v3

    claim.add_assertion(&ingredient).unwrap();

    // create mandatory opened action (optional for update manifest)
    let ingredient = claim.ingredient_assertions()[0];
    let mut ingredient_uri = to_assertion_uri(claim.label(), &ingredient.label());
    if let Some(instance) = instance {
        ingredient_uri.push_str(&format!("__{instance}"));
    }
    let ingredient_hashed_uri = HashedUri::new(
        ingredient_uri,
        Some(claim.alg().to_owned()),
        ingredient.hash(),
    );

    let a = Action::new(action)
        .set_parameter("ingredients", vec![ingredient_hashed_uri])
        .unwrap();
    let actions = Actions::new().add_action(a);

    // add action (this is optional for update manifest)
    claim.add_assertion(&actions).unwrap();

    Ok(())
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
    let redacted_uri = to_assertion_uri(pc.label(), labels::SCHEMA_ORG_INTERNAL);

    let (manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(ingredient_vec.clone()), &context)
            .unwrap();
    let mut redacted_store = Store::load_ingredient_to_claim(
        &mut claim,
        &manifest_bytes,
        Some(vec![redacted_uri.clone()]),
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
    let mut new_claim = Claim::new("adobe unit test", Some("merged_manifests"), 2);
    // ClaimGeneratorInfo is mandatory in Claim V2
    let cgi = ClaimGeneratorInfo::new("claim_v2_unit_test");
    new_claim.add_claim_generator_info(cgi);

    // load original ingredient without redaction
    let mut original_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let (original_manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(ingredient_vec), &context).unwrap();
    let original_store =
        Store::from_jumbf_with_context(&original_manifest_bytes, &mut original_log, &context)
            .unwrap();
    Store::load_ingredient_to_claim(&mut new_claim, &original_manifest_bytes, None, &context)
        .unwrap();
    // add original ingredient assertion as component to create conflict
    add_ingredient_assertion_to_claim(
        &original_store,
        &mut new_claim,
        "c2pa.opened",
        Relationship::ParentOf,
        None,
    )
    .unwrap();

    // load ingredient with redaction and try to redact again
    // it should not cause any issues and should retain the redacted ingredient assertion without error, and the conflict should be resolved with the current redaction
    output_stream2.rewind().unwrap();
    let mut redacted_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let (redacted_manifest_bytes, _) =
        Store::load_jumbf_from_stream(format, &mut output_stream2, &context).unwrap();
    let redacted_store =
        Store::from_jumbf_with_context(&redacted_manifest_bytes, &mut redacted_log, &context)
            .unwrap();
    Store::load_ingredient_to_claim(
        &mut new_claim,
        &redacted_manifest_bytes,
        Some(vec![redacted_uri.clone()]),
        &context,
    )
    .unwrap();
    // add redacted ingredient assertion as component
    add_ingredient_assertion_to_claim(
        &redacted_store,
        &mut new_claim,
        "c2pa.placed",
        Relationship::ComponentOf,
        Some(1),
    )
    .unwrap();

    // save output of the conflict store to see the conflict assertion
    output_stream2.rewind().unwrap();
    let mut output_stream3 = std::io::Cursor::new(Vec::new());
    let mut final_store = Store::from_context(&Context::new());

    final_store.commit_claim(new_claim).unwrap();
    final_store
        .save_to_stream(
            format,
            &mut output_stream2,
            &mut output_stream3,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // the confict_store is adjusted to remove the conflicting claim
    output_stream3.rewind().unwrap();
    let mut resolved_store_report =
        StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let resolved_store = Store::from_stream(
        format,
        &mut output_stream3,
        &mut resolved_store_report,
        &context,
    )
    .unwrap();

    // make sure the redaction stuck
    let redacted_claim = resolved_store.get_claim(pc.label()).unwrap();
    assert!(redacted_claim
        .get_assertion(labels::SCHEMA_ORG_INTERNAL, 0)
        .is_none());
}

#[test]
fn test_ingredient_labels_versioned_on_conflict() {
    // A manifest URN identifies a manifest, not its bytes.
    // The same manifest can reach one asset by two routes
    // and have only one of the copies change along the way.
    // Two ingredients (from the different paths)
    // then carry the same label with different (bytes) content.
    //
    // See https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_copying_existing_manifests
    // (C2PA spec 2.4 section 18.16.12)
    //
    // Here the three ingredients differ by databox content, triggering relabelling.
    // The first conflict must start at version 1 instead of erroring.
    let context = Context::new();
    let signer = test_signer(SigningAlg::Ps256);
    let shared_label = "urn:c2pa:11111111-2222-4333-8444-555555555555";

    let signed_ingredient = |variant: &str| -> Vec<u8> {
        let mut store = Store::from_context(&Context::new());
        let mut claim =
            Claim::new_with_user_guid("ingredient label conflict test", shared_label, 2).unwrap();
        claim.add_claim_generator_info(ClaimGeneratorInfo::new("conflict_test"));
        claim
            .add_databox("text/plain", variant.as_bytes().to_vec(), None)
            .unwrap();
        let actions = Actions::new()
            .add_action(Action::new("c2pa.created").set_source_type(DigitalSourceType::Empty));
        claim.add_assertion(&actions).unwrap();
        store.commit_claim(claim).unwrap();

        let (format, mut input, mut output) = create_test_streams("earth_apollo17.jpg");
        store
            .save_to_stream(format, &mut input, &mut output, signer.as_ref(), &context)
            .unwrap();
        output.rewind().unwrap();
        let (bytes, _) = Store::load_jumbf_from_stream(format, &mut output, &context).unwrap();
        bytes
    };

    // Preparing 3 ingredient varints, which will have the same shared URN.
    // They will have different databox content, dependent on the variant.
    let bytes_a = signed_ingredient("variant-a");
    let bytes_b = signed_ingredient("variant-b");
    let bytes_c = signed_ingredient("variant-c");

    let mut claim = Claim::new(
        "ingredient label conflict test top level",
        Some("c2pa-rs-sdk-test"),
        2,
    );
    claim.add_claim_generator_info(ClaimGeneratorInfo::new("outer"));

    // No conflict on this load...
    Store::load_ingredient_to_claim(&mut claim, &bytes_a, None, &context).unwrap();
    // First conflict happens at this load.
    Store::load_ingredient_to_claim(&mut claim, &bytes_b, None, &context).unwrap();
    // This is the second conflict.
    Store::load_ingredient_to_claim(&mut claim, &bytes_c, None, &context).unwrap();

    let keys: Vec<&String> = claim.claim_ingredient_store().keys().collect();
    let has = |label: &str| keys.iter().any(|k| k.as_str() == label);
    assert!(has(shared_label));
    // Verifies conflict resolution labelling
    assert!(
        has(&format!("{shared_label}::1_1")),
        "on first conflict, relabel should have version 1, got: {keys:?}"
    );
    assert!(
        has(&format!("{shared_label}::2_1")),
        "second conflict should relabel to version 2, got: {keys:?}"
    );
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
    let redacted_uri = to_assertion_uri(pc.label(), labels::SCHEMA_ORG_INTERNAL);

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
        .get_assertion(labels::SCHEMA_ORG_INTERNAL, 0)
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
        .get_assertion(labels::SCHEMA_ORG_INTERNAL, 0)
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
    let redacted_uri = to_assertion_uri(pc.label(), labels::SCHEMA_ORG_INTERNAL);

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
        .get_assertion(labels::SCHEMA_ORG_INTERNAL, 0)
        .is_none());

    assert!(redacted_claim
        .get_assertion(TEST_USER_ASSERTION, 0)
        .is_none());
}

// A URI listed in a claim's `redacted_assertions` must, if any box is still
// present at that location, contain only zero bytes regardless of the box's JUMBF type
// (spec 2.x §15.11.3.3.1). The honest builder removes the assertion entirely, so we
// reproduce the attack by building a legitimately-redacted asset and then injecting a
// non-zero CBOR assertion box back into the redacted slot — exactly what an attacker does
// by editing the manifest-store bytes (no key required, since redaction suppresses the
// ingredient manifest hash mismatch). Before the fix this forged box surfaced as a genuine
// assertion with no failures; it must now be rejected with `assertion.notRedacted`.
#[test]
fn test_forged_content_in_redacted_slot_is_rejected() {
    use crate::{
        assertions::C2paReason, claim::ClaimAssertionType, Builder, BuilderIntent, Reader,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../tests/fixtures/CA.jpg");
    const ASSERTION_LABEL: &str = "stds.schema-org.CreativeWork";

    // Read the parent so we can address the assertion we are going to redact.
    let mut input = Cursor::new(TEST_IMAGE);
    let parent = Reader::default()
        .with_stream("image/jpeg", &mut input)
        .expect("read parent");
    let parent_manifest_label = parent.active_label().unwrap().to_owned();
    let redacted_uri = to_assertion_uri(&parent_manifest_label, ASSERTION_LABEL);

    // Produce a normal, spec-compliant redaction of that assertion.
    let mut builder = Builder::default();
    builder.set_intent(BuilderIntent::Edit);
    builder.definition.redactions = Some(vec![redacted_uri.clone()]);
    let redacted_action = Action::new("c2pa.redacted")
        .set_reason(C2paReason::PiiPresent)
        .set_parameter("redacted".to_owned(), redacted_uri.clone())
        .unwrap();
    builder.add_action(redacted_action).unwrap();

    let signer = test_signer(SigningAlg::Ps256);
    let mut output = Cursor::new(Vec::new());
    builder
        .sign(signer.as_ref(), "image/jpeg", &mut input, &mut output)
        .expect("builder sign");
    output.set_position(0);

    let mut load_report = StatusTracker::default();
    let mut store =
        Store::from_stream("image/jpeg", &mut output, &mut load_report, &Context::new())
            .expect("load store");

    // Baseline: the honest redaction removes the assertion, so nothing sits at the
    // redacted URI and no notRedacted failure is raised.
    let mut baseline_report = StatusTracker::default();
    let _ = Store::verify_store(&store, None, &mut baseline_report, &Context::new());
    assert!(
        !baseline_report.has_status(validation_status::ASSERTION_NOT_REDACTED),
        "a properly redacted (removed) assertion must not raise assertion.notRedacted"
    );

    // Attack: plant a non-zero CBOR assertion box back into the redacted slot of the
    // ingredient (parent) manifest. `data()` for this box is non-zero, so the reader must
    // reject it even though its box type is not the C2PA Redaction UUID placeholder.
    let alg = store
        .get_claim(&parent_manifest_label)
        .expect("parent claim present")
        .alg()
        .to_owned();
    // A small non-zero CBOR map ({"x": 1}); the exact contents don't matter, only that
    // they are not all-zero.
    let forged = Assertion::from_data_cbor(ASSERTION_LABEL, &[0xa1, 0x61, 0x78, 0x01]);
    let forged_hash = Claim::calc_assertion_box_hash(ASSERTION_LABEL, &forged, None, &alg).unwrap();
    let forged_ca = ClaimAssertion::new(
        forged,
        0,
        &forged_hash,
        &alg,
        None,
        ClaimAssertionType::Created,
    );
    store
        .get_claim_mut(&parent_manifest_label)
        .expect("parent claim present")
        .put_assertion_store(forged_ca);

    let mut attack_report = StatusTracker::default();
    let _ = Store::verify_store(&store, None, &mut attack_report, &Context::new());
    assert!(
        attack_report.has_status(validation_status::ASSERTION_NOT_REDACTED),
        "forged non-zero content at a redacted URI must be rejected with assertion.notRedacted"
    );
}

// `Reader::with_store` used to independently re-derive `assertion.notRedacted`
// from presence alone (no zero check), by comparing the claim's declared redactions
// against assertions that failed to resolve. That logic predates the zero-content check
// above and had no coverage for a *present* redacted box, so it both missed the forged
// case's already-correct failure being logged twice, and false-positived on a validly
// zeroed box. Drive the same scenarios through `Reader::with_store` (not just
// `Store::verify_store`) to prove that's fixed.
#[test]
fn test_redacted_slot_content_through_reader() {
    use crate::{
        assertions::C2paReason, claim::ClaimAssertionType, Builder, BuilderIntent, Reader,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../tests/fixtures/CA.jpg");
    const ASSERTION_LABEL: &str = "stds.schema-org.CreativeWork";

    // Build a legitimately-redacted asset and return the loaded store plus the label
    // of the manifest whose assertion was redacted.
    fn build_redacted_store(image: &[u8]) -> (Store, String) {
        let mut input = Cursor::new(image);
        let parent = Reader::default()
            .with_stream("image/jpeg", &mut input)
            .expect("read parent");
        let parent_manifest_label = parent.active_label().unwrap().to_owned();
        let redacted_uri = to_assertion_uri(&parent_manifest_label, ASSERTION_LABEL);

        let mut builder = Builder::default();
        builder.set_intent(BuilderIntent::Edit);
        builder.definition.redactions = Some(vec![redacted_uri.clone()]);
        let redacted_action = Action::new("c2pa.redacted")
            .set_reason(C2paReason::PiiPresent)
            .set_parameter("redacted".to_owned(), redacted_uri)
            .unwrap();
        builder.add_action(redacted_action).unwrap();

        let signer = test_signer(SigningAlg::Ps256);
        let mut output = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), "image/jpeg", &mut input, &mut output)
            .expect("builder sign");
        output.set_position(0);

        let mut load_report = StatusTracker::default();
        let store =
            Store::from_stream("image/jpeg", &mut output, &mut load_report, &Context::new())
                .expect("load store");
        (store, parent_manifest_label)
    }

    // Replace the redacted slot's (removed) assertion with a present box built from
    // `assertion`, exactly as an attacker editing the manifest-store bytes would.
    fn plant_assertion(store: &mut Store, parent_manifest_label: &str, assertion: Assertion) {
        let alg = store
            .get_claim(parent_manifest_label)
            .expect("parent claim present")
            .alg()
            .to_owned();
        let hash = Claim::calc_assertion_box_hash(ASSERTION_LABEL, &assertion, None, &alg).unwrap();
        let claim_assertion =
            ClaimAssertion::new(assertion, 0, &hash, &alg, None, ClaimAssertionType::Created);
        store
            .get_claim_mut(parent_manifest_label)
            .expect("parent claim present")
            .put_assertion_store(claim_assertion);
    }

    fn count_status(log: &StatusTracker, code: &str) -> usize {
        log.logged_items()
            .iter()
            .filter(|item| item.validation_status.as_deref() == Some(code))
            .count()
    }

    // A validly zeroed box left in the redacted slot (the spec's alternative to full
    // removal) must not be flagged at all: not `assertion.notRedacted` (it *is*
    // correctly redacted) and not `assertion.missing` (it's present, just empty).
    {
        let (mut store, parent_manifest_label) = build_redacted_store(TEST_IMAGE);
        let zeroed = Assertion::from_data_uuid(ASSERTION_LABEL, C2PA_REDACTION_UUID, &[0u8; 4]);
        plant_assertion(&mut store, &parent_manifest_label, zeroed);

        let mut validation_log = StatusTracker::default();
        let _ = Store::verify_store(&store, None, &mut validation_log, &Context::new());
        let mut reader = Reader::default();
        let _ = reader.with_store(store, &mut validation_log);

        assert_eq!(
            count_status(&validation_log, validation_status::ASSERTION_NOT_REDACTED),
            0,
            "a present, zeroed redacted box must not raise assertion.notRedacted"
        );
        assert_eq!(
            count_status(&validation_log, validation_status::ASSERTION_MISSING),
            0,
            "a present, zeroed redacted box must not be counted as missing"
        );
    }

    // A forged, non-zero box in the redacted slot must be rejected exactly once, by
    // `Store::verify_store`'s zero-content check — not a second time by
    // `Reader::with_store`'s (now removed) presence-only reconciliation.
    {
        let (mut store, parent_manifest_label) = build_redacted_store(TEST_IMAGE);
        let forged = Assertion::from_data_cbor(ASSERTION_LABEL, &[0xa1, 0x61, 0x78, 0x01]);
        plant_assertion(&mut store, &parent_manifest_label, forged);

        let mut validation_log = StatusTracker::default();
        let _ = Store::verify_store(&store, None, &mut validation_log, &Context::new());
        let mut reader = Reader::default();
        let _ = reader.with_store(store, &mut validation_log);

        assert_eq!(
            count_status(&validation_log, validation_status::ASSERTION_NOT_REDACTED),
            1,
            "forged non-zero content at a redacted URI must be rejected exactly once"
        );
    }
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
    assert!(report.has_status(validation_status::INGREDIENT_MANIFEST_MISSING));
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
    // use Merkle tree with 1 MB chunks (1 KB chunks on this 64 MB asset take minutes)
    let context = crate::context::Context::new()
        .with_settings_value("core.merkle_tree_chunk_size_in_kb", 1024)
        .unwrap();

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
    // use Merkle tree with 1024 byte chunks an 0 proofs (no UUID boxes)
    let context = crate::context::Context::new()
        .with_settings_value("core.merkle_tree_chunk_size_in_kb", 1)
        .unwrap()
        .with_settings_value("core.merkle_tree_max_proofs", 0)
        .unwrap();

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
fn test_jumbf_generation_with_bmffv3_fixed_block_size_stream() {
    // use Merkle tree with 1024 byte chunks
    let context = crate::context::Context::new()
        .with_settings_value("core.merkle_tree_chunk_size_in_kb", 1)
        .unwrap();

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
    let cm = Store::get_composed_manifest(&em, "image/jpeg", &context).unwrap();

    // insert manifest into output asset
    let jpeg_io = get_assetio_handler_from_path(&ap).unwrap();
    let mut input_file = std::fs::File::open(&ap).unwrap();
    let ol = jpeg_io
        .get_writer("jpg")
        .unwrap()
        .get_object_locations(&mut input_file)
        .unwrap();

    let cai_loc = ol.iter().find(|o| o.htype == ObjectType::C2pa).unwrap();

    // remove any existing manifest
    jpeg_io.get_reader().read_c2pa(&mut input_file).unwrap();

    // build new asset in memory inserting new manifest
    let outbuf = Vec::new();
    let mut out_stream = Cursor::new(outbuf);
    input_file.rewind().unwrap();

    // write before
    let mut before = vec![0u8; usize::try_from(cai_loc.offset).unwrap()];
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
    let cm = Store::get_composed_manifest(&em, "jpg", &context).unwrap();

    // insert manifest into output asset
    let jpeg_io = get_assetio_handler_from_path(&ap).unwrap();
    let mut input_file = std::fs::File::open(&ap).unwrap();
    let ol = jpeg_io
        .get_writer("jpg")
        .unwrap()
        .get_object_locations(&mut input_file)
        .unwrap();

    let cai_loc = ol.iter().find(|o| o.htype == ObjectType::C2pa).unwrap();

    // remove any existing manifest
    jpeg_io.get_reader().read_c2pa(&mut input_file).unwrap();

    // build new asset in memory inserting new manifest
    let outbuf = Vec::new();
    let mut out_stream = Cursor::new(outbuf);
    input_file.rewind().unwrap();

    // write before
    let mut before = vec![0u8; usize::try_from(cai_loc.offset).unwrap()];
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

#[test]
fn test_sign_manifest_reserves_dynamic_assertion_placeholders_itself() {
    // A signer that advertises a dynamic assertion, with the caller never
    // reserving a placeholder slot for it. `sign_manifest` must reserve (and
    // fill in) that slot itself rather than requiring the caller to call
    // `add_dynamic_assertion_placeholders` first (see issue #2055 review for
    // why placeholder slots and real content must come from the same
    // `dynamic_assertions()` call).
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
            _claim: &PartialClaim,
        ) -> Result<DynamicAssertionContent> {
            let assertion = TestAssertion {
                my_tag: "some value I will replace".to_string(),
            };
            Ok(DynamicAssertionContent::Cbor(
                c2pa_cbor::to_vec(&assertion).unwrap(),
            ))
        }
    }

    struct DynamicSigner(crate::BoxedSigner);

    impl crate::Signer for DynamicSigner {
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
            vec![Box::new(TestDynamicAssertion {})]
        }
    }

    let signer = DynamicSigner(test_signer(SigningAlg::Ps256));
    let context = crate::context::Context::new().with_signer(signer);

    let mut claim = create_test_claim().unwrap();
    let mut hard_binding = DataHash::new("jumbf manifest", "sha256");
    hard_binding.hash = vec![0; 32];
    claim.add_assertion(&hard_binding).unwrap();

    let mut store = Store::from_context(&context);
    store.commit_claim(claim).unwrap();
    store.get_placeholder("jpeg", &context).unwrap();

    let jumbf_bytes = store.sign_manifest(&context, None).unwrap();

    let mut validation_log = StatusTracker::default();
    let signed_store =
        Store::from_jumbf_with_context(&jumbf_bytes, &mut validation_log, &context).unwrap();
    let pc = signed_store.provenance_claim().unwrap();
    assert!(
        pc.assertion_hashed_uri_from_label("com.mycompany.myassertion")
            .is_some(),
        "dynamic assertion should be present in the signed manifest"
    );
}

#[test]
fn test_datahash_embeddable_manifest_user_hashed() -> Result<()> {
    let sign_with_data_hash = |hash: Vec<u8>, exclusion: crate::HashRange| -> Result<Vec<u8>> {
        let mut data_hash = DataHash::new("jumbf manifest", "sha256");
        data_hash.set_hash(hash);
        data_hash.add_exclusion(exclusion);

        let definition = serde_json::json!({
            "claim_generator_info": [{"name": "c2pa_test", "version": "1.0.0"}],
            "title": "Test_Manifest",
            "assertions": [{
                "label": "c2pa.actions",
                "data": {"actions": [{
                    "action": "c2pa.created",
                    "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"
                }]}
            }]
        })
        .to_string();
        let mut builder = crate::Builder::default().with_definition(definition)?;
        builder.add_assertion(DataHash::LABEL, &data_hash)?;
        builder.sign_embeddable("image/jpeg")
    };

    const TEST_IMAGE_CLOUD: &[u8] = include_bytes!("../../tests/fixtures/cloud.jpg");

    // Start with a same-sized signed manifest, then update its exclusion range
    // to the actual embedded location before hashing the asset.
    let mut placeholder = sign_with_data_hash(vec![0; 32], crate::HashRange::new(0, 0))?;
    let mut embedded_asset = None;
    for _ in 0..4 {
        let mut input_stream = Cursor::new(TEST_IMAGE_CLOUD);
        let mut output_stream = Cursor::new(Vec::new());
        let offset = crate::utils::test::write_jpeg_placeholder_stream(
            &placeholder,
            "image/jpeg",
            &mut input_stream,
            &mut output_stream,
            None,
        )?;
        let next_placeholder = sign_with_data_hash(
            vec![0; 32],
            crate::HashRange::new(offset as u64, placeholder.len() as u64),
        )?;

        if next_placeholder.len() == placeholder.len() {
            output_stream.seek(SeekFrom::Start(offset as u64))?;
            output_stream.write_all(&next_placeholder)?;
            output_stream.rewind()?;
            embedded_asset = Some((offset, next_placeholder, output_stream));
            break;
        }
        placeholder = next_placeholder;
    }

    assert!(
        embedded_asset.is_some(),
        "Precomputed DataHash placeholder size did not stabilize"
    );
    let (offset, placeholder, mut output_stream) = embedded_asset.unwrap();

    // Calculate the asset hash outside the Builder, excluding the reserved manifest.
    let mut data_hash = DataHash::new("jumbf manifest", "sha256");
    data_hash.add_exclusion(crate::HashRange::new(
        offset as u64,
        placeholder.len() as u64,
    ));
    output_stream.rewind()?;
    data_hash.gen_hash_from_stream(&mut output_stream)?;

    let signed_manifest = sign_with_data_hash(
        data_hash.hash.clone(),
        crate::HashRange::new(offset as u64, placeholder.len() as u64),
    )?;
    assert_eq!(
        signed_manifest.len(),
        placeholder.len(),
        "The precomputed DataHash must preserve the reserved manifest size"
    );

    output_stream.seek(SeekFrom::Start(offset as u64))?;
    output_stream.write_all(&signed_manifest)?;
    output_stream.rewind()?;
    let reader = crate::Reader::default().with_stream("image/jpeg", output_stream)?;
    assert_eq!(reader.validation_state(), crate::ValidationState::Trusted);

    Ok(())
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

/// Two dynamic assertions that share a label must each land in their own
/// placeholder (`label` and `label__1`) with their own content and size.
/// Before the instance-aware replacement, both contents were written into
/// the first placeholder, leaving the second one as zeros and, when the two
/// reserve sizes differed, shifting the manifest so the data hash no longer
/// matched.
#[test]
fn test_dynamic_assertions_same_label_twice() {
    let context = crate::context::Context::new();

    #[derive(Serialize)]
    struct TestAssertion {
        my_tag: String,
    }

    #[derive(Debug)]
    struct TestDynamicAssertion {
        tag: String,
    }

    impl DynamicAssertion for TestDynamicAssertion {
        fn label(&self) -> String {
            "com.mycompany.myassertion".to_string()
        }

        fn reserve_size(&self) -> Result<usize> {
            let assertion = TestAssertion {
                my_tag: self.tag.clone(),
            };
            Ok(c2pa_cbor::to_vec(&assertion)?.len())
        }

        fn content(
            &self,
            label: &str,
            _size: Option<usize>,
            _claim: &PartialClaim,
        ) -> Result<DynamicAssertionContent> {
            // The label handed to us carries the instance suffix.
            let expected = if self.tag.len() > 8 {
                "com.mycompany.myassertion__1"
            } else {
                "com.mycompany.myassertion"
            };
            assert_eq!(label, expected);

            let assertion = TestAssertion {
                my_tag: self.tag.clone(),
            };

            Ok(DynamicAssertionContent::Cbor(
                c2pa_cbor::to_vec(&assertion).unwrap(),
            ))
        }
    }

    struct DynamicSigner(Box<dyn Signer>);

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

        // Two dynamic assertions with the SAME label and DIFFERENT sizes.
        fn dynamic_assertions(&self) -> Vec<Box<dyn crate::dynamic_assertion::DynamicAssertion>> {
            vec![
                Box::new(TestDynamicAssertion {
                    tag: "first".to_string(),
                }),
                Box::new(TestDynamicAssertion {
                    tag: "second, and longer".to_string(),
                }),
            ]
        }
    }

    let file_buffer = include_bytes!("../../tests/fixtures/earth_apollo17.jpg").to_vec();
    let mut buf_io = Cursor::new(file_buffer);

    let mut store = Store::from_context(&context);
    let claim1 = create_test_claim().unwrap();
    let signer = DynamicSigner(test_signer(SigningAlg::Ps256));
    store.commit_claim(claim1).unwrap();

    let mut result_stream = Cursor::new(Vec::new());
    store
        .save_to_stream("jpeg", &mut buf_io, &mut result_stream, &signer, &context)
        .unwrap();
    result_stream.rewind().unwrap();

    let mut report = StatusTracker::default();
    let new_store =
        Store::from_stream("image/jpeg", &mut result_stream, &mut report, &context).unwrap();
    assert!(!report.has_any_error(), "{report:?}");

    let claim = new_store.provenance_claim().unwrap();
    let mut tags = Vec::new();
    for label in ["com.mycompany.myassertion", "com.mycompany.myassertion__1"] {
        let ca = claim
            .claim_assertion_store()
            .iter()
            .find(|ca| ca.label() == label)
            .unwrap_or_else(|| panic!("missing {label}"));
        let value: serde_json::Value = c2pa_cbor::from_slice(ca.assertion().data()).unwrap();
        tags.push(value["my_tag"].as_str().unwrap().to_string());
    }
    assert_eq!(tags, vec!["first", "second, and longer"]);
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
        Some(&mut ClaimAssetData::Bytes(&result, "jpg")),
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
    context.settings_mut().verify.verify_after_reading = true;

    // test adding to actual image

    let tempdir = tempdirectory().expect("temp dir");
    let output_path = tempdir.path();

    // search folders for init segments
    let mut inits = Vec::new();
    for item in glob::glob(&fixture_path("bunny/**/BigBuckBunny_2s_init.mp4").to_string_lossy())
        .unwrap()
        .flatten()
    {
        inits.push(item);
    }

    // Create claims store.
    let mut store = Store::from_context(&context);

    // Create a new claim.
    let claim = create_test_claim().unwrap();
    store.commit_claim(claim).unwrap();

    // Do we generate JUMBF?
    let signer = test_cawg_signer(SigningAlg::Ps256, &[labels::SCHEMA_ORG_INTERNAL]).unwrap();

    store
        .save_to_bmff_fragmented(
            &inits,
            &PathBuf::from("BigBuckBunny_2s*.m4s"),
            &output_path.to_path_buf(),
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // verify the fragments
    for init_path in &inits {
        let init_name = PathBuf::from(init_path.file_name().unwrap_or_default());
        let init_dir = PathBuf::from(init_path.parent().unwrap().file_name().unwrap());

        let mut output_file = output_path.to_path_buf();
        output_file = output_file.join(&init_dir).join(&init_name);

        let mut init_stream = std::fs::File::open(&output_file).unwrap();

        // build the list of fragments for this init segment based on the glob pattern
        let mut fragments = Vec::new();
        let frag_glob = output_path.join(&init_dir).join("BigBuckBunny_2s*.m4s");
        let frag_glob_str = frag_glob.to_str().unwrap();

        // grab the fragments that go with this init segment
        for entry in glob::glob(frag_glob_str).unwrap() {
            fragments.push(entry.unwrap());
        }

        // check fragments individually
        for entry in &fragments {
            let mut validation_log = StatusTracker::default();

            let mut fragment_stream = std::fs::File::open(entry).unwrap();
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

        // check all fragments together with the init
        let mut validation_log = StatusTracker::default();
        init_stream.rewind().unwrap();
        let _manifest = Store::load_from_file_and_fragments(
            "mp4",
            &mut init_stream,
            &fragments,
            &mut validation_log,
            &context,
        )
        .unwrap();

        assert!(!validation_log.has_any_error());
    }
}

#[test]
#[cfg(feature = "file_io")]
fn test_bogus_cert() {
    use crate::builder::{Builder, BuilderIntent};

    let png = include_bytes!("../../tests/fixtures/libpng-test.png"); // Randomly generated local Ed25519
    let ed25519 = include_bytes!("../../tests/fixtures/certs/ed25519.pem");
    let certs = include_bytes!("../../tests/fixtures/certs/es256.pub");

    // bypass auto signature checks
    let context = Context::new()
        .with_settings_value("verify.verify_after_sign", false)
        .unwrap()
        .with_settings_value("verify.verify_trust", false)
        .unwrap();

    let mut builder = Builder::from_context(context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));

    let signer =
        crate::create_signer::from_keys(certs, ed25519, SigningAlg::Ed25519, None).unwrap();
    let mut dst = Cursor::new(Vec::new());

    builder
        .sign(&signer, "image/png", &mut Cursor::new(png), &mut dst)
        .unwrap();

    let reader = crate::Reader::default()
        .with_stream("image/png", &mut dst)
        .unwrap();

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
    struct FlushTrackingStream<T: ReadWriteSeek> {
        inner: T,
        buffer: Vec<u8>,
        flush_called: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl<T: ReadWriteSeek> FlushTrackingStream<T> {
        fn new(inner: T, flush_called: Arc<AtomicBool>, dropped: Arc<AtomicBool>) -> Self {
            Self {
                inner,
                buffer: Vec::new(),
                flush_called,
                dropped,
            }
        }
    }

    impl<T: ReadWriteSeek> Read for FlushTrackingStream<T> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    impl<T: ReadWriteSeek> Write for FlushTrackingStream<T> {
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

    impl<T: ReadWriteSeek> Seek for FlushTrackingStream<T> {
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

    impl<T: ReadWriteSeek> Drop for FlushTrackingStream<T> {
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

#[test]
fn test_ingredient_depth_limit_get_claim_referenced_manifests() {
    let store = Store::new();
    let claim = Claim::new("depth_test", Some("contentauth"), 2);
    let mut svi = StoreValidationInfo::default();
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

    // Pre-fill claim_label_path to exactly MAX_INGREDIENT_DEPTH entries so the
    // depth guard fires immediately without needing a real ingredient chain.
    let labels: Vec<String> = (0..MAX_INGREDIENT_DEPTH)
        .map(|i| format!("claim_{i}"))
        .collect();
    let mut claim_label_path: Vec<&str> = labels.iter().map(String::as_str).collect();

    let result = Store::get_claim_referenced_manifests_impl(
        &claim,
        &store,
        &mut svi,
        true,
        &mut validation_log,
        &mut claim_label_path,
    );

    assert!(
        matches!(result, Err(Error::InvalidAsset(_))),
        "expected Err(InvalidAsset) for depth >= MAX_INGREDIENT_DEPTH, got: {result:?}"
    );
}

#[test]
fn test_ingredient_depth_limit_ingredient_checks() {
    use crate::context::Context;

    let store = Store::new();
    let claim = Claim::new("depth_test", Some("contentauth"), 2);
    let svi = StoreValidationInfo::default();
    let mut validation_log = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let context = Context::new();

    let result = Store::ingredient_checks(
        &store,
        &claim,
        &svi,
        &mut validation_log,
        MAX_INGREDIENT_DEPTH,
        &context,
        &mut HashSet::new(),
    );

    assert!(
        matches!(result, Err(Error::InvalidAsset(_))),
        "expected Err(InvalidAsset) for depth >= MAX_INGREDIENT_DEPTH, got: {result:?}"
    );
}

// Verify that when an ingredient assertion is included in final_redactions, the claim it
// referenced is removed from the incoming store and from svi.ingredient_references.
#[test]
fn test_redacted_ingredient_assertion_removes_claim() {
    use crate::{
        hashed_uri::HashedUri, jumbf::labels::to_signature_uri, utils::test::create_test_store_v1,
        ClaimGeneratorInfo, ValidationResults,
    };

    let context = Context::new();
    let signer = test_signer(SigningAlg::Ps256);

    // --- Build M1: a simple signed manifest with no sub-ingredients. ---
    let (format, mut input_stream, mut m1_output) = create_test_streams("earth_apollo17.jpg");
    let mut m1_store = create_test_store_v1().unwrap();
    m1_store
        .save_to_stream(
            format,
            &mut input_stream,
            &mut m1_output,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    m1_output.rewind().unwrap();
    let m1_vec = m1_output.get_ref().clone();
    let mut m1_report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let m1_store_loaded = Store::from_stream(
        format,
        Cursor::new(m1_vec.clone()),
        &mut m1_report,
        &context,
    )
    .unwrap();
    let m1_pc = m1_store_loaded.provenance_claim().unwrap();
    let m1_label = m1_pc.label().to_owned();

    // --- Build M2: an update manifest whose ingredient assertion points to M1. ---
    let mut m2_claim = Claim::new("test", Some("m2_ingredient_redact"), 2);
    m2_claim.add_claim_generator_info(ClaimGeneratorInfo::new("test"));

    let (m1_jumbf, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(m1_vec.clone()), &context).unwrap();
    let mut m2_store =
        Store::load_ingredient_to_claim(&mut m2_claim, &m1_jumbf, None, &context).unwrap();

    let m1_hashes = m1_store_loaded.get_manifest_box_hashes(m1_pc);
    let parent_uri = HashedUri::new(
        m1_store_loaded.provenance_path().unwrap(),
        Some(m1_pc.alg().to_string()),
        &m1_hashes.manifest_box_hash,
    );
    let sig_uri = HashedUri::new(
        to_signature_uri(m1_pc.label()),
        Some(m1_pc.alg().to_string()),
        &m1_hashes.signature_box_hash,
    );

    let m1_validation = ValidationResults::from_store(&m1_store_loaded, &m1_report);
    let parent_ingredient = Ingredient::new_v3(Relationship::ParentOf)
        .set_active_manifests_and_signature_from_hashed_uri(Some(parent_uri), Some(sig_uri))
        .set_validation_results(Some(m1_validation));
    m2_claim.add_assertion(&parent_ingredient).unwrap();

    // An action referencing the ingredient is required by the update manifest schema.
    let ia = m2_claim.ingredient_assertions()[0];
    let ia_hashed_uri = HashedUri::new(
        to_assertion_uri(m2_claim.label(), &ia.label()),
        Some(m2_claim.alg().to_owned()),
        ia.hash(),
    );
    let actions = Actions::new().add_action(
        Action::new("c2pa.opened")
            .set_parameter("ingredients", vec![ia_hashed_uri])
            .unwrap(),
    );
    m2_claim.add_assertion(&actions).unwrap();

    m2_store.commit_update_manifest(m2_claim).unwrap();
    m1_output.rewind().unwrap();
    let mut m2_output = Cursor::new(Vec::new());
    m2_store
        .save_to_stream(
            format,
            &mut m1_output,
            &mut m2_output,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    // Load M2 back to discover the exact labels and ingredient assertion label.
    m2_output.rewind().unwrap();
    let m2_vec = m2_output.get_ref().clone();
    let mut m2_report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
    let m2_store_loaded = Store::from_stream(
        format,
        Cursor::new(m2_vec.clone()),
        &mut m2_report,
        &context,
    )
    .unwrap();
    let m2_pc = m2_store_loaded.provenance_claim().unwrap();
    let m2_label = m2_pc.label().to_owned();

    // Build a redaction URI targeting M2's ingredient assertion (which points to M1).
    let m2_ingredient_assertions = m2_pc.ingredient_assertions();
    assert!(
        !m2_ingredient_assertions.is_empty(),
        "M2 should have an ingredient assertion"
    );
    let ingredient_redaction_uri =
        to_assertion_uri(m2_pc.label(), &m2_ingredient_assertions[0].label());

    // --- Load M2 into M3 with the ingredient assertion redacted. ---
    let mut m3_claim = Claim::new("test", Some("m3_ingredient_redact"), 2);
    m3_claim.add_claim_generator_info(ClaimGeneratorInfo::new("test"));

    let (m2_jumbf, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(m2_vec), &context).unwrap();
    Store::load_ingredient_to_claim(
        &mut m3_claim,
        &m2_jumbf,
        Some(vec![ingredient_redaction_uri]),
        &context,
    )
    .unwrap();

    // M2 (the provenance claim of the incoming store) must still be present.
    assert!(
        m3_claim.claim_ingredient(&m2_label).is_some(),
        "M2 should remain in M3's ingredients"
    );

    // M1 must have been removed: its only reference (M2's ingredient assertion) was redacted.
    assert!(
        m3_claim.claim_ingredient(&m1_label).is_none(),
        "M1 should be removed because its only referencing assertion was redacted"
    );
}

const COLLECTION_ZIP: &[u8] = include_bytes!("../../tests/fixtures/sample1.zip");

#[test]
fn test_store_verify_zip_collection_hash() {
    let mut claim = create_test_claim().unwrap();

    let mut collection = CollectionHash::new(claim.alg().to_owned());
    collection
        .gen_hash_from_zip_stream(&mut Cursor::new(COLLECTION_ZIP))
        .unwrap();
    claim.add_created_assertion(&collection).unwrap();

    let mut store = Store::from_context(&Context::new());
    store.commit_claim(claim).unwrap();
    let claim = store.provenance_claim().unwrap();

    let svi = StoreValidationInfo {
        binding_claim: claim.label().to_string(),
        ..Default::default()
    };
    let context = Context::new();
    let mut report = StatusTracker::default();
    let mut asset_data = ClaimAssetData::Bytes(COLLECTION_ZIP, "zip");

    Claim::verify_hash_binding(claim, &mut asset_data, &svi, &mut report, &context).unwrap();

    assert!(report.has_status(validation_status::ASSERTION_COLLECTIONHASH_MATCH));
}

#[test]
fn test_sign_zip_generates_valid_collection_hash() {
    let mut context = Context::new();
    context.settings_mut().verify.verify_after_sign = false;

    let mut store = Store::from_context(&context);
    store.commit_claim(create_test_claim().unwrap()).unwrap();

    let signer = test_signer(SigningAlg::Ps256);
    let mut input = Cursor::new(COLLECTION_ZIP.to_vec());
    let mut output = Cursor::new(Vec::new());
    store
        .save_to_stream("zip", &mut input, &mut output, signer.as_ref(), &context)
        .unwrap();

    let mut report = StatusTracker::default();
    output.rewind().unwrap();
    Store::from_stream("zip", &mut output, &mut report, &context).unwrap();

    assert!(
        report.has_status(validation_status::ASSERTION_COLLECTIONHASH_MATCH),
        "the generated collection hash should verify against the signed ZIP"
    );
}

#[test]
fn test_sign_zip_update_manifest_is_unsupported() {
    let mut context = Context::new();
    context.settings_mut().verify.verify_after_sign = false;

    let mut claim = create_test_claim().unwrap();
    claim.set_update_manifest(true);

    let mut store = Store::from_context(&context);
    store.commit_claim(claim).unwrap();

    let signer = test_signer(SigningAlg::Ps256);
    let mut input = Cursor::new(COLLECTION_ZIP.to_vec());
    let mut output = Cursor::new(Vec::new());
    let result = store.save_to_stream("zip", &mut input, &mut output, signer.as_ref(), &context);

    assert!(
        matches!(&result, Err(Error::BadParam(msg)) if msg.contains("update manifests are not supported")),
        "expected update manifests to be rejected for ZIP, got {result:?}"
    );
}

#[cfg(feature = "fetch_remote_manifests")]
mod remote_manifest_response_tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::{
        http::{AsyncHttpResolver, HttpResolverError, SyncHttpResolver},
        settings::DEFAULT_MAX_MANIFEST_RESPONSE_SIZE,
    };

    const TEST_RESPONSE_SIZE: u64 = 16;

    struct Resolver {
        content_length: Option<&'static str>,
        body_length: u64,
        error_after: Option<u64>,
        probe_interruptions: usize,
        bytes_read: Arc<AtomicUsize>,
    }

    struct Body {
        remaining: u64,
        error_after: Option<u64>,
        probe_interruptions: usize,
        eof_returned: bool,
        bytes_read: Arc<AtomicUsize>,
    }

    impl Read for Body {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.bytes_read.load(Ordering::SeqCst) as u64 == TEST_RESPONSE_SIZE
                && self.probe_interruptions > 0
            {
                self.probe_interruptions -= 1;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            if self
                .error_after
                .is_some_and(|limit| self.bytes_read.load(Ordering::SeqCst) as u64 >= limit)
                || self.eof_returned
            {
                return Err(std::io::Error::other("test stream failure"));
            }
            let until_error = self.error_after.map_or(u64::MAX, |limit| {
                limit - self.bytes_read.load(Ordering::SeqCst) as u64
            });
            let len = self.remaining.min(buf.len() as u64).min(until_error) as usize;
            buf[..len].fill(b'x');
            self.remaining -= len as u64;
            if !buf.is_empty() && len == 0 {
                self.eof_returned = true;
            }
            self.bytes_read.fetch_add(len, Ordering::SeqCst);
            Ok(len)
        }
    }

    impl SyncHttpResolver for Resolver {
        fn http_resolve(
            &self,
            _request: http::Request<Vec<u8>>,
        ) -> std::result::Result<http::Response<Box<dyn Read>>, HttpResolverError> {
            let mut response = http::Response::builder().status(200);
            if let Some(len) = self.content_length {
                response = response.header(http::header::CONTENT_LENGTH, len);
            }
            Ok(response
                .body(Box::new(Body {
                    remaining: self.body_length,
                    error_after: self.error_after,
                    probe_interruptions: self.probe_interruptions,
                    eof_returned: false,
                    bytes_read: self.bytes_read.clone(),
                }) as Box<dyn Read>)
                .unwrap())
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl AsyncHttpResolver for Resolver {
        async fn http_resolve_async(
            &self,
            request: http::Request<Vec<u8>>,
        ) -> std::result::Result<http::Response<Box<dyn Read>>, HttpResolverError> {
            self.http_resolve(request)
        }
    }

    async fn fetch(
        content_length: Option<&'static str>,
        body_length: u64,
        error_after: Option<u64>,
        use_async: bool,
    ) -> (Result<Vec<u8>>, usize) {
        let context = Context::new()
            .with_settings_value("verify.max_manifest_response_size", TEST_RESPONSE_SIZE)
            .unwrap();
        fetch_with_context(context, content_length, body_length, error_after, use_async).await
    }

    async fn fetch_with_context(
        context: Context,
        content_length: Option<&'static str>,
        body_length: u64,
        error_after: Option<u64>,
        use_async: bool,
    ) -> (Result<Vec<u8>>, usize) {
        let bytes_read = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(Resolver {
            content_length,
            body_length,
            error_after,
            probe_interruptions: 0,
            bytes_read: bytes_read.clone(),
        });
        let context = context
            .with_resolver(resolver.clone())
            .with_resolver_async(resolver);
        let result = if use_async {
            Store::fetch_remote_manifest_async("https://example.com/manifest.c2pa", &context).await
        } else {
            Store::fetch_remote_manifest("https://example.com/manifest.c2pa", &context)
        };
        (result, bytes_read.load(Ordering::SeqCst))
    }

    fn assert_size_error(result: Result<Vec<u8>>) {
        assert!(
            matches!(result, Err(Error::RemoteManifestFetch(ref msg)) if msg == "remote manifest exceeds the 16 byte response size limit"),
            "expected response size error, got {result:?}"
        );
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_overflow_probe_retries_interrupted() {
        for use_async in [false, true] {
            for body_length in [TEST_RESPONSE_SIZE, TEST_RESPONSE_SIZE + 1] {
                let bytes_read = Arc::new(AtomicUsize::new(0));
                let resolver = Arc::new(Resolver {
                    content_length: None,
                    body_length,
                    error_after: None,
                    probe_interruptions: 2,
                    bytes_read: bytes_read.clone(),
                });
                let context = Context::new()
                    .with_settings_value("verify.max_manifest_response_size", TEST_RESPONSE_SIZE)
                    .unwrap()
                    .with_resolver(resolver.clone())
                    .with_resolver_async(resolver);
                let result = if use_async {
                    Store::fetch_remote_manifest_async(
                        "https://example.com/manifest.c2pa",
                        &context,
                    )
                    .await
                } else {
                    Store::fetch_remote_manifest("https://example.com/manifest.c2pa", &context)
                };
                if body_length == TEST_RESPONSE_SIZE {
                    assert_eq!(result.unwrap(), vec![b'x'; TEST_RESPONSE_SIZE as usize]);
                } else {
                    assert_size_error(result);
                }
                assert_eq!(bytes_read.load(Ordering::SeqCst) as u64, body_length);
            }
        }
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_oversized_header_rejected_before_reading() {
        for use_async in [false, true] {
            for header in ["18446744073709551615", "4294967295", "17"] {
                let (result, bytes_read) = fetch(Some(header), 1, None, use_async).await;
                assert_size_error(result);
                assert_eq!(bytes_read, 0);
            }
        }
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_body_limit_ignores_untrusted_header() {
        for use_async in [false, true] {
            for header in [
                None,
                Some("1"),
                Some("invalid"),
                Some("18446744073709551616"),
            ] {
                let (result, bytes_read) =
                    fetch(header, TEST_RESPONSE_SIZE + 100, None, use_async).await;
                assert_size_error(result);
                assert_eq!(bytes_read as u64, TEST_RESPONSE_SIZE + 1);
            }
        }
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_exact_limit_accepted() {
        for use_async in [false, true] {
            for header in [None, Some("16")] {
                let (result, bytes_read) = fetch(header, TEST_RESPONSE_SIZE, None, use_async).await;
                let body = result.unwrap();
                assert_eq!(body.len() as u64, TEST_RESPONSE_SIZE);
                assert!(body.iter().all(|byte| *byte == b'x'));
                assert_eq!(bytes_read as u64, TEST_RESPONSE_SIZE);
            }
        }
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_small_body_not_truncated_by_header() {
        for use_async in [false, true] {
            for header in [
                None,
                Some("0"),
                Some("1"),
                Some("3"),
                Some("10"),
                Some("invalid"),
            ] {
                let (result, bytes_read) = fetch(header, 3, None, use_async).await;
                assert_eq!(result.unwrap(), b"xxx");
                assert_eq!(bytes_read, 3);
            }
            let (result, bytes_read) = fetch(Some("0"), 0, None, use_async).await;
            assert!(result.unwrap().is_empty());
            assert_eq!(bytes_read, 0);
        }
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_body_read_error_propagated() {
        for use_async in [false, true] {
            let (result, _) = fetch(None, 3, Some(0), use_async).await;
            assert!(
                matches!(result, Err(Error::RemoteManifestFetch(ref msg)) if msg.contains("error reading content stream")),
                "expected stream read error, got {result:?}"
            );
        }
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_overflow_probe_read_error_propagated() {
        for use_async in [false, true] {
            let (result, bytes_read) = fetch(
                Some("16"),
                TEST_RESPONSE_SIZE,
                Some(TEST_RESPONSE_SIZE),
                use_async,
            )
            .await;
            assert!(
                matches!(result, Err(Error::RemoteManifestFetch(ref msg)) if msg == "error reading content stream"),
                "expected overflow probe read error, got {result:?}"
            );
            assert_eq!(bytes_read as u64, TEST_RESPONSE_SIZE);
        }
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_default_and_raised_limits_are_independent() {
        for use_async in [false, true] {
            let raised = Context::new()
                .with_settings_value(
                    "verify.max_manifest_response_size",
                    DEFAULT_MAX_MANIFEST_RESPONSE_SIZE + 1,
                )
                .unwrap();
            let (result, bytes_read) = fetch_with_context(
                raised,
                Some("10485761"),
                DEFAULT_MAX_MANIFEST_RESPONSE_SIZE + 1,
                None,
                use_async,
            )
            .await;
            let body = result.unwrap();
            assert_eq!(body.len() as u64, DEFAULT_MAX_MANIFEST_RESPONSE_SIZE + 1);
            assert_eq!(bytes_read, body.len());

            let default = Context::new();
            assert_eq!(
                default.settings().verify.max_manifest_response_size,
                DEFAULT_MAX_MANIFEST_RESPONSE_SIZE
            );
            let (result, bytes_read) =
                fetch_with_context(default, Some("10485761"), 1, None, use_async).await;
            assert!(
                matches!(result, Err(Error::RemoteManifestFetch(ref msg)) if msg == "remote manifest exceeds the 10485760 byte response size limit"),
                "expected the default limit to remain unchanged, got {result:?}"
            );
            assert_eq!(bytes_read, 0);

            let (result, bytes_read) = fetch_with_context(
                Context::new(),
                Some("10485760"),
                DEFAULT_MAX_MANIFEST_RESPONSE_SIZE,
                None,
                use_async,
            )
            .await;
            assert_eq!(
                result.unwrap().len() as u64,
                DEFAULT_MAX_MANIFEST_RESPONSE_SIZE
            );
            assert_eq!(bytes_read as u64, DEFAULT_MAX_MANIFEST_RESPONSE_SIZE);
        }
    }

    #[c2pa_test_async]
    async fn test_remote_manifest_directly_mutated_invalid_limit_rejected() {
        for use_async in [false, true] {
            for limit in [0, u64::MAX] {
                let mut context = Context::new();
                context.settings_mut().verify.max_manifest_response_size = limit;
                let (result, bytes_read) =
                    fetch_with_context(context, None, 1, None, use_async).await;
                assert!(
                    matches!(result, Err(Error::BadParam(ref msg)) if msg.contains("max_manifest_response_size")),
                    "expected invalid settings error, got {result:?}"
                );
                assert_eq!(bytes_read, 0);
            }
        }
    }
}

// SSRF via HTTP redirect during remote-manifest fetch
// (CAI-12574 / HackerOne #3784091).
//
// The report's PoC embeds a remote-manifest URL that an attacker server answers with a 302
// redirect to an internal / cloud-metadata endpoint (e.g. 169.254.169.254). The SDK must not
// follow that redirect. These tests drive the actual `fetch_remote_manifest` path rather than
// the resolver in isolation.
//
// Under the DEFAULT policy (`allow_redirects = true`), the initial (loopback, in this hermetic
// test) request is allowed, and the redirect is followed up to the point where its target is
// seen to be an internal address, which is then rejected as `RedirectTargetDisallowed`.
#[cfg(all(not(target_arch = "wasm32"), feature = "fetch_remote_manifests"))]
#[test]
fn test_remote_manifest_redirect_to_internal_blocked() {
    use httpmock::prelude::*;

    let server = MockServer::start();

    let redirect = server.mock(|when, then| {
        when.method(GET).path("/redirect-to-internal");
        then.status(302)
            .header("Location", "http://169.254.169.254/latest/meta-data/");
    });

    let context = Context::new();
    let result = Store::fetch_remote_manifest(&server.url("/redirect-to-internal"), &context);

    // The redirect to an internal address is rejected with an explanatory message.
    let err = result.expect_err("the redirect to an internal address must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("redirect") && msg.contains("internal"),
        "error should explain the blocked internal redirect, got: {msg}"
    );

    // The redirect endpoint is hit once; the internal target is never contacted.
    redirect.assert_calls(1);
}

// SSRF via a manifest URL that *directly* names a cloud-metadata address, no redirect involved
// (CAI-13326, the residual issue left after CAI-12574 closed the redirect vector).
//
// Under the DEFAULT policy (no `allowed_network_hosts` configured), the initial request is
// still rejected when it directly targets a link-local/cloud-metadata address. No network call
// is made at all — the guard rejects before dialing out — so this test needs no mock server.
#[cfg(all(not(target_arch = "wasm32"), feature = "fetch_remote_manifests"))]
#[test]
fn test_remote_manifest_direct_metadata_url_blocked() {
    let context = Context::new();
    let result = Store::fetch_remote_manifest("http://169.254.169.254/latest/meta-data/", &context);

    let err = result.expect_err("a direct request to a cloud-metadata address must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("link-local") || msg.contains("cloud-metadata"),
        "error should explain the blocked link-local/metadata target, got: {msg}"
    );
}

// With `allow_redirects = false`, the SDK refuses to follow any redirect at all.
#[cfg(all(not(target_arch = "wasm32"), feature = "fetch_remote_manifests"))]
#[test]
fn test_remote_manifest_redirects_disabled() {
    use httpmock::prelude::*;

    let server = MockServer::start();

    let redirect = server.mock(|when, then| {
        when.method(GET).path("/redirect");
        then.status(302).header("Location", server.url("/target"));
    });
    let target = server.mock(|when, then| {
        when.method(GET).path("/target");
        then.status(200).body("SSRF_CONFIRMED");
    });

    let context = Context::new()
        .with_settings("[core]\nallow_redirects = false\n")
        .unwrap();
    let result = Store::fetch_remote_manifest(&server.url("/redirect"), &context);

    assert!(
        result.is_err(),
        "allow_redirects = false must not follow the redirect"
    );

    // The redirect endpoint is hit once; the target is never contacted.
    redirect.assert_calls(1);
    target.assert_calls(0);
}

/// Builds a signed regular manifest (M2) that references a separately-signed
/// manifest (M1) as an `inputTo` ingredient.
///
/// When `corrupt_hash` is true, M2's ingredient assertion commits (under M2's
/// COSE signature) to a bogus `activeManifest` box hash, simulating an
/// `inputTo` ingredient whose manifest bytes were altered after signing.
/// `verify_after_sign` is disabled so the corrupt asset can be written and the
/// detection exercised on the read-back path.
///
/// Returns the asset mime format and the signed M2 bytes.
fn build_asset_with_input_to_ingredient(corrupt_hash: bool) -> (&'static str, Vec<u8>) {
    use crate::{
        hashed_uri::HashedUri, jumbf::labels::to_signature_uri, utils::test::create_test_store,
        ClaimGeneratorInfo, ValidationResults,
    };

    let mut context = Context::new();
    context.settings_mut().verify.verify_after_sign = false;
    let signer = test_signer(SigningAlg::Ps256);

    // --- M1: a standalone signed ingredient manifest. ---
    let (format, mut m1_input, mut m1_output) = create_test_streams("earth_apollo17.jpg");
    let mut m1_store = create_test_store().unwrap();
    m1_store
        .save_to_stream(
            format,
            &mut m1_input,
            &mut m1_output,
            signer.as_ref(),
            &context,
        )
        .unwrap();
    m1_output.rewind().unwrap();
    let m1_vec = m1_output.get_ref().clone();

    let mut m1_report = StatusTracker::default();
    let m1_store_loaded = Store::from_stream(
        format,
        Cursor::new(m1_vec.clone()),
        &mut m1_report,
        &context,
    )
    .unwrap();
    let m1_pc = m1_store_loaded.provenance_claim().unwrap();

    // --- M2: a regular manifest referencing M1 as an inputTo ingredient. ---
    let mut m2_claim = Claim::new("input_to_test", Some("m2_input_to"), 2);
    m2_claim.add_claim_generator_info(ClaimGeneratorInfo::new("test"));

    let (m1_jumbf, _) =
        Store::load_jumbf_from_stream(format, &mut Cursor::new(m1_vec.clone()), &context).unwrap();
    let mut m2_store =
        Store::load_ingredient_to_claim(&mut m2_claim, &m1_jumbf, None, &context).unwrap();

    let m1_hashes = m1_store_loaded.get_manifest_box_hashes(m1_pc);
    let mut manifest_box_hash = m1_hashes.manifest_box_hash.clone();
    if corrupt_hash {
        // Flip a byte so the signed hash no longer matches M1's actual bytes.
        manifest_box_hash[0] ^= 0xff;
    }
    let parent_uri = HashedUri::new(
        m1_store_loaded.provenance_path().unwrap(),
        Some(m1_pc.alg().to_string()),
        &manifest_box_hash,
    );
    let sig_uri = HashedUri::new(
        to_signature_uri(m1_pc.label()),
        Some(m1_pc.alg().to_string()),
        &m1_hashes.signature_box_hash,
    );

    let m1_validation = ValidationResults::from_store(&m1_store_loaded, &m1_report);
    let input_to_ingredient = Ingredient::new_v3(Relationship::InputTo)
        .set_active_manifests_and_signature_from_hashed_uri(Some(parent_uri), Some(sig_uri))
        .set_validation_results(Some(m1_validation));
    m2_claim.add_assertion(&input_to_ingredient).unwrap();

    // A created action plus an edit that consumes the inputTo ingredient.
    let ia = m2_claim.ingredient_assertions()[0];
    let ia_hashed_uri = HashedUri::new(
        to_assertion_uri(m2_claim.label(), &ia.label()),
        Some(m2_claim.alg().to_owned()),
        ia.hash(),
    );
    let actions = Actions::new()
        .add_action(Action::new("c2pa.created").set_source_type(DigitalSourceType::Empty))
        .add_action(
            Action::new("c2pa.edited")
                .set_parameter("ingredients", vec![ia_hashed_uri])
                .unwrap(),
        );
    m2_claim.add_assertion(&actions).unwrap();

    m2_store.commit_claim(m2_claim).unwrap();

    let (_f, mut m2_input, mut m2_output) = create_test_streams("earth_apollo17.jpg");
    m2_store
        .save_to_stream(
            format,
            &mut m2_input,
            &mut m2_output,
            signer.as_ref(),
            &context,
        )
        .unwrap();
    m2_output.rewind().unwrap();
    (format, m2_output.get_ref().clone())
}

// A well-formed `inputTo` ingredient must actually be hash-validated, not
// skipped. Regression guard for the vuln where `ingredient_checks` did an
// unconditional `continue` for `Relationship::InputTo`, so the ingredient
// manifest was never checked against its signed hash. The success code
// `ingredient.manifest.validated` is only emitted when that check runs.
#[test]
fn test_input_to_ingredient_is_validated() {
    let context = Context::new();
    let (format, m2_vec) = build_asset_with_input_to_ingredient(false);

    let mut report = StatusTracker::default();
    Store::from_stream(format, Cursor::new(m2_vec), &mut report, &context).unwrap();

    assert!(
        !report.has_any_error(),
        "valid inputTo ingredient should not produce errors: {:?}",
        report.logged_items()
    );
    assert!(
        report.has_status(validation_status::INGREDIENT_MANIFEST_VALIDATED),
        "inputTo ingredient manifest must be hash-validated, got: {:?}",
        report.logged_items()
    );
}

// Tampering an `inputTo` ingredient's manifest (so its bytes no longer match
// the hash the active claim signed) must be caught. Before the fix this path
// was skipped entirely and the asset reported Valid, forging source
// attribution. It must now surface `ingredient.manifest.mismatch`.
#[test]
fn test_input_to_ingredient_hash_mismatch_detected() {
    let context = Context::new();
    let (format, m2_vec) = build_asset_with_input_to_ingredient(true);

    let mut report = StatusTracker::default();
    let _ = Store::from_stream(format, Cursor::new(m2_vec), &mut report, &context);

    assert!(
        report.has_status(validation_status::INGREDIENT_MANIFEST_MISMATCH),
        "tampered inputTo ingredient must be detected as a manifest mismatch, got: {:?}",
        report.logged_items()
    );
    assert!(
        report.has_any_error(),
        "tampered inputTo ingredient must fail validation"
    );
}

// Cyclic `parentOf` chains also lead to going through cycles.
#[test]
fn test_hash_binding_manifest_parent_cycle_terminates() {
    use crate::{hashed_uri::HashedUri, jumbf::labels::to_manifest_uri, ClaimGeneratorInfo};

    let mut store = Store::new();

    let mut claim_a = Claim::new("cycle_a", Some("contentauth"), 2);
    let mut claim_b = Claim::new("cycle_b", Some("contentauth"), 2);
    claim_a.add_claim_generator_info(ClaimGeneratorInfo::new("test"));
    claim_b.add_claim_generator_info(ClaimGeneratorInfo::new("test"));
    claim_a.set_update_manifest(true);
    claim_b.set_update_manifest(true);

    let label_a = claim_a.label().to_owned();
    let label_b = claim_b.label().to_owned();

    // Create the cycle:
    // Point claims at each other, each as the other's parentOf.
    for (claim, parent_label) in [(&mut claim_a, &label_b), (&mut claim_b, &label_a)] {
        let parent_uri = HashedUri::new(
            to_manifest_uri(parent_label),
            Some(claim.alg().to_owned()),
            &[0u8; 32],
        );

        // Here we just want an(y) ingredient to finish creating cycles.
        let ingredient = Ingredient::new_v2("parent", "image/jpeg")
            .set_parent()
            .set_c2pa_manifest_from_hashed_uri(Some(parent_uri));
        claim.add_assertion(&ingredient).unwrap();
    }

    store.insert_restored_claim(label_a.clone(), claim_a);
    store.insert_restored_claim(label_b, claim_b);

    // Called directly in the test to verify the scenario,
    // otherwise currently call order of (more) public APIs prevents this.
    let binding = store.get_hash_binding_manifest(store.get_claim(&label_a).unwrap());
    assert!(
        binding.is_none(),
        "a parentOf cycle has no binding manifest and must terminate, got {binding:?}"
    );
}

// Manifest stores with deep inputTo ingredients links shouldn't cause exponential recursive checks
// (when verify is on).
#[test]
fn test_shared_ingredient_inputto_graph_verified_once() {
    use crate::{
        hashed_uri::HashedUri, jumbf::labels::to_signature_uri, utils::test::create_test_store,
        ClaimGeneratorInfo, ValidationResults,
    };

    const DEPTH: usize = 13;

    let mut build_context = Context::new();
    // Turn some settings off to allow building the test asset.
    build_context.settings_mut().verify.verify_after_sign = false;
    build_context.settings_mut().verify.verify_after_reading = false;
    let signer = test_signer(SigningAlg::Ps256);

    // This is a leaf node...
    let (format, mut leaf_input, mut leaf_output) = create_test_streams("earth_apollo17.jpg");
    create_test_store()
        .unwrap()
        .save_to_stream(
            format,
            &mut leaf_input,
            &mut leaf_output,
            signer.as_ref(),
            &build_context,
        )
        .unwrap();
    leaf_output.rewind().unwrap();
    let mut prev_vec = leaf_output.get_ref().clone();

    // Each level references the previous level's manifest
    // via 2 inputTo ingredient assertions pointing at the same child.
    for level in 1..DEPTH {
        let mut prev_report = StatusTracker::default();
        let prev_store = Store::from_stream(
            format,
            Cursor::new(prev_vec.clone()),
            &mut prev_report,
            &build_context,
        )
        .unwrap();
        let prev_pc = prev_store.provenance_claim().unwrap();
        let prev_hashes = prev_store.get_manifest_box_hashes(prev_pc);

        let mut claim = Claim::new("deep_shared", Some(&format!("m{level}")), 2);
        claim.add_claim_generator_info(ClaimGeneratorInfo::new("test"));

        let (prev_jumbf, _) =
            Store::load_jumbf_from_stream(format, &mut Cursor::new(prev_vec), &build_context)
                .unwrap();
        let mut store =
            Store::load_ingredient_to_claim(&mut claim, &prev_jumbf, None, &build_context).unwrap();

        for _ in 0..2 {
            let parent_uri = HashedUri::new(
                prev_store.provenance_path().unwrap(),
                Some(prev_pc.alg().to_string()),
                &prev_hashes.manifest_box_hash,
            );
            let sig_uri = HashedUri::new(
                to_signature_uri(prev_pc.label()),
                Some(prev_pc.alg().to_string()),
                &prev_hashes.signature_box_hash,
            );
            let validation = ValidationResults::from_store(&prev_store, &prev_report);
            let ingredient = Ingredient::new_v3(Relationship::InputTo)
                .set_active_manifests_and_signature_from_hashed_uri(Some(parent_uri), Some(sig_uri))
                .set_validation_results(Some(validation));
            claim.add_assertion(&ingredient).unwrap();
        }

        let mut actions = Actions::new()
            .add_action(Action::new("c2pa.created").set_source_type(DigitalSourceType::Empty));
        for ia in claim.ingredient_assertions() {
            let ia_hashed_uri = HashedUri::new(
                to_assertion_uri(claim.label(), &ia.label()),
                Some(claim.alg().to_owned()),
                ia.hash(),
            );
            actions = actions.add_action(
                Action::new("c2pa.edited")
                    .set_parameter("ingredients", vec![ia_hashed_uri])
                    .unwrap(),
            );
        }
        claim.add_assertion(&actions).unwrap();
        store.commit_claim(claim).unwrap();

        let (_f, mut input, mut output) = create_test_streams("earth_apollo17.jpg");
        store
            .save_to_stream(
                format,
                &mut input,
                &mut output,
                signer.as_ref(),
                &build_context,
            )
            .unwrap();
        output.rewind().unwrap();
        prev_vec = output.get_ref().clone();
    }

    // Starting verification from the top manifest will walk the graph we built.
    // (Default context re-enables the verification settings).
    let mut report = StatusTracker::default();
    Store::from_stream(format, Cursor::new(prev_vec), &mut report, &Context::new()).unwrap();

    // Memoization bounds validation steps...
    let validated = report
        .logged_items()
        .iter()
        .filter(|i| {
            i.validation_status.as_deref() == Some(validation_status::INGREDIENT_MANIFEST_VALIDATED)
        })
        .count();

    // ... so here we verify the validation count stayed below the bounds.
    assert!(
        validated <= 4 * DEPTH,
        "shared ingredient subtrees must be verified only once"
    );
}

#[test]
fn test_custom_anchor_ekus() {
    let mut context = crate::context::Context::new();

    // test adding to actual image
    let ap = fixture_path("C.jpg");

    let mut stream = std::fs::File::open(&ap).unwrap();
    let format = "image/jpeg";

    let (manifest_bytes, _remote_url) =
        Store::load_jumbf_from_stream(format, &mut stream, &context).unwrap();

    let mut log = StatusTracker::default();
    let _store = Store::from_jumbf_with_context(&manifest_bytes, &mut log, &context).unwrap();

    assert!(!log.has_any_error());

    // modify the settings so that the default EKUs are in the anchors
    let mut settings = Settings::default();
    let ekus = settings.trust.trust_config.take();

    let anchors = settings.trust.anchors.as_mut().unwrap();
    assert!(anchors.len() == 1); // this test expects one anchor set
    anchors[0].trust_config = ekus;
    settings.validate().unwrap();
    context.set_settings(settings).unwrap();

    stream.rewind().unwrap();

    // with alternate Context
    log = StatusTracker::default();
    let _store = Store::from_stream(format, &mut stream, &mut log, &context).unwrap();

    assert!(!log.has_any_error());
}
