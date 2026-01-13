// Copyright 2024 Adobe. All rights reserved.
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

use std::io::{self, Cursor, Seek};

#[cfg(not(target_arch = "wasm32"))]
use c2pa::identity::validator::CawgValidator;
use c2pa::{
    settings::Settings, validation_status, Builder, BuilderIntent, Error, ManifestAssertionKind,
    Reader, Result, ValidationState,
};

mod common;
#[cfg(all(feature = "add_thumbnails", feature = "file_io"))]
use common::compare_stream_to_known_good;
use common::test_signer;

#[test]
#[cfg(all(feature = "add_thumbnails", feature = "file_io"))]
fn test_builder_ca_jpg() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);

    use c2pa::assertions::Action;
    builder.add_action(Action::new("c2pa.published"))?;

    builder.add_action(serde_json::json!({
        "action": "c2pa.edited",
        "parameters": {
            "description": "edited",
            "name": "any value"
        },
        "softwareAgent": {
            "name": "TestApp",
            "version": "1.0.0"
        }
    }))?;

    let mut dest = Cursor::new(Vec::new());

    builder.sign(&Settings::signer()?, format, &mut source, &mut dest)?;

    // use this to update the known good
    // dest.set_position(0);
    // let reader = Reader::from_stream(format, &mut dest)?;
    // std::fs::write("tests/known_good/CA_test.json", reader.json()).unwrap();

    dest.set_position(0);
    compare_stream_to_known_good(&mut dest, format, "CA_test.json")
}

// Source: https://github.com/contentauth/c2pa-rs/issues/530
#[test]
fn test_builder_riff() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
    let mut source = Cursor::new(include_bytes!("fixtures/sample1.wav"));
    let format = "audio/wav";

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.definition.claim_version = Some(1); // use v1 for this test
    builder.no_embed = true;
    builder.sign(&Settings::signer()?, format, &mut source, &mut io::empty())?;

    Ok(())
}

// Constructs a C2PA asset that has an ingredient that references the main asset's active
// manifest as the ingredients active manifest.
//
// Source: https://github.com/contentauth/c2pa-rs/issues/1554
#[test]
fn test_builder_cyclic_ingredient() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let mut source = Cursor::new(include_bytes!("fixtures/no_manifest.jpg"));
    let format = "image/jpeg";

    let mut ingredient = Cursor::new(Vec::new());

    // Start by making a basic ingredient.
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.sign(&Settings::signer()?, format, &mut source, &mut ingredient)?;

    source.rewind()?;
    ingredient.rewind()?;

    let mut dest = Cursor::new(Vec::new());

    // Then create an asset with the basic ingredient.
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.add_ingredient_from_stream(
        serde_json::json!({}).to_string(),
        format,
        &mut ingredient,
    )?;
    builder.sign(&Settings::signer()?, format, &mut source, &mut dest)?;

    dest.rewind()?;
    ingredient.rewind()?;

    let active_manifest_uri = Reader::from_stream(format, &mut dest)?
        .active_label()
        .unwrap()
        .to_owned();
    let ingredient_uri = Reader::from_stream(format, ingredient)?
        .active_label()
        .unwrap()
        .to_owned();

    // If they aren't the same number of bytes then we can't reliably substitute the URI.
    assert_eq!(active_manifest_uri.len(), ingredient_uri.len());

    // Replace the ingredient active manifest with the main active manifest.
    let mut bytes = dest.into_inner();
    let old = ingredient_uri.as_bytes();
    let new = active_manifest_uri.as_bytes();

    let mut i = 0;
    while i + old.len() <= bytes.len() {
        if &bytes[i..i + old.len()] == old {
            bytes[i..i + old.len()].copy_from_slice(new);
            i += old.len();
        } else {
            i += 1;
        }
    }

    // Attempt to read the manifest with a cyclical ingredient.
    let mut cyclic_ingredient = Cursor::new(bytes);
    assert!(matches!(
        Reader::from_stream(format, &mut cyclic_ingredient),
        Err(Error::CyclicIngredients { .. })
    ));

    cyclic_ingredient.rewind()?;

    // Read the manifest without validating so we can test with post-validating the CAWG.
    Settings::from_toml(
        &toml::toml! {
            [verify]
            verify_after_reading = false
        }
        .to_string(),
    )?;
    #[cfg(not(target_arch = "wasm32"))]
    {
        let mut reader = Reader::from_stream(format, cyclic_ingredient)?;
        // Ideally we'd use a sync path for this. There are limitations for tokio on WASM.
        tokio::runtime::Runtime::new()?.block_on(reader.post_validate_async(&CawgValidator {}))?;
    }

    Ok(())
}

#[test]
fn test_builder_sidecar_only() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
    let mut source = Cursor::new(include_bytes!("fixtures/earth_apollo17.jpg"));
    let format = "image/jpeg";

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    builder.set_no_embed(true);
    let c2pa_data = builder.sign(&Settings::signer()?, format, &mut source, &mut io::empty())?;

    let reader1 = Reader::from_manifest_data_and_stream(&c2pa_data, format, &mut source)?;
    println!("reader1: {reader1}");

    let builder2: Builder = reader1.try_into()?;
    println!("builder2 {builder2}");

    //    let c2pa_stream = Cursor::new(c2pa_data);
    //    let reader = Reader::from_stream("application/c2pa", c2pa_stream)?;
    //    println!("reader: {reader}");

    Ok(())
}

#[test]
#[cfg(feature = "file_io")]
#[ignore = "generates a hash error, needs investigation"]
fn test_builder_fragmented() -> Result<()> {
    use common::tempdirectory;
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    let tempdir = tempdirectory().expect("temp dir");
    let output_path = tempdir.path();
    let mut init_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    init_path.push("tests/fixtures/bunny/**/BigBuckBunny_2s_init.mp4");
    let pattern = init_path.as_os_str().to_str().unwrap();
    for init in glob::glob(pattern).unwrap() {
        match init {
            Ok(p) => {
                let init_dir = p.parent().unwrap();
                let pattern_path = init_dir.join("BigBuckBunny_2s*.m4s"); // segment match pattern

                // grab the fragments that go with this init segment
                let mut fragments = Vec::new();
                for seg in glob::glob(pattern_path.to_str().unwrap())
                    .unwrap()
                    .flatten()
                {
                    fragments.push(seg);
                }

                dbg!(&fragments);
                // add manifest based on
                let mut new_output_path =
                    output_path.join(p.parent().unwrap().file_name().unwrap());
                new_output_path.push(p.file_name().unwrap());

                builder
                    .sign_fragmented_files(
                        &Settings::signer()?,
                        p.as_path(),
                        &fragments,
                        new_output_path.as_path(),
                    )
                    .unwrap();

                // verify the fragments
                let output_init = new_output_path.join(p.file_name().unwrap());
                let output_fragments = fragments
                    .into_iter()
                    .map(|f| new_output_path.join(f.file_name().unwrap()))
                    .collect();
                let reader = Reader::from_fragmented_files(&output_init, &output_fragments)?;
                //println!("reader: {}", reader);
                assert_eq!(reader.validation_status(), None);

                // test a single fragment
                let init_segment = std::fs::File::open(output_init)?;
                let fragment = std::fs::File::open(output_fragments[0].as_path())?;
                let reader = Reader::from_fragment("video/mp4", init_segment, fragment)?;
                assert_eq!(reader.validation_status(), None);
            }
            Err(e) => panic!("error = {e:?}"),
        }
    }
    Ok(())
}

#[test]
fn test_builder_remote_url_no_embed() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
    //let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    // disable remote fetching for this test
    Settings::from_toml(
        &toml::toml! {
            [verify]
            remote_manifest_fetch = false
        }
        .to_string(),
    )?;
    builder.no_embed = true;
    // very important to use a URL that does not exist, otherwise you may get a JumbfParseError or JumbfNotFound
    builder.set_remote_url("http://this_does_not_exist/foo.jpg");

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());

    builder.sign(&Settings::signer()?, format, &mut source, &mut dest)?;

    dest.set_position(0);
    let reader = Reader::from_stream(format, &mut dest);
    if let Err(c2pa::Error::RemoteManifestUrl(url)) = reader {
        assert_eq!(url, "http://this_does_not_exist/foo.jpg".to_string());
    } else {
        panic!("Expected Err(c2pa::Error::RemoteManifestUrl), got {reader:?}");
    }
    Ok(())
}

#[test]
fn test_builder_embedded_v1_otgp() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let mut source = Cursor::new(include_bytes!("fixtures/XCA.jpg"));
    let format = "image/jpeg";

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&Settings::signer()?, format, &mut source, &mut dest)?;
    dest.set_position(0);
    let reader = Reader::from_stream(format, &mut dest)?;
    // check that the v1 OTGP is embedded and we catch it correct with validation_results
    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    //println!("reader: {}", reader);
    assert_eq!(
        reader.active_manifest().unwrap().ingredients()[0]
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .failure[0]
            .code(),
        validation_status::ASSERTION_DATAHASH_MISMATCH
    );

    Ok(())
}

#[test]
fn test_dynamic_assertions_builder() -> Result<()> {
    use c2pa::{
        dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
        Signer, SigningAlg,
    };
    use serde::Serialize;
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
            Ok(serde_json::to_string(&assertion)?.len())
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

            Ok(DynamicAssertionContent::Json(serde_json::to_string(
                &assertion,
            )?))
        }
    }

    /// This is a Signer wrapped around a local temp signer,
    /// that implements the DynamicAssertion trait.
    struct DynamicSigner(Box<dyn Signer>);

    impl DynamicSigner {
        fn new() -> Self {
            Self(Box::new(test_signer()))
        }
    }

    impl Signer for DynamicSigner {
        fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
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
        fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
            vec![Box::new(TestDynamicAssertion {})]
        }
    }

    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    //let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());

    let signer = DynamicSigner::new();
    builder.sign(&signer, format, &mut source, &mut dest)?;

    dest.set_position(0);

    let reader = Reader::from_stream(format, &mut dest).unwrap();

    println!("reader: {reader}");

    assert_eq!(reader.validation_state(), ValidationState::Trusted);

    Ok(())
}

#[test]
fn test_assertion_created_field() -> Result<()> {
    use serde_json::json;

    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let definition = json!(
    {
        "assertions": [
        {
            "label": "org.test.gathered",
            "data": {
                "value": "gathered"
            }
        },
        {
            "label": "org.test.created",
            "kind": "Json",
            "data": {
                "value": "created"
            },
            "created": true
        }]
    }
    )
    .to_string();

    let mut builder = Builder::from_json(&definition)?;

    // Add a regular assertion (should default to created = false)
    builder.add_assertion("org.test.regular", &json!({"value": "regular"}))?;

    // let created = json!({
    //     "value": "created"
    // });
    // builder.add_assertion("org.test.created", &created)?;

    // let gathered = json!({
    //     "value": "gathered"
    // });
    // builder.add_assertion("org.test.gathered", &gathered)?;

    let mut dest = Cursor::new(Vec::new());
    builder.sign(&Settings::signer()?, format, &mut source, &mut dest)?;

    dest.set_position(0);
    let reader = Reader::from_stream(format, &mut dest)?;

    // Verify the manifest was created successfully
    assert_ne!(reader.validation_state(), ValidationState::Invalid);

    let manifest = reader.active_manifest().unwrap();

    // Find our test assertions
    let regular_assertion = manifest
        .assertions()
        .iter()
        .find(|a| a.label() == "org.test.regular")
        .expect("Should find regular assertion");

    let created_assertion = manifest
        .assertions()
        .iter()
        .find(|a| a.label() == "org.test.created")
        .expect("Should find created assertion");

    let gathered_assertion = manifest
        .assertions()
        .iter()
        .find(|a| a.label() == "org.test.gathered")
        .expect("Should find gathered assertion");

    // Verify the values are preserved correctly
    assert_eq!(regular_assertion.value().unwrap()["value"], "regular");
    assert_eq!(created_assertion.value().unwrap()["value"], "created");
    assert_eq!(gathered_assertion.value().unwrap()["value"], "gathered");

    assert_eq!(created_assertion.kind(), &ManifestAssertionKind::Json);
    assert_eq!(gathered_assertion.kind(), &ManifestAssertionKind::Cbor);
    assert_eq!(regular_assertion.kind(), &ManifestAssertionKind::Cbor);

    // Test the created() method to verify the created field is preserved
    assert!(!regular_assertion.created()); // add_assertion defaults to false
    assert!(created_assertion.created()); // explicitly set to true
    assert!(!gathered_assertion.created()); // explicitly set to false

    Ok(())
}

#[test]
fn test_metadata_formats_json_manifest() -> Result<()> {
    use c2pa::settings::Settings;
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let manifest_json = r#"
    {
        "assertions": [
            {
                "label": "c2pa.metadata",
                "kind": "Json",
                "data": {
                    "@context": { "exif": "http://ns.adobe.com/exif/1.0/" },
                    "exif:GPSLatitude": "39,21.102N"
                }
            },
            {
                "label": "cawg.metadata",
                "kind": "Json",
                "data": {
                    "@context": { "cawg": "http://cawg.org/ns/1.0/" },
                    "cawg:SomeField": "SomeValue"
                }
            },
            {
                "label": "c2pa.assertion.metadata",
                "data": {
                    "@context": { "custom": "http://custom.org/ns/1.0/" },
                    "custom:Field": "CustomValue"
                }
            },
            {
                "label": "org.myorg.metadata",
                "data": {
                    "@context": { "myorg": "http://myorg.org/ns/1.0/" },
                    "myorg:Field": "MyOrgValue"
                }
            }
        ]
    }
    "#;

    let mut builder = Builder::from_json(manifest_json)?;
    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    builder.sign(&Settings::signer()?, format, &mut source, &mut dest)?;

    dest.set_position(0);
    let reader = Reader::from_stream(format, &mut dest)?;

    for assertion in reader.active_manifest().unwrap().assertions() {
        match assertion.label() {
            "c2pa.assertion.metadata" => {
                assert_eq!(
                    assertion.kind(),
                    &ManifestAssertionKind::Cbor,
                    "c2pa.assertion.metadata should be CBOR"
                );
            }
            "c2pa.metadata" | "cawg.metadata" | "org.myorg.metadata" => {
                assert_eq!(
                    assertion.kind(),
                    &ManifestAssertionKind::Json,
                    "{} should be JSON",
                    assertion.label()
                );
            }
            _ => {}
        }
    }
    Ok(())
}

/// Test that path traversal attempts in archive resources are blocked
#[test]
fn test_archive_path_traversal_protection() -> Result<()> {
    Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

    let mut builder = Builder::new();
    builder.set_intent(BuilderIntent::Edit);

    // Try to add a resource with a path traversal attempt
    let mut malicious_resource = Cursor::new(b"malicious data");
    let result = builder.add_resource("../../../etc/passwd", &mut malicious_resource);

    // This should fail with a BadParam error
    match result {
        Err(Error::BadParam(msg)) if msg.contains("Path traversal not allowed") => {
            // Expected error
        }
        Err(e) => {
            panic!("Expected path traversal error, got: {:?}", e);
        }
        Ok(_) => {
            panic!("Path traversal should have been blocked!");
        }
    }

    // Also test absolute paths
    let mut malicious_resource2 = Cursor::new(b"malicious data");
    let result = builder.add_resource("/etc/passwd", &mut malicious_resource2);

    match result {
        Err(Error::BadParam(msg)) if msg.contains("Absolute path not allowed") => {
            // Expected error
        }
        Err(e) => {
            panic!("Expected absolute path error, got: {:?}", e);
        }
        Ok(_) => {
            panic!("Absolute path should have been blocked!");
        }
    }

    // Test that valid paths still work
    let mut valid_resource = Cursor::new(b"valid data");
    builder.add_resource("valid_resource.txt", &mut valid_resource)?;

    Ok(())
}
