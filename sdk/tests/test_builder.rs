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

use std::io::{self, Cursor};

use c2pa::{
    settings::load_settings_from_str, validation_status, Builder, Reader, Result, ValidationState,
};

mod common;
#[cfg(all(feature = "add_thumbnails", feature = "file_io"))]
use common::compare_stream_to_known_good;
use common::{fixtures_path, test_signer};

#[test]
#[cfg(all(feature = "add_thumbnails", feature = "file_io"))]
fn test_builder_ca_jpg() -> Result<()> {
    let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::from_json(&manifest_def)?;

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());

    builder.sign(&test_signer(), format, &mut source, &mut dest)?;

    // dest.set_position(0);
    // let path = common::known_good_path("CA_test.json");
    // let reader = c2pa::Reader::from_stream(format, &mut dest)?;
    // std::fs::write(path, reader.json())?;

    dest.set_position(0);
    compare_stream_to_known_good(&mut dest, format, "CA_test.json")
}

// Source: https://github.com/contentauth/c2pa-rs/issues/530
#[test]
fn test_builder_riff() -> Result<()> {
    let manifest_def = include_str!("fixtures/simple_manifest.json");
    let mut source = Cursor::new(include_bytes!("fixtures/sample1.wav"));
    let format = "audio/wav";

    let mut builder = Builder::from_json(manifest_def)?;
    builder.no_embed = true;
    builder.sign(&test_signer(), format, &mut source, &mut io::empty())?;

    Ok(())
}

#[test]
#[cfg(feature = "file_io")]
fn test_builder_fragmented() -> Result<()> {
    use common::tempdirectory;

    let manifest_def = include_str!("fixtures/simple_manifest.json");
    let mut builder = Builder::from_json(manifest_def)?;
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
                        &test_signer(),
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
    let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::from_json(&manifest_def)?;
    // disable remote fetching for this test
    load_settings_from_str(r#"{"verify": { "remote_manifest_fetch": false} }"#, "json")?;
    builder.no_embed = true;
    // very important to use a URL that does not exist, otherwise you may get a JumbfParseError or JumbfNotFound
    builder.set_remote_url("http://this_does_not_exist/foo.jpg");

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());

    builder.sign(&test_signer(), format, &mut source, &mut dest)?;

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
    let manifest_def = include_str!("fixtures/simple_manifest.json");
    let mut source = Cursor::new(include_bytes!("fixtures/XCA.jpg"));
    let format = "image/jpeg";

    let mut builder = Builder::from_json(manifest_def)?;
    builder.add_ingredient_from_stream(r#"{"relationship": "parentOf"}"#, format, &mut source)?;
    source.set_position(0);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&test_signer(), format, &mut source, &mut dest)?;
    dest.set_position(0);
    let reader = Reader::from_stream(format, &mut dest)?;
    // check that the v1 OTGP is embedded and we catch it correct with validation_results
    assert_eq!(reader.validation_status(), None);
    assert_ne!(reader.validation_state(), ValidationState::Invalid);
    //println!("reader: {}", reader);
    assert_eq!(
        reader.active_manifest().unwrap().ingredients()[0]
            .validation_status()
            .unwrap()[0]
            .code(),
        validation_status::ASSERTION_DATAHASH_MISMATCH
    );

    Ok(())
}

#[test]
fn test_dynamic_assertions_builder() -> Result<()> {
    use c2pa::{
        // assertions::{CreativeWork, SchemaDotOrgPerson},
        dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
        Signer,
        SigningAlg,
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
            //CreativeWork::LABEL.to_string()
            "com.mycompany.myassertion".to_string()
        }

        fn reserve_size(&self) -> Result<usize> {
            let assertion = TestAssertion {
                my_tag: "some value I will replace".to_string(),
            };
            // let assertion = CreativeWork::new()
            //     .add_author(SchemaDotOrgPerson::new().set_name("me").unwrap())
            //     .unwrap();
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

            // let assertion =
            //     CreativeWork::new().add_author(SchemaDotOrgPerson::new().set_name("me")?)?;

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

    let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::from_json(&manifest_def)?;

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());

    let signer = DynamicSigner::new();
    builder.sign(&signer, format, &mut source, &mut dest)?;

    dest.set_position(0);

    let reader = Reader::from_stream(format, &mut dest).unwrap();

    println!("reader: {reader}");

    assert_ne!(reader.validation_state(), ValidationState::Invalid);

    Ok(())
}
