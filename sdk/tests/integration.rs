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

/// Complete functional integration test with parent and ingredients.
// Isolate from wasm by wrapping in module.
#[cfg(feature = "file_io")]
mod integration_1 {
    use std::path::PathBuf;

    use c2pa::{
        assertions::{c2pa_action, Action, Actions},
        create_signer,
        settings::load_settings_from_str,
        Builder, ClaimGeneratorInfo, Ingredient, Reader, Result, Signer, SigningAlg,
    };
    use tempfile::tempdir;

    //const GENERATOR: &str = "app";

    // prevent tests from polluting the results of each other because of Rust unit test concurrency
    static PROTECT: std::sync::Mutex<u32> = std::sync::Mutex::new(1);

    fn get_temp_signer() -> Box<dyn Signer> {
        let _protect = PROTECT.lock().unwrap();

        // sign and embed into the target file
        let mut signcert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        signcert_path.push("tests/fixtures/certs/ps256.pub");
        let mut pkey_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pkey_path.push("tests/fixtures/certs/ps256.pem");
        create_signer::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None)
            .expect("get_signer_from_files")
    }

    fn configure_trust(
        trust_anchors: Option<String>,
        allowed_list: Option<String>,
        trust_config: Option<String>,
    ) -> Result<()> {
        let ta = r#"{"trust": { "trust_anchors": replacement_val } }"#;
        let al = r#"{"trust": { "allowed_list": replacement_val } }"#;
        let tc = r#"{"trust": { "trust_config": replacement_val } }"#;

        let mut enable_trust_checks = false;
        if let Some(trust_list) = trust_anchors {
            let replacement_val = serde_json::Value::String(trust_list).to_string(); // escape string
            let setting = ta.replace("replacement_val", &replacement_val);

            load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(allowed_list) = allowed_list {
            let replacement_val = serde_json::Value::String(allowed_list).to_string(); // escape string
            let setting = al.replace("replacement_val", &replacement_val);

            load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(trust_config) = trust_config {
            let replacement_val = serde_json::Value::String(trust_config).to_string(); // escape string
            let setting = tc.replace("replacement_val", &replacement_val);

            load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        // enable trust checks
        if enable_trust_checks {
            load_settings_from_str(r#"{"verify": { "verify_trust": true} }"#, "json")?;
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_embed_manifest() -> Result<()> {
        // set up parent and destination paths
        let dir = tempdir()?;
        let output_path = dir.path().join("test_file.jpg");
        let mut parent_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        parent_path.push("tests/fixtures/earth_apollo17.jpg");
        let mut ingredient_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ingredient_path.push("tests/fixtures/libpng-test.png");

        let config = include_bytes!("../tests/fixtures/certs/trust/store.cfg");
        let priv_trust = include_bytes!("../tests/fixtures/certs/trust/test_cert_root_bundle.pem");

        // Configure before first use so that trust settings are used for all calls.
        // In production code you should check that the file is indeed UTF-8 text.
        configure_trust(
            Some(String::from_utf8_lossy(priv_trust).to_string()),
            None,
            Some(String::from_utf8_lossy(config).to_string()),
        )?;

        let generator = ClaimGeneratorInfo::new("app");
        // create a new Manifest
        let mut builder = Builder::new();
        builder.set_claim_generator_info(generator);

        // allocate actions so we can add them
        let mut actions = Actions::new();

        // add a parent ingredient
        let mut parent = Ingredient::from_file(&parent_path)?;
        parent.set_is_parent();
        // add an action assertion stating that we imported this file
        actions = actions.add_action(
            Action::new(c2pa_action::EDITED)
                .set_when("2015-06-26T16:43:23+0200")
                .set_parameter("name".to_owned(), "import")?
                .set_parameter("identifier".to_owned(), parent.instance_id().to_owned())?,
        );

        // set the parent ingredient
        builder.add_ingredient(parent);

        actions = actions.add_action(
            Action::new("c2pa.edit").set_parameter("name".to_owned(), "brightnesscontrast")?,
        );

        // add an ingredient
        let ingredient = Ingredient::from_file(&ingredient_path)?;

        // add an action assertion stating that we imported this file
        actions = actions.add_action(
            Action::new(c2pa_action::EDITED)
                .set_parameter("name".to_owned(), "import")?
                .set_parameter("identifier".to_owned(), ingredient.instance_id().to_owned())?,
            // could add other parameters for position and size here
        );

        builder.add_ingredient(ingredient);

        builder.add_assertion(Actions::LABEL, &actions)?;

        // sign and embed into the target file
        let signer = get_temp_signer();
        builder.sign_file(signer.as_ref(), &parent_path, &output_path)?;

        // read our new file with embedded manifest
        let reader = Reader::from_file(&output_path)?;

        println!("{reader}");

        assert!(reader.active_manifest().is_some());
        if let Some(manifest) = reader.active_manifest() {
            assert!(manifest.title().is_some());
            assert_eq!(manifest.ingredients().len(), 2);
        } else {
            panic!("no manifest in store");
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_embed_json_manifest() -> Result<()> {
        // set up parent and destination paths
        let dir = tempdir()?;
        let output_path = dir.path().join("test_file.jpg");

        let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixture_path.push("tests/fixtures");

        let mut parent_path = fixture_path.clone();
        parent_path.push("earth_apollo17.jpg");
        let mut manifest_path = fixture_path.clone();
        manifest_path.push("manifest.json");

        let json = std::fs::read_to_string(manifest_path)?;

        let mut builder = Builder::from_json(&json)?;
        builder.base_path = Some(fixture_path.canonicalize()?);

        // sign and embed into the target file
        let signer = get_temp_signer();
        builder.sign_file(signer.as_ref(), &parent_path, &output_path)?;

        // read our new file with embedded manifest
        let reader = Reader::from_file(&output_path)?;

        println!("{reader}");
        // std::fs::copy(&output_path, "test_file.jpg")?; // for debugging to get copy of the file

        assert!(reader.active_manifest().is_some());
        if let Some(manifest) = reader.active_manifest() {
            assert!(manifest.title().is_some());
            assert_eq!(manifest.ingredients().len(), 2);
        } else {
            panic!("no manifest in store");
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_embed_bmff_manifest() -> Result<()> {
        // set up parent and destination paths
        let dir = tempdir()?;
        let output_path = dir.path().join("test_bmff.heic");

        let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixture_path.push("tests/fixtures");

        let mut parent_path = fixture_path.clone();
        parent_path.push("sample1.heic");
        let mut manifest_path = fixture_path.clone();
        manifest_path.push("simple_manifest.json");

        let json = std::fs::read_to_string(manifest_path)?;

        let mut builder = Builder::from_json(&json)?;
        builder.base_path = Some(fixture_path.canonicalize()?);

        // sign and embed into the target file
        let signer = get_temp_signer();
        builder.sign_file(signer.as_ref(), &parent_path, &output_path)?;

        // read our new file with embedded manifest
        let reader = Reader::from_file(&output_path)?;

        println!("{reader}");
        // std::fs::copy(&output_path, "test_file.jpg")?; // for debugging to get copy of the file

        assert!(reader.active_manifest().is_some());
        assert_eq!(reader.validation_status(), None);
        if let Some(manifest) = reader.active_manifest() {
            assert!(manifest.title().is_some());
        } else {
            panic!("no manifest in store");
        }
        Ok(())
    }

    struct PlacedCallback {
        path: String,
    }

    use c2pa::{Error, Manifest, ManifestPatchCallback};

    impl ManifestPatchCallback for PlacedCallback {
        fn patch_manifest(&self, manifest_store: &[u8]) -> Result<Vec<u8>> {
            use ::jumbf::parser::SuperBox;

            if let Ok((_raw, sb)) = SuperBox::from_slice(manifest_store) {
                if let Some(my_box) = sb.find_by_label(&self.path) {
                    // find box I am looking for
                    if let Some(db) = my_box.data_box() {
                        let data_offset = db.offset_within_superbox(&sb).unwrap();
                        let replace_bytes = r#"{"some_tag": "some value is replaced"}"#;

                        if db.data.len() != replace_bytes.len() {
                            return Err(Error::OtherError("replacement data size mismatch".into()));
                        }

                        // sanity check to make sure offset code is working
                        let offset = memchr::memmem::find(manifest_store, db.data).unwrap();
                        if offset != data_offset {
                            return Err(Error::OtherError("data box offset incorrect".into()));
                        }

                        let mut new_manifest_store = manifest_store.to_vec();
                        new_manifest_store.splice(
                            data_offset..data_offset + replace_bytes.len(),
                            replace_bytes.as_bytes().iter().cloned(),
                        );

                        return Ok(new_manifest_store);
                    }
                }

                Err(Error::NotFound)
            } else {
                Err(Error::OtherError("could not parse JUMBF".into()))
            }
        }
    }
    #[test]
    #[cfg(feature = "file_io")]
    fn test_placed_manifest() -> Result<()> {
        // set up parent and destination paths

        use std::io::Seek;
        let dir = tempdir()?;
        let output_path = dir.path().join("test_file.jpg");

        let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixture_path.push("tests/fixtures");
        let mut manifest_path = fixture_path.clone();
        manifest_path.push("manifest.json");
        let mut parent_path = fixture_path.clone();
        parent_path.push("earth_apollo17.jpg");

        let json = std::fs::read_to_string(manifest_path)?;

        let mut manifest = Manifest::from_json(&json)?;
        manifest.with_base_path(fixture_path.canonicalize()?)?;

        // sign and embed into the target file
        let signer = get_temp_signer();

        let mut input_stream = std::fs::File::open(&parent_path).unwrap();
        let mut output_stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output_path)
            .unwrap();

        // get placed manifest
        #[allow(deprecated)]
        let (placed_manifest, label) = manifest
            .get_placed_manifest(signer.reserve_size(), "jpg", &mut input_stream)
            .unwrap();

        // my manifest callback handler
        // set some data needed by callback to do what it needs to
        // for this example let's tell it which jumbf box we can to change
        // There is currently no way to get this directly from Manifest so I am using a hack
        // to get_placed_manifest to return the manifest UUID.
        let path = format!("{}/c2pa.assertions/{}", label, "com.mycompany.myassertion");

        let my_callback = PlacedCallback {
            path: path.to_string(),
        };

        let callbacks: Vec<Box<dyn ManifestPatchCallback>> = vec![Box::new(my_callback)];

        // add manifest back into data
        input_stream.rewind().unwrap();
        #[allow(deprecated)]
        Manifest::embed_placed_manifest(
            &placed_manifest,
            "jpg",
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &callbacks,
        )
        .unwrap();

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_placed_manifest_bmff() -> Result<()> {
        // set up parent and destination paths

        use std::io::Seek;
        let dir = tempdir()?;
        let output_path = dir.path().join("video1.mp4");

        let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixture_path.push("tests/fixtures");
        let mut manifest_path = fixture_path.clone();
        manifest_path.push("manifest.json");
        let mut parent_path = fixture_path.clone();
        parent_path.push("video1.mp4");

        let json = std::fs::read_to_string(manifest_path)?;

        let mut manifest = Manifest::from_json(&json)?;
        manifest.with_base_path(fixture_path.canonicalize()?)?;

        // sign and embed into the target file
        let signer = get_temp_signer();

        let mut input_stream = std::fs::File::open(&parent_path).unwrap();
        let mut output_stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output_path)
            .unwrap();

        // get placed manifest
        #[allow(deprecated)]
        let (placed_manifest, label) = manifest
            .get_placed_manifest(signer.reserve_size(), "mp4", &mut input_stream)
            .unwrap();

        // my manifest callback handler
        // set some data needed by callback to do what it needs to
        // for this example let's tell it which jumbf box we can to change
        // There is currently no way to get this directly from Manifest so I am using a hack
        // to get_placed_manifest to return the manifest UUID.
        let path = format!("{}/c2pa.assertions/{}", label, "com.mycompany.myassertion");

        let my_callback = PlacedCallback {
            path: path.to_string(),
        };

        let callbacks: Vec<Box<dyn ManifestPatchCallback>> = vec![Box::new(my_callback)];

        // add manifest back into data
        input_stream.rewind().unwrap();
        #[allow(deprecated)]
        Manifest::embed_placed_manifest(
            &placed_manifest,
            "mp4",
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &callbacks,
        )
        .unwrap();

        Ok(())
    }
}
