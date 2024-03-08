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

/// complete functional integration test with acquisitions and ingredients
// isolate from wasm by wrapping in module
#[cfg(feature = "file_io")]
mod integration_1 {

    use std::path::PathBuf;

    use c2pa::{
        assertions::{c2pa_action, Action, Actions},
        create_signer, settings, Ingredient, Manifest, ManifestStore, Result, Signer, SigningAlg,
    };
    use tempfile::tempdir;

    const GENERATOR: &str = "app";

    // prevent tests from polluting the results of each other because of Rust unit test concurrency
    static PROTECT: std::sync::Mutex<u32> = std::sync::Mutex::new(1); // prevent tests from polluting the results of each other

    fn get_temp_signer() -> Box<dyn Signer> {
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

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(allowed_list) = allowed_list {
            let replacement_val = serde_json::Value::String(allowed_list).to_string(); // escape string
            let setting = al.replace("replacement_val", &replacement_val);

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(trust_config) = trust_config {
            let replacement_val = serde_json::Value::String(trust_config).to_string(); // escape string
            let setting = tc.replace("replacement_val", &replacement_val);

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        // enable trust checks
        if enable_trust_checks {
            c2pa::settings::load_settings_from_str(
                r#"{"verify": { "verify_trust": true} }"#,
                "json",
            )?;
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_embed_manifest() -> Result<()> {
        let _protect = PROTECT.lock().unwrap();

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

        // create a new Manifest
        let mut manifest = Manifest::new(GENERATOR.to_owned());

        // allocate actions so we can add them
        let mut actions = Actions::new();

        // add a parent ingredient
        let parent = Ingredient::from_file(&parent_path)?;
        // add an action assertion stating that we imported this file
        actions = actions.add_action(
            Action::new(c2pa_action::EDITED)
                .set_when("2015-06-26T16:43:23+0200")
                .set_parameter("name".to_owned(), "import")?
                .set_parameter("identifier".to_owned(), parent.instance_id().to_owned())?,
        );

        // set the parent ingredient
        manifest.set_parent(parent)?;

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

        manifest.add_ingredient(ingredient);

        manifest.add_assertion(&actions)?;

        // sign and embed into the target file
        let signer = get_temp_signer();
        manifest.embed(&parent_path, &output_path, &*signer)?;

        // read our new file with embedded manifest
        let manifest_store = ManifestStore::from_file(&output_path)?;

        println!("{manifest_store}");

        assert!(manifest_store.get_active().is_some());
        if let Some(manifest) = manifest_store.get_active() {
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
        let _protect = PROTECT.lock().unwrap();

        settings::reset_default_settings().unwrap();

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

        let mut manifest = Manifest::from_json(&json)?;
        manifest.with_base_path(fixture_path.canonicalize()?)?;

        // sign and embed into the target file
        let signer = get_temp_signer();
        manifest.embed(&parent_path, &output_path, &*signer)?;

        // read our new file with embedded manifest
        let manifest_store = ManifestStore::from_file(&output_path)?;

        println!("{manifest_store}");
        // std::fs::copy(&output_path, "test_file.jpg")?; // for debugging to get copy of the file

        assert!(manifest_store.get_active().is_some());
        if let Some(manifest) = manifest_store.get_active() {
            assert!(manifest.title().is_some());
            assert_eq!(manifest.ingredients().len(), 2);
        } else {
            panic!("no manifest in store");
        }
        Ok(())
    }
}
