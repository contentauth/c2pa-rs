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
    use std::{io, path::PathBuf};

    use c2pa::{
        assertions::{c2pa_action, Action, Actions, AssetReference, Metadata},
        settings::Settings,
        Builder, Ingredient, Reader, Result,
    };
    #[allow(unused)] // different code path for WASI
    use tempfile::{tempdir, TempDir};

    /// Returns the path to a fixture file.
    fn fixture_path(file_name: &str) -> PathBuf {
        #[cfg(target_os = "wasi")]
        let mut fixture_path = PathBuf::from("/");
        #[cfg(not(target_os = "wasi"))]
        let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixture_path.push("tests/fixtures");
        fixture_path.push(file_name);
        fixture_path
    }

    // prevent tests from polluting the results of each other because of Rust unit test concurrency
    //static PROTECT: std::sync::Mutex<u32> = std::sync::Mutex::new(1);

    fn tempdirectory() -> io::Result<TempDir> {
        #[cfg(target_os = "wasi")]
        return TempDir::new_in("/");

        #[cfg(not(target_os = "wasi"))]
        return tempdir();
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_embed_manifest() -> Result<()> {
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

        // set up parent and destination paths
        let temp_dir = tempdirectory()?;
        let output_path = temp_dir.path().join("test_file.jpg");
        let parent_path = fixture_path("earth_apollo17.jpg");
        let ingredient_path = fixture_path("libpng-test.png");

        // let generator = ClaimGeneratorInfo::new("app");
        // create a new Manifest
        let mut builder = Builder::new();

        // allocate actions so we can add them
        let mut actions = Actions::new();

        // add a parent ingredient
        // let mut parent = Ingredient::from_file(&parent_path)?;
        // parent.set_is_parent();
        // add an action assertion stating that we imported this file
        actions = actions.add_action(
            Action::new(c2pa_action::OPENED)
                .set_when("2015-06-26T16:43:23+0200")
                .set_parameter("name".to_owned(), "import")?
                .set_parameter("org.cai.ingredientIds", ["apollo17"])?,
        );

        let ingredient_json = serde_json::json!({
            "name": "Earth from Apollo 17",
            "description": "A photo of Earth taken from Apollo 17",
            "relationship": "parentOf",
            "label": "apollo17"
        });
        // set the parent ingredient
        let mut parent_file = std::fs::File::open(&parent_path)?;
        builder.add_ingredient_from_stream(
            ingredient_json.to_string(),
            "image/jpeg",
            &mut parent_file,
        )?;

        actions = actions.add_action(
            Action::new("c2pa.edit").set_parameter("name".to_owned(), "brightnesscontrast")?,
        );

        // add an ingredient
        let ingredient = Ingredient::from_file(&ingredient_path)?;

        // add an action assertion stating that we imported this file
        actions = actions.add_action(
            Action::new(c2pa_action::EDITED)
                .set_parameter("name".to_owned(), "import")?
                .set_parameter("org.cai.ingredientIds", ["apollo17"])?,
        );

        builder.add_ingredient(ingredient);

        builder.add_assertion(Actions::LABEL, &actions)?;

        // sign and embed into the target file
        let signer = Settings::signer()?;
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
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

        // set up parent and destination paths
        let temp_dir = tempdirectory()?;
        let output_path = temp_dir.path().join("test_file.jpg");

        let parent_path = fixture_path("earth_apollo17.jpg");
        let manifest_path = fixture_path("manifest.json");

        let json = std::fs::read_to_string(manifest_path)?;

        let mut builder = Builder::from_json(&json)?;
        builder.base_path = Some(fixture_path(""));

        // sign and embed into the target file
        let signer = Settings::signer()?;
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
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

        // set up parent and destination paths
        let temp_dir = tempdirectory()?;
        let output_path = temp_dir.path().join("test_bmff.heic");

        let parent_path = fixture_path("sample1.heic");

        let mut builder = Builder::new();

        // sign and embed into the target file
        let signer = Settings::signer()?;
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

    #[test]
    #[cfg(feature = "file_io")]
    fn test_asset_reference_assertion() -> Result<()> {
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
        // set up parent and destination paths
        let temp_dir = tempdirectory()?;
        let output_path = temp_dir.path().join("test_file.jpg");
        let parent_path = fixture_path("earth_apollo17.jpg");

        // create a new Manifest
        let mut builder = Builder::new();

        // allocate references
        let references = AssetReference::new(
            "https://some.storage.us/foo",
            Some("A copy of the asset on the web"),
        )
        .add_reference("ipfs://cid", Some("A copy of the asset on IPFS"));

        // add references assertion
        builder.add_assertion(AssetReference::LABEL, &references)?;

        // sign and embed into the target file
        let signer = Settings::signer()?;
        builder.sign_file(signer.as_ref(), &parent_path, &output_path)?;

        // read our new file with embedded manifest
        let reader = Reader::from_file(&output_path)?;

        println!("{reader}");

        assert!(reader.active_manifest().is_some());
        if let Some(manifest) = reader.active_manifest() {
            assert!(manifest.title().is_some());
            assert_eq!(manifest.assertions().len(), 2); // one for AssetReference and one for Actions
            let assertion_ref: AssetReference = manifest.assertions()[1].to_assertion()?;
            assert_eq!(assertion_ref, references);
        } else {
            panic!("no manifest in store");
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_metadata_assertion() -> Result<()> {
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
        // set up parent and destination paths
        let temp_dir = tempdirectory()?;
        let output_path = temp_dir.path().join("test_file.jpg");
        let parent_path = fixture_path("earth_apollo17.jpg");

        // create a new Manifest
        let mut builder = Builder::new();

        // allocate references
        const C2PA_METADATA: &str = r#"{
         "@context" : {
            "exif": "http://ns.adobe.com/exif/1.0/",
            "Iptc4xmpExt": "http://iptc.org/std/Iptc4xmpExt/2008-02-29/",
            "photoshop" : "http://ns.adobe.com/photoshop/1.0/"
        },
        "photoshop:DateCreated": "Aug 31, 2022",
        "Iptc4xmpExt:DigitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture",
        "exif:GPSVersionID": "2.2.0.0",
        "exif:GPSLatitude": "39,21.102N"
        }
        "#;

        const CUSTOM_METADATA: &str = r#" {
        "@context" : {
            "bar": "http://foo.com/bar/1.0/"
        },
        "bar:baz" : "foo"
        }
        "#;

        // allocate metadata
        let c2pa_metadata_assertion = Metadata::new("c2pa.metadata", C2PA_METADATA)?;
        let custom_metadata_assertion = Metadata::new("custom.foo.metadata", CUSTOM_METADATA)?;

        // add metadata assertions
        builder.add_assertion_json(
            c2pa_metadata_assertion.get_label(),
            &c2pa_metadata_assertion,
        )?;
        builder.add_assertion_json(
            custom_metadata_assertion.get_label(),
            &custom_metadata_assertion,
        )?;

        // sign and embed into the target file
        let signer = Settings::signer()?;
        builder.sign_file(signer.as_ref(), &parent_path, &output_path)?;

        // read our new file with embedded manifest
        let reader = Reader::from_file(&output_path)?;

        println!("{reader}");

        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[cfg(feature = "file_io")]
    #[tokio::test]
    async fn test_cawg_signing_via_settings() -> Result<()> {
        Settings::from_toml(include_str!(
            "../tests/fixtures/test_settings_with_cawg_signing.toml"
        ))?;

        // Set up parent and destination paths.
        let temp_dir = tempdirectory()?;
        let output_path = temp_dir.path().join("test_file.jpg");
        let parent_path = fixture_path("earth_apollo17.jpg");

        // Create a new Manifest.
        let mut builder = Builder::new();

        // Sign and embed into the target file.
        let signer = Settings::signer()?;
        builder.sign_file(signer.as_ref(), &parent_path, &output_path)?;

        // Read back the new file with embedded manifest.
        let mut reader = Reader::from_file(&output_path)?;

        reader
            .post_validate_async(&c2pa::identity::validator::CawgValidator {})
            .await
            .unwrap();

        dbg!(&reader);

        // The test credentials are currently flagged as untrusted.
        // This will be fixed when https://github.com/contentauth/c2pa-rs/pull/1356
        // is merged.
        assert_eq!(
            reader
                .validation_results()
                .unwrap()
                .active_manifest()
                .unwrap()
                .failure()
                .last()
                .unwrap()
                .code(),
            "signingCredential.untrusted"
        );

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_certificate_status() -> Result<()> {
        use std::io::Cursor;

        use c2pa::ValidationState;
        use serde_json::json;
        let parent_json = json!({
            "title": "Parent Test",
            "relationship": "parentOf",
            "label": "CA.jpg",
        })
        .to_string();
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

        // set up parent and destination paths
        let temp_dir = tempdirectory()?;
        let output_path = temp_dir.path().join("test_file.jpg");
        let parent_path = fixture_path("earth_apollo17.jpg");

        // create a new Manifest
        let mut builder = Builder::new();

        // sign and embed into the target file
        let signer = Settings::signer()?;
        let mut source = Cursor::new(include_bytes!("fixtures/ocsp.jpg"));
        builder.add_ingredient_from_stream(parent_json, "image/jpeg", &mut source)?;
        builder.sign_file(signer.as_ref(), &parent_path, &output_path)?;

        // read our new file with embedded manifest
        let reader = Reader::from_file(&output_path)?;
        let reader_json = reader.json();
        // ensure certificate status assertion was created
        // TODO: wasm32 does not yet support OCSP fetching
        #[cfg(not(target_arch = "wasm32"))]
        assert!(reader_json.contains(r#"label": "c2pa.certificate-status"#));
        assert_eq!(reader.validation_status(), None);
        assert_eq!(reader.validation_state(), ValidationState::Valid);
        assert!(reader_json.contains("signingCredential.ocsp.notRevoked"));

        Ok(())
    }
}
