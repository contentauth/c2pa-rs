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
        assertions::{c2pa_action, Action, Actions, AssetReference},
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
}
