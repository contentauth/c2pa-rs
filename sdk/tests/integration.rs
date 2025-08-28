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

    #[cfg(feature = "v1_api")]
    struct PlacedCallback {
        path: String,
    }

    #[cfg(feature = "v1_api")]
    use c2pa::{Error, Manifest, ManifestPatchCallback};

    #[cfg(feature = "v1_api")]
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
    #[cfg(all(feature = "file_io", feature = "v1_api"))]
    fn test_placed_manifest() -> Result<()> {
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

        // set up parent and destination paths
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;
        use std::io::Seek;
        let dir = tempdirectory()?;
        let output_path = dir.path().join("test_file.jpg");

        #[cfg(target_os = "wasi")]
        let mut fixture_path = PathBuf::from("/");
        #[cfg(not(target_os = "wasi"))]
        let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixture_path.push("tests/fixtures");
        let mut manifest_path = fixture_path.clone();
        manifest_path.push("manifest.json");
        let mut parent_path = fixture_path.clone();
        parent_path.push("earth_apollo17.jpg");

        let json = std::fs::read_to_string(manifest_path)?;

        let mut manifest = Manifest::from_json(&json)?;
        // WASI does not support canonicalize(), but the path is canonical to begin with
        #[cfg(target_os = "wasi")]
        let base_path = fixture_path;
        #[cfg(not(target_os = "wasi"))]
        let base_path = fixture_path.canonicalize()?;
        manifest.with_base_path(base_path)?;

        // sign and embed into the target file
        let signer = Settings::signer()?;

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

    #[test]
    #[cfg(all(feature = "file_io", feature = "v1_api"))]
    fn test_placed_manifest_bmff() -> Result<()> {
        Settings::from_toml(include_str!("../tests/fixtures/test_settings.toml"))?;

        // set up parent and destination paths
        use std::io::Seek;
        let dir = tempdirectory()?;
        let output_path = dir.path().join("video1.mp4");

        #[cfg(target_os = "wasi")]
        let mut fixture_path = PathBuf::from("/");
        #[cfg(not(target_os = "wasi"))]
        let mut fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        fixture_path.push("tests/fixtures");
        let mut manifest_path = fixture_path.clone();
        manifest_path.push("manifest.json");
        let mut parent_path = fixture_path.clone();
        parent_path.push("video1.mp4");

        let json = std::fs::read_to_string(manifest_path)?;

        let mut manifest = Manifest::from_json(&json)?;
        // WASI does not support canonicalize(), but the path is canonical to begin with
        #[cfg(target_os = "wasi")]
        let base_path = fixture_path;
        #[cfg(not(target_os = "wasi"))]
        let base_path = fixture_path.canonicalize()?;
        manifest.with_base_path(base_path)?;

        // sign and embed into the target file
        let signer = Settings::signer()?;

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
