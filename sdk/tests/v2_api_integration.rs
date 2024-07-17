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

/// Complete functional integration test with acquisitions and ingredients.
//  Isolate from wasm by wrapping in module.
#[cfg(not(target_arch = "wasm32"))] // wasm doesn't support ed25519 yet
mod integration_v2 {

    use std::io::{Cursor, Seek};

    use anyhow::Result;
    use c2pa::{Builder, CallbackSigner, Reader, SigningAlg};
    use serde_json::json;

    const PARENT_JSON: &str = r#"
    {
        "title": "Parent Test",
        "format": "image/jpeg",
        "relationship": "parentOf"
    }
    "#;

    const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/assets/jpeg/CA.jpg");
    const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
    const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

    fn get_manifest_def(title: &str, format: &str) -> String {
        json!({
        "title": title,
        "format": format,
        "claim_generator_info": [
            {
                "name": "c2pa test",
                "version": env!("CARGO_PKG_VERSION")
            }
        ],
        "metadata": [
            {
                "dateTime": "1985-04-12T23:20:50.52Z",
                "my_custom_metadata": "my custom metatdata value"
            }
        ],
        "thumbnail": {
            "format": "image/jpeg",
            "identifier": "manifest_thumbnail.jpg"
        },
        "ingredients": [
            {
                "title": "Test",
                "format": "image/jpeg",
                "instance_id": "12345",
                "relationship": "inputTo"
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.edited",
                            "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
                            "softwareAgent": "Adobe Firefly 0.1.0"
                        }
                    ]
                }
            }
        ]
    }).to_string()
    }

    #[test]
    fn test_v2_integration() -> Result<()> {
        let title = "CA.jpg";
        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);

        let json = get_manifest_def(title, format);

        // don't try to verify on wasm since it doesn't support ed25519 yet

        let mut builder = Builder::from_json(&json)?;
        builder.add_ingredient(PARENT_JSON, format, &mut source)?;

        // add a manifest thumbnail ( just reuse the image for now )
        source.rewind()?;
        builder.add_resource("manifest_thumbnail.jpg", &mut source)?;

        // write the manifest builder to a zipped stream
        let mut zipped = Cursor::new(Vec::new());
        builder.to_archive(&mut zipped)?;

        // write the zipped stream to a file for debugging
        //let debug_path = format!("{}/../target/test.zip", env!("CARGO_MANIFEST_DIR"));
        // std::fs::write(debug_path, zipped.get_ref())?;

        // unzip the manifest builder from the zipped stream
        zipped.rewind()?;

        let mut dest = {
            let ed_signer = |_context: *const _, data: &[u8]| ed_sign(data, PRIVATE_KEY);
            let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);
            let mut builder = Builder::from_archive(&mut zipped)?;
            // sign the ManifestStoreBuilder and write it to the output stream
            let mut dest = Cursor::new(Vec::new());
            builder.sign(&signer, format, &mut source, &mut dest)?;

            // read and validate the signed manifest store
            dest.rewind()?;
            dest
        };

        let reader = Reader::from_stream(format, &mut dest)?;

        // extract a thumbnail image from the ManifestStore
        let mut thumbnail = Cursor::new(Vec::new());
        if let Some(manifest) = reader.active_manifest() {
            if let Some(thumbnail_ref) = manifest.thumbnail_ref() {
                reader.resource_to_stream(&thumbnail_ref.identifier, &mut thumbnail)?;
                println!(
                    "wrote thumbnail {} of size {}",
                    thumbnail_ref.format,
                    thumbnail.get_ref().len()
                );
            }
        }

        println!("{}", reader.json());
        assert!(reader.validation_status().is_none());
        assert_eq!(reader.active_manifest().unwrap().title().unwrap(), title);

        Ok(())
    }

    fn ed_sign(data: &[u8], private_key: &[u8]) -> c2pa::Result<Vec<u8>> {
        use ed25519_dalek::{Signature, Signer, SigningKey};
        use pem::parse;

        // Parse the PEM data to get the private key
        let pem = parse(private_key).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
        // For Ed25519, the key is 32 bytes long, so we skip the first 16 bytes of the PEM data
        let key_bytes = &pem.contents()[16..];
        let signing_key =
            SigningKey::try_from(key_bytes).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
        // Sign the data
        let signature: Signature = signing_key.sign(data);

        Ok(signature.to_bytes().to_vec())
    }
}
