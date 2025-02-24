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

//! Example App showing how to use the new v2 API
use std::io::{Cursor, Seek};

use anyhow::Result;
use c2pa::{
    settings::load_settings_from_str, validation_results::ValidationState, Builder, CallbackSigner,
    Reader,
};
use c2pa_crypto::raw_signature::SigningAlg;
use serde_json::json;

const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn manifest_def(title: &str, format: &str) -> String {
    json!({
        "title": title,
        "format": format,
        "claim_generator_info": [
            {
                "name": "c2pa test",
                "version": env!("CARGO_PKG_VERSION")
            }
        ],
        "thumbnail": {
            "format": format,
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
                            "softwareAgent": {
                                "name": "My AI Tool",
                                "version": "0.1.0"
                            }
                        }
                    ]
                }
            }
        ]
    }).to_string()
}

/// This example demonstrates how to use the new v2 API to create a manifest store
/// It uses only streaming apis, showing how to avoid file i/o
/// This example uses the `ed25519` signing algorithm
fn main() -> Result<()> {
    let title = "v2_edited.jpg";
    let format = "image/jpeg";
    let parent_name = "CA.jpg";
    let mut source = Cursor::new(TEST_IMAGE);

    let modified_core = json!({
        "core": {
            "debug": true,
            "hash_alg": "sha512",
            "max_memory_usage": 123456
        }
    })
    .to_string();

    load_settings_from_str(&modified_core, "json")?;

    let json = manifest_def(title, format);

    let mut builder = Builder::from_json(&json)?;
    builder.add_ingredient_from_stream(
        json!({
            "title": parent_name,
            "relationship": "parentOf"
        })
        .to_string(),
        format,
        &mut source,
    )?;

    let thumb_uri = builder
        .definition
        .thumbnail
        .as_ref()
        .map(|t| t.identifier.clone());

    // add a manifest thumbnail ( just reuse the image for now )
    if let Some(uri) = thumb_uri {
        if !uri.starts_with("self#jumbf") {
            source.rewind()?;
            builder.add_resource(&uri, &mut source)?;
        }
    }

    // write the manifest builder to a zipped stream
    let mut zipped = Cursor::new(Vec::new());
    builder.to_archive(&mut zipped)?;

    // write the zipped stream to a file for debugging
    //let debug_path = format!("{}/../target/test.zip", env!("CARGO_MANIFEST_DIR"));
    // std::fs::write(debug_path, zipped.get_ref())?;

    // unzip the manifest builder from the zipped stream
    zipped.rewind()?;

    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    let mut builder = Builder::from_archive(&mut zipped)?;
    // sign the ManifestStoreBuilder and write it to the output stream
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&signer, format, &mut source, &mut dest)?;

    // read and validate the signed manifest store
    dest.rewind()?;

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
    assert_ne!(reader.validation_state(), ValidationState::Invalid);
    assert_eq!(reader.active_manifest().unwrap().title().unwrap(), title);

    Ok(())
}

// use openssl::{error::ErrorStack, pkey::PKey};
// #[cfg(feature = "openssl")]
// fn ed_sign(data: &[u8], pkey: &[u8]) -> std::result::Result<Vec<u8>, ErrorStack> {
//     let pkey = PKey::private_key_from_pem(pkey)?;
//     let mut signer = openssl::sign::Signer::new_without_digest(&pkey)?;
//     signer.sign_oneshot_to_vec(data)
// }

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::*;

    use super::*;

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn test_v2_api() -> Result<()> {
        main()
    }
}
