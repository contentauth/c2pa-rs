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
use c2pa::{settings::Settings, validation_results::ValidationState, Builder, Reader};
use serde_json::json;

const TEST_SETTINGS: &str = include_str!("../tests/fixtures/test_settings.toml");
const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");

/// This example demonstrates how to use the new v2 API to create a manifest store
/// It uses only streaming apis, showing how to avoid file i/o
/// This example uses the `ed25519` signing algorithm
fn main() -> Result<()> {
    let title = "v2_edited.jpg";
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    Settings::from_toml(TEST_SETTINGS)?;

    let mut builder = Builder::edit();
    builder.definition.title = Some(title.to_string());

    builder.add_action(json!({
        "action": "c2pa.edited",
        "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia",
        "softwareAgent": {
            "name": "My AI Tool",
            "version": "0.1.0"
        }
    }))?;

    builder.add_ingredient(json!({
        "title": "Test",
        "format": format,
        "instance_id": "12345",
        "relationship": "inputTo"
    }))?;

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

    // unzip the manifest builder from the zipped stream
    zipped.rewind()?;

    let signer = Settings::signer()?;

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
    assert_eq!(reader.validation_state(), ValidationState::Valid);
    assert_eq!(reader.active_manifest().unwrap().title().unwrap(), title);

    Ok(())
}

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
