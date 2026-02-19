// Copyright 2023 Adobe. All rights reserved.
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

// Example demonstrating the placeholder/sign workflow for data-hashed embeddable manifests.
//
// This workflow allows clients to:
// 1. Create a placeholder manifest with a pre-sized DataHash assertion
// 2. Embed the placeholder into their asset
// 3. Calculate the hash of the asset (excluding the placeholder)
// 4. Update the DataHash in the Builder with the calculated hash
// 5. Sign the placeholder to create the final manifest
//
// This approach supports dynamic assertions (e.g., CAWG) and gives clients
// full control over the embedding and hashing process.

use std::{
    io::{Cursor, Seek, Write},
    path::PathBuf,
};

use c2pa::{
    assertions::{c2pa_action, Action},
    Builder, ClaimGeneratorInfo, HashRange, Reader, Result,
};
use serde_json::json;
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("DataHash demo");

    user_data_hash_with_placeholder_api()?;
    println!("Done with placeholder API");
    Ok(())
}

fn user_data_hash_with_placeholder_api() -> Result<()> {
    use c2pa::{Context, Settings};

    let mut claim_generator = ClaimGeneratorInfo::new("test_app".to_string());
    claim_generator.set_version("0.1");

    // Use Settings to configure signer with CAWG support
    let settings = Settings::new().with_toml(include_str!(
        "../tests/fixtures/test_settings_with_cawg_signing.toml"
    ))?;

    let src = "sdk/tests/fixtures/earth_apollo17.jpg";
    let format = "image/jpeg";
    let source = PathBuf::from(src);

    // Create a Builder with Context from Settings
    let context = Context::new().with_settings(settings)?.into_shared();
    let mut builder = Builder::from_shared_context(&context);

    let parent_json = json!({"relationship": "parentOf", "label": "parent_label"});
    builder.add_ingredient_from_stream(
        parent_json.to_string(),
        format,
        &mut std::fs::File::open(&source)?,
    )?;
    builder.add_action(
        Action::new(c2pa_action::OPENED).set_parameter("ingredientIds", ["parent_label"])?,
    )?;

    // Create the placeholder manifest (automatically adds a DataHash if none exists).
    // Returns composed bytes (format-specific wrapper applied) ready to embed.
    // The placeholder JUMBF length is stored internally for sign_embeddable().
    let jpeg_placeholder = builder.placeholder("image/jpeg")?;

    let bytes = std::fs::read(&source)?;
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len() + jpeg_placeholder.len());

    // Insert placeholder at beginning of JPEG (after SOI marker)
    let manifest_pos = 2;
    output.extend_from_slice(&bytes[0..manifest_pos]);
    output.extend_from_slice(&jpeg_placeholder);
    output.extend_from_slice(&bytes[manifest_pos..]);

    let mut output_stream = Cursor::new(output);

    // Register where the placeholder was embedded, then hash the asset.
    // set_data_hash_exclusions replaces the dummy exclusions from placeholder().
    builder.set_data_hash_exclusions(vec![HashRange::new(
        manifest_pos as u64,
        jpeg_placeholder.len() as u64,
    )])?;
    builder.update_hash_from_stream("image/jpeg", &mut output_stream)?;

    // Sign — the Builder stored the placeholder JUMBF length internally, so the returned
    // composed bytes are the same size as jpeg_placeholder and can patch it in-place.
    let final_manifest = builder.sign_embeddable("image/jpeg")?;

    // Replace placeholder with final signed manifest
    output_stream.seek(std::io::SeekFrom::Start(manifest_pos as u64))?;
    output_stream.write_all(&final_manifest)?;

    output_stream.rewind()?;
    let reader = Reader::from_stream("image/jpeg", &mut output_stream)?;

    println!("Manifest with placeholder API (supports dynamic assertions):");
    println!("{reader}\n");

    Ok(())
}
