// Copyright 2026 Adobe. All rights reserved.
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

//! Demonstrates how to redact an assertion from a parent manifest using an update manifest.
//!
//! Redaction removes an assertion from a prior manifest in the claim chain.
//! This is useful when you need to strip metadata (e.g., GPS coordinates)
//! before distributing an asset.
//!
//! The workflow:
//! 1. Create an initial manifest with a `c2pa.metadata` assertion containing EXIF data.
//! 2. Open the signed asset with a [`Reader`] to discover the assertion's JUMBF URI.
//! 3. Build an update manifest that redacts that assertion.
//! 4. Verify the redaction was applied.

use std::io::Cursor;

use anyhow::Result;
use c2pa::{
    assertions::{Action, C2paAction, C2paReason},
    settings::Settings,
    validation_results::ValidationState,
    Builder, BuilderIntent, Context, Reader,
};
use serde_json::json;

const SOURCE_IMAGE: &[u8] = include_bytes!("../tests/fixtures/earth_apollo17.jpg");

fn main() -> Result<()> {
    let format = "image/jpeg";

    let settings =
        Settings::new().with_json(include_str!("../tests/fixtures/test_settings.json"))?;
    let context = Context::new().with_settings(settings)?.into_shared();

    // --- Step 1: Create an initial manifest with a c2pa.metadata assertion ---

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(
        c2pa::DigitalSourceType::DigitalCapture,
    ));

    builder.add_assertion(
        "c2pa.metadata",
        &json!({
            "@context": {
                "exif": "http://ns.adobe.com/exif/1.0/",
                "tiff": "http://ns.adobe.com/tiff/1.0/"
            },
            "exif:GPSLatitude": "39,21.102N",
            "exif:GPSLongitude": "74,26.5737W",
            "tiff:Make": "CameraCompany",
            "tiff:Model": "Shooter S1"
        }),
    )?;

    let mut source = Cursor::new(SOURCE_IMAGE);
    let mut signed_asset = Cursor::new(Vec::new());
    builder.save_to_stream(format, &mut source, &mut signed_asset)?;

    // Verify the initial manifest has the metadata assertion.
    signed_asset.set_position(0);
    let reader = Reader::from_shared_context(&context).with_stream(format, &mut signed_asset)?;
    let manifest = reader
        .active_manifest()
        .ok_or(anyhow::anyhow!("no manifest"))?;

    // To redact an assertion you need its full JUMBF URI. The easiest way to
    // get it is via `assertion_references()`, which returns `HashedUri` values
    // whose `.url()` is the complete JUMBF URI for each assertion.
    let redacted_uri = manifest
        .assertion_references()
        .find(|r| r.url().contains("c2pa.metadata"))
        .map(|r| r.url())
        .expect("c2pa.metadata assertion reference should exist");

    println!("Redaction target URI: {redacted_uri}");

    // --- Create an update manifest that redacts the assertion ---

    let mut update_builder = Builder::from_shared_context(&context);
    update_builder.set_intent(BuilderIntent::Update);

    // Add the JUMBF URI to the redactions list.
    update_builder.definition.redactions = Some(vec![redacted_uri.clone()]);

    // Per the C2PA spec, include a c2pa.redacted action explaining the redaction.
    let redacted_action = Action::new(C2paAction::Redacted)
        .set_reason(C2paReason::PiiPresent)
        .set_parameter("redacted", &redacted_uri)?;
    update_builder.add_action(redacted_action)?;

    // Sign the update manifest. The source is the previously signed asset.
    signed_asset.set_position(0);
    let mut output = Cursor::new(Vec::new());
    update_builder.save_to_stream(format, &mut signed_asset, &mut output)?;

    // --- Verify the redaction ---

    output.set_position(0);
    let reader = Reader::from_shared_context(&context).with_stream(format, &mut output)?;

    assert_eq!(reader.validation_state(), ValidationState::Trusted);

    // Confirm the active manifest lists our URI in its redactions.
    // The SDK enforces that listed redactions are actually applied.
    let manifest = reader
        .active_manifest()
        .ok_or(anyhow::anyhow!("no manifest"))?;
    assert!(
        manifest
            .redactions()
            .is_some_and(|r| r.iter().any(|uri| uri == &redacted_uri)),
        "active manifest should list the redacted URI"
    );

    println!("Verified - c2pa.metadata assertion successfully redacted");
    println!("\nFull manifest store:\n{}", reader.json());

    Ok(())
}

#[cfg(test)]
mod tests {
    //use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::*;

    use super::*;

    //#[c2pa_test_async]
    #[test]
    fn test_redaction_example() -> Result<()> {
        main()
    }
}
