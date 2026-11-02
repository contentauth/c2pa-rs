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

//! Demonstrates how to sign an unsigned derived asset while keeping the original's
//! C2PA manifest as the parent ingredient, when the original is not available at
//! signing time.
//!
//! A derived asset, such as a downscaled proxy, often has no manifest of its own.
//! Capture the original as an ingredient archive while it is available, and add the
//! archive as the parent ingredient when signing the edited derived asset.
//!
//! The workflow:
//! 1. While the original is available, capture it as an ingredient archive.
//! 2. Create a derived asset (a downscaled copy) that has no manifest.
//! 3. Later, edit the derived asset without access to the original.
//! 4. Sign the edited asset, adding the archived original as its parent and
//!    recording every change made since the parent.
//! 5. Verify that the parent ingredient is the original's manifest.
//!
//! Run with: `cargo run --example sign_unsigned_derived_asset`

use std::{
    io::{Cursor, Seek},
    sync::Arc,
};

use anyhow::Result;
use c2pa::{
    validation_results::ValidationState, Builder, BuilderIntent, Context, Reader, Relationship,
    Settings,
};
use image::{imageops::FilterType, ImageFormat};
use serde_json::json;

const ORIGINAL: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
const FORMAT: &str = "image/jpeg";
const PARENT_LABEL: &str = "parent";

/// What is kept once the original is no longer available.
struct Ingested {
    original_manifest: String,
    parent_archive: Vec<u8>,
    derived: Vec<u8>,
}

/// Steps 1 and 2: the only code with access to the original.
fn ingest(context: &Arc<Context>, original: &[u8]) -> Result<Ingested> {
    // Kept only to verify the result in step 5.
    let original_manifest = Reader::from_shared_context(context)
        .with_stream(FORMAT, Cursor::new(original))?
        .active_label()
        .map(str::to_owned)
        .expect("original has a manifest");

    // 1. Capture the original as an ingredient archive. The archive keeps the
    // original's manifest store and the validation results captured now. Use
    // `write_ingredient_archive` rather than `to_archive`, which saves the whole builder.
    let mut builder = Builder::from_shared_context(context);
    builder.add_ingredient_from_stream(
        json!({
            "title": "CA.jpg",
            "relationship": "parentOf",
            "label": PARENT_LABEL
        })
        .to_string(),
        FORMAT,
        &mut Cursor::new(original),
    )?;
    let mut parent_archive = Cursor::new(Vec::new());
    builder.write_ingredient_archive(PARENT_LABEL, &mut parent_archive)?;

    // 2. Create a derived asset. Re-encoding the pixels does not carry the manifest over.
    let image = image::load_from_memory(original)?;
    let mut derived = Cursor::new(Vec::new());
    image
        .resize(image.width() / 2, image.height() / 2, FilterType::Triangle)
        .write_to(&mut derived, ImageFormat::Jpeg)?;
    assert!(
        Reader::from_shared_context(context)
            .with_stream(FORMAT, Cursor::new(derived.get_ref()))
            .is_err(),
        "derived asset should not have a manifest"
    );

    Ok(Ingested {
        original_manifest,
        parent_archive: parent_archive.into_inner(),
        derived: derived.into_inner(),
    })
}

fn main() -> Result<()> {
    let settings =
        Settings::new().with_json(include_str!("../tests/fixtures/test_settings.json"))?;
    let context = Context::new().with_settings(settings)?.into_shared();

    // 1-2. While the original is available, capture it as an ingredient archive and
    // create the derived asset. Ingest and signing usually happen at different times.
    let Ingested {
        original_manifest,
        parent_archive,
        derived,
    } = ingest(&context, ORIGINAL)?;

    // 3. Edit the derived asset. From here on, only the archive and the derived asset
    // are used.
    let mut edited = Cursor::new(Vec::new());
    image::load_from_memory(&derived)?
        .brighten(20)
        .write_to(&mut edited, ImageFormat::Jpeg)?;

    // 4. Sign the edited asset with the archived original as its parent.
    //
    // Record every change made since the parent, including the downscale that produced
    // the derived asset, since the derived asset has no manifest of its own. Marking the
    // actions assertion as `created` keeps these actions in the same assertion as the
    // `c2pa.opened` action that the edit intent adds.
    let mut builder = Builder::from_shared_context(&context).with_definition(
        json!({
            "title": "edited.jpg",
            "format": FORMAT,
            "claim_generator_info": [{
                "name": "sign unsigned derived asset example",
                "version": env!("CARGO_PKG_VERSION")
            }],
            "assertions": [{
                "label": "c2pa.actions.v2",
                "created": true,
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.resized",
                            "description": "Downscaled to half size"
                        },
                        {
                            "action": "c2pa.color_adjustments",
                            "parameters": { "name": "brightness" }
                        }
                    ]
                }
            }]
        })
        .to_string(),
    )?;

    // The edit intent adds the `c2pa.opened` action linked to the parent ingredient.
    // Without an explicit parent, it would use the asset being signed, which has no
    // manifest, so add the archived original as the parent.
    builder.set_intent(BuilderIntent::Edit);
    builder.add_ingredient_from_archive(&mut Cursor::new(&parent_archive))?;

    edited.rewind()?;
    let mut signed = Cursor::new(Vec::new());
    builder.save_to_stream(FORMAT, &mut edited, &mut signed)?;

    // 5. Verify that the parent ingredient is the original's manifest.
    signed.rewind()?;
    let reader = Reader::from_shared_context(&context).with_stream(FORMAT, &mut signed)?;
    println!("{}", reader.json());

    assert_eq!(reader.validation_state(), ValidationState::Trusted);
    let parent = reader
        .active_manifest()
        .expect("signed asset has a manifest")
        .ingredients()
        .iter()
        .find(|i| *i.relationship() == Relationship::ParentOf)
        .expect("signed asset has a parent ingredient");
    assert_eq!(parent.active_manifest(), Some(original_manifest.as_str()));

    // The parent ingredient records the validation results captured when the original
    // was archived.
    let parent_results = parent
        .validation_results()
        .expect("parent ingredient has validation results");
    assert_eq!(parent_results.validation_state(), ValidationState::Trusted);

    Ok(())
}

#[cfg(test)]
mod tests {
    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::*;

    use super::*;

    #[c2pa_test_async]
    async fn test_sign_unsigned_derived_asset() -> Result<()> {
        main()
    }
}
