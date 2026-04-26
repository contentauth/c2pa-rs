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

//! Test that diamond DAG manifests don't cause exponential revisits.
//!
//! In a diamond DAG (manifest A references B and C, both referencing D),
//! without dedup the recursive validation visits O(2^N) nodes instead of O(N).
//! At depth 14, that's 16,384 visits instead of ~28, causing 30-70 minute hangs.

use std::collections::HashMap;
use std::io::Cursor;
use std::time::Instant;

use c2pa::{Builder, BuilderIntent, Context, Reader, Result, Settings};
use serde_json::json;

mod common;

const TEST_SETTINGS: &str = include_str!("../tests/fixtures/test_settings.toml");

/// Generate a diamond DAG of manifests at the given depth.
///
/// Structure: at each level, two manifests both reference all manifests from the
/// previous level. The final manifest references both branches, creating a diamond.
fn generate_diamond_dag(depth: u32) -> Result<Vec<u8>> {
    let settings = Settings::new()
        .with_toml(TEST_SETTINGS)?
        .with_value("verify.verify_after_sign", false)?;
    let context = Context::new().with_settings(settings)?.into_shared();
    let format = "image/jpeg";
    let source_bytes: &[u8] = include_bytes!("fixtures/no_manifest.jpg");

    // Use the test_signer (ed25519, no TSA) to avoid network calls
    let signer = common::test_signer();

    let mut level_images: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();

    // Create base manifest (level 0)
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);
    let mut source = Cursor::new(source_bytes);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&signer, format, &mut source, &mut dest)?;
    level_images.insert(0, vec![dest.into_inner()]);

    // Build diamond: each level has two branches, both referencing all previous level manifests
    for level in 1..depth {
        let mut this_level: Vec<Vec<u8>> = Vec::new();

        for _branch in 0..2 {
            let mut builder = Builder::from_shared_context(&context);
            builder.set_intent(BuilderIntent::Edit);

            let prev_images = level_images.get(&(level - 1)).unwrap();
            for (idx, prev_image) in prev_images.iter().enumerate() {
                let ingredient_json = json!({
                    "title": format!("Parent_L{}_I{}", level - 1, idx),
                    "relationship": "parentOf",
                })
                .to_string();

                let mut ingredient_stream = Cursor::new(prev_image);
                builder.add_ingredient_from_stream(
                    ingredient_json,
                    format,
                    &mut ingredient_stream,
                )?;
            }

            let mut source = Cursor::new(source_bytes);
            let mut dest = Cursor::new(Vec::new());
            builder.sign(&signer, format, &mut source, &mut dest)?;
            this_level.push(dest.into_inner());
        }

        level_images.insert(level, this_level);
    }

    // Create final manifest referencing both branches
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);

    let prev_images = level_images.get(&(depth - 1)).unwrap();
    for (idx, prev_image) in prev_images.iter().enumerate() {
        let ingredient_json = json!({
            "title": format!("Branch_{}", idx),
            "relationship": "parentOf",
        })
        .to_string();

        let mut ingredient_stream = Cursor::new(prev_image);
        builder.add_ingredient_from_stream(ingredient_json, format, &mut ingredient_stream)?;
    }

    let mut source = Cursor::new(source_bytes);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&signer, format, &mut source, &mut dest)?;

    Ok(dest.into_inner())
}

/// Test that a diamond DAG at depth 8 completes in reasonable time.
///
/// Without the dedup fix, depth 8 would cause 2^8 = 256 manifest visits.
/// With the fix, it should visit only ~17 unique manifests.
/// We use a generous 60-second timeout — with the fix this takes < 1 second.
#[test]
fn diamond_dag_depth_8_completes_quickly() -> Result<()> {
    let depth = 8;

    let image_data = generate_diamond_dag(depth)?;

    let start = Instant::now();
    let mut stream = Cursor::new(&image_data);
    let reader = Reader::from_stream("image/jpeg", &mut stream)?;
    let elapsed = start.elapsed();

    let manifest_count = reader.iter_manifests().count();
    assert!(manifest_count > 0, "should have parsed manifests");

    // With the dedup fix, this should complete in well under 60 seconds.
    // Without the fix at depth 8, it would take significantly longer due to 256 visits.
    assert!(
        elapsed.as_secs() < 60,
        "Diamond DAG depth {} took {:?}, which exceeds the 60s limit. \
         This suggests the dedup fix is not working — O(2^N) exponential blowup.",
        depth,
        elapsed,
    );

    Ok(())
}
