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

//! Test that diamond DAG manifests are validated without exponential revisits.
//!
//! In a diamond DAG (manifest A references B and C, both referencing D),
//! the recursive validation in `ingredient_checks` /
//! `get_claim_referenced_manifests_impl` must dedupe already-visited manifests.
//! Without dedup, depth-N walks visit O(2^N) nodes instead of O(N), both hanging
//! validation and producing duplicate entries in the validation log.

use std::collections::HashSet;
use std::io::Cursor;

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

    let signer = common::test_signer();

    let mut prev_level: Vec<Vec<u8>> = Vec::new();

    // Level 0: single base manifest.
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);
    let mut source = Cursor::new(source_bytes);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&signer, format, &mut source, &mut dest)?;
    prev_level.push(dest.into_inner());

    // Intermediate levels: two branches that both ingest every prior-level manifest.
    for _level in 1..depth {
        let mut this_level: Vec<Vec<u8>> = Vec::new();
        for _branch in 0..2 {
            let mut builder = Builder::from_shared_context(&context);
            builder.set_intent(BuilderIntent::Edit);
            for (idx, prev_image) in prev_level.iter().enumerate() {
                let ingredient_json = json!({
                    "title": format!("Parent_{}", idx),
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
        prev_level = this_level;
    }

    // Final manifest closes the diamond by ingesting both top-level branches.
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);
    for (idx, prev_image) in prev_level.iter().enumerate() {
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

/// Validating a diamond DAG must touch each unique manifest exactly once.
///
/// At depth 8 the structure has 1 base + 2*(depth-1) intermediates + 1 final = 16
/// unique manifests. Without dedup the recursive walks would revisit nodes
/// 2^depth = 256 times, ballooning the validation log with duplicate entries
/// (and hanging entirely at higher depths). We assert the exact counts so a
/// regression of either dedup site (`ingredient_checks` or
/// `get_claim_referenced_manifests_impl`) is caught deterministically.
#[test]
fn diamond_dag_validates_each_manifest_once() -> Result<()> {
    let depth = 8;
    let expected_manifest_count = 1 + 2 * (depth - 1) as usize + 1;

    let image_data = generate_diamond_dag(depth)?;
    let mut stream = Cursor::new(&image_data);
    #[allow(deprecated)]
    let reader = Reader::from_stream("image/jpeg", &mut stream)?;

    assert_eq!(
        reader.iter_manifests().count(),
        expected_manifest_count,
        "expected one entry per unique manifest in the diamond",
    );

    let validation_results = reader
        .validation_results()
        .expect("reader should report validation_results");

    let statuses = all_statuses(validation_results);

    // Each manifest is signed with an untrusted test cert, so the count of
    // `signingCredential.untrusted` entries across active + ingredient deltas
    // must equal the number of unique manifests. Without dedup this would
    // explode to O(2^depth).
    let untrusted_urls: Vec<&str> = statuses
        .iter()
        .filter(|s| s.code() == "signingCredential.untrusted")
        .filter_map(|s| s.url())
        .collect();
    assert_eq!(
        untrusted_urls.len(),
        expected_manifest_count,
        "each unique manifest's untrusted-cert finding should appear exactly once",
    );

    // No manifest URI should be reported more than once across the entire
    // result set.
    let unique: HashSet<&str> = untrusted_urls.iter().copied().collect();
    assert_eq!(
        untrusted_urls.len(),
        unique.len(),
        "validation_results contains duplicate manifest URIs (dedup regression)",
    );

    Ok(())
}

/// Flatten every ValidationStatus across active + ingredient deltas into one
/// iterator so callers can count or inspect with simple closures.
fn all_statuses(vr: &c2pa::ValidationResults) -> Vec<&c2pa::validation_status::ValidationStatus> {
    let mut out = Vec::new();
    if let Some(active) = vr.active_manifest() {
        out.extend(active.success());
        out.extend(active.informational());
        out.extend(active.failure());
    }
    if let Some(deltas) = vr.ingredient_deltas() {
        for d in deltas {
            let s = d.validation_deltas();
            out.extend(s.success());
            out.extend(s.informational());
            out.extend(s.failure());
        }
    }
    out
}
