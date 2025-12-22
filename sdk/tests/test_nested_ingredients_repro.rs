// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
//
// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

// Run this:
// cargo test --test test_nested_ingredients_repro --features file_io
//
// This test writes two JSON files for comparison:
// - tests/test_nested_ingredients_repro_manifest1.json (manifest without serialization)
// - tests/test_nested_ingredients_repro_manifest2.json (manifest after serialize/deserialize)

#[cfg(feature = "file_io")]
use std::io::{Cursor, Seek};

#[cfg(feature = "file_io")]
use c2pa::{settings::Settings, Builder, Reader, Result};

#[cfg(feature = "file_io")]
mod common;
#[cfg(feature = "file_io")]
use common::test_signer;

#[test]
#[cfg(feature = "file_io")]
fn test_nested_ingredient_serialization_issue() -> Result<()> {
    // Load settings with c2pa archive generation enabled
    Settings::from_toml(include_str!("fixtures/test_settings.toml"))?;

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/repro-sundae-ice-cream.png");
    let format = "image/png";

    // Path 1: Create a builder, add ingredient, and sign directly (no serialization)
    let mut builder_1 = Builder::new();
    let mut ingredient_stream_1 = Cursor::new(TEST_IMAGE);
    let ingredient_json_1 = serde_json::json!({
        "title": "Sundae Ice Cream 1",
        "relationship": "parentOf",
    });
    builder_1.add_ingredient_from_stream(
        ingredient_json_1.to_string(),
        format,
        &mut ingredient_stream_1,
    )?;

    // Sign to get the reference manifest, which is complete
    let mut source_1 = Cursor::new(TEST_IMAGE);
    let mut first_signed = Cursor::new(Vec::new());
    builder_1.sign(&test_signer(), format, &mut source_1, &mut first_signed)?;

    first_signed.rewind()?;
    let first_reader = Reader::from_stream(format, &mut first_signed)?;
    let first_manifest_json = first_reader.json();

    println!("First manifest has {} bytes", first_manifest_json.len());

    // Let's keep it in a file, shall we?
    std::fs::write(
        "tests/test_nested_ingredients_repro_manifest1.json",
        &first_manifest_json
    )?;

    // Verify that first manifest has all ingredient data
    assert!(
        first_manifest_json.contains("Sundae Ice Cream"),
        "First manifest should contain the ingredient title"
    );

    // ================================== This is where we start to see issues
    // Do the exact same thing: create a Builder, add that image as ingredient
    // (Only difference is the title to differientiate the two test results)
    let mut builder_2 = Builder::new();
    let mut ingredient_stream_2 = Cursor::new(TEST_IMAGE);
    let ingredient_json_2 = serde_json::json!({
        "title": "Sundae Ice Cream 2",
        "relationship": "parentOf",
    });
    builder_2.add_ingredient_from_stream(
        ingredient_json_2.to_string(),
        format,
        &mut ingredient_stream_2,
    )?;

    // Serialize the builder to archive
    // (using c2pa format, didn't check for zip if there is the same issue, but I would think so)
    let mut archive = Cursor::new(Vec::new());
    builder_2.to_archive(&mut archive)?;

    // Deserialize the builder from the archive
    archive.rewind()?;
    let mut reloaded_builder = Builder::from_archive(&mut archive)?;

    // Sign the reloaded builder
    // Expectation: we should get the EXACT same manifest as the one which was not serialized after signing
    // Since they should be the same Builder/working store
    // (Expectation: same structure with the nested ingredients)
    let mut source_2 = Cursor::new(TEST_IMAGE);
    let mut second_signed = Cursor::new(Vec::new());
    reloaded_builder.sign(&test_signer(), format, &mut source_2, &mut second_signed)?;

    second_signed.rewind()?;
    let second_reader = Reader::from_stream(format, &mut second_signed)?;
    let second_manifest_json = second_reader.json();

    println!("Second manifest has {} bytes", second_manifest_json.len());

    // Write second manifest to file for comparison with the first one
    std::fs::write(
        "tests/test_nested_ingredients_repro_manifest2.json",
        &second_manifest_json
    )?;

    // The issue: we don't get the same manifest store. Original un-serialized store contains 3 manifests.
    // Serialized-deserialized-signed one lost data and contains only 2.
    let first_manifest_count = first_reader.manifests().len();
    let second_manifest_count = second_reader.manifests().len();

    println!("First manifest store has {} manifests", first_manifest_count);
    println!("Second manifest (serialized-deserialized) store has {} manifests", second_manifest_count);

    // manifests urn:uuid:7b53519d-d98d-4fd4-9823-39121199fe38 and urn:uuid:b5820ce6-3e0f-4e6e-8ad5-e52ccbbe97b6
    //are related to ingredient data
    assert_eq!(
        first_manifest_count, 3,
        "First manifest store should have 3 manifests"
    );

    // will fail until bug is fixed
    // manifest urn:uuid:b5820ce6-3e0f-4e6e-8ad5-e52ccbbe97b6 is there
    // manifest urn:uuid:7b53519d-d98d-4fd4-9823-39121199fe38 is lost but I think should be there
    assert_eq!(
        second_manifest_count, 3,
        "Second manifest store should have 3 manifests too"
    );

    Ok(())
}

