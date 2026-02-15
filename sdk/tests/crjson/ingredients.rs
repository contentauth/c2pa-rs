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

//! Tests for ingredient assertions in crJSON format

use c2pa::{CrJsonReader, Result};
use std::io::Cursor;

const IMAGE_WITH_INGREDIENT: &[u8] = include_bytes!("../fixtures/CA.jpg");

#[test]
fn test_ingredient_assertions_included() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_json_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    // Check first manifest for ingredient assertion
    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Should have ingredient assertion
    assert!(
        assertions.contains_key("c2pa.ingredient"),
        "assertions should contain c2pa.ingredient"
    );

    // Verify ingredient structure
    let ingredient = &assertions["c2pa.ingredient"];
    assert!(ingredient.is_object(), "ingredient should be an object");

    // Check for expected ingredient fields
    let ingredient_obj = ingredient.as_object().unwrap();
    assert!(
        ingredient_obj.contains_key("title"),
        "ingredient should have title"
    );
    assert!(
        ingredient_obj.contains_key("format"),
        "ingredient should have format"
    );

    // Verify all hashes in ingredient are base64 strings, not byte arrays
    if let Some(c2pa_manifest) = ingredient_obj.get("c2pa_manifest") {
        if let Some(hash) = c2pa_manifest.get("hash") {
            assert!(
                hash.is_string(),
                "ingredient c2pa_manifest hash should be string"
            );
        }
    }

    if let Some(thumbnail) = ingredient_obj.get("thumbnail") {
        if let Some(hash) = thumbnail.get("hash") {
            assert!(hash.is_string(), "ingredient thumbnail hash should be string");
        }
    }

    Ok(())
}

#[test]
fn test_ingredient_count_matches() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_json_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Count ingredient assertions
    let ingredient_count = assertions
        .keys()
        .filter(|k| k.starts_with("c2pa.ingredient"))
        .count();

    // CA.jpg has 1 ingredient (A.jpg as parent)
    assert_eq!(
        ingredient_count, 1,
        "Should have exactly 1 ingredient assertion"
    );

    Ok(())
}

#[test]
fn test_ingredient_referenced_in_claim() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_json_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    println!("Total manifests: {}", manifests.len());
    for (i, m) in manifests.iter().enumerate() {
        println!("Manifest {}: label={:?}", i, m.get("label"));
        if let Some(claim_v2) = m.get("claim.v2") {
            if let Some(created) = claim_v2.get("created_assertions") {
                println!("  Created assertions count: {}", created.as_array().map(|a| a.len()).unwrap_or(0));
            }
            if let Some(gathered) = claim_v2.get("gathered_assertions") {
                println!("  Gathered assertions count: {}", gathered.as_array().map(|a| a.len()).unwrap_or(0));
            }
        }
    }

    // Find the manifest with the ingredient (active manifest with claim v2)
    let active_manifest = manifests
        .iter()
        .filter(|m| {
            // Look for a manifest with non-empty created or gathered assertions
            if let Some(claim_v2) = m.get("claim.v2") {
                let has_created = claim_v2.get("created_assertions")
                    .and_then(|a| a.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                let has_gathered = claim_v2.get("gathered_assertions")
                    .and_then(|a| a.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                has_created || has_gathered
            } else {
                false
            }
        })
        .next()
        .expect("should have at least one manifest with assertions");

    // Check if ingredient is referenced in created_assertions
    let claim_v2 = active_manifest["claim.v2"]
        .as_object()
        .expect("claim.v2 should exist");

    let created_assertions = claim_v2["created_assertions"]
        .as_array()
        .expect("created_assertions should be array");

    let gathered_assertions = claim_v2["gathered_assertions"]
        .as_array()
        .expect("gathered_assertions should be array");

    // Debug: Print what we found
    println!("Created assertions count: {}", created_assertions.len());
    println!("Gathered assertions count: {}", gathered_assertions.len());
    for (i, a) in created_assertions.iter().enumerate() {
        println!("Created[{}]: {}", i, a.get("url").unwrap_or(&serde_json::Value::Null));
    }
    for (i, a) in gathered_assertions.iter().enumerate() {
        println!("Gathered[{}]: {}", i, a.get("url").unwrap_or(&serde_json::Value::Null));
    }

    // Find ingredient reference in EITHER created or gathered
    let has_ingredient_in_created = created_assertions.iter().any(|assertion_ref| {
        if let Some(url) = assertion_ref.get("url") {
            url.as_str()
                .map(|s| s.contains("c2pa.ingredient"))
                .unwrap_or(false)
        } else {
            false
        }
    });

    let has_ingredient_in_gathered = gathered_assertions.iter().any(|assertion_ref| {
        if let Some(url) = assertion_ref.get("url") {
            url.as_str()
                .map(|s| s.contains("c2pa.ingredient"))
                .unwrap_or(false)
        } else {
            false
        }
    });

    // Ingredient should be in one or the other
    assert!(
        has_ingredient_in_created || has_ingredient_in_gathered,
        "Ingredient should be referenced in either created_assertions or gathered_assertions"
    );

    Ok(())
}

#[test]
fn test_ingredient_in_actions_parameter() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_json_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Check actions assertion for ingredient reference
    if let Some(actions_assertion) = assertions.get("c2pa.actions.v2") {
        let actions = actions_assertion["actions"]
            .as_array()
            .expect("actions should be array");

        // Find action with ingredient parameter
        let has_ingredient_param = actions.iter().any(|action| {
            action
                .get("parameters")
                .and_then(|p| p.get("ingredient"))
                .is_some()
        });

        assert!(
            has_ingredient_param,
            "At least one action should have ingredient parameter"
        );
    }

    Ok(())
}

#[test]
fn test_multiple_ingredients_have_instances() -> Result<()> {
    // Note: CA.jpg only has 1 ingredient, so this test verifies the instance logic
    // For files with multiple ingredients, they would be labeled:
    // c2pa.ingredient__1, c2pa.ingredient__2, etc.

    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // For single ingredient, should be just "c2pa.ingredient"
    assert!(
        assertions.contains_key("c2pa.ingredient"),
        "Single ingredient should be c2pa.ingredient without instance"
    );

    // Should NOT have instance suffix for single ingredient
        assert!(
            !assertions.contains_key("c2pa.ingredient__1"),
            "Single ingredient should not have instance number"
        );

    Ok(())
}

#[test]
fn test_ingredient_label_matches_version() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Get the ingredient assertion (could be c2pa.ingredient, c2pa.ingredient.v2, or c2pa.ingredient.v3)
    let ingredient_key = assertions
        .keys()
        .find(|k| k.starts_with("c2pa.ingredient"))
        .expect("Should have an ingredient assertion");

    // Get the ingredient object
    let ingredient = &assertions[ingredient_key];
    let ingredient_obj = ingredient.as_object().expect("ingredient should be object");

    // Verify the label field is NOT present (it's redundant since the key is the label)
    assert!(
        !ingredient_obj.contains_key("label"),
        "Ingredient should not have redundant label field"
    );
    
    // Verify the key follows correct versioning pattern
    assert!(
        ingredient_key == "c2pa.ingredient" 
            || ingredient_key.starts_with("c2pa.ingredient.v"),
        "Ingredient key should be c2pa.ingredient or c2pa.ingredient.v{{N}}"
    );

    Ok(())
}

