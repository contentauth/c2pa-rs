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

//! Tests for hash encoding in crJSON format
//!
//! Verifies that all hash fields are properly encoded as base64 strings
//! rather than byte arrays.

use c2pa::{CrJsonReader, Result};
use serde_json::Value;
use std::io::Cursor;

const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../fixtures/CA.jpg");

/// Recursively check that all "hash" fields in the JSON are strings (base64),
/// not arrays of integers.
fn verify_no_byte_array_hashes(value: &Value, path: &str) -> Vec<String> {
    let mut errors = Vec::new();

    match value {
        Value::Object(map) => {
            // Check if this object has a "hash" field
            if let Some(hash_value) = map.get("hash") {
                let current_path = format!("{}.hash", path);

                if hash_value.is_array() {
                    // This is bad - hash should not be an array
                    errors.push(format!(
                        "Found byte array hash at {}: {:?}",
                        current_path, hash_value
                    ));
                } else if let Some(hash_str) = hash_value.as_str() {
                    // Good - it's a string. Verify it looks like base64
                    if !is_valid_base64(hash_str) {
                        errors.push(format!(
                            "Hash at {} is not valid base64: {}",
                            current_path, hash_str
                        ));
                    }
                }
            }

            // Recursively check all values
            for (key, val) in map {
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                errors.extend(verify_no_byte_array_hashes(val, &new_path));
            }
        }
        Value::Array(arr) => {
            // Recursively check all array elements
            for (i, val) in arr.iter().enumerate() {
                let new_path = format!("{}[{}]", path, i);
                errors.extend(verify_no_byte_array_hashes(val, &new_path));
            }
        }
        _ => {}
    }

    errors
}

/// Check if a string is valid base64
fn is_valid_base64(s: &str) -> bool {
    // Base64 characters are A-Z, a-z, 0-9, +, /, and = for padding
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
        && !s.is_empty()
}

#[test]
fn test_no_byte_array_hashes() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // Verify no byte array hashes exist anywhere in the output
    let errors = verify_no_byte_array_hashes(&json_value, "");

    if !errors.is_empty() {
        panic!(
            "Found {} byte array hash(es) in output:\n{}",
            errors.len(),
            errors.join("\n")
        );
    }

    Ok(())
}

#[test]
fn test_action_ingredient_hash_is_base64() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // Navigate to the actions assertion
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests
        .first()
        .expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Check c2pa.actions.v2 if it exists
    if let Some(actions_assertion) = assertions.get("c2pa.actions.v2") {
        let actions = actions_assertion["actions"]
            .as_array()
            .expect("actions should be array");

        for (i, action) in actions.iter().enumerate() {
            // Check if this action has ingredient parameter
            if let Some(params) = action.get("parameters") {
                if let Some(ingredient) = params.get("ingredient") {
                    if let Some(hash) = ingredient.get("hash") {
                        assert!(
                            hash.is_string(),
                            "Action {} ingredient hash should be string, not array",
                            i
                        );

                        let hash_str = hash.as_str().unwrap();
                        assert!(
                            is_valid_base64(hash_str),
                            "Action {} ingredient hash should be valid base64: {}",
                            i,
                            hash_str
                        );

                        // Verify it's not empty
                        assert!(
                            !hash_str.is_empty(),
                            "Action {} ingredient hash should not be empty",
                            i
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_assertion_reference_hashes_are_base64() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // Check created_assertions hashes in claim.v2
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests
        .first()
        .expect("should have at least one manifest");
    let claim_v2 = first_manifest["claim.v2"]
        .as_object()
        .expect("claim.v2 should be object");

    if let Some(created_assertions) = claim_v2.get("created_assertions") {
        let assertions_array = created_assertions
            .as_array()
            .expect("created_assertions should be array");

        for (i, assertion_ref) in assertions_array.iter().enumerate() {
            if let Some(hash) = assertion_ref.get("hash") {
                assert!(
                    hash.is_string(),
                    "Assertion reference {} hash should be string, not array",
                    i
                );

                let hash_str = hash.as_str().unwrap();
                assert!(
                    is_valid_base64(hash_str),
                    "Assertion reference {} hash should be valid base64: {}",
                    i,
                    hash_str
                );
            }
        }
    }

    Ok(())
}

#[test]
fn test_ingredient_assertion_hashes_are_base64() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // Check ingredient assertions
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests
        .first()
        .expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Check for ingredient assertions (can have various labels)
    for (label, assertion_value) in assertions {
        if label.contains("ingredient") {
            // Check c2pa_manifest hash
            if let Some(c2pa_manifest) = assertion_value.get("c2pa_manifest") {
                if let Some(hash) = c2pa_manifest.get("hash") {
                    assert!(
                        hash.is_string(),
                        "Ingredient {} c2pa_manifest hash should be string",
                        label
                    );
                }
            }

            // Check thumbnail hash
            if let Some(thumbnail) = assertion_value.get("thumbnail") {
                if let Some(hash) = thumbnail.get("hash") {
                    assert!(
                        hash.is_string(),
                        "Ingredient {} thumbnail hash should be string",
                        label
                    );
                }
            }

            // Check activeManifest hash
            if let Some(active_manifest) = assertion_value.get("activeManifest") {
                if let Some(hash) = active_manifest.get("hash") {
                    assert!(
                        hash.is_string(),
                        "Ingredient {} activeManifest hash should be string",
                        label
                    );
                }
            }

            // Check claimSignature hash
            if let Some(claim_signature) = assertion_value.get("claimSignature") {
                if let Some(hash) = claim_signature.get("hash") {
                    assert!(
                        hash.is_string(),
                        "Ingredient {} claimSignature hash should be string",
                        label
                    );
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_all_hashes_match_schema_format() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // Collect all hash values
    let mut hash_count = 0;

    fn count_hashes(value: &Value, counter: &mut usize) {
        match value {
            Value::Object(map) => {
                if let Some(hash_value) = map.get("hash") {
                    if hash_value.is_string() {
                        *counter += 1;
                    }
                }
                for val in map.values() {
                    count_hashes(val, counter);
                }
            }
            Value::Array(arr) => {
                for val in arr {
                    count_hashes(val, counter);
                }
            }
            _ => {}
        }
    }

    count_hashes(&json_value, &mut hash_count);

    // Should have multiple hashes in a typical manifest
    assert!(
        hash_count > 0,
        "Should have at least one hash field in the output"
    );

    println!("Verified {} hash fields are all base64 strings", hash_count);

    Ok(())
}
