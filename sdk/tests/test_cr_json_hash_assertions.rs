// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::io::Cursor;

use c2pa::{CrJsonReader, Result};

// Test image with manifest
const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("fixtures/C.jpg");

#[test]
fn test_hash_data_assertion_included() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Check that c2pa.hash.data is present
    assert!(
        assertions.contains_key("c2pa.hash.data"),
        "Should have c2pa.hash.data assertion"
    );

    Ok(())
}

#[test]
fn test_hash_data_structure() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    let hash_data = assertions
        .get("c2pa.hash.data")
        .expect("Should have c2pa.hash.data");

    let hash_data_obj = hash_data.as_object().expect("hash.data should be object");

    // Check required fields
    assert!(hash_data_obj.contains_key("hash"), "Should have hash field");
    assert!(hash_data_obj.contains_key("alg"), "Should have alg field");

    // Verify hash is base64 string, not byte array
    let hash = hash_data_obj["hash"]
        .as_str()
        .expect("hash should be a string (base64 encoded)");
    assert!(!hash.is_empty(), "hash should not be empty");
    
    // Verify the hash value doesn't look like a byte array representation
    // (if it were an array, it would serialize as an array in JSON)
    assert!(
        !hash_data_obj["hash"].is_array(),
        "hash should be a string, not an array"
    );

    Ok(())
}

#[test]
fn test_hash_data_algorithm() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    let hash_data = assertions
        .get("c2pa.hash.data")
        .expect("Should have c2pa.hash.data");

    let alg = hash_data["alg"]
        .as_str()
        .expect("alg should be a string");

    // Algorithm should be one of the standard hash algorithms
    assert!(
        alg == "sha256" || alg == "sha384" || alg == "sha512",
        "Algorithm should be a standard hash algorithm, got: {}",
        alg
    );

    Ok(())
}

#[test]
fn test_multiple_hash_assertions() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Count hash assertions (c2pa.hash.data, c2pa.hash.bmff, c2pa.hash.boxes)
    let hash_assertion_count = assertions
        .keys()
        .filter(|k| k.starts_with("c2pa.hash."))
        .count();

    // Should have at least one hash assertion
    assert!(
        hash_assertion_count >= 1,
        "Should have at least one hash assertion, found {}",
        hash_assertion_count
    );

    Ok(())
}

#[test]
fn test_hash_data_not_filtered() -> Result<()> {
    // This test ensures that c2pa.hash.data is included in crJSON format
    // even though it's filtered out in the standard Manifest format
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Verify that hash.data is included
    assert!(
        assertions.contains_key("c2pa.hash.data"),
        "c2pa.hash.data should be included in crJSON format"
    );

    // Compare with standard Reader to confirm it's normally filtered
    let standard_reader = c2pa::Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let standard_json = serde_json::to_value(standard_reader)?;
    
    // In standard format, manifests is a map, not an array
    let manifests_map = standard_json["manifests"]
        .as_object()
        .expect("standard manifests should be object");
    
    let first_standard_manifest = manifests_map.values().next().expect("should have a manifest");
    let standard_assertions = first_standard_manifest["assertions"]
        .as_array()
        .expect("standard assertions should be array");
    
    // Verify it's NOT in the standard assertions array
    let has_hash_data_in_standard = standard_assertions
        .iter()
        .any(|a| a.get("label").and_then(|l| l.as_str()) == Some("c2pa.hash.data"));
    
    assert!(
        !has_hash_data_in_standard,
        "c2pa.hash.data should be filtered out in standard format"
    );

    Ok(())
}

#[test]
fn test_hash_assertion_versioning() -> Result<()> {
    // This test verifies that hash assertions with versions (e.g., c2pa.hash.bmff.v2, v3)
    // are correctly labeled with their version suffix
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    // Check all hash assertion keys
    for (key, _value) in assertions.iter() {
        if key.starts_with("c2pa.hash.") {
            // If this is a versioned assertion, it should have .v{N} suffix
            // The key should be one of:
            // - c2pa.hash.data (v1, no suffix)
            // - c2pa.hash.data.v2
            // - c2pa.hash.data.v3
            // - c2pa.hash.bmff (v1, no suffix)
            // - c2pa.hash.bmff.v2
            // - c2pa.hash.bmff.v3
            // - c2pa.hash.boxes (v1, no suffix)
            // - etc.
            
            // Remove any instance suffix (_1, _2, etc.) for checking
            let base_key = key.split('_').next().unwrap_or(key);
            
            // Verify the label follows correct versioning pattern
            let is_valid = base_key == "c2pa.hash.data" 
                || base_key == "c2pa.hash.bmff"
                || base_key == "c2pa.hash.boxes"
                || base_key == "c2pa.hash.collection.data"
                || base_key.starts_with("c2pa.hash.data.v")
                || base_key.starts_with("c2pa.hash.bmff.v")
                || base_key.starts_with("c2pa.hash.boxes.v")
                || base_key.starts_with("c2pa.hash.collection.data.v");
            
            assert!(
                is_valid,
                "Hash assertion key '{}' should follow versioning pattern", 
                key
            );
        }
    }

    Ok(())
}

#[test]
fn test_hash_assertion_pad_encoding() -> Result<()> {
    // This test verifies that the 'pad' field in hash assertions is base64 encoded,
    // not an array of integers
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    let first_manifest = manifests.first().expect("should have at least one manifest");
    let assertions = first_manifest["assertions"]
        .as_object()
        .expect("assertions should be object");

    let hash_data = assertions
        .get("c2pa.hash.data")
        .expect("Should have c2pa.hash.data");

    let hash_data_obj = hash_data.as_object().expect("hash.data should be object");

    // Check if pad field exists
    if let Some(pad_value) = hash_data_obj.get("pad") {
        // Verify pad is a base64 string, not a byte array
        assert!(
            pad_value.is_string(),
            "pad should be a string (base64), not an array"
        );

        let pad = pad_value.as_str().expect("pad should be a string");
        
        // Verify it's not empty (unless the pad is actually empty)
        // An empty pad would encode to an empty string
        
        // Verify the pad value doesn't look like an array representation
        assert!(
            !pad_value.is_array(),
            "pad should be a string, not an array"
        );
    }

    Ok(())
}


