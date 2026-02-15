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

//! Schema compliance tests for crJSON format

use c2pa::{CrJsonReader, Result};
use std::io::Cursor;

const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("fixtures/CA.jpg");

#[test]
fn test_validation_status_schema_compliance() -> Result<()> {
    let mut reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;

    // Compute asset hash
    let mut stream = Cursor::new(IMAGE_WITH_MANIFEST);
    reader.compute_asset_hash(&mut stream)?;

    let json_value = reader.to_json_value()?;

    // Verify extras:validation_status exists
    let validation_status = json_value
        .get("extras:validation_status")
        .expect("extras:validation_status should exist");

    // Verify required fields
    assert!(
        validation_status.get("isValid").is_some(),
        "isValid field should exist"
    );
    assert!(
        validation_status.get("isValid").unwrap().is_boolean(),
        "isValid should be boolean"
    );

    // Verify error field (should be null or string)
    let error = validation_status
        .get("error")
        .expect("error field should exist");
    assert!(
        error.is_null() || error.is_string(),
        "error should be null or string"
    );

    // Verify validationErrors is an array
    let validation_errors = validation_status
        .get("validationErrors")
        .expect("validationErrors should exist");
    assert!(
        validation_errors.is_array(),
        "validationErrors should be an array"
    );

    // Verify each validationError object has required fields
    for error_obj in validation_errors.as_array().unwrap() {
        assert!(error_obj.is_object(), "Each error should be an object");
        let obj = error_obj.as_object().unwrap();

        // Required: code
        assert!(obj.contains_key("code"), "Error should have code field");
        assert!(
            obj.get("code").unwrap().is_string(),
            "code should be string"
        );

        // Optional: message
        if let Some(message) = obj.get("message") {
            assert!(message.is_string(), "message should be string");
        }

        // Required: severity
        assert!(
            obj.contains_key("severity"),
            "Error should have severity field"
        );
        let severity = obj.get("severity").unwrap().as_str().unwrap();
        assert!(
            severity == "error" || severity == "warning" || severity == "info",
            "severity should be error, warning, or info"
        );
    }

    // Verify entries array
    let entries = validation_status
        .get("entries")
        .expect("entries should exist");
    assert!(entries.is_array(), "entries should be an array");

    // Verify each entry object has required fields
    for entry_obj in entries.as_array().unwrap() {
        assert!(entry_obj.is_object(), "Each entry should be an object");
        let obj = entry_obj.as_object().unwrap();

        // Required: code
        assert!(obj.contains_key("code"), "Entry should have code field");
        assert!(
            obj.get("code").unwrap().is_string(),
            "code should be string"
        );

        // Optional: url
        if let Some(url) = obj.get("url") {
            assert!(url.is_string(), "url should be string");
        }

        // Optional: explanation
        if let Some(explanation) = obj.get("explanation") {
            assert!(explanation.is_string(), "explanation should be string");
        }

        // Required: severity
        assert!(
            obj.contains_key("severity"),
            "Entry should have severity field"
        );
        let severity = obj.get("severity").unwrap().as_str().unwrap();
        assert!(
            severity == "error" || severity == "warning" || severity == "info",
            "severity should be error, warning, or info"
        );
    }

    Ok(())
}

#[test]
fn test_manifest_status_schema_compliance() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // Get manifests array
    let manifests = json_value
        .get("manifests")
        .expect("manifests should exist")
        .as_array()
        .expect("manifests should be an array");

    // Check first manifest for status
    if let Some(manifest) = manifests.first() {
        if let Some(status) = manifest.get("status") {
            assert!(status.is_object(), "status should be an object");
            let status_obj = status.as_object().unwrap();

            // Per-manifest status can have: signature, trust, content, assertion
            // All should be strings or objects

            if let Some(signature) = status_obj.get("signature") {
                assert!(signature.is_string(), "signature status should be string");
            }

            if let Some(trust) = status_obj.get("trust") {
                assert!(trust.is_string(), "trust status should be string");
            }

            if let Some(content) = status_obj.get("content") {
                assert!(content.is_string(), "content status should be string");
            }

            if let Some(assertion) = status_obj.get("assertion") {
                assert!(assertion.is_object(), "assertion status should be object");
                // Each assertion status value should be a string
                for (_key, value) in assertion.as_object().unwrap() {
                    assert!(
                        value.is_string(),
                        "assertion status values should be strings"
                    );
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_asset_info_schema_compliance() -> Result<()> {
    let mut reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;

    // Compute hash to populate asset_info
    let mut stream = Cursor::new(IMAGE_WITH_MANIFEST);
    reader.compute_asset_hash(&mut stream)?;

    let json_value = reader.to_json_value()?;

    // Verify asset_info exists
    let asset_info = json_value
        .get("asset_info")
        .expect("asset_info should exist when hash is computed");

    assert!(asset_info.is_object(), "asset_info should be an object");
    let asset_info_obj = asset_info.as_object().unwrap();

    // Required: alg
    assert!(
        asset_info_obj.contains_key("alg"),
        "asset_info should have alg field"
    );
    assert!(
        asset_info_obj.get("alg").unwrap().is_string(),
        "alg should be string"
    );

    // Required: hash
    assert!(
        asset_info_obj.contains_key("hash"),
        "asset_info should have hash field"
    );
    assert!(
        asset_info_obj.get("hash").unwrap().is_string(),
        "hash should be string"
    );

    Ok(())
}

#[test]
fn test_context_schema_compliance() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // Verify @context exists
    let context = json_value.get("@context").expect("@context should exist");

    // @context can be array of URIs or object
    assert!(
        context.is_object() || context.is_array(),
        "@context should be object or array"
    );

    // If object, should have @vocab property
    if let Some(context_obj) = context.as_object() {
        if let Some(vocab) = context_obj.get("@vocab") {
            assert!(vocab.is_string(), "@vocab should be string");
        }
    }

    Ok(())
}

#[test]
fn test_manifests_array_schema_compliance() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // Verify manifests is an array
    let manifests = json_value.get("manifests").expect("manifests should exist");

    assert!(manifests.is_array(), "manifests should be an array");

    // Check each manifest
    for manifest in manifests.as_array().unwrap() {
        assert!(manifest.is_object(), "Each manifest should be an object");
        let manifest_obj = manifest.as_object().unwrap();

        // Should have label
        if let Some(label) = manifest_obj.get("label") {
            assert!(label.is_string(), "label should be string");
        }

        // Should have claim.v2
        if let Some(claim) = manifest_obj.get("claim.v2") {
            assert!(claim.is_object(), "claim.v2 should be object");
        }

        // Should have assertions as object (not array)
        if let Some(assertions) = manifest_obj.get("assertions") {
            assert!(
                assertions.is_object(),
                "assertions should be object, not array"
            );
        }
    }

    Ok(())
}

#[test]
fn test_content_object_exists() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    // content object should exist (can be empty)
    let content = json_value.get("content").expect("content should exist");
    assert!(content.is_object(), "content should be an object");

    Ok(())
}

#[test]
fn test_complete_schema_structure() -> Result<()> {
    let mut reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;

    // Compute hash for complete output
    let mut stream = Cursor::new(IMAGE_WITH_MANIFEST);
    reader.compute_asset_hash(&mut stream)?;

    let json_value = reader.to_json_value()?;

    // Verify all top-level required/expected fields
    assert!(json_value.get("@context").is_some(), "@context missing");
    assert!(
        json_value.get("asset_info").is_some(),
        "asset_info missing (with hash)"
    );
    assert!(json_value.get("manifests").is_some(), "manifests missing");
    assert!(json_value.get("content").is_some(), "content missing");
    assert!(
        json_value.get("extras:validation_status").is_some(),
        "extras:validation_status missing"
    );

    // Verify types
    assert!(json_value["@context"].is_object());
    assert!(json_value["asset_info"].is_object());
    assert!(json_value["manifests"].is_array());
    assert!(json_value["content"].is_object());
    assert!(json_value["extras:validation_status"].is_object());

    Ok(())
}
