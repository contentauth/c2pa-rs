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

//! Schema compliance tests for crJSON format.
//! These tests validate CrJSON output structure and alignment with `cli/schemas/crJSON-schema.json`.
//!
//! **Reviewing generated crJSON when tests run:** set the environment variable
//! `C2PA_WRITE_CRJSON=1` (or any value), then run the crjson tests. Generated crJSON
//! for the fixture (CA.jpg) will be written to `target/crjson_test_output/` under
//! the build target directory (e.g. `target/crjson_test_output/CA.jpg.json` when
//! running from the workspace root, or `sdk/target/crjson_test_output/CA.jpg.json`
//! when building from the sdk directory). Example:
//!
//! ```sh
//! C2PA_WRITE_CRJSON=1 cargo test crjson
//! # then open target/crjson_test_output/CA.jpg.json
//! ```

use c2pa::{CrJsonReader, Result};
use std::io::Cursor;

const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../fixtures/CA.jpg");

/// CrJSON schema (cli/schemas/crJSON-schema.json) - used to verify output structure.
const CRJSON_SCHEMA: &str = include_str!("../../../cli/schemas/crJSON-schema.json");

/// When C2PA_WRITE_CRJSON is set, write generated crJSON to target/crjson_test_output/
/// so you can review the exact output. Called at the start of tests that build CrJsonReader.
fn maybe_write_crjson_output(name: &str, json: &str) {
    if std::env::var("C2PA_WRITE_CRJSON").is_ok() {
        let out_dir = std::path::PathBuf::from("target/crjson_test_output");
        let _ = std::fs::create_dir_all(&out_dir);
        let path = out_dir.join(name);
        let _ = std::fs::write(&path, json);
        eprintln!("CrJSON written to {:?} (C2PA_WRITE_CRJSON=1)", path);
    }
}

#[test]
fn test_validation_results_schema_compliance() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    maybe_write_crjson_output("CA.jpg.json", &reader.json());

    let json_value = reader.to_json_value()?;

    // Verify validationResults exists
    let validation_results = json_value
        .get("validationResults")
        .expect("validationResults should exist");
    assert!(
        validation_results.is_object(),
        "validationResults should be an object"
    );

    let vr = validation_results.as_object().unwrap();

    // Required per schema: activeManifest (statusCodes with success, informational, failure)
    let active_manifest = vr
        .get("activeManifest")
        .expect("validationResults must have activeManifest per crJSON schema");
    assert!(active_manifest.is_object(), "activeManifest should be object");
    let am = active_manifest.as_object().unwrap();
    for key in &["success", "informational", "failure"] {
        let arr = am
            .get(*key)
            .unwrap_or_else(|| panic!("activeManifest must have {} array per schema", key));
        assert!(arr.is_array(), "{} should be array", key);
        for entry in arr.as_array().unwrap() {
            assert!(entry.is_object(), "Each entry should be object");
            let obj = entry.as_object().unwrap();
            assert!(obj.contains_key("code"), "Entry should have code (validationStatusEntry)");
            assert!(obj.get("code").unwrap().is_string(), "code should be string");
            if let Some(url) = obj.get("url") {
                assert!(url.is_string(), "url should be string");
            }
            if let Some(explanation) = obj.get("explanation") {
                assert!(explanation.is_string(), "explanation should be string");
            }
        }
    }

    // Optional: ingredientDeltas array
    if let Some(deltas) = vr.get("ingredientDeltas") {
        assert!(deltas.is_array(), "ingredientDeltas should be array");
        for item in deltas.as_array().unwrap() {
            assert!(item.is_object(), "Each delta should be object");
            let obj = item.as_object().unwrap();
            assert!(
                obj.contains_key("ingredientAssertionURI"),
                "Delta should have ingredientAssertionURI"
            );
            assert!(
                obj.contains_key("validationDeltas"),
                "Delta should have validationDeltas"
            );
        }
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

    // Check each manifest (schema required: label, assertions, signature, status; oneOf: claim or claim.v2)
    for manifest in manifests.as_array().unwrap() {
        assert!(manifest.is_object(), "Each manifest should be an object");
        let manifest_obj = manifest.as_object().unwrap();

        // Required: label
        let label = manifest_obj.get("label").expect("manifest should have label");
        assert!(label.is_string(), "label should be string");

        // Required: assertions (object, not array)
        let assertions = manifest_obj
            .get("assertions")
            .expect("manifest should have assertions");
        assert!(
            assertions.is_object(),
            "assertions should be object, not array"
        );

        // Required: signature (object with optional algorithm, issuer, etc.)
        let signature = manifest_obj
            .get("signature")
            .expect("manifest should have signature");
        assert!(signature.is_object(), "signature should be object");

        // Required: status (object)
        let status = manifest_obj.get("status").expect("manifest should have status");
        assert!(status.is_object(), "status should be object");

        // oneOf: either claim or claim.v2 (implementation emits claim.v2)
        let has_claim = manifest_obj.get("claim").is_some();
        let has_claim_v2 = manifest_obj.get("claim.v2").is_some();
        assert!(
            has_claim || has_claim_v2,
            "manifest should have either claim or claim.v2"
        );
        if let Some(claim_v2) = manifest_obj.get("claim.v2") {
            assert!(claim_v2.is_object(), "claim.v2 should be object");
            // Per crJSON schema, claim.v2.claim_generator_info is a single object, not an array
            if let Some(cgi) = claim_v2.get("claim_generator_info") {
                assert!(
                    cgi.is_object(),
                    "claim.v2.claim_generator_info must be object per schema, got array or other"
                );
                // When present, icon must be hashedUriMap (url, hash, optional alg) per schema
                if let Some(icon) = cgi.get("icon") {
                    assert!(icon.is_object(), "claim_generator_info.icon must be object (hashedUriMap)");
                    let icon_obj = icon.as_object().unwrap();
                    assert!(
                        icon_obj.get("url").and_then(|v| v.as_str()).is_some(),
                        "claim_generator_info.icon must have string 'url' (hashedUriMap)"
                    );
                    assert!(
                        icon_obj.get("hash").and_then(|v| v.as_str()).is_some(),
                        "claim_generator_info.icon must have string 'hash' (hashedUriMap)"
                    );
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_complete_schema_structure() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;

    let json_value = reader.to_json_value()?;

    // Verify all top-level required fields (no asset_info, content, or metadata)
    assert!(json_value.get("@context").is_some(), "@context missing");
    assert!(json_value.get("manifests").is_some(), "manifests missing");
    assert!(
        json_value.get("validationResults").is_some(),
        "validationResults missing"
    );

    // CrJSON does not include asset_info, content, or metadata
    assert!(json_value.get("asset_info").is_none());
    assert!(json_value.get("content").is_none());
    assert!(json_value.get("metadata").is_none());

    // Verify types
    assert!(json_value["@context"].is_object());
    assert!(json_value["manifests"].is_array());
    assert!(json_value["validationResults"].is_object());

    Ok(())
}

/// Load and parse the CrJSON schema file; ensure it defines the expected root properties
/// and does not include declaration, asset_info, content, or metadata.
#[test]
fn test_cr_json_schema_file_valid_and_matches_format() -> Result<()> {
    let schema_value: serde_json::Value =
        serde_json::from_str(CRJSON_SCHEMA).expect("crJSON-schema.json must be valid JSON");

    let props = schema_value
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("schema must have properties");

    // CrJSON schema must define these root properties
    assert!(props.contains_key("@context"), "schema must define @context");
    assert!(props.contains_key("manifests"), "schema must define manifests");
    assert!(
        props.contains_key("validationResults"),
        "schema must define validationResults"
    );

    // CrJSON schema must NOT include removed sections
    assert!(!props.contains_key("declaration"), "schema must not include declaration");
    assert!(!props.contains_key("asset_info"), "schema must not include asset_info");
    assert!(!props.contains_key("content"), "schema must not include content");
    assert!(!props.contains_key("metadata"), "schema must not include metadata");

    // Schema $id should reference crJSON-schema
    let id = schema_value.get("$id").and_then(|i| i.as_str()).unwrap_or("");
    assert!(
        id.contains("crJSON-schema"),
        "schema $id should reference crJSON-schema.json, got: {}",
        id
    );

    Ok(())
}

/// Verify CrJSON output from the reader conforms to the schema's root shape
/// (no declaration, asset_info, content, metadata).
#[test]
fn test_cr_json_output_matches_schema_root() -> Result<()> {
    let reader = CrJsonReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_json_value()?;

    let schema_value: serde_json::Value =
        serde_json::from_str(CRJSON_SCHEMA).expect("crJSON-schema.json must be valid JSON");
    let props = schema_value
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("schema must have properties");

    // Every top-level key in output should be allowed by the schema (or be additionalProperties)
    for key in json_value.as_object().unwrap().keys() {
        assert!(
            props.contains_key(key),
            "CrJSON output key {:?} is not in crJSON-schema.json properties (schema may allow via additionalProperties)",
            key
        );
    }

    // Output must not contain removed root keys
    assert!(json_value.get("declaration").is_none());
    assert!(json_value.get("asset_info").is_none());
    assert!(json_value.get("content").is_none());
    assert!(json_value.get("metadata").is_none());

    Ok(())
}
