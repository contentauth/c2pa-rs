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

use std::io::Cursor;

use c2pa::{Reader, Result};

const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../fixtures/CA.jpg");

/// CrJSON schema (cli/schemas/crJSON-schema.json) - used to verify output structure.
const CRJSON_SCHEMA: &str = include_str!("../../../cli/schemas/crJSON-schema.json");

/// When C2PA_WRITE_CRJSON is set, write generated crJSON to target/crjson_test_output/
/// so you can review the exact output. Called at the start of tests that build Reader crJSON.
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
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    maybe_write_crjson_output("CA.jpg.json", &reader.crjson());

    let json_value = reader.to_crjson_value()?;

    // Per-manifest validationResults (statusCodes: success, informational, failure, optional validationTime) and optional ingredientDeltas
    let manifests = json_value
        .get("manifests")
        .and_then(|m| m.as_array())
        .expect("manifests should exist");
    if let Some(first) = manifests.first() {
        let vr = first
            .get("validationResults")
            .expect("manifest must have validationResults per crJSON schema");
        assert!(vr.is_object(), "validationResults should be object");
        let vr_obj = vr.as_object().unwrap();
        for key in &["success", "informational", "failure"] {
            let arr = vr_obj
                .get(*key)
                .unwrap_or_else(|| panic!("validationResults must have {} array per schema", key));
            assert!(arr.is_array(), "{} should be array", key);
            for entry in arr.as_array().unwrap() {
                assert!(entry.is_object(), "Each entry should be object");
                let obj = entry.as_object().unwrap();
                assert!(
                    obj.contains_key("code"),
                    "Entry should have code (validationStatusEntry)"
                );
                assert!(
                    obj.get("code").unwrap().is_string(),
                    "code should be string"
                );
            }
        }
        // Optional: per-manifest validationTime (when validation was run)
        if let Some(vt) = vr_obj.get("validationTime") {
            assert!(vt.is_string(), "validationTime should be string (RFC 3339)");
        }
        // Optional: per-manifest ingredientDeltas
        if let Some(deltas) = first.get("ingredientDeltas") {
            assert!(
                deltas.is_array(),
                "manifest ingredientDeltas should be array"
            );
            for item in deltas.as_array().unwrap() {
                let obj = item.as_object().expect("Each delta should be object");
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
    }

    Ok(())
}

#[test]
fn test_manifest_validation_and_status_schema_compliance() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    // Each manifest has validationResults (manifestValidationResults: success, informational, failure, optional validationTime)
    let manifests = json_value
        .get("manifests")
        .expect("manifests should exist")
        .as_array()
        .expect("manifests should be an array");
    for manifest in manifests {
        let vr = manifest
            .get("validationResults")
            .expect("manifest should have validationResults");
        assert!(vr.is_object(), "validationResults should be object");
        let vr_obj = vr.as_object().unwrap();
        assert!(vr_obj.contains_key("success"));
        assert!(vr_obj.contains_key("informational"));
        assert!(vr_obj.contains_key("failure"));
        if let Some(vt) = vr_obj.get("validationTime") {
            assert!(vt.is_string(), "validationTime should be string (RFC 3339)");
        }
    }

    Ok(())
}

#[test]
fn test_context_schema_compliance() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

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
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    // Verify manifests is an array
    let manifests = json_value.get("manifests").expect("manifests should exist");

    assert!(manifests.is_array(), "manifests should be an array");

    // Check each manifest (schema required: label, assertions, signature, validationResults; oneOf: claim or claim.v2)
    for manifest in manifests.as_array().unwrap() {
        assert!(manifest.is_object(), "Each manifest should be an object");
        let manifest_obj = manifest.as_object().unwrap();

        // Required: label
        let label = manifest_obj
            .get("label")
            .expect("manifest should have label");
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

        // Required: validationResults (statusCodes object)
        let validation_results = manifest_obj
            .get("validationResults")
            .expect("manifest should have validationResults");
        assert!(
            validation_results.is_object(),
            "validationResults should be object"
        );

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
                    assert!(
                        icon.is_object(),
                        "claim_generator_info.icon must be object (hashedUriMap)"
                    );
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
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;

    let json_value = reader.to_crjson_value()?;

    // Verify all top-level required fields (no asset_info, content, or metadata)
    assert!(json_value.get("@context").is_some(), "@context missing");
    assert!(json_value.get("manifests").is_some(), "manifests missing");

    // CrJSON does not include asset_info, content, or metadata
    assert!(json_value.get("asset_info").is_none());
    assert!(json_value.get("content").is_none());
    assert!(json_value.get("metadata").is_none());

    // Verify types
    assert!(json_value["@context"].is_object());
    assert!(json_value["manifests"].is_array());

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
    assert!(
        props.contains_key("@context"),
        "schema must define @context"
    );
    assert!(
        props.contains_key("manifests"),
        "schema must define manifests"
    );

    // Manifest definition must have validationResults (manifestValidationResults) and ingredientDeltas (per-manifest)
    let definitions = schema_value
        .get("definitions")
        .and_then(|d| d.as_object())
        .expect("schema must have definitions");
    let manifest_def = definitions
        .get("manifest")
        .and_then(|m| m.as_object())
        .expect("schema must define manifest");
    let manifest_props = manifest_def
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("manifest must have properties");
    assert!(
        manifest_props.contains_key("validationResults"),
        "manifest must define validationResults (manifestValidationResults with validationTime)"
    );
    assert!(
        manifest_props.contains_key("ingredientDeltas"),
        "manifest must define ingredientDeltas (per-manifest)"
    );

    // CrJSON schema must NOT include removed sections
    assert!(
        !props.contains_key("declaration"),
        "schema must not include declaration"
    );
    assert!(
        !props.contains_key("asset_info"),
        "schema must not include asset_info"
    );
    assert!(
        !props.contains_key("content"),
        "schema must not include content"
    );
    assert!(
        !props.contains_key("metadata"),
        "schema must not include metadata"
    );

    // Schema $id should reference crJSON-schema
    let id = schema_value
        .get("$id")
        .and_then(|i| i.as_str())
        .unwrap_or("");
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
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

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
    assert!(json_value.get("validationInfo").is_none(), "validationInfo was removed; use per-manifest validationResults.validationTime");
    assert!(json_value.get("declaration").is_none());
    assert!(json_value.get("asset_info").is_none());
    assert!(json_value.get("content").is_none());
    assert!(json_value.get("metadata").is_none());

    Ok(())
}

/// Schema must define validationResults (used by ingredient assertions, e.g. c2pa.ingredient.v3).
/// When crJSON output contains an ingredient assertion with validationResults, it must match that definition.
#[test]
fn test_validation_results_definition_and_ingredient_usage() -> Result<()> {
    let schema_value: serde_json::Value =
        serde_json::from_str(CRJSON_SCHEMA).expect("crJSON-schema.json must be valid JSON");
    let definitions = schema_value
        .get("definitions")
        .and_then(|d| d.as_object())
        .expect("schema must have definitions");

    // validationResults definition must exist (used by manifest-level statusCodes and by ingredientAssertionV3)
    let validation_results_def = definitions
        .get("validationResults")
        .and_then(|v| v.as_object())
        .expect("schema must define validationResults for use by ingredient assertions");
    assert_eq!(
        validation_results_def
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or(""),
        "object",
        "validationResults must be type object"
    );
    let vr_props = validation_results_def
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("validationResults must have properties");
    assert!(
        vr_props.contains_key("activeManifest"),
        "validationResults must have activeManifest (statusCodes)"
    );
    assert!(
        vr_props.contains_key("ingredientDeltas"),
        "validationResults must have ingredientDeltas"
    );
    let vr_required = validation_results_def
        .get("required")
        .and_then(|r| r.as_array())
        .expect("validationResults must have required array");
    assert!(
        vr_required
            .iter()
            .any(|v| v.as_str() == Some("activeManifest")),
        "validationResults.required must include activeManifest"
    );

    // ingredientAssertionV3 must reference validationResults
    let ingredient_v3 = definitions
        .get("ingredientAssertionV3")
        .and_then(|v| v.as_object())
        .expect("schema must define ingredientAssertionV3");
    let v3_props = ingredient_v3
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("ingredientAssertionV3 must have properties");
    let vr_ref = v3_props
        .get("validationResults")
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("$ref"))
        .and_then(|r| r.as_str())
        .expect("ingredientAssertionV3.validationResults must have $ref to validationResults");
    assert_eq!(
        vr_ref, "#/definitions/validationResults",
        "ingredientAssertionV3.validationResults must $ref #/definitions/validationResults"
    );

    // When crJSON output contains an ingredient assertion with validationResults, validate its shape
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;
    let manifests = json_value
        .get("manifests")
        .and_then(|m| m.as_array())
        .expect("manifests should exist");
    for manifest in manifests {
        let assertions = match manifest.get("assertions").and_then(|a| a.as_object()) {
            Some(a) => a,
            None => continue,
        };
        for (_key, assertion_value) in assertions {
            let assertion_obj = match assertion_value.as_object() {
                Some(o) => o,
                None => continue,
            };
            if let Some(ingredient_vr) = assertion_obj.get("validationResults") {
                // This assertion has validationResults (e.g. v3 ingredient) - must match validationResults definition
                let vr = ingredient_vr
                    .as_object()
                    .expect("ingredient validationResults must be object");
                let active_manifest = vr
                    .get("activeManifest")
                    .expect("ingredient validationResults must have activeManifest per schema");
                let am = active_manifest
                    .as_object()
                    .expect("activeManifest must be object (statusCodes)");
                for key in &["success", "informational", "failure"] {
                    assert!(
                        am.contains_key(*key),
                        "ingredient validationResults.activeManifest must have {} array",
                        key
                    );
                    assert!(
                        am.get(*key).unwrap().as_array().is_some(),
                        "ingredient validationResults.activeManifest.{} must be array",
                        key
                    );
                }
                if let Some(deltas) = vr.get("ingredientDeltas") {
                    assert!(
                        deltas.is_array(),
                        "ingredient validationResults.ingredientDeltas must be array"
                    );
                }
            }
        }
    }

    Ok(())
}
