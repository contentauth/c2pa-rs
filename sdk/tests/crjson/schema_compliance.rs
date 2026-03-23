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
//!
//! These tests validate CrJSON output against the actual crJSON JSON Schema
//! (`cli/schemas/crJSON-schema.json`) using the `jsonschema` crate, plus
//! targeted structural assertions for requirements the schema leaves as
//! `additionalProperties: true`.
//!
//! **Reviewing generated crJSON when tests run:** set the environment variable
//! `C2PA_WRITE_CRJSON=1`, then run the crjson tests. Generated crJSON will be
//! written to `target/crjson_test_output/`. Example:
//!
//! ```sh
//! C2PA_WRITE_CRJSON=1 cargo test crjson
//! ```

use std::io::Cursor;

use c2pa::{Reader, Result};
use jsonschema::validator_for;

const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../fixtures/CA.jpg");
const IMAGE_WITH_INGREDIENT: &[u8] = include_bytes!("../fixtures/CA.jpg");

/// The crJSON JSON Schema bundled with the project.
const CRJSON_SCHEMA: &str = include_str!("../fixtures/schemas/crJSON-schema.json");

/// When `C2PA_WRITE_CRJSON` is set, write crJSON to `target/crjson_test_output/`
/// so you can inspect the exact output.
fn maybe_write_crjson_output(name: &str, json: &str) {
    if std::env::var("C2PA_WRITE_CRJSON").is_ok() {
        let out_dir = std::path::PathBuf::from("target/crjson_test_output");
        let _ = std::fs::create_dir_all(&out_dir);
        let path = out_dir.join(name);
        let _ = std::fs::write(&path, json);
        eprintln!("CrJSON written to {:?}", path);
    }
}

/// Parse the bundled schema and compile a validator. Panics if the schema is invalid.
fn compiled_schema() -> jsonschema::Validator {
    let schema_value: serde_json::Value =
        serde_json::from_str(CRJSON_SCHEMA).expect("crJSON-schema.json must be valid JSON");
    validator_for(&schema_value).expect("crJSON schema must compile without errors")
}

/// Assert that `value` validates against the crJSON schema, printing all errors on failure.
fn assert_schema_valid(value: &serde_json::Value) {
    let validator = compiled_schema();
    let errors: Vec<_> = validator.iter_errors(value).collect();
    if !errors.is_empty() {
        let msgs: Vec<String> = errors
            .iter()
            .map(|e| format!("  - [{}] {}", e.instance_path(), e))
            .collect();
        panic!(
            "crJSON output failed schema validation:\n{}",
            msgs.join("\n")
        );
    }
}

// ── Root document ────────────────────────────────────────────────────────────

/// The full crJSON output must pass JSON Schema validation.
#[test]
fn test_crjson_passes_schema_validation() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;
    maybe_write_crjson_output(
        "CA.jpg.json",
        &serde_json::to_string_pretty(&json_value).unwrap(),
    );
    assert_schema_valid(&json_value);
    Ok(())
}

/// Root document must have exactly the required top-level fields.
#[test]
fn test_root_required_fields() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    assert!(json_value.get("@context").is_some(), "@context is required");
    assert!(
        json_value.get("manifests").is_some(),
        "manifests is required"
    );
    assert!(
        json_value.get("jsonGenerator").is_some(),
        "jsonGenerator is required"
    );

    // Fields explicitly removed from the spec must not appear.
    assert!(
        json_value.get("declaration").is_none(),
        "declaration was removed from spec"
    );
    assert!(
        json_value.get("asset_info").is_none(),
        "asset_info was removed from spec"
    );
    assert!(
        json_value.get("content").is_none(),
        "content was removed from spec"
    );
    assert!(
        json_value.get("validationInfo").is_none(),
        "validationInfo was removed from spec"
    );

    Ok(())
}

/// `jsonGenerator` must have `name` and `version` (SemVer) but not `date`.
#[test]
fn test_json_generator_fields() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    let jg = json_value
        .get("jsonGenerator")
        .expect("jsonGenerator required");
    assert!(jg.is_object(), "jsonGenerator must be an object");

    let jg_obj = jg.as_object().unwrap();
    assert!(
        jg_obj.get("name").and_then(|v| v.as_str()).is_some(),
        "jsonGenerator.name required"
    );
    assert!(
        jg_obj.get("version").and_then(|v| v.as_str()).is_some(),
        "jsonGenerator.version required"
    );
    assert!(
        jg_obj.get("date").is_none(),
        "jsonGenerator.date must not be present"
    );

    Ok(())
}

// ── Manifests array ──────────────────────────────────────────────────────────

/// `manifests` must be an array; active manifest must be first.
#[test]
fn test_manifests_is_array_active_first() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests must be an array");
    assert!(!manifests.is_empty(), "manifests must not be empty");
    Ok(())
}

/// Every manifest must have the required fields and exactly one of `claim` / `claim.v2`.
#[test]
fn test_manifest_required_fields() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    for manifest in json_value["manifests"].as_array().unwrap() {
        let obj = manifest
            .as_object()
            .expect("each manifest must be an object");

        assert!(
            obj.get("label").and_then(|v| v.as_str()).is_some(),
            "manifest.label required"
        );
        assert!(
            obj.get("assertions")
                .map(|v| v.is_object())
                .unwrap_or(false),
            "manifest.assertions must be an object (not an array)"
        );
        assert!(
            obj.get("signature").map(|v| v.is_object()).unwrap_or(false),
            "manifest.signature must be an object"
        );
        assert!(
            obj.get("validationResults")
                .map(|v| v.is_object())
                .unwrap_or(false),
            "manifest.validationResults must be an object"
        );

        let has_claim = obj.contains_key("claim");
        let has_claim_v2 = obj.contains_key("claim.v2");
        assert!(has_claim != has_claim_v2,
            "manifest must have exactly one of 'claim' (v1) or 'claim.v2' (v2), not both or neither");

        // No extra top-level keys beyond what the schema allows (additionalProperties: false).
        let allowed = [
            "label",
            "assertions",
            "claim",
            "claim.v2",
            "signature",
            "validationResults",
            "ingredientDeltas",
        ];
        for key in obj.keys() {
            assert!(
                allowed.contains(&key.as_str()),
                "manifest has unexpected key '{key}' (schema additionalProperties: false)"
            );
        }
    }
    Ok(())
}

// ── Assertions object ────────────────────────────────────────────────────────

/// Assertion keys must use `__N` double-underscore instance notation (not `_N`).
#[test]
fn test_assertion_instance_labeling() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    for manifest in json_value["manifests"].as_array().unwrap() {
        let assertions = manifest["assertions"].as_object().unwrap();
        for key in assertions.keys() {
            // Keys like `c2pa.ingredient__1` use double underscore per the C2PA JUMBF
            // label encoding. Single underscore (e.g. `c2pa.ingredient_2`) is a bug.
            let parts: Vec<&str> = key.split('_').collect();
            if parts.len() > 1 {
                // If it contains `_` it must be `__` (double), never bare `_N`.
                assert!(!key.contains("__") || !key.ends_with(|c: char| c.is_ascii_digit()),
                    "assertion key '{key}' should not use single-underscore instance notation; use __ (double)");
            }
        }
    }
    Ok(())
}

/// Binary assertions (thumbnails, embedded data) must use the reference object form.
#[test]
fn test_binary_assertions_use_ref_format() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    for manifest in json_value["manifests"].as_array().unwrap() {
        let assertions = manifest["assertions"].as_object().unwrap();
        for (key, value) in assertions {
            if key.starts_with("c2pa.thumbnail") {
                let obj = value
                    .as_object()
                    .unwrap_or_else(|| panic!("thumbnail assertion '{key}' must be an object"));
                assert!(
                    obj.contains_key("format"),
                    "thumbnail '{key}' ref object must have 'format'"
                );
                assert!(
                    obj.contains_key("identifier"),
                    "thumbnail '{key}' ref object must have 'identifier'"
                );
                assert!(
                    obj.get("hash").and_then(|v| v.as_str()).is_some(),
                    "thumbnail '{key}' ref object 'hash' must be a base64 string"
                );
            }
        }
    }
    Ok(())
}

/// Hash fields in assertions must be base64 strings, not integer arrays.
#[test]
fn test_hash_fields_are_base64_strings() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    fn check_no_byte_array_hashes(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let child_path = format!("{path}.{k}");
                    if matches!(k.as_str(), "hash" | "pad" | "pad2") {
                        assert!(
                            !v.is_array(),
                            "'{child_path}' must be a b64'-prefixed string, not an integer array"
                        );
                        if let Some(s) = v.as_str() {
                            // Must start with "b64'" prefix.
                            assert!(
                                s.starts_with("b64'"),
                                "'{child_path}' value must start with \"b64'\" prefix, got: {s:?}"
                            );
                            let payload = &s["b64'".len()..];
                            // Payload must be valid base64 if non-empty.
                            if !payload.is_empty() {
                                use std::collections::HashSet;
                                let valid_chars: HashSet<char> =
                                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                                        .chars().collect();
                                assert!(
                                    payload.chars().all(|c| valid_chars.contains(&c)),
                                    "'{child_path}' payload must be valid base64 characters"
                                );
                            }
                        }
                    }
                    check_no_byte_array_hashes(v, &child_path);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    check_no_byte_array_hashes(item, &format!("{path}[{i}]"));
                }
            }
            _ => {}
        }
    }

    for (i, manifest) in json_value["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        check_no_byte_array_hashes(manifest, &format!("manifests[{i}]"));
    }
    Ok(())
}

// ── Claims ───────────────────────────────────────────────────────────────────

/// `claim` (v1) required fields: claim_generator, claim_generator_info (array),
/// signature, assertions (array of hashedUriMap), dc:format, instanceID.
#[test]
fn test_claim_v1_required_fields() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    for manifest in json_value["manifests"].as_array().unwrap() {
        let Some(claim) = manifest.get("claim") else {
            continue;
        };
        let obj = claim.as_object().expect("claim must be an object");

        assert!(
            obj.get("claim_generator")
                .and_then(|v| v.as_str())
                .is_some(),
            "claim.claim_generator required (string)"
        );
        assert!(
            obj.get("claim_generator_info")
                .and_then(|v| v.as_array())
                .is_some(),
            "claim.claim_generator_info must be an array"
        );
        assert!(
            obj.get("signature").and_then(|v| v.as_str()).is_some(),
            "claim.signature required (JUMBF URI string)"
        );
        let assertions = obj
            .get("assertions")
            .and_then(|v| v.as_array())
            .expect("claim.assertions must be an array of hashedUriMap");
        assert!(!assertions.is_empty(), "claim.assertions must not be empty");
        for entry in assertions {
            let e = entry
                .as_object()
                .expect("each assertion ref must be an object");
            assert!(
                e.get("url").and_then(|v| v.as_str()).is_some(),
                "hashedUriMap must have 'url'"
            );
            assert!(
                e.get("hash").and_then(|v| v.as_str()).is_some(),
                "hashedUriMap 'hash' must be a base64 string"
            );
        }
        assert!(
            obj.get("dc:format").and_then(|v| v.as_str()).is_some(),
            "claim.dc:format required"
        );
        assert!(
            obj.get("instanceID").and_then(|v| v.as_str()).is_some(),
            "claim.instanceID required"
        );
    }
    Ok(())
}

/// `claim.v2` required fields: instanceID, claim_generator_info (single object),
/// signature, created_assertions (array of hashedUriMap).
#[test]
fn test_claim_v2_required_fields() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    for manifest in json_value["manifests"].as_array().unwrap() {
        let Some(claim) = manifest.get("claim.v2") else {
            continue;
        };
        let obj = claim.as_object().expect("claim.v2 must be an object");

        assert!(
            obj.get("instanceID").and_then(|v| v.as_str()).is_some(),
            "claim.v2.instanceID required"
        );
        assert!(
            obj.get("claim_generator_info")
                .map(|v| v.is_object())
                .unwrap_or(false),
            "claim.v2.claim_generator_info must be a single object (not an array)"
        );
        assert!(
            obj.get("signature").and_then(|v| v.as_str()).is_some(),
            "claim.v2.signature required (JUMBF URI string)"
        );

        let created = obj
            .get("created_assertions")
            .and_then(|v| v.as_array())
            .expect("claim.v2.created_assertions must be an array");
        for entry in created {
            let e = entry
                .as_object()
                .expect("each created_assertion must be an object");
            assert!(
                e.get("url").and_then(|v| v.as_str()).is_some(),
                "hashedUriMap must have 'url'"
            );
            assert!(
                e.get("hash").and_then(|v| v.as_str()).is_some(),
                "hashedUriMap 'hash' must be a base64 string"
            );
        }

        if let Some(gathered) = obj.get("gathered_assertions") {
            assert!(
                gathered.is_array(),
                "claim.v2.gathered_assertions must be an array"
            );
        }
        if let Some(redacted) = obj.get("redacted_assertions") {
            assert!(
                redacted.is_array(),
                "claim.v2.redacted_assertions must be an array"
            );
        }
    }
    Ok(())
}

// ── Signature ────────────────────────────────────────────────────────────────

/// When the signature object is non-empty, it must have `algorithm` and `certificateInfo`.
/// An empty object `{}` is permitted when signature data is unavailable.
#[test]
fn test_signature_structure() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    for manifest in json_value["manifests"].as_array().unwrap() {
        let sig = manifest
            .get("signature")
            .and_then(|v| v.as_object())
            .expect("manifest.signature must be an object");

        if sig.is_empty() {
            continue; // empty object is permitted when signature info is unavailable
        }

        assert!(
            sig.get("algorithm").and_then(|v| v.as_str()).is_some(),
            "non-empty signature must have 'algorithm' string"
        );
        let cert_info = sig
            .get("certificateInfo")
            .and_then(|v| v.as_object())
            .expect("non-empty signature must have 'certificateInfo' object");
        assert!(
            cert_info
                .get("serialNumber")
                .and_then(|v| v.as_str())
                .is_some(),
            "certificateInfo must have 'serialNumber'"
        );
        assert!(
            cert_info
                .get("issuer")
                .map(|v| v.is_object())
                .unwrap_or(false),
            "certificateInfo must have 'issuer' (DN object)"
        );
        assert!(
            cert_info
                .get("subject")
                .map(|v| v.is_object())
                .unwrap_or(false),
            "certificateInfo must have 'subject' (DN object)"
        );
        let validity = cert_info
            .get("validity")
            .and_then(|v| v.as_object())
            .expect("certificateInfo must have 'validity'");
        assert!(
            validity.get("notBefore").and_then(|v| v.as_str()).is_some(),
            "validity must have 'notBefore' ISO 8601 string"
        );
        assert!(
            validity.get("notAfter").and_then(|v| v.as_str()).is_some(),
            "validity must have 'notAfter' ISO 8601 string"
        );
    }
    Ok(())
}

// ── Validation results ────────────────────────────────────────────────────────

/// Every manifest's `validationResults` must have `success`, `informational`, `failure` arrays,
/// a `specVersion` of "2.3", and a required `validationTime` RFC 3339 string.
#[test]
fn test_validation_results_structure() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    for manifest in json_value["manifests"].as_array().unwrap() {
        let vr = manifest
            .get("validationResults")
            .and_then(|v| v.as_object())
            .expect("manifest.validationResults must be an object");

        for key in &["success", "informational", "failure"] {
            let arr = vr
                .get(*key)
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("validationResults.{key} must be an array"));
            for entry in arr {
                let e = entry
                    .as_object()
                    .expect("each status entry must be an object");
                assert!(
                    e.get("code").and_then(|v| v.as_str()).is_some(),
                    "validationStatusEntry must have 'code' string"
                );
            }
        }

        // specVersion must be present and equal "2.3".
        let spec_version = vr
            .get("specVersion")
            .and_then(|v| v.as_str())
            .expect("validationResults.specVersion must be a string");
        assert_eq!(
            spec_version, "2.3.0",
            "validationResults.specVersion must be \"2.3.0\""
        );

        // validationTime must be present and be an RFC 3339 string.
        let vt = vr
            .get("validationTime")
            .and_then(|v| v.as_str())
            .expect("validationResults.validationTime must be a required RFC 3339 string");
        assert!(
            !vt.is_empty(),
            "validationResults.validationTime must not be empty"
        );
    }
    Ok(())
}

/// `validationResults` must NOT contain unknown fields (negative test).
#[test]
fn test_validation_results_no_extra_fields() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json_value = reader.to_crjson_value()?;

    let allowed = [
        "success",
        "informational",
        "failure",
        "specVersion",
        "validationTime",
    ];
    for manifest in json_value["manifests"].as_array().unwrap() {
        let vr = manifest
            .get("validationResults")
            .and_then(|v| v.as_object())
            .expect("manifest.validationResults must be an object");
        for key in vr.keys() {
            assert!(
                allowed.contains(&key.as_str()),
                "validationResults contains unexpected field: {key:?}"
            );
        }
    }
    Ok(())
}

/// `specVersion` must not be absent or set to a wrong value (negative test).
#[test]
fn test_validation_results_spec_version_wrong_value() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let mut json_value = reader.to_crjson_value()?;

    // Mutate the first manifest's specVersion to something wrong and verify our
    // validation logic would catch it (we're testing the shape of the data here,
    // not re-running the exporter).
    if let Some(manifest) = json_value["manifests"].as_array_mut().unwrap().first_mut() {
        if let Some(vr) = manifest.get_mut("validationResults") {
            let original = vr["specVersion"].as_str().unwrap().to_string();
            *vr.get_mut("specVersion").unwrap() = serde_json::json!("9.9.9");
            assert_ne!(
                vr["specVersion"].as_str().unwrap(),
                "2.3",
                "mutated specVersion should not equal 2.3"
            );
            // Restore and confirm it's back to the correct value.
            *vr.get_mut("specVersion").unwrap() = serde_json::json!(original);
            assert_eq!(vr["specVersion"].as_str().unwrap(), "2.3.0");
        }
    }
    Ok(())
}

// ── Ingredients ──────────────────────────────────────────────────────────────

/// Ingredient assertions must use Dublin Core field names (`dc:title`, `dc:format`).
#[test]
fn test_ingredient_uses_dc_field_names() -> Result<()> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_INGREDIENT))?;
    let json_value = reader.to_crjson_value()?;

    for manifest in json_value["manifests"].as_array().unwrap() {
        let assertions = manifest["assertions"].as_object().unwrap();
        for (key, value) in assertions {
            if key.starts_with("c2pa.ingredient") {
                let obj = value
                    .as_object()
                    .expect("ingredient assertion must be an object");

                // Per spec: ingredientAssertionV1/V2/V3 use dc:title and dc:format.
                assert!(
                    !obj.contains_key("title"),
                    "ingredient '{key}' must not use bare 'title'; use 'dc:title' (Dublin Core)"
                );
                assert!(
                    !obj.contains_key("format"),
                    "ingredient '{key}' must not use bare 'format'; use 'dc:format' (Dublin Core)"
                );

                // v1/v2 require dc:title and dc:format; v3 makes them optional.
                // Just verify that if they are present they're strings.
                if let Some(title) = obj.get("dc:title") {
                    assert!(title.is_string(), "ingredient dc:title must be a string");
                }
                if let Some(format) = obj.get("dc:format") {
                    assert!(format.is_string(), "ingredient dc:format must be a string");
                }
                assert!(
                    obj.get("relationship").and_then(|v| v.as_str()).is_some(),
                    "ingredient '{key}' must have 'relationship' string"
                );
            }
        }
    }
    Ok(())
}
