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

use std::io::Cursor;

use c2pa::{Reader, Result};

const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../fixtures/C.jpg");

/// Load a fixture and return the crJSON value for the first manifest's assertions object.
fn first_assertions() -> Result<serde_json::Value> {
    let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let json = reader.to_crjson_value()?;
    let manifest = json["manifests"][0].clone();
    Ok(manifest["assertions"].clone())
}

/// Verify that `c2pa.hash.data` is present, has a base64 `hash` string, a valid `alg`, and a
/// base64 (or empty-string) `pad` field. This single test replaces three formerly-separate tests
/// that each extracted the same assertion independently.
#[test]
fn test_hash_data_assertion_structure() -> Result<()> {
    let assertions = first_assertions()?;
    let obj = assertions
        .get("c2pa.hash.data")
        .and_then(|v| v.as_object())
        .expect("c2pa.hash.data must be present and be an object");

    let hash = obj
        .get("hash")
        .and_then(|v| v.as_str())
        .expect("c2pa.hash.data.hash must be a b64'-prefixed string");
    assert!(
        hash.starts_with("b64'"),
        "c2pa.hash.data.hash must start with \"b64'\" prefix, got: {hash:?}"
    );
    assert!(
        hash.len() > "b64'".len(),
        "c2pa.hash.data.hash payload must not be empty"
    );

    let alg = obj
        .get("alg")
        .and_then(|v| v.as_str())
        .expect("c2pa.hash.data.alg must be a string");
    assert!(
        matches!(alg, "sha256" | "sha384" | "sha512"),
        "c2pa.hash.data.alg must be a standard algorithm, got: {alg}"
    );

    if let Some(pad) = obj.get("pad") {
        let pad_str = pad.as_str().unwrap_or_else(|| {
            panic!("c2pa.hash.data.pad must be a b64'-prefixed string, not {pad:?}")
        });
        assert!(
            pad_str.starts_with("b64'"),
            "c2pa.hash.data.pad must start with \"b64'\" prefix, got: {pad_str:?}"
        );
    }

    Ok(())
}

/// `c2pa.hash.data` must appear in crJSON even though the standard `Reader` serialization
/// filters it out. This test verifies both sides of that contract.
#[test]
fn test_hash_data_not_filtered() -> Result<()> {
    let assertions = first_assertions()?;
    assert!(
        assertions.get("c2pa.hash.data").is_some(),
        "c2pa.hash.data must be included in crJSON output"
    );

    // Confirm it is absent from the standard Manifest JSON format.
    let standard_reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    let standard_json = serde_json::to_value(standard_reader)?;
    let standard_assertions = standard_json["manifests"]
        .as_object()
        .and_then(|m| m.values().next())
        .and_then(|m| m["assertions"].as_array())
        .expect("standard manifests.*.assertions must be an array");

    assert!(
        !standard_assertions
            .iter()
            .any(|a| a.get("label").and_then(|l| l.as_str()) == Some("c2pa.hash.data")),
        "c2pa.hash.data must be filtered out in standard Reader serialization"
    );

    Ok(())
}

/// Hash assertion keys must follow the known versioning pattern
/// (`c2pa.hash.data`, `c2pa.hash.bmff`, `c2pa.hash.boxes`, or those with a `.vN` suffix).
#[test]
fn test_hash_assertion_versioning() -> Result<()> {
    let assertions = first_assertions()?;
    for key in assertions
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| k.starts_with("c2pa.hash."))
    {
        // Strip any `__N` instance suffix to get the base label.
        let base = key.split("__").next().unwrap_or(key);
        let valid = matches!(
            base,
            "c2pa.hash.data" | "c2pa.hash.bmff" | "c2pa.hash.boxes" | "c2pa.hash.collection.data"
        ) || base.starts_with("c2pa.hash.data.v")
            || base.starts_with("c2pa.hash.bmff.v")
            || base.starts_with("c2pa.hash.boxes.v")
            || base.starts_with("c2pa.hash.collection.data.v");

        assert!(
            valid,
            "hash assertion key '{key}' does not follow the known versioning pattern"
        );
    }
    Ok(())
}

/// When a `c2pa.actions` assertion contains an ingredient with a `hash` field, that hash must be
/// a base64 string, not a byte array. (Migrated from the now-deleted hash_encoding.rs.)
#[test]
fn test_action_ingredient_hash_is_base64() -> Result<()> {
    let assertions = first_assertions()?;
    let actions_val = assertions
        .get("c2pa.actions.v2")
        .or_else(|| assertions.get("c2pa.actions"));
    let Some(actions_arr) = actions_val.and_then(|a| a["actions"].as_array()) else {
        return Ok(()); // fixture has no actions assertion; nothing to check
    };

    for (i, action) in actions_arr.iter().enumerate() {
        if let Some(hash) = action
            .get("parameters")
            .and_then(|p| p.get("ingredient"))
            .and_then(|ing| ing.get("hash"))
        {
            let hash_str = hash.as_str().unwrap_or_else(|| {
                panic!("action[{i}] ingredient hash must be a b64'-prefixed string, not an array")
            });
            assert!(
                hash_str.starts_with("b64'"),
                "action[{i}] ingredient hash must start with \"b64'\" prefix, got: {hash_str:?}"
            );
        }
    }
    Ok(())
}
