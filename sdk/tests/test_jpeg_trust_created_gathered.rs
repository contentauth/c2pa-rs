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

//! Tests for JPEG Trust format created_assertions vs gathered_assertions

use std::io::Cursor;

use c2pa::{Builder, Context, JpegTrustReader, Result, Settings};

const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
const TEST_SETTINGS: &str = include_str!("../tests/fixtures/test_settings.toml");

#[test]
fn test_created_and_gathered_assertions_separated() -> Result<()> {
    use serde_json::json;

    let settings = Settings::new().with_toml(TEST_SETTINGS)?;
    let context = Context::new().with_settings(settings)?.into_shared();

    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    // Create a manifest with both created and gathered assertions
    let definition = json!(
    {
        "assertions": [
        {
            "label": "org.test.gathered",
            "data": {
                "value": "gathered assertion"
            }
        },
        {
            "label": "org.test.created",
            "kind": "Json",
            "data": {
                "value": "created assertion"
            },
            "created": true
        }]
    }
    )
    .to_string();

    let mut builder = Builder::from_shared_context(&context).with_definition(&definition)?;

    // Add another regular assertion (should default to gathered)
    builder.add_assertion("org.test.regular", &json!({"value": "regular assertion"}))?;

    let mut dest = Cursor::new(Vec::new());
    builder.sign(context.signer()?, format, &mut source, &mut dest)?;

    // Now read it with JpegTrustReader
    dest.set_position(0);
    let reader = JpegTrustReader::from_stream(format, dest)?;
    let json_value = reader.to_json_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    // We need to find the manifest with our test assertions (the newly created one)
    // This is the most recent manifest with claim version 2 (which has created_assertions/gathered_assertions)
    let active_manifest = manifests
        .iter()
        .filter(|m| {
            // Filter for claim v2 manifests (which have non-empty created_assertions or gathered_assertions)
            if let Some(claim_v2) = m.get("claim.v2") {
                if let Some(created) = claim_v2.get("created_assertions") {
                    if let Some(arr) = created.as_array() {
                        return !arr.is_empty();
                    }
                }
                if let Some(gathered) = claim_v2.get("gathered_assertions") {
                    if let Some(arr) = gathered.as_array() {
                        return !arr.is_empty();
                    }
                }
            }
            false
        })
        .last()
        .expect("should have at least one claim v2 manifest");

    // Print the label for debugging
    println!("Manifest label: {:?}", active_manifest.get("label"));
    println!("Claim version: {:?}", active_manifest.get("claim.v2"));
    println!("Total manifests: {}", manifests.len());

    // Check claim.v2 for created_assertions and gathered_assertions
    let claim_v2 = active_manifest["claim.v2"]
        .as_object()
        .expect("claim.v2 should exist");

    let created_assertions = claim_v2["created_assertions"]
        .as_array()
        .expect("created_assertions should be array");

    let gathered_assertions = claim_v2["gathered_assertions"]
        .as_array()
        .expect("gathered_assertions should be array");

    // Print for debugging
    println!("Created assertions count: {}", created_assertions.len());
    println!("Gathered assertions count: {}", gathered_assertions.len());
    
    for (i, assertion) in created_assertions.iter().enumerate() {
        println!("Created[{}]: {}", i, assertion.get("url").unwrap());
    }
    
    for (i, assertion) in gathered_assertions.iter().enumerate() {
        println!("Gathered[{}]: {}", i, assertion.get("url").unwrap());
    }

    // Verify that gathered_assertions is not empty
    assert!(
        !gathered_assertions.is_empty(),
        "gathered_assertions should not be empty, but got {} gathered vs {} created",
        gathered_assertions.len(),
        created_assertions.len()
    );

    // Find the created assertion - should be in created_assertions
    let has_created_ref = created_assertions.iter().any(|assertion_ref| {
        if let Some(url) = assertion_ref.get("url") {
            url.as_str()
                .map(|s| s.contains("org.test.created"))
                .unwrap_or(false)
        } else {
            false
        }
    });

    assert!(
        has_created_ref,
        "created_assertions should reference org.test.created"
    );

    // Find the gathered assertion - should be in gathered_assertions
    let has_gathered_ref = gathered_assertions.iter().any(|assertion_ref| {
        if let Some(url) = assertion_ref.get("url") {
            url.as_str()
                .map(|s| s.contains("org.test.gathered"))
                .unwrap_or(false)
        } else {
            false
        }
    });

    assert!(
        has_gathered_ref,
        "gathered_assertions should reference org.test.gathered"
    );

    // Verify the regular assertion is in gathered_assertions (default behavior)
    let has_regular_ref = gathered_assertions.iter().any(|assertion_ref| {
        if let Some(url) = assertion_ref.get("url") {
            url.as_str()
                .map(|s| s.contains("org.test.regular"))
                .unwrap_or(false)
        } else {
            false
        }
    });

    assert!(
        has_regular_ref,
        "gathered_assertions should reference org.test.regular (default)"
    );

    // Verify all assertion references have proper hash format
    for assertion_ref in created_assertions.iter().chain(gathered_assertions.iter()) {
        assert!(
            assertion_ref.get("url").is_some(),
            "All assertion refs should have url"
        );
        assert!(
            assertion_ref.get("hash").is_some(),
            "All assertion refs should have hash"
        );
        
        let hash = assertion_ref.get("hash").unwrap();
        assert!(
            hash.is_string(),
            "Hash should be a string (base64), not an array"
        );
    }

    Ok(())
}

#[test]
fn test_hash_assertions_in_created() -> Result<()> {
    use serde_json::json;

    let settings = Settings::new().with_toml(TEST_SETTINGS)?;
    let context = Context::new().with_settings(settings)?.into_shared();

    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    // Create a simple manifest
    let definition = json!(
    {
        "assertions": [
        {
            "label": "org.test.simple",
            "data": {
                "value": "test"
            }
        }]
    }
    )
    .to_string();

    let mut builder = Builder::from_shared_context(&context).with_definition(&definition)?;

    let mut dest = Cursor::new(Vec::new());
    builder.sign(context.signer()?, format, &mut source, &mut dest)?;

    // Now read it with JpegTrustReader
    dest.set_position(0);
    let reader = JpegTrustReader::from_stream(format, dest)?;
    let json_value = reader.to_json_value()?;

    // Get manifests array
    let manifests = json_value["manifests"]
        .as_array()
        .expect("manifests should be array");

    // Find the manifest with our test assertions (the newly created one with claim v2)
    let active_manifest = manifests
        .iter()
        .filter(|m| {
            // Filter for claim v2 manifests with non-empty created_assertions
            if let Some(claim_v2) = m.get("claim.v2") {
                if let Some(created) = claim_v2.get("created_assertions") {
                    if let Some(arr) = created.as_array() {
                        return !arr.is_empty();
                    }
                }
            }
            false
        })
        .last()
        .expect("should have at least one claim v2 manifest");

    // Check claim.v2
    let claim_v2 = active_manifest["claim.v2"]
        .as_object()
        .expect("claim.v2 should exist");

    let created_assertions = claim_v2["created_assertions"]
        .as_array()
        .expect("created_assertions should be array");

    // Hash assertions (c2pa.hash.data, etc.) should be in created_assertions
    let has_hash_assertion = created_assertions.iter().any(|assertion_ref| {
        if let Some(url) = assertion_ref.get("url") {
            url.as_str()
                .map(|s| s.contains("c2pa.hash"))
                .unwrap_or(false)
        } else {
            false
        }
    });

    assert!(
        has_hash_assertion,
        "created_assertions should include hash assertions (c2pa.hash.*)"
    );

    Ok(())
}

