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

//! Integration tests for JpegTrustReader asset hash functionality

use c2pa::{JpegTrustReader, Result};
use std::io::Cursor;

const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("fixtures/CA.jpg");

#[test]
fn test_asset_hash_in_json_output() -> Result<()> {
    // Create reader and compute hash
    let mut reader = JpegTrustReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    
    // Initially no asset_info in output
    let json_without_hash = reader.json();
    assert!(!json_without_hash.contains("asset_info"));
    
    // Compute hash
    let mut stream = Cursor::new(IMAGE_WITH_MANIFEST);
    let computed_hash = reader.compute_asset_hash(&mut stream)?;
    
    // Now asset_info should be present
    let json_with_hash = reader.json();
    assert!(json_with_hash.contains("asset_info"));
    assert!(json_with_hash.contains(&computed_hash));
    assert!(json_with_hash.contains("\"alg\": \"sha256\""));
    
    Ok(())
}

#[test]
fn test_multiple_hash_computations() -> Result<()> {
    // Test that computing hash multiple times gives consistent results
    let mut reader = JpegTrustReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    
    // First computation
    let mut stream1 = Cursor::new(IMAGE_WITH_MANIFEST);
    let hash1 = reader.compute_asset_hash(&mut stream1)?;
    
    // Second computation (should overwrite)
    let mut stream2 = Cursor::new(IMAGE_WITH_MANIFEST);
    let hash2 = reader.compute_asset_hash(&mut stream2)?;
    
    // Hashes should be identical
    assert_eq!(hash1, hash2);
    
    // JSON should contain the hash
    let json = reader.json();
    assert!(json.contains(&hash2));
    
    Ok(())
}

#[test]
fn test_set_hash_directly() -> Result<()> {
    let mut reader = JpegTrustReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    
    // Set a custom hash
    let custom_hash = "AAABBBCCCDDDEEEFFF111222333444555666777888999===";
    reader.set_asset_hash("sha512", custom_hash);
    
    // Verify it appears in JSON with correct algorithm
    let json = reader.json();
    assert!(json.contains(custom_hash));
    assert!(json.contains("\"alg\": \"sha512\""));
    
    Ok(())
}

#[test]
fn test_accessor_methods() -> Result<()> {
    let mut reader = JpegTrustReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    
    // Initially None
    assert!(reader.asset_hash().is_none());
    
    // Set hash
    reader.set_asset_hash("sha256", "test_hash_value");
    
    // Should be accessible
    let (alg, hash) = reader.asset_hash().expect("Hash should be set");
    assert_eq!(alg, "sha256");
    assert_eq!(hash, "test_hash_value");
    
    Ok(())
}

#[test]
#[cfg(feature = "file_io")]
fn test_compute_from_file() -> Result<()> {
    let mut reader = JpegTrustReader::from_file("tests/fixtures/CA.jpg")?;
    
    // Compute hash from file
    let hash = reader.compute_asset_hash_from_file("tests/fixtures/CA.jpg")?;
    
    // Verify it's not empty
    assert!(!hash.is_empty());
    
    // Verify it's accessible
    assert!(reader.asset_hash().is_some());
    
    // Verify JSON includes it
    let json = reader.json();
    assert!(json.contains("asset_info"));
    assert!(json.contains(&hash));
    
    Ok(())
}

#[test]
#[cfg(feature = "file_io")]
fn test_different_files_different_hashes() -> Result<()> {
    // Read two different files
    let mut reader1 = JpegTrustReader::from_file("tests/fixtures/CA.jpg")?;
    let hash1 = reader1.compute_asset_hash_from_file("tests/fixtures/CA.jpg")?;
    
    let mut reader2 = JpegTrustReader::from_file("tests/fixtures/C.jpg")?;
    let hash2 = reader2.compute_asset_hash_from_file("tests/fixtures/C.jpg")?;
    
    // Different files should have different hashes
    assert_ne!(hash1, hash2);
    
    Ok(())
}

#[test]
fn test_hash_persistence_across_json_calls() -> Result<()> {
    let mut reader = JpegTrustReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    
    // Compute hash once
    let mut stream = Cursor::new(IMAGE_WITH_MANIFEST);
    let hash = reader.compute_asset_hash(&mut stream)?;
    
    // Get JSON multiple times
    let json1 = reader.json();
    let json2 = reader.json();
    
    // Both should contain the hash
    assert!(json1.contains(&hash));
    assert!(json2.contains(&hash));
    assert_eq!(json1, json2);
    
    Ok(())
}

#[test]
fn test_hash_format_is_base64() -> Result<()> {
    let mut reader = JpegTrustReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    
    let mut stream = Cursor::new(IMAGE_WITH_MANIFEST);
    let hash = reader.compute_asset_hash(&mut stream)?;
    
    // Base64 should only contain valid characters
    let is_valid_base64 = hash.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
    });
    
    assert!(is_valid_base64, "Hash should be valid base64: {}", hash);
    
    Ok(())
}

#[test]
fn test_complete_jpeg_trust_format_with_asset_info() -> Result<()> {
    let mut reader = JpegTrustReader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
    
    // Compute hash
    let mut stream = Cursor::new(IMAGE_WITH_MANIFEST);
    reader.compute_asset_hash(&mut stream)?;
    
    // Get JSON value
    let json_value = reader.to_json_value()?;
    
    // Verify complete structure
    assert!(json_value.get("@context").is_some());
    assert!(json_value.get("asset_info").is_some());
    assert!(json_value.get("manifests").is_some());
    assert!(json_value.get("content").is_some());
    
    // Verify asset_info structure
    let asset_info = json_value["asset_info"].as_object().expect("asset_info should be an object");
    assert!(asset_info.contains_key("alg"));
    assert!(asset_info.contains_key("hash"));
    assert_eq!(asset_info["alg"], "sha256");
    
    // Verify hash is a non-empty string
    let hash = asset_info["hash"].as_str().expect("hash should be a string");
    assert!(!hash.is_empty());
    
    Ok(())
}

