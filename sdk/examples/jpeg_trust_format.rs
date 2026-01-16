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

//! Example showing how to use JpegTrustReader to export C2PA manifests
//! in JPEG Trust format.

#[cfg(feature = "file_io")]
use c2pa::{JpegTrustReader, Result};

#[cfg(feature = "file_io")]
fn main() -> Result<()> {
        // Create a JpegTrustReader from a file
        let mut reader = JpegTrustReader::from_file("tests/fixtures/CA.jpg")?;

        // Compute the asset hash to include asset_info in the output
        println!("Computing asset hash...");
        let hash = reader.compute_asset_hash_from_file("tests/fixtures/CA.jpg")?;
        println!("Asset hash: {}\n", hash);

        // Get the JPEG Trust format JSON
        let jpeg_trust_json = reader.json();
        
        println!("JPEG Trust Format Output:");
        println!("{}", jpeg_trust_json);

        // You can also get the JSON as a Value for programmatic access
        let json_value = reader.to_json_value()?;
        
        // Access specific parts
        if let Some(manifests) = json_value.get("manifests").and_then(|m| m.as_array()) {
            println!("\nFound {} manifest(s)", manifests.len());
            
            for (i, manifest) in manifests.iter().enumerate() {
                println!("\nManifest {}:", i + 1);
                
                // Get the label
                if let Some(label) = manifest.get("label").and_then(|l| l.as_str()) {
                    println!("  Label: {}", label);
                }
                
                // Check claim.v2 data
                if let Some(claim_v2) = manifest.get("claim.v2") {
                    if let Some(title) = claim_v2.get("dc:title").and_then(|t| t.as_str()) {
                        println!("  Title: {}", title);
                    }
                    if let Some(instance_id) = claim_v2.get("instanceID").and_then(|i| i.as_str()) {
                        println!("  Instance ID: {}", instance_id);
                    }
                }
                
                // Check assertions (now in object format, not array)
                if let Some(assertions) = manifest.get("assertions").and_then(|a| a.as_object()) {
                    println!("  Assertions: {} found", assertions.len());
                    for (label, _value) in assertions.iter() {
                        println!("    - {}", label);
                    }
                }
                
                // Check validation status
                if let Some(status) = manifest.get("status") {
                    if let Some(signature) = status.get("signature").and_then(|s| s.as_str()) {
                        println!("  Signature Status: {}", signature);
                    }
                    if let Some(trust) = status.get("trust").and_then(|t| t.as_str()) {
                        println!("  Trust Status: {}", trust);
                    }
                }
            }
        }
        
        // Access overall validation status
        if let Some(validation) = json_value.get("extras:validation_status") {
            if let Some(is_valid) = validation.get("isValid").and_then(|v| v.as_bool()) {
                println!("\nOverall Validation: {}", if is_valid { "VALID" } else { "INVALID" });
            }
        }

        // You can also access the underlying Reader if needed for additional operations
        let inner_reader = reader.inner();
        println!("\nValidation State: {:?}", inner_reader.validation_state());
    
    Ok(())
}

#[cfg(not(feature = "file_io"))]
fn main() {
    println!("This example requires the 'file_io' feature to be enabled.");
    println!("Run with: cargo run --example jpeg_trust_format --features file_io");
}

