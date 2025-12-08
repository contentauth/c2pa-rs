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

//! Tests for tracking environmental impact data (CO2, energy, water) in C2PA manifests.
//!
//! Two approaches: `cawg_metadata` (manifest-level) and `action_parameters` (per-action).
//! Uses integer units (grams, watt-hours, milliliters) to avoid floating-point issues.

use std::io::Cursor;

use c2pa::{settings::Settings, Builder, ManifestAssertionKind, Reader, Result};
use serde_json::Value;

/// Shared test image bytes
const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
const TEST_FORMAT: &str = "image/jpeg";

/// Helper function to load test settings
fn load_test_settings() -> Result<()> {
    Settings::from_toml(include_str!("fixtures/test_settings.toml"))
}

/// Helper function to sign a manifest and return a reader
fn sign_and_read(manifest_json: &str) -> Result<Reader> {
    let mut builder = Builder::from_json(manifest_json)?;
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    builder.sign(&Settings::signer()?, TEST_FORMAT, &mut source, &mut dest)?;

    dest.set_position(0);
    Reader::from_stream(TEST_FORMAT, &mut dest)
}

/// Helper to get assertion value as owned Value (clones the reference)
fn get_assertion_data(assertion: &c2pa::ManifestAssertion) -> Value {
    assertion.value().unwrap().clone()
}

/// Tests for environmental data via `cawg.metadata` assertion (manifest-level).
mod cawg_metadata {
    use super::*;

    #[test]
    fn test_complete_environmental_data() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "cawg.metadata",
                    "kind": "Json",
                    "data": {
                        "@context": { "env": "https://cawg.io/environmental/1.0/" },
                        "env:co2eq_g": 400,
                        "env:energy_wh": 8,
                        "env:water_ml": 15000
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        // Find and verify the cawg.metadata assertion
        let mut found = false;
        for assertion in reader.active_manifest().unwrap().assertions() {
            if assertion.label() == "cawg.metadata" {
                // Verify it's stored as JSON
                assert_eq!(
                    assertion.kind(),
                    &ManifestAssertionKind::Json,
                    "cawg.metadata should be JSON format"
                );

                let data = get_assertion_data(assertion);

                // Verify @context
                let context = data.get("@context").expect("@context required");
                assert_eq!(
                    context.get("env").and_then(|v| v.as_str()),
                    Some("https://cawg.io/environmental/1.0/")
                );

                // Verify all environmental fields
                assert_eq!(data.get("env:co2eq_g").and_then(|v| v.as_i64()), Some(400));
                assert_eq!(data.get("env:energy_wh").and_then(|v| v.as_i64()), Some(8));
                assert_eq!(data.get("env:water_ml").and_then(|v| v.as_i64()), Some(15000));

                found = true;
            }
        }

        assert!(found, "cawg.metadata assertion should be present");
        Ok(())
    }

    #[test]
    fn test_partial_environmental_data_co2_only() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "cawg.metadata",
                    "kind": "Json",
                    "data": {
                        "@context": { "env": "https://cawg.io/environmental/1.0/" },
                        "env:co2eq_g": 250
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        let mut found = false;
        for assertion in reader.active_manifest().unwrap().assertions() {
            if assertion.label() == "cawg.metadata" {
                let data = get_assertion_data(assertion);

                // CO2 should be present
                assert_eq!(data.get("env:co2eq_g").and_then(|v| v.as_i64()), Some(250));

                // Energy and water should be absent
                assert!(
                    data.get("env:energy_wh").is_none(),
                    "energy_wh should not be present"
                );
                assert!(
                    data.get("env:water_ml").is_none(),
                    "water_ml should not be present"
                );

                found = true;
            }
        }

        assert!(found, "cawg.metadata assertion should be present");
        Ok(())
    }

    #[test]
    fn test_zero_environmental_values() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "cawg.metadata",
                    "kind": "Json",
                    "data": {
                        "@context": { "env": "https://cawg.io/environmental/1.0/" },
                        "env:co2eq_g": 0,
                        "env:energy_wh": 0,
                        "env:water_ml": 0
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        let mut found = false;
        for assertion in reader.active_manifest().unwrap().assertions() {
            if assertion.label() == "cawg.metadata" {
                let data = get_assertion_data(assertion);

                // All values should be 0
                assert_eq!(data.get("env:co2eq_g").and_then(|v| v.as_i64()), Some(0));
                assert_eq!(data.get("env:energy_wh").and_then(|v| v.as_i64()), Some(0));
                assert_eq!(data.get("env:water_ml").and_then(|v| v.as_i64()), Some(0));

                found = true;
            }
        }

        assert!(found, "cawg.metadata assertion should be present");
        Ok(())
    }

    #[test]
    fn test_large_environmental_values() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "cawg.metadata",
                    "kind": "Json",
                    "data": {
                        "@context": { "env": "https://cawg.io/environmental/1.0/" },
                        "env:co2eq_g": 1000000,
                        "env:energy_wh": 10000000,
                        "env:water_ml": 1000000000
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        let mut found = false;
        for assertion in reader.active_manifest().unwrap().assertions() {
            if assertion.label() == "cawg.metadata" {
                let data = get_assertion_data(assertion);

                assert_eq!(
                    data.get("env:co2eq_g").and_then(|v| v.as_i64()),
                    Some(1_000_000)
                );
                assert_eq!(
                    data.get("env:energy_wh").and_then(|v| v.as_i64()),
                    Some(10_000_000)
                );
                assert_eq!(
                    data.get("env:water_ml").and_then(|v| v.as_i64()),
                    Some(1_000_000_000)
                );

                found = true;
            }
        }

        assert!(found, "cawg.metadata assertion should be present");
        Ok(())
    }
}

/// Tests for environmental data via action parameters (per-action tracking).
mod action_parameters {
    use super::*;

    #[test]
    fn test_single_action_environmental_data() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.opened",
                                "parameters": {
                                    "env:co2eq_g": 100,
                                    "env:energy_wh": 2,
                                    "env:water_ml": 5000
                                }
                            }
                        ]
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        let mut found = false;
        for assertion in reader.active_manifest().unwrap().assertions() {
            if assertion.label().starts_with("c2pa.actions") {
                let data = get_assertion_data(assertion);
                let actions = data.get("actions").and_then(|a| a.as_array()).unwrap();

                assert_eq!(actions.len(), 1);

                let action = &actions[0];
                assert_eq!(
                    action.get("action").and_then(|v| v.as_str()),
                    Some("c2pa.opened")
                );

                let params = action.get("parameters").unwrap();
                assert_eq!(params.get("env:co2eq_g").and_then(|v| v.as_i64()), Some(100));
                assert_eq!(params.get("env:energy_wh").and_then(|v| v.as_i64()), Some(2));
                assert_eq!(params.get("env:water_ml").and_then(|v| v.as_i64()), Some(5000));

                found = true;
            }
        }

        assert!(found, "c2pa.actions assertion should be present");
        Ok(())
    }

    #[test]
    fn test_multiple_actions_environmental_data() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.opened",
                                "parameters": {
                                    "env:co2eq_g": 50,
                                    "env:energy_wh": 1
                                }
                            },
                            {
                                "action": "c2pa.edited",
                                "parameters": {
                                    "description": "Applied AI filter",
                                    "env:co2eq_g": 200,
                                    "env:energy_wh": 5
                                }
                            },
                            {
                                "action": "c2pa.published",
                                "parameters": {
                                    "env:co2eq_g": 50,
                                    "env:energy_wh": 1
                                }
                            }
                        ]
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        let mut found = false;
        for assertion in reader.active_manifest().unwrap().assertions() {
            if assertion.label().starts_with("c2pa.actions") {
                let data = get_assertion_data(assertion);
                let actions = data.get("actions").and_then(|a| a.as_array()).unwrap();

                assert_eq!(actions.len(), 3, "Should have 3 actions");

                // Verify each action has its expected CO2 value
                let co2_values: Vec<i64> = actions
                    .iter()
                    .filter_map(|a| {
                        a.get("parameters")
                            .and_then(|p| p.get("env:co2eq_g"))
                            .and_then(|v| v.as_i64())
                    })
                    .collect();

                assert_eq!(co2_values, vec![50, 200, 50]);

                found = true;
            }
        }

        assert!(found, "c2pa.actions assertion should be present");
        Ok(())
    }

    #[test]
    fn test_environmental_data_aggregation() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.opened",
                                "parameters": { "env:co2eq_g": 100 }
                            },
                            {
                                "action": "c2pa.edited",
                                "parameters": { "env:co2eq_g": 300 }
                            }
                        ]
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        let mut found = false;
        for assertion in reader.active_manifest().unwrap().assertions() {
            if assertion.label().starts_with("c2pa.actions") {
                let data = get_assertion_data(assertion);
                let actions = data.get("actions").and_then(|a| a.as_array()).unwrap();

                // Calculate total CO2 across all actions
                let total_co2: i64 = actions
                    .iter()
                    .filter_map(|a| {
                        a.get("parameters")
                            .and_then(|p| p.get("env:co2eq_g"))
                            .and_then(|v| v.as_i64())
                    })
                    .sum();

                assert_eq!(total_co2, 400, "Total CO2 should be 100 + 300 = 400g");

                found = true;
            }
        }

        assert!(found, "c2pa.actions assertion should be present");
        Ok(())
    }

    #[test]
    fn test_mixed_parameters_with_environmental_data() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.edited",
                                "softwareAgent": {
                                    "name": "AI Enhancement Tool",
                                    "version": "1.0"
                                },
                                "parameters": {
                                    "env:co2eq_g": 500,
                                    "env:energy_wh": 12,
                                    "env:water_ml": 20000
                                }
                            }
                        ]
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        let mut found = false;
        for assertion in reader.active_manifest().unwrap().assertions() {
            if assertion.label().starts_with("c2pa.actions") {
                let data = get_assertion_data(assertion);
                let actions = data.get("actions").and_then(|a| a.as_array()).unwrap();

                // Find our c2pa.edited action (there may be other actions from the source image)
                let edited_action = actions
                    .iter()
                    .find(|a| a.get("action").and_then(|v| v.as_str()) == Some("c2pa.edited"));

                assert!(edited_action.is_some(), "c2pa.edited action should exist");
                let action = edited_action.unwrap();

                // Verify softwareAgent is preserved
                let software_agent = action.get("softwareAgent").unwrap();
                assert_eq!(
                    software_agent.get("name").and_then(|v| v.as_str()),
                    Some("AI Enhancement Tool")
                );

                // Verify environmental parameters are preserved
                let params = action.get("parameters").unwrap();
                assert_eq!(params.get("env:co2eq_g").and_then(|v| v.as_i64()), Some(500));
                assert_eq!(params.get("env:energy_wh").and_then(|v| v.as_i64()), Some(12));
                assert_eq!(
                    params.get("env:water_ml").and_then(|v| v.as_i64()),
                    Some(20000)
                );

                found = true;
            }
        }

        assert!(found, "c2pa.actions assertion should be present");
        Ok(())
    }
}

/// Tests for combined approach: cawg.metadata (summary) + action parameters (breakdown).
mod combined {
    use super::*;

    #[test]
    fn test_combined_environmental_tracking() -> Result<()> {
        load_test_settings()?;

        let manifest_json = r#"
        {
            "assertions": [
                {
                    "label": "cawg.metadata",
                    "kind": "Json",
                    "data": {
                        "@context": { "env": "https://cawg.io/environmental/1.0/" },
                        "env:co2eq_g": 400,
                        "env:energy_wh": 8,
                        "env:water_ml": 15000,
                        "env:note": "Total environmental impact for this asset"
                    }
                },
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.opened",
                                "parameters": {
                                    "env:co2eq_g": 100,
                                    "env:energy_wh": 2,
                                    "env:water_ml": 5000
                                }
                            },
                            {
                                "action": "c2pa.edited",
                                "parameters": {
                                    "description": "AI enhancement",
                                    "env:co2eq_g": 300,
                                    "env:energy_wh": 6,
                                    "env:water_ml": 10000
                                }
                            }
                        ]
                    }
                }
            ]
        }
        "#;

        let reader = sign_and_read(manifest_json)?;

        let mut found_cawg = false;
        let mut found_actions = false;
        let mut summary_co2: i64 = 0;
        let mut actions_co2_total: i64 = 0;

        for assertion in reader.active_manifest().unwrap().assertions() {
            match assertion.label() {
                "cawg.metadata" => {
                    let data = get_assertion_data(assertion);
                    summary_co2 = data.get("env:co2eq_g").and_then(|v| v.as_i64()).unwrap_or(0);
                    found_cawg = true;
                }
                label if label.starts_with("c2pa.actions") => {
                    let data = get_assertion_data(assertion);
                    let actions = data.get("actions").and_then(|a| a.as_array()).unwrap();

                    actions_co2_total = actions
                        .iter()
                        .filter_map(|a| {
                            a.get("parameters")
                                .and_then(|p| p.get("env:co2eq_g"))
                                .and_then(|v| v.as_i64())
                        })
                        .sum();

                    found_actions = true;
                }
                _ => {}
            }
        }

        assert!(found_cawg, "cawg.metadata should be present");
        assert!(found_actions, "c2pa.actions should be present");

        // Verify summary matches sum of actions
        assert_eq!(
            summary_co2, actions_co2_total,
            "Summary CO2 ({}) should match sum of action CO2 ({})",
            summary_co2, actions_co2_total
        );

        Ok(())
    }
}

