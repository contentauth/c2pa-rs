// Copyright 2025 Adobe. All rights reserved.
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

use std::convert::TryInto;

use c2pa::{Error, Reader};
use serde_json::{Map, Value};
use tokio::runtime::Runtime;

use crate::decorators::cawg_decorator::{
    decorate_cawg_assertion_from_detailed_report, decorate_json_cawg_assertions,
};

/// Update/decorate the displayed JSON assertions for a more human-readable JSON output.
fn decorate_json_assertions(
    reader: &Reader,
    json_content: &mut Value,
    tokio_runtime: &Runtime,
) -> Result<(), Error> {
    if let Value::Object(map) = json_content {
        // Iterate over the key-value pairs
        for (key, value) in &mut *map {
            // Get additional CAWG details
            let current_manifest = reader.get_manifest(key);
            let current_manifest = match current_manifest {
                Some(current_manifest) => current_manifest,
                None => {
                    return Err(crate::Error::JsonSerializationError(
                        "Could not get current manifest".to_string(),
                    ));
                }
            };

            // Get the assertions as array from the JSON
            let assertions = match value.get_mut("assertions") {
                Some(assertions) => assertions,
                None => {
                    return Err(crate::Error::JsonSerializationError(
                        "Could not parse JSON assertions as object".to_string(),
                    ));
                }
            };
            let assertions_array = match assertions.as_array_mut() {
                Some(assertions_array) => assertions_array,
                None => {
                    return Err(crate::Error::JsonSerializationError(
                        "Could not parse JSON assertions as array".to_string(),
                    ));
                }
            };

            // Loop over the assertions to process those of interest
            for assertion in assertions_array {
                let label = match assertion.get("label") {
                    Some(label) => label.to_string(),
                    None => {
                        return Err(crate::Error::JsonSerializationError(
                            "Could not parse assertion label".to_string(),
                        ));
                    }
                };

                // for CAWG assertions, further parse the signature
                if label.contains("cawg.identity") {
                    decorate_json_cawg_assertions(current_manifest, assertion, tokio_runtime)?;
                }
            }
        }
    }

    Ok(())
}

/// Update/decorate the detailed displayed JSON string for a more human-readable JSON output.
pub(crate) fn decorate_json_detailed_display(
    reader: &Reader,
    tokio_runtime: &Runtime,
) -> Result<String, Error> {
    let json_report = reader.json_report();
    let extracted_report = match json_report {
        Ok(extracted_json_report) => extracted_json_report,
        Err(err) => {
            let message = format!("Could not parse JSON report: {:?}", err);
            return Err(crate::Error::JsonSerializationError(message));
        }
    };

    let mut report_json_map: Map<String, Value> = match serde_json::from_str(&extracted_report) {
        Ok(report_json_map) => report_json_map,
        Err(err) => {
            let message = format!("Could not parse extracted JSON detailed report: {:?}", err);
            return Err(crate::Error::JsonSerializationError(message));
        }
    };

    let manifests = match report_json_map.get_mut("manifests") {
        Some(manifests) => manifests,
        None => {
            return Err(crate::Error::JsonSerializationError(
                "No parsable JSON in manifest store (key: manifests)".to_string(),
            ));
        }
    };

    // Update assertion with more details (eg. for CAWG)
    match decorate_cawg_assertion_from_detailed_report(reader, manifests, tokio_runtime) {
        Ok(_) => (),
        Err(err) => {
            let message = format!("Could not decorate detailed JSON for display: {:?}", err);
            return Err(crate::Error::JsonSerializationError(message));
        }
    };

    // return decorated detailed JSON to display
    match serde_json::to_string_pretty(&report_json_map) {
        Ok(decorated_result) => Ok(decorated_result),
        Err(err) => {
            let message = format!(
                "Could not decorate displayed detailed JSON with additional details: {:?}",
                err
            );
            Err(crate::Error::JsonSerializationError(message))
        }
    }
}

/// Update/decorate the displayed JSON string for a more human-readable JSON output.
pub(crate) fn decorate_json_display(
    reader: &Reader,
    tokio_runtime: &Runtime,
) -> Result<String, Error> {
    let mut reader_content: serde_json::Map<String, serde_json::Value> = match reader.try_into() {
        Ok(mapped_json) => mapped_json,
        Err(_) => {
            return Err(crate::Error::JsonSerializationError(
                "Could not parse manifest store JSON content".to_string(),
            ));
        }
    };

    let manifests_json_content = match reader_content.get_mut("manifests") {
        Some(json) => json,
        None => {
            return Err(crate::Error::JsonSerializationError(
                "No JSON to parse in manifest store (key: manifests)".to_string(),
            ));
        }
    };

    // Update assertion with more details (eg. for CAWG)
    match decorate_json_assertions(reader, manifests_json_content, tokio_runtime) {
        Ok(_) => (),
        Err(err) => {
            let message = format!(
                "Could not decorate displayed JSON with additional details: {:?}",
                err
            );
            return Err(crate::Error::JsonSerializationError(message));
        }
    };

    // return decorated JSON to display
    match serde_json::to_string_pretty(&reader_content) {
        Ok(decorated_result) => Ok(decorated_result),
        Err(err) => {
            let message = format!(
                "Could not decorate displayed JSON with additional details: {:?}",
                err
            );
            Err(crate::Error::JsonSerializationError(message))
        }
    }
}
