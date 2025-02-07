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

use c2pa::Reader;
use cawg_identity::{claim_aggregation::IcaSignatureVerifier, IdentityAssertion};
use serde_json::{Map, Value};
use tokio::runtime::Runtime;

/// Update/decorate the displayed JSON assertions for a more human-readable JSON output.
pub(crate) fn decorate_cawg_assertion_from_detailed_report(
    reader: &Reader,
    json_content: &mut Value,
    tokio_runtime: &Runtime,
) -> Result<(), anyhow::Error> {
    if let Value::Object(map) = json_content {
        // Iterate over the key-value pairs
        for (key, value) in &mut *map {
            // Get additional CAWG details

            // Get the assertions as array from the JSON
            let assertions = match value.get_mut("assertion_store") {
                Some(assertions) => assertions,
                None => {
                    return Err(anyhow::Error::msg(
                        "Could not parse JSON assertions as object",
                    ));
                }
            };

            let cawg_assertion = match assertions.get_mut("cawg.identity") {
                Some(cawg_assertion) => cawg_assertion,
                None => {
                    return Err(anyhow::Error::msg(
                        "Could not parse CAWG identity details from assertion store",
                    ));
                }
            };

            let holding_manifest = match reader.get_manifest(key) {
                Some(holding_manifest) => holding_manifest,
                None => {
                    return Err(anyhow::Error::msg(
                        "Could not recover manifest holding CAWG data",
                    ));
                }
            };

            let parsed_cawg_json_string =
                match get_cawg_details_for_manifest(holding_manifest, tokio_runtime) {
                    Some(parsed_cawg_json_string) => parsed_cawg_json_string,
                    None => {
                        // Not a show-stopper:
                        // Could not parse CAWG details for manifest,
                        // so leaving original raw data unformatted.
                        return Ok(());
                    }
                };

            cawg_assertion["signature"] = match serde_json::from_str(&parsed_cawg_json_string) {
                Ok(decoded_cawg_assertion) => decoded_cawg_assertion,
                Err(err) => {
                    return Err(anyhow::Error::msg(err.to_string()));
                }
            };

            let cawg_assertion = match cawg_assertion.as_object_mut() {
                Some(cawg_assertion) => cawg_assertion,
                None => {
                    return Err(anyhow::Error::msg(
                        "Could not parse CAWG assertion data as object to decorate for display",
                    ));
                }
            };
            cawg_assertion.remove("pad1");
            cawg_assertion.remove("pad2");
        }
    }

    Ok(())
}

/// Update/decorate the displayed CAWG assertion for a more human-readable JSON output.
pub(crate) fn decorate_json_cawg_assertions(
    holding_manifest: &c2pa::Manifest,
    assertion: &mut Value,
    tokio_runtime: &Runtime,
) -> Result<(), anyhow::Error> {
    let parsed_cawg_json_string =
        match get_cawg_details_for_manifest(holding_manifest, tokio_runtime) {
            Some(parsed_cawg_json_string) => parsed_cawg_json_string,
            None => {
                // Could not parse CAWG details for manifest (leaving original raw data unformatted).
                // Not a fatal failure, so leaving raw data unformatted.
                return Ok(());
            }
        };

    // Let's look at the assertion data
    let assertion_data = match assertion.get_mut("data") {
        Some(assertion_data) => assertion_data,
        None => {
            return Err(anyhow::Error::msg("Could not parse CAWG assertion data"));
        }
    };

    // Update signature with parsed content
    let parsed_signature = match serde_json::from_str(&parsed_cawg_json_string) {
        Ok(parsed_signature) => parsed_signature,
        Err(err) => {
            return Err(anyhow::Error::msg(err.to_string()));
        }
    };
    assertion_data["signature"] = parsed_signature;

    // We don't need to show the padding fields either
    let assertion_data_map = match assertion_data.as_object_mut() {
        Some(assertion_data_map) => assertion_data_map,
        None => {
            return Err(anyhow::Error::msg(
                "Could not parse CAWG assertion data as object",
            ));
        }
    };
    assertion_data_map.remove("pad1");
    assertion_data_map.remove("pad2");

    Ok(())
}

/// Parse additional CAWG details from the manifest store to update displayed results.
/// As CAWG mostly async, this will block on network requests for checks using a tokio runtime.
fn get_cawg_details_for_manifest(
    manifest: &c2pa::Manifest,
    tokio_runtime: &Runtime,
) -> Option<String> {
    let ia_iter = IdentityAssertion::from_manifest(manifest);

    // TODO: Determine what should happen when multiple identities are reported (currently only 1 is supported)
    let mut parsed_cawg_json = String::new();

    ia_iter.for_each(|ia| {
        let identity_assertion = match ia {
            Ok(ia) => ia,
            Err(err) => {
                eprintln!("Could not parse CAWG identity assertion: {:?}", err);
                return;
            }
        };

        let isv = IcaSignatureVerifier {};
        let ica_validated = tokio_runtime.block_on(identity_assertion.validate(manifest, &isv));
        let ica = match ica_validated {
            Ok(ica) => ica,
            Err(err) => {
                eprintln!("Could not validate CAWG identity assertion: {:?}", err);
                return;
            }
        };

        parsed_cawg_json = match serde_json::to_string(&ica) {
            Ok(parsed_cawg_json) => parsed_cawg_json,
            Err(err) => {
                eprintln!(
                    "Could not parse CAWG identity claims aggregation details for manifest: {:?}",
                    err
                );
                return;
            }
        };
    });

    if parsed_cawg_json.is_empty() {
        return None;
    }

    // Get the JSON as mutable, so we can further parse and format CAWG data
    let maybe_map = serde_json::from_str(parsed_cawg_json.as_str());
    let mut map: Map<String, Value> = match maybe_map {
        Ok(map) => map,
        Err(err) => {
            eprintln!(
                "Could not parse convert CAWG identity claims details to JSON string map: {:?}",
                err
            );
            return None;
        }
    };

    // Get the credentials subject information...
    let credentials_subject_maybe = map.get_mut("credentialSubject");
    let credentials_subject = match credentials_subject_maybe {
        Some(credentials_subject) => credentials_subject,
        None => {
            eprintln!("Could not find credential subject in CAWG details for manifest");
            return None;
        }
    };
    let credentials_subject_as_obj = credentials_subject.as_object_mut();
    let credential_subject_details = match credentials_subject_as_obj {
        Some(credentials_subject) => credentials_subject,
        None => {
            eprintln!("Could not parse credential subject as object in CAWG details for manifest");
            return None;
        }
    };
    // As per design CAWG has some repetition between assertion an signature (c2paAsset field)
    // so we remove the c2paAsset field from the credential subject details too
    credential_subject_details.remove("c2paAsset");

    // return the for-display json-formatted string
    let serialized_content = serde_json::to_string(&map);
    match serialized_content {
        Ok(serialized_content) => Some(serialized_content),
        Err(err) => {
            eprintln!("Could not parse CAWG details for manifest: {:?}", err);
            None
        }
    }
}
