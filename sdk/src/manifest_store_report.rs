// Copyright 2022 Adobe. All rights reserved.
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

use crate::{
    assertion::AssertionData,
    claim::Claim,
    status_tracker::{DetailedStatusTracker, StatusTracker},
    store::Store,
    validation_status::ValidationStatus,
    Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
#[cfg(feature = "file_io")]
use std::path::Path;

/// Low level JSON based representation of Manifest Store - used for debugging
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ManifestStoreReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    active_manifest: Option<String>,
    manifests: HashMap<String, ManifestReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_status: Option<Vec<ValidationStatus>>,
}

impl ManifestStoreReport {
    /// Creates a ManifestStoreReport from an existing Store
    pub(crate) fn from_store(store: &Store) -> Result<Self> {
        let mut manifests = HashMap::<String, ManifestReport>::new();
        for claim in store.claims() {
            manifests.insert(claim.label().to_owned(), ManifestReport::from_claim(claim)?);
        }

        Ok(ManifestStoreReport {
            active_manifest: store.provenance_label(),
            manifests,
            validation_status: None,
        })
    }

    /// Creates a ManifestStoreReport from an existing Store and a validation log
    pub(crate) fn from_store_with_log(
        store: &Store,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Self> {
        let mut report = Self::from_store(store)?;

        // convert log items to ValidationStatus
        let mut statuses = Vec::new();
        for item in validation_log.get_log() {
            if let Some(status) = item.validation_status.as_ref() {
                statuses.push(
                    ValidationStatus::new(status.to_string())
                        .set_url(item.label.to_string())
                        .set_explanation(item.description.to_string()),
                );
            }
        }
        if !statuses.is_empty() {
            report.validation_status = Some(statuses);
        }
        Ok(report)
    }

    /// Creates a ManifestStoreReport from image bytes and a format
    pub fn from_bytes(format: &str, image_bytes: &[u8]) -> Result<Self> {
        let mut validation_log = DetailedStatusTracker::new();
        let store = Store::load_from_memory(format, image_bytes, true, &mut validation_log)?;
        Self::from_store_with_log(&store, &mut validation_log)
    }

    /// Creates a ManifestStoreReport from a file
    #[cfg(feature = "file_io")]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut validation_log = DetailedStatusTracker::new();
        let store = Store::load_from_asset(path.as_ref(), true, &mut validation_log)?;
        Self::from_store_with_log(&store, &mut validation_log)
    }

    /// create a json string representation of this structure, omitting binaries
    fn to_json(&self) -> String {
        let mut json = serde_json::to_string_pretty(self).unwrap_or_else(|e| e.to_string());

        json = b64_tag(json, "hash");
        json = omit_tag(json, "pad");

        json
    }
}

impl std::fmt::Display for ManifestStoreReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_json())
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct ManifestReport {
    claim: Value,
    assertion_store: HashMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_store: Option<Vec<Value>>,
    signature: SignatureReport,
}

impl ManifestReport {
    fn from_claim(claim: &Claim) -> Result<Self> {
        let mut assertion_store = HashMap::<String, Value>::new();
        let claim_assertions = claim.claim_assertion_store();
        for claim_assertion in claim_assertions.iter() {
            let hashlink = claim_assertion.label();
            let (label, instance) = Claim::assertion_label_from_link(&hashlink);
            let label = Claim::label_with_instance(&label, instance);
            let value = match claim_assertion.assertion().decode_data() {
                AssertionData::Json(_) | AssertionData::Cbor(_) => {
                    claim_assertion.assertion().as_json_object()? // todo:  this may cause data loss
                }
                AssertionData::Binary(x) => {
                    serde_json::to_value(format!("<omitted> len = {}", x.len()))?
                }
                AssertionData::Uuid(s, x) => {
                    serde_json::to_value(format!("uuid: {}, data: {}", s, base64::encode(x)))?
                }
            };
            assertion_store.insert(label, value);
        }

        // convert credential store to json values
        let credential_store: Vec<Value> = claim
            .get_verifiable_credentials()
            .iter()
            .filter_map(|d| match d {
                AssertionData::Json(s) => serde_json::from_str(s).ok(),
                _ => None,
            })
            .collect();

        let signature = match claim.signature_info() {
            Some(info) => SignatureReport {
                alg: info.alg.map_or_else(String::new, |a| a.to_string()),
                issuer: info.issuer_org,
                time: info.date.map(|d| d.to_rfc3339()),
            },
            None => SignatureReport::default(),
        };
        Ok(Self {
            claim: serde_json::to_value(claim)?, // todo:  this will lose tagging info
            assertion_store,
            credential_store: (!credential_store.is_empty()).then(|| credential_store),
            signature,
        })
    }
    /// create a json string representation of this structure, omitting binaries
    fn to_json(&self) -> String {
        let mut json = serde_json::to_string_pretty(self).unwrap_or_else(|e| e.to_string());

        json = b64_tag(json, "hash");
        json = omit_tag(json, "pad");

        json
    }
}

impl std::fmt::Display for ManifestReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_json())
    }
}

// used to report information from signature data
#[derive(Default, Debug, Deserialize, Serialize)]
struct SignatureReport {
    alg: String,
    // human readable issuing authority for this signature
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    // the time the signature was created
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<String>,
}

// replace the value of any field in the json string with a given key with the string <omitted>
fn omit_tag(mut json: String, tag: &str) -> String {
    while let Some(index) = json.find(&format!("\"{}\": [", tag)) {
        if let Some(idx2) = json[index..].find(']') {
            json = format!(
                "{}\"{}\": \"<omitted>\"{}",
                &json[..index],
                tag,
                &json[index + idx2 + 1..]
            );
        }
    }
    json
}

// make a base64 hash from the value of any field in the json string with key base64 hash
fn b64_tag(mut json: String, tag: &str) -> String {
    while let Some(index) = json.find(&format!("\"{}\": [", tag)) {
        if let Some(idx2) = json[index..].find(']') {
            let idx3 = json[index..].find('[').unwrap_or_default(); // ok since we just found it
            let bytes: Vec<u8> =
                serde_json::from_slice(json[index + idx3..index + idx2 + 1].as_bytes())
                    .unwrap_or_default();
            json = format!(
                "{}\"{}\": \"{}\"{}",
                &json[..index],
                tag,
                base64::encode(&bytes),
                &json[index + idx2 + 1..]
            );
        }
    }
    json
}

#[cfg(feature = "file_io")]
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::ManifestStoreReport;
    use crate::utils::test::fixture_path;

    #[test]
    fn manifest_store_report() {
        let path = fixture_path("CIE-sig-CA.jpg");
        let report = ManifestStoreReport::from_file(&path).expect("load_from_asset");
        println!("{}", report);
    }
}
