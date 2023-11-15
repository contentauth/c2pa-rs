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

use std::collections::HashMap;
#[cfg(feature = "file_io")]
use std::path::Path;

use atree::{Arena, Token};
use extfmt::Hexlify;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    assertion::AssertionData,
    claim::Claim,
    status_tracker::{DetailedStatusTracker, StatusTracker},
    store::Store,
    utils::base64,
    validation_status::ValidationStatus,
    Result,
};

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

    /// Prints tree view of manifest store
    #[cfg(feature = "file_io")]
    pub fn dump_tree<P: AsRef<Path>>(path: P) -> Result<()> {
        let mut validation_log = crate::status_tracker::DetailedStatusTracker::new();
        let store = crate::store::Store::load_from_asset(path.as_ref(), true, &mut validation_log)?;

        let claim = store.provenance_claim().ok_or(crate::Error::ClaimMissing {
            label: "None".to_string(),
        })?;

        let os_filename = path
            .as_ref()
            .file_name()
            .ok_or_else(|| crate::Error::BadParam("bad filename".to_string()))?;
        let asset_name = os_filename.to_string_lossy().into_owned();

        let (tree, root_token) = ManifestStoreReport::to_tree(&store, claim, &asset_name, false)?;
        fn walk_tree(tree: &Arena<String>, token: &Token) -> treeline::Tree<String> {
            let result = token.children_tokens(tree).fold(
                treeline::Tree::root(tree[*token].data.clone()),
                |mut root, entry_token| {
                    if entry_token.is_leaf(tree) {
                        root.push(treeline::Tree::root(tree[entry_token].data.clone()));
                    } else {
                        root.push(walk_tree(tree, &entry_token));
                    }
                    root
                },
            );

            result
        }

        // print tree
        println!("Tree View:\n {}", walk_tree(&tree, &root_token));

        Ok(())
    }

    /// Prints the certificate chain used to sign the active manifest.
    #[cfg(feature = "file_io")]
    pub fn dump_cert_chain<P: AsRef<Path>>(path: P) -> Result<()> {
        let mut validation_log = DetailedStatusTracker::new();
        let store = Store::load_from_asset(path.as_ref(), true, &mut validation_log)?;

        let cert_str = store.get_provenance_cert_chain()?;
        println!("{cert_str}");
        Ok(())
    }

    /// Returns the certificate chain used to sign the active manifest.
    #[cfg(feature = "file_io")]
    pub fn cert_chain<P: AsRef<Path>>(path: P) -> Result<String> {
        let mut validation_log = DetailedStatusTracker::new();
        let store = Store::load_from_asset(path.as_ref(), true, &mut validation_log)?;
        store.get_provenance_cert_chain()
    }

    /// Returns the certificate used to sign the active manifest.
    pub fn cert_chain_from_bytes(format: &str, bytes: &[u8]) -> Result<String> {
        let mut validation_log = DetailedStatusTracker::new();
        let store = Store::load_from_memory(format, bytes, true, &mut validation_log)?;
        store.get_provenance_cert_chain()
    }

    /// Creates a ManifestStoreReport from an existing Store and a validation log
    pub(crate) fn from_store_with_log(
        store: &Store,
        validation_log: &impl StatusTracker,
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
        Self::from_store_with_log(&store, &validation_log)
    }

    /// Creates a ManifestStoreReport from a file
    #[cfg(feature = "file_io")]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut validation_log = DetailedStatusTracker::new();
        let store = Store::load_from_asset(path.as_ref(), true, &mut validation_log)?;
        Self::from_store_with_log(&store, &validation_log)
    }

    /// create a json string representation of this structure, omitting binaries
    fn to_json(&self) -> String {
        let mut json = serde_json::to_string_pretty(self).unwrap_or_else(|e| e.to_string());

        json = b64_tag(json, "hash");
        json = omit_tag(json, "pad");

        json
    }

    #[allow(dead_code)]
    fn populate_node(
        tree: &mut Arena<String>,
        store: &Store,
        claim: &Claim,
        current_token: &Token,
        name_only: bool,
    ) -> Result<()> {
        let claim_assertions = claim.claim_assertion_store();
        for claim_assertion in claim_assertions.iter() {
            let hashlink = claim_assertion.label();
            let (label, instance) = Claim::assertion_label_from_link(&hashlink);
            let label = Claim::label_with_instance(&label, instance);

            current_token.append(tree, format!("Assertion:{label}"));
        }

        // recurse down ingredients
        for i in claim.ingredient_assertions() {
            let ingredient_assertion =
                <crate::assertions::Ingredient as crate::AssertionBase>::from_assertion(i)?;

            // is this an ingredient
            if let Some(ref c2pa_manifest) = &ingredient_assertion.c2pa_manifest {
                let label = Store::manifest_label_from_path(&c2pa_manifest.url());
                let hash = &c2pa_manifest.hash()[..5];

                if let Some(ingredient_claim) = store.get_claim(&label) {
                    // create new node
                    let data = if name_only {
                        format!("{}_{}", ingredient_assertion.title, Hexlify(hash))
                    } else {
                        format!("Asset:{}, Manifest:{}", ingredient_assertion.title, label)
                    };

                    let new_token = current_token.append(tree, data);

                    ManifestStoreReport::populate_node(
                        tree,
                        store,
                        ingredient_claim,
                        &new_token,
                        name_only,
                    )?;
                }
            } else {
                let asset_name = &ingredient_assertion.title;
                let data = if name_only {
                    asset_name.to_string()
                } else {
                    format!("Asset:{asset_name}")
                };
                current_token.append(tree, data);
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn to_tree(
        store: &Store,
        claim: &Claim,
        asset_name: &str,
        name_only: bool,
    ) -> Result<(Arena<String>, Token)> {
        let data = if name_only {
            asset_name.to_string()
        } else {
            format!("Asset:{}, Manifest:{}", asset_name, claim.label())
        };

        let (mut tree, root_token) = Arena::with_data(data);
        ManifestStoreReport::populate_node(&mut tree, store, claim, &root_token, name_only)?;
        Ok((tree, root_token))
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
            credential_store: if !credential_store.is_empty() {
                Some(credential_store)
            } else {
                None
            },
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
    while let Some(index) = json.find(&format!("\"{tag}\": [")) {
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
    while let Some(index) = json.find(&format!("\"{tag}\": [")) {
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

    use std::fs;

    use super::ManifestStoreReport;
    use crate::utils::test::fixture_path;

    #[test]
    fn manifest_store_report() {
        let path = fixture_path("CIE-sig-CA.jpg");
        let report = ManifestStoreReport::from_file(path).expect("load_from_asset");
        println!("{report}");
    }

    #[test]
    fn manifest_get_certchain_from_bytes() {
        let bytes = fs::read(fixture_path("CA.jpg")).expect("missing test asset");
        assert!(ManifestStoreReport::cert_chain_from_bytes("jpg", &bytes).is_ok())
    }

    #[test]
    fn manifest_get_certchain_from_bytes_no_manifest_err() {
        let bytes = fs::read(fixture_path("no_manifest.jpg")).expect("missing test asset");
        assert!(matches!(
            ManifestStoreReport::cert_chain_from_bytes("jpg", &bytes),
            Err(crate::Error::JumbfNotFound)
        ))
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn manifest_dump_tree() {
        let asset_name = "CA.jpg";
        let path = fixture_path(asset_name);

        ManifestStoreReport::dump_tree(path).expect("dump_tree");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn manifest_dump_certchain() {
        let asset_name = "CA.jpg";
        let path = fixture_path(asset_name);

        ManifestStoreReport::dump_cert_chain(path).expect("dump certs");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn manifest_get_certchain() {
        let asset_name = "CA.jpg";
        let path = fixture_path(asset_name);
        assert!(ManifestStoreReport::cert_chain(path).is_ok())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn manifest_get_certchain_no_manifest_err() {
        let asset_name = "no_manifest.jpg";
        let path = fixture_path(asset_name);
        assert!(matches!(
            ManifestStoreReport::cert_chain(path),
            Err(crate::Error::JumbfNotFound)
        ))
    }
}
