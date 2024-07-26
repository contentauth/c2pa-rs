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

use std::{
    collections::HashMap,
    fs::{self, File},
    io::Cursor,
    path::{Path, PathBuf},
    thread,
};

use c2pa::{Builder, Reader, Result, SigningAlg};
use serde::Deserialize;
use serde_json::Value;
use tiny_http::{Response, Server};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

#[derive(Debug, Deserialize)]
pub struct CompatAssetDetails {
    asset: PathBuf,
    category: String,
}

#[derive(Debug, Deserialize)]
pub struct CompatDetails {
    assets: Vec<CompatAssetDetails>,
    public_key: PathBuf,
    private_key: PathBuf,
    // TODO: temp
    // algorithm: SigningAlg,
    // tsa_url: String,
}

// Stabilizes hashes/uuids, all values prone to change during signing.
#[derive(Debug)]
struct Stabilizer {
    filter: HashMap<String, String>,
}

impl Stabilizer {
    pub fn new() -> Self {
        Self {
            filter: HashMap::new(),
        }
    }

    // Returns whether or not the value needs to be stabilized and the new stabilized value.
    pub fn stabilize_value(&mut self, value: &str) -> Option<&str> {
        if self.filter.contains_key(value) {
            self.filter.get(value).map(|x| x.as_str())
        } else if value.starts_with("xmp:iid:") {
            self.filter.insert(value.to_owned(), "[XMP_ID]".to_owned());

            self.filter.get(value).map(|x| x.as_str())
        } else if value.starts_with("urn:uuid:") {
            self.filter
                .insert(value.to_owned(), "[URN_UUID]".to_owned());

            self.filter.get(value).map(|x| x.as_str())
        } else {
            None
        }
    }

    pub fn stabilize_value_replace(&mut self, value: &mut Value) {
        if let Value::String(value) = value {
            if let Some(stabilized_value) = self.stabilize_value(value) {
                *value = stabilized_value.to_owned();
            }
        }
    }

    // This function does two things:
    // * Stabilizes unstable keys/values
    // * Filters new features/fields that do not exist in the original json
    pub fn stabilize(&mut self, original: &mut Value, modified: &mut Value) {
        match (original, modified) {
            (Value::Array(original_array), Value::Array(modified_array)) => {
                for (original_value, modified_value) in
                    original_array.iter_mut().zip(modified_array.iter_mut())
                {
                    self.stabilize_value_replace(original_value);
                    self.stabilize_value_replace(modified_value);

                    self.stabilize(original_value, modified_value);
                }
            }
            (Value::Object(original_map), Value::Object(modified_map)) => {
                for key in original_map.clone().keys() {
                    self.stabilize_value_replace(original_map.get_mut(key).unwrap());

                    if let Some(stabilized_key) = self.stabilize_value(key) {
                        let original_value = original_map.remove(key).unwrap();
                        original_map.insert(stabilized_key.to_owned(), original_value);
                    }
                }

                for (mut key, _) in modified_map.clone().into_iter() {
                    self.stabilize_value_replace(modified_map.get_mut(&key).unwrap());

                    // TODO: dedup with above
                    if let Some(stabilized_key) = self.stabilize_value(&key) {
                        let modified_value = modified_map.remove(&key).unwrap();
                        modified_map.insert(stabilized_key.to_owned(), modified_value);
                        key = stabilized_key.to_owned();
                    }

                    // If the original map doesn't contain the key by this point, then we know it's a new field
                    // introduced in a newer version of c2pa-rs, so ignore it.
                    if !original_map.contains_key(&key) {
                        modified_map.remove(&key);
                    } else {
                        self.stabilize(&mut original_map[&key], &mut modified_map[&key]);
                    }
                }
            }
            _ => {
                // In this case, the structure of the json is different, therefore not a match
            }
        }
    }
}

fn serve_remote_manifests() -> Result<()> {
    thread::spawn(|| {
        let server = Server::http("localhost:8000").unwrap();

        for request in server.incoming_requests() {
            let response = Response::from_file(
                File::open(format!("{FIXTURES}/compat/{}", request.url())).unwrap(),
            );
            request.respond(response).unwrap();
        }
    });

    Ok(())
}

// TODO: disabled for now until we have it impled
// #[test]
#[cfg(not(target_arch = "wasm32"))] // TODO: WASM doesn't support ed25519 yet
#[test]
fn test_compat() -> Result<()> {
    use c2pa::CallbackSigner;

    serve_remote_manifests()?;

    for version_dir in fs::read_dir(format!("{FIXTURES}/compat"))? {
        let version_dir = version_dir?.path();

        let details: CompatDetails =
            serde_json::from_reader(File::open(version_dir.join("compat-details.json"))?)?;

        let public_key = fs::read(fixture_path(&details.public_key))?;
        let private_key = fs::read(fixture_path(&details.private_key))?;

        for asset_details in details.assets {
            let asset_dir = version_dir.join(&asset_details.category);

            let format = c2pa::format_from_path(&asset_details.asset).unwrap();
            let extension = asset_details.asset.extension().unwrap().to_str().unwrap();
            let file_name = asset_details.asset.file_name().unwrap().to_str().unwrap();

            let private_key = private_key.clone();
            let signer = CallbackSigner::new(
                move |_context: *const (), data: &[u8]| ed_sign(data, &private_key),
                SigningAlg::Ed25519,
                public_key.clone(),
            );

            let expected_reader: Reader =
                serde_json::from_reader(File::open(asset_dir.join("manifest.json"))?)?;
            let expected_json_manifest_str = serde_json::to_string(&expected_reader)?;
            let mut expected_json_manifest_value = serde_json::to_value(&expected_reader)?;

            let mut stabilizer = Stabilizer::new();

            // Some versions of c2pa-rs don't support remote writing for certain assets.
            let remote_asset_path = asset_dir.join(format!("remote.{extension}"));
            if remote_asset_path.exists() {
                let mut expected_remote_asset = Cursor::new(fs::read(remote_asset_path)?);
                // TODO: we can preallocate here as well
                let mut actual_remote_asset = Cursor::new(Vec::new());
                let mut remote_builder = Builder::from_json(&expected_json_manifest_str)?;
                remote_builder.remote_url = Some(format!(
                    "localhost:8000/{}/{}/manifest.c2pa",
                    c2pa::VERSION,
                    &asset_details.category
                ));
                remote_builder.sign(
                    &signer,
                    &format,
                    &mut File::open(&format!("{FIXTURES}/{}", file_name))?,
                    &mut actual_remote_asset,
                )?;

                let mut actual_json_from_remote_asset = serde_json::to_value(Reader::from_stream(
                    &format,
                    &mut expected_remote_asset,
                )?)?;
                stabilizer.stabilize(
                    &mut expected_json_manifest_value,
                    &mut actual_json_from_remote_asset,
                );

                assert_eq!(expected_json_manifest_value, actual_json_from_remote_asset);
            }

            let mut expected_embedded_asset =
                Cursor::new(fs::read(asset_dir.join(format!("embedded.{extension}")))?);

            // TODO: we can preallocate w/ size of expected_embedded_asset
            let mut actual_embedded_asset = Cursor::new(Vec::new());
            Builder::from_json(&expected_json_manifest_str)?.sign(
                &signer,
                &format,
                &mut File::open(&format!("{FIXTURES}/{}", file_name))?,
                &mut actual_embedded_asset,
            )?;

            // We filter any new keys added when reading with the new version of c2pa-rs. This covers the case where
            // if a new field is added to a new version of c2pa-rs, it still reports as correct because the old fields
            // are still the same.
            let mut actual_json_from_embedded_asset =
                serde_json::to_value(Reader::from_stream(&format, &mut expected_embedded_asset)?)?;
            stabilizer.stabilize(
                &mut expected_json_manifest_value,
                &mut actual_json_from_embedded_asset,
            );

            // Note that we don't assert the binary manifest because they can still be different, we aren't providing
            // guarantees that they are stored the same, we are guaranteeing that they can still be read the same.
            assert_eq!(
                expected_json_manifest_value,
                actual_json_from_embedded_asset
            );
        }
    }

    Ok(())
}

fn fixture_path(subpath: &Path) -> String {
    format!("{FIXTURES}/{}", subpath.display())
}

// TODO: taken from v2pai example, WASM compatible?
fn ed_sign(data: &[u8], private_key: &[u8]) -> c2pa::Result<Vec<u8>> {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use pem::parse;

    // Parse the PEM data to get the private key
    let pem = parse(private_key).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    // For Ed25519, the key is 32 bytes long, so we skip the first 16 bytes of the PEM data
    let key_bytes = &pem.contents()[16..];
    let signing_key =
        SigningKey::try_from(key_bytes).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    // Sign the data
    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}
