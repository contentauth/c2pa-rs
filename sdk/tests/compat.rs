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
    fs::{self, File},
    io::Cursor,
    path::PathBuf,
    thread,
};

use c2pa::{Reader, Result, SigningAlg};
use serde::Deserialize;
use serde_json::Value;
use tiny_http::{Response, Server};

const FIXTURES_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

#[derive(Debug, Deserialize)]
pub struct BinarySize {
    uncompressed_patch_size: usize,
    applied_size: usize,
}

#[derive(Debug, Deserialize)]
pub struct CompatAssetDetails {
    asset: PathBuf,
    category: String,
    remote_size: Option<BinarySize>,
    embedded_size: BinarySize,
}

#[derive(Debug, Deserialize)]
pub struct CompatDetails {
    assets: Vec<CompatAssetDetails>,
    #[allow(dead_code)]
    certificate: PathBuf,
    #[allow(dead_code)]
    private_key: PathBuf,
    #[allow(dead_code)]
    algorithm: SigningAlg,
    // tsa_url: String,
}

// Stabilizes hashes/uuids, all values prone to change during signing.
#[derive(Debug)]
struct Stabilizer {}

impl Stabilizer {
    pub fn new() -> Self {
        Self {}
    }

    // Returns whether or not the value needs to be stabilized and the new stabilized value.
    pub fn stabilize_value(&mut self, value: &str) -> Option<&'static str> {
        if value.starts_with("xmp:iid:") {
            Some("[XMP_ID]")
        } else if value.starts_with("urn:uuid:") {
            Some("[URN_UUID]")
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

    // TODO: restructure this function so it takes into account top-level fields
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
                File::open(format!("{FIXTURES_PATH}/compat/{}", request.url())).unwrap(),
            );
            request.respond(response).unwrap();
        }
    });

    Ok(())
}

#[test]
fn test_compat() -> Result<()> {
    serve_remote_manifests()?;

    let fixtures_path = PathBuf::from(FIXTURES_PATH);
    for version_dir in fs::read_dir(fixtures_path.join("compat"))? {
        let version_dir = version_dir?.path();

        let details: CompatDetails =
            serde_json::from_reader(File::open(version_dir.join("compat-details.json"))?)?;

        for asset_details in details.assets {
            let asset_dir = version_dir.join(&asset_details.category);

            let format = c2pa::format_from_path(&asset_details.asset).unwrap();
            let original_asset = fs::read(fixtures_path.join(&asset_details.asset))?;

            let mut stabilizer = Stabilizer::new();

            // Some versions of c2pa-rs don't support remote writing for certain assets.
            if let Some(remote_size) = asset_details.remote_size {
                let expected_remote_asset_patch = fs::read(asset_dir.join("remote.patch"))?;
                let expected_remote_asset_patch = lz4_flex::decompress(
                    &expected_remote_asset_patch,
                    remote_size.uncompressed_patch_size,
                )
                .expect("Failed to decompress remote patch.");
                let mut expected_remote_asset = Vec::with_capacity(remote_size.applied_size);
                bsdiff::patch(
                    &original_asset,
                    &mut Cursor::new(expected_remote_asset_patch),
                    &mut expected_remote_asset,
                )
                .expect("Failed to apply remote patch.");

                let expected_remote_reader: Reader =
                    serde_json::from_reader(File::open(asset_dir.join("remote.json"))?)?;
                let mut expected_remote_json_manifest =
                    serde_json::to_value(expected_remote_reader)?;

                let mut actual_json_from_remote_asset = serde_json::to_value(Reader::from_stream(
                    &format,
                    Cursor::new(expected_remote_asset),
                )?)?;
                stabilizer.stabilize(
                    &mut expected_remote_json_manifest,
                    &mut actual_json_from_remote_asset,
                );

                assert_eq!(expected_remote_json_manifest, actual_json_from_remote_asset);
            }

            let embedded_size = asset_details.embedded_size;

            let expected_embedded_asset_patch = fs::read(asset_dir.join("embedded.patch"))?;
            let expected_embedded_asset_patch = lz4_flex::decompress(
                &expected_embedded_asset_patch,
                embedded_size.uncompressed_patch_size,
            )
            .expect("Failed to decompress embedded patch.");
            let mut expected_embedded_asset = Vec::with_capacity(embedded_size.applied_size);
            bsdiff::patch(
                &original_asset,
                &mut Cursor::new(expected_embedded_asset_patch),
                &mut expected_embedded_asset,
            )
            .expect("Failed to apply embedded patch.");

            let expected_embedded_reader: Reader =
                serde_json::from_reader(File::open(asset_dir.join("embedded.json"))?)?;
            let mut expected_embedded_json_manifest =
                serde_json::to_value(&expected_embedded_reader)?;

            // We filter any new keys added when reading with the new version of c2pa-rs. This covers the case where
            // if a new field is added to a new version of c2pa-rs, it still reports as correct because the old fields
            // are still the same.
            let mut actual_json_from_embedded_asset = serde_json::to_value(Reader::from_stream(
                &format,
                Cursor::new(expected_embedded_asset),
            )?)?;
            stabilizer.stabilize(
                &mut expected_embedded_json_manifest,
                &mut actual_json_from_embedded_asset,
            );

            // Note that we don't assert the binary manifest because they can still be different, we aren't providing
            // guarantees that they are stored the same, we are guaranteeing that they can still be read the same.
            assert_eq!(
                expected_embedded_json_manifest,
                actual_json_from_embedded_asset
            );
        }
    }

    Ok(())
}
