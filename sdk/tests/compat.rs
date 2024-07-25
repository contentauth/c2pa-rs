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

// TODO: temp
#![allow(dead_code)]

use std::{
    fs::{self, File},
    io::Cursor,
    path::PathBuf,
    thread,
};

use c2pa::{Builder, Reader, Result, SigningAlg};
use serde::Deserialize;
use tiny_http::{Response, Server};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "tests/fixtures");

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
    algorithm: SigningAlg,
    tsa_url: String,
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
fn test_compat() -> Result<()> {
    serve_remote_manifests()?;

    for version_dir in fs::read_dir(format!("{FIXTURES}/compat"))? {
        let version_dir = version_dir?.path();

        let expected_json_manifest = fs::read_to_string(version_dir.join("manifest.json"))?;
        let details: CompatDetails =
            serde_json::from_reader(File::open(version_dir.join("compat-details.json"))?)?;

        for asset_details in details.assets {
            let asset_dir = version_dir.join(&asset_details.category);

            let format = c2pa::format_from_path(&asset_details.asset).unwrap();
            let extension = asset_details.asset.extension().unwrap().to_str().unwrap();
            let file_name = asset_details.asset.file_name().unwrap().to_str().unwrap();

            let mut expected_embedded_asset =
                Cursor::new(fs::read(asset_dir.join(format!("embedded.{extension}")))?);
            let mut expected_remote_asset =
                Cursor::new(fs::read(asset_dir.join(format!("remote.{extension}")))?);
            let expected_c2pa_manifest = Cursor::new(fs::read(asset_dir.join("manifest.c2pa"))?);

            // TODO: we can preallocate w/ size of expected_embedded_asset
            let mut actual_embedded_asset = Cursor::new(Vec::new());
            Builder::from_json(&expected_json_manifest)?.sign(
                &*c2pa::create_signer::from_files(
                    &details.public_key,
                    &details.private_key,
                    details.algorithm,
                    Some(details.tsa_url.clone()),
                )?,
                &format,
                &mut File::open(&format!("{FIXTURES}/{}", file_name))?,
                &mut actual_embedded_asset,
            )?;

            // TODO: we can preallocate here as well
            let mut actual_remote_asset = Cursor::new(Vec::new());
            let mut remote_builder = Builder::from_json(&expected_json_manifest)?;
            remote_builder.remote_url = Some(format!(
                "localhost:8000/{}/{}/manifest.c2pa",
                c2pa::VERSION,
                &asset_details.category
            ));
            let actual_c2pa_manifest = remote_builder.sign(
                &*c2pa::create_signer::from_files(
                    &details.public_key,
                    &details.private_key,
                    details.algorithm,
                    Some(details.tsa_url.clone()),
                )?,
                &format,
                &mut File::open(&format!("{FIXTURES}/{}", file_name))?,
                &mut actual_remote_asset,
            )?;

            let actual_json_from_embedded_asset =
                Reader::from_stream(&format, &mut expected_embedded_asset)?.json();
            let actual_json_from_remote_asset =
                Reader::from_stream(&format, &mut expected_remote_asset)?.json();

            assert_eq!(expected_json_manifest, actual_json_from_embedded_asset);
            assert_eq!(expected_json_manifest, actual_json_from_remote_asset);
            assert_eq!(
                expected_embedded_asset.into_inner(),
                actual_embedded_asset.into_inner()
            );
            assert_eq!(
                expected_remote_asset.into_inner(),
                actual_remote_asset.into_inner()
            );
            assert_eq!(expected_c2pa_manifest.into_inner(), actual_c2pa_manifest);
        }
    }

    Ok(())
}
