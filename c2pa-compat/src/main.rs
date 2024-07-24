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
    path::Path,
};

use c2pa::{create_signer, Builder, Result, SigningAlg};
use serde::Serialize;

const FULL_MANIFEST: &str = include_str!("./full-manifest.json");

// TODO: these assets should be as small as possible
const DETAILS: CompatDetails = CompatDetails::new(&[
    CompatAssetDetails::new("C.jpg", "jpeg"),
    CompatAssetDetails::new("sample1.gif", "gif"),
    CompatAssetDetails::new("sample1.svg", "svg"),
    // TODO: add an asset from each parser category
]);

const BASE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/tests/fixtures");

#[derive(Debug, Serialize)]
pub struct CompatAssetDetails {
    asset: &'static str,
    category: &'static str,
}

impl CompatAssetDetails {
    pub const fn new(asset: &'static str, category: &'static str) -> Self {
        Self { asset, category }
    }
}

// Redefined in `sdk/tests/compat.rs`, can't make lib.rs without circular dependency or a separate crate.
#[derive(Debug, Serialize)]
pub struct CompatDetails {
    assets: &'static [CompatAssetDetails],
    sign_cert: &'static str,
    pkey: &'static str,
    algorithm: SigningAlg,
    tsa_url: &'static str,
}

impl CompatDetails {
    pub const fn new(assets: &'static [CompatAssetDetails]) -> Self {
        Self {
            assets,
            sign_cert: "certs/ps256.pub",
            pkey: "certs/ps256.pem",
            algorithm: SigningAlg::Ps256,
            tsa_url: "TODO",
        }
    }
}

fn fixture_path(subpath: &str) -> String {
    format!("{BASE_PATH}/{subpath}")
}

// TODO: ideally this tool will run from CI on publish (if tests fail, cancel)
// TODO: also, we need to have a predefined set of hash assertions that are added on a per-asset basis,
//       maybe the hash assertion should be specified in compat-details?
fn main() -> Result<()> {
    let compat_dir = fixture_path(&format!("compat/{}", c2pa::VERSION));
    fs::create_dir(&compat_dir)?;

    fs::write(format!("{compat_dir}/manifest.json"), FULL_MANIFEST)?;
    fs::write(
        format!("{compat_dir}/compat-details.json"),
        serde_json::to_string(&DETAILS)?,
    )?;

    for asset_details in DETAILS.assets {
        let format = c2pa::format_from_path(asset_details.asset).unwrap();

        let mut signed_embedded_asset = Cursor::new(Vec::new());
        Builder::from_json(FULL_MANIFEST)?.sign(
            &*create_signer::from_files(
                &fixture_path(DETAILS.sign_cert),
                &fixture_path(DETAILS.pkey),
                DETAILS.algorithm,
                Some(fixture_path(DETAILS.tsa_url)),
            )?,
            &format,
            &mut File::open(fixture_path(asset_details.asset))?,
            &mut signed_embedded_asset,
        )?;
        // TODO: need to set resource base path

        // TODO: can we share the builder or does it mutate itself?
        let mut signed_sidecar_asset = Cursor::new(Vec::new());
        let mut sidecar_builder = Builder::from_json(FULL_MANIFEST)?;
        sidecar_builder.no_embed = true;

        let sidecar_c2pa_manifest = sidecar_builder.sign(
            &*create_signer::from_files(
                &fixture_path(DETAILS.sign_cert),
                &fixture_path(DETAILS.pkey),
                DETAILS.algorithm,
                Some(fixture_path(DETAILS.tsa_url)),
            )?,
            &format,
            &mut File::open(fixture_path(asset_details.asset))?,
            &mut signed_sidecar_asset,
        )?;
        // TODO: need to set resource base path

        let dir_path = format!("{compat_dir}/{}", asset_details.category);
        fs::create_dir(&dir_path)?;

        let asset_path = Path::new(asset_details.asset);
        let extension = asset_path.extension().unwrap().to_str().unwrap();

        fs::write(
            format!("{dir_path}/sidecar.{extension}"),
            signed_sidecar_asset.into_inner(),
        )?;
        fs::write(format!("{dir_path}/sidecar.c2pa"), sidecar_c2pa_manifest)?;
        fs::write(
            format!("{dir_path}/embedded.{extension}"),
            signed_embedded_asset.into_inner(),
        )?;
    }

    Ok(())
}
