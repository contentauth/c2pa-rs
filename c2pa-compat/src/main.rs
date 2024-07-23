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
    io,
    path::PathBuf,
};

use c2pa::{create_signer, Builder, Result, SigningAlg};
use serde::Serialize;

const FULL_MANIFEST: &str = include_str!("./full-manifest.json");

const ASSET_PATH: &str = "C.jpg";
const SIGNCERT_PATH: &str = "certs/ps256.pub";
const PKEY_PATH: &str = "certs/ps256.pem";
const ALGORITHM: SigningAlg = SigningAlg::Ps256;
const TSA_URL: &str = "TODO";

const BASE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../sdk/tests/fixtures");

// Redefined in `sdk/tests/compat.rs`, can't make lib.rs without circular dependency or a separate crate.
#[derive(Debug, Serialize)]
pub struct CompatDetails {
    asset: PathBuf,
    signcert: PathBuf,
    pkey: PathBuf,
    algorithm: SigningAlg,
    tsa_url: String,
}

fn fixture_path(subpath: &str) -> String {
    format!("{BASE_PATH}/{subpath}")
}

// TODO: ideally this tool will run from CI on publish (if tests fail, cancel)
// TODO: also, we need to have a predefined set of hash assertions that are added on a per-asset basis,
//       maybe the hash assertion should be specified in compat-details?
fn main() -> Result<()> {
    let details = CompatDetails {
        asset: PathBuf::from(fixture_path(ASSET_PATH)),
        signcert: PathBuf::from(fixture_path(SIGNCERT_PATH)),
        pkey: PathBuf::from(fixture_path(PKEY_PATH)),
        algorithm: ALGORITHM,
        tsa_url: TSA_URL.to_owned(),
    };

    let format = c2pa::format_from_path(&details.asset).unwrap();

    let c2pa_manifest = Builder::from_json(FULL_MANIFEST)?.sign(
        &*create_signer::from_files(
            &details.signcert,
            &details.pkey,
            details.algorithm,
            Some(details.tsa_url.clone()),
        )?,
        &format,
        &mut File::open(&details.asset)?,
        &mut io::empty(),
    )?;
    // TODO: need to set resource base path

    let dir_path = fixture_path(&format!("compat/{}", c2pa::VERSION));
    fs::create_dir(&dir_path)?;

    // TODO: To be more extensive, we should be generating embedded/remote manifests
    //       for each type of asset/parser. For remote manifests, we can store a
    //       URL to the repo where the asset will be uploaded.
    //       This will ensure three things: (1) manifest parsing compatability, (2) remote
    //       manifest parsing compatability, (3) asset embedding compatability
    //
    //       These changes would significantly benefit from having a separate repo to store
    //       assets.

    fs::write(format!("{dir_path}/manifest.json"), FULL_MANIFEST)?;
    fs::write(format!("{dir_path}/manifest.c2pa"), c2pa_manifest)?;
    fs::write(
        format!("{dir_path}/compat-details.json"),
        serde_json::to_string(&details)?,
    )?;

    Ok(())
}
