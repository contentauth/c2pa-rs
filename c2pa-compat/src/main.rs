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
const SIGNCERT_PATH: &str = "ps256.pub";
const PKEY_PATH: &str = "ps256.pem";
const ALGORITHM: SigningAlg = SigningAlg::Ps256;
const TSA_URL: &str = "TODO";

// Redefined in `sdk/tests/compat.rs`, can't make lib.rs without circular dependency or a separate crate.
#[derive(Debug, Serialize)]
pub struct CompatDetails {
    asset: PathBuf,
    signcert: PathBuf,
    pkey: PathBuf,
    algorithm: SigningAlg,
    tsa_url: String,
}

// TODO: ideally this tool will run from CI on publish (if tests fail, cancel)
fn main() -> Result<()> {
    let details = CompatDetails {
        asset: PathBuf::from(ASSET_PATH),
        signcert: PathBuf::from(SIGNCERT_PATH),
        pkey: PathBuf::from(PKEY_PATH),
        algorithm: ALGORITHM,
        tsa_url: TSA_URL.to_owned(),
    };

    let format = c2pa::format_from_path(ASSET_PATH).unwrap();

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

    let dir_path = format!("./sdk/tests/fixtures/compat/{}", c2pa::VERSION);
    fs::create_dir(&dir_path)?;

    // TODO: to be more extensive, we can test embedding the manifest in the asset
    //       but if we do that, we should probably do it for every type of supported asset.
    //       we should also test embedding the manifest as a remote manifest
    //       if assets are stored in a separate repo, we can reference the github url?
    //
    //       this is a big benefit of having a separate assets repo, we (for the most part)
    //       don't care how large it gets because it doesn't flood our history

    fs::write(format!("{dir_path}/manifest.json"), FULL_MANIFEST)?;
    fs::write(format!("{dir_path}/manifest.c2pa"), c2pa_manifest)?;
    fs::write(
        format!("{dir_path}/compat-details.json"),
        serde_json::to_string(&details)?,
    )?;

    Ok(())
}
