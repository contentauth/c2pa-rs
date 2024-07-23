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
    io::{self, Cursor},
    path::PathBuf,
};

use c2pa::{create_signer, Builder, Reader, Result, SigningAlg};
use serde::Deserialize;

const COMPAT_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "tests/fixtures/compat");

#[derive(Debug, Deserialize)]
pub struct CompatDetails {
    asset: PathBuf,
    signcert: PathBuf,
    pkey: PathBuf,
    algorithm: SigningAlg,
    tsa_url: String,
}

// TODO: disabled for now until we have it impled
// #[test]
fn test_compat() -> Result<()> {
    for version_dir in fs::read_dir(COMPAT_FIXTURES)? {
        let version_dir_path = version_dir?.path();

        let details: CompatDetails =
            serde_json::from_reader(File::open(version_dir_path.join("compat-details.json"))?)?;
        let format = c2pa::format_from_path(&details.asset).unwrap();

        let expected_json_manifest = fs::read_to_string(version_dir_path.join("manifest.json"))?;
        let mut expected_c2pa_manifest =
            Cursor::new(fs::read(version_dir_path.join("manifest.c2pa"))?);

        let actual_c2pa_manifest = Builder::from_json(&expected_json_manifest)?.sign(
            &*create_signer::from_files(
                details.signcert,
                details.pkey,
                details.algorithm,
                Some(details.tsa_url),
            )?,
            &format,
            &mut File::open(&details.asset)?,
            &mut io::empty(),
        )?;
        let actual_json_manifest =
            Reader::from_stream(&format, &mut expected_c2pa_manifest)?.json();

        assert_eq!(expected_json_manifest, actual_json_manifest);
        assert_eq!(expected_c2pa_manifest.into_inner(), actual_c2pa_manifest);
    }

    Ok(())
}
