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

use std::{fs::File, io::Cursor};

use c2pa::{Builder, Reader, Result};

mod common;
use common::{assets::iter_assets, fixtures_path, test_signer, unescape_json};
use insta::{allow_duplicates, assert_json_snapshot};

#[test]
fn test_builder_ca_jpg() -> Result<()> {
    let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::from_json(&manifest_def)?;

    const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());
    builder.sign(&test_signer(), format, &mut source, &mut dest)?;

    apply_filters!();
    assert_json_snapshot!(unescape_json(
        &Reader::from_stream(format, &mut dest)?.json()
    )?);

    Ok(())
}

#[test]
fn test_builder_embed_all_assets() -> Result<()> {
    // TODO: example test that runs on all sample files (seems there's an error in one of them?)
    allow_duplicates! {
        || -> Result<()> {
            for asset in iter_assets() {
                let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;

                let format = infer::get(asset).unwrap().mime_type();
                let mut source = Cursor::new(asset);
                let mut dest = Cursor::new(Vec::new());

                let mut builder = Builder::from_json(&manifest_def)?;
                builder.sign(&test_signer(), format, &mut source, &mut dest)?;

                apply_filters!();
                assert_json_snapshot!(unescape_json(
                    &Reader::from_stream(format, &mut dest)?.json()
                )?, {
                   ".manifests.*.format" => "[FORMAT]",
                });
            }

            Ok(())
        // TODO: https://github.com/mitsuhiko/insta/issues/530
        }().unwrap()
    }

    Ok(())
}
