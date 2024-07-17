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

use std::io::Cursor;

use c2pa::{Builder, Reader, Result};

mod common;
use common::{
    assets::{test_asset_kind, test_asset_kinds, Asset},
    fixtures_path, test_signer, unescape_json,
};
use insta::{allow_duplicates, assert_json_snapshot, Settings};

fn test_asset_io(assets: Vec<Asset>) -> Result<()> {
    allow_duplicates! {
        || -> Result<()> {
            for mut asset in assets {
                // TODO: add module holding json manifests
                let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;

                // TODO: temp, c2pa-rs should infer from signature
                let format = infer::get(&asset.to_bytes()?).unwrap().mime_type();

                let mut dest = Cursor::new(Vec::new());

                let mut builder = Builder::from_json(&manifest_def)?;
                builder.sign(&test_signer(), format, &mut asset, &mut dest)?;

                apply_filters!();
                assert_json_snapshot!(unescape_json(
                    &Reader::from_stream(format, &mut dest)?.json()
                )?, {
                   ".manifests.*.format" => "[FORMAT]",
                });
            }

            Ok(())
        }().unwrap()
    };

    Ok(())
}

#[test]
fn test_asset_io_data_hash() -> Result<()> {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_suffix("data_hash");
    settings.bind(|| {
        test_asset_io(test_asset_kinds(&[
            "jpeg", "png", "riff", "svg", "mp3", "tiff", "gif",
        ])?)
    })
}

#[test]
fn test_asset_io_bmff_hash() -> Result<()> {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_suffix("bmff_hash");
    settings.add_redaction(".manifests.*.assertions.*.data.hash", "[HASH]");
    settings.bind(|| test_asset_io(test_asset_kind("bmff")?))
}

#[test]
fn test_asset_io_box_hash() -> Result<()> {
    Ok(())
}

#[test]
fn test_asset_io_collection_hash() -> Result<()> {
    Ok(())
}
