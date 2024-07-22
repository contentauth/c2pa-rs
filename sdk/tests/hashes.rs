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
use common::{test_signer, unescape_json};
use insta::{allow_duplicates, assert_json_snapshot, Settings};

fn test_hashes(assets: &[(&str, &[u8])]) -> Result<()> {
    allow_duplicates! {
        || -> Result<()> {
            for (format, asset) in assets {
                let manifest_def = include_str!("fixtures/simple_manifest.json");
                let mut asset = Cursor::new(asset);

                let mut dest = Cursor::new(Vec::new());
                let mut builder = Builder::from_json(&manifest_def)?;
                builder.sign(&test_signer(), &format, &mut asset, &mut dest)?;

                apply_filters!();
                assert_json_snapshot!(unescape_json(
                    &Reader::from_stream(&format, &mut dest)?.json()
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
fn test_data_hash() -> Result<()> {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_suffix("data_hash");
    settings.bind(|| {
        test_hashes(&[
            ("image/jpeg", include_bytes!("fixtures/C.jpg")),
            ("image/png", include_bytes!("fixtures/sample1.png")),
            ("image/webp", include_bytes!("fixtures/sample1.webp")),
            ("image/svg+xml", include_bytes!("fixtures/sample1.svg")),
            ("audio/mpeg", include_bytes!("fixtures/sample1.mp3")),
            ("image/tiff", include_bytes!("fixtures/TUSCANY.TIF")),
            ("image/gif", include_bytes!("fixtures/sample1.gif")),
        ])
    })
}

#[test]
fn test_bmff_hash() -> Result<()> {
    let mut settings = Settings::clone_current();
    settings.set_snapshot_suffix("bmff_hash");
    settings.add_redaction(".manifests.*.assertions.*.data.hash", "[HASH]");
    settings.bind(|| test_hashes(&[("video/mp4", include_bytes!("fixtures/video1.mp4"))]))
}

#[test]
fn test_box_hash() -> Result<()> {
    Ok(())
}

#[test]
fn test_collection_hash() -> Result<()> {
    Ok(())
}
