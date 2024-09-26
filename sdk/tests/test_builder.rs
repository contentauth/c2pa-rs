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

use std::io::{self, Cursor};

use c2pa::{Builder, Result};

mod common;
use common::{compare_stream_to_known_good, fixtures_path, test_signer};

#[test]
fn test_builder_ca_jpg() -> Result<()> {
    let manifest_def = std::fs::read_to_string(fixtures_path("simple_manifest.json"))?;
    let mut builder = Builder::from_json(&manifest_def)?;

    const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);

    let mut dest = Cursor::new(Vec::new());

    builder.sign(&test_signer(), format, &mut source, &mut dest)?;

    // dest.set_position(0);
    // let path = common::known_good_path("CA_test.json");
    // let reader = c2pa::Reader::from_stream(format, &mut dest)?;
    // std::fs::write(path, reader.json())?;

    dest.set_position(0);
    compare_stream_to_known_good(&mut dest, format, "CA_test.json")
}

// Source: https://github.com/contentauth/c2pa-rs/issues/530
#[test]
fn test_builder_riff() -> Result<()> {
    let manifest_def = include_str!("../tests/fixtures/simple_manifest.json");
    let mut source = Cursor::new(include_bytes!("fixtures/sample1.wav"));
    let format = "audio/wav";

    let mut builder = Builder::from_json(manifest_def)?;
    builder.no_embed = true;
    builder.sign(&test_signer(), format, &mut source, &mut io::empty())?;

    Ok(())
}
