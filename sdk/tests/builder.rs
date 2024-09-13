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

use c2pa::{Builder, Reader, Result};

mod common;
use common::{test_signer, unescape_json};
use insta::assert_json_snapshot;

#[test]
fn test_builder_read() -> Result<()> {
    let manifest_def = include_str!("../tests/fixtures/simple_manifest.json");
    let mut builder = Builder::from_json(manifest_def)?;

    let format = "image/jpeg";
    let mut source = Cursor::new(include_bytes!("fixtures/CA.jpg"));

    let mut dest = Cursor::new(Vec::new());
    builder.sign(&test_signer(), format, &mut source, &mut dest)?;

    apply_filters!();
    assert_json_snapshot!(unescape_json(
        &Reader::from_stream(format, &mut dest)?.json()
    )?);

    Ok(())
}

#[test]
fn test_builder_archive() -> Result<()> {
    let manifest_def = include_str!("../tests/fixtures/simple_manifest.json");
    let mut builder = Builder::from_json(manifest_def)?;

    let mut dest = Cursor::new(Vec::new());
    builder.to_archive(&mut dest)?;

    let builder = Builder::from_archive(dest)?;

    apply_filters!();
    assert_json_snapshot!(builder);

    Ok(())
}

// Source: https://github.com/contentauth/c2pa-rs/issues/528
#[test]
fn test_builder_read_empty_stream() -> Result<()> {
    let manifest_def = include_str!("../tests/fixtures/simple_manifest.json");
    let mut source = Cursor::new(include_bytes!("fixtures/sample1.svg"));
    let format = "image/svg+xml";

    let mut builder = Builder::from_json(manifest_def)?;
    let manifest_bytes = builder.sign(&test_signer(), format, &mut source, &mut io::empty())?;

    Reader::from_manifest_data_and_stream(&manifest_bytes, format, Cursor::new(vec![]))?;

    Ok(())
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

#[test]
fn test_builder_jpeg() -> Result<()> {
    let manifest_def = include_str!("../tests/fixtures/simple_manifest.json");
    let mut source = Cursor::new(include_bytes!("fixtures/CA.jpg"));
    //let mut source = std::fs::File::open("tests/fixtures/CA.jpg")?;
    let format = "image/jpeg";

    let mut builder = Builder::from_json(manifest_def)?;
    let start = std::time::Instant::now();
    builder.sign(&test_signer(), format, &mut source, &mut io::empty())?;
    let duration = start.elapsed();
    println!("test_builder_riff took: {:?}", duration);

    Ok(())
}
