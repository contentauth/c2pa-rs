// Copyright 2022 Adobe. All rights reserved.
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

mod common;

use std::fs::{self, File};

use anyhow::Result;
use c2pa::Reader;
use common::{cli, test_img_path, TEST_IMAGE_WITH_MANIFEST_FORMAT};
use insta::assert_json_snapshot;
use insta_cmd::assert_cmd_snapshot;

use crate::common::unescape_json;

#[test]
fn test_extract_manifest() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path().join("test_extract_manifest.json");

    assert_cmd_snapshot!(cli()
        .arg("extract")
        .arg("manifest")
        .arg(test_img_path())
        .arg("--output")
        .arg(&output_path));

    assert_json_snapshot!(unescape_json(&fs::read_to_string(&output_path)?)?);

    Ok(())
}

#[test]
fn test_extract_manifest_binary() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path().join("manifest_data.c2pa");

    assert_cmd_snapshot!(cli()
        .arg("extract")
        .arg("manifest")
        .arg(test_img_path())
        .arg("--output")
        .arg(&output_path)
        .arg("--binary"));

    assert_json_snapshot!(unescape_json(
        &Reader::from_manifest_data_and_stream(
            &fs::read(&output_path)?,
            TEST_IMAGE_WITH_MANIFEST_FORMAT,
            &File::open(test_img_path())?
        )?
        .json()
    )?);

    Ok(())
}

#[test]
fn test_extract_ingredient() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path().join("ingredient.json");

    assert_cmd_snapshot!(cli()
        .arg("extract")
        .arg("ingredient")
        .arg(test_img_path())
        .arg("--output")
        .arg(&output_path));

    assert_json_snapshot!(
        unescape_json(&fs::read_to_string(&output_path)?)?, {
        ".instance_id" => "[XMP_ID]"
    });

    Ok(())
}

#[test]
fn test_extract_resources() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path();

    assert_cmd_snapshot!(cli()
        .arg("extract")
        .arg("resources")
        .arg(test_img_path())
        .arg("--output")
        .arg(output_path)
        .arg("--force"));

    // TODO: convert resources file tree to json and assert snapshot

    Ok(())
}
