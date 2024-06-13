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

use std::fs;

use anyhow::Result;
use c2pa::ManifestStore;
use common::{cli, fixture_path, test_img_path, unescape_json, TEST_IMAGE_WITH_MANIFEST};
use insta::{assert_json_snapshot, Settings};
use insta_cmd::assert_cmd_snapshot;

#[test]
fn test_sign() -> Result<()> {
    apply_filters!();

    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path().join(TEST_IMAGE_WITH_MANIFEST);

    assert_cmd_snapshot!(cli()
        .arg("sign")
        .arg(test_img_path())
        .arg("--manifest")
        .arg(fixture_path("ingredient_test.json"))
        .arg("--output")
        .arg(&output_path));

    apply_sorted_output!();

    assert_json_snapshot!(unescape_json(
        &ManifestStore::from_file(output_path)?.to_string()
    )?);

    Ok(())
}

#[test]
fn test_sign_glob() -> Result<()> {
    apply_filters!();

    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path();

    let input_dir = fixture_path("signed-images");
    let input_glob = format!("{}/*", input_dir.to_string_lossy().as_ref());

    assert_cmd_snapshot!(cli()
        .arg("sign")
        .arg(fixture_path(&input_glob))
        .arg("--manifest")
        .arg(fixture_path("ingredient_test.json"))
        .arg("--output")
        .arg(output_path));

    apply_sorted_output!();

    let mut manifest_snapshots = Vec::new();
    for entry in fs::read_dir(input_dir)? {
        let output_path = output_path.join(entry?.file_name());
        manifest_snapshots.push(unescape_json(
            &ManifestStore::from_file(output_path)?.to_string(),
        )?);
    }

    assert_json_snapshot!(manifest_snapshots);

    Ok(())
}

#[test]
fn test_sign_parent() -> Result<()> {
    apply_filters!();

    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path().join(TEST_IMAGE_WITH_MANIFEST);

    assert_cmd_snapshot!(cli()
        .arg("sign")
        .arg(test_img_path())
        .arg("--manifest")
        .arg(fixture_path("ingredient_test.json"))
        .arg("--parent")
        .arg(fixture_path("signed-images").join("verify.jpeg"))
        .arg("--output")
        .arg(&output_path));

    apply_sorted_output!();

    assert_json_snapshot!(unescape_json(
        &ManifestStore::from_file(output_path)?.to_string()
    )?);

    Ok(())
}

#[test]
fn test_sign_sidecar() -> Result<()> {
    apply_filters!();

    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path();

    assert_cmd_snapshot!(cli()
        .arg("sign")
        .arg(test_img_path())
        .arg("--manifest")
        .arg(fixture_path("ingredient_test.json"))
        .arg("--output")
        .arg(output_path)
        .arg("--sidecar"));

    apply_sorted_output!();

    assert_json_snapshot!(unescape_json(
        &ManifestStore::from_file(output_path.join("C.jpg"))?.to_string()
    )?);
    assert_json_snapshot!(unescape_json(
        &ManifestStore::from_file(output_path.join("C.c2pa"))?.to_string()
    )?);

    Ok(())
}
