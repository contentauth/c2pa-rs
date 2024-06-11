mod common;

use std::fs;

use anyhow::Result;
use c2pa::ManifestStore;
use common::{cmd, test_img_path, unescape_json, TEST_IMAGE_WITH_MANIFEST_FORMAT};
use insta::assert_json_snapshot;
use insta_cmd::assert_cmd_snapshot;

#[test]
fn test_extract_manifest() -> Result<()> {
    apply_path_filters!();

    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path().join("test_extract_manifest.json");

    assert_cmd_snapshot!(cmd()
        .arg("extract")
        .arg("manifest")
        .arg(test_img_path())
        .arg("--output")
        .arg(&output_path));

    assert_json_snapshot!(unescape_json(&fs::read_to_string(&output_path)?)?);

    Ok(())
}

#[test]
fn test_extract_ingredient() -> Result<()> {
    apply_path_filters!();

    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path();

    assert_cmd_snapshot!(cmd()
        .arg("extract")
        .arg("ingredient")
        .arg(test_img_path())
        .arg("--output")
        .arg(output_path));

    assert_json_snapshot!(unescape_json(&fs::read_to_string(
        output_path.join("ingredient.json")
    )?)?, {
        ".instance_id" => "[XMP_ID]"
    });

    assert_json_snapshot!(unescape_json(
        &ManifestStore::from_manifest_and_asset_bytes(
            &fs::read(output_path.join("manifest_data.c2pa"))?,
            TEST_IMAGE_WITH_MANIFEST_FORMAT,
            &fs::read(test_img_path())?
        )?
        .to_string()
    )?);

    Ok(())
}

#[test]
fn test_extract_resourecs() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path();

    assert_cmd_snapshot!(cmd()
        .arg("extract")
        .arg("resources")
        .arg(test_img_path())
        .arg("--output")
        .arg(output_path));

    // TODO: convert resources file tree to json and assert snapshot

    Ok(())
}
