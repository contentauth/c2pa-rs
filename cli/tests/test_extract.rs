mod test_utils;

use std::fs;

use anyhow::Result;
use insta::assert_json_snapshot;
use insta_cmd::assert_cmd_snapshot;
use test_utils::{cmd, test_img_path};

// TODO: ignore path in cmd output
#[test]
fn test_extract_manifest() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path().join("test_extract_manifest.json");

    assert_cmd_snapshot!(cmd()
        .arg("extract")
        .arg("manifest")
        .arg("--output")
        .arg(&output_path)
        .arg(test_img_path()));

    assert_json_snapshot!(fs::read_to_string(&output_path)?);

    Ok(())
}

#[test]
fn test_extract_ingredient() -> Result<()> {
    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path();

    assert_cmd_snapshot!(cmd()
        .arg("extract")
        .arg("ingredient")
        .arg("--output")
        .arg(output_path)
        .arg(test_img_path()));

    assert_json_snapshot!(fs::read_to_string(output_path.join("ingredient.json"))?);
    // TODO: construct manifest from output_path.join("manifest_data.c2pa") and do snapshot

    Ok(())
}
