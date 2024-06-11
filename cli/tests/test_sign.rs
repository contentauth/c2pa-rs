mod common;

use anyhow::Result;
use c2pa::ManifestStore;
use common::{cmd, fixture_path, test_img_path, unescape_json, TEST_IMAGE_WITH_MANIFEST};
use insta::assert_json_snapshot;
use insta_cmd::assert_cmd_snapshot;

#[test]
fn test_sign() -> Result<()> {
    apply_path_filters!();
    apply_manifest_filters!();

    let tempdir = tempfile::tempdir()?;
    let output_path = tempdir.path().join(TEST_IMAGE_WITH_MANIFEST);

    assert_cmd_snapshot!(cmd()
        .arg("sign")
        .arg(test_img_path())
        .arg("--manifest")
        .arg(fixture_path("ingredient_test.json"))
        .arg("--output")
        .arg(&output_path));

    assert_json_snapshot!(unescape_json(
        &ManifestStore::from_file(output_path)?.to_string()
    )?);

    Ok(())
}
