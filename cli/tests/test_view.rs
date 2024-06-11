mod common;

use common::{cmd, test_img_path};
use insta_cmd::assert_cmd_snapshot;

#[test]
fn test_view_manifest() {
    assert_cmd_snapshot!(cmd().arg("view").arg("manifest").arg(test_img_path()));
}

// TODO: https://github.com/mitsuhiko/insta-cmd/issues/15
#[test]
fn test_view_manifest_debug() {
    // assert_cmd_snapshot!(cmd()
    //     .arg("view")
    //     .arg("manifest")
    //     .arg("--debug")
    //     .arg(test_img_path()));
}

// TODO: https://github.com/mitsuhiko/insta-cmd/issues/15
#[test]
fn test_view_ingredient() {
    // assert_cmd_snapshot!(cmd().arg("view").arg("ingredient").arg(test_img_path()));
}

#[test]
fn test_view_info() {
    assert_cmd_snapshot!(cmd().arg("view").arg("info").arg(test_img_path()));
}

#[test]
fn test_view_manifest_info() {
    assert_cmd_snapshot!(cmd().arg("view").arg("tree").arg(test_img_path()));
}

// TODO: https://github.com/mitsuhiko/insta-cmd/issues/15
#[test]
fn test_view_manifest_certs() {
    // let mut binding = cmd();
    // let mut cmd = binding.arg("view").arg("certs").arg(test_img_path());
    // assert_cmd_snapshot!(cmd);
}
