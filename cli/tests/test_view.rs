mod test_utils;

use insta_cmd::assert_cmd_snapshot;
use test_utils::{cmd, test_img_path};

#[test]
fn test_view_manifest() {
    assert_cmd_snapshot!(cmd().arg("view").arg("manifest").arg(test_img_path()));
}

// TODO: remove variable changing info from output
#[test]
fn test_view_manifest_debug() {
    assert_cmd_snapshot!(cmd()
        .arg("view")
        .arg("manifest")
        .arg("--debug")
        .arg(test_img_path()));
}

// TODO: remove variable changing info from output
#[test]
fn test_view_ingredient() {
    assert_cmd_snapshot!(cmd().arg("view").arg("ingredient").arg(test_img_path()));
}

#[test]
fn test_view_info() {
    assert_cmd_snapshot!(cmd().arg("view").arg("infop").arg(test_img_path()));
}

#[test]
fn test_view_manifest_info() {
    assert_cmd_snapshot!(cmd().arg("view").arg("tree").arg(test_img_path()));
}

// TODO: remove variable changing info from output
#[test]
fn test_view_manifest_certs() {
    assert_cmd_snapshot!(cmd().arg("view").arg("certs").arg(test_img_path()));
}
