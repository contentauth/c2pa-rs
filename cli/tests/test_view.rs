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
