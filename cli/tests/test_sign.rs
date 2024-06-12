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

use anyhow::Result;
use c2pa::ManifestStore;
use common::{cli, fixture_path, test_img_path, unescape_json, TEST_IMAGE_WITH_MANIFEST};
use insta::{assert_json_snapshot, Settings};
use insta_cmd::assert_cmd_snapshot;

#[test]
fn test_sign() -> Result<()> {
    hide_info!();
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

    // The order of the output can be arbitrary, so we sort it beforehand
    // as to not affect the diff.
    let mut settings = Settings::clone_current();
    settings.set_sort_maps(true);
    let _guard = settings.bind_to_scope();

    assert_json_snapshot!(unescape_json(
        &ManifestStore::from_file(output_path)?.to_string()
    )?);

    Ok(())
}
