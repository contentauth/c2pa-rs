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

use common::{cli, create_mock_server, fixture_path, test_img_path};
use httpmock::MockServer;
use insta_cmd::assert_cmd_snapshot;

#[test]
fn test_load_trust_from_trusted_file() {
    assert_cmd_snapshot!(cli()
        .arg("view")
        .arg("manifest")
        .arg(test_img_path())
        .arg("--trust-anchors")
        .arg(fixture_path("trust/anchors.pem"))
        .arg("--trust-config")
        .arg(fixture_path("trust/store.cfg")));
}

#[test]
fn test_load_trust_from_untrusted_file() {
    assert_cmd_snapshot!(cli()
        .arg("view")
        .arg("manifest")
        .arg(test_img_path())
        .arg("--trust-anchors")
        .arg(fixture_path("trust/no-match.pem"))
        .arg("--trust-config")
        .arg(fixture_path("trust/store.cfg")));
}

#[test]
fn test_load_trust_from_trusted_url() {
    let server = MockServer::start();
    let mocks = create_mock_server(&server, "trust/anchors.pem", "trust/store.cfg");

    assert_cmd_snapshot!(cli()
        .arg("view")
        .arg("manifest")
        .arg(test_img_path())
        .arg("--trust-anchors")
        .arg(server.url("/trust/anchors.pem"))
        .arg("--trust-config")
        .arg(server.url("/trust/store.cfg")));

    mocks.iter().for_each(|m| m.assert());
}

#[test]
fn test_load_trust_from_untrusted_url() {
    let server = MockServer::start();
    let mocks = create_mock_server(&server, "trust/no-match.pem", "trust/store.cfg");

    assert_cmd_snapshot!(cli()
        .arg("view")
        .arg("manifest")
        .arg(test_img_path())
        .arg("--trust-anchors")
        .arg(server.url("/trust/anchors.pem"))
        .arg("--trust-config")
        .arg(server.url("/trust/store.cfg")));

    mocks.iter().for_each(|m| m.assert());
}

#[test]
fn test_load_trust_from_trusted_url_env() {
    let server = MockServer::start();
    let mocks = create_mock_server(&server, "trust/anchors.pem", "trust/store.cfg");

    assert_cmd_snapshot!(cli()
        .arg("view")
        .arg("manifest")
        .arg(test_img_path())
        .env("C2PATOOL_TRUST_ANCHORS", server.url("/trust/anchors.pem"))
        .env("C2PATOOL_TRUST_CONFIG", server.url("/trust/store.cfg")));

    mocks.iter().for_each(|m| m.assert());
}

#[test]
fn test_load_trust_from_untrusted_url_env() {
    let server = MockServer::start();
    let mocks = create_mock_server(&server, "trust/no-match.pem", "trust/store.cfg");

    assert_cmd_snapshot!(cli()
        .arg("view")
        .arg("manifest")
        .arg(test_img_path())
        .env("C2PATOOL_TRUST_ANCHORS", server.url("/trust/anchors.pem"))
        .env("C2PATOOL_TRUST_CONFIG", server.url("/trust/store.cfg")));

    mocks.iter().for_each(|m| m.assert());
}
