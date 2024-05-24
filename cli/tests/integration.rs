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

use std::{error::Error, fs, path::PathBuf, process::Command};

// Add methods on commands
use assert_cmd::prelude::*;
use httpmock::{prelude::*, Mock};
use predicate::str;
use predicates::prelude::*;

const TEST_IMAGE_WITH_MANIFEST: &str = "C.jpg"; // save for manifest tests

fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(name);
    fs::canonicalize(path).expect("canonicalize")
}

#[test]
// c2patool tests/fixtures/C.jpg trust --trust_anchors=tests/fixtures/trust/anchors.pem --trust_config=tests/fixtures/trust/store.cfg
fn tool_load_trust_settings_from_file_trusted() -> Result<(), Box<dyn Error>> {
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("trust")
        .arg("--trust_anchors")
        .arg(fixture_path("trust/anchors.pem"))
        .arg("--trust_config")
        .arg(fixture_path("trust/store.cfg"))
        .assert()
        .success()
        .stdout(str::contains("C2PA Test Signing Cert"))
        .stdout(str::contains("signingCredential.untrusted").not());
    Ok(())
}

#[test]
// c2patool tests/fixtures/C.jpg trust --trust_anchors=tests/fixtures/trust/no-match.pem --trust_config=tests/fixtures/trust/store.cfg
fn tool_load_trust_settings_from_file_untrusted() -> Result<(), Box<dyn Error>> {
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("trust")
        .arg("--trust_anchors")
        .arg(fixture_path("trust/no-match.pem"))
        .arg("--trust_config")
        .arg(fixture_path("trust/store.cfg"))
        .assert()
        .success()
        .stdout(str::contains("C2PA Test Signing Cert"))
        .stdout(str::contains("signingCredential.untrusted"));
    Ok(())
}

fn create_mock_server<'a>(
    server: &'a MockServer,
    anchor_source: &str,
    config_source: &str,
) -> Vec<Mock<'a>> {
    let anchor_path = fixture_path(anchor_source).to_str().unwrap().to_owned();
    let trust_mock = server.mock(|when, then| {
        when.method(GET).path("/trust/anchors.pem");
        then.status(200)
            .header("content-type", "text/plain")
            .body_from_file(anchor_path);
    });
    let config_path = fixture_path(config_source).to_str().unwrap().to_owned();
    let config_mock = server.mock(|when, then| {
        when.method(GET).path("/trust/store.cfg");
        then.status(200)
            .header("content-type", "text/plain")
            .body_from_file(config_path);
    });

    vec![trust_mock, config_mock]
}

#[test]
fn tool_load_trust_settings_from_url_arg_trusted() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start();
    let mocks = create_mock_server(&server, "trust/anchors.pem", "trust/store.cfg");

    // Test flags
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("trust")
        .arg("--trust_anchors")
        .arg(server.url("/trust/anchors.pem"))
        .arg("--trust_config")
        .arg(server.url("/trust/store.cfg"))
        .assert()
        .success()
        .stdout(str::contains("C2PA Test Signing Cert"))
        .stdout(str::contains("signingCredential.untrusted").not());

    mocks.iter().for_each(|m| m.assert());

    Ok(())
}

#[test]
fn tool_load_trust_settings_from_url_arg_untrusted() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start();
    let mocks = create_mock_server(&server, "trust/no-match.pem", "trust/store.cfg");

    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("trust")
        .arg("--trust_anchors")
        .arg(server.url("/trust/anchors.pem"))
        .arg("--trust_config")
        .arg(server.url("/trust/store.cfg"))
        .assert()
        .success()
        .stdout(str::contains("C2PA Test Signing Cert"))
        .stdout(str::contains("signingCredential.untrusted"));

    mocks.iter().for_each(|m| m.assert());

    Ok(())
}

#[test]
fn tool_load_trust_settings_from_url_env_trusted() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start();
    let mocks = create_mock_server(&server, "trust/anchors.pem", "trust/store.cfg");

    // Test flags
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("trust")
        .env("C2PATOOL_TRUST_ANCHORS", server.url("/trust/anchors.pem"))
        .env("C2PATOOL_TRUST_CONFIG", server.url("/trust/store.cfg"))
        .assert()
        .success()
        .stdout(str::contains("C2PA Test Signing Cert"))
        .stdout(str::contains("signingCredential.untrusted").not());

    mocks.iter().for_each(|m| m.assert());

    Ok(())
}

#[test]
fn tool_load_trust_settings_from_url_env_untrusted() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start();
    let mocks = create_mock_server(&server, "trust/no-match.pem", "trust/store.cfg");

    // Test flags
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("trust")
        .env("C2PATOOL_TRUST_ANCHORS", server.url("/trust/anchors.pem"))
        .env("C2PATOOL_TRUST_CONFIG", server.url("/trust/store.cfg"))
        .assert()
        .success()
        .stdout(str::contains("C2PA Test Signing Cert"))
        .stdout(str::contains("signingCredential.untrusted"));

    mocks.iter().for_each(|m| m.assert());

    Ok(())
}
