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

use std::{error::Error, fs, fs::create_dir_all, path::PathBuf, process::Command};

// Add methods on commands
use assert_cmd::prelude::*;
use httpmock::{prelude::*, Mock};
use predicate::str;
use predicates::prelude::*;
use serde_json::Value;

const TEST_IMAGE: &str = "earth_apollo17.jpg";
//const TEST_IMAGE: &str = "libpng-test.png"; // save for png testing
const TEST_IMAGE_WITH_MANIFEST: &str = "C.jpg"; // save for manifest tests

fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(name);
    fs::canonicalize(path).expect("canonicalize")
}

fn temp_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    create_dir_all(&path).ok();
    path.join(name)
}

#[test]
fn tool_not_found() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("c2patool")?;
    cmd.arg("test/file/notfound.jpg");
    cmd.assert().failure().stderr(str::contains("os error"));
    Ok(())
}

#[test]
fn tool_not_found_info() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("c2patool")?;
    cmd.arg("test/file/notfound.jpg").arg("--info");
    cmd.assert()
        .failure()
        .stderr(str::contains("file not found"));
    Ok(())
}

#[test]
fn tool_jpeg_no_report() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("c2patool")?;
    cmd.arg(fixture_path(TEST_IMAGE));
    cmd.assert()
        .failure()
        .stderr(str::contains("No claim found"));
    Ok(())
}

#[test]
fn tool_info() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("c2patool")?;
    cmd.arg(fixture_path("C.jpg")).arg("--info");
    cmd.assert()
        .success()
        .stdout(str::contains("Validated\nOne manifest"));
    Ok(())
}

#[test]
fn tool_embed_jpeg_report() -> Result<(), Box<dyn Error>> {
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE))
        .arg("-m")
        .arg("sample/test.json")
        .arg("-p")
        .arg(fixture_path(TEST_IMAGE))
        .arg("-o")
        .arg(temp_path("out.jpg"))
        .arg("-f")
        .assert()
        .success() // should this be a failure?
        .stdout(str::contains("My Title"));
    Ok(())
}

#[test]
fn tool_fs_output_report() -> Result<(), Box<dyn Error>> {
    let path = temp_path("output_dir");
    Command::cargo_bin("c2patool")?
        .arg(fixture_path("verify.jpeg"))
        .arg("-o")
        .arg(&path)
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains(format!(
            "Manifest report written to the directory {path:?}"
        )));

    let manifest_json = path.join("manifest_store.json");

    let contents = fs::read_to_string(manifest_json)?;
    let json: Value = serde_json::from_str(&contents)?;
    assert_eq!(
        json.as_object()
            .unwrap()
            .get("active_manifest")
            .unwrap()
            .as_str()
            .unwrap(),
        "adobe:urn:uuid:df1d2745-5beb-4d6c-bd99-3527e29c7df0",
    );

    Ok(())
}

#[test]
fn tool_fs_output_report_supports_detailed_flag() -> Result<(), Box<dyn Error>> {
    let path = temp_path("./output_detailed");
    Command::cargo_bin("c2patool")?
        .arg(fixture_path("verify.jpeg"))
        .arg("-o")
        .arg(&path)
        .arg("-f")
        .arg("-d")
        .assert()
        .success()
        .stdout(str::contains(format!(
            "Manifest report written to the directory {path:?}"
        )));

    let manifest_json = path.join("detailed.json");
    let contents = fs::read_to_string(manifest_json)?;

    let json: Value = serde_json::from_str(&contents)?;
    assert!(json.as_object().unwrap().get("validation_status").is_some());

    Ok(())
}

#[test]
fn tool_fs_output_fails_when_output_exists() -> Result<(), Box<dyn Error>> {
    let path = temp_path("./output_conflict");
    // Create conflict directory.
    create_dir_all(&path)?;
    Command::cargo_bin("c2patool")?
        .arg(fixture_path("C.jpg"))
        .arg("-o")
        .arg(&path)
        .assert()
        .failure()
        .stderr(str::contains(
            "Error: Output already exists, use -f/force to force write",
        ));
    Ok(())
}

#[test]
// c2patool tests/fixtures/C.jpg -fo target/tmp/manifest_test
fn tool_test_manifest_folder() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = temp_path("manifest_test");
    // first export a c2pa file
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("-o")
        .arg(&out_path)
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("Manifest report written"));
    // then read it back in
    let json =
        std::fs::read_to_string(out_path.join("manifest_store.json")).expect("read manifest");
    assert!(json.contains("make_test_images"));
    Ok(())
}

#[test]
// c2patool tests/fixtures/C.jpg -ifo target/tmp/ingredient_test
fn tool_test_ingredient_folder() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = temp_path("ingredient_test");
    // first export a c2pa file
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("-o")
        .arg(&out_path)
        .arg("--ingredient")
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("Ingredient report written"));
    // then read it back in
    let json = std::fs::read_to_string(out_path.join("ingredient.json")).expect("read manifest");
    assert!(json.contains("manifest_data"));
    Ok(())
}

#[test]
// c2patool tests/fixtures/C.jpg -ifo target/tmp/ingredient_json
// c2patool tests/fixtures/earth_apollo17.jpg -m sample/test.json -p target/tmp/ingredient_json/ingredient.json -fo target/tmp/out_2.jpg
fn tool_test_manifest_ingredient_json() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = temp_path("ingredient_json");
    // first export a c2pa file
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
        .arg("-o")
        .arg(&out_path)
        .arg("--ingredient")
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("Ingredient report written"));

    let json_path = out_path.join("ingredient.json");

    let parent = json_path.to_string_lossy().to_string();
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE))
        .arg("-p")
        .arg(parent)
        .arg("-m")
        .arg("sample/test.json")
        .arg("-o")
        .arg(temp_path("out_2.jpg"))
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("My Title"));
    Ok(())
}

#[test]
// c2patool tests/fixtures/earth_apollo17.jpg -m tests/fixtures/ingredient_test.json -fo target/tmp/ingredients.jpg
fn tool_embed_jpeg_with_ingredients_report() -> Result<(), Box<dyn Error>> {
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE))
        .arg("-m")
        .arg(fixture_path("ingredient_test.json"))
        .arg("-o")
        .arg(temp_path("ingredients.jpg"))
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("ingredients.jpg"))
        .stdout(str::contains("test ingredient"))
        .stdout(str::contains("temporal"))
        .stdout(str::contains("earth_apollo17.jpg"));
    Ok(())
}

#[test]
fn tool_extensions_do_not_match() -> Result<(), Box<dyn Error>> {
    let path = temp_path("./foo.png");
    Command::cargo_bin("c2patool")?
        .arg(fixture_path("C.jpg"))
        .arg("-m")
        .arg(fixture_path("ingredient_test.json"))
        .arg("-o")
        .arg(&path)
        .assert()
        .failure()
        .stderr(str::contains("Output type must match source type"));
    Ok(())
}

#[test]
fn tool_similar_extensions_match() -> Result<(), Box<dyn Error>> {
    let path = temp_path("./similar.JpEg");

    Command::cargo_bin("c2patool")?
        .arg(fixture_path("C.jpg"))
        .arg("-m")
        .arg(fixture_path("ingredient_test.json"))
        .arg("-o")
        .arg(&path)
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("similar."));
    Ok(())
}

#[test]
fn tool_fail_if_thumbnail_missing() -> Result<(), Box<dyn Error>> {
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE))
        .arg("-c")
        .arg("{\"thumbnail\": {\"identifier\": \"thumb.jpg\",\"format\": \"image/jpeg\"}}")
        .arg("-o")
        .arg(temp_path("out_thumb.jpg"))
        .arg("-f")
        .assert()
        .failure()
        .stderr(str::contains("resource not found"));
    Ok(())
}

#[test]
fn test_succeed_using_example_signer() -> Result<(), Box<dyn Error>> {
    let output = temp_path("./output_external.jpg");

    // We are calling a cargo/bin here that successfully signs claim bytes. We are using
    // a cargo/bin because it works on all OSs, we like Rust, and our example external signing
    // code is compiled and verified during every test of this project.
    let mut successful_process = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    successful_process.push("target/debug/signer-path-success");

    Command::cargo_bin("c2patool")?
        .arg(fixture_path("earth_apollo17.jpg"))
        .arg("--signer-path")
        .arg(&successful_process)
        .arg("--reserve-size")
        .arg("20248")
        .arg("--manifest")
        .arg("sample/test.json")
        .arg("-o")
        .arg(&output)
        .arg("-f")
        .assert()
        .success();

    Ok(())
}

#[test]
fn test_fails_for_not_found_external_signer() -> Result<(), Box<dyn Error>> {
    let output = temp_path("./output_external.jpg");

    Command::cargo_bin("c2patool")?
        .arg(fixture_path("earth_apollo17.jpg"))
        .arg("--signer-path")
        .arg("./executable-not-found-test")
        .arg("--reserve-size")
        .arg("10248")
        .arg("--manifest")
        .arg("sample/test.json")
        .arg("-o")
        .arg(&output)
        .arg("-f")
        .assert()
        .stderr(str::contains("Failed to run command at"))
        .failure();

    Ok(())
}

#[test]
fn test_fails_for_external_signer_failure() -> Result<(), Box<dyn Error>> {
    let output = temp_path("./output_external.jpg");

    let mut failing_process = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    failing_process.push("target/debug/signer-path-fail");

    Command::cargo_bin("c2patool")?
        .arg(fixture_path("earth_apollo17.jpg"))
        .arg("--signer-path")
        .arg(&failing_process)
        .arg("--reserve-size")
        .arg("20248")
        .arg("--manifest")
        .arg("sample/test.json")
        .arg("-o")
        .arg(&output)
        .arg("-f")
        .assert()
        .stderr(str::contains("User supplied signer process failed"))
        // Ensures stderr from user executable is revealed to client.
        .stderr(str::contains("signer-path-fail-stderr"))
        .failure();

    Ok(())
}

#[test]
fn test_fails_for_external_signer_success_without_stdout() -> Result<(), Box<dyn Error>> {
    let output = temp_path("./output_external.jpg");

    let mut failing_process = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    failing_process.push("target/debug/signer-path-no-stdout");

    Command::cargo_bin("c2patool")?
        .arg(fixture_path("earth_apollo17.jpg"))
        .arg("--signer-path")
        .arg(&failing_process)
        .arg("--reserve-size")
        .arg("10248")
        .arg("--manifest")
        .arg("sample/test.json")
        .arg("-o")
        .arg(&output)
        .arg("-f")
        .assert()
        .stderr(str::contains("User supplied process succeeded, but the external process did not write signature bytes to stdout"))
        .failure();

    Ok(())
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
