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

#![cfg(not(target_os = "wasi"))]
use std::{
    error::Error,
    fs::{self, create_dir_all},
    path::PathBuf,
};

use assert_cmd::prelude::*;
use std::process::Command;
use predicate::str;
use predicates::prelude::*;
use serde_json::Value;
use tempfile::tempdir;

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

// Helper functions for cleaner tests
fn c2patool() -> Command {
    Command::cargo_bin("c2patool").unwrap()
}

fn show(input: &str) -> Command {
    let mut cmd = c2patool();
    cmd.arg("show").arg(fixture_path(input));
    cmd
}

fn ingredient(input: &str, output: &str) -> Command {
    let mut cmd = c2patool();
    cmd.arg("ingredient")
        .arg(fixture_path(input))
        .arg("-o")
        .arg(temp_path(output));
    cmd
}

fn edit(parent: &str, manifest: &str, output: &str) -> Command {
    let mut cmd = c2patool();
    cmd.arg("edit")
        .arg("--parent")
        .arg(fixture_path(parent))
        .arg("-m")
        .arg(manifest)
        .arg("-o")
        .arg(temp_path(output))
        .arg("-f");
    cmd
}

#[test]
fn tool_not_found() -> Result<(), Box<dyn Error>> {
    c2patool()
        .args(["show", "test/file/notfound.jpg"])
        .assert()
        .failure()
        .stderr(str::contains("os error"));
    Ok(())
}

#[test]
fn tool_not_found_info() -> Result<(), Box<dyn Error>> {
    c2patool()
        .args(["show", "test/file/notfound.jpg", "--info"])
        .assert()
        .failure()
        .stderr(str::contains("file not found"));
    Ok(())
}

#[test]
fn tool_jpeg_no_report() -> Result<(), Box<dyn Error>> {
    show(TEST_IMAGE)
        .assert()
        .failure()
        .stderr(str::contains("No claim found"));
    Ok(())
}

#[test]
// c2patool show tests/fixtures/C.jpg --info
fn tool_info() -> Result<(), Box<dyn Error>> {
    show(TEST_IMAGE_WITH_MANIFEST)
        .arg("--info")
        .assert()
        .success()
        .stdout(str::contains("Provenance URI = self#jumbf=/c2pa/contentauth:urn:uuid:"))
        .stdout(str::contains("Manifest store size = 51217"));
    Ok(())
}

#[test]
fn tool_embed_jpeg_report() -> Result<(), Box<dyn Error>> {
    edit(TEST_IMAGE, "sample/test.json", "out.jpg")
        .assert()
        .success()
        .stdout(str::contains("My Title"));
    Ok(())
}
#[test]
fn tool_fs_output_report() -> Result<(), Box<dyn Error>> {
    let path = temp_path("output_dir");
    show("verify.jpeg")
        .arg("-o").arg(&path)
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains(format!("Manifest report written to the directory {path:?}")));
    
    let manifest_json = path.join("manifest_store.json");
    let json: Value = serde_json::from_str(&fs::read_to_string(manifest_json)?)?;
    assert_eq!(
        json["active_manifest"].as_str().unwrap(),
        "adobe:urn:uuid:df1d2745-5beb-4d6c-bd99-3527e29c7df0"
    );
    Ok(())
}
#[test]
fn tool_fs_output_report_supports_detailed_flag() -> Result<(), Box<dyn Error>> {
    let path = temp_path("./output_detailed");
    show("verify.jpeg")
        .args(["-o", path.to_str().unwrap(), "-f", "-d"])
        .assert()
        .success()
        .stdout(str::contains(format!("Manifest report written to the directory {path:?}")));
    
    let json: Value = serde_json::from_str(&fs::read_to_string(path.join("detailed.json"))?)?;
    assert!(json["validation_results"].is_object());
    Ok(())
}
#[test]
fn tool_fs_output_fails_when_output_exists() -> Result<(), Box<dyn Error>> {
    let path = temp_path("./output_conflict");
    create_dir_all(&path)?;
    
    show("C.jpg")
        .arg("-o").arg(&path)
        .assert()
        .failure()
        .stderr(str::contains("Error: Output already exists; use -f/force to force write"));
    Ok(())
}
#[test]
// c2patool show tests/fixtures/C.jpg -fo target/tmp/manifest_test
fn tool_test_manifest_folder() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = temp_path("manifest_test");
    show(TEST_IMAGE_WITH_MANIFEST)
        .args(["-o", out_path.to_str().unwrap(), "-f"])
        .assert()
        .success()
        .stdout(str::contains("Manifest report written"));
    
    let json = fs::read_to_string(out_path.join("manifest_store.json"))?;
    assert!(json.contains("make_test_images"));
    Ok(())
}

#[test]
// c2patool ingredient tests/fixtures/C.jpg -o target/tmp/ingredient_test --detailed -f
fn tool_test_ingredient_folder() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = temp_path("ingredient_test");
    ingredient(TEST_IMAGE_WITH_MANIFEST, "ingredient_test")
        .arg("--detailed")
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("Ingredient"));
    
    let json = fs::read_to_string(out_path.join("ingredient.json"))?;
    assert!(json.contains("manifest_data"));
    Ok(())
}
#[test]
// c2patool ingredient tests/fixtures/C.jpg -o target/tmp/ingredient_json --detailed -f
// c2patool edit --parent target/tmp/ingredient_json/ingredient.json -m sample/test.json -o target/tmp/out_2.jpg -f
fn tool_test_manifest_ingredient_json() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = temp_path("ingredient_json");
    // first export a c2pa file
    ingredient(TEST_IMAGE_WITH_MANIFEST, "ingredient_json")
        .arg("--detailed")
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("Ingredient"));
    let json_path = out_path.join("ingredient.json");
    let parent = json_path.to_string_lossy().to_string();
    c2patool()
        .arg("edit")
        .arg("--parent")
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
// c2patool edit --parent tests/fixtures/earth_apollo17.jpg -m tests/fixtures/ingredient_test.json -o target/tmp/ingredients.jpg -f
fn tool_embed_jpeg_with_ingredients_report() -> Result<(), Box<dyn Error>> {
    edit(TEST_IMAGE, &fixture_path("ingredient_test.json").to_string_lossy(), "ingredients.jpg")
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
    c2patool()
        .arg("edit")
        .arg("--parent")
        .arg(fixture_path("C.jpg"))
        .arg("-m")
        .arg(fixture_path("ingredient_test.json"))
        .arg("-o")
        .arg(&path)
        .assert()
        .failure()
        .stderr(str::contains("Output type must match"));
    Ok(())
}
#[test]
fn tool_similar_extensions_match() -> Result<(), Box<dyn Error>> {
    let path = temp_path("./similar.JpEg");
    c2patool()
        .arg("edit")
        .arg("--parent")
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
    c2patool()
        .arg("edit")
        .arg("--parent")
        .arg(fixture_path(TEST_IMAGE))
        .arg("--manifest-json")
        .arg("{\"thumbnail\": {\"identifier\": \"thumb.jpg\",\"format\": \"image/jpeg\"}})")
        .arg("-o")
        .arg(temp_path("out_thumb.jpg"))
        .arg("-f")
        .assert()
        .failure()
        .stderr(str::contains("resource not found"));
    Ok(())
}

#[test]
fn tool_sign_to_same_file_with_force() -> Result<(), Box<dyn Error>> {
    let tmp_dir = tempdir()?;
    let file_path = tmp_dir.path().join("same_image.jpg");
    fs::copy(fixture_path(TEST_IMAGE), &file_path)?;

    c2patool()
        .arg("edit")
        .arg("--parent")
        .arg(&file_path)
        .arg("-m")
        .arg(fixture_path("ingredient_test.json"))
        .arg("-o")
        .arg(&file_path)
        .arg("-f")
        .assert()
        .success()
        .stdout(str::contains("same_image.jpg"))
        .stdout(str::contains("test ingredient"))
        .stdout(str::contains("temporal"))
        .stdout(str::contains("earth_apollo17.jpg"));
    Ok(())
}

#[test]
fn tool_sign_to_same_file_no_force() -> Result<(), Box<dyn Error>> {
    let tmp_dir = tempdir()?;
    let file_path = tmp_dir.path().join("same_image.jpg");
    fs::copy(fixture_path(TEST_IMAGE), &file_path)?;

    c2patool()
        .arg("edit")
        .arg("--parent")
        .arg(&file_path)
        .arg("-m")
        .arg(fixture_path("ingredient_test.json"))
        .arg("-o")
        .arg(&file_path)
        .assert()
        .failure()
        .stderr(str::contains(
            "Error: Output already exists; use -f/force to force write",
        ));

    Ok(())
}
// #[test]
// fn test_succeed_using_example_signer() -> Result<(), Box<dyn Error>> {
//     let output = temp_path("./output_external.jpg");
//     // We are calling a cargo/bin here that successfully signs claim bytes. We are using
//     // a cargo/bin because it works on all OSs, we like Rust, and our example external signing
//     // code is compiled and verified during every test of this project.
//     let mut successful_process = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     successful_process.push("target/debug/signer-path-success");
//     Command::cargo_bin("c2patool")?
//         .arg(fixture_path("earth_apollo17.jpg"))
//         .arg("--signer-path")
//         .arg(&successful_process)
//         .arg("--reserve-size")
//         .arg("20248")
//         .arg("--manifest")
//         .arg("sample/test.json")
//         .arg("-o")
//         .arg(&output)
//         .arg("-f")
//         .assert()
//         .success();
//     Ok(())
// }
// #[test]
// fn test_fails_for_not_found_external_signer() -> Result<(), Box<dyn Error>> {
//     let output = temp_path("./output_external.jpg");
//     Command::cargo_bin("c2patool")?
//         .arg(fixture_path("earth_apollo17.jpg"))
//         .arg("--signer-path")
//         .arg("./executable-not-found-test")
//         .arg("--reserve-size")
//         .arg("10248")
//         .arg("--manifest")
//         .arg("sample/test.json")
//         .arg("-o")
//         .arg(&output)
//         .arg("-f")
//         .assert()
//         .stderr(str::contains("Failed to run command at"))
//         .failure();
//     Ok(())
// }
// #[test]
// fn test_fails_for_external_signer_failure() -> Result<(), Box<dyn Error>> {
//     let output = temp_path("./output_external.jpg");
//     let mut failing_process = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     failing_process.push("target/debug/signer-path-fail");
//     Command::cargo_bin("c2patool")?
//         .arg(fixture_path("earth_apollo17.jpg"))
//         .arg("--signer-path")
//         .arg(&failing_process)
//         .arg("--reserve-size")
//         .arg("20248")
//         .arg("--manifest")
//         .arg("sample/test.json")
//         .arg("-o")
//         .arg(&output)
//         .arg("-f")
//         .assert()
//         .stderr(str::contains("User supplied signer process failed"))
//         // Ensures stderr from user executable is revealed to client.
//         .stderr(str::contains("signer-path-fail-stderr"))
//         .failure();
//     Ok(())
// }
// #[test]
// fn test_fails_for_external_signer_success_without_stdout() -> Result<(), Box<dyn Error>> {
//     let output = temp_path("./output_external.jpg");
//     let mut failing_process = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//     failing_process.push("target/debug/signer-path-no-stdout");
//     Command::cargo_bin("c2patool")?
//         .arg(fixture_path("earth_apollo17.jpg"))
//         .arg("--signer-path")
//         .arg(&failing_process)
//         .arg("--reserve-size")
//         .arg("10248")
//         .arg("--manifest")
//         .arg("sample/test.json")
//         .arg("-o")
//         .arg(&output)
//         .arg("-f")
//         .assert()
//         .stderr(str::contains("User supplied process succeeded, but the external process did not write signature bytes to stdout"))
//         .failure();
//     Ok(())
// }

// Trust tests commented out - trust is now configured via settings file instead of command line
// #[test]
// // c2patool tests/fixtures/C.jpg trust --trust_anchors=tests/fixtures/trust/anchors.pem --trust_config=tests/fixtures/trust/store.cfg
// fn tool_load_trust_settings_from_file_trusted() -> Result<(), Box<dyn Error>> {
//     Command::new(cargo::cargo_bin!("c2patool"))
//         .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
//         .arg("trust")
//         .arg("--trust_anchors")
//         .arg(fixture_path("trust/anchors.pem"))
//         .arg("--trust_config")
//         .arg(fixture_path("trust/store.cfg"))
//         .assert()
//         .success()
//         .stdout(str::contains("C2PA Test Signing Cert"))
//         .stdout(str::contains("signingCredential.untrusted").not());
//     Ok(())
// }

// #[test]
// // c2patool tests/fixtures/C.jpg trust --trust_anchors=tests/fixtures/trust/no-match.pem --trust_config=tests/fixtures/trust/store.cfg
// fn tool_load_trust_settings_from_file_untrusted() -> Result<(), Box<dyn Error>> {
//     Command::new(cargo::cargo_bin!("c2patool"))
//         .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
//         .arg("trust")
//         .arg("--trust_anchors")
//         .arg(fixture_path("trust/no-match.pem"))
//         .arg("--trust_config")
//         .arg(fixture_path("trust/store.cfg"))
//         .assert()
//         .success()
//         .stdout(str::contains("C2PA Test Signing Cert"))
//         .stdout(str::contains("signingCredential.untrusted"));
//     Ok(())
// }

// fn create_mock_server<'a>(
//     server: &'a MockServer,
//     anchor_source: &str,
//     config_source: &str,
// ) -> Vec<Mock<'a>> {
//     let anchor_path = fixture_path(anchor_source).to_str().unwrap().to_owned();
//     let trust_mock = server.mock(|when, then| {
//         when.method(GET).path("/trust/anchors.pem");
//         then.status(200)
//             .header("content-type", "text/plain")
//             .body_from_file(anchor_path);
//     });
//     let config_path = fixture_path(config_source).to_str().unwrap().to_owned();
//     let config_mock = server.mock(|when, then| {
//         when.method(GET).path("/trust/store.cfg");
//         then.status(200)
//             .header("content-type", "text/plain")
//             .body_from_file(config_path);
//     });
//
//     vec![trust_mock, config_mock]
// }

// #[test]
// fn tool_load_trust_settings_from_url_arg_trusted() -> Result<(), Box<dyn Error>> {
//     let server = MockServer::start();
//     let mocks = create_mock_server(&server, "trust/anchors.pem", "trust/store.cfg");
//
//     // Test flags
//     Command::new(cargo::cargo_bin!("c2patool"))
//         .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
//         .arg("trust")
//         .arg("--trust_anchors")
//         .arg(server.url("/trust/anchors.pem"))
//         .arg("--trust_config")
//         .arg(server.url("/trust/store.cfg"))
//         .assert()
//         .success()
//         .stdout(str::contains("C2PA Test Signing Cert"))
//         .stdout(str::contains("signingCredential.untrusted").not());
//
//     mocks.iter().for_each(|m| m.assert());
//
//     Ok(())
// }

// #[test]
// fn tool_load_trust_settings_from_url_arg_untrusted() -> Result<(), Box<dyn Error>> {
//     let server = MockServer::start();
//     let mocks = create_mock_server(&server, "trust/no-match.pem", "trust/store.cfg");
//
//     Command::new(cargo::cargo_bin!("c2patool"))
//         .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
//         .arg("trust")
//         .arg("--trust_anchors")
//         .arg(server.url("/trust/anchors.pem"))
//         .arg("--trust_config")
//         .arg(server.url("/trust/store.cfg"))
//         .assert()
//         .success()
//         .stdout(str::contains("C2PA Test Signing Cert"))
//         .stdout(str::contains("signingCredential.untrusted"));
//
//     mocks.iter().for_each(|m| m.assert());
//
//     Ok(())
// }

// #[test]
// fn tool_load_trust_settings_from_url_env_trusted() -> Result<(), Box<dyn Error>> {
//     let server = MockServer::start();
//     let mocks = create_mock_server(&server, "trust/anchors.pem", "trust/store.cfg");
//
//     // Test flags
//     Command::new(cargo::cargo_bin!("c2patool"))
//         .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
//         .arg("trust")
//         .env("C2PATOOL_TRUST_ANCHORS", server.url("/trust/anchors.pem"))
//         .env("C2PATOOL_TRUST_CONFIG", server.url("/trust/store.cfg"))
//         .assert()
//         .success()
//         .stdout(str::contains("C2PA Test Signing Cert"))
//         .stdout(str::contains("signingCredential.untrusted").not());
//
//     mocks.iter().for_each(|m| m.assert());
//
//     Ok(())
// }

// #[test]
// fn tool_load_trust_settings_from_url_env_untrusted() -> Result<(), Box<dyn Error>> {
//     let server = MockServer::start();
//     let mocks = create_mock_server(&server, "trust/no-match.pem", "trust/store.cfg");
//
//     // Test flags
//     Command::new(cargo::cargo_bin!("c2patool"))
//         .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
//         .arg("trust")
//         .env("C2PATOOL_TRUST_ANCHORS", server.url("/trust/anchors.pem"))
//         .env("C2PATOOL_TRUST_CONFIG", server.url("/trust/store.cfg"))
//         .assert()
//         .success()
//         .stdout(str::contains("C2PA Test Signing Cert"))
//         .stdout(str::contains("signingCredential.untrusted"));
//
//     mocks.iter().for_each(|m| m.assert());
//
//     Ok(())
// }

#[test]
// c2patool show tests/fixtures/C.jpg --tree
fn tool_tree() -> Result<(), Box<dyn Error>> {
    show(TEST_IMAGE_WITH_MANIFEST)
        .arg("--tree")
        .assert()
        .success()
        .stdout(str::contains("Asset:C.jpg, Manifest:contentauth:urn:uuid:"))
        .stdout(str::contains("Assertion:c2pa.actions"));
    Ok(())
}

#[test]
// c2patool --settings .../trust/cawg_test_settings.toml show C_with_CAWG_data.jpg
fn tool_read_image_with_cawg_data() -> Result<(), Box<dyn Error>> {
    c2patool()
        .arg("--settings")
        .arg(fixture_path("trust/cawg_test_settings.toml"))
        .arg("show")
        .arg(fixture_path("C_with_CAWG_data.jpg"))
        .assert()
        .success()
        .stdout(str::contains("cawg.identity"))
        .stdout(str::contains("c2pa.assertions/cawg.training-mining"))
        .stdout(str::contains("cawg.identity.well-formed"));
    Ok(())
}

#[test]
// c2patool --settings .../trust/cawg_test_settings.toml show --detailed C_with_CAWG_data.jpg
fn tool_read_image_with_details_with_cawg_data() -> Result<(), Box<dyn Error>> {
    c2patool()
        .arg("--settings")
        .arg(fixture_path("trust/cawg_test_settings.toml"))
        .arg("show")
        .arg(fixture_path("C_with_CAWG_data.jpg"))
        .arg("--detailed")
        .assert()
        .success()
        .stdout(str::contains("assertion_store"))
        .stdout(str::contains("cawg.identity"))
        .stdout(str::contains("c2pa.assertions/cawg.training-mining"))
        .stdout(str::contains("cawg.identity.well-formed"));
    Ok(())
}

#[test]
// c2patool --settings .../trust/cawg_sign_settings.toml edit --parent file.jpg -m manifest.json -o output.jpg
fn tool_sign_image_with_cawg_data() -> Result<(), Box<dyn Error>> {
    let tmp_dir = tempdir()?;
    let file_path = tmp_dir.path().join("same_image.jpg");
    fs::copy(fixture_path(TEST_IMAGE), &file_path)?;

    let output_path = tmp_dir.path().join("same_image_cawg_signed.jpg");

    c2patool()
        .arg("--settings")
        .arg(fixture_path("trust/cawg_sign_settings.toml"))
        .arg("edit")
        .arg("--parent")
        .arg(&file_path)
        .arg("-m")
        .arg(fixture_path("ingredient_test.json"))
        .arg("-o")
        .arg(&output_path)
        .arg("-f")
        .assert()
        .success();

    c2patool()
        .arg("--settings")
        .arg(fixture_path("trust/cawg_sign_settings.toml"))
        .arg("show")
        .arg(&output_path)
        .assert()
        .success()
        .stdout(str::contains("cawg.identity"))
        .stdout(str::contains("c2pa.assertions/cawg.training-mining"));
    // .stdout(str::contains("cawg.identity.well-formed"));
    // ^^ Enable this when #1356 lands.
    Ok(())
}
