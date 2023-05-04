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

use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::fs::create_dir_all;
use std::path::PathBuf;
use std::process::Command;

const TEST_IMAGE: &str = "earth_apollo17.jpg";
//const TEST_IMAGE: &str = "libpng-test.png"; // save for png testing
const TEST_IMAGE_WITH_MANIFEST: &str = "C.jpg"; // save for manifest tests

fn fixture_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures");
    path.push(name);
    std::fs::canonicalize(path).expect("canonicalize")
}

fn temp_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&path).ok();
    path.join(name)
}

#[test]
fn tool_not_found() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("c2patool")?;
    cmd.arg("test/file/notfound.jpg");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("os error"));
    Ok(())
}

#[test]
fn tool_not_found_info() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("c2patool")?;
    cmd.arg("test/file/notfound.jpg").arg("--info");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("file not found"));
    Ok(())
}

#[test]
fn tool_jpeg_no_report() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("c2patool")?;
    cmd.arg(fixture_path(TEST_IMAGE));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No claim found"));
    Ok(())
}

#[test]
fn tool_info() -> Result<(), Box<dyn Error>> {
    let mut cmd = Command::cargo_bin("c2patool")?;
    cmd.arg(fixture_path("C.jpg")).arg("--info");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Validated\nOne manifest"));
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
        .stdout(predicate::str::contains("My Title"));
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
        .stdout(predicate::str::contains(format!(
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
        .stdout(predicate::str::contains(format!(
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
        .stderr(predicate::str::contains(
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
        .stdout(predicate::str::contains("Manifest report written"));
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
        .stdout(predicate::str::contains("Ingredient report written"));
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
        .stdout(predicate::str::contains("Ingredient report written"));

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
        .stdout(predicate::str::contains("My Title"));
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
        .stdout(predicate::str::contains("ingredients.jpg"))
        .stdout(predicate::str::contains("test ingredient"))
        .stdout(predicate::str::contains("earth_apollo17.jpg"));
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
        .stderr(predicate::str::contains(
            "Output type must match source type",
        ));
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
        .stdout(predicate::str::contains("similar."));
    Ok(())
}

#[test]
fn tool_fail_if_thumnail_missing() -> Result<(), Box<dyn Error>> {
    Command::cargo_bin("c2patool")?
        .arg(fixture_path(TEST_IMAGE))
        .arg("-c")
        .arg("{\"thumbnail\": {\"identifier\": \"thumb.jpg\",\"format\": \"image/jpeg\"}}")
        .arg("-o")
        .arg(temp_path("out_thumb.jpg"))
        .arg("-f")
        .assert()
        .failure()
        .stderr(predicate::str::contains("resource not found"));
    Ok(())
}
