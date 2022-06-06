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

// isolate from wasm by wrapping in module
#[cfg(not(target_arch = "wasm32"))]
mod integration {
    use assert_cmd::prelude::*; // Add methods on commands
    use predicates::prelude::*;
    use std::path::PathBuf;
    use std::process::Command;

    const TEST_IMAGE: &str = "earth_apollo17.jpg";
    //const TEST_IMAGE: &str = "libpng-test.png"; // save for png testing
    //const TEST_IMAGE_WITH_MANIFEST: &str = "C.jpg"; // save for manifest tests

    fn fixture_path(name: &str) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../sdk/tests/fixtures");
        path.push(name);
        std::fs::canonicalize(path).expect("canonicalize")
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(&path).ok();
        path.push(name);
        path
    }

    #[test]
    fn tool_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin("c2patool")?;
        cmd.arg("test/file/not.found");
        cmd.assert()
            .failure()
            .stdout(predicate::str::contains("File not found"));
        Ok(())
    }

    #[test]
    fn tool_version_check() {
        // ensure c2patool version matches the toolkit version
        assert_eq!(c2pa::VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn tool_jpeg_no_report() -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::cargo_bin("c2patool")?;
        cmd.arg(fixture_path(TEST_IMAGE));
        cmd.assert()
            .failure()
            .stdout(predicate::str::contains("No claim found"));
        Ok(())
    }

    #[test]
    fn tool_embed_jpeg_report() -> Result<(), Box<dyn std::error::Error>> {
        generate_x509_temp_keys();

        Command::cargo_bin("c2patool")?
            .arg("sample/config.json")
            .arg("-p")
            .arg(fixture_path(TEST_IMAGE))
            .arg("-o")
            .arg(temp_path("out.jpg"))
            .assert()
            .success() // should this be a failure?
            .stdout(predicate::str::contains("My Title"));
        Ok(())
    }

    /* remove this until the c2patool supports .c2pa write again
    #[test]
    fn tool_manifest_report() -> Result<(), Box<dyn std::error::Error>> {
        generate_x509_temp_keys();

        // first export a c2pa file
        Command::cargo_bin("c2patool")?
            .arg(fixture_path(TEST_IMAGE_WITH_MANIFEST))
            .arg("-o")
            .arg(temp_path("manifest.c2pa"))
            .assert()
            .success()
            .stdout(predicate::str::contains("C2PA Testing"));
        // then read it back in
        Command::cargo_bin("c2patool")?
            .arg(temp_path("manifest.c2pa"))
            .assert()
            .success()
            .stdout(predicate::str::contains("C2PA Testing"));
        Ok(())
    }
    */

    fn generate_x509_temp_keys() {
        let mut x509_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        x509_path.pop();
        x509_path.push(".x509");

        std::fs::create_dir_all(&x509_path).expect("Can't create .x509 dir in repo");

        // Test for existence of x509_path.temp_key.pub and .pem.

        let priv_key_path = x509_path.join("temp_key.pem");
        let sign_cert_path = x509_path.join("temp_key.pub");

        if !(priv_key_path.exists() && sign_cert_path.exists()) {
            // Creating the signer (which we don't use) has the side effect of
            // creating temporary private key and signing certificate.
            c2pa::get_temp_signer(&x509_path);
        }
    }
}
