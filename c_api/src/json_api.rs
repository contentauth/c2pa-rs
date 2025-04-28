// Copyright 2023 Adobe. All rights reserved.
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

use c2pa::{Ingredient, Manifest, Reader};
use cawg_identity::validator::CawgValidator;
use tokio::runtime::Runtime;

use crate::{Error, Result, SignerInfo};

/// Returns the version of the c2pa SDK used in this library
pub fn sdk_version() -> String {
    String::from(c2pa::VERSION)
}

/// Returns ManifestStore JSON string from a file path.
///
/// If data_dir is provided, any thumbnail or c2pa data will be written to that folder.
/// Any Validation errors will be reported in the validation_status field.
pub fn read_file(path: &str, data_dir: Option<String>) -> Result<String> {
    let mut reader = Reader::from_file(path).map_err(Error::from_c2pa_error)?;
    let runtime = Runtime::new().map_err(|e| Error::Other(e.to_string()))?;
    runtime
        .block_on(reader.post_validate_async(&CawgValidator {}))
        .map_err(Error::from_c2pa_error)?;
    Ok(if let Some(dir) = data_dir {
        let json = reader.json();
        reader.to_folder(&dir).map_err(Error::from_c2pa_error)?;
        json
    } else {
        reader.json()
    })
}

/// Returns an Ingredient JSON string from a file path.
///
/// Any thumbnail or c2pa data will be written to data_dir if provided
pub fn read_ingredient_file(path: &str, data_dir: &str) -> Result<String> {
    Ok(Ingredient::from_file_with_folder(path, data_dir)
        .map_err(Error::from_c2pa_error)?
        .to_string())
}

/// Adds a manifest to the source file and writes the result to the destination file.
/// Also returns the binary manifest data for optional cloud storage
/// A manifest definition must be supplied
/// Signer information must also be supplied
///
/// Any file paths in the manifest will be read relative to the source file
pub fn sign_file(
    source: &str,
    dest: &str,
    manifest_json: &str,
    signer_info: &SignerInfo,
    data_dir: Option<String>,
) -> Result<Vec<u8>> {
    let mut manifest = Manifest::from_json(manifest_json).map_err(Error::from_c2pa_error)?;

    // if data_dir is provided, set the base path for the manifest
    if let Some(path) = data_dir {
        manifest
            .with_base_path(path)
            .map_err(Error::from_c2pa_error)?;
    }

    // If the source file has a manifest store, and no parent is specified, treat the source's manifest store as the parent.
    if manifest.parent().is_none() {
        let source_ingredient = Ingredient::from_file(source).map_err(Error::from_c2pa_error)?;
        if source_ingredient.manifest_data().is_some() {
            manifest
                .set_parent(source_ingredient)
                .map_err(Error::from_c2pa_error)?;
        }
    }

    let signer = signer_info.signer()?;
    #[allow(deprecated)]
    manifest
        .embed(&source, &dest, &*signer)
        .map_err(Error::from_c2pa_error)
}

#[cfg(test)]
mod tests {
    use std::{fs::remove_dir_all, path::PathBuf};

    use super::*;

    /// returns a path to a file in the fixtures folder
    pub fn test_path(path: &str) -> String {
        let base = env!("CARGO_MANIFEST_DIR");
        format!("{}/../sdk/{}", base, path)
    }

    #[test]
    fn test_verify_from_file_no_base() {
        let path = test_path("tests/fixtures/C.jpg");
        let result = read_file(&path, None);
        assert!(result.is_ok());
        let json_report = result.unwrap();
        println!("{}", json_report);
        assert!(json_report.contains("C.jpg"));
        assert!(!json_report.contains("validation_status"));
    }

    #[test]
    fn test_read_from_file_with_base() {
        let path = test_path("tests/fixtures/C.jpg");
        let data_dir = "../target/data_dir";
        if PathBuf::from(data_dir).exists() {
            remove_dir_all(data_dir).unwrap();
        }
        let result = read_file(&path, Some(data_dir.to_owned()));
        //assert!(result.is_ok());
        let json_report = result.unwrap();
        println!("{}", json_report);
        assert!(json_report.contains("C.jpg"));
        assert!(PathBuf::from(data_dir).exists());
        assert!(json_report.contains("thumbnail"));
    }

    #[test]
    fn test_verify_from_file_cawg_identity() {
        let path = test_path("tests/fixtures/C_with_CAWG_data.jpg");
        let result = read_file(&path, None);
        assert!(result.is_ok());
        let json_report = result.unwrap();
        println!("{}", json_report);
        assert!(json_report.contains("cawg.identity"));
        assert!(json_report.contains("cawg.ica.credential_valid"));
    }
}
