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

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use c2pa::{identity::validator::CawgValidator, Error, Ingredient, Reader};
#[cfg(not(target_os = "wasi"))]
use tokio::runtime::Runtime;
#[cfg(target_os = "wasi")]
use wstd::runtime::block_on;

/// Convert certain SDK errors to user-friendly messages.
pub fn special_errs(e: Error) -> anyhow::Error {
    match e {
        Error::JumbfNotFound => anyhow!("No claim found"),
        Error::FileNotFound(name) => anyhow!("File not found: {name}"),
        Error::UnsupportedType => anyhow!("Unsupported file type"),
        Error::XmpNotSupported => {
            anyhow!("Format does not support XMP; cannot embed a remote URL reference")
        }
        Error::PrereleaseError => anyhow!("Prerelease claim found"),
        _ => e.into(),
    }
}

/// Normalize file extensions for comparison (case-insensitive, jpeg→jpg, tiff→tif).
pub fn ext_normal(path: &Path) -> String {
    let ext = path
        .extension()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .to_lowercase();
    match ext.as_str() {
        "jpeg" => "jpg".to_string(),
        "tiff" => "tif".to_string(),
        _ => ext,
    }
}

/// Load an ingredient from a file, directory (containing ingredient.json), or JSON file.
pub fn load_ingredient(path: &Path) -> Result<Ingredient> {
    let mut path_buf = PathBuf::from(path);
    let path = if path.is_dir() {
        path_buf = path_buf.join("ingredient.json");
        path_buf.as_path()
    } else {
        path
    };
    if path.extension() == Some(std::ffi::OsStr::new("json")) {
        let json = std::fs::read_to_string(path)?;
        let mut ingredient: Ingredient = serde_json::from_slice(json.as_bytes())?;
        if let Some(base) = path.parent() {
            ingredient.resources_mut().set_base_path(base);
        }
        Ok(ingredient)
    } else {
        #[allow(deprecated)]
        Ok(Ingredient::from_file(path)?)
    }
}

/// Run CAWG post-validation asynchronously.
pub fn validate_cawg(reader: &mut Reader) -> Result<()> {
    #[cfg(not(target_os = "wasi"))]
    {
        Runtime::new()?
            .block_on(reader.post_validate_async(&CawgValidator {}))
            .map_err(anyhow::Error::from)
    }
    #[cfg(target_os = "wasi")]
    {
        block_on(reader.post_validate_async(&CawgValidator {})).map_err(anyhow::Error::from)
    }
}
