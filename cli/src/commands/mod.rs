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

pub mod config;
pub mod fragment;
pub mod ingredient;
pub mod resume;
pub mod show;
pub mod sign;

use std::{
    fs::{copy, remove_file, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use c2pa::{
    format_from_path, identity::validator::CawgValidator, Builder, Ingredient, Reader, Signer,
};
use serde::Deserialize;
use tempfile::NamedTempFile;
#[cfg(not(target_os = "wasi"))]
use tokio::runtime::Runtime;
#[cfg(target_os = "wasi")]
use wstd::runtime::block_on;

use crate::signer::SignConfig;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ManifestDef {
    #[allow(dead_code)]
    #[serde(flatten)]
    pub manifest: c2pa::ManifestDefinition,
    pub ingredient_paths: Option<Vec<PathBuf>>,
}

pub(crate) fn special_errs(e: c2pa::Error) -> anyhow::Error {
    match e {
        c2pa::Error::JumbfNotFound => anyhow::anyhow!("No claim found"),
        c2pa::Error::FileNotFound(name) => anyhow::anyhow!("File not found: {name}"),
        c2pa::Error::UnsupportedType => anyhow::anyhow!("Unsupported file type"),
        c2pa::Error::PrereleaseError => anyhow::anyhow!("Prerelease claim found"),
        _ => e.into(),
    }
}

pub(crate) fn ext_normal(path: &Path) -> String {
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

pub(crate) fn load_ingredient(path: &Path) -> Result<Ingredient> {
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
        Ok(Ingredient::from_file(path)?)
    }
}

pub(crate) fn validate_cawg(reader: &mut Reader) -> Result<()> {
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

/// Read manifest JSON from a file path or inline string, returning the JSON and base path.
pub(crate) fn load_manifest_json(
    manifest: Option<&PathBuf>,
    manifest_json: Option<&String>,
) -> Result<(String, Option<PathBuf>)> {
    match manifest {
        Some(manifest_path) => {
            let base_path = std::fs::canonicalize(manifest_path)?
                .parent()
                .map(|p| p.to_path_buf());
            Ok((std::fs::read_to_string(manifest_path)?, base_path))
        }
        None => Ok((
            manifest_json.cloned().unwrap_or_default(),
            std::env::current_dir().ok(),
        )),
    }
}

/// Create a Builder and SignConfig from manifest JSON, with base path applied.
pub(crate) fn create_builder_from_json(
    json: &str,
    base_path: Option<&PathBuf>,
) -> Result<(Builder, SignConfig)> {
    let mut sign_config = SignConfig::from_json(json)?;
    let mut builder = Builder::from_json(json)?;

    if let Some(base) = base_path {
        builder.set_base_path(base);
        sign_config.set_base_path(base);
    }

    Ok((builder, sign_config))
}

/// Add ingredients listed in the manifest definition's `ingredient_paths` field.
pub(crate) fn add_manifest_ingredients(
    builder: &mut Builder,
    json: &str,
    base_path: Option<&PathBuf>,
) -> Result<()> {
    let manifest_def: ManifestDef = serde_json::from_slice(json.as_bytes())?;
    if let Some(paths) = manifest_def.ingredient_paths {
        for mut path in paths {
            if let Some(base) = base_path {
                if !path.is_absolute() {
                    path = base.join(&path);
                }
            }
            let ingredient = load_ingredient(&path)?;
            builder.add_ingredient(ingredient);
        }
    }
    Ok(())
}

/// Add ingredients from command-line paths.
pub(crate) fn add_cli_ingredients(builder: &mut Builder, paths: &[PathBuf]) -> Result<()> {
    for ingredient_path in paths {
        let ingredient = load_ingredient(ingredient_path)?;
        builder.add_ingredient(ingredient);
    }
    Ok(())
}

/// Configure remote URL and sidecar/no-embed options on the builder.
pub(crate) fn configure_remote_sidecar(
    builder: &mut Builder,
    remote: Option<&String>,
    sidecar: bool,
) {
    if let Some(remote_url) = remote {
        builder.set_remote_url(remote_url.clone());
        if sidecar {
            builder.set_no_embed(true);
        }
    } else if sidecar {
        builder.set_no_embed(true);
    }
}

/// Get a signer, trying Settings first, then falling back to SignConfig.
pub(crate) fn get_signer(sign_config: &SignConfig) -> Result<Box<dyn Signer>> {
    match c2pa::settings::Settings::signer() {
        Ok(signer) => Ok(signer),
        Err(c2pa::Error::MissingSignerSettings) => sign_config.signer(),
        Err(err) => Err(err)?,
    }
}

/// Sign and write output, with common output handling.
///
/// Handles force/overwrite checks, signing via `sign_file` (or stream-based
/// `sign` for same-file scenarios), optional sidecar writing, and post-sign
/// validation output.
pub(crate) fn sign_to_output(
    builder: &mut Builder,
    sign_config: &SignConfig,
    input: &Path,
    output: &Path,
    sidecar: bool,
    force: bool,
) -> Result<()> {
    if ext_normal(output) != ext_normal(input) {
        bail!("Output type must match input type");
    }

    if output.exists() && !force {
        bail!("Output already exists; use -f/force to force write");
    }

    let signer = get_signer(sign_config)?;

    let manifest_data = if input == output {
        // Same-file signing: use streams so format is detected from the
        // original path rather than a temp file with no extension.
        let format = format_from_path(input)
            .ok_or(c2pa::Error::UnsupportedType)
            .context("unsupported file type")?;
        let mut source = File::open(input)?;
        let mut temp = NamedTempFile::new()?;

        if builder.definition.title.is_none() {
            if let Some(title) = output.file_name() {
                builder.definition.title = Some(title.to_string_lossy().to_string());
            }
        }

        let manifest_data = builder
            .sign(signer.as_ref(), &format, &mut source, &mut temp)
            .context("embedding manifest")?;

        drop(source);

        if let Some(output_dir) = output.parent() {
            std::fs::create_dir_all(output_dir)?;
        }

        match temp.persist(output) {
            Ok(_) => {}
            Err(e) => {
                copy(e.file, output)?;
            }
        }

        manifest_data
    } else {
        if output.exists() && force {
            remove_file(output)?;
        }
        builder
            .sign_file(signer.as_ref(), input, output)
            .context("embedding manifest")?
    };

    if sidecar {
        let sidecar_path = output.with_extension("c2pa");
        File::create(&sidecar_path)?.write_all(&manifest_data)?;
    }

    let mut reader = Reader::from_file(output).map_err(special_errs)?;
    validate_cawg(&mut reader)?;
    println!("{reader}");

    Ok(())
}

/// Save the builder as an archive file.
pub(crate) fn save_archive(builder: &mut Builder, output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!("Output already exists; use -f/force to force write");
    }
    let mut archive_file = File::create(output)?;
    builder.to_archive(&mut archive_file)?;
    println!("Builder archive saved to: {}", output.display());
    Ok(())
}
