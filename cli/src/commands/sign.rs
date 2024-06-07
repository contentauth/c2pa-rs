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

use std::{
    env,
    ffi::OsStr,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use c2pa::{Ingredient, Manifest};
use serde::Deserialize;

use crate::{
    callback_signer::{CallbackSigner, CallbackSignerConfig, ExternalProcessRunner},
    commands::{InputSource, Sign},
    load_trust_settings,
    signer::SignConfig,
};

// Add fields that are not part of the standard Manifest
#[derive(Debug, Deserialize)]
struct ExtendedManifest {
    #[serde(flatten)]
    manifest: Manifest,
    // allows adding ingredients with file paths
    ingredient_paths: Option<Vec<PathBuf>>,
}

pub fn sign(config: Sign) -> Result<()> {
    if config.output.exists() && !config.force {
        bail!("Output already exists use `--force` to overwrite")
    }

    load_trust_settings(&config.trust)?;

    let replacement_val = serde_json::Value::Bool(!config.no_verify).to_string();
    let vs = r#"{"verify": { "verify_after_sign": replacement_val } }"#;
    let setting = vs.replace("replacement_val", &replacement_val);

    c2pa::settings::load_settings_from_str(&setting, "json")?;

    // In the c2pa unstable_api we will be able to reuse a lot of this work.
    let input = &config.path;
    for entry in glob::glob(input)? {
        let path = entry?;

        let json = config.manifest.resolve()?;
        // read the signing information from the manifest definition
        let mut sign_config = SignConfig::from_json(&json)?;

        // read the manifest information
        let ext_manifest: ExtendedManifest = serde_json::from_str(&json)?;
        let mut manifest = ext_manifest.manifest;

        // add claim_tool generator so we know this was created using this tool
        let tool_generator = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        manifest.claim_generator = if manifest.claim_generator.starts_with("c2pa/") {
            tool_generator // just replace the default generator
        } else {
            format!("{} {}", manifest.claim_generator, tool_generator)
        };

        let base_path = if let InputSource::Path(ref manifest_path) = config.manifest {
            fs::canonicalize(manifest_path)?
                .parent()
                .map(|p| p.to_path_buf())
                .context("Cannot find manifest parent path")?
        } else {
            env::current_dir()?
        };

        // set manifest base path before ingredients so ingredients can override it
        manifest.with_base_path(&base_path)?;
        sign_config.set_base_path(&base_path);

        // Add any ingredients specified as file paths
        if let Some(paths) = ext_manifest.ingredient_paths {
            for mut path in paths {
                // ingredient paths are relative to the manifest path
                if !path.is_absolute() {
                    path = base_path.join(&path)
                }

                manifest.add_ingredient(load_ingredient(&path)?);
            }
        }

        if let Some(parent_path) = &config.parent {
            manifest.set_parent(load_ingredient(parent_path)?)?;
        }

        // If the source file has a manifest store, and no parent is specified treat the source as a parent.
        // note: This could be treated as an update manifest eventually since the image is the same
        if manifest.parent().is_none() {
            let source_ingredient = Ingredient::from_file(&path)?;
            if source_ingredient.manifest_data().is_some() {
                manifest.set_parent(source_ingredient)?;
            }
        }

        match &config.manifest {
            InputSource::Path(_) => {
                if config.sidecar {
                    manifest.set_sidecar_manifest();
                }
            }
            InputSource::Url(url) => match config.sidecar {
                true => {
                    manifest.set_remote_manifest(url.to_string());
                }
                false => {
                    manifest.set_embedded_manifest_with_remote_ref(url.to_string());
                }
            },
        }

        let signer = match &config.signer_path {
            Some(signer_process_name) => {
                let cb_config = CallbackSignerConfig::new(&sign_config, config.reserve_size)?;

                let process_runner = Box::new(ExternalProcessRunner::new(
                    cb_config.clone(),
                    signer_process_name.to_owned(),
                ));
                let signer = CallbackSigner::new(process_runner, cb_config);

                Box::new(signer)
            }
            None => sign_config.signer()?,
        };

        manifest
            .embed(Path::new(&path), &config.output, signer.as_ref())
            .context("embedding manifest")?;
    }

    Ok(())
}

// loads an ingredient, allowing for a folder or json ingredient
fn load_ingredient(path: &Path) -> Result<Ingredient> {
    if path.extension() == Some(OsStr::new("json")) {
        let reader = BufReader::new(File::open(path)?);
        let mut ingredient: Ingredient = serde_json::from_reader(reader)?;

        if let Some(base) = path.parent() {
            ingredient.resources_mut().set_base_path(base);
        }

        Ok(ingredient)
    } else {
        Ok(Ingredient::from_file(path)?)
    }
}

#[cfg(test)]
pub mod tests {
    // use super::*;

    #[test]
    fn test_sign() {
        // TODO: construct Sign {} and call sign()
    }
}
