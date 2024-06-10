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
use clap::Parser;
use serde::Deserialize;

use crate::{
    callback_signer::{CallbackSigner, CallbackSignerConfig, ExternalProcessRunner},
    commands::{InputSource, Trust},
    load_trust_settings,
    signer::SignConfig,
};

#[derive(Debug, Parser)]
pub struct Sign {
    /// Input glob path to asset.
    pub path: String,

    /// Path to output file or folder (if multiple inputs are specified)
    #[clap(short, long)]
    pub output: PathBuf,

    /// Path or URL to manifest JSON.
    #[clap(short, long, value_parser = InputSource::validate)]
    pub manifest: InputSource,

    /// Generate a .c2pa manifest file next to the output without embedding.
    #[clap(short, long)]
    pub sidecar: bool,

    /// Force overwrite of output if it already exists.
    #[clap(short, long)]
    pub force: bool,

    /// Path to the parent ingredient json.
    #[clap(short, long)]
    pub parent: Option<PathBuf>,

    /// Path to an executable that will sign the claim bytes, defaults to built-in signer.
    #[clap(long)]
    pub signer_path: Option<PathBuf>,

    /// To be used with the [callback_signer] argument. This value should equal: 1024 (CoseSign1) +
    /// the size of cert provided in the manifest definition's `sign_cert` field + the size of the
    /// signature of the Time Stamp Authority response. For example:
    ///
    /// The reserve-size can be calculated like this if you aren't including a `tsa_url` key in
    /// your manifest description:
    ///
    ///     1024 + sign_cert.len()
    ///
    /// Or, if you are including a `tsa_url` in your manifest definition, you will calculate the
    /// reserve size like this:
    ///
    ///     1024 + sign_cert.len() + tsa_signature_response.len()
    ///
    /// Note:
    /// We'll default the `reserve-size` to a value of 20_000, if no value is provided. This
    /// will probably leave extra `0`s of unused space. Please specify a reserve-size if possible.
    #[clap(long, default_value("20000"))]
    pub reserve_size: usize,

    /// Do not perform validation of signature after signing.
    #[clap(long)]
    pub no_verify: bool,

    #[clap(flatten)]
    pub trust: Trust,
}

// Add fields that are not part of the standard Manifest
#[derive(Debug, Deserialize)]
struct ExtendedManifest {
    #[serde(flatten)]
    manifest: Manifest,
    // allows adding ingredients with file paths
    ingredient_paths: Option<Vec<PathBuf>>,
}

impl Sign {
    pub fn execute(&self) -> Result<()> {
        if self.output.exists() && !self.force {
            bail!("Output already exists use `--force` to overwrite");
        }

        // It's not ideal to create a second iterator over globs especially when it's only used for validation,
        // although there aren't many options besides performing some caching trickery in the second glob iterator.
        if glob::glob(&self.path)?.nth(1).is_some() {
            if !self.output.is_dir() {
                bail!("Output must be a folder if specifying multiple paths as input");
            }
        } else if !self.output.is_file() {
            bail!("Output must be a file if specifying one path as input");
        }

        load_trust_settings(&self.trust)?;

        let replacement_val = serde_json::Value::Bool(!self.no_verify).to_string();
        let vs = r#"{"verify": { "verify_after_sign": replacement_val } }"#;
        let setting = vs.replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;

        // In the c2pa unstable_api we will be able to reuse a lot of this work rather than
        // reconstructing the entire manifest each iteration.
        for entry in glob::glob(&self.path)? {
            let path = entry?;

            let json = self.manifest.resolve()?;
            // read the signing information from the manifest definition
            let mut sign_config = SignConfig::from_json(&json)?;

            // read the manifest information
            let ext_manifest: ExtendedManifest = serde_json::from_str(&json)?;
            let mut manifest = ext_manifest.manifest;

            // add claim_tool generator so we know this was created using this tool
            let tool_generator =
                format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            manifest.claim_generator = if manifest.claim_generator.starts_with("c2pa/") {
                tool_generator // just replace the default generator
            } else {
                format!("{} {}", manifest.claim_generator, tool_generator)
            };

            let base_path = if let InputSource::Path(ref manifest_path) = self.manifest {
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

            if let Some(parent_path) = &self.parent {
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

            match &self.manifest {
                InputSource::Path(_) => {
                    if self.sidecar {
                        manifest.set_sidecar_manifest();
                    }
                }
                InputSource::Url(url) => match self.sidecar {
                    true => {
                        manifest.set_remote_manifest(url.to_string());
                    }
                    false => {
                        manifest.set_embedded_manifest_with_remote_ref(url.to_string());
                    }
                },
            }

            let signer = match &self.signer_path {
                Some(signer_process_name) => {
                    let cb_config = CallbackSignerConfig::new(&sign_config, self.reserve_size)?;

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
                .embed(Path::new(&path), &self.output, signer.as_ref())
                .context("embedding manifest")?;
        }

        Ok(())
    }
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
