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

    /// Path to output file or folder (if glob specified).
    #[clap(short, long)]
    pub output: PathBuf,

    /// Path or URL to manifest .json.
    #[clap(short, long, value_parser = InputSource::validate)]
    pub manifest: InputSource,

    /// Generate a .c2pa manifest file next to the output without embedding.
    #[clap(short, long)]
    pub sidecar: bool,

    /// Force overwrite output file(s) if they already exists.
    #[clap(short, long)]
    pub force: bool,

    /// Path to the parent ingredient .json.
    #[clap(short, long)]
    pub parent: Option<PathBuf>,

    /// Path to an executable that will sign the claim bytes, defaults to built-in signer.
    #[clap(long)]
    pub signer_path: Option<PathBuf>,

    /// Do not perform validation of signature after signing.
    #[clap(long)]
    pub no_verify: bool,

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

#[derive(Debug)]
pub struct ValidationResults {
    paths: Vec<PathBuf>,
    is_output_dir: bool,
}

impl Sign {
    pub fn execute(&self) -> Result<()> {
        let validation_results = self.validate()?;

        load_trust_settings(&self.trust)?;

        let replacement_val = serde_json::Value::Bool(!self.no_verify).to_string();
        let vs = r#"{"verify": { "verify_after_sign": replacement_val } }"#;
        let setting = vs.replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;

        // In the c2pa unstable_api we will be able to reuse a lot of this work rather than
        // reconstructing the entire manifest each iteration.
        for path in validation_results.paths {
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

            let output = match validation_results.is_output_dir {
                true => {
                    // It's safe to unwrap because we already validated this in the beginning of the function.
                    self.output.join(path.file_name().unwrap())
                }
                false => self.output.to_owned(),
            };
            manifest
                .embed(&path, &output, signer.as_ref())
                .context("embedding manifest")?;
        }

        Ok(())
    }

    // Validates input and output paths for conflicts and returns whether the output is
    // a file or a folder.
    pub fn validate(&self) -> Result<ValidationResults> {
        let paths = glob::glob(&self.path)?.collect::<Result<Vec<PathBuf>, _>>()?;
        if paths.is_empty() {
            bail!("Input path not found")
        }

        // These restrictions allow a file or folder to be specified as output if there is only one input. If
        // there are multiple inputs, the output must be a folder.
        let is_output_dir = if self.output.exists() {
            if paths.len() >= 2 {
                if !self.output.is_dir() {
                    // If the output exists and there are at least two inputs, it must be a folder.
                    bail!("Output path must be a folder if multiple inputs are specified")
                } else {
                    // If the output exists and there are at least two inputs and the output is a folder,
                    // then ensure each file within the folder doesn't already exist.
                    for path in &paths {
                        // A glob always returns a file path, so it's safe to unwrap.
                        let output = self.output.join(path.file_name().unwrap());
                        if output.exists() {
                            bail!("Output path `{}` already exists", output.display());
                        }
                    }

                    true
                }
            } else if self.output.is_file() {
                // If the output exists and there's one input and the output is a file, --force must be specified.
                if !self.force {
                    bail!("Output path already exists use `--force` to overwrite")
                }

                false
            } else {
                // If the output exists and there's one input and the output is a folder, then ensure
                // the file doesn't exist in the output.

                // A glob always returns a file path, so it's safe to unwrap.
                let output = self.output.join(paths[0].file_name().unwrap());
                if output.exists() {
                    bail!("Output path `{}` already exists", output.display());
                }

                true
            }
        } else if paths.len() >= 2 {
            // If the output doesn't exist and there's at least two inputs, we assume it's a folder.

            // TODO: re-evaluate this decision, the copy (cp) tool requires a dir exists, doesn't create it auto
            fs::create_dir_all(&self.output)?;
            true
        } else {
            // If the output doesn't exist and there's one input, we assume the output is a file.

            // TODO: this will be removed eventually, see https://github.com/contentauth/c2patool/issues/150
            if !self.sidecar {
                let input_ext = ext_normal(Path::new(&self.path));
                let output_ext = ext_normal(&self.output);
                if input_ext != output_ext {
                    bail!("Manifest cannot be embedded if extensions do not match {}≠{}, specify `--sidecar` to sidecar the manifest", input_ext, output_ext);
                }
            }

            false
        };

        Ok(ValidationResults {
            paths,
            is_output_dir,
        })
    }
}

// normalize extensions so we can compare them
fn ext_normal(path: &Path) -> String {
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
