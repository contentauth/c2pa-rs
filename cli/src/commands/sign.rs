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
    io::{BufReader, Cursor},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use c2pa::{Builder, ClaimGeneratorInfo, Ingredient, ManifestDefinition};
use clap::{Args, Parser};
use log::{error, warn};
use reqwest::Url;
use serde::Deserialize;

use crate::{
    callback_signer::{CallbackSigner, CallbackSignerConfig, ExternalProcessRunner},
    commands::{load_trust_settings, InputSource, Trust},
    signer::SignConfig,
};

#[derive(Debug, Parser)]
pub struct Sign {
    /// Input path(s) to asset(s).
    pub paths: Vec<PathBuf>,

    /// Path to output file or folder (if >1 path specified).
    #[clap(short, long)]
    pub output: PathBuf,

    #[clap(flatten)]
    pub manifest_source: ManifestSource,

    /// Generate a .c2pa manifest file next to the output without embedding.
    #[clap(short, long)]
    pub sidecar: bool,

    /// Do not embed manifest into input.
    #[clap(long)]
    pub no_embed: bool,

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

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct ManifestSource {
    /// Path to manifest .json.
    #[clap(short, long)]
    pub manifest: Option<PathBuf>,

    /// URL to manifest .json.
    #[clap(long)]
    pub manifest_url: Option<Url>,
}

#[derive(Debug, Deserialize)]
struct ManifestDefinitionExt {
    #[serde(flatten)]
    definition: ManifestDefinition,
    // Allows ingredients to be specified as a path or inline.
    ingredients: Option<Vec<IngredientSource>>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IngredientSource {
    Ingredient(Ingredient),
    Path(PathBuf),
}

impl Sign {
    pub fn execute(&self) -> Result<()> {
        let is_output_dir = self.validate()?;

        load_trust_settings(&self.trust)?;

        let replacement_val = serde_json::Value::Bool(!self.no_verify).to_string();
        let vs = r#"{"verify": { "verify_after_sign": replacement_val } }"#;
        let setting = vs.replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;

        // In the c2pa unstable_api we will be able to reuse a lot of this work rather than
        // reconstructing the entire manifest each iteration.
        let mut errs = Vec::new();
        for src in &self.paths {
            let dst = match is_output_dir {
                true => {
                    // It's safe to unwrap because we already validated this in the beginning of the function.
                    self.output.join(src.file_name().unwrap())
                }
                false => self.output.clone(),
            };

            if let Err(err) = self.sign_file(src, &dst) {
                error!(
                    "Failed to sign asset at path `{}`, {}",
                    src.display(),
                    err.to_string()
                );
                errs.push(err);
            }
        }

        if !errs.is_empty() {
            bail!("Failed to sign {}/{} assets", errs.len(), self.paths.len());
        }

        Ok(())
    }

    fn sign_file(&self, src: &Path, dst: &Path) -> Result<()> {
        // Safe to unwrap because we know at least one of the fields are required.
        let input_source = InputSource::from_path_or_url(
            self.manifest_source.manifest.as_deref(),
            self.manifest_source.manifest_url.as_ref(),
        )
        .unwrap();
        let json = input_source.resolve()?;
        // read the signing information from the manifest definition
        let mut sign_config = SignConfig::from_json(&json)?;

        // read the manifest information
        let mut definition_ext: ManifestDefinitionExt = serde_json::from_str(&json)?;

        let mut claim_gen_info = ClaimGeneratorInfo::new(env!("CARGO_PKG_NAME"));
        claim_gen_info.set_version(env!("CARGO_PKG_VERSION"));
        definition_ext
            .definition
            .claim_generator_info
            .push(claim_gen_info);

        let base_path = if let Some(ref manifest_path) = self.manifest_source.manifest {
            fs::canonicalize(manifest_path)?
                .parent()
                .map(|p| p.to_path_buf())
                .context("Cannot find manifest parent path")?
        } else {
            env::current_dir()?
        };

        // TODO: https://github.com/contentauth/c2pa-rs/pull/544
        let mut builder = Builder::from_json(&serde_json::to_string(&definition_ext.definition)?)?;
        builder.no_embed = self.no_embed;
        if let Some(url) = &self.manifest_source.manifest_url {
            builder.remote_url = Some(url.to_string());
        }

        if let Some(ingredients) = definition_ext.ingredients {
            for ingredient_source in ingredients {
                match ingredient_source {
                    IngredientSource::Ingredient(ingredient) => {
                        // TODO: not a beautiful sight
                        let data = ingredient
                            .data_ref()
                            .map(|data_ref| ingredient.resources().get(&data_ref.identifier))
                            .transpose()?;
                        let data = data.as_deref().map(|data| data.as_slice()).unwrap_or(&[]);

                        // TODO: shouldn't have to serialize
                        let ingredient_json = serde_json::to_string(&ingredient)?;
                        builder.add_ingredient(
                            ingredient_json,
                            ingredient.format(),
                            &mut Cursor::new(data),
                        )?;
                    }
                    IngredientSource::Path(mut path) => {
                        // ingredient paths are relative to the manifest path
                        if !path.is_absolute() {
                            path = base_path.join(&path);
                        }

                        let ingredient = load_ingredient(&path)?;
                        let ingredient = builder.add_ingredient(
                            // TODO: shouldn't have to reserialize
                            serde_json::to_string(&ingredient)?,
                            ingredient.format(),
                            // TODO: shouldn't have to read from file again
                            &mut File::open(&path)?,
                        )?;

                        // TODO: shouldn't have to set this again
                        if let Some(base) = path.parent() {
                            ingredient.with_base_path(base)?;
                        }
                    }
                }
            }
        }

        if let Some(parent_path) = &self.parent {
            let mut ingredient = load_ingredient(parent_path)?;
            ingredient.set_is_parent();
            let ingredient = builder.add_ingredient(
                // TODO: shouldn't have to reserialize
                serde_json::to_string(&ingredient)?,
                ingredient.format(),
                // TODO: shouldn't have to read from file again
                &mut File::open(parent_path)?,
            )?;

            // TODO: shouldn't have to set this again
            if let Some(base) = parent_path.parent() {
                ingredient.with_base_path(base)?;
            }
        }

        // If the source file has a manifest store, and no parent is specified treat the source as a parent.
        // note: This could be treated as an update manifest eventually since the image is the same
        let parent_exists = definition_ext
            .definition
            .ingredients
            .iter()
            .any(|ingredient| ingredient.is_parent());
        if !parent_exists {
            let mut source_ingredient = Ingredient::from_file(src)?;
            if source_ingredient.manifest_data().is_some() {
                source_ingredient.set_is_parent();

                let ingredient = builder.add_ingredient(
                    // TODO: we shouldn't have to reserialize this
                    serde_json::to_string(&source_ingredient)?,
                    source_ingredient.format(),
                    // TODO: shouldn't have to read from file again
                    &mut File::open(src)?,
                )?;

                // TODO: shouldn't have to set this again
                if let Some(base) = src.parent() {
                    ingredient.with_base_path(base)?;
                }
            }
        }

        sign_config.set_base_path(&base_path);
        builder.base_path = Some(base_path);

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

        let binary_manifest = builder.sign_file(signer.as_ref(), src, dst)?;

        // TODO: Take sidecar as output path similar to self.output, fixes #134
        if self.sidecar {
            let mut dst = dst.to_owned();
            dst.set_extension("c2pa");
            fs::write(dst, binary_manifest)?;
        }

        Ok(())
    }

    // Validates input and output paths for conflicts and returns whether the output is
    // a file or a folder.
    fn validate(&self) -> Result<bool> {
        let num_outputs = if self.sidecar {
            self.paths.len() * 2
        } else {
            self.paths.len()
        };

        // These restrictions allow a file or folder to be specified as output if there is only one input. If
        // there are multiple inputs, the output must be a folder.
        let is_output_dir = match (self.output.exists(), self.output.is_dir(), num_outputs) {
            // If the output exists and there are at least two inputs, it must be a folder.
            (true, false, 2..) => {
                bail!("Output path must be a folder if multiple inputs are specified")
            }
            // If the output exists and there are at least two inputs and the output is a folder,
            // then ensure each file within the folder doesn't already exist.
            (true, true, 2..) => {
                if !self.force {
                    let mut exists = 0;
                    for path in &self.paths {
                        // A glob always returns a file path, so it's safe to unwrap.
                        let mut output = self.output.join(path.file_name().unwrap());
                        if output.exists() {
                            exists += 1;
                            warn!("Output path `{}` already exists", output.display());
                        }

                        if self.sidecar {
                            output.set_extension("c2pa");
                            if output.exists() {
                                exists += 1;
                                warn!("Sidecar output path `{}` already exists", output.display());
                            }
                        }
                    }

                    if exists > 0 {
                        bail!(
                            "{}/{} paths already exist, use `--verbose` for more info or `--force` to overwrite",
                            exists,
                            num_outputs
                        );
                    }
                }

                true
            }
            // If the output exists and there's one input and the output is a file, --force must be specified.
            (true, false, 1) => {
                if !self.force {
                    bail!("Output path already exists use `--force` to overwrite")
                }

                false
            }
            // If the output exists and there's one input and the output is a folder, then ensure
            // the file doesn't exist in the output.
            (true, true, 1) => {
                if !self.force {
                    // A glob always returns a file path, so it's safe to unwrap.
                    let output = self.output.join(self.paths[0].file_name().unwrap());
                    if output.exists() {
                        bail!(
                            "Output path `{}` already exists use `--force` to overwrite",
                            output.display()
                        );
                    }
                }

                true
            }
            // If the output doesn't exist and there's at least two inputs, we assume it's a folder.
            (false, false, 2..) => {
                // TODO: re-evaluate this decision, the copy (cp) tool requires a dir exists, doesn't create it auto
                fs::create_dir_all(&self.output)?;
                true
            }
            // If the output doesn't exist and there's one input, we assume the output is a file.
            (false, false, 1) => {
                // TODO: this will be removed eventually, see https://github.com/contentauth/c2patool/issues/150
                if !self.sidecar {
                    let input_ext = ext_normal(&self.paths[0]);
                    let output_ext = ext_normal(&self.output);
                    if input_ext != output_ext {
                        bail!("Manifest cannot be embedded if extensions do not match {}≠{}, specify `--sidecar` to sidecar the manifest", input_ext, output_ext);
                    }
                }

                false
            }
            // If there are no inputs specified, then error.
            (_, _, 0) => bail!("Input path not found"),
            // If the output doesn't exist then it's impossible to know if it's a file or a folder.
            (false, true, _) => unreachable!(),
        };

        Ok(is_output_dir)
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
            ingredient.with_base_path(base)?;
        }

        Ok(ingredient)
    } else {
        Ok(Ingredient::from_file(path)?)
    }
}
