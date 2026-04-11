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
    fs::{copy, create_dir_all, remove_file, File},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use c2pa::{
    format_from_path, settings::Settings, Builder, ClaimGeneratorInfo, Context as C2paContext,
    ManifestDefinition, Signer,
};
use serde::Deserialize;
use tempfile::NamedTempFile;

use crate::{
    callback_signer::{CallbackSigner, CallbackSignerConfig, ExternalProcessRunner},
    signer::SignConfig,
    util::{ext_normal, load_ingredient},
};

/// Manifest definition extended with ingredient file paths that are not part
/// of the standard ManifestDefinition schema.
#[derive(Debug, Default, Deserialize)]
pub struct ManifestDef {
    #[serde(flatten)]
    pub manifest: ManifestDefinition,
    pub ingredient_paths: Option<Vec<PathBuf>>,
}

/// Options that control how the output is written after signing.
pub struct OutputOptions<'a> {
    pub output: &'a Path,
    pub sidecar: bool,
    pub force: bool,
}

/// Build and configure a Builder from a manifest JSON string, including
/// claim generator info and base path for resource resolution.
pub fn setup_builder(
    json: &str,
    base_path: Option<&PathBuf>,
    context: &Arc<C2paContext>,
) -> Result<(Builder, SignConfig)> {
    let sign_config = SignConfig::from_json(json)?;
    let manifest_def: ManifestDef = serde_json::from_slice(json.as_bytes())?;
    let mut builder = Builder::from_shared_context(context).with_definition(json)?;
    let mut manifest = manifest_def.manifest;

    // Record that this manifest was created with c2patool.
    let mut tool_generator = ClaimGeneratorInfo::new(env!("CARGO_PKG_NAME"));
    tool_generator.set_version(env!("CARGO_PKG_VERSION"));
    if !manifest.claim_generator_info.is_empty()
        || manifest.claim_generator_info[0].name == "c2pa-rs"
    {
        manifest.claim_generator_info = vec![tool_generator];
    } else {
        manifest.claim_generator_info.insert(1, tool_generator);
    }

    if let Some(base) = base_path {
        builder.set_base_path(base);
    }

    // Add any ingredient file paths declared in the manifest JSON.
    if let Some(paths) = manifest_def.ingredient_paths {
        for mut ingredient_path in paths {
            if let Some(base) = base_path {
                if !ingredient_path.is_absolute() {
                    ingredient_path = base.join(&ingredient_path);
                }
            }
            let ingredient = load_ingredient(&ingredient_path)?;
            builder.add_ingredient(ingredient);
        }
    }

    Ok((builder, sign_config))
}

/// Select a signer based on available configuration (settings signer, external
/// process, or embedded key material from the manifest JSON).
pub fn select_signer(
    sign_config: &SignConfig,
    settings: &mut Settings,
    signer_path: Option<PathBuf>,
    reserve_size: usize,
) -> Result<Box<dyn Signer>> {
    if let Some(signer_process_name) = signer_path {
        let cb_config = CallbackSignerConfig::new(sign_config, reserve_size)?;
        let process_runner = Box::new(ExternalProcessRunner::new(
            cb_config.clone(),
            signer_process_name,
        ));
        Ok(Box::new(CallbackSigner::new(process_runner, cb_config)))
    } else if let Some(signer_cfg) = settings.signer.take() {
        let c2pa_signer = signer_cfg.c2pa_signer()?;
        if let Some(cawg_cfg) = settings.cawg_x509_signer.take() {
            Ok(cawg_cfg.cawg_signer(c2pa_signer)?)
        } else {
            Ok(c2pa_signer)
        }
    } else {
        sign_config.signer()
    }
}

/// Sign an asset and write it to `output`, handling sidecar generation,
/// remote URL embedding, same-file overwrite, and output directory creation.
///
/// Returns the raw manifest data bytes on success (used for e.g. sidecar write).
pub fn sign_to_output(
    builder: &mut Builder,
    signer: &dyn Signer,
    input: &Path,
    opts: &OutputOptions,
) -> Result<Vec<u8>> {
    let output = opts.output;

    if ext_normal(output) != ext_normal(input) {
        bail!("Output type must match source type");
    }
    if output.exists() {
        if opts.force && output != input {
            remove_file(output)?;
        } else if !opts.force {
            bail!("Output already exists; use -f/force to force write");
        }
    }
    if output.file_name().is_none() {
        bail!("Missing filename on output");
    }
    if output.extension().is_none() {
        bail!("Missing extension output");
    }

    // Set title from output filename if not already set.
    if builder.definition.title.is_none() {
        if let Some(title) = output.file_name() {
            builder.definition.title = Some(title.to_string_lossy().to_string());
        }
    }

    let manifest_data = if input != output {
        builder
            .sign_file(signer, input, output)
            .context("embedding manifest")?
    } else {
        // Same-file write: sign into a temp file then atomically replace.
        let format = format_from_path(input)
            .ok_or(c2pa::Error::UnsupportedType)
            .context("unsupported file type")?;
        let mut source = File::open(input)?;
        let mut temp_file = NamedTempFile::new()?;
        let data = builder
            .sign(signer, &format, &mut source, &mut temp_file)
            .context("embedding manifest")?;

        if let Some(output_dir) = output.parent() {
            create_dir_all(output_dir)?;
        }
        match temp_file.persist(output) {
            Ok(_) => {}
            Err(e) => {
                copy(e.file, output)?;
            }
        }
        data
    };

    if opts.sidecar {
        let sidecar = output.with_extension("c2pa");
        File::create(&sidecar)?.write_all(&manifest_data)?;
    }

    Ok(manifest_data)
}

/// Configure remote URL and/or sidecar (no-embed) on the builder.
pub fn configure_output_mode(builder: &mut Builder, remote: Option<&String>, sidecar: bool) {
    match (remote, sidecar) {
        (Some(url), true) => {
            builder.set_no_embed(true);
            builder.set_remote_url(url.clone());
        }
        (Some(url), false) => {
            builder.set_remote_url(url.clone());
        }
        (None, true) => {
            builder.set_no_embed(true);
        }
        (None, false) => {}
    }
}

/// If the source file already has manifest data and no parent ingredient has
/// been set, automatically treat it as a parent ingredient.
pub fn maybe_add_source_as_parent(builder: &mut Builder, source: &Path, is_fragment: bool) {
    let has_parent = builder.definition.ingredients.iter().any(|i| i.is_parent());
    if !has_parent && !is_fragment {
        #[allow(deprecated)]
        if let Ok(mut ingredient) = c2pa::Ingredient::from_file(source) {
            if ingredient.manifest_data().is_some() {
                ingredient.set_is_parent();
                builder.add_ingredient(ingredient);
            }
        }
    }
}
