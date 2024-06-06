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

#![doc = include_str!("../README.md")]

use std::{
    env,
    ffi::OsStr,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{Error, Ingredient, Manifest, ManifestStore, ManifestStoreReport};
use clap::Parser;
use commands::{CliArgs, Commands, Information, InputSource, Trust};
use serde::Deserialize;
use signer::SignConfig;

use crate::{
    callback_signer::{CallbackSigner, CallbackSignerConfig, ExternalProcessRunner},
    info::info,
};

mod commands;
mod info;

mod callback_signer;
mod signer;

// Add fields that are not part of the standard Manifest
#[derive(Debug, Deserialize)]
struct ExtendedManifest {
    #[serde(flatten)]
    manifest: Manifest,
    // allows adding ingredients with file paths
    ingredient_paths: Option<Vec<PathBuf>>,
}

// loads an ingredient, allowing for a folder or json ingredient
fn load_ingredient(path: &Path) -> Result<Ingredient> {
    // TODO: implicit?
    // if the path is a folder, look for ingredient.json
    let path = match path.is_dir() {
        true => &path.join("ingredient.json"),
        false => path,
    };

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

fn load_trust_settings(trust: &Trust) -> Result<()> {
    if let Some(trust_list) = &trust.trust_anchors {
        let data = trust_list.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "trust_anchors": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    if let Some(allowed_list) = &trust.allowed_list {
        let data = allowed_list.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "allowed_list": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    if let Some(trust_config) = &trust.trust_config {
        let data = trust_config.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "trust_config": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    if trust.trust_anchors.is_some() || trust.allowed_list.is_some() || trust.trust_config.is_some()
    {
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": true} }"#, "json")?;
    } else {
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": false} }"#, "json")?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    // set RUST_LOG=debug to get detailed debug logging
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }
    env_logger::init();

    load_trust_settings(&args.trust)?;

    match args.command {
        Commands::Sign {
            input,
            output,
            manifest: manifest_source,
            no_embed,
            force,
            parent,
            signer_path,
            reserve_size,
            no_verify_signing,
        } => {
            if output.exists() && !force {
                bail!("Output already exists use `--force` to overwrite")
            }

            let replacement_val = serde_json::Value::Bool(!no_verify_signing).to_string();
            let vs = r#"{"verify": { "verify_after_sign": replacement_val } }"#;
            let setting = vs.replace("replacement_val", &replacement_val);

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            // TODO: for now
            let input = &input[0];

            let json = manifest_source.resolve()?;
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

            let base_path = if let InputSource::Path(ref manifest_path) = manifest_source {
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

            if let Some(parent_path) = parent {
                manifest.set_parent(load_ingredient(&parent_path)?)?;
            }

            // If the source file has a manifest store, and no parent is specified treat the source as a parent.
            // note: This could be treated as an update manifest eventually since the image is the same
            if manifest.parent().is_none() {
                let source_ingredient = Ingredient::from_file(input)?;
                if source_ingredient.manifest_data().is_some() {
                    manifest.set_parent(source_ingredient)?;
                }
            }

            match &manifest_source {
                InputSource::Path(_) => {
                    if no_embed {
                        manifest.set_sidecar_manifest();
                    }
                }
                InputSource::Url(url) => match no_embed {
                    true => {
                        manifest.set_remote_manifest(url.to_string());
                    }
                    false => {
                        manifest.set_embedded_manifest_with_remote_ref(url.to_string());
                    }
                },
            }

            let signer = if let Some(signer_process_name) = signer_path {
                let cb_config = CallbackSignerConfig::new(&sign_config, reserve_size)?;

                let process_runner = Box::new(ExternalProcessRunner::new(
                    cb_config.clone(),
                    signer_process_name,
                ));
                let signer = CallbackSigner::new(process_runner, cb_config);

                Box::new(signer)
            } else {
                sign_config.signer()?
            };

            manifest
                .embed(input, &output, signer.as_ref())
                .context("embedding manifest")?;
        }
        Commands::Display { command } => match command {
            Information::Manifest { input, debug } => {
                let report = match debug {
                    true => ManifestStoreReport::from_file(&input).map(|r| r.to_string()),
                    false => ManifestStore::from_file(&input).map(|r| r.to_string()),
                };

                // TODO: is this needed?
                let report = match report {
                    Ok(report) => Ok(report),
                    Err(Error::JumbfNotFound) => Err(anyhow!("No claim found")),
                    Err(Error::PrereleaseError) => Err(anyhow!("Prerelease claim found")),
                    Err(err) => Err(err.into()),
                }?;

                println!("{report}");
            }
            Information::Stats { input } => {
                info(&input)?;
            }
            Information::Tree { input } => {
                ManifestStoreReport::dump_tree(input)?;
            }
            Information::Certs { input } => {
                ManifestStoreReport::dump_cert_chain(input)?;
            }
        },
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const CONFIG: &str = r#"{
        "alg": "es256",
        "private_key": "es256_private.key",
        "sign_cert": "es256_certs.pem",
        "ta_url": "http://timestamp.digicert.com",
        "assertions": [
            {
                "label": "org.contentauth.test",
                 "data": {"my_key": "whatever I want"}
            }
        ]
    }"#;

    #[test]
    fn test_manifest_config() {
        const SOURCE_PATH: &str = "tests/fixtures/earth_apollo17.jpg";
        const OUTPUT_PATH: &str = "target/tmp/unit_out.jpg";
        fs::create_dir_all("target/tmp").expect("create_dir");
        let mut manifest = Manifest::from_json(CONFIG).expect("from_json");

        let signer = SignConfig::from_json(CONFIG)
            .unwrap()
            .set_base_path("sample")
            .signer()
            .expect("get_signer");

        let _result = manifest
            .embed(SOURCE_PATH, OUTPUT_PATH, signer.as_ref())
            .expect("embed");

        let ms = ManifestStore::from_file(OUTPUT_PATH)
            .expect("from_file")
            .to_string();
        //let ms = report_from_path(&OUTPUT_PATH, false).expect("report_from_path");
        assert!(ms.contains("my_key"));
    }
}
