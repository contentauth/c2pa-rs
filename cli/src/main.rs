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

/// Tool to display and create C2PA manifests
///
/// A file path to an asset must be provided
/// If only the path is given, this will generate a summary report of any claims in that file
/// If a manifest definition json file is specified, the claim will be added to any existing claims
use std::{
    fs::{create_dir_all, remove_dir_all, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{Error, Ingredient, Manifest, ManifestStore, ManifestStoreReport};
use clap::{AppSettings, Parser, Subcommand};
use serde::Deserialize;

mod info;
use info::info;
mod signer;
use signer::SignConfig;

/// Tool for displaying and creating C2PA manifests.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, setting = AppSettings::ArgRequiredElseHelp)]
struct CliArgs {
    /// Path to manifest definition JSON file.
    #[clap(short, long, requires = "output")]
    manifest: Option<PathBuf>,

    /// Path to output file or folder.
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// Path to a parent file.
    #[clap(short, long)]
    parent: Option<PathBuf>,

    /// Manifest definition passed as a JSON string.
    #[clap(short, long, conflicts_with = "manifest")]
    config: Option<String>,

    /// Display detailed C2PA-formatted manifest data.
    #[clap(short, long)]
    detailed: bool,

    /// Force overwrite of output if it already exists.
    #[clap(short, long)]
    force: bool,

    /// The path to an asset to examine or embed a manifest into.
    path: PathBuf,

    /// Embed remote URL manifest reference.
    #[clap(short, long)]
    remote: Option<String>,

    /// Generate a sidecar (.c2pa) manifest
    #[clap(short, long)]
    sidecar: bool,

    /// Write ingredient report and assets to a folder.
    #[clap(short, long)]
    ingredient: bool,

    /// Create a tree diagram of the manifest store.
    #[clap(long)]
    tree: bool,

    /// Extract certificate chain.
    #[clap(long = "certs")]
    cert_chain: bool,

    /// Show manifest size, XMP url and other stats.
    #[clap(long)]
    info: bool,
}

#[derive(Debug, Default, Deserialize)]
// Add fields that are not part of the standard Manifest
struct ManifestDef {
    #[serde(flatten)]
    manifest: Manifest,
    // allows adding ingredients with file paths
    ingredient_paths: Option<Vec<PathBuf>>,
}

// convert certain errors to output messages
fn special_errs(e: c2pa::Error) -> anyhow::Error {
    match e {
        Error::JumbfNotFound => anyhow!("No claim found"),
        Error::FileNotFound(name) => anyhow!("File not found: {}", name),
        Error::UnsupportedType => anyhow!("Unsupported file type"),
        Error::PrereleaseError => anyhow!("Prerelease claim found"),
        _ => e.into(),
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
    // if the path is a folder, look for ingredient.json
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

#[derive(Debug, Subcommand)]
enum SubCommand {
    AddManifest {},
}

impl SubCommand {
    fn has_command(potential_command: Option<String>) -> bool {
        let Some(potential_command) = potential_command else {
            return false;
        };

        let vector = vec!["add-manifest".to_string()];
        vector.contains(&potential_command)
    }
}

#[derive(Debug, Parser)]
struct SubcommandArguments {
    #[clap(subcommand)]
    command: SubCommand,
}

fn main() -> Result<()> {
    let first_arg = std::env::args().nth(1);
    if SubCommand::has_command(first_arg) {
        let args = SubcommandArguments::parse();
        match args.command {
            SubCommand::AddManifest {} => {
                println!("add-manifest!");
            }
        }
        return Ok(());
    }

    let args = CliArgs::parse();

    // set RUST_LOG=debug to get detailed debug logging
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }
    env_logger::init();

    let path = &args.path;

    if args.info {
        return info(path);
    }

    if args.cert_chain {
        ManifestStoreReport::dump_cert_chain(path)?;
        return Ok(());
    }

    if args.tree {
        ManifestStoreReport::dump_tree(path)?;
        return Ok(());
    }

    // Remove manifest needs to also remove XMP provenance
    // if args.remove_manifest {
    //     match args.output {
    //         Some(output) => {
    //             if output.exists() && !args.force {
    //                 bail!("Output already exists, use -f/force to force write");
    //             }
    //             if path != &output {
    //                 std::fs::copy(path, &output)?;
    //             }
    //             Manifest::remove_manifest(&output)?
    //         },
    //         None => {
    //             bail!("The -o/--output argument is required for this operation");
    //         }
    //     }
    //     return Ok(());
    // }

    // if we have a manifest config, process it
    if args.manifest.is_some() || args.config.is_some() {
        // read the json from file or config, and get base path if from file
        let (json, base_path) = match args.manifest.as_deref() {
            Some(manifest_path) => {
                let base_path = std::fs::canonicalize(manifest_path)?
                    .parent()
                    .map(|p| p.to_path_buf());
                (std::fs::read_to_string(manifest_path)?, base_path)
            }
            None => (
                args.config.unwrap_or_default(),
                std::env::current_dir().ok(),
            ),
        };

        // read the signing information from the manifest definition
        let mut sign_config = SignConfig::from_json(&json)?;

        // read the manifest information
        let manifest_def: ManifestDef = serde_json::from_slice(json.as_bytes())?;
        let mut manifest = manifest_def.manifest;

        // add claim_tool generator so we know this was created using this tool
        let tool_generator = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        if manifest.claim_generator.starts_with("c2pa/") {
            manifest.claim_generator = tool_generator // just replace the default generator
        } else {
            manifest.claim_generator = format!("{} {}", manifest.claim_generator, tool_generator);
        }

        // set manifest base path before ingredients so ingredients can override it
        if let Some(base) = base_path.as_ref() {
            manifest.with_base_path(base)?;
            sign_config.set_base_path(base);
        }

        // Add any ingredients specified as file paths
        if let Some(paths) = manifest_def.ingredient_paths {
            for mut path in paths {
                // ingredient paths are relative to the manifest path
                if let Some(base) = &base_path {
                    if !(path.is_absolute()) {
                        path = base.join(&path)
                    }
                }
                let ingredient = load_ingredient(&path)?;
                manifest.add_ingredient(ingredient);
            }
        }

        if let Some(parent_path) = args.parent {
            let ingredient = load_ingredient(&parent_path)?;
            manifest.set_parent(ingredient)?;
        }

        // If the source file has a manifest store, and no parent is specified treat the source as a parent.
        // note: This could be treated as an update manifest eventually since the image is the same
        if manifest.parent().is_none() {
            let source_ingredient = Ingredient::from_file(&args.path)?;
            if source_ingredient.manifest_data().is_some() {
                manifest.set_parent(source_ingredient)?;
            }
        }

        if let Some(remote) = args.remote {
            if args.sidecar {
                manifest.set_embedded_manifest_with_remote_ref(remote);
            } else {
                manifest.set_remote_manifest(remote);
            }
        } else if args.sidecar {
            manifest.set_sidecar_manifest();
        }

        if let Some(output) = args.output {
            if ext_normal(&output) != ext_normal(&args.path) {
                bail!("Output type must match source type");
            }
            if output.exists() && !args.force {
                bail!("Output already exists, use -f/force to force write");
            }

            if output.file_name().is_none() {
                bail!("Missing filename on output");
            }
            if output.extension().is_none() {
                bail!("Missing extension output");
            }

            let signer = sign_config.signer()?;

            manifest
                .embed(&args.path, &output, signer.as_ref())
                .context("embedding manifest")?;

            // generate a report on the output file
            if args.detailed {
                println!(
                    "{}",
                    ManifestStoreReport::from_file(&output).map_err(special_errs)?
                );
            } else {
                println!(
                    "{}",
                    ManifestStore::from_file(&output).map_err(special_errs)?
                )
            }
        }
    } else if args.parent.is_some() || args.sidecar || args.remote.is_some() {
        bail!("manifest definition required with these options or flags")
    } else if let Some(output) = args.output {
        if output.is_file() || output.extension().is_some() {
            bail!("Output must be a folder for this option.")
        }
        if output.exists() {
            if args.force {
                remove_dir_all(&output)?;
            } else {
                bail!("Output already exists, use -f/force to force write");
            }
        }
        create_dir_all(&output)?;
        if args.ingredient {
            let report = Ingredient::from_file_with_folder(&args.path, &output)
                .map_err(special_errs)?
                .to_string();
            File::create(output.join("ingredient.json"))?.write_all(&report.into_bytes())?;
            println!("Ingredient report written to the directory {:?}", &output);
        } else {
            let report = ManifestStore::from_file_with_resources(&args.path, &output)
                .map_err(special_errs)?
                .to_string();
            if args.detailed {
                // for a detailed report first call the above to generate the thumbnails
                // then call this to add the detailed report
                let detailed = ManifestStoreReport::from_file(&args.path)
                    .map_err(special_errs)?
                    .to_string();
                File::create(output.join("detailed.json"))?.write_all(&detailed.into_bytes())?;
            }
            File::create(output.join("manifest_store.json"))?.write_all(&report.into_bytes())?;
            println!("Manifest report written to the directory {:?}", &output);
        }
    } else if args.ingredient {
        println!(
            "{}",
            Ingredient::from_file(&args.path).map_err(special_errs)?
        )
    } else if args.detailed {
        println!(
            "{}",
            ManifestStoreReport::from_file(&args.path).map_err(special_errs)?
        )
    } else {
        println!(
            "{}",
            ManifestStore::from_file(&args.path).map_err(special_errs)?
        )
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
        create_dir_all("target/tmp").expect("create_dir");
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
