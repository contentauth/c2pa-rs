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
    fs::{self, create_dir_all, remove_dir_all, File},
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{Builder, ClaimGeneratorInfo, Error, Ingredient, ManifestStoreReport, Reader};
use clap::{Parser, Subcommand};
use log::debug;
use serde::Deserialize;
use signer::SignConfig;
use url::Url;

use crate::{
    callback_signer::{CallbackSigner, CallbackSignerConfig, ExternalProcessRunner},
    info::info,
};

mod info;

mod callback_signer;
mod signer;

/// Tool for displaying and creating C2PA manifests.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help(true))]
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

    /// Do not perform validation of signature after signing
    #[clap(long = "no_signing_verify")]
    no_signing_verify: bool,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Show manifest size, XMP url and other stats.
    #[clap(long)]
    info: bool,

    /// Path to an executable that will sign the claim bytes.
    #[clap(long)]
    signer_path: Option<PathBuf>,

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
    reserve_size: usize,
}

#[derive(Clone, Debug)]
enum TrustResource {
    File(PathBuf),
    Url(Url),
}

fn parse_resource_string(s: &str) -> Result<TrustResource> {
    if let Ok(url) = s.parse::<Url>() {
        Ok(TrustResource::Url(url))
    } else {
        let p = PathBuf::from_str(s)?;

        Ok(TrustResource::File(p))
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    Trust {
        /// URL or path to file containing list of trust anchors in PEM format
        #[arg(long = "trust_anchors", env="C2PATOOL_TRUST_ANCHORS", value_parser = parse_resource_string)]
        trust_anchors: Option<TrustResource>,

        /// URL or path to file containing specific manifest signing certificates in PEM format to implicitly trust
        #[arg(long = "allowed_list", env="C2PATOOL_ALLOWED_LIST", value_parser = parse_resource_string)]
        allowed_list: Option<TrustResource>,

        /// URL or path to file containing configured EKUs in Oid dot notation
        #[arg(long = "trust_config", env="C2PATOOL_TRUST_CONFIG", value_parser = parse_resource_string)]
        trust_config: Option<TrustResource>,
    },
}

#[derive(Debug, Default, Deserialize)]
// Add fields that are not part of the standard Manifest
struct ManifestDef {
    #[serde(flatten)]
    builder: Builder,
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

fn load_trust_resource(resource: &TrustResource) -> Result<String> {
    match resource {
        TrustResource::File(path) => {
            let data = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read trust resource from path: {:?}", path))?;

            Ok(data)
        }
        TrustResource::Url(url) => {
            let data = reqwest::blocking::get(url.to_string())?
                .text()
                .with_context(|| format!("Failed to read trust resource from URL: {}", url))?;

            Ok(data)
        }
    }
}

fn configure_sdk(args: &CliArgs) -> Result<()> {
    let ta = r#"{"trust": { "trust_anchors": replacement_val } }"#;
    let al = r#"{"trust": { "allowed_list": replacement_val } }"#;
    let tc = r#"{"trust": { "trust_config": replacement_val } }"#;
    let vs = r#"{"verify": { "verify_after_sign": replacement_val } }"#;

    let mut enable_trust_checks = false;

    match &args.command {
        Some(Commands::Trust {
            trust_anchors,
            allowed_list,
            trust_config,
        }) => {
            if let Some(trust_list) = &trust_anchors {
                let data = load_trust_resource(trust_list)?;
                debug!("Using trust anchors from {:?}", trust_list);
                let replacement_val = serde_json::Value::String(data).to_string(); // escape string
                let setting = ta.replace("replacement_val", &replacement_val);

                c2pa::settings::load_settings_from_str(&setting, "json")?;

                enable_trust_checks = true;
            }

            if let Some(allowed_list) = &allowed_list {
                let data = load_trust_resource(allowed_list)?;
                debug!("Using allowed list from {:?}", allowed_list);
                let replacement_val = serde_json::Value::String(data).to_string(); // escape string
                let setting = al.replace("replacement_val", &replacement_val);

                c2pa::settings::load_settings_from_str(&setting, "json")?;

                enable_trust_checks = true;
            }

            if let Some(trust_config) = &trust_config {
                let data = load_trust_resource(trust_config)?;
                debug!("Using trust config from {:?}", trust_config);
                let replacement_val = serde_json::Value::String(data).to_string(); // escape string
                let setting = tc.replace("replacement_val", &replacement_val);

                c2pa::settings::load_settings_from_str(&setting, "json")?;

                enable_trust_checks = true;
            }
        }
        None => {}
    }

    // if any trust setting is provided enable the trust checks
    if enable_trust_checks {
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": true} }"#, "json")?;
    } else {
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": false} }"#, "json")?;
    }

    // enable or disable verification after signing
    {
        let replacement_val = serde_json::Value::Bool(!args.no_signing_verify).to_string();
        let setting = vs.replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
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

    // configure the SDK
    configure_sdk(&args).context("Could not configure c2pa-rs")?;

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
        let manifest_def: ManifestDef = serde_json::from_str(&json)?;
        let mut builder = manifest_def.builder;

        let mut claim_gen_info = ClaimGeneratorInfo::new(env!("CARGO_PKG_NAME"));
        claim_gen_info.set_version(env!("CARGO_PKG_VERSION"));
        builder.definition.claim_generator_info.push(claim_gen_info);

        if let Some(base) = base_path.as_ref() {
            sign_config.set_base_path(base);
        }

        if let Some(paths) = manifest_def.ingredient_paths {
            for mut path in paths {
                if let Some(base) = &base_path {
                    if !(path.is_absolute()) {
                        path = base.join(&path)
                    }
                }

                let ingredient = load_ingredient(&path)?;
                builder.definition.ingredients.push(ingredient);
            }
        }

        if let Some(parent_path) = args.parent {
            let ingredient = load_ingredient(&parent_path)?;
            // TODO: Relationship isn't exported from c2pa-rs
            // ingredient.set_relationship(Relationship::ParentOf);
            builder.definition.ingredients.push(ingredient);
        }

        let parent_exists = builder
            .definition
            .ingredients
            .iter()
            .any(|ingredient| ingredient.is_parent());
        if !parent_exists {
            let source_ingredient = Ingredient::from_file(&args.path)?;
            if source_ingredient.manifest_data().is_some() {
                // source_ingredient.set_relationship(Relationship::ParentOf);
                builder.definition.ingredients.push(source_ingredient);
            }
        }

        if let Some(remote) = args.remote {
            builder.remote_url = Some(remote);
        }

        // TODO: handle sidecar

        if let Some(output) = args.output {
            if ext_normal(&output) != ext_normal(&args.path) {
                bail!("Output type must match source type");
            }
            if output.exists() && !args.force {
                bail!("Output already exists, use -f/force to force overwrite");
            }

            if output.file_name().is_none() {
                bail!("Missing filename on output");
            }
            if output.extension().is_none() {
                bail!("Missing extension output");
            }

            let signer = if let Some(signer_process_name) = args.signer_path {
                let cb_config = CallbackSignerConfig::new(&sign_config, args.reserve_size)?;

                let process_runner = Box::new(ExternalProcessRunner::new(
                    cb_config.clone(),
                    signer_process_name,
                ));
                let signer = CallbackSigner::new(process_runner, cb_config);

                Box::new(signer)
            } else {
                sign_config.signer()?
            };

            match args.sidecar {
                true => {
                    if let Some(ext) = c2pa::format_from_path(&args.path) {
                        let binary_manifest = builder.sign(
                            signer.as_ref(),
                            &ext,
                            &mut File::open(&args.path)?,
                            &mut io::empty(),
                        )?;
                        fs::write(&output, binary_manifest)?;
                    }
                }
                false => {
                    builder.sign_file(signer.as_ref(), &args.path, &output)?;
                }
            }

            // generate a report on the output file
            if args.detailed {
                println!("{:?}", Reader::from_file(output).map_err(special_errs)?);
            } else {
                println!("{}", Reader::from_file(output).map_err(special_errs)?)
            }
        } else {
            bail!("Output path required with manifest definition")
        }
    } else if args.parent.is_some() || args.sidecar || args.remote.is_some() {
        bail!("Manifest definition required with these options or flags")
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
            let reader = Reader::from_file(path).map_err(special_errs)?;
            for manifest in reader.iter_manifests() {
                let manifest_path = output.join(
                    manifest
                        .label()
                        .context("Failed to get maniest label")?
                        .replace(':', "_"),
                );
                for resource_ref in manifest.resources().iter_resources() {
                    // TODO: need a method in c2pa-rs to normalize the identifier (removing jumbf tag)
                    let resource_path = manifest_path.join(&resource_ref.identifier);
                    std::fs::create_dir_all(
                        resource_path
                            .parent()
                            .context("Failed to find resource parent path from label")?,
                    )?;
                    reader.resource_to_stream(
                        &resource_ref.identifier,
                        File::create(&resource_path)?,
                    )?;
                }
            }

            if args.detailed {
                // for a detailed report first call the above to generate the thumbnails
                // then call this to add the detailed report
                let detailed = format!("{:?}", Reader::from_file(path).map_err(special_errs)?);

                File::create(output.join("detailed.json"))?.write_all(&detailed.into_bytes())?;
            }
            File::create(output.join("manifest_store.json"))?
                .write_all(&reader.to_string().into_bytes())?;
            println!("Manifest report written to the directory {:?}", &output);
        }
    } else if args.ingredient {
        println!(
            "{}",
            Ingredient::from_file(&args.path).map_err(special_errs)?
        )
    } else if args.detailed {
        println!("{:?}", Reader::from_file(path).map_err(special_errs)?)
    } else {
        println!("{}", Reader::from_file(path).map_err(special_errs)?)
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use c2pa::Manifest;

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

        let ms = Reader::from_file(OUTPUT_PATH)
            .expect("from_file")
            .to_string();
        //let ms = report_from_path(&OUTPUT_PATH, false).expect("report_from_path");
        assert!(ms.contains("my_key"));
    }
}
