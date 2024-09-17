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
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{Error, Ingredient, Manifest, ManifestStore, ManifestStoreReport, Signer};
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

    /// To be used with the [callback_signer] argument. This value should at least: size of CoseSign1 CBOR +
    /// the size of certificate chain provided in the manifest definition's `sign_cert` field + the size of the
    /// signature of the Time Stamp Authority response. A typical size of CoseSign1 CBOR is in the 1-2K range. If
    /// the reserve size is too small an error will be returned during signing.
    /// For example:
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

// We only construct one per invocation, not worth shrinking this.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Sub-command to configure trust store options, "trust --help for more details"
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
    /// Sub-command to add manifest to fragmented BMFF content
    ///
    /// The init path can be a glob to process entire directories of content, for example:
    ///
    /// c2patool -m test2.json -o /my_output_folder "/my_renditions/**/my_init.mp4" fragment --fragments_glob "myfile_abc*[0-9].m4s"
    ///
    /// Note: the glob patterns are quoted to prevent shell expansion.
    Fragment {
        /// Glob pattern to find the fragments of the asset. The path is automatically set to be the same as
        /// the init segment.
        ///
        /// The fragments_glob pattern should only match fragment file names not the full paths (e.g. "myfile_abc*[0-9].m4s"
        /// to match [myfile_abc1.m4s, myfile_abc2180.m4s, ...] )
        #[arg(long = "fragments_glob", verbatim_doc_comment)]
        fragments_glob: Option<PathBuf>,
    },
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
    const TA: &str = r#"{"trust": { "trust_anchors": replacement_val } }"#;
    const AL: &str = r#"{"trust": { "allowed_list": replacement_val } }"#;
    const TC: &str = r#"{"trust": { "trust_config": replacement_val } }"#;
    const VS: &str = r#"{"verify": { "verify_after_sign": replacement_val } }"#;

    let mut enable_trust_checks = false;

    if let Some(Commands::Trust {
        trust_anchors,
        allowed_list,
        trust_config,
    }) = &args.command
    {
        if let Some(trust_list) = &trust_anchors {
            let data = load_trust_resource(trust_list)?;
            debug!("Using trust anchors from {:?}", trust_list);
            let replacement_val = serde_json::Value::String(data).to_string(); // escape string
            let setting = TA.replace("replacement_val", &replacement_val);

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(allowed_list) = &allowed_list {
            let data = load_trust_resource(allowed_list)?;
            debug!("Using allowed list from {:?}", allowed_list);
            let replacement_val = serde_json::Value::String(data).to_string(); // escape string
            let setting = AL.replace("replacement_val", &replacement_val);

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(trust_config) = &trust_config {
            let data = load_trust_resource(trust_config)?;
            debug!("Using trust config from {:?}", trust_config);
            let replacement_val = serde_json::Value::String(data).to_string(); // escape string
            let setting = TC.replace("replacement_val", &replacement_val);

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }
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
        let setting = VS.replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    Ok(())
}

fn sign_fragmented(
    manifest: &mut Manifest,
    signer: &dyn Signer,
    init_pattern: &Path,
    frag_pattern: &PathBuf,
    output_path: &Path,
) -> Result<()> {
    // search folders for init segments
    let ip = init_pattern.to_str().ok_or(c2pa::Error::OtherError(
        "could not parse source pattern".into(),
    ))?;
    let inits = glob::glob(ip).context("could not process glob pattern")?;
    let mut count = 0;
    for init in inits {
        match init {
            Ok(p) => {
                let mut fragments = Vec::new();
                let init_dir = p.parent().context("init segment had no parent dir")?;
                let seg_glob = init_dir.join(frag_pattern); // segment match pattern

                // grab the fragments that go with this init segment
                let seg_glob_str = seg_glob.to_str().context("fragment path not valid")?;
                let seg_paths = glob::glob(seg_glob_str).context("fragment glob not valid")?;
                for seg in seg_paths {
                    match seg {
                        Ok(f) => fragments.push(f),
                        Err(_) => return Err(anyhow!("fragment path not valid")),
                    }
                }

                println!("Adding manifest to: {:?}", p);
                let new_output_path =
                    output_path.join(init_dir.file_name().context("invalid file name")?);
                manifest.embed_to_bmff_fragmented(&p, &fragments, &new_output_path, signer)?;

                count += 1;
            }
            Err(_) => bail!("bad path to init segment"),
        }
    }
    if count == 0 {
        println!("No files matching pattern: {}", ip);
    }
    Ok(())
}

fn verify_fragmented(init_pattern: &Path, frag_pattern: &Path) -> Result<Vec<ManifestStore>> {
    let mut stores = Vec::new();

    let ip = init_pattern
        .to_str()
        .context("could not parse source pattern")?;
    let inits = glob::glob(ip).context("could not process glob pattern")?;
    let mut count = 0;

    // search folders for init segments
    for init in inits {
        match init {
            Ok(p) => {
                let mut fragments = Vec::new();
                let init_dir = p.parent().context("init segment had no parent dir")?;
                let seg_glob = init_dir.join(frag_pattern); // segment match pattern

                // grab the fragments that go with this init segment
                let seg_glob_str = seg_glob.to_str().context("fragment path not valid")?;
                let seg_paths = glob::glob(seg_glob_str).context("fragment glob not valid")?;
                for seg in seg_paths {
                    match seg {
                        Ok(f) => fragments.push(f),
                        Err(_) => return Err(anyhow!("fragment path not valid")),
                    }
                }

                println!("Verifying manifest: {:?}", p);
                let store = ManifestStore::from_fragments(p, &fragments, true)?;
                if let Some(vs) = store.validation_status() {
                    if let Some(e) = vs.iter().find(|v| !v.passed()) {
                        eprintln!("Error validating segments: {:?}", e);
                        return Ok(stores);
                    }
                }

                stores.push(store);

                count += 1;
            }
            Err(_) => bail!("bad path to init segment"),
        }
    }

    if count == 0 {
        println!("No files matching pattern: {}", ip);
    }

    Ok(stores)
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

    let is_fragment = matches!(
        &args.command,
        Some(Commands::Fragment { fragments_glob: _ })
    );

    // make sure path is not a glob when not fragmented
    if !args.path.is_file() && !is_fragment {
        bail!("glob patterns only allowed when using \"fragment\" command")
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
        if manifest.parent().is_none() && !is_fragment {
            let source_ingredient = Ingredient::from_file(&args.path)?;
            if source_ingredient.manifest_data().is_some() {
                manifest.set_parent(source_ingredient)?;
            }
        }

        if let Some(remote) = args.remote {
            if args.sidecar {
                manifest.set_remote_manifest(remote);
            } else {
                manifest.set_embedded_manifest_with_remote_ref(remote);
            }
        } else if args.sidecar {
            manifest.set_sidecar_manifest();
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

        if let Some(output) = args.output {
            // fragmented embedding
            if let Some(Commands::Fragment { fragments_glob }) = &args.command {
                if output.exists() && !output.is_dir() {
                    bail!("Output cannot point to existing file, must be a directory");
                }

                if let Some(fg) = &fragments_glob {
                    return sign_fragmented(
                        &mut manifest,
                        signer.as_ref(),
                        &args.path,
                        fg,
                        &output,
                    );
                } else {
                    bail!("fragments_glob must be set");
                }
            } else {
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

                #[allow(deprecated)] // todo: remove when we can
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
    } else if let Some(Commands::Fragment {
        fragments_glob: Some(fg),
    }) = &args.command
    {
        let stores = verify_fragmented(&args.path, fg)?;
        if stores.len() == 1 {
            println!("{}", stores[0]);
        } else {
            println!("{} Init manifests validated", stores.len());
        }
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

        #[allow(deprecated)] // todo: remove when we can
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
