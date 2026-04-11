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

/// Tool to display and create C2PA manifests.
///
/// A file path to an asset must be provided. If only the path is given, a
/// summary report of any C2PA claims in that file is displayed. If a manifest
/// definition JSON file is specified with -m/--manifest, the claim is added to
/// any existing claims in the asset.
use std::{path::PathBuf, sync::Arc};

use anyhow::{bail, Context, Result};
use c2pa::{settings::Settings, Context as C2paContext};
use clap::{Parser, Subcommand};
use etcetera::BaseStrategy;

mod callback_signer;
mod fragment;
mod info;
mod read;
mod sign;
mod signer;
mod tree;
mod trust;
mod util;

use trust::{apply_trust_settings, parse_resource_string, TrustResource};

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
    #[clap(short, long, conflicts_with = "crjson")]
    detailed: bool,

    /// Output manifest data in crJSON format.
    #[clap(long, conflicts_with = "detailed")]
    crjson: bool,

    /// Force overwrite of output if it already exists.
    #[clap(short, long)]
    force: bool,

    /// The path to an asset to examine or embed a manifest into.
    path: PathBuf,

    /// Embed remote URL manifest reference.
    #[clap(short, long)]
    remote: Option<String>,

    /// Path to a binary .c2pa manifest to use for validation against the input asset.
    ///
    /// This field will override the input asset's embedded or remote manifest.
    #[clap(long)]
    external_manifest: Option<PathBuf>,

    /// Generate a sidecar (.c2pa) manifest.
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

    /// Do not perform validation of signature after signing.
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

    /// Reserve size for the external signer's CoseSign1 CBOR output.
    ///
    /// A typical value is: 1024 + sign_cert.len() (+ tsa_signature_response.len()
    /// if using a TSA). Defaults to 20000 if not specified.
    #[clap(long, default_value("20000"))]
    reserve_size: usize,

    /// Path to the settings file in JSON or TOML.
    ///
    /// By default the settings file is read from `$XDG_CONFIG_HOME/c2pa/c2pa.toml`.
    #[clap(
        long,
        env = "C2PATOOL_SETTINGS",
        default_value = default_settings_path().into_os_string()
    )]
    settings: PathBuf,
}

fn default_settings_path() -> PathBuf {
    let strategy = etcetera::choose_base_strategy().unwrap();
    let mut path = strategy.config_dir();
    path.push("c2pa");
    path.push("c2pa.toml");
    path
}

// We only construct one per invocation, not worth shrinking this.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Commands {
    /// Configure trust store options — use `trust --help` for details.
    Trust {
        /// URL or path to file containing list of trust anchors in PEM format.
        #[arg(long = "trust_anchors", env = "C2PATOOL_TRUST_ANCHORS", value_parser = parse_resource_string)]
        trust_anchors: Option<TrustResource>,

        /// URL or path to file containing specific manifest signing certificates to implicitly trust.
        #[arg(long = "allowed_list", env = "C2PATOOL_ALLOWED_LIST", value_parser = parse_resource_string)]
        allowed_list: Option<TrustResource>,

        /// URL or path to file containing configured EKUs in Oid dot notation.
        #[arg(long = "trust_config", env = "C2PATOOL_TRUST_CONFIG", value_parser = parse_resource_string)]
        trust_config: Option<TrustResource>,
    },
    /// Add a C2PA manifest to fragmented BMFF content.
    ///
    /// The init path can be a glob to process entire directories of content:
    ///
    ///   c2patool -m test.json -o /output "/renditions/**/init.mp4" fragment \
    ///       --fragments_glob "file_abc*[0-9].m4s"
    ///
    /// NOTE: Quote glob patterns to prevent shell expansion.
    Fragment {
        /// Glob pattern matching fragment file names (not full paths).
        #[arg(long = "fragments_glob", verbatim_doc_comment)]
        fragments_glob: Option<PathBuf>,
    },
}

fn configure_sdk(args: &CliArgs) -> Result<(Settings, Arc<C2paContext>)> {
    let mut settings = if args.settings.exists() {
        Settings::new().with_file(&args.settings)?
    } else {
        Settings::default()
    };

    if let Some(Commands::Trust {
        trust_anchors,
        allowed_list,
        trust_config,
    }) = &args.command
    {
        apply_trust_settings(
            &mut settings,
            trust_anchors.as_ref(),
            allowed_list.as_ref(),
            trust_config.as_ref(),
        )?;
    }

    let context = Arc::new(C2paContext::new().with_settings(&settings)?);
    Ok((settings, context))
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }
    env_logger::init();

    let path = &args.path;

    if args.info {
        return info::info(path);
    }

    if args.cert_chain {
        let reader = c2pa::Reader::from_context(C2paContext::new())
            .with_file(path)
            .map_err(util::special_errs)?;
        if let Some(manifest) = reader.active_manifest() {
            if let Some(si) = manifest.signature_info() {
                println!("{}", si.cert_chain());
                return Ok(());
            }
        }
        bail!("No certificate chain found");
    }

    if args.tree {
        println!("{}", tree::tree(path)?);
        return Ok(());
    }

    let is_fragment = matches!(
        &args.command,
        Some(Commands::Fragment { fragments_glob: _ })
    );

    let (mut settings, context) = configure_sdk(&args).context("Could not configure c2pa-rs")?;

    // --- Signing path: manifest JSON or inline config was provided ---
    if args.manifest.is_some() || args.config.is_some() {
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

        let (mut builder, mut sign_config) =
            sign::setup_builder(&json, base_path.as_ref(), &context)?;

        // sign_config also needs the base path for resolving key/cert files.
        if let Some(base) = &base_path {
            sign_config.set_base_path(base);
        }

        if let Some(parent_path) = args.parent {
            let mut ingredient = util::load_ingredient(&parent_path)?;
            ingredient.set_is_parent();
            builder.add_ingredient(ingredient);
        }

        sign::maybe_add_source_as_parent(&mut builder, path, is_fragment);
        sign::configure_output_mode(&mut builder, args.remote.as_ref(), args.sidecar);

        let signer = sign::select_signer(
            &sign_config,
            &mut settings,
            args.signer_path,
            args.reserve_size,
        )?;

        let output = args
            .output
            .as_ref()
            .context("Output path required with manifest definition")?;

        if let Some(Commands::Fragment { fragments_glob }) = &args.command {
            if output.exists() && !output.is_dir() {
                bail!("Output cannot point to existing file, must be a directory");
            }
            let fg = fragments_glob
                .as_ref()
                .context("fragments_glob must be set")?;
            return fragment::sign_fragmented(&mut builder, signer.as_ref(), path, fg, output);
        }

        let opts = sign::OutputOptions {
            output,
            sidecar: args.sidecar,
            force: args.force,
        };
        sign::sign_to_output(&mut builder, signer.as_ref(), path, &opts)?;

        // Show a report on the signed output.
        let mut reader = c2pa::Reader::from_shared_context(&context)
            .with_file(output)
            .map_err(util::special_errs)?;
        util::validate_cawg(&mut reader)?;
        read::print_reader(&reader, args.detailed, args.crjson)?;

    // --- Read-only path: output folder requested without a manifest ---
    } else if args.parent.is_some() || args.sidecar || args.remote.is_some() {
        bail!("Manifest definition required with these options or flags")
    } else if let Some(output) = args.output {
        if output.is_file() || output.extension().is_some() {
            bail!("Output must be a folder for this option.")
        }
        if args.ingredient {
            read::write_ingredient_to_folder(path, &output, args.force)?;
        } else {
            read::write_reader_to_folder(path, &output, args.detailed, args.force, &context)?;
        }

    // --- Ingredient report to stdout ---
    } else if args.ingredient {
        #[allow(deprecated)]
        let ingredient = c2pa::Ingredient::from_file(path).map_err(util::special_errs)?;
        println!("{ingredient}");

    // --- Fragmented read/verify ---
    } else if let Some(Commands::Fragment {
        fragments_glob: Some(fg),
    }) = &args.command
    {
        let mut stores = fragment::verify_fragmented(path, fg, &context)?;
        fragment::print_verified(&mut stores)?;

    // --- Default: read and display manifest ---
    } else {
        let mut reader = read::open_reader(path, args.external_manifest.as_ref(), &context)?;
        util::validate_cawg(&mut reader)?;
        read::print_reader(&reader, args.detailed, args.crjson)?;
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use c2pa::{BuilderIntent, DigitalSourceType};
    use tempfile::TempDir;

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

    fn tempdirectory() -> Result<TempDir> {
        #[cfg(target_os = "wasi")]
        return TempDir::new_in("/").map_err(Into::into);

        #[cfg(not(target_os = "wasi"))]
        return tempfile::tempdir().map_err(Into::into);
    }

    #[allow(deprecated)]
    #[test]
    fn test_manifest_config() {
        const SOURCE_PATH: &str = "tests/fixtures/earth_apollo17.jpg";
        let tempdir = tempdirectory().unwrap();
        let output_path = tempdir.path().join("unit_out.jpg");
        let mut builder = c2pa::Builder::from_json(CONFIG).expect("from_json");
        builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));

        let signer = signer::SignConfig::from_json(CONFIG)
            .unwrap()
            .set_base_path("sample")
            .signer()
            .expect("get_signer");

        let _result = builder
            .sign_file(signer.as_ref(), SOURCE_PATH, &output_path)
            .expect("embed");

        let ms = c2pa::Reader::from_file(output_path)
            .expect("from_file")
            .to_string();
        println!("{ms}");
        assert!(ms.contains("my_key"));
    }
}
