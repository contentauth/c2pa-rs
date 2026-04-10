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
/// A file path to an asset must be provided. If only the path
/// is given, this will generate a summary report of any claims
/// in that file. If a manifest definition JSON file is specified,
/// the claim will be added to any existing claims.
use std::path::PathBuf;

use anyhow::{Context, Result};
use c2pa::settings::Settings;
use clap::{Parser, Subcommand};
use etcetera::BaseStrategy;

mod callback_signer;
mod commands;
mod info;
mod signer;
mod tree;

/// Tool for displaying and creating C2PA manifests.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, arg_required_else_help(true))]
struct CliArgs {
    /// Path to SDK settings file (JSON or TOML format)
    ///
    /// Configure signing credentials, trust anchors, and SDK behavior.
    /// Default location: $XDG_CONFIG_HOME/c2pa/settings.json
    #[clap(
        long,
        env = "C2PATOOL_SETTINGS",
        default_value = default_settings_path().into_os_string()
    )]
    settings: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

fn default_settings_path() -> PathBuf {
    let strategy = etcetera::choose_base_strategy().unwrap();
    let mut path = strategy.config_dir();
    path.push("c2pa");
    path.push("settings.json");
    path
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Read and validate a C2PA asset
    Show {
        /// Path to asset to examine
        #[clap(value_name = "FILE")]
        input: PathBuf,

        /// Show detailed C2PA-formatted manifest data
        #[clap(short, long)]
        detailed: bool,

        /// Display as tree diagram
        #[clap(long)]
        tree: bool,

        /// Extract certificate chain to stdout
        #[clap(long)]
        certs: bool,

        /// Show manifest size, XMP URL and other stats
        #[clap(long)]
        info: bool,

        /// Path to external .c2pa manifest (overrides embedded)
        #[clap(long, value_name = "FILE")]
        external_manifest: Option<PathBuf>,

        /// Output file or directory for report
        #[clap(short, long, value_name = "PATH")]
        output: Option<PathBuf>,

        /// Force overwrite if output exists
        #[clap(short, long)]
        force: bool,
    },

    /// Create a saved ingredient from an asset (.c2pa file)
    Ingredient {
        /// Path to asset
        #[clap(value_name = "FILE")]
        input: PathBuf,

        /// Output .c2pa file path or directory for detailed report
        #[clap(short, long, value_name = "FILE|DIR")]
        output: PathBuf,

        /// Generate detailed ingredient report with assets
        #[clap(short, long)]
        detailed: bool,

        /// Force overwrite if output exists
        #[clap(short, long)]
        force: bool,
    },

    /// Create a new manifest with digital source type (create intent)
    Create {
        /// Input asset file (used to generate output, not a parent)
        #[clap(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Digital source type for the new asset
        #[clap(long, value_name = "TYPE")]
        source_type: String,

        /// Path to manifest definition JSON file
        #[clap(short, long, value_name = "FILE", conflicts_with = "manifest_json")]
        manifest: Option<PathBuf>,

        /// Manifest definition as JSON string
        #[clap(long, conflicts_with = "manifest")]
        manifest_json: Option<String>,

        /// Additional ingredient files or .c2pa archives to add
        #[clap(long = "ingredient", value_name = "FILE")]
        ingredients: Vec<PathBuf>,

        /// Output path for signed asset or builder archive (.c2pa)
        #[clap(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Save as builder archive instead of signing
        #[clap(long, conflicts_with_all = ["sidecar", "remote"])]
        archive: bool,

        /// Generate sidecar (.c2pa) instead of embedding signature
        #[clap(long, conflicts_with = "archive")]
        sidecar: bool,

        /// Embed remote URL manifest reference
        #[clap(long, value_name = "URL", conflicts_with = "archive")]
        remote: Option<String>,

        /// Force overwrite if output exists
        #[clap(short, long)]
        force: bool,
    },

    /// Edit an existing asset with new assertions (edit intent)
    Edit {
        /// Parent asset (required, creates parent ingredient)
        #[clap(short, long, value_name = "FILE")]
        parent: PathBuf,

        /// Input asset file (edited version, defaults to parent if not specified)
        #[clap(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Path to manifest definition JSON file
        #[clap(short, long, value_name = "FILE", conflicts_with = "manifest_json")]
        manifest: Option<PathBuf>,

        /// Manifest definition as JSON string
        #[clap(long, conflicts_with = "manifest")]
        manifest_json: Option<String>,

        /// Additional ingredient files or .c2pa archives to add
        #[clap(long = "ingredient", value_name = "FILE")]
        ingredients: Vec<PathBuf>,

        /// Output path for signed asset or builder archive (.c2pa)
        #[clap(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Save as builder archive instead of signing
        #[clap(long, conflicts_with_all = ["sidecar", "remote"])]
        archive: bool,

        /// Generate sidecar (.c2pa) instead of embedding signature
        #[clap(long, conflicts_with = "archive")]
        sidecar: bool,

        /// Embed remote URL manifest reference
        #[clap(long, value_name = "URL", conflicts_with = "archive")]
        remote: Option<String>,

        /// Force overwrite if output exists
        #[clap(short, long)]
        force: bool,
    },

    /// Update an existing asset with minimal changes (update intent)
    Update {
        /// Input asset (this is the parent for update intent)
        #[clap(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Path to manifest definition JSON file
        #[clap(short, long, value_name = "FILE", conflicts_with = "manifest_json")]
        manifest: Option<PathBuf>,

        /// Manifest definition as JSON string
        #[clap(long, conflicts_with = "manifest")]
        manifest_json: Option<String>,

        /// Output path for signed asset or builder archive (.c2pa)
        #[clap(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Save as builder archive instead of signing
        #[clap(long, conflicts_with_all = ["sidecar", "remote"])]
        archive: bool,

        /// Generate sidecar (.c2pa) instead of embedding signature
        #[clap(long, conflicts_with = "archive")]
        sidecar: bool,

        /// Embed remote URL manifest reference
        #[clap(long, value_name = "URL", conflicts_with = "archive")]
        remote: Option<String>,

        /// Force overwrite if output exists
        #[clap(short, long)]
        force: bool,
    },

    /// Resume work from a saved builder archive
    Resume {
        /// Path to builder archive (.c2pa)
        #[clap(value_name = "FILE")]
        archive: PathBuf,

        /// Additional ingredient files or .c2pa archives to add
        #[clap(long = "ingredient", value_name = "FILE")]
        ingredients: Vec<PathBuf>,

        /// Output path for signed asset or updated builder archive (.c2pa)
        #[clap(short, long, value_name = "FILE")]
        output: PathBuf,

        /// Save as builder archive instead of signing
        #[clap(long, conflicts_with_all = ["sidecar", "remote"])]
        archive_output: bool,

        /// Generate sidecar (.c2pa) instead of embedding signature
        #[clap(long, conflicts_with = "archive_output")]
        sidecar: bool,

        /// Embed remote URL manifest reference
        #[clap(long, value_name = "URL", conflicts_with = "archive_output")]
        remote: Option<String>,

        /// Force overwrite if output exists
        #[clap(short, long)]
        force: bool,
    },

    /// Manage settings configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Sign fragmented BMFF content
    Fragment {
        /// Path to init segment (can be a glob pattern)
        #[clap(value_name = "INIT_SEGMENT")]
        input: PathBuf,

        /// Path to manifest definition JSON
        #[clap(short, long, value_name = "FILE")]
        manifest: PathBuf,

        /// Glob pattern for fragment files
        #[clap(long, value_name = "PATTERN")]
        fragments_glob: PathBuf,

        /// Output directory
        #[clap(short, long, value_name = "DIR")]
        output: PathBuf,

        /// Force overwrite if output exists
        #[clap(short, long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ConfigAction {
    /// Show current settings
    Show,

    /// Initialize default config file
    Init {
        /// Force overwrite if config already exists
        #[clap(short, long)]
        force: bool,
    },

    /// Validate config file
    Validate,

    /// Show path to config file
    Path,
}

fn configure_sdk(args: &CliArgs) -> Result<()> {
    if args.settings.exists() {
        Settings::from_file(&args.settings)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    env_logger::init();

    configure_sdk(&args).context("Could not configure c2pa-rs")?;

    match &args.command {
        Commands::Show {
            input,
            detailed,
            tree,
            certs,
            info,
            external_manifest,
            output,
            force,
        } => commands::show::run(
            input,
            *detailed,
            *tree,
            *certs,
            *info,
            external_manifest.as_ref(),
            output.as_ref(),
            *force,
        ),

        Commands::Ingredient {
            input,
            output,
            detailed,
            force,
        } => commands::ingredient::run(input, output, *detailed, *force),

        Commands::Create {
            input,
            source_type: _,
            manifest,
            manifest_json,
            ingredients,
            output,
            archive,
            sidecar,
            remote,
            force,
        } => commands::sign::run_create(
            input,
            manifest.as_ref(),
            manifest_json.as_ref(),
            ingredients,
            output,
            *archive,
            *sidecar,
            remote.as_ref(),
            *force,
        ),

        Commands::Edit {
            parent,
            input,
            manifest,
            manifest_json,
            ingredients,
            output,
            archive,
            sidecar,
            remote,
            force,
        } => commands::sign::run_edit(
            parent,
            input.as_ref(),
            manifest.as_ref(),
            manifest_json.as_ref(),
            ingredients,
            output,
            *archive,
            *sidecar,
            remote.as_ref(),
            *force,
        ),

        Commands::Update {
            input,
            manifest,
            manifest_json,
            output,
            archive,
            sidecar,
            remote,
            force,
        } => commands::sign::run_update(
            input,
            manifest.as_ref(),
            manifest_json.as_ref(),
            output,
            *archive,
            *sidecar,
            remote.as_ref(),
            *force,
        ),

        Commands::Resume {
            archive: archive_path,
            ingredients,
            output,
            archive_output,
            sidecar,
            remote,
            force,
        } => commands::resume::run(
            archive_path,
            ingredients,
            output,
            *archive_output,
            *sidecar,
            remote.as_ref(),
            *force,
        ),

        Commands::Config { action } => commands::config::run(&args.settings, action),

        Commands::Fragment {
            input,
            manifest,
            fragments_glob,
            output,
            force,
        } => commands::fragment::run(input, manifest, fragments_glob, output, *force),
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use c2pa::{Builder, Reader};
    use tempfile::TempDir;

    use crate::signer::SignConfig;

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

    fn tempdirectory() -> anyhow::Result<TempDir> {
        #[cfg(target_os = "wasi")]
        return TempDir::new_in("/").map_err(Into::into);

        #[cfg(not(target_os = "wasi"))]
        return tempfile::tempdir().map_err(Into::into);
    }

    #[test]
    fn test_manifest_config() {
        const SOURCE_PATH: &str = "tests/fixtures/earth_apollo17.jpg";
        let tempdir = tempdirectory().unwrap();
        let output_path = tempdir.path().join("unit_out.jpg");
        let mut builder = Builder::from_json(CONFIG).expect("from_json");

        let signer = SignConfig::from_json(CONFIG)
            .unwrap()
            .set_base_path("sample")
            .signer()
            .expect("get_signer");

        let _result = builder
            .sign_file(signer.as_ref(), SOURCE_PATH, &output_path)
            .expect("embed");

        let ms = Reader::from_file(output_path)
            .expect("from_file")
            .to_string();
        println!("{ms}");
        assert!(ms.contains("my_key"));
    }
}
