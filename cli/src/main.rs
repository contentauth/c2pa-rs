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
use std::{
    env,
    fs::{self, copy, create_dir_all, remove_dir_all, remove_file, File},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{
    format_from_path, identity::validator::CawgValidator, settings::Settings, Builder,
    ClaimGeneratorInfo, Error, Ingredient, ManifestDefinition, Reader, Signer,
};
use clap::{Parser, Subcommand};
use etcetera::BaseStrategy;
use log::debug;
use serde::Deserialize;
use signer::SignConfig;
use tempfile::NamedTempFile;
#[cfg(not(target_os = "wasi"))]
use tokio::runtime::Runtime;
#[cfg(target_os = "wasi")]
use wstd::runtime::block_on;

use crate::{
    info::info,
};

mod info;
mod tree;

mod callback_signer;
mod signer;

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
enum ConfigAction {
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

#[derive(Debug, Default, Deserialize)]
// Add fields that are not part of the standard Manifest
struct ManifestDef {
    #[serde(flatten)]
    manifest: ManifestDefinition,
    // allows adding ingredients with file paths
    ingredient_paths: Option<Vec<PathBuf>>,
}

// Convert certain errors to output messages.
fn special_errs(e: c2pa::Error) -> anyhow::Error {
    match e {
        Error::JumbfNotFound => anyhow!("No claim found"),
        Error::FileNotFound(name) => anyhow!("File not found: {name}"),
        Error::UnsupportedType => anyhow!("Unsupported file type"),
        Error::PrereleaseError => anyhow!("Prerelease claim found"),
        _ => e.into(),
    }
}

// Normalize extensions so we can compare them.
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

fn configure_sdk(args: &CliArgs) -> Result<()> {
    if args.settings.exists() {
        Settings::from_file(&args.settings)?;
    }
    Ok(())
}

fn sign_fragmented(
    builder: &mut Builder,
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

                println!("Adding manifest to: {p:?}");
                let new_output_path =
                    output_path.join(init_dir.file_name().context("invalid file name")?);
                builder.sign_fragmented_files(signer, &p, &fragments, &new_output_path)?;

                count += 1;
            }
            Err(_) => bail!("bad path to init segment"),
        }
    }
    if count == 0 {
        println!("No files matching pattern: {ip}");
    }
    Ok(())
}

fn verify_fragmented(init_pattern: &Path, frag_pattern: &Path) -> Result<Vec<Reader>> {
    let mut readers = Vec::new();

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

                println!("Verifying manifest: {p:?}");
                let reader = Reader::from_fragmented_files(p, &fragments)?;
                if let Some(vs) = reader.validation_status() {
                    if let Some(e) = vs.iter().find(|v| !v.passed()) {
                        eprintln!("Error validating segments: {e:?}");
                        return Ok(readers);
                    }
                }

                readers.push(reader);

                count += 1;
            }
            Err(_) => bail!("bad path to init segment"),
        }
    }

    if count == 0 {
        println!("No files matching pattern: {ip}");
    }

    Ok(readers)
}

// run cawg validation if supported
fn validate_cawg(reader: &mut Reader) -> Result<()> {
    #[cfg(not(target_os = "wasi"))]
    {
        Runtime::new()?
            .block_on(reader.post_validate_async(&CawgValidator {}))
            .map_err(anyhow::Error::from)
    }
    #[cfg(target_os = "wasi")]
    {
        block_on(reader.post_validate_async(&CawgValidator {})).map_err(anyhow::Error::from)
    }
}

fn handle_config_command(args: &CliArgs, action: &ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            if args.settings.exists() {
                let content = std::fs::read_to_string(&args.settings)?;
                println!("{}", content);
            } else {
                println!("No settings file found at: {}", args.settings.display());
                println!("Run 'c2patool config init' to create a default settings file.");
            }
        }
        ConfigAction::Init { force } => {
            if args.settings.exists() && !force {
                bail!(
                    "Settings file already exists at: {}\nUse --force to overwrite",
                    args.settings.display()
                );
            }

            // Create parent directory if it doesn't exist
            if let Some(parent) = args.settings.parent() {
                std::fs::create_dir_all(parent)?;
            }

            // Create default settings file (JSON format) matching SDK Settings structure
            let default_settings = serde_json::json!({
                "sign": {
                    "alg": "es256",
                    "private_key": "path/to/private.key",
                    "sign_cert": "path/to/certs.pem",
                    "ta_url": "http://timestamp.digicert.com"
                },
                "verify": {
                    "verify_trust": false
                }
            });

            let settings_str = serde_json::to_string_pretty(&default_settings)?;
            std::fs::write(&args.settings, settings_str)?;

            println!("Default settings file created at: {}", args.settings.display());
            println!("\nEdit this file to configure your signing credentials and other settings.");
        }
        ConfigAction::Validate => {
            if !args.settings.exists() {
                bail!("Settings file not found at: {}", args.settings.display());
            }

            // Try to load settings to validate
            Settings::from_file(&args.settings)?;
            println!("Settings file is valid: {}", args.settings.display());
        }
        ConfigAction::Path => {
            println!("{}", args.settings.display());
            if args.settings.exists() {
                println!("(file exists)");
            } else {
                println!("(file does not exist)");
            }
        }
    }
    Ok(())
}

fn get_signer(sign_config: &SignConfig) -> Result<Box<dyn Signer>> {
    match Settings::signer() {
        Ok(signer) => Ok(signer),
        Err(Error::MissingSignerSettings) => sign_config.signer(),
        Err(err) => Err(err)?,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_create_command(
    input: &Path,
    _source_type: &str,
    manifest: Option<&PathBuf>,
    manifest_json: Option<&String>,
    ingredients: &[PathBuf],
    output: &Path,
    archive: bool,
    sidecar: bool,
    remote: Option<&String>,
    force: bool,
) -> Result<()> {
    // TODO: Add support for source_type (Intent::Create) when SDK supports it
    
    // Read the json from file or string
    let (json, base_path) = match manifest {
        Some(manifest_path) => {
            let base_path = std::fs::canonicalize(manifest_path)?
                .parent()
                .map(|p| p.to_path_buf());
            (std::fs::read_to_string(manifest_path)?, base_path)
        }
        None => (
            manifest_json.cloned().unwrap_or_default(),
            std::env::current_dir().ok(),
        ),
    };

    let mut sign_config = SignConfig::from_json(&json)?;
    let manifest_def: ManifestDef = serde_json::from_slice(json.as_bytes())?;
    let mut builder = Builder::from_json(&json)?;

    // Set base path
    if let Some(base) = base_path.as_ref() {
        builder.set_base_path(base);
        sign_config.set_base_path(base);
    }

    // Add ingredients from manifest definition
    if let Some(paths) = manifest_def. {
        for mut path in paths {
            if let Some(base) = &base_path {
                if !path.is_absolute() {
                    path = base.join(&path);
                }
            }
            let ingredient = load_ingredient(&path)?;
            builder.add_ingredient(ingredient);
        }
    }

    // Add ingredients from command line
    for ingredient_path in ingredients {
        let ingredient = load_ingredient(ingredient_path)?;
        builder.add_ingredient(ingredient);
    }

    // Handle remote/sidecar options
    if let Some(remote_url) = remote {
        builder.set_remote_url(remote_url.clone());
        if sidecar {
            builder.set_no_embed(true);
        }
    } else if sidecar {
        builder.set_no_embed(true);
    }

    if archive {
        // Save as builder archive
        if output.exists() && !force {
            bail!("Output already exists; use -f/force to force write");
        }
        let mut archive_file = File::create(output)?;
        builder.to_archive(&mut archive_file)?;
        println!("Builder archive saved to: {}", output.display());
    } else {
        // Sign and save
        let signer = get_signer(&sign_config)?;
        
        if ext_normal(output) != ext_normal(input) {
            bail!("Output type must match source type");
        }

        // Handle force flag - delete output if it exists and force is true
        if output.exists() && force {
            remove_file(output)?;
        } else if output.exists() {
            bail!("Output already exists; use -f/force to force write");
        }

        let manifest_data = builder
            .sign_file(signer.as_ref(), input, output)
            .context("embedding manifest")?;

        if sidecar {
            let sidecar_path = output.with_extension("c2pa");
            File::create(&sidecar_path)?.write_all(&manifest_data)?;
        }

        let mut reader = Reader::from_file(output).map_err(special_errs)?;
        validate_cawg(&mut reader)?;
        println!("{reader}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_edit_command(
    parent: &Path,
    input: Option<&PathBuf>,
    manifest: Option<&PathBuf>,
    manifest_json: Option<&String>,
    ingredients: &[PathBuf],
    output: &Path,
    archive: bool,
    sidecar: bool,
    remote: Option<&String>,
    force: bool,
) -> Result<()> {
    // Use parent as input if not specified
    let input_path = input.map(|p| p.as_path()).unwrap_or(parent);

    // Read the json from file or string
    let (json, base_path) = match manifest {
        Some(manifest_path) => {
            let base_path = std::fs::canonicalize(manifest_path)?
                .parent()
                .map(|p| p.to_path_buf());
            (std::fs::read_to_string(manifest_path)?, base_path)
        }
        None => (
            manifest_json.cloned().unwrap_or_default(),
            std::env::current_dir().ok(),
        ),
    };

    let mut sign_config = SignConfig::from_json(&json)?;
    let manifest_def: ManifestDef = serde_json::from_slice(json.as_bytes())?;
    let mut builder = Builder::from_json(&json)?;

    // Set base path
    if let Some(base) = base_path.as_ref() {
        builder.set_base_path(base);
        sign_config.set_base_path(base);
    }

    // Add ingredients from manifest definition
    if let Some(paths) = manifest_def.ingredient_paths {
        for mut path in paths {
            if let Some(base) = &base_path {
                if !path.is_absolute() {
                    path = base.join(&path);
                }
            }
            let ingredient = load_ingredient(&path)?;
            builder.add_ingredient(ingredient);
        }
    }

    // Add parent ingredient
    let mut parent_ingredient = load_ingredient(parent)?;
    parent_ingredient.set_is_parent();
    builder.add_ingredient(parent_ingredient);

    // Add ingredients from command line
    for ingredient_path in ingredients {
        let ingredient = load_ingredient(ingredient_path)?;
        builder.add_ingredient(ingredient);
    }

    // Handle remote/sidecar options
    if let Some(remote_url) = remote {
        builder.set_remote_url(remote_url.clone());
        if sidecar {
            builder.set_no_embed(true);
        }
    } else if sidecar {
        builder.set_no_embed(true);
    }

    if archive {
        // Save as builder archive
        if output.exists() && !force {
            bail!("Output already exists; use -f/force to force write");
        }
        let mut archive_file = File::create(output)?;
        builder.to_archive(&mut archive_file)?;
        println!("Builder archive saved to: {}", output.display());
    } else {
        // Sign and save
        let signer = get_signer(&sign_config)?;
        
        if ext_normal(output) != ext_normal(input_path) {
            bail!("Output type must match input type");
        }

        // Special case: if input and output are the same, copy input to temp file first
        let temp_input = if input_path == output && output.exists() {
            let temp = NamedTempFile::new()?;
            copy(input_path, temp.path())?;
            Some(temp)
        } else {
            None
        };

        let actual_input = if let Some(ref temp) = temp_input {
            temp.path()
        } else {
            input_path
        };

        // Handle force flag - delete output if it exists and force is true
        if output.exists() && force {
            remove_file(output)?;
        } else if output.exists() {
            bail!("Output already exists; use -f/force to force write");
        }

        let manifest_data = builder
            .sign_file(signer.as_ref(), actual_input, output)
            .context("embedding manifest")?;

        if sidecar {
            let sidecar_path = output.with_extension("c2pa");
            File::create(&sidecar_path)?.write_all(&manifest_data)?;
        }

        let mut reader = Reader::from_file(output).map_err(special_errs)?;
        validate_cawg(&mut reader)?;
        println!("{reader}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_update_command(
    input: &Path,
    manifest: Option<&PathBuf>,
    manifest_json: Option<&String>,
    output: &Path,
    archive: bool,
    sidecar: bool,
    remote: Option<&String>,
    force: bool,
) -> Result<()> {
    // Read the json from file or string
    let (json, base_path) = match manifest {
        Some(manifest_path) => {
            let base_path = std::fs::canonicalize(manifest_path)?
                .parent()
                .map(|p| p.to_path_buf());
            (std::fs::read_to_string(manifest_path)?, base_path)
        }
        None => (
            manifest_json.cloned().unwrap_or_default(),
            std::env::current_dir().ok(),
        ),
    };

    let mut sign_config = SignConfig::from_json(&json)?;
    let manifest_def: ManifestDef = serde_json::from_slice(json.as_bytes())?;
    let mut builder = Builder::from_json(&json)?;

    // Set base path
    if let Some(base) = base_path.as_ref() {
        builder.set_base_path(base);
        sign_config.set_base_path(base);
    }

    // Add ingredients from manifest definition
    if let Some(paths) = manifest_def.ingredient_paths {
        for mut path in paths {
            if let Some(base) = &base_path {
                if !path.is_absolute() {
                    path = base.join(&path);
                }
            }
            let ingredient = load_ingredient(&path)?;
            builder.add_ingredient(ingredient);
        }
    }

    // For update, input is the parent
    let mut parent_ingredient = load_ingredient(input)?;
    parent_ingredient.set_is_parent();
    builder.add_ingredient(parent_ingredient);

    // Handle remote/sidecar options
    if let Some(remote_url) = remote {
        builder.set_remote_url(remote_url.clone());
        if sidecar {
            builder.set_no_embed(true);
        }
    } else if sidecar {
        builder.set_no_embed(true);
    }

    if archive {
        // Save as builder archive
        if output.exists() && !force {
            bail!("Output already exists; use -f/force to force write");
        }
        let mut archive_file = File::create(output)?;
        builder.to_archive(&mut archive_file)?;
        println!("Builder archive saved to: {}", output.display());
    } else {
        // Sign and save
        let signer = get_signer(&sign_config)?;
        
        if ext_normal(output) != ext_normal(input) {
            bail!("Output type must match input type");
        }

        // Handle force flag - delete output if it exists and force is true
        if output.exists() && force {
            remove_file(output)?;
        } else if output.exists() {
            bail!("Output already exists; use -f/force to force write");
        }

        let manifest_data = builder
            .sign_file(signer.as_ref(), input, output)
            .context("embedding manifest")?;

        if sidecar {
            let sidecar_path = output.with_extension("c2pa");
            File::create(&sidecar_path)?.write_all(&manifest_data)?;
        }

        let mut reader = Reader::from_file(output).map_err(special_errs)?;
        validate_cawg(&mut reader)?;
        println!("{reader}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_resume_command(
    archive_path: &Path,
    ingredients: &[PathBuf],
    output: &Path,
    archive_output: bool,
    sidecar: bool,
    remote: Option<&String>,
    force: bool,
) -> Result<()> {
    // Load builder from archive
    let mut builder = Builder::from_archive(File::open(archive_path)?)?;

    // Add ingredients from command line
    for ingredient_path in ingredients {
        let ingredient = load_ingredient(ingredient_path)?;
        builder.add_ingredient(ingredient);
    }

    // Handle remote/sidecar options
    if let Some(remote_url) = remote {
        builder.set_remote_url(remote_url.clone());
        if sidecar {
            builder.set_no_embed(true);
        }
    } else if sidecar {
        builder.set_no_embed(true);
    }

    if archive_output {
        // Save as builder archive
        if output.exists() && !force {
            bail!("Output already exists; use -f/force to force write");
        }
        let mut archive_file = File::create(output)?;
        builder.to_archive(&mut archive_file)?;
        println!("Builder archive saved to: {}", output.display());
    } else {
        // Sign and save
        // Get signer from settings since we don't have manifest JSON
        let _signer = match Settings::signer() {
            Ok(signer) => signer,
            Err(e) => bail!("No signer configured in settings: {}", e),
        };
        
        if output.exists() && !force {
            bail!("Output already exists; use -f/force to force write");
        }

        // TODO: Need to get the input path from the archive
        // For now, this will need SDK support
        bail!("Resume signing not yet fully implemented - SDK needs to store input reference in archive");
    }

    Ok(())
}

fn handle_fragment_command(
    input: &Path,
    manifest: &Path,
    fragments_glob: &Path,
    output: &Path,
    force: bool,
) -> Result<()> {
    if output.exists() && !output.is_dir() {
        bail!("Output cannot point to existing file, must be a directory");
    }

    if output.exists() && !force {
        bail!("Output already exists; use -f/force to force write");
    }

    // Read manifest
    let json = std::fs::read_to_string(manifest)?;
    let base_path = std::fs::canonicalize(manifest)?
        .parent()
        .map(|p| p.to_path_buf());

    let mut sign_config = SignConfig::from_json(&json)?;
    let manifest_def: ManifestDef = serde_json::from_slice(json.as_bytes())?;
    let mut builder = Builder::from_json(&json)?;

    // Set base path
    if let Some(base) = base_path.as_ref() {
        builder.set_base_path(base);
        sign_config.set_base_path(base);
    }

    // Add ingredients from manifest definition
    if let Some(paths) = manifest_def.ingredient_paths {
        for mut path in paths {
            if let Some(base) = &base_path {
                if !path.is_absolute() {
                    path = base.join(&path);
                }
            }
            let ingredient = load_ingredient(&path)?;
            builder.add_ingredient(ingredient);
        }
    }

    let signer = get_signer(&sign_config)?;

    sign_fragmented(&mut builder, signer.as_ref(), input, &fragments_glob.to_path_buf(), output)?;

    Ok(())
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    // set RUST_LOG=debug to get detailed debug logging
    // if std::env::var("RUST_LOG").is_err() {
    //     std::env::set_var("RUST_LOG", "error");
    // }
    env_logger::init();

    // configure the SDK
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
        } => {
            if *info {
                return self::info(input);
            }

            if *certs {
                let reader = Reader::from_file(input).map_err(special_errs)?;
                if let Some(manifest) = reader.active_manifest() {
                    if let Some(si) = manifest.signature_info() {
                        println!("{}", si.cert_chain());
                        return Ok(());
                    }
                }
                bail!("No certificate chain found");
            }

            if *tree {
                println!("{}", self::tree::tree(input)?);
                return Ok(());
            }

            let mut reader = if let Some(external_manifest) = external_manifest {
                let c2pa_data = fs::read(external_manifest)?;
                let format = match c2pa::format_from_path(input) {
                    Some(format) => format,
                    None => bail!("Format for {:?} is unrecognized", input),
                };
                Reader::from_manifest_data_and_stream(&c2pa_data, &format, File::open(input)?)
                    .map_err(special_errs)?
            } else {
                Reader::from_file(input).map_err(special_errs)?
            };

            validate_cawg(&mut reader)?;

            // Handle output to file or directory
            if let Some(output_path) = output {
                if output_path.is_dir() || (!output_path.exists() && output_path.extension().is_none()) {
                    // Directory output - write manifest_store.json and optionally detailed.json
                    if output_path.exists() {
                        if *force {
                            remove_dir_all(output_path)?;
                        } else {
                            bail!("Output already exists; use -f/force to force write");
                        }
                    }
                    create_dir_all(output_path)?;

                    if *detailed {
                        let detailed_json = format!("{reader:#?}");
                        File::create(output_path.join("detailed.json"))?
                            .write_all(detailed_json.as_bytes())?;
                    } else {
                        let summary = reader.to_string();
                        File::create(output_path.join("manifest_store.json"))?
                            .write_all(summary.as_bytes())?;
                    }
                    println!("Manifest report written to the directory {output_path:?}");
                } else {
                    // File output
                    if output_path.exists() && !force {
                        bail!("Output already exists; use -f/force to force write");
                    }
                    let content = if *detailed {
                        format!("{reader:#?}")
                    } else {
                        reader.to_string()
                    };
                    std::fs::write(output_path, content)?;
                    println!("Manifest report written to {}", output_path.display());
                }
            } else {
                // Print to stdout
                if *detailed {
                    println!("{reader:#?}");
                } else {
                    println!("{reader}");
                }
            }
        }

        Commands::Ingredient {
            input,
            output,
            detailed,
            force,
        } => {
            if output.is_file() || output.extension().is_some() {
                // Single file output
                if output.exists() && !force {
                    bail!("Output already exists; use -f/force to force write");
                }
                let ingredient = Ingredient::from_file(input).map_err(special_errs)?;
                let report = ingredient.to_string();
                std::fs::write(output, report)?;
                println!("Ingredient saved to: {}", output.display());
            } else {
                // Directory output
                if output.exists() {
                    if *force {
                        remove_dir_all(output)?;
                    } else {
                        bail!("Output already exists; use -f/force to force write");
                    }
                }
                create_dir_all(output)?;

                if *detailed {
                    let report = Ingredient::from_file_with_folder(input, output)
                        .map_err(special_errs)?
                        .to_string();
                    File::create(output.join("ingredient.json"))?.write_all(&report.into_bytes())?;
                    println!("Ingredient report written to: {}", output.display());
                } else {
                    let ingredient = Ingredient::from_file(input).map_err(special_errs)?;
                    let report = ingredient.to_string();
                    File::create(output.join("ingredient.json"))?.write_all(&report.into_bytes())?;
                    println!("Ingredient saved to: {}", output.display());
                }
            }
        }

        Commands::Create {
            input,
            source_type,
            manifest,
            manifest_json,
            ingredients,
            output,
            archive,
            sidecar,
            remote,
            force,
        } => {
            handle_create_command(
                input,
                source_type,
                manifest.as_ref(),
                manifest_json.as_ref(),
                ingredients,
                output,
                *archive,
                *sidecar,
                remote.as_ref(),
                *force,
            )?;
        }

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
        } => {
            handle_edit_command(
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
            )?;
        }

        Commands::Update {
            input,
            manifest,
            manifest_json,
            output,
            archive,
            sidecar,
            remote,
            force,
        } => {
            handle_update_command(
                input,
                manifest.as_ref(),
                manifest_json.as_ref(),
                output,
                *archive,
                *sidecar,
                remote.as_ref(),
                *force,
            )?;
        }

        Commands::Resume {
            archive: archive_path,
            ingredients,
            output,
            archive_output,
            sidecar,
            remote,
            force,
        } => {
            handle_resume_command(
                archive_path,
                ingredients,
                output,
                *archive_output,
                *sidecar,
                remote.as_ref(),
                *force,
            )?;
        }

        Commands::Config { action } => {
            handle_config_command(&args, action)?;
        }

        Commands::Fragment {
            input,
            manifest,
            fragments_glob,
            output,
            force,
        } => {
            handle_fragment_command(input, manifest, fragments_glob, output, *force)?;
        }
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

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
        //let ms = report_from_path(&OUTPUT_PATH, false).expect("report_from_path");
        assert!(ms.contains("my_key"));
    }
}
