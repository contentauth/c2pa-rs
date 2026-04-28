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
/// A file path to an asset is required for normal commands (not for `init`).
/// If only the path is given, this will generate a summary report of any claims
/// in that file. If a manifest definition JSON file is specified,
/// the claim will be added to any existing claims.
use std::{
    env,
    fs::{self, copy, create_dir_all, remove_dir_all, remove_file, File},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{
    format_from_path, identity::validator::CawgValidator, settings::Settings, Builder,
    ClaimGeneratorInfo, Context as C2paContext, Error, Ingredient, ManifestDefinition, Reader,
    Signer,
};
use clap::{Parser, Subcommand};
use env_logger::Env;
use etcetera::BaseStrategy;
use log::debug;
use serde::Deserialize;
use signer::SignConfig;
use tempfile::NamedTempFile;
#[cfg(not(target_os = "wasi"))]
use tokio::runtime::Runtime;
use url::Url;
#[cfg(target_os = "wasi")]
use wstd::runtime::block_on;

use crate::{
    callback_signer::{CallbackSigner, CallbackSignerConfig, ExternalProcessRunner},
    info::info,
};

mod info;
mod tree;

mod callback_signer;
mod signer;

/// Official C2PA conformance trust list (PEM bundle).
const TRUST_LIST_OFFICIAL_URL: &str =
    "https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem";
/// Legacy interim trust anchors (PEM), fetched only with `init trust --legacy`.
const TRUST_LIST_LEGACY_ANCHORS_URL: &str = "https://contentcredentials.org/trust/anchors.pem";
const TRUST_LEGACY_STORE_CFG_URL: &str = "https://contentcredentials.org/trust/store.cfg";
const TRUST_LEGACY_ALLOWED_URL: &str = "https://contentcredentials.org/trust/allowed.sha256.txt";

/// Sidecar trust files stored next to the settings file (`--settings` parent directory).
const SIDECAR_TRUST_LIST_PEM: &str = "c2pa-trust-list.pem";
const SIDECAR_TRUST_LIST_LEGACY_PEM: &str = "c2pa-trust-list-legacy.pem";
const SIDECAR_TRUST_STORE_CFG: &str = "c2pa-trust-store.cfg";
const SIDECAR_TRUST_ALLOWED: &str = "c2pa-trust-allowed.sha256.txt";

/// Tool for displaying and creating C2PA manifests.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    arg_required_else_help(true),
    subcommand_negates_reqs = true
)]
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

    /// Path to an asset (omit for `init` only).
    path: Option<PathBuf>,

    /// Embed remote URL manifest reference.
    #[clap(short, long)]
    remote: Option<String>,

    /// Path to a binary .c2pa manifest to use for validation against the input asset.
    ///
    /// This field will override the input asset's embedded or remote manifest.
    #[clap(long)]
    external_manifest: Option<PathBuf>,

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

    /// Reserved buffer size for `--signer-path` signing only.
    #[clap(long, default_value("20000"))]
    reserve_size: usize,

    // TODO: ideally this would be called config, not to be confused with the other config arg
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
enum InitCmd {
    /// Fetch trust PEM/config sidecars next to `--settings` (no PATH required).
    Trust {
        /// Also fetch legacy interim anchors, store config, and allowed list (separate files).
        #[arg(long)]
        legacy: bool,
    },
}

// We only construct one per invocation, not worth shrinking this.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Commands {
    /// Bootstrap files beside `--settings` (trust lists, …).
    Init {
        #[command(subcommand)]
        cmd: InitCmd,
    },
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
    /// NOTE: The glob patterns are quoted to prevent shell expansion.
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
    // Flattened into the JSON root; the field is not read directly after deserialize.
    #[serde(flatten)]
    _manifest: ManifestDefinition,
    // allows adding ingredients with file paths
    ingredient_paths: Option<Vec<PathBuf>>,
}

// Convert certain errors to output messages.
fn special_errs(e: c2pa::Error) -> anyhow::Error {
    match e {
        Error::JumbfNotFound => anyhow!("No claim found"),
        Error::FileNotFound(name) => anyhow!("File not found: {name}"),
        Error::UnsupportedType => anyhow!("Unsupported file type"),
        Error::XmpNotSupported => {
            anyhow!("Format does not support XMP; cannot embed a remote URL reference")
        }
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
        #[allow(deprecated)]
        let result = Ingredient::from_file(path)?;
        Ok(result)
    }
}

fn load_trust_resource(resource: &TrustResource) -> Result<String> {
    match resource {
        TrustResource::File(path) => {
            let data = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read trust resource from path: {path:?}"))?;

            Ok(data)
        }
        TrustResource::Url(url) => {
            #[cfg(not(target_os = "wasi"))]
            let data = reqwest::blocking::get(url.to_string())?
                .text()
                .with_context(|| format!("Failed to read trust resource from URL: {url}"))?;

            #[cfg(target_os = "wasi")]
            let data = blocking_get(&url.to_string())?;
            Ok(data)
        }
    }
}

#[cfg(target_os = "wasi")]
fn blocking_get(url: &str) -> Result<String> {
    use std::io::Read;

    use url::Url;
    use wasi::http::{
        outgoing_handler,
        types::{Fields, OutgoingRequest, Scheme},
    };

    let parsed_url =
        Url::parse(url).map_err(|e| Error::ResourceNotFound(format!("invalid URL: {}", e)))?;
    let path_with_query = parsed_url[url::Position::BeforeHost..].to_string();
    let request = OutgoingRequest::new(Fields::new());
    request.set_path_with_query(Some(&path_with_query)).unwrap();

    // Set the scheme based on the URL.
    let scheme = match parsed_url.scheme() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        _ => return Err(anyhow!("unsupported URL scheme".to_string(),)),
    };

    request.set_scheme(Some(&scheme)).unwrap();

    match outgoing_handler::handle(request, None) {
        Ok(resp) => {
            resp.subscribe().block();

            let response = resp
                .get()
                .expect("HTTP request response missing")
                .expect("HTTP request response requested more than once")
                .expect("HTTP request failed");

            if response.status() == 200 {
                let raw_header = response.headers().get("Content-Length");
                if raw_header.first().map(|val| val.is_empty()).unwrap_or(true) {
                    return Err(anyhow!("url returned no content length".to_string()));
                }

                let str_parsed_header = match std::str::from_utf8(raw_header.first().unwrap()) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(anyhow!(format!(
                            "error parsing content length header: {}",
                            e
                        )))
                    }
                };

                let content_length: usize = match str_parsed_header.parse() {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(anyhow!(format!(
                            "error parsing content length header: {}",
                            e
                        )))
                    }
                };

                let body = {
                    let mut buf = Vec::with_capacity(content_length);
                    let response_body = response
                        .consume()
                        .expect("failed to get incoming request body");
                    let mut stream = response_body
                        .stream()
                        .expect("failed to get response body stream");
                    stream
                        .read_to_end(&mut buf)
                        .expect("failed to read response body");
                    buf
                };

                let body_string = std::str::from_utf8(&body)
                    .map_err(|e| anyhow!(format!("invalid UTF-8: {}", e)))?;
                Ok(body_string.to_string())
            } else {
                Err(anyhow!(format!(
                    "fetch failed: code: {}",
                    response.status(),
                )))
            }
        }

        Err(e) => Err(anyhow!(e.to_string())),
    }
}

/// Write `contents` to `dest` atomically: temp file in the same directory, fsync, then rename.
/// If `dest` already exists it is replaced without truncating in place (best-effort crash safety).
fn atomic_write_file(dest: &Path, contents: &[u8]) -> Result<()> {
    let parent = dest
        .parent()
        .context("destination path has no parent directory")?;
    fs::create_dir_all(parent)?;
    let stem = dest
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("c2pa-trust");
    let tmp = parent.join(format!(".{stem}.{}.tmp", std::process::id()));
    {
        let mut f = File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    if cfg!(windows) && dest.exists() {
        fs::remove_file(dest)?;
    }
    fs::rename(&tmp, dest)
        .with_context(|| format!("atomic rename {} -> {}", tmp.display(), dest.display()))?;
    Ok(())
}

/// Load trust PEM/config sidecars from the same directory as `--settings`, if present.
/// Returns whether any trust material was applied (for enabling `verify_trust`).
fn apply_trust_sidecars(settings: &mut Settings, settings_path: &Path) -> Result<bool> {
    let Some(dir) = settings_path.parent() else {
        return Ok(false);
    };
    let mut applied = false;

    let official = dir.join(SIDECAR_TRUST_LIST_PEM);
    if official.exists() {
        let data = fs::read_to_string(&official)
            .with_context(|| format!("read trust sidecar {}", official.display()))?;
        settings.update_from_str(
            &toml::toml! {
                [trust]
                trust_anchors = data
            }
            .to_string(),
            "toml",
        )?;
        applied = true;
    }

    let legacy_pem = dir.join(SIDECAR_TRUST_LIST_LEGACY_PEM);
    if legacy_pem.exists() {
        let data = fs::read_to_string(&legacy_pem)
            .with_context(|| format!("read legacy trust sidecar {}", legacy_pem.display()))?;
        settings.update_from_str(
            &toml::toml! {
                [trust]
                user_anchors = data
            }
            .to_string(),
            "toml",
        )?;
        applied = true;
    }

    let store_cfg = dir.join(SIDECAR_TRUST_STORE_CFG);
    if store_cfg.exists() {
        let data = fs::read_to_string(&store_cfg)
            .with_context(|| format!("read trust sidecar {}", store_cfg.display()))?;
        settings.update_from_str(
            &toml::toml! {
                [trust]
                trust_config = data
            }
            .to_string(),
            "toml",
        )?;
        applied = true;
    }

    let allowed = dir.join(SIDECAR_TRUST_ALLOWED);
    if allowed.exists() {
        let data = fs::read_to_string(&allowed)
            .with_context(|| format!("read trust sidecar {}", allowed.display()))?;
        settings.update_from_str(
            &toml::toml! {
                [trust]
                allowed_list = data
            }
            .to_string(),
            "toml",
        )?;
        applied = true;
    }

    Ok(applied)
}

fn run_trust_init(legacy: bool, settings_path: &Path) -> Result<()> {
    #[cfg(target_os = "wasi")]
    {
        bail!("`init trust` is not supported on this target (network fetch unavailable)");
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let dir = settings_path
            .parent()
            .context("settings path has no parent directory")?;
        fs::create_dir_all(dir)?;

        println!("Fetching official C2PA trust list...");
        let official = load_trust_resource(&TrustResource::Url(
            Url::parse(TRUST_LIST_OFFICIAL_URL).expect("constant URL"),
        ))?;
        let dest = dir.join(SIDECAR_TRUST_LIST_PEM);
        atomic_write_file(&dest, official.as_bytes())?;
        println!("Wrote {}", dest.display());

        if legacy {
            println!("Fetching legacy interim trust material...");
            let leg = load_trust_resource(&TrustResource::Url(
                Url::parse(TRUST_LIST_LEGACY_ANCHORS_URL).expect("constant URL"),
            ))?;
            atomic_write_file(&dir.join(SIDECAR_TRUST_LIST_LEGACY_PEM), leg.as_bytes())?;

            let cfg = load_trust_resource(&TrustResource::Url(
                Url::parse(TRUST_LEGACY_STORE_CFG_URL).expect("constant URL"),
            ))?;
            atomic_write_file(&dir.join(SIDECAR_TRUST_STORE_CFG), cfg.as_bytes())?;

            let allowed = load_trust_resource(&TrustResource::Url(
                Url::parse(TRUST_LEGACY_ALLOWED_URL).expect("constant URL"),
            ))?;
            atomic_write_file(&dir.join(SIDECAR_TRUST_ALLOWED), allowed.as_bytes())?;

            println!("Wrote legacy sidecars under {}", dir.display());
        }

        println!(
            "Trust sidecars are loaded automatically on the next run (same directory as {}).",
            settings_path.display()
        );
        Ok(())
    }
}

fn configure_sdk(args: &CliArgs) -> Result<Settings> {
    let mut settings = if args.settings.exists() {
        Settings::new().with_file(&args.settings)?
    } else {
        Settings::default()
    };

    let sidecar_trust = apply_trust_sidecars(&mut settings, &args.settings)?;

    let mut enable_trust_checks = sidecar_trust;

    if let Some(Commands::Trust {
        trust_anchors,
        allowed_list,
        trust_config,
    }) = &args.command
    {
        if let Some(trust_list) = &trust_anchors {
            debug!("Using trust anchors from {trust_list:?}");

            let data = load_trust_resource(trust_list)?;
            settings.update_from_str(
                &toml::toml! {
                    [trust]
                    trust_anchors = data
                }
                .to_string(),
                "toml",
            )?;

            enable_trust_checks = true;
        }

        if let Some(allowed_list) = &allowed_list {
            debug!("Using allowed list from {allowed_list:?}");

            let data = load_trust_resource(allowed_list)?;
            settings.update_from_str(
                &toml::toml! {
                    [trust]
                    allowed_list = data
                }
                .to_string(),
                "toml",
            )?;

            enable_trust_checks = true;
        }

        if let Some(trust_config) = &trust_config {
            debug!("Using trust config from {trust_config:?}");

            let data = load_trust_resource(trust_config)?;
            settings.update_from_str(
                &toml::toml! {
                    [trust]
                    trust_config = data
                }
                .to_string(),
                "toml",
            )?;

            enable_trust_checks = true;
        }
    }

    // If trust material came from CLI or sidecars, enable trust checks (cannot disable defaults).
    if enable_trust_checks {
        settings.update_from_str(
            &toml::toml! {
                [verify]
                verify_trust = true
            }
            .to_string(),
            "toml",
        )?;
    }

    Ok(settings)
}

fn sign_fragmented(
    builder: &mut Builder,
    signer: &dyn Signer,
    init_pattern: &Path,
    frag_pattern: &Path,
    output_path: &Path,
) -> Result<()> {
    // search folders for init segments
    let ip = init_pattern.to_str().ok_or(c2pa::Error::OtherError(
        "could not parse source pattern".into(),
    ))?;
    let inits = glob::glob(ip).context("could not process glob pattern")?;
    let count = inits.count();

    if count > 0 {
        builder.sign_fragmented_files(signer, init_pattern, frag_pattern, output_path)?;
    } else {
        println!("No files matching pattern: {ip}");
    }

    Ok(())
}

fn verify_fragmented(
    init_pattern: &Path,
    frag_pattern: &Path,
    context: &Arc<C2paContext>,
) -> Result<Vec<Reader>> {
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
                let reader =
                    Reader::from_shared_context(context).with_fragmented_files(p, &fragments)?;
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

fn reader_from_args(
    asset_path: &Path,
    args: &CliArgs,
    context: &Arc<C2paContext>,
) -> Result<Reader> {
    if let Some(external_manifest) = &args.external_manifest {
        let c2pa_data = fs::read(external_manifest)?;
        let format = match c2pa::format_from_path(asset_path) {
            Some(format) => format,
            None => {
                bail!("Format for {:?} is unrecognized", asset_path);
            }
        };
        Ok(Reader::from_shared_context(context)
            .with_manifest_data_and_stream(&c2pa_data, &format, File::open(asset_path)?)
            .map_err(special_errs)?)
    } else {
        Ok(Reader::from_shared_context(context)
            .with_file(asset_path)
            .map_err(special_errs)?)
    }
}

// Utility to catch reader formatting errors and print the reader json or detailed json
// formatting can fail if Reader CBOR is deeply nested or malformed
fn print_reader(reader: &Reader, detailed: bool, crjson: bool) -> Result<()> {
    let result = if crjson {
        reader.crjson_checked()
    } else if detailed {
        reader.detailed_json_checked()
    } else {
        reader.json_checked()
    }
    .map_err(|e| anyhow!("Error formatting output: {}", e));
    match result {
        Ok(json) => {
            println!("{json}");
            Ok(())
        }
        Err(e) => bail!("Error formatting output: {}", e),
    }
}

/// True when `--output` is suitable for folder-style use (e.g. `--ingredient` to a report dir,
/// or manifest report to a directory). A missing path is allowed (`create_dir_all` will make it);
/// an existing path must be a directory (names like `v1.0` are not inferred from a dot in the
/// last component).
pub(crate) fn folder_mode_output_path_ok(path: &Path) -> bool {
    !path.exists() || path.is_dir()
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    // default to error logging, RUST_LOG=debug to get detailed debug logging
    env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();

    if let Some(Commands::Init { cmd }) = &args.command {
        return match cmd {
            InitCmd::Trust { legacy } => run_trust_init(*legacy, &args.settings),
        };
    }

    let path = args
        .path
        .as_ref()
        .context("PATH to an asset is required (omit only for `init`)")?;

    if args.info {
        return info(path);
    }

    if args.cert_chain {
        let reader = Reader::from_context(C2paContext::new())
            .with_file(path)
            .map_err(special_errs)?;
        // todo: add cawg certs here??
        if let Some(manifest) = reader.active_manifest() {
            if let Some(si) = manifest.signature_info() {
                println!("{}", si.cert_chain());
                // todo: add ocsp validation info
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

    // configure the SDK
    let mut settings = configure_sdk(&args).context("Could not configure c2pa-rs")?;
    let context = Arc::new(C2paContext::new().with_settings(&settings)?);

    // Remove manifest needs to also remove XMP provenance
    // if args.remove_manifest {
    //     match args.output {
    //         Some(output) => {
    //             if output.exists() && !args.force {
    //                 bail!("Output already exists; use -f/force to force write");
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
        let mut builder = Builder::from_shared_context(&context).with_definition(&json)?;

        // add claim_tool generator so we know this was created using this tool
        let mut tool_generator = ClaimGeneratorInfo::new(env!("CARGO_PKG_NAME"));
        tool_generator.set_version(env!("CARGO_PKG_VERSION"));
        if builder.definition.claim_generator_info.is_empty()
            || builder.definition.claim_generator_info[0].name == "c2pa-rs"
        {
            builder.definition.claim_generator_info = vec![tool_generator];
        }
        // else: user supplied a custom `claim_generator_info` (v2 allows only one); keep it

        // set manifest base path before ingredients so ingredients can override it
        if let Some(base) = base_path.as_ref() {
            builder.set_base_path(base);
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
                builder.add_ingredient(ingredient);
            }
        }

        if let Some(parent_path) = args.parent {
            let mut ingredient = load_ingredient(&parent_path)?;
            ingredient.set_is_parent();
            builder.add_ingredient(ingredient);
        }

        // If the source file has a manifest store, and no parent is specified treat the source as a parent.
        // note: This could be treated as an update manifest eventually since the image is the same
        let has_parent = builder.definition.ingredients.iter().any(|i| i.is_parent());
        if !has_parent && !is_fragment {
            #[allow(deprecated)]
            let mut source_ingredient = Ingredient::from_file(path)?;
            if source_ingredient.manifest_data().is_some() {
                source_ingredient.set_is_parent();
                builder.add_ingredient(source_ingredient);
            }
        }

        if let Some(remote) = args.remote {
            if args.sidecar {
                builder.set_no_embed(true);
                builder.set_remote_url(remote);
            } else {
                builder.set_remote_url(remote);
            }
        } else if args.sidecar {
            builder.set_no_embed(true);
        }

        let signer = if let Some(signer_process_name) = args.signer_path {
            let cb_config = CallbackSignerConfig::new(&sign_config, args.reserve_size)?;

            let process_runner = Box::new(ExternalProcessRunner::new(
                cb_config.clone(),
                signer_process_name,
            ));
            let signer = CallbackSigner::new(process_runner, cb_config);

            Box::new(signer)
        } else if let Some(signer_cfg) = settings.signer.take() {
            let c2pa_signer = signer_cfg.c2pa_signer()?;
            if let Some(cawg_cfg) = settings.cawg_x509_signer.take() {
                cawg_cfg.cawg_signer(c2pa_signer)?
            } else {
                c2pa_signer
            }
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
                    return sign_fragmented(&mut builder, signer.as_ref(), path, fg, &output);
                } else {
                    bail!("fragments_glob must be set");
                }
            } else {
                if ext_normal(&output) != ext_normal(path) {
                    bail!("Output type must match source type");
                }
                if output.exists() {
                    if args.force && output != *path {
                        remove_file(&output)?;
                    } else if !args.force {
                        bail!("Output already exists; use -f/force to force write");
                    }
                }
                if output.file_name().is_none() {
                    bail!("Missing filename on output");
                }
                if output.extension().is_none() {
                    bail!("Missing extension output");
                }

                let manifest_data = if *path != output {
                    builder
                        .sign_file(signer.as_ref(), path, &output)
                        .context("embedding manifest")?
                } else {
                    let mut file = NamedTempFile::new()?;
                    let format = format_from_path(path)
                        .ok_or(c2pa::Error::UnsupportedType)
                        .context("unsupported file type")?;
                    let mut source = File::open(path)?;
                    if builder.definition.title.is_none() {
                        if let Some(title) = output.file_name() {
                            builder.definition.title = Some(title.to_string_lossy().to_string());
                        }
                    }
                    let manifest_data =
                        builder.sign(signer.as_ref(), &format, &mut source, &mut file)?;

                    if !output.exists() {
                        // ensure the path to the file exists
                        if let Some(output_dir) = &output.parent() {
                            create_dir_all(output_dir)?;
                        }
                    }

                    match file.persist(&output) {
                        Ok(_) => {}
                        Err(e) => {
                            let file = e.file;
                            copy(file, &output)?;
                        }
                    }

                    manifest_data
                };

                if args.sidecar {
                    let sidecar = output.with_extension("c2pa");
                    let mut file = File::create(&sidecar)?;
                    file.write_all(&manifest_data)?;
                }

                // generate a report on the output file
                let mut reader = Reader::from_shared_context(&context)
                    .with_file(&output)
                    .map_err(special_errs)?;
                validate_cawg(&mut reader)?;
                print_reader(&reader, args.detailed, args.crjson)?;
            }
        } else {
            bail!("Output path required with manifest definition")
        }
    } else if args.parent.is_some() || args.sidecar || args.remote.is_some() {
        bail!("Manifest definition required with these options or flags")
    } else if let Some(output) = args.output {
        if !folder_mode_output_path_ok(&output) {
            bail!("Output must be a folder for this option.")
        }
        if output.exists() {
            if args.force {
                remove_dir_all(&output)?;
            } else {
                bail!("Output already exists; use -f/force to force write");
            }
        }
        create_dir_all(&output)?;
        if args.ingredient {
            #[allow(deprecated)]
            let report = Ingredient::from_file_with_folder(path, &output)
                .map_err(special_errs)?
                .to_string();
            File::create(output.join("ingredient.json"))?.write_all(&report.into_bytes())?;
            println!("Ingredient report written to the directory {:?}", &output);
        } else {
            let mut reader = Reader::from_shared_context(&context)
                .with_file(path)
                .map_err(special_errs)?;
            validate_cawg(&mut reader)?;
            reader.to_folder(&output)?;
            let report = reader.to_string();
            if args.detailed {
                // for a detailed report first call the above to generate the thumbnails
                // then call this to add the detailed report
                let detailed = format!("{reader:#?}");
                File::create(output.join("detailed.json"))?.write_all(&detailed.into_bytes())?;
            }
            File::create(output.join("manifest_store.json"))?.write_all(&report.into_bytes())?;
            println!("Manifest report written to the directory {:?}", &output);
        }
    } else if args.ingredient {
        #[allow(deprecated)]
        let ingredient = Ingredient::from_file(path).map_err(special_errs)?;
        println!("{}", ingredient)
    } else if let Some(Commands::Fragment {
        fragments_glob: Some(fg),
    }) = &args.command
    {
        let mut stores = verify_fragmented(path, fg, &context)?;
        if stores.len() == 1 {
            validate_cawg(&mut stores[0])?;
            println!("{}", stores[0]);
        } else {
            for store in &mut stores {
                validate_cawg(store)?;
            }
            println!("{} Init manifests validated", stores.len());
        }
    } else {
        let mut reader = reader_from_args(path, &args, &context)?;
        validate_cawg(&mut reader)?;
        print_reader(&reader, args.detailed, args.crjson)?;
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs::{create_dir, write};

    use c2pa::{BuilderIntent, DigitalSourceType, Settings};
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
    fn folder_mode_output_path_accepts_dir_with_dot_in_name() {
        let tmp = tempdirectory().unwrap();
        let p = tmp.path().join("release.v1.0");
        create_dir(&p).unwrap();
        assert!(folder_mode_output_path_ok(&p));
    }

    #[test]
    fn folder_mode_output_path_accepts_nonexistent_path() {
        let tmp = tempdirectory().unwrap();
        let p = tmp.path().join("not_created_yet");
        assert!(folder_mode_output_path_ok(&p));
    }

    #[test]
    fn folder_mode_output_path_rejects_existing_file() {
        let tmp = tempdirectory().unwrap();
        let f = tmp.path().join("report.json");
        write(&f, b"{}").unwrap();
        assert!(!folder_mode_output_path_ok(&f));
    }

    #[allow(deprecated)]
    #[test]
    fn test_manifest_config() {
        const SOURCE_PATH: &str = "tests/fixtures/earth_apollo17.jpg";
        let tempdir = tempdirectory().unwrap();
        let output_path = tempdir.path().join("unit_out.jpg");
        let mut builder = Builder::from_json(CONFIG).expect("from_json");
        builder.set_intent(BuilderIntent::Create(DigitalSourceType::Empty));

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

    #[test]
    fn atomic_write_file_writes_and_replaces() {
        let tmp = tempdirectory().unwrap();
        let dest = tmp.path().join("out.pem");
        atomic_write_file(&dest, b"first").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "first");
        atomic_write_file(&dest, b"second").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "second");
    }

    #[test]
    fn apply_trust_sidecars_reads_official_pem() {
        const SAMPLE_ANCHOR_PEM: &str = include_str!("../../cli/tests/fixtures/trust/anchors.pem");
        let tmp = tempdirectory().unwrap();
        let settings_path = tmp.path().join("c2pa.toml");
        write(
            tmp.path().join(SIDECAR_TRUST_LIST_PEM),
            SAMPLE_ANCHOR_PEM.as_bytes(),
        )
        .unwrap();
        let mut settings = Settings::default();
        assert!(apply_trust_sidecars(&mut settings, &settings_path).unwrap());
        let ta = settings
            .trust
            .trust_anchors
            .as_deref()
            .expect("trust_anchors");
        assert!(ta.contains("BEGIN CERTIFICATE"));
    }
}
