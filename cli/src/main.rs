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
    fs::{create_dir_all, remove_dir_all, remove_file, File},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{
    identity::validator::CawgValidator, Builder, ClaimGeneratorInfo, Error, Ingredient,
    ManifestDefinition, Reader, Signer,
};
use clap::{Parser, Subcommand};
use log::debug;
use serde::Deserialize;
use signer::SignConfig;
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
    #[serde(flatten)]
    manifest: ManifestDefinition,
    // allows adding ingredients with file paths
    ingredient_paths: Option<Vec<PathBuf>>,
}

// Convert certain errors to output messages.
fn special_errs(e: c2pa::Error) -> anyhow::Error {
    match e {
        Error::JumbfNotFound => anyhow!("No claim found"),
        Error::FileNotFound(name) => anyhow!("File not found: {}", name),
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
            debug!("Using trust anchors from {trust_list:?}");
            let replacement_val = serde_json::Value::String(data).to_string(); // escape string
            let setting = TA.replace("replacement_val", &replacement_val);

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(allowed_list) = &allowed_list {
            let data = load_trust_resource(allowed_list)?;
            debug!("Using allowed list from {allowed_list:?}");
            let replacement_val = serde_json::Value::String(data).to_string(); // escape string
            let setting = AL.replace("replacement_val", &replacement_val);

            c2pa::settings::load_settings_from_str(&setting, "json")?;

            enable_trust_checks = true;
        }

        if let Some(trust_config) = &trust_config {
            let data = load_trust_resource(trust_config)?;
            debug!("Using trust config from {trust_config:?}");
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
        let reader = Reader::from_file(path).map_err(special_errs)?;
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
    configure_sdk(&args).context("Could not configure c2pa-rs")?;

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
        let mut builder = Builder::from_json(&json)?;
        let mut manifest = manifest_def.manifest;

        // add claim_tool generator so we know this was created using this tool
        let mut tool_generator = ClaimGeneratorInfo::new(env!("CARGO_PKG_NAME"));
        tool_generator.set_version(env!("CARGO_PKG_VERSION"));
        if !manifest.claim_generator_info.is_empty()
            || manifest.claim_generator_info[0].name == "c2pa-rs"
        {
            manifest.claim_generator_info = vec![tool_generator];
        } else {
            manifest.claim_generator_info.insert(1, tool_generator);
        }

        // set manifest base path before ingredients so ingredients can override it
        if let Some(base) = base_path.as_ref() {
            builder.base_path = Some(base.clone());
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
            let mut source_ingredient = Ingredient::from_file(&args.path)?;
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
                    return sign_fragmented(&mut builder, signer.as_ref(), &args.path, fg, &output);
                } else {
                    bail!("fragments_glob must be set");
                }
            } else {
                if ext_normal(&output) != ext_normal(&args.path) {
                    bail!("Output type must match source type");
                }
                if output.exists() {
                    if args.force {
                        remove_file(&output)?;
                    } else {
                        bail!("Output already exists; use -f/force to force write");
                    }
                }

                if output.file_name().is_none() {
                    bail!("Missing filename on output");
                }
                if output.extension().is_none() {
                    bail!("Missing extension output");
                }

                let manifest_data = builder
                    .sign_file(signer.as_ref(), &args.path, &output)
                    .context("embedding manifest")?;

                if args.sidecar {
                    let sidecar = output.with_extension("c2pa");
                    let mut file = File::create(&sidecar)?;
                    file.write_all(&manifest_data)?;
                }

                // generate a report on the output file
                let mut reader = Reader::from_file(&output).map_err(special_errs)?;
                validate_cawg(&mut reader)?;
                if args.detailed {
                    println!("{reader:#?}");
                } else {
                    println!("{reader}")
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
                bail!("Output already exists; use -f/force to force write");
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
            let mut reader = Reader::from_file(&args.path).map_err(special_errs)?;
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
        println!(
            "{}",
            Ingredient::from_file(&args.path).map_err(special_errs)?
        )
    } else if args.detailed {
        let mut reader = Reader::from_file(&args.path).map_err(special_errs)?;
        validate_cawg(&mut reader)?;
        println!("{reader:#?}");
    } else if let Some(Commands::Fragment {
        fragments_glob: Some(fg),
    }) = &args.command
    {
        let mut stores = verify_fragmented(&args.path, fg)?;
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
        let mut reader = Reader::from_file(&args.path).map_err(special_errs)?;
        validate_cawg(&mut reader)?;
        println!("{reader}");
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
