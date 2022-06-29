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
/// If a claim def json file is specified, the claim will be added to any existing claims
/// If the claim def includes an asset_path, the claims in that file will be used instead
///
///
use anyhow::{anyhow, Result};
use c2pa::{Error, Ingredient, Manifest, ManifestStore, ManifestStoreReport};

use std::{
    fs,
    path::{Path, PathBuf},
    process::exit,
};
use structopt::{clap::AppSettings, StructOpt};

use tempfile::tempdir;

pub mod config;
use config::Config;
mod signer;
use signer::get_c2pa_signer;

// define the command line options
#[derive(Debug, StructOpt)]
#[structopt(about = "Tool for displaying and creating C2PA manifests.",global_settings = &[AppSettings::ColoredHelp, AppSettings::ArgRequiredElseHelp])]
struct CliArgs {
    #[structopt(parse(from_os_str))]
    #[structopt(short = "o", long = "output", help = "Path to output file.")]
    output: Option<std::path::PathBuf>,

    #[structopt(parse(from_os_str))]
    #[structopt(short = "p", long = "parent", help = "Path to parent file.")]
    parent: Option<std::path::PathBuf>,

    #[structopt(
        short = "c",
        long = "config",
        help = "Configuration passed as a JSON string."
    )]
    config: Option<String>,

    #[structopt(
        short = "d",
        long = "detailed",
        help = "Display detailed C2PA-formatted manifest data."
    )]
    detailed: bool,

    /// The path to the asset to read, or a JSON configuration file.
    #[structopt(parse(from_os_str))]
    path: Option<std::path::PathBuf>,
}

// converts any relative paths to absolute from base_path
pub fn fix_relative_path(path: &Path, base_path: &Path) -> PathBuf {
    if path.is_absolute() {
        return PathBuf::from(path);
    }
    let mut p = PathBuf::from(base_path);
    p.push(path);
    p
}

fn handle_config(
    json: &str,
    base_dir: &Path,
    parent: Option<&Path>,
    output_opt: Option<&Path>,
    is_detailed: bool,
) -> Result<String> {
    let config: Config = serde_json::from_str(json)?;

    let base_path = match &config.base_path {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(base_dir),
    };

    let signer = get_c2pa_signer(&config, &base_path)?;

    // construct a claim generator for this tool
    let mut claim_generator = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    // if the config has a claim_generator, add it as the first entry
    if let Some(generator) = config.claim_generator {
        claim_generator = format!("{} {}", generator, claim_generator);
    }

    let mut manifest = Manifest::new(claim_generator);

    if let Some(vendor) = config.vendor {
        manifest.set_vendor(vendor);
    }

    if let Some(credentials) = config.credentials.as_ref() {
        for credential in credentials {
            manifest.add_verifiable_credential(credential)?;
        }
    }

    // if the config has a parent, set the parent asset
    let parent = match parent {
        Some(parent) => Some(PathBuf::from(parent)),
        None => config
            .parent
            .as_deref()
            .map(|parent| fix_relative_path(parent, &base_path)),
    };
    if let Some(parent) = parent.as_ref() {
        if !parent.exists() {
            eprintln!("Parent file not found {:#?}", parent);
            exit(1);
        }
        manifest.set_parent(Ingredient::from_file(parent)?)?;
    }

    // add all the ingredients (config ingredients do not include the parent)
    if let Some(ingredients) = config.ingredients.as_ref() {
        for ingredient in ingredients {
            let path = fix_relative_path(ingredient, &base_path);
            if !path.exists() {
                eprintln!("Ingredient file not found {:#?}", path);
                exit(1);
            }
            let ingredient = Ingredient::from_file(&path).unwrap_or_else(|e| {
                eprintln!("error loading ingredient {:?} {:?}", &path, e);
                exit(1);
            });
            manifest.add_ingredient(ingredient);
        }
    }

    // add any assertions
    for assertion in config.assertions {
        manifest.add_labeled_assertion(assertion.label(), &assertion.value()?)?;
    }

    // if we have an output option, then we must have a source image to add a claim to
    // we need to determine the source file and copy it a temporary location where we will update it
    // once successfully written we can copy the temp back to the output location, possibly overwriting
    // The source can be an existing file at the output_path, or the parent file if we have one.
    if let Some(output) = output_opt {
        let file_name = match output.file_name().and_then(|s| s.to_str()) {
            Some(name) => name,
            None => {
                eprintln!("Missing or invalid filename on output");
                exit(1);
            }
        };
        // check for valid extension and do special extension handling
        let _extension = match output.extension().and_then(|s| s.to_str()) {
            Some(ext) => ext,
            None => {
                eprintln!("Missing or invalid extension on output");
                exit(1);
            }
        };

        // Predefine the manifest asset if we need to set a title
        // Todo: find a better way to set the title
        if let Some(t) = config.title.as_ref() {
            let mut asset = Ingredient::from_file_info(output);
            asset.set_title(t.to_owned());
            manifest.set_asset(asset);
        };

        // The source path points to the image we want to sign.
        // If a file already exists at the output location, we will treat that as the source
        // Otherwise, since this tool does no image editing, we can treat the parent file as the source.
        let source_path = match output.exists() {
            true => output,
            false => {
                let mut output_dir = PathBuf::from(output);
                output_dir.pop();
                std::fs::create_dir_all(&output_dir)?;
                parent.as_deref().filter(|p| p.exists()).or_else(||{
                    eprintln!("A valid parent path or existing output file is required for claim embedding");
                    exit(1);
                }).unwrap()
            }
        };

        // Embed to a temporary file and then rename or copy back to the output.
        // This way we never have a half written manifest if something fails.
        let dir = tempdir()?;

        // temp file_name must match output file name, it may be used as the claim title
        let temp_path = dir.path().join(&file_name);

        manifest
            .embed(source_path, &temp_path, signer.as_ref())
            .unwrap_or_else(|e| {
                eprintln!("error embedding manifest: {:?}", e);
                exit(1);
            });

        // embed completed successfully, now rename to the target path
        std::fs::rename(&temp_path, &output)
            // if rename fails, try to copy in case we are on different volumes
            .or_else(|_| std::fs::copy(&temp_path, &output).and(Ok(())))
            .map_err(Error::IoError)?;

        // generate a report on the output file
        report_from_path(&output, is_detailed)
    } else if is_detailed {
        Err(anyhow!("detailed report not supported for preview"))
    } else {
        Ok(ManifestStore::from_manifest(&manifest)?.to_string())
    }
}

// prints the requested kind of report or exits with error
fn report_from_path<P: AsRef<Path>>(path: &P, is_detailed: bool) -> Result<String> {
    let report = match is_detailed {
        true => ManifestStoreReport::from_file(path).map(|r| r.to_string()),
        false => ManifestStore::from_file(path).map(|r| r.to_string()),
    };
    // Map some errors to strings we expect
    report.map_err(|e| match e {
        Error::JumbfNotFound => anyhow!("No claim found"),
        Error::FileNotFound(name) => anyhow!("File not found: {}", name),
        Error::UnsupportedType => anyhow!("Unsupported file type"),
        Error::PrereleaseError => anyhow!("Prerelease claim found"),
        _ => e.into(),
    })
}

fn main() -> Result<()> {
    let args = CliArgs::from_args();

    // set RUST_LOG=debug to get detailed debug logging
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }
    env_logger::init();

    let mut config = args.config;
    let mut base_dir = PathBuf::from(".");

    if let Some(path) = args.path.clone() {
        let extension = path.extension().and_then(|p| p.to_str()).unwrap_or("");
        if extension == "json" {
            // file paths in Config are relative to the json file
            base_dir = PathBuf::from(&path);
            base_dir.pop();

            config = Some(fs::read_to_string(&path)?);
        } else {
            println!("{}", report_from_path(&path, args.detailed)?);
        }
    }

    if let Some(json) = config {
        println!(
            "{}",
            handle_config(
                &json,
                &base_dir,
                args.parent.as_deref(),
                args.output.as_deref(),
                args.detailed,
            )?
        );
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    const CONFIG: &str = r#"{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "whatever I want"}}]}"#;

    #[test]
    fn test_handle_config() {
        //let config = Some(fs::read_to_string("sample/test.json").expect("read_json"));
        let report = handle_config(
            CONFIG,
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            Some(&PathBuf::from("tests/fixtures/earth_apollo17.jpg")),
            Some(&PathBuf::from("target/tmp/unit_out.jpg")),
            false,
        )
        .expect("handle_config");
        assert!(report.contains("my_key"));
    }
}
