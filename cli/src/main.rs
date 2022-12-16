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
///
use std::fs::{create_dir_all, remove_dir_all};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{Error, ManifestStore, ManifestStoreReport};
use structopt::{clap::AppSettings, StructOpt};

mod info;
use info::info;
pub mod manifest_config;
use manifest_config::ManifestConfig;
mod fs_report;
mod signer;
use signer::get_c2pa_signer;

// define the command line options
#[derive(Debug, StructOpt)]
#[structopt(about = "Tool for displaying and creating C2PA manifests.",global_settings = &[AppSettings::ColoredHelp, AppSettings::ArgRequiredElseHelp])]
struct CliArgs {
    #[structopt(parse(from_os_str))]
    #[structopt(
        short = "m",
        long = "manifest",
        help = "Path to manifest definition JSON file."
    )]
    manifest: Option<PathBuf>,

    #[structopt(parse(from_os_str))]
    #[structopt(short = "o", long = "output", help = "Path to output file or folder.")]
    output: Option<PathBuf>,

    #[structopt(parse(from_os_str))]
    #[structopt(short = "p", long = "parent", help = "Path to a parent file.")]
    parent: Option<PathBuf>,

    #[structopt(
        short = "c",
        long = "config",
        help = "Manifest definition passed as a JSON string."
    )]
    config: Option<String>,

    #[structopt(
        short = "d",
        long = "detailed",
        help = "Display detailed C2PA-formatted manifest data."
    )]
    detailed: bool,

    #[structopt(
        short = "f",
        long = "force",
        help = "Force overwrite of output if it already exists."
    )]
    force: bool,

    /// The path to an asset to examine or embed a manifest into.
    #[structopt(parse(from_os_str))]
    path: Vec<PathBuf>,

    #[structopt(
        short = "r",
        long = "remote",
        help = "Embed remote URL manifest reference."
    )]
    remote: Option<String>,

    #[structopt(
        short = "s",
        long = "sidecar",
        help = "Generate a sidecar (.c2pa) manifest"
    )]
    sidecar: bool,

    #[structopt(long = "info", help = "Show manifest size, XMP url and other stats")]
    info: bool,
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

    if args.info && !args.path.is_empty() {
        return info(&args.path[0]);
    }

    // get manifest config from either the -manifest option or the -config option
    let config = if let Some(json) = args.config {
        if args.manifest.is_some() {
            bail!("Do not use config and manifest options together");
        }
        Some(ManifestConfig::from_json(&json)?)
    } else if let Some(config_path) = args.manifest {
        Some(ManifestConfig::from_file(&config_path)?)
    } else {
        None
    };

    // if we have a manifest config, process it
    if let Some(mut manifest_config) = config {
        if let Some(parent_path) = args.parent {
            manifest_config.parent = Some(parent_path)
        }

        for path in args.path {
        // If the source file has a manifest store, and no parent is specified treat the source as a parent.
        // note: This could be treated as an update manifest eventually since the image is the same
        let source_ingredient = c2pa::Ingredient::from_file(&path)?;
        if source_ingredient.manifest_data().is_some() && manifest_config.parent.is_none() {
            manifest_config.parent = Some(std::fs::canonicalize(&path)?);
        }

        let mut manifest = manifest_config.to_manifest()?;

        if let Some(ref remote) = args.remote {
            if args.sidecar {
                manifest.set_embedded_manifest_with_remote_ref(remote);
            } else {
                manifest.set_remote_manifest(remote);
            }
        } else if args.sidecar {
            manifest.set_sidecar_manifest();
        }

        if let Some(ref output) = args.output {
            if output.extension() != path.extension() {
                bail!("output type must match source type");
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

            // create any needed folders for the output path (embed should do this)
            let mut output_dir = PathBuf::from(&output);
            output_dir.pop();
            create_dir_all(&output_dir)?;

            let signer = get_c2pa_signer(&manifest_config)?;

            manifest
                .embed(&path, &output, signer.as_ref())
                .context("embedding manifest")?;

            // generate a report on the output file
            match report_from_path(&output, args.detailed) {
                Ok(result) => println!("{result}"),
                Err(err) => println!("{err}"),
            }
            //println!("{}", report_from_path(&output, args.detailed)?);
        } else if args.detailed {
            bail!("detailed report not supported for preview");
        } else {
            // normally the output file provides the title, format and other manifest fields
            // since there is no output file, gather some information from the source
            if let Some(extension) = path
                .extension()
                .map(|e| e.to_string_lossy().to_string())
            {
                // set the format field
                match extension.as_str() {
                    "jpg" | "jpeg" => {
                        manifest.set_format("image/jpeg");
                    }
                    "png" => {
                        manifest.set_format("image/png");
                    }
                    _ => (),
                }
            }
            println!("{}", ManifestStore::from_manifest(&manifest)?)
        }
        }
    } else if let Some(output) = args.output {
        if output.exists() {
            if args.force {
                remove_dir_all(&output)?;
            } else {
                bail!("Output already exists, use -f/force to force write");
            }
        }
        for path in args.path {
            //let manifest_path = output.join()
            fs_report::write_report_for_path(&path, &output, args.detailed)?;
            println!("Manifest report written to the directory {:?}", &output);
        }
    } else if args.parent.is_some() || args.sidecar || args.remote.is_some() || args.force {
        bail!("manifest definition required with these options or flags")
    } else {
        // let extension = path.extension().and_then(|p| p.to_str()).unwrap_or("");
        // just report from file if no manifest configuration given
        for path in args.path {
            match report_from_path(&path, args.detailed) {
                Ok(result) => println!("{path:?}:\n{result}"),
                Err(err) => println!("{path:?}: {err}"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    const CONFIG: &str = r#"{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "whatever I want"}}]}"#;

    #[test]
    fn test_manifest_config() {
        const SOURCE_PATH: &str = "tests/fixtures/earth_apollo17.jpg";
        const OUTPUT_PATH: &str = "target/unit_out.jpg";

        let config = ManifestConfig::from_json(CONFIG).expect("from_json");
        let mut manifest = config.to_manifest().expect("to_manifest");

        let signer = get_c2pa_signer(&config).expect("get_signer");

        let _result = manifest
            .embed(SOURCE_PATH, OUTPUT_PATH, signer.as_ref())
            .expect("embed");

        //let ms = ManifestStore::from_bytes("jpeg", result, false).expect("from_bytes");
        let ms = report_from_path(&OUTPUT_PATH, false).expect("report_from_path");
        assert!(ms.contains("my_key"));
    }
}
