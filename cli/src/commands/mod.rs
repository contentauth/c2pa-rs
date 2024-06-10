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

mod extract;
mod sign;
mod view;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
pub use extract::extract;
pub use sign::sign;
use url::Url;
pub use view::view;

/// Tool for displaying and creating C2PA manifests.
#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct CliArgs {
    // TODO: restrict it so input and command can't be specified simulataneously
    /// Input path to asset to display manifset for.
    pub path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Use verbose output (-vv very verbose output).
    #[arg(short, long, global=true, action = ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Sign an asset with a manifest.
    Sign(Sign),
    /// View information about a manifest in an asset.
    #[clap(subcommand)]
    View(View),
    /// Extract known resources from a manifest (e.g. thumbnails).
    Extract(Extract),
}

#[derive(Debug, Parser)]
pub struct Sign {
    /// Input glob path to asset.
    pub path: String,

    /// Path to output file or folder (if multiple inputs are specified)
    #[clap(short, long)]
    pub output: PathBuf,

    /// Path or URL to manifest JSON.
    #[clap(short, long, value_parser = InputSource::validate)]
    pub manifest: InputSource,

    /// Generate a .c2pa manifest file next to the output without embedding.
    #[clap(short, long)]
    pub sidecar: bool,

    /// Force overwrite of output if it already exists.
    #[clap(short, long)]
    pub force: bool,

    /// Path to the parent ingredient json.
    #[clap(short, long)]
    pub parent: Option<PathBuf>,

    /// Path to an executable that will sign the claim bytes, defaults to built-in signer.
    #[clap(long)]
    pub signer_path: Option<PathBuf>,

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
    pub reserve_size: usize,

    /// Do not perform validation of signature after signing.
    #[clap(long)]
    pub no_verify: bool,

    #[clap(flatten)]
    pub trust: Trust,
}

#[derive(Debug, Subcommand)]
pub enum View {
    /// View manifest in JSON format.
    Manifest {
        /// Input path to asset.
        path: PathBuf,

        /// Display debug information about the manifest.
        #[clap(short, long)]
        debug: bool,

        #[clap(flatten)]
        trust: Trust,
    },
    /// View various info about the manifest (e.g. file size).
    Info {
        /// Input path to asset.
        path: PathBuf,

        #[clap(flatten)]
        trust: Trust,
    },
    /// View a tree diagram of the manifest store.
    Tree {
        /// Input path to asset.
        path: PathBuf,

        #[clap(flatten)]
        trust: Trust,
    },
    /// View the manifest certificate chain.
    Certs {
        /// Input path to asset.
        path: PathBuf,

        #[clap(flatten)]
        trust: Trust,
    },
}

#[derive(Debug, Parser)]
pub struct Extract {
    /// Input glob path to asset.
    pub path: String,

    /// Path to output folder.
    #[clap(short, long)]
    pub output: PathBuf,

    #[clap(flatten)]
    trust: Trust,
    // TODO: add flag for additionally exporting unknown ingredients (ingredients that
    // do not have a standardized label) as a binary file
}

#[derive(Debug, Default, Parser)]
pub struct Trust {
    /// Path or URL to file containing list of trust anchors in PEM format.
    #[clap(long, env="C2PATOOL_TRUST_ANCHORS", value_parser = InputSource::validate)]
    pub trust_anchors: Option<InputSource>,

    /// Path or URL to file containing specific manifest signing certificates in PEM format to implicitly trust.
    #[clap(long, env="C2PATOOL_ALLOWED_LIST", value_parser = InputSource::validate)]
    pub allowed_list: Option<InputSource>,

    /// Path or URL to file containing configured EKUs in Oid dot notation.
    #[clap(long, env="C2PATOOL_TRUST_CONFIG", value_parser = InputSource::validate)]
    pub trust_config: Option<InputSource>,
}

#[derive(Debug, Clone)]
pub enum InputSource {
    Path(PathBuf),
    Url(Url),
}

impl InputSource {
    fn validate(s: &str) -> Result<InputSource> {
        if let Ok(url) = s.parse::<Url>() {
            Ok(InputSource::Url(url))
        } else {
            Ok(InputSource::Path(s.into()))
        }
    }

    pub fn resolve(&self) -> Result<String> {
        let data = match self {
            InputSource::Path(path) => fs::read_to_string(path)
                .with_context(|| format!("Failed to read input from path: {:?}", path))?,
            InputSource::Url(url) => reqwest::blocking::get(url.to_string())?
                .text()
                .with_context(|| format!("Failed to read input from URL: {}", url))?,
        };
        Ok(data)
    }
}
