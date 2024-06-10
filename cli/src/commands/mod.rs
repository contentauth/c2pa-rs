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
use url::Url;

pub use self::{extract::Extract, sign::Sign, view::View};

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
