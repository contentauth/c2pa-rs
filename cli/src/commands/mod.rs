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

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use reqwest::Url;

pub use self::{extract::Extract, sign::Sign, view::View};

/// Tool for displaying and creating C2PA manifests.
#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct CliArgs {
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
    /// Extract manifest data from an asset.
    #[clap(subcommand)]
    Extract(Extract),
}

#[derive(Debug, Default, Parser)]
pub struct Trust {
    #[clap(flatten)]
    pub trust_anchors_source: TrustAnchorsSource,

    #[clap(flatten)]
    pub allowed_list_source: AllowedListSource,

    #[clap(flatten)]
    pub trust_config_source: TrustConfigSource,
}

#[derive(Debug, Default, Args)]
#[group(required = false, multiple = false)]
pub struct TrustAnchorsSource {
    /// Path to file containing list of trust anchors in PEM format.
    #[clap(long, env = "C2PATOOL_TRUST_ANCHORS")]
    pub trust_anchors: Option<PathBuf>,

    /// URL to file containing list of trust anchors in PEM format.
    #[clap(long, env = "C2PATOOL_TRUST_ANCHORS_URL")]
    pub trust_anchors_url: Option<Url>,
}

#[derive(Debug, Default, Args)]
#[group(required = false, multiple = false)]
pub struct AllowedListSource {
    /// Path to file containing list of trust anchors in PEM format.
    #[clap(long, env = "C2PATOOL_ALLOWED_LIST")]
    pub allowed_list: Option<PathBuf>,

    /// URL to file containing list of trust anchors in PEM format.
    #[clap(long, env = "C2PATOOL_ALLOWED_LISTURL")]
    pub allowed_list_url: Option<Url>,
}

#[derive(Debug, Default, Args)]
#[group(required = false, multiple = false)]
pub struct TrustConfigSource {
    /// Path to file containing configured EKUs in Oid dot notation.
    #[clap(long, env = "C2PATOOL_TRUST_CONFIG")]
    pub trust_config: Option<PathBuf>,

    /// URL to file containing configured EKUs in Oid dot notation.
    #[clap(long, env = "C2PATOOL_TRUST_CONFIG_URL")]
    pub trust_config_url: Option<Url>,
}

#[derive(Debug, Clone)]
pub enum InputSource<'a> {
    Path(&'a Path),
    Url(&'a Url),
}

impl InputSource<'_> {
    pub fn from_path_or_url<'a>(
        path: Option<&'a Path>,
        url: Option<&'a Url>,
    ) -> Option<InputSource<'a>> {
        if let Some(path) = path {
            Some(InputSource::Path(path))
        } else {
            url.map(InputSource::Url)
        }
    }

    pub fn resolve(&self) -> Result<String> {
        match self {
            InputSource::Path(path) => fs::read_to_string(path)
                .with_context(|| format!("Failed to read input from path: {:?}", path)),
            InputSource::Url(url) => reqwest::blocking::get((*url).to_owned())?
                .text()
                .with_context(|| format!("Failed to read input from URL: {}", url)),
        }
    }
}

pub fn load_trust_settings(trust: &Trust) -> Result<()> {
    let trust_anchors = InputSource::from_path_or_url(
        trust.trust_anchors_source.trust_anchors.as_deref(),
        trust.trust_anchors_source.trust_anchors_url.as_ref(),
    );
    if let Some(trust_anchors) = &trust_anchors {
        let data = trust_anchors.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "trust_anchors": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    let allowed_list = InputSource::from_path_or_url(
        trust.allowed_list_source.allowed_list.as_deref(),
        trust.allowed_list_source.allowed_list_url.as_ref(),
    );
    if let Some(allowed_list) = &allowed_list {
        let data = allowed_list.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "allowed_list": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    let trust_config = InputSource::from_path_or_url(
        trust.trust_config_source.trust_config.as_deref(),
        trust.trust_config_source.trust_config_url.as_ref(),
    );
    if let Some(trust_config) = &trust_config {
        let data = trust_config.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "trust_config": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    if trust_anchors.is_some() || allowed_list.is_some() || trust_config.is_some() {
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": true} }"#, "json")?;
    } else {
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": false} }"#, "json")?;
    }

    Ok(())
}
