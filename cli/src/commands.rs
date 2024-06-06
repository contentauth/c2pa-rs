use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use url::Url;

/// Tool for displaying and creating C2PA manifests.
#[derive(Debug, Parser)]
#[command(author, version, about, rename_all = "snake_case")]
pub struct CliArgs {
    // TODO: restrict it so input and command can't be specified simulataneously
    /// Input path to asset to display manifset for.
    pub input: Option<PathBuf>,

    #[clap(flatten)]
    pub trust: Trust,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
#[command(rename_all = "snake_case")]
pub enum Commands {
    /// Sign an asset with a manifest.
    Sign {
        /// Input path(s) to asset.
        input: Vec<PathBuf>,

        // TODO: impl parser to require dir if multiple inputs
        /// Path to output file or folder (if multiple inputs are specified)
        #[clap(short, long)]
        output: PathBuf,

        /// Path or URL to manifest JSON.
        #[clap(short, long, value_parser = InputSource::validate)]
        manifest: InputSource,

        /// Generate a .c2pa manifest file next to the output without embedding.
        #[clap(short, long)]
        no_embed: bool,

        /// Force overwrite of output if it already exists.
        #[clap(short, long)]
        force: bool,

        /// Path to the parent ingredient json.
        #[clap(short, long)]
        parent: Option<PathBuf>,

        /// Path to an executable that will sign the claim bytes, defaults to built-in signer.
        #[clap(long)]
        signer_path: Option<PathBuf>,

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
        reserve_size: usize,

        /// Do not perform validation of signature after signing.
        #[clap(long)]
        no_verify_signing: bool,
    },
    /// Display information about a C2PA manifest in an asset.
    Display {
        #[command(subcommand)]
        command: Information,
    },
}

#[derive(Debug, Parser)]
#[command(rename_all = "snake_case")]
pub struct Trust {
    /// Path or URL to file containing list of trust anchors in PEM format.
    #[clap(long, global=true, env="C2PATOOL_TRUST_ANCHORS", value_parser = InputSource::validate)]
    pub trust_anchors: Option<InputSource>,

    /// Path or URL to file containing specific manifest signing certificates in PEM format to implicitly trust.
    #[clap(long, global=true, env="C2PATOOL_ALLOWED_LIST", value_parser = InputSource::validate)]
    pub allowed_list: Option<InputSource>,

    /// Path or url to file containing configured EKUs in Oid dot notation.
    #[clap(long, global=true, env="C2PATOOL_TRUST_CONFIG", value_parser = InputSource::validate)]
    pub trust_config: Option<InputSource>,
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "snake_case")]
pub enum Information {
    /// Display user-friendly information about the manifest.
    Manifest {
        /// Input path to asset.
        input: PathBuf,

        /// Display debug information about the manifest.
        #[clap(short, long)]
        debug: bool,
    },
    /// Display statistics about the manifest (e.g. file size).
    Stats { input: PathBuf },
    /// Create a tree diagram of the manifest store.
    Tree { input: PathBuf },
    /// Display certificate chain.
    Certs { input: PathBuf },
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
                .with_context(|| format!("Failed to read trust resource from path: {:?}", path))?,
            InputSource::Url(url) => reqwest::blocking::get(url.to_string())?
                .text()
                .with_context(|| format!("Failed to read trust resource from URL: {}", url))?,
        };
        Ok(data)
    }
}
