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

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use c2pa::{Error, Ingredient, IngredientOptions, ManifestStore, ManifestStoreReport};
use clap::Subcommand;

use crate::{commands::Trust, load_trust_settings};

#[derive(Debug, Subcommand)]
pub enum View {
    /// View manifest in .json format.
    Manifest {
        /// Input path to asset.
        path: PathBuf,

        /// Display debug information about the manifest.
        #[clap(short, long)]
        debug: bool,

        #[clap(flatten)]
        trust: Trust,
    },
    /// View ingredient in .json format.
    Ingredient {
        /// Input path to asset.
        path: PathBuf,

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

impl View {
    pub fn execute(&self) -> Result<()> {
        match self {
            View::Manifest { path, debug, trust } => {
                if !path.is_file() {
                    bail!("Input path must be a file");
                }

                load_trust_settings(trust)?;

                let report = match debug {
                    true => ManifestStoreReport::from_file(path).map(|r| r.to_string()),
                    false => ManifestStore::from_file(path).map(|r| r.to_string()),
                };

                let report = match report {
                    Ok(report) => Ok(report),
                    Err(Error::JumbfNotFound) => Err(anyhow!("No claim found")),
                    Err(Error::PrereleaseError) => Err(anyhow!("Prerelease claim found")),
                    Err(err) => Err(err.into()),
                }?;

                println!("{report}");
            }
            View::Ingredient { path, trust } => {
                if !path.is_file() {
                    bail!("Input path must be a file");
                }

                load_trust_settings(trust)?;

                let report = Ingredient::from_file(path)?.to_string();
                println!("{report}");
            }
            View::Info { path, trust } => {
                if !path.is_file() {
                    bail!("Input path must be a file");
                }

                load_trust_settings(trust)?;

                struct Options {}
                impl IngredientOptions for Options {
                    fn thumbnail(&self, _path: &Path) -> Option<(String, Vec<u8>)> {
                        None
                    }
                }
                let ingredient = c2pa::Ingredient::from_file_with_options(path, &Options {})?;
                println!("Information for {}", ingredient.title());
                let mut is_cloud_manifest = false;
                //println!("instanceID = {}", ingredient.instance_id());
                if let Some(provenance) = ingredient.provenance() {
                    is_cloud_manifest = !provenance.starts_with("self#jumbf=");
                    if is_cloud_manifest {
                        println!("Cloud URL = {provenance}");
                    } else {
                        println!("Provenance URI = {provenance}");
                    }
                }

                let file_size = std::fs::metadata(path).unwrap().len();
                if let Some(manifest_data) = ingredient.manifest_data() {
                    if is_cloud_manifest {
                        println!(
                            "Remote manifest store size = {} (file size = {})",
                            manifest_data.len(),
                            file_size
                        );
                    } else {
                        println!(
                            "Manifest store size = {} ({:.2}% of file size {})",
                            manifest_data.len(),
                            (manifest_data.len() as f64 / file_size as f64) * 100f64,
                            file_size
                        );
                    }
                    if let Some(validation_status) = ingredient.validation_status() {
                        println!("Validation issues:");
                        for status in validation_status {
                            println!("   {}", status.code());
                        }
                    } else {
                        println!("Validated");
                    }
                    let manifest_store = ManifestStore::from_bytes("c2pa", &manifest_data, false)?;
                    match manifest_store.manifests().len() {
                        0 => println!("No manifests"),
                        1 => println!("One manifest"),
                        n => println!("{n} manifests"),
                    }
                } else if is_cloud_manifest {
                    println!("Unable to fetch cloud manifest. (file size = {file_size})");
                } else {
                    println!("No C2PA Manifests. (file size = {file_size})");
                }
            }
            View::Tree { path, trust } => {
                if !path.is_file() {
                    bail!("Input path must be a file");
                }

                load_trust_settings(trust)?;

                ManifestStoreReport::dump_tree(path)?;
            }
            View::Certs { path, trust } => {
                if !path.is_file() {
                    bail!("Input path must be a file");
                }

                load_trust_settings(trust)?;

                ManifestStoreReport::dump_cert_chain(path)?;
            }
        }

        Ok(())
    }
}
