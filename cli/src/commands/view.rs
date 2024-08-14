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

use std::{
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};
use c2pa::{Ingredient, IngredientOptions, Manifest, Reader};
use clap::{Parser, Subcommand};

use crate::commands::{load_trust_settings, Trust};

#[derive(Debug, Subcommand)]
pub enum View {
    /// View manifest in .json format.
    Manifest {
        /// Input path to asset.
        path: PathBuf,

        /// Display detailed information about the manifest.
        #[clap(short, long)]
        detailed: bool,

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
    Tree(Tree),
    /// View the active manifest certificate chain.
    Certs {
        /// Input path to asset.
        path: PathBuf,

        #[clap(flatten)]
        trust: Trust,
        //
        // TODO: expose args to extract certificates from specific manifest
    },
}

#[derive(Debug, Parser)]
pub struct Tree {
    /// Input path to asset.
    path: PathBuf,

    // TODO: Ideally this would provide full URIs to assertions/manifests, but we need a reliable way to
    //       get them or manipulate them
    // /// Display detailed information about the manifest.
    // #[clap(short, long)]
    // detailed: bool,
    //
    #[clap(flatten)]
    trust: Trust,
}

impl View {
    pub fn execute(&self) -> Result<()> {
        match self {
            View::Manifest {
                path,
                detailed,
                trust,
            } => {
                if !path.is_file() {
                    bail!("Input path must be a file");
                }

                load_trust_settings(trust)?;

                let reader = Reader::from_file(path)?;
                match detailed {
                    // TODO: c2pa-rs shouldn't output pretty by default unless if # is included
                    true => println!("{:#?}", reader),
                    false => println!("{}", reader),
                };
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
                    let manifest_store =
                        Reader::from_stream("c2pa", Cursor::new(manifest_data.as_ref()))?;
                    match manifest_store.iter_manifests().count() {
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
            View::Tree(tree) => tree.execute()?,
            View::Certs { path, trust } => {
                if !path.is_file() {
                    bail!("Input path must be a file");
                }

                load_trust_settings(trust)?;

                let reader = Reader::from_file(path)?;
                match reader.active_manifest() {
                    Some(active_manifest) => match active_manifest.signature_info() {
                        Some(signature_info) => println!("{}", signature_info.cert_chain()),
                        None => bail!("Unable to get signature info from active manifest"),
                    },
                    None => bail!("Unable to find active manifest"),
                }
            }
        }

        Ok(())
    }
}

impl Tree {
    pub fn execute(&self) -> Result<()> {
        if !self.path.is_file() {
            bail!("Input path must be a file");
        }

        load_trust_settings(&self.trust)?;

        let reader = Reader::from_file(&self.path)?;
        match reader.active_manifest() {
            Some(active_manifest) => {
                let mut tree = self.tree_from_title(active_manifest.title().unwrap_or(""));

                self.recurse_tree_from_manifest(&reader, active_manifest, &mut tree)?;
                println!("{}", tree);
            }

            None => bail!("Unable to find active manifest"),
        }

        Ok(())
    }

    fn tree_from_title(&self, title: &str) -> termtree::Tree<String> {
        termtree::Tree::new(format!("Asset:{}", title))
    }

    fn recurse_tree_from_manifest(
        &self,
        reader: &Reader,
        manifest: &Manifest,
        tree: &mut termtree::Tree<String>,
    ) -> Result<()> {
        // if self.detailed {
        if let Some(manifest_label) = manifest.label() {
            tree.push(format!("Manifest:{}", manifest_label));
        }
        // }

        for assertion_ref in manifest.assertion_references() {
            let url = assertion_ref.url();
            // let label = if self.detailed {
            //     &url
            // } else {
            //     url.split('/').last().unwrap_or(&url)
            // };
            let label = url.split('/').last().unwrap_or(&url);

            tree.push(format!("Assertion:{}", label));
        }

        for ingredient in manifest.ingredients() {
            let mut sub_tree = self.tree_from_title(ingredient.title());
            self.recurse_tree(reader, ingredient, &mut sub_tree)?;
            tree.push(sub_tree);
        }

        Ok(())
    }

    fn recurse_tree(
        &self,
        reader: &Reader,
        ingredient: &Ingredient,
        tree: &mut termtree::Tree<String>,
    ) -> Result<()> {
        if let Some(manifest_label) = ingredient.active_manifest() {
            if let Some(manifest) = reader.get_manifest(manifest_label) {
                self.recurse_tree_from_manifest(reader, manifest, tree)?;
            }
        }

        Ok(())
    }
}
