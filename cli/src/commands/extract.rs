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

use std::{fs, path::PathBuf};

use anyhow::{bail, Result};
use c2pa::{jumbf_io, Ingredient, ManifestStore};
use clap::Parser;

use crate::{commands::Trust, load_trust_settings};

#[derive(Debug, Parser)]
pub enum Extract {
    /// Extract the .json manifest.
    Manifest {
        /// Input path to asset.
        path: PathBuf,

        /// Path to output file.
        #[clap(short, long)]
        output: PathBuf,

        /// Extract binary .c2pa manifest.
        #[clap(short, long)]
        binary: bool,

        /// Force overwrite output if it already exists.
        #[clap(short, long)]
        force: bool,

        #[clap(flatten)]
        trust: Trust,
    },
    /// Extract the .json ingredient and .c2pa manifest file.
    Ingredient {
        /// Input path to asset.
        path: PathBuf,

        /// Path to output folder.
        #[clap(short, long)]
        output: PathBuf,

        /// Force overwrite output if it already exists.
        #[clap(short, long)]
        force: bool,

        #[clap(flatten)]
        trust: Trust,
    },
    /// Extract known resources from a manifest (e.g. thumbnails).
    Resources {
        /// Input glob path to asset.
        path: String,

        /// Path to output folder.
        #[clap(short, long)]
        output: PathBuf,

        /// Force overwrite output and clear children if it already exists.
        #[clap(short, long)]
        force: bool,

        #[clap(flatten)]
        trust: Trust,
        //
        // TODO: add flag for additionally exporting unknown ingredients (ingredients that
        // do not have a standardized label) as a binary file
    },
}

impl Extract {
    pub fn execute(&self) -> Result<()> {
        match self {
            Extract::Manifest {
                path,
                output,
                binary,
                force,
                trust,
            } => {
                if !path.exists() {
                    bail!("Input path does not exist")
                } else if !path.is_file() {
                    bail!("Input path must be a file")
                }

                if output.exists() {
                    if !output.is_file() {
                        bail!("Output path must be a file");
                    } else if !force {
                        bail!("Output path already exists use `--force` to overwrite");
                    }
                }

                load_trust_settings(trust)?;

                match binary {
                    true => {
                        let manifest = jumbf_io::load_jumbf_from_file(path)?;
                        // Validates the jumbf refers to a valid manifest.
                        match c2pa::format_from_path(path) {
                            Some(format) => {
                                ManifestStore::from_manifest_and_asset_bytes(
                                    &manifest,
                                    &format,
                                    &fs::read(path)?,
                                )?;
                            }
                            None => bail!("Path `{}` is missing file extension", path.display()),
                        }
                        fs::write(output, manifest)?;
                    }
                    false => {
                        let manifest = ManifestStore::from_file(path)?;
                        fs::write(output, manifest.to_string())?;
                    }
                }
            }
            Extract::Ingredient {
                path,
                output,
                force,
                trust,
            } => {
                if !path.exists() {
                    bail!("Input path does not exist")
                } else if !path.is_file() {
                    bail!("Input path must be a file")
                }

                let ingredient_path = output.join("ingredient.json");
                let manifest_data_path = output.join("manifest_data.c2pa");

                if !output.exists() {
                    fs::create_dir_all(output)?;
                } else if !output.is_dir() {
                    bail!("Output path must be a folder");
                } else if !force && (ingredient_path.exists() || manifest_data_path.exists()) {
                    bail!(
                        "One or both paths already exist: `{}` or `{}` use `--force` to overwrite",
                        ingredient_path.display(),
                        manifest_data_path.display()
                    );
                }

                load_trust_settings(trust)?;

                let ingredient = Ingredient::from_file(path)?;
                fs::write(&ingredient_path, ingredient.to_string())?;

                if let Some(manifest_data) = ingredient.manifest_data() {
                    fs::write(&manifest_data_path, manifest_data.as_ref())?;
                }
            }
            Extract::Resources {
                path,
                output,
                force,
                trust,
            } => {
                if glob::glob(path)?.next().is_none() {
                    bail!("Input path does not exist")
                }

                if !output.exists() {
                    fs::create_dir_all(output)?;
                } else if !output.is_dir() {
                    bail!("Output path must be a folder");
                } else if !force {
                    bail!(
                        "Output path already exists use `--force` to overwrite and clear children"
                    );
                }

                load_trust_settings(trust)?;

                for entry in glob::glob(path)? {
                    let path = entry?;
                    if path.is_dir() {
                        bail!("Input path cannot be a folder when extracting resources");
                    }

                    ManifestStore::from_file_with_resources(&path, output)?;
                }
            }
        }
        Ok(())
    }
}
