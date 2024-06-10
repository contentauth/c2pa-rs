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
use c2pa::{Ingredient, ManifestStore};
use clap::Parser;

use crate::{commands::Trust, load_trust_settings};

#[derive(Debug, Parser)]
pub enum Extract {
    /// Extract known resources from a manifest (e.g. thumbnails).
    Resources {
        /// Input path to asset.
        path: String,

        /// Path to output folder.
        #[clap(short, long)]
        output: PathBuf,

        /// Force overwrite output if it already exists.
        #[clap(short, long)]
        force: bool,

        #[clap(flatten)]
        trust: Trust,
        //
        // TODO: add flag for additionally exporting unknown ingredients (ingredients that
        // do not have a standardized label) as a binary file
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
    /// Extract the .json manifest.
    Manifest {
        /// Input path to asset.
        path: PathBuf,

        /// Path to output file.
        #[clap(short, long)]
        output: PathBuf,

        /// Force overwrite output if it already exists.
        #[clap(short, long)]
        force: bool,

        #[clap(flatten)]
        trust: Trust,
    },
}

impl Extract {
    pub fn execute(&self) -> Result<()> {
        match self {
            Extract::Resources {
                path,
                output,
                force,
                trust,
            } => {
                if !output.exists() {
                    fs::create_dir_all(output)?;
                } else if !output.is_dir() {
                    bail!("Output path must be a folder");
                } else if !force {
                    bail!("Output path already exists use `--force` to overwrite");
                }

                load_trust_settings(trust)?;

                // TODO: validate input path similar to when signing
                for entry in glob::glob(path)? {
                    let path = entry?;
                    if path.is_dir() {
                        bail!("Input path cannot be a folder when extracting resources");
                    }

                    ManifestStore::from_file_with_resources(&path, output)?;
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

                if !output.exists() {
                    fs::create_dir_all(output)?;
                } else if !output.is_dir() {
                    bail!("Output path must be a folder");
                } else if !force {
                    bail!("Output path already exists use `--force` to overwrite");
                }

                load_trust_settings(trust)?;

                let ingredient = Ingredient::from_file(path)?;
                fs::write(output.join("ingredient.json"), ingredient.to_string())?;

                if let Some(manifest_data) = ingredient.manifest_data() {
                    fs::write(output.join("manifest_data.c2pa"), manifest_data.as_ref())?;
                }
            }
            Extract::Manifest {
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

                if output.exists() {
                    if !output.is_file() {
                        bail!("Output path must be a file");
                    } else if !force {
                        bail!("Output path already exists use `--force` to overwrite");
                    }
                }

                load_trust_settings(trust)?;

                let manifest = ManifestStore::from_file(path)?;
                fs::write(output, manifest.to_string())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    // use super::*;

    #[test]
    fn test_sign() {
        // TODO:
    }
}
