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

use std::path::Path;

use anyhow::{anyhow, Result};
use c2pa::{Error, IngredientOptions, ManifestStore, ManifestStoreReport};

use crate::args::View;

pub fn view(config: View) -> Result<()> {
    match config {
        View::Manifest { path, debug } => {
            let report = match debug {
                true => ManifestStoreReport::from_file(&path).map(|r| r.to_string()),
                false => ManifestStore::from_file(&path).map(|r| r.to_string()),
            };

            let report = match report {
                Ok(report) => Ok(report),
                Err(Error::JumbfNotFound) => Err(anyhow!("No claim found")),
                Err(Error::PrereleaseError) => Err(anyhow!("Prerelease claim found")),
                Err(err) => Err(err.into()),
            }?;

            println!("{report}");
        }
        View::Info { path } => {
            struct Options {}
            impl IngredientOptions for Options {
                fn thumbnail(&self, _path: &Path) -> Option<(String, Vec<u8>)> {
                    None
                }
            }
            let ingredient = c2pa::Ingredient::from_file_with_options(&path, &Options {})?;
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

            let file_size = std::fs::metadata(&path).unwrap().len();
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
        View::Tree { path } => {
            ManifestStoreReport::dump_tree(path)?;
        }
        View::Certs { path } => {
            ManifestStoreReport::dump_cert_chain(path)?;
        }
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    const SOURCE_PATH: &str = "tests/fixtures/C.jpg";

    #[test]
    fn test_view_manifest() -> Result<()> {
        view(View::Manifest {
            path: SOURCE_PATH.into(),
            debug: false,
        })
    }

    #[test]
    fn test_view_manifest_debug() -> Result<()> {
        view(View::Manifest {
            path: SOURCE_PATH.into(),
            debug: true,
        })
    }

    #[test]
    fn test_view_info() -> Result<()> {
        view(View::Info {
            path: SOURCE_PATH.into(),
        })
    }

    #[test]
    fn test_view_tree() -> Result<()> {
        view(View::Tree {
            path: SOURCE_PATH.into(),
        })
    }

    #[test]
    fn test_view_certs() -> Result<()> {
        view(View::Certs {
            path: SOURCE_PATH.into(),
        })
    }
}
