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

use anyhow::Result;
use c2pa::{IngredientOptions, ManifestStore};

/// display additional C2PA information about the asset (not json formatted)
pub fn info(path: &Path) -> Result<()> {
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
            println!("Cloud URL = {}", provenance);
        } else {
            println!("Provenance URI = {}", provenance);
        }
    }

    if let Some(manifest_data) = ingredient.manifest_data() {
        let file_size = std::fs::metadata(path).unwrap().len();
        if is_cloud_manifest {
            println!(
                "Remote manifest store size = {} (file size = {})",
                manifest_data.len(),
                file_size
            );
        } else {
            println!(
                "Manifest store size = {} ({:.2}% of {})",
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
        let manifest_store = ManifestStore::from_bytes("c2pa", manifest_data, false)?;
        match manifest_store.manifests().len() {
            0 => println!("No manifests"),
            1 => println!("One manifest"),
            n => println!("{} manifests", n),
        }
    } else if is_cloud_manifest {
        println!("Unable to fetch cloud manifest");
    } else {
        println!("No C2PA Manifests");
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_manifest_config() {
        const SOURCE_PATH: &str = "tests/fixtures/C.jpg";

        info(&std::path::PathBuf::from(SOURCE_PATH)).expect("info");
    }
}
