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

use std::{io::Seek, path::Path};

use anyhow::Result;
use c2pa::{format_from_path, Builder, Context, Reader, Settings};

/// Display additional C2PA information about the asset (not JSON formatted).
pub fn info(path: &Path) -> Result<()> {
    let mut stream = std::fs::File::open(path)
        .map_err(|_| c2pa::Error::FileNotFound(path.to_string_lossy().to_string()))?;
    let format = format_from_path(path).unwrap_or_default();

    // Disable thumbnail generation for info command to speed up processing
    let settings = Settings::new().with_value("builder.thumbnail.enabled", false)?;
    let mut builder = Builder::from_context(Context::new().with_settings(settings)?);
    let ingredient = builder.add_ingredient_from_stream("{}", &format, &mut stream)?;

    println!("Information for {}", ingredient.title().unwrap_or_default());
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

        stream.rewind()?;
        let reader = Reader::default().with_stream(&format, &mut stream)?;

        let manifests: Vec<_> = reader.iter_manifests().collect();
        match manifests.len() {
            0 => println!("No manifests"),
            1 => println!("One manifest"),
            n => println!("{n} manifests"),
        }
    } else if is_cloud_manifest {
        println!("Unable to fetch cloud manifest. (file size = {file_size})");
    } else {
        println!("No C2PA Manifests. (file size = {file_size})");
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
