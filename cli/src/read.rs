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
    fs::{self, create_dir_all, remove_dir_all, File},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, bail, Result};
use c2pa::{Context as C2paContext, Reader};

use crate::util::{special_errs, validate_cawg};

/// Open a reader from a file path, optionally using an external .c2pa manifest override.
pub fn open_reader(
    path: &Path,
    external_manifest: Option<&PathBuf>,
    context: &Arc<C2paContext>,
) -> Result<Reader> {
    if let Some(ext_manifest) = external_manifest {
        let c2pa_data = fs::read(ext_manifest)?;
        let format = match c2pa::format_from_path(path) {
            Some(f) => f,
            None => bail!("Format for {:?} is unrecognized", path),
        };
        Ok(Reader::from_shared_context(context)
            .with_manifest_data_and_stream(&c2pa_data, &format, File::open(path)?)
            .map_err(special_errs)?)
    } else {
        Ok(Reader::from_shared_context(context)
            .with_file(path)
            .map_err(special_errs)?)
    }
}

/// Print a reader's manifest store to stdout in JSON, detailed, or crJSON format.
///
/// Formatting can fail if the CBOR is deeply nested or malformed — this surfaces
/// that error clearly rather than panicking.
pub fn print_reader(reader: &Reader, detailed: bool, crjson: bool) -> Result<()> {
    let result = if crjson {
        reader.crjson_checked()
    } else if detailed {
        reader.detailed_json_checked()
    } else {
        reader.json_checked()
    }
    .map_err(|e| anyhow!("Error formatting output: {}", e));

    match result {
        Ok(json) => {
            println!("{json}");
            Ok(())
        }
        Err(e) => bail!("Error formatting output: {}", e),
    }
}

/// Read a manifest store and write it (and thumbnails) to a folder on disk.
pub fn write_reader_to_folder(
    path: &Path,
    output: &Path,
    detailed: bool,
    force: bool,
    context: &Arc<C2paContext>,
) -> Result<()> {
    if output.exists() {
        if force {
            remove_dir_all(output)?;
        } else {
            bail!("Output already exists; use -f/force to force write");
        }
    }
    create_dir_all(output)?;

    let mut reader = Reader::from_shared_context(context)
        .with_file(path)
        .map_err(special_errs)?;
    validate_cawg(&mut reader)?;
    reader.to_folder(output)?;

    let report = reader.to_string();
    if detailed {
        let detailed_str = format!("{reader:#?}");
        File::create(output.join("detailed.json"))?.write_all(detailed_str.as_bytes())?;
    }
    File::create(output.join("manifest_store.json"))?.write_all(report.as_bytes())?;

    println!("Manifest report written to the directory {:?}", output);
    Ok(())
}

/// Write an ingredient report and associated assets to a folder on disk.
pub fn write_ingredient_to_folder(path: &Path, output: &Path, force: bool) -> Result<()> {
    if output.exists() {
        if force {
            remove_dir_all(output)?;
        } else {
            bail!("Output already exists; use -f/force to force write");
        }
    }
    create_dir_all(output)?;

    #[allow(deprecated)]
    let report = c2pa::Ingredient::from_file_with_folder(path, output)
        .map_err(special_errs)?
        .to_string();
    File::create(output.join("ingredient.json"))?.write_all(report.as_bytes())?;

    println!("Ingredient report written to the directory {:?}", output);
    Ok(())
}
