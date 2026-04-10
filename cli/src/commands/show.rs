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
};

use anyhow::{bail, Result};
use c2pa::Reader;

use super::{special_errs, validate_cawg};
use crate::info::info;

pub fn run(
    input: &Path,
    detailed: bool,
    tree: bool,
    certs: bool,
    show_info: bool,
    external_manifest: Option<&PathBuf>,
    output: Option<&PathBuf>,
    force: bool,
) -> Result<()> {
    if show_info {
        return info(input);
    }

    if certs {
        let reader = Reader::from_file(input).map_err(special_errs)?;
        if let Some(manifest) = reader.active_manifest() {
            if let Some(si) = manifest.signature_info() {
                println!("{}", si.cert_chain());
                return Ok(());
            }
        }
        bail!("No certificate chain found");
    }

    if tree {
        println!("{}", crate::tree::tree(input)?);
        return Ok(());
    }

    let mut reader = if let Some(external_manifest) = external_manifest {
        let c2pa_data = fs::read(external_manifest)?;
        let format = match c2pa::format_from_path(input) {
            Some(format) => format,
            None => bail!("Format for {:?} is unrecognized", input),
        };
        Reader::from_manifest_data_and_stream(&c2pa_data, &format, File::open(input)?)
            .map_err(special_errs)?
    } else {
        Reader::from_file(input).map_err(special_errs)?
    };

    validate_cawg(&mut reader)?;

    if let Some(output_path) = output {
        write_report(&reader, output_path, detailed, force)?;
    } else {
        print_report(&reader, detailed)?;
    }

    Ok(())
}

fn write_report(reader: &Reader, output_path: &Path, detailed: bool, force: bool) -> Result<()> {
    let is_directory =
        output_path.is_dir() || (!output_path.exists() && output_path.extension().is_none());

    if is_directory {
        if output_path.exists() {
            if force {
                remove_dir_all(output_path)?;
            } else {
                bail!("Output already exists; use -f/force to force write");
            }
        }
        create_dir_all(output_path)?;

        if detailed {
            let detailed_json = format!("{reader:#?}");
            File::create(output_path.join("detailed.json"))?.write_all(detailed_json.as_bytes())?;
        } else {
            let summary = reader.to_string();
            File::create(output_path.join("manifest_store.json"))?.write_all(summary.as_bytes())?;
        }
        println!("Manifest report written to the directory {output_path:?}");
    } else {
        if output_path.exists() && !force {
            bail!("Output already exists; use -f/force to force write");
        }
        let content = if detailed {
            format!("{reader:#?}")
        } else {
            reader.to_string()
        };
        fs::write(output_path, content)?;
        println!("Manifest report written to {}", output_path.display());
    }

    Ok(())
}

fn print_report(reader: &Reader, detailed: bool) -> Result<()> {
    if detailed {
        println!("{reader:#?}");
    } else {
        println!("{reader}");
    }
    Ok(())
}
