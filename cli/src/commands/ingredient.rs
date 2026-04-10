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
    fs::{create_dir_all, remove_dir_all, File},
    io::Write,
    path::Path,
};

use anyhow::{bail, Result};
use c2pa::Ingredient;

use super::special_errs;

pub fn run(input: &Path, output: &Path, detailed: bool, force: bool) -> Result<()> {
    if output.is_file() || output.extension().is_some() {
        write_single_file(input, output, force)
    } else {
        write_to_directory(input, output, detailed, force)
    }
}

fn write_single_file(input: &Path, output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!("Output already exists; use -f/force to force write");
    }
    let ingredient = Ingredient::from_file(input).map_err(special_errs)?;
    let report = ingredient.to_string();
    std::fs::write(output, report)?;
    println!("Ingredient saved to: {}", output.display());
    Ok(())
}

fn write_to_directory(input: &Path, output: &Path, detailed: bool, force: bool) -> Result<()> {
    if output.exists() {
        if force {
            remove_dir_all(output)?;
        } else {
            bail!("Output already exists; use -f/force to force write");
        }
    }
    create_dir_all(output)?;

    if detailed {
        let report = Ingredient::from_file_with_folder(input, output)
            .map_err(special_errs)?
            .to_string();
        File::create(output.join("ingredient.json"))?.write_all(report.as_bytes())?;
        println!("Ingredient report written to: {}", output.display());
    } else {
        let ingredient = Ingredient::from_file(input).map_err(special_errs)?;
        let report = ingredient.to_string();
        File::create(output.join("ingredient.json"))?.write_all(report.as_bytes())?;
        println!("Ingredient saved to: {}", output.display());
    }
    Ok(())
}
