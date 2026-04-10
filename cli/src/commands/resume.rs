// Copyright 2024 Adobe. All rights reserved.
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
    fs::File,
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};
use c2pa::Builder;

use super::{add_cli_ingredients, configure_remote_sidecar, save_archive};

pub fn run(
    archive_path: &Path,
    ingredients: &[PathBuf],
    output: &Path,
    archive_output: bool,
    sidecar: bool,
    remote: Option<&String>,
    force: bool,
) -> Result<()> {
    let mut builder = Builder::from_archive(File::open(archive_path)?)?;

    add_cli_ingredients(&mut builder, ingredients)?;
    configure_remote_sidecar(&mut builder, remote, sidecar);

    if archive_output {
        save_archive(&mut builder, output, force)
    } else {
        // TODO: Need to get the input path from the archive for signing
        let _signer = match c2pa::settings::Settings::signer() {
            Ok(signer) => signer,
            Err(e) => bail!("No signer configured in settings: {e}"),
        };

        if output.exists() && !force {
            bail!("Output already exists; use -f/force to force write");
        }

        bail!("Resume signing not yet fully implemented - SDK needs to store input reference in archive");
    }
}
