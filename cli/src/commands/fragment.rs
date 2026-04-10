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

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use c2pa::{Builder, Signer};

use super::{add_manifest_ingredients, create_builder_from_json, get_signer, load_manifest_json};

pub fn run(
    input: &Path,
    manifest: &Path,
    fragments_glob: &Path,
    output: &Path,
    force: bool,
) -> Result<()> {
    if output.exists() && !output.is_dir() {
        bail!("Output cannot point to existing file, must be a directory");
    }

    if output.exists() && !force {
        bail!("Output already exists; use -f/force to force write");
    }

    let (json, base_path) = load_manifest_json(Some(&manifest.to_path_buf()), None)?;
    let (mut builder, sign_config) = create_builder_from_json(&json, base_path.as_ref())?;

    add_manifest_ingredients(&mut builder, &json, base_path.as_ref())?;

    let signer = get_signer(&sign_config)?;

    sign_fragmented(
        &mut builder,
        signer.as_ref(),
        input,
        &fragments_glob.to_path_buf(),
        output,
    )
}

fn sign_fragmented(
    builder: &mut Builder,
    signer: &dyn Signer,
    init_pattern: &Path,
    frag_pattern: &PathBuf,
    output_path: &Path,
) -> Result<()> {
    let ip = init_pattern.to_str().ok_or(c2pa::Error::OtherError(
        "could not parse source pattern".into(),
    ))?;
    let inits = glob::glob(ip).context("could not process glob pattern")?;
    let mut count = 0;
    for init in inits {
        match init {
            Ok(p) => {
                let mut fragments = Vec::new();
                let init_dir = p.parent().context("init segment had no parent dir")?;
                let seg_glob = init_dir.join(frag_pattern);

                let seg_glob_str = seg_glob.to_str().context("fragment path not valid")?;
                let seg_paths = glob::glob(seg_glob_str).context("fragment glob not valid")?;
                for seg in seg_paths {
                    match seg {
                        Ok(f) => fragments.push(f),
                        Err(_) => return Err(anyhow::anyhow!("fragment path not valid")),
                    }
                }

                println!("Adding manifest to: {p:?}");
                let new_output_path =
                    output_path.join(init_dir.file_name().context("invalid file name")?);
                builder.sign_fragmented_files(signer, &p, &fragments, &new_output_path)?;

                count += 1;
            }
            Err(_) => bail!("bad path to init segment"),
        }
    }
    if count == 0 {
        println!("No files matching pattern: {ip}");
    }
    Ok(())
}
