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

use std::{path::Path, sync::Arc};

use anyhow::{anyhow, bail, Context, Result};
use c2pa::{Builder, Context as C2paContext, Reader, Signer};

use crate::util::validate_cawg;

/// Sign all init segments matching `init_pattern` (glob) along with their
/// associated fragments (`frag_pattern` relative to each init dir).
pub fn sign_fragmented(
    builder: &mut Builder,
    signer: &dyn Signer,
    init_pattern: &Path,
    frag_pattern: &Path,
    output_path: &Path,
) -> Result<()> {
    let ip = init_pattern
        .to_str()
        .ok_or_else(|| anyhow!("could not parse source pattern"))?;
    let inits = glob::glob(ip).context("could not process glob pattern")?;
    let mut count = 0;

    for init in inits {
        match init {
            Ok(p) => {
                let init_dir = p.parent().context("init segment had no parent dir")?;
                let seg_glob = init_dir.join(frag_pattern);
                let seg_glob_str = seg_glob.to_str().context("fragment path not valid")?;

                let mut fragments = Vec::new();
                for seg in glob::glob(seg_glob_str).context("fragment glob not valid")? {
                    match seg {
                        Ok(f) => fragments.push(f),
                        Err(_) => return Err(anyhow!("fragment path not valid")),
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

/// Read and validate all init segments matching `init_pattern` and their
/// associated fragments (`frag_pattern` relative to each init dir).
pub fn verify_fragmented(
    init_pattern: &Path,
    frag_pattern: &Path,
    context: &Arc<C2paContext>,
) -> Result<Vec<Reader>> {
    let ip = init_pattern
        .to_str()
        .context("could not parse source pattern")?;
    let inits = glob::glob(ip).context("could not process glob pattern")?;
    let mut readers = Vec::new();
    let mut count = 0;

    for init in inits {
        match init {
            Ok(p) => {
                let init_dir = p.parent().context("init segment had no parent dir")?;
                let seg_glob = init_dir.join(frag_pattern);
                let seg_glob_str = seg_glob.to_str().context("fragment path not valid")?;

                let mut fragments = Vec::new();
                for seg in glob::glob(seg_glob_str).context("fragment glob not valid")? {
                    match seg {
                        Ok(f) => fragments.push(f),
                        Err(_) => return Err(anyhow!("fragment path not valid")),
                    }
                }

                println!("Verifying manifest: {p:?}");
                let reader =
                    Reader::from_shared_context(context).with_fragmented_files(p, &fragments)?;
                if let Some(vs) = reader.validation_status() {
                    if let Some(e) = vs.iter().find(|v| !v.passed()) {
                        eprintln!("Error validating segments: {e:?}");
                        return Ok(readers);
                    }
                }
                readers.push(reader);
                count += 1;
            }
            Err(_) => bail!("bad path to init segment"),
        }
    }

    if count == 0 {
        println!("No files matching pattern: {ip}");
    }
    Ok(readers)
}

/// Print or validate the results of `verify_fragmented`.
pub fn print_verified(readers: &mut [Reader]) -> Result<()> {
    if readers.len() == 1 {
        validate_cawg(&mut readers[0])?;
        println!("{}", readers[0]);
    } else {
        for reader in readers.iter_mut() {
            validate_cawg(reader)?;
        }
        println!("{} Init manifests validated", readers.len());
    }
    Ok(())
}
