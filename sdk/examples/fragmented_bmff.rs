// Copyright 2025 Adobe. All rights reserved.
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

//! Example App that generates a CAWG manifest for a given file
//! and validates the identity assertion.
//!
//! This example is not supported on WASI targets.
//!
//! ```bash
//! cargo run --example fragmented_cawg -- /path/to/source/init_segment_or_glob  fragment_glob_pattern path/to/destination/folder
//! ```

mod cawg {
    use std::path::{Path, PathBuf};

    use anyhow::{anyhow, bail, Context as AnyhowContext, Result};
    use c2pa::{
        Builder,
        Settings,
        Signer,
    };
    use serde_json::json;

    fn manifest_def() -> String {
        json!({
            "claim_generator_info": [
                {
                    "name": "c2pa cawg test",
                    "version": env!("CARGO_PKG_VERSION")
                }
            ],
            "assertions": [
                {
                    "label": "c2pa.actions",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "digitalSourceType": " http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
                            }
                        ]
                    }
                },
                {
                    "label": "cawg.training-mining",
                    "data": {
                    "entries": {
                        "cawg.ai_inference": {
                        "use": "notAllowed"
                        },
                        "cawg.ai_generative_training": {
                        "use": "notAllowed"
                        }
                    }
                    }
                }
            ]
        })
        .to_string()
    }

    pub fn run<S: AsRef<Path>, G: AsRef<Path>, D: AsRef<Path>>(
        source: S,
        glob_pattern: G,
        dest: D,
    ) -> Result<()> {
        let source = source.as_ref();
        let glob_pattern = glob_pattern.as_ref().to_path_buf();
        let dest = dest.as_ref();
        
        // Ensure output directory exists
        std::fs::create_dir_all(dest)?;

        let settings = Settings::new()
            .with_toml(include_str!("../tests/fixtures/test_settings_with_cawg_signing.toml"))?
            .with_value(
                "cawg_x509_signer.local.referenced_assertions",
                vec!["cawg.training-mining"],
            )?;
        let context = c2pa::Context::new().with_settings(settings)?.into_shared();
        let mut builder = Builder::new().with_shared_context(&context).with_definition(manifest_def())?;

        sign_fragmented(&mut builder, context.signer()?, source, &glob_pattern, dest)
    }

    fn sign_fragmented(
        builder: &mut Builder,
        signer: &dyn Signer,
        init_pattern: &Path,
        frag_pattern: &PathBuf,
        output_path: &Path,
    ) -> Result<()> {
        // search folders for init segments
        let ip = init_pattern
            .to_str()
            .ok_or(anyhow!("could not parse source pattern"))?;
        let inits = glob::glob(ip).context("could not process glob pattern")?;
        let mut count = 0;
        for init in inits {
            match init {
                Ok(p) => {
                    let mut fragments = Vec::new();
                    let init_dir = p.parent().context("init segment had no parent dir")?;
                    let seg_glob = init_dir.join(frag_pattern); // segment match pattern

                    // grab the fragments that go with this init segment
                    let seg_glob_str = seg_glob.to_str().context("fragment path not valid")?;
                    let seg_paths = glob::glob(seg_glob_str).context("fragment glob not valid")?;
                    for seg in seg_paths {
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
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Creates a CAWG manifest (requires source path to init segment or init segment glob, glob pattern for fragments, and destination folder paths)");
        std::process::exit(1);
    }
    let source: std::path::PathBuf = std::path::PathBuf::from(&args[1]);
    let glob_pattern: std::path::PathBuf = std::path::PathBuf::from(&args[2]);
    let dest: std::path::PathBuf = std::path::PathBuf::from(&args[3]);
    cawg::run(source, glob_pattern, dest)
}
