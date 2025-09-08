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

    use anyhow::{anyhow, bail, Context, Result};
    use c2pa::{
        crypto::raw_signature,
        identity::{
            builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
            x509::X509CredentialHolder,
        },
        Builder, Signer, SigningAlg,
    };
    use serde_json::json;

    const CERTS: &[u8] = include_bytes!("../../sdk/tests/fixtures/certs/es256.pub");
    const PRIVATE_KEY: &[u8] = include_bytes!("../../sdk/tests/fixtures/certs/es256.pem");

    const CAWG_CERTS: &[u8] = include_bytes!("../../sdk/tests/fixtures/certs/ed25519.pub");
    const CAWG_PRIVATE_KEY: &[u8] = include_bytes!("../../sdk/tests/fixtures/certs/ed25519.pem");

    fn manifest_def() -> String {
        json!({
            "claim_version": 2,
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

    /// Creates a CAWG signer from a certificate chains and private keys.
    fn cawg_signer(referenced_assertions: &[&str]) -> Result<impl Signer> {
        let c2pa_raw_signer = raw_signature::signer_from_cert_chain_and_private_key(
            CERTS,
            PRIVATE_KEY,
            SigningAlg::Es256,
            None,
        )?;

        let cawg_raw_signer = raw_signature::signer_from_cert_chain_and_private_key(
            CAWG_CERTS,
            CAWG_PRIVATE_KEY,
            SigningAlg::Ed25519,
            None,
        )?;

        let mut ia_signer = IdentityAssertionSigner::new(c2pa_raw_signer);

        let x509_holder = X509CredentialHolder::from_raw_signer(cawg_raw_signer);
        let mut iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
        iab.add_referenced_assertions(referenced_assertions);

        ia_signer.add_identity_assertion(iab);
        Ok(ia_signer)
    }

    pub fn run<S: AsRef<Path>, G: AsRef<Path>, D: AsRef<Path>>(
        source: S,
        glob_pattern: G,
        dest: D,
    ) -> Result<()> {
        let source = source.as_ref();
        let glob_pattern = glob_pattern.as_ref().to_path_buf();
        let dest = dest.as_ref();

        let mut builder = Builder::from_json(&manifest_def())?;
        builder.definition.claim_version = Some(2); // CAWG should only be used on v2 claims

        // This example will generate a CAWG manifest referencing the training-mining
        // assertion.
        let signer = cawg_signer(&["cawg.training-mining"])?;

        sign_fragmented(&mut builder, &signer, source, &glob_pattern, dest)
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
