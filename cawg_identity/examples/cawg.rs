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
//! cargo run --example cawg -- /path/to/source/file /path/to/destination/file
//! ```

#[cfg(any(target_os = "wasi", not(target_arch = "wasm32")))]
mod cawg {
    use std::path::Path;

    use anyhow::Result;
    use c2pa::{AsyncSigner, Builder, Reader, SigningAlg};
    use c2pa_crypto::raw_signature;
    use cawg_identity::{
        builder::{AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner},
        validator::CawgValidator,
        x509::X509CredentialHolder,
    };
    use serde_json::json;

    const CERTS: &[u8] = include_bytes!("../../sdk/tests/fixtures/certs/ed25519.pub");
    const PRIVATE_KEY: &[u8] = include_bytes!("../../sdk/tests/fixtures/certs/ed25519.pem");

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
                                "action": "c2pa.opened",
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
    fn async_cawg_signer() -> Result<impl AsyncSigner> {
        let c2pa_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
            CERTS,
            PRIVATE_KEY,
            SigningAlg::Ed25519,
            None,
        )?;

        let cawg_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
            CERTS,
            PRIVATE_KEY,
            SigningAlg::Ed25519,
            None,
        )?;

        let mut ia_signer = AsyncIdentityAssertionSigner::new(c2pa_raw_signer);

        let x509_holder = X509CredentialHolder::from_async_raw_signer(cawg_raw_signer);
        let iab = AsyncIdentityAssertionBuilder::for_credential_holder(x509_holder);
        ia_signer.add_identity_assertion(iab);
        Ok(ia_signer)
    }

    pub async fn run<S: AsRef<Path>, D: AsRef<Path>>(source: S, dest: D) -> Result<()> {
        let source = source.as_ref();
        let dest = dest.as_ref();

        if dest.exists() {
            // delete the destination file if it exists
            std::fs::remove_file(dest)?;
        }

        let signer = async_cawg_signer()?;
        let mut builder = Builder::from_json(&manifest_def())?;
        builder.definition.claim_version = Some(2); // sets this to claim version 2
        builder.sign_file_async(&signer, source, &dest).await?;

        let mut reader = Reader::from_file(dest)?;

        reader.post_validate_async(&CawgValidator {}).await?;

        println!("{reader}");
        Ok(())
    }
}

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
fn main() {
    println!("This example is not supported on non-WASI Wasm targets.");
}
#[cfg(any(target_os = "wasi", not(target_arch = "wasm32")))]
#[cfg_attr(target_os = "wasi", wstd::main)]
#[cfg_attr(not(target_arch = "wasm32"), tokio::main)]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Creates a CAWG manifest (requires source and destination file paths)");
        std::process::exit(1);
    }
    let source: std::path::PathBuf = std::path::PathBuf::from(&args[1]);
    let dest: std::path::PathBuf = std::path::PathBuf::from(&args[2]);
    cawg::run(source, dest).await
}
