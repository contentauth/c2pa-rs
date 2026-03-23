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
    use c2pa::{settings::Settings, Builder, Context, DigitalSourceType, Reader};
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

    pub async fn run<S: AsRef<Path>, D: AsRef<Path>>(source: S, dest: D) -> Result<()> {
        let source = source.as_ref();
        let dest = dest.as_ref();

        // delete the destination file if it exists
        if dest.exists() {
            std::fs::remove_file(dest)?;
        }

        // load our cawg signing settings
        let settings = Settings::new().with_toml(include_str!(
            "../tests/fixtures/test_settings_with_cawg_signing.toml"
        ))?;
        let context = Context::new().with_settings(settings)?.into_shared();

        // get the signer from context
        let signer = context.signer()?;

        let mut builder =
            Builder::from_shared_context(&context).with_definition(manifest_def().as_str())?;
        builder.set_intent(c2pa::BuilderIntent::Create(
            DigitalSourceType::DigitalCapture,
        ));

        builder.sign_file(signer, source, dest)?;

        let reader = Reader::from_shared_context(&context)
            .with_file_async(dest)
            .await?;
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
