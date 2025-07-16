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

//! Example App that generates a manifest store listing for a given file

use anyhow::Result;
#[cfg(target_arch = "wasm32")]
fn main() -> Result<()> {
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<()> {
    use std::io::Read;

    use c2pa::{format_from_path, Error, Reader};

    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let path = std::path::PathBuf::from(&args[1]);
        let format = format_from_path(&path).ok_or(Error::UnsupportedType)?;
        let mut file = std::fs::File::open(&path)?;

        let reader = match Reader::from_stream(&format, &mut file) {
            Ok(reader) => Ok(reader),
            Err(Error::RemoteManifestUrl(url)) => {
                println!("Fetching remote manifest from {url}");
                let mut c2pa_data = Vec::new();
                let resp = ureq::get(&url).call()?;
                resp.into_reader().read_to_end(&mut c2pa_data)?;
                Reader::from_manifest_data_and_stream(&c2pa_data, &format, &mut file)
            }
            Err(Error::JumbfNotFound) => {
                // if not embedded or cloud, check for sidecar first and load if it exists
                let potential_sidecar_path = path.with_extension("c2pa");
                if potential_sidecar_path.exists() {
                    let manifest_data = std::fs::read(potential_sidecar_path)?;
                    Ok(Reader::from_manifest_data_and_stream(
                        &manifest_data,
                        &format,
                        &mut file,
                    )?)
                } else {
                    Err(Error::JumbfNotFound)
                }
            }
            Err(e) => Err(e),
        }?;
        println!("{reader}");
    } else {
        println!("Prints a manifest report (requires a file path argument)")
    }
    Ok(())
}
