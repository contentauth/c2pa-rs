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
        // check for a sidecar first
        let external_manifest = path.with_extension("c2pa");
        let reader = if external_manifest.exists() {
            println!("Using external manifest: {}", external_manifest.display());
            let c2pa_data = std::fs::read(&external_manifest)?;
            let format = path
                .extension()
                .and_then(|ext| ext.to_str())
                .ok_or(Error::UnsupportedType)?;
            Reader::from_c2pa_data_and_stream(&c2pa_data, format, &mut file)
        } else {
            match Reader::from_stream(&format, &mut file) {
                Ok(reader) => Ok(reader),
                Err(Error::RemoteManifestUrl(url)) => {
                    println!("Fetching remote manifest from {}", url);
                    let mut c2pa_data = Vec::new();
                    let resp = ureq::get(&url).call()?;
                    resp.into_reader().read_to_end(&mut c2pa_data)?;
                    Reader::from_c2pa_data_and_stream(&c2pa_data, &format, &mut file)
                }
                Err(e) => Err(e),
            }
        }?;
        println!("{reader}");
    } else {
        println!("Prints a manifest report (requires a file path argument)")
    }
    Ok(())
}
