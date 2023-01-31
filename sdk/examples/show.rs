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

//! Example App that generates a manifest store listing for a given file
use anyhow::Result;
use c2pa::ManifestStore;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let ms = ManifestStore::from_file(&args[1])?;
        println!("{ms}");
    } else {
        println!("Prints a manifest report (requires a file path argument)")
    }
    Ok(())
}
