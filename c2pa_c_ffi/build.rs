// Copyright 2023 Adobe. All rights reserved.
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

//! This creates the c2pa.h header file and the c2pa_version.txt file
//! in the target directory. It is intended to be run as part of the build process.
//! The crate version is added to the header file.
use std::{env, path::Path};

fn main() {
    // Get the version from the environment variable set by Cargo.
    let version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is not set");

    // Get the workspace target directory.
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR environment variable not set");
    println!("Running c2pa_c_ffi folder build script: {out_dir:?}");

    let workspace_target_dir = Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .expect("Invalid OUT_DIR structure");

    // Generate the bindings using cbindgen.
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let config_path = Path::new(&crate_dir).join("cbindgen.toml");

    let mut config = cbindgen::Config::from_file(config_path).unwrap();

    // Add a version string to the header.
    config.header = match config.header {
        Some(ref mut header) => {
            header.push_str(&format!("\n// Version: {version}\n"));
            Some(header.clone())
        }
        None => Some(format!("\n// Version: {version}\n")),
    };

    // Generate the header file.
    cbindgen::generate_with_config(&crate_dir, config).map_or_else(
        |error| match error {
            cbindgen::Error::ParseSyntaxError { .. } => {
                eprintln!("Warning: ParseSyntaxError encountered while generating bindings");
            }
            e => panic!("{e:?}"),
        },
        |bindings| {
            println!(
                "Writing c2pa.h to: {:?}",
                workspace_target_dir.join("c2pa.h")
            );
            bindings.write_to_file(workspace_target_dir.join("c2pa.h"));
        },
    );
}
