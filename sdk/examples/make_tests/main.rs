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

//! This generates a set of test images with a wide variety of configurations
//! To run this, use the following command in a terminal
//! cargo run --release --example make_tests
//!
use anyhow::Result;
use std::path::PathBuf;
// The make_tests sample is not designed to work with a wasm build
// so we provide a wasm stub here and only include the module for non wasm
#[cfg(not(target_arch = "wasm32"))]
mod make_tests;
#[cfg(not(target_arch = "wasm32"))]
use crate::make_tests::make_tests;

#[cfg(target_arch = "wasm32")]
fn make_tests(_output_folder: &std::path::Path, _alg: &str, _tsa: Option<String>) -> Result<()> {
    panic!("Not implemented for wasm");
}

const TARGET_FOLDER: &str = "target/test_images";
fn main() -> Result<()> {
    // set RUST_LOG=debug to get detailed debug logging
    env_logger::init();

    // choose a timestamp service authority
    let tsa = Some("http://timestamp.digicert.com".to_string());

    make_tests(&PathBuf::from(TARGET_FOLDER), "ps256", tsa)?;

    Ok(())
}
