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
//! cargo run --release --bin make_test_images
mod make_test_images;
use anyhow::{Context, Result};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let path = if args.len() > 1 {
        args[1].as_ref()
    } else {
        "make_test_images/tests.json"
    };
    let buf = std::fs::read_to_string(path).context(format!("Reading {path}"))?;
    let config: make_test_images::Config =
        serde_json::from_str(&buf).context("Config file format")?;

    // set RUST_LOG=debug to get detailed debug logging
    env_logger::init();

    make_test_images::MakeTestImages::new(config).run()?;

    Ok(())
}
