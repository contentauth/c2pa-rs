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
mod compare_manifests;
mod make_test_images;
mod make_thumbnail;
use anyhow::{Context, Result};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let config = if args.len() > 2 {
        make_test_images::Config {
            alg: "ps256".to_owned(),
            tsa_url: None,
            output_path: "target/images".to_owned(),
            default_ext: "jpg".to_owned(),
            author: None,
            recipes: Vec::new(),
            compare_folders: Some([args[1].clone(), args[2].clone()]),
        }
    } else {
        let path = if args.len() > 1 {
            args[1].as_ref()
        } else {
            "make_test_images/tests.json"
        };
        let buf = std::fs::read_to_string(path).context(format!("Reading {path}"))?;
        let config: make_test_images::Config =
            serde_json::from_str(&buf).context("Config file format error")?;
        config
    };

    // set RUST_LOG=debug to get detailed debug logging
    env_logger::init();

    make_test_images::MakeTestImages::new(config).run()?;

    Ok(())
}
