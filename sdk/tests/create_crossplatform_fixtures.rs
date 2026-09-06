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

//! Produces the signed ZIP fixtures used cross-platform.
//! Runs once per operating system.

use std::{
    fs,
    io::{Cursor, Write},
    path::PathBuf,
};

use c2pa::{Builder, Reader, Result};
use serde_json::json;
use zip::{write::SimpleFileOptions, ZipWriter};

mod common;
use common::{test_context, test_signer};

/// Placeholder manifest for test asset.
fn manifest_json() -> String {
    // Record the generating OS in the manifest too.
    let operating_system = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);

    json!({
        "claim_generator_info": [
            {
                "name": "c2pa-rs test",
                "version": "0.1.0",
                "operating_system": operating_system
            }
        ],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"
                        }
                    ]
                }
            }
        ]
    })
    .to_string()
}

/// Same struct as existing test fixture.
const NESTED_ENTRIES: &[&str] = &[
    "test-file",
    "sample1/test1.txt",
    "sample1/test2.txt",
    "sample1/test1/test1.txt",
    "sample1/test1/test2.txt",
    "sample1/test1/test3.txt",
];

fn output_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/crossplatform-fixtures")
}

/// Create an archive as test asset.
fn build_archive(entry_names: &[&str]) -> Vec<u8> {
    let mut writer = ZipWriter::new_stream(Vec::new());
    for name in entry_names {
        writer
            .start_file(*name, SimpleFileOptions::default())
            .unwrap();
        let content = name.rsplit('/').next().unwrap_or(name);
        writer.write_all(content.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// Sign test ZIP.
fn sign_archive(unsigned: Vec<u8>, file_name: &str) -> Result<()> {
    let mut builder = Builder::from_context(test_context()).with_definition(manifest_json())?;

    let mut source = Cursor::new(unsigned);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&test_signer(), "zip", &mut source, &mut dest)?;

    let signed = dest.into_inner();
    let dir = output_dir();
    fs::create_dir_all(&dir)?;
    let path = dir.join(file_name);
    fs::write(&path, &signed)?;
    println!("wrote {}", path.display());

    log_reread_manifest(&signed, file_name)
}

/// Read signed manifest.
fn log_reread_manifest(signed: &[u8], file_name: &str) -> Result<()> {
    let mut stream = Cursor::new(signed);
    let reader = Reader::from_context(test_context()).with_stream("zip", &mut stream)?;
    println!("{file_name}:\n{}", reader.json());

    Ok(())
}

#[test]
#[ignore = "ignored since used only for test asset generation"]
fn create_crossplatform_fixtures() -> Result<()> {
    let os = std::env::consts::OS;
    sign_archive(build_archive(NESTED_ENTRIES), &format!("sample1-{os}.zip"))?;

    Ok(())
}
