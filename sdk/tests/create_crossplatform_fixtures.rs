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
//! Run once per operating system.

use std::{
    fs,
    io::{Cursor, Write},
    path::PathBuf,
};

use c2pa::{Builder, Result};
use zip::{write::SimpleFileOptions, ZipWriter};

mod common;
use common::{test_context, test_signer};

/// Signed with a `c2pa.created` action carrying the empty digital source type,
/// since these archives hold no captured content.
const MANIFEST_JSON: &str = r#"{
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
}"#;

/// Mirrors `tests/fixtures/sample1.zip`, plus a separator-free `test-file` entry
/// that acts as the control: its key is identical on every operating system, so a
/// difference in the other keys isolates to nested paths.
const NESTED_ENTRIES: &[&str] = &[
    "test-file",
    "sample1/test1.txt",
    "sample1/test2.txt",
    "sample1/test1/test1.txt",
    "sample1/test1/test2.txt",
    "sample1/test1/test3.txt",
];

/// U+00E9 and U+00E8 as single code points.
const COMPOSED_NAME: &str = "sample1/éphémère.txt";

/// The same name with each accent as a base letter followed by U+0301 / U+0300.
const DECOMPOSED_NAME: &str = "sample1/e\u{301}phe\u{301}me\u{300}re.txt";

/// Resolved from the manifest directory rather than the working directory, so the
/// path is the same whether cargo is invoked from the workspace root or from `sdk`.
fn output_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/crossplatform-fixtures")
}

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

fn sign_archive(unsigned: Vec<u8>, file_name: &str) -> Result<()> {
    let mut builder = Builder::from_context(test_context()).with_definition(MANIFEST_JSON)?;

    let mut source = Cursor::new(unsigned);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(&test_signer(), "zip", &mut source, &mut dest)?;

    let dir = output_dir();
    fs::create_dir_all(&dir)?;
    let path = dir.join(file_name);
    fs::write(&path, dest.into_inner())?;
    println!("wrote {}", path.display());

    Ok(())
}

#[test]
#[ignore = "run explicitly to regenerate the committed cross-platform fixtures"]
fn create_crossplatform_fixtures() -> Result<()> {
    let os = std::env::consts::OS;
    sign_archive(build_archive(NESTED_ENTRIES), &format!("nested.{os}.zip"))?;

    // Both spellings of the same logical name are signed wherever this runs: the
    // stored bytes come from the input archive, so the operating system that signs
    // them does not change the key.
    sign_archive(build_archive(&[COMPOSED_NAME]), "unicode-composed.zip")?;
    sign_archive(build_archive(&[DECOMPOSED_NAME]), "unicode-decomposed.zip")?;

    Ok(())
}
