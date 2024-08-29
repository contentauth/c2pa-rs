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

mod common;
use std::io::Cursor;

use c2pa::{Error, Reader, Result};
use common::unescape_json;
use insta::assert_json_snapshot;

#[test]
#[cfg(feature = "file_io")]
fn test_reader_not_found() -> Result<()> {
    let result = Reader::from_file("not_found.png");
    assert!(matches!(result, Err(Error::IoError(_))));
    Ok(())
}

#[test]
fn test_reader_no_jumbf() -> Result<()> {
    let asset = Cursor::new(include_bytes!("fixtures/sample1.png"));
    let result = Reader::from_stream("image/png", asset);
    assert!(matches!(result, Err(Error::JumbfNotFound)));
    Ok(())
}

#[test]
fn test_reader_ca_jpg() -> Result<()> {
    let asset = Cursor::new(include_bytes!("fixtures/CA.jpg"));
    let reader = Reader::from_stream("image/jpeg", asset)?;
    apply_filters!();
    assert_json_snapshot!(unescape_json(&reader.json())?);
    Ok(())
}

#[test]
fn test_reader_c_jpg() -> Result<()> {
    let asset = Cursor::new(include_bytes!("fixtures/C.jpg"));
    let reader = Reader::from_stream("image/jpeg", asset)?;
    apply_filters!();
    assert_json_snapshot!(unescape_json(&reader.json())?);
    Ok(())
}

#[test]
fn test_reader_xca_jpg() -> Result<()> {
    let asset = Cursor::new(include_bytes!("fixtures/XCA.jpg"));
    let reader = Reader::from_stream("image/jpeg", asset)?;
    apply_filters!();
    assert_json_snapshot!(unescape_json(&reader.json())?);
    Ok(())
}
