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
use c2pa::{Error, Reader, Result};
use common::{assert_err, compare_to_known_good, fixture_stream};

#[test]
#[cfg(feature = "file_io")]
fn test_reader_not_found() -> Result<()> {
    let result = Reader::from_file("not_found.png");
    assert_err!(result, Err(Error::IoError(_)));
    Ok(())
}

#[test]
fn test_reader_no_jumbf() -> Result<()> {
    let (format, mut stream) = fixture_stream("sample1.png")?;
    let result = Reader::from_stream(&format, &mut stream);
    assert_err!(result, Err(Error::JumbfNotFound));
    Ok(())
}

#[test]
#[cfg_attr(not(any(target_arch = "wasm32", feature = "openssl")), ignore)]
fn test_reader_ca_jpg() -> Result<()> {
    let (format, mut stream) = fixture_stream("CA.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream)?;
    compare_to_known_good(&reader, "CA.json")
}

#[test]
#[cfg_attr(not(any(target_arch = "wasm32", feature = "openssl")), ignore)]
fn test_reader_c_jpg() -> Result<()> {
    let (format, mut stream) = fixture_stream("C.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream)?;
    compare_to_known_good(&reader, "C.json")
}

#[test]
#[cfg_attr(not(any(target_arch = "wasm32", feature = "openssl")), ignore)]
fn test_reader_xca_jpg() -> Result<()> {
    let (format, mut stream) = fixture_stream("XCA.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream)?;
    compare_to_known_good(&reader, "XCA.json")
}

#[test]
#[ignore]
/// Generates the known good for the above tests
/// This is ignored by default
/// to call use test -- --ignored
fn write_known_goods() -> Result<()> {
    let filenames = ["CA.jpg", "C.jpg", "XCA.jpg"];
    for filename in &filenames {
        common::write_known_good(filename)?;
    }
    Ok(())
}
