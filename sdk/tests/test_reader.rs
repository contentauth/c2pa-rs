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
use c2pa::{settings::Settings, validation_status, Error, Reader, Result};
use c2pa_macros::c2pa_test_async;
use common::{assert_err, compare_to_known_good, fixture_stream};
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

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
fn test_reader_ca_jpg() -> Result<()> {
    let (format, mut stream) = fixture_stream("CA.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream)?;
    compare_to_known_good(&reader, "CA.json")
}

#[test]
fn test_reader_c_jpg() -> Result<()> {
    let (format, mut stream) = fixture_stream("C.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream)?;
    compare_to_known_good(&reader, "C.json")
}

#[test]
fn test_reader_xca_jpg() -> Result<()> {
    Settings::from_string(include_str!("fixtures/test_settings.json"), "json")?;

    let (format, mut stream) = fixture_stream("XCA.jpg")?;
    let reader = Reader::from_stream(&format, &mut stream)?;
    // validation_results should have the expected failure
    assert_eq!(
        reader
            .validation_results()
            .unwrap()
            .active_manifest()
            .unwrap()
            .failure[0]
            .code(),
        validation_status::ASSERTION_DATAHASH_MISMATCH
    );
    compare_to_known_good(&reader, "XCA.json")
}

#[c2pa_test_async]
async fn test_reader_remote_url_async() -> Result<()> {
    Settings::from_toml(
        &toml::toml! {
            [verify]
            remote_manifest_fetch = true
        }
        .to_string(),
    )?;

    let reader = Reader::from_stream_async(
        "image/jpeg",
        std::io::Cursor::new(include_bytes!("./fixtures/cloud.jpg")),
    )
    .await?;
    let remote_url = reader.remote_url();
    assert_eq!(remote_url, Some("https://cai-manifests.adobe.com/manifests/adobe-urn-uuid-5f37e182-3687-462e-a7fb-573462780391"));
    assert!(!reader.is_embedded());

    Ok(())
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
