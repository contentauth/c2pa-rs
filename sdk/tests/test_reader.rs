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
use c2pa::{validation_status, Builder, Context, Error, Reader, Result, Settings, ValidationState};
#[cfg(feature = "fetch_remote_manifests")]
use c2pa_macros::c2pa_test_async;
use common::{assert_err, compare_to_known_good, fixture_stream};
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[test]
#[cfg(feature = "file_io")]
fn test_reader_not_found() -> Result<()> {
    let result = Reader::default().with_file("not_found.png");
    assert_err!(result, Err(Error::IoError(_)));
    Ok(())
}

#[test]
fn test_reader_no_jumbf() -> Result<()> {
    let (format, mut stream) = fixture_stream("sample1.png")?;
    let result = Reader::default().with_stream(&format, &mut stream);
    assert_err!(result, Err(Error::JumbfNotFound));
    Ok(())
}

#[test]
fn test_reader_ca_jpg() -> Result<()> {
    let (format, mut stream) = fixture_stream("CA.jpg")?;
    let reader = Reader::default().with_stream(&format, &mut stream)?;
    compare_to_known_good(&reader, "CA.json")
}

#[test]
fn test_reader_c_jpg() -> Result<()> {
    let (format, mut stream) = fixture_stream("C.jpg")?;
    let reader = Reader::default().with_stream(&format, &mut stream)?;
    compare_to_known_good(&reader, "C.json")
}

#[test]
fn test_reader_xca_jpg() -> Result<()> {
    let settings = Settings::new().with_json(include_str!("fixtures/test_settings.json"))?;
    let context = Context::new().with_settings(settings)?;

    let (format, mut stream) = fixture_stream("XCA.jpg")?;
    let reader = Reader::from_context(context).with_stream(&format, &mut stream)?;
    // validation_results should have the expected failure
    let failures = &reader
        .validation_results()
        .unwrap()
        .active_manifest()
        .unwrap()
        .failure;
    assert!(
        failures
            .iter()
            .any(|failure| failure.code() == validation_status::ASSERTION_DATAHASH_MISMATCH),
        "expected {expected} in failure codes: {actual:?}",
        expected = validation_status::ASSERTION_DATAHASH_MISMATCH,
        actual = failures
            .iter()
            .map(|failure| failure.code())
            .collect::<Vec<_>>()
    );
    compare_to_known_good(&reader, "XCA.json")
}

#[cfg(feature = "fetch_remote_manifests")]
#[c2pa_test_async]
async fn test_reader_remote_url_async() -> Result<()> {
    let reader = Reader::default()
        .with_stream_async(
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

/// Test that validation_state() uses the Reader's context settings also
/// when calling with_manifest_data_and_stream.
#[test]
fn test_reader_validation_state_uses_context_settings() -> Result<()> {
    use std::io::Cursor;

    let settings = Settings::new().with_json(include_str!("fixtures/test_settings.json"))?;
    let context = Context::new()
        .with_settings(settings)?
        .with_signer(common::test_signer())
        .into_shared();

    let mut builder = Builder::from_shared_context(&context);
    builder.no_embed = true;

    const TEST_IMAGE: &[u8] = include_bytes!("fixtures/CA.jpg");
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    let manifest_data = builder.save_to_stream(format, &mut source, &mut dest)?;

    dest.set_position(0);

    let reader = Reader::from_shared_context(&context).with_manifest_data_and_stream(
        &manifest_data,
        format,
        &mut dest,
    )?;

    assert_eq!(
        reader.validation_state(),
        ValidationState::Trusted,
        "Expected Trusted state when trust is configured in the Reader context"
    );

    Ok(())
}

// ── format-detection tests ────────────────────────────────────────────────────

/// with_stream should succeed even when the caller supplies the wrong MIME type,
/// because content-based detection overrides the provided format string.
#[test]
fn test_reader_stream_wrong_format_overridden_by_detection() -> Result<()> {
    // CA.jpg is a real JPEG; pass "image/png" as the format — detection must
    // recognise the FF D8 FF magic and succeed anyway.
    let (_correct_format, mut stream) = fixture_stream("CA.jpg")?;
    let reader = Reader::default().with_stream("image/png", &mut stream)?;
    compare_to_known_good(&reader, "CA.json")
}

/// with_file should succeed when the file has a wrong extension, because
/// content-based detection takes priority over the extension.
#[test]
#[cfg(feature = "file_io")]
fn test_reader_file_wrong_extension_overridden_by_detection() -> Result<()> {
    use std::io::Write;

    use tempfile::Builder;

    // Copy CA.jpg bytes into a temp file whose name ends in ".png".
    let jpeg_bytes = include_bytes!("fixtures/CA.jpg");
    #[cfg(target_os = "wasi")]
    let mut tmp = Builder::new()
        .suffix(".png")
        .tempfile_in("/")
        .map_err(c2pa::Error::IoError)?;
    #[cfg(not(target_os = "wasi"))]
    let mut tmp = Builder::new()
        .suffix(".png")
        .tempfile()
        .map_err(c2pa::Error::IoError)?;
    tmp.write_all(jpeg_bytes).map_err(c2pa::Error::IoError)?;
    tmp.flush().map_err(c2pa::Error::IoError)?;

    let reader = Reader::default().with_file(tmp.path())?;
    compare_to_known_good(&reader, "CA.json")
}

/// with_file should succeed when the file has no extension at all, because
/// content-based detection fills in the format.
#[test]
#[cfg(feature = "file_io")]
fn test_reader_file_no_extension_overridden_by_detection() -> Result<()> {
    use tempfile::Builder;

    let jpeg_bytes = include_bytes!("fixtures/CA.jpg");
    #[cfg(target_os = "wasi")]
    let tmp = Builder::new()
        .tempfile_in("/")
        .map_err(c2pa::Error::IoError)?;
    #[cfg(not(target_os = "wasi"))]
    let tmp = Builder::new()
        .tempfile()
        .map_err(c2pa::Error::IoError)?;
    // Rename to strip the extension entirely.
    let no_ext_path = tmp.path().with_extension("");
    std::fs::write(&no_ext_path, jpeg_bytes).map_err(c2pa::Error::IoError)?;

    let reader = Reader::default().with_file(&no_ext_path)?;
    // Clean up the extra file we created (tmp itself is cleaned up on drop).
    let _ = std::fs::remove_file(&no_ext_path);
    compare_to_known_good(&reader, "CA.json")
}
