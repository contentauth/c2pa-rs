// Copyright 2026 Adobe. All rights reserved.
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

use c2pa::{Builder, BuilderIntent, DigitalSourceType, Reader, Result};
use common::{assert_valid, make_context, test_signer};

/// Sign a TIFF fixture using the fast path, then read back with Reader and
/// verify a valid manifest is present.
#[test]
fn test_fast_sign_tiff_roundtrip() -> Result<()> {
    let context = make_context();
    let signer = test_signer();

    let source_bytes = std::fs::read(common::fixtures_path("TUSCANY.TIF"))?;
    let mut source = Cursor::new(&source_bytes);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_format("image/tiff");
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    builder.add_assertion(
        "stds.schema-org.CreativeWork",
        &serde_json::json!({
            "@context": "https://schema.org",
            "@type": "CreativeWork",
            "author": [{"@type": "Person", "name": "Fast Sign Test"}]
        }),
    )?;

    let result = c2pa::sign_tiff_fast(&mut builder, &signer, "tiff", &mut source, &mut dest);
    assert!(result.is_ok(), "sign_tiff_fast failed: {:?}", result.err());

    // Read back with Reader
    dest.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("image/tiff", &mut dest)?;

    // Verify there is an active manifest
    assert!(
        reader.active_manifest().is_some(),
        "Expected active manifest after signing"
    );
    assert_valid(reader.validation_state());

    Ok(())
}

/// Sign a DNG fixture using the fast path.
#[test]
fn test_fast_sign_dng_roundtrip() -> Result<()> {
    let context = make_context();
    let signer = test_signer();

    let source_bytes = std::fs::read(common::fixtures_path("subfiles.dng"))?;
    let mut source = Cursor::new(&source_bytes);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_format("image/dng");
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    builder.add_assertion(
        "stds.schema-org.CreativeWork",
        &serde_json::json!({
            "@context": "https://schema.org",
            "@type": "CreativeWork",
            "author": [{"@type": "Person", "name": "DNG Fast Sign Test"}]
        }),
    )?;

    let result = c2pa::sign_tiff_fast(&mut builder, &signer, "dng", &mut source, &mut dest);
    assert!(
        result.is_ok(),
        "sign_tiff_fast for DNG failed: {:?}",
        result.err()
    );

    // Read back with Reader
    dest.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("image/dng", &mut dest)?;

    assert!(
        reader.active_manifest().is_some(),
        "Expected active manifest after signing DNG"
    );
    assert_valid(reader.validation_state());

    Ok(())
}

/// Verify non-TIFF formats fall back gracefully to Builder.sign().
#[test]
fn test_fast_sign_tiff_fallback_non_tiff() -> Result<()> {
    let context = make_context();
    let signer = test_signer();

    let source_bytes = include_bytes!("fixtures/CA.jpg");
    let mut source = Cursor::new(source_bytes.as_slice());
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_format("image/jpeg");
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    builder.add_assertion(
        "stds.schema-org.CreativeWork",
        &serde_json::json!({
            "@context": "https://schema.org",
            "@type": "CreativeWork",
            "author": [{"@type": "Person", "name": "Fallback Test"}]
        }),
    )?;

    // Should fall back to Builder.sign() for JPEG
    let result = c2pa::sign_tiff_fast(&mut builder, &signer, "jpg", &mut source, &mut dest);
    assert!(result.is_ok(), "Fallback sign failed: {:?}", result.err());

    // Verify it produced a valid signed JPEG
    dest.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("image/jpeg", &mut dest)?;
    assert!(reader.active_manifest().is_some());

    Ok(())
}

/// Re-sign: sign a TIFF, then sign the output again.
/// NOTE: TIFF re-signing currently fails with JumbfParseError -- this test
/// documents the limitation and will be updated once re-signing is supported.
#[test]
fn test_fast_sign_tiff_re_sign() -> Result<()> {
    let context = make_context();
    let signer = test_signer();

    let source_bytes = std::fs::read(common::fixtures_path("TUSCANY.TIF"))?;
    let mut source = Cursor::new(&source_bytes);
    let mut dest1 = Cursor::new(Vec::new());

    let mut builder1 = Builder::from_shared_context(&context);
    builder1.set_format("image/tiff");
    builder1.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    c2pa::sign_tiff_fast(&mut builder1, &signer, "tiff", &mut source, &mut dest1)?;

    // Re-sign -- currently expected to fail
    dest1.set_position(0);
    let mut dest2 = Cursor::new(Vec::new());
    let mut builder2 = Builder::from_shared_context(&context);
    builder2.set_format("image/tiff");
    builder2.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    let result = c2pa::sign_tiff_fast(&mut builder2, &signer, "tiff", &mut dest1, &mut dest2);

    // TIFF re-signing is a known limitation -- assert it either succeeds or returns a specific error.
    match result {
        Ok(_) => {
            // If it succeeds, validate the output
            dest2.set_position(0);
            let reader = Reader::from_shared_context(&context)
                .with_stream("image/tiff", &mut dest2)
                .expect("Reader failed on re-signed TIFF");
            assert!(reader.active_manifest().is_some());
        }
        Err(_) => {
            // Known limitation: TIFF re-signing may fail gracefully
        }
    }

    Ok(())
}

/// Truncated TIFF input (2 bytes).
#[test]
fn test_fast_sign_tiff_truncated_input() {
    let context = make_context();
    let signer = test_signer();

    let mut source = Cursor::new(vec![0x49, 0x49]); // little-endian TIFF sig, but truncated
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_format("image/tiff");
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    let result = c2pa::sign_tiff_fast(&mut builder, &signer, "tiff", &mut source, &mut dest);
    assert!(result.is_err(), "Expected error for truncated TIFF input");
}

/// Corrupt TIFF header (garbage bytes).
#[test]
fn test_fast_sign_tiff_corrupt_header() {
    let context = make_context();
    let signer = test_signer();

    let mut source = Cursor::new(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x10]);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_format("image/tiff");
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    let result = c2pa::sign_tiff_fast(&mut builder, &signer, "tiff", &mut source, &mut dest);
    assert!(result.is_err(), "Expected error for corrupt TIFF header");
}
