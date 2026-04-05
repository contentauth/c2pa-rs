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

//! Integration tests for the RIFF fast signer.

use std::io::Cursor;

use c2pa::{
    sign_riff_fast, Builder, BuilderIntent, DigitalSourceType, Reader,
};

mod common;
use common::{assert_valid, make_context, test_signer};

#[test]
fn test_fast_sign_wav_roundtrip() {
    let context = make_context();
    let signer = test_signer();

    let source_bytes = include_bytes!("fixtures/sample1.wav");
    let mut source = Cursor::new(source_bytes.to_vec());
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));

    let result = sign_riff_fast(&mut builder, &signer, "wav", &mut source, &mut dest);
    assert!(
        result.is_ok(),
        "sign_riff_fast failed: {}",
        result.err().unwrap()
    );

    // Read back and verify
    dest.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("audio/wav", &mut dest)
        .expect("Failed to read signed WAV");

    assert!(
        !reader.manifests().is_empty(),
        "No manifests found in signed WAV"
    );
    assert!(
        reader.active_manifest().is_some(),
        "No active manifest in signed WAV"
    );
    assert_valid(reader.validation_state());
}

#[test]
fn test_fast_sign_webp_roundtrip() {
    let context = make_context();
    let signer = test_signer();

    let source_bytes = include_bytes!("fixtures/test.webp");
    let mut source = Cursor::new(source_bytes.to_vec());
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));

    let result = sign_riff_fast(&mut builder, &signer, "webp", &mut source, &mut dest);
    assert!(
        result.is_ok(),
        "sign_riff_fast failed for WebP: {:?}",
        result.err()
    );

    // Read back and verify
    dest.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("image/webp", &mut dest)
        .expect("Failed to read signed WebP");

    assert!(
        !reader.manifests().is_empty(),
        "No manifests found in signed WebP"
    );
    assert!(
        reader.active_manifest().is_some(),
        "No active manifest in signed WebP"
    );
    assert_valid(reader.validation_state());
}

#[test]
fn test_fast_sign_avi_roundtrip() {
    let context = make_context();
    let signer = test_signer();

    let source_bytes = include_bytes!("fixtures/test.avi");
    let mut source = Cursor::new(source_bytes.to_vec());
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));

    let result = sign_riff_fast(&mut builder, &signer, "avi", &mut source, &mut dest);
    assert!(
        result.is_ok(),
        "sign_riff_fast failed for AVI: {:?}",
        result.err()
    );

    // Read back and verify
    dest.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("video/avi", &mut dest)
        .expect("Failed to read signed AVI");

    assert!(
        !reader.manifests().is_empty(),
        "No manifests found in signed AVI"
    );
    assert!(
        reader.active_manifest().is_some(),
        "No active manifest in signed AVI"
    );
    assert_valid(reader.validation_state());
}

#[test]
fn test_fast_sign_output_is_valid_riff() {
    // Verify the output is structurally valid RIFF that the standard
    // reader can parse.
    let context = make_context();
    let signer = test_signer();

    let source_bytes = include_bytes!("fixtures/sample1.wav");
    let mut source = Cursor::new(source_bytes.to_vec());
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));

    sign_riff_fast(&mut builder, &signer, "wav", &mut source, &mut dest).unwrap();

    // The output should start with RIFF header
    let output = dest.into_inner();
    assert!(output.len() > 12);
    assert_eq!(&output[0..4], b"RIFF");
    assert_eq!(&output[8..12], b"WAVE");

    // RIFF size field should match
    let riff_size = u32::from_le_bytes(output[4..8].try_into().unwrap());
    assert_eq!(
        riff_size as usize + 8,
        output.len(),
        "RIFF size field does not match output length"
    );
}

#[test]
fn test_fast_sign_riff_re_sign() {
    // Sign a WAV, then sign the output again
    let context = make_context();
    let signer = test_signer();

    let source_bytes = include_bytes!("fixtures/sample1.wav");
    let mut source = Cursor::new(source_bytes.to_vec());
    let mut dest1 = Cursor::new(Vec::new());

    let mut builder1 = Builder::from_shared_context(&context);
    builder1.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    sign_riff_fast(&mut builder1, &signer, "wav", &mut source, &mut dest1)
        .expect("first sign failed");

    // Re-sign with Edit intent (needs parent ingredient)
    dest1.set_position(0);
    let mut dest2 = Cursor::new(Vec::new());
    let mut builder2 = Builder::from_shared_context(&context);
    builder2.set_intent(BuilderIntent::Edit);
    dest1.set_position(0);
    builder2
        .add_ingredient_from_stream(
            serde_json::json!({"relationship": "parentOf"}).to_string(),
            "audio/wav",
            &mut dest1,
        )
        .expect("Failed to add parent ingredient");
    dest1.set_position(0);
    sign_riff_fast(&mut builder2, &signer, "wav", &mut dest1, &mut dest2)
        .expect("re-sign failed");

    // Verify the re-signed output can be read
    dest2.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("audio/wav", &mut dest2)
        .expect("Reader failed");
    assert!(reader.active_manifest().is_some());
    assert_valid(reader.validation_state());
}

#[test]
fn test_fast_sign_riff_truncated_input() {
    // Pass a source that is only 4 bytes
    let context = make_context();
    let signer = test_signer();

    let mut source = Cursor::new(vec![0u8; 4]);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    let result = sign_riff_fast(&mut builder, &signer, "wav", &mut source, &mut dest);
    assert!(result.is_err(), "Expected error for truncated input");
}

#[test]
fn test_fast_sign_riff_empty_input() {
    // Pass a 0-byte source
    let context = make_context();
    let signer = test_signer();

    let mut source = Cursor::new(Vec::new());
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    let result = sign_riff_fast(&mut builder, &signer, "wav", &mut source, &mut dest);
    assert!(result.is_err(), "Expected error for empty input");
}

#[test]
fn test_fast_sign_riff_corrupt_header() {
    // Pass a file starting with garbage bytes
    let context = make_context();
    let signer = test_signer();

    let mut source = Cursor::new(vec![
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    ]);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
    let result = sign_riff_fast(&mut builder, &signer, "wav", &mut source, &mut dest);
    assert!(result.is_err(), "Expected error for corrupt header");
}
