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

use std::io::Cursor;

use c2pa::{sign_bmff_fast, Builder, BuilderIntent, Reader};

mod common;
use common::{assert_valid, make_context, test_signer};

const TEST_MP4: &[u8] = include_bytes!("fixtures/video1.mp4");
const TEST_JPG: &[u8] = include_bytes!("fixtures/C.jpg");

#[test]
fn test_fast_sign_bmff_roundtrip() {
    let context = make_context();
    let signer = test_signer();

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);

    let mut source = Cursor::new(TEST_MP4);

    // Add the source as a parent ingredient (required for Edit intent)
    let parent_def = serde_json::json!({"relationship": "parentOf"});
    builder
        .add_ingredient_from_stream(parent_def.to_string(), "video/mp4", &mut source)
        .expect("Failed to add parent ingredient");
    source.set_position(0);

    let mut dest = Cursor::new(Vec::new());

    let result = sign_bmff_fast(&mut builder, &signer, "video/mp4", &mut source, &mut dest);
    assert!(result.is_ok(), "sign_bmff_fast failed: {:?}", result.err());

    // Read back and verify the manifest validates
    dest.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("video/mp4", &mut dest)
        .expect("Reader failed");

    assert_valid(reader.validation_state());
}

#[test]
fn test_fast_sign_bmff_re_sign() {
    let context = make_context();
    let signer = test_signer();

    // First sign
    let mut builder1 = Builder::from_shared_context(&context);
    builder1.set_intent(BuilderIntent::Edit);
    let mut source1 = Cursor::new(TEST_MP4);
    let parent_def = serde_json::json!({"relationship": "parentOf"});
    builder1
        .add_ingredient_from_stream(parent_def.to_string(), "video/mp4", &mut source1)
        .expect("Failed to add parent ingredient");
    source1.set_position(0);
    let mut dest1 = Cursor::new(Vec::new());
    sign_bmff_fast(&mut builder1, &signer, "video/mp4", &mut source1, &mut dest1)
        .expect("first sign failed");

    // Re-sign the output
    let mut builder2 = Builder::from_shared_context(&context);
    builder2.set_intent(BuilderIntent::Edit);
    dest1.set_position(0);
    let parent_def2 = serde_json::json!({"relationship": "parentOf"});
    builder2
        .add_ingredient_from_stream(parent_def2.to_string(), "video/mp4", &mut dest1)
        .expect("Failed to add re-sign ingredient");
    dest1.set_position(0);
    let mut dest2 = Cursor::new(Vec::new());
    sign_bmff_fast(&mut builder2, &signer, "video/mp4", &mut dest1, &mut dest2)
        .expect("re-sign failed");

    // Verify the re-signed output is valid
    dest2.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("video/mp4", &mut dest2)
        .expect("Reader for re-signed output failed");
    assert_valid(reader.validation_state());
    assert!(
        reader.manifests().len() >= 2,
        "Expected at least 2 manifests after re-signing, got {}",
        reader.manifests().len()
    );
}

#[test]
fn test_fast_sign_matches_standard_sign() {
    let context = make_context();
    let signer = test_signer();

    // Sign with fast_sign
    let mut builder_fast = Builder::from_shared_context(&context);
    builder_fast.set_intent(BuilderIntent::Edit);
    builder_fast.deterministic = true;
    builder_fast.definition.instance_id = "xmp:iid:test-deterministic".to_string();

    let mut source_fast = Cursor::new(TEST_MP4);

    // Add parent ingredient for Edit intent
    let parent_def = serde_json::json!({"relationship": "parentOf"});
    builder_fast
        .add_ingredient_from_stream(parent_def.to_string(), "video/mp4", &mut source_fast)
        .expect("Failed to add parent ingredient for fast sign");
    source_fast.set_position(0);

    let mut dest_fast = Cursor::new(Vec::new());
    sign_bmff_fast(
        &mut builder_fast,
        &signer,
        "video/mp4",
        &mut source_fast,
        &mut dest_fast,
    )
    .expect("fast sign failed");

    // Sign with standard Builder::sign (it auto-adds parent for Edit intent)
    let mut builder_std = Builder::from_shared_context(&context);
    builder_std.set_intent(BuilderIntent::Edit);

    let mut source_std = Cursor::new(TEST_MP4);
    let mut dest_std = Cursor::new(Vec::new());
    builder_std
        .sign(&signer, "video/mp4", &mut source_std, &mut dest_std)
        .expect("standard sign failed");

    // Read both back
    dest_fast.set_position(0);
    let reader_fast = Reader::from_shared_context(&context)
        .with_stream("video/mp4", &mut dest_fast)
        .expect("Reader for fast sign output failed");

    dest_std.set_position(0);
    let reader_std = Reader::from_shared_context(&context)
        .with_stream("video/mp4", &mut dest_std)
        .expect("Reader for standard sign output failed");

    // Both should produce valid manifests
    assert_valid(reader_fast.validation_state());
    assert_valid(reader_std.validation_state());

    // Both should have the same number of manifests
    assert_eq!(
        reader_fast.manifests().len(),
        reader_std.manifests().len(),
        "Manifest count mismatch"
    );

    // Both should have the same assertion labels (same structure)
    let fast_manifest = reader_fast
        .active_manifest()
        .expect("No active manifest for fast sign");
    let std_manifest = reader_std
        .active_manifest()
        .expect("No active manifest for standard sign");

    let mut fast_labels: Vec<String> = fast_manifest
        .assertions()
        .iter()
        .map(|a| a.label().to_string())
        .collect();
    fast_labels.sort();

    let mut std_labels: Vec<String> = std_manifest
        .assertions()
        .iter()
        .map(|a| a.label().to_string())
        .collect();
    std_labels.sort();

    assert_eq!(
        fast_labels, std_labels,
        "Assertion labels differ between fast and standard sign"
    );
}

#[test]
fn test_fast_sign_non_bmff_fallback() {
    let context = make_context();
    let signer = test_signer();

    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);

    let mut source = Cursor::new(TEST_JPG);
    let mut dest = Cursor::new(Vec::new());

    // sign_bmff_fast with a JPEG should fall back to Builder::sign
    let result = sign_bmff_fast(
        &mut builder,
        &signer,
        "image/jpeg",
        &mut source,
        &mut dest,
    );
    assert!(
        result.is_ok(),
        "sign_bmff_fast JPEG fallback failed: {:?}",
        result.err()
    );

    // Read back and verify the manifest validates
    dest.set_position(0);
    let reader = Reader::from_shared_context(&context)
        .with_stream("image/jpeg", &mut dest)
        .expect("Reader for JPEG fallback failed");

    assert_valid(reader.validation_state());
}

#[test]
fn test_fast_sign_bmff_truncated_input() {
    let context = make_context();
    let signer = test_signer();
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);
    let mut source = Cursor::new(vec![0u8; 4]);
    let mut dest = Cursor::new(Vec::new());
    let result = sign_bmff_fast(&mut builder, &signer, "video/mp4", &mut source, &mut dest);
    assert!(result.is_err(), "Expected error for truncated input");
}

#[test]
fn test_fast_sign_bmff_corrupt_header() {
    let context = make_context();
    let signer = test_signer();
    let mut builder = Builder::from_shared_context(&context);
    builder.set_intent(BuilderIntent::Edit);
    let mut source = Cursor::new(vec![
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
    ]);
    let mut dest = Cursor::new(Vec::new());
    let result = sign_bmff_fast(&mut builder, &signer, "video/mp4", &mut source, &mut dest);
    assert!(result.is_err(), "Expected error for corrupt header");
}
