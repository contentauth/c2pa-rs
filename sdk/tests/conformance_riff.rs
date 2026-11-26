use std::io::Cursor;

use c2pa::{Builder, HashRange, Reader};
use serde_json::json;

mod common;
use common::test_context;

#[test]
fn riff_payload_exclusions_validate_without_data_hash_mismatch() {
    for (format, asset) in [
        (
            "audio/wav",
            include_bytes!("fixtures/conformance/wav_valid.wav").as_slice(),
        ),
        (
            "image/webp",
            include_bytes!("fixtures/conformance/webp_valid.webp").as_slice(),
        ),
    ] {
        let reader = Reader::default()
            .with_stream(format, Cursor::new(asset))
            .unwrap();
        let json = reader.to_crjson_value().unwrap();
        assert!(
            has_code(&json, "success", "assertion.dataHash.match"),
            "{format}: {json}"
        );
        assert!(
            !has_code(&json, "failure", "assertion.dataHash.mismatch"),
            "{format}: {json}"
        );
    }
}

#[test]
fn riff_payload_exclusions_still_detect_asset_tampering() {
    for (format, asset) in [
        (
            "audio/wav",
            include_bytes!("fixtures/conformance/wav_valid.wav").as_slice(),
        ),
        (
            "image/webp",
            include_bytes!("fixtures/conformance/webp_valid.webp").as_slice(),
        ),
    ] {
        let mut tampered = asset.to_vec();
        // Change media bytes before the C2PA chunk, leaving its manifest intact.
        tampered[128] ^= 1;
        let reader = Reader::default()
            .with_stream(format, Cursor::new(tampered))
            .unwrap();
        let json = reader.to_crjson_value().unwrap();
        assert!(
            has_code(&json, "failure", "assertion.dataHash.mismatch"),
            "{format}: {json}"
        );
        assert!(
            !has_code(&json, "success", "assertion.dataHash.match"),
            "{format}: {json}"
        );
    }
}

/// Appends `manifest` as a `C2PA` chunk at the end of the first `RIFF` chunk,
/// followed by a zero pad byte when its length is odd. Returns the asset and the
/// offset of the chunk.
fn embed_c2pa_chunk(riff: &[u8], manifest: &[u8]) -> (Vec<u8>, u64) {
    let mut asset = riff.to_vec();
    let offset = asset.len() as u64;
    asset.extend_from_slice(b"C2PA");
    asset.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    asset.extend_from_slice(manifest);
    if manifest.len() % 2 == 1 {
        asset.push(0);
    }
    let riff_size = (asset.len() - 8) as u32;
    asset[4..8].copy_from_slice(&riff_size.to_le_bytes());
    (asset, offset)
}

/// Signs `riff` with a manifest whose data hash exclusions are produced by
/// `exclusions` from the `C2PA` chunk offset and manifest length. The title is
/// padded until the manifest length is odd, so the chunk has a pad byte.
fn sign_with_exclusions(
    riff: &[u8],
    exclusions: impl Fn(u64, u64) -> Vec<HashRange>,
) -> c2pa::Result<Vec<u8>> {
    for title_len in 1..=4 {
        let mut builder = Builder::from_context(test_context())
            .with_definition(json!({
                "title": "t".repeat(title_len),
                "assertions": [{
                    "label": "c2pa.actions",
                    "data": { "actions": [{
                        "action": "c2pa.created",
                        "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
                    }]}
                }]
            }))?;
        // Raw JUMBF: the RIFF chunk is composed here.
        let placeholder = builder.placeholder("application/c2pa")?;
        if placeholder.len() % 2 == 0 {
            continue;
        }
        let (mut asset, offset) = embed_c2pa_chunk(riff, &placeholder);
        builder.set_data_hash_exclusions(exclusions(offset, placeholder.len() as u64))?;
        builder.update_hash_from_stream("image/webp", &mut Cursor::new(&asset))?;
        let manifest = builder.sign_embeddable("application/c2pa")?;
        assert_eq!(manifest.len(), placeholder.len());
        let start = offset as usize + 8;
        asset[start..start + manifest.len()].copy_from_slice(&manifest);
        return Ok(asset);
    }
    panic!("no odd-length manifest found");
}

#[test]
fn riff_exclusions_may_include_c2pa_header_fields_and_pad_byte() -> c2pa::Result<()> {
    let riff = include_bytes!("fixtures/sample1.webp");
    // Exclusions that begin at the chunk identifier, size field or manifest store,
    // and end at the pad byte; plus the original c2pa-rs form without the pad byte,
    // and a range that also excludes the top-level RIFF size field.
    let cases: [fn(u64, u64) -> Vec<HashRange>; 5] = [
        |offset, len| vec![HashRange::new(offset, 8 + len + 1)],
        |offset, len| vec![HashRange::new(offset + 4, 4 + len + 1)],
        |offset, len| vec![HashRange::new(offset + 8, len + 1)],
        |offset, len| vec![HashRange::new(offset, 8 + len)],
        |offset, len| {
            vec![
                HashRange::new(4, 4),
                HashRange::new(offset + 4, 4 + len + 1),
            ]
        },
    ];
    for (i, exclusions) in cases.into_iter().enumerate() {
        let asset = sign_with_exclusions(riff, exclusions)?;
        let reader =
            Reader::from_context(test_context()).with_stream("image/webp", Cursor::new(&asset))?;
        let json = reader.to_crjson_value()?;
        assert!(
            has_code(&json, "success", "assertion.dataHash.match"),
            "case {i}: {json}"
        );
        assert!(
            !has_code(&json, "failure", "assertion.dataHash.mismatch"),
            "case {i}: {json}"
        );

        // A non-zero pad byte inside an exclusion is rejected.
        if i < 3 {
            let mut tampered = asset.clone();
            *tampered.last_mut().unwrap() = 1;
            let reader = Reader::from_context(test_context())
                .with_stream("image/webp", Cursor::new(tampered))?;
            let json = reader.to_crjson_value()?;
            assert!(
                has_code(&json, "failure", "assertion.dataHash.mismatch"),
                "case {i}: {json}"
            );
        }
    }
    Ok(())
}

fn has_code(json: &serde_json::Value, kind: &str, code: &str) -> bool {
    json["manifests"][0]["validationResults"][kind]
        .as_array()
        .is_some_and(|statuses| statuses.iter().any(|status| status["code"] == code))
}
