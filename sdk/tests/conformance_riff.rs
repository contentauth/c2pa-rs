use std::io::Cursor;

use c2pa::Reader;

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

fn has_code(json: &serde_json::Value, kind: &str, code: &str) -> bool {
    json["manifests"][0]["validationResults"][kind]
        .as_array()
        .is_some_and(|statuses| statuses.iter().any(|status| status["code"] == code))
}
