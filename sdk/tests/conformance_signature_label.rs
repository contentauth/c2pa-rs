use std::io::Cursor;

use c2pa::Reader;

fn has_code(json: &serde_json::Value, kind: &str, code: &str) -> bool {
    json["manifests"][0]["validationResults"][kind]
        .as_array()
        .is_some_and(|statuses| statuses.iter().any(|status| status["code"] == code))
}

#[test]
fn missing_signature_box_or_reference_cannot_validate() {
    for asset in [
        include_bytes!("fixtures/conformance/sig_missing.jpg").as_slice(),
        include_bytes!("fixtures/conformance/sig_uri_invalid.jpg").as_slice(),
    ] {
        let reader = Reader::default()
            .with_stream("image/jpeg", Cursor::new(asset))
            .unwrap();
        let json = reader.to_crjson_value().unwrap();
        assert!(
            has_code(&json, "failure", "claimSignature.missing"),
            "{json}"
        );
        assert!(
            !has_code(&json, "success", "claimSignature.validated"),
            "{json}"
        );
        assert!(
            !has_code(&json, "success", "claimSignature.insideValidity"),
            "{json}"
        );
        assert!(
            !has_code(&json, "failure", "claimSignature.mismatch"),
            "{json}"
        );
    }
}

#[test]
fn correctly_labeled_signature_still_validates() {
    let reader = Reader::default()
        .with_stream(
            "image/jpeg",
            Cursor::new(include_bytes!("fixtures/conformance/sig_es256.jpg")),
        )
        .unwrap();
    let json = reader.to_crjson_value().unwrap();
    assert!(
        has_code(&json, "success", "claimSignature.validated"),
        "{json}"
    );
    assert!(
        !has_code(&json, "failure", "claimSignature.missing"),
        "{json}"
    );
}

#[c2pa_macros::c2pa_test_async]
async fn signature_label_resolution_async() {
    for (asset, missing) in [
        (
            include_bytes!("fixtures/conformance/sig_missing.jpg").as_slice(),
            true,
        ),
        (
            include_bytes!("fixtures/conformance/sig_uri_invalid.jpg").as_slice(),
            true,
        ),
        (
            include_bytes!("fixtures/conformance/sig_es256.jpg").as_slice(),
            false,
        ),
    ] {
        let reader = Reader::default()
            .with_stream_async("image/jpeg", Cursor::new(asset))
            .await
            .unwrap();
        let json = reader.to_crjson_value().unwrap();
        assert_eq!(
            has_code(&json, "failure", "claimSignature.missing"),
            missing,
            "{json}"
        );
        assert_eq!(
            has_code(&json, "success", "claimSignature.validated"),
            !missing,
            "{json}"
        );
        assert!(
            !has_code(&json, "failure", "claimSignature.mismatch"),
            "{json}"
        );
    }
}
