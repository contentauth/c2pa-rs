use std::io::Cursor;

use c2pa::Reader;

fn has_code(json: &serde_json::Value, kind: &str, code: &str) -> bool {
    json["manifests"][0]["validationResults"][kind]
        .as_array()
        .is_some_and(|statuses| statuses.iter().any(|status| status["code"] == code))
}

#[test]
fn rejected_assertion_cannot_validate_asset_binding() {
    let reader = Reader::default()
        .with_stream(
            "image/jpeg",
            Cursor::new(include_bytes!(
                "fixtures/conformance/tampered_assertion.jpg"
            )),
        )
        .unwrap();
    let json = reader.to_crjson_value().unwrap();
    assert!(
        has_code(&json, "failure", "assertion.hashedURI.mismatch"),
        "{json}"
    );
    assert!(
        !has_code(&json, "success", "assertion.dataHash.match"),
        "{json}"
    );
}

#[test]
fn authenticated_assertion_still_validates_asset_binding() {
    let reader = Reader::default()
        .with_stream(
            "image/jpeg",
            Cursor::new(include_bytes!("fixtures/conformance/sig_es256.jpg")),
        )
        .unwrap();
    let json = reader.to_crjson_value().unwrap();
    assert!(
        has_code(&json, "success", "assertion.dataHash.match"),
        "{json}"
    );
    assert!(
        !has_code(&json, "failure", "assertion.hashedURI.mismatch"),
        "{json}"
    );
}
