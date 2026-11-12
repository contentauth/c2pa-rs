use std::io::Cursor;

use c2pa::Reader;

fn has_code(json: &serde_json::Value, kind: &str, code: &str) -> bool {
    json["manifests"][0]["validationResults"][kind]
        .as_array()
        .is_some_and(|statuses| statuses.iter().any(|status| status["code"] == code))
}

#[test]
fn unsupported_algorithm_is_not_a_hash_mismatch() {
    let reader = Reader::default()
        .with_stream(
            "image/jpeg",
            Cursor::new(include_bytes!(
                "fixtures/conformance/unsupported_hashed_uri_algorithm.jpg"
            )),
        )
        .unwrap();
    let json = reader.to_crjson_value().unwrap();
    assert!(
        has_code(&json, "failure", "algorithm.unsupported"),
        "{json}"
    );
    assert!(
        !has_code(&json, "success", "assertion.dataHash.match"),
        "{json}"
    );
    for code in ["hashedURI.mismatch", "assertion.hashedURI.mismatch"] {
        assert!(!has_code(&json, "failure", code), "{json}");
    }
}

#[test]
fn supported_algorithms_preserve_match_and_mismatch_results() {
    for (asset, tampered) in [
        (
            include_bytes!("fixtures/conformance/tampered_assertion.jpg").as_slice(),
            true,
        ),
        (
            include_bytes!("fixtures/conformance/sig_es256.jpg").as_slice(),
            false,
        ),
    ] {
        let reader = Reader::default()
            .with_stream("image/jpeg", Cursor::new(asset))
            .unwrap();
        let json = reader.to_crjson_value().unwrap();
        assert!(
            !has_code(&json, "failure", "algorithm.unsupported"),
            "{json}"
        );
        assert_eq!(
            has_code(&json, "failure", "assertion.hashedURI.mismatch"),
            tampered,
            "{json}"
        );
        if !tampered {
            assert!(
                has_code(&json, "success", "assertion.hashedURI.match"),
                "{json}"
            );
        }
    }
}

#[c2pa_macros::c2pa_test_async]
async fn unsupported_algorithm_is_classified_async() {
    let reader = Reader::default()
        .with_stream_async(
            "image/jpeg",
            Cursor::new(include_bytes!(
                "fixtures/conformance/unsupported_hashed_uri_algorithm.jpg"
            )),
        )
        .await
        .unwrap();
    let json = reader.to_crjson_value().unwrap();
    assert!(
        has_code(&json, "failure", "algorithm.unsupported"),
        "{json}"
    );
    assert!(
        !has_code(&json, "failure", "assertion.hashedURI.mismatch"),
        "{json}"
    );
    assert!(
        !has_code(&json, "success", "assertion.dataHash.match"),
        "{json}"
    );
}
