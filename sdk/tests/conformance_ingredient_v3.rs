use std::io::Cursor;

use c2pa::Reader;

#[test]
fn v3_ingredient_requires_validation_results() {
    let reader = Reader::default()
        .with_stream(
            "image/jpeg",
            Cursor::new(include_bytes!(
                "fixtures/conformance/ingredient_with_missing_validation_results.jpg"
            )),
        )
        .unwrap();
    assert!(reader
        .validation_status()
        .unwrap()
        .iter()
        .any(|status| status.code() == "assertion.ingredient.malformed"));
    let json = reader.to_crjson_value().unwrap();
    let ingredient = &json["manifests"][0]["assertions"]["c2pa.ingredient.v3"];
    assert!(ingredient["activeManifest"].is_object(), "{json}");
    assert!(ingredient.get("validationResults").is_none(), "{json}");
    assert!(
        json["manifests"][0]["validationResults"]["failure"]
            .as_array()
            .unwrap()
            .iter()
            .any(|status| status["code"] == "assertion.ingredient.malformed"),
        "{json}"
    );
}

#[c2pa_macros::c2pa_test_async]
async fn malformed_v3_ingredient_results_export_async() {
    let reader = Reader::default()
        .with_stream_async(
            "image/jpeg",
            Cursor::new(include_bytes!(
                "fixtures/conformance/ingredient_with_missing_validation_results.jpg"
            )),
        )
        .await
        .unwrap();
    let json = reader.to_crjson_value().unwrap();
    assert!(
        json["manifests"][0]["validationResults"]["failure"]
            .as_array()
            .unwrap()
            .iter()
            .any(|status| status["code"] == "assertion.ingredient.malformed"),
        "{json}"
    );
}
