use std::io::Cursor;

use c2pa::Reader;

#[test]
fn spec_collection_array_docx_validates() {
    let reader = Reader::default()
        .with_stream(
            "docx",
            Cursor::new(include_bytes!("fixtures/conformance/docx_valid.docx")),
        )
        .unwrap();
    let json = reader.to_crjson_value().unwrap();
    let manifest = &json["manifests"][0];
    assert!(
        manifest["assertions"]["c2pa.hash.collection.data"]["uris"].is_array(),
        "{json}"
    );
    assert!(
        manifest["validationResults"]["success"]
            .as_array()
            .unwrap()
            .iter()
            .any(|status| status["code"] == "assertion.collectionHash.match"),
        "{json}"
    );
    assert!(
        !manifest["validationResults"]["failure"]
            .as_array()
            .unwrap()
            .iter()
            .any(|status| status["code"]
                .as_str()
                .is_some_and(|code| code.starts_with("assertion.collectionHash."))),
        "{json}"
    );
}

#[c2pa_macros::c2pa_test_async]
async fn spec_collection_array_docx_validates_async() {
    let reader = Reader::default()
        .with_stream_async(
            "docx",
            Cursor::new(include_bytes!("fixtures/conformance/docx_valid.docx")),
        )
        .await
        .unwrap();
    let json = reader.to_crjson_value().unwrap();
    assert!(
        json["manifests"][0]["validationResults"]["success"]
            .as_array()
            .unwrap()
            .iter()
            .any(|status| status["code"] == "assertion.collectionHash.match"),
        "{json}"
    );
}
