use c2pa_wasm::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_supported_mime_types() {
    let mime_types = C2paReader::supported_mime_types();
    assert!(mime_types.length() > 0);
}

#[wasm_bindgen_test]
fn test_version() {
    let version = version();
    assert!(!version.is_empty());
}

#[wasm_bindgen_test]
fn test_name() {
    let name = name();
    assert_eq!(name, "c2pa-rs");
}

#[wasm_bindgen_test]
fn test_is_format_supported() {
    assert!(is_format_supported("image/jpeg"));
    assert!(is_format_supported("image/png"));
    assert!(!is_format_supported("text/plain"));
}
