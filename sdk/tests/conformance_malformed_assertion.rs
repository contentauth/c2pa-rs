use std::io::Cursor;

use c2pa::{validation_status::ASSERTION_CBOR_INVALID, Reader};

/// An actions assertion that is not well-formed CBOR is reported as
/// assertion.cbor.invalid in the validation results, instead of making the
/// reader fail.
#[test]
fn malformed_actions_assertion_is_reported_as_cbor_invalid() {
    let reader = Reader::default()
        .with_stream(
            "image/jpeg",
            Cursor::new(include_bytes!(
                "fixtures/conformance/malformed_assertion.jpg"
            )),
        )
        .unwrap();

    let failures = reader
        .validation_results()
        .and_then(|results| results.active_manifest())
        .map(|statuses| statuses.failure().clone())
        .unwrap_or_default();
    assert!(
        failures
            .iter()
            .any(|status| status.code() == ASSERTION_CBOR_INVALID),
        "{failures:?}"
    );
}
