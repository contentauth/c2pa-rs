use c2pa_claim::{Assertion, Claim, ClaimGeneratorInfo, HashedUri};

#[test]
fn v2_cbor_roundtrip() {
    // Build a claim with two assertions.
    let cgi = ClaimGeneratorInfo::new("TestApp");
    let mut claim = Claim::new("urn:c2pa:test-label", cgi);

    // Assertion 1 — raw CBOR bytes
    let cbor_payload = c2pa_cbor::to_vec(&serde_json::json!({"key": "value"})).unwrap();
    let assertion1 = Assertion::from_data_cbor("c2pa.test", &cbor_payload);

    // Assertion 2 — JSON
    let assertion2 = Assertion::from_data_cbor("c2pa.custom", b"{}");

    claim.add_assertion(assertion1);
    claim.add_assertion(assertion2);

    // Round-trip
    let bytes = claim.data().expect("serialization failed");
    let restored = Claim::from_data("urn:c2pa:test-label", &bytes).expect("deserialization failed");

    // Verify identity-stable fields
    assert_eq!(restored.label(), "urn:c2pa:test-label");
    assert_eq!(restored.version(), 2);
    assert_eq!(restored.claim_generator_info().name, "TestApp");
    assert_eq!(restored.alg.as_deref(), Some("sha256"));

    // Two created_assertions entries were written
    let ca = restored.created_assertions();
    assert_eq!(ca.len(), 2);

    // URIs point into the right assertion store location
    assert!(ca[0].url().contains("c2pa.test"));
    assert!(ca[1].url().contains("c2pa.custom"));

    // Both are relative URIs
    assert!(ca[0].is_relative_url());
    assert!(ca[1].is_relative_url());
}

#[test]
fn v2_cbor_roundtrip_with_title() {
    let mut cgi = ClaimGeneratorInfo::new("TitleApp");
    cgi.set_version("2.0");

    let mut claim = Claim::new("urn:c2pa:titled", cgi);
    claim.set_title("My Asset");

    let bytes = claim.data().expect("serialization failed");
    let restored = Claim::from_data("urn:c2pa:titled", &bytes).expect("deserialization failed");

    assert_eq!(restored.title(), Some("My Asset"));
    assert_eq!(
        restored.claim_generator_info().version.as_deref(),
        Some("2.0")
    );
}

#[test]
fn v2_cbor_roundtrip_with_icon() {
    let mut cgi = ClaimGeneratorInfo::new("IconApp");
    let icon = HashedUri::new(
        "self#jumbf=urn:c2pa:test-label/c2pa.databoxes/icon".to_string(),
        Some("sha256".to_string()),
        &[0u8; 32],
    );
    cgi.set_icon(icon.clone());

    let claim = Claim::new("urn:c2pa:icontest", cgi);

    let bytes = claim.data().expect("serialization failed");
    let restored = Claim::from_data("urn:c2pa:icontest", &bytes).expect("deserialization failed");

    let restored_icon = restored
        .claim_generator_info()
        .icon()
        .expect("icon missing");
    assert_eq!(restored_icon.url(), icon.url());
    assert_eq!(restored_icon.hash(), icon.hash());
}
