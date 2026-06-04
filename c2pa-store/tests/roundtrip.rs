use c2pa_claim::{assertion::Assertion, Claim, ClaimGeneratorInfo};
use c2pa_store::Store;

/// Load and inspect a real signed C2PA manifest store (.c2pa sidecar file).
#[test]
fn read_real_manifest() {
    let bytes = std::fs::read("tests/fixtures/manifest_data.c2pa").expect("fixture not found");

    let store = Store::from_jumbf(&bytes).expect("from_jumbf");

    // One manifest in this store
    assert_eq!(store.claims().len(), 1);

    let claim = store.provenance_claim().expect("provenance claim");

    // V1 claim from the contentauth vendor
    assert_eq!(claim.version(), 1);
    assert!(
        claim.label().starts_with("contentauth:urn:uuid:"),
        "unexpected label: {}",
        claim.label()
    );

    // Signature bytes were loaded from the JUMBF signature box
    assert!(
        !claim.signature_val().is_empty(),
        "signature_val should be populated"
    );

    // All four assertions were restored from the assertion store (including embedded file)
    let assertion_labels: Vec<String> = claim.assertions().iter().map(|a| a.label()).collect();
    assert_eq!(assertion_labels.len(), 4, "got: {assertion_labels:?}");
    println!("Assertion labels: {assertion_labels:?}");
    assert!(
        assertion_labels
            .iter()
            .any(|l| l.starts_with("c2pa.thumbnail.claim")),
        "missing thumbnail: {assertion_labels:?}"
    );
    assert!(
        assertion_labels.contains(&"stds.schema-org.CreativeWork".to_string()),
        "missing CreativeWork: {assertion_labels:?}"
    );
    assert!(
        assertion_labels.contains(&"c2pa.actions".to_string()),
        "missing c2pa.actions: {assertion_labels:?}"
    );
    assert!(
        assertion_labels.contains(&"c2pa.hash.data".to_string()),
        "missing c2pa.hash.data: {assertion_labels:?}"
    );
}

/// Check whether `claim.data()` re-encodes to the same bytes that were
/// originally in the JUMBF claim box.  If they match, the COSE signature
/// would still verify after re-serialisation.
#[test]
fn claim_cbor_reserialization_is_stable() {
    use std::io::Cursor;

    use c2pa_store::jumbf::boxes::{
        BoxReader, CAIManifest, Cai, CAI_ASSERTION_STORE_UUID, CAI_CLAIM_UUID, CAI_SIGNATURE_UUID,
    };

    let bytes = std::fs::read("tests/fixtures/manifest_data.c2pa").expect("fixture not found");

    // --- Extract the original claim CBOR bytes directly from the JUMBF ---
    let super_box = BoxReader::read_super_box(&mut Cursor::new(&bytes[..])).unwrap();
    let cai_block = Cai::from(super_box);

    let manifest_sbox = CAIManifest::from(cai_block.data_box_as_superbox(0).unwrap()).unwrap();
    let manifest_inner = manifest_sbox.super_box();

    let mut original_claim_cbor: Option<Vec<u8>> = None;
    for i in 0..manifest_inner.data_box_count() {
        let child = manifest_inner.data_box_as_superbox(i).unwrap();
        let uuid = child.desc_box().uuid();
        if uuid == CAI_CLAIM_UUID {
            original_claim_cbor = child.data_box_as_cbor_box(0).map(|b| b.cbor().clone());
            break;
        }
        // suppress unused-import warnings from the other UUID constants
        let _ = (CAI_ASSERTION_STORE_UUID, CAI_SIGNATURE_UUID);
    }
    let original_cbor = original_claim_cbor.expect("claim CBOR not found in fixture");

    // --- Load through our store and re-encode ---
    let store = Store::from_jumbf(&bytes).expect("from_jumbf");
    let claim = store.provenance_claim().expect("provenance claim");
    let reencoded_cbor = claim.data().expect("claim.data()");

    // --- Compare ---
    if original_cbor != reencoded_cbor {
        // Transcode CBOR → JSON for a readable diff on failure
        fn cbor_to_json_string(bytes: &[u8]) -> String {
            let buf: Vec<u8> = Vec::new();
            let mut from = c2pa_cbor::Deserializer::from_slice(bytes);
            let mut to = serde_json::Serializer::pretty(buf);
            serde_transcode::transcode(&mut from, &mut to)
                .ok()
                .and_then(|_| String::from_utf8(to.into_inner()).ok())
                .unwrap_or_else(|| format!("<{} bytes>", bytes.len()))
        }
        println!(
            "CBOR DIFFERS ({} vs {} bytes)",
            original_cbor.len(),
            reencoded_cbor.len()
        );
        println!("original:  {}", cbor_to_json_string(&original_cbor));
        println!("reencoded: {}", cbor_to_json_string(&reencoded_cbor));
    }

    assert_eq!(
        original_cbor, reencoded_cbor,
        "claim CBOR changed on re-encoding — COSE signature would not verify"
    );
}

/// Re-serialise the loaded real manifest and verify it round-trips without
/// losing any structure. We do not re-verify the COSE signature (that needs
/// the crypto stack) — we just confirm the claim count and assertion labels
/// survive a second from_jumbf pass.
#[test]
fn real_manifest_reserialization_stability() {
    let bytes = std::fs::read("tests/fixtures/manifest_data.c2pa").expect("fixture not found");

    let store = Store::from_jumbf(&bytes).expect("first from_jumbf");

    // Re-serialize (signature bytes are preserved from the loaded claim)
    let rebytes = store.to_jumbf().expect("to_jumbf");
    assert!(!rebytes.is_empty());
    assert_eq!(bytes, rebytes, "re-serialized bytes differ from original");

    // Parse the re-serialized form
    let store2 = Store::from_jumbf(&rebytes).expect("second from_jumbf");

    assert_eq!(store2.claims().len(), store.claims().len());

    let c1 = store.provenance_claim().unwrap();
    let c2 = store2.provenance_claim().unwrap();

    assert_eq!(c1.label(), c2.label());
    assert_eq!(c1.version(), c2.version());
    assert_eq!(c1.assertions().len(), c2.assertions().len());

    let labels1: Vec<String> = c1.assertions().iter().map(|a| a.label()).collect();
    let labels2: Vec<String> = c2.assertions().iter().map(|a| a.label()).collect();
    assert_eq!(labels1, labels2);
}

fn cbor_bytes(v: serde_json::Value) -> Vec<u8> {
    c2pa_cbor::to_vec(&v).expect("cbor encode")
}

/// Build a minimal DataHash assertion payload encoded as CBOR, using a proper
/// CBOR byte string for the hash field so the encoded size is fixed regardless
/// of hash byte values (same as the real `DataHash` struct does via serde_bytes).
fn data_hash_cbor(hash: &[u8], exclusion_start: u64, exclusion_len: u64) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Exclusion {
        start: u64,
        length: u64,
    }
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        name: &'a str,
        #[serde(with = "serde_bytes")]
        hash: &'a [u8],
        exclusions: Vec<Exclusion>,
    }
    c2pa_cbor::to_vec(&Payload {
        name: "jumbf manifest",
        hash,
        exclusions: vec![Exclusion {
            start: exclusion_start,
            length: exclusion_len,
        }],
    })
    .expect("cbor encode")
}

fn minimal_v2_claim(label: &str) -> Claim {
    let cgi = ClaimGeneratorInfo::new("TestApp");
    let mut claim = Claim::new(label, cgi);
    claim.add_assertion(Assertion::from_data_cbor(
        "c2pa.test",
        &cbor_bytes(serde_json::json!({"key": "value"})),
    ));
    claim
}

#[test]
fn commit_and_lookup() {
    let mut store = Store::new();
    let label = store
        .commit_claim(minimal_v2_claim("urn:c2pa:test"))
        .unwrap();

    assert_eq!(store.claims().len(), 1);
    assert_eq!(store.get_claim(&label).unwrap().label(), label);
    assert_eq!(store.provenance_claim().unwrap().label(), label);
    assert_eq!(store.provenance_label(), Some(label.as_str()));
}

#[test]
fn jumbf_roundtrip_v2() {
    let claim = minimal_v2_claim("urn:c2pa:round-trip-test");
    let original_label = claim.label().to_string();

    let mut store = Store::new();
    store.commit_claim(claim).unwrap();

    let jumbf_bytes = store.to_jumbf().expect("to_jumbf");
    assert!(!jumbf_bytes.is_empty());

    let restored = Store::from_jumbf(&jumbf_bytes).expect("from_jumbf");

    assert_eq!(restored.claims().len(), 1);
    let pc = restored.provenance_claim().unwrap();
    assert_eq!(pc.label(), original_label);
    assert_eq!(pc.version(), 2);
    assert_eq!(pc.claim_generator_info().name, "TestApp");
    assert_eq!(pc.alg.as_deref(), Some("sha256"));
    assert_eq!(pc.assertions().len(), 1);
    assert_eq!(pc.assertions()[0].label(), "c2pa.test");
}

#[test]
fn jumbf_roundtrip_two_manifests() {
    let mut store = Store::new();
    store
        .commit_claim(minimal_v2_claim("urn:c2pa:first"))
        .unwrap();
    store
        .commit_claim(minimal_v2_claim("urn:c2pa:second"))
        .unwrap();

    let bytes = store.to_jumbf().expect("to_jumbf");
    let restored = Store::from_jumbf(&bytes).expect("from_jumbf");

    assert_eq!(restored.claims().len(), 2);
    assert_eq!(restored.provenance_label(), Some("urn:c2pa:second"));
}

// ── Signing workflow tests ──────────────────────────────────────────────────
//
// These tests exercise both C2PA signing workflows without a real signer.
// They use pre-set signature_val bytes to simulate the COSE output so the
// JUMBF structure and size invariants can be verified in isolation.

/// Workflow 1 — sign-first (sidecar / cloud manifest).
///
/// The claim is fully built (hard bindings already known), signed externally,
/// then committed.  The caller sets signature_val before commit; to_jumbf()
/// produces a finished manifest.
#[test]
fn workflow_sign_first_sidecar() {
    let cgi = ClaimGeneratorInfo::new("TestApp");
    let mut claim = Claim::new("urn:c2pa:sidecar-test", cgi);

    // Hard binding was computed before signing (asset was already available)
    claim.add_assertion(Assertion::from_data_cbor(
        "c2pa.hash.data",
        &cbor_bytes(serde_json::json!({
            "name": "jumbf manifest",
            "hash": vec![0u8; 32],     // real SHA-256 would go here
            "exclusions": []
        })),
    ));

    // Caller COSE-signs the claim CBOR (simulated with dummy bytes here)
    let fake_sig = vec![0xab_u8; 512];
    claim.set_signature_val(fake_sig.clone());

    // Commit — already signed, so the store can produce a finished JUMBF
    let mut store = Store::new();
    store.commit_claim(claim).unwrap();

    let jumbf = store.to_jumbf().unwrap();
    assert!(!jumbf.is_empty());

    // Round-trip: the real signature bytes survive
    let restored = Store::from_jumbf(&jumbf).unwrap();
    assert_eq!(
        restored.provenance_claim().unwrap().signature_val(),
        fake_sig.as_slice()
    );
}

/// Workflow 2 — placeholder → update hard binding → sign (embedded manifest).
///
/// The manifest must be sized before the asset hash can be computed, so we
/// produce a placeholder JUMBF first, then update the hash assertion, then
/// (conceptually) sign.  The critical property is that both JUMBF outputs are
/// the same byte length, so the second can patch the first in place.
#[test]
fn workflow_embedded_placeholder_then_sign() {
    // Simulated signer reserve size — in production this comes from
    // signer.reserve_size().  Choose a value large enough to dwarf the
    // "signature placeholder:…" string.
    let reserve_size: usize = 10_240;

    let cgi = ClaimGeneratorInfo::new("TestApp");
    let mut claim = Claim::new("urn:c2pa:embedded-test", cgi);

    // The exclusion region (where the manifest sits in the asset) is known
    // up-front and stays the same in both passes.  Only the hash bytes change.
    let exclusion_start: u64 = 4096;
    let exclusion_len: u64 = 12288; // reserved space for the manifest

    // Phase 1: placeholder hard binding — zeroed 32-byte hash, same CBOR
    // encoding size as a real SHA-256 (both are CBOR byte strings).
    claim.add_assertion(Assertion::from_data_cbor(
        "c2pa.hash.data",
        &data_hash_cbor(&[0u8; 32], exclusion_start, exclusion_len),
    ));

    let mut store = Store::new();
    store.commit_claim(claim).unwrap();

    let placeholder_jumbf = store.to_jumbf_with_reserve(reserve_size).unwrap();
    assert!(!placeholder_jumbf.is_empty());

    // (External: embed placeholder_jumbf in asset at exclusion_start,
    //  compute SHA-256 over the whole asset with the placeholder in place.)

    // Phase 2: only the hash changes — exclusions are identical to Phase 1.
    let real_assertion = Assertion::from_data_cbor(
        "c2pa.hash.data",
        &data_hash_cbor(&[0xde_u8; 32], exclusion_start, exclusion_len),
    );
    store
        .provenance_claim_mut()
        .unwrap()
        .replace_assertion("c2pa.hash.data", real_assertion);

    // Caller COSE-signs the updated claim CBOR (simulated here).
    // In production: sign_claim_bytes(claim.data()?, signer, reserve_size, …)
    let fake_sig = vec![0xcd_u8; reserve_size];
    store
        .provenance_claim_mut()
        .unwrap()
        .set_signature_val(fake_sig);

    // Produce the final JUMBF — must be the same size as the placeholder so
    // it can be written back into the asset at the same offset.
    let final_jumbf = store.to_jumbf_with_reserve(reserve_size).unwrap();

    assert_eq!(
        placeholder_jumbf.len(),
        final_jumbf.len(),
        "placeholder and signed JUMBF must have identical byte length"
    );

    // Sanity: the final JUMBF parses correctly
    let restored = Store::from_jumbf(&final_jumbf).unwrap();
    let pc = restored.provenance_claim().unwrap();
    assert_eq!(pc.assertions().len(), 1);
    assert_eq!(pc.assertions()[0].label(), "c2pa.hash.data");
}

/// Verify that replace_assertion is a no-op when the label is not found.
#[test]
fn replace_assertion_noop_on_missing_label() {
    let cgi = ClaimGeneratorInfo::new("TestApp");
    let mut claim = Claim::new("urn:c2pa:replace-test", cgi);
    claim.add_assertion(Assertion::from_data_cbor(
        "c2pa.actions.v2",
        &cbor_bytes(serde_json::json!({"actions": []})),
    ));

    let before_len = claim.assertions().len();
    claim.replace_assertion(
        "c2pa.hash.data", // not present
        Assertion::from_data_cbor("c2pa.hash.data", &[]),
    );
    assert_eq!(claim.assertions().len(), before_len, "should be unchanged");
}

#[test]
fn unsigned_placeholder_roundtrip() {
    let claim = minimal_v2_claim("urn:c2pa:unsigned");
    assert!(claim.signature_val().is_empty());

    let mut store = Store::new();
    store.commit_claim(claim).unwrap();

    let bytes = store.to_jumbf().expect("to_jumbf");
    let restored = Store::from_jumbf(&bytes).expect("from_jumbf");

    // Signature bytes come back as the placeholder, which is non-empty
    let sig = restored.provenance_claim().unwrap().signature_val();
    assert!(!sig.is_empty());
}

// ── Sidecar full-pipeline test ───────────────────────────────────────────────

/// Build a test signer from the sdk's embedded test certificates.
fn sidecar_test_signer() -> Box<dyn c2pa::Signer> {
    c2pa::create_signer::from_keys(
        include_bytes!("../../sdk/tests/fixtures/certs/ps256.pub"),
        include_bytes!("../../sdk/tests/fixtures/certs/ps256.pem"),
        c2pa::SigningAlg::Ps256,
        None,
    )
    .expect("test signer")
}

/// Full sidecar signing workflow with ingredient support.
///
/// C.jpg already has an embedded manifest store, so this test demonstrates
/// the complete pipeline:
///
/// 1. `Ingredient::from_stream()` on C.jpg — produces the ingredient assertion
///    AND the embedded manifest bytes.
/// 2. Assertions are added in required order:
///    - `c2pa.ingredient` first (its `HashedUri` is needed by the action)
///    - `c2pa.actions` (`c2pa.opened` + `DigitalSourceType`, referencing the ingredient)
///    - `c2pa.hash.data` (whole-asset SHA-256 via `DataHash::gen_hash_from_stream`)
/// 3. Ingredient manifests are loaded into the store before the main claim so
///    they appear first in the JUMBF.
/// 4. The claim is signed and committed; JUMBF is validated via both our store
///    and the sdk's parser.
#[test]
fn sidecar_full_signed_manifest() {
    use std::io::Cursor;

    use c2pa::{
        assertions::{c2pa_action, Action, Actions, DataHash, DigitalSourceType, Ingredient},
        Context, Relationship,
    };

    let asset_bytes = std::fs::read("../sdk/tests/fixtures/C.jpg").expect("C.jpg fixture");

    // 1. Ingredient assertion — must come first so its HashedUri can be put
    //    into the action's parameters.ingredients array.
    // Note: This is the actual Ingredient Assertion, not the higher level one.
    let (ingredient, manifest_bytes) = Ingredient::from_stream(
        Relationship::ParentOf,
        "image/jpeg",
        &mut Cursor::new(&asset_bytes),
        &Context::new(),
    )
    .expect("Ingredient::from_stream");

    let ingredient_cbor = c2pa_cbor::to_vec(&ingredient).expect("ingredient cbor");

    let ingredient_json = serde_json::to_string_pretty(&ingredient).expect("ingredient json");
    println!("Ingredient assertion JSON:\n{ingredient_json}");

    // 2. Build the claim and add the ingredient assertion first
    let cgi = ClaimGeneratorInfo::new("c2pa-store-sidecar-test/0.1");
    let mut claim = Claim::new("urn:c2pa:sidecar-test", cgi);

    let ingredient_uri = claim.add_assertion(Assertion::from_data_cbor(
        "c2pa.ingredient.v3",
        &ingredient_cbor,
    ));

    // 3. Actions assertion: c2pa.opened, referencing the ingredient via its URI
    let actions = Actions::new().add_action(
        Action::new(c2pa_action::OPENED)
            .set_source_type(DigitalSourceType::DigitalCapture)
            .set_parameter(
                "ingredients".to_string(),
                serde_json::json!([serde_json::to_value(&ingredient_uri).unwrap()]),
            )
            .expect("set_parameter ingredients"),
    );
    let actions_cbor = c2pa_cbor::to_vec(&actions).expect("actions cbor");
    claim.add_assertion(Assertion::from_data_cbor("c2pa.actions.v2", &actions_cbor));

    // 4. DataHash hard binding — whole-asset SHA-256, no exclusions (sidecar)
    let mut dh = DataHash::new("jumbf manifest", "sha256");
    dh.gen_hash_from_stream(&mut Cursor::new(&asset_bytes))
        .expect("gen_hash_from_stream");
    let dh_cbor = c2pa_cbor::to_vec(&dh).expect("DataHash cbor");
    claim.add_assertion(Assertion::from_data_cbor("c2pa.hash.data", &dh_cbor));

    // 5. Sign the claim CBOR
    let signer = sidecar_test_signer();
    let claim_cbor = claim.data().expect("claim cbor");
    let cose_bytes = c2pa::cose_sign::sign_claim(
        &claim_cbor,
        signer.as_ref(),
        signer.reserve_size(),
        &c2pa::settings::Settings::default(),
    )
    .expect("sign_claim");
    claim.set_signature_val(cose_bytes);

    // 6. Build store: ingredient manifests first, then the active manifest
    let mut store = Store::new();
    if let Some(bytes) = manifest_bytes {
        store
            .add_ingredient_manifests(&bytes)
            .expect("add_ingredient_manifests");
    }
    store.commit_claim(claim).expect("commit_claim");
    let jumbf = store.to_jumbf().expect("to_jumbf");
    assert!(!jumbf.is_empty());

    // 7a. Our store: confirms JUMBF round-trips and COSE bytes survive
    let our_restored = Store::from_jumbf(&jumbf).expect("our from_jumbf");
    assert!(
        our_restored.claims().len() > 1,
        "ingredient manifests should be present alongside the active manifest"
    );
    let our_claim = our_restored
        .provenance_claim()
        .expect("our provenance claim");
    assert_eq!(our_claim.version(), 2);
    assert!(
        !our_claim.signature_val().is_empty(),
        "real COSE signature should be present"
    );
    assert!(
        our_claim
            .assertions()
            .iter()
            .any(|a| a.label() == "c2pa.ingredient.v3"),
        "missing c2pa.ingredient"
    );
    assert!(
        our_claim
            .assertions()
            .iter()
            .any(|a| a.label() == "c2pa.actions.v2"),
        "missing c2pa.actions"
    );
    assert!(
        our_claim
            .assertions()
            .iter()
            .any(|a| a.label() == "c2pa.hash.data"),
        "missing c2pa.hash.data"
    );

    // 7b. sdk parser: proves the JUMBF is spec-compliant
    let mut log = c2pa::status_tracker::StatusTracker::default();
    let sdk_store = c2pa::store::Store::from_jumbf(&jumbf, &mut log).expect("sdk from_jumbf");
    assert!(!log.has_any_error(), "sdk parse errors: {log:?}");
    assert!(
        sdk_store.claims().len() > 1,
        "sdk should see ingredient + active manifests"
    );

    let sdk_claim = sdk_store.provenance_claim().expect("sdk provenance claim");
    assert_eq!(sdk_claim.version(), 2);
    let urls: Vec<String> = sdk_claim.assertions().iter().map(|h| h.url()).collect();
    assert!(
        urls.iter().any(|u| u.contains("c2pa.ingredient.v3")),
        "sdk: missing c2pa.ingredient: {urls:?}"
    );
    assert!(
        urls.iter().any(|u| u.contains("c2pa.actions.v2")),
        "sdk: missing c2pa.actions: {urls:?}"
    );
    assert!(
        urls.iter().any(|u| u.contains("c2pa.hash.data")),
        "sdk: missing c2pa.hash.data: {urls:?}"
    );

    let reader =
        c2pa::Reader::from_manifest_data_and_stream(&jumbf, "image/jpg", Cursor::new(asset_bytes))
            .unwrap();
    println!("Reader status: {reader}");
}
