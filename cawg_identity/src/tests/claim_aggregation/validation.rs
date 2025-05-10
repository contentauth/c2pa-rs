// Copyright 2025 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! This test suite verifies the behaviors described in [§8.1.7, “Validating an
//! identity assertion with an identity claims aggregation credential”] of the
//! CAWG identity specification:
//!
//! [§8.1.7, “Validating an identity assertion with an identity claims aggregation credential”]: https://cawg.io/identity/1.1-draft+ica-validation/#_validating_an_identity_assertion_with_an_identity_claims_aggregation_credential

use std::io::Cursor;

use c2pa::Reader;
use c2pa_status_tracker::{LogKind, StatusTracker};
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    claim_aggregation::{IcaSignatureVerifier, IcaValidationError},
    tests::fixtures::claim_aggregation::ica_credential_example,
    IdentityAssertion, ValidationError,
};

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn success_case() {
    // If the value of `signer_payload.sig_type` is
    // `cawg.identity_claims_aggregation`, the validator SHOULD proceed with
    // validation of the `signature` value as described in the remainder of this
    // section.
    //
    // A successful validation report SHOULD include the content of the verifiable
    // credential and available information about the credential’s issuer.

    // §8.1.7.5. Success code
    //
    // If the validator has completed the process without generating any failure
    // codes, it MUST issue the success code `cawg.ica.credential_valid` for this
    // assertion.

    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/claim_aggregation/ica_validation/success.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());
    assert!(subject.time_stamp.is_none());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Success);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "ICA credential is valid");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.credential_valid"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn invalid_cose_sign1() {
    // 8.1.7.2.1. Parse the `COSE_Sign1` structure
    //
    // The validator SHALL parse the full `signature` value as a `COSE_Sign1` object
    // as described in [Section 4.2, “Signing with one signer,”] of RFC 9052. If
    // parsing fails, the validator MUST stop validation at this point and issue the
    // failure code `cawg.ica.invalid_cose_sign1`.
    //
    // [Section 4.2, “Signing with one signer,”]: https://www.rfc-editor.org/rfc/rfc9052.html#name-signing-with-one-signer

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/invalid_cose_sign1.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_err = ia.validate(manifest, &mut st, &isv).await.unwrap_err();
    st.pop_current_uri();

    assert_eq!(
        ica_err,
        ValidationError::SignatureError(IcaValidationError::CoseDecodeError(
            "extraneous data in CBOR input".to_owned()
        ))
    );

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid COSE_Sign1 data structure");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(extraneous data in CBOR input)"
    );
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_cose_sign1"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn invalid_cose_sign_alg() {
    // 8.1.7.2.1. Parse the `COSE_Sign1` structure
    //
    // The validator SHALL inspect the `COSE_Sign1` protected header `alg` to
    // determine the cryptographic algorithm used to issue the signature. The `alg`
    // value MUST be one of the following algorithm labels (corresponding to the
    // values supported by the C2PA technical specification as of this writing):
    //
    // * -7 (ECDSA w/SHA-256)
    // * -35 (ECDSA w/ SHA-384)
    // * -36 (ECDSA w/ SHA-512)
    // * -37 (RSASSA-PSS w/ SHA-256)
    // * -38 (RSASSA-PSS w/ SHA-384)
    // * -39 (RSASSA-PSS w/ SHA-512)
    // * -8 (EdDSA)
    //
    // NOTE: Only the Ed25519 instance of EdDSA is supported.
    //
    // If the `alg` header contains any other value or is not present, the validator
    // MUST issue the failure code `cawg.ica.invalid_alg` but MAY continue
    // validation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/invalid_cose_sign_alg.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_err = ia.validate(manifest, &mut st, &isv).await.unwrap_err();
    st.pop_current_uri();

    assert_eq!(
        ica_err,
        ValidationError::SignatureError(IcaValidationError::UnsupportedSignatureType(
            "Assigned(SHA_1)".to_owned()
        ))
    );

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid COSE_Sign1 signature algorithm");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(UnsupportedSignatureType(\"Assigned(SHA_1)\"))"
    );
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_alg"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn missing_cose_sign_alg() {
    // Same as above, but in this case, NO signature algorithm is specified in the
    // `COSE_Sign1` data structure.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/missing_cose_sign_alg.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_err = ia.validate(manifest, &mut st, &isv).await.unwrap_err();
    st.pop_current_uri();

    assert_eq!(
        ica_err,
        ValidationError::SignatureError(IcaValidationError::SignatureTypeMissing)
    );

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Missing COSE_Sign1 signature algorithm");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(SignatureTypeMissing)"
    );
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_alg"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn invalid_content_type() {
    // The validator SHALL inspect the `COSE_Sign1` protected header `content type`
    // to determine the content type of the enclosed credential. The `content type`
    // header MUST be the exact value `application/vc`. If it is not, the validator
    // MUST issue the failure `code cawg.ica.invalid_content_type` but MAY continue
    // validation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/invalid_content_type.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid COSE_Sign1 content type header");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(UnsupportedContentType(\"\\\"application/bogus\\\"\"))"
    );
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_content_type"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn invalid_content_type_assigned() {
    // Same as above, but in this case, an assigned constant content type is
    // specified in the `COSE_Sign1` data structure.

    let format = "image/jpeg";
    let test_image = include_bytes!(
        "../fixtures/claim_aggregation/ica_validation/invalid_content_type_assigned.jpg"
    );

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid COSE_Sign1 content type header");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(UnsupportedContentType(\"Assigned(OctetStream)\"))"
    );
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_content_type"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn missing_content_type() {
    // Same as above, but in this case, NO content type is specified in the
    // `COSE_Sign1` data structure.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/missing_content_type.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid COSE_Sign1 content type header");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(ContentTypeMissing)"
    );
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_content_type"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn missing_vc() {
    // The validator SHALL obtain the unprotected `payload` of the `COSE_Sign1` data
    // structure. This payload is the raw JSON-LD content of the verifiable
    // credential. A validator SHALL attempt to parse the core verifiable credential
    // data syntax of this credential using the following methods:
    //
    // * [Section 6, “Syntaxes,” of Verifiable credentials data model, version 1.1]
    // * [Section 6, “Syntaxes,” of Verifiable credentials data model, version 2.0]
    //
    // If the validator is unable to parse the credential using either version of
    // the Verifiable credentials data model, the validator MUST stop validation at
    // this point and issue the failure code
    // `cawg.ica.invalid_verifiable_credential`.
    //
    // [Section 6, “Syntaxes,” of Verifiable credentials data model, version 1.1]: https://www.w3.org/TR/vc-data-model/#syntaxes
    // [Section 6, “Syntaxes,” of Verifiable credentials data model, version 2.0]: https://www.w3.org/TR/vc-data-model-2.0/#syntaxes

    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/claim_aggregation/ica_validation/missing_vc.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_err = ia.validate(manifest, &mut st, &isv).await.unwrap_err();
    st.pop_current_uri();

    assert_eq!(
        ica_err,
        ValidationError::SignatureError(IcaValidationError::CredentialPayloadMissing)
    );

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Missing COSE_Sign1 payload");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(CredentialPayloadMissing)"
    );
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_verifiable_credential"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn invalid_vc() {
    // ^^ Same as above but the VC is corrupted rather than missing.

    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/claim_aggregation/ica_validation/invalid_vc.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_err = ia.validate(manifest, &mut st, &isv).await.unwrap_err();
    st.pop_current_uri();

    assert_eq!(
        ica_err,
        ValidationError::SignatureError(IcaValidationError::JsonDecodeError(
            "expected value at line 1 column 1".to_owned()
        ))
    );

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid JSON-LD for verifiable credential");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(JsonDecodeError(\"expected value at line 1 column 1\"))"
    );
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_verifiable_credential"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn invalid_issuer_did() {
    // 8.1.7.2.3. Obtain the credential issuer’s public key
    //
    // The validator SHALL obtain the identity of the identity claims aggregator by
    // inspecting the issuer field of the verifiable credential. The identity SHOULD
    // be expressed as a DID (decentralized identifier), either as issuer itself or
    // issuer.id. If no DID is located at either location, the validator MUST issue
    // the failure code cawg.ica.invalid_issuer but MAY continue validation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/invalid_issuer_did.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid issuer DID");
    assert_eq!(li.crate_name, "c2pa");

    assert!(li
        .err_val
        .as_ref()
        .unwrap()
        .starts_with("SignatureError(UnsupportedIssuerDid(\"invalid DID `not-did:jwk:"));

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_issuer"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn unsupported_did_method() {
    // The validator SHALL resolve the DID document as described in Section 7.1,
    // “DID resolution,” of the DID specification. If the DID uses a DID method that
    // is unsupported by the validator, the validator MUST issue the failure code
    // `cawg.ica.did_unsupported_method` but MAY continue validation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/invalid_issuer_did.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid issuer DID");
    assert_eq!(li.crate_name, "c2pa");

    assert!(li
        .err_val
        .as_ref()
        .unwrap()
        .starts_with("SignatureError(UnsupportedIssuerDid(\"invalid DID `not-did:jwk:"));

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_issuer"
    );

    assert!(log_items.next().is_none());
}

// TO DO (CAI-7996): Not sure why this doesn't run on Wasm/WASI.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn unresolvable_did() {
    // If the DID can not be resolved, the validator MUST issue the failure code
    // `cawg.ica.did_unavailable` but MAY continue validation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/unresolvable_did.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Unable to resolve issuer DID");
    assert_eq!(li.crate_name, "c2pa");

    assert_eq!(li
        .err_val
        .as_ref()
        .unwrap(),
        "SignatureError(DidResolutionError(\"the document was not found: https://example.com/.well-known/did.json\"))");

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.did_unavailable"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn did_doc_without_assertion_method() {
    // The validator SHALL locate within the DID document the `assertionMethod`
    // verification method as described in Section 5.3.2, “Assertion,” of the DID
    // specification. This verification method SHALL contain public key material
    // corresponding to the stated issuer. If the public key material can not be
    // located, the validator MUST issue the failure code
    // `cawg.ica.missing_public_key` but MAY continue validation.

    let format = "image/jpeg";
    let test_image = include_bytes!(
        "../fixtures/claim_aggregation/ica_validation/did_doc_without_assertion_method.jpg"
    );

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid issuer DID document");
    assert_eq!(li.crate_name, "c2pa");

    assert_eq!(li
        .err_val
        .as_ref()
        .unwrap(),
        "SignatureError(InvalidDidDocument(\"DID document doesn't contain an assertionMethod entry\"))");

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.invalid_did_document"
    );

    assert!(log_items.next().is_none());
}

// #[test]
// #[ignore]
// fn did_is_untrusted() {
//     // The validator SHALL verify that the issuer’s DID is present or can be
//     // traced to its preconfigured list of trustable entities. If the issuer
// is     // not verifiably trusted, the validator MUST issue the failure code
//     // `cawg.ica.untrusted_issuer` but MAY continue validation.

//     // TO DO (CAI-7980): Add option to configure trusted ICA issuers.
// }

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn signature_mismatch() {
    // 8.1.7.2.4. Verify the COSE signature
    //
    // The validator SHALL verify the signature using the public key material just
    // identified and the unsecured verifiable credential as payload as described by
    // Section 4.4, “Signing and verification process,” of RFC 9052. If the
    // signature does not match, the validator MUST issue the failure code
    // `cawg.ica.signature_mismatch` but MAY continue validation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/signature_mismatch.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Signature does not match credential");
    assert_eq!(li.crate_name, "c2pa");

    assert_eq!(li.err_val.as_ref().unwrap(), "SignatureMismatch");

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.signature_mismatch"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn valid_time_stamp() {
    // 8.1.7.2.5. Verify the time stamp, if present
    //
    // The validator SHALL inspect the time stamp included in the `COSE_Sign1` data
    // structure if it is present. This will be stored in a COSE unprotected header
    // named `sigTst2`. If such a header is found, the validator SHALL follow the
    // procedure described in Section 10.3.2.5, “Time-stamps,” of the C2PA technical
    // specification. If the validation is successful, the validator MUST issue the
    // success code `cawg.ica.time_stamp.validated`. If the validation is not
    // successful, the validator MUST issue the status code
    // `cawg.ica.time_stamp.invalid`. It MAY continue validation, but MUST NOT use
    // the time stamp in any further validation calculation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/valid_time_stamp.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let tst_info = subject.time_stamp.as_ref().unwrap();

    assert_eq!(tst_info.gen_time.to_string(), "20250423194523Z");

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Success);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Time stamp validated");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.time_stamp.validated"
    );

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Success);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "ICA credential is valid");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.credential_valid"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn invalid_time_stamp() {
    // 8.1.7.2.5. Verify the time stamp, if present
    //
    // The validator SHALL inspect the time stamp included in the `COSE_Sign1` data
    // structure if it is present. This will be stored in a COSE unprotected header
    // named `sigTst2`. If such a header is found, the validator SHALL follow the
    // procedure described in Section 10.3.2.5, “Time-stamps,” of the C2PA technical
    // specification. If the validation is successful, the validator MUST issue the
    // success code `cawg.ica.time_stamp.validated`. If the validation is not
    // successful, the validator MUST issue the status code
    // `cawg.ica.time_stamp.invalid`. It MAY continue validation, but MUST NOT use
    // the time stamp in any further validation calculation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/invalid_time_stamp.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    assert!(subject.time_stamp.is_none());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Time stamp does not match credential");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(InvalidTimeStamp)"
    );

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.time_stamp.invalid"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn valid_from_missing() {
    // 8.1.7.2.6. Verify the credential’s validity range
    //
    // The validator SHALL inspect the credential’s effective date. This may be
    // stored as `issuanceDate` or `validFrom`, depending on the version of the
    // verifiable credentials data model in use. If this field is missing, the
    // validator MUST issue the failure code `cawg.ica.valid_from.missing` but MAY
    // continue validation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/valid_from_missing.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());
    assert!(ica_vc.valid_from.is_none());
    assert!(subject.time_stamp.is_none());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "credential does not have a validFrom date");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(MissingValidFromDate)"
    );

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.valid_from.missing"
    );

    assert!(log_items.next().is_none());
}

// TO DO (CAI-7996): Not sure why this doesn't run on Wasm/WASI.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn valid_from_in_future() {
    // 8.1.7.2.6. Verify the credential’s validity range
    //
    // The validator SHALL compare the effective date of the credential against each
    // of the following values, if available:
    //
    // * Current date and time

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/valid_from_in_future.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());
    assert!(subject.time_stamp.is_none());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(
        li.description,
        "credential's validFrom date is unacceptable (validFrom is after current date/time)"
    );
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(InvalidValidFromDate(\"validFrom is after current date/time\"))"
    );

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.valid_from.invalid"
    );

    assert!(log_items.next().is_none());
}

// TO DO (CAI-7996): Not sure why this doesn't run on Wasm/WASI.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn valid_from_after_time_stamp() {
    // 8.1.7.2.6. Verify the credential’s validity range
    //
    // The validator SHALL compare the effective date of the credential against each
    // of the following values, if available:
    //
    // * Time stamp for the COSE signature as described in Section 8.1.6,
    //   “Verifiable credential proof mechanism”

    let format = "image/jpeg";
    let test_image = include_bytes!(
        "../fixtures/claim_aggregation/ica_validation/valid_from_after_time_stamp.jpg"
    );

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());
    assert!(subject.time_stamp.is_some());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Success);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Time stamp validated");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.time_stamp.validated"
    );

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(
        li.description,
        "credential's validFrom date is unacceptable (validFrom is after CAWG signature time stamp)"
    );
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(InvalidValidFromDate(\"validFrom is after CAWG signature time stamp\"))"
    );

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.valid_from.invalid"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn valid_until_in_future() {
    // If the expiration date is present, the validator SHALL compare the expiration
    // date of the credential against each of the following values, if available:
    //
    // * Current date and time
    // * Time stamp for the C2PA Manifest as described in Section 10.3.2.5,
    //   “Time-stamps,” of the C2PA technical specification
    // * Time stamp for the COSE signature as described in Section 8.1.6,
    //   “Verifiable credential proof mechanism”
    //
    // If the credential’s expiration date is earlier than any of the above values,
    // the validator MUST issue the failure code `cawg.ica.valid_until.invalid` but
    // MAY continue validation.
    //
    // In this test case, the expiration date is present, but far in the future.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/valid_until_in_future.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Success);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "ICA credential is valid");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.credential_valid"
    );

    assert!(log_items.next().is_none());
}

// TO DO (CAI-7996): Not sure why this doesn't run on Wasm/WASI.
#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn valid_until_in_past() {
    // If the expiration date is present, the validator SHALL compare the expiration
    // date of the credential against each of the following values, if available:
    //
    // * Current date and time
    // * Time stamp for the C2PA Manifest as described in Section 10.3.2.5,
    //   “Time-stamps,” of the C2PA technical specification
    // * Time stamp for the COSE signature as described in Section 8.1.6,
    //   “Verifiable credential proof mechanism”
    //
    // If the credential’s expiration date is earlier than any of the above values,
    // the validator MUST issue the failure code `cawg.ica.valid_until.invalid` but
    // MAY continue validation.
    //
    // In this test case, the expiration date is set far in the past.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/valid_until_in_past.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_eq!(&subject.c2pa_asset, ia.signer_payload());
    assert!(subject.time_stamp.is_none());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(
        li.description,
        "credential's validUntil date is unacceptable (validUntil is before current date/time)"
    );
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(InvalidValidUntilDate(\"validUntil is before current date/time\"))"
    );

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.valid_until.invalid"
    );

    assert!(log_items.next().is_none());
}

// #[test]
// #[ignore]
// fn credential_is_revoked() {
//     // 8.1.7.2.7. Verify the credential’s revocation status
//     //
//     // If the credential contains a `credentialStatus` entry, the validator
//     // SHALL inspect the contents of that entry. If the entry contains an
// entry     // with its `statusPurpose` set to `revocation`, the validator
// SHALL follow     // the procedures described as described by the
// corresponding `type` entry.

//     // TO DO (CAI-7993): CAWG SDK should check ICA issuer revocation status.
// }

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn signer_payload_mismatch() {
    // 8.1.7.3. Verify binding to C2PA asset
    //
    // The validator SHALL take the content of `signer_payload in the identity
    // assertion and perform the transformations from CBOR to JSON as described in
    // Section 8.1.2.6, “Binding to C2PA asset”. The validator SHALL then compare
    // the transformed `signer_payload` data structure to the `c2paAsset` field
    // contained within the verifiable credential’s `credentialSubject` field. If
    // the data structures do not match, the validator MUST issue the failure code
    // `cawg.ica.signer_payload.mismatch` but MAY continue validation.

    let format = "image/jpeg";
    let test_image =
        include_bytes!("../fixtures/claim_aggregation/ica_validation/signer_payload_mismatch.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    let manifest = reader.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};

    // HACK: See if we can transition to PostValidate without losing access
    // to the ica_vc member below.
    st.push_current_uri("(IA label goes here)");
    let ica_vc = ia.validate(manifest, &mut st, &isv).await.unwrap();
    st.pop_current_uri();

    // Start matching against expected values.
    let expected_identities = ica_credential_example::ica_example_identities();

    let subject = ica_vc.credential_subjects.first();
    assert_eq!(subject.verified_identities, expected_identities);
    assert_ne!(&subject.c2pa_asset, ia.signer_payload());
    assert!(subject.time_stamp.is_none());

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "c2paAsset does not match signer_payload");
    assert_eq!(li.crate_name, "c2pa");
    assert_eq!(
        li.err_val.as_ref().unwrap(),
        "SignatureError(SignerPayloadMismatch)"
    );

    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.signer_payload.mismatch"
    );

    assert!(log_items.next().is_none());
}

// #[test]
// #[ignore]
// fn verified_identities() {
//     // 8.1.7.4. Verify verified identities
//     //
//     // The validator SHALL inspect the contents of the `verifiedIdentities`
//     // field contained within the verifiable credential’s `credentialSubject`
//     // field. If this field is missing, if it is not a JSON array, or if it
// is     // an empty array, the validator MUST issue the failure code
//     // `cawg.ica.verified_identities.missing` but MAY continue validation.
//     //
//     // The validator SHALL inspect each entry in the `verifiedIdentities`
// array.     // For each entry, it SHALL verify each of the conditions stated
// in Section     // 8.1.2.5, “Verified identities” and issue the failure code
//     // `cawg.ica.verified_identities.invalid` if any condition stated there
// is     // unmet.
//     //
//     // The validator MAY annotate entries in the `verifiedIdentities` array
//     // according to its own policies regarding trust or validity of each
//     // identity.

//     // TO DO (CAI-7994): CAWG SDK should inspect verifiedIdentities array.
// }
