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

use crate::{
    claim_aggregation::{IcaSignatureVerifier, IcaValidationError},
    tests::fixtures::claim_aggregation::ica_credential_example,
    IdentityAssertion, ValidationError,
};

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
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
    assert_eq!(subject.c2pa_asset, ia.signer_payload);

    let mut log_items = st.logged_items().iter();

    let li = log_items.next().unwrap();
    dbg!(li);

    assert_eq!(li.kind, LogKind::Success);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "ICA credential is valid");
    assert_eq!(li.crate_name, "cawg-identity");
    assert_eq!(
        li.validation_status.as_ref().unwrap(),
        "cawg.ica.credential_valid"
    );

    assert!(log_items.next().is_none());
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
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
    dbg!(li);

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid COSE_Sign1 data structure");
    assert_eq!(li.crate_name, "cawg-identity");
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
    dbg!(li);

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Invalid COSE_Sign1 signature algorithm");
    assert_eq!(li.crate_name, "cawg-identity");
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
    dbg!(li);

    assert_eq!(li.kind, LogKind::Failure);
    assert_eq!(li.label, "(IA label goes here)");
    assert_eq!(li.description, "Missing COSE_Sign1 signature algorithm");
    assert_eq!(li.crate_name, "cawg-identity");
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
