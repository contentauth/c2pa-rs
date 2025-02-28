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

//! This test suite checks the enforcement of generic identity assertion
//! validation as described in [§7.1, Validation method].
//!
//! IMPORTANT: The CAWG SDK does not currently support the optional fields named
//! * `expected_partial_claim`
//! * `expected_claim_generator`
//! * `expected_countersigners`
//!
//! [§7.1, Validation method]: https://cawg.io/identity/1.1-draft/#_validation_method

use std::io::Cursor;

use c2pa::Reader;
use c2pa_crypto::raw_signature::SigningAlg;
use c2pa_status_tracker::{LogKind, StatusTracker};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{x509::X509SignatureVerifier, IdentityAssertion};

/// An identity assertion MUST contain a valid CBOR data structure that contains
/// the required fields as documented in the identity rule in [Section 5.2,
/// “CBOR schema”]. The `cawg.identity.cbor.invalid` error code SHALL be used to
/// report assertions that do not follow this rule.
///
/// [Section 5.2, “CBOR schema”]: https://cawg.io/identity/1.1-draft/#_cbor_schema
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn malformed_cbor() {
    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/validation_method/malformed_cbor.jpg");

    let mut test_image = Cursor::new(test_image);

    // Initial read with default `Reader` should pass without issues.
    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    // Re-parse with identity assertion code should find malformed CBOR error.
    let mut status_tracker = StatusTracker::default();

    let active_manifest = reader.active_manifest().unwrap();
    let ia_results: Vec<Result<IdentityAssertion, c2pa::Error>> =
        IdentityAssertion::from_manifest(active_manifest, &mut status_tracker).collect();

    assert_eq!(ia_results.len(), 1);

    let ia_err = ia_results[0].as_ref().unwrap_err();
    assert_eq!(ia_err.to_string(), "could not decode assertion cawg.identity (version (no version), content type application/json): missing field `signer_payload`");

    assert_eq!(status_tracker.logged_items().len(), 1);

    let log = &status_tracker.logged_items()[0];
    assert_eq!(log.kind, LogKind::Failure);
    assert_eq!(log.label, "cawg.identity");
    assert_eq!(log.description, "invalid CBOR");
    assert_eq!(
        log.validation_status.as_ref().unwrap().as_ref(),
        "cawg.identity.cbor.invalid"
    );
}

/// A validator SHALL NOT consider any extra fields not documented in the
/// `identity` rule during the validation process.
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn extra_fields() {
    // The test asset `extra_field.jpg` was written using a temporarily modified
    // version of this SDK that generated an `other_stuff` string value at the top
    // level of the identity assertion CBOR.

    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/validation_method/extra_field.jpg");

    let mut test_image = Cursor::new(test_image);

    // Initial read with default `Reader` should pass without issues.
    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    // Re-parse with identity assertion code should find malformed CBOR error.
    let mut status_tracker = StatusTracker::default();

    let active_manifest = reader.active_manifest().unwrap();
    let ia_results: Vec<Result<IdentityAssertion, c2pa::Error>> =
        IdentityAssertion::from_manifest(active_manifest, &mut status_tracker).collect();

    assert_eq!(ia_results.len(), 1);

    let ia = ia_results[0].as_ref().unwrap();
    dbg!(ia);

    let sp = &ia.signer_payload;
    assert_eq!(sp.referenced_assertions.len(), 1);

    assert_eq!(
        sp.referenced_assertions[0].url(),
        "self#jumbf=c2pa.assertions/c2pa.hash.data".to_owned()
    );

    assert_eq!(sp.sig_type, "cawg.x509.cose".to_owned());

    // TEMPORARY: Should report success code.
    assert_eq!(status_tracker.logged_items().len(), 0);

    // let log = &status_tracker.logged_items()[0];
    // assert_eq!(log.kind, LogKind::Failure);
    // assert_eq!(log.label, "cawg.identity");
    // assert_eq!(log.description, "invalid CBOR");
    // assert_eq!(
    //     log.validation_status.as_ref().unwrap().as_ref(),
    //     "cawg.identity.cbor.invalid"
    // );
}

/// For each entry in `signer_payload.referenced_assertions`, the validator MUST
/// verify that the same entry exists in either the `created_assertions` or
/// `gathered_assertions` entry of the C2PA claim. (For version 1 claims, the
/// entry must appear in the `assertions` entry.) The
/// `cawg.identity.assertion.mismatch` error code SHALL be used to report
/// violations of this rule.
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn assertion_not_in_claim_v1() {
    // The test asset `extra_assertion_claim_v1.jpg` was written using a temporarily
    // modified version of this SDK that incorrectly added an extra hashed URI to
    // `referenced_assertions` that is not present in the claim.

    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/validation_method/extra_assertion_claim_v1.jpg");

    let mut test_image = Cursor::new(test_image);

    // Initial read with default `Reader` should pass without issues.
    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    // Re-parse with identity assertion code should find extra assertion error.
    let mut status_tracker = StatusTracker::default();

    let active_manifest = reader.active_manifest().unwrap();
    let ia_results: Vec<Result<IdentityAssertion, c2pa::Error>> =
        IdentityAssertion::from_manifest(active_manifest, &mut status_tracker).collect();

    assert_eq!(ia_results.len(), 1);

    // This condition is parseable, but incorrect. There should be a validation
    // status log for this failure.
    let ia = ia_results[0].as_ref().unwrap();

    let sp = &ia.signer_payload;
    assert_eq!(sp.referenced_assertions.len(), 2);

    assert_eq!(
        sp.referenced_assertions[0].url(),
        "self#jumbf=c2pa.assertions/c2pa.hash.data".to_owned()
    );

    assert_eq!(
        sp.referenced_assertions[1].url(),
        "self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/testing.bogus.assertion".to_owned()
    );

    assert_eq!(sp.sig_type, "cawg.x509.cose".to_owned());

    let x509_verifier = X509SignatureVerifier {};
    let sig_info = ia
        .validate(
            reader.active_manifest().unwrap(),
            &mut status_tracker,
            &x509_verifier,
        )
        .await
        .unwrap();

    assert_eq!(status_tracker.logged_items().len(), 1);

    let log = &status_tracker.logged_items()[0];
    assert_eq!(log.kind, LogKind::Failure);
    assert_eq!(log.label, "NEED TO FIND LABEL"); // !!!
    assert_eq!(log.description, "referenced assertion not in claim");
    assert_eq!(
        log.validation_status.as_ref().unwrap().as_ref(),
        "cawg.identity.assertion.mismatch"
    );

    let cert_info = &sig_info.cert_info;
    assert_eq!(cert_info.alg.unwrap(), SigningAlg::Ed25519);
    assert_eq!(
        cert_info.issuer_org.as_ref().unwrap(),
        "C2PA Test Signing Cert"
    );
}

/// For each entry in `signer_payload.referenced_assertions`, the validator MUST
/// verify that the same entry exists in either the `created_assertions` or
/// `gathered_assertions` entry of the C2PA claim. (For version 1 claims, the
/// entry must appear in the `assertions` entry.) The
/// `cawg.identity.assertion.mismatch` error code SHALL be used to report
/// violations of this rule.
#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
#[ignore]
async fn assertion_not_in_claim_v2() {
    todo!("Generate a suitable V2 asset with an extra assertion");
}
