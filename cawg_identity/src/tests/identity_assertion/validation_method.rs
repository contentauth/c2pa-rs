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
use c2pa_status_tracker::{LogKind, StatusTracker};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::IdentityAssertion;

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
