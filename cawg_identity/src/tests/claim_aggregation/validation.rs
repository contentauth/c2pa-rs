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
    claim_aggregation::IcaSignatureVerifier,
    tests::fixtures::claim_aggregation::ica_credential_example, IdentityAssertion,
};

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
async fn success_case() {
    // If the value of signer_payload.sig_type is cawg.identity_claims_aggregation,
    // the validator SHOULD proceed with validation of the signature value as
    // described in the remainder of this section.
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
