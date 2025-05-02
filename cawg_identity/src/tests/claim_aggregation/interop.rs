// Copyright 2024 Adobe. All rights reserved.
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

use std::{io::Cursor, str::FromStr};

use c2pa::{HashedUri, Reader};
use c2pa_status_tracker::StatusTracker;
use chrono::{DateTime, FixedOffset};
use iref::UriBuf;
use non_empty_string::NonEmptyString;
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    claim_aggregation::{IcaSignatureVerifier, IdentityProvider, VerifiedIdentity},
    IdentityAssertion, SignerPayload,
};

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn adobe_connected_identities() {
    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/claim_aggregation/adobe_connected_identities.jpg");

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
    let ica = ia.validate(manifest, &mut st, &isv).await.unwrap();

    // There should be exactly one verified identity.
    let ica_vc = ica.credential_subjects.first();

    assert_eq!(ica_vc.verified_identities.len().get(), 1);
    let vi1 = ica_vc.verified_identities.first();

    assert_eq!(
        vi1,
        &VerifiedIdentity {
            type_: NonEmptyString::new("cawg.social_media".to_string(),).unwrap(),
            name: None,
            username: Some(NonEmptyString::new("testuser23".to_string(),).unwrap(),),
            address: None,
            uri: Some(UriBuf::from_str("https://net.s2stagehance.com/testuser23").unwrap(),),
            verified_at: DateTime::<FixedOffset>::parse_from_rfc3339("2025-04-09T22:45:26+00:00")
                .unwrap(),
            provider: IdentityProvider {
                id: UriBuf::from_str("https://behance.net").unwrap(),
                name: NonEmptyString::new("behance".to_string(),).unwrap(),
            },
        }
    );

    let expected_hex_literal: &[u8] = &[
        222, 12, 254, 33, 138, 24, 216, 89, 74, 194, 44, 202, 254, 234, 79, 175, 58, 31, 243, 141,
        143, 60, 113, 134, 81, 85, 8, 248, 86, 167, 211, 178,
    ];
    assert_eq!(
        ica_vc.c2pa_asset,
        SignerPayload {
            referenced_assertions: vec![HashedUri::new(
                "self#jumbf=c2pa.assertions/c2pa.hash.data".to_owned(),
                Some("sha256".to_string()),
                expected_hex_literal
            )],
            roles: vec!(),
            sig_type: "cawg.identity_claims_aggregation".to_owned(),
        }
    );

    // Check the summary report for the entire manifest store.
    let mut st = StatusTracker::default();
    let ia_summary = IdentityAssertion::summarize_from_reader(&reader, &mut st, &isv).await;
    let ia_json = serde_json::to_string(&ia_summary).unwrap();

    assert_eq!(
        ia_json,
        r#"{"urn:uuid:19e83793-4427-4161-b682-a53b975a6f72":[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2025-04-09T22:46:13Z","verifiedIdentities":[{"type":"cawg.social_media","username":"testuser23","uri":"https://net.s2stagehance.com/testuser23","verifiedAt":"2025-04-09T22:45:26Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://cawg.io/identity/1.1/ica/schema/","type":"JSONSchema"}]}}]}"#
    );

    // Check the summary report for this manifest.
    let mut st = StatusTracker::default();
    let ia_summary = IdentityAssertion::summarize_all(manifest, &mut st, &isv).await;
    let ia_json = serde_json::to_string(&ia_summary).unwrap();

    assert_eq!(
        ia_json,
        r#"[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2025-04-09T22:46:13Z","verifiedIdentities":[{"type":"cawg.social_media","username":"testuser23","uri":"https://net.s2stagehance.com/testuser23","verifiedAt":"2025-04-09T22:45:26Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://cawg.io/identity/1.1/ica/schema/","type":"JSONSchema"}]}}]"#
    );
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn ims_multiple_manifests() {
    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/claim_aggregation/ims_multiple_manifests.jpg");

    let mut test_image = Cursor::new(test_image);

    let reader = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(reader.validation_status(), None);

    // Check the summary report for the entire manifest store.
    let mut st = StatusTracker::default();
    let isv = IcaSignatureVerifier {};
    let ia_summary = IdentityAssertion::summarize_from_reader(&reader, &mut st, &isv).await;
    let ia_json = serde_json::to_string(&ia_summary).unwrap();

    assert_eq!(
        ia_json,
        r#"{"contentauth:urn:uuid:b2b1f7fa-b119-4de1-9c0d-c97fbea3f2c3":[],"urn:uuid:6aba7a19-9f59-44c1-8e1f-1fb396aa06f8":[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2025-04-09T22:46:13Z","verifiedIdentities":[{"type":"cawg.social_media","username":"testuser23","uri":"https://net.s2stagehance.com/testuser23","verifiedAt":"2025-04-09T22:45:26Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://cawg.io/identity/1.1/ica/schema/","type":"JSONSchema"}]}}]}"#
    );
}
