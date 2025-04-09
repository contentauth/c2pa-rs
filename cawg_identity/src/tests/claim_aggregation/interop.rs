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
            username: Some(NonEmptyString::new("Robert Tiles".to_string(),).unwrap(),),
            address: None,
            uri: Some(UriBuf::from_str("https://net.s2stagehance.com/roberttiles").unwrap(),),
            verified_at: DateTime::<FixedOffset>::parse_from_rfc3339("2024-09-24T18:15:11+00:00")
                .unwrap(),
            provider: IdentityProvider {
                id: UriBuf::from_str("https://behance.net").unwrap(),
                name: NonEmptyString::new("behance".to_string(),).unwrap(),
            },
        }
    );

    assert_eq!(
        ica_vc.c2pa_asset,
        SignerPayload {
            referenced_assertions: vec![HashedUri::new(
                "self#jumbf=c2pa.assertions/c2pa.hash.data".to_owned(),
                None,
                &hex_literal::hex!("58514c7072376d453164794f783477317a716e4f63716159325a594d686a5031526c7a552f7877614259383d")
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
        r#"{"urn:uuid:b55062ef-96b6-4f6e-bb7d-9c415f130471":[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2024-10-03T21:47:02Z","verifiedIdentities":[{"type":"cawg.social_media","username":"Robert Tiles","uri":"https://net.s2stagehance.com/roberttiles","verifiedAt":"2024-09-24T18:15:11Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://creator-assertions.github.io/schemas/v1/creator-identity-assertion.json","type":"JSONSchema"}]}}]}"#
    );

    // Check the summary report for this manifest.
    let mut st = StatusTracker::default();
    let ia_summary = IdentityAssertion::summarize_all(manifest, &mut st, &isv).await;
    let ia_json = serde_json::to_string(&ia_summary).unwrap();

    assert_eq!(
        ia_json,
        r#"[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2024-10-03T21:47:02Z","verifiedIdentities":[{"type":"cawg.social_media","username":"Robert Tiles","uri":"https://net.s2stagehance.com/roberttiles","verifiedAt":"2024-09-24T18:15:11Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://creator-assertions.github.io/schemas/v1/creator-identity-assertion.json","type":"JSONSchema"}]}}]"#
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
        r#"{"urn:uuid:7256ca36-2a90-44ec-914d-f17c8d70c31f":[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2025-02-13T00:40:47Z","verifiedIdentities":[{"type":"cawg.social_media","username":"firstlast555","uri":"https://net.s2stagehance.com/firstlast555","verifiedAt":"2025-01-10T19:53:59Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://cawg.io/schemas/v1/creator-identity-assertion.json","type":"JSONSchema"}]}}],"urn:uuid:b55062ef-96b6-4f6e-bb7d-9c415f130471":[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2024-10-03T21:47:02Z","verifiedIdentities":[{"type":"cawg.social_media","username":"Robert Tiles","uri":"https://net.s2stagehance.com/roberttiles","verifiedAt":"2024-09-24T18:15:11Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://creator-assertions.github.io/schemas/v1/creator-identity-assertion.json","type":"JSONSchema"}]}}]}"#
    );
}
