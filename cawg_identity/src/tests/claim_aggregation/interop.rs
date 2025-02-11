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
use chrono::{DateTime, FixedOffset};
use iref::UriBuf;
use non_empty_string::NonEmptyString;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    claim_aggregation::{IcaSignatureVerifier, IdentityProvider, VerifiedIdentity},
    IdentityAssertion, SignerPayload,
};

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
async fn adobe_connected_identities() {
    let format = "image/jpeg";
    let test_image = include_bytes!("../fixtures/claim_aggregation/adobe_connected_identities.jpg");

    let mut test_image = Cursor::new(test_image);

    let manifest_store = Reader::from_stream(format, &mut test_image).unwrap();
    assert_eq!(manifest_store.validation_status(), None);

    let manifest = manifest_store.active_manifest().unwrap();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());

    // And that identity assertion should be valid for this manifest.
    let isv = IcaSignatureVerifier {};
    let ica = ia.validate(manifest, &isv).await.unwrap();

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
            sig_type: "cawg.identity_claims_aggregation".to_owned(),
        }
    );

    // Check the summary report for this manifest.
    let ia_summary = IdentityAssertion::summarize_all(&manifest, &isv).await;
    let ia_json = serde_json::to_string(&ia_summary).unwrap();

    assert_eq!(
        ia_json,
        r#"[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://creator-assertions.github.io/tbd/tbd"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2024-10-03T21:47:02Z","verifiedIdentities":[{"type":"cawg.social_media","username":"Robert Tiles","uri":"https://net.s2stagehance.com/roberttiles","verifiedAt":"2024-09-24T18:15:11Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://creator-assertions.github.io/schemas/v1/creator-identity-assertion.json","type":"JSONSchema"}]}}]"#
    );
}
