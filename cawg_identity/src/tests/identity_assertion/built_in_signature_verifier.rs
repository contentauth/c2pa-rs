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

use std::{
    io::{Cursor, Seek},
    str::FromStr,
};

use c2pa::{Builder, HashedUri, Reader, SigningAlg};
use c2pa_crypto::raw_signature;
use c2pa_status_tracker::StatusTracker;
use chrono::{DateTime, FixedOffset};
use iref::UriBuf;
use non_empty_string::NonEmptyString;

use crate::{
    builder::{
        AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner, IdentityAssertionBuilder,
        IdentityAssertionSigner,
    },
    claim_aggregation::{IdentityProvider, VerifiedIdentity},
    identity_assertion::built_in_signature_verifier::BuiltInCredential,
    tests::fixtures::{
        cert_chain_and_private_key_for_alg, default_built_in_signature_verifier, manifest_json,
        parent_json, NaiveCredentialHolder,
    },
    x509::AsyncX509CredentialHolder,
    IdentityAssertion, SignerPayload, ValidationError,
};

const TEST_IMAGE: &[u8] = include_bytes!("../../../../sdk/tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../../sdk/tests/fixtures/thumbnail.jpg");

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn x509_simple_case() {
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_json(&manifest_json()).unwrap();
    builder
        .add_ingredient_from_stream(parent_json(), format, &mut source)
        .unwrap();

    builder
        .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
        .unwrap();

    let mut c2pa_signer = AsyncIdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

    let (cawg_cert_chain, cawg_private_key) =
        cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

    let cawg_raw_signer = raw_signature::async_signer_from_cert_chain_and_private_key(
        &cawg_cert_chain,
        &cawg_private_key,
        SigningAlg::Ed25519,
        None,
    )
    .unwrap();

    let x509_holder = AsyncX509CredentialHolder::from_async_raw_signer(cawg_raw_signer);
    let iab = AsyncIdentityAssertionBuilder::for_credential_holder(x509_holder);
    c2pa_signer.add_identity_assertion(iab);

    builder
        .sign_async(&c2pa_signer, format, &mut source, &mut dest)
        .await
        .unwrap();

    // Read back the Manifest that was generated.
    dest.rewind().unwrap();

    let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
    assert_eq!(manifest_store.validation_status(), None);

    let manifest = manifest_store.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let verifier = default_built_in_signature_verifier();
    let sig_info = ia.validate(manifest, &mut st, &verifier).await.unwrap();

    let BuiltInCredential::X509Signature(sig_info) = sig_info else {
        panic!("Incorrect credential type returned");
    };

    let cert_info = &sig_info.cert_info;
    assert_eq!(cert_info.alg.unwrap(), SigningAlg::Ed25519);
    assert_eq!(
        cert_info.issuer_org.as_ref().unwrap(),
        "C2PA Test Signing Cert"
    );

    // TO DO: Not sure what to check from COSE_Sign1.
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test::wasm_bindgen_test
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
    let verifier = default_built_in_signature_verifier();
    let ica = ia.validate(manifest, &mut st, &verifier).await.unwrap();

    let BuiltInCredential::IdentityClaimsAggregationCredential(ica) = ica else {
        panic!("Incorrect credential type returned");
    };

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
    let ia_summary = IdentityAssertion::summarize_from_reader(&reader, &mut st, &verifier).await;
    let ia_json = serde_json::to_string(&ia_summary).unwrap();

    assert_eq!(
        ia_json,
        r#"{"urn:uuid:19e83793-4427-4161-b682-a53b975a6f72":[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2025-04-09T22:46:13Z","verifiedIdentities":[{"type":"cawg.social_media","username":"testuser23","uri":"https://net.s2stagehance.com/testuser23","verifiedAt":"2025-04-09T22:45:26Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://cawg.io/identity/1.1/ica/schema/","type":"JSONSchema"}]}}]}"#
    );

    // Check the summary report for this manifest.
    let mut st = StatusTracker::default();
    let ia_summary = IdentityAssertion::summarize_all(manifest, &mut st, &verifier).await;
    let ia_json = serde_json::to_string(&ia_summary).unwrap();

    assert_eq!(
        ia_json,
        r#"[{"sig_type":"cawg.identity_claims_aggregation","referenced_assertions":["c2pa.hash.data"],"named_actor":{"@context":["https://www.w3.org/ns/credentials/v2","https://cawg.io/identity/1.1/ica/context/"],"type":["VerifiableCredential","IdentityClaimsAggregationCredential"],"issuer":"did:web:connected-identities.identity-stage.adobe.com","validFrom":"2025-04-09T22:46:13Z","verifiedIdentities":[{"type":"cawg.social_media","username":"testuser23","uri":"https://net.s2stagehance.com/testuser23","verifiedAt":"2025-04-09T22:45:26Z","provider":{"id":"https://behance.net","name":"behance"}}],"credentialSchema":[{"id":"https://cawg.io/identity/1.1/ica/schema/","type":"JSONSchema"}]}}]"#
    );
}

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test::wasm_bindgen_test
)]
#[cfg_attr(target_os = "wasi", wstd::test)]
async fn err_naive_credential_holder() {
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::from_json(&manifest_json()).unwrap();
    builder
        .add_ingredient_from_stream(parent_json(), format, &mut source)
        .unwrap();

    builder
        .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
        .unwrap();

    let mut signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

    let nch = NaiveCredentialHolder {};
    let iab = IdentityAssertionBuilder::for_credential_holder(nch);
    signer.add_identity_assertion(iab);

    builder
        .sign(&signer, format, &mut source, &mut dest)
        .unwrap();

    // Read back the Manifest that was generated.
    dest.rewind().unwrap();

    let manifest_store = Reader::from_stream(format, &mut dest).unwrap();
    assert_eq!(manifest_store.validation_status(), None);

    let manifest = manifest_store.active_manifest().unwrap();
    let mut st = StatusTracker::default();
    let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

    // Should find exactly one identity assertion.
    let ia = ia_iter.next().unwrap().unwrap();
    assert!(ia_iter.next().is_none());
    drop(ia_iter);

    // And that identity assertion should be valid for this manifest.
    let verifier = default_built_in_signature_verifier();
    let err = ia.validate(manifest, &mut st, &verifier).await.unwrap_err();

    match err {
        ValidationError::UnknownSignatureType(sig_type) => {
            assert_eq!(sig_type, "INVALID.identity.naive_credential");
        }
        _ => {
            panic!("Unexpected error type: {err:?}");
        }
    }
}
