// Copyright 2026 Adobe. All rights reserved.
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

//! Tests for the verifiable credential binding (CAWG identity 1.3 draft
//! §8.3.5, “Validating an identity assertion with a verifiable credential
//! binding”).
//!
//! Each test signs `CA.jpg` with an identity assertion whose credential is
//! issued on the spot by an Ed25519 `did:jwk` issuer, optionally altered to
//! produce one failure, then reads it back and checks the `cawg.*` codes
//! reported for the identity assertion.

#![allow(clippy::unwrap_used)]

use std::io::{Cursor, Seek};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use c2pa_macros::c2pa_test_async;
use coset::{iana, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::{
    identity::{
        builder::{
            CredentialHolder, IdentityAssertionBuilder, IdentityAssertionSigner,
            IdentityBuilderError,
        },
        tests::{
            add_cawg_ica_issuers,
            fixtures::{manifest_json, parent_json},
        },
        vc_binding::CAWG_VCB_SIG_TYPE,
        SignerPayload,
    },
    settings::Settings,
    Builder, Context, Reader, SigningAlg,
};

const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

/// A fixed Ed25519 key for the test issuer.
fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// The `did:jwk` for [`issuer_key`].
fn issuer_did() -> String {
    let jwk = json!({
        "alg": "EdDSA",
        "kty": "OKP",
        "crv": "Ed25519",
        "x": BASE64_URL_SAFE_NO_PAD.encode(issuer_key().verifying_key().as_bytes()),
    });
    format!("did:jwk:{}", BASE64_URL_SAFE_NO_PAD.encode(jwk.to_string()))
}

/// A valid verifiable credential binding for `signer_payload`.
fn binding_credential(signer_payload: &SignerPayload) -> Value {
    let terms_of_use = crate::identity::vc_binding::terms_of_use_for(signer_payload).unwrap();

    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://cawg.io/identity/1.2/vcb/context/",
        ],
        "type": ["VerifiableCredential", "C2PABindingCredential", "CAWGVerifiedIdentities"],
        "issuer": issuer_did(),
        "validFrom": "2024-05-27T11:40:40Z",
        "credentialSubject": [
            {
                "id": "did:example:named-actor",
                "type": "cawg.social_media",
                "name": "Silly Cats 929",
                "username": "sillycats929",
                "uri": "https://example-social-network.com/sillycats929",
                "method": "cawg.federated_login",
                "provider": {
                    "id": "https://example-social-network.com",
                    "name": "Example Social Network",
                },
                "verifiedAt": "2024-05-27T08:40:39.569856Z",
            },
            {
                "id": "did:example:named-actor",
                "type": "cawg.web_site",
                "uri": "https://named-actor-site.example",
                "provider": { "name": "Example Domain Verifier" },
                "verifiedAt": "2024-09-25T22:13:35Z",
            },
        ],
        "termsOfUse": terms_of_use,
    })
}

type Tweak = Box<dyn Fn(&mut Value) + Send + Sync>;

/// Issues a verifiable credential binding for each signer payload it's asked
/// to sign, after applying `tweak` to the credential JSON.
struct TestVcbHolder {
    tweak: Tweak,
    content_type: &'static str,
    algorithm: iana::Algorithm,
    corrupt_signature: bool,
}

impl Default for TestVcbHolder {
    fn default() -> Self {
        Self {
            tweak: Box::new(|_| {}),
            content_type: "application/vc",
            algorithm: iana::Algorithm::EdDSA,
            corrupt_signature: false,
        }
    }
}

impl TestVcbHolder {
    fn tweak(tweak: impl Fn(&mut Value) + Send + Sync + 'static) -> Self {
        Self {
            tweak: Box::new(tweak),
            ..Default::default()
        }
    }
}

impl CredentialHolder for TestVcbHolder {
    fn sig_type(&self) -> &'static str {
        CAWG_VCB_SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        8192
    }

    fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        let mut credential = binding_credential(signer_payload);
        (self.tweak)(&mut credential);

        let key = issuer_key();
        let mut sign1 = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(self.algorithm)
                    .content_type(self.content_type.to_owned())
                    .build(),
            )
            .payload(credential.to_string().into_bytes())
            .create_signature(b"", |data| key.sign(data).to_bytes().to_vec())
            .build();

        if self.corrupt_signature {
            sign1.signature[0] ^= 0xff;
        }

        Ok(sign1.to_tagged_vec().unwrap())
    }
}

/// Signs `CA.jpg` with an identity assertion from `holder`.
fn sign_with(holder: TestVcbHolder) -> Cursor<Vec<u8>> {
    let format = "image/jpeg";
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());

    let mut builder = Builder::default().with_definition(manifest_json()).unwrap();
    builder
        .add_ingredient_from_stream(parent_json(), format, &mut source)
        .unwrap();
    builder
        .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
        .unwrap();

    let mut signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);
    signer.add_identity_assertion(IdentityAssertionBuilder::for_credential_holder(holder));

    builder
        .sign(&signer, format, &mut source, &mut dest)
        .unwrap();
    dest.rewind().unwrap();
    dest
}

/// Reads `asset` and returns the `cawg.*` status codes reported for its
/// identity assertion. `trusted` puts the test issuer on the trust list.
async fn cawg_codes(asset: &mut Cursor<Vec<u8>>, trusted: bool) -> Vec<String> {
    let mut settings = Settings::default();
    settings.core.decode_identity_assertions = true;
    if trusted {
        add_cawg_ica_issuers(&mut settings, &[&issuer_did()]);
    }
    let context = Context::new()
        .with_settings(settings)
        .unwrap()
        .into_shared();

    let reader = Reader::from_shared_context(&context)
        .with_stream_async("image/jpeg", asset)
        .await
        .unwrap();

    let results = reader.validation_results().unwrap();
    let active = results.active_manifest().unwrap();
    active
        .success()
        .iter()
        .chain(active.failure())
        .chain(active.informational())
        .filter(|s| s.code().starts_with("cawg."))
        .filter(|s| s.url().is_some_and(|u| u.ends_with("/cawg.identity")))
        .map(|s| s.code().to_string())
        .collect()
}

fn has(codes: &[String], code: &str) -> bool {
    codes.iter().any(|c| c == code)
}

/// The verifier reports `failure` and withholds `cawg.vcb.credential_valid`.
async fn assert_fails_with(holder: TestVcbHolder, failure: &str) {
    let mut asset = sign_with(holder);
    let codes = cawg_codes(&mut asset, true).await;
    assert!(has(&codes, failure), "expected {failure}: {codes:?}");
    assert!(!has(&codes, "cawg.vcb.credential_valid"), "{codes:?}");
}

#[c2pa_test_async]
async fn valid_binding_from_trusted_issuer() {
    let mut asset = sign_with(TestVcbHolder::default());
    let codes = cawg_codes(&mut asset, true).await;

    assert!(has(&codes, "cawg.vcb.credential_valid"), "{codes:?}");
    assert!(
        !codes
            .iter()
            .any(|c| c.starts_with("cawg.vcb.") && c != "cawg.vcb.credential_valid"),
        "{codes:?}"
    );
}

#[c2pa_test_async]
async fn decoded_assertion_carries_verified_identities() {
    let mut asset = sign_with(TestVcbHolder::default());

    let mut settings = Settings::default();
    settings.core.decode_identity_assertions = true;
    add_cawg_ica_issuers(&mut settings, &[&issuer_did()]);
    let context = Context::new()
        .with_settings(settings)
        .unwrap()
        .into_shared();
    let reader = Reader::from_shared_context(&context)
        .with_stream_async("image/jpeg", &mut asset)
        .await
        .unwrap();

    let json: Value = serde_json::from_str(&reader.json()).unwrap();
    let active = json["active_manifest"].as_str().unwrap();
    let identity = json["manifests"][active]["assertions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["label"] == "cawg.identity")
        .unwrap();

    let data = &identity["data"];
    assert_eq!(data["issuer"], issuer_did());
    assert_eq!(data["verifiedIdentities"][0]["username"], "sillycats929");
    assert_eq!(data["verifiedIdentities"][1]["type"], "cawg.web_site");
    assert_eq!(data["signer_payload"]["sig_type"], CAWG_VCB_SIG_TYPE);
}

#[c2pa_test_async]
async fn untrusted_issuer() {
    let mut asset = sign_with(TestVcbHolder::default());
    let codes = cawg_codes(&mut asset, false).await;

    assert!(has(&codes, "cawg.vcb.untrusted_issuer"), "{codes:?}");
    assert!(!has(&codes, "cawg.vcb.credential_valid"), "{codes:?}");
}

#[c2pa_test_async]
async fn unsupported_algorithm() {
    // The signature is still Ed25519; only the declared algorithm changes.
    assert_fails_with(
        TestVcbHolder {
            algorithm: iana::Algorithm::ES256,
            ..Default::default()
        },
        "cawg.vcb.invalid_alg",
    )
    .await;
}

#[c2pa_test_async]
async fn wrong_content_type() {
    assert_fails_with(
        TestVcbHolder {
            content_type: "application/json",
            ..Default::default()
        },
        "cawg.vcb.invalid_content_type",
    )
    .await;
}

#[c2pa_test_async]
async fn presentation_not_yet_supported() {
    assert_fails_with(
        TestVcbHolder {
            content_type: "application/vp",
            ..Default::default()
        },
        "cawg.vcb.invalid_verifiable_credential",
    )
    .await;
}

#[c2pa_test_async]
async fn missing_vcb_context() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| vc["@context"] = json!(["https://www.w3.org/ns/credentials/v2"])),
        "cawg.vcb.invalid_verifiable_credential",
    )
    .await;
}

#[c2pa_test_async]
async fn missing_binding_credential_type() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            vc["type"] = json!(["VerifiableCredential", "CAWGVerifiedIdentities"])
        }),
        "cawg.vcb.invalid_verifiable_credential",
    )
    .await;
}

#[c2pa_test_async]
async fn missing_asset_binding() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            vc.as_object_mut().unwrap().remove("termsOfUse");
        }),
        "cawg.vcb.invalid_verifiable_credential",
    )
    .await;
}

#[c2pa_test_async]
async fn unsupported_did_method() {
    // The issuer change also breaks the signature check, which is not reached.
    assert_fails_with(
        TestVcbHolder::tweak(|vc| vc["issuer"] = json!("did:example:issuer")),
        "cawg.vcb.did_unsupported_method",
    )
    .await;
}

#[c2pa_test_async]
async fn invalid_issuer() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| vc["issuer"] = json!("https://not-a-did.example")),
        "cawg.vcb.invalid_issuer",
    )
    .await;
}

#[c2pa_test_async]
async fn signature_mismatch() {
    assert_fails_with(
        TestVcbHolder {
            corrupt_signature: true,
            ..Default::default()
        },
        "cawg.vcb.signature_mismatch",
    )
    .await;
}

#[c2pa_test_async]
async fn valid_from_missing() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            vc.as_object_mut().unwrap().remove("validFrom");
        }),
        "cawg.vcb.valid_from.missing",
    )
    .await;
}

#[c2pa_test_async]
async fn valid_from_in_future() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| vc["validFrom"] = json!("2999-01-01T00:00:00Z")),
        "cawg.vcb.valid_from.invalid",
    )
    .await;
}

#[c2pa_test_async]
async fn valid_until_in_past() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| vc["validUntil"] = json!("2025-01-01T00:00:00Z")),
        "cawg.vcb.valid_until.invalid",
    )
    .await;
}

#[c2pa_test_async]
async fn credential_status_is_reported_unsupported() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            vc["credentialStatus"] = json!({
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "94567",
                "statusListCredential": "https://example.com/credentials/status/3",
            })
        }),
        "cawg.vcb.revocation.unsupported",
    )
    .await;
}

#[c2pa_test_async]
async fn snake_case_binding_does_not_match() {
    // The draft's examples use `referenced_assertions`; its normative text
    // requires lowerCamelCase, which is what this implementation follows.
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            let tou = vc["termsOfUse"].as_object_mut().unwrap();
            let ras = tou.remove("referencedAssertions").unwrap();
            tou.insert("referenced_assertions".to_owned(), ras);
        }),
        "cawg.vcb.signer_payload.mismatch",
    )
    .await;
}

#[c2pa_test_async]
async fn binding_for_other_assertions_does_not_match() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            vc["termsOfUse"]["referencedAssertions"][0]["hash"] =
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        }),
        "cawg.vcb.signer_payload.mismatch",
    )
    .await;
}

#[c2pa_test_async]
async fn conflicting_bindings() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            let tou = vc["termsOfUse"].clone();
            let mut other = tou.clone();
            other["note"] = json!("b");
            let mut first = tou;
            first["note"] = json!("a");
            vc["termsOfUse"] = json!([first, other]);
        }),
        "cawg.vcb.binding.mismatch",
    )
    .await;
}

#[c2pa_test_async]
async fn invalid_verified_identity() {
    // `cawg.social_media` requires `username`.
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            vc["credentialSubject"][0]
                .as_object_mut()
                .unwrap()
                .remove("username");
        }),
        "cawg.vcb.verified_identities.invalid",
    )
    .await;
}

#[c2pa_test_async]
async fn verified_identities_without_type() {
    assert_fails_with(
        TestVcbHolder::tweak(|vc| {
            vc["type"] = json!(["VerifiableCredential", "C2PABindingCredential"])
        }),
        "cawg.vcb.invalid_verifiable_credential",
    )
    .await;
}

#[c2pa_test_async]
async fn credential_without_verified_identities() {
    // A binding credential need not carry verified identities.
    let mut asset = sign_with(TestVcbHolder::tweak(|vc| {
        vc["type"] = json!(["VerifiableCredential", "C2PABindingCredential"]);
        vc["credentialSubject"] = json!({ "id": "did:example:named-actor" });
    }));
    let codes = cawg_codes(&mut asset, true).await;
    assert!(has(&codes, "cawg.vcb.credential_valid"), "{codes:?}");
}
