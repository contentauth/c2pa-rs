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

use std::{fs::OpenOptions, io::Cursor, str::FromStr};

use c2pa::{Manifest, ManifestStore};
use chrono::{DateTime, FixedOffset, Utc};
use coset::{CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use iref::UriBuf;
use non_empty_string::NonEmptyString;
use nonempty_collections::{nev, NEVec};
use thiserror::Error;

use crate::{
    builder::{CredentialHolder, IdentityAssertionBuilder, ManifestBuilder},
    claim_aggregation::{
        w3c_vc::{
            did::DidBuf,
            jwk::{Algorithm, Jwk, Params},
        },
        IdentityAssertionVc, IdentityClaimsAggregationVc, IdentityProvider, VcVerifiedIdentity,
    },
    tests::fixtures::{temp_c2pa_signer, temp_dir_path},
    IdentityAssertion, SignerPayload,
};

/// TO DO: Move what we can from this to more generic code in pub mod w3c_vc.
pub(super) struct TestIssuer {
    setup: TestSetup,
}

enum TestSetup {
    UserAndIssuerJwk(Jwk, Jwk),
    // Credential(Credential), // redo for ssi 0.8.0
}

#[async_trait::async_trait]
impl CredentialHolder for TestIssuer {
    fn sig_type(&self) -> &'static str {
        "cawg.identity_claims_aggregation"
    }

    fn reserve_size(&self) -> usize {
        10240 // 🤷🏻‍♂️
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>> {
        // TO DO: ERROR HANDLING
        match &self.setup {
            TestSetup::UserAndIssuerJwk(user_jwk, issuer_jwk) => {
                // WARNING: did:jwk is great for simple test cases such as this
                // but is strongly discouraged for production use cases. In other words,
                // please don't copy and paste this into your own implementation!

                let _user_did = generate_did_jwk_url(&user_jwk.to_public());
                let issuer_did = generate_did_jwk_url(&issuer_jwk.to_public());

                // Use the identities as shown in https://creator-assertions.github.io/identity/1.1-draft/#vc-credentialsubject-verifiedIdentities.

                let verified_identities: NEVec<VcVerifiedIdentity> = nev![
                    VcVerifiedIdentity {
                        type_: non_empty_str("cawg.document_verification"),
                        name: Some(non_empty_str("First-Name Last-Name")),
                        username: None,
                        address: None,
                        uri: None,
                        provider: IdentityProvider {
                            id: UriBuf::from_str("https://example-id-verifier.com").unwrap(),
                            name: non_empty_str("Example ID Verifier"),
                        },
                        verified_at: DateTime::<FixedOffset>::from_str("2024-07-26T22:30:15Z").unwrap(),
                    },
                    VcVerifiedIdentity {
                        type_: non_empty_str("cawg.affiliation"),
                        name: None,
                        username: None,
                        address: None,
                        uri: None,
                        provider: IdentityProvider {
                            id: UriBuf::from_str("https://example-affiliated-organization.com")
                                .unwrap(),
                            name: non_empty_str("Example Affiliated Organization"),
                        },
                        verified_at: DateTime::<FixedOffset>::from_str("2024-07-26T22:29:57Z").unwrap(),
                    },
                    VcVerifiedIdentity {
                        type_: non_empty_str("cawg.social_media"),
                        name: Some(non_empty_str("Silly Cats 929")),
                        username: Some(non_empty_str("username")),
                        address: None,
                        uri: Some(UriBuf::from_str("https://example-social-network.com/username").unwrap()),
                        provider: IdentityProvider {
                            id: UriBuf::from_str("https://example-social-network.com")
                                .unwrap(),
                            name: non_empty_str("Example Social Network"),
                        },
                        verified_at: DateTime::<FixedOffset>::from_str("2024-05-27T08:40:39.569856Z").unwrap(),
                    },
                    VcVerifiedIdentity {
                        type_: non_empty_str("cawg.crypto_wallet"),
                        name: None,
                        username: None,
                        address: Some(non_empty_str("fa64ef445f994138bdeb9baac6ce1e16")),
                        uri: Some(UriBuf::from_str("https://example-crypto-wallet.com/fa64ef445f994138bdeb9baac6ce1e16").unwrap()),
                        provider: IdentityProvider {
                            id: UriBuf::from_str("https://example-crypto-wallet.com")
                                .unwrap(),
                            name: non_empty_str("Example Crypto Wallet"),
                        },
                        verified_at: DateTime::<FixedOffset>::from_str("2024-05-27T08:40:39.569856Z").unwrap(),
                    }
                ];

                let cia = IdentityClaimsAggregationVc {
                    verified_identities,
                    c2pa_asset: signer_payload.clone(),
                };

                let subjects = NEVec::new(cia);

                let mut asset_vc = IdentityAssertionVc::new(None, issuer_did.into_uri(), subjects);

                asset_vc.valid_from = Some(Utc::now().into());

                Ok(sign_into_cose(&asset_vc, issuer_jwk).await.unwrap())
            }
        }
    }
}

impl TestIssuer {
    pub(super) fn new() -> Self {
        Self {
            setup: TestSetup::UserAndIssuerJwk(
                Jwk::generate_ed25519().unwrap(),
                Jwk::generate_ed25519().unwrap(),
            ),
        }
    }

    pub(super) fn from_asset_vc(_asset_vc_json: &str) -> Self {
        unimplemented!("Rebuild for ssi 0.8.0");
        /*
        let vc = Credential::from_json(asset_vc_json).unwrap();
        Self {
            setup: TestSetup::Credential(vc),
        }
        */
    }

    pub(super) async fn test_basic_case(self) {
        // TO DO: See if we can make this a non-consuming function.
        // Currently does so because IdentityAssertionBuilder takes
        // ownership of the CredentialHolder instance.

        // TO DO: Clean up code and extract into builder interface.
        // For now, just looking for a simple proof-of-concept.

        let cloud_jpg = include_bytes!("../fixtures/cloud.jpg");
        let mut input_stream = Cursor::new(cloud_jpg);

        let temp_dir = tempfile::tempdir().unwrap();
        let dest = temp_dir_path(&temp_dir, "cloud_output.jpg");

        let mut output_stream = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dest)
            .unwrap();

        // TO DO: Add a metadata assertion as an example.

        // Here we act as an identity claims aggregator.

        let iab = IdentityAssertionBuilder::for_credential_holder(self);

        let signer = temp_c2pa_signer();
        let mut mb = ManifestBuilder::default();
        mb.add_assertion(iab);

        let manifest: Manifest = Manifest::new("identity_test/simple_case");
        mb.build(
            manifest,
            "jpg",
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
        )
        .await
        .unwrap();

        // Here we act as an identity assertion consumer.

        let manifest_store = ManifestStore::from_file(&dest).unwrap();
        assert!(manifest_store.validation_status().is_none());

        let manifest = manifest_store.get_active().unwrap();
        let identity: IdentityAssertion = manifest.find_assertion("cawg.identity").unwrap();

        let _sp = identity.check_signer_payload(manifest).unwrap();
        identity.check_padding().unwrap();

        let report = identity.validate(manifest).await.unwrap();

        let sp = report.signer_payload;
        let ra = &sp.referenced_assertions;
        assert_eq!(ra.len(), 1);

        let ra1 = ra.first().unwrap();
        assert_eq!(ra1.url, "self#jumbf=c2pa.assertions/c2pa.hash.data");
        assert_eq!(ra1.alg, Some("sha256".to_owned()));

        assert_eq!(
            report.signer_payload.sig_type,
            "cawg.identity_claims_aggregation"
        );

        dbg!(&report.named_actor);

        for vi in report.named_actor.verified_identities() {
            dbg!(vi.type_());
        }
    }
}

fn non_empty_str(s: &str) -> NonEmptyString {
    NonEmptyString::try_from(s).unwrap()
}

// TEMPORARY home for this while we figure out new signing interface

pub(crate) async fn sign_into_cose(
    vc: &IdentityAssertionVc,
    signer: &Jwk,
) -> Result<Vec<u8>, TbdError> {
    let payload_bytes = serde_json::to_vec(vc).unwrap();

    let coset_alg = match signer.get_algorithm().unwrap() {
        Algorithm::EdDsa => coset::iana::Algorithm::EdDSA,
        ssi_alg => {
            unimplemented!("Add support for SSI alg {ssi_alg:?}")
        }
    };

    let mut protected = HeaderBuilder::new()
        .algorithm(coset_alg)
        .content_type("application/vc".to_owned())
        .build();

    if let Some(key_id) = signer.key_id.clone() {
        protected.key_id = key_id.as_bytes().to_vec();
    }

    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes.to_vec())
        .create_signature(b"", |pt| sign_bytes(signer, pt))
        .build();

    // TO DO (#27): Remove panic.
    #[allow(clippy::unwrap_used)]
    Ok(sign1.to_tagged_vec().unwrap())
}

// TEMPORARY error struct while we sort out new signing interface
// This is here mostly to remind us that upstream code will need to handle
// errors.
#[derive(Debug, Error)]
pub(crate) enum TbdError {
    #[allow(dead_code)]
    #[error("Something went wrong")]
    SomethingWentWrong,
}

fn sign_bytes(signer: &Jwk, payload: &[u8]) -> Vec<u8> {
    // Q&D implementation of Ed25519 signing for now.
    // TO DO: Configurable signing for general cases.

    // TO DO (#27): Remove unwraps.
    #[allow(clippy::unwrap_used)]
    let algorithm = signer.get_algorithm().unwrap();
    match algorithm {
        Algorithm::EdDsa => match &signer.params {
            Params::Okp(okp) => {
                let secret = ed25519_dalek::SigningKey::try_from(okp).unwrap();
                use ed25519_dalek::Signer;
                secret.sign(payload).to_bytes().to_vec()
            } // _ => unimplemented!("only JWKParams::OKP is supported for now"),
        },
        _ => unimplemented!("signing algorithm not yet supported"),
    }
}

fn generate_did_jwk_url(key: &Jwk) -> DidBuf {
    let key = key.to_public();
    let normalized = serde_json::to_string(&key).unwrap();
    let method_id = multibase::Base::Base64Url.encode(normalized);
    DidBuf::new(format!("did:jwk:{method_id}#0")).unwrap()
}
