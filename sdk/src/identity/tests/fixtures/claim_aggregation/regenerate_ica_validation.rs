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

//! Regenerates the `ica_validation/*.jpg` identity claims aggregation test
//! fixtures used by `identity::tests::claim_aggregation::validation`.
//!
//! Each fixture is the standard test asset with one ICA identity assertion
//! whose credential uses [`ica_example_identities`] and is signed with the
//! Ed25519 test key as the `did:jwk` issuer [`ICA_FIXTURE_JWK_ISSUER`], except
//! for the single defect the fixture is named after. The COSE envelope is
//! built here (rather than with `crypto::cose::sign`) so that each variant can
//! change exactly one header or field.
//!
//! The time-stamp fixtures need network access to an RFC 3161 service
//! (`http://timestamp.digicert.com`), as the original fixtures did. Run with:
//!
//! ```text
//! cargo test -p c2pa --lib regenerate_ica_validation_fixtures -- --ignored --nocapture
//! ```
//!
//! Set `ICA_FIXTURE=<name>` (for example `signature_mismatch`) to regenerate a
//! single fixture. Afterwards, update the manifest labels that the tests in
//! `tests/claim_aggregation/validation.rs` expect (printed for each fixture).

use std::io::Cursor;

use async_trait::async_trait;
use c2pa_raw_crypto::{signer_from_private_key, RawSigner, RawSignerError};
use chrono::{NaiveDate, TimeDelta, Utc};
use coset::{
    iana::{self, CoapContentFormat, EnumI64},
    CoseSign1Builder, HeaderBuilder, ProtectedHeader, RegisteredLabel, TaggedCborSerializable,
};
use iref::UriBuf;
use nonempty_collections::nev;

use super::ica_credential_example::ica_example_identities;
use crate::{
    crypto::{
        cert_chain_pem_to_der,
        cose::{add_sigtst_header, CoseSigner, TimeStampStorage},
        time_stamp::{default_rfc3161_request, TimeStampError, TimeStampProvider},
    },
    identity::{
        builder::{
            AsyncCredentialHolder, AsyncIdentityAssertionBuilder, AsyncIdentityAssertionSigner,
            IdentityBuilderError,
        },
        claim_aggregation::{IcaCredential, IdentityClaimsAggregationVc, CAWG_ICA_SIG_TYPE},
        tests::{
            fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
            ICA_FIXTURE_JWK_ISSUER,
        },
        SignerPayload,
    },
    Builder, Context, HashedUri, Reader, SigningAlg,
};

const TEST_IMAGE: &[u8] = include_bytes!("../../../../../tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../../../tests/fixtures/thumbnail.jpg");
const TSA_URL: &str = "http://timestamp.digicert.com";
const OUT_DIR: &str = "src/identity/tests/fixtures/claim_aggregation/ica_validation";

/// The single defect (or valid variation) each fixture carries.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Variant {
    Success,
    InvalidCoseSign1,
    InvalidCoseSignAlg,
    MissingCoseSignAlg,
    InvalidContentType,
    MissingContentType,
    InvalidContentTypeAssigned,
    InvalidVc,
    MissingVc,
    InvalidIssuerDid,
    UnsupportedDidMethod,
    UnresolvableDid,
    DidDocWithoutAssertionMethod,
    SignatureMismatch,
    ValidTimeStamp,
    InvalidTimeStamp,
    ValidFromMissing,
    ValidFromInFuture,
    ValidFromAfterTimeStamp,
    ValidUntilInFuture,
    ValidUntilInPast,
    SignerPayloadMismatch,
    CryptoWalletMissingAddress,
}

impl Variant {
    const ALL: [(Variant, &'static str); 23] = [
        (Variant::Success, "success"),
        (Variant::InvalidCoseSign1, "invalid_cose_sign1"),
        (Variant::InvalidCoseSignAlg, "invalid_cose_sign_alg"),
        (Variant::MissingCoseSignAlg, "missing_cose_sign_alg"),
        (Variant::InvalidContentType, "invalid_content_type"),
        (Variant::MissingContentType, "missing_content_type"),
        (
            Variant::InvalidContentTypeAssigned,
            "invalid_content_type_assigned",
        ),
        (Variant::InvalidVc, "invalid_vc"),
        (Variant::MissingVc, "missing_vc"),
        (Variant::InvalidIssuerDid, "invalid_issuer_did"),
        (Variant::UnsupportedDidMethod, "unsupported_did_method"),
        (Variant::UnresolvableDid, "unresolvable_did"),
        (
            Variant::DidDocWithoutAssertionMethod,
            "did_doc_without_assertion_method",
        ),
        (Variant::SignatureMismatch, "signature_mismatch"),
        (Variant::ValidTimeStamp, "valid_time_stamp"),
        (Variant::InvalidTimeStamp, "invalid_time_stamp"),
        (Variant::ValidFromMissing, "valid_from_missing"),
        (Variant::ValidFromInFuture, "valid_from_in_future"),
        (
            Variant::ValidFromAfterTimeStamp,
            "valid_from_after_time_stamp",
        ),
        (Variant::ValidUntilInFuture, "valid_until_in_future"),
        (Variant::ValidUntilInPast, "valid_until_in_past"),
        (Variant::SignerPayloadMismatch, "signer_payload_mismatch"),
        (
            Variant::CryptoWalletMissingAddress,
            "crypto_wallet_missing_address",
        ),
    ];

    fn issuer(self) -> String {
        // The method-specific part of the did:jwk issuer (the encoded JWK).
        let jwk = ICA_FIXTURE_JWK_ISSUER.trim_start_matches("did:jwk:");
        match self {
            Variant::InvalidIssuerDid => format!("not-did:jwk:{jwk}"),
            Variant::UnsupportedDidMethod => format!("did:example:{jwk}"),
            Variant::UnresolvableDid => {
                "did:web:cawg-test-data.github.io:test-case:unresolvable-did".to_owned()
            }
            Variant::DidDocWithoutAssertionMethod => {
                "did:web:cawg-test-data.github.io:test-case:no-assertion-method".to_owned()
            }
            _ => ICA_FIXTURE_JWK_ISSUER.to_owned(),
        }
    }

    fn time_stamped(self) -> bool {
        matches!(
            self,
            Variant::ValidTimeStamp | Variant::InvalidTimeStamp | Variant::ValidFromAfterTimeStamp
        )
    }
}

/// Signs with the Ed25519 test key; also acts as the time-stamp provider for
/// time-stamped variants.
struct FixtureCoseSigner {
    signer: Box<dyn RawSigner + Send + Sync>,
    cert_chain: Vec<Vec<u8>>,
    variant: Variant,
}

impl TimeStampProvider for FixtureCoseSigner {
    fn time_stamp_service_url(&self) -> Option<String> {
        self.variant.time_stamped().then(|| TSA_URL.to_owned())
    }

    fn send_time_stamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>, TimeStampError>> {
        let url = self.time_stamp_service_url()?;
        let mut message = message.to_vec();
        if self.variant == Variant::InvalidTimeStamp {
            // Time-stamp different bytes, so the token's message imprint doesn't
            // match the signature it is attached to.
            message[0] = 42;
            message[4] = 98;
        }
        let body = match self.time_stamp_request_body(&message) {
            Ok(body) => body,
            Err(e) => return Some(Err(e)),
        };
        Some(default_rfc3161_request(
            &url,
            None,
            &body,
            &message,
            &Context::new(),
        ))
    }
}

impl CoseSigner for FixtureCoseSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError> {
        self.signer.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.signer.alg()
    }

    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError> {
        Ok(self.cert_chain.clone())
    }
}

struct IcaFixtureHolder {
    cose_signer: FixtureCoseSigner,
}

impl IcaFixtureHolder {
    fn new(variant: Variant) -> Self {
        let (chain, key) = cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);
        Self {
            cose_signer: FixtureCoseSigner {
                signer: signer_from_private_key(&key, SigningAlg::Ed25519).unwrap(),
                cert_chain: cert_chain_pem_to_der(&chain).unwrap(),
                variant,
            },
        }
    }

    fn variant(&self) -> Variant {
        self.cose_signer.variant
    }

    fn credential_json(&self, signer_payload: &SignerPayload) -> String {
        let variant = self.variant();

        // ICA §8.1.2: c2paAsset is signer_payload with hashes as base64 strings.
        let mut c2pa_asset = signer_payload.clone();
        if variant == Variant::SignerPayloadMismatch {
            let r = c2pa_asset.referenced_assertions[0].clone();
            let mut wrong_hash = r.hash();
            wrong_hash[0] = 42;
            wrong_hash[4] = 98;
            c2pa_asset.referenced_assertions[0] = HashedUri::new(r.url(), r.alg(), &wrong_hash);
        }
        c2pa_asset.referenced_assertions = c2pa_asset
            .referenced_assertions
            .iter()
            .map(|a| {
                let encoded = crate::crypto::base64::encode(&a.hash());
                HashedUri::new(a.url(), a.alg(), encoded.as_bytes())
            })
            .collect();

        let mut verified_identities = ica_example_identities();
        if variant == Variant::CryptoWalletMissingAddress {
            // The CAWG specification's original example: `username` instead of
            // the `address` that §8.1.2.5 requires for `cawg.crypto_wallet`.
            for identity in verified_identities.iter_mut() {
                if identity.type_.as_str() == "cawg.crypto_wallet" {
                    identity.address = None;
                    identity.username =
                        Some(non_empty_string::NonEmptyString::new("username".to_owned()).unwrap());
                }
            }
        }
        let subject = IdentityClaimsAggregationVc {
            c2pa_asset,
            verified_identities,
            time_stamp: None,
        };
        let issuer = UriBuf::new(variant.issuer().into_bytes()).unwrap();
        let mut vc = IcaCredential::new(None, issuer, nev![subject]);

        let far_future = NaiveDate::from_ymd_opt(2200, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc()
            .fixed_offset();
        let far_past = NaiveDate::from_ymd_opt(1900, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc()
            .fixed_offset();
        vc.valid_from = match variant {
            Variant::ValidFromMissing => None,
            Variant::ValidFromInFuture => Some(far_future),
            Variant::ValidFromAfterTimeStamp => {
                Some(Utc::now().fixed_offset() + TimeDelta::new(60, 0).unwrap())
            }
            _ => Some(Utc::now().fixed_offset()),
        };
        vc.valid_until = match variant {
            Variant::ValidUntilInFuture => Some(far_future),
            Variant::ValidUntilInPast => Some(far_past),
            _ => None,
        };

        let json = serde_json::to_string(&vc).unwrap();
        if variant == Variant::InvalidVc {
            json.replace("{\"", "xxx")
        } else {
            json
        }
    }
}

#[async_trait]
impl AsyncCredentialHolder for IcaFixtureHolder {
    fn sig_type(&self) -> &'static str {
        CAWG_ICA_SIG_TYPE
    }

    fn reserve_size(&self) -> usize {
        // Credential JSON, certificate chain and (possibly) an RFC 3161 token.
        20_000
    }

    async fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError> {
        let variant = self.variant();
        let payload = self.credential_json(signer_payload).into_bytes();

        if variant == Variant::ValidTimeStamp {
            // Make sure the time stamp follows validFrom.
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        let mut protected = match variant {
            Variant::InvalidCoseSignAlg => HeaderBuilder::new().algorithm(iana::Algorithm::SHA_1),
            Variant::MissingCoseSignAlg => HeaderBuilder::new(),
            _ => HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA),
        };
        protected = protected.value(
            iana::HeaderParameter::X5Chain.to_i64(),
            coset::cbor::value::Value::Bytes(self.cose_signer.cert_chain[0].clone()),
        );
        protected = match variant {
            Variant::InvalidContentType => protected.content_type("application/bogus".to_owned()),
            Variant::MissingContentType => protected,
            Variant::InvalidContentTypeAssigned => {
                protected.content_format(CoapContentFormat::OctetStream)
            }
            _ => protected.content_type("application/vc".to_owned()),
        };
        let protected = protected.build();
        let p_header = ProtectedHeader {
            original_data: None,
            header: protected.clone(),
        };

        let mut sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload.clone())
            .create_signature(b"", |data| self.cose_signer.sign(data).unwrap())
            .build();

        // `sigTst2` (C2PA "v2" countersignature time stamp): the time stamp
        // covers the CBOR-encoded signature, as in `crypto::cose::sign_v2`.
        let mut signature_cbor: Vec<u8> = vec![];
        coset::cbor::into_writer(
            &serde_bytes::ByteBuf::from(sign1.signature.clone()),
            &mut signature_cbor,
        )
        .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))?;
        sign1.unprotected = add_sigtst_header(
            &self.cose_signer,
            &signature_cbor,
            &p_header,
            HeaderBuilder::new(),
            TimeStampStorage::V2_sigTst2_CTT,
        )
        .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))?
        .build();

        match variant {
            Variant::MissingVc => sign1.payload = None,
            Variant::SignatureMismatch => {
                // Same JSON content, different bytes: the credential still
                // parses, but the signature no longer verifies.
                let mut different_bytes = b"{ ".to_vec();
                different_bytes.extend_from_slice(&payload[1..]);
                sign1.payload = Some(different_bytes);
            }
            _ => {}
        }

        let mut bytes = sign1
            .to_tagged_vec()
            .map_err(|e| IdentityBuilderError::SignerError(e.to_string()))?;
        if variant == Variant::InvalidCoseSign1 {
            bytes[0] = 42;
        }
        Ok(bytes)
    }
}

#[tokio::test]
#[ignore = "regenerates ica_validation fixtures (needs network for time stamps); run explicitly"]
async fn regenerate_ica_validation_fixtures() {
    std::fs::create_dir_all(OUT_DIR).unwrap();

    let only = std::env::var("ICA_FIXTURE").ok();

    for (variant, name) in Variant::ALL {
        if only.as_deref().is_some_and(|only| only != name) {
            continue;
        }
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

        let mut signer = AsyncIdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);
        signer.add_identity_assertion(AsyncIdentityAssertionBuilder::for_credential_holder(
            IcaFixtureHolder::new(variant),
        ));
        builder
            .sign_async(&signer, format, &mut source, &mut dest)
            .await
            .unwrap();

        let path = format!("{OUT_DIR}/{name}.jpg");
        std::fs::write(&path, dest.get_ref()).unwrap();

        dest.set_position(0);
        let reader = crate::identity::tests::read_manifest(format, &mut dest).await;
        println!("{name}: {}", reader.active_label().unwrap());
    }
}
