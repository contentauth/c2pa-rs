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

use async_trait::async_trait;
use coset::{CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable};

use super::w3c_vc::{
    did::Did,
    did_web,
    jwk::{Jwk, JwkError, Params},
};
use crate::{
    claim_aggregation::{w3c_vc::jwk::Algorithm, IcaCredential},
    SignatureVerifier, SignerPayload, ValidationError,
};

/// An implementation of [`SignatureVerifier`] that supports Identity Claims
/// Aggregation Credentials (a specific grammar of W3C Verifiable Credentials)
/// as specified in [§8.1, Identity claims aggregation] and secured by COSE as
/// specified in [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE] of
/// _Securing Verifiable Credentials using JOSE and COSE._
///
/// [`SignatureVerifier`]: crate::SignatureVerifier
/// [§8.1, Identity claims aggregation]: https://creator-assertions.github.io/identity/1.1-draft/#_identity_claims_aggregation
/// [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE]: https://w3c.github.io/vc-jose-cose/#securing-vcs-with-cose
pub struct IcaSignatureVerifier {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureVerifier for IcaSignatureVerifier {
    type Error = ();
    type Output = IcaCredential;

    async fn check_signature(
        &self,
        _signer_payload: &SignerPayload,
        signature: &[u8],
    ) -> Result<Self::Output, ValidationError<Self::Error>> {
        // At the receiving end, deserialize the bytes back to a `CoseSign1` object.

        // TO DO (#27): Remove unwrap.
        #[allow(clippy::unwrap_used)]
        let sign1 = CoseSign1::from_tagged_slice(signature).unwrap();

        // TEMPORARY: Require EdDSA algorithm.

        // TO DO (#27): Remove panic.
        #[allow(clippy::panic)]
        let _ssi_alg = if let Some(ref alg) = sign1.protected.header.alg {
            match alg {
                RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA) => {
                    Algorithm::EdDsa
                }
                _ => {
                    panic!("TO DO: Add suport for signing alg {alg:?}");
                }
            }
        } else {
            panic!("ERROR: COSE protected headers do not contain a signing algorithm");
        };

        // TO DO (#27): Remove panic.
        #[allow(clippy::panic)]
        if let Some(ref cty) = sign1.protected.header.content_type {
            match cty {
                coset::ContentType::Text(ref cty) => {
                    if cty != "application/vc" {
                        panic!("ERROR: COSE content type is unsupported {cty:?}");
                    }
                }
                _ => {
                    panic!("ERROR: COSE content type is unsupported {cty:?}");
                }
            }
        } else {
            panic!("ERROR: COSE protected headers do not contain required content type header");
        }

        // Interpret the unprotected payload, which should be the raw VC.

        // TO DO (#27): Remove panic.
        #[allow(clippy::panic)]
        let Some(ref payload_bytes) = sign1.payload
        else {
            panic!("ERROR: COSE Sign1 data structure has no payload");
        };

        // TO DO (#27): Remove panic.
        #[allow(clippy::expect_used)]
        let ica_credential: IcaCredential = serde_json::from_slice(payload_bytes)
            .expect("ERROR: can't decode VC as IdentityAssertionVc");

        // Discover public key for issuer DID and validate signature.
        // TEMPORARY version supports did:jwk and did:web only.

        // TO DO (#27): Remove panic.
        #[allow(clippy::unwrap_used)]
        let issuer_id = Did::new(&ica_credential.issuer).unwrap();
        let (primary_did, _fragment) = issuer_id.split_fragment();

        // TO DO (#27): Remove panic.
        #[allow(clippy::unwrap_used)]
        #[allow(clippy::panic)]
        let jwk = match primary_did.method_name() {
            "jwk" => {
                let jwk = primary_did.method_specific_id();
                let jwk = multibase::Base::decode(&multibase::Base::Base64Url, jwk).unwrap();
                let jwk: Jwk = serde_json::from_slice(&jwk).unwrap();
                jwk
            }
            "web" => {
                #[allow(clippy::expect_used)]
                let did_doc = did_web::resolve(&primary_did).await.expect("No output");

                let vm1 = did_doc
                    .verification_relationships
                    .assertion_method
                    .first()
                    .unwrap();

                let super::w3c_vc::did_doc::ValueOrReference::Value(vm1) = vm1 else {
                    panic!("not value");
                };
                let jwk_prop = vm1.properties.get("publicKeyJwk").unwrap();
                dbg!(&jwk_prop);

                // OMG SO HACKY!
                let jwk_json = serde_json::to_string_pretty(jwk_prop).unwrap();
                dbg!(&jwk_json);

                let jwk: Jwk = serde_json::from_str(&jwk_json).unwrap();
                dbg!(&jwk);

                jwk
            }
            x => {
                panic!("Unsupported DID method {x:?}");
            }
        };

        // TEMPORARY only support ED25519.
        // TO DO (#27): Remove panic.
        #[allow(clippy::panic)]
        let Params::Okp(ref okp) = jwk.params;
        // else {
        //     panic!("Temporarily unsupported params type");
        // };
        assert_eq!(okp.curve, "Ed25519");

        // Check the signature, which needs to have the same `aad` provided, by
        // providing a closure that can do the verify operation.
        // TO DO (#27): Remove panic.
        #[allow(clippy::unwrap_used)]
        sign1
            .verify_signature(b"", |sig, data| {
                use ed25519_dalek::Verifier;
                let public_key = ed25519_dalek::VerifyingKey::try_from(okp)?;
                let signature: ed25519_dalek::Signature = sig.try_into().map_err(JwkError::from)?;
                public_key.verify(data, &signature).map_err(JwkError::from)
            })
            .unwrap();

        // Enforce [§8.1.1.4. Validity].
        //
        // [§8.1.1.4. Validity]: https://creator-assertions.github.io/identity/1.1-draft/#vc-property-validFrom

        // TO DO (#27): Remove panic.
        assert!(ica_credential.valid_from.is_some());
        // TO DO: Enforce validity window as compared to sig time (or now if no TSA
        // time).

        // TO DO: Verify that signer_payload is same as c2paAsset.

        Ok(ica_credential)
    }
}
