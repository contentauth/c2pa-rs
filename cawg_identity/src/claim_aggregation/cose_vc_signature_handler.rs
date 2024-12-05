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

use std::fmt::{Debug, Formatter};

use async_trait::async_trait;
use coset::{CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable};
use nonempty_collections::{vector::Iter, NEVec, NonEmptyIterator};

use crate::{
    claim_aggregation::{
        w3c_vc::{
            did::Did,
            did_web,
            jwk::{Algorithm, Jwk, JwkError, Params},
        },
        IdentityAssertionVc, VcVerifiedIdentity,
    },
    identity_assertion::VerifiedIdentities,
    NamedActor, SignatureHandler, SignerPayload, ValidationResult, VerifiedIdentity,
};

/// An implementation of [`SignatureHandler`] that supports Identity Claims
/// Aggregation Credentials (a specific grammar of W3C Verifiable Credentials)
/// as specified in [§8.1, Identity claims aggregation] and secured by COSE as
/// specified in [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE] of
/// _Securing Verifiable Credentials using JOSE and COSE._
///
/// [`SignatureHandler`]: crate::SignatureHandler
/// [§8.1, Identity claims aggregation]: https://creator-assertions.github.io/identity/1.1-draft/#_identity_claims_aggregation
/// [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE]: https://w3c.github.io/vc-jose-cose/#securing-vcs-with-cose
pub struct CoseVcSignatureHandler {}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureHandler for CoseVcSignatureHandler {
    fn can_handle_sig_type(sig_type: &str) -> bool {
        sig_type == "cawg.identity_claims_aggregation"
    }

    async fn check_signature<'a>(
        &self,
        _signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn NamedActor<'a>>> {
        // TEMPORARY implementation. Hopefully to be replaced by more robust code in
        // `ssi` crate soon.

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
        let asset_vc: IdentityAssertionVc = serde_json::from_slice(payload_bytes)
            .expect("ERROR: can't decode VC as IdentityAssertionVc");

        // Discover public key for issuer DID and validate signature.
        // TEMPORARY version supports did:jwk and did:web only.

        // TO DO (#27): Remove panic.
        #[allow(clippy::unwrap_used)]
        let issuer_id = Did::new(&asset_vc.issuer).unwrap();
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
        assert!(asset_vc.valid_from.is_some());
        // TO DO: Check if ssi crate enforces valid_from < now.
        // Also check if ssi enforces expiration date.

        // TO DO: Verify that signer_payload is same as c2paAsset.

        Ok(Box::new(VcNamedActor(asset_vc)))
    }
}

/// An implementation of [`NamedActor`] that describes the subject of an
/// Identity Claims Aggregation credential.
///
/// [`NamedActor`]: crate::NamedActor
pub struct VcNamedActor(IdentityAssertionVc);

impl<'a> NamedActor<'a> for VcNamedActor {
    fn display_name(&self) -> Option<String> {
        // TO DO: Extract this from VC
        None
    }

    fn is_trusted(&self) -> bool {
        false
        // todo!("Is this on trust list?");
    }

    fn verified_identities(&self) -> VerifiedIdentities {
        let subject = self.0.credential_subjects.first();
        Box::new(VcVerifiedIdentities::new(&subject.verified_identities))
    }
}

impl Debug for VcNamedActor {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let display_name = if let Some(dn) = self.display_name() {
            dn
        } else {
            "(none)".to_owned()
        };

        f.debug_struct("VcNamedActor")
            .field("display_name", &display_name)
            .field("(credential)", &self.0)
            .finish()
    }
}

struct VcVerifiedIdentities<'a>(Iter<'a, VcVerifiedIdentity>);

impl<'a> VcVerifiedIdentities<'a> {
    fn new(verified_identities: &'a NEVec<VcVerifiedIdentity>) -> Self {
        Self(verified_identities.iter())
    }
}

impl<'a> Iterator for VcVerifiedIdentities<'a> {
    type Item = Box<&'a dyn VerifiedIdentity>;

    fn next(&mut self) -> Option<Box<&'a dyn VerifiedIdentity>> {
        self.0
            .next()
            .map(|vc_vi| Box::<&'a (dyn VerifiedIdentity + 'a)>::new(vc_vi))
    }
}
