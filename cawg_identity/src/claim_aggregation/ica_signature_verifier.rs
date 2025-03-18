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
use c2pa_status_tracker::{log_current_item, StatusTracker};
use coset::{CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable};

use crate::{
    claim_aggregation::{
        w3c_vc::{
            did::Did,
            did_web,
            jwk::{Algorithm, Jwk, JwkError, Params},
        },
        IcaCredential, IcaValidationError,
    },
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
    type Error = IcaValidationError;
    type Output = IcaCredential;

    async fn check_signature(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<Self::Output, ValidationError<Self::Error>> {
        if signer_payload.sig_type != super::CAWG_ICA_SIG_TYPE {
            log_current_item!(
                "unsupported signature type",
                "X509SignatureVerifier::check_signature"
            )
            .validation_status("cawg.identity.sig_type.unknown")
            .failure_no_throw(
                status_tracker,
                ValidationError::<IcaValidationError>::UnknownSignatureType(
                    signer_payload.sig_type.clone(),
                ),
            );

            return Err(ValidationError::UnknownSignatureType(
                signer_payload.sig_type.clone(),
            ));
        }

        // The signature should be a `CoseSign1` object.
        let sign1 = CoseSign1::from_tagged_slice(signature)?;

        // Identify the signature.
        let _ssi_alg = if let Some(ref alg) = sign1.protected.header.alg {
            match alg {
                // TEMPORARY: Require EdDSA algorithm.
                RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA) => {
                    Algorithm::EdDsa
                }
                _ => {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::UnsupportedSignatureType(format!("{alg:?}")),
                    ));
                }
            }
        } else {
            return Err(ValidationError::SignatureError(
                IcaValidationError::SignatureTypeMissing,
            ));
        };

        if let Some(ref cty) = sign1.protected.header.content_type {
            match cty {
                coset::ContentType::Text(ref cty) => {
                    if cty != "application/vc" {
                        return Err(ValidationError::SignatureError(
                            IcaValidationError::UnsupportedContentType(format!("{cty:?}")),
                        ));
                    }
                }
                _ => {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::UnsupportedContentType(format!("{cty:?}")),
                    ));
                }
            }
        } else {
            return Err(ValidationError::SignatureError(
                IcaValidationError::ContentTypeMissing,
            ));
        }

        // Interpret the unprotected payload, which should be the raw VC.
        let Some(ref payload_bytes) = sign1.payload else {
            return Err(ValidationError::SignatureError(
                IcaValidationError::CredentialPayloadMissing,
            ));
        };

        let ica_credential: IcaCredential = serde_json::from_slice(payload_bytes)?;

        // Discover public key for issuer DID and validate signature.
        // TEMPORARY version supports did:jwk and did:web only.
        let issuer_id = Did::new(&ica_credential.issuer)?;
        let (primary_did, _fragment) = issuer_id.split_fragment();

        let jwk = match primary_did.method_name() {
            "jwk" => {
                let jwk = primary_did.method_specific_id();

                let jwk =
                    multibase::Base::decode(&multibase::Base::Base64Url, jwk).map_err(|e| {
                        ValidationError::SignatureError(IcaValidationError::UnsupportedIssuerDid(
                            e.to_string(),
                        ))
                    })?;

                let jwk: Jwk = serde_json::from_slice(&jwk).map_err(|e| {
                    ValidationError::SignatureError(IcaValidationError::UnsupportedIssuerDid(
                        e.to_string(),
                    ))
                })?;

                jwk
            }

            "web" => {
                let did_doc = did_web::resolve(&primary_did).await?;

                let Some(vm1) = did_doc.verification_relationships.assertion_method.first() else {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::UnsupportedIssuerDid(
                            "DID document doesn't contain an assertion_method entry".to_string(),
                        ),
                    ));
                };

                let super::w3c_vc::did_doc::ValueOrReference::Value(vm1) = vm1 else {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::UnsupportedIssuerDid(
                            "DID document's assertion_method is not a value".to_string(),
                        ),
                    ));
                };

                let Some(jwk_prop) = vm1.properties.get("publicKeyJwk") else {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::UnsupportedIssuerDid(
                            "DID document's assertion_method doesn't contain a publicKeyJwk entry"
                                .to_string(),
                        ),
                    ));
                };

                dbg!(&jwk_prop);

                // OMG SO HACKY!
                let Ok(jwk_json) = serde_json::to_string_pretty(jwk_prop) else {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::UnsupportedIssuerDid(
                            "couldn't re-serialize JWK".to_string(),
                        ),
                    ));
                };

                let Ok(jwk) = serde_json::from_str(&jwk_json) else {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::UnsupportedIssuerDid(
                            "couldn't re-serialize JWK".to_string(),
                        ),
                    ));
                };

                jwk
            }

            x => {
                return Err(ValidationError::SignatureError(
                    IcaValidationError::UnsupportedIssuerDid(format!("unsupported DID method {x}")),
                ));
            }
        };

        // TEMPORARY: only support ED25519.
        let Params::Okp(ref okp) = jwk.params;
        if okp.curve != "Ed25519" {
            return Err(ValidationError::SignatureError(
                IcaValidationError::UnsupportedIssuerDid(format!(
                    "unsupported OKP curve {}",
                    okp.curve
                )),
            ));
        }

        // Check the signature, which needs to have the same `aad` provided, by
        // providing a closure that can do the verify operation.
        sign1
            .verify_signature(b"", |sig, data| {
                use ed25519_dalek::Verifier;
                let public_key = ed25519_dalek::VerifyingKey::try_from(okp)?;
                let signature: ed25519_dalek::Signature = sig.try_into().map_err(JwkError::from)?;
                public_key.verify(data, &signature).map_err(JwkError::from)
            })
            .map_err(|_e| ValidationError::InvalidSignature)?;

        // Enforce [§8.1.1.4. Validity].
        //
        // [§8.1.1.4. Validity]: https://creator-assertions.github.io/identity/1.1-draft/#vc-property-validFrom
        let Some(_valid_from) = ica_credential.valid_from else {
            return Err(ValidationError::SignatureError(
                IcaValidationError::MissingValidFromDate,
            ));
        };

        // TO DO: Enforce signer_payload matches what was stated outside the signature.

        // TO DO: Enforce validity window as compared to sig time (or now if no TSA
        // time).

        // TO DO: Verify that signer_payload is same as c2paAsset.

        Ok(ica_credential)
    }
}
