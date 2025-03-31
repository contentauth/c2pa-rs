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
use c2pa::HashedUri;
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
        let mut ok = true;

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
        let sign1 = CoseSign1::from_tagged_slice(signature).inspect_err(|err| {
            log_current_item!(
                "Invalid COSE_Sign1 data structure",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.invalid_cose_sign1")
            .failure_no_throw(status_tracker, ValidationError::from(err));
        })?;

        // Identify the signature.
        let _ssi_alg = if let Some(ref alg) = sign1.protected.header.alg {
            match alg {
                // TO DO (CAI-7965): Support algorithms other than EdDSA.
                RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA) => {
                    Algorithm::EdDsa
                }
                _ => {
                    let err = ValidationError::SignatureError(
                        IcaValidationError::UnsupportedSignatureType(format!("{alg:?}")),
                    );

                    log_current_item!(
                        "Invalid COSE_Sign1 signature algorithm",
                        "IcaSignatureVerifier::check_signature"
                    )
                    .validation_status("cawg.ica.invalid_alg")
                    .failure_no_throw(
                        status_tracker,
                        ValidationError::<Self::Error>::from(err.clone()),
                    );

                    return Err(err);
                }
            }
        } else {
            let err = ValidationError::SignatureError(IcaValidationError::SignatureTypeMissing);

            log_current_item!(
                "Missing COSE_Sign1 signature algorithm",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.invalid_alg")
            .failure_no_throw(
                status_tracker,
                ValidationError::<Self::Error>::from(err.clone()),
            );

            return Err(err);
        };

        if let Some(ref cty) = sign1.protected.header.content_type {
            match cty {
                coset::ContentType::Text(ref cty) => {
                    if cty != "application/vc" {
                        let err = ValidationError::SignatureError(
                            IcaValidationError::UnsupportedContentType(format!("{cty:?}")),
                        );

                        log_current_item!(
                            "Invalid COSE_Sign1 content type header",
                            "IcaSignatureVerifier::check_signature"
                        )
                        .validation_status("cawg.ica.invalid_content_type")
                        .failure_no_throw(
                            status_tracker,
                            ValidationError::<Self::Error>::from(err.clone()),
                        );

                        ok = false;
                    }
                }

                _ => {
                    let err = ValidationError::SignatureError(
                        IcaValidationError::UnsupportedContentType(format!("{cty:?}")),
                    );

                    log_current_item!(
                        "Invalid COSE_Sign1 content type header",
                        "IcaSignatureVerifier::check_signature"
                    )
                    .validation_status("cawg.ica.invalid_content_type")
                    .failure_no_throw(
                        status_tracker,
                        ValidationError::<Self::Error>::from(err.clone()),
                    );

                    ok = false;
                }
            }
        } else {
            let err = ValidationError::SignatureError(IcaValidationError::ContentTypeMissing);

            log_current_item!(
                "Invalid COSE_Sign1 content type header",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.invalid_content_type")
            .failure_no_throw(
                status_tracker,
                ValidationError::<Self::Error>::from(err.clone()),
            );

            ok = false;
        }

        // Interpret the unprotected payload, which should be the raw VC.
        let Some(ref payload_bytes) = sign1.payload else {
            return Err(ValidationError::SignatureError(
                IcaValidationError::CredentialPayloadMissing,
            ));
        };

        // TO DO (CAI-7970): Add support for VC version 1.
        let mut ica_credential: IcaCredential =
            serde_json::from_slice(payload_bytes).inspect_err(|err| {
                log_current_item!(
                    "Invalid JSON-LD for verifiable credential",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.invalid_verifiable_credential")
                .failure_no_throw(status_tracker, ValidationError::from(err));
            })?;

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

        // Post-process c2pa_asset to decode from base64 to raw binary.

        {
            let subject = ica_credential.credential_subjects.first_mut();

            let decoded_assertions = subject
                .c2pa_asset
                .referenced_assertions
                .iter()
                .map(|a| {
                    let base64_hash =
                        String::from_utf8(a.hash()).unwrap_or_else(|_| "invalid UTF8".to_string());

                    let decoded_hash = c2pa_crypto::base64::decode(&base64_hash)
                        .unwrap_or_else(|_| b"invalid base64".to_vec());

                    HashedUri::new(a.url(), a.alg(), &decoded_hash)
                })
                .collect();

            subject.c2pa_asset.referenced_assertions = decoded_assertions;

            // The DynamicAssertion mechanism doesn't always populate the `alg` field when
            // offering the partial claim for signature but some signers fill that in with a
            // default value. Work around this by copying only the `alg` value from inside
            // the VC.
            let mut signer_payload = signer_payload.clone();
            let new_ras = signer_payload
                .referenced_assertions
                .iter()
                .zip(subject.c2pa_asset.referenced_assertions.iter())
                .map(|(sp_ra, vc_ra)| {
                    if sp_ra.alg().is_none() {
                        HashedUri::new(sp_ra.url(), vc_ra.alg(), &sp_ra.hash())
                    } else {
                        sp_ra.clone()
                    }
                })
                .collect();

            signer_payload.referenced_assertions = new_ras;

            if &signer_payload != &subject.c2pa_asset {
                ok = false;

                log_current_item!(
                    "c2paAsset does not match signer_payload",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.signer_payload.mismatch")
                .failure(
                    status_tracker,
                    ValidationError::InternalError("signer payload mismatch".to_string()),
                )?;
            }
        }

        if ok {
            log_current_item!(
                "ICA credential is valid",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.credential_valid")
            .success(status_tracker);
        }

        Ok(ica_credential)
    }
}
