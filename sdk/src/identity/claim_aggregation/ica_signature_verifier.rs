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
use base64::{prelude::BASE64_URL_SAFE, Engine};
use chrono::{DateTime, Utc};
use coset::{CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable};

use crate::{
    crypto::{
        asn1::rfc3161::TstInfo,
        cose::{validate_cose_tst_info_async, CertificateTrustPolicy},
    },
    identity::{
        claim_aggregation::{
            w3c_vc::{
                did::Did,
                did_web,
                jwk::{Algorithm, Jwk, JwkError, Params},
            },
            IcaCredential, IcaValidationError,
        },
        SignatureVerifier, SignerPayload, ValidationError,
    },
    log_current_item,
    status_tracker::StatusTracker,
    validation_status::{
        TIMESTAMP_MALFORMED, TIMESTAMP_MISMATCH, TIMESTAMP_TRUSTED, TIMESTAMP_VALIDATED,
    },
    HashedUri,
};

/// An implementation of [`SignatureVerifier`] that supports Identity Claims
/// Aggregation Credentials (a specific grammar of W3C Verifiable Credentials)
/// as specified in [§8.1, Identity claims aggregation] and secured by COSE as
/// specified in [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE] of
/// _Securing Verifiable Credentials using JOSE and COSE._
///
/// [`SignatureVerifier`]: crate::identity::SignatureVerifier
/// [§8.1, Identity claims aggregation]: https://creator-assertions.github.io/identity/1.1-draft/#_identity_claims_aggregation
/// [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE]: https://w3c.github.io/vc-jose-cose/#securing-vcs-with-cose
pub struct IcaSignatureVerifier {
    // TO DO (CAI-7980): Add option to configure trusted ICA issuers.
}

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
        self.check_sig_type(signer_payload, status_tracker)?;

        let sign1 = self.decode_cose_sign1(signature, status_tracker)?;
        let _ssi_alg = self.decode_signing_alg(&sign1, status_tracker)?;

        // From this point forward, most errors are recoverable. We can only issue a
        // "credential valid" status if no errors are detected, so we use the `ok`
        // variable to keep track of whether any error statuses are logged.
        let mut ok = true;

        self.check_content_type(&sign1, status_tracker, &mut ok)?;

        // Interpret the unprotected payload, which should be the raw VC.
        let payload_bytes = self.payload_bytes(&sign1, status_tracker)?;

        // TO DO (CAI-7970): Add support for VC version 1.
        let mut ica_credential = self.parse_ica_vc_v2(payload_bytes, status_tracker)?;

        self.check_issuer_signature(&sign1, &ica_credential)
            .await
            .or_else(|err| {
                ok = false;
                self.handle_signature_error(err, status_tracker)
            })?;

        // todo: no trust list support yet for CAWG so passthrough for now
        let local_ctp = CertificateTrustPolicy::passthrough();
        // tracker to capture the C2PA timestamp informational statuses
        let mut timestamp_tracker = StatusTracker::default();

        // todo: since this is calling the C2PA Cose timestamp validator should it follow the C2PA rules?
        // todo: (CAI-8847) since C2PA requires trust lists for TSAs what does that mean for CAWG since it is using
        // the C2PA header's timestamp
        let maybe_tst_info = match validate_cose_tst_info_async(
            &sign1,
            payload_bytes,
            &local_ctp,
            &mut timestamp_tracker,
        )
        .await
        .inspect(|tst_info| self.save_time_stamp(tst_info, &mut ica_credential, status_tracker))
        {
            Ok(tst_info) => Some(tst_info),
            Err(_err) => {
                self.handle_time_stamp_error(&mut timestamp_tracker, status_tracker, &mut ok)?;
                None
            }
        };

        self.check_valid_from(&ica_credential, maybe_tst_info.as_ref())
            .await
            .or_else(|err| {
                ok = false;
                self.handle_non_fatal_error(err, status_tracker)
            })?;

        self.check_valid_until(&ica_credential, maybe_tst_info.as_ref())
            .await
            .or_else(|err| {
                ok = false;
                self.handle_non_fatal_error(err, status_tracker)
            })?;

        // TO DO (CAI-7993): CAWG SDK should check ICA issuer revocation status.

        self.cross_check_signer_payload(&ica_credential, signer_payload, status_tracker, &mut ok)?;

        // TO DO (CAI-7994): CAWG SDK should inspect verifiedIdentities array.

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

impl IcaSignatureVerifier {
    /// Signal an error if the `sig_type` value is not
    /// `cawg.identity_claims_aggregation`.
    fn check_sig_type(
        &self,
        signer_payload: &SignerPayload,
        status_tracker: &mut StatusTracker,
    ) -> Result<(), ValidationError<IcaValidationError>> {
        if signer_payload.sig_type == super::CAWG_ICA_SIG_TYPE {
            Ok(())
        } else {
            let err = ValidationError::<IcaValidationError>::UnknownSignatureType(
                signer_payload.sig_type.clone(),
            );

            log_current_item!(
                "unsupported signature type",
                "X509SignatureVerifier::check_signature"
            )
            .validation_status("cawg.identity.sig_type.unknown")
            .failure_no_throw(status_tracker, err.clone());

            Err(err)
        }
    }

    /// Parse the `signature` value as a [`CoseSign1`] data structure.
    fn decode_cose_sign1(
        &self,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<CoseSign1, ValidationError<IcaValidationError>> {
        CoseSign1::from_tagged_slice(signature)
            .inspect_err(|err| {
                log_current_item!(
                    "Invalid COSE_Sign1 data structure",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.invalid_cose_sign1")
                .failure_no_throw(status_tracker, ValidationError::from(err));
            })
            .map_err(|e| e.into())
    }

    /// Read the protected `alg` header from the [`CoseSign1`] data structure
    /// and convert that to a corresponding [`Algorithm`] type.
    fn decode_signing_alg(
        &self,
        sign1: &CoseSign1,
        status_tracker: &mut StatusTracker,
    ) -> Result<Algorithm, ValidationError<IcaValidationError>> {
        if let Some(ref alg) = sign1.protected.header.alg {
            match alg {
                // TO DO (CAI-7965): Support algorithms other than EdDSA.
                RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA) => {
                    Ok(Algorithm::EdDsa)
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
                    .failure_no_throw(status_tracker, err.clone());

                    Err(err)
                }
            }
        } else {
            let err = ValidationError::SignatureError(IcaValidationError::SignatureTypeMissing);

            log_current_item!(
                "Missing COSE_Sign1 signature algorithm",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.invalid_alg")
            .failure_no_throw(status_tracker, err.clone());

            Err(err)
        }
    }

    /// Signal an error if the COSE `content_type` header is anything other than
    /// `application/vc`.
    fn check_content_type(
        &self,
        sign1: &CoseSign1,
        status_tracker: &mut StatusTracker,
        ok: &mut bool,
    ) -> Result<(), ValidationError<IcaValidationError>> {
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
                        .failure(status_tracker, err.clone())?;

                        *ok = false;
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
                    .failure(status_tracker, err.clone())?;

                    *ok = false;
                }
            }
        } else {
            let err = ValidationError::SignatureError(IcaValidationError::ContentTypeMissing);

            log_current_item!(
                "Invalid COSE_Sign1 content type header",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.invalid_content_type")
            .failure(status_tracker, err.clone())?;

            *ok = false;
        }

        Ok(())
    }

    fn payload_bytes<'a>(
        &self,
        sign1: &'a CoseSign1,
        status_tracker: &mut StatusTracker,
    ) -> Result<&'a Vec<u8>, ValidationError<IcaValidationError>> {
        let Some(ref payload_bytes) = sign1.payload else {
            let err = ValidationError::SignatureError(IcaValidationError::CredentialPayloadMissing);

            log_current_item!(
                "Missing COSE_Sign1 payload",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.invalid_verifiable_credential")
            .failure_no_throw(status_tracker, err.clone());

            return Err(err);
        };

        Ok(payload_bytes)
    }

    fn parse_ica_vc_v2(
        &self,
        payload_bytes: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<IcaCredential, ValidationError<IcaValidationError>> {
        let mut ica_credential: IcaCredential =
            serde_json::from_slice(payload_bytes).map_err(|err| {
                let err = ValidationError::from(err);

                log_current_item!(
                    "Invalid JSON-LD for verifiable credential",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.invalid_verifiable_credential")
                .failure_no_throw(status_tracker, err.clone());

                err
            })?;

        // Post-process c2pa_asset to decode from base64 to raw binary.
        let subject = ica_credential.credential_subjects.first_mut();

        let decoded_assertions = subject
            .c2pa_asset
            .referenced_assertions
            .iter()
            .map(|a| {
                let base64_hash =
                    String::from_utf8(a.hash()).unwrap_or_else(|_| "invalid UTF8".to_string());

                let decoded_hash = crate::crypto::base64::decode(&base64_hash)
                    .unwrap_or_else(|_| b"invalid base64".to_vec());

                HashedUri::new(a.url(), a.alg(), &decoded_hash)
            })
            .collect();

        subject.c2pa_asset.referenced_assertions = decoded_assertions;

        Ok(ica_credential)
    }

    async fn check_issuer_signature(
        &self,
        sign1: &CoseSign1,
        ica_credential: &IcaCredential,
    ) -> Result<(), ValidationError<IcaValidationError>> {
        // Discover public key for issuer DID and validate signature.
        // TEMPORARY version supports did:jwk and did:web only.

        // TO DO (CAI-7976): Accept issuer DID in either `issuer` or `issuer.id` field.
        // Currently only `issuer` field is supported.
        let issuer_id = Did::new(&ica_credential.issuer)?;
        let (primary_did, _fragment) = issuer_id.split_fragment();

        let jwk = match primary_did.method_name() {
            "jwk" => {
                let jwk = primary_did.method_specific_id();

                let jwk = BASE64_URL_SAFE.decode(jwk).map_err(|e| {
                    ValidationError::SignatureError(IcaValidationError::InvalidDidDocument(
                        e.to_string(),
                    ))
                })?;

                let jwk: Jwk = serde_json::from_slice(&jwk).map_err(|e| {
                    ValidationError::SignatureError(IcaValidationError::InvalidDidDocument(
                        e.to_string(),
                    ))
                })?;

                jwk
            }

            "web" => {
                let did_doc = did_web::resolve(&primary_did).await?;

                let Some(vm1) = did_doc.verification_relationships.assertion_method.first() else {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::InvalidDidDocument(
                            "DID document doesn't contain an assertionMethod entry".to_string(),
                        ),
                    ));
                };

                let super::w3c_vc::did_doc::ValueOrReference::Value(vm1) = vm1 else {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::InvalidDidDocument(
                            "DID document's assertionMethod is not a value".to_string(),
                        ),
                    ));
                };

                let Some(jwk_prop) = vm1.properties.get("publicKeyJwk") else {
                    return Err(ValidationError::SignatureError(
                        IcaValidationError::InvalidDidDocument(
                            "DID document's assertionMethod doesn't contain a publicKeyJwk entry"
                                .to_string(),
                        ),
                    ));
                };

                // OMG SO HACKY!
                let Ok(jwk_json) = serde_json::to_string_pretty(jwk_prop) else {
                    return Err(ValidationError::InternalError(
                        "couldn't re-serialize JWK".to_string(),
                    ));
                };

                let Ok(jwk) = serde_json::from_str(&jwk_json) else {
                    return Err(ValidationError::InternalError(
                        "couldn't re-serialize JWK".to_string(),
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
                IcaValidationError::InvalidDidDocument(format!(
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
            .map_err(|_e| ValidationError::SignatureMismatch)?;

        // TO DO: Enforce signer_payload matches what was stated outside the signature.

        // TO DO: Enforce validity window as compared to sig time (or now if no TSA
        // time).

        Ok(())
    }

    fn handle_signature_error(
        &self,
        err: ValidationError<IcaValidationError>,
        status_tracker: &mut StatusTracker,
    ) -> Result<(), ValidationError<IcaValidationError>> {
        // NOTE: We handle logging here because all error conditions that are detectable
        // in `check_issuer_signature` are fatal to signature verification, BUT they are
        // not fatal to the overall interpretation of the identity assertion.
        //
        // In the event that the status tracker is configured to proceed when possible,
        // we log the error condition related to the signature and proceed.

        match err {
            ValidationError::SignatureError(IcaValidationError::UnsupportedIssuerDid(_)) => {
                log_current_item!(
                    "Invalid issuer DID",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.invalid_issuer")
                .failure(status_tracker, err)?;
            }

            ValidationError::SignatureError(IcaValidationError::DidResolutionError(_)) => {
                log_current_item!(
                    "Unable to resolve issuer DID",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.did_unavailable")
                .failure(status_tracker, err)?;
            }

            ValidationError::SignatureError(IcaValidationError::InvalidDidDocument(_)) => {
                log_current_item!(
                    "Invalid issuer DID document",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.invalid_did_document")
                .failure(status_tracker, err)?;
            }

            ValidationError::SignatureMismatch => {
                log_current_item!(
                    "Signature does not match credential",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.signature_mismatch")
                .failure(status_tracker, err)?;
            }

            _ => {
                // TO REVIEW: Is there a better CAWG status code to use here? We don't expect
                // this code path to be reached, but it's a fallback to avoid a panic.
                log_current_item!(
                    "Unexpected error condition",
                    "IcaSignatureVerifier::check_signature"
                )
                .validation_status("cawg.ica.did_unavailable")
                .failure(status_tracker, err)?;
            }
        }

        Ok(())
    }

    fn save_time_stamp(
        &self,
        tst_info: &TstInfo,
        ica_credential: &mut IcaCredential,
        status_tracker: &mut StatusTracker,
    ) {
        ica_credential.credential_subjects.first_mut().time_stamp = Some(tst_info.clone());

        log_current_item!(
            "Time stamp validated",
            "IcaSignatureVerifier::check_signature"
        )
        .validation_status("cawg.ica.time_stamp.validated")
        .success(status_tracker);
    }

    // all errors from timestamp verify are now informational, so map the informational
    // codes to CAWG timestamp errors.
    fn handle_time_stamp_error(
        &self,
        timestamp_tracker: &mut StatusTracker,
        cawg_tracker: &mut StatusTracker,
        ok: &mut bool,
    ) -> Result<(), ValidationError<IcaValidationError>> {
        if timestamp_tracker.has_status(TIMESTAMP_MALFORMED)
            | timestamp_tracker.has_status(TIMESTAMP_MISMATCH)
        {
            *ok = false;

            log_current_item!(
                "Time stamp does not match credential",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.time_stamp.invalid")
            .failure(
                cawg_tracker,
                ValidationError::SignatureError(IcaValidationError::InvalidTimeStamp),
            )?;
        } else if timestamp_tracker.has_status(TIMESTAMP_VALIDATED)
            && timestamp_tracker.has_status(TIMESTAMP_TRUSTED)
        {
            *ok = true;
        } else if !timestamp_tracker.logged_items().is_empty() {
            // any other logged issue
            *ok = false;
            log_current_item!(
                "Unable to process time stamp",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.time_stamp.invalid")
            .failure(
                cawg_tracker,
                ValidationError::SignatureError(IcaValidationError::InvalidTimeStamp),
            )?;
        }

        Ok(())
    }

    // Enforce [§8.1.1.4. Validity].
    //
    // [§8.1.1.4. Validity]: https://cawg.io/identity/1.1-draft/
    async fn check_valid_from(
        &self,
        ica_credential: &IcaCredential,
        maybe_tst_info: Option<&TstInfo>,
    ) -> Result<(), (IcaValidationError, &'static str)> {
        let Some(valid_from) = ica_credential.valid_from else {
            return Err((
                IcaValidationError::MissingValidFromDate,
                "cawg.ica.valid_from.missing",
            ));
        };

        // TO DO: Bring in substitute for now() on Wasm.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let now = Utc::now().fixed_offset();

            if now < valid_from {
                return Err((
                    IcaValidationError::InvalidValidFromDate(
                        "validFrom is after current date/time".to_owned(),
                    ),
                    "cawg.ica.valid_from.invalid",
                ));
            }
        }

        if let Some(tst_info) = maybe_tst_info {
            let cawg_signer_time: DateTime<Utc> = tst_info.gen_time.clone().into();
            let cawg_signer_time = cawg_signer_time.fixed_offset();

            if cawg_signer_time < valid_from {
                return Err((
                    IcaValidationError::InvalidValidFromDate(
                        "validFrom is after CAWG signature time stamp".to_string(),
                    ),
                    "cawg.ica.valid_from.invalid",
                ));
            }
        }

        // TO DO (CAI-7988): Enforce validFrom can not be later than
        // C2PA Manifest time stamp.

        Ok(())
    }

    async fn check_valid_until(
        &self,
        ica_credential: &IcaCredential,
        maybe_tst_info: Option<&TstInfo>,
    ) -> Result<(), (IcaValidationError, &'static str)> {
        let Some(valid_until) = ica_credential.valid_until else {
            // CAWG spec does not require a validUntil entry, so if there is not, we exit
            // quietly here.
            return Ok(());
        };

        // TO DO: Bring in substitute for now() on Wasm.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let now = Utc::now().fixed_offset();

            if now > valid_until {
                return Err((
                    IcaValidationError::InvalidValidUntilDate(
                        "validUntil is before current date/time".to_owned(),
                    ),
                    "cawg.ica.valid_until.invalid",
                ));
            }
        }

        if let Some(tst_info) = maybe_tst_info {
            let cawg_signer_time: DateTime<Utc> = tst_info.gen_time.clone().into();
            let cawg_signer_time = cawg_signer_time.fixed_offset();

            if cawg_signer_time > valid_until {
                return Err((
                    IcaValidationError::InvalidValidUntilDate(
                        "validUntil is before CAWG signature time stamp".to_owned(),
                    ),
                    "cawg.ica.valid_until.invalid",
                ));
            }
        }

        // TO DO (CAI-7988): Enforce validUntil can not be earlier than
        // C2PA Manifest time stamp.

        Ok(())
    }

    fn handle_non_fatal_error(
        &self,
        err: (IcaValidationError, &'static str),
        status_tracker: &mut StatusTracker,
    ) -> Result<(), ValidationError<IcaValidationError>> {
        // NOTE: We handle logging here because we want to signal at most one of the
        // possible error conditions that are detectable in `check_valid_from`, BUT they
        // are not fatal to the overall interpretation of the identity assertion.
        //
        // In the event that the status tracker is configured to proceed when possible,
        // we log the error condition related to the signature and proceed.
        let (err, msg) = err;

        log_current_item!(err.to_string(), "IcaSignatureVerifier::check_signature")
            .validation_status(msg)
            .failure(status_tracker, ValidationError::SignatureError(err))?;

        Ok(())
    }

    /// Verify that `signer_payload` is the same as credential issuer signed.
    fn cross_check_signer_payload(
        &self,
        ica_credential: &IcaCredential,
        signer_payload: &SignerPayload,
        status_tracker: &mut StatusTracker,
        ok: &mut bool,
    ) -> Result<(), ValidationError<IcaValidationError>> {
        let subject = ica_credential.credential_subjects.first();

        // The `DynamicAssertion` mechanism doesn't always populate the `alg` field when
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

        if signer_payload != subject.c2pa_asset {
            *ok = false;

            log_current_item!(
                "c2paAsset does not match signer_payload",
                "IcaSignatureVerifier::check_signature"
            )
            .validation_status("cawg.ica.signer_payload.mismatch")
            .failure(
                status_tracker,
                ValidationError::SignatureError(IcaValidationError::SignerPayloadMismatch),
            )?;
        }

        Ok(())
    }
}
