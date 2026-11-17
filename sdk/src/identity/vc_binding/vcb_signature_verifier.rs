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

use async_generic::async_generic;
use async_trait::async_trait;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use coset::{CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable};
use serde_json::Value;

use super::{
    binding::{aggregate_terms_of_use, asset_bindings, expected_binding},
    codes,
    vcb_credential::{
        VcbCredential, VcbVerifiableCredential, VcbVerifiedIdentity, C2PA_BINDING_CREDENTIAL_TYPE,
        CAWG_VERIFIED_IDENTITIES_TYPE, VC_BINDING_CONTEXT_IRI,
    },
    VcbValidationError, CAWG_VCB_SIG_TYPE,
};
use crate::{
    context::Context,
    crypto::{
        asn1::rfc3161::TstInfo,
        cose::{validate_cose_tst_info, validate_cose_tst_info_async, CertificateTrustPolicy},
    },
    identity::{
        claim_aggregation::w3c_vc::{
            credential::{VERIFIABLE_CREDENTIAL_CONTEXT, VERIFIABLE_CREDENTIAL_TYPE},
            did::Did,
            did_doc::ValueOrReference,
            did_web,
            jwk::{Jwk, JwkError, Params},
        },
        SignatureVerifier, SignerPayload, ValidationError,
    },
    log_current_item,
    settings::TrustListKind,
    status_tracker::StatusTracker,
    validation_status::{
        TIMESTAMP_MALFORMED, TIMESTAMP_MISMATCH, TIMESTAMP_TRUSTED, TIMESTAMP_VALIDATED,
    },
};

type Result<T> = std::result::Result<T, ValidationError<VcbValidationError>>;

const FN: &str = "VcbSignatureVerifier::check_signature";

/// An implementation of [`SignatureVerifier`] for the verifiable credential
/// binding (`sig_type` `cawg.verifiable_credential_binding`) of the CAWG
/// identity 1.3 draft, §8.3, whose outermost credential is a W3C verifiable
/// credential (data model 2.0) secured with COSE as described in [§3.3.1
/// Securing JSON-LD Verifiable Credentials with COSE] of _Securing Verifiable
/// Credentials using JOSE and COSE._
///
/// This implementation does not yet support:
/// - an outermost verifiable presentation (`application/vp`),
/// - verifiable credentials data model 1.1,
/// - signature algorithms other than EdDSA (Ed25519),
/// - DID methods other than `did:jwk` and `did:web`,
/// - checking `credentialStatus` (revocation), which is reported as
///   `cawg.vcb.revocation.unsupported`.
///
/// [§3.3.1 Securing JSON-LD Verifiable Credentials with COSE]: https://www.w3.org/TR/vc-jose-cose/#securing-vcs-with-cose
pub struct VcbSignatureVerifier<'a> {
    /// Context under which validation is performed.
    ///
    /// The `trusted_ica_issuers` lists of the CAWG trust anchors on this
    /// context's [`Settings`](crate::settings::Settings) name the trusted
    /// credential issuer DIDs. An issuer that is not listed is reported with
    /// `cawg.vcb.untrusted_issuer`.
    context: &'a Context,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureVerifier for VcbSignatureVerifier<'_> {
    type Error = VcbValidationError;
    type Output = VcbCredential;

    fn check_signature(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<Self::Output> {
        self.verify(signer_payload, signature, status_tracker)
    }

    async fn check_signature_async(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<Self::Output> {
        self.verify_async(signer_payload, signature, status_tracker)
            .await
    }
}

impl<'a> VcbSignatureVerifier<'a> {
    /// Creates a verifier that validates under `context`.
    pub fn new(context: &'a Context) -> Self {
        Self { context }
    }

    #[async_generic]
    fn verify(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<VcbCredential> {
        self.check_sig_type(signer_payload, status_tracker)?;

        // Steps that make the rest impossible stop validation; after those, every
        // problem is logged and validation continues. `cawg.vcb.credential_valid`
        // is issued only if no failure was logged, which `ok` tracks.
        let sign1 = self.decode_cose_sign1(signature, status_tracker)?;
        self.check_signing_alg(&sign1, status_tracker)?;

        let mut ok = self.check_content_type(&sign1, status_tracker)?;

        let payload = self.payload_bytes(&sign1, status_tracker)?;
        let credential = self.parse_credential(payload, status_tracker)?;

        ok &= self.check_structure(&credential, status_tracker)?;

        let signature_result = if _sync {
            self.check_issuer_signature(&sign1, &credential)
        } else {
            self.check_issuer_signature_async(&sign1, &credential).await
        };
        let signature_ok = match signature_result {
            Ok(()) => true,
            Err(err) => {
                ok = false;
                self.handle_signature_error(err, status_tracker)?;
                false
            }
        };

        // Issuer trust only means something once the signature holds. It is
        // scoped to this identity assertion and doesn't affect the manifest.
        if signature_ok {
            ok &= self.check_issuer_trust(&credential, status_tracker);
        }

        // As for identity claims aggregation, CAWG has no TSA trust list yet.
        let local_ctp = CertificateTrustPolicy::passthrough();
        let mut timestamp_tracker = StatusTracker::default();
        let tst_result = if _sync {
            validate_cose_tst_info(&sign1, payload, &local_ctp, &mut timestamp_tracker, false)
        } else {
            validate_cose_tst_info_async(&sign1, payload, &local_ctp, &mut timestamp_tracker, false)
                .await
        };
        let time_stamp = match tst_result {
            Ok(tst_info) => {
                log_current_item!("Time stamp validated", FN)
                    .validation_status(codes::TIME_STAMP_VALIDATED)
                    .success(status_tracker);
                Some(tst_info)
            }
            Err(_) => {
                ok &= self.handle_time_stamp_error(&timestamp_tracker, status_tracker)?;
                None
            }
        };

        for check in [
            Self::check_valid_from(&credential, time_stamp.as_ref()),
            Self::check_valid_until(&credential, time_stamp.as_ref()),
            Self::check_revocation(&credential),
        ] {
            if let Err((err, code)) = check {
                ok = false;
                log_current_item!(err.to_string(), FN)
                    .validation_status(code)
                    .failure(status_tracker, ValidationError::SignatureError(err))?;
            }
        }

        ok &= self.check_binding(&credential, signer_payload, status_tracker)?;

        let (identities_ok, verified_identities) =
            self.check_verified_identities(&credential, status_tracker)?;
        ok &= identities_ok;

        if ok {
            log_current_item!("Verifiable credential binding is valid", FN)
                .validation_status(codes::CREDENTIAL_VALID)
                .success(status_tracker);
        }

        Ok(VcbCredential {
            credential,
            verified_identities,
            signer_payload: signer_payload.clone(),
            time_stamp,
        })
    }

    fn check_sig_type(
        &self,
        signer_payload: &SignerPayload,
        status_tracker: &mut StatusTracker,
    ) -> Result<()> {
        if signer_payload.sig_type == CAWG_VCB_SIG_TYPE {
            return Ok(());
        }

        let err = ValidationError::<VcbValidationError>::UnknownSignatureType(
            signer_payload.sig_type.clone(),
        );
        log_current_item!("unsupported signature type", FN)
            .validation_status("cawg.identity.sig_type.unknown")
            .failure_no_throw(status_tracker, err.clone());
        Err(err)
    }

    fn decode_cose_sign1(
        &self,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<CoseSign1> {
        CoseSign1::from_tagged_slice(signature).map_err(|err| {
            let err = ValidationError::from(err);
            log_current_item!("Invalid COSE_Sign1 data structure", FN)
                .validation_status(codes::INVALID_COSE_SIGN1)
                .failure_no_throw(status_tracker, err.clone());
            err
        })
    }

    /// Only EdDSA (Ed25519) is supported, as for identity claims aggregation.
    fn check_signing_alg(
        &self,
        sign1: &CoseSign1,
        status_tracker: &mut StatusTracker,
    ) -> Result<()> {
        let err = match sign1.protected.header.alg {
            Some(RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA)) => {
                return Ok(())
            }
            Some(ref alg) => VcbValidationError::UnsupportedSignatureType(format!("{alg:?}")),
            None => VcbValidationError::SignatureTypeMissing,
        };

        let err = ValidationError::SignatureError(err);
        log_current_item!("Invalid COSE_Sign1 signature algorithm", FN)
            .validation_status(codes::INVALID_ALG)
            .failure_no_throw(status_tracker, err.clone());
        Err(err)
    }

    /// The content type must be `application/vc`. An `application/vp` outermost
    /// credential is valid per the draft but not yet supported, which stops
    /// validation.
    fn check_content_type(
        &self,
        sign1: &CoseSign1,
        status_tracker: &mut StatusTracker,
    ) -> Result<bool> {
        let err = match sign1.protected.header.content_type {
            Some(coset::ContentType::Text(ref cty)) if cty == "application/vc" => return Ok(true),
            Some(coset::ContentType::Text(ref cty)) if cty == "application/vp" => {
                let err =
                    ValidationError::SignatureError(VcbValidationError::PresentationNotSupported);
                log_current_item!("Verifiable presentations are not yet supported", FN)
                    .validation_status(codes::INVALID_VERIFIABLE_CREDENTIAL)
                    .failure_no_throw(status_tracker, err.clone());
                return Err(err);
            }
            Some(ref cty) => VcbValidationError::UnsupportedContentType(format!("{cty:?}")),
            None => VcbValidationError::ContentTypeMissing,
        };

        log_current_item!("Invalid COSE_Sign1 content type header", FN)
            .validation_status(codes::INVALID_CONTENT_TYPE)
            .failure(status_tracker, ValidationError::SignatureError(err))?;
        Ok(false)
    }

    fn payload_bytes<'b>(
        &self,
        sign1: &'b CoseSign1,
        status_tracker: &mut StatusTracker,
    ) -> Result<&'b Vec<u8>> {
        sign1.payload.as_ref().ok_or_else(|| {
            let err = ValidationError::SignatureError(VcbValidationError::CredentialPayloadMissing);
            log_current_item!("Missing COSE_Sign1 payload", FN)
                .validation_status(codes::INVALID_VERIFIABLE_CREDENTIAL)
                .failure_no_throw(status_tracker, err.clone());
            err
        })
    }

    fn parse_credential(
        &self,
        payload: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<VcbVerifiableCredential> {
        serde_json::from_slice(payload).map_err(|err| {
            let err = ValidationError::from(err);
            log_current_item!("Invalid JSON-LD for verifiable credential", FN)
                .validation_status(codes::INVALID_VERIFIABLE_CREDENTIAL)
                .failure_no_throw(status_tracker, err.clone());
            err
        })
    }

    /// Checks the `@context`, `type` and `termsOfUse` requirements for the
    /// outermost credential.
    fn check_structure(
        &self,
        credential: &VcbVerifiableCredential,
        status_tracker: &mut StatusTracker,
    ) -> Result<bool> {
        let has_context = |iri: &str| credential.contexts.iter().any(|c| c.as_str() == iri);
        let has_type = |t: &str| credential.types.iter().any(|ct| ct == t);

        let problem = if !has_context(VERIFIABLE_CREDENTIAL_CONTEXT.as_str()) {
            Some(format!(
                "@context does not include {VERIFIABLE_CREDENTIAL_CONTEXT}"
            ))
        } else if !has_context(VC_BINDING_CONTEXT_IRI.as_str()) {
            Some(format!(
                "@context does not include {VC_BINDING_CONTEXT_IRI}"
            ))
        } else if !has_type(VERIFIABLE_CREDENTIAL_TYPE) {
            Some(format!(
                "type does not include {VERIFIABLE_CREDENTIAL_TYPE}"
            ))
        } else if asset_bindings(credential.extra_properties.get("termsOfUse")).is_empty() {
            Some("termsOfUse has no entry of type C2PAAssetBinding".to_owned())
        } else if !has_type(C2PA_BINDING_CREDENTIAL_TYPE) {
            Some(format!(
                "type does not include {C2PA_BINDING_CREDENTIAL_TYPE}"
            ))
        } else {
            None
        };

        let Some(problem) = problem else {
            return Ok(true);
        };

        log_current_item!(problem.clone(), FN)
            .validation_status(codes::INVALID_VERIFIABLE_CREDENTIAL)
            .failure(
                status_tracker,
                ValidationError::SignatureError(VcbValidationError::InvalidCredential(problem)),
            )?;
        Ok(false)
    }

    /// Discovers the issuer's public key from its DID and verifies the
    /// `COSE_Sign1` signature. Supports `did:jwk` and `did:web`.
    #[async_generic]
    fn check_issuer_signature(
        &self,
        sign1: &CoseSign1,
        credential: &VcbVerifiableCredential,
    ) -> Result<()> {
        let issuer = Did::new(&credential.issuer)?;
        let (primary_did, _fragment) = issuer.split_fragment();

        let invalid_doc = |msg: String| {
            ValidationError::SignatureError(VcbValidationError::InvalidDidDocument(msg))
        };

        let jwk: Jwk = match primary_did.method_name() {
            "jwk" => {
                let bytes = BASE64_URL_SAFE_NO_PAD
                    .decode(primary_did.method_specific_id().trim_end_matches('='))
                    .map_err(|e| invalid_doc(e.to_string()))?;
                serde_json::from_slice(&bytes).map_err(|e| invalid_doc(e.to_string()))?
            }

            "web" => {
                let did_doc = if _sync {
                    did_web::resolve(&primary_did, self.context)?
                } else {
                    did_web::resolve_async(&primary_did, self.context).await?
                };

                let Some(ValueOrReference::Value(vm)) =
                    did_doc.verification_relationships.assertion_method.first()
                else {
                    return Err(invalid_doc(
                        "DID document has no embedded assertionMethod entry".to_owned(),
                    ));
                };

                let Some(jwk) = vm.properties.get("publicKeyJwk") else {
                    return Err(invalid_doc(
                        "assertionMethod has no publicKeyJwk entry".to_owned(),
                    ));
                };

                serde_json::from_value(jwk.clone()).map_err(|e| invalid_doc(e.to_string()))?
            }

            method => {
                return Err(ValidationError::SignatureError(
                    VcbValidationError::UnsupportedDidMethod(format!("did:{method}")),
                ));
            }
        };

        let Params::Okp(ref okp) = jwk.params;
        if okp.curve != "Ed25519" {
            return Err(invalid_doc(format!("unsupported OKP curve {}", okp.curve)));
        }

        sign1
            .verify_signature(b"", |sig, data| {
                use ed25519_dalek::Verifier;
                let public_key = ed25519_dalek::VerifyingKey::try_from(okp)?;
                let signature: ed25519_dalek::Signature = sig.try_into().map_err(JwkError::from)?;
                public_key.verify(data, &signature).map_err(JwkError::from)
            })
            .map_err(|_| ValidationError::SignatureMismatch)
    }

    fn handle_signature_error(
        &self,
        err: ValidationError<VcbValidationError>,
        status_tracker: &mut StatusTracker,
    ) -> Result<()> {
        let (description, code) = match err {
            ValidationError::SignatureError(VcbValidationError::InvalidIssuerDid(_)) => {
                ("Invalid issuer DID", codes::INVALID_ISSUER)
            }
            ValidationError::SignatureError(VcbValidationError::UnsupportedDidMethod(_)) => (
                "Unsupported issuer DID method",
                codes::DID_UNSUPPORTED_METHOD,
            ),
            ValidationError::SignatureError(VcbValidationError::InvalidDidDocument(_)) => {
                ("Invalid issuer DID document", codes::INVALID_DID_DOCUMENT)
            }
            ValidationError::SignatureMismatch => (
                "Signature does not match credential",
                codes::SIGNATURE_MISMATCH,
            ),
            // DID resolution failures, and anything unexpected while resolving.
            _ => ("Unable to resolve issuer DID", codes::DID_UNAVAILABLE),
        };

        log_current_item!(description, FN)
            .validation_status(code)
            .failure(status_tracker, err)?;
        Ok(())
    }

    /// The issuer must be on a CAWG trust anchor's `trusted_ica_issuers` list.
    /// An untrusted issuer is recorded informationally: it withholds
    /// `cawg.vcb.credential_valid` but doesn't fail the enclosing manifest.
    fn check_issuer_trust(
        &self,
        credential: &VcbVerifiableCredential,
        status_tracker: &mut StatusTracker,
    ) -> bool {
        let issuer = credential.issuer.as_str();
        let issuer = issuer.split_once('#').map_or(issuer, |(did, _)| did);

        let trusted = self
            .context
            .settings()
            .trust
            .anchors
            .iter()
            .flatten()
            .filter(|a| a.trust_kind == TrustListKind::CAWG)
            .filter_map(|a| a.trusted_ica_issuers.as_ref())
            .any(|issuers| issuers.iter().any(|t| t == issuer));

        if !trusted {
            log_current_item!("Credential issuer is not a trusted issuer", FN)
                .validation_status(codes::UNTRUSTED_ISSUER)
                .informational(status_tracker);
        }
        trusted
    }

    fn handle_time_stamp_error(
        &self,
        timestamp_tracker: &StatusTracker,
        status_tracker: &mut StatusTracker,
    ) -> Result<bool> {
        let invalid = timestamp_tracker.has_status(TIMESTAMP_MALFORMED)
            || timestamp_tracker.has_status(TIMESTAMP_MISMATCH)
            || !(timestamp_tracker.logged_items().is_empty()
                || timestamp_tracker.has_status(TIMESTAMP_VALIDATED)
                    && timestamp_tracker.has_status(TIMESTAMP_TRUSTED));

        if invalid {
            log_current_item!("Time stamp is not valid for this credential", FN)
                .validation_status(codes::TIME_STAMP_INVALID)
                .failure(
                    status_tracker,
                    ValidationError::SignatureError(VcbValidationError::InvalidTimeStamp),
                )?;
        }
        Ok(!invalid)
    }

    fn check_valid_from(
        credential: &VcbVerifiableCredential,
        time_stamp: Option<&TstInfo>,
    ) -> std::result::Result<(), (VcbValidationError, &'static str)> {
        let Some(valid_from) = credential.valid_from else {
            return Err((
                VcbValidationError::MissingValidFromDate,
                codes::VALID_FROM_MISSING,
            ));
        };

        if Utc::now().fixed_offset() < valid_from {
            return Err((
                VcbValidationError::InvalidValidFromDate("validFrom is in the future".to_owned()),
                codes::VALID_FROM_INVALID,
            ));
        }

        if let Some(tst) = time_stamp {
            let signed_at: DateTime<Utc> = tst.gen_time.clone().into();
            if signed_at.fixed_offset() < valid_from {
                return Err((
                    VcbValidationError::InvalidValidFromDate(
                        "validFrom is after the COSE time stamp".to_owned(),
                    ),
                    codes::VALID_FROM_INVALID,
                ));
            }
        }

        Ok(())
    }

    fn check_valid_until(
        credential: &VcbVerifiableCredential,
        time_stamp: Option<&TstInfo>,
    ) -> std::result::Result<(), (VcbValidationError, &'static str)> {
        let Some(valid_until) = credential.valid_until else {
            return Ok(());
        };

        if Utc::now().fixed_offset() > valid_until {
            return Err((
                VcbValidationError::InvalidValidUntilDate("validUntil is in the past".to_owned()),
                codes::VALID_UNTIL_INVALID,
            ));
        }

        if let Some(tst) = time_stamp {
            let signed_at: DateTime<Utc> = tst.gen_time.clone().into();
            if signed_at.fixed_offset() > valid_until {
                return Err((
                    VcbValidationError::InvalidValidUntilDate(
                        "validUntil is before the COSE time stamp".to_owned(),
                    ),
                    codes::VALID_UNTIL_INVALID,
                ));
            }
        }

        Ok(())
    }

    /// Revocation checking isn't implemented, so a credential that offers a
    /// `credentialStatus` is reported as `cawg.vcb.revocation.unsupported`
    /// rather than silently treated as not revoked.
    fn check_revocation(
        credential: &VcbVerifiableCredential,
    ) -> std::result::Result<(), (VcbValidationError, &'static str)> {
        if credential.extra_properties.contains_key("credentialStatus") {
            Err((
                VcbValidationError::RevocationUnsupported,
                codes::REVOCATION_UNSUPPORTED,
            ))
        } else {
            Ok(())
        }
    }

    /// Aggregates the `C2PAAssetBinding` `termsOfUse` entries and checks that
    /// they match `signer_payload`.
    fn check_binding(
        &self,
        credential: &VcbVerifiableCredential,
        signer_payload: &SignerPayload,
        status_tracker: &mut StatusTracker,
    ) -> Result<bool> {
        let bindings = asset_bindings(credential.extra_properties.get("termsOfUse"));
        if bindings.is_empty() {
            // Already reported by `check_structure`.
            return Ok(false);
        }

        let actual = match aggregate_terms_of_use(bindings) {
            Ok(actual) => Value::Object(actual),
            Err(property) => {
                log_current_item!("Conflicting C2PAAssetBinding values", FN)
                    .validation_status(codes::BINDING_MISMATCH)
                    .failure(
                        status_tracker,
                        ValidationError::SignatureError(VcbValidationError::BindingMismatch(
                            property,
                        )),
                    )?;
                return Ok(false);
            }
        };

        let mut expected =
            expected_binding(signer_payload).map_err(ValidationError::InternalError)?;
        fill_missing_algs(&mut expected, &actual);

        if expected == actual {
            return Ok(true);
        }

        log_current_item!("termsOfUse binding does not match signer_payload", FN)
            .validation_status(codes::SIGNER_PAYLOAD_MISMATCH)
            .failure(
                status_tracker,
                ValidationError::SignatureError(VcbValidationError::SignerPayloadMismatch),
            )?;
        Ok(false)
    }

    /// When the credential has type `CAWGVerifiedIdentities`, every credential
    /// subject must be a valid verified identity. A credential whose subjects
    /// look like verified identities must have that type.
    fn check_verified_identities(
        &self,
        credential: &VcbVerifiableCredential,
        status_tracker: &mut StatusTracker,
    ) -> Result<(bool, Vec<VcbVerifiedIdentity>)> {
        let declared = credential
            .types
            .iter()
            .any(|t| t == CAWG_VERIFIED_IDENTITIES_TYPE);

        let subjects: Vec<&std::collections::BTreeMap<String, Value>> = credential
            .credential_subjects
            .iter()
            .map(|s| &s.properties)
            .collect();
        let typed = subjects.iter().filter(|p| p.contains_key("type")).count();

        if !declared {
            let has_cawg_identities = subjects.iter().any(|p| {
                p.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t.starts_with("cawg."))
            });
            if has_cawg_identities {
                let problem = format!("credential subjects are CAWG verified identities but type does not include {CAWG_VERIFIED_IDENTITIES_TYPE}");
                log_current_item!(problem.clone(), FN)
                    .validation_status(codes::INVALID_VERIFIABLE_CREDENTIAL)
                    .failure(
                        status_tracker,
                        ValidationError::SignatureError(VcbValidationError::InvalidCredential(
                            problem,
                        )),
                    )?;
                return Ok((false, Vec::new()));
            }
            return Ok((true, Vec::new()));
        }

        if typed == 0 {
            log_current_item!("Credential has no verified identities", FN)
                .validation_status(codes::VERIFIED_IDENTITIES_MISSING)
                .failure(
                    status_tracker,
                    ValidationError::SignatureError(VcbValidationError::VerifiedIdentitiesMissing),
                )?;
            return Ok((false, Vec::new()));
        }

        let mut identities = Vec::new();
        let mut problems = Vec::new();
        for (index, properties) in subjects.into_iter().enumerate() {
            let object = properties.clone().into_iter().collect();
            match serde_json::from_value::<VcbVerifiedIdentity>(Value::Object(object))
                .map_err(|e| e.to_string())
                .and_then(|identity| identity.check_type_requirements().map(|()| identity))
            {
                Ok(identity) => identities.push(identity),
                Err(problem) => problems.push(format!("credentialSubject[{index}]: {problem}")),
            }
        }

        if problems.is_empty() {
            return Ok((true, identities));
        }

        // C2PA status codes can't point at one entry, so the message lists them.
        let problem = problems.join("; ");
        log_current_item!(format!("Invalid verified identity: {problem}"), FN)
            .validation_status(codes::VERIFIED_IDENTITIES_INVALID)
            .failure(
                status_tracker,
                ValidationError::SignatureError(VcbValidationError::VerifiedIdentityInvalid(
                    problem,
                )),
            )?;
        Ok((false, identities))
    }
}

/// The `DynamicAssertion` mechanism doesn't always fill in a referenced
/// assertion's `alg` when offering the partial claim for signature, while
/// signers often do. As for identity claims aggregation, accept the
/// credential's `alg` for an entry whose `signer_payload` `alg` is missing.
fn fill_missing_algs(expected: &mut Value, actual: &Value) {
    let (Some(expected), Some(actual)) = (
        expected
            .get_mut("referencedAssertions")
            .and_then(Value::as_array_mut),
        actual.get("referencedAssertions").and_then(Value::as_array),
    ) else {
        return;
    };

    for (e, a) in expected.iter_mut().zip(actual) {
        if let (Some(e), Some(alg)) = (e.as_object_mut(), a.get("alg")) {
            e.entry("alg").or_insert_with(|| alg.clone());
        }
    }
}
