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

use std::{
    borrow::Cow,
    collections::BTreeMap,
    fmt::{Debug, Formatter},
};

use async_generic::async_generic;
use c2pa_raw_crypto::RawSignatureValidationError;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    context::Context,
    crypto::cose::{parse_cose_sign1, CertificateTrustPolicy, CoseError, Verifier},
    dynamic_assertion::PartialClaim,
    identity::{
        claim_aggregation::IcaSignatureVerifier,
        identity_assertion::{
            report::{
                IdentityAssertionReport, IdentityAssertionsForManifest,
                IdentityAssertionsForManifestStore, SignerPayloadReport,
            },
            signer_payload::SignerPayload,
        },
        internal::debug_byte_slice::DebugByteSlice,
        x509::{X509SignatureInfo, X509StatusRemapGuard},
        SignatureVerifier, ToCredentialSummary, ValidationError,
    },
    jumbf::labels::to_assertion_uri,
    log_current_item, log_item,
    settings::TrustListKind,
    status_tracker::StatusTracker,
    validation_status::{CAWG_X509_SIGNATURE_MISMATCH, CAWG_X509_SIGNATURE_VALIDATED},
    Manifest, Reader,
};

/// This struct represents the raw content of the identity assertion.
///
/// Use [`AsyncIdentityAssertionBuilder`] and -- at your option,
/// [`AsyncIdentityAssertionSigner`] -- to ensure correct construction of a new
/// identity assertion.
///
/// [`AsyncIdentityAssertionBuilder`]: crate::identity::builder::AsyncIdentityAssertionBuilder
/// [`AsyncIdentityAssertionSigner`]: crate::identity::builder::AsyncIdentityAssertionSigner
#[derive(Deserialize, Serialize)]
pub struct IdentityAssertion {
    pub(crate) signer_payload: SignerPayload,

    #[serde(with = "serde_bytes")]
    pub(crate) signature: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pub(crate) pad1: Vec<u8>,

    // Must use explicit ByteBuf here because #[serde(with = "serde_bytes")]
    // does not work with Option<Vec<u8>>.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pad2: Option<ByteBuf>,

    // Label for the assertion. Only assigned when reading from a manifest.
    #[serde(skip)]
    pub(crate) label: Option<String>,
}

#[allow(unused)] // TEMPORARY while considering API simplification
impl IdentityAssertion {
    /// Find the `IdentityAssertion`s that may be present in a given
    /// [`Manifest`].
    ///
    /// Iterator returns a [`Result`] because each assertion may fail to parse.
    ///
    /// Aside from CBOR parsing, no further validation is performed.
    pub(crate) fn from_manifest<'a>(
        manifest: &'a Manifest,
        status_tracker: &'a mut StatusTracker,
    ) -> impl Iterator<Item = Result<Self, crate::Error>> + use<'a> {
        manifest
            .assertions()
            .iter()
            .filter(|a| a.label() == "cawg.identity" || a.label().starts_with("cawg.identity__"))
            .map(|a| {
                let mut ia: Result<Self, crate::Error> = a.to_assertion();
                if let Ok(ref mut ia) = ia {
                    if let Some(manifest_label) = manifest.label() {
                        ia.label = Some(to_assertion_uri(manifest_label, a.label()));
                    }
                }
                // TO DO: Add error readout if the proposed new setting resulted
                // in this assertion being parsed and converted to JSON. This function
                // has become incompatible with the now-default behavior to validate
                // identity assertions during parsing. This applies only if this API
                // becomes public again.
                (a.label().to_owned(), ia)
            })
            .inspect(|(label, r)| {
                let mut label = label.to_owned();
                if let Err(err) = r {
                    if let Some(manifest_label) = manifest.label() {
                        label = to_assertion_uri(manifest_label, &label);
                    }

                    log_item!(label, "invalid CBOR", "IdentityAssertion::from_manifest")
                        .validation_status("cawg.identity.cbor.invalid")
                        .failure_no_throw(
                            status_tracker,
                            crate::Error::AssertionSpecificError(err.to_string()),
                        );
                }
            })
            .map(move |(_label, r)| r)
    }

    /// Create a summary report from this `IdentityAssertion`.
    ///
    /// This will [`validate`] the assertion and then render the result as
    /// an opaque [`Serialize`]-able struct that describes the decoded content
    /// of the identity assertion.
    ///
    /// [`validate`]: Self::validate
    pub(crate) async fn to_summary<SV: SignatureVerifier>(
        &self,
        manifest: &Manifest,
        status_tracker: &mut StatusTracker,
        verifier: &SV,
    ) -> impl Serialize
    where
        <SV as SignatureVerifier>::Output: 'static,
    {
        self.to_summary_impl(manifest, status_tracker, verifier)
            .await
    }

    pub(crate) async fn to_summary_impl<SV: SignatureVerifier>(
        &self,
        manifest: &Manifest,
        status_tracker: &mut StatusTracker,
        verifier: &SV,
    ) -> IdentityAssertionReport<
        <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
    >
    where
        <SV as SignatureVerifier>::Output: 'static,
    {
        match self.validate(manifest, status_tracker, verifier).await {
            Ok(named_actor) => {
                let summary = named_actor.to_summary();

                IdentityAssertionReport {
                    signer_payload: SignerPayloadReport::from_signer_payload(&self.signer_payload),
                    named_actor: Some(summary),
                }
            }

            Err(_err) => {
                todo!("Handle summary report for failure case");
            }
        }
    }

    /// Summarize all of the identity assertions found for a [`Manifest`].
    pub(crate) async fn summarize_all<SV: SignatureVerifier>(
        manifest: &Manifest,
        status_tracker: &mut StatusTracker,
        verifier: &SV,
    ) -> impl Serialize {
        Self::summarize_all_impl(manifest, status_tracker, verifier).await
    }

    pub(crate) async fn summarize_all_impl<SV: SignatureVerifier>(
        manifest: &Manifest,
        status_tracker: &mut StatusTracker,
        verifier: &SV,
    ) -> IdentityAssertionsForManifest<
        <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
    > {
        // NOTE: We can't write this using .map(...).collect() because there are async
        // calls.
        let mut reports: Vec<
            IdentityAssertionReport<
                <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
            >,
        > = vec![];

        let assertion_results: Vec<Result<IdentityAssertion, crate::Error>> =
            Self::from_manifest(manifest, status_tracker).collect();

        for assertion in assertion_results {
            let report = match assertion {
                Ok(assertion) => {
                    assertion
                        .to_summary_impl(manifest, status_tracker, verifier)
                        .await
                }
                Err(_) => {
                    todo!("Handle assertion failed to parse case");
                }
            };

            reports.push(report);
        }

        IdentityAssertionsForManifest::<
            <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
        > {
            assertion_reports: reports,
        }
    }

    /// Summarize all of the identity assertions found for a [`Reader`].
    pub(crate) async fn summarize_from_reader<SV: SignatureVerifier>(
        reader: &Reader,
        status_tracker: &mut StatusTracker,
        verifier: &SV,
    ) -> impl Serialize {
        // NOTE: We can't write this using .map(...).collect() because there are async
        // calls.
        let mut reports: BTreeMap<
            String,
            IdentityAssertionsForManifest<
                <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
            >,
        > = BTreeMap::new();

        for (id, manifest) in reader.manifests() {
            let report = Self::summarize_all_impl(manifest, status_tracker, verifier).await;
            reports.insert(id.clone(), report);
        }

        IdentityAssertionsForManifestStore::<
            <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
        > {
            assertions_for_manifest: reports,
        }
    }

    /// Using the provided [`SignatureVerifier`], check the validity of this
    /// identity assertion.
    ///
    /// If successful, returns the credential-type specific information that can
    /// be derived from the signature. This is the [`SignatureVerifier::Output`]
    /// type which typically describes the named actor, but may also contain
    /// information about the time of signing or the credential's source.
    pub(crate) async fn validate<SV: SignatureVerifier>(
        &self,
        manifest: &Manifest,
        status_tracker: &mut StatusTracker,
        verifier: &SV,
    ) -> Result<SV::Output, ValidationError<SV::Error>> {
        if let Some(ref label) = self.label {
            status_tracker.push_current_uri(label);
        }

        let result = self.validate_imp(manifest, status_tracker, verifier).await;

        if self.label.is_some() {
            status_tracker.pop_current_uri();
        }

        result
    }

    async fn validate_imp<SV: SignatureVerifier>(
        &self,
        manifest: &Manifest,
        status_tracker: &mut StatusTracker,
        verifier: &SV,
    ) -> Result<SV::Output, ValidationError<SV::Error>> {
        self.check_padding(status_tracker)?;

        self.signer_payload
            .check_against_manifest(manifest, status_tracker)?;

        verifier
            .check_signature_async(&self.signer_payload, &self.signature, status_tracker)
            .await
    }

    /// Validate this identity assertion against a list of claim assertion URIs.
    ///
    /// Accepts a plain slice of [`HashedUri`]s so callers do not need to
    /// construct the internal [`PartialClaim`] type.
    ///
    /// The sync variant (`validate_partial_claim`) handles `cawg.x509.cose`
    /// fully; other signature types that require network I/O (e.g.
    /// `cawg.identity_claims_aggregation`) are skipped with an informational
    /// log entry and return `None` from the caller's perspective.
    ///
    /// The async variant (`validate_partial_claim_async`) handles all known
    /// signature types.
    #[async_generic]
    pub(crate) fn validate_partial_claim(
        &self,
        partial_claim: &PartialClaim,
        status_tracker: &mut StatusTracker,
        context: &Context,
    ) -> Result<serde_json::Value, ValidationError<String>> {
        let settings = context.settings();
        self.check_padding(status_tracker)?;

        self.signer_payload
            .check_against_partial_claim(partial_claim, status_tracker)?;

        let sig_type = self.signer_payload.sig_type.as_str();

        if sig_type == "cawg.x509.cose" {
            let mut ctp = CertificateTrustPolicy::default();

            // Load the trust handler settings. Don't worry about status as these
            // are checked during setting generation.

            let cose_verifier = if settings.trust.verify_trust_list {
                if let Some(anchors) = &settings.trust.anchors_for_trust_kind(TrustListKind::CAWG) {
                    for anchor in anchors {
                        let _ = ctp.add_trust_anchors(
                            anchor.trust_anchors.as_bytes(),
                            anchor.trust_uri.as_deref().unwrap_or(""),
                            anchor.trust_kind.clone().into(),
                            anchor.trust_config.clone(),
                        );

                        if let Some(al) = &anchor.allowed_list {
                            let _ = ctp.add_end_entity_credentials(al.as_bytes());
                        }
                    }
                }
                Verifier::VerifyTrustPolicy(Cow::Owned(ctp))
            } else {
                Verifier::IgnoreProfileAndTrustPolicy
            };

            let mut signer_payload_cbor: Vec<u8> = vec![];
            c2pa_cbor::to_writer(&mut signer_payload_cbor, &self.signer_payload).map_err(|_| {
                ValidationError::InternalError("CBOR serialization error".to_string())
            })?;

            let signature_result = {
                let mut remap_guard = X509StatusRemapGuard::new(status_tracker);
                let status_tracker = remap_guard.status_tracker();

                match parse_cose_sign1(&self.signature, &signer_payload_cbor, status_tracker) {
                    Ok(cose_sign1) => {
                        let verify_result = if _sync {
                            cose_verifier.verify_signature(
                                &self.signature,
                                &signer_payload_cbor,
                                &[],
                                None,
                                status_tracker,
                            )
                        } else {
                            cose_verifier
                                .verify_signature_async(
                                    &self.signature,
                                    &signer_payload_cbor,
                                    &[],
                                    None,
                                    status_tracker,
                                )
                                .await
                        };

                        verify_result
                            .map(|cert_info| (cose_sign1, cert_info))
                            .map_err(|e| match e {
                                CoseError::RawSignatureValidationError(
                                    RawSignatureValidationError::SignatureMismatch,
                                ) => {
                                    log_current_item!(
                                        "signature mismatch",
                                        "validate_partial_claim"
                                    )
                                    .validation_status(CAWG_X509_SIGNATURE_MISMATCH)
                                    .failure_no_throw(
                                        status_tracker,
                                        ValidationError::<String>::SignatureMismatch,
                                    );

                                    ValidationError::SignatureMismatch
                                }

                                e => ValidationError::SignatureError(e.to_string()),
                            })
                    }

                    Err(e) => Err(ValidationError::SignatureError(e.to_string())),
                }
            }; // `remap_guard` drops here, remapping the codes logged above.

            let (cose_sign1, cert_info) = signature_result?;

            log_current_item!(
                "X.509 identity assertion signature validated",
                "validate_partial_claim"
            )
            .validation_status(CAWG_X509_SIGNATURE_VALIDATED)
            .success(status_tracker);

            let info = X509SignatureInfo {
                signer_payload: self.signer_payload.clone(),
                cose_sign1,
                cert_info,
            };
            let result = info.to_summary();

            log_current_item!(
                "CAWG X.509 identity signature valid",
                "validate_partial_claim"
            )
            .validation_status("cawg.identity.well-formed")
            .success(status_tracker);
            // TO DO (CAI-7980): Should instead issue `cawg.identity.trusted` if the
            // signing cert is found on a configured trust list.

            serde_json::to_value(result)
                .map_err(|e| ValidationError::UnknownSignatureType(e.to_string()))
        } else if sig_type == "cawg.identity_claims_aggregation" {
            let verifier = IcaSignatureVerifier::new(context);

            let result = if _sync {
                verifier
                    .check_signature(&self.signer_payload, &self.signature, status_tracker)
                    .map(|v| v.to_summary())
                    .map_err(|e| ValidationError::UnknownSignatureType(e.to_string()))
            } else {
                verifier
                    .check_signature_async(&self.signer_payload, &self.signature, status_tracker)
                    .await
                    .map(|v| v.to_summary())
                    .map_err(|e| ValidationError::UnknownSignatureType(e.to_string()))
            }?;

            // NOTE: The `cawg.ica.credential_valid` success code is issued by
            // `IcaSignatureVerifier::check_signature` itself, and only when the
            // credential is valid and its issuer is trusted (i.e. no
            // `cawg.ica.untrusted_issuer` notice was generated). We must not issue
            // it again here, or an untrusted issuer would be reported as valid.

            serde_json::to_value(result)
                .map_err(|e| ValidationError::UnknownSignatureType(e.to_string()))
        } else {
            Err(ValidationError::UnknownSignatureType(sig_type.to_string()))
        }
    }

    fn check_padding<E: Debug>(
        &self,
        status_tracker: &mut StatusTracker,
    ) -> Result<(), ValidationError<E>> {
        if !self.pad1.iter().all(|b| *b == 0) {
            log_current_item!(
                "invalid value in pad fields",
                "SignerPayload::check_padding"
            )
            .validation_status("cawg.identity.pad.invalid")
            .failure(status_tracker, ValidationError::<E>::InvalidPadding)?;

            // We'll only get to this line if `pad1` is invalid and the status tracker is
            // configured to continue through recoverable errors. In that case, we want to
            // avoid logging a second "invalid padding" warning if `pad2` is also invalid.
            return Ok(());
        }

        if let Some(pad2) = self.pad2.as_ref() {
            if !pad2.iter().all(|b| *b == 0) {
                log_current_item!(
                    "invalid value in pad fields",
                    "SignerPayload::check_padding"
                )
                .validation_status("cawg.identity.pad.invalid")
                .failure(status_tracker, ValidationError::<E>::InvalidPadding)?;
            }
        }

        Ok(())
    }

    /// TO DO: Docs
    pub fn signer_payload(&self) -> &SignerPayload {
        &self.signer_payload
    }
}

impl Debug for IdentityAssertion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("IdentityAssertion")
            .field("signer_payload", &self.signer_payload)
            .field("signature", &DebugByteSlice(&self.signature))
            .field("label", &self.label)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        dynamic_assertion::PartialClaim,
        identity::{
            builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
            tests::{
                fixtures::{cert_chain_and_private_key_for_alg, manifest_json, parent_json},
                read_manifest,
            },
            x509::X509CredentialHolder,
        },
        Builder, SigningAlg,
    };

    const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
    const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

    #[c2pa_test_async]
    async fn x509_signature_mismatch_is_reported() {
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

        let mut c2pa_signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

        let (cawg_cert_chain, cawg_private_key) =
            cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

        let cawg_raw_signer =
            c2pa_raw_crypto::signer_from_private_key(&cawg_private_key, SigningAlg::Ed25519)
                .unwrap();

        let x509_holder = X509CredentialHolder::from_raw_signer(
            cawg_raw_signer,
            crate::crypto::cert_chain_pem_to_der(&cawg_cert_chain).unwrap(),
        );
        let iab = IdentityAssertionBuilder::for_credential_holder(x509_holder);
        c2pa_signer.add_identity_assertion(iab);

        builder
            .sign(&c2pa_signer, format, &mut source, &mut dest)
            .unwrap();

        // Read back the Manifest that was generated.
        dest.rewind().unwrap();

        let manifest_store = read_manifest(format, &mut dest).await;
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        // Should find exactly one identity assertion.
        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        let mut partial_claim = PartialClaim::default();
        for referenced_assertion in &ia.signer_payload.referenced_assertions {
            partial_claim.add_assertion(referenced_assertion);
        }

        // Tamper with the signer payload (leaving the original signature bytes
        // untouched) so that the COSE signature no longer matches. This is a
        // syntactically valid `SignerPayload`, so it exercises a genuine
        // cryptographic mismatch -- through the production `validate_partial_claim`
        // path used during normal manifest reading -- rather than a CBOR parsing
        // failure.
        let mut tampered_signer_payload = ia.signer_payload.clone();
        tampered_signer_payload.roles.push("tampered".to_string());

        let tampered_ia = IdentityAssertion {
            signer_payload: tampered_signer_payload,
            signature: ia.signature.clone(),
            pad1: ia.pad1.clone(),
            pad2: ia.pad2.clone(),
            label: None,
        };

        let context = Context::new();
        let err = tampered_ia
            .validate_partial_claim_async(&partial_claim, &mut st, &context)
            .await
            .unwrap_err();

        assert_eq!(err.to_string(), "signature is invalid");

        let log = st
            .logged_items()
            .iter()
            .find(|item| item.description == "signature mismatch")
            .unwrap();

        assert_eq!(log.kind, crate::status_tracker::LogKind::Failure);
        assert_eq!(
            log.validation_status.as_ref().unwrap().as_ref() as &str,
            CAWG_X509_SIGNATURE_MISMATCH
        );

        // Signature bytes that don't even parse as a COSE_Sign1 structure are a
        // different Rust error variant (`SignatureError`, not
        // `SignatureMismatch`) from the cryptographic mismatch above, but the
        // CAWG spec reports both under the same status code -- see the longer
        // comment in x509_signature_verifier.rs's equivalent test.
        let malformed_ia = IdentityAssertion {
            signer_payload: ia.signer_payload.clone(),
            signature: b"not a COSE_Sign1 structure".to_vec(),
            pad1: ia.pad1.clone(),
            pad2: ia.pad2.clone(),
            label: None,
        };

        let mut malformed_st = StatusTracker::default();
        let malformed_err = malformed_ia
            .validate_partial_claim_async(&partial_claim, &mut malformed_st, &context)
            .await
            .unwrap_err();

        assert!(matches!(malformed_err, ValidationError::SignatureError(_)));

        assert!(malformed_st.has_status(CAWG_X509_SIGNATURE_MISMATCH));
    }
}
