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

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    crypto::cose::{CertificateTrustPolicy, Verifier},
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
        x509::X509SignatureVerifier,
        SignatureVerifier, ToCredentialSummary, ValidationError,
    },
    jumbf::labels::to_assertion_uri,
    log_current_item, log_item,
    status_tracker::StatusTracker,
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
            .check_signature(&self.signer_payload, &self.signature, status_tracker)
            .await
    }

    /// Using the provided [`SignatureVerifier`], check the validity of this
    /// identity assertion.
    ///
    /// If successful, returns the credential-type specific information that can
    /// be derived from the signature. This is the [`SignatureVerifier::Output`]
    /// type which typically describes the named actor, but may also contain
    /// information about the time of signing or the credential's source.
    pub(crate) async fn validate_partial_claim(
        &self,
        partial_claim: &PartialClaim,
        status_tracker: &mut StatusTracker,
    ) -> Result<serde_json::Value, ValidationError<String>> {
        let settings = crate::settings::get_settings().unwrap_or_default();
        self.check_padding(status_tracker)?;

        self.signer_payload
            .check_against_partial_claim(partial_claim, status_tracker)?;

        let sig_type = self.signer_payload.sig_type.as_str();

        if sig_type == "cawg.x509.cose" {
            let mut ctp = CertificateTrustPolicy::default();

            // Load the trust handler settings. Don't worry about status as these
            // are checked during setting generation.

            let cose_verifier = if settings.cawg_trust.verify_trust_list {
                if let Some(ta) = settings.cawg_trust.trust_anchors {
                    let _ = ctp.add_trust_anchors(ta.as_bytes());
                }

                if let Some(pa) = settings.cawg_trust.user_anchors {
                    let _ = ctp.add_user_trust_anchors(pa.as_bytes());
                }

                if let Some(tc) = settings.cawg_trust.trust_config {
                    ctp.add_valid_ekus(tc.as_bytes());
                }

                if let Some(al) = settings.cawg_trust.allowed_list {
                    let _ = ctp.add_end_entity_credentials(al.as_bytes());
                }

                Verifier::VerifyTrustPolicy(Cow::Owned(ctp))
            } else {
                Verifier::IgnoreProfileAndTrustPolicy
            };

            let verifier = X509SignatureVerifier { cose_verifier };

            let result = verifier
                .check_signature(&self.signer_payload, &self.signature, status_tracker)
                .await
                .map(|v| v.to_summary())
                .map_err(|e| ValidationError::UnknownSignatureType(e.to_string()))?;

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
            let verifier = IcaSignatureVerifier {};

            let result = verifier
                .check_signature(&self.signer_payload, &self.signature, status_tracker)
                .await
                .map(|v| v.to_summary())
                .map_err(|e| ValidationError::UnknownSignatureType(e.to_string()))?;
            log_current_item!(
                "CAWG identity_claims_aggregation signature valid",
                "validate_partial_claim"
            )
            .validation_status("cawg.ica.credential_valid")
            .success(status_tracker);

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
