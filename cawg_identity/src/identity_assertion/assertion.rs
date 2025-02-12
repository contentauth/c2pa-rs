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
    collections::HashMap,
    fmt::{Debug, Formatter},
};

use c2pa::{Manifest, Reader};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    identity_assertion::{
        report::{
            IdentityAssertionReport, IdentityAssertionsForManifest,
            IdentityAssertionsForManifestStore, SignerPayloadReport,
        },
        signer_payload::SignerPayload,
    },
    internal::debug_byte_slice::DebugByteSlice,
    SignatureVerifier, ToCredentialSummary, ValidationError,
};

/// This struct represents the raw content of the identity assertion.
///
/// Use [`AsyncIdentityAssertionBuilder`] and -- at your option,
/// [`AsyncIdentityAssertionSigner`] -- to ensure correct construction of a new
/// identity assertion.
///
/// [`AsyncIdentityAssertionBuilder`]: crate::builder::AsyncIdentityAssertionBuilder
/// [`AsyncIdentityAssertionSigner`]: crate::builder::AsyncIdentityAssertionSigner
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
}

impl IdentityAssertion {
    /// Find the `IdentityAssertion`s that may be present in a given
    /// [`Manifest`].
    ///
    /// Iterator returns a [`Result`] because each assertion may fail to parse.
    ///
    /// Aside from CBOR parsing, no further validation is performed.
    pub fn from_manifest(
        manifest: &Manifest,
    ) -> impl Iterator<Item = Result<Self, c2pa::Error>> + use<'_> {
        manifest
            .assertions()
            .iter()
            .filter(|a| a.label().starts_with("cawg.identity"))
            .map(|a| a.to_assertion())
    }

    /// Create a summary report from this `IdentityAssertion`.
    ///
    /// This will [`validate`] the assertion and then render the result as
    /// an opaque [`Serialize`]-able struct that describes the decoded content
    /// of the identity assertion.
    ///
    /// [`validate`]: Self::validate
    pub async fn to_summary<SV: SignatureVerifier>(
        &self,
        manifest: &Manifest,
        verifier: &SV,
    ) -> impl Serialize
    where
        <SV as SignatureVerifier>::Output: 'static,
    {
        self.to_summary_impl(manifest, verifier).await
    }

    pub(crate) async fn to_summary_impl<SV: SignatureVerifier>(
        &self,
        manifest: &Manifest,
        verifier: &SV,
    ) -> IdentityAssertionReport<
        <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
    >
    where
        <SV as SignatureVerifier>::Output: 'static,
    {
        match self.validate(manifest, verifier).await {
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
    pub async fn summarize_all<SV: SignatureVerifier>(
        manifest: &Manifest,
        verifier: &SV,
    ) -> impl Serialize {
        Self::summarize_all_impl(manifest, verifier).await
    }

    pub(crate) async fn summarize_all_impl<SV: SignatureVerifier>(
        manifest: &Manifest,
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

        for assertion in Self::from_manifest(manifest) {
            let report = match assertion {
                Ok(assertion) => assertion.to_summary_impl(manifest, verifier).await,
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

    /// Summarize all of the identity assertions found for a [`ManifestStore`].
    ///
    /// [`ManifestStore`]: c2pa::ManifestStore
    #[cfg(feature = "v1_api")]
    pub async fn summarize_manifest_store<SV: SignatureVerifier>(
        store: &c2pa::ManifestStore,
        verifier: &SV,
    ) -> impl Serialize {
        // NOTE: We can't write this using .map(...).collect() because there are async
        // calls.
        let mut reports: HashMap<
            String,
            IdentityAssertionsForManifest<
                <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
            >,
        > = HashMap::new();

        for (id, manifest) in store.manifests() {
            let report = Self::summarize_all_impl(manifest, verifier).await;
            reports.insert(id.clone(), report);
        }

        IdentityAssertionsForManifestStore::<
            <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
        > {
            assertions_for_manifest: reports,
        }
    }

    /// Summarize all of the identity assertions found for a [`Reader`].
    pub async fn summarize_from_reader<SV: SignatureVerifier>(
        reader: &Reader,
        verifier: &SV,
    ) -> impl Serialize {
        // NOTE: We can't write this using .map(...).collect() because there are async
        // calls.
        let mut reports: HashMap<
            String,
            IdentityAssertionsForManifest<
                <<SV as SignatureVerifier>::Output as ToCredentialSummary>::CredentialSummary,
            >,
        > = HashMap::new();

        for manifest in reader.iter_manifests() {
            let report = Self::summarize_all_impl(manifest, verifier).await;

            // TO DO: What to do if manifest doesn't have a label?
            if let Some(label) = manifest.label() {
                reports.insert(label.to_owned(), report);
            }
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
    pub async fn validate<SV: SignatureVerifier>(
        &self,
        manifest: &Manifest,
        verifier: &SV,
    ) -> Result<SV::Output, ValidationError<SV::Error>> {
        self.check_padding()?;

        self.signer_payload.check_against_manifest(manifest)?;

        verifier
            .check_signature(&self.signer_payload, &self.signature)
            .await
    }

    fn check_padding<E>(&self) -> Result<(), ValidationError<E>> {
        if !self.pad1.iter().all(|b| *b == 0) {
            return Err(ValidationError::InvalidPadding);
        }

        if let Some(pad2) = self.pad2.as_ref() {
            if !pad2.iter().all(|b| *b == 0) {
                return Err(ValidationError::InvalidPadding);
            }
        }

        Ok(())
    }
}

impl Debug for IdentityAssertion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("IdentityAssertion")
            .field("signer_payload", &self.signer_payload)
            .field("signature", &DebugByteSlice(&self.signature))
            .finish()
    }
}
