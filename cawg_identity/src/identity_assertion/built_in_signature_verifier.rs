// Copyright 2025 Adobe. All rights reserved.
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

use std::fmt::Debug;

use async_trait::async_trait;
use c2pa_crypto::cose::CoseError;
use c2pa_status_tracker::StatusTracker;
use serde::Serialize;

use crate::{
    claim_aggregation::{
        IcaCredential, IcaCredentialSummary, IcaSignatureVerifier, IcaValidationError,
    },
    x509::{X509SignatureInfo, X509SignatureReport, X509SignatureVerifier},
    SignatureVerifier, SignerPayload, ToCredentialSummary, ValidationError,
};

/// A `BuiltInSignatureVerifier` is an implementation of [`SignatureVerifier`]
/// that can read all of the signature types that are supported by this SDK.
pub struct BuiltInSignatureVerifier {
    /// Configuration to use when an identity claims aggregation credential is
    /// presented.
    pub ica_verifier: IcaSignatureVerifier,

    /// Configuration to use when an X.509 credential is presented.
    pub x509_verifier: X509SignatureVerifier,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureVerifier for BuiltInSignatureVerifier {
    type Error = BuiltInSignatureError;
    type Output = BuiltInCredential;

    async fn check_signature(
        &self,
        signer_payload: &SignerPayload,
        signature: &[u8],
        status_tracker: &mut StatusTracker,
    ) -> Result<Self::Output, ValidationError<Self::Error>> {
        match signer_payload.sig_type.as_str() {
            crate::claim_aggregation::CAWG_ICA_SIG_TYPE => self
                .ica_verifier
                .check_signature(signer_payload, signature, status_tracker)
                .await
                .map(BuiltInCredential::IdentityClaimsAggregationCredential)
                .map_err(map_err_to_built_in),

            crate::x509::CAWG_X509_SIG_TYPE => self
                .x509_verifier
                .check_signature(signer_payload, signature, status_tracker)
                .await
                .map(BuiltInCredential::X509Signature)
                .map_err(map_err_to_built_in),

            sig_type => Err(ValidationError::UnknownSignatureType(sig_type.to_string())),
        }
    }
}

fn map_err_to_built_in<E: Into<BuiltInSignatureError>>(
    err: ValidationError<E>,
) -> ValidationError<BuiltInSignatureError> {
    match err {
        ValidationError::AssertionNotInClaim(s) => ValidationError::AssertionNotInClaim(s),
        ValidationError::AssertionMismatch(s) => ValidationError::AssertionMismatch(s),

        ValidationError::DuplicateAssertionReference(s) => {
            ValidationError::DuplicateAssertionReference(s)
        }

        ValidationError::NoHardBindingAssertion => ValidationError::NoHardBindingAssertion,
        ValidationError::UnknownSignatureType(s) => ValidationError::UnknownSignatureType(s),
        ValidationError::InvalidSignature => ValidationError::InvalidSignature,
        ValidationError::InvalidPadding => ValidationError::InvalidPadding,
        ValidationError::SignatureError(e) => ValidationError::SignatureError(e.into()),
        ValidationError::InternalError(s) => ValidationError::InternalError(s),
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum BuiltInCredential {
    IdentityClaimsAggregationCredential(IcaCredential),
    X509Signature(X509SignatureInfo),
}

impl ToCredentialSummary for BuiltInCredential {
    type CredentialSummary = BuiltInCredentialSummary;

    fn to_summary(&self) -> Self::CredentialSummary {
        match self {
            Self::IdentityClaimsAggregationCredential(ica) => {
                BuiltInCredentialSummary::IcaCredentialSummary(ica.to_summary())
            }
            Self::X509Signature(sig_info) => {
                BuiltInCredentialSummary::X509CredentialSummary(sig_info.to_summary())
            }
        }
    }
}

#[non_exhaustive]
pub enum BuiltInCredentialSummary {
    IcaCredentialSummary(IcaCredentialSummary),
    X509CredentialSummary(X509SignatureReport),
}

impl Serialize for BuiltInCredentialSummary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::IcaCredentialSummary(ica) => ica.serialize(serializer),
            Self::X509CredentialSummary(x509) => x509.serialize(serializer),
        }
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum BuiltInSignatureError {
    IcaValidationError(IcaValidationError),
    X509CoseValidationError(CoseError),
}

impl From<IcaValidationError> for BuiltInSignatureError {
    fn from(e: IcaValidationError) -> Self {
        Self::IcaValidationError(e)
    }
}

impl From<CoseError> for BuiltInSignatureError {
    fn from(e: CoseError) -> Self {
        Self::X509CoseValidationError(e)
    }
}
