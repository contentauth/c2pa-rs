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

use std::fmt::Debug;

use crate::identity::{
    claim_aggregation::w3c_vc::{did::InvalidDid, did_web::DidWebError},
    ValidationError,
};

/// Describes the ways in which a CAWG verifiable credential binding can fail
/// validation.
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum VcbValidationError {
    /// The `signature` value could not be decoded as a tagged `COSE_Sign1`.
    #[error("COSE decoding error ({0})")]
    CoseDecodeError(String),

    /// The `COSE_Sign1` protected header names an unsupported algorithm.
    #[error("unsupported COSE signature algorithm ({0})")]
    UnsupportedSignatureType(String),

    /// The `COSE_Sign1` protected header has no `alg` entry.
    #[error("COSE signature did not specify a signature algorithm")]
    SignatureTypeMissing,

    /// The `COSE_Sign1` protected header names an unsupported content type.
    #[error("unsupported COSE content type ({0})")]
    UnsupportedContentType(String),

    /// The `COSE_Sign1` protected header has no content type.
    #[error("COSE signature did not specify a content type")]
    ContentTypeMissing,

    /// The outermost credential is a verifiable presentation, which this
    /// implementation does not yet support.
    #[error("verifiable presentations are not yet supported")]
    PresentationNotSupported,

    /// The `COSE_Sign1` structure has no payload.
    #[error("COSE signature did not include the credential payload")]
    CredentialPayloadMissing,

    /// The payload is not a valid verifiable credential.
    #[error("JSON decoding error ({0})")]
    JsonDecodeError(String),

    /// The credential does not meet the verifiable credential binding
    /// requirements for `@context`, `type` or `termsOfUse`.
    #[error("invalid verifiable credential binding ({0})")]
    InvalidCredential(String),

    /// The `issuer` is not a valid DID.
    #[error("invalid issuer DID ({0})")]
    InvalidIssuerDid(String),

    /// The issuer DID uses a DID method that this implementation can't resolve.
    #[error("unsupported issuer DID method ({0})")]
    UnsupportedDidMethod(String),

    /// The issuer DID could not be resolved.
    #[error("DID could not be resolved ({0})")]
    DidResolutionError(String),

    /// The issuer's DID document could not be parsed or has no usable key.
    #[error(
        "the DID document could not be parsed or did not contain usable public key material ({0})"
    )]
    InvalidDidDocument(String),

    /// The RFC 3161 time stamp on the `COSE_Sign1` was not valid.
    #[error("the RFC 3161 time stamp was not valid for this credential")]
    InvalidTimeStamp,

    /// The credential has no `validFrom` date.
    #[error("credential does not have a validFrom date")]
    MissingValidFromDate,

    /// The credential's `validFrom` date is unacceptable.
    #[error("credential's validFrom date is unacceptable ({0})")]
    InvalidValidFromDate(String),

    /// The credential's `validUntil` date is unacceptable.
    #[error("credential's validUntil date is unacceptable ({0})")]
    InvalidValidUntilDate(String),

    /// Two `termsOfUse` objects of type `C2PAAssetBinding` give conflicting
    /// values for the same property.
    #[error("conflicting termsOfUse values for {0}")]
    BindingMismatch(String),

    /// The aggregated `termsOfUse` binding does not match `signer_payload`.
    #[error("termsOfUse binding does not match signer_payload")]
    SignerPayloadMismatch,

    /// The credential has type `CAWGVerifiedIdentities` but no usable
    /// `credentialSubject` entries.
    #[error("credential has no verified identities")]
    VerifiedIdentitiesMissing,

    /// One or more `credentialSubject` entries do not meet the verified
    /// identity requirements.
    #[error("invalid verified identity ({0})")]
    VerifiedIdentityInvalid(String),

    /// The credential has a `credentialStatus` entry, which this implementation
    /// does not yet check.
    #[error("credential status (revocation) checking is not supported")]
    RevocationUnsupported,
}

impl From<coset::CoseError> for ValidationError<VcbValidationError> {
    fn from(err: coset::CoseError) -> Self {
        // `coset::CoseError` doesn't implement Eq and other traits we need.
        Self::SignatureError(VcbValidationError::CoseDecodeError(err.to_string()))
    }
}

impl From<serde_json::Error> for ValidationError<VcbValidationError> {
    fn from(err: serde_json::Error) -> Self {
        Self::SignatureError(VcbValidationError::JsonDecodeError(err.to_string()))
    }
}

impl From<InvalidDid> for ValidationError<VcbValidationError> {
    fn from(err: InvalidDid) -> Self {
        Self::SignatureError(VcbValidationError::InvalidIssuerDid(err.to_string()))
    }
}

impl From<DidWebError> for ValidationError<VcbValidationError> {
    fn from(err: DidWebError) -> Self {
        match err {
            DidWebError::Client(_) => Self::InternalError(err.to_string()),
            DidWebError::DidMismatch { .. } => {
                Self::SignatureError(VcbValidationError::InvalidDidDocument(err.to_string()))
            }
            _ => Self::SignatureError(VcbValidationError::DidResolutionError(err.to_string())),
        }
    }
}
