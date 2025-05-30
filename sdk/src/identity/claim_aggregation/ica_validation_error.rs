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

use crate::identity::{
    claim_aggregation::w3c_vc::{did::InvalidDid, did_web::DidWebError},
    ValidationError,
};

/// Describes the ways in which a CAWG identity claims aggregation credential
/// can fail validation.
///
/// Intended to be used as a subtype for [`ValidationError`].
///
/// [`ValidationError`]: crate::identity::ValidationError
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum IcaValidationError {
    /// An error occurred while decoding the COSE credential information.
    #[error("COSE decoding error ({0})")]
    CoseDecodeError(String),

    /// Unsupported signature algorithm.
    #[error("unsupported COSE signature algorithm ({0})")]
    UnsupportedSignatureType(String),

    /// Signature algorithm missing in COSE headers.
    #[error("COSE signature did not specify a signature algorithm")]
    SignatureTypeMissing,

    /// Unsupported content type in COSE signature.
    #[error("unsupported COSE content type ({0})")]
    UnsupportedContentType(String),

    /// Content type missing in COSE headers.
    #[error("COSE signature did not specify a content type")]
    ContentTypeMissing,

    /// Credential payload missing.
    #[error("COSE signature did not include the credential payload")]
    CredentialPayloadMissing,

    /// An error occurred while decoding the JSON verifiable credential data
    /// structure.
    #[error("JSON decoding error ({0})")]
    JsonDecodeError(String),

    /// Unsupported issuer DID.
    #[error("unsupported issuer DID ({0})")]
    UnsupportedIssuerDid(String),

    /// DID could not be resolved (network error, etc.).
    #[error("DID could not be resolved ({0})")]
    DidResolutionError(String),

    /// Invalid issuer DID document.
    #[error(
        "the DID document could not be parsed or did not contain usable public key material ({0})"
    )]
    InvalidDidDocument(String),

    /// RFC 3161 time stamp is invalid.
    #[error("the RFC 3161 time stamp was not valid for this credential")]
    InvalidTimeStamp,

    /// `validFrom` date is missing.
    #[error("credential does not have a validFrom date")]
    MissingValidFromDate,

    /// `validFrom` date is unacceptable. As an example, the `validFrom` date
    /// this is later than the RFC 3161 time stamp for the credential or the
    /// C2PA manifest would be deemed unacceptable.
    #[error("credential's validFrom date is unacceptable ({0})")]
    InvalidValidFromDate(String),

    /// `validUntil` date is unacceptable.
    #[error("credential's validUntil date is unacceptable ({0})")]
    InvalidValidUntilDate(String),

    /// `c2paAsset` does not match `signer_payload`
    #[error("c2paAsset does not match signer_payload")]
    SignerPayloadMismatch,
}

impl From<coset::CoseError> for ValidationError<IcaValidationError> {
    fn from(err: coset::CoseError) -> Self {
        // We capture the string error because `coset::CoseError` doesn't implement Eq
        // and a few other traits that we need.
        Self::SignatureError(IcaValidationError::CoseDecodeError(err.to_string()))
    }
}

impl From<serde_json::Error> for ValidationError<IcaValidationError> {
    fn from(err: serde_json::Error) -> Self {
        // We capture the string error because `serde_json::Error` doesn't implement Eq
        // and a few other traits that we need.
        Self::SignatureError(IcaValidationError::JsonDecodeError(err.to_string()))
    }
}

impl From<InvalidDid> for ValidationError<IcaValidationError> {
    fn from(err: InvalidDid) -> Self {
        Self::SignatureError(IcaValidationError::UnsupportedIssuerDid(err.to_string()))
    }
}

impl From<DidWebError> for ValidationError<IcaValidationError> {
    fn from(err: DidWebError) -> Self {
        match err {
            DidWebError::Client(_) => Self::InternalError(err.to_string()),
            _ => Self::SignatureError(IcaValidationError::DidResolutionError(err.to_string())),
        }
    }
}
