// Copyright 2022 Adobe. All rights reserved.
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

// #![deny(missing_docs)] (we'll turn this on once fully documented)

use thiserror::Error;
use std::string::FromUtf8Error;
use zip::result::ZipError;

use crate::crypto::{cose::CoseError, raw_signature::RawSignerError, time_stamp::TimeStampError};

/// `Error` enumerates errors returned by most C2PA toolkit operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    // --- c2pa errors ---
    /// Could not find a claim with this label.
    #[error("claim missing: label = {label}")]
    ClaimMissing { label: String },

    /// An assertion has an unsupported version
    #[error("Unsupported Assertion version")]
    AssertionUnsupportedVersion,

    /// An assertion could not be found at the expected URL.
    #[error("assertion missing: url = {url}")]
    AssertionMissing { url: String },

    /// The attempt to serialize the assertion (typically to JSON or CBOR) failed.
    #[error("unable to encode assertion data")]
    AssertionEncoding(String),

    #[error(transparent)]
    AssertionDecoding(#[from] crate::assertion::AssertionDecodeError),

    #[error("assertion could not be redacted")]
    AssertionInvalidRedaction,

    #[error("could not find the assertion to redact")]
    AssertionRedactionNotFound,

    #[error("assertion-specific error: {0}")]
    AssertionSpecificError(String),

    #[error("bad parameter: {0}")]
    BadParam(String),

    #[error("required feature missing")]
    MissingFeature(String),

    #[error("feature implementation incomplete")]
    NotImplemented(String),

    /// The attempt to serialize the claim to CBOR failed.
    #[error("claim could not be converted to CBOR")]
    ClaimEncoding,

    /// The attempt to deserialize the claim from CBOR failed.
    #[error("claim could not be converted from CBOR")]
    ClaimDecoding,

    #[error("claim already signed, no further changes allowed")]
    ClaimAlreadySigned,

    #[error("attempt to add new claim without signing last claim")]
    ClaimUnsigned,

    #[error("missing signature box link")]
    ClaimMissingSignatureBox,

    #[error("identity required required with copyright assertion")]
    ClaimMissingIdentity,

    #[error("incompatible claim version")]
    ClaimVersion,

    #[error("invalid claim content")]
    ClaimInvalidContent,

    #[error("claim missing hard binding")]
    ClaimMissingHardBinding,

    #[error("claim contains multiple hard bindings")]
    ClaimMultipleHardBinding,

    #[error("claim contains self redactions")]
    ClaimSelfRedact,

    #[error("claim contains disallowed redactions")]
    ClaimDisallowedRedaction,

    #[error("update manifest is invalid")]
    UpdateManifestInvalid,

    #[error("more than one manifest store detected")]
    TooManyManifestStores,

    /// The COSE Sign1 structure can not be parsed.
    #[error("COSE Sign1 structure can not be parsed: {coset_error}")]
    InvalidCoseSignature {
        coset_error: coset::CoseError, /* NOTE: We can not use #[transparent] here because
                                        * coset::CoseError does not implement std::Error::error
                                        * and can't because coset is nostd. */
    },

    /// The COSE signature uses an algorithm that is not supported by this crate.
    #[error("COSE signature algorithm is not supported")]
    CoseSignatureAlgorithmNotSupported,

    #[error("COSE could not find verification key")]
    CoseMissingKey,

    /// The COSE signature did not contain a signing certificate.
    #[error("could not find signing certificate chain in COSE signature")]
    CoseX5ChainMissing,

    #[error("COSE error parsing certificate")]
    CoseInvalidCert,

    #[error("COSE signature invalid")]
    CoseSignature,

    #[error("COSE verifier failure")]
    CoseVerifier,

    #[error("COSE certificate has expired")]
    CoseCertExpiration,

    #[error("COSE certificate has been revoked")]
    CoseCertRevoked,

    #[error("COSE certificate not trusted")]
    CoseCertUntrusted,

    /// Unable to parse the time stamp from this signature.
    #[error("COSE time stamp could not be parsed")]
    CoseInvalidTimeStamp,

    #[error("COSE time stamp had expired cert")]
    CoseTimeStampValidity,

    /// The time stamp in the signature did not match the signed data.
    #[error("COSE time stamp does not match data")]
    CoseTimeStampMismatch,

    /// Unable to generate a trusted time stamp.
    #[error("could not generate a trusted time stamp")]
    CoseTimeStampGeneration,

    #[error("COSE TimeStamp Authority failure")]
    CoseTimeStampAuthority,

    #[error("COSE Signature too big for JUMBF box")]
    CoseSigboxTooSmall,

    #[error("COSE Signer does not contain signing certificate")]
    CoseNoCerts,

    #[error("WASM verifier error")]
    WasmVerifier,

    #[error("WASM RSA-PSS key import error: {0}")]
    WasmRsaKeyImport(String),

    #[error("WASM RSA-PSS verification error")]
    WasmRsaVerification,

    #[error("WASM crypto key error")]
    WasmKey,

    #[error("WASM not called from window or worker global scope")]
    WasmInvalidContext,

    #[error("WASM could not load crypto library")]
    WasmNoCrypto,

    /// Unable to generate valid JUMBF for a claim.
    #[error("could not create valid JUMBF for claim")]
    JumbfCreationError,

    #[error("thread receive error")]
    ThreadReceiveError,

    #[error("no JUMBF data found")]
    JumbfNotFound,

    #[error("required JUMBF box not found")]
    JumbfBoxNotFound,

    #[error("could not fetch the remote manifest {0}")]
    RemoteManifestFetch(String),

    #[error("must fetch remote manifests from url {0}")]
    RemoteManifestUrl(String),

    #[error("stopped because of logged error")]
    LogStop,

    #[error("not found")]
    NotFound,

    #[error("type is unsupported")]
    UnsupportedType,

    #[error("embedding error")]
    EmbeddingError,

    // Working claim errors
    #[error("ingredient file not found")]
    IngredientNotFound,

    #[error("file not found: {0}")]
    FileNotFound(String),

    #[error("resource not found: {0}")]
    ResourceNotFound(String),

    #[error("XMP read error")]
    XmpReadError(String),

    #[error("XMP write error")]
    XmpWriteError(String),

    #[error("XMP is not supported")]
    XmpNotSupported,

    #[error("C2PA provenance not found in XMP")]
    ProvenanceMissing,

    #[error("hash verification( {0} )")]
    HashMismatch(String),

    #[error("claim verification failure: {0}")]
    ClaimVerification(String),

    #[error("PDF read error")]
    PdfReadError,

    #[error(transparent)]
    InvalidClaim(#[from] crate::store::InvalidClaimError),

    #[error("asset could not be parsed: {0}")]
    InvalidAsset(String),

    #[error(transparent)]
    JumbfParseError(#[from] crate::jumbf::boxes::JumbfParseError),

    #[error("The Verifiable Content structure is not valid")]
    VerifiableCredentialInvalid,

    /// Could not parse ECDSA signature. (Only appears when using WASM web crypto.)
    #[error("could not parse ECDSA signature")]
    InvalidEcdsaSignature,

    #[error("missing data box")]
    MissingDataBox,

    #[error("could not generate XML")]
    XmlWriteError,

    #[error("unknown algorithm")]
    UnknownAlgorithm,

    #[error("invalid signing key")]
    InvalidSigningKey,

    // --- third-party errors ---
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    JsonError(#[from] serde_json::Error),

    #[error(transparent)]
    #[cfg(feature = "add_thumbnails")]
    ImageError(#[from] image::ImageError),

    #[error(transparent)]
    CborError(#[from] serde_cbor::Error),

    #[error(transparent)]
    OtherError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("prerelease content detected")]
    PrereleaseError,

    #[error("capability is not supported by this version: {0}")]
    VersionCompatibility(String),

    #[error("insufficient memory space for operation")]
    InsufficientMemory,

    #[error("parameters out of range")]
    OutOfRange,

    #[error(transparent)]
    TimeStampError(#[from] crate::crypto::time_stamp::TimeStampError),

    #[error(transparent)]
    RawSignatureValidationError(#[from] crate::crypto::raw_signature::RawSignatureValidationError),

    #[error(transparent)]
    RawSignerError(#[from] crate::crypto::raw_signature::RawSignerError),

    #[error(transparent)]
    CertificateProfileError(#[from] crate::crypto::cose::CertificateProfileError),

    #[error(transparent)]
    CertificateTrustError(#[from] crate::crypto::cose::CertificateTrustError),

    #[error(transparent)]
    InvalidCertificateError(#[from] crate::crypto::cose::InvalidCertificateError),

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
    #[error("internal error ({0})")]
    InternalError(String),

    #[error("Unsupported hashing algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// A specialized `Result` type for C2PA toolkit operations.
pub type Result<T> = std::result::Result<T, Error>;

impl From<CoseError> for Error {
    fn from(err: CoseError) -> Self {
        match err {
            CoseError::MissingSigningCertificateChain => Self::CoseX5ChainMissing,
            CoseError::MultipleSigningCertificateChains => Self::CoseVerifier,
            CoseError::NoTimeStampToken => Self::NotFound,
            CoseError::UnsupportedSigningAlgorithm => Self::CoseSignatureAlgorithmNotSupported,
            CoseError::InvalidEcdsaSignature => Self::InvalidEcdsaSignature,
            CoseError::CborParsingError(_) => Self::CoseTimeStampGeneration,
            CoseError::CborGenerationError(_) => Self::CoseTimeStampGeneration,
            CoseError::TimeStampError(e) => e.into(),
            CoseError::CertificateProfileError(e) => e.into(),
            CoseError::CertificateTrustError(e) => e.into(),
            CoseError::BoxSizeTooSmall => Self::CoseSigboxTooSmall,
            CoseError::RawSignerError(e) => e.into(),
            CoseError::RawSignatureValidationError(e) => e.into(),
            CoseError::InternalError(e) => Self::InternalError(e),
        }
    }
}

impl From<Error> for CoseError {
    fn from(err: Error) -> Self {
        match err {
            Error::CoseX5ChainMissing => Self::MissingSigningCertificateChain,
            Error::CoseVerifier => Self::MultipleSigningCertificateChains,
            Error::NotFound => Self::NoTimeStampToken,
            Error::CoseSignatureAlgorithmNotSupported => Self::UnsupportedSigningAlgorithm,
            Error::InvalidEcdsaSignature => Self::InvalidEcdsaSignature,
            Error::CoseTimeStampGeneration => Self::CborGenerationError(err.to_string()),
            Error::TimeStampError(e) => Self::TimeStampError(e),
            Error::CertificateProfileError(e) => Self::CertificateProfileError(e),
            Error::CertificateTrustError(e) => Self::CertificateTrustError(e),
            Error::CoseSigboxTooSmall => Self::BoxSizeTooSmall,
            Error::RawSignerError(e) => Self::RawSignerError(e),
            Error::RawSignatureValidationError(e) => Self::RawSignatureValidationError(e),
            _ => Self::InternalError(err.to_string()),
        }
    }
}

impl From<Error> for RawSignerError {
    fn from(err: Error) -> Self {
        // See if better mappings exist, but I doubt it.
        Self::InternalError(err.to_string())
    }
}

impl From<Error> for TimeStampError {
    fn from(err: Error) -> Self {
        // See if better mappings exist, but I doubt it.
        Self::InternalError(err.to_string())
    }
}

impl From<ZipError> for Error {
    fn from(err: ZipError) -> Self {
        Error::OtherError(Box::new(err))
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Error::OtherError(Box::new(err))
    }
}
