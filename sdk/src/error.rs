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
    AssertionEncoding,

    #[error(transparent)]
    AssertionDecoding(#[from] crate::assertion::AssertionDecodeError),

    #[error("assertion could not be redacted")]
    AssertionInvalidRedaction,

    #[error("could not find the assertion to redact")]
    AssertionRedactionNotFound,

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

    #[error("could not fetch the remote manifest")]
    RemoteManifestFetch(String),

    #[error("must fetch remote manifests from url")]
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
    #[cfg(all(not(target_arch = "wasm32"), feature = "add_thumbnails"))]
    ImageError(#[from] image::ImageError),

    #[error(transparent)]
    CborError(#[from] serde_cbor::Error),

    #[error("could not acquire OpenSSL FFI mutex")]
    OpenSslMutexError,

    #[error(transparent)]
    #[cfg(feature = "openssl")]
    OpenSslError(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    OtherError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("prerelease content detected")]
    PrereleaseError,
}

/// A specialized `Result` type for C2PA toolkit operations.
pub type Result<T> = std::result::Result<T, Error>;
