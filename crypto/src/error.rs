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

#![deny(missing_docs)]

use thiserror::Error;

/// `Error` enumerates errors returned by most c2pa-crypto operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An invalid parameter was provided.
    #[error("bad parameter: {0}")]
    BadParam(String),

    /// A feature is not yet implemented.
    #[error("feature implementation incomplete")]
    NotImplemented(String),

    /// The COSE Sign1 structure can not be parsed.
    #[error("COSE Sign1 structure can not be parsed: {coset_error}")]
    InvalidCoseSignature {
        /// Error from coset parser.
        coset_error: coset::CoseError, /* NOTE: We can not use #[transparent] here because
                                        * coset::CoseError does not implement std::Error::error
                                        * and can't because coset is nostd. */
    },

    /// The COSE signature uses an algorithm that is not supported by this
    /// crate.
    #[error("COSE signature algorithm is not supported")]
    CoseSignatureAlgorithmNotSupported,

    /// Could not find a verification key.
    #[error("COSE could not find verification key")]
    CoseMissingKey,

    /// The COSE signature did not contain a signing certificate.
    #[error("could not find signing certificate chain in COSE signature")]
    CoseX5ChainMissing,

    /// The certificate contained an invalid certificate.
    #[error("COSE error parsing certificate")]
    CoseInvalidCert,

    /// The COSE signature was invalid.
    #[error("COSE signature invalid")]
    CoseSignature,

    /// An error occurred in the COSE verifier.
    #[error("COSE verifier failure")]
    CoseVerifier,

    /// The COSE certificate has expired.
    #[error("COSE certificate has expired")]
    CoseCertExpiration,

    /// The COSE certificate was revoked.
    #[error("COSE certificate has been revoked")]
    CoseCertRevoked,

    /// The COSE certificate was not trusted.
    #[error("COSE certificate not trusted")]
    CoseCertUntrusted,

    /// Unable to parse the time stamp from this signature.
    #[error("COSE time stamp could not be parsed")]
    CoseInvalidTimeStamp,

    /// The COSE time stamp uses an expired certificate.
    #[error("COSE time stamp had expired cert")]
    CoseTimeStampValidity,

    /// The time stamp in the signature did not match the signed data.
    #[error("COSE time stamp does not match data")]
    CoseTimeStampMismatch,

    /// Unable to generate a trusted time stamp.
    #[error("could not generate a trusted time stamp")]
    CoseTimeStampGeneration,

    /// Timestamp uses unrecognized signature.
    #[error("COSE TimeStamp Authority failure")]
    CoseTimeStampAuthority,

    /// The signature box was not large enough for the COSE signature.
    #[error("COSE Signature too big for JUMBF box")]
    CoseSigboxTooSmall,

    /// The signer does not contain any signing certificates.
    #[error("COSE Signer does not contain signing certificate")]
    CoseNoCerts,

    /// Error in WASM verifier.
    #[error("WASM verifier error")]
    WasmVerifier,

    /// Could not process RSA signature.
    #[error("WASM RSA-PSS key import error: {0}")]
    WasmRsaKeyImport(String),

    /// WASM crypto key error.
    #[error("WASM crypto key error")]
    WasmKey,

    /// WASM called from incorrect context.
    #[error("WASM not called from window or worker global scope")]
    WasmInvalidContext,

    /// Failed to load WASM crypto library.
    #[error("WASM could not load crypto library")]
    WasmNoCrypto,

    /// Stopped because an error was logged.
    #[error("stopped because of logged error")]
    LogStop,

    /// The requested item was not found.
    #[error("not found")]
    NotFound,

    /// The type is unsupported.
    #[error("type is unsupported")]
    UnsupportedType,

    /// Could not parse ECDSA signature.
    #[error("could not parse ECDSA signature")]
    InvalidEcdsaSignature,

    /// An unrecognized algorithm was specified.
    #[error("unknown algorithm")]
    UnknownAlgorithm,

    /// Could not acquire OpenSSL mutex.
    #[error("could not acquire OpenSSL FFI mutex")]
    OpenSslMutexError,

    // --- third-party errors ---
    /// An I/O error occurred.
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// An error parsing or generating CBOR occurred.
    #[error(transparent)]
    CborError(#[from] serde_cbor::Error),

    /// An error occurred in OpenSSL.
    #[error(transparent)]
    #[cfg(feature = "openssl")]
    OpenSslError(#[from] openssl::error::ErrorStack),

    /// An error occurred from a dependent crate.
    #[error(transparent)]
    OtherError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// A specialized `Result` type for c2pa-crypto operations.
pub type Result<T> = std::result::Result<T, Error>;
