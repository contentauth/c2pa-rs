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
    #[error("bad parameter: {0}")]
    BadParam(String),

    #[error("feature implementation incomplete")]
    NotImplemented(String),

    /// The COSE Sign1 structure can not be parsed.
    #[error("COSE Sign1 structure can not be parsed: {coset_error}")]
    InvalidCoseSignature {
        coset_error: coset::CoseError, /* NOTE: We can not use #[transparent] here because
                                        * coset::CoseError does not implement std::Error::error
                                        * and can't because coset is nostd. */
    },

    /// The COSE signature uses an algorithm that is not supported by this
    /// crate.
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

    #[error("WASM crypto key error")]
    WasmKey,

    #[error("WASM not called from window or worker global scope")]
    WasmInvalidContext,

    #[error("WASM could not load crypto library")]
    WasmNoCrypto,

    #[error("stopped because of logged error")]
    LogStop,

    #[error("not found")]
    NotFound,

    #[error("type is unsupported")]
    UnsupportedType,

    /// Could not parse ECDSA signature. (Only appears when using WASM web
    /// crypto.)
    #[error("could not parse ECDSA signature")]
    InvalidEcdsaSignature,

    #[error("unknown algorithm")]
    UnknownAlgorithm,

    // --- third-party errors ---
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    CborError(#[from] serde_cbor::Error),

    #[error("could not acquire OpenSSL FFI mutex")]
    OpenSslMutexError,

    #[error(transparent)]
    #[cfg(feature = "openssl")]
    OpenSslError(#[from] openssl::error::ErrorStack),

    #[error(transparent)]
    OtherError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// A specialized `Result` type for C2PA toolkit operations.
pub type Result<T> = std::result::Result<T, Error>;
