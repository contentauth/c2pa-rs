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

use thiserror::Error;

use crate::{Oid, SigningAlg};

/// Checks a signature encoded using a specific signature algorithm
/// and a public key.
///
/// IMPORTANT: This signature is typically embedded in a wrapper provided by
/// another signature mechanism. In the C2PA ecosystem, this wrapper is
/// typically COSE, but `RawSignatureValidator` does not implement COSE.
pub trait RawSignatureValidator {
    /// Returns `Ok(())` if the signature `sig` is valid for the raw content
    /// `data` and the public key `public_key`.
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError>;
}

/// Returns a built-in signature validator for the requested signature
/// algorithm.
///
/// Which validators are available may vary depending on the platform and
/// which crate features were enabled. Returns `None` if no validator is
/// available for `alg` (including when no cryptography backend was enabled at
/// build time).
pub fn validator_for_signing_alg(alg: SigningAlg) -> Option<Box<dyn RawSignatureValidator>> {
    #[cfg(feature = "rust_native_crypto")]
    {
        crate::rust_native::validators::validator_for_signing_alg(alg)
    }

    #[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
    {
        return crate::openssl::validators::validator_for_signing_alg(alg);
    }

    #[cfg(not(any(feature = "rust_native_crypto", feature = "openssl")))]
    {
        let _ = alg;
        None
    }
}

/// Returns a built-in signature validator for the requested signature
/// algorithm as identified by signature and hash algorithm OIDs.
///
/// Which validators are available may vary depending on the platform and
/// which crate features were enabled. Returns `None` if no validator is
/// available (including when no cryptography backend was enabled at build
/// time).
pub fn validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg: &Oid,
) -> Option<Box<dyn RawSignatureValidator>> {
    #[cfg(feature = "rust_native_crypto")]
    {
        crate::rust_native::validators::validator_for_sig_and_hash_algs(
            sig_alg.as_bytes(),
            hash_alg.as_bytes(),
        )
    }

    #[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
    {
        return crate::openssl::validators::validator_for_sig_and_hash_algs(
            sig_alg.as_bytes(),
            hash_alg.as_bytes(),
        );
    }

    #[cfg(not(any(feature = "rust_native_crypto", feature = "openssl")))]
    {
        let _ = (sig_alg, hash_alg);
        None
    }
}

/// Describes errors that can be identified when validating a raw signature.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RawSignatureValidationError {
    /// The signature does not match the provided data or public key.
    #[error("the signature does not match the provided data or public key")]
    SignatureMismatch,

    /// An error was reported by the underlying cryptography implementation.
    #[error("an error was reported by the cryptography library: {0}")]
    CryptoLibraryError(String),

    /// An invalid public key was provided.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// An invalid signature value was provided.
    #[error("invalid signature value")]
    InvalidSignature,

    /// The signature uses an unsupported signing or hash algorithm.
    #[error("signature uses an unsupported algorithm")]
    UnsupportedAlgorithm,

    /// An unexpected internal error occured while validating the signature.
    #[error("internal error ({0})")]
    InternalError(String),
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for RawSignatureValidationError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::CryptoLibraryError(err.to_string())
    }
}

#[cfg(feature = "openssl")]
impl From<crate::openssl::OpenSslMutexUnavailable> for RawSignatureValidationError {
    fn from(err: crate::openssl::OpenSslMutexUnavailable) -> Self {
        Self::InternalError(err.to_string())
    }
}
