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

use async_trait::async_trait;
use bcder::Oid;
use thiserror::Error;

use crate::crypto::raw_signature::SigningAlg;

/// A `RawSignatureValidator` implementation checks a signature encoded using a
/// specific signature algorithm and a private/public key pair.
///
/// IMPORTANT: This signature is typically embedded in a wrapper provided by
/// another signature mechanism. In the C2PA ecosystem, this wrapper is
/// typically COSE, but `RawSignatureValidator` does not implement COSE.
pub trait RawSignatureValidator {
    /// Return `Ok(())` if the signature `sig` is valid for the raw content
    /// `data` and the public key `public_key`.
    fn validate(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError>;
}

/// An `AsyncRawSignatureValidator` implementation checks a signature encoded
/// using a specific signature algorithm and a private/public key pair.
///
/// IMPORTANT: This signature is typically embedded in a wrapper provided by
/// another signature mechanism. In the C2PA ecosystem, this wrapper is
/// typically COSE, but `AsyncRawSignatureValidator` does not implement COSE.
///
/// The WASM implementation of `c2pa-crypto` also implements
/// [`RawSignatureValidator`] (the synchronous version), but some encryption
/// algorithms are not supported. For that reason, it's preferable to use this
/// implementation on WASM.
///
/// [`RawSignatureValidator`]: crate::crypto::raw_signature::RawSignatureValidator
#[async_trait(?Send)]
pub trait AsyncRawSignatureValidator {
    /// Return `Ok(())` if the signature `sig` is valid for the raw content
    /// `data` and the public key `public_key`.
    async fn validate_async(
        &self,
        sig: &[u8],
        data: &[u8],
        public_key: &[u8],
    ) -> Result<(), RawSignatureValidationError>;
}

/// Return a built-in signature validator for the requested signature
/// algorithm.
///
/// Which validators are available may vary depending on the platform and
/// which crate features were enabled.
pub fn validator_for_signing_alg(alg: SigningAlg) -> Option<Box<dyn RawSignatureValidator>> {
    #[cfg(feature = "rust_native_crypto")]
    {
        if let Some(validator) =
            crate::crypto::raw_signature::rust_native::validators::validator_for_signing_alg(alg)
        {
            return Some(validator);
        }
    }

    #[cfg(feature = "openssl")]
    if let Some(validator) =
        crate::crypto::raw_signature::openssl::validators::validator_for_signing_alg(alg)
    {
        return Some(validator);
    }

    let _ = alg; // this value will be unused in this case
    None
}

/// Return a built-in signature validator for the requested signature
/// algorithm as identified by OID.
///
/// Which validators are available may vary depending on the platform and
/// which crate features were enabled.
pub(crate) fn validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg: &Oid,
) -> Option<Box<dyn RawSignatureValidator>> {
    // TO REVIEW: Do we need any of the RSA-PSS algorithms for this use case?
    #[cfg(feature = "rust_native_crypto")]
    {
        if let Some(validator) =
            crate::crypto::raw_signature::rust_native::validators::validator_for_sig_and_hash_algs(
                sig_alg, hash_alg,
            )
        {
            return Some(validator);
        }
    }

    #[cfg(feature = "openssl")]
    if let Some(validator) =
        crate::crypto::raw_signature::openssl::validators::validator_for_sig_and_hash_algs(
            sig_alg, hash_alg,
        )
    {
        return Some(validator);
    }

    let _ = sig_alg; // this value will be unused in this case
    let _ = hash_alg; // this value will be unused in this case

    None
}

/// Return a built-in signature validator for the requested signature
/// algorithm.
///
/// Which validators are available may vary depending on the platform and
/// which crate features were enabled.
///
/// IMPORTANT: Only available on WASM builds. There are no built-in async
/// validators for other platforms.
#[cfg(target_arch = "wasm32")]
pub fn async_validator_for_signing_alg(
    alg: SigningAlg,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    crate::crypto::raw_signature::rust_native::validators::async_validator_for_signing_alg(alg)
}
#[cfg(target_arch = "wasm32")]
pub(crate) fn async_validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg: &Oid,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    crate::crypto::raw_signature::rust_native::validators::async_validator_for_sig_and_hash_algs(
        sig_alg, hash_alg,
    )
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

    /// The time stamp uses an unsupported signing or hash algorithm.
    #[error("signature uses an unsupported algorithm")]
    UnsupportedAlgorithm,

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
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
impl From<crate::crypto::raw_signature::openssl::OpenSslMutexUnavailable>
    for RawSignatureValidationError
{
    fn from(err: crate::crypto::raw_signature::openssl::OpenSslMutexUnavailable) -> Self {
        Self::InternalError(err.to_string())
    }
}
