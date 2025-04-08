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

use super::oids::{
    ans1_oid_bcder_oid, ECDSA_WITH_SHA256_OID, ECDSA_WITH_SHA384_OID, ECDSA_WITH_SHA512_OID,
    ED25519_OID, SHA1_OID, SHA1_WITH_RSAENCRYPTION_OID, SHA256_OID, SHA256_WITH_RSAENCRYPTION_OID,
    SHA384_OID, SHA384_WITH_RSAENCRYPTION_OID, SHA512_OID, SHA512_WITH_RSAENCRYPTION_OID,
};
use crate::raw_signature::SigningAlg;

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
/// [`RawSignatureValidator`]: crate::raw_signature::RawSignatureValidator
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
    #[cfg(any(target_arch = "wasm32", feature = "rust_native_crypto"))]
    {
        if let Some(validator) =
            crate::raw_signature::rust_native::validators::validator_for_signing_alg(alg)
        {
            return Some(validator);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    if let Some(validator) =
        crate::raw_signature::openssl::validators::validator_for_signing_alg(alg)
    {
        return Some(validator);
    }

    let _ = alg; // this value will be unused in this case
    None
}
// Find correct hash choice to the signing alg,
// this also works as a passthrough if the hash is known.
fn signing_alg_to_hash_alg(sign_hash_alg: &Oid) -> Oid {
    let hash = if sign_hash_alg.as_ref() == SHA256_WITH_RSAENCRYPTION_OID.as_bytes() {
        SHA256_OID.to_owned()
    } else if sign_hash_alg.as_ref() == SHA384_WITH_RSAENCRYPTION_OID.as_bytes() {
        SHA384_OID.to_owned()
    } else if sign_hash_alg.as_ref() == SHA512_WITH_RSAENCRYPTION_OID.as_bytes() {
        SHA512_OID.to_owned()
    } else if sign_hash_alg.as_ref() == SHA1_WITH_RSAENCRYPTION_OID.as_bytes() {
        SHA1_OID.to_owned()
    } else if sign_hash_alg.as_ref() == ECDSA_WITH_SHA256_OID.as_bytes() {
        SHA256_OID.to_owned()
    } else if sign_hash_alg.as_ref() == ECDSA_WITH_SHA384_OID.as_bytes() {
        SHA384_OID.to_owned()
    } else if sign_hash_alg.as_ref() == ECDSA_WITH_SHA512_OID.as_bytes() {
        SHA512_OID.to_owned()
    } else if sign_hash_alg.as_ref() == ED25519_OID.as_bytes() {
        SHA512_OID.to_owned()
    } else {
        return sign_hash_alg.to_owned();
    };

    ans1_oid_bcder_oid(&hash).unwrap_or(sign_hash_alg.to_owned())
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
    // adjust hash if needed
    let hash_alg = signing_alg_to_hash_alg(hash_alg);

    // TO REVIEW: Do we need any of the RSA-PSS algorithms for this use case?
    #[cfg(any(target_arch = "wasm32", feature = "rust_native_crypto"))]
    {
        if let Some(validator) =
            crate::raw_signature::rust_native::validators::validator_for_sig_and_hash_algs(
                sig_alg, &hash_alg,
            )
        {
            return Some(validator);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    if let Some(validator) =
        crate::raw_signature::openssl::validators::validator_for_sig_and_hash_algs(
            sig_alg, &hash_alg,
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
    crate::raw_signature::rust_native::validators::async_validator_for_signing_alg(alg)
}
#[cfg(target_arch = "wasm32")]
pub(crate) fn async_validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg: &Oid,
) -> Option<Box<dyn AsyncRawSignatureValidator>> {
    crate::raw_signature::rust_native::validators::async_validator_for_sig_and_hash_algs(
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

#[cfg(not(target_arch = "wasm32"))]
impl From<openssl::error::ErrorStack> for RawSignatureValidationError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::CryptoLibraryError(err.to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<crate::raw_signature::openssl::OpenSslMutexUnavailable> for RawSignatureValidationError {
    fn from(err: crate::raw_signature::openssl::OpenSslMutexUnavailable) -> Self {
        Self::InternalError(err.to_string())
    }
}
