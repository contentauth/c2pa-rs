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

use bcder::Oid;
use thiserror::Error;

use super::oids::*;
use crate::SigningAlg;

/// A `RawSignatureValidator` implementation checks a signature encoded using a
/// specific signature algorithm and a private/public key pair.
///
/// IMPORTANT: This signature is typically embedded in a wrapper provided by
/// another signature mechanism. In the C2PA ecosystem, this wrapper is
/// typically COSE, but `RawSignatureValidator` does not implement COSE.
pub trait RawSignatureValidator {
    /// Return `true` if the signature `sig` is valid for the raw content `data`
    /// and the public key `public_key`.
    fn validate(
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
    #[cfg(feature = "openssl")]
    if let Some(validator) = crate::openssl::validators::validator_for_signing_alg(alg) {
        return Some(validator);
    }

    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    if let Some(validator) = crate::webcrypto::validators::validator_for_signing_alg(alg) {
        return Some(validator);
    }

    None
}

/// Return a built-in signature validator for the requested signature
/// algorithm as identified by OID.
///
/// Which validators are available may vary depending on the platform and
/// which crate features were enabled.
///
/// TEMPORARILY PUBLIC: This will become `pub(crate)` once time stamp code moves
/// into c2pa-crypto
pub fn validator_for_sig_and_hash_algs(
    sig_alg: &Oid,
    hash_alg: &Oid,
) -> Option<Box<dyn RawSignatureValidator>> {
    if sig_alg.as_ref() == RSA_OID.as_bytes()
        || sig_alg.as_ref() == SHA256_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA384_WITH_RSAENCRYPTION_OID.as_bytes()
        || sig_alg.as_ref() == SHA512_WITH_RSAENCRYPTION_OID.as_bytes()
    {
        // TO REVIEW: Do we need any of the RSA-PSS algorithms for this use case?

        #[cfg(feature = "openssl")]
        if let Some(validator) =
            crate::openssl::validators::validator_for_sig_and_hash_algs(sig_alg, hash_alg)
        {
            return Some(validator);
        }

        // Not sure yet if we'll need legacy validators for WASM.
        #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
        if let Some(validator) =
            crate::webcrypto::validators::validator_for_sig_and_hash_algs(sig_alg, hash_alg)
        {
            return Some(validator);
        }
    } else if sig_alg.as_ref() == EC_PUBLICKEY_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA256_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA384_OID.as_bytes()
        || sig_alg.as_ref() == ECDSA_WITH_SHA512_OID.as_bytes()
    {
        if hash_alg.as_ref() == SHA256_OID.as_bytes() {
            return validator_for_signing_alg(SigningAlg::Es256);
        } else if hash_alg.as_ref() == SHA384_OID.as_bytes() {
            return validator_for_signing_alg(SigningAlg::Es384);
        } else if hash_alg.as_ref() == SHA512_OID.as_bytes() {
            return validator_for_signing_alg(SigningAlg::Es512);
        }
    } else if sig_alg.as_ref() == ED25519_OID.as_bytes() {
        return validator_for_signing_alg(SigningAlg::Ed25519);
    }

    None
}

/// Describes errors that can be identified when validating a raw signature.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RawSignatureValidationError {
    /// The signature does not match the provided data or public key.
    #[error("the signature does not match the provided data or public key")]
    SignatureMismatch,

    /// An error was reported by the OpenSSL native code.
    ///
    /// NOTE: We do not directly capture the OpenSSL error itself because it
    /// lacks an Eq implementation. Instead we capture the error description.
    #[cfg(feature = "openssl")]
    #[error("an error was reported by OpenSSL native code: {0}")]
    OpenSslError(String),

    /// The OpenSSL native code mutex could not be acquired.
    #[cfg(feature = "openssl")]
    #[error(transparent)]
    OpenSslMutexUnavailable(#[from] crate::openssl::OpenSslMutexUnavailable),

    /// An invalid public key was provided.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// An invalid signature value was provided.
    #[error("invalid signature value")]
    InvalidSignature,
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for RawSignatureValidationError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::OpenSslError(err.to_string())
    }
}
