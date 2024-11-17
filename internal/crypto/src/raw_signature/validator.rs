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
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for RawSignatureValidationError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::OpenSslError(err.to_string())
    }
}
