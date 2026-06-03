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

use thiserror::Error;

use crate::SigningAlg;

/// Implementations of the `RawSigner` trait generate a cryptographic signature
/// over an arbitrary byte array.
///
/// A `RawSigner` holds a private key and is concerned _only_ with producing a
/// raw signature. It deliberately exposes neither the private key nor the
/// signing certificate chain. Higher-level concerns — the certificate chain,
/// RFC 3161 time stamping, OCSP stapling, and COSE framing — are the
/// responsibility of the calling code.
pub trait RawSigner {
    /// Returns a raw signature over the original byte slice.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError>;

    /// Returns the algorithm implemented by this signer.
    fn alg(&self) -> SigningAlg;

    /// Returns the maximum size in bytes of the raw signature produced by
    /// [`sign`]. Signing will fail if the result of [`sign`] is larger than
    /// this value.
    ///
    /// This describes _only_ the raw signature; it does not account for the
    /// certificate chain, time stamp, OCSP response, or COSE framing that
    /// calling code may add around it.
    ///
    /// [`sign`]: Self::sign
    fn max_signature_size(&self) -> usize;
}

/// Describes errors that can be identified when generating a raw signature.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RawSignerError {
    /// The signing credentials are invalid.
    #[error("invalid signing credentials ({0})")]
    InvalidSigningCredentials(String),

    /// An I/O error occurred. This typically happens when loading
    /// public/private key material from files.
    ///
    /// NOTE: We do not directly capture the I/O error itself because it
    /// lacks an `Eq` implementation. Instead we capture the error description.
    #[error("I/O error ({0})")]
    IoError(String),

    /// An error was reported by the underlying cryptography implementation.
    #[error("an error was reported by the cryptography library: {0}")]
    CryptoLibraryError(String),

    /// The requested signing algorithm is not supported by the available
    /// cryptography backend.
    #[error("unsupported signing algorithm: {0}")]
    UnsupportedAlgorithm(SigningAlg),

    /// No cryptography backend was enabled at build time. Enable either the
    /// `rust_native_crypto` (default) or `openssl` feature to use the built-in
    /// signers.
    #[error("no cryptography backend was enabled at build time")]
    NoCryptoBackend,

    /// An unexpected internal error occured while generating the signature.
    #[error("internal error ({0})")]
    InternalError(String),
}

impl From<std::io::Error> for RawSignerError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for RawSignerError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::CryptoLibraryError(err.to_string())
    }
}

#[cfg(feature = "openssl")]
impl From<crate::openssl::OpenSslMutexUnavailable> for RawSignerError {
    fn from(err: crate::openssl::OpenSslMutexUnavailable) -> Self {
        Self::InternalError(err.to_string())
    }
}

/// Converts JSON-encoded PEM data (with \n) to proper PEM format
fn fix_json_pem(data: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(data)
        .replace("\\n", "\n")
        .into_bytes()
}

/// Returns a built-in [`RawSigner`] instance using the provided private key.
///
/// The key must be supplied in PEM form. The signing certificate chain is
/// _not_ a concern of the raw signer; the caller is responsible for tracking it.
///
/// Which signers are available may vary depending on the platform and which
/// crate features were enabled. If the desired signing algorithm is
/// unavailable, will respond with `Err(RawSignerError::UnsupportedAlgorithm)`.
///
/// If no cryptography backend was enabled at build time, will respond with
/// `Err(RawSignerError::NoCryptoBackend)`.
///
/// May return an `Err` response if the private key is invalid.
#[allow(unused)] // arguments may be unused if no backend is enabled
pub fn signer_from_private_key(
    private_key: &[u8],
    alg: SigningAlg,
) -> Result<Box<dyn RawSigner + Send + Sync>, RawSignerError> {
    let private_key = fix_json_pem(private_key);

    #[cfg(feature = "rust_native_crypto")]
    {
        return crate::rust_native::signers::signer_from_private_key(&private_key, alg);
    }

    #[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
    {
        return crate::openssl::signers::signer_from_private_key(&private_key, alg);
    }

    #[cfg(not(any(feature = "rust_native_crypto", feature = "openssl")))]
    Err(RawSignerError::NoCryptoBackend)
}
