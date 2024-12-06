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

use async_trait::async_trait;
use thiserror::Error;

use crate::SigningAlg;

/// Implementations of the `RawSigner` trait generate a cryptographic signature
/// over an arbitrary byte array.
///
/// If an implementation _can_ be asynchronous, that is preferred.
pub trait RawSigner {
    /// Return a raw signature over the original byte slice.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RawSignerError>;

    /// Return the algorithm implemented by this signer.
    fn alg(&self) -> SigningAlg;

    /// Return the signing certificate chain.
    ///
    /// Each certificate should be encoded in DER format and sequenced from
    /// end-entity certificate to the outermost certificate authority.
    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError>;

    /// Return the size in bytes of the largest possible expected signature.
    /// Signing will fail if the result of the [`sign`] function is larger
    /// than this value.
    ///
    /// [`sign`]: Self::sign
    fn reserve_size(&self) -> usize;

    /// Return an OCSP response for the signing certificate if available.
    ///
    /// By pre-querying the value for the signing certificate, the value can be
    /// cached which will reduce load on the certificate authority, as
    /// recommended by the C2PA spec.
    fn ocsp_response(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Implementations of the `AsyncRawSigner` trait generate a cryptographic
/// signature over an arbitrary byte array.
///
/// Use this trait only when the implementation must be asynchronous.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait AsyncRawSigner: Sync {
    /// Return a raw signature over the original byte slice.
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>, RawSignerError>;

    /// Return the algorithm implemented by this signer.
    fn alg(&self) -> SigningAlg;

    /// Return the signing certificate chain.
    ///
    /// Each certificate should be encoded in DER format and sequenced from
    /// end-entity certificate to the outermost certificate authority.
    fn cert_chain(&self) -> Result<Vec<Vec<u8>>, RawSignerError>;

    /// Return the size in bytes of the largest possible expected signature.
    /// Signing will fail if the result of the [`sign`] function is larger
    /// than this value.
    ///
    /// [`sign`]: Self::sign
    fn reserve_size(&self) -> usize;

    /// Return an OCSP response for the signing certificate if available.
    ///
    /// By pre-querying the value for the signing certificate, the value can be
    /// cached which will reduce load on the certificate authority, as
    /// recommended by the C2PA spec.
    async fn ocsp_response(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Describes errors that can be identified when generating a raw signature.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RawSignerError {
    /// An I/O error occurred. This typically happens when loading
    /// public/private key material from files.
    ///
    /// NOTE: We do not directly capture the I/O error itself because it
    /// lacks an `Eq` implementation. Instead we capture the error description.
    #[error("I/O error ({0})")]
    IoError(String),

    /// An error was reported by the OpenSSL native code.
    ///
    /// NOTE: We do not directly capture the OpenSSL error itself because it
    /// lacks an `Eq` implementation. Instead we capture the error description.
    #[cfg(feature = "openssl")]
    #[error("an error was reported by OpenSSL native code: {0}")]
    OpenSslError(String),

    /// The OpenSSL native code mutex could not be acquired.
    #[cfg(feature = "openssl")]
    #[error(transparent)]
    OpenSslMutexUnavailable(#[from] crate::openssl::OpenSslMutexUnavailable),

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
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
        Self::OpenSslError(err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<crate::webcrypto::WasmCryptoError> for RawSignerError {
    fn from(err: crate::webcrypto::WasmCryptoError) -> Self {
        match err {
            crate::webcrypto::WasmCryptoError::UnknownContext => {
                Self::InternalError("unknown WASM context")
            }
            crate::webcrypto::WasmCryptoError::NoCryptoAvailable => {
                Self::InternalError("WASM crypto unavailable")
            }
        }
    }
}

/// This trait exists to allow the built-in [`RawSigner`] implementations to be
/// configured from a private/public key pair.
#[allow(dead_code)] // TEMPORARY while refactoring
pub(crate) trait ConfigurableSigner: RawSigner + Sized {
    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self, RawSignerError>;

    fn from_files<P: AsRef<std::path::Path>>(
        signcert_path: P,
        pkey_path: P,
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self, RawSignerError> {
        let signcert = std::fs::read(signcert_path)?;
        let pkey = std::fs::read(pkey_path)?;

        Self::from_signcert_and_pkey(&signcert, &pkey, alg, tsa_url)
    }
}
