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
#[cfg(feature = "file_io")]
use crate::Error;
use crate::{Result, SigningAlg};
/// The `Signer` trait generates a cryptographic signature over a byte array.
///
/// This trait exists to allow the signature mechanism to be extended.
pub trait Signer {
    /// Returns a new byte array which is a signature over the original.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Returns the algorithm of the Signer.
    fn alg(&self) -> SigningAlg;

    /// Returns the certificates as a Vec containing a Vec of DER bytes for each certificate.
    fn certs(&self) -> Result<Vec<Vec<u8>>>;

    /// Returns the size in bytes of the largest possible expected signature.
    /// Signing will fail if the result of the `sign` function is larger
    /// than this value.
    fn reserve_size(&self) -> usize;

    /// URL for time authority to time stamp the signature
    fn time_authority_url(&self) -> Option<String> {
        None
    }

    /// OCSP response for the signing cert if available
    /// This is the only C2PA supported cert revocation method.
    /// By pre-querying the value for a your signing cert the value can
    /// be cached taking pressure off of the CA (recommended by C2PA spec)
    fn ocsp_val(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Trait to allow loading of signing credential from external sources
pub(crate) trait ConfigurableSigner: Signer + Sized {
    /// Create signer form credential files
    #[cfg(feature = "file_io")]
    fn from_files<P: AsRef<std::path::Path>>(
        signcert_path: P,
        pkey_path: P,
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self> {
        let signcert = std::fs::read(signcert_path).map_err(Error::IoError)?;
        let pkey = std::fs::read(pkey_path).map_err(Error::IoError)?;

        Self::from_signcert_and_pkey(&signcert, &pkey, alg, tsa_url)
    }

    /// Create signer from credentials data
    fn from_signcert_and_pkey(
        signcert: &[u8],
        pkey: &[u8],
        alg: SigningAlg,
        tsa_url: Option<String>,
    ) -> Result<Self>;
}

#[cfg(feature = "async_signer")]
use async_trait::async_trait;

/// The `AsyncSigner` trait generates a cryptographic signature over a byte array.
///
/// This trait exists to allow the signature mechanism to be extended.
///
/// Use this when the implementation is asynchronous.
#[cfg(feature = "async_signer")]
#[async_trait]
pub trait AsyncSigner: Sync {
    /// Returns a new byte array which is a signature over the original.
    async fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>>;

    /// Returns the algorithm of the Signer.
    fn alg(&self) -> SigningAlg;

    /// Returns the certificates as a Vec containing a Vec of DER bytes for each certificate.
    fn certs(&self) -> Result<Vec<Vec<u8>>>;

    /// Returns the size in bytes of the largest possible expected signature.
    /// Signing will fail if the result of the `sign` function is larger
    /// than this value.
    fn reserve_size(&self) -> usize;

    /// URL for time authority to time stamp the signature
    fn time_authority_url(&self) -> Option<String> {
        None
    }

    /// OCSP response for the signing cert if available
    /// This is the only C2PA supported cert revocation method.
    /// By pre-querying the value for a your signing cert the value can
    /// be cached taking pressure off of the CA (recommended by C2PA spec)
    fn ocsp_val(&self) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(feature = "async_signer")]
#[async_trait]
pub trait RemoteSigner: Sync {
    /// Returns the `CoseSign1` bytes signed by the [`RemoteSigner`].
    ///
    /// The size of returned `Vec` must match the value returned by `reserve_size`.
    /// This data will be embedded in the JUMBF `c2pa.signature` box of the manifest.
    /// `data` are the bytes of the claim to be remotely signed.
    async fn sign_remote(&self, data: &[u8]) -> Result<Vec<u8>>;

    /// Returns the size in bytes of the largest possible expected signature.
    ///
    /// Signing will fail if the result of the `sign` function is larger
    /// than this value.
    fn reserve_size(&self) -> usize;
}
