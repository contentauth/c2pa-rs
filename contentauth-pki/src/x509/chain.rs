// Copyright 2026 Adobe. All rights reserved.
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

//! Chain cryptography and association with explicitly supplied anchors.

use asn1_rs::FromDer;
use thiserror::Error;
use x509_parser::certificate::X509Certificate;

use super::certificate::{cert_signing_alg, verify_data};

#[cfg(feature = "rust_native_crypto")]
mod native;

#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
mod openssl;

/// A cryptographically verified sequence of certificate signatures.
///
/// This does not establish CA authorization, validity periods, certificate
/// profiles, revocation, anchor association, or trust. The last certificate's
/// own signature is not checked, because its issuer is not in the sequence.
#[derive(Debug)]
pub struct SignatureVerifiedChain<'a> {
    certificates: &'a [Vec<u8>],
}

impl SignatureVerifiedChain<'_> {
    /// Original certificates, in the order supplied by the host.
    pub fn certificates(&self) -> &[Vec<u8>] {
        self.certificates
    }
}

/// Check every certificate signature against the next certificate's public key.
///
/// At least two certificates are required to establish any signature relation.
/// This is not path building or a trust decision.
pub fn verify_chain_signatures(
    certificates: &[Vec<u8>],
) -> Result<SignatureVerifiedChain<'_>, ChainError> {
    if certificates.len() < 2 {
        return Err(ChainError::InvalidCertificate);
    }

    for pair in certificates.windows(2) {
        let (_, certificate) =
            X509Certificate::from_der(&pair[0]).map_err(|_| ChainError::InvalidCertificate)?;

        if !verify_data(
            &pair[1],
            cert_signing_alg(&certificate),
            certificate.signature_value.as_ref(),
            certificate.tbs_certificate.as_ref(),
        )? {
            return Err(ChainError::SignatureMismatch);
        }
    }

    Ok(SignatureVerifiedChain { certificates })
}

/// A valid path associated with the host-supplied anchor set at a supplied time.
///
/// No certificate profile, role, revocation, or private credential check is
/// implied. The host must decide whether this anchor set is trusted for the
/// application role; this result is not an application acceptance verdict.
#[derive(Debug)]
pub struct AnchorAssociation<'a> {
    certificate: &'a [u8],
    anchors: &'a [Vec<u8>],
    validation_time: i64,
}

impl AnchorAssociation<'_> {
    /// Original leaf certificate encoding.
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate
    }

    /// The specific anchor set supplied for this path evaluation.
    pub fn anchors(&self) -> &[Vec<u8>] {
        self.anchors
    }

    /// Host-selected evaluation time, in Unix seconds.
    pub fn validation_time(&self) -> i64 {
        self.validation_time
    }
}

/// Evaluate chain mechanics against one explicitly selected anchor set.
///
/// The host supplies a leaf-first chain, DER anchors, and Unix time. The
/// selected backend preserves its existing path-building and partial-chain
/// behavior. No default anchors, clock, EKU configuration, or I/O is used.
pub fn validate_chain_to_anchors<'a>(
    chain: &[Vec<u8>],
    certificate: &'a [u8],
    anchors: &'a [Vec<u8>],
    validation_time: i64,
) -> Result<AnchorAssociation<'a>, ChainError> {
    #[cfg(feature = "rust_native_crypto")]
    native::check_certificate_trust(anchors, chain, certificate, validation_time)?;

    #[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
    openssl::check_certificate_trust(anchors, chain, certificate, validation_time)?;

    #[cfg(not(any(feature = "openssl", feature = "rust_native_crypto")))]
    {
        let _ = (chain, certificate, validation_time);

        return Err(ChainError::InternalError(
            "no implementation for certificate evaluation available".into(),
        ));
    }

    #[cfg(any(feature = "openssl", feature = "rust_native_crypto"))]
    Ok(AnchorAssociation {
        certificate,
        anchors,
        validation_time,
    })
}

/// Errors from certificate signature and chain mechanics, without SDK statuses.
#[derive(Debug, Eq, Error, PartialEq)]
pub enum ChainError {
    /// No valid path was established to the supplied anchor set.
    #[error("no valid chain to the supplied anchor set")]
    NoAnchorAssociation,

    /// A certificate signature did not verify with the supplied issuer key.
    #[error("certificate signature mismatch")]
    SignatureMismatch,

    /// An issuing CA on an otherwise associated chain was outside its validity.
    #[error("a CA certificate in the chain is outside its validity period")]
    CaCertificateOutsideValidity,

    /// Certificate parsing, algorithm selection, or signature inputs were invalid.
    #[error("the certificate or certificate chain is invalid")]
    InvalidCertificate,

    /// The selected cryptography backend returned an error.
    #[error("an error was reported by the cryptography library: {0}")]
    CryptoLibraryError(String),

    /// The requested backend was unavailable or could not be initialized.
    #[error("internal error ({0})")]
    InternalError(String),
}

#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
impl From<::openssl::error::ErrorStack> for ChainError {
    fn from(error: ::openssl::error::ErrorStack) -> Self {
        Self::CryptoLibraryError(error.to_string())
    }
}

#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
impl From<c2pa_raw_crypto::OpenSslMutexUnavailable> for ChainError {
    fn from(error: c2pa_raw_crypto::OpenSslMutexUnavailable) -> Self {
        Self::InternalError(error.to_string())
    }
}
