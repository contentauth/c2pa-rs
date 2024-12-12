// Copyright 2023 Adobe. All rights reserved.
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

#![allow(missing_docs)] // TEMPORARY while refactoring

//! Provides an interface for describing trust lists and EKU configurations used
//! when verifying signing certificates.

use std::{
    collections::HashSet,
    fmt,
    io::Read,
    panic::{RefUnwindSafe, UnwindSafe},
};

use asn1_rs::Oid;
use thiserror::Error;

/// An implementation of `TrustHandler` retains information about trust anchors
/// and allowed EKUs to be used when verifying C2PA signing certificates.
pub trait TrustHandler: RefUnwindSafe + UnwindSafe + Sync + Send {
    /// Set trust anchors (root X.509 certificates) that shall be accepted when
    /// verifying COSE signatures.
    ///
    /// From [§14.4.1, C2PA Signers] of the C2PA Technical Specification:
    ///
    /// > A validator shall maintain the following lists for C2PA signers:
    /// >
    /// > * The list of X.509 certificate trust anchors provided by the C2PA
    /// > (i.e., the C2PA Trust List).
    /// > * A list of additional X.509 certificate trust anchors.
    /// > * A list of accepted Extended Key Usage (EKU) values. _(not relevant
    /// > for this API)_
    /// >
    /// > NOTE: Some of these lists can be empty.
    /// >
    /// > In addition to the list of trust anchors provided in the C2PA Trust
    /// > List, a validator should allow a user to configure additional trust
    /// > anchor stores, and should provide default options or offer lists
    /// > maintained by external parties that the user may opt into to populate
    /// > the validator’s trust anchor store for C2PA signers.
    ///
    /// This function reads one or more X.509 root certificates in PEM format
    /// and configures the trust handler to accept certificates that chain up to
    /// these trust anchors.
    ///
    /// [§14.4.1, C2PA Signers]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_c2pa_signers
    fn set_trust_anchors(
        &mut self,
        trust_anchor_pems: &mut dyn Read,
    ) -> Result<(), TrustHandlerError>;

    // add allowed list
    fn load_allowed_list(&mut self, allowed_list: &mut dyn Read) -> Result<(), TrustHandlerError>;

    // append private trust anchors
    fn append_private_trust_data(
        &mut self,
        private_anchors_data: &mut dyn Read,
    ) -> Result<(), TrustHandlerError>;

    // clear all entries in trust handler list
    fn clear(&mut self);

    // load EKU configuration
    fn load_configuration(&mut self, config_data: &mut dyn Read) -> Result<(), TrustHandlerError>;

    // list off auxillary allowed EKU Oid
    fn get_auxillary_ekus(&self) -> Vec<Oid>;

    // list of all anchors
    fn get_anchors(&self) -> Vec<Vec<u8>>;

    // set of allowed cert hashes
    fn get_allowed_list(&self) -> &HashSet<String>;
}

impl fmt::Debug for dyn TrustHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrustHandler Installed")
    }
}

/// Describes errors that can be identified when configuring or using a
/// `TrustHandler` implementation.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TrustHandlerError {
    /// An invalid certificate was detected.
    #[error("Invalid certificate detected")]
    InvalidCertificate,

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

    /// An I/O error occurred while reading trust data.
    #[error("I/O error ({0})")]
    IoError(String),

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
    #[error("internal error ({0})")]
    InternalError(&'static str),
}

impl From<std::io::Error> for TrustHandlerError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for TrustHandlerError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::OpenSslError(err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<crate::webcrypto::WasmCryptoError> for TrustHandlerError {
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
