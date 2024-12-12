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

/// An implementation of `TrustHandlerConfig` retains information about trust
/// lists and allowed EKUs to be used when verifying signing certificates.
pub trait TrustHandlerConfig: RefUnwindSafe + UnwindSafe + Sync + Send {
    // add trust anchors
    fn load_trust_anchors_from_data(
        &mut self,
        trust_data: &mut dyn Read,
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

impl fmt::Debug for dyn TrustHandlerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TrustHandler Installed")
    }
}

/// Describes errors that can be identified when configuring a
/// `TrustHandlerConfig` implementation.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TrustHandlerError {
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
