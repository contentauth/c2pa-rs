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

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

// Note: `SigningAlg` is defined in this crate, so `#[non_exhaustive]` does not
// force a wildcard arm on the matches below; downstream crates, however, must
// account for future algorithms.
//
// Backend selection: `rust_native_crypto` takes precedence. When both features
// are enabled (which can happen through Cargo feature unification in a
// workspace), the signer/validator dispatch uses the rust-native backend; the
// OpenSSL backend is still compiled but goes unused. The OpenSSL backend is
// exercised only when `openssl` is enabled and `rust_native_crypto` is not.

pub mod ec_utils;
pub mod oids;

mod oid;
pub use oid::Oid;

// The OpenSSL backend is *compiled* whenever the `openssl` feature is enabled,
// but the runtime dispatch (see `signer.rs` / `validator.rs`) only selects it
// when `rust_native_crypto` is not also enabled. This split keeps the API
// surface (e.g. `OpenSslMutex`) consistent for downstream crates regardless of
// how Cargo unifies features.
#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "openssl")]
pub use openssl::{OpenSslMutex, OpenSslMutexUnavailable};

#[cfg(feature = "rust_native_crypto")]
mod rust_native;

mod signer;
pub use signer::{signer_from_private_key, RawSigner, RawSignerError};

mod signing_alg;
pub use signing_alg::{SigningAlg, UnknownAlgorithmError};

#[cfg(test)]
mod tests;

mod validator;
pub use validator::{
    validator_for_sig_and_hash_algs, validator_for_signing_alg, RawSignatureValidationError,
    RawSignatureValidator,
};
