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

//! Tools for working with raw signature algorithms.

pub(crate) mod oids;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod openssl;

#[cfg(any(target_arch = "wasm32", feature = "rust_native_crypto", test))]
pub(crate) mod rust_native;

pub(crate) mod signer;
pub use signer::{
    async_signer_from_cert_chain_and_private_key, signer_from_cert_chain_and_private_key,
    AsyncRawSigner, RawSigner, RawSignerError,
};

mod signing_alg;
pub use signing_alg::{SigningAlg, UnknownAlgorithmError};

mod validator;
#[cfg(target_arch = "wasm32")]
pub(crate) use validator::async_validator_for_sig_and_hash_algs;
#[cfg(target_arch = "wasm32")]
pub use validator::async_validator_for_signing_alg;

pub(crate) use validator::validator_for_sig_and_hash_algs;
pub use validator::{
    validator_for_signing_alg, AsyncRawSignatureValidator, RawSignatureValidationError,
    RawSignatureValidator,
};
