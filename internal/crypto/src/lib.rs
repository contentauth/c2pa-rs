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

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]
#![deny(warnings)]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg, doc_cfg_hide))]

pub mod asn1;
pub mod base64;
pub mod hash;
pub(crate) mod internal;

pub mod ocsp;

#[cfg(all(feature = "openssl", not(target_arch = "wasm32")))]
pub mod openssl;

#[cfg(all(feature = "openssl", target_arch = "wasm32"))]
compile_error!("OpenSSL feature is not compatible with WASM platform");

pub mod raw_signature;

mod signing_alg;
pub use signing_alg::{SigningAlg, UnknownAlgorithmError};

pub mod time_stamp;
pub mod validation_codes;

#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
pub mod webcrypto;

#[cfg(test)]
pub(crate) mod tests;
