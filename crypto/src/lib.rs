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

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
// #![deny(missing_docs)] // SOON!
#![deny(warnings)]
#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg, doc_cfg_hide))]

// Public modules
pub mod cose_sign;
#[cfg(feature = "openssl")]
pub mod create_signer;
pub mod validation_status;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub mod cose_validator; // [scouten 2024-06-27]: Hacking to make public.
pub(crate) mod error;
pub(crate) mod ocsp_utils;

#[cfg(all(feature = "openssl", target_arch = "wasm32"))]
compile_error!("The openssl feature can not be used on WASM builds.");

#[cfg(feature = "openssl")]
pub mod openssl; // [scouten 2024-06-27]: Hacking to make public.

pub(crate) mod signer;
pub(crate) mod signing_alg;
pub mod status_tracker; // [scouten 2024-06-27]: Hacking to make this public.
                        // pub(crate) mod store;
pub(crate) mod time_stamp;
pub(crate) mod trust_config;
pub mod validator; // [scouten 2024-06-27]: Hacking to make public.

pub(crate) mod internal;

#[cfg(test)]
pub(crate) mod tests;

pub use error::{Error, Result};
pub use signer::{AsyncSigner, RemoteSigner, Signer};
pub use signing_alg::SigningAlg;
pub use trust_config::{
    trust_handler_config::TrustHandlerConfig, trust_pass_through::TrustPassThrough,
};
