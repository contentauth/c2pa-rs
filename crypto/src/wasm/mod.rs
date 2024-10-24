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

pub(crate) mod context;

pub(crate) mod rsa_wasm_signer;
#[allow(unused)]
pub(crate) use rsa_wasm_signer::{RsaWasmSigner, RsaWasmSignerAsync};

mod hash_by_alg;
pub(crate) mod webcrypto_validator;
pub use webcrypto_validator::validate_async;
pub(crate) mod webpki_trust_handler;

#[allow(unused_imports)] // TEMPORARY: Figure this out later.
pub(crate) use webpki_trust_handler::verify_data;
#[allow(unused_imports)] // TEMPORARY: Figure this out later.
pub(crate) use webpki_trust_handler::WebTrustHandlerConfig;
