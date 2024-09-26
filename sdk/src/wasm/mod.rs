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

#[cfg(target_arch = "wasm32")]
pub(crate) mod context;
#[cfg(target_arch = "wasm32")]
pub(crate) mod rsa_wasm_signer;
#[cfg(target_arch = "wasm32")]
#[allow(unused)]
pub(crate) use rsa_wasm_signer::RsaWasmSignerAsync;
#[cfg(target_arch = "wasm32")]
pub(crate) mod util;
#[cfg(target_arch = "wasm32")]
pub(crate) mod webcrypto_validator;
#[cfg(target_arch = "wasm32")]
pub use webcrypto_validator::validate_async;
#[cfg(target_arch = "wasm32")]
pub(crate) mod webpki_trust_handler;
#[cfg(target_arch = "wasm32")]
pub(crate) use webpki_trust_handler::verify_data;
#[cfg(target_arch = "wasm32")]
pub(crate) use webpki_trust_handler::WebTrustHandlerConfig;
