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

#[cfg(feature = "openssl")]
mod openssl_trust_handler;
#[cfg(test)]
pub(crate) mod temp_signer;

#[cfg(feature = "openssl")]
pub(crate) use openssl_trust_handler::verify_trust;
#[cfg(feature = "openssl")]
pub(crate) use openssl_trust_handler::OpenSSLTrustHandlerConfig;

#[cfg(test)]
pub(crate) mod temp_signer_async;

#[cfg(test)]
#[allow(unused_imports)]
#[cfg(feature = "openssl")]
pub(crate) use temp_signer_async::AsyncSignerAdapter;
