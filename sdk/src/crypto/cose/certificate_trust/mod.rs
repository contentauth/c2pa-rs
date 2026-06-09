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

//! Backends for checking X.509 certificate trust against a
//! [`CertificateTrustPolicy`](super::CertificateTrustPolicy).
//!
//! The active backend mirrors the cryptography backend selected for
//! `c2pa-raw-crypto`.

// The OpenSSL trust backend is only used when `openssl` is enabled and
// `rust_native_crypto` is not; when both are enabled the dispatch in
// `certificate_trust_policy.rs` prefers `rust_native_crypto` (mirroring
// `c2pa-raw-crypto`). Gating the module to match that dispatch avoids compiling
// it as dead code.
#[cfg(all(feature = "openssl", not(feature = "rust_native_crypto")))]
pub(crate) mod openssl;

#[cfg(feature = "rust_native_crypto")]
pub(crate) mod rust_native;
