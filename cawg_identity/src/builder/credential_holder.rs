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

use async_trait::async_trait;

use crate::SignerPayload;

/// An implementation of `CredentialHolder` is able to generate a signature over
/// the [`SignerPayload`] data structure on behalf of a credential holder.
///
/// Implementations of this trait will specialize based on the kind of
/// credential as specified in [§8. Credentials, signatures, and validation
/// methods] from the CAWG Identity Assertion specification.
///
/// [§8. Credentials, signatures, and validation methods]: https://creator-assertions.github.io/identity/1.0-draft/#_credentials_signatures_and_validation_methods
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait CredentialHolder {
    /// Returns the designated `sig_type` value for this kind of credential.
    fn sig_type(&self) -> &'static str;

    /// Returns the maximum expected size in bytes of the `signature`
    /// field for the identity assertion which will be subsequently
    /// returned by the [`sign`] function. Signing will fail if the
    /// subsequent signature is larger than this number of bytes.
    ///
    /// [`sign`]: Self::sign
    fn reserve_size(&self) -> usize;

    /// Signs the [`SignerPayload`] data structure on behalf of the credential
    /// holder.
    ///
    /// If successful, returns the exact binary content to be placed in
    /// the `signature` field for this identity assertion.
    ///
    /// The signature MUST NOT be larger than the size previously stated
    /// by the [`reserve_size`] function.
    ///
    /// [`reserve_size`]: Self::reserve_size
    async fn sign(&self, signer_payload: &SignerPayload) -> c2pa::Result<Vec<u8>>;
}
