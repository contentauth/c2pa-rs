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

use crate::{
    identity::{builder::IdentityBuilderError, SignerPayload},
    maybe_send_sync::{MaybeSend, MaybeSync},
};

/// An implementation of `CredentialHolder` is able to generate a signature
/// over the [`SignerPayload`] data structure on behalf of a credential holder.
///
/// If network calls are to be made, it is better to implement
/// [`AsyncCredentialHolder`].
///
/// Implementations of this trait will specialize based on the kind of
/// credential as specified in [§8. Credentials, signatures, and validation
/// methods] from the CAWG Identity Assertion specification.
///
/// [§8. Credentials, signatures, and validation methods]: https://cawg.io/identity/1.1-draft/#_credentials_signatures_and_validation_methods
pub trait CredentialHolder {
    /// Returns the designated `sig_type` value for this kind of credential.
    fn sig_type(&self) -> &'static str;

    /// Returns the reserved size of the complete encoded identity assertion,
    /// including signer payload, signature, and padding. The signature alone
    /// cannot use this entire budget. Use
    /// [`IdentityAssertionBuilder::signature_capacity`](super::IdentityAssertionBuilder::signature_capacity)
    /// with the actual signer payload to calculate its available capacity.
    /// Signing fails if the signer payload and signature do not fit.
    ///
    /// [`sign`]: Self::sign
    /// [`Error::BadParam`]: crate::Error::BadParam
    fn reserve_size(&self) -> usize;

    /// Signs the [`SignerPayload`] data structure on behalf of the credential
    /// holder.
    ///
    /// If successful, returns the exact binary content to be placed in
    /// the `signature` field for this identity assertion.
    ///
    /// The signature and assertion wrapper MUST fit the budget previously stated
    /// by the [`reserve_size`] function.
    ///
    /// [`reserve_size`]: Self::reserve_size
    fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError>;
}

/// An implementation of `AsyncCredentialHolder` is able to generate a signature
/// over the [`SignerPayload`] data structure on behalf of a credential holder.
///
/// Implementations of this trait will specialize based on the kind of
/// credential as specified in [§8. Credentials, signatures, and validation
/// methods] from the CAWG Identity Assertion specification.
///
/// [§8. Credentials, signatures, and validation methods]: https://cawg.io/identity/1.1-draft/#_credentials_signatures_and_validation_methods
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncCredentialHolder: MaybeSync + MaybeSend {
    /// Returns the designated `sig_type` value for this kind of credential.
    fn sig_type(&self) -> &'static str;

    /// Returns the reserved size of the complete encoded identity assertion,
    /// including signer payload, signature, and padding. The signature alone
    /// cannot use this entire budget. Use
    /// [`IdentityAssertionBuilder::signature_capacity`](super::IdentityAssertionBuilder::signature_capacity)
    /// with the actual signer payload to calculate its available capacity.
    /// Signing fails if the signer payload and signature do not fit.
    ///
    /// [`sign`]: Self::sign
    /// [`Error::BadParam`]: crate::Error::BadParam
    fn reserve_size(&self) -> usize;

    /// Signs the [`SignerPayload`] data structure on behalf of the credential
    /// holder.
    ///
    /// If successful, returns the exact binary content to be placed in
    /// the `signature` field for this identity assertion.
    ///
    /// The signature and assertion wrapper MUST fit the budget previously stated
    /// by the [`reserve_size`] function.
    ///
    /// [`reserve_size`]: Self::reserve_size
    async fn sign(&self, signer_payload: &SignerPayload) -> Result<Vec<u8>, IdentityBuilderError>;
}
