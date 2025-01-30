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

use std::fmt::{Debug, Formatter};

use c2pa::Manifest;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    identity_assertion::signer_payload::SignerPayload, internal::debug_byte_slice::DebugByteSlice,
    SignatureVerifier, ValidationError,
};

/// This struct represents the raw content of the identity assertion.
///
/// Use [`AsyncIdentityAssertionBuilder`] and -- at your option,
/// [`AsyncIdentityAssertionSigner`] -- to ensure correct construction of a new
/// identity assertion.
///
/// [`AsyncIdentityAssertionBuilder`]: crate::builder::AsyncIdentityAssertionBuilder
/// [`AsyncIdentityAssertionSigner`]: crate::builder::AsyncIdentityAssertionSigner
#[derive(Deserialize, Serialize)]
pub struct IdentityAssertion {
    pub(crate) signer_payload: SignerPayload,

    #[serde(with = "serde_bytes")]
    pub(crate) signature: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pub(crate) pad1: Vec<u8>,

    // Must use explicit ByteBuf here because #[serde(with = "serde_bytes")]
    // does not work with Option<Vec<u8>>.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pad2: Option<ByteBuf>,
}

impl IdentityAssertion {
    /// Find the `IdentityAssertion`s that may be present in a given
    /// [`Manifest`].
    ///
    /// Iterator returns a [`Result`] because each assertion may fail to parse.
    ///
    /// Aside from CBOR parsing, no further validation is performed.
    pub fn from_manifest(
        manifest: &Manifest,
    ) -> impl Iterator<Item = Result<Self, c2pa::Error>> + use<'_> {
        manifest
            .assertions()
            .iter()
            .filter(|a| a.label().starts_with("cawg.identity"))
            .map(|a| a.to_assertion())
    }

    /// Using the provided [`SignatureVerifier`], check the validity of this
    /// identity assertion.
    ///
    /// If successful, returns the credential-type specific information that can
    /// be derived from the signature. This is the [`SignatureVerifier::Output`]
    /// type which typically describes the named actor, but may also contain
    /// information about the time of signing or the credential's source.
    pub async fn validate<SV: SignatureVerifier>(
        &self,
        manifest: &Manifest,
        verifier: &SV,
    ) -> Result<SV::Output, ValidationError<SV::Error>> {
        self.check_padding()?;

        self.signer_payload.check_against_manifest(manifest)?;

        verifier
            .check_signature(&self.signer_payload, &self.signature)
            .await
    }

    fn check_padding<E>(&self) -> Result<(), ValidationError<E>> {
        if !self.pad1.iter().all(|b| *b == 0) {
            return Err(ValidationError::InvalidPadding);
        }

        if let Some(pad2) = self.pad2.as_ref() {
            if !pad2.iter().all(|b| *b == 0) {
                return Err(ValidationError::InvalidPadding);
            }
        }

        Ok(())
    }
}

impl Debug for IdentityAssertion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("IdentityAssertion")
            .field("signer_payload", &self.signer_payload)
            .field("signature", &DebugByteSlice(&self.signature))
            .finish()
    }
}
