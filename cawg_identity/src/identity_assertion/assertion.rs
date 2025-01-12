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

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    identity_assertion::signer_payload::SignerPayload, internal::debug_byte_slice::DebugByteSlice,
};

/// This struct represents the raw content of the identity assertion.
///
/// Use [`IdentityAssertionBuilder`] and -- at your option,
/// [`IdentityAssertionSigner`] to ensure correct construction of a new identity
/// assertion.
///
/// [`IdentityAssertionBuilder`]: crate::builder::IdentityAssertionBuilder
/// [`IdentityAssertionSigner`]: crate::builder::IdentityAssertionSigner
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

impl Debug for IdentityAssertion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("IdentityAssertion")
            .field("signer_payload", &self.signer_payload)
            .field("signature", &DebugByteSlice(&self.signature))
            .finish()
    }
}
