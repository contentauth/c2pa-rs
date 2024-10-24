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

use crate::identity_assertion::{NamedActor, SignerPayload, ValidationResult};

/// A `SignatureHandler` can read one kind of signature from an identity
/// assertion, assess the validity of the signature, and return information
/// about the corresponding credential subject.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait SignatureHandler {
    /// Returns true if this handler can process a signature with
    /// the given `sig_type` code.
    fn can_handle_sig_type(sig_type: &str) -> bool;

    /// Check the signature, returning an instance of [`NamedActor`] if
    /// the signature is valid.
    ///
    /// Will only be called if `can_handle_sig_type` returns `true`
    /// for this signature.
    async fn check_signature<'a>(
        &self,
        signer_payload: &SignerPayload,
        signature: &'a [u8],
    ) -> ValidationResult<Box<dyn NamedActor<'a>>>;
}
