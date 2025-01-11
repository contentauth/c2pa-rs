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

use std::fmt::Debug;

use async_trait::async_trait;
use c2pa::{DynamicAssertion, PreliminaryClaim};

use crate::builder::CredentialHolder;

/// An `IdentityAssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to an [`IdentityAssertionSigner`],
/// it ensures that the proper data is added to the final C2PA Manifest.
///
/// [`IdentityAssertionSigner`]: crate::builder::IdentityAssertionSigner
#[derive(Debug)]
pub struct IdentityAssertionBuilder {
    #[cfg(not(target_arch = "wasm32"))]
    credential_holder: Box<dyn CredentialHolder + Sync + Send>,

    #[cfg(target_arch = "wasm32")]
    credential_holder: Box<dyn CredentialHolder>,
    // referenced_assertions: Vec<MumbleSomething>,
}

impl IdentityAssertionBuilder {
    /// Create an `IdentityAssertionBuilder` for the given
    /// `CredentialHolder` instance.
    pub fn for_credential_holder<CH: CredentialHolder + 'static>(credential_holder: CH) -> Self {
        Self {
            credential_holder: Box::new(credential_holder),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl DynamicAssertion for IdentityAssertionBuilder {
    fn label(&self) -> String {
        "cawg.identity".to_string()
    }

    fn reserve_size(&self) -> usize {
        self.credential_holder.reserve_size()
        // TO DO: Credential holder will state reserve size for signature.
        // Add additional size for CBOR wrapper outside signature.
    }

    async fn content(
        &self,
        _label: &str,
        _size: Option<usize>,
        _claim: &PreliminaryClaim,
    ) -> c2pa::Result<Vec<u8>> {
        unimplemented!();
    }
}
