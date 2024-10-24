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

use crate::builder::CredentialHolder;

/// An `IdentityAssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to a [`ManifestBuilder`],
/// it ensures that the proper data is added to the final C2PA Manifest.
///
/// [`ManifestBuilder`]: crate::builder::ManifestBuilder
pub struct IdentityAssertionBuilder {
    pub(crate) credential_holder: Box<dyn CredentialHolder>,
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
