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

/// An `AsyncIdentityAssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to an
/// [`AsyncIdentityAssertionSigner`], it ensures that the proper data is added
/// to the final C2PA Manifest.
///
/// Use this when the overall C2PA Manifest signing path is asynchronous.
///
/// [`AsyncIdentityAssertionSigner`]: crate::builder::AsyncIdentityAssertionSigner
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::builder::AsyncIdentityAssertionBuilder"
)]
pub use c2pa::identity::builder::AsyncIdentityAssertionBuilder;
/// An `IdentityAssertionBuilder` gathers together the necessary components
/// for an identity assertion. When added to an [`IdentityAssertionSigner`],
/// it ensures that the proper data is added to the final C2PA Manifest.
///
/// Use this when the overall C2PA Manifest signing path is synchronous.
/// Note that this may limit the available set of credential holders.
///
/// Prefer [`AsyncIdentityAssertionBuilder`] when the C2PA Manifest signing
/// path is asynchronous or any network calls will be made by the
/// `CredentialHolder` implementation.
///
/// [`IdentityAssertionSigner`]: crate::builder::IdentityAssertionSigner
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::builder::IdentityAssertionBuilder"
)]
pub use c2pa::identity::builder::IdentityAssertionBuilder;
