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

/// An implementation of `AsyncCredentialHolder` is able to generate a signature
/// over the `SignerPayload` data structure on behalf of a credential holder.
///
/// Implementations of this trait will specialize based on the kind of
/// credential as specified in [§8. Credentials, signatures, and validation
/// methods] from the CAWG Identity Assertion specification.
///
/// [§8. Credentials, signatures, and validation methods]: https://cawg.io/identity/1.1-draft/#_credentials_signatures_and_validation_methods

#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::builder::AsyncCredentialHolder"
)]
pub use c2pa::identity::builder::AsyncCredentialHolder;
/// An implementation of `CredentialHolder` is able to generate a signature
/// over the `SignerPayload` data structure on behalf of a credential holder.
///
/// If network calls are to be made, it is better to implement
/// `AsyncCredentialHolder`.
///
/// Implementations of this trait will specialize based on the kind of
/// credential as specified in [§8. Credentials, signatures, and validation
/// methods] from the CAWG Identity Assertion specification.
///
/// [§8. Credentials, signatures, and validation methods]: https://cawg.io/identity/1.1-draft/#_credentials_signatures_and_validation_methods
#[deprecated(
    since = "0.14.0",
    note = "Moved to c2pa::identity::builder::CredentialHolder"
)]
pub use c2pa::identity::builder::CredentialHolder;
