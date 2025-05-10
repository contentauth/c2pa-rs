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

/// Describes the ways in which a CAWG identity assertion can fail validation as
/// described in [§7. Validating the identity assertion].
///
/// This error type includes a parameter `SignatureError`, which allows
/// signature-type specific errors to be passed back. See
/// [`SignatureVerifier::Error`].
///
/// [§7. Validating the identity assertion]: https://creator-assertions.github.io/identity/1.0-draft/#_validating_the_identity_assertion
/// [`SignatureVerifier::Error`]: crate::SignatureVerifier::Error
#[deprecated(since = "0.14.0", note = "Moved to c2pa::identity::ValidationError")]
pub use c2pa::identity::ValidationError;
