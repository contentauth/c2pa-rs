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

/// Describes the ways in which a CAWG identity
/// assertion can fail validation as described in
/// [§7. Validating the identity assertion].
///
/// [§7. Validating the identity assertion]: https://creator-assertions.github.io/identity/1.0-draft/#_validating_the_identity_assertion
/// [`IdentityAssertion`]: crate::IdentityAssertion
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ValidationError {
    /// The named assertion could not be found in the claim.
    #[error("No assertion with the label {0:#?} in the claim")]
    AssertionNotInClaim(String),

    /// The named assertion exists in the claim, but the hash does not match.
    #[error("The assertion with the label {0:#?} is not the same as in the claim")]
    AssertionMismatch(String),

    /// The named assertion was referenced more than once in the identity
    /// assertion.
    #[error("The assertion with the label {0:#?} is referenced multiple times")]
    MultipleAssertionReferenced(String),

    /// No hard-binding assertion was referenced in the identity assertion.
    #[error("No hard binding assertion is referenced")]
    NoHardBindingAssertion,

    /// The `sig_type` field is not recognized.
    #[error("Unable to parse a signature of type {0:#?}")]
    UnknownSignatureType(String),

    /// The signature is not valid.
    #[error("Signature is invalid")]
    InvalidSignature,

    /// The `pad1` or `pad2` fields contain values other than 0x00 bytes.
    #[error("Invalid padding")]
    InvalidPadding,

    /// Unexpected error while parsing or validating the identity assertion.
    #[error("Unexpected error")]
    UnexpectedError,
}

/// Result type for validation operations.
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;
