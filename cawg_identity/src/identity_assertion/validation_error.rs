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

#![allow(unused)] // TEMPORARY while building

use std::fmt::Debug;

/// Describes the ways in which a CAWG identity assertion can fail validation as
/// described in [§7. Validating the identity assertion].
///
/// This error type includes a parameter `SignatureError`, which allows
/// signature-type specific errors to be passed back. See
/// [`SignatureVerifier::Error`].
///
/// [§7. Validating the identity assertion]: https://creator-assertions.github.io/identity/1.0-draft/#_validating_the_identity_assertion
/// [`SignatureVerifier::Error`]: crate::SignatureVerifier::Error
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ValidationError<SignatureError> {
    /// The referenced assertion could not be found in the claim.
    #[error("no assertion with the label {0:#?} in the claim")]
    AssertionNotInClaim(String),

    /// The referenced assertion exists in the claim, but the hash does not
    /// match.
    #[error("the assertion with the label {0:#?} is not the same as in the claim")]
    AssertionMismatch(String),

    /// The referenced assertion was referenced more than once by the identity
    /// assertion.
    #[error("the named with the label {0:#?} is referenced multiple times")]
    DuplicateAssertionReference(String),

    /// No hard-binding assertion was referenced by the identity assertion.
    #[error("no hard binding assertion is referenced")]
    NoHardBindingAssertion,

    /// The `sig_type` field is not recognized.
    #[error("unable to parse a signature of type {0:#?}")]
    UnknownSignatureType(String),

    /// The signature is not valid.
    #[error("signature is invalid")]
    InvalidSignature,

    /// The `pad1` or `pad2` fields contain values other than 0x00 bytes.
    #[error("invalid padding")]
    InvalidPadding,

    /// Signature-specific error.
    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    /// An unexpected internal error occured while parsing the identity
    /// assertion.
    #[error("internal error ({0})")]
    InternalError(String),
}
