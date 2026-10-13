// Copyright 2022 Adobe. All rights reserved.
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

use thiserror::Error;

/// `InvalidClaimError` provides additional detail on error cases for
/// [`Store::from_jumbf`](crate::store::Store::from_jumbf).
#[derive(Debug, Error)]
pub enum InvalidClaimError {
    /// The "c2pa" block was not found in the asset.
    #[error("\"c2pa\" block not found")]
    C2paBlockNotFound,

    #[error("\"c2pa\" multiple claim boxes found in manifest")]
    C2paMultipleClaimBoxes,

    /// More than one core manifest box of the same type was found.
    #[error("\"c2pa\" multiple manifest boxes of the same type found in manifest")]
    C2paMultipleManifestBoxes,

    /// The claim superbox was not found.
    #[error("claim superbox not found")]
    ClaimSuperboxNotFound,

    /// The claim description box was not found.
    #[error("claim description box not found")]
    ClaimDescriptionBoxNotFound,

    /// More than one claim description box was found.
    #[error("more than one claim description box was found for {label}")]
    DuplicateClaimBox { label: String },

    /// The expected data not found in claim box.
    #[error("claim cbor box not valid")]
    ClaimBoxData,

    /// The claim has a version that is newer than supported by this crate.
    #[error("claim version is too new, not supported")]
    ClaimVersionTooNew,

    /// The claim has a version does not match JUMBF box label.
    #[error("claim version does not match JUMBF box label")]
    ClaimBoxVersion,

    /// The claim description box could not be parsed.
    #[error("claim description box was invalid")]
    ClaimDescriptionBoxInvalid,

    /// The claim signature box was not found.
    #[error("claim signature box was not found")]
    ClaimSignatureBoxNotFound,

    /// The claim signature description box was not found.
    #[error("claim signature description box was not found")]
    ClaimSignatureDescriptionBoxNotFound,

    /// The claim signature description box was invalid.
    #[error("claim signature description box was invalid")]
    ClaimSignatureDescriptionBoxInvalid,

    /// The assertion store superbox was not found.
    #[error("assertion store superbox not found")]
    AssertionStoreSuperboxNotFound,

    /// The verifiable credentials store could not be read.
    #[error("the verifiable credentials store could not be read")]
    VerifiableCredentialStoreInvalid,

    /// The feature is not supported by version
    #[error("the manifest contained a feature not support by version")]
    UnsupportedFeature(String),

    /// The assertion store does not contain the expected number of assertions.
    #[error(
        "unexpected number of assertions in assertion store (expected {expected}, found {found})"
    )]
    AssertionCountMismatch { expected: usize, found: usize },
}
