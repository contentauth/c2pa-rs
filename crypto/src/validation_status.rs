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

//! Implements validation status for specific parts of a manifest.
//!
//! See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_existing_manifests>.

#![deny(missing_docs)]

/// The claim signature referenced in the ingredient's claim validated.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_VALIDATED: &str = "claimSignature.validated";

/// The signing credential is listed on the validator's trust list.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_TRUSTED: &str = "signingCredential.trusted";

/// The claim signature referenced in the ingredient's claim
/// failed to validate.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_MISMATCH: &str = "claimSignature.mismatch";

/// The signing credential is not listed on the validator's trust list.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_UNTRUSTED: &str = "signingCredential.untrusted";

/// The signing credential is not valid for signing.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_INVALID: &str = "signingCredential.invalid";

/// The signing credential has been revoked by the issuer.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_REVOKED: &str = "signingCredential.revoked";

/// The signing credential has expired.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_EXPIRED: &str = "signingCredential.expired";

/// The time-stamp does not correspond to the contents of the claim.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const TIMESTAMP_MISMATCH: &str = "timeStamp.mismatch";

/// The signed time-stamp attribute in the signature falls outside the
/// validity window of the signing certificate or the TSA's certificate.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const TIMESTAMP_OUTSIDE_VALIDITY: &str = "timeStamp.outsideValidity";
/// The value of an `alg` header, or other header that specifies an
/// algorithm used to compute the value of another field, is unknown
/// or unsupported.
///
/// `ValidationStatus.url()` will point to a C2PA claim box or C2PA assertion.
pub const ALGORITHM_UNSUPPORTED: &str = "algorithm.unsupported";
