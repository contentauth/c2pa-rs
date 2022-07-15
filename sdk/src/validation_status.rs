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

use log::debug;
use serde::{Deserialize, Serialize};

use crate::{
    assertion::AssertionBase,
    assertions::Ingredient,
    error::Error,
    jumbf,
    status_tracker::{LogItem, StatusTracker},
    store::Store,
};

/// A `ValidationStatus` struct describes the validation status of a
/// specific part of a manifest.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_existing_manifests>.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationStatus {
    code: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<String>,
}

impl ValidationStatus {
    pub(crate) fn new<S: Into<String>>(code: S) -> Self {
        Self {
            code: code.into(),
            url: None,
            explanation: None,
        }
    }

    /// Returns the validation status code.
    ///
    /// Validation status codes are the labels from the "Value"
    /// column in <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_existing_manifests>.
    ///
    /// These are also defined as constants in the
    /// [`validation_status`](crate::validation_status) mod.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the internal JUMBF reference to the entity that was validated.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Returns a human-readable description of the validation that was performed.
    pub fn explanation(&self) -> Option<&str> {
        self.explanation.as_deref()
    }

    /// Sets the internal JUMBF reference to the entity was validated.
    pub(crate) fn set_url(mut self, url: String) -> Self {
        self.url = Some(url);
        self
    }

    /// Sets the human-readable description of the validation that was performed.
    pub(crate) fn set_explanation(mut self, explanation: String) -> Self {
        self.explanation = Some(explanation);
        self
    }

    /// Returns `true` if this has a successful validation code.
    pub fn passed(&self) -> bool {
        is_success(&self.code)
    }

    // Maps errors into validation_status codes.
    fn code_from_error(error: &Error) -> &str {
        match error {
            Error::ClaimMissing { .. } => CLAIM_MISSING,
            Error::AssertionMissing { .. } => ASSERTION_MISSING,
            Error::AssertionDecoding(_code) => STATUS_ASSERTION_MALFORMED, // todo: no code for invalid assertion format
            Error::HashMismatch(_) => ASSERTION_DATAHASH_MATCH,
            Error::PrereleaseError => STATUS_PRERELEASE,
            _ => STATUS_OTHER,
        }
    }

    /// Creates a ValidationStatus from an error code.
    pub(crate) fn from_error(error: &Error) -> Self {
        // We need to create error codes here for client processing.
        let code = Self::code_from_error(error);
        debug!("ValidationStatus {} from error {:#?}", code, error);
        Self::new(code.to_string()).set_explanation(error.to_string())
    }

    /// Creates a ValidationStatus from a validation_log item.
    pub(crate) fn from_validation_item(item: &LogItem) -> Option<Self> {
        match item.validation_status.as_ref() {
            Some(status) => Some(
                Self::new(status.to_string())
                    .set_url(item.label.to_string())
                    .set_explanation(item.description.to_string()),
            ),
            // If we don't have a validation_status, then make one from the err_val
            // using the description plus error text explanation.
            None => item.err_val.as_ref().map(|e| {
                let code = Self::code_from_error(e);
                Self::new(code.to_string())
                    .set_url(item.label.to_string())
                    .set_explanation(format!("{}: {}", item.description, e))
            }),
        }
    }
}

impl PartialEq for ValidationStatus {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.url == other.url
    }
}

// TODO: Does this still need to be public? (I do see one reference in the JS SDK.)

/// Given a `Store` and a `StatusTracker`, return `ValidationStatus` items for each
/// item in the tracker which reflect errors in the active manifest or which would not
/// be reported as a validation error for any ingredient.
pub fn status_for_store(
    store: &Store,
    validation_log: &mut impl StatusTracker,
) -> Vec<ValidationStatus> {
    let statuses: Vec<ValidationStatus> = validation_log
        .get_log()
        .iter()
        .filter_map(ValidationStatus::from_validation_item)
        .filter(|s| !is_success(&s.code))
        .collect();

    // Filter out any status that is already captured in an ingredient assertion.
    if let Some(claim) = store.provenance_claim() {
        let active_manifest = Some(claim.label().to_string());

        // This closure returns true if the URI references the store's active manifest.
        let is_active_manifest = |uri: Option<&str>| {
            uri.filter(|uri| jumbf::labels::manifest_label_from_uri(uri) == active_manifest)
                .is_some()
        };

        // We only need to do the more detailed filtering if there are any status
        // reports that reference ingredients.
        if statuses
            .iter()
            .any(|s| !is_active_manifest(s.url.as_deref()))
        {
            // Collect all the ValidationStatus records from all the ingredients in the store.
            let ingredient_statuses: Vec<ValidationStatus> = claim
                .ingredient_assertions()
                .iter()
                .filter_map(|a| Ingredient::from_assertion(a).ok())
                .filter_map(|i| i.validation_status)
                .flat_map(|x| x.into_iter())
                .collect();

            // Filter to only contain the active statuses and nested statuses not found in active.
            return statuses
                .iter()
                .filter(|s| {
                    is_active_manifest(s.url.as_deref())
                        || !ingredient_statuses.iter().any(|i| s == &i)
                })
                .map(|s| s.to_owned())
                .collect();
        }
    }

    statuses
}

// -- success codes --

/// The claim signature referenced in the ingredient's claim validated.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_VALIDATED: &str = "claimSignature.validated";

/// The signing credential is listed on the validator's trust list.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const SIGNING_CREDENTIAL_TRUSTED: &str = "signingCredential.trusted";

/// The time-stamp credential is listed on the validator's trust list.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const TIMESTAMP_TRUSTED: &str = "timeStamp.trusted";

/// The hash of the the referenced assertion in the ingredient's manifest
/// matches the corresponding hash in the assertion's hashed URI in the claim.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_HASHEDURI_MATCH: &str = "assertion.hashedURI.match";

/// Hash of a byte range of the asset matches the hash declared in the
/// data hash assertion.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_DATAHASH_MATCH: &str = "assertion.dataHash.match";

/// Hash of a box-based asset matches the hash declared in the BMFF
/// hash assertion.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_BMFFHASH_MATCH: &str = "assertion.bmffHash.match";

/// A non-embedded (remote) assertion was accessible at the time of
/// validation.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_ACCESSIBLE: &str = "assertion.accessible";

// -- failure codes --

/// The referenced claim in the ingredient's manifest cannot be found.
///
/// `ValidationStatus.url()` will point to a C2PA claim box.
pub const CLAIM_MISSING: &str = "claim.missing";

/// More than one claim box is present in the manifest.
///
/// `ValidationStatus.url()` will point to a C2PA claim box.
pub const CLAIM_MULTIPLE: &str = "claim.multiple";

/// No hard bindings are present in the claim.
///
/// `ValidationStatus.url()` will point to a C2PA claim box.
pub const HARD_BINDINGS_MISSING: &str = "claim.hardBindings.missing";

/// The hash of the the referenced ingredient claim in the manifest
/// does not match the corresponding hash in the ingredient's hashed
/// URI in the claim.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const INGREDIENT_HASHEDURI_MISMATCH: &str = "ingredient.hashedURI.mismatch";

/// The claim signature referenced in the ingredient's claim
/// cannot be found in its manifest.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_MISSING: &str = "claimSignature.missing";

/// The claim signature referenced in the ingredient's claim
/// failed to validate.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const CLAIM_SIGNATURE_MISMATCH: &str = "claimSignature.mismatch";

/// The manifest has more than one ingredient whose `relationship`
/// is `parentOf`.
///
/// `ValidationStatus.url()` will point to a C2PA claim box.
pub const MANIFEST_MULTIPLE_PARENTS: &str = "manifest.multipleParents";

/// The manifest is an update manifest, but it contains hard binding
/// or actions assertions.
///
/// `ValidationStatus.url()` will point to a C2PA claim box.
pub const MANIFEST_UPDATE_INVALID: &str = "manifest.update.invalid";

/// The manifest is an update manifest, but it contains either zero
/// or multiple `parentOf` ingredients.
///
/// `ValidationStatus.url()` will point to a C2PA claim box.
pub const MANIFEST_UPDATE_WRONG_PARENTS: &str = "manifest.update.wrongParents";

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

/// The time-stamp credential is not listed on the validator's trust list.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const TIMESTAMP_UNTRUSTED: &str = "timeStamp.untrusted";

/// The signed time-stamp attribute in the signature falls outside the
/// validity window of the signing certificate or the TSA's certificate.
///
/// `ValidationStatus.url()` will point to a C2PA claim signature box.
pub const TIMESTAMP_OUTSIDE_VALIDITY: &str = "timeStamp.outsideValidity";

/// The hash of the the referenced assertion in the manifest does not
/// match the corresponding hash in the assertion's hashed URI in the claim.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_HASHEDURI_MISMATCH: &str = "assertion.hashedURI.mismatch";

/// An assertion listed in the ingredient's claim is missing from the
/// ingredient's manifest.
///
/// `ValidationStatus.url()` will point to a C2PA claim box.
pub const ASSERTION_MISSING: &str = "assertion.missing";

/// An assertion was found in the ingredient's manifest that was not
/// explicitly declared in the ingredient's claim.
///
/// `ValidationStatus.url()` will point to a C2PA claim box or assertion.
pub const ASSERTION_UNDECLARED: &str = "assertion.undeclared";

/// A non-embedded (remote) assertion was inaccessible at the time of validation.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_INACCESSIBLE: &str = "assertion.inaccessible";

/// An assertion was declared as redacted in the ingredient's claim
/// but is still present in the ingredient's manifest.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_NOT_REDACTED: &str = "assertion.notRedacted";

/// An assertion was declared as redacted by its own claim.
///
/// `ValidationStatus.url()` will point to a C2PA claim box.
pub const ASSERTION_SELF_REDACTED: &str = "assertion.selfRedacted";

/// An `action` assertion was redacted when the ingredient's
/// claim was created.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ACTION_ASSERTION_REDACTED: &str = "assertion.action.redacted";

/// The hash of a byte range of the asset does not match the
/// hash declared in the data hash assertion.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_DATAHASH_MISMATCH: &str = "assertion.dataHash.mismatch";

/// The hash of a box-based asset does not match the hash declared
/// in the BMFF hash assertion.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_BMFFHASH_MISMATCH: &str = "assertion.bmffHash.mismatch";

/// A hard binding assertion is in a cloud data assertion.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_CLOUDDATA_HARD_BINDING: &str = "assertion.clouddata.hardBinding";

/// An update manifest contains a cloud data assertion referencing
/// an actions assertion.
///
/// `ValidationStatus.url()` will point to a C2PA assertion.
pub const ASSERTION_CLOUDDATA_ACTIONS: &str = "assertion.clouddata.actions";

/// The value of an `alg` header, or other header that specifies an
/// algorithm used to compute the value of another field, is unknown
/// or unsupported.
///
/// `ValidationStatus.url()` will point to a C2PA claim box or C2PA assertion.
pub const ALGORITHM_UNSUPPORTED: &str = "algorithm.unsupported";

// -- unofficial status codes --

pub(crate) const STATUS_OTHER: &str = "com.adobe.other";
pub(crate) const STATUS_PRERELEASE: &str = "com.adobe.prerelease";
pub(crate) const STATUS_ASSERTION_MALFORMED: &str = "com.adobe.assertion.malformed";

/// Returns `true` if the status code is a known C2PA success status code.
///
/// Returns `false` if the status code is a known C2PA failure status
/// code or is unknown.
///
/// # Examples
///
/// ```
/// use c2pa::validation_status::*;
///
/// assert!(is_success(CLAIM_SIGNATURE_VALIDATED));
/// assert!(!is_success(SIGNING_CREDENTIAL_REVOKED));
/// ```
pub fn is_success(status_code: &str) -> bool {
    matches!(
        status_code,
        CLAIM_SIGNATURE_VALIDATED
            | SIGNING_CREDENTIAL_TRUSTED
            | TIMESTAMP_TRUSTED
            | ASSERTION_HASHEDURI_MATCH
            | ASSERTION_DATAHASH_MATCH
            | ASSERTION_BMFFHASH_MATCH
            | ASSERTION_ACCESSIBLE
    )
}
