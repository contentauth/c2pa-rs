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

pub use c2pa_status_tracker::validation_codes::*;
use c2pa_status_tracker::{LogItem, StatusTracker};
use log::debug;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{assertion::AssertionBase, assertions::Ingredient, error::Error, jumbf, store::Store};

/// A `ValidationStatus` struct describes the validation status of a
/// specific part of a manifest.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_existing_manifests>.
#[derive(Clone, Debug, Deserialize, Serialize, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ValidationStatus {
    code: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<String>,

    #[serde(skip_serializing)]
    #[allow(dead_code)]
    success: Option<bool>, // deprecated in 2.x, allow reading for compatibility
}

impl ValidationStatus {
    pub(crate) fn new<S: Into<String>>(code: S) -> Self {
        Self {
            code: code.into(),
            url: None,
            explanation: None,
            success: None,
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
    pub fn set_url<S: Into<String>>(mut self, url: S) -> Self {
        self.url = Some(url.into());
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
    fn code_from_error_str(error: &str) -> &str {
        match error {
            e if e.starts_with("ClaimMissing") => CLAIM_MISSING,
            e if e.starts_with("AssertionMissing") => ASSERTION_MISSING,
            e if e.starts_with("AssertionDecoding") => ASSERTION_REQUIRED_MISSING,
            e if e.starts_with("HashMismatch") => ASSERTION_DATAHASH_MATCH,
            e if e.starts_with("RemoteManifestFetch") => MANIFEST_INACCESSIBLE,
            e if e.starts_with("PrereleaseError") => STATUS_PRERELEASE,
            _ => GENERAL_ERROR,
        }
    }

    // Maps errors into validation_status codes.
    fn code_from_error(error: &Error) -> &str {
        match error {
            Error::ClaimMissing { .. } => CLAIM_MISSING,
            Error::AssertionMissing { .. } => ASSERTION_MISSING,
            Error::AssertionDecoding(_code) => ASSERTION_REQUIRED_MISSING, /* todo detect json/cbor errors */
            Error::HashMismatch(_) => ASSERTION_DATAHASH_MATCH,
            Error::RemoteManifestFetch(_) => MANIFEST_INACCESSIBLE,
            Error::PrereleaseError => STATUS_PRERELEASE,
            _ => GENERAL_ERROR,
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
                let code = Self::code_from_error_str(e);
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

use crate::validation_results::ValidationResultsMap;
/// Given a `Store` and a `StatusTracker`, return `ValidationResultsMap
pub fn validation_results_for_store(
    store: &Store,
    validation_log: &impl StatusTracker,
) -> ValidationResultsMap {
    let mut results = ValidationResultsMap::default();

    let mut statuses: Vec<ValidationStatus> = validation_log
        .logged_items()
        .iter()
        .filter_map(ValidationStatus::from_validation_item)
        .collect();

    // Filter out any status that is already captured in an ingredient assertion.
    if let Some(claim) = store.provenance_claim() {
        let active_manifest = Some(claim.label().to_string());

        // This closure returns true if the URI references the store's active manifest.
        let is_active_manifest = |uri: Option<&str>| {
            uri.map_or(false, |uri| {
                jumbf::labels::manifest_label_from_uri(uri) == active_manifest
            })
        };

        // Convert any relative manifest urls found in ingredient validation statuses to absolute.
        let make_absolute = |i: Ingredient| {
            i.validation_status.map(|mut statuses| {
                if let Some(label) = i
                    .active_manifest
                    .as_ref()
                    .or(i.c2pa_manifest.as_ref())
                    .map(|m| m.url())
                    .and_then(|uri| jumbf::labels::manifest_label_from_uri(&uri))
                {
                    for status in &mut statuses {
                        if let Some(url) = &status.url {
                            if url.starts_with("self#jumbf") {
                                // Some are just labels (i.e. "Cose_Sign1")
                                status.url = Some(jumbf::labels::to_absolute_uri(&label, url));
                            }
                        }
                    }
                }
                statuses
            })
        };

        // We only need to do the more detailed filtering if there are any status
        // reports that reference ingredients.
        if statuses
            .iter()
            .any(|s| !is_active_manifest(s.url.as_deref()))
        {
            // Collect all the ValidationStatus records from all the ingredients in the store.
            let ingredient_statuses: Vec<ValidationStatus> = store
                .claims()
                .iter()
                .flat_map(|c| c.ingredient_assertions())
                .filter_map(|a| Ingredient::from_assertion(a).ok())
                .filter_map(make_absolute)
                .flatten()
                .collect();

            // Filter statuses to only contain those from the active manifest and those not found in any ingredient.
            statuses.retain(|s| {
                is_active_manifest(s.url.as_deref()) || !ingredient_statuses.iter().any(|i| i == s)
            })
        }
        let active_manifest_label = claim.label().to_string();
        for status in statuses {
            results.add_status(&active_manifest_label, status);
        }
    }
    results
}

// TODO: Does this still need to be public? (I do see one reference in the JS SDK.)

/// Given a `Store` and a `StatusTracker`, return `ValidationStatus` items for each
/// item in the tracker which reflect errors in the active manifest or which would not
/// be reported as a validation error for any ingredient.
pub fn status_for_store(
    store: &Store,
    validation_log: &impl StatusTracker,
) -> Vec<ValidationStatus> {
    let validation_results = validation_results_for_store(store, validation_log);
    validation_results.validation_errors().unwrap_or_default()
    // let results = validation_results
    //     .active_manifest()
    //     .map_or_else(Vec::new, |m| m.failure().clone());
    // let results2 = validation_results
    //     .ingredient_deltas()
    //     .map_or_else(Vec::new, |v| {
    //         v.iter()
    //             .flat_map(|i| i.validation_deltas().failure().clone())
    //             .collect()
    //     });
    // results.into_iter().chain(results2).collect()
}

// -- unofficial status code --

pub(crate) const STATUS_PRERELEASE: &str = "com.adobe.prerelease";
