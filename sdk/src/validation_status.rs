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
//! See <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_existing_manifests>.

#![deny(missing_docs)]

use log::debug;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cfg(feature = "v1_api")]
use crate::status_tracker::StatusTracker;
#[cfg(feature = "v1_api")]
use crate::store::Store;
pub use crate::validation_results::validation_codes::*;
use crate::{
    error::Error,
    jumbf,
    status_tracker::{LogItem, LogKind},
};

/// A `ValidationStatus` struct describes the validation status of a
/// specific part of a manifest.
///
/// See <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_existing_manifests>.
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

    #[serde(skip)]
    #[serde(default = "default_log_kind")]
    kind: LogKind,

    #[serde(skip)]
    ingredient_uri: Option<String>,
}

fn default_log_kind() -> LogKind {
    LogKind::Success
}

impl ValidationStatus {
    pub(crate) fn new<S: Into<String>>(code: S) -> Self {
        Self {
            code: code.into(),
            url: None,
            explanation: None,
            success: None,
            ingredient_uri: None,
            kind: LogKind::Success,
        }
    }

    pub(crate) fn new_failure<S: Into<String>>(code: S) -> Self {
        Self::new(code).set_kind(LogKind::Failure)
    }

    /// Returns the validation status code.
    ///
    /// Validation status codes are the labels from the "Value"
    /// column in <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_existing_manifests>.
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

    /// Returns the internal JUMBF reference to the Ingredient that was validated.
    pub fn ingredient_uri(&self) -> Option<&str> {
        self.ingredient_uri.as_deref()
    }

    /// Sets the internal JUMBF reference to the entity was validated.
    pub fn set_url<S: Into<String>>(mut self, url: S) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Sets the LogKind for this validation status.
    pub fn set_kind(mut self, kind: LogKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets the internal JUMBF reference to the Ingredient that was validated.
    pub fn set_ingredient_uri<S: Into<String>>(mut self, uri: S) -> Self {
        self.ingredient_uri = Some(uri.into());
        self
    }

    /// Sets the human-readable description of the validation that was performed.
    pub(crate) fn set_explanation(mut self, explanation: String) -> Self {
        self.explanation = Some(explanation);
        self
    }

    /// Returns `true` if this has a successful validation code.
    pub fn passed(&self) -> bool {
        self.kind != LogKind::Failure
    }

    /// Returns the LogKind for this validation status.
    pub fn kind(&self) -> &LogKind {
        &self.kind
    }

    // Maps errors into validation_status codes.
    fn code_from_error_str(error: &str) -> &str {
        match error {
            "ClaimMissing" => CLAIM_MISSING,
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
        debug!("ValidationStatus {code} from error {error:#?}");
        Self::new_failure(code.to_string()).set_explanation(error.to_string())
    }

    /// Creates a ValidationStatus from a validation_log item.
    pub(crate) fn from_log_item(item: &LogItem) -> Option<Self> {
        match item.validation_status.as_ref() {
            Some(status) => Some({
                let mut vi = Self::new(status.to_string())
                    .set_url(item.label.to_string())
                    .set_kind(item.kind.clone())
                    .set_explanation(item.description.to_string());
                if let Some(ingredient_uri) = &item.ingredient_uri {
                    vi = vi.set_ingredient_uri(ingredient_uri.to_string());
                }
                vi
            }),
            // If we don't have a validation_status, then make one from the err_val
            // using the description plus error text explanation.
            None => item.err_val.as_ref().map(|e| {
                let code = Self::code_from_error_str(e);
                Self::new_failure(code.to_string())
                    .set_url(item.label.to_string())
                    .set_explanation(format!("{}: {}", item.description, e))
            }),
        }
    }

    // converts a validation status url into and absolute URI given the manifest label.
    pub(crate) fn make_absolute(&mut self, manifest_label: &str) {
        if let Some(url) = &self.url {
            if url.starts_with("self#jumbf") {
                // Some are just labels (i.e. "Cose_Sign1")
                self.url = Some(jumbf::labels::to_absolute_uri(manifest_label, url));
            }
        }
    }
}

impl PartialEq for ValidationStatus {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.url == other.url && self.kind == other.kind
    }
}

// TODO: Does this still need to be public? (I do see one reference in the JS SDK.)

/// Get the validation status for a store.
///
/// Given a `Store` and a `StatusTracker`, return `ValidationStatus` items for each
/// item in the tracker which reflect errors in the active manifest or which would not
/// be reported as a validation error for any ingredient.
#[cfg(feature = "v1_api")]
pub fn status_for_store(store: &Store, validation_log: &StatusTracker) -> Vec<ValidationStatus> {
    let validation_results =
        crate::validation_results::ValidationResults::from_store(store, validation_log);
    validation_results.validation_errors().unwrap_or_default()
}

// -- unofficial status code --

pub(crate) const STATUS_PRERELEASE: &str = "com.adobe.prerelease";
