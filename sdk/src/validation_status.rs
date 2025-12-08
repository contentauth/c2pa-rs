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
    pub(crate) fn code_from_error(error: &Error) -> &'static str {
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
    #[allow(dead_code)]
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

// -- unofficial status code --

pub(crate) const STATUS_PRERELEASE: &str = "com.adobe.prerelease";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    mod explanation {
        use super::super::*;

        #[test]
        fn none() {
            let status = ValidationStatus::new("test.code");
            assert_eq!(status.explanation(), None);
        }

        #[test]
        fn some() {
            let status = ValidationStatus::new("test.code")
                .set_explanation("This is a test explanation".to_string());

            assert_eq!(status.explanation(), Some("This is a test explanation"));
        }

        #[test]
        fn with_error() {
            let error = Error::ClaimMissing {
                label: "test_claim".to_string(),
            };

            let status = ValidationStatus::from_error(&error);
            assert!(status.explanation().is_some());
            assert!(status.explanation().unwrap().contains("claim missing"));
        }

        #[test]
        fn empty_string() {
            let status = ValidationStatus::new("test.code").set_explanation("".to_string());
            assert_eq!(status.explanation(), Some(""));
        }
    }

    mod passed {
        use super::super::*;

        #[test]
        fn success_kind() {
            let status = ValidationStatus::new("test.code");
            assert!(status.passed());
        }

        #[test]
        fn informational_kind() {
            let status = ValidationStatus::new("test.code").set_kind(LogKind::Informational);
            assert!(status.passed());
        }

        #[test]
        fn failure_kind() {
            let status = ValidationStatus::new_failure("test.code");
            assert!(!status.passed());
        }

        #[test]
        fn failure_from_error() {
            let error = Error::ClaimMissing {
                label: "test_claim".to_string(),
            };

            let status = ValidationStatus::from_error(&error);
            assert!(!status.passed());
        }
    }

    mod code_from_error_str {
        use super::super::*;

        #[test]
        fn claim_missing() {
            assert_eq!(
                ValidationStatus::code_from_error_str("ClaimMissing"),
                CLAIM_MISSING
            );
        }

        #[test]
        fn assertion_missing_prefix() {
            assert_eq!(
                ValidationStatus::code_from_error_str("AssertionMissing: some details"),
                ASSERTION_MISSING
            );
        }

        #[test]
        fn hash_mismatch_prefix() {
            assert_eq!(
                ValidationStatus::code_from_error_str("HashMismatch: details"),
                ASSERTION_DATAHASH_MATCH
            );
        }

        #[test]
        fn unrecognized_error_returns_general_error() {
            assert_eq!(
                ValidationStatus::code_from_error_str("SomeUnknownError"),
                GENERAL_ERROR
            );
        }

        #[test]
        fn empty_string_returns_general_error() {
            assert_eq!(ValidationStatus::code_from_error_str(""), GENERAL_ERROR);
        }

        #[test]
        fn random_string_returns_general_error() {
            assert_eq!(
                ValidationStatus::code_from_error_str("ThisDoesNotMatchAnything"),
                GENERAL_ERROR
            );
        }
    }

    mod code_from_error {
        use super::super::*;
        use crate::assertion::{AssertionDecodeError, AssertionDecodeErrorCause};

        #[test]
        fn claim_missing() {
            let error = Error::ClaimMissing {
                label: "test_claim".to_string(),
            };

            assert_eq!(ValidationStatus::code_from_error(&error), CLAIM_MISSING);
        }

        #[test]
        fn assertion_missing() {
            let error = Error::AssertionMissing {
                url: "test_url".to_string(),
            };

            assert_eq!(ValidationStatus::code_from_error(&error), ASSERTION_MISSING);
        }

        #[test]
        fn assertion_decoding() {
            let decode_error = AssertionDecodeError {
                label: "test.assertion".to_string(),
                version: Some(1),
                content_type: "application/json".to_string(),
                source: AssertionDecodeErrorCause::BinaryDataNotUtf8,
            };
            let error = Error::AssertionDecoding(decode_error);

            assert_eq!(
                ValidationStatus::code_from_error(&error),
                ASSERTION_REQUIRED_MISSING
            );
        }

        #[test]
        fn hash_mismatch() {
            let error = Error::HashMismatch("hash mismatch details".to_string());

            assert_eq!(
                ValidationStatus::code_from_error(&error),
                ASSERTION_DATAHASH_MATCH
            );
        }

        #[test]
        fn remote_manifest_fetch() {
            let error = Error::RemoteManifestFetch("http://example.com".to_string());

            assert_eq!(
                ValidationStatus::code_from_error(&error),
                MANIFEST_INACCESSIBLE
            );
        }

        #[test]
        fn prerelease_error() {
            let error = Error::PrereleaseError;

            assert_eq!(ValidationStatus::code_from_error(&error), STATUS_PRERELEASE);
        }

        #[test]
        fn other_error_returns_general_error() {
            let error = Error::ClaimEncoding;

            assert_eq!(ValidationStatus::code_from_error(&error), GENERAL_ERROR);
        }

        #[test]
        fn bad_param_returns_general_error() {
            let error = Error::BadParam("invalid parameter".to_string());

            assert_eq!(ValidationStatus::code_from_error(&error), GENERAL_ERROR);
        }
    }

    mod make_absolute {
        use super::super::*;

        #[test]
        fn url_none() {
            let mut status = ValidationStatus::new("test.code");
            assert_eq!(status.url(), None);

            status.make_absolute("test_manifest");

            // URL should still be None after make_absolute
            assert_eq!(status.url(), None);
        }

        #[test]
        fn url_does_not_start_with_self_jumbf() {
            let mut status = ValidationStatus::new("test.code")
                .set_url("http://example.com/some/url");

            let original_url = status.url().unwrap().to_string();
            status.make_absolute("test_manifest");

            // URL should remain unchanged
            assert_eq!(status.url(), Some(original_url.as_str()));
        }

        #[test]
        fn url_starts_with_self_jumbf() {
            let mut status =
                ValidationStatus::new("test.code").set_url("self#jumbf=c2pa.assertions/test");

            status.make_absolute("active_manifest");

            // URL should be converted to absolute URI with manifest label
            assert!(status.url().is_some());
            let url = status.url().unwrap();
            assert!(url.contains("active_manifest"));
            assert!(url.starts_with("self#jumbf=/c2pa/active_manifest"));
        }

        #[test]
        fn url_is_just_label() {
            let mut status = ValidationStatus::new("test.code").set_url("Cose_Sign1");

            let original_url = status.url().unwrap().to_string();
            status.make_absolute("test_manifest");

            // URL should remain unchanged (doesn't start with "self#jumbf")
            assert_eq!(status.url(), Some(original_url.as_str()));
        }
    }
}
