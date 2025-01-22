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

pub use c2pa_status_tracker::validation_codes::*;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::validation_status::ValidationStatus;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// Indicates if the manifest store is valid and trusted.
/// 
/// The Trusted state implies the manifest store is valid and the active signature is trusted.
pub enum ValidationState {
    /// Errors were found in the manifest store.
    Invalid,
    /// No errors were found in validation, but the active signature is not trusted.
    Valid,
    /// The manifest store is valid and the active signature is trusted.
    Trusted,
}

#[derive(Clone, Serialize, Default, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct StatusCodesMap {
    pub success: Vec<ValidationStatus>, // an array of validation success codes. May be empty.
    pub informational: Vec<ValidationStatus>, // an array of validation informational codes. May be empty.
    pub failure: Vec<ValidationStatus>,       // an array of validation failure codes. May be empty.
}

impl StatusCodesMap {
    pub fn add_status(&mut self, status: ValidationStatus) {
        if status.passed() {
            self.success.push(status);
        } else {
            self.failure.push(status);
        }
    }

    pub fn add_success_val(mut self, sm: ValidationStatus) -> Self {
        self.success.push(sm);
        self
    }

    pub fn success(&self) -> &Vec<ValidationStatus> {
        self.success.as_ref()
    }

    pub fn add_informational_val(mut self, sm: ValidationStatus) -> Self {
        self.informational.push(sm);
        self
    }

    pub fn informational(&self) -> &Vec<ValidationStatus> {
        self.informational.as_ref()
    }

    pub fn add_failure_val(mut self, sm: ValidationStatus) -> Self {
        self.failure.push(sm);
        self
    }

    pub fn failure(&self) -> &Vec<ValidationStatus> {
        self.failure.as_ref()
    }
}

#[derive(Clone, Serialize, Default, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// A map of validation results for a manifest store.
/// 
/// The map contains the validation results for the active manifest and any ingredient deltas.
/// It is normal for there to be many 
pub struct ValidationResultsMap {
    #[serde(rename = "activeManifest", skip_serializing_if = "Option::is_none")]
    active_manifest: Option<StatusCodesMap>, // Validation status codes for the ingredient's active manifest. Present if ingredient is a C2PA asset. Not present if the ingredient is not a C2PA asset.

    #[serde(rename = "ingredientDeltas", skip_serializing_if = "Option::is_none")]
    ingredient_deltas: Option<Vec<IngredientDeltaValidationResultMap>>, // List of any changes/deltas between the current and previous validation results for each ingredient's manifest. Present if the the ingredient is a C2PA asset.
}

impl ValidationResultsMap {
    /// Returns the [ValidationState] of the manifest store based on the validation results.
    pub fn validation_state(&self) -> ValidationState {
        let mut is_trusted = true; // Assume the state is trusted until proven otherwise
        if let Some(active_manifest) = self.active_manifest.as_ref() {
            if !active_manifest.failure().is_empty() {
                return ValidationState::Invalid;
            }
            // There must be a trusted credential in the active manifest for the state to be trusted
            is_trusted = active_manifest.success().iter().any(|status| {
                status.code() == crate::validation_status::SIGNING_CREDENTIAL_TRUSTED
            });
        }
        if let Some(ingredient_deltas) = self.ingredient_deltas.as_ref() {
            for idv in ingredient_deltas.iter() {
                if !idv.validation_deltas().failure().is_empty() {
                    return ValidationState::Invalid;
                }
            }
        }
        if is_trusted {
            ValidationState::Trusted
        } else {
            ValidationState::Valid
        }
    }

    /// Returns a list of all validation errors in the results map.
    pub fn validation_errors(&self) -> Option<Vec<ValidationStatus>> {
        let mut status_vec = Vec::new();
        if let Some(active_manifest) = self.active_manifest.as_ref() {
            status_vec.extend(active_manifest.failure().to_vec());
        }
        if let Some(ingredient_deltas) = self.ingredient_deltas.as_ref() {
            for idv in ingredient_deltas.iter() {
                status_vec.extend(idv.validation_deltas().failure().to_vec());
            }
        }
        if status_vec.is_empty() {
            None
        } else {
            Some(status_vec)
        }
    }

    /// Adds a validation status to the results map.
    pub fn add_status(&mut self, active_manifest_label: &str, status: ValidationStatus) {
        use crate::jumbf::labels::manifest_label_from_uri;
        let active_manifest_label = active_manifest_label.to_string();

        // This closure returns true if the URI references the store's active manifest.
        let is_active_manifest = |uri: Option<&str>| {
            uri.is_some_and(|uri| manifest_label_from_uri(uri) == Some(active_manifest_label))
        };

        // todo - test if we can just use lack of an ingredient URI to determine if it's the active manifest
        if is_active_manifest(status.url()) {
            let scm = self
                .active_manifest
                .get_or_insert_with(StatusCodesMap::default);
            scm.add_status(status);
        } else {
            let ingredient_url = status.ingredient_uri().unwrap_or("NOT FOUND!!!"); //todo: is there an error status for this?
            let ingredient_vec = self.ingredient_deltas.get_or_insert_with(Vec::new);
            match ingredient_vec
                .iter_mut()
                .find(|idv| idv.ingredient_assertion_uri() == ingredient_url)
            {
                Some(idv) => {
                    idv.validation_deltas_mut().add_status(status);
                }
                None => {
                    let mut idv = IngredientDeltaValidationResultMap::new(
                        ingredient_url,
                        StatusCodesMap::default(),
                    );
                    idv.validation_deltas_mut().add_status(status);
                    ingredient_vec.push(idv);
                }
            };
        }
    }

    /// Returns the active manifest status codes, if present.
    pub fn active_manifest(&self) -> Option<&StatusCodesMap> {
        self.active_manifest.as_ref()
    }

    /// Returns the ingredient deltas, if present.
    pub fn ingredient_deltas(&self) -> Option<&Vec<IngredientDeltaValidationResultMap>> {
        self.ingredient_deltas.as_ref()
    }

    pub fn add_active_manifest(mut self, scm: StatusCodesMap) -> Self {
        self.active_manifest = Some(scm);
        self
    }

    pub fn add_ingredient_delta(mut self, idv: IngredientDeltaValidationResultMap) -> Self {
        if let Some(id) = self.ingredient_deltas.as_mut() {
            id.push(idv);
        } else {
            self.ingredient_deltas = Some(vec![idv]);
        }
        self
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct IngredientDeltaValidationResultMap {
    #[serde(rename = "ingredientAssertionURI")]
    ingredient_assertion_uri: String, // JUMBF URI reference to the ingredient assertion
    #[serde(rename = "validationDeltas")]
    validation_deltas: StatusCodesMap, // Validation results for the ingredient's active manifest
}

impl IngredientDeltaValidationResultMap {
    pub fn new<S: Into<String>>(
        ingredient_assertion_uri: S,
        validation_deltas: StatusCodesMap,
    ) -> Self {
        IngredientDeltaValidationResultMap {
            ingredient_assertion_uri: ingredient_assertion_uri.into(),
            validation_deltas,
        }
    }

    pub fn ingredient_assertion_uri(&self) -> &str {
        self.ingredient_assertion_uri.as_str()
    }

    pub fn validation_deltas(&self) -> &StatusCodesMap {
        &self.validation_deltas
    }

    pub fn validation_deltas_mut(&mut self) -> &mut StatusCodesMap {
        &mut self.validation_deltas
    }
}
