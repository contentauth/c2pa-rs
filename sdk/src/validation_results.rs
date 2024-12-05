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

use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Default, Deserialize, Debug, PartialEq, Eq)]
pub struct StatusMap {
    code: String, //A label-formatted string that describes the status
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>, // JUMBF URI reference to the JUMBF box to which this status code applies
    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<String>, // (1..max-tstr-length), // A human readable string explaining the status
    #[serde(skip_serializing_if = "Option::is_none")]
    success: Option<bool>, // DEPRECATED. Does the code reflect success (true) or failure (false)
}

impl StatusMap {
    pub fn new<S: Into<String>>(code: S) -> Self {
        Self {
            code: code.into(),
            ..Default::default()
        }
    }

    pub fn set_url<S: Into<String>>(mut self, url: S) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn url(&self) -> Option<&String> {
        self.url.as_ref()
    }

    pub fn set_explanation<S: Into<String>>(mut self, explanation: S) -> Self {
        self.explanation = Some(explanation.into());
        self
    }

    pub fn explanation(&self) -> Option<&String> {
        self.explanation.as_ref()
    }

    pub fn set_success(mut self, success: bool) -> Self {
        self.success = Some(success);
        self
    }

    pub fn success(&self) -> Option<bool> {
        self.success
    }
}

#[derive(Clone, Serialize, Default, Deserialize, Debug, PartialEq, Eq)]
pub struct StatusCodesMap {
    pub success: Vec<StatusMap>, // an array of validation success codes. May be empty.
    pub informational: Vec<StatusMap>, // an array of validation informational codes. May be empty.
    pub failure: Vec<StatusMap>, // an array of validation failure codes. May be empty.
}

impl StatusCodesMap {
    pub fn add_success_val(mut self, sm: StatusMap) -> Self {
        self.success.push(sm);
        self
    }

    pub fn success(&self) -> &Vec<StatusMap> {
        self.success.as_ref()
    }

    pub fn add_informational_val(mut self, sm: StatusMap) -> Self {
        self.informational.push(sm);
        self
    }

    pub fn informational(&self) -> &Vec<StatusMap> {
        self.informational.as_ref()
    }

    pub fn add_failure_val(mut self, sm: StatusMap) -> Self {
        self.failure.push(sm);
        self
    }

    pub fn failure(&self) -> &Vec<StatusMap> {
        self.failure.as_ref()
    }
}

#[derive(Clone, Serialize, Default, Deserialize, Debug, PartialEq, Eq)]
pub struct ValidationResultsMap {
    #[serde(rename = "activeManifest", skip_serializing_if = "Option::is_none")]
    active_manifest: Option<StatusCodesMap>, // Validation status codes for the ingredient's active manifest. Present if ingredient is a C2PA asset. Not present if the ingredient is not a C2PA asset.

    #[serde(rename = "ingredientDeltas", skip_serializing_if = "Option::is_none")]
    ingredient_deltas: Option<Vec<IngredientDeltaValidationResultMap>>, // List of any changes/deltas between the current and previous validation results for each ingredient's manifest. Present if the the ingredient is a C2PA asset.
}

impl ValidationResultsMap {
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
}
