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
use c2pa::ManifestAssertion;

use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

/// A `ClaimDef` defines the components used to build a claim
#[derive(Debug, Deserialize)]
pub struct ClaimDef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(alias = "recorder")]
    pub claim_generator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingredients: Option<Vec<PathBuf>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertions: Vec<ManifestAssertion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}
