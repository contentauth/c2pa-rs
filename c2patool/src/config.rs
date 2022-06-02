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

/// Defines the components used to build a claim to embed in a manifest
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Optional prefix added to the generated Manifest Label
    ///
    /// This is typically Internet domain name for the vendor (i.e. `adobe`)
    pub vendor: Option<String>,
    /// A User Agent formatted string identifying the software/hardware/system produced this claim
    ///
    /// Spaces are not allowed in names, versions can be specified with product/1.0 syntax
    pub claim_generator: Option<String>,
    /// Optional title to use for this claim, defaults to the output file name
    pub title: Option<String>,
    /// Optional parent ingredient file path
    pub parent: Option<PathBuf>,
    /// A List of verified credentials
    pub credentials: Option<Vec<Value>>,
    /// A list of non-parent ingredients to include
    pub ingredients: Option<Vec<PathBuf>>,
    /// A list of [ManifestAssertion] to add to this created manifest
    pub assertions: Vec<ManifestAssertion>,
    /// An optional base path to use for any relative paths in defined in this structure
    pub base_path: Option<PathBuf>,
    /// Signing algorithm to use - must match the associated certs
    ///
    /// Must be one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519 ]
    /// Defaults to ps256
    pub alg: Option<String>,
    /// A path to a file containing the private key required for signing
    pub private_key: Option<PathBuf>,
    /// A path to a file containing the signing cert required for signing
    pub sign_cert: Option<PathBuf>,
    /// A Url to a Time Authority to use when signing the manifest
    pub ta_url: Option<String>,
}
