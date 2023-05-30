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

use std::fmt;

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Hashed Uri structure as defined by C2PA spec
/// It is annotated to produce the correctly tagged cbor serialization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct HashedUri {
    url: String, // URI stored as tagged cbor
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(with = "serde_bytes")]
    #[cfg_attr(feature = "json_schema", schemars(with = "Vec<u8>"))]
    hash: Vec<u8>, // hash stored as cbor byte string

    // salt used to generate hash
    #[serde(skip_deserializing, skip_serializing)]
    salt: Option<Vec<u8>>,
}

impl HashedUri {
    pub fn new(url: String, alg: Option<String>, hash_bytes: &[u8]) -> Self {
        Self {
            url,
            alg,
            hash: hash_bytes.to_vec(),
            salt: None,
        }
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn is_relative_url(&self) -> bool {
        crate::jumbf::labels::manifest_label_from_uri(&self.url).is_none()
    }

    pub fn alg(&self) -> Option<String> {
        self.alg.clone()
    }

    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }

    pub(crate) fn update_hash(&mut self, hash: Vec<u8>) {
        self.hash = hash;
    }

    pub fn add_salt(&mut self, salt: Option<Vec<u8>>) {
        self.salt = salt;
    }

    pub fn salt(&self) -> &Option<Vec<u8>> {
        &self.salt
    }
}

impl fmt::Display for HashedUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "url: {}, alg: {:?}, hash", self.url, self.alg)
    }
}
