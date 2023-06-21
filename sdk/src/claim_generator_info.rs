// Copyright 2023 Adobe. All rights reserved.
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
use std::collections::HashMap;

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::resource_store::UriOrResource;

/// Description of the claim generator, or the software used in generating the claim.
///
/// This structure is also used for actions softwareAgent
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ClaimGeneratorInfo {
    /// A human readable string naming the claim_generator
    pub name: String,
    /// A human readable string of the product's version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// hashed URI to the icon (either embedded or remote)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<UriOrResource>,
    // Any other values that are not part of the standard
    #[serde(flatten)]
    other: HashMap<String, Value>,
}

impl ClaimGeneratorInfo {
    pub fn new<S: Into<String>>(name: S) -> Self {
        Self {
            name: name.into(),
            version: None,
            icon: None,
            other: HashMap::new(),
        }
    }

    /// Returns the software agent that performed the action.
    pub fn icon(&self) -> Option<&UriOrResource> {
        self.icon.as_ref()
    }

    /// Sets the version of the generator.
    pub fn set_version<S: Into<String>>(&mut self, version: S) -> &mut Self {
        self.version = Some(version.into());
        self
    }

    /// Sets the icon of the generator.
    pub fn set_icon<S: Into<UriOrResource>>(&mut self, uri_or_resource: S) -> &mut Self {
        self.icon = Some(uri_or_resource.into());
        self
    }

    /// Adds a new key/value pair to the generator info.
    pub fn insert<K, V>(&mut self, key: K, value: V) -> &Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        self.other.insert(key.into(), value.into());
        self
    }

    /// Gets additional values by key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.other.get(key)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{hashed_uri::HashedUri, resource_store::ResourceRef};

    #[test]
    fn test_resource_ref() {
        let mut g = super::ClaimGeneratorInfo::new("test");
        g.set_version("1.0")
            .set_icon(ResourceRef::new("image/svg", "myicon"));

        let json = serde_json::to_string_pretty(&g).expect("Failed to serialize");
        println!("{json}");

        let result: ClaimGeneratorInfo =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(g, result);
    }

    #[test]
    fn test_hashed_uri() {
        let mut g = super::ClaimGeneratorInfo::new("test");
        g.set_version("1.0").set_icon(HashedUri::new(
            "self#jumbf=c2pa.databoxes.data_box".to_string(),
            None,
            b"hashed",
        ));

        let json = serde_json::to_string_pretty(&g).expect("Failed to serialize");
        println!("{json}");

        let result: ClaimGeneratorInfo =
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(g, result);
    }
}
