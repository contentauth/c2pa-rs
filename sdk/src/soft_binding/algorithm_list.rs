// Copyright 2026 Adobe. All rights reserved.
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

//! A parsed C2PA soft binding algorithm registry.
//!
//! Use this to parse a list of soft binding algorithms from a JSON string and
//! to build a list of soft binding algorithms. Use this to parse the official
//! C2PA soft binding algorithm registry from the JSON file at
//! <https://github.com/c2pa-org/softbinding-algorithm-list/blob/main/softbinding-algorithm-list.json>.
//! The list can be used to validate soft binding algorithms in C2PA
//! assertions and to look up [Soft Binding Resolution API](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html)
//! endpoints for a given algorithm.

use serde::{Deserialize, Serialize};

use crate::{
    cbor_types::{DateT, UriT},
    Result,
};

/// A parsed C2PA soft binding algorithm registry.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(transparent)]
pub struct SoftBindingList(pub Vec<SoftBindingAlgorithm>);

impl SoftBindingList {
    /// Parse a JSON string containing a soft binding algorithm list.
    pub fn from_json_str(json: &str) -> Result<Self> {
        let list: Self = serde_json::from_str(json)?;
        list.validate()?;
        Ok(list)
    }

    fn validate(&self) -> Result<()> {
        for algorithm in &self.0 {
            algorithm.validate()?;
        }
        Ok(())
    }

    /// Returns a list of soft binding algorithms strings from a vector of `SoftBindingAlgorithm` entries using the `alg` field.
    pub fn algorithm_strings(&self) -> Vec<String> {
        self.0.iter().map(|alg| alg.alg.clone()).collect()
    }

    /// Returns all entries in this registry.
    pub fn algorithms(&self) -> &[SoftBindingAlgorithm] {
        &self.0
    }

    /// Find the registry entry for a given algorithm string (e.g. `"com.adobe.trustmark.Q"`).
    pub fn find(&self, alg: &str) -> Option<&SoftBindingAlgorithm> {
        self.0.iter().find(|a| a.alg == alg)
    }
}

/// A single soft binding algorithm entry.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SoftBindingAlgorithm {
    pub identifier: u16,

    #[serde(default)]
    pub deprecated: bool,

    pub alg: String,

    #[serde(rename = "type")]
    pub alg_type: SoftBindingAlgorithmType,

    #[serde(rename = "decodedMediaTypes", skip_serializing_if = "Option::is_none")]
    pub decoded_media_types: Option<Vec<SoftBindingMediaType>>,

    #[serde(rename = "encodedMediaTypes", skip_serializing_if = "Option::is_none")]
    pub encoded_media_types: Option<Vec<String>>,

    #[serde(rename = "entryMetadata")]
    pub entry_metadata: SoftBindingEntryMetadata,

    #[serde(
        rename = "softBindingResolutionApis",
        skip_serializing_if = "Option::is_none"
    )]
    pub soft_binding_resolution_apis: Option<Vec<UriT>>,
}

impl SoftBindingAlgorithm {
    fn validate(&self) -> Result<()> {
        if self
            .decoded_media_types
            .as_ref()
            .map(Vec::is_empty)
            .unwrap_or(false)
        {
            return Err(crate::error::Error::ValidationRule(
                "decodedMediaTypes must be a non-empty array when present".to_owned(),
            ));
        }

        if self
            .encoded_media_types
            .as_ref()
            .map(Vec::is_empty)
            .unwrap_or(false)
        {
            return Err(crate::error::Error::ValidationRule(
                "encodedMediaTypes must be a non-empty array when present".to_owned(),
            ));
        }

        if self.decoded_media_types.is_none() && self.encoded_media_types.is_none() {
            return Err(crate::error::Error::ValidationRule(
                "soft binding algorithm entry must include decodedMediaTypes or encodedMediaTypes"
                    .to_owned(),
            ));
        }

        if let Some(apis) = &self.soft_binding_resolution_apis {
            if apis.is_empty() {
                return Err(crate::error::Error::ValidationRule(
                    "softBindingResolutionApis must be a non-empty array when present".to_owned(),
                ));
            }
            for api in apis {
                url::Url::parse(api.as_ref()).map_err(|_| {
                    crate::error::Error::ValidationRule(format!(
                        "softBindingResolutionApis contains invalid URI: {}",
                        api.as_ref()
                    ))
                })?;
            }
        }

        self.entry_metadata.validate()
    }

    /// The algorithm identifier string (e.g. `"com.adobe.trustmark.Q"`).
    pub fn alg(&self) -> &str {
        &self.alg
    }

    /// Whether this algorithm entry is deprecated. Deprecated algorithms shall not be used
    /// for creating soft bindings, and their use for resolving soft bindings is discouraged.
    pub fn is_deprecated(&self) -> bool {
        self.deprecated
    }

    /// The kind of soft binding (watermark or fingerprint) this algorithm implements.
    pub fn alg_type(&self) -> &SoftBindingAlgorithmType {
        &self.alg_type
    }

    /// The [Soft Binding Resolution API](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html)
    /// endpoints this algorithm's registry entry advertises. Empty if none are configured.
    pub fn resolution_apis(&self) -> &[UriT] {
        self.soft_binding_resolution_apis.as_deref().unwrap_or(&[])
    }
}

/// Metadata for a soft binding algorithm entry.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SoftBindingEntryMetadata {
    pub description: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub categories: Option<Vec<String>>,

    #[serde(rename = "dateEntered")]
    pub date_entered: DateT,

    pub contact: String,

    #[serde(rename = "informationalUrl")]
    pub informational_url: UriT,
}

impl SoftBindingEntryMetadata {
    fn validate(&self) -> Result<()> {
        url::Url::parse(self.informational_url.as_ref()).map_err(|_| {
            crate::error::Error::ValidationRule(format!(
                "entryMetadata.informationalUrl is not a valid URI: {}",
                self.informational_url.as_ref()
            ))
        })?;
        Ok(())
    }
}

/// The type of soft binding algorithm.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SoftBindingAlgorithmType {
    Watermark,
    Fingerprint,
}

/// Target media types for soft binding algorithms.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SoftBindingMediaType {
    Application,
    Audio,
    Image,
    Model,
    Text,
    Video,
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_soft_binding_list_json_parse() {
        let json = r#"[
            {
                "identifier": 1,
                "alg": "com.example.watermark.alg1",
                "type": "watermark",
                "decodedMediaTypes": ["image"],
                "entryMetadata": {
                    "description": "Example watermarking algorithm",
                    "dateEntered": "2025-01-01T00:00:00Z",
                    "contact": "contact@example.com",
                    "informationalUrl": "https://example.com/softbinding/alg1"
                }
            }
        ]"#;

        let list = SoftBindingList::from_json_str(json).unwrap();
        assert_eq!(list.0.len(), 1);
        let algorithm = &list.0[0];
        assert_eq!(algorithm.identifier, 1);
        assert_eq!(algorithm.alg, "com.example.watermark.alg1");
        assert!(matches!(
            algorithm.alg_type,
            SoftBindingAlgorithmType::Watermark
        ));
        assert_eq!(
            algorithm.decoded_media_types.as_ref().unwrap(),
            &[SoftBindingMediaType::Image]
        );

        // get the algorithm strings
        let alg_strings = list.algorithm_strings();
        assert_eq!(alg_strings, vec!["com.example.watermark.alg1"]);

        // find the algorithm by name
        assert!(list.find("com.example.watermark.alg1").is_some());
        assert!(list.find("com.example.nonexistent").is_none());
    }

    #[test]
    fn test_resolution_apis() {
        let json = r#"[
            {
                "identifier": 1,
                "alg": "com.example.watermark.alg1",
                "type": "watermark",
                "decodedMediaTypes": ["image"],
                "entryMetadata": {
                    "description": "Example watermarking algorithm",
                    "dateEntered": "2025-01-01T00:00:00Z",
                    "contact": "contact@example.com",
                    "informationalUrl": "https://example.com/softbinding/alg1"
                },
                "softBindingResolutionApis": ["https://example.com/resolve"]
            }
        ]"#;

        let list = SoftBindingList::from_json_str(json).unwrap();
        let algorithm = list.find("com.example.watermark.alg1").unwrap();
        assert_eq!(algorithm.resolution_apis().len(), 1);
        assert_eq!(
            algorithm.resolution_apis()[0].as_ref(),
            "https://example.com/resolve"
        );

        // an entry with no resolution APIs configured returns an empty slice
        let json_no_apis = r#"[
            {
                "identifier": 2,
                "alg": "com.example.watermark.alg2",
                "type": "watermark",
                "decodedMediaTypes": ["image"],
                "entryMetadata": {
                    "description": "Example watermarking algorithm",
                    "dateEntered": "2025-01-01T00:00:00Z",
                    "contact": "contact@example.com",
                    "informationalUrl": "https://example.com/softbinding/alg2"
                }
            }
        ]"#;
        let list_no_apis = SoftBindingList::from_json_str(json_no_apis).unwrap();
        let algorithm_no_apis = list_no_apis.find("com.example.watermark.alg2").unwrap();
        assert!(algorithm_no_apis.resolution_apis().is_empty());
    }
}
