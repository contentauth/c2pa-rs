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

use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{
        assertion_metadata::AssetType, cloud_data::HashedExtUri, labels, AssertionMetadata,
    },
    error::{Error, Result},
};

/// An unhashed external reference location.
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct UnhashedExtUri {
    /// HTTP(S) URL to the externally stored data.
    pub url: String,

    /// Optional IANA media type for the referenced data.
    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    pub dc_format: Option<String>,

    /// Optional size of the referenced data in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// Optional asset type classifications for the referenced data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,
}

impl UnhashedExtUri {
    /// Create a new unhashed external reference URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            dc_format: None,
            size: None,
            data_types: None,
        }
    }

    /// Set the media type of the referenced data.
    pub fn set_dc_format(mut self, dc_format: impl Into<String>) -> Self {
        self.dc_format = Some(dc_format.into());
        self
    }

    /// Set the size of the referenced data in bytes.
    pub fn set_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }
}

/// The `location` field of an external reference assertion: either hashed or
/// unhashed remote data.
#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum ExternalReferenceLocation {
    Hashed(HashedExtUri),
    Unhashed(UnhashedExtUri),
}

impl ExternalReferenceLocation {
    /// Create a hashed reference location.
    pub fn hashed(url: impl Into<String>, alg: impl Into<String>, hash: Vec<u8>) -> Self {
        Self::Hashed(HashedExtUri::new(url, alg, hash))
    }

    /// Create an unhashed reference location.
    pub fn unhashed(url: impl Into<String>) -> Self {
        Self::Unhashed(UnhashedExtUri::new(url))
    }
}

/// An external reference assertion points to remotely stored assertion or non-assertion data.
///
/// When `location` is hashed, the data is cryptographically bound to the claim at signing time.
/// When `location` is unhashed, the external data is advisory and may change over time.
///
/// See [External Reference - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_external_reference).
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct ExternalReference {
    /// The remotely stored assertion or data.
    pub location: ExternalReferenceLocation,

    /// Optional label for the referenced assertion, if relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Optional human-readable description of the remotely stored data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional metadata about the assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AssertionMetadata>,
}

impl ExternalReference {
    pub const LABEL: &'static str = labels::EXTERNAL_REFERENCE;

    /// Creates a new hashed external reference.
    pub fn new_hashed(url: impl Into<String>, alg: impl Into<String>, hash: Vec<u8>) -> Self {
        Self {
            location: ExternalReferenceLocation::hashed(url, alg, hash),
            label: None,
            description: None,
            metadata: None,
        }
    }

    /// Creates a new unhashed external reference.
    pub fn new_unhashed(url: impl Into<String>) -> Self {
        Self {
            location: ExternalReferenceLocation::unhashed(url),
            label: None,
            description: None,
            metadata: None,
        }
    }

    /// Validates the external reference according to the C2PA 2.4 rules.
    ///
    /// For the hashed form, `alg` and `hash` must both be present and non-empty.
    /// If a `label` is present, it must not be one of the forbidden assertion labels.
    #[allow(unused)]
    pub(crate) fn validate(&self) -> Result<()> {
        let url = match &self.location {
            ExternalReferenceLocation::Hashed(h) => h.url.as_str(),
            ExternalReferenceLocation::Unhashed(u) => u.url.as_str(),
        };

        if url.trim().is_empty() {
            return Err(Error::ValidationRule(
                "external reference location.url must not be empty".to_owned(),
            ));
        }

        match &self.location {
            ExternalReferenceLocation::Hashed(h) => {
                if h.alg.trim().is_empty() || h.hash.is_empty() {
                    return Err(Error::ValidationRule(
                        "hashed external reference requires both alg and hash fields".to_owned(),
                    ));
                }
            }
            ExternalReferenceLocation::Unhashed(_) => {}
        }

        if let Some(label) = &self.label {
            const FORBIDDEN: [&str; 14] = [
                "c2pa.action",
                "c2pa.actions",
                "c2pa.actions.v2",
                labels::CLOUD_DATA,
                labels::EXTERNAL_REFERENCE,
                "c2pa.hash.bmff.v2",
                "c2pa.hash.bmff.v3",
                labels::BOX_HASH,
                labels::COLLECTION_HASH,
                labels::DATA_HASH,
                "c2pa.hash.multi-asset",
                "c2pa.ingredient",
                "c2pa.ingredient.v2",
                "c2pa.ingredient.v3",
            ];

            if FORBIDDEN.contains(&label.as_str()) {
                return Err(Error::ValidationRule(format!(
                    "external reference label '{}' is forbidden per C2PA 2.4",
                    label
                )));
            }
        }

        Ok(())
    }

    /// Sets the label of the referenced assertion, if relevant.
    pub fn set_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Sets a description for the referenced data.
    pub fn set_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets optional metadata about the assertion.
    pub fn set_metadata(mut self, metadata: AssertionMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl AssertionCbor for ExternalReference {}

impl AssertionBase for ExternalReference {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use crate::{
        assertion::AssertionBase,
        assertions::{cloud_data::HashedExtUri, ExternalReference, ExternalReferenceLocation},
    };

    #[test]
    fn test_hashed_reference_round_trip() {
        let original = ExternalReference::new_hashed(
            "https://example.com/remote-metadata",
            "sha256",
            vec![0xde, 0xad, 0xbe, 0xef],
        )
        .set_label("c2pa.metadata")
        .set_description("Remote metadata assertion");

        let assertion = original.to_assertion().expect("to_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), ExternalReference::LABEL);

        let result = ExternalReference::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(result, original);
    }

    #[test]
    fn test_unhashed_reference_round_trip() {
        let original = ExternalReference::new_unhashed("https://example.com/data.json")
            .set_label("c2pa.metadata")
            .set_description("Advisory metadata source");

        let assertion = original.to_assertion().expect("to_assertion");
        let result = ExternalReference::from_assertion(&assertion).expect("from_assertion");

        assert_eq!(result, original);
    }

    #[test]
    fn test_validate_requires_url() {
        let assertion = ExternalReference::new_unhashed("   ");
        assert!(assertion.validate().is_err());
    }

    #[test]
    fn test_validate_requires_alg_and_hash_together() {
        let assertion =
            ExternalReference::new_hashed("https://example.com/data.json", "sha256", vec![]);
        assert!(assertion.validate().is_err());

        let assertion = ExternalReference {
            location: ExternalReferenceLocation::Hashed(HashedExtUri {
                url: "https://example.com/data.json".to_owned(),
                alg: String::new(),
                hash: vec![1, 2, 3],
                data_types: None,
            }),
            label: None,
            description: None,
            metadata: None,
        };
        assert!(assertion.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_forbidden_labels() {
        let assertion =
            ExternalReference::new_hashed("https://example.com/data.json", "sha256", vec![1, 2, 3])
                .set_label("c2pa.hash.data");

        assert!(assertion.validate().is_err());
    }
}
