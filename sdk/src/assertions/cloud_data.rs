// Copyright 2025 Adobe. All rights reserved.
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
    assertions::{assertion_metadata::AssetType, labels, AssertionMetadata},
    error::Result,
};

/// The `location` field of a [`CloudData`] assertion: a URL with its
/// pre-computed hash so the remote content can be integrity-checked on fetch.
///
/// The `dc:format` and `size` fields defined on the base `$hashed-ext-uri-map`
/// CDDL rule **shall not** appear here; the cloud data assertion carries those
/// at the top level instead (`content_type` and `size`).
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct HashedExtUri {
    /// HTTPS URL at which the externally-stored assertion data can be retrieved.
    pub url: String,

    /// Hash algorithm identifier (e.g. `"sha256"`, `"sha384"`, `"sha512"`).
    pub alg: String,

    /// Cryptographic hash of the data at [`url`](Self::url), encoded as a byte
    /// string. Used to verify integrity when the external data is fetched.
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,

    /// Optional asset type classifications for the externally-stored data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,
}

impl HashedExtUri {
    /// Creates a new `HashedExtUri` with the given URL, algorithm, and hash.
    pub fn new(url: impl Into<String>, alg: impl Into<String>, hash: Vec<u8>) -> Self {
        Self {
            url: url.into(),
            alg: alg.into(),
            hash,
            data_types: None,
        }
    }

    /// Sets asset type classifications for the externally-stored data.
    pub fn set_data_types(mut self, data_types: Vec<AssetType>) -> Self {
        self.data_types = Some(data_types);
        self
    }
}

/// A `CloudData` assertion references externally-hosted assertion data rather
/// than embedding it directly in the manifest's assertion store.
///
/// Because the data lives outside the manifest, it is **not** retrieved or
/// validated during standard manifest validation. Applications that specifically
/// require the external content are responsible for fetching and verifying it.
///
/// Hard binding assertions (`c2pa.hash.*`) and actions assertions
/// (`c2pa.actions`, `c2pa.actions.v2`) must never be stored as cloud data.
///
/// See [Cloud data - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_cloud_data).
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct CloudData {
    /// Label of the C2PA assertion type stored at the remote location
    /// (e.g. `"c2pa.metadata"`, `"c2pa.soft-binding"`).
    pub label: String,

    /// Size of the externally-stored data in bytes (minimum 1).
    pub size: u64,

    /// HTTPS URL and integrity hash of the externally-hosted assertion data.
    pub location: HashedExtUri,

    /// IANA media type (MIME type) of the remotely-stored data.
    /// Defaults to `application/jumbf` when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Optional metadata about this assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AssertionMetadata>,
}

impl CloudData {
    pub const LABEL: &'static str = labels::CLOUD_DATA;

    /// Creates a new `CloudData` assertion.
    ///
    /// # Arguments
    /// * `label`    – Label of the assertion type stored at the remote location.
    /// * `size`     – Byte length of the remote data (must be ≥ 1).
    /// * `location` – URL and integrity hash of the remote assertion.
    pub fn new(label: impl Into<String>, size: u64, location: HashedExtUri) -> Self {
        Self {
            label: label.into(),
            size,
            location,
            content_type: None,
            metadata: None,
        }
    }

    /// Sets the MIME type of the externally-stored data.
    pub fn set_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Sets optional metadata about this assertion.
    pub fn set_metadata(mut self, metadata: AssertionMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Returns `true` if [`label`](CloudData::label) names a hard binding assertion
    /// (`c2pa.hash.data`, any `c2pa.hash.bmff.*`, `c2pa.hash.boxes`,
    /// `c2pa.hash.collection.data`, or `c2pa.hash.multi-asset`).
    ///
    /// Hard bindings must not be stored as cloud data; this method is used by
    /// validators to emit [`assertion.cloud-data.hardBinding`].
    ///
    /// [`assertion.cloud-data.hardBinding`]: crate::validation_results::validation_codes::ASSERTION_CLOUD_DATA_HARD_BINDING
    pub(crate) fn is_hard_binding(&self) -> bool {
        let l = self.label.as_str();
        l == labels::DATA_HASH
            || l == labels::BOX_HASH
            || l == labels::COLLECTION_HASH
            || l == "c2pa.hash.multi-asset"
            || l.starts_with(labels::BMFF_HASH)
    }

    /// Returns `true` if [`label`](CloudData::label) names an actions assertion
    /// (`c2pa.actions` or any versioned variant such as `c2pa.actions.v2`).
    ///
    /// Actions assertions must not be stored as cloud data in update manifests;
    /// this method is used by validators to emit [`assertion.cloud-data.actions`].
    ///
    /// [`assertion.cloud-data.actions`]: crate::validation_results::validation_codes::ASSERTION_CLOUD_DATA_ACTIONS
    pub(crate) fn is_actions(&self) -> bool {
        labels::base(&self.label) == labels::ACTIONS
    }
}

impl AssertionCbor for CloudData {}

impl AssertionBase for CloudData {
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

    use super::*;
    use crate::assertions::labels;

    fn make_location() -> HashedExtUri {
        HashedExtUri::new(
            "https://example.com/assertion-data",
            "sha256",
            vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
        )
    }

    #[test]
    fn test_round_trip_minimal() {
        let original = CloudData::new("c2pa.metadata", 1024, make_location());

        let assertion = original.to_assertion().expect("to_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), CloudData::LABEL);

        let result = CloudData::from_assertion(&assertion).expect("from_assertion");
        assert_eq!(result, original);
    }

    #[test]
    fn test_round_trip_all_fields() {
        let original = CloudData::new(
            "c2pa.metadata",
            4321,
            HashedExtUri::new(
                "https://storage.example.com/metadata.cbor",
                "sha384",
                vec![0xde, 0xad, 0xbe, 0xef],
            ),
        )
        .set_content_type("application/jumbf");

        let assertion = original.to_assertion().expect("to_assertion");
        let result = CloudData::from_assertion(&assertion).expect("from_assertion");

        assert_eq!(result.label, original.label);
        assert_eq!(result.size, original.size);
        assert_eq!(result.location, original.location);
        assert_eq!(result.content_type, original.content_type);
    }

    #[test]
    fn test_is_hard_binding() {
        let make = |label: &str| CloudData::new(label, 1, make_location());

        assert!(make(labels::DATA_HASH).is_hard_binding());
        assert!(make(labels::BMFF_HASH).is_hard_binding());
        assert!(make("c2pa.hash.bmff.v2").is_hard_binding());
        assert!(make("c2pa.hash.bmff.v3").is_hard_binding());
        assert!(make(labels::BOX_HASH).is_hard_binding());
        assert!(make(labels::COLLECTION_HASH).is_hard_binding());
        assert!(make("c2pa.hash.multi-asset").is_hard_binding());
        assert!(!make("c2pa.metadata").is_hard_binding());
    }

    #[test]
    fn test_is_actions() {
        let make = |label: &str| CloudData::new(label, 1, make_location());

        assert!(make(labels::ACTIONS).is_actions());
        assert!(make("c2pa.actions.v2").is_actions());
        assert!(!make("c2pa.metadata").is_actions());
    }
}
