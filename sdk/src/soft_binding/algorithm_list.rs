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

use crate::Result;

/// The media types that the [`SoftBindingAlgorithmEntry`] can decode.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IanaMediaType {
    /// A application media type.
    Application,
    /// A audio media type.
    Audio,
    /// A image media type.
    Image,
    /// A model media type.
    Model,
    /// A text media type.
    Text,
    /// A video media type.
    Video,
}

/// The kind of algorithm the soft binding is.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SoftBindingAlgorithmKind {
    /// A watermark algorithm kind.
    Watermark,
    /// A fingerprint algorithm kind.
    Fingerprint,
}

/// Metadata about a particular [`SoftBindingAlgorithmEntry`].
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftBindingAlgorithmEntryMetadata {
    /// Human readable description of the algorithm.
    pub description: String,
    // TODO: what format? chrono/time?
    /// Date of entry for this algorithm.
    pub date_entered: String,
    // TODO: email only
    /// An email for contact information about the algorithm.
    pub contact: String,
    // TODO: URI only
    /// A web page containing more details about the algorithm.
    pub informational_url: String,
}

/// An entry in the soft binding algorithm list.
///
/// An entry can refer to a single algorithm version but can refer to multiple API endpoints
/// that understands the algorithm.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftBindingAlgorithmEntry {
    /// This identifier will be assigned when the soft binding algorithm is added to the list.
    pub identifier: u16,
    /// Indicates whether this soft binding algorithm is deprecated. Deprecated algorithms
    /// shall not be used for creating soft bindings.  Deprecated algorithms may be used for
    /// resolving soft bindings but this behaviour is discouraged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,
    /// Entity-specific namespace as specified for C2PA Assertions labels that shall begin
    /// with the Internet domain name for the entity similar to how Java packages are
    /// defined (e.g., `com.example.algo1`, `net.example.algos.algo2`)
    pub alg: String,
    /// Type of soft binding implemented by this algorithm.
    #[serde(rename = "type")]
    pub kind: SoftBindingAlgorithmKind,
    /// IANA top level media type (rendered) for which this soft binding algorithm applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded_media_types: Option<Vec<IanaMediaType>>,
    // TODO: mime type
    /// IANA media type for which this soft binding algorithm applies, e.g., application/pdf
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoded_media_types: Option<Vec<String>>,
    /// Metadata about this soft binding algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_metadata: Option<SoftBindingAlgorithmEntryMetadata>,
    // TODO: URI only
    /// A list of Soft Binding Resolution APIs supporting this algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft_binding_resolution_apis: Option<Vec<String>>,
}

/// A convenience struct for managing a list of [`SoftBindingAlgorithmEntry`]s.
///
/// The soft binding algorithm list is defined in the spec [here](https://spec.c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html#soft-binding-algorithm-list).
///
/// The actual list of approved soft binding algorithms and JSON schema is defined [here](https://github.com/c2pa-org/softbinding-algorithm-list).
#[derive(Debug, Clone)]
pub struct SoftBindingAlgorithmList {
    entries: Vec<SoftBindingAlgorithmEntry>,
}

impl SoftBindingAlgorithmList {
    // TODO: do we want to have a ::new() method where we embed the list directly into this library?
    //       It may be a good idea if the JSON list is stored at a stable link in c2pa.org

    /// Create a [`SoftBindingAlgorithmList`] from a JSON list.
    ///
    /// The raw JSON list can be found at the URL below:
    /// <https://raw.githubusercontent.com/c2pa-org/softbinding-algorithm-list/refs/heads/main/softbinding-algorithm-list.json>
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(SoftBindingAlgorithmList {
            entries: serde_json::from_str(json)?,
        })
    }

    /// Returns a slice of [`SoftBindingAlgorithmEntry`]s stored in this list.
    pub fn entries(&self) -> &[SoftBindingAlgorithmEntry] {
        &self.entries
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;

    /// A small mock soft binding algorithm list used for testing.
    pub fn mock_soft_binding_algorithm_list(base_url: &str) -> Vec<SoftBindingAlgorithmEntry> {
        let mut list: Vec<SoftBindingAlgorithmEntry> =
            serde_json::from_value(mock_soft_binding_algorithm_list_raw()).unwrap();
        for entry in &mut list {
            entry.soft_binding_resolution_apis = Some(vec![base_url.to_owned()]);
        }
        list
    }

    /// The first 3 soft binding algorithms defined in the soft binding algorithm list:
    /// <https://github.com/c2pa-org/softbinding-algorithm-list/blob/main/softbinding-algorithm-list.json>
    fn mock_soft_binding_algorithm_list_raw() -> serde_json::Value {
        json!([
            {
                "identifier": 1,
                "alg": "com.digimarc.validate.1",
                "type": "watermark",
                "decodedMediaTypes": [
                    "audio",
                    "video",
                    "text",
                    "image"
                ],
                "entryMetadata": {
                    "description": "Digimarc Validate Digital Watermarking algorithm",
                    "dateEntered": "2024-05-17T17:00:00.000Z",
                    "contact": "info@digimarc.com",
                    "informationalUrl": "https://www.digimarc.com/products/digital-content-authentication"
                }
            },
            {
                "identifier": 2,
                "alg": "org.atsc.a336",
                "type": "watermark",
                "decodedMediaTypes": [
                    "audio",
                    "video",
                    "image"
                ],
                "entryMetadata": {
                    "description": "ATSC watermarking (A/334, A/335, A/336)",
                    "dateEntered": "2024-05-17T15:43:00.000Z",
                    "contact": "atsc@atsc.org",
                    "informationalUrl": "https://www.atsc.org/atsc-documents/a3362017-content-recovery-redistribution-scenarios/"
                }
            },
            {
                "identifier": 3,
                "alg": "io.iscc.v0",
                "type": "fingerprint",
                "decodedMediaTypes": [
                    "text",
                    "image",
                    "audio",
                    "video",
                    "application"
                ],
                "entryMetadata": {
                    "description": "ISO 24138 - International Standard Content Code (ISCC) V0 algorithm",
                    "dateEntered": "2024-05-17T16:00:00Z",
                    "contact": "info@iscc.io",
                    "informationalUrl": "https://www.iso.org/standard/77899.html"
                }
            },
        ])
    }

    #[test]
    fn test_serde_round_trip() {
        let list = mock_soft_binding_algorithm_list_raw();

        let deserialized: Vec<SoftBindingAlgorithmEntry> =
            serde_json::from_value(list.clone()).unwrap();
        let serialized = serde_json::to_value(deserialized).unwrap();

        assert_eq!(list, serialized);
    }
}
