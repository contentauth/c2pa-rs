use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    error::Result,
};

/// An `AssetReference` assertion provides information on one or more locations of
/// where a copy of the asset may be obtained.
///
/// This assertion contains a list of references, each one declaring a location expressed as a URI and
/// optionally a description. The URI may be either a single asset or it may reference a directory.
///
/// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_asset_reference>
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct AssetReference {
    pub references: Vec<Reference>,
}

impl AssetReference {
    pub const LABEL: &'static str = labels::ASSET_REFERENCE;

    /// Creates an AssetReference to a location.
    pub fn new(uri: &str, description: Option<&str>) -> Self {
        Self {
            references: vec![Reference::new(uri, description)],
        }
    }

    /// Adds an [`AssetReference`] to this assertion's list of references.
    pub fn add_reference(mut self, uri: &str, description: Option<&str>) -> Self {
        self.references.push(Reference::new(uri, description));
        self
    }
}

/// Defines a single location of where a copy of the asset may be obtained.
#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
pub struct Reference {
    pub reference: ReferenceUri,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Reference {
    /// Creates a new reference to a location, and optionally a description.
    pub fn new(uri: &str, description: Option<&str>) -> Self {
        Reference {
            reference: ReferenceUri {
                uri: uri.to_owned(),
            },
            description: description.map(String::from),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
pub struct ReferenceUri {
    pub uri: String,
}

impl AssertionCbor for AssetReference {}

impl AssertionBase for AssetReference {
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

    use crate::{assertion::AssertionBase, assertions::AssetReference};

    #[test]
    fn assertion_references() {
        let original = AssetReference::new(
            "https://some.storage.us/foo",
            Some("A copy of the asset on the web"),
        )
        .add_reference("ipfs://cid", Some("A copy of the asset on IPFS"));

        assert_eq!(original.references.len(), 2);

        let assertion = original.to_assertion().unwrap();
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), AssetReference::LABEL);

        let result = AssetReference::from_assertion(&assertion).unwrap();
        assert_eq!(result, original)
    }

    #[test]
    fn test_json_round_trip() {
        let json = serde_json::json!({
            "references": [
                {
                "description": "A copy of the asset on the web",
                "reference": {
                    "uri": "https://some.storage.us/foo"
                    }
                },
                {
                "description": "A copy of the asset on IPFS",
                "reference": {
                    "uri": "ipfs://cid"
                    }
                }
            ]
        });

        let original: AssetReference = serde_json::from_value(json).unwrap();
        let assertion = original.to_assertion().unwrap();
        let result = AssetReference::from_assertion(&assertion).unwrap();

        assert_eq!(result, original);
    }
}
