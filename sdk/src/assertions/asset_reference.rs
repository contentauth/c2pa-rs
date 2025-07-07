use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    error::Result,
};

const ASSERTION_CREATION_VERSION: usize = 2;

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct AssetReference {
    pub references: Vec<Reference>,
}

impl AssetReference {
    pub const LABEL: &'static str = labels::ASSET_REFERENCE;

    pub fn new() -> Self {
        Self {
            references: Vec::new(),
        }
    }

    pub fn add_reference(mut self, reference: Reference) -> Self {
        self.references.push(reference);
        self
    }
}

#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
pub struct Reference {
    pub reference: InnerReference,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Reference {
    pub fn new(uri: &str, description: Option<&str>) -> Self {
        Reference {
            reference: InnerReference {
                uri: uri.to_owned(),
            },
            description: description.map(String::from),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
pub struct InnerReference {
    pub uri: String,
}

impl AssertionCbor for AssetReference {}

impl AssertionBase for AssetReference {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

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
        assertions::{asset_reference::Reference, AssetReference},
    };

    fn make_reference1() -> Reference {
        Reference::new(
            "https://some.storage.us/foo",
            Some("A copy of the asset on the web"),
        )
    }

    fn make_reference2() -> Reference {
        Reference::new("ipfs://cid", Some("A copy of the asset on IPFS"))
    }

    #[test]
    fn assertion_references() {
        let original = AssetReference::new()
            .add_reference(make_reference1())
            .add_reference(make_reference2());

        assert_eq!(original.references.len(), 2);

        let assertion = original.to_assertion().unwrap();
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), format!("{}.v2", AssetReference::LABEL));

        let result = AssetReference::from_assertion(&assertion).unwrap();
        assert_eq!(result.references.len(), 2);

        assert_eq!(result.references, original.references);
    }
}
