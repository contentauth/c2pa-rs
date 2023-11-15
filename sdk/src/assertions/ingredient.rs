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

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{labels, Metadata, ReviewRating},
    error::Result,
    hashed_uri::HashedUri,
    validation_status::ValidationStatus,
};

const ASSERTION_CREATION_VERSION: usize = 2;

// Used to differentiate a parent from a component
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub enum Relationship {
    #[serde(rename = "parentOf")]
    ParentOf,
    #[serde(rename = "componentOf")]
    #[default]
    ComponentOf,
    #[serde(rename = "inputTo")]
    InputTo,
}

/// An ingredient assertion
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Ingredient {
    #[serde(rename = "dc:title")]
    pub title: String,
    #[serde(rename = "dc:format")]
    pub format: String,
    #[serde(rename = "documentID", skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    #[serde(rename = "instanceID", skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c2pa_manifest: Option<HashedUri>,
    #[serde(rename = "validationStatus", skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<Vec<ValidationStatus>>,
    pub relationship: Relationship,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<HashedUri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<HashedUri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "informational_URI", skip_serializing_if = "Option::is_none")]
    pub informational_uri: Option<String>,
}

impl Ingredient {
    /// Label prefix for an ingredient assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_ingredient>.
    pub const LABEL: &'static str = labels::INGREDIENT;

    pub fn new(title: &str, format: &str, instance_id: &str, document_id: Option<&str>) -> Self {
        Self {
            title: title.to_owned(),
            format: format.to_owned(),
            document_id: document_id.map(|id| id.to_owned()),
            instance_id: Some(instance_id.to_owned()),
            ..Default::default()
        }
    }

    pub fn new_v2<S1, S2>(title: S1, format: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self {
            title: title.into(),
            format: format.into(),
            ..Default::default()
        }
    }

    /// determines if an ingredient is a v2 ingredient
    fn is_v2(&self) -> bool {
        self.instance_id.is_none()
            || self.data.is_some()
            || self.description.is_some()
            || self.informational_uri.is_some()
    }

    pub fn set_parent(mut self) -> Self {
        self.relationship = Relationship::ParentOf;
        self
    }

    pub fn set_c2pa_manifest_from_hashed_uri(mut self, provenance: Option<HashedUri>) -> Self {
        self.c2pa_manifest = provenance;
        self
    }

    pub fn set_thumbnail_hash_link(mut self, thumbnail: Option<&str>) -> Self {
        self.thumbnail =
            thumbnail.map(|thumb| HashedUri::new(thumb.to_owned(), None, "Hash".as_bytes()));
        self
    }

    pub fn set_thumbnail(mut self, hashed_uri: Option<&HashedUri>) -> Self {
        self.thumbnail = hashed_uri.map(|h| h.to_owned());
        self
    }

    pub fn add_review(mut self, review: ReviewRating) -> Self {
        let metadata = self.metadata.unwrap_or_default();
        self.metadata = Some(metadata.add_review(review));
        self
    }

    pub fn add_reviews(mut self, reviews: Option<Vec<ReviewRating>>) -> Self {
        if let Some(reviews) = reviews {
            let metadata = Metadata::new().set_reviews(reviews);
            self.metadata = Some(metadata);
        };
        self
    }

    pub fn add_validation_status(mut self, status: ValidationStatus) {
        match &mut self.validation_status {
            None => self.validation_status = Some(vec![status]),
            Some(validation_status) => validation_status.push(status),
        }
    }
}

impl AssertionCbor for Ingredient {}

impl AssertionBase for Ingredient {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    /// if we require v2 fields then use V2
    fn version(&self) -> Option<usize> {
        if self.is_v2() {
            Some(2)
        } else {
            Some(1)
        }
    }

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
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertion::{AssertionCbor, AssertionData};

    #[test]
    fn assertion_ingredient() {
        let original = Ingredient::new(
            "image 1.jpg",
            "image/jpeg",
            "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
            Some("xmp.did:87d51599-286e-43b2-9478-88c79f49c347"),
        )
        .set_thumbnail_hash_link(Some("#c2pa.ingredient.thumbnail.jpeg"));
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), Ingredient::LABEL);
        let result = Ingredient::from_cbor_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.title, result.title);
        assert_eq!(original.format, result.format);
        assert_eq!(original.document_id, result.document_id);
        assert_eq!(original.instance_id, result.instance_id);
        assert_eq!(original.thumbnail, result.thumbnail);
    }

    #[test]
    fn test_build_assertion() {
        let assertion = Ingredient::new(
            "image 1.jpg",
            "image/jpeg",
            "xmp.did:87d51599-286e-43b2-9478-88c79f49c347",
            Some("xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d"),
        )
        .set_thumbnail_hash_link(Some("#c2pa.ingredient.thumbnail.jpeg"))
        .to_assertion()
        .unwrap();

        println!("assertion label: {}", assertion.label());

        let j = assertion.data();

        let from_j = Assertion::from_data_cbor(&assertion.label(), j);
        let ad_ref = from_j.decode_data();

        if let AssertionData::Cbor(ref ad_cbor) = ad_ref {
            // compare results
            let orig_d = assertion.decode_data();
            if let AssertionData::Cbor(ref orig_cbor) = orig_d {
                assert_eq!(orig_cbor, ad_cbor);
            } else {
                panic!("Couldn't decode orig_d");
            }
        } else {
            panic!("Couldn't decode ad_ref");
        }
    }

    #[test]
    fn test_binary_round_trip() {
        let assertion = Ingredient::new(
            "image 1.jpg",
            "image/jpeg",
            "xmp.did:87d51599-286e-43b2-9478-88c79f49c347",
            Some("xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d"),
        )
        //.set_provenance("")
        .set_thumbnail_hash_link(Some("#c2pa.ingredient.thumbnail.jpeg"))
        .to_assertion()
        .unwrap();

        let orig_bytes = assertion.data();

        let assertion_from_binary = Assertion::from_data_cbor(&assertion.label(), orig_bytes);

        println!(
            "Label Match Test {} = {}",
            assertion.label(),
            assertion_from_binary.label()
        );
        assert_eq!(assertion.label(), assertion_from_binary.label());

        // compare the data as bytes
        assert_eq!(orig_bytes, assertion_from_binary.data());
        println!("Decoded binary matches")
    }

    #[test]
    fn test_assertion_with_reviews() {
        let review = ReviewRating::new(
            "a 3rd party plugin was used",
            Some("actions.unknownActionsPerformed".to_string()),
            1,
        );
        let original = Ingredient::new(
            "image 1.jpg",
            "image/jpeg",
            "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
            Some("xmp.did:87d51599-286e-43b2-9478-88c79f49c347"),
        )
        .add_review(review);

        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), Ingredient::LABEL);
        let restored = Ingredient::from_cbor_assertion(&assertion).expect("from_assertion");
        assert_eq!(original.title, restored.title);
        assert_eq!(original.format, restored.format);
        assert_eq!(original.document_id, restored.document_id);
        assert_eq!(original.instance_id, restored.instance_id);
        assert_eq!(original.thumbnail, restored.thumbnail);

        assert!(restored.metadata.is_some());
        let metadata = restored.metadata.unwrap();
        let date_time = metadata.date_time().unwrap();
        let date_time_parsed = chrono::DateTime::parse_from_rfc3339(date_time);

        assert!(metadata.reviews().is_some());
        assert!(date_time_parsed.is_ok());

        let reviews = metadata.reviews().unwrap();

        assert_eq!(reviews.len(), 1);
        assert_eq!(
            reviews[0].code.as_ref().unwrap(),
            "actions.unknownActionsPerformed"
        );
        assert_eq!(reviews[0].explanation, "a 3rd party plugin was used");
        assert_eq!(reviews[0].value, 1);
    }
}
