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

use std::collections::HashMap;

use chrono::{SecondsFormat, Utc};
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{labels, region_of_interest::RegionOfInterest},
    error::Result,
    hashed_uri::HashedUri,
    utils::cbor_types::DateT,
};

const ASSERTION_CREATION_VERSION: usize = 1;

/// The AssertionMetadata structure can be used as part of other assertions or on its own to reference others
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct AssertionMetadata {
    #[serde(rename = "reviewRatings", skip_serializing_if = "Option::is_none")]
    reviews: Option<Vec<ReviewRating>>,
    #[serde(rename = "dateTime", skip_serializing_if = "Option::is_none")]
    date_time: Option<DateT>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<HashedUri>,
    #[serde(rename = "dataSource", skip_serializing_if = "Option::is_none")]
    data_source: Option<DataSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    localizations: Option<Vec<HashMap<String, HashMap<String, String>>>>, // not implemented
    #[serde(rename = "regionOfInterest", skip_serializing_if = "Option::is_none")]
    region_of_interest: Option<RegionOfInterest>,
    /// Arbitrary key/value pairs as permitted by the C2PA spec.
    /// Uses flatten to allow these fields to be serialized at the same level as known fields.
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    additional_fields: HashMap<String, Value>,
}

impl AssertionMetadata {
    /// Label prefix for an assertion metadata assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_metadata_about_assertions>.
    pub const LABEL: &'static str = labels::ASSERTION_METADATA;

    pub fn new() -> Self {
        // Get current time (platform-specific)
        let date_time = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);

        Self {
            reviews: None,
            date_time: Some(DateT(date_time)),
            reference: None,
            data_source: None,
            localizations: None,
            region_of_interest: None,
            additional_fields: HashMap::new(),
        }
    }

    /// Returns the list of [`ReviewRating`] for this assertion if it exists.
    pub fn reviews(&self) -> Option<&[ReviewRating]> {
        self.reviews.as_deref()
    }

    /// Returns the ISO 8601 date-time string when the assertion was created/generated.
    pub fn date_time(&self) -> Option<&str> {
        self.date_time.as_deref()
    }

    /// Returns the vec of localizations maps if they exist.
    pub fn localizations(&self) -> Option<&Vec<HashMap<String, HashMap<String, String>>>> {
        self.localizations.as_ref()
    }

    /// Returns the [`DataSource`] for this assertion if it exists.
    pub fn data_source(&self) -> Option<&DataSource> {
        self.data_source.as_ref()
    }

    /// Returns the [`RegionOfInterest`] for this assertion if it exists.
    pub fn region_of_interest(&self) -> Option<&RegionOfInterest> {
        self.region_of_interest.as_ref()
    }

    /// Adds a [`ReviewRating`] associated with the assertion.
    pub fn add_review(mut self, review: ReviewRating) -> Self {
        match &mut self.reviews {
            None => self.reviews = Some(vec![review]),
            Some(reviews) => reviews.push(review),
        }
        self
    }

    /// Sets the list of [`ReviewRating`]s associated with the assertion.
    ///
    /// This replaces any previous list.
    pub fn set_reviews(mut self, reviews: Vec<ReviewRating>) -> Self {
        self.reviews = Some(reviews);
        self
    }

    /// Sets the ISO 8601 date-time string when the assertion was created/generated.
    pub fn set_date_time(mut self, date_time: String) -> Self {
        self.date_time = Some(DateT(date_time));
        self
    }

    /// Sets a [`HashedUri`] reference to another assertion to which this metadata applies.
    #[cfg(test)] // only referenced from test code
    pub(crate) fn set_reference(mut self, reference: HashedUri) -> Self {
        self.reference = Some(reference);
        self
    }

    /// Sets a description of the source of the assertion data, selected from a predefined list.
    pub fn set_data_source(mut self, data_source: DataSource) -> Self {
        self.data_source = Some(data_source);
        self
    }

    /// Sets the region of interest.
    pub fn set_region_of_interest(mut self, region_of_interest: RegionOfInterest) -> Self {
        self.region_of_interest = Some(region_of_interest);
        self
    }

    /// Sets all localizations, replacing any existing ones
    pub fn set_localizations(
        mut self,
        localizations: Vec<HashMap<String, HashMap<String, String>>>,
    ) -> Self {
        self.localizations = Some(localizations);
        self
    }

    /// Sets an arbitrary key/value pair in the metadata.
    ///
    /// This allows adding custom fields that are not part of the standard schema,
    /// as permitted by the C2PA specification.
    ///
    /// # Arguments
    ///
    /// * `key` - The key for the custom field
    /// * `value` - The value as a serde_json::Value
    ///
    /// # Example
    ///
    /// ```
    /// use c2pa::assertions::AssertionMetadata;
    /// use serde_json::json;
    ///
    /// let metadata = AssertionMetadata::new()
    ///     .set_field("customKey", json!("customValue"))
    ///     .set_field("nestedObject", json!({"foo": "bar", "count": 42}));
    /// ```
    pub fn set_field<S: Into<String>>(mut self, key: S, value: Value) -> Self {
        self.additional_fields.insert(key.into(), value);
        self
    }

    /// Gets an arbitrary key/value pair from the metadata.
    ///
    /// Returns `None` if the key doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up
    pub fn get_field(&self, key: &str) -> Option<&Value> {
        self.additional_fields.get(key)
    }

    /// Returns a reference to all additional fields.
    pub fn additional_fields(&self) -> &HashMap<String, Value> {
        &self.additional_fields
    }

    /// Sets multiple arbitrary key/value pairs at once, replacing any existing ones.
    ///
    /// # Arguments
    ///
    /// * `fields` - A HashMap of key/value pairs to set
    pub fn set_additional_fields(mut self, fields: HashMap<String, Value>) -> Self {
        self.additional_fields = fields;
        self
    }
}

impl Default for AssertionMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AssertionMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&serde_json::to_string_pretty(self).unwrap_or_default())
    }
}

impl AssertionCbor for AssertionMetadata {}

impl AssertionBase for AssertionMetadata {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

/// DATA_SOURCE Type values
pub mod c2pa_source {
    pub const SIGNER: &str = "signer";
    pub const GENERATOR_REE: &str = "claimGenerator.REE";
    pub const GENERATOR_TEE: &str = "claimGenerator.TEE";
    pub const LOCAL_REE: &str = "localProvider.REE";
    pub const LOCAL_TEE: &str = "localProvider.TEE";
    pub const REMOTE_REE: &str = "remoteProvider.1stParty";
    pub const REMOTE_TEE: &str = "remoteProvider.3rdParty";
    pub const HUMAN_ANONYMOUS: &str = "humanEntry.anonymous";
    pub const HUMAN_IDENTIFIED: &str = "humanEntry.identified";
}

/// A description of the source for assertion data
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct DataSource {
    /// A value from among the enumerated list indicating the source of the assertion.
    #[serde(rename = "type")]
    pub source_type: String,

    /// A human-readable string giving details about the source of the assertion data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// A list of [`Actor`]s associated with this source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actors: Option<Vec<Actor>>,
}

impl DataSource {
    pub fn new(source_type: &str) -> Self {
        Self {
            source_type: source_type.to_owned(),
            details: None,
            actors: None,
        }
    }

    /// Sets a human-readable string giving details about the source of the assertion data.
    pub fn set_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Sets a list of [`Actor`]s associated with this source.
    pub fn set_actors(mut self, actors: Option<Vec<Actor>>) -> Self {
        self.actors = actors;
        self
    }
}

/// Identifies a person responsible for an action.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct Actor {
    /// An identifier for a human actor, used when the "type" is `humanEntry.identified`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,

    /// List of references to W3C Verifiable Credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<HashedUri>>,
}

impl Actor {
    pub fn new(identifier: Option<&str>, credentials: Option<&Vec<HashedUri>>) -> Self {
        Self {
            identifier: identifier.map(|id| id.to_owned()),
            credentials: credentials.cloned(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReviewCode {
    #[serde(rename(serialize = "actions.unknownActionsPerformed"))]
    ActionsUnknown,
    #[serde(rename(serialize = "actions.missing"))]
    ActionsMissing,
    #[serde(rename(serialize = "actions.possiblyMissing"))]
    ActionsPossiblyMissing,
    #[serde(rename(serialize = "depthMap.sceneMismatch"))]
    DepthMapSceneMismatch,
    #[serde(rename(serialize = "ingredient.modified"))]
    IngredientModified,
    #[serde(rename(serialize = "ingredient.possiblyModified"))]
    IngredientPossiblyModified,
    #[serde(rename(serialize = "thumbnail.primaryMismatch"))]
    ThumbnailPrimaryMismatch,
    #[serde(rename(serialize = "stds.iptc.location.inaccurate"))]
    IptcLocationInaccurate,
    #[serde(rename(serialize = "stds.schema-org.CreativeWork.misattributed"))]
    CreativeWorkMisAttributed,
    #[serde(rename(serialize = "stds.schema-org.CreativeWork.missingAttribution"))]
    CreativeWorkMissingAttribution,
    Other(String),
}

/// A rating on an Assertion.
///
/// See <https://c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_review_ratings>.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ReviewRating {
    pub explanation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub value: u8,
}

impl ReviewRating {
    pub fn new(explanation: &str, code: Option<String>, value: u8) -> Self {
        Self {
            explanation: explanation.to_owned(),
            value, // should be in range 1 to 5
            code,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct AssetType {
    #[serde(rename = "type")]
    pub asset_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl AssetType {
    pub fn new<S: Into<String>>(asset_type: S, version: Option<String>) -> Self {
        AssetType {
            asset_type: asset_type.into(),
            version,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct DataBox {
    #[serde(rename = "dc:format")]
    pub format: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::region_of_interest::{Range, RangeType, Time, TimeType};

    #[test]
    fn assertion_metadata() {
        let review = ReviewRating::new("foo", Some("bar".to_owned()), 3);
        let mut translations = HashMap::new();
        translations.insert("en-US".to_owned(), "Kevin's Five Cats".to_owned());
        translations.insert("es-MX".to_owned(), "Los Cinco Gatos de Kevin".to_owned());
        let mut localizations = HashMap::new();
        localizations.insert("dc:title".to_owned(), translations);

        let original = AssertionMetadata::new()
            .add_review(review)
            .set_localizations(vec![localizations])
            .set_region_of_interest(RegionOfInterest {
                region: vec![Range {
                    range_type: RangeType::Temporal,
                    time: Some(Time {
                        time_type: TimeType::Npt,
                        start: None,
                        end: None,
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            });

        println!("{:}", &original);
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), AssertionMetadata::LABEL);
        let result = AssertionMetadata::from_assertion(&assertion).expect("extract_assertion");
        println!("{:?}", serde_json::to_string(&result));
        assert_eq!(original.date_time, result.date_time);
        assert_eq!(original.reviews, result.reviews);
        let localizations = result.localizations.as_ref().unwrap();
        assert_eq!(
            localizations[0]
                .get("dc:title")
                .unwrap()
                .get("en-US")
                .unwrap(),
            "Kevin's Five Cats"
        );
        assert_eq!(
            original.region_of_interest.as_ref(),
            result.region_of_interest()
        );

        // Test round-trip serialization
        let assertion = original.to_assertion().expect("build_assertion");
        let result = AssertionMetadata::from_assertion(&assertion).expect("extract_assertion");

        assert_eq!(original.localizations, result.localizations);
        assert_eq!(original.reviews.unwrap().len(), 1);
    }

    #[test]
    fn test_arbitrary_key_value_pairs() {
        use serde_json::json;

        // Create metadata with arbitrary key/value pairs
        let original = AssertionMetadata::new()
            .set_field("customString", json!("test value"))
            .set_field("customNumber", json!(42))
            .set_field("customBool", json!(true))
            .set_field("customObject", json!({"nested": "value", "count": 123}))
            .set_field("customArray", json!(["item1", "item2", "item3"]));

        // Test getter methods
        assert_eq!(
            original.get_field("customString"),
            Some(&json!("test value"))
        );
        assert_eq!(original.get_field("customNumber"), Some(&json!(42)));
        assert_eq!(original.get_field("customBool"), Some(&json!(true)));
        assert_eq!(
            original.get_field("customObject"),
            Some(&json!({"nested": "value", "count": 123}))
        );
        assert_eq!(original.get_field("nonexistent"), None);

        // Test additional_fields getter
        assert_eq!(original.additional_fields().len(), 5);
        assert!(original.additional_fields().contains_key("customString"));

        // Test serialization/deserialization round-trip
        let assertion = original.to_assertion().expect("build_assertion");
        let result = AssertionMetadata::from_assertion(&assertion).expect("extract_assertion");

        // Verify all fields survived round-trip
        assert_eq!(result.get_field("customString"), Some(&json!("test value")));
        assert_eq!(result.get_field("customNumber"), Some(&json!(42)));
        assert_eq!(result.get_field("customBool"), Some(&json!(true)));
        assert_eq!(
            result.get_field("customObject"),
            Some(&json!({"nested": "value", "count": 123}))
        );
        assert_eq!(
            result.get_field("customArray"),
            Some(&json!(["item1", "item2", "item3"]))
        );
        assert_eq!(result.additional_fields().len(), 5);
    }

    #[test]
    fn test_set_additional_fields() {
        use serde_json::json;

        let mut fields = HashMap::new();
        fields.insert("field1".to_owned(), json!("value1"));
        fields.insert("field2".to_owned(), json!(100));
        fields.insert("field3".to_owned(), json!({"key": "val"}));

        let metadata = AssertionMetadata::new().set_additional_fields(fields.clone());

        assert_eq!(metadata.additional_fields(), &fields);
        assert_eq!(metadata.get_field("field1"), Some(&json!("value1")));
        assert_eq!(metadata.get_field("field2"), Some(&json!(100)));
    }

    #[test]
    fn test_arbitrary_fields_with_standard_fields() {
        use serde_json::json;

        let review = ReviewRating::new("test review", Some("test.code".to_owned()), 3);

        // Mix arbitrary fields with standard fields
        let original = AssertionMetadata::new()
            .add_review(review)
            .set_date_time("2021-06-28T16:49:32.874Z".to_owned())
            .set_field("customField1", json!("custom value 1"))
            .set_field("customField2", json!({"nested": true}));

        // Serialize and deserialize
        let assertion = original.to_assertion().expect("build_assertion");
        let result = AssertionMetadata::from_assertion(&assertion).expect("extract_assertion");

        // Verify standard fields
        assert!(result.reviews().is_some());
        assert_eq!(result.reviews().unwrap().len(), 1);
        assert_eq!(result.date_time(), Some("2021-06-28T16:49:32.874Z"));

        // Verify custom fields
        assert_eq!(
            result.get_field("customField1"),
            Some(&json!("custom value 1"))
        );
        assert_eq!(
            result.get_field("customField2"),
            Some(&json!({"nested": true}))
        );
    }

    #[test]
    fn test_empty_additional_fields() {
        // Test that empty additional_fields are handled correctly
        let original = AssertionMetadata::new();

        assert_eq!(original.additional_fields().len(), 0);
        assert_eq!(original.get_field("anything"), None);

        // Serialize and deserialize
        let assertion = original.to_assertion().expect("build_assertion");
        let result = AssertionMetadata::from_assertion(&assertion).expect("extract_assertion");

        assert_eq!(result.additional_fields().len(), 0);
    }

    #[test]
    fn test_cbor_serialization_with_arbitrary_fields() {
        use serde_json::json;

        // Create metadata with various field types
        let original = AssertionMetadata::new()
            .set_field("stringField", json!("test"))
            .set_field("numberField", json!(42.5))
            .set_field("boolField", json!(false))
            .set_field("nullField", json!(null))
            .set_field("arrayField", json!([1, 2, 3]))
            .set_field("objectField", json!({"a": 1, "b": "two"}));

        // Convert to CBOR and back
        let cbor_bytes = c2pa_cbor::to_vec(&original).expect("serialize to CBOR");
        let result: AssertionMetadata =
            c2pa_cbor::from_slice(&cbor_bytes).expect("deserialize from CBOR");

        // Verify all fields
        assert_eq!(result.get_field("stringField"), Some(&json!("test")));
        assert_eq!(result.get_field("numberField"), Some(&json!(42.5)));
        assert_eq!(result.get_field("boolField"), Some(&json!(false)));
        assert_eq!(result.get_field("nullField"), Some(&json!(null)));
        assert_eq!(result.get_field("arrayField"), Some(&json!([1, 2, 3])));
        assert_eq!(
            result.get_field("objectField"),
            Some(&json!({"a": 1, "b": "two"}))
        );
    }
}
