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
    assertions::labels,
    error::Result,
    hashed_uri::HashedUri,
    utils::cbor_types::DateT,
};

const ASSERTION_CREATION_VERSION: usize = 1;

/// The Metadata structure can be used as part of other assertions or on its own to reference others
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Metadata {
    #[serde(rename = "reviewRatings", skip_serializing_if = "Option::is_none")]
    reviews: Option<Vec<ReviewRating>>,
    #[serde(rename = "dateTime", skip_serializing_if = "Option::is_none")]
    date_time: Option<DateT>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<HashedUri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_source: Option<DataSource>,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}

impl Metadata {
    /// Label prefix for an assertion metadata assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_metadata_about_assertions>.
    pub const LABEL: &'static str = labels::ASSERTION_METADATA;

    pub fn new() -> Self {
        Self {
            reviews: None,
            date_time: Some(DateT(
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            )),
            reference: None,
            data_source: None,
            other: HashMap::new(),
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

    /// Returns the [`DataSource`] for this assertion if it exists.
    pub fn data_source(&self) -> Option<&DataSource> {
        self.data_source.as_ref()
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
    pub fn set_date_time(&mut self, date_time: String) -> &mut Self {
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

    /// Adds an additional key / value pair.
    pub fn insert(&mut self, key: &str, value: Value) -> &mut Self {
        self.other.insert(key.to_string(), value);
        self
    }

    /// Gets additional values by key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.other.get(key)
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

impl AssertionCbor for Metadata {}

impl AssertionBase for Metadata {
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

/// A rating on an [`Assertion`].
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_claim_review>.
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

#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct DataBox {
    #[serde(rename = "dc:format")]
    pub format: String,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    pub data_types: Option<Vec<AssetType>>,
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn assertion_metadata() {
        let review = ReviewRating::new("foo", Some("bar".to_owned()), 3);
        let test_value = Value::from("test");
        let mut original = Metadata::new().add_review(review);
        original.insert("foo", test_value);
        println!("{:?}", &original);
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), Metadata::LABEL);
        let result = Metadata::from_assertion(&assertion).expect("extract_assertion");
        println!("{:?}", serde_json::to_string(&result));
        assert_eq!(original.date_time, result.date_time);
        assert_eq!(original.reviews, result.reviews);
        assert_eq!(original.get("foo").unwrap(), "test");
        //assert_eq!(original.reviews.unwrap().len(), 1);
    }
}
