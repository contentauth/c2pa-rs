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

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    error::Result,
    hashed_uri::HashedUri,
};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

const ASSERTION_CREATION_VERSION: usize = 1;

/// The Metadata structure can be used as part of other assertions or on its own to reference others
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Metadata {
    #[serde(rename = "reviewRatings", skip_serializing_if = "Option::is_none")]
    pub reviews: Option<Vec<ReviewRating>>,
    #[serde(rename = "dateTime", skip_serializing_if = "Option::is_none")]
    pub date_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<HashedUri>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_source: Option<DataSource>,
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
            date_time: Some(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
            reference: None,
            data_source: None,
            other: HashMap::new(),
        }
    }

    /// add a review rating associated with the assertion
    pub fn add_review(mut self, review: ReviewRating) -> Self {
        match &mut self.reviews {
            None => self.reviews = Some(vec![review]),
            Some(reviews) => reviews.push(review),
        }
        self
    }

    /// Set review ratings associated with the assertion
    pub fn set_reviews(mut self, reviews: Option<Vec<ReviewRating>>) -> Self {
        self.reviews = reviews;
        self
    }

    /// Set hashed_uri reference to another assertion to which this metadata applies
    pub fn set_reference(mut self, reference: Option<HashedUri>) -> Self {
        self.reference = reference;
        self
    }

    /// set a description of the source of the assertion data, selected from a predefined list
    pub fn set_data_source(mut self, data_source: Option<DataSource>) -> Self {
        self.data_source = data_source;
        self
    }

    /// add additional key / value pair
    pub fn insert(&mut self, key: &str, value: &Value) -> &mut Self {
        self.other.insert(key.to_string(), value.clone());
        self
    }

    /// get additional values by key
    pub fn get(self, key: &str) -> Option<Value> {
        self.other.get(key).cloned()
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
pub const C2PA_SOURCE_SIGNER: &str = "signer";
pub const C2PA_SOURCE_GENERATOR_REE: &str = "claimGenerator.REE";
pub const C2PA_SOURCE_GENERATOR_TEE: &str = "claimGenerator.TEE";
pub const C2PA_SOURCE_LOCAL_REE: &str = "localProvider.REE";
pub const C2PA_SOURCE_LOCAL_TEE: &str = "localProvider.TEE";
pub const C2PA_SOURCE_REMOTE_REE: &str = "remoteProvider.1stParty";
pub const C2PA_SOURCE_REMOTE_TEE: &str = "remoteProvider.3rdParty";
pub const C2PA_SOURCE_HUMAN_ANONYMOUS: &str = "humanEntry.anonymous";
pub const C2PA_SOURCE_HUMAN_IDENTIFIED: &str = "humanEntry.identified";

/// A description of the source for assertion data
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
pub struct DataSource {
    #[serde(rename = "type")]
    pub source_type: String, // A value from among the enumerated list indicating the source of the assertion
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>, // A human readable string giving details about the source of the assertion data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actors: Option<Vec<Actor>>, //  array of hashed_uri references to W3C Verifiable Credentials
}

impl DataSource {
    pub fn new(source_type: &str) -> Self {
        Self {
            source_type: source_type.to_owned(),
            details: None,
            actors: None,
        }
    }

    /// Set a human readable string giving details about the source of the assertion data
    pub fn set_details(mut self, details: Option<&str>) -> Self {
        self.details = details.map(|s| s.to_owned());
        self
    }

    /// Set list of actors associated with this source
    pub fn set_actors(mut self, actors: Option<&Vec<Actor>>) -> Self {
        self.actors = actors.cloned();
        self
    }
}
/// identifies a person responsible for an action
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq)]
pub struct Actor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>, // An identifier for a human actor, used when the "type" is humanEntry.identified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<HashedUri>>, // array of hashed_uri references to W3C Verifiable Credentials
}

impl Actor {
    pub fn new(identifier: Option<&str>, credentials: Option<&Vec<HashedUri>>) -> Self {
        Self {
            identifier: identifier.map(|id| id.to_owned()),
            credentials: credentials.cloned(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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

/// A rating on an assertion
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
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
        original.insert("foo", &test_value);
        println!("{:?}", &original);
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), Metadata::LABEL);
        let result = Metadata::from_assertion(&assertion).expect("extract_assertion");
        println!("{:?}", serde_json::to_string(&result));
        assert_eq!(original.date_time, result.date_time);
        assert_eq!(original.reviews, result.reviews);
        assert_eq!(original.get("foo").unwrap(), "test".to_string());
        //assert_eq!(original.reviews.unwrap().len(), 1);
    }
}
