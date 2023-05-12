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

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionJson},
    assertions::labels,
    error::{Error, Result},
    hashed_uri::HashedUri,
};

const ASSERTION_CREATION_VERSION: usize = 1;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SchemaDotOrg {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    object_context: Option<Value>,
    #[serde(rename = "@type", default = "default_type")]
    object_type: String,
    #[serde(flatten)]
    value: HashMap<String, Value>,
}

// used to set the default @type if it is missing
fn default_type() -> String {
    "Thing".to_string()
}

impl SchemaDotOrg {
    /// constructs an empty Schema.org object of the specified @type with @context
    pub fn new(object_type: String) -> Self {
        Self {
            object_context: None,
            object_type,
            value: HashMap::new(),
        }
    }

    /// sets the @context field for Schema dot org.
    pub fn set_default_context(mut self) -> Self {
        self.object_context = Some(json!("https://schema.org"));
        self
    }

    /// sets the @context field for Schema dot org.
    pub fn set_context(mut self, context: Value) -> Self {
        self.object_context = Some(context);
        self
    }

    /// return the @type value from the object
    pub fn object_type(&self) -> &str {
        self.object_type.as_str()
    }

    /// get values by key as an instance of type `T`.
    /// This return T is owned, not a reference
    /// # Errors
    ///
    /// This conversion can fail if the structure of the field at key does not match the
    /// structure expected by `T`
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.value
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// insert key / value pair of instance of type `T`
    /// # Errors
    ///
    /// This conversion can fail if `T`'s implementation of `Serialize` decides to
    /// fail, or if `T` contains a map with non-string keys.
    pub fn insert<T: Serialize>(mut self, key: String, value: T) -> Result<Self> {
        self.value.insert(key, serde_json::to_value(value)?);
        Ok(self)
    }

    // add a value to a Vec stored at key
    pub fn insert_push<T: Serialize + DeserializeOwned>(
        self,
        key: String,
        value: T,
    ) -> Result<Self> {
        Ok(match self.get(&key) as Option<Vec<T>> {
            Some(mut v) => {
                v.push(value);
                self
            }
            None => self.insert(key, &Vec::from([value]))?,
        })
    }

    /// creates the struct from a correctly formatted JSON string
    pub fn from_json_str(json: &str) -> Result<Self> {
        serde_json::from_slice(json.as_bytes()).map_err(Error::JsonError)
    }
}

impl Default for SchemaDotOrg {
    fn default() -> Self {
        Self::new(default_type())
    }
}

impl AssertionJson for SchemaDotOrg {}

impl AssertionBase for SchemaDotOrg {
    const LABEL: &'static str = labels::SCHEMA_ORG;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_json_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_json_assertion(assertion)
    }
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SchemaDotOrgPerson(SchemaDotOrg);

impl SchemaDotOrgPerson {
    pub const CREDENTIAL: &'static str = "credential";
    pub const IDENTIFIER: &'static str = "identifier";
    pub const NAME: &'static str = "name";
    pub const PERSON: &'static str = "Person";

    pub fn new() -> Self {
        Self(SchemaDotOrg::new(Self::PERSON.to_owned()))
    }

    pub fn new_person<S: Into<String>>(name: S, identifier: S) -> Result<Self> {
        Self(SchemaDotOrg::new(Self::PERSON.to_owned()))
            .set_name(name)?
            .set_identifier(identifier)
    }

    /// get values by key
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.0.get(key)
    }

    /// insert key / value pair
    pub fn insert<S: Into<String>, T: Serialize>(self, key: S, value: T) -> Result<Self> {
        self.0.insert(key.into(), value).map(Self)
    }

    // add a value to a Vec stored at key
    pub fn insert_push<S: Into<String>, T>(self, key: S, value: T) -> Result<Self>
    where
        T: Serialize + DeserializeOwned,
    {
        self.0.insert_push(key.into(), value).map(Self)
    }

    // get name field if it exists
    pub fn name(&self) -> Option<String> {
        self.get(Self::NAME)
    }

    pub fn set_name<S: Into<String>>(self, author: S) -> Result<Self> {
        self.insert(Self::NAME.to_string(), author.into())
    }

    // get identifier field if it exists
    pub fn identifier(&self) -> Option<String> {
        self.get(Self::IDENTIFIER)
    }

    pub fn set_identifier<S: Into<String>>(self, identifier: S) -> Result<Self> {
        self.insert(Self::IDENTIFIER.to_owned(), identifier.into())
    }

    pub fn add_credential(self, credential: HashedUri) -> Result<Self> {
        self.insert_push(Self::CREDENTIAL.to_owned(), credential)
    }
}

impl Default for SchemaDotOrgPerson {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for SchemaDotOrgPerson {
    type Target = SchemaDotOrg;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    const USER: &str = "Joe Bloggs";
    const USER_ID: &str = "1234567890";
    const IDENTITY_URI: &str = "https://some_identity/service/";

    // example review rating from
    // https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_claim_review
    const RATING: &str = r#"{
        "@context": "http://schema.org",
        "@type": "ClaimReview",
        "claimReviewed": "The world is flat",
        "reviewRating": {
          "@type": "Rating",
          "ratingValue": "1",
          "bestRating": "5",
          "worstRating": "1",
          "ratingExplanation": "The world is not flat",
          "alternateName": "False"
        },
        "itemReviewed": {
          "@type": "CreativeWork",
          "author": {
            "@type": "Person",
            "name": "A N Other"
          },
          "headline": "Earth: Flat."
        }
      }"#;

    #[test]
    fn assertion_creative_work() {
        let uri = HashedUri::new(USER_ID.to_string(), None, b"abcde");
        let original_person = SchemaDotOrgPerson::new()
            .set_name(USER.to_owned())
            .unwrap()
            .set_identifier(IDENTITY_URI.to_owned())
            .unwrap()
            .add_credential(uri)
            .unwrap();
        let original = SchemaDotOrg::new("CreativeWork".to_owned())
            .insert("author".to_owned(), original_person.clone())
            .expect("insert");
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/json");
        assert_eq!(assertion.label(), SchemaDotOrg::LABEL);
        let result = SchemaDotOrg::from_assertion(&assertion).expect("extract_assertion");
        assert_eq!(original.object_type(), result.object_type());
        let result_person = result.get::<SchemaDotOrgPerson>("author").unwrap();
        assert_eq!(original_person.name(), result_person.name());
    }

    #[test]
    fn from_rating() {
        let original = SchemaDotOrg::from_json_str(RATING).expect("from_json");
        let original_claim_reviewed: String = original.get("claimReviewed").unwrap();
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/json");
        assert_eq!(assertion.label(), SchemaDotOrg::LABEL);
        let result = SchemaDotOrg::from_assertion(&assertion).expect("extract_assertion");
        assert_eq!(original.object_type(), result.object_type());
        let result_claim_reviewed: String = result.get("claimReviewed").unwrap();
        assert_eq!(original_claim_reviewed, result_claim_reviewed);
    }
}
