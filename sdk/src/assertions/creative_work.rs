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

use std::ops::Deref;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionJson},
    assertions::{labels, SchemaDotOrg, SchemaDotOrgPerson},
    error::Result,
};

const ASSERTION_CREATION_VERSION: usize = 1;
const CW_AUTHOR: &str = "author";

#[derive(Serialize, Deserialize, Debug)]
pub struct CreativeWork(SchemaDotOrg);

impl CreativeWork {
    /// Label prefix for a creative work assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_creative_work>.
    pub const LABEL: &'static str = labels::CREATIVE_WORK;

    pub fn new() -> CreativeWork {
        Self(
            SchemaDotOrg::new("CreativeWork".to_owned()).set_context(json!("http://schema.org/")),
            // todo: this should reflect the c2pa extensions in some way to be correct
            //.set_context(json!(["http://schema.org/",{"credential": {"@id": "c2pa:Credential"},"alg": {"@id": "c2pa:Alg"},"hash": {"@id": "c2pa:hash"}}]))
        )
    }

    /// get values by key
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.0.get(key)
    }

    /// insert key / value pair
    pub fn insert<S: Into<String>, T: Serialize>(self, key: S, value: T) -> Result<Self> {
        self.0.insert(key.into(), value).map(Self)
    }

    /// get creative work from json string
    pub fn from_json_str(json: &str) -> Result<Self> {
        SchemaDotOrg::from_json_str(json).map(Self)
    }

    // get author field if it exists
    pub fn author(&self) -> Option<Vec<SchemaDotOrgPerson>> {
        self.get(CW_AUTHOR)
    }

    pub fn set_author(self, author: &[SchemaDotOrgPerson]) -> Result<Self> {
        self.insert(CW_AUTHOR.to_owned(), author)
    }

    pub fn add_author(self, author: SchemaDotOrgPerson) -> Result<Self> {
        let mut v = self.author().unwrap_or_default();
        v.push(author);
        self.insert(CW_AUTHOR.to_owned(), &v)
    }
}

impl Default for CreativeWork {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for CreativeWork {
    type Target = SchemaDotOrg;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AssertionJson for CreativeWork {}

impl AssertionBase for CreativeWork {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_json_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_json_assertion(assertion)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::hashed_uri::HashedUri;

    const USER: &str = "Joe Bloggs";
    const USER_ID: &str = "1234567890";
    const IDENTITY_URI: &str = "https://some_identity/service/";

    // example CreativeWork from
    // https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_claim_review
    const SAMPLE_CREATIVE_WORK: &str = r#"{
        "@context": [
          "http://schema.org/",
          {
            "credential": null
          }
        ],
        "@type": "CreativeWork",
        "datePublished": "2021-05-20T23:02:36+00:00",
        "publisher": {
          "name": "BBC News",
          "publishingPrinciples": "https://www.bbc.co.uk/news/help-41670342",
          "logo": "https://m.files.bbci.co.uk/modules/bbc-morph-news-waf-page-meta/5.1.0/bbc_news_logo.png",
          "parentOrganization": {
            "name": "BBC",
            "legalName": "British Broadcasting Corporation"
          }
        },
        "url": "https://www.bbc.co.uk/news/av/world-europe-57194011",
        "identifier": "p09j7vzv",
        "producer": {
          "identifier": "https://en.wikipedia.org/wiki/Joe_Bloggs",
          "name": "Joe Bloggs",
          "credential": [
            {
              "url": "self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.credentials/Joe_Bloggs",
              "alg": "sha256",
              "hash": "Auxjtmax46cC2N3Y9aFmBO9Jfay8LEwJWzBUtZ0sUM8gA"
            }
          ]
        },
        "copyrightHolder": {
          "name": "BBC",
          "legalName": "British Broadcasting Corporation"
        },
        "copyrightYear": 2021,
        "copyrightNotice": "Copyright © 2021 BBC."
      }"#;

    const STOCK_CREATIVE_WORK: &str = r#"{"@type":"CreativeWork","@context":"https://schema.org","url":"https://stock.adobe.com/295991044"}"#;

    #[test]
    fn assertion_creative_work() {
        let uri = HashedUri::new(USER_ID.to_string(), None, b"abcde");
        let cw_person = SchemaDotOrgPerson::new()
            .set_name(USER.to_owned())
            .unwrap()
            .set_identifier(IDENTITY_URI.to_owned())
            .unwrap()
            .insert(
                "@id".to_owned(),
                ["https://www.twitter.com/joebloggs".to_owned()].to_vec(),
            )
            .unwrap()
            .add_credential(uri)
            .unwrap();
        let original = CreativeWork::new()
            .add_author(cw_person.clone())
            .expect("add_author")
            // example of adding a different kind of person field
            .insert("creator".to_owned(), cw_person)
            .expect("insert");
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/json");
        assert_eq!(assertion.label(), CreativeWork::LABEL);
        let result = CreativeWork::from_assertion(&assertion).expect("extract_assertion");
        assert_eq!(
            original.author().unwrap()[0].name(),
            result.author().unwrap()[0].name()
        );
    }

    #[test]
    fn from_creative_work_sample() {
        let original = CreativeWork::from_json_str(SAMPLE_CREATIVE_WORK).expect("from_json_str");
        let original_publisher: SchemaDotOrgPerson = original.get("publisher").unwrap();
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/json");
        assert_eq!(assertion.label(), CreativeWork::LABEL);
        let result = CreativeWork::from_assertion(&assertion).expect("extract_assertion");
        assert_eq!(original.object_type(), result.object_type());
        let result_publisher: SchemaDotOrgPerson = result.get("publisher").unwrap();
        assert_eq!(result_publisher.name().unwrap(), "BBC News");
        assert_eq!(original_publisher.name(), result_publisher.name());
    }

    #[test]
    fn from_creative_work_stock() {
        let original = CreativeWork::from_json_str(STOCK_CREATIVE_WORK).expect("from_json_str");
        let original_url: String = original.get("url").unwrap();
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/json");
        assert_eq!(assertion.label(), CreativeWork::LABEL);
        let result = CreativeWork::from_assertion(&assertion).expect("extract_assertion");
        assert_eq!(original.object_type(), result.object_type());
        let result_url: String = result.get("url").unwrap();
        assert_eq!(original_url, result_url);
    }
}
