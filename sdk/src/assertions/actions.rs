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
    assertions::{labels, Actor, Metadata},
    error::Result,
    Error,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Specification defined C2PA actions
pub mod c2pa_action {
    /// Changes to tone, saturation, etc.
    pub const COLOR_ADJUSTMENTS: &str = "c2pa.color_adjustments";
    /// The format of the asset was changed.
    pub const CONVERTED: &str = "c2pa.converted";
    /// The asset was first created, usually the asset's origin.
    pub const CREATED: &str = "c2pa.created";
    /// Areas of the asset's "editorial" content were cropped out.
    pub const CROPPED: &str = "c2pa.cropped";
    /// Changes using drawing tools including brushes or eraser.
    pub const DRAWING: &str = "c2pa.drawing";
    /// Generalized actions that affect the "editorial" meaning of the content.
    pub const EDITED: &str = "c2pa.edited";
    /// Changes to appearance with applied filters, styles, etc.
    pub const FILTERED: &str = "c2pa.filtered";
    /// An existing asset was opened and is being set as the `parentOf` ingredient.
    pub const OPENED: &str = "c2pa.opened";
    /// Changes to the direction and position of content.
    pub const ORIENTATION: &str = "c2pa.orientation";
    /// Added/Placed a `componentOf` ingredient into the asset.
    pub const PLACED: &str = "c2pa.placed";
    /// Asset is released to a wider audience.
    pub const PUBLISHED: &str = "c2pa.published";
    /// A conversion of one packaging or container format to another. Content may be repackaged without transcoding.
    /// Does not include any adjustments that would affect the "editorial" meaning of the content.
    pub const REPACKAGED: &str = "c2pa.repackaged";
    /// Changes to content dimensions and/or file size
    pub const RESIZED: &str = "c2pa.resized";
    /// A direct conversion of one encoding to another, including resolution scaling, bitrate adjustment and encoding format change.
    /// Does not include any adjustments that would affect the "editorial" meaning of the content.
    pub const TRANSCODED: &str = "c2pa.transcoded";
    /// Something happened, but the claim_generator cannot specify what.
    pub const UNKNOWN: &str = "c2pa.unknown";
}

/// Defines an action taken on an image
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct Action {
    #[serde(rename = "action")]
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(rename = "softwareAgent", skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<String>,
    #[serde(rename = "InstanceId", skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actors: Option<Vec<Actor>>,
}

impl Action {
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            when: None,
            software_agent: None,
            changed: None,
            instance_id: None,
            parameters: None,
            actors: None,
        }
    }

    /// set Timestamp of when the action occurred
    pub fn set_when(mut self, when: &str) -> Self {
        self.when = Some(when.to_owned());
        self
    }

    /// Set the software agent that performed the action.
    pub fn set_software_agent(mut self, software_agent: &str) -> Self {
        self.software_agent = Some(software_agent.to_owned());
        self
    }

    /// Set a list of the parts of the resource that were changed since the previous event history.
    pub fn set_changed(mut self, changed: Option<&Vec<&str>>) -> Self {
        self.changed = changed.map(|v| v.join(";"));
        self
    }

    /// The value of the xmpMM:InstanceID property for the modified (output) resource
    pub fn set_instance_id(mut self, id: &str) -> Self {
        self.instance_id = Some(id.to_owned());
        self
    }

    /// Set additional parameters of the action. These will often vary by the type of action
    pub fn set_parameter<T: Serialize>(mut self, key: String, value: T) -> Result<Self> {
        let value = serde_json::to_value(value).map_err(|_| Error::AssertionEncoding)?;
        self.parameters = Some(match self.parameters {
            Some(mut parameters) => {
                parameters.insert(key, value);
                parameters
            }
            None => {
                let mut p = HashMap::new();
                p.insert(key, value);
                p
            }
        });
        Ok(self)
    }

    /// An array of the creators that undertook this action
    pub fn set_actors(mut self, actors: Option<&Vec<Actor>>) -> Self {
        self.actors = actors.cloned();
        self
    }
}

/// A list of actions as an assertion
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct Actions {
    pub actions: Vec<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

impl Actions {
    /// Label prefix for an actions assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_actions>.
    pub const LABEL: &'static str = labels::ACTIONS;

    /// creates a new Actions object
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            metadata: None,
        }
    }

    /// Adds an action
    pub fn add_action(&mut self, action: Action) -> &mut Self {
        self.actions.push(action);
        self
    }

    /// Adds a metadata structure to the action
    pub fn add_metadata(&mut self, metadata: Metadata) -> &Self {
        self.metadata = Some(metadata);
        self
    }

    /// creates an actions assertion from a compatible JSON Value
    pub fn from_json_value(json: &serde_json::Value) -> Result<Self> {
        let actions: Actions = serde_json::from_value(json.clone())?;
        Ok(actions)
    }
}

impl AssertionCbor for Actions {}

impl AssertionBase for Actions {
    const LABEL: &'static str = labels::ACTIONS;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

impl Default for Actions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    use crate::assertion::{Assertion, AssertionData};
    use crate::assertions::metadata::{DataSource, ReviewRating, C2PA_SOURCE_GENERATOR_REE};
    use crate::hashed_uri::HashedUri;

    fn make_hashed_uri1() -> HashedUri {
        HashedUri::new(
            "self#jumbf=verified_credentials/1234".to_string(),
            None,
            b"hashed",
        )
    }

    fn make_action1() -> Action {
        Action::new(c2pa_action::CROPPED)
            .set_software_agent("test")
            .set_when("2015-06-26T16:43:23+0200")
            .set_parameter(
                "foo".to_owned(),
                &r#"{
                "left": 0,
                "right": 2000,
                "top": 1000,
                "bottom": 4000
            }"#
                .to_owned(),
            )
            .unwrap()
            .set_parameter("ingredient".to_owned(), &make_hashed_uri1())
            .unwrap()
            .set_changed(Some(&["this", "that"].to_vec()))
            .set_instance_id("xmp.iid:cb9f5498-bb58-4572-8043-8c369e6bfb9b")
            .set_actors(Some(
                &[Actor::new(
                    Some("Somebody"),
                    Some(&[make_hashed_uri1()].to_vec()),
                )]
                .to_vec(),
            ))
    }

    #[test]
    fn assertion_actions() {
        let mut original = Actions::new();
        original
            .add_action(make_action1())
            .add_action(
                Action::new("c2pa.filtered")
                    .set_parameter("name".to_owned(), &"gaussian blur")
                    .unwrap()
                    .set_when("2015-06-26T16:43:23+0200"),
            )
            .add_metadata(
                Metadata::new()
                    .add_review(ReviewRating::new("foo", Some("bar".to_owned()), 3))
                    .set_reference(Some(make_hashed_uri1()))
                    .set_data_source(Some(DataSource::new(C2PA_SOURCE_GENERATOR_REE))),
            );

        dbg!(&original);
        assert_eq!(original.actions.len(), 2);
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), Actions::LABEL);

        let result = Actions::from_assertion(&assertion).expect("extract_assertion");
        assert_eq!(result.actions.len(), 2);
        assert_eq!(result.actions[0].label, original.actions[0].label);
        assert_eq!(
            result.actions[0].parameters.as_ref().unwrap().get("name"),
            original.actions[0].parameters.as_ref().unwrap().get("name")
        );
        assert_eq!(result.actions[1].label, original.actions[1].label);
        assert_eq!(
            result.actions[1].parameters.as_ref().unwrap().get("name"),
            original.actions[1].parameters.as_ref().unwrap().get("name")
        );
        assert_eq!(result.actions[1].when, original.actions[1].when);
        assert_eq!(
            result.metadata.unwrap().date_time,
            original.metadata.unwrap().date_time
        );
    }

    #[test]
    fn test_build_assertion() {
        let assertion = Actions::new()
            .add_action(
                Action::new("c2pa.cropped")
                    .set_parameter(
                        "coordinate".to_owned(),
                        r#"{
                        "left": 0,
                        "right": 2000,
                        "top": 1000,
                        "bottom": 4000
                    }"#,
                    )
                    .unwrap(),
            )
            .add_action(
                Action::new("c2pa.filtered")
                    .set_parameter("name".to_owned(), "gaussian blur")
                    .unwrap()
                    .set_when("2015-06-26T16:43:23+0200"),
            )
            .to_assertion()
            .unwrap();

        println!("assertion label: {}", assertion.label());

        let j = assertion.data();
        //println!("assertion as json {:#?}", j);

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
        let assertion = Actions::new()
            // .set_dictionary("http://testdictionary")
            .add_action(
                Action::new("c2pa.cropped")
                    .set_parameter(
                        "name".to_owned(),
                        r#"{
                        "left": 0,
                        "right": 2000,
                        "top": 1000,
                        "bottom": 4000
                    }"#,
                    )
                    .unwrap(),
            )
            .add_action(
                Action::new("c2pa.filtered")
                    .set_parameter("name".to_owned(), "gaussian blur")
                    .unwrap()
                    .set_when("2015-06-26T16:43:23+0200"),
            )
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
    fn test_json_round_trip() {
        let json = serde_json::json!({
            "actions": [
                  {
                    "action": "c2pa.edited",
                    "parameters": {
                      "description": "gradient",
                      "name": "any value"
                    }
                  },
                  {
                    "action": "c2pa.edited",
                    "parameters": {
                      "description": "import"
                    }
                  },
                ],
            "metadata": {
                "mytag": "myvalue"
            }
        });
        let original = Actions::from_json_value(&json).expect("from json");
        let assertion = original.to_assertion().expect("build_assertion");
        let result = Actions::from_assertion(&assertion).expect("extract_assertion");
        println!("{:?}", serde_json::to_string(&result));
        assert_eq!(original.actions, result.actions);
    }
}
