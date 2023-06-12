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

use serde::{Deserialize, Serialize};
use serde_cbor::Value;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{labels, Actor, Metadata},
    error::Result,
    resource_store::UriOrResource,
    utils::cbor_types::DateT,
    ClaimGeneratorInfo,
};

const ASSERTION_CREATION_VERSION: usize = 2;

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

/// We use this to allow SourceAgent to be either a string or a ClaimGeneratorInfo
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum SoftwareAgent {
    String(String),
    ClaimGeneratorInfo(ClaimGeneratorInfo),
}

impl From<&str> for SoftwareAgent {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<ClaimGeneratorInfo> for SoftwareAgent {
    fn from(c: ClaimGeneratorInfo) -> Self {
        Self::ClaimGeneratorInfo(c)
    }
}

/// Defines a single action taken on an asset.
///
/// An [`Action`] describes what took place on the asset, when it took place,
/// along with possible other information such as what software performed
/// the action.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_actions>.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Action {
    /// The label associated with this action. See ([`c2pa_action`]).
    action: String,

    /// Timestamp of when the action occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    when: Option<DateT>,

    /// The software agent that performed the action.
    #[serde(rename = "softwareAgent", skip_serializing_if = "Option::is_none")]
    software_agent: Option<SoftwareAgent>,

    /// A semicolon-delimited list of the parts of the resource that were changed since the previous event history.
    ///
    /// If not present, presumed to be undefined.
    /// When tracking changes and the scope of the changed components is unknown,
    /// it should be assumed that anything might have changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    changed: Option<String>,

    /// The value of the `xmpMM:InstanceID` property for the modified (output) resource.
    #[serde(rename = "instanceId", skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,

    /// Additional parameters of the action. These vary by the type of action.
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<HashMap<String, Value>>,

    /// An array of the creators that undertook this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    actors: Option<Vec<Actor>>,

    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`
    #[serde(rename = "digitalSourceType", skip_serializing_if = "Option::is_none")]
    source_type: Option<String>,

    /// List of related actions.
    #[serde(skip_serializing_if = "Option::is_none")]
    related: Option<Vec<Action>>,

    // The reason why this action was performed, required when the action is `c2pa.redacted`
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl Action {
    /// Create a new action with a specific action label.
    ///
    /// This label is often one of the labels defined in [`c2pa_action`],
    /// but can also be a custom string in reverse-domain format.
    pub fn new(label: &str) -> Self {
        Self {
            action: label.to_owned(),
            ..Default::default()
        }
    }

    fn is_v2(&self) -> bool {
        matches!(
            self.software_agent,
            Some(SoftwareAgent::ClaimGeneratorInfo(_))
        )
    }

    /// Returns the label for this action.
    ///
    /// This label is often one of the labels defined in [`c2pa_action`],
    /// but can also be a custom string in reverse-domain format.
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Returns the timestamp of when the action occurred.
    ///
    /// This string, if present, will be in ISO-8601 date format.
    pub fn when(&self) -> Option<&str> {
        self.when.as_deref()
    }

    /// Returns the software agent that performed the action.
    pub fn software_agent(&self) -> Option<&SoftwareAgent> {
        self.software_agent.as_ref()
    }

    /// Returns a mutable software agent that performed the action.
    pub fn software_agent_mut(&mut self) -> Option<&mut SoftwareAgent> {
        self.software_agent.as_mut()
    }

    /// Returns the value of the `xmpMM:InstanceID` property for the modified
    /// (output) resource.
    pub fn instance_id(&self) -> Option<&str> {
        self.instance_id.as_deref()
    }

    /// Returns the additional parameters for this action.
    ///
    /// These vary by the type of action.
    pub fn parameters(&self) -> Option<&HashMap<String, Value>> {
        self.parameters.as_ref()
    }

    /// Returns an individual action parameter if it exists.
    pub fn get_parameter(&self, key: &str) -> Option<&Value> {
        match self.parameters.as_ref() {
            Some(parameters) => parameters.get(key),
            None => None,
        }
    }

    /// An array of the [`Actor`]s that undertook this action.
    pub fn actors(&self) -> Option<&[Actor]> {
        self.actors.as_deref()
    }

    /// Returns a digitalSourceType as defined at <https://cv.iptc.org/newscodes/digitalsourcetype/>.
    pub fn source_type(&self) -> Option<&str> {
        self.source_type.as_deref()
    }

    /// Returns the list of related actions.
    ///
    /// This is only present in C2PA v2.
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_related>.
    pub fn related(&self) -> Option<&[Action]> {
        self.related.as_deref()
    }

    /// Returns the reason why this action was performed.
    ///
    /// This is only present in C2PA v2.
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_reason>.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Sets the timestamp for when the action occurred.
    ///
    /// This timestamp must be in ISO-8601 date.
    pub fn set_when<S: Into<String>>(mut self, when: S) -> Self {
        self.when = Some(DateT(when.into()));
        self
    }

    /// Sets the software agent that performed the action.
    pub fn set_software_agent<S: Into<SoftwareAgent>>(mut self, software_agent: S) -> Self {
        self.software_agent = Some(software_agent.into());
        self
    }

    /// Sets the list of the parts of the resource that were changed
    /// since the previous event history.
    pub fn set_changed(mut self, changed: Option<&Vec<&str>>) -> Self {
        self.changed = changed.map(|v| v.join(";"));
        self
    }

    /// Sets the value of the `xmpMM:InstanceID` property for the
    /// modified (output) resource.
    pub fn set_instance_id<S: Into<String>>(mut self, id: S) -> Self {
        self.instance_id = Some(id.into());
        self
    }

    /// Sets the additional parameters for this action.
    ///
    /// These vary by the type of action.
    pub fn set_parameter<S: Into<String>, T: Serialize>(
        mut self,
        key: S,
        value: T,
    ) -> Result<Self> {
        let value_bytes = serde_cbor::ser::to_vec(&value)?;
        let value = serde_cbor::from_slice(&value_bytes)?;

        self.parameters = Some(match self.parameters {
            Some(mut parameters) => {
                parameters.insert(key.into(), value);
                parameters
            }
            None => {
                let mut p = HashMap::new();
                p.insert(key.into(), value);
                p
            }
        });
        Ok(self)
    }

    /// Sets the array of [`Actor`]s that undertook this action.
    pub fn set_actors(mut self, actors: Option<&Vec<Actor>>) -> Self {
        self.actors = actors.cloned();
        self
    }

    /// Set a digitalSourceType URI as defined at <https://cv.iptc.org/newscodes/digitalsourcetype/>.
    pub fn set_source_type<S: Into<String>>(mut self, uri: S) -> Self {
        self.source_type = Some(uri.into());
        self
    }

    /// Sets the list of related actions.
    ///
    /// This is only present in C2PA v2.
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_related>.
    pub fn set_related(mut self, related: Option<&Vec<Action>>) -> Self {
        self.related = related.cloned();
        self
    }

    /// Sets the reason why this action was performed.
    ///
    /// This is only present in C2PA v2.
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_reason>.
    pub fn set_reason<S: Into<String>>(mut self, reason: S) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

#[derive(Deserialize, Serialize, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ActionTemplate {
    /// The label associated with this action. See ([`c2pa_action`]).
    pub action: String,

    /// The software agent that performed the action.
    #[serde(rename = "softwareAgent", skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<SoftwareAgent>,

    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`
    #[serde(rename = "digitalSourceType", skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<UriOrResource>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, Value>>,
}

impl ActionTemplate {
    /// Creates a new ActionTemplate.
    pub fn new<S: Into<String>>(action: S) -> Self {
        Self {
            action: action.into(),
            ..Default::default()
        }
    }
}

/// An `Actions` assertion provides information on edits and other
/// actions taken that affect the asset’s content.
///
/// This assertion contains a list of [`Action`], each one declaring
/// what took place on the asset, when it took place, along with possible
/// other information such as what software performed the action.
///
/// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_actions>.
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Actions {
    /// A list of [`Action`]s.
    pub actions: Vec<Action>,

    /// list of templates for the [`Action`]s
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<ActionTemplate>>,

    /// Additional information about the assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

impl Actions {
    /// Label prefix for an [`Actions`] assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_actions>.
    pub const LABEL: &'static str = labels::ACTIONS;

    /// Creates a new [`Actions`] assertion struct.
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            templates: None,
            metadata: None,
        }
    }

    /// determines if actions is V2
    fn is_v2(&self) -> bool {
        if self.templates.is_some() {
            return true;
        };
        self.actions.iter().any(|a| a.is_v2())
    }

    /// Returns the list of [`Action`]s.
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// Returns mutable list of [`Action`]s.
    pub fn actions_mut(&mut self) -> &mut [Action] {
        &mut self.actions
    }

    /// Returns the assertion's [`Metadata`], if it exists.
    pub fn metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }

    /// Internal method to update actions to meet spec requirements
    pub(crate) fn update_action(mut self, index: usize, action: Action) -> Self {
        self.actions[index] = action;
        self
    }

    /// Adds an [`Action`] to this assertion's list of actions.
    pub fn add_action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    /// Sets [`Metadata`] for the action.
    pub fn add_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Creates a CBOR [`Actions`] assertion from a compatible JSON value.
    pub fn from_json_value(json: &serde_json::Value) -> Result<Self> {
        let buf: Vec<u8> = Vec::new();
        let json_str = json.to_string();
        let mut from = serde_json::Deserializer::from_str(&json_str);
        let mut to = serde_cbor::Serializer::new(buf);

        serde_transcode::transcode(&mut from, &mut to)?;
        let buf2 = to.into_inner();

        let actions: Actions = serde_cbor::from_slice(&buf2)?;
        Ok(actions)
    }
}

impl AssertionCbor for Actions {}

impl AssertionBase for Actions {
    const LABEL: &'static str = labels::ACTIONS;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    /// if we require v2 fields then use V2
    fn version(&self) -> Option<usize> {
        if self.is_v2() {
            Some(2)
        } else {
            Some(1)
        }
    }

    /// if we require v2 fields then use V2
    fn label(&self) -> &str {
        if self.is_v2() {
            "c2pa.actions.v2"
        } else {
            labels::ACTIONS
        }
    }

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
    use crate::{
        assertion::{Assertion, AssertionData},
        assertions::metadata::{c2pa_source::GENERATOR_REE, DataSource, ReviewRating},
        hashed_uri::HashedUri,
    };

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
                r#"{
                "left": 0,
                "right": 2000,
                "top": 1000,
                "bottom": 4000
            }"#
                .to_owned(),
            )
            .unwrap()
            .set_parameter("ingredient".to_owned(), make_hashed_uri1())
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
        let original = Actions::new()
            .add_action(make_action1())
            .add_action(
                Action::new("c2pa.filtered")
                    .set_parameter("name".to_owned(), "gaussian blur")
                    .unwrap()
                    .set_when("2015-06-26T16:43:23+0200")
                    .set_source_type("digsrctype:algorithmicMedia"),
            )
            .add_metadata(
                Metadata::new()
                    .add_review(ReviewRating::new("foo", Some("bar".to_owned()), 3))
                    .set_reference(make_hashed_uri1())
                    .set_data_source(DataSource::new(GENERATOR_REE)),
            );

        assert_eq!(original.actions.len(), 2);
        let assertion = original.to_assertion().expect("build_assertion");
        assert_eq!(assertion.mime_type(), "application/cbor");
        assert_eq!(assertion.label(), Actions::LABEL);

        let result = Actions::from_assertion(&assertion).expect("extract_assertion");
        assert_eq!(result.actions.len(), 2);
        assert_eq!(result.actions[0].action(), original.actions[0].action());
        assert_eq!(
            result.actions[0].parameters().unwrap().get("name"),
            original.actions[0].parameters().unwrap().get("name")
        );
        assert_eq!(result.actions[1].action(), original.actions[1].action());
        assert_eq!(
            result.actions[1].parameters.as_ref().unwrap().get("name"),
            original.actions[1].parameters.as_ref().unwrap().get("name")
        );
        assert_eq!(result.actions[1].when(), original.actions[1].when());
        assert_eq!(
            result.actions[1].source_type().unwrap(),
            "digsrctype:algorithmicMedia"
        );
        assert_eq!(
            result.metadata.unwrap().date_time(),
            original.metadata.unwrap().date_time()
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
                    },
                    "softwareAgent": "TestApp"
                  },
                  {
                    "action": "c2pa.opened",
                    "instanceId": "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
                    "parameters": {
                      "description": "import"
                    },
                    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia",
                    "softwareAgent": "TestApp 1.0",
                  },
                ],
            "metadata": {
                "mytag": "myvalue"
            }
        });
        let original = Actions::from_json_value(&json).expect("from json");
        let assertion = original.to_assertion().expect("build_assertion");
        let result = Actions::from_assertion(&assertion).expect("extract_assertion");
        assert_eq!(result.label(), labels::ACTIONS);
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        assert_eq!(original.actions, result.actions);
        assert_eq!(
            result.actions[0].software_agent().unwrap(),
            &SoftwareAgent::String("TestApp".to_string())
        );
    }

    #[test]
    fn test_json_v2_round_trip() {
        let json = serde_json::json!({
            "actions": [
                  {
                    "action": "c2pa.edited",
                    "parameters": {
                      "description": "gradient",
                      "name": "any value"
                    },
                    "softwareAgent": "TestApp"
                  },
                  {
                    "action": "c2pa.opened",
                    "instanceId": "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
                    "parameters": {
                      "description": "import"
                    },
                    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia",
                    "softwareAgent": {
                        "name": "TestApp",
                        "version": "1.0",
                        "something": "else"
                    },
                  },
                  {
                    "action": "com.joesphoto.filter",
                  }
            ],
            "templates": [
                {
                    "action": "com.joesphoto.filter",
                    "description": "Magic Filter",
                    "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/compositeSynthetic",
                    "softwareAgent" : {
                        "name": "Joe's Photo Editor",
                        "version": "2.0",
                        "schema.org.SoftwareApplication.operatingSystem": "Windows 10"
                    }
                }
            ],
            "metadata": {
                "mytag": "myvalue"
            }
        });
        let original = Actions::from_json_value(&json).expect("from json");
        let assertion = original.to_assertion().expect("build_assertion");
        let result = Actions::from_assertion(&assertion).expect("extract_assertion");
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        assert_eq!(result.label(), "c2pa.actions.v2");
        assert_eq!(original.actions, result.actions);
        assert_eq!(original.templates, result.templates);
        assert_eq!(
            result.actions[0].software_agent().unwrap(),
            &SoftwareAgent::String("TestApp".to_string())
        );
    }
}
