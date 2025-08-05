// Copyright 2025 Adobe. All rights reserved.
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

use std::{collections::HashMap, env::consts};

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    assertions::{
        region_of_interest::RegionOfInterest, Action, ActionTemplate, Actions, Actor,
        AssertionMetadata, AssetType, SoftwareAgent,
    },
    builder::AssertionDefinition,
    cbor_types::DateT,
    claim::Claim,
    resolver::{Resolver, ResourceResolver},
    ClaimGeneratorInfo, HashedUri, Ingredient, ResourceRef, Result, SigningAlg,
};

// TODO: does these fields (besides id) need to be specified at the manifest level or the resolver level?
//       the resolver is responsible for inheriting these properties anyways
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ResourceDefinition {
    pub identifier: String,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_types: Option<Vec<AssetType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<SigningAlg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl ResourceDefinition {
    pub fn resolve<T: Resolver>(self, resolver: &T, claim: &mut Claim) -> Result<HashedUri> {
        // TODO: handle
        #[allow(clippy::unwrap_used)]
        let resource = resolver.resolve(self).unwrap();
        resolver.resource_resolve(claim, resource)
    }
}

/// Settings for how to specify the claim generator info's operating system.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ClaimGeneratorInfoOSDefinition {
    /// Whether or not to infer the operating system.
    pub infer: bool,
    /// The name of the operating system.
    ///
    /// Note this field overrides [ClaimGeneratorInfoOSSettings::infer].
    pub name: Option<String>,
}

impl Default for ClaimGeneratorInfoOSDefinition {
    fn default() -> Self {
        Self {
            infer: true,
            name: None,
        }
    }
}

/// Settings for the claim generator info.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ClaimGeneratorInfoDefinition {
    /// A human readable string naming the claim_generator.
    pub name: String,
    /// A human readable string of the product's version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Reference to an icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<ResourceDefinition>,
    /// Settings for the claim generator info's operating system field.
    #[serde(alias = "operatingSystem")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<ClaimGeneratorInfoOSDefinition>,
    /// Any other values that are not part of the standard.
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

impl ClaimGeneratorInfoDefinition {
    pub fn resolve<T: Resolver>(
        self,
        resolver: &T,
        claim: &mut Claim,
    ) -> Result<ClaimGeneratorInfo> {
        Ok(ClaimGeneratorInfo {
            name: self.name,
            version: self.version,
            icon: self
                .icon
                .map(|icon| icon.resolve(resolver, claim))
                .transpose()?,
            operating_system: {
                let os = self.operating_system.unwrap_or_default();
                match os.infer {
                    true => Some(consts::OS.to_owned()),
                    false => os.name,
                }
            },
            other: self.other,
        })
    }
}

impl Default for ClaimGeneratorInfoDefinition {
    fn default() -> Self {
        Self {
            name: crate::NAME.to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            icon: None,
            operating_system: None,
            other: HashMap::new(),
        }
    }
}

/// Settings for an action template.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ActionTemplateDefinition {
    /// The label associated with this action. See ([c2pa_action][crate::assertions::actions::c2pa_action]).
    pub action: String,
    /// The software agent that performed the action.
    #[serde(alias = "softwareAgent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<ClaimGeneratorInfoDefinition>,
    // TODO: change this to use string names and document in c2pa.toml
    /// 0-based index into the softwareAgents array
    #[serde(alias = "softwareAgentIndex")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent_index: Option<usize>,
    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`
    #[serde(alias = "digitalSourceType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    /// Reference to an icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<ResourceDefinition>,
    /// Description of the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Additional parameters for the template
    #[serde(alias = "templateParameters")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_parameters: Option<HashMap<String, serde_json::Value>>,
}

impl ActionTemplateDefinition {
    pub fn resolve<T: Resolver>(self, resolver: &T, claim: &mut Claim) -> Result<ActionTemplate> {
        Ok(ActionTemplate {
            action: self.action,
            software_agent: self
                .software_agent
                .map(|software_agent| software_agent.resolve(resolver, claim))
                .transpose()?,
            software_agent_index: self.software_agent_index,
            source_type: self.source_type,
            icon: self
                .icon
                .map(|icon| icon.resolve(resolver, claim))
                .transpose()?,
            description: self.description,
            template_parameters: self
                .template_parameters
                .map(|template_parameters| {
                    template_parameters
                        .into_iter()
                        .map(|(key, value)| {
                            serde_cbor::value::to_value(value)
                                .map(|value| (key, value))
                                .map_err(|err| err.into())
                        })
                        .collect::<Result<HashMap<String, serde_cbor::Value>>>()
                })
                .transpose()?,
        })
    }
}

/// Settings for an action.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ActionDefinition {
    /// The label associated with this action. See ([`c2pa_action`]).
    pub action: String,
    /// Timestamp of when the action occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<DateT>,
    /// The software agent that performed the action.
    #[serde(alias = "softwareAgent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<ClaimGeneratorInfoDefinition>,
    // TODO: this can be abstracted
    /// 0-based index into the softwareAgents array.
    #[serde(alias = "softwareAgentIndex")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent_index: Option<usize>,
    /// A semicolon-delimited list of the parts of the resource that were changed since the previous event history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<String>,
    /// A list of the regions of interest of the resource that were changed.
    ///
    /// If not present, presumed to be undefined.
    /// When tracking changes and the scope of the changed components is unknown,
    /// it should be assumed that anything might have changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<Vec<RegionOfInterest>>,
    // TODO: is deprecated, do we still read it? validate it?
    /// This is NOT the instanceID in the spec.
    /// It is now deprecated but was previously used to map the action to an ingredient.
    #[serde(alias = "instanceID")]
    #[serde(skip_serializing)]
    pub instance_id: Option<String>,
    /// Additional parameters of the action. These vary by the type of action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, serde_json::Value>>,
    /// An array of the creators that undertook this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actors: Option<Vec<Actor>>,
    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`.
    #[serde(alias = "digitalSourceType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    /// List of related actions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related: Option<Vec<ActionDefinition>>,
    // The reason why this action was performed, required when the action is `c2pa.redacted`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Description of the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ActionDefinition {
    pub fn resolve<T: Resolver>(self, resolver: &T, claim: &mut Claim) -> Result<Action> {
        Ok(Action {
            action: self.action,
            when: self.when,
            software_agent: self
                .software_agent
                .map(|software_agent| software_agent.resolve(resolver, claim))
                .transpose()?
                .map(SoftwareAgent::ClaimGeneratorInfo),
            software_agent_index: self.software_agent_index,
            changed: self.changed,
            changes: self.changes,
            #[allow(deprecated)]
            instance_id: self.instance_id,
            parameters: self
                .parameters
                .map(|template_parameters| {
                    template_parameters
                        .into_iter()
                        .map(|(key, value)| {
                            serde_cbor::value::to_value(value)
                                .map(|value| (key, value))
                                .map_err(|err| err.into())
                        })
                        .collect::<Result<HashMap<String, serde_cbor::Value>>>()
                })
                .transpose()?,
            actors: self.actors,
            source_type: self.source_type,
            related: self
                .related
                .map(|related| {
                    related
                        .into_iter()
                        .map(|action| action.resolve(resolver, claim))
                        .collect()
                })
                .transpose()?,
            reason: self.reason,
            description: self.description,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ActionsDefinition {
    /// A list of [`Action`]s.
    pub actions: Vec<ActionDefinition>,
    /// A list of of the software/hardware that did the action.
    #[serde(alias = "softwareAgents")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agents: Option<Vec<ClaimGeneratorInfoDefinition>>,
    /// If present & true, indicates that no actions took place that were not included in the actions list.
    #[serde(alias = "allActionsIncluded")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_actions_included: Option<bool>,
    /// list of templates for the [`Action`]s
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<ActionTemplateDefinition>>,
    /// Additional information about the assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AssertionMetadata>,
}

impl ActionsDefinition {
    pub fn resolve<T: Resolver>(self, resolver: &T, claim: &mut Claim) -> Result<Actions> {
        Ok(Actions {
            actions: self
                .actions
                .into_iter()
                .map(|action| action.resolve(resolver, claim))
                .collect::<Result<Vec<Action>>>()?,
            software_agents: self
                .software_agents
                .map(|software_agents| {
                    software_agents
                        .into_iter()
                        .map(|software_agent| software_agent.resolve(resolver, claim))
                        .collect::<Result<Vec<ClaimGeneratorInfo>>>()
                })
                .transpose()?,
            all_actions_included: self.all_actions_included,
            templates: self
                .templates
                .map(|templates| {
                    templates
                        .into_iter()
                        .map(|template| template.resolve(resolver, claim))
                        .collect::<Result<Vec<ActionTemplate>>>()
                })
                .transpose()?,
            metadata: self.metadata,
        })
    }
}

/// Use a ManifestDefinition to define a manifest and to build a `ManifestStore`.
/// A manifest is a collection of ingredients and assertions
/// used to define a claim that can be signed and embedded into a file.
#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ManifestDefinition {
    /// The version of the claim.  Defaults to 1.
    #[serde(alias = "claimVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_version: Option<u8>,

    /// Optional prefix added to the generated Manifest Label
    /// This is typically a reverse domain name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    /// Claim Generator Info is always required with at least one entry
    #[serde(alias = "claimGeneratorInfo")]
    #[serde(default = "default_claim_generator_info")]
    pub claim_generator_info: Vec<ClaimGeneratorInfoDefinition>,

    /// Optional manifest metadata. This will be deprecated in the future; not recommended to use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Vec<AssertionMetadata>>,

    /// A human-readable title, generally source filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// The format of the source file as a MIME type.
    #[serde(default = "default_format")]
    pub format: String,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata.
    #[serde(alias = "instanceID")]
    #[serde(default = "default_instance_id")]
    pub instance_id: String,

    /// An optional ResourceRef to a thumbnail image that represents the asset that was signed.
    /// Must be available when the manifest is signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<ResourceRef>,

    /// A List of ingredients
    #[serde(default = "default_vec::<Ingredient>")]
    pub ingredients: Vec<Ingredient>,

    /// A list of assertions
    #[serde(default = "default_vec::<AssertionDefinition>")]
    pub assertions: Vec<AssertionDefinition>,

    /// A list of redactions - URIs to redacted assertions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redactions: Option<Vec<String>>,

    /// Allows you to pre-define the manifest label, which must be unique.
    /// Not intended for general use.  If not set, it will be assigned automatically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

fn default_instance_id() -> String {
    format!("xmp:iid:{}", Uuid::new_v4())
}

fn default_claim_generator_info() -> Vec<ClaimGeneratorInfoDefinition> {
    [ClaimGeneratorInfoDefinition::default()].to_vec()
}

fn default_format() -> String {
    "application/octet-stream".to_owned()
}

fn default_vec<T>() -> Vec<T> {
    Vec::new()
}

impl ManifestDefinition {
    pub fn resolve<T: Resolver>(self, resolver: &T, claim: &mut Claim) -> Result<()> {
        // TODO: it would make sense if we can call def.resolve() and it handles all the adding to claim and return a Manifest?
        todo!()
    }
}
