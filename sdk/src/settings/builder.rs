// Copyright 2024 Adobe. All rights reserved.
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

use serde::{Deserialize, Serialize};

use crate::{
    assertions::{
        region_of_interest::RegionOfInterest, Action, ActionTemplate, Actor, SoftwareAgent,
    },
    cbor_types::DateT,
    resource_store::UriOrResource,
    settings::SettingsValidate,
    ClaimGeneratorInfo, Error, ResourceRef, Result,
};

// TODO: thumbnails/previews for audio?
/// Possible output types for automatic thumbnail generation.
///
/// These formats are a combination of types supported in [image-rs](https://docs.rs/image/latest/image/enum.ImageFormat.html)
/// and types defined by the [IANA registry media type](https://www.iana.org/assignments/media-types/media-types.xhtml) (as defined in the spec).
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ThumbnailFormat {
    /// An image in PNG format.
    Png,
    /// An image in JPEG format.
    Jpeg,
    /// An image in GIF format.
    Gif,
    /// An image in WEBP format.
    WebP,
    /// An image in TIFF format.
    Tiff,
}
/// Quality of the thumbnail.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ThumbnailQuality {
    /// Low quality.
    Low,
    /// Medium quality.
    Medium,
    /// High quality.
    High,
}

/// Settings for controlling automatic thumbnail generation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ThumbnailSettings {
    /// Whether or not to automatically generate thumbnails.
    pub enabled: bool,
    /// Whether to ignore thumbnail generation errors.
    ///
    /// This may occur, for instance, if the thumbnail media type or color layout isn't
    /// supported.
    pub ignore_errors: bool,
    /// The size of the longest edge of the thumbnail.
    ///
    /// This function will resize the input to preserve aspect ratio.
    pub long_edge: u32,
    /// Format of the thumbnail.
    ///
    /// If this field isn't specified, the thumbnail format will correspond to the
    /// input format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<ThumbnailFormat>,
    /// Whether or not to prefer a smaller sized media format for the thumbnail.
    ///
    /// Note that [ThumbnailSettings::format] takes precedence over this field. In addition,
    /// if the output format is unsupported, it will default to the smallest format regardless
    /// of the value of this field.
    ///
    /// For instance, if the source input type is a PNG, but it doesn't have an alpha channel,
    /// the image will be converted to a JPEG of smaller size.
    pub prefer_smallest_format: bool,
    /// The output quality of the thumbnail.
    ///
    /// This setting contains sensible defaults for things like quality, compression, and
    /// algorithms for various formats.
    pub quality: ThumbnailQuality,
}

impl Default for ThumbnailSettings {
    fn default() -> Self {
        ThumbnailSettings {
            enabled: true,
            ignore_errors: true,
            long_edge: 1024,
            format: None,
            prefer_smallest_format: true,
            quality: ThumbnailQuality::Medium,
        }
    }
}

impl SettingsValidate for ThumbnailSettings {
    fn validate(&self) -> Result<()> {
        #[cfg(not(feature = "add_thumbnails"))]
        if self.enabled {
            log::warn!("c2pa-rs feature `add_thumbnails` must be enabled to generate thumbnails!");
        }

        Ok(())
    }
}

/// Settings for the auto actions (e.g. created, opened, placed).
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct AutoActionSettings {
    /// Whether to enable this auto action or not.
    pub enabled: bool,
    // TODO: enum
    /// The default source type for the auto action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
}

/// Settings for how to specify the claim generator info's operating system.
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ClaimGeneratorInfoOSSettings {
    /// Whether or not to infer the operating system.
    pub infer: bool,
    /// The name of the operating system.
    ///
    /// Note this field overrides [ClaimGeneratorInfoOSSettings::infer].
    pub name: Option<String>,
}

impl Default for ClaimGeneratorInfoOSSettings {
    fn default() -> Self {
        Self {
            infer: true,
            name: None,
        }
    }
}

/// Settings for the claim generator info.
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ClaimGeneratorInfoSettings {
    /// A human readable string naming the claim_generator.
    pub name: String,
    /// A human readable string of the product's version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Hashed URI to the icon (either embedded or remote).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<UriOrResource>,
    /// Settings for the claim generator info's operating system field.
    pub operating_system: ClaimGeneratorInfoOSSettings,
    /// Any other values that are not part of the standard.
    #[serde(flatten)]
    pub other: HashMap<String, toml::Value>,
}

impl TryFrom<ClaimGeneratorInfoSettings> for ClaimGeneratorInfo {
    type Error = Error;

    fn try_from(value: ClaimGeneratorInfoSettings) -> Result<Self> {
        Ok(ClaimGeneratorInfo {
            name: value.name,
            version: value.version,
            icon: value.icon,
            operating_system: match value.operating_system.infer {
                true => Some(consts::OS.to_owned()),
                false => value.operating_system.name,
            },
            other: value
                .other
                .into_iter()
                .map(|(key, value)| {
                    serde_json::to_value(value)
                        .map(|value| (key, value))
                        .map_err(|err| err.into())
                })
                .collect::<Result<HashMap<String, serde_json::Value>>>()?,
        })
    }
}

/// Settings for an action template.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ActionTemplateSettings {
    /// The label associated with this action. See ([c2pa_action][crate::assertions::actions::c2pa_action]).
    pub action: String,
    /// The software agent that performed the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<ClaimGeneratorInfoSettings>,
    // TODO: change this to use names
    /// 0-based index into the softwareAgents array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent_index: Option<usize>,
    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    // TODO: handle paths/urls
    /// Reference to an icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<ResourceRef>,
    /// Description of the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Additional parameters for the template
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_parameters: Option<HashMap<String, toml::Value>>,
}

impl TryFrom<ActionTemplateSettings> for ActionTemplate {
    type Error = Error;

    fn try_from(value: ActionTemplateSettings) -> Result<Self> {
        Ok(ActionTemplate {
            action: value.action,
            software_agent: value
                .software_agent
                .map(|software_agent| software_agent.try_into())
                .transpose()?,
            software_agent_index: value.software_agent_index,
            source_type: value.source_type,
            icon: value.icon.map(UriOrResource::ResourceRef),
            description: value.description,
            template_parameters: value
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
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ActionSettings {
    /// The label associated with this action. See ([`c2pa_action`]).
    pub action: String,
    /// Timestamp of when the action occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<DateT>,
    /// The software agent that performed the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<ClaimGeneratorInfoSettings>,
    /// 0-based index into the softwareAgents array.
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
    /// This is NOT the instanceID in the spec.
    /// It is now deprecated but was previously used to map the action to an ingredient.
    #[deprecated(since = "0.37.0", note = "Use `org.cai.ingredientIds` instead")]
    #[serde(skip_serializing)]
    pub instance_id: Option<String>,
    /// Additional parameters of the action. These vary by the type of action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<HashMap<String, toml::Value>>,
    /// An array of the creators that undertook this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actors: Option<Vec<Actor>>,
    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    /// List of related actions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related: Option<Vec<Action>>,
    // The reason why this action was performed, required when the action is `c2pa.redacted`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Description of the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl TryFrom<ActionSettings> for Action {
    type Error = Error;

    fn try_from(value: ActionSettings) -> Result<Self> {
        Ok(Action {
            action: value.action,
            when: value.when,
            software_agent: value
                .software_agent
                .map(|software_agent| software_agent.try_into())
                .transpose()?
                .map(SoftwareAgent::ClaimGeneratorInfo),
            software_agent_index: value.software_agent_index,
            changed: value.changed,
            changes: value.changes,
            #[allow(deprecated)]
            instance_id: value.instance_id,
            parameters: value
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
            actors: value.actors,
            source_type: value.source_type,
            related: value.related,
            reason: value.reason,
            description: value.description,
        })
    }
}

/// Settings for configuring the "base" [Actions][crate::assertions::Actions] assertion.
///
/// The reason this setting exists only for an [Actions][crate::assertions::Actions] assertion
/// is because of its mandations and reusable fields.
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ActionsSettings {
    /// Whether or not to set the [Actions::all_actions_included][crate::assertions::Actions::all_actions_included]
    /// field.
    pub all_actions_included: bool,
    /// Templates to be added to the [Actions::templates][crate::assertions::Actions::templates] field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templates: Option<Vec<ActionTemplateSettings>>,
    // TODO: should we define a new struct for "Action" too, like ActionTemplateSettings?
    /// Actions to be added to the [Actions::actions][crate::assertions::Actions::actions] field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ActionSettings>>,
    /// Whether to automatically generate a c2pa.created [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.created action assertion, see here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion>
    pub auto_created_action: AutoActionSettings,
    /// Whether to automatically generate a c2pa.opened [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.opened action assertion, see here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion>
    pub auto_opened_action: AutoActionSettings,
    /// Whether to automatically generate a c2pa.placed [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.placed action assertion, see:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_relationship>
    pub auto_placed_action: AutoActionSettings,
}

impl Default for ActionsSettings {
    fn default() -> Self {
        ActionsSettings {
            all_actions_included: true,
            templates: None,
            actions: None,
            auto_created_action: AutoActionSettings {
                enabled: false,
                source_type: None,
            },
            auto_opened_action: AutoActionSettings {
                enabled: true,
                source_type: None,
            },
            auto_placed_action: AutoActionSettings {
                enabled: true,
                source_type: None,
            },
        }
    }
}

impl SettingsValidate for ActionsSettings {
    fn validate(&self) -> Result<()> {
        match self.auto_created_action.enabled && self.auto_created_action.source_type.is_none() {
            true => Err(Error::MissingAutoCreatedActionSourceType),
            false => Ok(()),
        }
    }
}

/// Settings for the [Builder][crate::Builder].
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Default)]
pub(crate) struct BuilderSettings {
    /// Claim generator info that is automatically added to the builder.
    ///
    /// Note that this information will prepend any claim generator info
    /// provided explicitly to the builder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator_info: Option<ClaimGeneratorInfo>,
    /// Various settings for configuring automatic thumbnail generation.
    pub thumbnail: ThumbnailSettings,
    /// Settings for configuring fields in an [Actions][crate::assertions::Actions] assertion.
    ///
    /// For more information on the reasoning behind this field see [ActionsSettings].
    pub actions: ActionsSettings,
}

impl SettingsValidate for BuilderSettings {
    fn validate(&self) -> Result<()> {
        self.actions.validate()?;
        self.thumbnail.validate()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::source_type;

    #[test]
    fn test_auto_created_action_without_source_type() {
        let actions_settings = ActionsSettings {
            auto_created_action: AutoActionSettings {
                enabled: true,
                source_type: None,
            },
            ..Default::default()
        };

        assert!(actions_settings.validate().is_err());
    }

    #[test]
    fn test_auto_created_action_with_source_type() {
        let actions_settings = ActionsSettings {
            auto_created_action: AutoActionSettings {
                enabled: true,
                source_type: Some(source_type::EMPTY.to_owned()),
            },
            ..Default::default()
        };

        assert!(actions_settings.validate().is_ok());
    }
}
