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

use serde::{Deserialize, Serialize};

use crate::{
    assertions::DigitalSourceType,
    definitions::{ActionDefinition, ActionTemplateDefinition, ClaimGeneratorInfoDefinition},
    settings::SettingsValidate,
    Error, Result,
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

// #[allow(unused)]
// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// pub(crate) struct ClaimGeneratorInfoSettings {
//     #[serde(flatten)]
//     pub other: HashMap<String, toml::Value>,

//     #[serde(flatten)]
//     pub definition: ClaimGeneratorInfoDefinition,
// }

// impl TryFrom<ClaimGeneratorInfoSettings> for ClaimGeneratorInfoDefinition {
//     type Error = Error;

//     fn try_from(value: ClaimGeneratorInfoSettings) -> Result<Self> {
//         let mut definition = value.definition;
//         definition.other = value
//             .other
//             .into_iter()
//             .map(|(key, value)| {
//                 serde_json::to_value(value)
//                     .map(|value| (key, value))
//                     .map_err(|err| err.into())
//             })
//             .collect::<Result<HashMap<String, serde_json::Value>>>()?;
//         Ok(definition)
//     }
// }

// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// pub(crate) struct ActionTemplateSettings {
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub template_parameters: Option<HashMap<String, toml::Value>>,

//     #[serde(flatten)]
//     pub definition: ActionTemplateDefinition,
// }

// impl TryFrom<ActionTemplateSettings> for ActionTemplateDefinition {
//     type Error = Error;

//     fn try_from(value: ActionTemplateSettings) -> Result<Self> {
//         let mut definition = value.definition;
//         definition.template_parameters = value
//             .template_parameters
//             .map(|template_parameters| {
//                 template_parameters
//                     .into_iter()
//                     .map(|(key, value)| {
//                         serde_json::to_value(value)
//                             .map(|value| (key, value))
//                             .map_err(|err| err.into())
//                     })
//                     .collect::<Result<HashMap<String, serde_json::Value>>>()
//             })
//             .transpose()?;
//         Ok(definition)
//     }
// }

// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// pub(crate) struct ActionSettings {
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub parameters: Option<HashMap<String, toml::Value>>,

//     #[serde(flatten)]
//     pub definition: ActionDefinition,
// }

// impl TryFrom<ActionSettings> for ActionDefinition {
//     type Error = Error;

//     fn try_from(value: ActionSettings) -> Result<Self> {
//         let mut definition = value.definition;
//         definition.parameters = value
//             .parameters
//             .map(|template_parameters| {
//                 template_parameters
//                     .into_iter()
//                     .map(|(key, value)| {
//                         serde_json::value::to_value(value)
//                             .map(|value| (key, value))
//                             .map_err(|err| err.into())
//                     })
//                     .collect::<Result<HashMap<String, serde_json::Value>>>()
//             })
//             .transpose()?;
//         Ok(definition)
//     }
// }

/// Settings for the auto actions (e.g. created, opened, placed).
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct AutoActionSettings {
    /// Whether to enable this auto action or not.
    pub enabled: bool,
    /// The default source type for the auto action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<DigitalSourceType>,
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
    pub templates: Option<Vec<ActionTemplateDefinition>>,
    /// Actions to be added to the [Actions::actions][crate::assertions::Actions::actions] field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ActionDefinition>>,
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
                enabled: true,
                source_type: Some(DigitalSourceType::Empty),
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

// TODO: do more validation on URL fields, cert fields, etc.
/// Settings for the [Builder][crate::Builder].
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Default)]
pub(crate) struct BuilderSettings {
    /// Claim generator info that is automatically added to the builder.
    ///
    /// Note that this information will prepend any claim generator info
    /// provided explicitly to the builder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator_info: Option<ClaimGeneratorInfoDefinition>,
    /// Various settings for configuring automatic thumbnail generation.
    pub thumbnail: ThumbnailSettings,
    /// Settings for configuring fields in an [Actions][crate::assertions::Actions] assertion.
    ///
    /// For more information on the reasoning behind this field see [ActionsSettings].
    pub actions: ActionsSettings,

    // Certificate statuses will be fetched for either all the manifest labels, or just the active manifest.
    pub certificate_status_fetch: Option<OcspFetch>,

    // Whether or not existing OCSP responses should be overridden by new values.
    pub certificate_status_should_override: Option<bool>,
}

#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OcspFetch {
    All,
    Active,
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
    use crate::assertions::DigitalSourceType;

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
                source_type: Some(DigitalSourceType::Empty),
            },
            ..Default::default()
        };

        assert!(actions_settings.validate().is_ok());
    }
}
