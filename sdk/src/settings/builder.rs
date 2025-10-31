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

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    assertions::{
        region_of_interest::RegionOfInterest, Action, ActionParameters, ActionTemplate,
        DigitalSourceType, SoftwareAgent,
    },
    builder::BuilderIntent,
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
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThumbnailFormat {
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
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ThumbnailQuality {
    /// Low quality.
    Low,
    /// Medium quality.
    Medium,
    /// High quality.
    High,
}

/// Settings for controlling automatic thumbnail generation.
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ThumbnailSettings {
    /// Whether or not to automatically generate thumbnails.
    ///
    /// The default value is true.
    ///
    /// <div class="warning">
    /// This setting is only applicable if the crate is compiled with the `add_thumbnails` feature.
    /// </div>
    pub enabled: bool,
    /// Whether to ignore thumbnail generation errors.
    ///
    /// This may occur, for instance, if the thumbnail media type or color layout isn't
    /// supported.
    ///
    /// The default value is true.
    pub ignore_errors: bool,
    /// The size of the longest edge of the thumbnail.
    ///
    /// This function will resize the input to preserve aspect ratio.
    ///
    /// The default value is 1024.
    pub long_edge: u32,
    /// Format of the thumbnail.
    ///
    /// If this field isn't specified, the thumbnail format will correspond to the
    /// input format.
    ///
    /// The default value is None.
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
    ///
    /// The default value is true.
    pub prefer_smallest_format: bool,
    /// The output quality of the thumbnail.
    ///
    /// This setting contains sensible defaults for things like quality, compression, and
    /// algorithms for various formats.
    ///
    /// The default value is [`ThumbnailQuality::Medium`].
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
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AutoActionSettings {
    /// Whether to enable this auto action or not.
    pub enabled: bool,
    /// The default source type for the auto action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<DigitalSourceType>,
}

#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged, rename_all = "lowercase")]
pub enum ClaimGeneratorInfoOperatingSystem {
    /// Whether or not to automatically infer the operating system.
    ///
    /// This option will attempt to following the [LLVM "triples"] conventions. For more information,
    /// see [`ClaimGeneratorInfoOperatingSystem::Other`].
    ///
    /// [LLVM "triples"]: https://clang.llvm.org/docs/CrossCompilation.html#target-triple
    Auto,
    /// The name of the operating system.
    ///
    /// It is recommended to follow the [LLVM "triples"] conventions to define the operating system,
    /// with the format `<arch><sub>-<vendor>-<sys>-<env>`. For instance:
    /// - `x86_64-unknown-linux-gnu`
    /// - `x86_64-pc-windows-msvc`
    /// - `arm64-apple-darwin`
    ///
    /// [LLVM "triples"]: https://clang.llvm.org/docs/CrossCompilation.html#target-triple
    Other(String),
}

/// Settings for the claim generator info.
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ClaimGeneratorInfoSettings {
    /// A human readable string naming the claim_generator.
    pub name: String,
    /// A human readable string of the product's version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Reference to an icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) icon: Option<ResourceRef>,
    /// Settings for the claim generator info's operating system field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<ClaimGeneratorInfoOperatingSystem>,
    /// Any other values that are not part of the standard.
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

impl TryFrom<ClaimGeneratorInfoSettings> for ClaimGeneratorInfo {
    type Error = Error;

    fn try_from(value: ClaimGeneratorInfoSettings) -> Result<Self> {
        Ok(ClaimGeneratorInfo {
            name: value.name,
            version: value.version,
            icon: value.icon.map(UriOrResource::ResourceRef),
            operating_system: {
                value.operating_system.map(|os| match os {
                    ClaimGeneratorInfoOperatingSystem::Auto => {
                        format!("{}-unknown-{}", consts::ARCH, consts::OS)
                    }
                    ClaimGeneratorInfoOperatingSystem::Other(name) => name,
                })
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
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ActionTemplateSettings {
    /// The label associated with this action. See ([c2pa_action][crate::assertions::actions::c2pa_action]).
    pub action: String,
    /// The software agent that performed the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<ClaimGeneratorInfoSettings>,
    // TODO: change this to use string names and document in c2pa.toml
    /// 0-based index into the softwareAgents array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent_index: Option<usize>,
    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<DigitalSourceType>,
    // TODO: handle paths/urls and document in the sample c2pa.toml
    /// Reference to an icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<ResourceRef>,
    /// Description of the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Additional parameters for the template
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_parameters: Option<HashMap<String, serde_json::Value>>,
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
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
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
    /// A list of the regions of interest of the resource that were changed.
    ///
    /// If not present, presumed to be undefined.
    /// When tracking changes and the scope of the changed components is unknown,
    /// it should be assumed that anything might have changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<Vec<RegionOfInterest>>,

    /// Additional parameters of the action. These vary by the type of action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ActionParameters>,
    /// One of the defined URI values at `<https://cv.iptc.org/newscodes/digitalsourcetype/>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<DigitalSourceType>,
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
            changes: value.changes,
            parameters: value.parameters,
            source_type: value.source_type,
            related: value.related,
            reason: value.reason,
            description: value.description,
            ..Default::default()
        })
    }
}

/// Settings for configuring the "base" [Actions][crate::assertions::Actions] assertion.
///
/// The reason this setting exists only for an [Actions][crate::assertions::Actions] assertion
/// is because of its mandations and reusable fields.
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActionsSettings {
    /// Whether or not to set the [Actions::all_actions_included][crate::assertions::Actions::all_actions_included]
    /// field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_actions_included: Option<bool>,
    /// Templates to be added to the [Actions::templates][crate::assertions::Actions::templates] field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) templates: Option<Vec<ActionTemplateSettings>>,
    /// Actions to be added to the [Actions::actions][crate::assertions::Actions::actions] field.
    // TODO: ActionSettings indirectly depends on ActionParameters which contains a serde_cbor::Value and
    // schemars can't generate a schema for cbor values. It also doesn't feel right to change our API for
    // the sake of json schemas.
    #[cfg_attr(feature = "json_schema", schemars(skip))]
    pub(crate) actions: Option<Vec<ActionSettings>>,
    /// Whether to automatically generate a c2pa.created [Action] assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.created action assertion, see here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion>
    pub auto_created_action: AutoActionSettings,
    /// Whether to automatically generate a c2pa.opened [Action] assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.opened action assertion, see here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion>
    pub auto_opened_action: AutoActionSettings,
    /// Whether to automatically generate a c2pa.placed [Action] assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.placed action assertion, see:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_relationship>
    pub auto_placed_action: AutoActionSettings,
}

impl Default for ActionsSettings {
    fn default() -> Self {
        ActionsSettings {
            all_actions_included: None,
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
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Default)]
pub struct BuilderSettings {
    /// Claim generator info that is automatically added to the builder.
    ///
    /// Note that this information will prepend any claim generator info
    /// provided explicitly to the builder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator_info: Option<ClaimGeneratorInfoSettings>,
    /// Various settings for configuring automatic thumbnail generation.
    pub thumbnail: ThumbnailSettings,
    /// Settings for configuring fields in an [Actions][crate::assertions::Actions] assertion.
    ///
    /// For more information on the reasoning behind this field see [ActionsSettings].
    pub actions: ActionsSettings,
    // TODO: this setting affects fetching and generation of the assertion; needs clarification
    /// Whether to create [`CertificateStatus`] assertions for manifests to store certificate revocation
    /// status. The assertion can be fetched for the active manifest or for all manifests (including
    /// ingredients).
    ///
    /// The default is to not fetch them at all.
    ///
    /// See more information in the spec here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#certificate_status_assertion>
    ///
    /// [`CertificateStatus`]: crate::assertions::CertificateStatus
    pub(crate) certificate_status_fetch: Option<OcspFetchScope>,
    // TODO: this setting affects fetching and generation of the assertion; needs clarification
    /// Whether to only use [`CertificateStatus`] assertions to check certificate revocation status. If there
    /// is a stapled OCSP in the COSE claim of the manifest, it will be ignored. If [`Verify::ocsp_fetch`] is
    /// enabled, it will also be ignored.
    ///
    /// The default value is false.
    ///
    /// [`CertificateStatus`]: crate::assertions::CertificateStatus
    /// [`Verify::ocsp_fetch`]: crate::settings::Verify::ocsp_fetch
    pub(crate) certificate_status_should_override: Option<bool>,
    /// The default [`BuilderIntent`] for the [`Builder`].
    ///
    /// See [`BuilderIntent`] for more information.
    ///
    /// [`BuilderIntent`]: crate::BuilderIntent
    /// [`Builder`]: crate::Builder
    pub intent: Option<BuilderIntent>,
    /// Assertions with a base label included in this list will be automatically marked as a created assertion.
    /// Assertions not in this list will be automatically marked as gathered.
    ///
    /// Note that the label should be a **base label**, not including the assertion version nor instance.
    ///
    /// See more information on the difference between created vs gathered assertions in the spec here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_fields>
    pub created_assertion_labels: Option<Vec<String>>,

    /// Whether to generate a C2PA archive (instead of zip) when writing the manifest builder.
    /// This will eventually become the default behavior.
    pub generate_c2pa_archive: Option<bool>,
}

/// The scope of which manifests to fetch for OCSP.
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OcspFetchScope {
    /// Fetch OCSP for all manifests.
    All,
    /// Fetch OCSP for the active manifest only.
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
