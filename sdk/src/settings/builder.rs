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

use std::{collections::HashMap, env::consts, io::Read};

use serde::{Deserialize, Serialize};

use crate::{
    assertions::{Action, ActionTemplate},
    create_signer,
    resource_store::UriOrResource,
    settings::{Settings, SettingsValidate},
    utils::thumbnail::ThumbnailFormat,
    ClaimGeneratorInfo, Error, Result, Signer, SigningAlg,
};

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

/// Settings for configuring a local or remote [Signer][crate::Signer].
///
/// A [Signer][crate::Signer] can be obtained by calling [BuilderSettings::signer].
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SignerSettings {
    /// A signer configured locally.
    Local {
        // TODO: doc fields
        alg: SigningAlg,
        sign_cert: String,
        private_key: String,
        tsa_url: Option<String>,
    },
    /// A signer configured remotely.
    Remote {
        // TODO: document the remote API
        url: String,
        alg: SigningAlg,
        sign_cert: String,
        tsa_url: Option<String>,
    },
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

// TODO: maybe we should store these "Settings"-type of structs in the Builder instead of the actual
//       struct that's embedded into the claim. Structs like this can be converted to the internal ones
//       when signing?
// TODO: this redefinition of the struct isn't ideal either, see ActionTemplateSettings for more info
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

// TODO: it's not ideal redefining this entire struct, but we need to change serde_json::Value to toml::Value
//       for template_parameters. Another issue is that some fields are defined in camelCase in the original struct.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActionTemplateSettings {
    pub action: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent: Option<ClaimGeneratorInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_agent_index: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<UriOrResource>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_parameters: Option<HashMap<String, toml::Value>>,
}

impl TryFrom<ActionTemplateSettings> for ActionTemplate {
    type Error = Error;

    fn try_from(value: ActionTemplateSettings) -> Result<Self> {
        Ok(ActionTemplate {
            action: value.action,
            software_agent: value.software_agent,
            software_agent_index: value.software_agent_index,
            source_type: value.source_type,
            icon: value.icon,
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
    pub actions: Option<Vec<Action>>,
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
    /// Information about the signer used for signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerSettings>,
    /// Information about the CAWG signer used for CAWG signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cawg_signer: Option<SignerSettings>,
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

impl BuilderSettings {
    // TODO: add async signer?
    /// Returns the constructed signer from the [BuilderSettings::signer] field.
    ///
    /// If the signer settings aren't specified, this function will return [Error::MissingSignerSettings][crate::Error::MissingSignerSettings].
    pub fn signer() -> Result<Box<dyn Signer>> {
        BuilderSettings::signer_from_settings("builder.signer")
    }

    // TODO: add async signer?
    /// Returns the constructed CAWG signer from the [BuilderSettings::cawg_signer] field.
    ///
    /// This function is used in conjunction with [IdentityAssertionSigner::new][crate::identity::builder::IdentityAssertionSigner::new].
    ///
    /// If the signer settings aren't specified, this function will return [Error::MissingSignerSettings][crate::Error::MissingSignerSettings].
    pub fn cawg_signer() -> Result<Box<dyn Signer>> {
        BuilderSettings::signer_from_settings("builder.cawg_signer")
    }

    fn signer_from_settings(settings_path: &'static str) -> Result<Box<dyn Signer>> {
        let signer_info = Settings::get_value::<Option<SignerSettings>>(settings_path);
        match signer_info {
            Ok(Some(signer_info)) => match signer_info {
                SignerSettings::Local {
                    alg,
                    sign_cert,
                    private_key,
                    tsa_url,
                } => create_signer::from_keys(
                    sign_cert.as_bytes(),
                    private_key.as_bytes(),
                    alg,
                    tsa_url.to_owned(),
                ),
                SignerSettings::Remote {
                    url,
                    alg,
                    sign_cert,
                    tsa_url,
                } => Ok(Box::new(RemoteSigner {
                    url,
                    alg,
                    reserve_size: 10000 + sign_cert.len(),
                    certs: vec![sign_cert.into_bytes()],
                    tsa_url,
                })),
            },
            #[cfg(test)]
            _ => Ok(crate::utils::test_signer::test_signer(SigningAlg::Ps256)),
            #[cfg(not(test))]
            _ => Err(Error::MissingSignerSettings),
        }
    }
}

// TODO: move this to a separate file?
#[derive(Debug)]
pub(crate) struct RemoteSigner {
    url: String,
    alg: SigningAlg,
    certs: Vec<Vec<u8>>,
    reserve_size: usize,
    tsa_url: Option<String>,
}

impl Signer for RemoteSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let response = ureq::post(&self.url)
            .send_bytes(data)
            .map_err(|_| Error::FailedToRemoteSign)?;
        let mut bytes: Vec<u8> = Vec::with_capacity(self.reserve_size);
        response
            .into_reader()
            .take(self.reserve_size as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.certs.clone())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use crate::{assertions::source_type, utils::test_signer};

    use super::*;

    #[test]
    fn test_make_test_signer() {
        // Makes a default test signer.
        assert!(Settings::signer().is_ok());
        assert!(Settings::cawg_signer().is_ok());
    }

    #[test]
    fn test_make_local_signer() {
        // Testing with a different alg than the default test signer.
        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);
        Settings::from_toml(
            &toml::toml! {
                [builder.signer.local]
                alg = (alg.to_string())
                sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                private_key = (String::from_utf8(private_key.to_vec()).unwrap())

                [builder.cawg_signer.local]
                alg = (alg.to_string())
                sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                private_key = (String::from_utf8(private_key.to_vec()).unwrap())
            }
            .to_string(),
        )
        .unwrap();

        let signers = [
            Settings::signer().unwrap(),
            Settings::cawg_signer().unwrap(),
        ];
        for signer in signers {
            assert_eq!(signer.alg(), alg);
            assert_eq!(signer.time_authority_url(), None);
            assert!(signer.sign(&[1, 2, 3]).is_ok());
        }
    }

    #[test]
    fn test_make_remote_signer() {
        // TODO: how do we normally test remote things?
    }

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
