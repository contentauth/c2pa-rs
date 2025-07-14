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
    create_signer,
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

// TODO: doc
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct SignerSettings {
    pub alg: SigningAlg,
    pub sign_cert: Vec<u8>,
    pub private_key: Vec<u8>,
    pub tsa_url: Option<String>,
}

/// Settings for the auto actions (e.g. created, opened, placed).
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct AutoActionSettings {
    /// Whether to enable this auto action or not.
    pub enabled: bool,
    // TODO: enum
    /// The default source type for the auto action.
    pub source_type: Option<String>,
}

/// Settings for the [Builder].
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct BuilderSettings {
    /// Information about the signer used for signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerSettings>,
    /// Claim generator info that is automatically added to the builder.
    ///
    /// Note that this information will prepend any claim generator info
    /// provided explicitly to the builder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_generator_info: Option<ClaimGeneratorInfo>,
    /// Various settings for configuring automatic thumbnail generation.
    pub thumbnail: ThumbnailSettings,
    /// Whether to automatically generate a c2pa.created [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.created action assertion, see here:
    /// https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion
    pub auto_created_action: AutoActionSettings,
    /// Whether to automatically generate a c2pa.opened [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.opened action assertion, see here:
    /// https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion
    pub auto_opened_action: AutoActionSettings,
    /// Whether to automatically generate a c2pa.placed [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.placed action assertion, see here:
    /// https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_relationship
    pub auto_placed_action: AutoActionSettings,
}

impl Default for BuilderSettings {
    fn default() -> Self {
        Self {
            signer: None,
            claim_generator_info: None,
            thumbnail: Default::default(),
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

impl SettingsValidate for BuilderSettings {
    fn validate(&self) -> Result<()> {
        if self.auto_created_action.enabled && self.auto_created_action.source_type.is_none() {
            return Err(Error::MissingAutoCreatedActionSourceType);
        }

        self.thumbnail.validate()
    }
}

impl Settings {
    /// Returns the constructed signer from the signer field in [Settings].
    ///
    /// If the signer settings aren't specified, this function will return [Error::UnspecifiedSignerSettings][crate::Error::UnspecifiedSignerSettings].
    pub fn signer() -> Result<Box<dyn Signer>> {
        let signer_info = Settings::get_value::<Option<SignerSettings>>("builder.signer");
        if let Ok(Some(signer_info)) = signer_info {
            create_signer::from_keys(
                &signer_info.sign_cert,
                &signer_info.private_key,
                signer_info.alg,
                signer_info.tsa_url.to_owned(),
            )
        } else {
            Err(Error::MissingSignerSettings)
        }
    }
}
