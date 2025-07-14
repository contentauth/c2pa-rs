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

#[cfg(feature = "file_io")]
use std::path::Path;
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Cursor},
};

use config::{Config, FileFormat};
use serde_derive::{Deserialize, Serialize};

use crate::{
    create_signer, crypto::base64, utils::thumbnail::ThumbnailFormat, ClaimGeneratorInfo, Error,
    Result, Signer, SigningAlg,
};

thread_local!(
    static SETTINGS: RefCell<Config> =
        RefCell::new(Config::try_from(&Settings::default()).unwrap_or_default());
);

// trait used to validate user input to make sure user supplied configurations are valid
pub(crate) trait SettingsValidate {
    // returns error if settings are invalid
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

// Settings for trust list feature
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[allow(unused)]
pub(crate) struct Trust {
    user_anchors: Option<String>,
    trust_anchors: Option<String>,
    trust_config: Option<String>,
    allowed_list: Option<String>,
}

impl Trust {
    // load PEMs
    fn load_trust_from_data(&self, trust_data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut certs = Vec::new();

        for pem_result in x509_parser::pem::Pem::iter_from_buffer(trust_data) {
            let pem = pem_result.map_err(|_e| Error::CoseInvalidCert)?;
            certs.push(pem.contents);
        }
        Ok(certs)
    }

    // sanity check to see if can parse trust settings
    fn test_load_trust(&self, allowed_list: &[u8]) -> Result<()> {
        // check pems
        if let Ok(cert_list) = self.load_trust_from_data(allowed_list) {
            if !cert_list.is_empty() {
                return Ok(());
            }
        }

        // try to load the of base64 encoded encoding of the sha256 hash of the certificate DER encoding
        let reader = Cursor::new(allowed_list);
        let buf_reader = BufReader::new(reader);
        let mut found_der_hash = false;

        let mut inside_cert_block = false;
        for l in buf_reader.lines().map_while(|v| v.ok()) {
            if l.contains("-----BEGIN") {
                inside_cert_block = true;
            }
            if l.contains("-----END") {
                inside_cert_block = false;
            }

            // sanity check that that is is base64 encoded and outside of certificate block
            if !inside_cert_block && base64::decode(&l).is_ok() && !l.is_empty() {
                found_der_hash = true;
            }
        }

        if found_der_hash {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for Trust {
    fn default() -> Self {
        // load test config store for unit tests
        #[cfg(test)]
        {
            let mut trust = Self {
                user_anchors: None,
                trust_anchors: None,
                trust_config: None,
                allowed_list: None,
            };

            trust.trust_config = Some(
                String::from_utf8_lossy(include_bytes!("../tests/fixtures/certs/trust/store.cfg"))
                    .into_owned(),
            );
            trust.user_anchors = Some(
                String::from_utf8_lossy(include_bytes!(
                    "../tests/fixtures/certs/trust/test_cert_root_bundle.pem"
                ))
                .into_owned(),
            );

            trust
        }
        #[cfg(not(test))]
        {
            Self {
                user_anchors: None,
                trust_anchors: None,
                trust_config: None,
                allowed_list: None,
            }
        }
    }
}

impl SettingsValidate for Trust {
    fn validate(&self) -> Result<()> {
        if let Some(ta) = &self.trust_anchors {
            self.test_load_trust(ta.as_bytes())?;
        }

        if let Some(pa) = &self.user_anchors {
            self.test_load_trust(pa.as_bytes())?;
        }

        if let Some(al) = &self.allowed_list {
            self.test_load_trust(al.as_bytes())?;
        }

        Ok(())
    }
}

// Settings for core C2PA-RS functionality
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[allow(unused)]
pub(crate) struct Core {
    debug: bool,
    hash_alg: String,
    salt_jumbf_boxes: bool,
    prefer_box_hash: bool,
    prefer_bmff_merkle_tree: bool,
    compress_manifests: bool,
    max_memory_usage: Option<u64>,
    // TODO: pending https://github.com/contentauth/c2pa-rs/pull/1180
    // prefer_update_manifests: bool,
}

impl Default for Core {
    fn default() -> Self {
        Self {
            debug: false,
            hash_alg: "sha256".into(),
            salt_jumbf_boxes: true,
            prefer_box_hash: false,
            prefer_bmff_merkle_tree: false,
            compress_manifests: true,
            max_memory_usage: None,
            // prefer_update_manifests: true,
        }
    }
}

impl SettingsValidate for Core {
    fn validate(&self) -> Result<()> {
        match self.hash_alg.as_str() {
            "sha256" | "sha384" | "sha512" => Ok(()),
            _ => Err(Error::UnsupportedType),
        }
    }
}

// Settings for verification options
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[allow(unused)]
pub(crate) struct Verify {
    verify_after_reading: bool,
    verify_after_sign: bool,
    verify_trust: bool,
    verify_timestamp_trust: bool,
    ocsp_fetch: bool,
    remote_manifest_fetch: bool,
    check_ingredient_trust: bool,
    skip_ingredient_conflict_resolution: bool,
    strict_v1_validation: bool,
}

impl Default for Verify {
    fn default() -> Self {
        Self {
            verify_after_reading: true,
            verify_after_sign: true,
            verify_trust: cfg!(test),
            verify_timestamp_trust: !cfg!(test), // verify timestamp trust unless in test mode
            ocsp_fetch: false,
            remote_manifest_fetch: true,
            check_ingredient_trust: true,
            skip_ingredient_conflict_resolution: false,
            strict_v1_validation: false,
        }
    }
}

impl SettingsValidate for Verify {}

/// Quality of the thumbnail.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ThumbnailSettings {
    /// Whether or not to automatically generate thumbnails.
    enabled: bool,
    /// Whether to ignore thumbnail generation errors.
    ///
    /// This may occur, for instance, if the thumbnail media type or color layout isn't
    /// supported.
    ignore_errors: bool,
    /// The size of the longest edge of the thumbnail.
    ///
    /// This function will resize the input to preserve aspect ratio.
    long_edge: u32,
    /// Format of the thumbnail.
    ///
    /// If this field isn't specified, the thumbnail format will correspond to the
    /// input format.
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<ThumbnailFormat>,
    /// Whether or not to prefer a smaller sized media format for the thumbnail.
    ///
    /// Note that [ThumbnailSettings::format] takes precedence over this field. In addition,
    /// if the output format is unsupported, it will default to the smallest format regardless
    /// of the value of this field.
    ///
    /// For instance, if the source input type is a PNG, but it doesn't have an alpha channel,
    /// the image will be converted to a JPEG of smaller size.
    prefer_smallest_format: bool,
    /// The output quality of the thumbnail.
    ///
    /// This setting contains sensible defaults for things like quality, compression, and
    /// algorithms for various formats.
    quality: ThumbnailQuality,
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

#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SignerSettings {
    alg: SigningAlg,
    sign_cert: Vec<u8>,
    private_key: Vec<u8>,
    tsa_url: Option<String>,
}

#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AutoActionSettings {
    /// Whether to enable this auto action or not.
    enabled: bool,
    // TODO: enum
    /// The default source type for the auto action.
    source_type: Option<String>,
}

// Settings for Builder API options
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct Builder {
    /// Information about the signer used for signing.
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<SignerSettings>,
    /// Claim generator info that is automatically added to the builder.
    ///
    /// Note that this information will prepend any claim generator info
    /// provided explicitly to the builder.
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_generator_info: Option<ClaimGeneratorInfo>,
    /// Various settings for configuring automatic thumbnail generation.
    thumbnail: ThumbnailSettings,
    /// Whether to automatically generate a c2pa.created [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.created action assertion, see here:
    /// https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion
    auto_created_action: AutoActionSettings,
    /// Whether to automatically generate a c2pa.opened [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.opened action assertion, see here:
    /// https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_mandatory_presence_of_at_least_one_actions_assertion
    auto_opened_action: AutoActionSettings,
    /// Whether to automatically generate a c2pa.placed [Action][crate::assertions::Action]
    /// assertion or error that it doesn't already exist.
    ///
    /// For more information about the mandatory conditions for a c2pa.placed action assertion, see here:
    /// https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_relationship
    auto_placed_action: AutoActionSettings,
}

impl Default for Builder {
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

impl SettingsValidate for Builder {
    fn validate(&self) -> Result<()> {
        if self.auto_created_action.enabled && self.auto_created_action.source_type.is_none() {
            return Err(Error::MissingAutoCreatedActionSourceType);
        }

        self.thumbnail.validate()
    }
}

const MAJOR_VERSION: usize = 1;
const MINOR_VERSION: usize = 0;

// Settings configuration for C2PA-RS.  Default configuration values
// are lazy loaded on first use.  Values can also be loaded from a configuration
// file or by setting specific value via code.  There is a single configuration
// setting for the entire C2PA-RS instance.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[allow(unused)]
pub struct Settings {
    version_major: usize,
    version_minor: usize,
    trust: Trust,
    core: Core,
    verify: Verify,
    builder: Builder,
}

impl Settings {
    #[cfg(feature = "file_io")]
    pub fn from_file<P: AsRef<Path>>(setting_path: P) -> Result<Self> {
        let ext = setting_path
            .as_ref()
            .extension()
            .ok_or(Error::UnsupportedType)?
            .to_string_lossy();

        let setting_buf = std::fs::read(&setting_path).map_err(Error::IoError)?;
        Settings::from_string(&String::from_utf8_lossy(&setting_buf), &ext)
    }

    pub fn from_string(settings_str: &str, format: &str) -> Result<Self> {
        let f = match format.to_lowercase().as_str() {
            "json" => FileFormat::Json,
            "json5" => FileFormat::Json5,
            //"ini" => FileFormat::Ini,
            "toml" => FileFormat::Toml,
            //"yaml" => FileFormat::Yaml,
            "ron" => FileFormat::Ron,
            _ => return Err(Error::UnsupportedType),
        };

        let new_config = Config::builder()
            .add_source(config::File::from_str(settings_str, f))
            .build()
            .map_err(|_e| Error::BadParam("could not parse configuration file".into()))?;

        let update_config = SETTINGS.with_borrow(|current_settings| {
            Config::builder()
                .add_source(current_settings.clone())
                .add_source(new_config)
                .build() // merge overrides, allows for partial changes
        });

        match update_config {
            Ok(update_config) => {
                // sanity check the values before committing
                let settings = update_config
                    .clone()
                    .try_deserialize::<Settings>()
                    .map_err(|_e| {
                        Error::BadParam("configuration file contains unrecognized param".into())
                    })?;

                settings.validate()?;

                SETTINGS.set(update_config.clone());

                Ok(settings)
            }
            Err(_) => Err(Error::OtherError("could not update configuration".into())),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version_major: MAJOR_VERSION,
            version_minor: MINOR_VERSION,
            trust: Default::default(),
            core: Default::default(),
            verify: Default::default(),
            builder: Default::default(),
        }
    }
}

impl SettingsValidate for Settings {
    fn validate(&self) -> Result<()> {
        if self.version_major > MAJOR_VERSION {
            return Err(Error::VersionCompatibility(
                "settings version too new".into(),
            ));
        }
        self.trust.validate()?;
        self.core.validate()?;
        self.trust.validate()?;
        self.builder.validate()
    }
}

// Get snapshot of the Settings objects, returns None if there is an error
#[allow(unused)]
pub(crate) fn get_settings() -> Option<Settings> {
    SETTINGS.with_borrow(|config| config.clone().try_deserialize::<Settings>().ok())
}

// Load settings from configuration file
#[allow(unused)]
#[cfg(feature = "file_io")]
pub(crate) fn load_settings_from_file<P: AsRef<Path>>(settings_path: P) -> Result<()> {
    let ext = settings_path
        .as_ref()
        .extension()
        .ok_or(Error::UnsupportedType)?
        .to_string_lossy();

    let setting_buf = std::fs::read(&settings_path).map_err(Error::IoError)?;

    #[allow(deprecated)]
    load_settings_from_str(&String::from_utf8_lossy(&setting_buf), &ext)
}

/// Load settings from string representation of the configuration. Format of configuration must be supplied.
#[allow(unused)]
// TODO: when this is removed, remove the additional features (for all supported formats) from the Cargo.toml
#[deprecated = "use load_settings instead (note it is TOML only)"]
pub fn load_settings_from_str(settings_str: &str, format: &str) -> Result<()> {
    Settings::from_string(settings_str, format).map(|_| ())
}

// TODO: doc
#[allow(unused)]
pub fn load_settings(toml: &str) -> Result<()> {
    Settings::from_string(toml, "toml").map(|_| ())
}

// Save the current configuration to a json file.
#[allow(unused)]
#[cfg(feature = "file_io")]
pub(crate) fn save_settings_as_json<P: AsRef<Path>>(settings_path: P) -> Result<()> {
    let settings =
        get_settings().ok_or(Error::OtherError("could not get current settings".into()))?;

    let settings_json = serde_json::to_string_pretty(&settings).map_err(Error::JsonError)?;

    std::fs::write(settings_path, settings_json.as_bytes()).map_err(Error::IoError)
}

// Set a Settings value by path reference.  The path is nested names of of the Settings objects
// separated by "." notation.  For example "core.hash_alg" would set settings.core.hash_alg value.
// The nesting can be arbitrarily deep based on the Settings definition.
#[allow(unused)]
pub(crate) fn set_settings_value<T: Into<config::Value>>(value_path: &str, value: T) -> Result<()> {
    let c = SETTINGS.take();

    let update_config = Config::builder()
        .add_source(c.clone())
        .set_override(value_path, value);

    if let Ok(updated) = update_config {
        let update_config = updated
            .build()
            .map_err(|_e| Error::OtherError("could not update configuration".into()))?;

        let settings = update_config
            .clone()
            .try_deserialize::<Settings>()
            .map_err(|_e| {
                Error::BadParam("configuration file contains unrecognized param".into())
            })?;
        settings.validate()?;

        SETTINGS.set(update_config);

        Ok(())
    } else {
        SETTINGS.set(c);
        Err(Error::OtherError("could not save settings".into()))
    }
}

// Get a Settings value by path reference.  The path is nested names of of the Settings objects
// separated by "." notation.  For example "core.hash_alg" would get the settings.core.hash_alg value.
// The nesting can be arbitrarily deep based on the Settings definition.
#[allow(unused)]
pub(crate) fn get_settings_value<'de, T: serde::de::Deserialize<'de>>(
    value_path: &str,
) -> Result<T> {
    SETTINGS.with_borrow(|current_settings| {
        let update_config = Config::builder()
            .add_source(current_settings.clone())
            .build()
            .map_err(|_e| Error::OtherError("could not update configuration".into()))?;

        update_config
            .get::<T>(value_path)
            .map_err(|_| Error::NotFound)
    })
}

/// Returns the constructed signer from the signer field in settings.
///
/// If the signer settings aren't specified, this function will return [Error::UnspecifiedSignerSettings][crate::Error::UnspecifiedSignerSettings].
pub fn get_settings_signer() -> Result<Box<dyn Signer>> {
    let signer_info = get_settings_value::<Option<SignerSettings>>("builder.signer");
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

// Set settings back to the default values.  Current use case is for testing.
#[allow(unused)]
pub fn reset_default_settings() -> Result<()> {
    if let Ok(default_settings) = Config::try_from(&Settings::default()) {
        SETTINGS.set(default_settings);
        Ok(())
    } else {
        Err(Error::OtherError("could not save settings".into()))
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    #[cfg(feature = "file_io")]
    use crate::utils::io_utils::tempdirectory;

    #[test]
    fn test_get_defaults() {
        let settings = get_settings().unwrap();

        assert_eq!(settings.core, Core::default());
        assert_eq!(settings.trust, Trust::default());
        assert_eq!(settings.verify, Verify::default());
        assert_eq!(settings.builder, Builder::default());

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_get_val_by_direct_path() {
        // you can do this for all values but if these sanity checks pass they all should if the path is correct
        assert_eq!(
            get_settings_value::<String>("core.hash_alg").unwrap(),
            Core::default().hash_alg
        );
        assert_eq!(
            get_settings_value::<bool>("builder.thumbnail.enabled").unwrap(),
            Builder::default().thumbnail.enabled
        );
        assert_eq!(
            get_settings_value::<Option<String>>("trust.user_anchors").unwrap(),
            Trust::default().user_anchors
        );

        // test getting full objects
        assert_eq!(get_settings_value::<Core>("core").unwrap(), Core::default());
        assert_eq!(
            get_settings_value::<Verify>("verify").unwrap(),
            Verify::default()
        );
        assert_eq!(
            get_settings_value::<Builder>("builder").unwrap(),
            Builder::default()
        );
        assert_eq!(
            get_settings_value::<Trust>("trust").unwrap(),
            Trust::default()
        );

        // test implicit deserialization
        let hash_alg: String = get_settings_value("core.hash_alg").unwrap();
        let remote_manifest_fetch: bool =
            get_settings_value("verify.remote_manifest_fetch").unwrap();
        let auto_thumbnail: bool = get_settings_value("builder.thumbnail.enabled").unwrap();
        let user_anchors: Option<String> = get_settings_value("trust.user_anchors").unwrap();

        assert_eq!(hash_alg, Core::default().hash_alg);
        assert_eq!(
            remote_manifest_fetch,
            Verify::default().remote_manifest_fetch
        );
        assert_eq!(auto_thumbnail, Builder::default().thumbnail.enabled);
        assert_eq!(user_anchors, Trust::default().user_anchors);

        // test implicit deserialization on objects
        let core: Core = get_settings_value("core").unwrap();
        let verify: Verify = get_settings_value("verify").unwrap();
        let builder: Builder = get_settings_value("builder").unwrap();
        let trust: Trust = get_settings_value("trust").unwrap();

        assert_eq!(core, Core::default());
        assert_eq!(verify, Verify::default());
        assert_eq!(builder, Builder::default());
        assert_eq!(trust, Trust::default());

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_set_val_by_direct_path() {
        let ts = include_bytes!("../tests/fixtures/certs/trust/test_cert_root_bundle.pem");

        // test updating values
        set_settings_value("core.hash_alg", "sha512").unwrap();
        set_settings_value("verify.remote_manifest_fetch", false).unwrap();
        set_settings_value("builder.thumbnail.enabled", false).unwrap();
        set_settings_value(
            "trust.user_anchors",
            Some(String::from_utf8(ts.to_vec()).unwrap()),
        )
        .unwrap();

        assert_eq!(
            get_settings_value::<String>("core.hash_alg").unwrap(),
            "sha512"
        );
        assert!(!get_settings_value::<bool>("verify.remote_manifest_fetch").unwrap());
        assert!(!get_settings_value::<bool>("builder.thumbnail.enabled").unwrap());
        assert_eq!(
            get_settings_value::<Option<String>>("trust.user_anchors").unwrap(),
            Some(String::from_utf8(ts.to_vec()).unwrap())
        );

        // the current config should be different from the defaults
        assert_ne!(get_settings_value::<Core>("core").unwrap(), Core::default());
        assert_ne!(
            get_settings_value::<Verify>("verify").unwrap(),
            Verify::default()
        );
        // assert_ne!(
        //     get_settings_value::<Builder>("builder").unwrap(),
        //     Builder::default()
        // );
        assert!(get_settings_value::<Trust>("trust").unwrap() == Trust::default());

        reset_default_settings().unwrap();
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_save_load() {
        let temp_dir = tempdirectory().unwrap();
        let op = crate::utils::test::temp_dir_path(&temp_dir, "sdk_config.json");

        save_settings_as_json(&op).unwrap();

        load_settings_from_file(&op).unwrap();
        let settings = get_settings().unwrap();

        assert_eq!(settings, Settings::default());

        reset_default_settings().unwrap();
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_save_load_from_string() {
        let temp_dir = tempdirectory().unwrap();
        let op = crate::utils::test::temp_dir_path(&temp_dir, "sdk_config.json");

        save_settings_as_json(&op).unwrap();

        let setting_buf = std::fs::read(&op).unwrap();

        {
            let settings_str: &str = &String::from_utf8_lossy(&setting_buf);
            Settings::from_string(settings_str, "json").map(|_| ())
        }
        .unwrap();
        let settings = get_settings().unwrap();

        assert_eq!(settings, Settings::default());

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_partial_loading() {
        // we support just changing the fields you are interested in changing
        // here is an example of incomplete structures only overriding specific
        // fields

        let modified_core = toml::toml! {
            [core]
            debug = true
            hash_alg = "sha512"
            max_memory_usage = 123456
        }
        .to_string();

        load_settings(&modified_core).unwrap();

        // see if updated values match
        assert!(get_settings_value::<bool>("core.debug").unwrap());
        assert_eq!(
            get_settings_value::<String>("core.hash_alg").unwrap(),
            "sha512".to_string()
        );
        assert_eq!(
            get_settings_value::<u32>("core.max_memory_usage").unwrap(),
            123456u32
        );

        // check a few defaults to make sure they are still there
        assert_eq!(
            get_settings_value::<bool>("builder.thumbnail.enabled").unwrap(),
            Builder::default().thumbnail.enabled
        );

        assert_eq!(
            get_settings_value::<bool>("core.salt_jumbf_boxes").unwrap(),
            Core::default().salt_jumbf_boxes
        );

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_bad_setting() {
        let modified_core = toml::toml! {
            [core]
            debug = true
            hash_alg = "sha1000000"
            max_memory_usage = 123456
        }
        .to_string();

        assert!(load_settings(&modified_core).is_err());

        reset_default_settings().unwrap();
    }
    #[test]
    fn test_hidden_setting() {
        let secret = toml::toml! {
            [hidden]
            test1 = true
            test2 = "hello world"
            test3 = 123456
        }
        .to_string();

        load_settings(&secret).unwrap();

        assert!(get_settings_value::<bool>("hidden.test1").unwrap());
        assert_eq!(
            get_settings_value::<String>("hidden.test2").unwrap(),
            "hello world".to_string()
        );
        assert_eq!(
            get_settings_value::<u32>("hidden.test3").unwrap(),
            123456u32
        );

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_all_setting() {
        let all_settings = toml::toml! {
            version_major = 1
            version_minor = 0

            [trust]

            [Core]
            debug = false
            hash_alg = "sha256"
            salt_jumbf_boxes = true
            prefer_box_hash = false
            prefer_bmff_merkle_tree = false
            compress_manifests = true

            [Verify]
            verify_after_reading = true
            verify_after_sign = true
            verify_trust = true
            ocsp_fetch = false
            remote_manifest_fetch = true
            check_ingredient_trust = true
            skip_ingredient_conflict_resolution = false
            strict_v1_validation = false
        }
        .to_string();

        load_settings(&all_settings).unwrap();

        reset_default_settings().unwrap();
    }
}
