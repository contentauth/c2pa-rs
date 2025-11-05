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

/// Settings for configuring the [`Builder`][crate::Builder].
pub mod builder;
/// Settings for configuring the [`Settings::signer`].
pub mod signer;

#[cfg(feature = "file_io")]
use std::path::Path;
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Cursor},
};

use config::{Config, FileFormat};
use serde_derive::{Deserialize, Serialize};
use signer::SignerSettings;

use crate::{crypto::base64, settings::builder::BuilderSettings, Error, Result, Signer};

const VERSION: u32 = 1;

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

/// Settings to configure the trust list.
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Trust {
    /// Whether to verify certificates against the trust lists specified in [`Trust`]. This
    /// option is ONLY applicable to CAWG.
    ///
    /// The default value is true.
    ///
    /// <div class="warning">
    /// Verifying trust is REQUIRED by the CAWG spec. This option should only be used for development or testing.
    /// </div>
    pub(crate) verify_trust_list: bool,
    /// List of additional user-provided trust anchor root certificates as a PEM bundle.
    pub user_anchors: Option<String>,
    /// List of default trust anchor root certificates as a PEM bundle.
    ///
    /// Normally this option contains the official C2PA-recognized trust anchors found here:
    /// <https://github.com/c2pa-org/conformance-public/tree/main/trust-list>
    pub trust_anchors: Option<String>,
    /// List of allowed extended key usage (EKU) object identifiers (OID) that
    /// certificates must have.
    pub trust_config: Option<String>,
    /// List of explicitly allowed certificates as a PEM bundle.
    pub allowed_list: Option<String>,
}

impl Trust {
    // load PEMs
    fn load_trust_from_data(&self, trust_data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut certs = Vec::new();

        // allow for JSON-encoded PEMs with \n
        let trust_data = String::from_utf8_lossy(trust_data)
            .replace("\\n", "\n")
            .into_bytes();
        for pem_result in x509_parser::pem::Pem::iter_from_buffer(&trust_data) {
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
            Err(Error::CoseInvalidCert)
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
                verify_trust_list: true,
                user_anchors: None,
                trust_anchors: None,
                trust_config: None,
                allowed_list: None,
            };

            trust.trust_config = Some(
                String::from_utf8_lossy(include_bytes!(
                    "../../tests/fixtures/certs/trust/store.cfg"
                ))
                .into_owned(),
            );
            trust.user_anchors = Some(
                String::from_utf8_lossy(include_bytes!(
                    "../../tests/fixtures/certs/trust/test_cert_root_bundle.pem"
                ))
                .into_owned(),
            );

            trust
        }
        #[cfg(not(test))]
        {
            Self {
                verify_trust_list: true,
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

/// Settings to configure core features.
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Core {
    /// Size of the [`BmffHash`] merkle tree chunks in kilobytes.
    ///
    /// This option is associated with the [`MerkleMap::fixed_block_size`] field.
    ///
    /// See more information in the spec here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_bmff_based_hash>
    ///
    /// [`MerkleMap::fixed_block_size`]: crate::assertions::MerkleMap::fixed_block_size
    /// [`BmffHash`]: crate::assertions::BmffHash
    pub merkle_tree_chunk_size_in_kb: Option<usize>,
    /// Maximum number of proofs when validating or writing a [`BmffHash`] merkle tree.
    ///
    /// This option defaults to 5.
    ///
    /// See more information in the spec here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_bmff_based_hash>
    ///
    /// [`BmffHash`]: crate::assertions::BmffHash
    pub merkle_tree_max_proofs: usize,
    /// Maximum amount of data in megabytes that will be loaded into memory before
    /// being stored in temporary files on the disk.
    ///
    /// This option defaults to 512MB and can result in noticeable performance improvements.
    pub backing_store_memory_threshold_in_mb: usize,
    /// Whether to decode CAWG [`IdentityAssertion`]s during reading in the [`Reader`].
    ///
    /// This option defaults to true.
    ///
    /// [`IdentityAssertion`]: crate::identity::IdentityAssertion
    /// [`Reader`]: crate::Reader
    pub decode_identity_assertions: bool,
}

impl Default for Core {
    fn default() -> Self {
        Self {
            merkle_tree_chunk_size_in_kb: None,
            merkle_tree_max_proofs: 5,
            backing_store_memory_threshold_in_mb: 512,
            decode_identity_assertions: true,
        }
    }
}

impl SettingsValidate for Core {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Settings to configure the verification process.
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Verify {
    /// Whether to verify the manifest after reading in the [`Reader`].
    ///
    /// The default value is true.
    ///
    /// <div class="warning">
    /// Disabling validation can improve reading performance, BUT it carries the risk of reading an invalid
    /// manifest.
    /// </div>
    ///
    /// [`Reader`]: crate::Reader
    pub verify_after_reading: bool,
    /// Whether to verify the manifest after signing in the [`Builder`].
    ///
    /// The default value is true.
    ///
    /// <div class="warning">
    /// Disabling validation can improve signing performance, BUT it carries the risk of signing an invalid
    /// manifest.
    /// </div>
    ///
    /// [`Builder`]: crate::Builder
    pub verify_after_sign: bool,
    /// Whether to verify certificates against the trust lists specified in [`Trust`]. To configure
    /// timestamp certificate verification, see [`Verify::verify_timestamp_trust`].
    ///
    /// The default value is true.
    ///
    /// <div class="warning">
    /// Verifying trust is REQUIRED by the C2PA spec. This option should only be used for development or testing.
    /// </div>
    pub(crate) verify_trust: bool,
    /// Whether to verify the timestamp certificates against the trust lists specified in [`Trust`].
    ///
    /// The default value is true.
    ///
    /// <div class="warning">
    /// Verifying timestamp trust is REQUIRED by the C2PA spec. This option should only be used for development or testing.
    /// </div>
    pub(crate) verify_timestamp_trust: bool,
    /// Whether to fetch the certificates OCSP status during validation.
    ///
    /// Revocation status is checked in the following order:
    /// 1. The OCSP staple stored in the COSE claim of the manifest
    /// 2. Otherwise if `ocsp_fetch` is enabled, it fetches a new OCSP status
    /// 3. Otherwise if `ocsp_fetch` is disabled, it checks `CertificateStatus` assertions
    ///
    /// The default value is false.
    pub ocsp_fetch: bool,
    /// Whether to fetch remote manifests in the following scenarios:
    /// - Constructing a [`Reader`]
    /// - Constructing an [`Ingredient`]
    /// - Adding an [`Ingredient`] to the [`Builder`]
    ///
    /// The default value is true.
    ///
    /// <div class="warning">
    /// This setting is only applicable if the crate is compiled with the `fetch_remote_manifests` feature.
    /// </div>
    ///
    /// [`Reader`]: crate::Reader
    /// [`Ingredient`]: crate::Ingredient
    /// [`Builder`]: crate::Builder
    pub remote_manifest_fetch: bool,
    /// Whether to verify ingredient certificates against the trust lists specific in [`Trust`].
    ///
    /// The default value is true.
    pub(crate) check_ingredient_trust: bool,
    /// Whether to skip ingredient conflict resolution when multiple ingredients have the same
    /// manifest identifier. This settings is only applicable for C2PA v2 validation.
    ///
    /// The default value is false.
    ///
    /// See more information in the spec here:
    /// <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_versioning_manifests_due_to_conflicts>
    pub(crate) skip_ingredient_conflict_resolution: bool,
    /// Whether to do strictly C2PA v1 validation or otherwise the latest validation.
    ///
    /// The default value is false.
    pub strict_v1_validation: bool,
}

impl Default for Verify {
    fn default() -> Self {
        Self {
            verify_after_reading: true,
            verify_after_sign: true,
            verify_trust: true,
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

/// Settings for configuring all aspects of c2pa-rs.
///
/// [Settings::default] will be set thread-locally by default. Any settings set via
/// [Settings::from_toml] or [Settings::from_file] will also be thread-local.
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Settings {
    /// Version of the configuration.
    pub version: u32,
    // TODO (https://github.com/contentauth/c2pa-rs/issues/1314):
    // Rename to c2pa_trust? Discuss possibly breaking change.
    /// Settings for configuring the C2PA trust lists.
    pub trust: Trust,
    /// Settings for configuring the CAWG trust lists.
    pub cawg_trust: Trust,
    /// Settings for configuring core features.
    pub core: Core,
    /// Settings for configuring verification.
    pub verify: Verify,
    /// Settings for configuring the [`Builder`].
    ///
    /// [`Builder`]: crate::Builder
    pub builder: BuilderSettings,
    /// Settings for configuring the base C2PA signer, accessible via [`Settings::signer`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerSettings>,
    /// Settings for configuring the CAWG x509 signer, accessible via [`Settings::signer`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cawg_x509_signer: Option<SignerSettings>,
}

impl Settings {
    #[cfg(feature = "file_io")]
    pub fn from_file<P: AsRef<Path>>(settings_path: P) -> Result<Self> {
        let ext = settings_path
            .as_ref()
            .extension()
            .ok_or(Error::UnsupportedType)?
            .to_string_lossy();

        let setting_buf = std::fs::read(&settings_path).map_err(Error::IoError)?;
        Settings::from_string(&String::from_utf8_lossy(&setting_buf), &ext)
    }

    /// Load settings from string representation of the configuration. Format of configuration must be supplied (json or toml).
    pub fn from_string(settings_str: &str, format: &str) -> Result<Self> {
        let f = match format.to_lowercase().as_str() {
            "json" => FileFormat::Json,
            //"json5" => FileFormat::Json5,
            //"ini" => FileFormat::Ini,
            "toml" => FileFormat::Toml,
            //"yaml" => FileFormat::Yaml,
            //ron" => FileFormat::Ron,
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
                    .map_err(|e| Error::BadParam(e.to_string()))?;

                settings.validate()?;

                SETTINGS.set(update_config.clone());

                Ok(settings)
            }
            Err(_) => Err(Error::OtherError("could not update configuration".into())),
        }
    }

    /// Set the [Settings] from a toml file.
    pub fn from_toml(toml: &str) -> Result<()> {
        Settings::from_string(toml, "toml").map(|_| ())
    }

    /// Set the [Settings] from a url to a toml file.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_url(url: &str) -> Result<()> {
        let toml = ureq::get(url)
            .call()
            .map_err(|_| Error::FailedToFetchSettings)?
            .into_body()
            .read_to_string()
            .map_err(|_| Error::FailedToFetchSettings)?;
        Settings::from_toml(&toml)
    }

    /// Set a [Settings] value by path reference. The path is nested names of of the Settings objects
    /// separated by "." notation.
    ///
    /// For example "core.hash_alg" would set settings.core.hash_alg value. The nesting can be arbitrarily
    /// deep based on the [Settings] definition.
    #[allow(unused)]
    pub(crate) fn set_value<T: Into<config::Value>>(value_path: &str, value: T) -> Result<()> {
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
                .map_err(|e| Error::BadParam(e.to_string()))?;
            settings.validate()?;

            SETTINGS.set(update_config);

            Ok(())
        } else {
            SETTINGS.set(c);
            Err(Error::OtherError("could not save settings".into()))
        }
    }

    /// Get a [Settings] value by path reference. The path is nested names of of the [Settings] objects
    /// separated by "." notation.
    ///
    /// For example "core.hash_alg" would get the settings.core.hash_alg value. The nesting can be arbitrarily
    /// deep based on the [Settings] definition.
    #[allow(unused)]
    fn get_value<'de, T: serde::de::Deserialize<'de>>(value_path: &str) -> Result<T> {
        SETTINGS.with_borrow(|current_settings| {
            let update_config = Config::builder()
                .add_source(current_settings.clone())
                .build()
                .map_err(|_e| Error::OtherError("could not update configuration".into()))?;

            update_config
                .get::<T>(value_path)
                .map_err(|_| Error::BadParam("could not get settings value".into()))
        })
    }

    /// Set [Settings] back to the default values.
    #[allow(unused)]
    pub(crate) fn reset() -> Result<()> {
        if let Ok(default_settings) = Config::try_from(&Settings::default()) {
            SETTINGS.set(default_settings);
            Ok(())
        } else {
            Err(Error::OtherError("could not save settings".into()))
        }
    }

    /// Serializes the [Settings] into a toml string.
    pub fn to_toml() -> Result<String> {
        let settings =
            get_settings().ok_or(Error::OtherError("could not get current settings".into()))?;
        Ok(toml::to_string(&settings)?)
    }

    /// Serializes the [Settings] into a pretty (formatted) toml string.
    pub fn to_pretty_toml() -> Result<String> {
        let settings =
            get_settings().ok_or(Error::OtherError("could not get current settings".into()))?;
        Ok(toml::to_string_pretty(&settings)?)
    }

    /// Returns the constructed signer from the `signer` field.
    ///
    /// If the signer settings aren't specified, this function will return [Error::MissingSignerSettings].
    #[inline]
    pub fn signer() -> Result<Box<dyn Signer>> {
        SignerSettings::signer()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version: VERSION,
            trust: Default::default(),
            cawg_trust: Default::default(),
            core: Default::default(),
            verify: Default::default(),
            builder: Default::default(),
            signer: None,
            cawg_x509_signer: None,
        }
    }
}

impl SettingsValidate for Settings {
    fn validate(&self) -> Result<()> {
        if self.version > VERSION {
            return Err(Error::VersionCompatibility(
                "settings version too new".into(),
            ));
        }
        if let Some(signer) = &self.signer {
            signer.validate()?;
        }
        if let Some(cawg_x509_signer) = &self.cawg_x509_signer {
            cawg_x509_signer.validate()?;
        }
        self.trust.validate()?;
        self.cawg_trust.validate()?;
        self.core.validate()?;
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
#[deprecated = "use `Settings::from_file`"]
#[cfg(feature = "file_io")]
pub(crate) fn load_settings_from_file<P: AsRef<Path>>(settings_path: P) -> Result<()> {
    Settings::from_file(settings_path)?;
    Ok(())
}

/// Load settings from string representation of the configuration. Format of configuration must be supplied.
#[allow(unused)]
pub fn load_settings_from_str(settings_str: &str, format: &str) -> Result<()> {
    Settings::from_string(settings_str, format).map(|_| ())
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

/// See [Settings::set_value] for more information.
#[allow(unused)]
pub(crate) fn set_settings_value<T: Into<config::Value>>(value_path: &str, value: T) -> Result<()> {
    Settings::set_value(value_path, value)
}

/// See [Settings::get_value] for more information.
#[allow(unused)]
fn get_settings_value<'de, T: serde::de::Deserialize<'de>>(value_path: &str) -> Result<T> {
    Settings::get_value(value_path)
}

/// Reset all settings back to default values.
#[allow(unused)]
// #[deprecated = "use `Settings::reset` instead"]
pub fn reset_default_settings() -> Result<()> {
    Settings::reset()
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
        assert_eq!(settings.cawg_trust, Trust::default());
        assert_eq!(settings.verify, Verify::default());
        assert_eq!(settings.builder, BuilderSettings::default());

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_get_val_by_direct_path() {
        // you can do this for all values but if these sanity checks pass they all should if the path is correct
        assert_eq!(
            get_settings_value::<bool>("builder.thumbnail.enabled").unwrap(),
            BuilderSettings::default().thumbnail.enabled
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
            get_settings_value::<BuilderSettings>("builder").unwrap(),
            BuilderSettings::default()
        );
        assert_eq!(
            get_settings_value::<Trust>("trust").unwrap(),
            Trust::default()
        );

        // test implicit deserialization
        let remote_manifest_fetch: bool =
            get_settings_value("verify.remote_manifest_fetch").unwrap();
        let auto_thumbnail: bool = get_settings_value("builder.thumbnail.enabled").unwrap();
        let user_anchors: Option<String> = get_settings_value("trust.user_anchors").unwrap();

        assert_eq!(
            remote_manifest_fetch,
            Verify::default().remote_manifest_fetch
        );
        assert_eq!(auto_thumbnail, BuilderSettings::default().thumbnail.enabled);
        assert_eq!(user_anchors, Trust::default().user_anchors);

        // test implicit deserialization on objects
        let core: Core = get_settings_value("core").unwrap();
        let verify: Verify = get_settings_value("verify").unwrap();
        let builder: BuilderSettings = get_settings_value("builder").unwrap();
        let trust: Trust = get_settings_value("trust").unwrap();

        assert_eq!(core, Core::default());
        assert_eq!(verify, Verify::default());
        assert_eq!(builder, BuilderSettings::default());
        assert_eq!(trust, Trust::default());

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_set_val_by_direct_path() {
        let ts = include_bytes!("../../tests/fixtures/certs/trust/test_cert_root_bundle.pem");

        // test updating values
        Settings::set_value("core.merkle_tree_chunk_size_in_kb", 10).unwrap();
        Settings::set_value("verify.remote_manifest_fetch", false).unwrap();
        Settings::set_value("builder.thumbnail.enabled", false).unwrap();
        Settings::set_value(
            "trust.user_anchors",
            Some(String::from_utf8(ts.to_vec()).unwrap()),
        )
        .unwrap();

        assert_eq!(
            get_settings_value::<usize>("core.merkle_tree_chunk_size_in_kb").unwrap(),
            10
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
        assert_ne!(
            get_settings_value::<BuilderSettings>("builder").unwrap(),
            BuilderSettings::default()
        );
        assert!(get_settings_value::<Trust>("trust").unwrap() == Trust::default());

        reset_default_settings().unwrap();
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_save_load() {
        let temp_dir = tempdirectory().unwrap();
        let op = crate::utils::test::temp_dir_path(&temp_dir, "sdk_config.json");

        save_settings_as_json(&op).unwrap();

        Settings::from_file(&op).unwrap();
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

        Settings::from_toml(&modified_core).unwrap();

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
            BuilderSettings::default().thumbnail.enabled
        );

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_bad_setting() {
        let modified_core = toml::toml! {
            [core]
            merkle_tree_chunk_size_in_kb = true
            merkle_tree_max_proofs = "sha1000000"
            backing_store_memory_threshold_in_mb = -123456
        }
        .to_string();

        assert!(Settings::from_toml(&modified_core).is_err());

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

        Settings::from_toml(&secret).unwrap();

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
            version = 1

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

        Settings::from_toml(&all_settings).unwrap();

        reset_default_settings().unwrap();
    }

    #[test]
    fn test_load_settings_from_sample_toml() {
        #[cfg(target_os = "wasi")]
        Settings::reset().unwrap();

        let toml = include_bytes!("../../examples/c2pa.toml");
        Settings::from_toml(std::str::from_utf8(toml).unwrap()).unwrap();
    }
}
