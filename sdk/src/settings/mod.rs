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

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use signer::SignerSettings;

use crate::{
    crypto::base64, http::restricted::HostPattern, settings::builder::BuilderSettings, Error,
    Result,
};

const VERSION: u32 = 1;

/// Maximum recursion depth for JSON merging.
const MERGE_MAX_DEPTH: usize = 64;

/// Default maximum number of assertions allowed per manifest.
/// Shared by [`BuilderSettings`], [`Verify`], [`crate::Claim`], and [`crate::Store`] so that
/// all enforcement points use the same value.
pub(crate) const MAX_ASSERTIONS: usize = 100_000;

thread_local!(
    static SETTINGS: RefCell<Value> = RefCell::new(
        serde_json::to_value(Settings::default()).unwrap_or(Value::Object(Map::new())),
    );
);

// trait used to validate user input to make sure user supplied configurations are valid
pub(crate) trait SettingsValidate {
    // returns error if settings are invalid
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

/// Settings to configure the trust list.
#[cfg_attr(
    feature = "json_schema",
    derive(schemars::JsonSchema),
    schemars(default)
)]
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
    /// Exact-match allow-list of trusted CAWG identity claims aggregation (ICA)
    /// issuer DIDs.
    ///
    /// Each entry is a full DID string (any DID method) that is compared, after
    /// stripping any fragment, against the `issuer` of an ICA verifiable
    /// credential. An issuer that is not present on this list is reported with
    /// the informational code `cawg.ica.untrusted_issuer` for that identity
    /// assertion and its `cawg.ica.credential_valid` success code is withheld.
    ///
    /// The default value is empty, meaning that NO ICA issuer is trusted. This
    /// is a deliberate secure default: a self-issued `did:jwk` (or any other
    /// issuer) is not trustworthy simply because its signature is
    /// self-consistent. Populate this list with the DIDs of issuers you trust.
    // TO DO (CAI-12709): This field is only meaningful for `cawg_trust`, not for
    // the C2PA `trust`. Move it (and the other CAWG-relevant settings) to a
    // dedicated `CawgTrust` struct so it no longer pollutes the C2PA `Trust`.
    pub trusted_ica_issuers: Option<Vec<String>>,
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
                // Trust the ICA issuer DIDs used by the bundled CAWG test
                // fixtures so the existing ICA validation tests continue to
                // produce `cawg.ica.credential_valid`.
                trusted_ica_issuers: Some(vec![
                    "did:jwk:eyJhbGciOiJFZERTQSIsImt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiTXA1LTBlODNuTmdRaGRoQlc4UnNoa2p5OTBzYTFBOUpJemtJdGNEcUN1SSJ9".to_string(),
                    "did:web:connected-identities.identity-stage.adobe.com".to_string(),
                ]),
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
                trusted_ica_issuers: None,
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
#[cfg_attr(
    feature = "json_schema",
    derive(schemars::JsonSchema),
    schemars(default)
)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Core {
    /// Size of the [`BmffHash`] merkle tree chunks in kilobytes.
    ///
    /// This option is associated with the [`MerkleMap::fixed_block_size`] field.
    ///
    /// See more information in the spec here:
    /// [bmff_based_hash - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_bmff_based_hash)
    ///
    /// [`MerkleMap::fixed_block_size`]: crate::assertions::MerkleMap::fixed_block_size
    /// [`BmffHash`]: crate::assertions::BmffHash
    pub merkle_tree_chunk_size_in_kb: Option<usize>,
    /// Maximum number of proof hashes stored in UUID merkle boxes when  generating a [`BmffHash`] merkle tree.  This
    /// determines the Merkle tree row stored in the manifest and thus the number of proof hashes that need to be
    /// provided during validation. The value may be 0 to store just leaf node hashes (no UUID boxes are generated in this case).
    ///
    /// This option defaults to 5.
    ///
    /// See more information in the spec here:
    /// [bmff_based_hash - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_bmff_based_hash)
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
    /// <div class="warning">
    /// The CAWG identity assertion does not currently respect this setting.
    /// See [Issue #1645](https://github.com/contentauth/c2pa-rs/issues/1645).
    /// </div>
    ///
    /// List of host patterns that are allowed for network requests.
    ///
    /// Each pattern may include:
    /// - A scheme (e.g. `https://` or `http://`)
    /// - A hostname or IP address (e.g. `contentauthenticity.org` or `192.0.2.1`)
    ///     - The hostname may contain a single leading wildcard (e.g. `*.contentauthenticity.org`)
    /// - An optional port (e.g. `contentauthenticity.org:443` or `192.0.2.1:8080`)
    ///
    /// Matching is case-insensitive. A wildcard pattern such as `*.contentauthenticity.org` matches
    /// `sub.contentauthenticity.org`, but does not match `contentauthenticity.org` or `fakecontentauthenticity.org`.
    /// If a scheme is present in the pattern, only URIs using the same scheme are considered a match. If the scheme
    /// is omitted, any scheme is allowed as long as the host matches.
    ///
    /// The behavior is as follows:
    /// - `None` (default) no filtering enabled.
    /// - `Some(vec)` where `vec` is empty, all traffic is blocked.
    /// - `Some(vec)` with at least one pattern, filtering enabled for only those patterns.
    ///
    /// # Examples
    ///
    /// Pattern: `*.contentauthenticity.org`
    /// - Does match:
    ///   - `https://sub.contentauthenticity.org`
    ///   - `http://api.contentauthenticity.org`
    /// - Does **not** match:
    ///   - `https://contentauthenticity.org` (no subdomain)
    ///   - `https://sub.fakecontentauthenticity.org` (different host)
    ///
    /// Pattern: `http://192.0.2.1:8080`
    /// - Does match:
    ///   - `http://192.0.2.1:8080`
    /// - Does **not** match:
    ///   - `https://192.0.2.1:8080` (scheme mismatch)
    ///   - `http://192.0.2.1` (port omitted)
    ///   - `http://192.0.2.2:8080` (different IP address)
    ///
    /// These settings are applied by the SDK's HTTP resolvers to restrict network requests.
    /// When network requests occur depends on the operations being performed (reading manifests,
    /// validating credentials, timestamping, etc.).
    pub allowed_network_hosts: Option<Vec<HostPattern>>,
    /// Whether to prefer compressing manifests. This can reduce the size of the manifest. Compressed manifest
    /// are not always possible and will default back to uncompressed if the manifest contains features
    /// that are not compatible with compression.
    ///
    ///  The default value is false.
    ///
    /// See more information in the spec here:
    /// [Compressed manifests - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_compressed_boxes)
    pub prefer_compress_manifests: bool,
    /// Maximum size in megabytes of a Brotli-decompressed JUMBF manifest.
    /// Limits memory consumption from decompression bomb attacks.
    ///
    /// The default is 32 MB.
    pub max_decompressed_manifest_size_in_mb: usize,
}

impl Default for Core {
    fn default() -> Self {
        Self {
            merkle_tree_chunk_size_in_kb: None,
            merkle_tree_max_proofs: 5,
            backing_store_memory_threshold_in_mb: 512,
            decode_identity_assertions: true,
            allowed_network_hosts: None,
            prefer_compress_manifests: false,
            max_decompressed_manifest_size_in_mb: 32,
        }
    }
}

impl SettingsValidate for Core {
    fn validate(&self) -> Result<()> {
        const MAX_MANIFEST_SIZE_MB: usize = 1024; // 1 GiB
        if self.max_decompressed_manifest_size_in_mb > MAX_MANIFEST_SIZE_MB {
            return Err(Error::BadParam(format!(
                "max_decompressed_manifest_size_in_mb must not exceed {MAX_MANIFEST_SIZE_MB} MB"
            )));
        }
        Ok(())
    }
}

/// Settings to configure the verification process.
#[cfg_attr(
    feature = "json_schema",
    derive(schemars::JsonSchema),
    schemars(default)
)]
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
    /// The default value is false.
    ///
    /// In the future, this setting will default to true.
    ///
    /// <div class="warning">
    /// Disabling validation can improve signing performance, BUT it carries the risk of signing an invalid
    /// manifest.
    /// </div>
    ///
    /// [`Builder`]: crate::Builder
    pub verify_after_sign: bool,
    /// Whether to include asset hash validation when verifying after signing.
    ///
    /// The default value is false.
    ///
    /// Has no effect when [`Verify::verify_after_sign`] is false.
    pub(crate) verify_after_sign_hash: bool,
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
    /// Whether to skip ingredient conflict resolution when multiple ingredients have the same
    /// manifest identifier. This settings is only applicable for C2PA v2 validation.
    ///
    /// The default value is false.
    ///
    /// See more information in the spec here:
    /// [versioning_manifests_due_to_conflicts - C2PA Technical Specification](https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_versioning_manifests_due_to_conflicts)
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
            // TODO: set this to true [#1875](https://github.com/contentauth/c2pa-rs/issues/1875)
            verify_after_sign: cfg!(test),
            verify_after_sign_hash: cfg!(test),
            verify_trust: true,
            verify_timestamp_trust: !cfg!(test), // verify timestamp trust unless in test mode
            ocsp_fetch: false,
            remote_manifest_fetch: true,
            skip_ingredient_conflict_resolution: false,
            strict_v1_validation: false,
        }
    }
}

impl SettingsValidate for Verify {}

#[cfg_attr(
    feature = "json_schema",
    derive(schemars::JsonSchema),
    schemars(default)
)]
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct SoftBinding {
    pub soft_binding_algorithms: Option<Vec<String>>,
}

impl SettingsValidate for SoftBinding {}

/// Settings for configuring all aspects of c2pa-rs.
///
/// [Settings::default] will be set thread-locally by default. Any settings set via
/// [Settings::from_toml] or [Settings::from_file] will also be thread-local.
#[cfg_attr(
    feature = "json_schema",
    derive(schemars::JsonSchema),
    schemars(default)
)]
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
    /// List of soft binding algorithms to validate against. If not specified, soft binding errors may be generated.
    pub soft_binding: SoftBinding,
}

impl Settings {
    #[cfg(feature = "file_io")]
    /// Load thread-local [Settings] from a file.
    ///
    /// Use [`Settings::new().with_file()`](Settings::with_file) instead,
    /// which does not modify thread-local state.
    #[doc(hidden)]
    #[deprecated(
        note = "Use `Settings::new().with_file(path)` instead, which does not modify thread-local state."
    )]
    #[allow(deprecated)]
    pub fn from_file<P: AsRef<Path>>(settings_path: P) -> Result<Self> {
        let ext = settings_path
            .as_ref()
            .extension()
            .ok_or(Error::UnsupportedType)?
            .to_string_lossy();

        let setting_buf = std::fs::read(&settings_path).map_err(Error::IoError)?;
        Settings::from_string(&String::from_utf8_lossy(&setting_buf), &ext)
    }

    /// Load thread-local [Settings] from string representation of the configuration.
    /// Format of configuration must be supplied (json or toml).
    ///
    /// Use [`Settings::new().with_json()`](Settings::with_json) or
    /// [`Settings::new().with_toml()`](Settings::with_toml) instead,
    /// which do not modify thread-local state.
    #[doc(hidden)]
    #[deprecated(
        note = "Use `Settings::new().with_json(str)` or `Settings::new().with_toml(str)` instead, which do not modify thread-local state."
    )]
    pub fn from_string(settings_str: &str, format: &str) -> Result<Self> {
        let overlay = parse_to_value(settings_str, format)?;
        let mut merged = SETTINGS.with_borrow(Value::clone);
        merge_json(&mut merged, overlay);

        let settings: Settings =
            serde_json::from_value(merged.clone()).map_err(|e| Error::BadParam(e.to_string()))?;
        settings.validate()?;

        SETTINGS.set(merged);
        Ok(settings)
    }

    /// Set the thread-local [Settings] from a toml string.
    ///
    /// Use [`Settings::new().with_toml()`](Settings::with_toml) instead,
    /// which does not modify thread-local state.
    #[deprecated(
        note = "Use `Settings::new().with_toml(toml)` instead, which does not modify thread-local state."
    )]
    #[allow(deprecated)]
    pub fn from_toml(toml: &str) -> Result<()> {
        Settings::from_string(toml, "toml").map(|_| ())
    }

    /// Update this `Settings` instance from a string representation.
    /// This overlays the provided configuration on top of the current settings
    /// without affecting the thread-local settings.
    ///
    /// # Arguments
    /// * `settings_str` - The configuration string
    /// * `format` - The format of the configuration ("json" or "toml")
    ///
    /// # Example
    /// ```
    /// use c2pa::settings::Settings;
    ///
    /// let mut settings = Settings::default();
    ///
    /// // Update with TOML
    /// settings
    ///     .update_from_str(
    ///         r#"
    ///     [verify]
    ///     verify_after_sign = false
    /// "#,
    ///         "toml",
    ///     )
    ///     .unwrap();
    ///
    /// assert!(!settings.verify.verify_after_sign);
    ///
    /// // Update with JSON (can set values to null)
    /// settings
    ///     .update_from_str(
    ///         r#"
    ///     {
    ///         "verify": {
    ///             "verify_after_sign": true
    ///         }
    ///     }
    /// "#,
    ///         "json",
    ///     )
    ///     .unwrap();
    ///
    /// assert!(settings.verify.verify_after_sign);
    /// ```
    pub fn update_from_str(&mut self, settings_str: &str, format: &str) -> Result<()> {
        *self = self.with_string(settings_str, format)?;
        Ok(())
    }

    /// Set a [Settings] value by path reference. The path is nested names of of the Settings objects
    /// separated by "." notation.
    ///
    /// For example "core.hash_alg" would set settings.core.hash_alg value. The nesting can be arbitrarily
    /// deep based on the [Settings] definition.
    #[allow(unused)]
    pub(crate) fn set_thread_local_value<T: Into<Value>>(value_path: &str, value: T) -> Result<()> {
        let mut merged = SETTINGS.with_borrow(Value::clone);
        set_at_path(&mut merged, value_path, value.into())?;

        let settings: Settings =
            serde_json::from_value(merged.clone()).map_err(|e| Error::BadParam(e.to_string()))?;
        settings.validate()?;

        SETTINGS.set(merged);
        Ok(())
    }

    /// Get a [Settings] value by path reference from the thread-local settings.
    /// The path is nested names of of the [Settings] objects
    /// separated by "." notation.
    ///
    /// For example "core.hash_alg" would get the settings.core.hash_alg value. The nesting can be arbitrarily
    /// deep based on the [Settings] definition.
    #[allow(unused)]
    fn get_thread_local_value<T: serde::de::DeserializeOwned>(value_path: &str) -> Result<T> {
        SETTINGS.with_borrow(|current| {
            let leaf = get_at_path(current, value_path)
                .ok_or_else(|| Error::BadParam("could not get settings value".into()))?;
            serde_json::from_value(leaf.clone())
                .map_err(|err| Error::BadParam(format!("could not get settings value: {err}")))
        })
    }

    /// Set the thread-local [Settings] back to the default values.
    /// to be deprecated
    #[allow(unused)]
    pub(crate) fn reset() -> Result<()> {
        let value = serde_json::to_value(Settings::default())
            .map_err(|err| Error::OtherError(format!("could not reset settings: {err}").into()))?;
        SETTINGS.set(value);
        Ok(())
    }

    /// Creates a new Settings instance with default values.
    ///
    /// This is the starting point for the builder pattern. Use with `.with_json()`,
    /// `.with_toml()`, or `.with_value()` to configure settings without touching
    /// thread-local state.
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::settings::Settings;
    /// # use c2pa::Context;
    /// # fn main() -> c2pa::Result<()> {
    /// let settings = Settings::new().with_json(r#"{"verify": {"verify_trust": true}}"#)?;
    /// let context = Context::new().with_settings(settings)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Load settings from JSON string using the builder pattern.
    ///
    /// This does NOT update thread-local settings. It overlays the JSON configuration
    /// on top of the current Settings instance.
    ///
    /// # Arguments
    ///
    /// * `json` - JSON string containing settings configuration
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::settings::Settings;
    /// # fn main() -> c2pa::Result<()> {
    /// let settings = Settings::new().with_json(r#"{"verify": {"verify_trust": true}}"#)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_json(&self, json: &str) -> Result<Self> {
        self.with_string(json, "json")
    }

    /// Load settings from TOML string using the builder pattern.
    ///
    /// This does NOT update thread-local settings. It overlays the TOML configuration
    /// on top of the current Settings instance. For the legacy behavior that
    /// updates thread-locals, use `Settings::from_toml()`.
    ///
    /// # Arguments
    ///
    /// * `toml` - TOML string containing settings configuration
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::settings::Settings;
    /// # fn main() -> c2pa::Result<()> {
    /// let settings = Settings::new().with_toml(
    ///     r#"
    ///         [verify]
    ///         verify_trust = true
    ///     "#,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_toml(&self, toml: &str) -> Result<Self> {
        self.with_string(toml, "toml")
    }

    /// Load settings from a file using the builder pattern.
    ///
    /// The file format (JSON or TOML) is inferred from the file extension.
    /// This does NOT update thread-local settings.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the settings file
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use c2pa::settings::Settings;
    /// # fn main() -> c2pa::Result<()> {
    /// let settings = Settings::new().with_file("config.toml")?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "file_io")]
    pub fn with_file<P: AsRef<Path>>(&self, path: P) -> Result<Self> {
        let path = path.as_ref();
        let ext = path
            .extension()
            .ok_or(Error::BadParam(
                "settings file must have json or toml extension".into(),
            ))?
            .to_str()
            .ok_or(Error::BadParam("invalid settings file name".into()))?;
        let setting_buf = std::fs::read(path).map_err(Error::IoError)?;
        self.with_string(&String::from_utf8_lossy(&setting_buf), ext)
    }

    /// Load settings from string representation (builder pattern helper).
    ///
    /// This overlays the parsed configuration on top of the current Settings
    /// instance without touching thread-local state.
    fn with_string(&self, settings_str: &str, format: &str) -> Result<Self> {
        let overlay = parse_to_value(settings_str, format)?;
        let mut merged =
            serde_json::to_value(self).map_err(|err| Error::OtherError(Box::new(err)))?;
        merge_json(&mut merged, overlay);

        let settings: Settings =
            serde_json::from_value(merged).map_err(|err| Error::BadParam(err.to_string()))?;
        settings.validate()?;

        Ok(settings)
    }

    /// Serializes the thread-local [Settings] into a toml string.
    ///
    /// Use `toml::to_string(&settings)` on a [`Settings`] instance instead.
    #[doc(hidden)]
    #[deprecated(
        note = "Use `toml::to_string(&settings)` on a `Settings` instance instead of reading from thread-local state."
    )]
    pub fn to_toml() -> Result<String> {
        let settings = get_thread_local_settings();
        Ok(toml::to_string(&settings)?)
    }

    /// Serializes the thread-local [Settings] into a pretty (formatted) toml string.
    ///
    /// Use `toml::to_string_pretty(&settings)` on a [`Settings`] instance instead.
    #[doc(hidden)]
    #[deprecated(
        note = "Use `toml::to_string_pretty(&settings)` on a `Settings` instance instead of reading from thread-local state."
    )]
    pub fn to_pretty_toml() -> Result<String> {
        let settings = get_thread_local_settings();
        Ok(toml::to_string_pretty(&settings)?)
    }

    /// Returns the constructed signer from the thread-local `signer` settings field.
    ///
    /// If the signer settings aren't specified, this function will return [Error::MissingSignerSettings].
    ///
    /// Configure the signer via a [`Context`](crate::Context) passed explicitly to
    /// [`Builder::from_context`](crate::Builder::from_context) instead.
    #[inline]
    #[deprecated(
        note = "Configure the signer via `Context` and pass it to `Builder::from_context` instead of using thread-local signer settings."
    )]
    pub fn signer() -> Result<crate::BoxedSigner> {
        SignerSettings::signer()
    }

    /// Sets a value at the specified path in this Settings instance using the builder pattern.
    ///
    /// The path uses dot notation to navigate nested structures.
    /// For example: "verify.verify_trust", "core.hash_alg", "builder.thumbnail.enabled"
    ///
    /// # Arguments
    ///
    /// * `path` - A dot-separated path to the setting (e.g., "verify.verify_trust")
    /// * `value` - Any value that can be converted into a `serde_json::Value`
    ///
    /// # Returns
    ///
    /// The updated Settings instance (for chaining)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is invalid
    /// - The value type doesn't match the expected type
    /// - Validation fails after the change
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::settings::Settings;
    /// # fn main() -> c2pa::Result<()> {
    /// let settings = Settings::default()
    ///     .with_value("verify.verify_trust", true)?
    ///     .with_value("core.merkle_tree_max_proofs", 10)?
    ///     .with_value("core.backing_store_memory_threshold_in_mb", 256)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_value<T: Into<Value>>(&self, path: &str, value: T) -> Result<Self> {
        let mut merged =
            serde_json::to_value(self).map_err(|err| Error::OtherError(Box::new(err)))?;
        set_at_path(&mut merged, path, value.into())
            .map_err(|err| Error::BadParam(format!("invalid path '{path}': {err}")))?;

        let updated_settings: Settings = serde_json::from_value(merged)
            .map_err(|err| Error::BadParam(format!("invalid value for '{path}': {err}")))?;
        updated_settings.validate()?;

        Ok(updated_settings)
    }

    /// Sets a value at the specified path, modifying this Settings instance in place.
    ///
    /// This is a mutable alternative to [`with_value`](Settings::with_value).
    ///
    /// # Arguments
    ///
    /// * `path` - A dot-separated path to the setting
    /// * `value` - Any value that can be converted into a `serde_json::Value`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is invalid
    /// - The value type doesn't match the expected type
    /// - Validation fails after the change
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::settings::Settings;
    /// # fn main() -> c2pa::Result<()> {
    /// let mut settings = Settings::default();
    /// settings.set_value("verify.verify_trust", false)?;
    /// settings.set_value("core.merkle_tree_max_proofs", 10)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_value<T: Into<Value>>(&mut self, path: &str, value: T) -> Result<()> {
        *self = self.with_value(path, value)?;
        Ok(())
    }

    /// Gets a value at the specified path from this Settings instance.
    ///
    /// The path uses dot notation to navigate nested structures.
    /// The return type is inferred from context or can be specified explicitly.
    ///
    /// # Arguments
    ///
    /// * `path` - A dot-separated path to the setting
    ///
    /// # Type Parameters
    ///
    /// * `T` - The expected type of the value (must implement Deserialize)
    ///
    /// # Returns
    ///
    /// The value at the specified path
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path doesn't exist
    /// - The value can't be deserialized to type T
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::settings::Settings;
    /// # fn main() -> c2pa::Result<()> {
    /// let settings = Settings::default();
    ///
    /// // Type can be inferred
    /// let verify_trust: bool = settings.get_value("verify.verify_trust")?;
    ///
    /// // Or specified explicitly
    /// let max_proofs = settings.get_value::<usize>("core.merkle_tree_max_proofs")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_value<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let value = serde_json::to_value(self).map_err(|err| Error::OtherError(Box::new(err)))?;
        let leaf = get_at_path(&value, path)
            .ok_or_else(|| Error::BadParam(format!("value at '{path}' not found")))?;
        serde_json::from_value(leaf.clone())
            .map_err(|err| Error::BadParam(format!("failed to get value at '{path}': {err}")))
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
            soft_binding: Default::default(),
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

/// Overlays `overlay` onto `target`. Objects are merged key-by-key, and any
/// other value (e.g. `null` and arrays) replaces the target value.
fn merge_json(target: &mut Value, overlay: Value) {
    merge_json_depth(target, overlay, 0);
}

fn merge_json_depth(target: &mut Value, overlay: Value, depth: usize) {
    match (target, overlay) {
        (Value::Object(target_map), Value::Object(overlay_map)) if depth < MERGE_MAX_DEPTH => {
            for (key, overlay_value) in overlay_map {
                merge_json_depth(
                    target_map.entry(key).or_insert(Value::Null),
                    overlay_value,
                    depth + 1,
                );
            }
        }
        (target, overlay) => *target = overlay,
    }
}

fn parse_to_value(settings_str: &str, format: &str) -> Result<Value> {
    match format.to_lowercase().as_str() {
        "json" => serde_json::from_str(settings_str)
            .map_err(|err| Error::BadParam(format!("could not parse configuration: {err}"))),
        "toml" => {
            let toml_value: toml::Value = toml::from_str(settings_str)
                .map_err(|err| Error::BadParam(format!("could not parse configuration: {err}")))?;
            serde_json::to_value(toml_value)
                .map_err(|err| Error::BadParam(format!("could not parse configuration: {err}")))
        }
        _ => Err(Error::UnsupportedType),
    }
}

fn set_at_path(target: &mut Value, path: &str, value: Value) -> Result<()> {
    let mut segments = path.split('.').peekable();
    let mut current = target;
    while let Some(segment) = segments.next() {
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        let Some(map) = current.as_object_mut() else {
            // Unreachable, but to be safe...
            return Err(Error::BadParam("expected object at path segment".into()));
        };
        if segments.peek().is_none() {
            map.insert(segment.to_string(), value);
            return Ok(());
        }
        current = map
            .entry(segment.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    Err(Error::BadParam("empty path".into()))
}

fn get_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// Get a snapshot of the thread-local Settings, always returns a valid Settings object.
/// If the thread-local settings cannot be deserialized, returns default Settings.
#[allow(unused)]
pub(crate) fn get_thread_local_settings() -> Settings {
    SETTINGS.with_borrow(|value| serde_json::from_value(value.clone()).unwrap_or_default())
}

/// See [Settings::set_thread_local_value] for more information.
#[cfg(test)]
pub(crate) fn set_settings_value<T: Into<Value>>(value_path: &str, value: T) -> Result<()> {
    Settings::set_thread_local_value(value_path, value)
}

/// See [Settings::get_thread_local_value] for more information.
#[cfg(test)]
fn get_settings_value<T: serde::de::DeserializeOwned>(value_path: &str) -> Result<T> {
    Settings::get_thread_local_value(value_path)
}

/// Reset all settings back to default values.
#[cfg(test)]
// #[deprecated = "use `Settings::reset` instead"]
pub fn reset_default_settings() -> Result<()> {
    Settings::reset()
}

// Used for backwards compatibility with the `config` crate.
pub(crate) fn deserialize_case_insensitive<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = Value::deserialize(deserializer)?;
    serde_json::from_value(normalize_enum_value(value)).map_err(serde::de::Error::custom)
}

// Used for backwards compatibility with the `config` crate.
pub(crate) fn deserialize_case_insensitive_opt<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    Option::<Value>::deserialize(deserializer)?
        .map(|v| serde_json::from_value(normalize_enum_value(v)).map_err(serde::de::Error::custom))
        .transpose()
}

// Used for backwards compatibility with the `config` crate.
fn normalize_enum_value(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(s.to_lowercase()),
        other => other,
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    #[cfg(feature = "file_io")]
    use crate::utils::io_utils::tempdirectory;
    use crate::{utils::test::test_settings, SigningAlg};

    /// Legacy test: verifies the thread-local settings API reads defaults and round-trips values.
    #[test]
    fn test_thread_local_settings() {
        // Verify defaults are accessible via thread-local
        let settings = get_thread_local_settings();
        assert_eq!(settings.core, Core::default());
        assert_eq!(settings.trust, Trust::default());
        assert_eq!(settings.verify, Verify::default());
        assert_eq!(settings.builder, BuilderSettings::default());

        // Verify individual values can be read by path
        assert_eq!(
            get_settings_value::<bool>("builder.thumbnail.enabled").unwrap(),
            BuilderSettings::default().thumbnail.enabled
        );
        assert_eq!(
            get_settings_value::<bool>("verify.remote_manifest_fetch").unwrap(),
            Verify::default().remote_manifest_fetch
        );

        // Verify set/get round-trip via thread-local API
        Settings::set_thread_local_value("core.merkle_tree_chunk_size_in_kb", 10).unwrap();
        Settings::set_thread_local_value("verify.remote_manifest_fetch", false).unwrap();
        Settings::set_thread_local_value("builder.thumbnail.enabled", false).unwrap();

        assert_eq!(
            get_settings_value::<usize>("core.merkle_tree_chunk_size_in_kb").unwrap(),
            10
        );
        assert!(!get_settings_value::<bool>("verify.remote_manifest_fetch").unwrap());
        assert!(!get_settings_value::<bool>("builder.thumbnail.enabled").unwrap());

        reset_default_settings().unwrap();
    }

    #[cfg(feature = "file_io")]
    #[test]
    fn test_save_load() {
        let temp_dir = tempdirectory().unwrap();
        let op = crate::utils::test::temp_dir_path(&temp_dir, "sdk_config.json");

        let settings_json = serde_json::to_string_pretty(&Settings::default()).unwrap();
        std::fs::write(&op, settings_json.as_bytes()).unwrap();

        let settings = Settings::new().with_file(&op).unwrap();
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn test_settings_from_json_str() {
        // Verify that Settings round-trips through JSON without touching thread-local state.
        let json = serde_json::to_string(&Settings::default()).unwrap();
        let settings = Settings::new().with_json(&json).unwrap();
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn test_bad_setting() {
        // Verify that type-invalid TOML values are rejected without touching thread-local state.
        let modified_core = toml::toml! {
            [core]
            merkle_tree_chunk_size_in_kb = true
            merkle_tree_max_proofs = "sha1000000"
            backing_store_memory_threshold_in_mb = -123456
            max_decompressed_manifest_size_in_mb = -123456
        }
        .to_string();

        assert!(Settings::new().with_toml(&modified_core).is_err());
    }

    #[test]
    fn test_core_validate_rejects_oversized_manifest_cap() {
        let result =
            Settings::default().with_value("core.max_decompressed_manifest_size_in_mb", 1025usize);
        assert!(result.is_err());
    }

    /// Legacy test: verifies arbitrary (hidden) keys can be stored and retrieved via the
    /// thread-local Figment config. This is not possible with the instance-based API since
    /// unknown keys are not part of the `Settings` struct.
    #[test]
    #[allow(deprecated)]
    fn test_thread_local_hidden_setting() {
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
    fn test_load_settings_from_sample_toml() {
        let toml = include_bytes!("../../examples/c2pa.toml");
        Settings::new()
            .with_toml(std::str::from_utf8(toml).unwrap())
            .unwrap();
    }

    #[test]
    fn test_update_from_str_toml() {
        let mut settings = Settings::default();

        // Check defaults
        assert!(settings.verify.verify_after_reading);
        assert!(settings.verify.verify_trust);

        // Set both to false
        settings
            .update_from_str(
                r#"
            [verify]
            verify_after_reading = false
            verify_trust = false
        "#,
                "toml",
            )
            .unwrap();

        assert!(!settings.verify.verify_after_reading);
        assert!(!settings.verify.verify_trust);

        // Override: set one to true, keep other false
        settings
            .update_from_str(
                r#"
            [verify]
            verify_after_reading = true
        "#,
                "toml",
            )
            .unwrap();

        assert!(settings.verify.verify_after_reading);
        assert!(!settings.verify.verify_trust);
    }

    #[test]
    fn test_update_from_str_json() {
        let mut settings = Settings::default();

        // Check defaults
        assert!(settings.verify.verify_after_reading);
        assert!(settings.verify.verify_trust);
        assert!(settings.builder.created_assertion_labels.is_none());

        // Set both to false and set created_assertion_labels
        settings
            .update_from_str(
                r#"
            {
                "verify": {
                    "verify_after_reading": false,
                    "verify_trust": false
                },
                "builder": {
                    "created_assertion_labels": ["c2pa.metadata"]
                }
            }
        "#,
                "json",
            )
            .unwrap();

        assert!(!settings.verify.verify_after_reading);
        assert!(!settings.verify.verify_trust);
        assert_eq!(
            settings.builder.created_assertion_labels,
            Some(vec!["c2pa.metadata".to_string()])
        );

        // Override: set one to true, keep other false
        settings
            .update_from_str(
                r#"
            {
                "verify": {
                    "verify_after_reading": true
                }
            }
        "#,
                "json",
            )
            .unwrap();

        assert!(settings.verify.verify_after_reading);
        assert!(!settings.verify.verify_trust);
        assert_eq!(
            settings.builder.created_assertion_labels,
            Some(vec!["c2pa.metadata".to_string()])
        );

        // Set created_assertion_labels back to null
        settings
            .update_from_str(
                r#"
            {
                "builder": {
                    "created_assertion_labels": null
                }
            }
        "#,
                "json",
            )
            .unwrap();

        assert!(settings.verify.verify_after_reading);
        assert!(!settings.verify.verify_trust);
        assert!(settings.builder.created_assertion_labels.is_none());
    }

    #[test]
    fn test_update_from_str_invalid() {
        assert!(Settings::default()
            .update_from_str("invalid toml { ]", "toml")
            .is_err());
        assert!(Settings::default()
            .update_from_str("{ invalid json }", "json")
            .is_err());
        assert!(Settings::default().update_from_str("data", "yaml").is_err());
    }

    #[test]
    fn test_instance_with_value() {
        // Test builder pattern with with_value
        let settings = Settings::default()
            .with_value("verify.verify_trust", false)
            .unwrap()
            .with_value("core.merkle_tree_chunk_size_in_kb", 1024i64)
            .unwrap()
            .with_value("builder.thumbnail.enabled", false)
            .unwrap();

        assert!(!settings.verify.verify_trust);
        assert_eq!(settings.core.merkle_tree_chunk_size_in_kb, Some(1024));
        assert!(!settings.builder.thumbnail.enabled);
    }

    #[test]
    fn test_instance_set_value() {
        // Test mutable set_value
        let mut settings = Settings::default();

        settings.set_value("verify.verify_trust", true).unwrap();
        settings
            .set_value("core.merkle_tree_chunk_size_in_kb", 2048i64)
            .unwrap();
        settings
            .set_value("builder.thumbnail.enabled", false)
            .unwrap();

        assert!(settings.verify.verify_trust);
        assert_eq!(settings.core.merkle_tree_chunk_size_in_kb, Some(2048));
        assert!(!settings.builder.thumbnail.enabled);
    }

    #[test]
    fn test_instance_get_value() {
        let mut settings = Settings::default();
        settings.verify.verify_trust = false;
        settings.core.merkle_tree_chunk_size_in_kb = Some(512);

        // Test type inference
        let verify_trust: bool = settings.get_value("verify.verify_trust").unwrap();
        assert!(!verify_trust);

        // Test explicit type
        let chunk_size = settings
            .get_value::<Option<usize>>("core.merkle_tree_chunk_size_in_kb")
            .unwrap();
        assert_eq!(chunk_size, Some(512));
    }

    #[test]
    fn test_instance_methods_with_context() {
        // Test that instance methods work with Context
        use crate::Context;

        let settings = Settings::default()
            .with_value("verify.verify_after_sign", true)
            .unwrap()
            .with_value("verify.verify_trust", true)
            .unwrap();

        let _context = Context::new().with_settings(settings).unwrap();

        // If we get here without errors, the integration works
    }

    #[test]
    fn test_instance_value_error_handling() {
        // Test invalid type (trying to set string to bool field)
        let mut settings = Settings::default();
        let result = settings.set_value("verify.verify_trust", "not a bool");
        assert!(result.is_err());

        // Test get non-existent path
        let settings = Settings::default();
        let result = settings.get_value::<bool>("does.not.exist");
        assert!(result.is_err());

        // Test with_value on invalid type
        let result = Settings::default().with_value("verify.verify_trust", "not a bool");
        assert!(result.is_err());
    }

    #[test]
    fn test_test_settings() {
        // Test that test_settings loads correctly
        let settings = test_settings();

        // Verify it has trust anchors (test fixture includes multiple root CAs)
        assert!(
            settings.trust.trust_anchors.is_some(),
            "test_settings should include trust anchors"
        );
        assert!(
            !settings.trust.trust_anchors.as_ref().unwrap().is_empty(),
            "test_settings trust_anchors should not be empty"
        );

        // Verify it has a signer configured
        assert!(
            settings.signer.is_some(),
            "test_settings should include a signer"
        );

        // Verify we have a local signer with valid configuration
        if let Some(SignerSettings::Local { alg, .. }) = &settings.signer {
            // Just verify we have an algorithm set (validates the structure loaded correctly)
            assert!(
                matches!(
                    alg,
                    SigningAlg::Ps256
                        | SigningAlg::Es256
                        | SigningAlg::Es384
                        | SigningAlg::Es512
                        | SigningAlg::Ed25519
                ),
                "test_settings should have a valid signing algorithm"
            );
        } else {
            panic!("test_settings should have a Local signer configured");
        }
    }

    #[test]
    fn test_builder_pattern() {
        // Test Settings::new() with builder pattern
        let settings = Settings::new()
            .with_json(r#"{"verify": {"verify_trust": false}}"#)
            .unwrap();
        assert!(!settings.verify.verify_trust);

        // Test chaining with_json and with_value
        let settings = Settings::new()
            .with_json(r#"{"verify": {"verify_after_reading": false}}"#)
            .unwrap()
            .with_value("verify.verify_trust", true)
            .unwrap();
        assert!(!settings.verify.verify_after_reading);
        assert!(settings.verify.verify_trust);

        // Test with_toml
        let settings = Settings::new()
            .with_toml(
                r#"
                [verify]
                verify_trust = false
                verify_after_sign = false
                "#,
            )
            .unwrap();
        assert!(!settings.verify.verify_trust);
        assert!(!settings.verify.verify_after_sign);

        // Test that it doesn't update thread-locals
        let original = get_thread_local_settings();
        let _settings = Settings::new()
            .with_json(r#"{"verify": {"verify_trust": false}}"#)
            .unwrap();
        let after = get_thread_local_settings();
        // thread-local settings should be unchanged
        assert_eq!(
            original.verify.verify_trust, after.verify.verify_trust,
            "Builder pattern should not modify thread_local settings"
        );
    }

    #[test]
    fn test_loading_soft_binding_algorithms() {
        let settings = Settings::new()
            .with_json(
                r#"
                {
                    "soft_binding": {
                        "soft_binding_algorithms": ["com.adobe.trustmark.Q", "com.adobe.trustmark.C"]
                    }
                }
            "#,
            )
            .unwrap();

        assert_eq!(
            settings.soft_binding.soft_binding_algorithms,
            Some(vec![
                "com.adobe.trustmark.Q".to_string(),
                "com.adobe.trustmark.C".to_string()
            ])
        );
    }
}
