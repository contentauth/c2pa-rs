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

//! The Reader provides a way to read a manifest store from an asset.
//! It also performs validation on the manifest store.

#[cfg(feature = "file_io")]
use std::fs::{read, File};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Seek, Write},
    sync::Arc,
};

use async_generic::async_generic;
use async_trait::async_trait;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

#[cfg(feature = "file_io")]
use crate::utils::io_utils::uri_to_path;
use crate::{
    claim::Claim,
    context::Context,
    dynamic_assertion::PartialClaim,
    error::{Error, Result},
    jumbf::labels::{manifest_label_from_uri, to_absolute_uri, to_relative_uri},
    jumbf_io, log_item,
    manifest::StoreOptions,
    manifest_store_report::ManifestStoreReport,
    status_tracker::StatusTracker,
    store::Store,
    utils::hash_utils::hash_to_b64,
    validation_results::{ValidationResults, ValidationState},
    validation_status::{ValidationStatus, ASSERTION_MISSING, ASSERTION_NOT_REDACTED},
    Ingredient, Manifest, ManifestAssertion, Relationship,
};

/// MaybeSend allows for no Send bound on wasm32 targets
/// todo: move this to a common module
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// A trait for post-validation of manifest assertions.
pub trait PostValidator {
    fn validate(
        &self,
        label: &str,
        assertion: &ManifestAssertion,
        uri: &str,
        preliminary_claim: &PartialClaim,
        tracker: &mut StatusTracker,
    ) -> Result<Option<Value>>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncPostValidator {
    async fn validate(
        &self,
        label: &str,
        assertion: &ManifestAssertion,
        uri: &str,
        preliminary_claim: &PartialClaim,
        tracker: &mut StatusTracker,
    ) -> Result<Option<Value>>;
}

/// Use a Reader to read and validate a manifest store.
#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[derive(Default)]
pub struct Reader {
    /// A label for the active (most recent) manifest in the store
    active_manifest: Option<String>,

    /// A HashMap of Manifests
    manifests: HashMap<String, Manifest>,

    /// ValidationStatus generated when loading the ManifestStore from an asset
    validation_status: Option<Vec<ValidationStatus>>,

    /// ValidationStatus generated when loading the ManifestStore from an asset
    validation_results: Option<ValidationResults>,

    /// The validation state of the manifest store
    validation_state: Option<ValidationState>,

    #[serde(skip)]
    /// We keep this around so we can generate a detailed report if needed
    pub(crate) store: Store,

    #[serde(skip)]
    /// Map to hold post-validation assertion values for reports
    /// the key is an assertion uri and the value is the assertion value
    assertion_values: HashMap<String, Value>,

    #[serde(skip)]
    context: Arc<Context>,
}

impl Reader {
    /// Create a new Reader with the given [`Context`].
    ///
    /// This method takes ownership of the [`Context`] and wraps it in an [`Arc`] internally.
    /// Use this for single-use contexts where you don't need to share the context.
    ///
    /// # Arguments
    /// * `context` - The [`Context`] to use for the Reader
    ///
    /// # Returns
    /// A new Reader
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::{Context, Reader, Result};
    /// # fn main() -> Result<()> {
    /// let context = Context::new().with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?;
    /// let reader = Reader::from_context(context);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_context(context: Context) -> Self {
        Self {
            context: Arc::new(context),
            store: Store::new(),
            assertion_values: HashMap::new(),
            ..Default::default()
        }
    }

    /// Create a new Reader with a shared [`Context`].
    ///
    /// This method allows sharing a single [`Context`] across multiple builders or readers,
    /// even across threads. The [`Arc`] is cloned internally, so you pass a reference.
    ///
    /// # Arguments
    /// * `context` - A reference to an [`Arc<Context>`] to share.
    ///
    /// # Returns
    /// A new [`Reader`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use c2pa::{Context, Reader, Result};
    /// # use std::sync::Arc;
    /// # fn main() -> Result<()> {
    /// // Create a shared Context once
    /// let ctx = Arc::new(Context::new().with_settings(r#"{"verify": {"verify_after_sign": true}}"#)?);
    ///
    /// // Share it across multiple Readers (even across threads!)
    /// let reader1 = Reader::from_shared_context(&ctx);
    /// let reader2 = Reader::from_shared_context(&ctx);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_shared_context(context: &Arc<Context>) -> Self {
        Self {
            context: Arc::clone(context),
            store: Store::new(),
            assertion_values: HashMap::new(),
            ..Default::default()
        }
    }

    /// Add manifest store from a stream to the [`Reader`]
    /// # Arguments
    /// * `format` - The format of the stream.  MIME type or extension that maps to a MIME type.
    /// * `stream` - The stream to read from.  Must implement the Read and Seek traits.
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    #[async_generic]
    pub fn with_stream(
        mut self,
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();
        stream.rewind()?; // Ensure stream is at the start
        let store = if _sync {
            Store::from_stream(format, stream, &mut validation_log, &self.context)
        } else {
            Store::from_stream_async(format, stream, &mut validation_log, &self.context).await
        }?;

        if _sync {
            self.with_store(store, &mut validation_log)
        } else {
            self.with_store_async(store, &mut validation_log).await
        }?;
        Ok(self)
    }

    /// Create a manifest store [`Reader`] from a stream.  A Reader is used to validate C2PA data from an asset.
    ///
    /// # Arguments
    /// * `format` - The format of the stream.  MIME type or extension that maps to a MIME type.
    /// * `stream` - The stream to read from.  Must implement the Read and Seek traits.
    ///   Send trait is required for sync operations and Sync trait is required for async operations.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # Note
    /// [CAWG identity] assertions require async calls for validation.
    ///
    /// [CAWG identity]: https://cawg.io/identity/
    #[async_generic]
    pub fn from_stream(format: &str, stream: impl Read + Seek + MaybeSend) -> Result<Reader> {
        // Legacy behavior: explicitly get global settings for backward compatibility
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings)?;

        if _sync {
            Reader::from_context(context).with_stream(format, stream)
        } else {
            Reader::from_context(context)
                .with_stream_async(format, stream)
                .await
        }
    }

    #[cfg(feature = "file_io")]
    /// Add manifest store from a file to the [`Reader`].
    /// If the `fetch_remote_manifests` feature is enabled, and the asset refers to a remote manifest, the function fetches a remote manifest.
    ///
    /// NOTE: If the file does not have a manifest store, the function will check for a sidecar manifest with the same base file name and a .c2pa extension.
    ///
    /// # Arguments
    /// * `path` - The path to the file.
    ///
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    ///
    /// # Errors
    /// Returns an [`Error`] when the manifest data cannot be read from the specified file.  If there's no error upon reading, you must still check validation status to ensure that the manifest data is validated.  That is, even if there are no errors, the data still might not be valid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use c2pa::{Context, Reader};
    /// # fn main() -> c2pa::Result<()> {
    /// let reader = Reader::from_context(Context::new()).with_file("path/to/file.jpg")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    /// [CAWG identity] assertions require async calls for validation.
    ///
    /// [CAWG identity]: https://cawg.io/identity/
    #[async_generic]
    pub fn with_file<P: AsRef<std::path::Path>>(mut self, path: P) -> Result<Self> {
        let path = path.as_ref();
        let format = crate::format_from_path(path).ok_or(crate::Error::UnsupportedType)?;
        let mut file = File::open(path)?;

        // Try loading from stream first
        let mut validation_log = StatusTracker::default();
        let store = if _sync {
            Store::from_stream(&format, &mut file, &mut validation_log, &self.context)
        } else {
            Store::from_stream_async(&format, &mut file, &mut validation_log, &self.context).await
        };

        match store {
            Err(Error::JumbfNotFound) => {
                // if not embedded or cloud, check for sidecar first and load if it exists
                let potential_sidecar_path = path.with_extension("c2pa");
                if potential_sidecar_path.exists() {
                    let manifest_data = read(potential_sidecar_path)?;
                    validation_log = StatusTracker::default();
                    let store = if _sync {
                        Store::from_manifest_data_and_stream(
                            &manifest_data,
                            &format,
                            &mut file,
                            &mut validation_log,
                            &self.context,
                        )
                    } else {
                        Store::from_manifest_data_and_stream_async(
                            &manifest_data,
                            &format,
                            &mut file,
                            &mut validation_log,
                            &self.context,
                        )
                        .await
                    }?;
                    if _sync {
                        self.with_store(store, &mut validation_log)
                    } else {
                        self.with_store_async(store, &mut validation_log).await
                    }?;
                    Ok(self)
                } else {
                    Err(Error::JumbfNotFound)
                }
            }
            Ok(store) => {
                if _sync {
                    self.with_store(store, &mut validation_log)
                } else {
                    self.with_store_async(store, &mut validation_log).await
                }?;
                Ok(self)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a manifest store [`Reader`] from a file.
    /// If the `fetch_remote_manifests` feature is enabled, and the asset refers to a remote manifest, the function fetches a remote manifest.
    ///
    /// NOTE: If the file does not have a manifest store, the function will check for a sidecar manifest with the same base file name and a .c2pa extension.
    ///
    /// # Arguments
    /// * `path` - The path to the file.
    ///
    /// # Returns
    /// A [`Reader`] for the manifest store.
    ///
    /// # Errors
    /// Returns an [`Error`] when the manifest data cannot be read from the specified file.  If there's no error upon reading, you must still check validation status to ensure that the manifest data is validated.  That is, even if there are no errors, the data still might not be valid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use c2pa::Reader;
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// ```
    ///
    /// # Note
    /// [CAWG identity] assertions require async calls for validation.
    ///
    /// [CAWG identity]: https://cawg.io/identity/
    #[cfg(feature = "file_io")]
    #[async_generic]
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Reader> {
        // Legacy behavior: explicitly get thread-local settings for backward compatibility
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings)?;

        if _sync {
            Reader::from_context(context).with_file(path)
        } else {
            Reader::from_context(context).with_file_async(path).await
        }
    }

    /// Create a manifest store [`Reader`] from a JSON string.
    /// # Arguments
    /// * `json` - A JSON string containing a manifest store definition.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # WARNING
    /// This function is intended for use in testing. Don't use it in an implementation.
    pub fn from_json(json: &str) -> Result<Reader> {
        serde_json::from_str(json).map_err(crate::Error::JsonError)
    }

    /// Add manifest store from existing `c2pa_data` and a stream to the [`Reader`].
    /// Use this to validate a remote manifest or a sidecar manifest.
    /// # Arguments
    /// * `c2pa_data` - A C2PA manifest store in JUMBF format.
    /// * `format` - The format of the stream.
    /// * `stream` - The stream to verify the store against.
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    /// # Errors
    /// This function returns an [`Error`] if the c2pa_data is not valid, or severe errors occur in validation.
    /// You must check validation status for non-severe errors.
    #[async_generic]
    pub fn with_manifest_data_and_stream(
        mut self,
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();

        let store = if _sync {
            Store::from_manifest_data_and_stream(
                c2pa_data,
                format,
                stream,
                &mut validation_log,
                &self.context,
            )
        } else {
            Store::from_manifest_data_and_stream_async(
                c2pa_data,
                format,
                stream,
                &mut validation_log,
                &self.context,
            )
            .await
        }?;
        if _sync {
            self.with_store(store, &mut validation_log)
        } else {
            self.with_store_async(store, &mut validation_log).await
        }?;
        Ok(self)
    }

    /// Create a manifest store [`Reader`] from existing `c2pa_data` and a stream.
    /// Use this to validate a remote manifest or a sidecar manifest.
    /// # Arguments
    /// * `c2pa_data` - A C2PA manifest store in JUMBF format.
    /// * `format` - The format of the stream.
    /// * `stream` - The stream to verify the store against.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # Errors
    /// This function returns an [`Error`] ef the c2pa_data is not valid, or severe errors occur in validation.
    /// You must check validation status for non-severe errors.
    #[async_generic]
    pub fn from_manifest_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Reader> {
        // Get thread-local settings (if any) for backward compatibility
        let settings = crate::settings::get_thread_local_settings();
        let context = Context::new().with_settings(settings).unwrap_or_default();
        if _sync {
            Reader::from_context(context).with_manifest_data_and_stream(c2pa_data, format, stream)
        } else {
            Reader::from_context(context)
                .with_manifest_data_and_stream_async(c2pa_data, format, stream)
                .await
        }
    }

    /// Add manifest store from an initial segment and a fragment stream to the [`Reader`].
    /// This would be used to load and validate fragmented MP4 files that span multiple separate asset files.
    /// # Arguments
    /// * `format` - The format of the stream.
    /// * `stream` - The initial segment stream.
    /// * `fragment` - The fragment stream.
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    /// # Errors
    /// This function returns an [`Error`] if the streams are not valid, or severe errors occur in validation.
    /// You must check validation status for non-severe errors.
    #[async_generic]
    pub fn with_fragment(
        mut self,
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
        mut fragment: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();

        let store = if _sync {
            Store::load_fragment_from_stream(
                format,
                &mut stream,
                &mut fragment,
                &mut validation_log,
                &self.context,
            )
        } else {
            Store::load_fragment_from_stream_async(
                format,
                &mut stream,
                &mut fragment,
                &mut validation_log,
                &self.context,
            )
            .await
        }?;

        if _sync {
            self.with_store(store, &mut validation_log)
        } else {
            self.with_store_async(store, &mut validation_log).await
        }?;
        Ok(self)
    }

    /// Create a [`Reader`] from an initial segment and a fragment stream.
    /// This would be used to load and validate fragmented MP4 files that span multiple separate asset files.
    /// # Arguments
    /// * `format` - The format of the stream.
    /// * `stream` - The initial segment stream.
    /// * `fragment` - The fragment stream.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # Errors
    /// This function returns an [`Error`] if the streams are not valid, or severe errors occur in validation.
    /// You must check validation status for non-severe errors.
    #[async_generic]
    pub fn from_fragment(
        format: &str,
        stream: impl Read + Seek + MaybeSend,
        fragment: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        if _sync {
            Reader::from_context(Context::new()).with_fragment(format, stream, fragment)
        } else {
            Reader::from_context(Context::new())
                .with_fragment_async(format, stream, fragment)
                .await
        }
    }

    /// Add manifest store from an initial segment and fragments to the [`Reader`].
    /// This would be used to load and validate fragmented MP4 files that span
    /// multiple separate asset files.
    /// # Arguments
    /// * `path` - The path to the initial segment file.
    /// * `fragments` - A vector of paths to fragment files.
    /// # Returns
    /// The updated [`Reader`] with the added manifest store.
    /// # Errors
    /// Returns an [`Error`] when the manifest data cannot be read from the specified files.
    #[cfg(feature = "file_io")]
    pub fn with_fragmented_files<P: AsRef<std::path::Path>>(
        mut self,
        path: P,
        fragments: &Vec<std::path::PathBuf>,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();

        let asset_type = jumbf_io::get_supported_file_extension(path.as_ref())
            .ok_or(crate::Error::UnsupportedType)?;

        let mut init_segment = std::fs::File::open(path.as_ref())?;

        match Store::load_from_file_and_fragments(
            &asset_type,
            &mut init_segment,
            fragments,
            &mut validation_log,
            &self.context,
        ) {
            Ok(store) => {
                self.with_store(store, &mut validation_log)?;
                Ok(self)
            }
            Err(e) => Err(e),
        }
    }

    /// Loads a [`Reader`]` from an initial segment and fragments.  This
    /// would be used to load and validate fragmented MP4 files that span
    /// multiple separate asset files.
    #[cfg(feature = "file_io")]
    pub fn from_fragmented_files<P: AsRef<std::path::Path>>(
        path: P,
        fragments: &Vec<std::path::PathBuf>,
    ) -> Result<Reader> {
        Reader::from_context(Context::new()).with_fragmented_files(path, fragments)
    }

    /// Returns a [Vec] of mime types that [c2pa-rs] is able to read.
    pub fn supported_mime_types() -> Vec<String> {
        jumbf_io::supported_reader_mime_types()
    }

    /// replace assertion values in the reader json with the values from the assertion_values map
    /// # Arguments
    /// * `reader_json` - The reader json to update
    /// # Returns
    /// The updated reader json
    fn to_json_formatted(&self) -> Result<Value> {
        let mut json = serde_json::to_value(self).map_err(Error::JsonError)?;

        // If we ran post-validation, we need to update the assertion values in the report
        if !self.assertion_values.is_empty() {
            if let Some(manifests) = json.get_mut("manifests").and_then(|m| m.as_object_mut()) {
                for (manifest_label, manifest) in manifests.iter_mut() {
                    // Get assertions array once instead of multiple lookups
                    if let Some(assertions) = manifest
                        .get_mut("assertions")
                        .and_then(|a| a.as_array_mut())
                    {
                        for assertion in assertions.iter_mut() {
                            // Get label once and reuse
                            if let Some(label) = assertion.get("label").and_then(|l| l.as_str()) {
                                let uri =
                                    crate::jumbf::labels::to_assertion_uri(manifest_label, label);
                                if let Some(value) = self.assertion_values.get(&uri) {
                                    // Only create new string if we need to insert
                                    if let Some(assertion_mut) = assertion.as_object_mut() {
                                        assertion_mut.insert("data".to_string(), value.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Convert hash values to base64 strings
        Ok(hash_to_b64(json))
    }

    /// Convert the reader to a JSON value with detailed formatting.
    /// This view more closely resembles the original JUMBF manifest store.
    fn to_json_detailed_formatted(&self) -> Result<Value> {
        let report = match self.validation_results() {
            Some(results) => ManifestStoreReport::from_store_with_results(&self.store, results),
            None => ManifestStoreReport::from_store(&self.store),
        }?;

        let mut json = serde_json::to_value(report).map_err(Error::JsonError)?;

        // If we ran post-validation, we need to update the assertion values in the report
        if !self.assertion_values.is_empty() {
            if let Some(manifests) = json.get_mut("manifests").and_then(|m| m.as_object_mut()) {
                for (manifest_label, manifest) in manifests.iter_mut() {
                    if let Some(assertions) = manifest
                        .get_mut("assertion_store")
                        .and_then(|a| a.as_object_mut())
                    {
                        for (label, assertion) in assertions.iter_mut() {
                            let uri = crate::jumbf::labels::to_assertion_uri(manifest_label, label);
                            if let Some(value) = self.assertion_values.get(&uri) {
                                *assertion = value.clone();
                            }
                        }
                    }
                }
            }
        }
        // Convert hash values to base64 strings
        json = hash_to_b64(json);
        Ok(json)
    }

    /// Get the Reader as a JSON string
    /// This just calls to_json_formatted
    pub fn json(&self) -> String {
        self.json_checked().unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the Reader as a JSON string, returning an error if formatting fails
    ///
    /// This is useful when you need to handle errors from deeply nested or malformed structures.
    /// For a version that never fails, use [`Self::json()`].
    pub fn json_checked(&self) -> Result<String> {
        let value = self.to_json_formatted()?;
        serde_json::to_string_pretty(&value).map_err(Error::JsonError)
    }

    /// Get the Reader as a detailed JSON string
    /// This just calls to_json_detailed_formatted
    pub fn detailed_json(&self) -> String {
        self.detailed_json_checked()
            .unwrap_or_else(|_| "{}".to_string())
    }

    /// Get the Reader as a detailed JSON string, returning an error if formatting fails
    ///
    /// This is useful when you need to handle errors from deeply nested or malformed structures.
    /// For a version that never fails, use [`Self::detailed_json()`].
    pub fn detailed_json_checked(&self) -> Result<String> {
        let value = self.to_json_detailed_formatted()?;
        serde_json::to_string_pretty(&value).map_err(Error::JsonError)
    }

    /// Returns the remote url of the manifest if this [`Reader`] obtained the manifest remotely.
    pub fn remote_url(&self) -> Option<&str> {
        self.store.remote_url()
    }

    /// Returns if the [`Reader`] was created from an embedded manifest.
    pub fn is_embedded(&self) -> bool {
        self.store.is_embedded()
    }

    /// Get the [`ValidationStatus`] array of the manifest store if it exists.
    /// Call this method to check for validation errors.
    ///
    /// This validation report only includes error statuses applied to the active manifest
    /// and error statuses for ingredients that are not already reported by the ingredient status.
    /// Use the [`ValidationStatus`] `url` method to identify the associated manifest; this can be useful when a validation error does not refer to the active manifest.
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let stream = std::io::Cursor::new(include_bytes!("../tests/fixtures/CA.jpg"));
    /// let reader = Reader::from_stream("image/jpeg", stream).unwrap();
    /// let status = reader.validation_status();
    /// ```
    pub fn validation_status(&self) -> Option<&[ValidationStatus]> {
        self.validation_status.as_deref()
    }

    /// Get the [`ValidationResults`] map of an asset if it exists.
    ///
    /// Call this method to check for detailed validation results.
    /// The validation_state method should be used to determine the overall validation state.
    ///
    /// The results are divided between the active manifest and ingredient deltas.
    /// The deltas will only exist if there are validation errors not already reported in ingredients
    /// It is normal for there to be many success and information statuses.
    /// Any errors will be reported in the failure array.
    ///
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let stream = std::io::Cursor::new(include_bytes!("../tests/fixtures/CA.jpg"));
    /// let reader = Reader::from_stream("image/jpeg", stream).unwrap();
    /// let status = reader.validation_results();
    /// ```
    pub fn validation_results(&self) -> Option<&ValidationResults> {
        self.validation_results.as_ref()
    }

    /// Get the [`ValidationState`] of the manifest store.
    pub fn validation_state(&self) -> ValidationState {
        if let Some(validation_results) = self.validation_results() {
            return validation_results.validation_state();
        }

        let verify_trust = self.context.settings().verify.verify_trust;
        match self.validation_status() {
            Some(status) => {
                // if there are any errors, the state is invalid unless the only error is an untrusted credential
                let errs = status
                    .iter()
                    .any(|s| s.code() != crate::validation_status::SIGNING_CREDENTIAL_UNTRUSTED);
                if errs {
                    ValidationState::Invalid
                } else if verify_trust {
                    // If we verified trust and didn't get an error, we can assume it is trusted
                    ValidationState::Trusted
                } else {
                    ValidationState::Valid
                }
            }
            None => {
                if verify_trust {
                    // if we are verifying trust, and there is no validation status, we can assume it is trusted
                    ValidationState::Trusted
                } else {
                    ValidationState::Valid
                }
            }
        }
    }

    /// Return the active [`Manifest`], or `None` if there's no active manifest.
    pub fn active_manifest(&self) -> Option<&Manifest> {
        if let Some(label) = self.active_manifest.as_ref() {
            self.manifests.get(label)
        } else {
            None
        }
    }

    /// Return the active [`Manifest`], or `None` if there's no active manifest.
    pub fn active_label(&self) -> Option<&str> {
        self.active_manifest.as_deref()
    }

    /// Returns an iterator over a collection of [`Manifest`] structs.
    pub fn iter_manifests(&self) -> impl Iterator<Item = &Manifest> + '_ {
        self.manifests.values()
    }

    /// Returns a reference to the [`Manifest`] collection.
    pub fn manifests(&self) -> &HashMap<String, Manifest> {
        &self.manifests
    }

    /// Given a label, return the associated [`Manifest`], if it exists.
    /// # Arguments
    /// * `label` - The label of the requested [`Manifest`].
    pub fn get_manifest(&self, label: &str) -> Option<&Manifest> {
        self.manifests.get(label)
    }

    /// Write a resource identified by URI to the given stream.
    /// Use this function, for example, to get a thumbnail or icon image and write it to a stream.
    /// # Arguments
    /// * `uri` - The URI of the resource to write (from an identifier field).
    /// * `stream` - The stream to write to.
    /// # Returns
    /// The number of bytes written.
    /// # Errors
    /// Returns [`Error`] if the resource does not exist.
    ///
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// #[cfg(feature = "file_io")]
    /// {
    ///     let stream = std::io::Cursor::new(Vec::new());
    ///     let reader = Reader::from_file("path/to/file.jpg").unwrap();
    ///     let manifest = reader.active_manifest().unwrap();
    ///     let uri = &manifest.thumbnail_ref().unwrap().identifier;
    ///     let bytes_written = reader.resource_to_stream(uri, stream).unwrap();
    /// }
    /// ```
    /// TODO: Fix the example to not read from a file.
    pub fn resource_to_stream(
        &self,
        uri: &str,
        stream: impl Write + Read + Seek + MaybeSend,
    ) -> Result<usize> {
        // get the manifest referenced by the uri, or the active one if None
        // add logic to search for local or absolute uri identifiers
        let (manifest, label) = match manifest_label_from_uri(uri) {
            Some(label) => (self.manifests.get(&label), label),
            None => (
                self.active_manifest(),
                self.active_label().unwrap_or_default().to_string(),
            ),
        };
        let relative_uri = to_relative_uri(uri);
        let absolute_uri = to_absolute_uri(&label, uri);

        if let Some(manifest) = manifest {
            let find_resource = |uri: &str| -> Result<&crate::ResourceStore> {
                let mut resources = manifest.resources();
                if !resources.exists(uri) {
                    // also search ingredients resources to support Reader model
                    for ingredient in manifest.ingredients() {
                        if ingredient.resources().exists(uri) {
                            resources = ingredient.resources();
                            return Ok(resources);
                        }
                    }
                } else {
                    return Ok(resources);
                }
                Err(Error::ResourceNotFound(uri.to_owned()))
            };
            let result = find_resource(&relative_uri);
            match result {
                Ok(resource) => resource.write_stream(&relative_uri, stream),
                Err(_) => match find_resource(&absolute_uri) {
                    Ok(resource) => resource.write_stream(&absolute_uri, stream),
                    Err(e) => Err(e),
                },
            }
        } else {
            Err(Error::ResourceNotFound(uri.to_owned()))
        }
        .map(|size| size as usize)
    }

    /// Write all resources to a folder.
    ///
    ///
    /// This function writes all resources to a folder.
    /// Resources are stored in sub-folders corresponding to manifest label.
    /// Conversions ensure the file paths are valid.
    ///
    /// # Arguments
    /// * `path` - The path to the folder to write to.
    /// # Errors
    /// Returns an [`Error`] if the resources cannot be written to the folder.
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// reader.to_folder("path/to/folder").unwrap();
    /// ```
    #[cfg(feature = "file_io")]
    pub fn to_folder<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.as_ref().join("manifest_store.json"), self.json())?;
        let c2pa_data = self.store.to_jumbf_internal(0)?;
        std::fs::write(path.as_ref().join("manifest_data.c2pa"), c2pa_data)?;
        for manifest in self.manifests.values() {
            let resources = manifest.resources();
            for (uri, data) in resources.resources() {
                let id_path = uri_to_path(uri, manifest.label());
                let path = path.as_ref().join(id_path);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut file = std::fs::File::create(&path)?;
                file.write_all(data)?;
            }
        }
        Ok(())
    }

    #[async_generic()]
    pub(crate) fn with_store(
        &mut self,
        store: Store,
        validation_log: &mut StatusTracker,
    ) -> Result<&Self> {
        let active_manifest = store.provenance_label();
        let mut manifests = HashMap::new();
        let mut options = StoreOptions::default();

        for claim in store.claims() {
            let manifest_label = claim.label();
            let result = if _sync {
                Manifest::from_store(
                    &store,
                    manifest_label,
                    &mut options,
                    validation_log,
                    self.context.settings(),
                )
            } else {
                Manifest::from_store_async(
                    &store,
                    manifest_label,
                    &mut options,
                    validation_log,
                    self.context.settings(),
                )
                .await
            };

            match result {
                Ok(mut manifest) => {
                    // Generate manifest_data for ingredients
                    Self::populate_ingredient_manifest_data(&store, &mut manifest)?;
                    manifests.insert(manifest_label.to_owned(), manifest);
                }
                Err(e) => {
                    let uri = crate::jumbf::labels::to_manifest_uri(manifest_label);
                    let code = ValidationStatus::code_from_error(&e);
                    log_item!(uri.clone(), "Failed to load manifest", "Reader::from_store")
                        .validation_status(code)
                        .failure(validation_log, Error::C2PAValidation(e.to_string()))?;
                }
            };
        }

        let validation_results = ValidationResults::from_store(&store, validation_log);

        // resolve redactions
        // Even though we validate
        // compare options.redacted_assertions and options.missing_assertions
        // remove all overlapping values from both arrays
        // any remaining redacted assertions are not actually redacted
        // any remaining missing assertions are not actually missing

        let mut redacted = options.redacted_assertions.clone();
        let mut missing = options.missing_assertions.clone();
        redacted.retain(|item| !missing.contains(item));
        missing.retain(|item| !options.redacted_assertions.contains(item));

        // Add any remaining redacted assertions to the validation results
        for uri in &redacted {
            log_item!(uri.clone(), "assertion not redacted", "Reader::from_store")
                .validation_status(ASSERTION_NOT_REDACTED)
                .informational(validation_log);
        }

        for uri in &missing {
            log_item!(uri.clone(), "assertion missing", "Reader::from_store")
                .validation_status(ASSERTION_MISSING)
                .informational(validation_log);
        }

        let validation_state = validation_results.validation_state();

        self.active_manifest = active_manifest;
        self.manifests = manifests;
        self.validation_status = validation_results.validation_errors();
        self.validation_results = Some(validation_results);
        self.validation_state = Some(validation_state);
        self.store = store;
        Ok(self)
    }

    /// Populate manifest_data references for all ingredients in a manifest
    fn populate_ingredient_manifest_data(store: &Store, manifest: &mut Manifest) -> Result<()> {
        for ingredient in manifest.ingredients_mut() {
            if let Some(active_label) = ingredient.active_manifest() {
                if let Some(claim) = store.get_claim(active_label) {
                    // Generate the ingredient store with all referenced claims
                    let ingredient_store = {
                        let mut ingredient_store = Store::new();
                        let mut active_claim = claim.clone();

                        // Recursively collect all ingredient claims
                        Self::collect_ingredient_claims_for_store(store, claim, &mut active_claim)?;

                        // Add the main claim
                        ingredient_store.commit_claim(active_claim)?;
                        ingredient_store
                    };

                    let c2pa_data = ingredient_store.to_jumbf_internal(0)?;

                    // Create a unique resource name based on the ingredient's active manifest label
                    // This ensures each ingredient has a uniquely identifiable manifest_data resource
                    let resource_name = format!("{}/manifest_data", active_label.replace('/', "_"));

                    let manifest_data_ref = ingredient.resources_mut().add_with(
                        &resource_name,
                        "application/c2pa",
                        c2pa_data,
                    )?;

                    ingredient.set_manifest_data_ref(manifest_data_ref)?;
                }
            }
        }
        Ok(())
    }

    /// Helper method to recursively collect ingredient claims for a store
    fn collect_ingredient_claims_for_store(
        store: &Store,
        claim: &Claim,
        active_claim: &mut Claim,
    ) -> Result<()> {
        let mut visited = std::collections::HashSet::new();
        let mut path = Vec::new();
        Self::collect_ingredient_claims_for_store_impl(
            store,
            claim,
            active_claim,
            &mut visited,
            &mut path,
        )
    }

    /// Uses the similar cycle detection strategy as Store::get_claim_referenced_manifests_impl
    fn collect_ingredient_claims_for_store_impl(
        store: &Store,
        claim: &Claim,
        active_claim: &mut Claim,
        visited: &mut std::collections::HashSet<String>,
        path: &mut Vec<String>,
    ) -> Result<()> {
        Self::collect_ingredient_claims_impl(store, claim, active_claim, visited, path)
    }

    /// Shared implementation for recursively collecting ingredient claims.
    ///
    /// Uses path-based cycle detection similar to Store::get_claim_referenced_manifests_impl:
    /// - `visited`: Claims that have been fully processed (allows DAG convergence)
    /// - `path`: Current traversal path to detect and skip cycles
    fn collect_ingredient_claims_impl(
        store: &Store,
        claim: &Claim,
        active_claim: &mut Claim,
        visited: &mut std::collections::HashSet<String>,
        path: &mut Vec<String>,
    ) -> Result<()> {
        let claim_label = claim.label();

        if visited.contains(claim_label) {
            return Ok(());
        }

        // Check for cycle: is this claim already in our current path?
        // If so, skip it silently (validation should have already caught this when enabled)
        if path.iter().any(|p| p == claim_label) {
            return Ok(());
        }

        path.push(claim_label.to_string());

        for ingredient in claim.claim_ingredients() {
            let ingredient_label = ingredient.label();

            if let Some(ingredient_claim) = store.get_claim(ingredient_label) {
                Self::collect_ingredient_claims_impl(
                    store,
                    ingredient_claim,
                    active_claim,
                    visited,
                    path,
                )?;

                // Then add this ingredient claim to the primary claim
                active_claim.replace_ingredient_or_insert(
                    ingredient_claim.label().to_string(),
                    ingredient_claim.clone(),
                );
            }
        }

        // Mark as fully processed
        visited.insert(claim_label.to_string());

        // Remove from current path
        path.pop();

        Ok(())
    }

    /// Post-validate the reader. This function is called after the reader is created.
    #[async_generic(async_signature(
        &mut self,
        validator: &impl AsyncPostValidator
    ))]
    pub fn post_validate(&mut self, validator: &impl PostValidator) -> Result<()> {
        let mut validation_log = StatusTracker::default();
        let mut validation_results = self.validation_results.take().unwrap_or_default();
        let mut assertion_values = HashMap::new();
        if let Some(active_label) = self.active_label() {
            let values = if _sync {
                self.walk_manifest(active_label, validator, &mut validation_log)
            } else {
                self.walk_manifest_async(active_label, validator, &mut validation_log)
                    .await
            }?;
            assertion_values.extend(values);
            for log in validation_log.logged_items() {
                if let Some(status) = ValidationStatus::from_log_item(log) {
                    validation_results.add_status(status);
                } else {
                    eprintln!("Failed to create status from log item: {log:?}");
                }
            }
        }
        self.validation_results = Some(validation_results);
        self.assertion_values.extend(assertion_values);
        Ok(())
    }

    #[async_generic(async_signature(
        &self,
        manifest_label: &str,
        validator: &impl AsyncPostValidator,
        validation_log: &mut StatusTracker
    ))]
    fn walk_manifest(
        &self,
        manifest_label: &str,
        validator: &impl PostValidator,
        validation_log: &mut StatusTracker,
    ) -> Result<HashMap<String, Value>> {
        let mut assertion_values = HashMap::new();
        let mut stack: Vec<(String, Option<String>)> = vec![(manifest_label.to_string(), None)];
        let mut seen = HashSet::new();

        while let Some((current_label, parent_uri)) = stack.pop() {
            seen.insert(current_label.clone());

            // If we're processing an ingredient, push its URI to the validation log
            if let Some(uri) = &parent_uri {
                validation_log.push_ingredient_uri(uri.clone());
            }

            let manifest = match self.get_manifest(&current_label) {
                Some(m) => m,
                None => {
                    // skip this manifest if not found
                    continue;
                }
            };

            let mut partial_claim = crate::dynamic_assertion::PartialClaim::default();
            {
                if let Some(claim) = self.store.get_claim(&current_label) {
                    for assertion in claim.assertions() {
                        partial_claim.add_assertion(assertion);
                    }
                }
            }

            // Process assertions for current manifest
            for assertion in manifest.assertions().iter() {
                let assertion_uri =
                    crate::jumbf::labels::to_assertion_uri(&current_label, assertion.label());
                let result = if _sync {
                    validator.validate(
                        assertion.label(),
                        assertion,
                        &assertion_uri,
                        &partial_claim,
                        validation_log,
                    )
                } else {
                    validator
                        .validate(
                            assertion.label(),
                            assertion,
                            &assertion_uri,
                            &partial_claim,
                            validation_log,
                        )
                        .await
                }?;
                if let Some(value) = result {
                    assertion_values.insert(assertion_uri, value);
                }
            }

            // Add ingredients to stack for processing
            for ingredient in manifest.ingredients().iter() {
                if let Some(label) = ingredient.active_manifest() {
                    if !seen.contains(label) {
                        let ingredient_uri = crate::jumbf::labels::to_assertion_uri(
                            &current_label,
                            ingredient.label().unwrap_or("unknown"),
                        );
                        stack.push((label.to_string(), Some(ingredient_uri)));
                    }
                }
            }

            // If we're processing an ingredient, pop its URI from the validation log
            if parent_uri.is_some() {
                validation_log.pop_ingredient_uri();
            }
        }

        Ok(assertion_values)
    }

    /// Convert the Reader back into a Builder.
    ///
    /// This method handles three different cases:
    /// 1. **Builder Archive**: Restores the builder with ingredient stores properly rebuilt
    /// 2. **Archived Ingredient**: Creates a new builder with the archived ingredient
    /// 3. **Regular C2PA Manifest**: Converts the entire Reader into a parent ingredient in a new builder
    ///
    /// # Errors
    /// Returns an [`Error`] if there is no active manifest.
    pub fn into_builder(self) -> Result<crate::Builder> {
        match self.manifest_type() {
            ManifestType::ArchivedBuilder => {
                // Builder archive: rebuild ingredients from unified store
                self.manifest_into_builder()
            }
            ManifestType::ArchivedIngredient => {
                // Archived ingredient: extract and add to new builder
                let ingredient = self
                    .active_manifest()
                    .and_then(|m| m.ingredients().first())
                    .ok_or(Error::IngredientNotFound)?
                    .to_owned();

                let mut builder = crate::Builder::from_shared_context(&self.context);
                builder.add_ingredient(ingredient);
                Ok(builder)
            }
            ManifestType::SignedManifest => {
                // Regular manifest: use existing manifest_into_builder logic
                // TODO: In the future, this should convert the entire reader to a parent ingredient
                // For now, preserve existing behavior for backward compatibility
                self.manifest_into_builder()
            }
        }
    }

    /// Converts the entire Reader into a single parent Ingredient.
    /// The entire manifest store is embedded as manifest_data.
    /// Returns the ingredient and the context to use for the new builder.
    fn reader_to_parent_ingredient(self) -> Result<(Ingredient, Arc<Context>)> {
        let context = self.context.clone();
        
        let manifest = self
            .active_manifest()
            .ok_or(Error::ClaimMissing {
                label: "active manifest".to_string(),
            })?;

        // Create ingredient from manifest metadata
        let mut ingredient = Ingredient::new(
            manifest.title().unwrap_or(""),
            manifest.format().unwrap_or("application/octet-stream"),
            manifest.instance_id(),
        );

        // Set as parent ingredient
        ingredient.set_relationship(Relationship::ParentOf);

        // Copy thumbnail if present
        if let Some(thumb_ref) = manifest.thumbnail_ref() {
            ingredient.set_thumbnail_ref(thumb_ref.clone())?;
        }

        // Add validation results from the reader
        if let Some(validation_status) = self.validation_status.clone() {
            if !validation_status.is_empty() {
                ingredient.set_validation_status(validation_status);
            }
        }
        
        if let Some(validation_results) = self.validation_results.clone() {
            ingredient.set_validation_results(validation_results);
        }

        // Set active manifest label
        if let Some(label) = &self.active_manifest {
            ingredient.set_active_manifest(label.clone());

            // Extract and embed the full manifest store as manifest_data
            if let Some(claim) = self.store.get_claim(label) {
                let ingredient_store = {
                    let mut store = Store::new();
                    let mut active_claim = claim.clone();

                    // Recursively collect all nested ingredient claims
                    Self::collect_ingredient_claims_for_store(&self.store, claim, &mut active_claim)?;

                    store.commit_claim(active_claim)?;
                    store
                };

                let jumbf = ingredient_store.to_jumbf_internal(0)?;
                ingredient.set_manifest_data(jumbf)?;
            }
        }

        Ok((ingredient, context))
    }

    /// Converts a Reader into a Builder by rebuilding ingredient stores from the unified store.
    /// Works for both builder archives and regular manifests.
    fn manifest_into_builder(mut self) -> Result<crate::Builder> {
        // Preserve the Reader's context in the new Builder
        let context = self.context;
        let mut builder = crate::Builder::from_shared_context(&context);

        if let Some(label) = &self.active_manifest {
            if let Some(parts) = crate::jumbf::labels::manifest_label_to_parts(label) {
                builder.definition.vendor = parts.cgi.clone();
                if parts.is_v1 {
                    builder.definition.claim_version = Some(1);
                }
            }
            builder.definition.label = Some(label.to_string());

            if let Some(mut manifest) = self.manifests.remove(label) {
                builder.definition.claim_generator_info =
                    manifest.claim_generator_info.take().unwrap_or_default();
                builder.definition.format = manifest.format().unwrap_or_default().to_string();
                builder.definition.title = manifest.title().map(|s| s.to_owned());
                builder.definition.instance_id = manifest.instance_id().to_owned();
                builder.definition.thumbnail = manifest.thumbnail_ref().cloned();
                builder.definition.redactions = manifest.redactions.take();

                let ingredients = std::mem::take(&mut manifest.ingredients);
                for mut ingredient in ingredients {
                    if let Some(active_manifest) = ingredient.active_manifest() {
                        let ingredient_claim = self.store.get_claim(active_manifest);
                        if let Some(claim) = ingredient_claim {
                            // recreate an ingredient store to get the jumbf data
                            // ... recursively collect all nested ingredient claims
                            let ingredient_store = {
                                let mut ingredient_store = Store::new();
                                let mut active_claim = claim.clone();

                                // Recursion happens here for claims collection - re-embed nested claims from store
                                Self::collect_ingredient_claims_for_store(
                                    &self.store,
                                    claim,
                                    &mut active_claim,
                                )?;

                                // Add the main claim with all nested ingredients
                                ingredient_store.commit_claim(active_claim)?;
                                ingredient_store
                            };
                            let jumbf = ingredient_store.to_jumbf_internal(0)?;
                            // Add manifest_data to the ingredient's own resources
                            let manifest_data_ref = ingredient.resources_mut().add_with(
                                "manifest_data",
                                "application/c2pa",
                                jumbf,
                            )?;
                            ingredient.set_manifest_data_ref(manifest_data_ref)?;
                        }
                    }
                    builder.add_ingredient(ingredient);
                }

                for assertion in manifest.assertions.iter() {
                    builder.add_assertion(assertion.label(), assertion.value()?)?;
                }

                for (uri, data) in manifest.resources().resources() {
                    builder.add_resource(uri, std::io::Cursor::new(data))?;
                }
            }
        }
        Ok(builder)
    }

    /// Convert a Reader into an [`Ingredient`] using the parent ingredient from the active manifest.
    /// # Errors
    /// Returns an [`Error`] if there is no parent ingredient.
    pub(crate) fn to_ingredient(&self) -> Result<Ingredient> {
        // make a copy of the parent ingredient (or return an error if not found)
        let ingredient = self
            .active_manifest()
            .and_then(|m| m.ingredients().first())
            .ok_or_else(|| Error::IngredientNotFound)?
            .to_owned();

        Ok(ingredient)
    }

    /// Determines the type of manifest this reader represents.
    ///
    /// Returns:
    /// - `ManifestType::ArchivedBuilder` if this is a builder archive (created with `Builder::to_archive()`)
    /// - `ManifestType::ArchivedIngredient` if this appears to be an archived ingredient
    /// - `ManifestType::SignedManifest` if this is a regular signed C2PA manifest
    pub(crate) fn manifest_type(&self) -> ManifestType {
        let manifest = match self.active_manifest() {
            Some(m) => m,
            None => return ManifestType::SignedManifest,
        };

        // Check for explicit archive type marker (new archives)
        if let Some(archive_type) = manifest
            .claim_generator_info
            .as_ref()
            .and_then(|infos| infos.first())
            .and_then(|info| info.get("org.contentauth.archive_type"))
            .and_then(|v| v.as_str())
        {
            return match archive_type {
                "builder" => ManifestType::ArchivedBuilder,
                "ingredient" => ManifestType::ArchivedIngredient,
                _ => ManifestType::SignedManifest,
            };
        }

        // Fallback for old archives without marker
        let has_data_hash = manifest
            .assertions()
            .iter()
            .any(|a| a.label() == crate::assertions::DataHash::LABEL);
        
        let has_box_hash = manifest
            .assertions()
            .iter()
            .any(|a| a.label() == crate::assertions::BoxHash::LABEL);

        // Two hard bindings = old builder archive (illegal but still detect it)
        if has_data_hash && has_box_hash {
            return ManifestType::ArchivedBuilder;
        }

        // If it has ingredients, assume archived ingredient
        if !manifest.ingredients().is_empty() {
            return ManifestType::ArchivedIngredient;
        }

        // Default: regular signed C2PA manifest
        ManifestType::SignedManifest
    }
}

/// Represents the type of C2PA data in a Reader
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestType {
    /// A Builder that was archived with to_archive()
    ArchivedBuilder,
    /// An ingredient that was explicitly archived
    ArchivedIngredient,
    /// A regular signed C2PA manifest from an asset
    SignedManifest,
}

/// Convert the Reader to a JSON value.
impl TryFrom<Reader> for serde_json::Value {
    type Error = Error;

    fn try_from(reader: Reader) -> Result<Self> {
        reader.to_json_formatted()
    }
}
impl TryFrom<&Reader> for serde_json::Value {
    type Error = Error;

    fn try_from(reader: &Reader) -> Result<Self> {
        reader.to_json_formatted()
    }
}

/// Prints the JSON of the manifest data.
impl std::fmt::Display for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = self.json_checked().map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

/// Prints the full debug details of the manifest data.
impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = self.detailed_json_checked().map_err(|_| std::fmt::Error)?;
        f.write_str(&json)
    }
}

impl TryInto<crate::Builder> for Reader {
    type Error = Error;

    fn try_into(self) -> Result<crate::Builder> {
        self.into_builder()
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    use std::io::Cursor;

    use super::*;
    use crate::utils::test::test_context;

    const IMAGE_COMPLEX_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CACAE-uri-CA.jpg");
    const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
    #[cfg(feature = "fetch_remote_manifests")]
    const IMAGE_WITH_REMOTE_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/cloud.jpg");
    const IMAGE_WITH_INGREDIENT_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CACA.jpg");

    #[test]
    // Verify that we can convert a Reader back into a Builder re-sign and the read it back again
    fn test_into_builder() -> Result<()> {
        let context = test_context().into_shared();
        let mut source = Cursor::new(IMAGE_WITH_INGREDIENT_MANIFEST);
        let format = "image/jpeg";
        let reader = Reader::from_shared_context(&context).with_stream(format, &mut source)?;
        println!("{reader}");

        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        let mut builder: crate::Builder = reader.try_into()?;
        println!("{builder}");

        source.set_position(0);
        let mut dest = Cursor::new(Vec::new());
        builder.save_to_stream(format, &mut source, &mut dest)?;

        dest.set_position(0);
        let reader2 = Reader::from_shared_context(&context).with_stream(format, &mut dest)?;
        println!("{reader2}");

        assert_eq!(reader2.validation_state(), ValidationState::Trusted);
        //std::fs::write("../target/CA-rebuilt.jpg", dest.get_ref())?;
        Ok(())
    }

    #[test]
    fn test_reader_embedded() -> Result<()> {
        let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_MANIFEST))?;
        assert_eq!(reader.remote_url(), None);
        assert!(reader.is_embedded());

        Ok(())
    }

    #[test]
    fn test_reader_new_with_stream() -> Result<()> {
        let context = test_context();

        let mut source = Cursor::new(IMAGE_WITH_MANIFEST);

        let reader = Reader::from_context(context).with_stream("image/jpeg", &mut source)?;

        assert_eq!(reader.remote_url(), None);
        assert!(reader.is_embedded());
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        assert!(reader.active_manifest().is_some());

        Ok(())
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn test_reader_remote_url() -> Result<()> {
        let reader = Reader::from_stream("image/jpeg", Cursor::new(IMAGE_WITH_REMOTE_MANIFEST))?;
        let remote_url = reader.remote_url();
        assert_eq!(remote_url, Some("https://cai-manifests.adobe.com/manifests/adobe-urn-uuid-5f37e182-3687-462e-a7fb-573462780391"));
        assert!(!reader.is_embedded());

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_reader_from_file_no_manifest() -> Result<()> {
        let result = Reader::from_file("tests/fixtures/IMG_0003.jpg");
        assert!(matches!(result, Err(Error::JumbfNotFound)));
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_reader_from_file_validation_err() -> Result<()> {
        let reader = Reader::from_file("tests/fixtures/XCA.jpg")?;
        assert!(reader.validation_status().is_some());
        assert_eq!(
            reader.validation_status().unwrap()[0].code(),
            crate::validation_status::ASSERTION_DATAHASH_MISMATCH
        );
        assert_eq!(reader.validation_state(), ValidationState::Invalid);
        Ok(())
    }

    #[test]
    fn test_reader_trusted() -> Result<()> {
        let context = Context::new();
        let reader = Reader::from_context(context)
            .with_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        Ok(())
    }

    #[test]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_from_file_nested_errors() -> Result<()> {
        // disable trust check so that the status is Valid vs Trusted
        let settings = crate::Settings::default()
            .with_value("verify.verify_trust", false)
            .unwrap();
        let context = Context::new().with_settings(settings).unwrap();
        let reader = Reader::from_context(context)
            .with_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        println!("{reader}");
        assert_eq!(reader.validation_status(), None);
        assert_eq!(reader.validation_state(), ValidationState::Valid);
        assert_eq!(reader.manifests.len(), 3);
        Ok(())
    }

    #[test]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_nested_resource() -> Result<()> {
        let reader =
            Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        assert_eq!(reader.validation_status(), None);
        assert_eq!(reader.manifests.len(), 3);
        let manifest = reader.active_manifest().unwrap();
        let ingredient = manifest.ingredients().iter().next().unwrap();
        let uri = ingredient.thumbnail_ref().unwrap().identifier.clone();
        let stream = std::io::Cursor::new(Vec::new());
        let bytes_written = reader.resource_to_stream(&uri, stream)?;
        assert_eq!(bytes_written, 41810);
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    /// Tests that the reader can write resources to a folder and that ingredients have manifest_data populated
    fn test_reader_to_folder() -> Result<()> {
        // Skip this test in GitHub workflow when target is WASI
        if std::env::var("GITHUB_ACTIONS").is_ok() && cfg!(target_os = "wasi") {
            eprintln!("Skipping test_reader_to_folder on WASI in GitHub Actions");
            return Ok(());
        }

        use crate::utils::{io_utils::tempdirectory, test::temp_dir_path};
        let reader = Reader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_INGREDIENT_MANIFEST),
        )?;
        assert_eq!(reader.validation_status(), None);

        // Test that ingredients have manifest_data populated
        if let Some(manifest) = reader.active_manifest() {
            for ingredient in manifest.ingredients() {
                // Verify that each ingredient has manifest_data
                assert!(
                    ingredient.manifest_data().is_some(),
                    "Ingredient should have manifest_data populated"
                );

                // Verify the manifest_data is not empty
                let manifest_data = ingredient.manifest_data().unwrap();
                assert!(
                    !manifest_data.is_empty(),
                    "Ingredient manifest_data should not be empty"
                );
            }
        }

        let temp_dir = tempdirectory().unwrap();
        reader.to_folder(temp_dir.path())?;
        let path = temp_dir_path(&temp_dir, "manifest_store.json");
        assert!(path.exists());
        let path = temp_dir_path(&temp_dir, "manifest_data.c2pa");
        assert!(path.exists());
        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_detailed_json() -> Result<()> {
        let reader = Reader::from_file("tests/fixtures/CACAE-uri-CA.jpg")?;
        let json = reader.json();
        let detailed_json = reader.detailed_json();
        let parsed_json: Value = serde_json::from_str(json.as_str())?;
        let parsed_detailed_json: Value = serde_json::from_str(detailed_json.as_str())?;

        // Undetailed JSON doesn't include "claim" object as child of active manifest object
        // Detailed JSON does include the "claim" object.
        assert!(
            if let Some(active_manifest) = parsed_json["active_manifest"].as_str() {
                let mut is_valid = parsed_json["manifests"]
                    .get(active_manifest)
                    .and_then(|m| m.get("claim"))
                    .is_none();
                is_valid &= parsed_detailed_json["manifests"]
                    .get(active_manifest)
                    .and_then(|m| m.get("claim"))
                    .is_some();
                is_valid
            } else {
                false
            }
        );
        assert!(json.len() < detailed_json.len()); // Detailed JSON should contain more information
        Ok(())
    }

    #[test]
    fn test_reader_post_validate() -> Result<()> {
        use crate::{log_item, status_tracker::StatusTracker};

        let mut reader =
            Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_WITH_MANIFEST))?;

        struct TestValidator;
        impl PostValidator for TestValidator {
            fn validate(
                &self,
                label: &str,
                assertion: &ManifestAssertion,
                uri: &str,
                _preliminary_claim: &PartialClaim,
                tracker: &mut StatusTracker,
            ) -> Result<Option<Value>> {
                let desc = tracker
                    .ingredient_uri()
                    .unwrap_or("active_manifest")
                    .to_string();
                #[allow(clippy::single_match)]
                match label {
                    "c2pa.actions" => {
                        let actions = assertion.to_assertion::<crate::assertions::Actions>()?;
                        // build a comma separated string list of actions
                        let desc = actions
                            .actions
                            .iter()
                            .map(|action| action.action().to_string())
                            .collect::<Vec<String>>()
                            .join(",");

                        log_item!(uri.to_string(), desc.clone(), "test validator")
                            .validation_status("cai.test.action")
                            .success(tracker);
                        let result = Value::String(desc);
                        return Ok(Some(result));
                    }
                    _ => {}
                }
                log_item!(uri.to_string(), desc, "test validator")
                    .validation_status("cai.test.something")
                    .success(tracker);
                Ok(None)
            }
        }

        reader.post_validate(&TestValidator {})?;

        println!("{reader}");
        //Err(Error::NotImplemented("foo".to_string()))
        Ok(())
    }

    #[test]
    fn test_reader_is_send_sync() {
        // Compile-time assertion that Reader is Send + Sync on non-WASM
        // On WASM, MaybeSend/MaybeSync don't require Send + Sync, so these traits
        // won't be implemented, but that's correct for single-threaded WASM
        #[cfg(not(target_arch = "wasm32"))]
        {
            fn assert_send<T: Send>() {}
            fn assert_sync<T: Sync>() {}

            assert_send::<Reader>();
            assert_sync::<Reader>();
        }
    }
}
