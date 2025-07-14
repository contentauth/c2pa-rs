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
    collections::HashMap,
    io::{Read, Seek, Write},
};

use async_generic::async_generic;
use async_trait::async_trait;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

use crate::{
    claim::ClaimAssetData,
    crypto::base64,
    dynamic_assertion::PartialClaim,
    error::{Error, Result},
    jumbf::labels::{manifest_label_from_uri, to_absolute_uri, to_relative_uri},
    jumbf_io,
    manifest::StoreOptions,
    manifest_store_report::ManifestStoreReport,
    settings::get_settings_value,
    status_tracker::StatusTracker,
    store::Store,
    validation_results::{ValidationResults, ValidationState},
    validation_status::ValidationStatus,
    Manifest, ManifestAssertion,
};

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
    store: Store,

    #[serde(skip)]
    /// Map to hold post-validation assertion values for resports
    /// the key is an assertion uri and the value is the assertion value
    assertion_values: HashMap<String, Value>,
}

type ValidationFn =
    dyn Fn(&str, &crate::ManifestAssertion, &mut StatusTracker) -> Option<serde_json::Value>;

impl Reader {
    /// Create a manifest store [`Reader`] from a stream.  A Reader is used to validate C2PA data from an asset.
    /// # Arguments
    /// * `format` - The format of the stream.  MIME type or extension that maps to a MIME type.
    /// * `stream` - The stream to read from.  Must implement the Read and Seek traits. (NOTE: Explain Send trait, required for both sync & async?).
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # Errors
    /// Returns an [`Error`] when the manifest data cannot be read.  If there's no error upon reading, you must still check validation status to ensure that the manifest data is validated.  That is, even if there are no errors, the data still might not be valid.
    /// # Example
    /// This example reads from a memory buffer and prints out the JSON manifest data.
    /// ```no_run
    /// use std::io::Cursor;
    ///
    /// use c2pa::Reader;
    /// let mut stream = Cursor::new(include_bytes!("../tests/fixtures/CA.jpg"));
    /// let reader = Reader::from_stream("image/jpeg", stream).unwrap();
    /// println!("{}", reader.json());
    /// ```
    #[async_generic()]
    pub fn from_stream(format: &str, mut stream: impl Read + Seek + Send) -> Result<Reader> {
        let verify = get_settings_value::<bool>("verify.verify_after_reading")?; // defaults to true
        let mut validation_log = StatusTracker::default();

        let store = if _sync {
            Store::from_stream(format, &mut stream, verify, &mut validation_log)
        } else {
            Store::from_stream_async(format, &mut stream, verify, &mut validation_log).await
        }?;

        Self::from_store(store, &validation_log)
    }

    #[cfg(feature = "file_io")]
    /// Create a manifest store [`Reader`] from a file.
    /// If the `fetch_remote_manifests` feature is enabled, and the asset refers to a remote manifest, the function fetches a remote manifest.
    /// NOTE: If the file does not have a manifest store, the function will check for a sidecar manifest with the same base file name and a .c2pa extension.
    /// # Arguments
    /// * `path` - The path to the file.
    /// # Returns
    /// A [`Reader`] for the manifest store.
    /// # Errors
    /// Returns an [`Error`] when the manifest data cannot be read from the specified file.  If there's no error upon reading, you must still check validation status to ensure that the manifest data is validated.  That is, even if there are no errors, the data still might not be valid.
    /// # Example
    /// This example
    /// ```no_run
    /// use c2pa::Reader;
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// ```
    #[async_generic()]
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Reader> {
        let path = path.as_ref();
        let format = crate::format_from_path(path).ok_or(crate::Error::UnsupportedType)?;
        let mut file = File::open(path)?;
        let result = if _sync {
            Self::from_stream(&format, &mut file)
        } else {
            Self::from_stream_async(&format, &mut file).await
        };
        match result {
            Err(Error::JumbfNotFound) => {
                // if not embedded or cloud, check for sidecar first and load if it exists
                let potential_sidecar_path = path.with_extension("c2pa");
                if potential_sidecar_path.exists() {
                    let manifest_data = read(potential_sidecar_path)?;
                    if _sync {
                        Self::from_manifest_data_and_stream(&manifest_data, &format, &mut file)
                    } else {
                        Self::from_manifest_data_and_stream_async(
                            &manifest_data,
                            &format,
                            &mut file,
                        )
                        .await
                    }
                } else {
                    Err(Error::JumbfNotFound)
                }
            }
            _ => result,
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
    #[async_generic()]
    pub fn from_manifest_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + Send,
    ) -> Result<Reader> {
        let mut validation_log = StatusTracker::default();

        let verify = get_settings_value::<bool>("verify.verify_after_reading")?; // defaults to true

        let store = if _sync {
            Store::from_manifest_data_and_stream(
                c2pa_data,
                format,
                stream,
                verify,
                &mut validation_log,
            )
        } else {
            Store::from_manifest_data_and_stream_async(
                c2pa_data,
                format,
                stream,
                verify,
                &mut validation_log,
            )
            .await
        }?;

        Self::from_store(store, &validation_log)
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
    #[async_generic()]
    pub fn from_fragment(
        format: &str,
        mut stream: impl Read + Seek + Send,
        mut fragment: impl Read + Seek + Send,
    ) -> Result<Self> {
        let mut validation_log = StatusTracker::default();
        let manifest_bytes = Store::load_jumbf_from_stream(format, &mut stream)?;
        let store = Store::from_jumbf(&manifest_bytes, &mut validation_log)?;

        let verify = get_settings_value::<bool>("verify.verify_after_reading")?; // defaults to true
                                                                                 // verify the store
        if verify {
            let mut fragment = ClaimAssetData::StreamFragment(&mut stream, &mut fragment, format);
            if _sync {
                Store::verify_store(&store, &mut fragment, &mut validation_log)
            } else {
                Store::verify_store_async(&store, &mut fragment, &mut validation_log).await
            }?;
        };

        Self::from_store(store, &validation_log)
    }

    #[cfg(feature = "file_io")]
    /// Loads a [`Reader`]` from an initial segment and fragments.  This
    /// would be used to load and validate fragmented MP4 files that span
    /// multiple separate asset files.
    pub fn from_fragmented_files<P: AsRef<std::path::Path>>(
        path: P,
        fragments: &Vec<std::path::PathBuf>,
    ) -> Result<Reader> {
        let verify = get_settings_value::<bool>("verify.verify_after_reading")?; // defaults to true

        let mut validation_log = StatusTracker::default();

        let asset_type = jumbf_io::get_supported_file_extension(path.as_ref())
            .ok_or(crate::Error::UnsupportedType)?;

        let mut init_segment = std::fs::File::open(path.as_ref())?;

        match Store::load_from_file_and_fragments(
            &asset_type,
            &mut init_segment,
            fragments,
            verify,
            &mut validation_log,
        ) {
            Ok(store) => Self::from_store(store, &validation_log),
            Err(e) => Err(e),
        }
    }

    /// replace byte arrays with base64 encoded strings
    fn hash_to_b64(mut value: Value) -> Value {
        use std::collections::VecDeque;

        let mut queue = VecDeque::new();
        queue.push_back(&mut value);

        while let Some(current) = queue.pop_front() {
            match current {
                Value::Object(obj) => {
                    for (_, v) in obj.iter_mut() {
                        if let Value::Array(hash_arr) = v {
                            if !hash_arr.is_empty() && hash_arr.iter().all(|x| x.is_number()) {
                                // Pre-allocate with capacity to avoid reallocations
                                let mut hash_bytes = Vec::with_capacity(hash_arr.len());
                                // Convert numbers to bytes safely
                                for n in hash_arr.iter() {
                                    if let Some(num) = n.as_u64() {
                                        hash_bytes.push(num as u8);
                                    }
                                }
                                *v = Value::String(base64::encode(&hash_bytes));
                            }
                        }
                        queue.push_back(v);
                    }
                }
                Value::Array(arr) => {
                    for v in arr.iter_mut() {
                        queue.push_back(v);
                    }
                }
                _ => {}
            }
        }
        value
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

        // Process manifests
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
                            let uri = crate::jumbf::labels::to_assertion_uri(manifest_label, label);
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

        Ok(Self::hash_to_b64(json))
    }

    fn to_json_detailed_formatted(&self) -> Result<Value> {
        let report = match self.validation_results() {
            Some(results) => ManifestStoreReport::from_store_with_results(&self.store, results),
            None => ManifestStoreReport::from_store(&self.store),
        }?;
        let mut json = serde_json::to_value(report).map_err(Error::JsonError)?;
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
        };
        json = Self::hash_to_b64(json);
        Ok(json)
    }

    /// Get the manifest store as a JSON string
    pub fn json(&self) -> String {
        match self.to_json_formatted() {
            Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_default(),
            Err(_) => "{}".to_string(),
        }
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

        let verify_trust = get_settings_value("verify.verify_trust").unwrap_or(false);
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
    /// let stream = std::io::Cursor::new(Vec::new());
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// let manifest = reader.active_manifest().unwrap();
    /// let uri = &manifest.thumbnail_ref().unwrap().identifier;
    /// let bytes_written = reader.resource_to_stream(uri, stream).unwrap();
    /// ```
    /// TODO: Fix the example to not read from a file.
    pub fn resource_to_stream(
        &self,
        uri: &str,
        stream: impl Write + Read + Seek + Send,
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

    /// Convert a URI to a file path. (todo: move this to utils)
    fn uri_to_path(uri: &str, manifest_label: &str) -> String {
        let mut path = uri.to_string();
        if path.starts_with("self#jumbf=") {
            // convert to a file path always including the manifest label
            path = path.replace("self#jumbf=", "");
            if path.starts_with("/c2pa/") {
                path = path.replacen("/c2pa/", "", 1);
            } else {
                path = format!("{manifest_label}/{path}");
            }
            path = path.replace([':'], "_");
        }
        path
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
        std::fs::write(path.as_ref().join("manifest.json"), self.json())?;
        for manifest in self.manifests.values() {
            let resources = manifest.resources();
            for (uri, data) in resources.resources() {
                let id_path = Self::uri_to_path(uri, manifest.label().unwrap_or("unknown"));
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
    fn from_store(store: Store, validation_log: &StatusTracker) -> Result<Self> {
        let mut validation_results = ValidationResults::from_store(&store, validation_log);

        let active_manifest = store.provenance_label();
        let mut manifests = HashMap::new();
        let mut options = StoreOptions::default();

        for claim in store.claims() {
            let manifest_label = claim.label();
            let result = if _sync {
                Manifest::from_store(&store, manifest_label, &mut options)
            } else {
                Manifest::from_store_async(&store, manifest_label, &mut options).await
            };
            match result {
                Ok(manifest) => {
                    manifests.insert(manifest_label.to_owned(), manifest);
                }
                Err(e) => {
                    validation_results.add_status(ValidationStatus::from_error(&e));
                    return Err(e);
                }
            };
        }

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
        // todo: figure out what to do here!
        if !redacted.is_empty() {
            eprintln!("Not Redacted: {redacted:?}");
            return Err(Error::AssertionRedactionNotFound);
        }
        if !missing.is_empty() {
            eprintln!("Assertion Missing: {missing:?}");
            return Err(Error::AssertionMissing {
                url: redacted[0].to_owned(),
            });
        }

        let validation_state = validation_results.validation_state();
        Ok(Self {
            active_manifest,
            manifests,
            validation_status: validation_results.validation_errors(),
            validation_results: Some(validation_results),
            validation_state: Some(validation_state),
            store,
            assertion_values: HashMap::new(),
        })
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

        while let Some((current_label, parent_uri)) = stack.pop() {
            // If we're processing an ingredient, push its URI to the validation log
            if let Some(uri) = &parent_uri {
                validation_log.push_ingredient_uri(uri.clone());
            }

            let manifest = self
                .get_manifest(&current_label)
                .ok_or(Error::ClaimMissing {
                    label: current_label.clone(),
                })?;

            let mut partial_claim = crate::dynamic_assertion::PartialClaim::default();
            {
                let claim = self
                    .store
                    .get_claim(&current_label)
                    .ok_or(Error::ClaimEncoding)?;
                for assertion in claim.assertions() {
                    partial_claim.add_assertion(assertion);
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
                    let ingredient_uri = crate::jumbf::labels::to_assertion_uri(
                        &current_label,
                        ingredient.label().unwrap_or("unknown"),
                    );
                    stack.push((label.to_string(), Some(ingredient_uri)));
                }
            }

            // If we're processing an ingredient, pop its URI from the validation log
            if parent_uri.is_some() {
                validation_log.pop_ingredient_uri();
            }
        }

        Ok(assertion_values)
    }
}

/// Convert the Reader to a JSON value.
impl TryFrom<Reader> for serde_json::Value {
    type Error = Error;

    fn try_from(reader: Reader) -> Result<Self> {
        reader.to_json_formatted()
    }
}

/// Prints the JSON of the manifest data.
impl std::fmt::Display for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.json().as_str())
    }
}

/// Prints the full debug details of the manifest data.
impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = self
            .to_json_detailed_formatted()
            .map_err(|_| std::fmt::Error)?;
        // let report = match self.validation_results() {
        //     Some(results) => ManifestStoreReport::from_store_with_results(&self.store, results),
        //     None => ManifestStoreReport::from_store(&self.store),
        // }
        // .map_err(|_| std::fmt::Error)?;
        let output = serde_json::to_string_pretty(&json).map_err(|_| std::fmt::Error)?;
        f.write_str(&output)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    const IMAGE_COMPLEX_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CACAE-uri-CA.jpg");
    const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");

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
    #[cfg(not(target_os = "wasi"))] // todo: enable when disable we find out wasi trust issues
    fn test_reader_trusted() -> Result<()> {
        let reader =
            Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        Ok(())
    }

    #[test]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_from_file_nested_errors() -> Result<()> {
        // disable trust check so that the status is Valid vs Trusted
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let reader =
            Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
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
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_to_folder() -> Result<()> {
        use crate::utils::{io_utils::tempdirectory, test::temp_dir_path};
        let reader = Reader::from_file("tests/fixtures/CACAE-uri-CA.jpg")?;
        assert_eq!(reader.validation_status(), None);
        let temp_dir = tempdirectory().unwrap();
        reader.to_folder(temp_dir.path())?;
        let path = temp_dir_path(&temp_dir, "manifest.json");
        assert!(path.exists());
        #[cfg(target_os = "wasi")]
        crate::utils::io_utils::wasm_remove_dir_all(temp_dir)?;
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
}
