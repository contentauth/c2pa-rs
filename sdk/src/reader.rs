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
use std::io::{Read, Seek, Write};

use async_generic::async_generic;
use c2pa_status_tracker::DetailedStatusTracker;
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[cfg(feature = "file_io")]
use crate::error::Error;
use crate::{
    claim::ClaimAssetData,
    error::Result,
    manifest_store::ManifestStore,
    settings::get_settings_value,
    store::Store,
    validation_results::{ValidationResults, ValidationState},
    validation_status::ValidationStatus,
    Manifest, ManifestStoreReport,
};

/// A reader for the manifest store.
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct Reader {
    pub(crate) manifest_store: ManifestStore,
}

impl Reader {
    /// Create a manifest store [`Reader`] from a stream.  A Reader is used to validate C2PA data from an asset.
    /// # Arguments
    /// * `format` - The format of the stream.  MIME type or extension that maps to a MIME type.
    /// * `stream` - The stream to read from.  Must implement the Read and Seek traits. (NOTE: Explain Send trait, required for both sync & async?).
    /// # Returns
    /// A Reader for the manifest store.
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
        #[allow(deprecated)]
        let reader = if _sync {
            ManifestStore::from_stream(format, &mut stream, verify)
        } else {
            ManifestStore::from_stream_async(format, &mut stream, verify).await
        }?;
        Ok(Reader {
            manifest_store: reader,
        })
    }

    #[cfg(feature = "file_io")]
    /// Create a manifest store [`Reader`] from a file.
    /// If the `fetch_remote_manifests` feature is enabled, and the asset refers to a remote manifest, the function fetches a remote manifest.
    /// NOTE: If the file does not have a manifest store, the function will check for a sidecar manifest with the same base file name and a .c2pa extension.
    /// # Arguments
    /// * `path` - The path to the file.
    /// # Returns
    /// A reader for the manifest store.
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
        let manifest_store = serde_json::from_str(json)?;
        Ok(Reader { manifest_store })
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
        mut stream: impl Read + Seek + Send,
    ) -> Result<Reader> {
        let mut validation_log = DetailedStatusTracker::default();

        // first we convert the JUMBF into a usable store
        let store = Store::from_jumbf(c2pa_data, &mut validation_log)?;

        let verify = get_settings_value::<bool>("verify.verify_after_reading")?; // defaults to true

        if _sync {
            if verify {
                Store::verify_store(
                    &store,
                    &mut ClaimAssetData::Stream(&mut stream, format),
                    &mut validation_log,
                )?;
            }
        } else {
            if verify {
                Store::verify_store_async(
                    &store,
                    &mut ClaimAssetData::Stream(&mut stream, format),
                    &mut validation_log,
                )
                .await?;
            }
        }

        Ok(Reader {
            manifest_store: ManifestStore::from_store(store, &validation_log),
        })
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
        let mut validation_log = DetailedStatusTracker::default();
        let manifest_bytes = Store::load_jumbf_from_stream(format, &mut stream)?;
        let store = Store::from_jumbf(&manifest_bytes, &mut validation_log)?;

        let verify = get_settings_value::<bool>("verify.verify_after_reading")?; // defaults to true
                                                                                 // verify the store
        if verify {
            let mut fragment = ClaimAssetData::StreamFragment(&mut stream, &mut fragment, format);
            if _sync {
                // verify store and claims
                Store::verify_store(&store, &mut fragment, &mut validation_log)
            } else {
                // verify store and claims
                Store::verify_store_async(&store, &mut fragment, &mut validation_log).await
            }?;
        };

        Ok(Self {
            manifest_store: ManifestStore::from_store(store, &validation_log),
        })
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
        #[allow(deprecated)]
        Ok(Reader {
            manifest_store: ManifestStore::from_fragments(path, fragments, verify)?,
        })
    }

    /// Get the manifest store as a JSON string.
    pub fn json(&self) -> String {
        self.manifest_store.to_string()
    }

    /// Get the manifest store as a serde serialized JSON value map.
    pub fn json_value_map(&self) -> Result<Map<String, Value>> {
        match serde_json::from_str(self.json().as_str()) {
            Ok(mapped_json) => Ok(mapped_json),
            Err(err) => Err(crate::Error::JsonSerializationError(err.to_string())),
        }
    }

    // Get the full report as json
    pub fn json_report(&self) -> Result<String> {
        let report = ManifestStoreReport::from_store(self.manifest_store.store());
        let mut report = match report {
            Ok(report) => report,
            Err(err) => return Err(crate::Error::JsonSerializationError(err.to_string())),
        };
        report.validation_results = self.manifest_store.validation_results().cloned();
        Ok(report.to_string())
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
        self.manifest_store.validation_status()
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
        self.manifest_store.validation_results()
    }

    /// Get the [`ValidationState`] of the manifest store.
    pub fn validation_state(&self) -> ValidationState {
        if let Some(validation_results) = self.manifest_store.validation_results() {
            return validation_results.validation_state();
        }

        let verify_trust = get_settings_value("verify.trusted").unwrap_or(false);
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
        self.manifest_store.get_active()
    }

    /// Return the active [`Manifest`], or `None` if there's no active manifest.
    pub fn active_label(&self) -> Option<&str> {
        self.manifest_store.active_label()
    }

    /// Returns an iterator over a collection of [`Manifest`] structs.
    pub fn iter_manifests(&self) -> impl Iterator<Item = &Manifest> + '_ {
        self.manifest_store.manifests().values()
    }

    /// Given a label, return the associated [`Manifest`], if it exists.
    /// # Arguments
    /// * `label` - The label of the requested [`Manifest`].
    pub fn get_manifest(&self, label: &str) -> Option<&Manifest> {
        self.manifest_store.get(label)
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
        mut stream: impl Write + Read + Seek + Send,
    ) -> Result<usize> {
        self.manifest_store
            .get_resource(uri, &mut stream)
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
                path = format!("{}/{path}", manifest_label);
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
        for manifest in self.manifest_store.manifests().values() {
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
}

impl Default for Reader {
    fn default() -> Self {
        Self {
            manifest_store: ManifestStore::new(),
        }
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
        let mut report = ManifestStoreReport::from_store(self.manifest_store.store())
            .map_err(|_| std::fmt::Error)?;
        report.validation_results = self.manifest_store.validation_results().cloned();
        f.write_str(&report.to_string())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    use super::*;

    const IMAGE_COMPLEX_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CACAE-uri-CA.jpg");

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

    // This test is disabled until we can set settings without interfering with other tests
    // #[test]
    // fn test_reader_trusted() -> Result<()> {
    //     const TEST_SETTINGS: &str = include_str!("../tests/fixtures/certs/trust/test_settings.toml");
    //     crate::settings::load_settings_from_str(TEST_SETTINGS, "toml")?;
    //     let reader = Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
    //     assert_eq!(reader.validation_state(), ValidationState::Trusted);
    //     crate::settings::set_settings_value("verify.trusted", false)?;
    //     Ok(())
    // }

    #[test]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_from_file_nested_errors() -> Result<()> {
        let reader =
            Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        println!("{reader}");
        assert_eq!(reader.validation_status(), None);
        assert_eq!(reader.validation_state(), ValidationState::Valid);
        assert_eq!(reader.manifest_store.manifests().len(), 3);
        Ok(())
    }

    #[test]
    /// Test that the reader can validate a file with nested assertion errors
    fn test_reader_nested_resource() -> Result<()> {
        let reader =
            Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_COMPLEX_MANIFEST))?;
        assert_eq!(reader.validation_status(), None);
        assert_eq!(reader.manifest_store.manifests().len(), 3);
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
        let reader = Reader::from_file("tests/fixtures/CACAE-uri-CA.jpg")?;
        assert_eq!(reader.validation_status(), None);
        reader.to_folder("../target/reader_folder")?;
        assert!(std::path::Path::new("../target/reader_folder/manifest.json").exists());
        Ok(())
    }
}
