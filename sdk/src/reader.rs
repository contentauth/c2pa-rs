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

#[cfg(feature = "file_io")]
use crate::error::Error;
use crate::{
    claim::ClaimAssetData, error::Result, manifest_store::ManifestStore,
    settings::get_settings_value, status_tracker::DetailedStatusTracker, store::Store,
    validation_status::ValidationStatus, Manifest,
};

/// A reader for the manifest store.
#[derive(Debug)]
pub struct Reader {
    pub(crate) manifest_store: ManifestStore,
}

impl Reader {
    /// Create a manifest store Reader from a stream.
    /// # Arguments
    /// * `format` - The format of the stream.
    /// * `stream` - The stream to read from.
    /// # Returns
    /// A reader for the manifest store.
    /// # Errors
    /// If the stream is not a valid manifest store.
    /// validation status should be checked for non severe errors
    /// # Example
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
    /// Create a manifest store Reader from a file.
    /// # Arguments
    /// * `path` - The path to the file.
    /// # Returns
    /// A reader for the manifest store.
    /// # Errors
    /// If the file is not a valid manifest store.
    /// validation status should be checked for non severe errors.
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// ```
    /// # Note
    /// If the file does not have a manifest store, the function will check for a sidecar manifest
    /// with the same name and a .c2pa extension.
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Reader> {
        let path = path.as_ref();
        let format = crate::format_from_path(path).ok_or(crate::Error::UnsupportedType)?;
        let mut file = File::open(path)?;
        let result = Self::from_stream(&format, &mut file);
        if let Err(Error::JumbfNotFound) = result {
            // if not embedded or cloud, check for sidecar first and load if it exists
            let potential_sidecar_path = path.with_extension("c2pa");
            if potential_sidecar_path.exists() {
                let manifest_data = read(potential_sidecar_path)?;
                return Self::from_manifest_data_and_stream(&manifest_data, &format, &mut file);
            }
        }
        result
    }

    /// Create a manifest store [`Reader`]` from a JSON string.
    /// # Arguments
    /// * `json` - A Json String containing a manifest store definition.
    /// # Returns
    /// A [`Reader`]` for the manifest store.
    /// # Note
    /// This should only be used for testing
    /// Any referenced resources will not be available
    pub fn from_json(json: &str) -> Result<Reader> {
        let manifest_store = serde_json::from_str(json)?;
        Ok(Reader { manifest_store })
    }

    /// Create a manifest store [`Reader`] from existing c2pa_data and a stream
    /// You can use this to validate a remote manifest or a sidecar manifest
    /// # Arguments
    /// * `c2pa_data` - The c2pa data (a manifest store in JUMBF format)
    /// * `format` - The format of the stream
    /// * `stream` - The stream to verify the store against
    /// # Returns
    /// A [`Reader`] for the manifest store
    /// # Errors
    /// If the c2pa_data is not valid, or severe errors occur in validation
    /// validation status should be checked for non severe errors
    #[async_generic()]
    pub fn from_manifest_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        mut stream: impl Read + Seek + Send,
    ) -> Result<Reader> {
        let mut validation_log = DetailedStatusTracker::new();

        // first we convert the JUMBF into a usable store
        let store = Store::from_jumbf(c2pa_data, &mut validation_log)?;

        if _sync {
            Store::verify_store(
                &store,
                &mut ClaimAssetData::Stream(&mut stream, format),
                &mut validation_log,
            )?;
        } else {
            Store::verify_store_async(
                &store,
                &mut ClaimAssetData::Stream(&mut stream, format),
                &mut validation_log,
            )
            .await?;
        }

        Ok(Reader {
            manifest_store: ManifestStore::from_store(&store, &validation_log),
        })
    }

    /// Get the manifest store as a JSON string
    pub fn json(&self) -> String {
        self.manifest_store.to_string()
    }

    /// Get the [`ValidationStatus`] array of the manifest store if it exists.
    ///
    /// This validation report only includes error statuses on applied to the active manifest.
    /// And error statuses for ingredients that are not already reported by the ingredient status.
    /// The uri field can be used to identify the associated manifest.
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let stream = std::io::Cursor::new(include_bytes!("../tests/fixtures/CA.jpg"));
    /// let reader = Reader::from_stream("image/jpeg", stream).unwrap();
    /// let status = reader.validation_status();
    /// ```
    /// # Note
    /// The validation status should be checked for validation errors.
    pub fn validation_status(&self) -> Option<&[ValidationStatus]> {
        self.manifest_store.validation_status()
    }

    /// Return the active [`Manifest`] if it exists.
    pub fn active_manifest(&self) -> Option<&Manifest> {
        self.manifest_store.get_active()
    }

    /// Return the active [`Manifest`] label if one exists.
    pub fn active_label(&self) -> Option<&str> {
        self.manifest_store.active_label()
    }

    /// Return a [`Manifest`] for a given label if it exists.
    /// # Arguments
    /// * `label` - The label of the requested [`Manifest`]
    pub fn get_manifest(&self, label: &str) -> Option<&Manifest> {
        self.manifest_store.get(label)
    }

    /// Write a resource identified by URI to the given stream.
    /// # Arguments
    /// * `uri` - The URI of the resource to write (from an identifier field).
    /// * `stream` - The stream to write to.
    /// # Returns
    /// The number of bytes written.
    /// # Errors
    /// If the resource does not exist.
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let stream = std::io::Cursor::new(Vec::new());
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// let manifest = reader.active_manifest().unwrap();
    /// let uri = &manifest.thumbnail_ref().unwrap().identifier;
    /// let bytes_written = reader.resource_to_stream(uri, stream).unwrap();
    /// ```
    pub fn resource_to_stream(
        &self,
        uri: &str,
        mut stream: impl Write + Read + Seek + Send,
    ) -> Result<usize> {
        self.manifest_store
            .get_resource(uri, &mut stream)
            .map(|size| size as usize)
    }
}

impl Default for Reader {
    fn default() -> Self {
        Self {
            manifest_store: ManifestStore::new(),
        }
    }
}

impl std::fmt::Display for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.json().as_str())
    }
}
