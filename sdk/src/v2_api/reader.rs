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
use std::fs::{read, File};
use std::io::Cursor;

use async_generic::async_generic;

#[cfg(feature = "file_io")]
use crate::error::Error;
use crate::{
    claim::ClaimAssetData, error::Result, manifest_store::ManifestStore,
    status_tracker::DetailedStatusTracker, store::Store, validation_status::ValidationStatus,
    CAIRead, CAIReadWrite, Manifest,
};

/// A reader for the manifest store
#[derive(Debug)]
pub struct Reader {
    pub(crate) manifest_store: ManifestStore,
}

impl Reader {
    pub fn new() -> Self {
        Self {
            manifest_store: ManifestStore::new(),
        }
    }

    /// Create a manifest store Reader from a stream
    /// # Arguments
    /// * `format` - The format of the stream
    /// * `stream` - The stream to read from
    /// # Returns
    /// A reader for the manifest store
    /// # Errors
    /// If the stream is not a valid manifest store
    /// validation status should be checked for non severe errors
    /// # Example
    /// ```no_run
    /// use std::io::Cursor;
    ///
    /// use c2pa::Reader;
    /// let mut stream = Cursor::new(include_bytes!("../../tests/fixtures/CA.jpg").to_vec());
    /// let reader = Reader::from_stream("image/jpeg", &mut stream).unwrap();
    /// println!("{}", reader.json());
    /// ```
    #[async_generic(async_signature(
        format: &str,
        stream: &mut dyn CAIRead,
    ))]
    pub fn from_stream(format: &str, stream: &mut dyn CAIRead) -> Result<Reader> {
        let verify = true; // todo: get this from config
        let reader = if _sync {
            ManifestStore::from_stream(format, stream, verify)
        } else {
            ManifestStore::from_stream_async(format, stream, verify).await
        }?;
        Ok(Reader {
            manifest_store: reader,
        })
    }

    /// Create a manifest store Reader from bytes
    /// # Arguments
    /// * `format` - The format of the bytes
    /// * `bytes` - The bytes to read from
    /// # Returns
    /// A reader for the manifest store
    /// # Errors
    /// If the bytes are do not contain a manifest store
    /// validation status should be checked for non severe errors
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let bytes = include_bytes!("../../tests/fixtures/CA.jpg").to_vec();
    /// let reader = Reader::from_bytes("image/jpeg", &bytes).unwrap();
    /// ```
    pub fn from_bytes(format: &str, bytes: &[u8]) -> Result<Reader> {
        let mut stream = Cursor::new(bytes);
        Self::from_stream(format, &mut stream)
    }

    #[cfg(feature = "file_io")]
    /// Create a manifest store Reader from a file
    /// # Arguments
    /// * `path` - The path to the file
    /// # Returns
    /// A reader for the manifest store
    /// # Errors
    /// If the file is not a valid manifest store
    /// validation status should be checked for non severe errors
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let reader = Reader::from_file("path/to/file.jpg").unwrap();
    /// ```
    /// # Note
    /// If the file does not have a manifest store, the function will check for a sidecar manifest
    /// with the same name and a .c2pa extension
    /// If the sidecar manifest exists, it will be used instead
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
                return Self::from_c2pa_data_and_stream(&manifest_data, &format, &mut file);
            }
        }
        result
    }

    /// Create a manifest store Reader from a JSON string
    /// # Arguments
    /// * `json` - The JSON string
    /// # Returns
    /// A reader for the manifest store
    /// # Note
    /// This should only be used for testing
    /// Any referenced resources will not be available
    pub fn from_json(json: &str) -> Result<Reader> {
        let manifest_store = serde_json::from_str(json)?;
        Ok(Reader { manifest_store })
    }

    /// Create a manifest store Reader from existing c2pa_data and a stream
    /// You can use this to validate a remote manifest or a sidecar manifest
    /// # Arguments
    /// * `c2pa_data` - The c2pa data (a manifest store in JUMBF format)
    /// * `format` - The format of the stream
    /// * `stream` - The stream to verify the store against
    /// # Returns
    /// A reader for the manifest store
    /// # Errors
    /// If the c2pa_data is not valid, or severe errors occur in validation
    /// validation status should be checked for non severe errors
    #[async_generic(async_signature(
        c2pa_data: &[u8],
        format: &str,
        stream: &mut dyn CAIRead,
    ))]
    pub fn from_c2pa_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        stream: &mut dyn CAIRead,
    ) -> Result<Reader> {
        let mut validation_log = DetailedStatusTracker::new();

        // first we convert the JUMBF into a usable store
        let store = Store::from_jumbf(c2pa_data, &mut validation_log)?;

        if _sync {
            Store::verify_store(
                &store,
                &mut ClaimAssetData::Stream(stream, format),
                &mut validation_log,
            )?;
        } else {
            Store::verify_store_async(
                &store,
                &mut ClaimAssetData::Stream(stream, format),
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

    /// Get the validation status of the manifest store
    /// # Returns
    /// The validation status of the manifest store
    /// # Example
    /// ```no_run
    /// use c2pa::Reader;
    /// let reader =
    ///     Reader::from_bytes("image/jpeg", include_bytes!("../../tests/fixtures/CA.jpg")).unwrap();
    /// let status = reader.validation_status();
    /// ```
    /// # Note
    /// The validation status should be checked for non severe errors`
    pub fn validation_status(&self) -> Option<&[ValidationStatus]> {
        self.manifest_store.validation_status()
    }

    /// Get the active manifest
    /// # Returns
    /// The active manifest if it exists
    pub fn active(&self) -> Option<&Manifest> {
        self.manifest_store.get_active()
    }

    /// Get the active manifest label
    pub fn active_label(&self) -> Option<&str> {
        self.manifest_store.active_label()
    }

    /// Return a Manifest for a given label
    /// # Arguments
    /// * `label` - The label of the manifest to return
    /// # Returns
    /// The manifest if it exists
    pub fn get(&self, label: &str) -> Option<&Manifest> {
        self.manifest_store.get(label)
    }

    /// Write a resource identified by uri to the given stream
    /// # Arguments
    /// * `uri` - The URI of the resource to write
    /// * `stream` - The stream to write to
    /// # Returns
    /// The number of bytes written
    /// # Errors
    /// If the resource does not exist
    pub fn resource_to_stream(&self, uri: &str, stream: &mut dyn CAIReadWrite) -> Result<usize> {
        self.manifest_store
            .get_resource(uri, stream)
            .map(|size| size as usize)
    }
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.json().as_str())
    }
}
