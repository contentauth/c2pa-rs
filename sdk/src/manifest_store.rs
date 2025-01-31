// Copyright 2022 Adobe. All rights reserved.
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
    collections::HashMap,
    io::{Read, Seek, Write},
};

use async_generic::async_generic;
use c2pa_crypto::base64;
use c2pa_status_tracker::{DetailedStatusTracker, StatusTracker};
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    claim::ClaimAssetData,
    jumbf::labels::{manifest_label_from_uri, to_absolute_uri, to_relative_uri},
    store::Store,
    validation_results::ValidationResults,
    validation_status::{validation_results_for_store, ValidationStatus},
    Error, Manifest, Result,
};

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// A Container for a set of Manifests and a ValidationStatus list
pub struct ManifestStore {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// A label for the active (most recent) manifest in the store
    active_manifest: Option<String>,

    /// A HashMap of Manifests
    manifests: HashMap<String, Manifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// ValidationStatus generated when loading the ManifestStore from an asset
    validation_status: Option<Vec<ValidationStatus>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    // ValidationStatus generated when loading the ManifestStore from an asset
    validation_results: Option<ValidationResults>,

    #[serde(skip)]
    /// The internal store representing the manifest store
    store: Store,
}

impl ManifestStore {
    /// allocates a new empty ManifestStore
    pub fn new() -> Self {
        ManifestStore {
            active_manifest: None,
            manifests: HashMap::<String, Manifest>::new(),
            validation_status: None,
            store: Store::new(),
            validation_results: None,
        }
    }

    /// Returns a reference to the active manifest label or None
    pub fn active_label(&self) -> Option<&str> {
        self.active_manifest.as_deref()
    }

    /// Returns a reference to the active manifest or None
    pub fn get_active(&self) -> Option<&Manifest> {
        if let Some(label) = self.active_manifest.as_ref() {
            self.get(label)
        } else {
            None
        }
    }

    /// Returns a reference to manifest HashMap
    pub fn manifests(&self) -> &HashMap<String, Manifest> {
        &self.manifests
    }

    /// Returns a reference to the requested manifest or None
    pub fn get(&self, label: &str) -> Option<&Manifest> {
        self.manifests.get(label)
    }

    // writes a resource identified uri to the given stream
    pub fn get_resource(&self, uri: &str, stream: impl Write + Read + Seek + Send) -> Result<u64> {
        // get the manifest referenced by the uri, or the active one if None
        // add logic to search for local or absolute uri identifiers
        let (manifest, label) = match manifest_label_from_uri(uri) {
            Some(label) => (self.get(&label), label),
            None => (
                self.get_active(),
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
    }

    /// Returns a reference the [ValidationStatus] Vec or None
    pub fn validation_status(&self) -> Option<&[ValidationStatus]> {
        self.validation_status.as_deref()
    }

    pub fn validation_results(&self) -> Option<&ValidationResults> {
        self.validation_results.as_ref()
    }

    /// creates a ManifestStore from a Store with validation
    #[allow(dead_code)] // async not used without v1 feature
    #[async_generic]
    pub(crate) fn from_store(store: Store, validation_log: &impl StatusTracker) -> ManifestStore {
        if _sync {
            Self::from_store_impl(
                store,
                validation_log,
                #[cfg(feature = "file_io")]
                None,
            )
        } else {
            Self::from_store_impl_async(
                store,
                validation_log,
                #[cfg(feature = "file_io")]
                None,
            )
            .await
        }
    }

    /// creates a ManifestStore from a Store writing resources to resource_path
    #[cfg(all(feature = "file_io", feature = "v1_api"))]
    pub(crate) fn from_store_with_resources(
        store: Store,
        validation_log: &impl StatusTracker,
        resource_path: &Path,
    ) -> ManifestStore {
        ManifestStore::from_store_impl(store, validation_log, Some(resource_path))
    }

    // internal implementation of from_store
    fn from_store_impl(
        store: Store,
        validation_log: &impl StatusTracker,
        #[cfg(feature = "file_io")] resource_path: Option<&Path>,
    ) -> ManifestStore {
        let mut validation_results = validation_results_for_store(&store, validation_log);

        let mut manifest_store = ManifestStore::new();
        manifest_store.active_manifest = store.provenance_label();
        manifest_store.store = store;

        let store = &manifest_store.store;
        for claim in store.claims() {
            let manifest_label = claim.label();
            #[cfg(feature = "file_io")]
            let result = Manifest::from_store(store, manifest_label, resource_path);
            #[cfg(not(feature = "file_io"))]
            let result = Manifest::from_store(store, manifest_label);

            match result {
                Ok(manifest) => {
                    manifest_store
                        .manifests
                        .insert(manifest_label.to_owned(), manifest);
                }
                Err(e) => {
                    validation_results.add_status(manifest_label, ValidationStatus::from_error(&e));
                }
            };
        }

        manifest_store.validation_status = validation_results.validation_errors();
        manifest_store.validation_results = Some(validation_results);

        manifest_store
    }

    async fn from_store_impl_async(
        store: Store,
        validation_log: &impl StatusTracker,
        #[cfg(feature = "file_io")] resource_path: Option<&Path>,
    ) -> ManifestStore {
        let mut validation_results = validation_results_for_store(&store, validation_log);

        let mut manifest_store = ManifestStore::new();
        manifest_store.active_manifest = store.provenance_label();
        manifest_store.store = store;

        let store = &manifest_store.store;
        for claim in store.claims() {
            let manifest_label = claim.label();
            #[cfg(feature = "file_io")]
            let result = Manifest::from_store_async(store, manifest_label, resource_path).await;
            #[cfg(not(feature = "file_io"))]
            let result = Manifest::from_store_async(store, manifest_label).await;

            match result {
                Ok(manifest) => {
                    manifest_store
                        .manifests
                        .insert(manifest_label.to_owned(), manifest);
                }
                Err(e) => {
                    validation_results.add_status(manifest_label, ValidationStatus::from_error(&e));
                }
            };
        }

        manifest_store.validation_status = validation_results.validation_errors();
        manifest_store.validation_results = Some(validation_results);

        manifest_store
    }

    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    /// Creates a new Manifest Store from a Manifest
    #[allow(dead_code)]
    #[deprecated(since = "0.38.0", note = "Please use Reader::from_json() instead")]
    #[cfg(feature = "v1_api")]
    pub fn from_manifest(manifest: &Manifest) -> Result<Self> {
        use c2pa_status_tracker::OneShotStatusTracker;
        let store = manifest.to_store()?;
        Ok(Self::from_store_impl(
            store,
            &OneShotStatusTracker::default(),
            #[cfg(feature = "file_io")]
            manifest.resources().base_path(),
        ))
    }

    /// Generate a Store from a format string and bytes.
    #[cfg(feature = "v1_api")]
    #[deprecated(since = "0.38.0", note = "Please use Reader::from_stream() instead")]
    #[cfg(feature = "v1_api")]
    #[async_generic]
    pub fn from_bytes(format: &str, image_bytes: &[u8], verify: bool) -> Result<ManifestStore> {
        let mut validation_log = DetailedStatusTracker::default();

        let result = if _sync {
            Store::load_from_memory(format, image_bytes, verify, &mut validation_log)
        } else {
            Store::load_from_memory_async(format, image_bytes, verify, &mut validation_log).await
        };

        match result {
            Ok(store) => {
                if _sync {
                    Ok(Self::from_store(store, &validation_log))
                } else {
                    Ok(Self::from_store_async(store, &validation_log).await)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Generate a Store from a format string and stream.
    #[deprecated(since = "0.38.0", note = "Please use Reader::from_stream() instead")]
    #[async_generic(async_signature(
        format: &str,
        mut stream: impl Read + Seek + Send,
        verify: bool,
    ))]
    pub fn from_stream(
        format: &str,
        mut stream: impl Read + Seek + Send,
        verify: bool,
    ) -> Result<ManifestStore> {
        let mut validation_log = DetailedStatusTracker::default();

        let manifest_bytes = Store::load_jumbf_from_stream(format, &mut stream)?;
        let store = Store::from_jumbf(&manifest_bytes, &mut validation_log)?;
        if verify {
            // verify store and claims
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
        }
        Ok(Self::from_store(store, &validation_log))
    }

    #[cfg(feature = "file_io")]
    /// Loads a ManifestStore from a file
    /// Example:
    ///
    /// ```
    /// # use c2pa::Result;
    /// use c2pa::ManifestStore;
    /// # fn main() -> Result<()> {
    /// let manifest_store = ManifestStore::from_file("tests/fixtures/C.jpg")?;
    /// println!("{}", manifest_store);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "v1_api")]
    #[deprecated(since = "0.38.0", note = "Please use Reader::from_file() instead")]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<ManifestStore> {
        let mut validation_log = DetailedStatusTracker::default();

        let store = Store::load_from_asset(path.as_ref(), true, &mut validation_log)?;
        Ok(Self::from_store(store, &validation_log))
    }

    #[cfg(all(feature = "file_io", feature = "v1_api"))]
    /// Loads a ManifestStore from a file adding resources to a folder
    /// Example:
    ///
    /// ```
    /// # use c2pa::Result;
    /// use c2pa::ManifestStore;
    /// # fn main() -> Result<()> {
    /// let manifest_store = ManifestStore::from_file_with_resources(
    ///     "tests/fixtures/C.jpg",
    ///     "../target/tmp/manifest_store",
    /// )?;
    /// println!("{}", manifest_store);
    /// # Ok(())
    /// # }
    /// ```
    #[allow(dead_code)]
    #[deprecated(
        since = "0.38.0",
        note = "Please use Reader::from_file()?.to_folder() instead"
    )]
    pub fn from_file_with_resources<P: AsRef<Path>>(
        path: P,
        resource_path: P,
    ) -> Result<ManifestStore> {
        let mut validation_log = DetailedStatusTracker::default();

        let store = Store::load_from_asset(path.as_ref(), true, &mut validation_log)?;
        Ok(Self::from_store_with_resources(
            store,
            &validation_log,
            resource_path.as_ref(),
        ))
    }

    /// Loads a ManifestStore from an init segment and fragment.  This
    /// would be used to load and validate fragmented MP4 files that span
    /// multiple separate assets.
    #[allow(dead_code)]
    #[deprecated(
        since = "0.38.0",
        note = "Please use Reader::from_fragment_async() instead"
    )]
    #[cfg(feature = "v1_api")]
    pub async fn from_fragment_bytes_async(
        format: &str,
        init_bytes: &[u8],
        fragment_bytes: &[u8],
        verify: bool,
    ) -> Result<ManifestStore> {
        let mut validation_log = DetailedStatusTracker::default();

        match Store::load_fragment_from_memory_async(
            format,
            init_bytes,
            fragment_bytes,
            verify,
            &mut validation_log,
        )
        .await
        {
            Ok(store) => Ok(Self::from_store_async(store, &validation_log).await),
            Err(e) => Err(e),
        }
    }

    #[cfg(feature = "file_io")]
    #[deprecated(
        since = "0.38.0",
        note = "Please use Reader::from_fragmented_files() instead"
    )]
    /// Loads a ManifestStore from an init segment and fragments.  This
    /// would be used to load and validate fragmented MP4 files that span
    /// multiple separate assets files.
    pub fn from_fragments<P: AsRef<Path>>(
        path: P,
        fragments: &Vec<std::path::PathBuf>,
        verify: bool,
    ) -> Result<ManifestStore> {
        let mut validation_log = DetailedStatusTracker::default();

        let asset_type = crate::jumbf_io::get_supported_file_extension(path.as_ref())
            .ok_or(crate::Error::UnsupportedType)?;

        let mut init_segment = std::fs::File::open(path.as_ref())?;

        match Store::load_from_file_and_fragments(
            &asset_type,
            &mut init_segment,
            fragments,
            verify,
            &mut validation_log,
        ) {
            Ok(store) => Ok(Self::from_store(store, &validation_log)),
            Err(e) => Err(e),
        }
    }

    /// Asynchronously loads a manifest from a buffer holding a binary manifest (.c2pa) and validates against an asset buffer
    ///
    /// # Example: Creating a manifest store from a .c2pa manifest and validating it against an asset
    /// ```
    /// use c2pa::{Result, ManifestStore};
    ///
    /// # fn main() -> Result<()> {
    /// #    async {
    ///         let asset_bytes = include_bytes!("../tests/fixtures/cloud.jpg");
    ///         let manifest_bytes = include_bytes!("../tests/fixtures/cloud_manifest.c2pa");
    ///
    ///         let manifest_store = ManifestStore::from_manifest_and_asset_bytes_async(manifest_bytes, "image/jpg", asset_bytes)
    ///             .await
    ///             .unwrap();
    ///
    ///         println!("{}", manifest_store);
    /// #    };
    /// #
    /// #    Ok(())
    /// }
    /// ```
    #[allow(dead_code)]
    #[deprecated(
        since = "0.38.0",
        note = "Please use Reader::from_manifest_data_and_stream_async() instead"
    )]
    #[cfg(feature = "v1_api")]
    pub async fn from_manifest_and_asset_bytes_async(
        manifest_bytes: &[u8],
        format: &str,
        asset_bytes: &[u8],
    ) -> Result<ManifestStore> {
        let mut validation_log = DetailedStatusTracker::default();
        let store = Store::from_jumbf(manifest_bytes, &mut validation_log)?;

        Store::verify_store_async(
            &store,
            &mut ClaimAssetData::Bytes(asset_bytes, format),
            &mut validation_log,
        )
        .await?;

        Ok(Self::from_store_async(store, &validation_log).await)
    }

    /// Synchronously loads a manifest from a buffer holding a binary manifest (.c2pa) and validates against an asset buffer
    ///
    /// # Example: Creating a manifest store from a .c2pa manifest and validating it against an asset
    /// ```
    /// use c2pa::{Result, ManifestStore};
    ///
    /// # fn main() -> Result<()> {
    /// #    async {
    ///         let asset_bytes = include_bytes!("../tests/fixtures/cloud.jpg");
    ///         let manifest_bytes = include_bytes!("../tests/fixtures/cloud_manifest.c2pa");
    ///
    ///         let manifest_store = ManifestStore::from_manifest_and_asset_bytes(manifest_bytes, "image/jpg", asset_bytes)
    ///             .unwrap();
    ///
    ///         println!("{}", manifest_store);
    /// #    };
    /// #
    /// #    Ok(())
    /// }
    #[allow(dead_code)]
    #[deprecated(
        since = "0.38.0",
        note = "Please use Reader::from_manifest_data_and_stream() instead"
    )]
    #[cfg(feature = "v1_api")]
    pub fn from_manifest_and_asset_bytes(
        manifest_bytes: &[u8],
        format: &str,
        asset_bytes: &[u8],
    ) -> Result<ManifestStore> {
        let mut validation_log = DetailedStatusTracker::default();
        let store = Store::from_jumbf(manifest_bytes, &mut validation_log)?;

        Store::verify_store(
            &store,
            &mut ClaimAssetData::Bytes(asset_bytes, format),
            &mut validation_log,
        )?;

        Ok(Self::from_store(store, &validation_log))
    }
}

impl Default for ManifestStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ManifestStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut json = serde_json::to_string_pretty(self).unwrap_or_default();

        fn omit_tag(mut json: String, tag: &str) -> String {
            while let Some(index) = json.find(&format!("\"{tag}\": [")) {
                if let Some(idx2) = json[index..].find(']') {
                    json = format!(
                        "{}\"{}\": \"<omitted>\"{}",
                        &json[..index],
                        tag,
                        &json[index + idx2 + 1..]
                    );
                }
            }
            json
        }

        // Make a base64 hash from Vec<u8> values.
        fn b64_tag(mut json: String, tag: &str) -> String {
            while let Some(index) = json.find(&format!("\"{tag}\": [")) {
                if let Some(idx2) = json[index..].find(']') {
                    let idx3 = json[index..].find('[').unwrap_or_default();

                    let bytes: Vec<u8> =
                        serde_json::from_slice(json[index + idx3..index + idx2 + 1].as_bytes())
                            .unwrap_or_default();

                    json = format!(
                        "{}\"{}\": \"{}\"{}",
                        &json[..index],
                        tag,
                        base64::encode(&bytes),
                        &json[index + idx2 + 1..]
                    );
                }
            }

            json
        }

        json = b64_tag(json, "hash");
        json = omit_tag(json, "pad");

        f.write_str(&json)
    }
}

#[cfg(all(test, any(target_arch = "wasm32", feature = "openssl")))]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use c2pa_status_tracker::OneShotStatusTracker;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use super::*;
    use crate::utils::test::create_test_store;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    // #[cfg_attr(not(target_arch = "wasm32"), test)]
    // #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[test]
    fn manifest_report() {
        let store = create_test_store().expect("creating test store");

        let manifest_store = ManifestStore::from_store(store, &OneShotStatusTracker::default());
        assert!(manifest_store.active_manifest.is_some());
        assert!(!manifest_store.manifests.is_empty());
        let manifest = manifest_store.get_active().unwrap();
        assert!(!manifest.ingredients().is_empty());
        // make sure we have two different ingredients
        assert_eq!(manifest.ingredients()[0].format(), Some("image/jpeg"));
        assert_eq!(manifest.ingredients()[1].format(), Some("image/png"));

        let full_report = manifest_store.to_string();
        assert!(!full_report.is_empty());
        println!("{full_report}");
    }

    #[test]
    #[cfg(feature = "v1_api")]
    #[allow(deprecated)]
    fn manifest_report_image() {
        let image_bytes = include_bytes!("../tests/fixtures/CA.jpg");

        let manifest_store = ManifestStore::from_bytes("image/jpeg", image_bytes, true).unwrap();

        assert!(!manifest_store.manifests.is_empty());
        assert!(manifest_store.active_label().is_some());
        assert!(manifest_store.get_active().is_some());
        assert!(!manifest_store.manifests().is_empty());
        assert_eq!(manifest_store.validation_status(), None);
        let manifest = manifest_store.get_active().unwrap();
        assert!(!manifest.ingredients().is_empty());
        assert_eq!(manifest.issuer().unwrap(), "C2PA Test Signing Cert");
        assert!(manifest.time().is_some());
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg(feature = "v1_api")]
    #[allow(deprecated)]
    async fn manifest_report_image_async() {
        let image_bytes = include_bytes!("../tests/fixtures/CA.jpg");

        let manifest_store = ManifestStore::from_bytes_async("image/jpeg", image_bytes, true)
            .await
            .unwrap();

        assert!(!manifest_store.manifests.is_empty());
        assert!(manifest_store.active_label().is_some());
        assert!(manifest_store.get_active().is_some());
        assert!(!manifest_store.manifests().is_empty());
        assert_eq!(manifest_store.validation_status(), None);
        let manifest = manifest_store.get_active().unwrap();
        assert!(!manifest.ingredients().is_empty());
        assert_eq!(manifest.issuer().unwrap(), "C2PA Test Signing Cert");
        assert!(manifest.time().is_some());
    }

    #[test]
    #[cfg(feature = "file_io")]
    #[cfg(feature = "v1_api")]
    #[allow(deprecated)]
    fn manifest_report_from_file() {
        let manifest_store = ManifestStore::from_file("tests/fixtures/CA.jpg").unwrap();
        println!("{manifest_store}");

        assert!(manifest_store.active_label().is_some());
        assert!(manifest_store.get_active().is_some());
        assert!(!manifest_store.manifests().is_empty());
        assert_eq!(manifest_store.validation_status(), None);
        let manifest = manifest_store.get_active().unwrap();
        assert!(!manifest.ingredients().is_empty());
        assert_eq!(manifest.issuer().unwrap(), "C2PA Test Signing Cert");
        assert!(manifest.time().is_some());
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[allow(deprecated)]
    #[cfg(feature = "v1_api")]
    async fn manifest_report_from_manifest_and_asset_bytes_async() {
        let asset_bytes = include_bytes!("../tests/fixtures/cloud.jpg");
        let manifest_bytes = include_bytes!("../tests/fixtures/cloud_manifest.c2pa");

        let manifest_store = ManifestStore::from_manifest_and_asset_bytes_async(
            manifest_bytes,
            "image/jpg",
            asset_bytes,
        )
        .await
        .unwrap();
        assert!(!manifest_store.manifests().is_empty());
        assert_eq!(manifest_store.validation_status(), None);
        println!("{manifest_store}");
    }

    #[test]
    #[cfg(feature = "file_io")]
    #[cfg(feature = "v1_api")]
    #[allow(deprecated)]
    fn manifest_report_from_file_with_resources() {
        let manifest_store = ManifestStore::from_file_with_resources(
            "tests/fixtures/CIE-sig-CA.jpg",
            "../target/ms",
        )
        .expect("from_store_with_resources");
        println!("{manifest_store}");

        assert!(manifest_store.active_label().is_some());
        assert!(manifest_store.get_active().is_some());
        assert!(!manifest_store.manifests().is_empty());
        assert_eq!(manifest_store.validation_status(), None);
        let manifest = manifest_store.get_active().unwrap();
        assert!(!manifest.ingredients().is_empty());
        assert_eq!(manifest.issuer().unwrap(), "C2PA Test Signing Cert");
        assert!(manifest.time().is_some());
    }

    #[test]
    #[cfg(feature = "v1_api")]
    #[allow(deprecated)]
    fn manifest_report_from_stream() {
        let image_bytes: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
        let stream = std::io::Cursor::new(image_bytes);
        let manifest_store = ManifestStore::from_stream("image/jpeg", stream, true).unwrap();
        println!("{manifest_store}");

        assert!(manifest_store.active_label().is_some());
        assert!(manifest_store.get_active().is_some());
        assert!(!manifest_store.manifests().is_empty());
        assert_eq!(manifest_store.validation_status(), None);
        let manifest = manifest_store.get_active().unwrap();
        assert!(!manifest.ingredients().is_empty());
        assert_eq!(manifest.issuer().unwrap(), "C2PA Test Signing Cert");
        assert!(manifest.time().is_some());
    }
}
