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

#![deny(missing_docs)]
#[cfg(feature = "file_io")]
use std::path::{Path, PathBuf};
use std::{borrow::Cow, io::Cursor};

use log::{debug, error};
#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    assertion::{get_thumbnail_image_type, Assertion, AssertionBase},
    assertions::{self, labels, Metadata, Relationship, Thumbnail},
    asset_io::CAIRead,
    claim::{Claim, ClaimAssetData},
    error::{Error, Result},
    hashed_uri::HashedUri,
    jumbf::{
        self,
        labels::{manifest_label_from_uri, to_assertion_uri},
    },
    jumbf_io::load_jumbf_from_stream,
    resource_store::{skip_serializing_resources, ResourceRef, ResourceStore},
    status_tracker::{log_item, DetailedStatusTracker, StatusTracker},
    store::Store,
    utils::{base64, xmp_inmemory_utils::XmpInfo},
    validation_status::{self, status_for_store, ValidationStatus},
};

#[derive(Debug, Default, Deserialize, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// An `Ingredient` is any external asset that has been used in the creation of an image.
pub struct Ingredient {
    /// A human-readable title, generally source filename.
    title: String,

    /// The format of the source file as a MIME type.
    #[serde(default = "default_format")]
    format: String,

    /// Document ID from `xmpMM:DocumentID` in XMP metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    document_id: Option<String>,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata.
    //#[serde(default = "default_instance_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,

    /// URI from `dcterms:provenance` in XMP metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<String>,

    /// A thumbnail image capturing the visual state at the time of import.
    ///
    /// A tuple of thumbnail MIME format (i.e. `image/jpeg`) and binary bits of the image.
    #[serde(skip_serializing_if = "Option::is_none")]
    thumbnail: Option<ResourceRef>,

    /// An optional hash of the asset to prevent duplicates.
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,

    /// Set to `ParentOf` if this is the parent ingredient.
    ///
    /// There can only be one parent ingredient in the ingredients.
    // is_parent: Option<bool>,
    #[serde(default = "default_relationship")]
    relationship: Relationship,

    /// The active manifest label (if one exists).
    ///
    /// If this ingredient has a [`ManifestStore`],
    /// this will hold the label of the active [`Manifest`].
    ///
    /// [`Manifest`]: crate::Manifest
    /// [`ManifestStore`]: crate::ManifestStore
    #[serde(skip_serializing_if = "Option::is_none")]
    active_manifest: Option<String>,

    /// Validation results.
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_status: Option<Vec<ValidationStatus>>,

    /// A reference to the actual data of the ingredient.
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<ResourceRef>,

    /// Additional description of the ingredient.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,

    /// URI to an informational page about the ingredient or its data.
    #[serde(rename = "informational_URI", skip_serializing_if = "Option::is_none")]
    informational_uri: Option<String>,

    /// Any additional [`Metadata`] as defined in the C2PA spec.
    ///
    /// [`Manifest`]: crate::Manifest
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Metadata>,

    /// A [`ManifestStore`] from the source asset extracted as a binary C2PA blob.
    ///
    /// [`ManifestStore`]: crate::ManifestStore
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_data: Option<ResourceRef>,

    #[serde(skip_deserializing)]
    #[serde(skip_serializing_if = "skip_serializing_resources")]
    resources: ResourceStore,
}

fn default_instance_id() -> String {
    format!("xmp:iid:{}", Uuid::new_v4())
}

fn default_format() -> String {
    "application/octet-stream".to_owned()
}

fn default_relationship() -> Relationship {
    Relationship::default()
}

impl Ingredient {
    /// Constructs a new `Ingredient`.
    ///
    /// # Arguments
    ///
    /// * `title` - A user-displayable name for this ingredient (often a filename).
    /// * `format` - The MIME media type of the ingredient - i.e. `image/jpeg`.
    /// * `instance_id` - A unique identifier, such as the value of the ingredient's `xmpMM:InstanceID`.
    ///
    /// # Examples
    ///
    /// ```
    /// use c2pa::Ingredient;
    /// let ingredient = Ingredient::new("title", "image/jpeg", "ed610ae51f604002be3dbf0c589a2f1f");
    /// ```
    pub fn new<S>(title: S, format: S, instance_id: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            title: title.into(),
            format: format.into(),
            instance_id: Some(instance_id.into()),
            ..Default::default()
        }
    }

    /// Constructs a new V2 `Ingredient`.
    ///
    /// # Arguments
    ///
    /// * `title` - A user-displayable name for this ingredient (often a filename).
    /// * `format` - The MIME media type of the ingredient - i.e. `image/jpeg`.
    ///
    /// # Examples
    ///
    /// ```
    /// use c2pa::Ingredient;
    /// let ingredient = Ingredient::new_v2("title", "image/jpeg");
    /// ```
    pub fn new_v2<S1, S2>(title: S1, format: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        Self {
            title: title.into(),
            format: format.into(),
            ..Default::default()
        }
    }

    // try to determine if this is a V2 ingredient
    pub(crate) fn is_v2(&self) -> bool {
        self.instance_id.is_none()
            || self.data.is_some()
            || self.description.is_some()
            || self.informational_uri.is_some()
            || self.relationship == Relationship::InputTo
    }

    /// Returns a user-displayable title for this ingredient.
    pub fn title(&self) -> &str {
        self.title.as_str()
    }

    /// Returns a MIME content_type for this asset associated with this ingredient.
    pub fn format(&self) -> &str {
        self.format.as_str()
    }

    /// Returns a document identifier if one exists.
    pub fn document_id(&self) -> Option<&str> {
        self.document_id.as_deref()
    }

    /// Returns the instance identifier.
    ///
    /// For v2 ingredients this can return an empty string
    pub fn instance_id(&self) -> &str {
        self.instance_id.as_deref().unwrap_or("")
    }

    /// Returns the provenance uri if available.
    pub fn provenance(&self) -> Option<&str> {
        self.provenance.as_deref()
    }

    /// Returns a ResourceRef or `None`.
    pub fn thumbnail_ref(&self) -> Option<&ResourceRef> {
        self.thumbnail.as_ref()
    }

    /// Returns thumbnail tuple Some((format, bytes)) or None
    pub fn thumbnail(&self) -> Option<(&str, Cow<Vec<u8>>)> {
        self.thumbnail
            .as_ref()
            .and_then(|t| Some(t.format.as_str()).zip(self.resources.get(&t.identifier).ok()))
    }

    /// Returns a Cow of thumbnail bytes or Err(Error::NotFound)`.
    pub fn thumbnail_bytes(&self) -> Result<Cow<Vec<u8>>> {
        match self.thumbnail.as_ref() {
            Some(thumbnail) => self.resources.get(&thumbnail.identifier),
            None => Err(Error::NotFound),
        }
    }

    /// Returns an optional hash to uniquely identify this asset
    pub fn hash(&self) -> Option<&str> {
        self.hash.as_deref()
    }

    /// Returns `true` if this is labeled as the parent ingredient.
    pub fn is_parent(&self) -> bool {
        self.relationship == Relationship::ParentOf
    }

    /// Returns the relationship status of the ingredient.
    pub fn relationship(&self) -> &Relationship {
        &self.relationship
    }

    /// Returns a reference to the [`ValidationStatus`]s if they exist.
    pub fn validation_status(&self) -> Option<&[ValidationStatus]> {
        self.validation_status.as_deref()
    }

    /// Returns a reference to [`Metadata`] if it exists.
    pub fn metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }

    /// Returns the label for the active [`Manifest`] in this ingredient
    /// if one exists.
    ///
    /// If `None`, the ingredient has no [`Manifest`]s.
    ///
    /// [`Manifest`]: crate::Manifest
    pub fn active_manifest(&self) -> Option<&str> {
        self.active_manifest.as_deref()
    }

    /// Returns a reference to C2PA manifest data if it exists.
    ///
    /// manifest_data is the binary form of a manifest store in .c2pa format.
    pub fn manifest_data_ref(&self) -> Option<&ResourceRef> {
        self.manifest_data.as_ref()
    }

    /// Returns a copy on write ref to the manifest data bytes or None`.
    ///
    /// manifest_data is the binary form of a manifest store in .c2pa format.
    pub fn manifest_data(&self) -> Option<Cow<Vec<u8>>> {
        self.manifest_data
            .as_ref()
            .and_then(|r| self.resources.get(&r.identifier).ok())
    }

    /// Returns a reference to ingredient data if it exists.
    pub fn data_ref(&self) -> Option<&ResourceRef> {
        self.data.as_ref()
    }

    /// Returns the detailed description of the ingredient if it exists.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns an informational uri for the ingredient if it exists.
    pub fn informational_uri(&self) -> Option<&str> {
        self.informational_uri.as_deref()
    }

    /// Sets a human-readable title for this ingredient.
    pub fn set_title<S: Into<String>>(&mut self, title: S) -> &mut Self {
        self.title = title.into();
        self
    }

    /// Sets the document instanceId.
    ///
    /// This call is optional for v2 ingredients.
    ///
    /// Typically this is found in XMP under `xmpMM:InstanceID`.
    pub fn set_instance_id<S: Into<String>>(&mut self, instance_id: S) -> &mut Self {
        self.instance_id = Some(instance_id.into());
        self
    }

    /// Sets the document identifier.
    ///
    /// This call is optional.
    ///
    /// Typically this is found in XMP under `xmpMM:DocumentID`.
    pub fn set_document_id<S: Into<String>>(&mut self, document_id: S) -> &mut Self {
        self.document_id = Some(document_id.into());
        self
    }

    /// Sets the provenance URI.
    ///
    /// This call is optional.
    ///
    /// Typically this is found in XMP under `dcterms:provenance`.
    pub fn set_provenance<S: Into<String>>(&mut self, provenance: S) -> &mut Self {
        self.provenance = Some(provenance.into());
        self
    }

    /// Identifies this ingredient as the parent.
    ///
    /// Only one ingredient should be flagged as a parent.
    /// Use Manifest.set_parent to ensure this is the only parent ingredient
    pub fn set_is_parent(&mut self) -> &mut Self {
        self.relationship = Relationship::ParentOf;
        self
    }

    /// Set the ingredient Relationship status.
    ///
    /// Only one ingredient should be set as a parentOf.
    /// Use Manifest.set_parent to ensure this is the only parent ingredient
    pub fn set_relationship(&mut self, relationship: Relationship) -> &mut Self {
        self.relationship = relationship;
        self
    }

    /// Sets the thumbnail from a ResourceRef.
    pub fn set_thumbnail_ref(&mut self, thumbnail: ResourceRef) -> Result<&mut Self> {
        self.thumbnail = Some(thumbnail);
        Ok(self)
    }

    /// Sets the thumbnail format and image data.
    pub fn set_thumbnail<S: Into<String>, B: Into<Vec<u8>>>(
        &mut self,
        format: S,
        bytes: B,
    ) -> Result<&mut Self> {
        let base_id = self.instance_id().to_string();
        self.thumbnail = Some(self.resources.add_with(&base_id, &format.into(), bytes)?);
        Ok(self)
    }

    /// Sets the thumbnail format and image data only in memory
    ///
    /// This is only used for internally generated thumbnails - when
    /// reading thumbnails from files, we don't want to write these to file
    /// So this ensures they stay in memory unless written out.
    #[deprecated(note = "Please use set_thumbnail instead", since = "0.28.0")]
    pub fn set_memory_thumbnail<S: Into<String>, B: Into<Vec<u8>>>(
        &mut self,
        format: S,
        bytes: B,
    ) -> Result<&mut Self> {
        // Do not write this as a file when reading from files
        #[cfg(feature = "file_io")]
        let base_path = self.resources_mut().take_base_path();
        let base_id = self.instance_id().to_string();
        self.thumbnail = Some(self.resources.add_with(&base_id, &format.into(), bytes)?);
        #[cfg(feature = "file_io")]
        if let Some(path) = base_path {
            self.resources_mut().set_base_path(path)
        }
        Ok(self)
    }

    /// Sets the hash value generated from the entire asset.
    pub fn set_hash<S: Into<String>>(&mut self, hash: S) -> &mut Self {
        self.hash = Some(hash.into());
        self
    }

    /// Adds a [ValidationStatus] to this ingredient.
    pub fn add_validation_status(&mut self, status: ValidationStatus) -> &mut Self {
        match &mut self.validation_status {
            None => self.validation_status = Some(vec![status]),
            Some(validation_status) => validation_status.push(status),
        }
        self
    }

    /// Adds any desired [`Metadata`] to this ingredient.
    pub fn set_metadata(&mut self, metadata: Metadata) -> &mut Self {
        self.metadata = Some(metadata);
        self
    }

    /// Sets the label for the active manifest in the manifest data.
    pub fn set_active_manifest<S: Into<String>>(&mut self, label: S) -> &mut Self {
        self.active_manifest = Some(label.into());
        self
    }

    /// Sets a reference to Manifest C2PA data
    pub fn set_manifest_data_ref(&mut self, data_ref: ResourceRef) -> Result<&mut Self> {
        // verify the resource referenced exists
        if !self.resources.exists(&data_ref.identifier) {
            return Err(Error::NotFound);
        };
        self.manifest_data = Some(data_ref);
        Ok(self)
    }

    /// Sets the Manifest C2PA data for this ingredient with bytes
    pub fn set_manifest_data(&mut self, data: Vec<u8>) -> Result<&mut Self> {
        let base_id = self.instance_id().to_string();
        self.manifest_data = Some(
            self.resources
                .add_with(&base_id, "application/c2pa", data)?,
        );
        Ok(self)
    }

    /// Sets a reference to Ingredient data
    pub fn set_data_ref(&mut self, data_ref: ResourceRef) -> Result<&mut Self> {
        // verify the resource referenced exists
        if !self.resources.exists(&data_ref.identifier) {
            return Err(Error::NotFound);
        };
        self.data = Some(data_ref);
        Ok(self)
    }

    /// Sets a detailed description for this ingredient
    pub fn set_description<S: Into<String>>(&mut self, description: S) -> &mut Self {
        self.description = Some(description.into());
        self
    }

    /// Sets an informational uri if needed
    pub fn set_informational_uri<S: Into<String>>(&mut self, uri: S) -> &mut Self {
        self.informational_uri = Some(uri.into());
        self
    }

    /// Return an immutable reference to the ingredient resources
    pub fn resources(&self) -> &ResourceStore {
        &self.resources
    }

    /// Return an mutable reference to the ingredient resources
    pub fn resources_mut(&mut self) -> &mut ResourceStore {
        &mut self.resources
    }

    /// Gathers filename, extension, and format from a file path.
    #[cfg(feature = "file_io")]
    fn get_path_info(path: &std::path::Path) -> (String, String, String) {
        let title = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "".into());

        let extension = path
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_else(|| "".into())
            .to_lowercase();

        let format = crate::utils::mime::extension_to_mime(&extension)
            .unwrap_or("application/binary")
            .to_owned();
        (title, extension, format)
    }

    /// Generates an `Ingredient` from a file path, including XMP info
    /// from the file if available.
    ///
    /// This is used for making asset ingredients that should not load [`ManifestStore`]s.
    ///
    /// [`ManifestStore`]: crate::ManifestStore
    #[cfg(feature = "file_io")]
    pub fn from_file_info<P: AsRef<Path>>(path: P) -> Self {
        // get required information from the file path
        let (title, _, format) = Self::get_path_info(path.as_ref());

        // if we can open the file try tto get xmp info
        match std::fs::File::open(path).map_err(Error::IoError) {
            Ok(mut file) => Self::from_stream_info(&mut file, &format, &title),
            Err(_) => Self {
                title,
                format,
                ..Default::default()
            },
        }
    }

    /// Generates an `Ingredient` from a stream, including XMP info
    pub fn from_stream_info<F, S>(stream: &mut dyn CAIRead, format: F, title: S) -> Self
    where
        F: Into<String>,
        S: Into<String>,
    {
        let format = format.into();
        // if we can open the file try tto get xmp info
        let xmp_info = XmpInfo::from_source(stream, &format);

        let id = if let Some(id) = xmp_info.instance_id {
            id
        } else {
            default_instance_id()
        };

        let mut ingredient = Self::new(title.into(), format, id);

        ingredient.document_id = xmp_info.document_id; // use document id if one exists
        ingredient.provenance = xmp_info.provenance;

        ingredient
    }

    // utility method to set the validation status from store result and log
    // also sets the thumbnail from the claim if valid and it exists
    fn update_validation_status(
        &mut self,
        result: Result<Store>,
        manifest_bytes: Option<Vec<u8>>,
        validation_log: &impl StatusTracker,
    ) -> Result<()> {
        match result {
            Ok(store) => {
                // generate ValidationStatus from ValidationItems filtering for only errors
                let statuses = status_for_store(&store, validation_log);

                if let Some(claim) = store.provenance_claim() {
                    // if the parent claim is valid and has a thumbnail, use it
                    if statuses.is_empty() {
                        if let Some(hashed_uri) = claim
                            .assertions()
                            .iter()
                            .find(|hashed_uri| hashed_uri.url().contains(labels::CLAIM_THUMBNAIL))
                        {
                            // We found a valid claim thumbnail so just reference it, we don't need to copy it
                            let thumb_manifest = manifest_label_from_uri(&hashed_uri.url())
                                .unwrap_or_else(|| claim.label().to_string());
                            let uri =
                                jumbf::labels::to_absolute_uri(&thumb_manifest, &hashed_uri.url());
                            // Try to determine the format from the assertion label in the URL
                            let format = hashed_uri
                                .url()
                                .rsplit_once('.')
                                .map(|(_, ext)| format!("image/{}", ext))
                                .unwrap_or_else(|| "image/jpeg".to_string()); // default to jpeg??
                            let mut thumb = crate::resource_store::ResourceRef::new(format, uri);
                            // keep track of the alg and hash for reuse
                            thumb.alg = hashed_uri.alg();
                            let hash = base64::encode(&hashed_uri.hash());
                            thumb.hash = Some(hash);
                            self.set_thumbnail_ref(thumb)?;
                        }
                    }
                    self.active_manifest = Some(claim.label().to_string());
                }

                if let Some(bytes) = manifest_bytes {
                    self.set_manifest_data(bytes)?;
                }

                self.validation_status = if statuses.is_empty() {
                    None
                } else {
                    Some(statuses)
                };
                Ok(())
            }
            Err(Error::JumbfNotFound)
            | Err(Error::ProvenanceMissing)
            | Err(Error::UnsupportedType) => Ok(()), // no claims but valid file
            Err(Error::BadParam(desc)) if desc == *"unrecognized file type" => Ok(()),
            Err(Error::RemoteManifestUrl(url)) => {
                let status = ValidationStatus::new(validation_status::MANIFEST_INACCESSIBLE)
                    .set_url(url)
                    .set_explanation("Remote manifest not fetched".to_string());
                self.validation_status = Some(vec![status]);
                Ok(())
            }
            Err(Error::RemoteManifestFetch(url)) => {
                let status = ValidationStatus::new(validation_status::MANIFEST_INACCESSIBLE)
                    .set_url(url)
                    .set_explanation("Unable to fetch remote manifest".to_string());
                self.validation_status = Some(vec![status]);
                Ok(())
            }
            Err(e) => {
                // we can ignore the error here because it should have a log entry corresponding to it
                debug!("ingredient {:?}", e);
                // convert any other error to a validation status
                let statuses: Vec<ValidationStatus> = validation_log
                    .get_log()
                    .iter()
                    .filter_map(ValidationStatus::from_validation_item)
                    .filter(|s| !validation_status::is_success(s.code()))
                    .collect();
                self.validation_status = if statuses.is_empty() {
                    None
                } else {
                    Some(statuses)
                };
                Ok(())
            }
        }
    }

    #[cfg(feature = "file_io")]
    /// Creates an `Ingredient` from a file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_file_with_options(path.as_ref(), &DefaultOptions { base: None })
    }

    #[cfg(feature = "file_io")]
    /// Creates an `Ingredient` from a file path.
    pub fn from_file_with_folder<P: AsRef<Path>>(path: P, folder: P) -> Result<Self> {
        Self::from_file_with_options(
            path.as_ref(),
            &DefaultOptions {
                base: Some(PathBuf::from(folder.as_ref())),
            },
        )
    }

    fn thumbnail_from_assertion(assertion: &Assertion) -> (String, Vec<u8>) {
        (
            format!(
                "image/{}",
                get_thumbnail_image_type(&assertion.label_root())
            ),
            assertion.data().to_vec(),
        )
    }

    /// Creates an `Ingredient` from a file path and options.
    #[cfg(feature = "file_io")]
    pub fn from_file_with_options<P: AsRef<Path>>(
        path: P,
        options: &dyn IngredientOptions,
    ) -> Result<Self> {
        Self::from_file_impl(path.as_ref(), options)
    }

    // Internal implementation to avoid code bloat.
    #[cfg(feature = "file_io")]
    fn from_file_impl(path: &Path, options: &dyn IngredientOptions) -> Result<Self> {
        #[cfg(feature = "diagnostics")]
        let _t = crate::utils::time_it::TimeIt::new("Ingredient:from_file_with_options");

        // from the source file we need to get the XMP, JUMBF and generate a thumbnail
        debug!("ingredient {:?}", path);

        // get required information from the file path
        let mut ingredient = Self::from_file_info(path);

        if !path.exists() {
            return Err(Error::FileNotFound(ingredient.title));
        }

        // configure for writing to folders if that option is set
        if let Some(folder) = options.base_path().as_ref() {
            ingredient.with_base_path(folder)?;
        }

        // if options includes a title, use it
        if let Some(opt_title) = options.title(path) {
            ingredient.title = opt_title;
        }

        // optionally generate a hash so we know if the file has changed
        ingredient.hash = options.hash(path);

        let mut validation_log = DetailedStatusTracker::new();

        // retrieve the manifest bytes from embedded, sidecar or remote and convert to store if found
        let (result, manifest_bytes) = match Store::load_jumbf_from_path(path) {
            Ok(manifest_bytes) => {
                (
                    // generate a store from the buffer and then validate from the asset path
                    Store::from_jumbf(&manifest_bytes, &mut validation_log)
                        .and_then(|mut store| {
                            // verify the store
                            store
                                .verify_from_path(path, &mut validation_log)
                                .map(|_| store)
                        })
                        .map_err(|e| {
                            // add a log entry for the error so we act like verify
                            validation_log.log_silent(
                                log_item!("asset", "error loading file", "Ingredient::from_file")
                                    .set_error(&e),
                            );
                            e
                        }),
                    Some(manifest_bytes),
                )
            }
            Err(err) => (Err(err), None),
        };

        // set validation status from result and log
        ingredient.update_validation_status(result, manifest_bytes, &validation_log)?;

        // create a thumbnail if we don't already have a manifest with a thumb we can use
        if ingredient.thumbnail.is_none() {
            if let Some((format, image)) = options.thumbnail(path) {
                ingredient.set_thumbnail(format, image)?;
            }
        }

        Ok(ingredient)
    }

    /// Creates an `Ingredient` from a memory buffer.
    ///
    /// This does not set title or hash
    /// Thumbnail will be set only if one can be retrieved from a previous valid manifest
    pub fn from_memory(format: &str, buffer: &[u8]) -> Result<Self> {
        let mut stream = Cursor::new(buffer);
        Self::from_stream(format, &mut stream)
    }

    /// Creates an `Ingredient` from a stream.
    ///
    /// This does not set title or hash
    /// Thumbnail will be set only if one can be retrieved from a previous valid manifest
    pub fn from_stream(format: &str, stream: &mut dyn CAIRead) -> Result<Self> {
        let mut ingredient = Self::from_stream_info(stream, format, "untitled");
        stream.rewind()?;

        let mut validation_log = DetailedStatusTracker::new();

        // retrieve the manifest bytes from embedded, sidecar or remote and convert to store if found
        let (result, manifest_bytes) = match load_jumbf_from_stream(format, stream) {
            Ok(manifest_bytes) => {
                (
                    // generate a store from the buffer and then validate from the asset path
                    Store::from_jumbf(&manifest_bytes, &mut validation_log)
                        .and_then(|mut store| {
                            // verify the store
                            //todo, change this when we have a stream version of verify
                            let mut buf: Vec<u8> = Vec::new();
                            stream.rewind()?;
                            stream.read_to_end(&mut buf).map_err(Error::IoError)?;
                            store
                                .verify_from_buffer(&buf, format, &mut validation_log)
                                .map(|_| store)
                        })
                        .map_err(|e| {
                            // add a log entry for the error so we act like verify
                            validation_log.log_silent(
                                log_item!("asset", "error loading file", "Ingredient::from_file")
                                    .set_error(&e),
                            );
                            e
                        }),
                    Some(manifest_bytes),
                )
            }
            Err(err) => (Err(err), None),
        };

        // set validation status from result and log
        ingredient.update_validation_status(result, manifest_bytes, &validation_log)?;

        // create a thumbnail if we don't already have a manifest with a thumb we can use
        #[cfg(feature = "add_thumbnails")]
        if ingredient.thumbnail.is_none() {
            stream.rewind()?;
            match crate::utils::thumbnail::make_thumbnail_from_stream(format, stream) {
                Ok((format, image)) => {
                    ingredient.set_thumbnail(format, image)?;
                }
                Err(err) => {
                    log::warn!("Could not create thumbnail. {err}");
                }
            }
        }

        Ok(ingredient)
    }

    /// Creates an `Ingredient` from a memory buffer (async version).
    ///
    /// This does not set title or hash
    /// Thumbnail will be set only if one can be retrieved from a previous valid manifest
    pub async fn from_memory_async(format: &str, buffer: &[u8]) -> Result<Self> {
        let mut stream = Cursor::new(buffer);
        Self::from_stream_async(format, &mut stream).await
    }

    /// Creates an `Ingredient` from a stream (async version).
    ///
    /// This does not set title or hash
    /// Thumbnail will be set only if one can be retrieved from a previous valid manifest
    pub async fn from_stream_async(format: &str, stream: &mut dyn CAIRead) -> Result<Self> {
        let mut ingredient = Self::from_stream_info(stream, format, "untitled");
        stream.rewind()?;

        let mut validation_log = DetailedStatusTracker::new();

        // retrieve the manifest bytes from embedded, sidecar or remote and convert to store if found
        let (result, manifest_bytes) = match Store::load_jumbf_from_stream(format, stream) {
            Ok(manifest_bytes) => {
                (
                    // generate a store from the buffer and then validate from the asset path
                    match Store::from_jumbf(&manifest_bytes, &mut validation_log) {
                        Ok(store) => {
                            // verify the store
                            Store::verify_store_async(
                                &store,
                                &mut ClaimAssetData::Stream(stream, format),
                                &mut validation_log,
                            )
                            .await
                            .map(|_| store)
                        }
                        Err(e) => {
                            validation_log.log_silent(
                                log_item!(
                                    "asset",
                                    "error loading asset",
                                    "Ingredient::from_stream_async"
                                )
                                .set_error(&e),
                            );
                            Err(e)
                        }
                    },
                    Some(manifest_bytes),
                )
            }
            Err(err) => (Err(err), None),
        };

        // set validation status from result and log
        ingredient.update_validation_status(result, manifest_bytes, &validation_log)?;

        // create a thumbnail if we don't already have a manifest with a thumb we can use
        #[cfg(feature = "add_thumbnails")]
        if ingredient.thumbnail.is_none() {
            stream.rewind()?;
            match crate::utils::thumbnail::make_thumbnail_from_stream(format, stream) {
                Ok((format, image)) => {
                    ingredient.set_thumbnail(format, image)?;
                }
                Err(err) => {
                    log::warn!("Could not create thumbnail. {err}");
                }
            }
        }

        Ok(ingredient)
    }

    /// Creates an Ingredient from a store and a URI to an ingredient assertion.
    /// claim_label identifies the claim for relative paths
    pub(crate) fn from_ingredient_uri(
        store: &Store,
        claim_label: &str,
        ingredient_uri: &str,
        #[cfg(feature = "file_io")] resource_path: Option<&Path>,
    ) -> Result<Self> {
        let assertion =
            store
                .get_assertion_from_uri(ingredient_uri)
                .ok_or(Error::AssertionMissing {
                    url: ingredient_uri.to_owned(),
                })?;
        let ingredient_assertion = assertions::Ingredient::from_assertion(assertion)?;

        let mut validation_status = match ingredient_assertion.validation_status.as_ref() {
            Some(status) => status.clone(),
            None => Vec::new(),
        };

        let active_manifest = ingredient_assertion
            .c2pa_manifest
            .and_then(|hash_url| manifest_label_from_uri(&hash_url.url()));

        debug!(
            "Adding Ingredient {} {:?}",
            ingredient_assertion.title, &active_manifest
        );

        // todo: find a better way to do this if we keep this code
        let mut ingredient = Ingredient::new(
            &ingredient_assertion.title,
            &ingredient_assertion.format,
            &ingredient_assertion
                .instance_id
                .unwrap_or_else(default_instance_id),
        );
        ingredient.document_id = ingredient_assertion.document_id;
        ingredient.resources.set_label(claim_label); // set the label for relative paths

        #[cfg(feature = "file_io")]
        if let Some(base_path) = resource_path {
            ingredient.resources_mut().set_base_path(base_path)
        }

        if let Some(hashed_uri) = ingredient_assertion.thumbnail.as_ref() {
            // This could be a relative or absolute thumbnail reference to another manifest
            let target_claim_label = match manifest_label_from_uri(&hashed_uri.url()) {
                Some(label) => label,           // use the manifest from the thumbnail uri
                None => claim_label.to_owned(), /* relative so use the whole url from the thumbnail assertion */
            };
            let maybe_resource_ref = match hashed_uri.url() {
                uri if uri.contains(jumbf::labels::ASSERTIONS) => {
                    // if this is a claim thumbnail, then use the label from the thumbnail uri
                    store
                        .get_assertion_from_uri_and_claim(&hashed_uri.url(), &target_claim_label)
                        .map(|assertion| {
                            let (format, image) = Self::thumbnail_from_assertion(assertion);
                            ingredient
                                .resources
                                .add_uri(&hashed_uri.url(), &format, image)
                        })
                }
                uri if uri.contains(jumbf::labels::DATABOXES) => store
                    .get_data_box_from_uri_and_claim(&hashed_uri.url(), &target_claim_label)
                    .map(|data_box| {
                        ingredient.resources.add_uri(
                            &hashed_uri.url(),
                            &data_box.format,
                            data_box.data.clone(),
                        )
                    }),
                _ => None,
            };
            match maybe_resource_ref {
                Some(data_ref) => {
                    ingredient.thumbnail = Some(data_ref?);
                }
                None => {
                    error!("failed to get {} from {}", hashed_uri.url(), ingredient_uri);
                    validation_status.push(
                        ValidationStatus::new(validation_status::ASSERTION_MISSING.to_string())
                            .set_url(hashed_uri.url()),
                    );
                }
            }
        };

        if let Some(data_uri) = ingredient_assertion.data.as_ref() {
            let data_box = store
                .get_data_box_from_uri_and_claim(&data_uri.url(), claim_label)
                .ok_or_else(|| {
                    error!("failed to get {} from {}", data_uri.url(), ingredient_uri);
                    Error::AssertionMissing {
                        url: data_uri.url(),
                    }
                })?;

            let mut data_ref = ingredient.resources_mut().add_uri(
                &data_uri.url(),
                &data_box.format,
                data_box.data.clone(),
            )?;
            data_ref.data_types = data_box.data_types.clone();
            ingredient.set_data_ref(data_ref)?;
        }

        ingredient.relationship = ingredient_assertion.relationship;
        ingredient.active_manifest = active_manifest;
        if !validation_status.is_empty() {
            ingredient.validation_status = Some(validation_status)
        }
        ingredient.metadata = ingredient_assertion.metadata;
        ingredient.description = ingredient_assertion.description;
        ingredient.informational_uri = ingredient_assertion.informational_uri;
        Ok(ingredient)
    }

    /// Converts a higher level Ingredient into the appropriate components in a claim
    pub(crate) fn add_to_claim(
        &self,
        claim: &mut Claim,
        redactions: Option<Vec<String>>,
    ) -> Result<HashedUri> {
        let mut thumbnail = None;

        // add the ingredient manifest_data to the claim
        // this is how any existing claims are added to the new store
        let c2pa_manifest = match self.manifest_data_ref() {
            Some(resource_ref) => {
                let manifest_label = self
                    .active_manifest
                    .clone()
                    .ok_or(Error::IngredientNotFound)?;

                //if this is the parent ingredient then apply any redactions, converting from labels to uris
                let redactions = match self.is_parent() {
                    true => redactions.as_ref().map(|redactions| {
                        redactions
                            .iter()
                            .map(|r| to_assertion_uri(&manifest_label, r))
                            .collect()
                    }),
                    false => None,
                };

                // get the c2pa manifest bytes
                let manifest_data = self.resources.get(&resource_ref.identifier)?;

                // have Store check and load ingredients and add them to a claim
                let ingredient_store = Store::load_ingredient_to_claim(
                    claim,
                    &manifest_label,
                    &manifest_data,
                    redactions,
                )?;

                // get the ingredient map loaded in previous
                match claim.claim_ingredient(&manifest_label) {
                    Some(ingredient_claims) => {
                        // get the ingredient active claim from the ingredients claim map
                        if let Some(ingredient_active_claim) = ingredient_claims
                            .iter()
                            .find(|c| c.label() == manifest_label)
                        {
                            let hash =
                                ingredient_store.get_manifest_box_hash(ingredient_active_claim); // get C2PA 1.2 JUMBF box hash

                            let uri = jumbf::labels::to_manifest_uri(&manifest_label);

                            // if there are validations and they have all passed, then use the parent claim thumbnail if available
                            if let Some(validation_status) = self.validation_status.as_ref() {
                                if validation_status.iter().all(|r| r.passed()) {
                                    thumbnail = ingredient_active_claim
                                        .assertions()
                                        .iter()
                                        .find(|hashed_uri| {
                                            hashed_uri.url().contains(labels::CLAIM_THUMBNAIL)
                                        })
                                        .map(|t| {
                                            // convert ingredient uris to absolute when adding them
                                            // since this uri references a different manifest
                                            let url = jumbf::labels::to_absolute_uri(
                                                &manifest_label,
                                                &t.url(),
                                            );
                                            HashedUri::new(url, t.alg(), &t.hash())
                                        });
                                }
                            }
                            // generate c2pa_manifest hashed_uri
                            Some(crate::hashed_uri::HashedUri::new(
                                uri,
                                Some(ingredient_active_claim.alg().to_owned()),
                                hash.as_ref(),
                            ))
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            }
            None => None,
        };

        // if the ingredient defines a thumbnail, add it to the claim
        // otherwise use the parent claim thumbnail if available
        if let Some(thumb_ref) = self.thumbnail_ref() {
            let hash_url = match manifest_label_from_uri(&thumb_ref.identifier) {
                Some(_) => {
                    let hash = match thumb_ref.hash.as_ref() {
                        Some(h) => base64::decode(h)
                            .map_err(|_e| Error::BadParam("Invalid hash".to_string()))?,
                        None => return Err(Error::BadParam("hash is missing".to_string())), /* todo: add hash missing error */
                    };
                    HashedUri::new(thumb_ref.identifier.clone(), thumb_ref.alg.clone(), &hash)
                }
                None => {
                    let data = self.thumbnail_bytes()?;
                    if self.is_v2() {
                        // v2 ingredients use databoxes for thumbnails
                        claim.add_databox(
                            &thumb_ref.format,
                            data.into_owned(),
                            thumb_ref.data_types.clone(),
                        )?
                    } else {
                        claim.add_assertion(&Thumbnail::new(
                            &labels::add_thumbnail_format(
                                labels::INGREDIENT_THUMBNAIL,
                                &thumb_ref.format,
                            ),
                            data.into_owned(),
                        ))?
                    }
                }
            };
            thumbnail = Some(hash_url);
        }

        let mut data = None;
        if let Some(data_ref) = self.data_ref() {
            let box_data = self.resources.get(&data_ref.identifier)?;
            let hash_url = claim.add_databox(
                &data_ref.format,
                box_data.into_owned(),
                data_ref.data_types.clone(),
            )?;

            data = Some(hash_url);
        };

        // instance_id is required in V1 so we generate one if it's not provided
        let instance_id = match self.instance_id.as_ref() {
            Some(id) => Some(id.to_owned()),
            None => {
                if self.data.is_some()
                    || self.description.is_some()
                    || self.informational_uri.is_some()
                {
                    None // not required in V2
                } else {
                    Some(default_instance_id())
                }
            }
        };

        let mut ingredient_assertion = assertions::Ingredient::new_v2(&self.title, &self.format);
        ingredient_assertion.instance_id = instance_id;
        ingredient_assertion.document_id = self.document_id.to_owned();
        ingredient_assertion.c2pa_manifest = c2pa_manifest;
        ingredient_assertion.relationship = self.relationship.clone();
        ingredient_assertion.thumbnail = thumbnail;
        ingredient_assertion.metadata = self.metadata.clone();
        ingredient_assertion.validation_status = self.validation_status.clone();
        ingredient_assertion.data = data;
        ingredient_assertion.description = self.description.clone();
        ingredient_assertion.informational_uri = self.informational_uri.clone();
        claim.add_assertion(&ingredient_assertion)
    }

    /// Setting a base path will make the ingredient use resource files instead of memory buffers
    ///
    /// The files will be relative to the given base path
    #[cfg(feature = "file_io")]
    pub fn with_base_path<P: AsRef<Path>>(&mut self, base_path: P) -> Result<&Self> {
        std::fs::create_dir_all(&base_path)?;
        self.resources.set_base_path(base_path.as_ref());
        Ok(self)
    }

    /// Asynchronously create an Ingredient from a binary manifest (.c2pa) and asset bytes
    ///
    /// # Example: Create an Ingredient from a binary manifest (.c2pa) and asset bytes
    /// ```
    /// use c2pa::{Result, Ingredient};
    ///
    /// # fn main() -> Result<()> {
    /// #    async {
    ///         let asset_bytes = include_bytes!("../tests/fixtures/cloud.jpg");
    ///         let manifest_bytes = include_bytes!("../tests/fixtures/cloud_manifest.c2pa");
    ///
    ///         let ingredient = Ingredient::from_manifest_and_asset_bytes_async(manifest_bytes.to_vec(), "image/jpeg", asset_bytes)
    ///             .await
    ///             .unwrap();
    ///
    ///         println!("{}", ingredient);
    /// #    };
    /// #
    /// #    Ok(())
    /// }
    /// ```
    pub async fn from_manifest_and_asset_bytes_async<M: Into<Vec<u8>>>(
        manifest_bytes: M,
        format: &str,
        asset_bytes: &[u8],
    ) -> Result<Self> {
        let mut stream = Cursor::new(asset_bytes);
        Self::from_manifest_and_asset_stream_async(manifest_bytes, format, &mut stream).await
    }

    /// Asynchronously create an Ingredient from a binary manifest (.c2pa) and asset
    pub async fn from_manifest_and_asset_stream_async<M: Into<Vec<u8>>>(
        manifest_bytes: M,
        format: &str,
        stream: &mut dyn CAIRead,
    ) -> Result<Self> {
        let mut ingredient = Self::from_stream_info(stream, format, "untitled");

        let mut validation_log = DetailedStatusTracker::new();

        let manifest_bytes: Vec<u8> = manifest_bytes.into();
        // generate a store from the buffer and then validate from the asset path
        let result = match Store::from_jumbf(&manifest_bytes, &mut validation_log) {
            Ok(store) => {
                // verify the store
                stream.rewind()?;
                Store::verify_store_async(
                    &store,
                    &mut ClaimAssetData::Stream(stream, format),
                    &mut validation_log,
                )
                .await
                .map(|_| store)
            }
            Err(e) => {
                // add a log entry for the error so we act like verify
                validation_log.log_silent(
                    log_item!("asset", "error loading file", "Ingredient::from_file").set_error(&e),
                );
                Err(e)
            }
        };

        // set validation status from result and log
        ingredient.update_validation_status(result, Some(manifest_bytes), &validation_log)?;

        // create a thumbnail if we don't already have a manifest with a thumb we can use
        #[cfg(feature = "add_thumbnails")]
        if ingredient.thumbnail.is_none() {
            stream.rewind()?;
            match crate::utils::thumbnail::make_thumbnail_from_stream(format, stream) {
                Ok((format, image)) => {
                    ingredient.set_thumbnail(format, image)?;
                }
                Err(err) => {
                    log::warn!("Could not create thumbnail. {err}");
                }
            }
        }
        Ok(ingredient)
    }
}

impl std::fmt::Display for Ingredient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let report = serde_json::to_string_pretty(self).unwrap_or_default();
        f.write_str(&report)
    }
}

/// This defines optional operations when creating [`Ingredient`] structs from files.
#[cfg(feature = "file_io")]
pub trait IngredientOptions {
    /// This allows setting the title for the ingredient.
    ///
    /// If it returns `None`, then the default behavior is to use the file's name.
    fn title(&self, _path: &Path) -> Option<String> {
        None
    }

    /// Returns an optional hash value for the ingredient
    ///
    /// This can be used to test for duplicate ingredients or if a source file has changed.
    /// If hash is_some() Manifest.add_ingredient will dedup matching hashes
    fn hash(&self, _path: &Path) -> Option<String> {
        None
    }

    /// Returns an optional thumbnail image representing the asset
    ///
    /// The first value is the content type of the thumbnail, i.e. image/jpeg
    /// The second value is bytes of the thumbnail image
    /// The default is to have no thumbnail, so you must provide an override to have a thumbnail image
    fn thumbnail(&self, _path: &Path) -> Option<(String, Vec<u8>)> {
        #[cfg(feature = "add_thumbnails")]
        return crate::utils::thumbnail::make_thumbnail(_path).ok();
        #[cfg(not(feature = "add_thumbnails"))]
        None
    }

    /// Returns an optional folder path
    ///
    /// If Some, binary data will be stored in files in the given folder
    fn base_path(&self) -> Option<&Path> {
        None
    }
}

/// DefaultOptions returns None for Title and Hash and generates thumbnail for supported thumbnails
///
/// This can be use with Ingredient::from_file_with_options
#[cfg(feature = "file_io")]
pub struct DefaultOptions {
    /// If Some, the ingredient will read/write binary assets using this folder.
    ///
    /// If None, the assets will be kept in memory.
    pub base: Option<std::path::PathBuf>,
}

#[cfg(feature = "file_io")]
impl IngredientOptions for DefaultOptions {
    fn base_path(&self) -> Option<&Path> {
        self.base.as_deref()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use super::*;
    use crate::assertions::Metadata;

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    fn test_ingredient_api() {
        let mut ingredient = Ingredient::new("title", "format", "instance_id");
        ingredient
            .resources_mut()
            .add("id", "data".as_bytes().to_vec())
            .expect("add");
        ingredient
            .set_document_id("document_id")
            .set_title("title2")
            .set_hash("hash")
            .set_provenance("provenance")
            .set_is_parent()
            .set_relationship(Relationship::ParentOf)
            .set_metadata(Metadata::new())
            .set_thumbnail("format", "thumbnail".as_bytes().to_vec())
            .unwrap()
            .set_active_manifest("active_manifest")
            .set_manifest_data("data".as_bytes().to_vec())
            .expect("set_manifest")
            .set_description("description")
            .set_informational_uri("uri")
            .set_data_ref(ResourceRef::new("format", "id"))
            .expect("set_data_ref")
            .add_validation_status(ValidationStatus::new("status_code"));
        assert_eq!(ingredient.title(), "title2");
        assert_eq!(ingredient.format(), "format");
        assert_eq!(ingredient.instance_id(), "instance_id");
        assert_eq!(ingredient.document_id(), Some("document_id"));
        assert_eq!(ingredient.provenance(), Some("provenance"));
        assert_eq!(ingredient.hash(), Some("hash"));
        assert!(ingredient.is_parent());
        assert_eq!(ingredient.relationship(), &Relationship::ParentOf);
        assert_eq!(ingredient.description(), Some("description"));
        assert_eq!(ingredient.informational_uri(), Some("uri"));
        assert_eq!(ingredient.data_ref().unwrap().format, "format");
        assert_eq!(ingredient.data_ref().unwrap().identifier, "id");
        assert!(ingredient.metadata().is_some());
        assert_eq!(ingredient.thumbnail().unwrap().0, "format");
        assert_eq!(
            *ingredient.thumbnail().unwrap().1,
            "thumbnail".as_bytes().to_vec()
        );
        assert_eq!(
            *ingredient.thumbnail_bytes().unwrap(),
            "thumbnail".as_bytes().to_vec()
        );
        assert_eq!(ingredient.active_manifest(), Some("active_manifest"));

        assert_eq!(
            ingredient.validation_status().unwrap()[0].code(),
            "status_code"
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_stream_async_jpg() {
        let image_bytes = include_bytes!("../tests/fixtures/CA.jpg");
        let title = "Test Image";
        let format = "image/jpeg";
        let mut ingredient = Ingredient::from_memory_async(format, image_bytes)
            .await
            .expect("from_memory");
        ingredient.set_title(title);

        println!("ingredient = {ingredient}");
        assert_eq!(&ingredient.title, title);
        assert_eq!(ingredient.format(), format);
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.metadata().is_none());
        #[cfg(target_arch = "wasm32")]
        web_sys::console::debug_2(
            &"ingredient_from_memory_async:".into(),
            &ingredient.to_string().into(),
        );
        assert!(ingredient.validation_status().is_none());
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    // Note this does not work from wasm32, due to validation issues
    #[cfg(not(target_arch = "wasm32"))]
    fn test_stream_jpg() {
        let image_bytes = include_bytes!("../tests/fixtures/CA.jpg");
        let title = "Test Image";
        let format = "image/jpeg";
        let mut ingredient = Ingredient::from_memory(format, image_bytes).expect("from_memory");
        ingredient.set_title(title);

        println!("ingredient = {ingredient}");
        assert_eq!(&ingredient.title, title);
        assert_eq!(ingredient.format(), format);
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.metadata().is_none());
        assert!(ingredient.validation_status().is_none());
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_stream_ogp() {
        let image_bytes = include_bytes!("../tests/fixtures/XCA.jpg");
        let title = "XCA.jpg";
        let format = "image/jpeg";
        let mut ingredient = Ingredient::from_memory_async(format, image_bytes)
            .await
            .expect("from_memory");
        ingredient.set_title(title);

        println!("ingredient = {ingredient}");
        assert_eq!(&ingredient.title, title);
        assert_eq!(ingredient.format(), format);
        #[cfg(feature = "add_thumbnails")]
        assert!(ingredient.thumbnail().is_some());
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.metadata().is_none());
        assert!(ingredient.validation_status().is_some());
        assert_eq!(
            ingredient.validation_status().unwrap()[0].code(),
            validation_status::ASSERTION_DATAHASH_MISMATCH
        );
    }

    #[allow(dead_code)]
    #[cfg_attr(not(any(target_arch = "wasm32", feature = "file_io")), actix::test)]
    #[cfg(not(target_arch = "wasm32"))]
    async fn test_jpg_cloud_from_memory() {
        let image_bytes = include_bytes!("../tests/fixtures/cloud.jpg");
        let format = "image/jpeg";
        let ingredient = Ingredient::from_memory_async(format, image_bytes)
            .await
            .expect("from_memory_async");
        // println!("ingredient = {ingredient}");
        assert_eq!(&ingredient.title, "untitled");
        assert_eq!(ingredient.format(), format);
        assert!(ingredient.provenance().is_some());
        assert!(ingredient.provenance().unwrap().starts_with("https:"));
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.validation_status().is_none());
    }

    #[allow(dead_code)]
    #[cfg_attr(not(any(target_arch = "wasm32", feature = "file_io")), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_jpg_cloud_from_memory_no_file_io() {
        let image_bytes = include_bytes!("../tests/fixtures/cloud.jpg");
        let format = "image/jpeg";
        let ingredient = Ingredient::from_memory_async(format, image_bytes)
            .await
            .expect("from_memory_async");
        // println!("ingredient = {ingredient}");
        assert!(ingredient.validation_status().is_some());
        assert_eq!(
            ingredient.validation_status().unwrap()[0].code(),
            validation_status::MANIFEST_INACCESSIBLE
        );
        assert!(ingredient.validation_status().unwrap()[0]
            .url()
            .unwrap()
            .starts_with("http"));
        assert!(ingredient.manifest_data().is_none());
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    async fn test_jpg_cloud_from_memory_and_manifest() {
        let asset_bytes = include_bytes!("../tests/fixtures/cloud.jpg");
        let manifest_bytes = include_bytes!("../tests/fixtures/cloud_manifest.c2pa");
        let format = "image/jpeg";
        let ingredient = Ingredient::from_manifest_and_asset_bytes_async(
            manifest_bytes.to_vec(),
            format,
            asset_bytes,
        )
        .await
        .unwrap();
        #[cfg(target_arch = "wasm32")]
        web_sys::console::debug_2(
            &"ingredient_from_memory_async:".into(),
            &ingredient.to_string().into(),
        );
        assert!(ingredient.validation_status().is_none());
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.provenance().is_some());
    }
}

#[cfg(test)]
#[cfg(feature = "file_io")]
mod tests_file_io {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use super::*;
    use crate::utils::test::fixture_path;
    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    const NO_MANIFEST_JPEG: &str = "earth_apollo17.jpg";
    const MANIFEST_JPEG: &str = "C.jpg";
    const BAD_SIGNATURE_JPEG: &str = "E-sig-CA.jpg";
    const PRERELEASE_JPEG: &str = "prerelease.jpg";

    fn stats(ingredient: &Ingredient) -> usize {
        let thumb_size = ingredient.thumbnail_bytes().map_or(0, |i| i.len());
        let manifest_data_size = ingredient.manifest_data().map_or(0, |r| r.len());

        println!(
            "  {} instance_id: {}, thumb size: {}, manifest_data size: {}",
            ingredient.title(),
            ingredient.instance_id(),
            thumb_size,
            manifest_data_size,
        );
        ingredient.title().len() + ingredient.instance_id().len() + thumb_size + manifest_data_size
    }

    // check for correct thumbnail generation with or without add_thumbnails feature
    fn test_thumbnail(ingredient: &Ingredient, format: &str) {
        if cfg!(feature = "add_thumbnails") {
            assert!(ingredient.thumbnail().is_some());
            assert_eq!(ingredient.thumbnail().unwrap().0, format);
        } else {
            assert!(ingredient.thumbnail().is_none());
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_psd() {
        // std::env::set_var("RUST_LOG", "debug");
        // env_logger::init();
        let ap = fixture_path("Purple Square.psd");
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {ingredient}");
        assert_eq!(ingredient.title(), "Purple Square.psd");
        assert_eq!(ingredient.format(), "image/vnd.adobe.photoshop");
        assert!(ingredient.thumbnail().is_none()); // should always be none
        assert!(ingredient.manifest_data().is_none());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_manifest_jpg() {
        let ap = fixture_path(MANIFEST_JPEG);
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {ingredient}");
        assert_eq!(&ingredient.title, MANIFEST_JPEG);
        assert_eq!(ingredient.format(), "image/jpeg");
        assert!(ingredient.thumbnail_ref().is_some()); // we don't generate this thumbnail
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.metadata().is_none());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_no_manifest_jpg() {
        let ap = fixture_path(NO_MANIFEST_JPEG);
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {ingredient}");
        assert_eq!(&ingredient.title, NO_MANIFEST_JPEG);
        assert_eq!(ingredient.format(), "image/jpeg");
        test_thumbnail(&ingredient, "image/jpeg");
        assert!(ingredient.provenance().is_none());
        assert!(ingredient.manifest_data().is_none());
        assert!(ingredient.metadata().is_none());
        assert!(ingredient.instance_id().starts_with("xmp.iid:"));
        #[cfg(feature = "add_thumbnails")]
        assert!(ingredient
            .thumbnail_ref()
            .unwrap()
            .identifier
            .starts_with("xmp.iid"));
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_jpg_options() {
        struct MyOptions {}
        impl IngredientOptions for MyOptions {
            fn title(&self, _path: &Path) -> Option<String> {
                Some("MyTitle".to_string())
            }

            fn hash(&self, _path: &Path) -> Option<String> {
                Some("1234568abcdef".to_string())
            }

            fn thumbnail(&self, _path: &Path) -> Option<(String, Vec<u8>)> {
                Some(("image/foo".to_string(), "bits".as_bytes().to_owned()))
            }
        }

        let ap = fixture_path(NO_MANIFEST_JPEG);
        let ingredient = Ingredient::from_file_with_options(ap, &MyOptions {}).expect("from_file");
        stats(&ingredient);

        assert_eq!(ingredient.title(), "MyTitle");
        assert_eq!(ingredient.format(), "image/jpeg");
        assert_eq!(ingredient.hash(), Some("1234568abcdef"));
        assert_eq!(ingredient.thumbnail_ref().unwrap().format, "image/foo"); // always generated
        assert!(ingredient.manifest_data().is_none());
        assert!(ingredient.metadata().is_none());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_png_no_claim() {
        let ap = fixture_path("libpng-test.png");
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {ingredient}");
        assert_eq!(ingredient.title(), "libpng-test.png");
        test_thumbnail(&ingredient, "image/png");
        assert!(ingredient.provenance().is_none());
        assert!(ingredient.manifest_data.is_none());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_jpg_bad_signature() {
        let ap = fixture_path(BAD_SIGNATURE_JPEG);
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {ingredient}");
        assert_eq!(ingredient.title(), BAD_SIGNATURE_JPEG);
        assert_eq!(ingredient.format(), "image/jpeg");
        test_thumbnail(&ingredient, "image/jpeg");
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.validation_status().is_some());
        assert!(ingredient
            .validation_status()
            .unwrap()
            .iter()
            .any(|s| s.code() == validation_status::CLAIM_SIGNATURE_MISMATCH));
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_jpg_prerelease() {
        let ap = fixture_path(PRERELEASE_JPEG);
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {ingredient}");
        assert_eq!(ingredient.title(), PRERELEASE_JPEG);
        assert_eq!(ingredient.format(), "image/jpeg");
        test_thumbnail(&ingredient, "image/jpeg");
        assert!(ingredient.provenance().is_some());
        assert!(ingredient.manifest_data().is_none());
        assert!(ingredient.validation_status().is_some());
        assert_eq!(
            ingredient.validation_status().unwrap()[0].code(),
            validation_status::STATUS_PRERELEASE
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_jpg_nested() {
        let ap = fixture_path("CIE-sig-CA.jpg");
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        println!("ingredient = {ingredient}");
        assert!(ingredient.validation_status().is_none());
        assert!(ingredient.manifest_data().is_some());
    }

    #[test]
    #[cfg(feature = "fetch_remote_manifests")]
    fn test_jpg_cloud_failure() {
        let ap = fixture_path("cloudx.jpg");
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        println!("ingredient = {ingredient}");
        assert!(ingredient.validation_status().is_some());
        assert_eq!(
            ingredient.validation_status().unwrap()[0].code(),
            validation_status::MANIFEST_INACCESSIBLE
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_jpg_with_path() {
        let ap = fixture_path("CA.jpg");
        let mut folder = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        folder.push("../target/tmp/ingredient");
        let ingredient = Ingredient::from_file_with_folder(ap, folder).expect("from_file");
        println!("ingredient = {ingredient}");
        assert_eq!(ingredient.validation_status(), None);

        // verify ingredient thumbnail is an absolute url reference to a claim thumbnail
        assert!(ingredient
            .thumbnail_ref()
            .unwrap()
            .identifier
            .contains(labels::JPEG_CLAIM_THUMBNAIL));

        // verify  manifest_data exists
        assert!(ingredient.manifest_data_ref().is_some());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_file_based_ingredient() {
        let mut folder = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        folder.push("tests/fixtures");
        let mut ingredient = Ingredient::new("title", "format", "instance_id");
        ingredient.resources.set_base_path(folder);

        assert!(ingredient.thumbnail_ref().is_none());
        assert!(ingredient
            .set_manifest_data_ref(ResourceRef::new("image/jpg", "foo"))
            .is_err());
        assert!(ingredient.manifest_data_ref().is_none());
        // verify we can set a reference
        assert!(ingredient
            .set_thumbnail_ref(ResourceRef::new("image/jpg", "C.jpg"))
            .is_ok());
        assert!(ingredient.thumbnail_ref().is_some());
        assert!(ingredient
            .set_manifest_data_ref(ResourceRef::new("application/c2pa", "cloud_manifest.c2pa"))
            .is_ok());
        assert!(ingredient.manifest_data_ref().is_some());
    }

    #[test]
    fn test_input_to_ingredient() {
        // create an inputTo ingredient
        let mut ingredient = Ingredient::new_v2("prompt", "text/plain");
        ingredient.relationship = Relationship::InputTo;

        // add a resource containing our data
        ingredient
            .resources_mut()
            .add("prompt_id", "pirate with bird on shoulder")
            .expect("add");

        // create a resource reference for the data
        let mut data_ref = ResourceRef::new("text/plain", "prompt_id");
        let data_type = crate::assertions::AssetType {
            asset_type: "c2pa.types.generator.prompt".to_string(),
            version: None,
        };
        data_ref.data_types = Some([data_type].to_vec());

        // add the data reference to the ingredient
        ingredient.set_data_ref(data_ref).expect("set_data_ref");

        println!("ingredient = {ingredient}");

        assert_eq!(ingredient.title(), "prompt");
        assert_eq!(ingredient.format(), "text/plain");
        assert_eq!(ingredient.instance_id(), "");
        assert_eq!(ingredient.data_ref().unwrap().identifier, "prompt_id");
        assert_eq!(ingredient.data_ref().unwrap().format, "text/plain");
        assert_eq!(ingredient.relationship(), &Relationship::InputTo);
        assert_eq!(
            ingredient.data_ref().unwrap().data_types.as_ref().unwrap()[0].asset_type,
            "c2pa.types.generator.prompt"
        );
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_input_to_file_based_ingredient() {
        let mut folder = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        folder.push("tests/fixtures");
        let mut ingredient = Ingredient::new_v2("title", "format");
        ingredient.resources.set_base_path(folder);
        //let mut _data_ref = ResourceRef::new("image/jpg", "foo");
        //data_ref.data_types = vec!["c2pa.types.dataset.pytorch".to_string()];
    }
}
