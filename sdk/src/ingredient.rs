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
use std::borrow::Cow;
#[cfg(feature = "file_io")]
use std::path::{Path, PathBuf};

use log::{debug, error};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    assertion::{get_thumbnail_image_type, Assertion, AssertionBase},
    assertions::{self, labels, Metadata, Relationship, Thumbnail},
    claim::Claim,
    error::{Error, Result},
    hashed_uri::HashedUri,
    jumbf,
    resource_store::{skip_serializing_resources, ResourceRef, ResourceStore},
    store::Store,
    validation_status::{self, ValidationStatus},
};
#[cfg(feature = "file_io")]
use crate::{error::wrap_io_err, validation_status::status_for_store, xmp_inmemory_utils::XmpInfo};
#[derive(Debug, Default, Deserialize, Serialize)]
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
    #[serde(default = "default_instance_id")]
    instance_id: String,

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

    /// Set to `true` if this is the parent ingredient.
    ///
    /// There can only be one parent ingredient in the ingredients.
    #[serde(skip_serializing_if = "Option::is_none")]
    is_parent: Option<bool>,

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

    /// Any additional [`Metadata`] as defined in the C2PA spec.
    ///
    /// [`Manifest`]: crate::Manifest
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Metadata>,

    /// A [`ManifestStore`] from the source asset extracted as a binary C2PA blob.
    ///
    /// [`ManifestStore`]: crate::ManifestStore
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_data: Option<String>,

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
    /// let ingredient = Ingredient::new("title","image/jpeg","ed610ae51f604002be3dbf0c589a2f1f");
    /// ```
    pub fn new<S>(title: S, format: S, instance_id: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            title: title.into(),
            format: format.into(),
            instance_id: instance_id.into(),
            ..Default::default()
        }
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
    pub fn instance_id(&self) -> &str {
        self.instance_id.as_str()
    }

    /// Returns the provenance uri if available.
    pub fn provenance(&self) -> Option<&str> {
        self.provenance.as_deref()
    }

    /// Returns a tuple with thumbnail format and image bytes or `None`.
    pub fn thumbnail(&self) -> Option<&ResourceRef> {
        self.thumbnail.as_ref()
    }

    /// Returns a Cow of thumbnail bytes or Err(Error::NotFound)`.
    ///
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
        self.is_parent.unwrap_or(false)
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
    /// This is the binary form of a manifest store in .c2pa format.
    pub fn manifest_data(&self) -> Option<Cow<Vec<u8>>> {
        if let Some(identifier) = self.manifest_data.as_ref() {
            if let Ok(data) = self.resources.get(identifier) {
                return Some(data);
            }
        }
        None
    }

    /// Sets a human-readable title for this ingredient.
    pub fn set_title<S: Into<String>>(&mut self, title: S) -> &mut Self {
        self.title = title.into();
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
        self.is_parent = Some(true);
        self
    }

    /// Sets the thumbnail from a ResourceRef.
    pub fn set_thumbnail(&mut self, thumbnail: ResourceRef) -> &mut Self {
        self.thumbnail = Some(thumbnail);
        self
    }

    /// Sets the thumbnail content_type and image data.
    pub fn set_thumbnail_from_bytes<S: Into<String>, B: Into<Vec<u8>>>(
        &mut self,
        content_type: S,
        bytes: B,
    ) -> Result<&mut Self> {
        let content_type: String = content_type.into();
        let thumb_ref = ResourceRef::from_content_type(&content_type);
        self.resources.add(&thumb_ref.identifier, bytes)?;
        self.thumbnail = Some(thumb_ref);
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

    /// Sets the Manifest C2PA data for this ingredient.
    pub fn set_manifest_data(&mut self, data: Vec<u8>) -> Result<&mut Self> {
        let id = ResourceStore::content_type_id("c2pa");
        self.resources.add(id.clone(), data)?;
        self.manifest_data = Some(id);
        dbg!(&self.manifest_data);
        Ok(self)
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

        let format = match extension.as_ref() {
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            "psd" => "image/vnd.adobe.photoshop",
            "tiff" => "image/tiff",
            "svg" => "image/svg+xml",
            "ico" => "image/x-icon",
            "bmp" => "image/bmp",
            "webp" => "image/webp",
            "dng" => "image/dng",
            "heic" => "image/heic",
            "heif" => "image/heif",
            "mp2" | "mpa" | "mpe" | "mpeg" | "mpg" | "mpv2" => "video/mpeg",
            "mp4" => "video/mp4",
            "avif" => "image/avif",
            "mov" | "qt" => "video/quicktime",
            "m4a" => "audio/mp4",
            "mid" | "rmi" => "audio/mid",
            "mp3" => "audio/mpeg",
            "wav" => "audio/vnd.wav",
            "aif" | "aifc" | "aiff" => "audio/aiff",
            "ogg" => "audio/ogg",
            "pdf" => "application/pdf",
            "ai" => "application/postscript",
            _ => "application/octet-stream",
        }
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
        fn make_id(id_type: &str) -> String {
            let uuid = Uuid::new_v4();
            //warn!("Generating fake id {}", uuid);
            format!("xmp:{}id:{}", id_type, uuid)
        }

        // get required information from the file path
        let (title, _, format) = Self::get_path_info(path.as_ref());

        // if we can open the file try tto get xmp info
        let xmp_info = match std::fs::File::open(path).map_err(wrap_io_err) {
            Ok(mut file) => XmpInfo::from_source(&mut file, &format),
            Err(_) => XmpInfo::default(),
        };

        // instance id is required so generate one if we don't have one
        let instance_id = xmp_info.instance_id.unwrap_or_else(|| make_id("i"));

        let mut ingredient = Self::new(&title, &format, &instance_id);
        ingredient.document_id = xmp_info.document_id; // use document id if one exists
        ingredient.provenance = xmp_info.provenance;

        ingredient
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
        // these are declared inside this function in order to isolate them for wasm builds
        use crate::status_tracker::{log_item, DetailedStatusTracker, StatusTracker};

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

        // generate a store from the buffer and then validate from the asset path
        // load and verify store in single call - no need to call low level jumbf_io functions
        match result {
            Ok(store) => {
                // generate ValidationStatus from ValidationItems filtering for only errors
                let statuses = status_for_store(&store, &mut validation_log);

                if let Some(claim) = store.provenance_claim() {
                    // if the parent claim is valid and has a thumbnail, use it
                    if statuses.is_empty() {
                        // search claim to find a claim thumbnail assertion without knowing the format
                        if let Some(claim_assertion) = claim
                            .claim_assertion_store()
                            .iter()
                            .find(|ca| ca.label_raw().starts_with(labels::CLAIM_THUMBNAIL))
                        {
                            let (format, image) =
                                Self::thumbnail_from_assertion(claim_assertion.assertion());
                            let thumb_ref = ResourceRef::from_content_type(format);
                            ingredient.resources.add(&thumb_ref.identifier, image)?;
                            ingredient.set_thumbnail(thumb_ref);
                        }
                    }
                    ingredient.active_manifest = Some(claim.label().to_string());
                }
                if let Some(bytes) = manifest_bytes {
                    let id = ResourceStore::content_type_id("c2pa");
                    ingredient.resources.add(id.clone(), bytes)?;
                    ingredient.manifest_data = Some(id);
                }

                ingredient.validation_status = if statuses.is_empty() {
                    None
                } else {
                    Some(statuses)
                };
            }
            Err(Error::JumbfNotFound)
            | Err(Error::ProvenanceMissing)
            | Err(Error::UnsupportedType) => {} // no claims but valid file
            Err(Error::BadParam(desc)) if desc == *"unrecognized file type" => {}
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
                ingredient.validation_status = if statuses.is_empty() {
                    None
                } else {
                    Some(statuses)
                };
            }
        }

        // create a thumbnail if we don't already have a manifest with a thumb we can use
        if ingredient.thumbnail.is_none() {
            if let Some((format, image)) = options.thumbnail(path) {
                ingredient.set_thumbnail_from_bytes(format, image)?;
            }
        }

        Ok(ingredient)
    }

    /// Creates an Ingredient from a store and a URI to an ingredient assertion.
    pub(crate) fn from_ingredient_uri(
        store: &Store,
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

        let is_parent = match ingredient_assertion.relationship {
            Relationship::ParentOf => Some(true),
            Relationship::ComponentOf => None,
        };

        let active_manifest = ingredient_assertion
            .c2pa_manifest
            .and_then(|hash_url| jumbf::labels::manifest_label_from_uri(&hash_url.url()));

        let thumbnail = ingredient_assertion.thumbnail.and_then(|hashed_uri| {
            // This could be a relative or absolute thumbnail reference to another manifest
            let target_label = match jumbf::labels::manifest_label_from_uri(&hashed_uri.url()) {
                Some(label) => label,              // use the manifest from the thumbnail uri
                None => ingredient_uri.to_owned(), // relative so use the whole url from the thumbnail assertion
            };
            match store.get_assertion_from_uri_and_claim(&hashed_uri.url(), &target_label) {
                Some(assertion) => Some(Self::thumbnail_from_assertion(assertion)),
                None => {
                    error!("failed to get {} from {}", hashed_uri.url(), ingredient_uri);
                    validation_status.push(
                        ValidationStatus::new(validation_status::ASSERTION_MISSING.to_string())
                            .set_url(hashed_uri.url()),
                    );
                    None
                }
            }
        });

        debug!(
            "Adding Ingredient {} {:?}",
            ingredient_assertion.title, &active_manifest
        );

        // todo: find a better way to do this if we keep this code
        let mut ingredient = Ingredient::new(
            &ingredient_assertion.title,
            &ingredient_assertion.format,
            &ingredient_assertion.instance_id,
        );
        ingredient.document_id = ingredient_assertion.document_id;

        #[cfg(feature = "file_io")]
        if let Some(base_path) = resource_path {
            ingredient.resources_mut().set_base_path(base_path)
        }

        if let Some((format, image)) = thumbnail {
            ingredient.set_thumbnail_from_bytes(format, image)?;
        }

        ingredient.is_parent = is_parent;
        ingredient.active_manifest = active_manifest;
        if !validation_status.is_empty() {
            ingredient.validation_status = Some(validation_status)
        }
        ingredient.metadata = ingredient_assertion.metadata;
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
        let c2pa_manifest = match self.manifest_data() {
            Some(buffer) => {
                let manifest_label = self
                    .active_manifest
                    .clone()
                    .ok_or(Error::IngredientNotFound)?;

                //if this is the parent ingredient then apply any redactions, converting from labels to uris
                let redactions = match self.is_parent() {
                    true => redactions.as_ref().map(|redactions| {
                        redactions
                            .iter()
                            .map(|r| jumbf::labels::to_assertion_uri(&manifest_label, r))
                            .collect()
                    }),
                    false => None,
                };

                // have Store check and load ingredients and add them to a claim
                Store::load_ingredient_to_claim(claim, &manifest_label, &buffer, redactions)?;

                // get the ingredient map loaded in previous
                match claim.claim_ingredient(&manifest_label) {
                    Some(ingredient_claims) => {
                        // get the ingredient active claim from the ingredients claim map
                        if let Some(ingredient_active_claim) = ingredient_claims
                            .iter()
                            .find(|c| c.label() == manifest_label)
                        {
                            let hash = ingredient_active_claim.hash();
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
                                            let assertion_label =
                                                jumbf::labels::assertion_label_from_uri(&t.url())
                                                    .unwrap_or_default();
                                            let url = jumbf::labels::to_assertion_uri(
                                                &manifest_label,
                                                &assertion_label,
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

        let relationship = if self.is_parent() {
            Relationship::ParentOf
        } else {
            Relationship::ComponentOf
        };

        // add ingredient thumbnail assertion if one is given and we don't already have one from the parent claim
        if thumbnail.is_none() {
            if let Some(thumb_ref) = self.thumbnail() {
                let hash_url = claim.add_assertion(&Thumbnail::new(
                    &labels::add_thumbnail_format(
                        labels::INGREDIENT_THUMBNAIL,
                        &thumb_ref.content_type,
                    ),
                    self.resources.get(&thumb_ref.identifier)?.to_vec(),
                ))?;

                thumbnail = Some(hash_url);
            }
        }

        let mut ingredient_assertion = assertions::Ingredient::new(
            &self.title,
            &self.format,
            &self.instance_id,
            self.document_id.as_deref(),
        );

        ingredient_assertion.c2pa_manifest = c2pa_manifest;
        ingredient_assertion.relationship = relationship;
        ingredient_assertion.thumbnail = thumbnail;
        ingredient_assertion.metadata = self.metadata.clone();
        ingredient_assertion.validation_status = self.validation_status.clone();
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

#[cfg(feature = "file_io")]
/// DefaultOptions returns None for Title and Hash and generates thumbnail for supported thumbnails
///
/// This can be use with Ingredient::from_file_with_options
pub struct DefaultOptions {
    base: Option<std::path::PathBuf>,
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

    use super::*;
    use crate::assertions::Metadata;

    #[test]
    fn test_ingredient_api() {
        let mut ingredient = Ingredient::new("title", "format", "instance_id");
        ingredient
            .set_document_id("document_id")
            .set_title("title2")
            .set_hash("hash")
            .set_provenance("provenance")
            .set_is_parent()
            .set_metadata(Metadata::new())
            .set_thumbnail_from_bytes("format", "thumbnail".as_bytes().to_vec())
            .unwrap()
            .set_active_manifest("active_manifest")
            .set_manifest_data("data".as_bytes().to_vec())
            .expect("set_manifest")
            .add_validation_status(ValidationStatus::new("status_code"));
        assert_eq!(ingredient.title(), "title2");
        assert_eq!(ingredient.format(), "format");
        assert_eq!(ingredient.instance_id(), "instance_id");
        assert_eq!(ingredient.document_id(), Some("document_id"));
        assert_eq!(ingredient.provenance(), Some("provenance"));
        assert_eq!(ingredient.hash(), Some("hash"));
        assert!(ingredient.is_parent());
        assert!(ingredient.metadata().is_some());
        assert_eq!(ingredient.thumbnail().unwrap().content_type, "format");
        // assert_eq!(ingredient.thumbnail().)
        //     ResourceRef::new
        //     Some(("format", Cow::Owned("thumbnail".as_bytes().to_vec())))
        // );
        assert_eq!(ingredient.active_manifest(), Some("active_manifest"));
        assert_eq!(
            ingredient.manifest_data(),
            Some(Cow::Owned("data".as_bytes().to_vec()))
        );
        assert_eq!(
            ingredient.validation_status().unwrap()[0].code(),
            "status_code"
        );
    }
}

#[cfg(test)]
#[cfg(feature = "file_io")]
mod tests_file_io {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::utils::test::fixture_path;

    const NO_MANIFEST_JPEG: &str = "earth_apollo17.jpg";
    const MANIFEST_JPEG: &str = "C.jpg";
    const BAD_SIGNATURE_JPEG: &str = "E-sig-CA.jpg";
    const PRERELEASE_JPEG: &str = "prerelease.jpg";

    fn stats(ingredient: &Ingredient) -> usize {
        let thumb_size = ingredient.thumbnail().map_or(0, |thumb_ref| {
            ingredient
                .resources()
                .get(&thumb_ref.identifier)
                .map(|i| i.len())
                .unwrap_or(0)
        });
        let manifest_data_size = ingredient.manifest_data().map_or(0, |v| v.len());

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
            assert_eq!(ingredient.thumbnail().unwrap().content_type, format);
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

        println!("ingredient = {}", ingredient);
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

        println!("ingredient = {}", ingredient);
        assert_eq!(&ingredient.title, MANIFEST_JPEG);
        assert_eq!(ingredient.format(), "image/jpeg");
        assert!(ingredient.thumbnail().is_some()); // we don't generate this thumbnail
        assert!(ingredient.provenance().is_some());
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.metadata().is_none());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_no_manifest_jpg() {
        let ap = fixture_path(NO_MANIFEST_JPEG);
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {}", ingredient);
        assert_eq!(&ingredient.title, NO_MANIFEST_JPEG);
        assert_eq!(ingredient.format(), "image/jpeg");
        test_thumbnail(&ingredient, "image/jpeg");
        assert!(ingredient.provenance().is_none());
        assert!(ingredient.manifest_data().is_none());
        assert!(ingredient.metadata().is_none());
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

        let ap = fixture_path(MANIFEST_JPEG);
        let ingredient = Ingredient::from_file_with_options(ap, &MyOptions {}).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {}", ingredient);
        assert_eq!(ingredient.title(), "MyTitle");
        assert_eq!(ingredient.format(), "image/jpeg");
        assert!(ingredient.hash().is_some());
        assert!(ingredient.thumbnail().is_some()); // always generated
        assert!(ingredient.provenance().is_some());
        assert!(ingredient.manifest_data().is_some());
        assert!(ingredient.metadata().is_none());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_png_no_claim() {
        let ap = fixture_path("libpng-test.png");
        let ingredient = Ingredient::from_file(ap).expect("from_file");
        stats(&ingredient);

        println!("ingredient = {}", ingredient);
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

        //println!("ingredient = {}", ingredient);
        assert_eq!(ingredient.title(), BAD_SIGNATURE_JPEG);
        assert_eq!(ingredient.format(), "image/jpeg");
        test_thumbnail(&ingredient, "image/jpeg");
        assert!(ingredient.provenance().is_some());
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

        println!("ingredient = {}", ingredient);
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
        println!("ingredient = {}", ingredient);
        assert_eq!(ingredient.validation_status(), None);
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_jpg_with_path() {
        let ap = fixture_path("CIE-sig-CA.jpg");
        let mut folder = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        folder.push("../target/tmp/ingredient");
        let ingredient = Ingredient::from_file_with_folder(ap, folder).expect("from_file");
        println!("ingredient = {}", ingredient);
        assert_eq!(ingredient.validation_status(), None);
    }
}
