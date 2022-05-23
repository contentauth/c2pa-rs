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

use crate::{
    assertion::{get_thumbnail_image_type, Assertion, AssertionBase},
    assertions::{self, labels, Metadata, Relationship, Thumbnail},
    cbor_types::BytesT,
    claim::Claim,
    error::{Error, Result},
    hashed_uri::HashedUri,
    jumbf,
    store::Store,
    validation_status::{self, ValidationStatus},
};
use std::ops::Deref;

#[cfg(feature = "file_io")]
use crate::{error::wrap_io_err, validation_status::status_for_store, xmp_inmemory_utils::XmpInfo};
use log::{debug, error};
use serde::{Deserialize, Serialize};

#[cfg(feature = "file_io")]
use std::path::Path;
#[derive(Debug, Deserialize, Serialize)]
/// An ingredient is any external asset that has been used in the creation of an image
///
/// This structure captures information about that asset so a user can
pub struct Ingredient {
    /// A human readable title, generally source filename
    title: String,

    /// The format of the source file as a mime type or extension
    format: String,

    /// Document ID from `xmpMM:DocumentID` in XMP metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    document_id: Option<String>,

    /// Instance ID from `xmpMM:InstanceID` in XMP metadata
    instance_id: String,

    /// URI from `dcterms:provenance` in XMP metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<String>,

    /// A thumbnail image capturing the visual state at the time of import
    /// A tuple of thumbnail mime format (i.e. image/jpg) and binary bits of the image
    #[serde(skip_serializing)]
    thumbnail: Option<(String, BytesT)>,

    /// An optional hash of the asset to prevent duplicates
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,

    /// Set to True if this is a parent asset
    #[serde(skip_serializing_if = "Option::is_none")]
    is_parent: Option<bool>,

    /// The active manifest label if one exists
    /// If this ingredient has a ManifestStore, this will hold the label of the active Manifest
    #[serde(skip_serializing_if = "Option::is_none")]
    active_manifest: Option<String>,

    /// Validation results
    #[serde(skip_serializing_if = "Option::is_none")]
    validation_status: Option<Vec<ValidationStatus>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// any additional Metadata as defined in the C2PA spec
    metadata: Option<Metadata>,

    /// A ManifestStore from the source asset extracted as a binary c2pa blob
    #[serde(skip_serializing)]
    manifest_data: Option<Vec<u8>>,
}

impl Ingredient {
    pub fn new(title: &str, format: &str, instance_id: &str) -> Self {
        Self {
            title: title.to_owned(),
            format: format.to_owned(),
            document_id: None,
            instance_id: instance_id.to_owned(),
            provenance: None,
            thumbnail: None,
            hash: None,
            is_parent: None,
            active_manifest: None,
            validation_status: None,
            metadata: None,
            manifest_data: None,
        }
    }

    /// Returns a user displayable title for this ingredient
    pub fn title(&self) -> &str {
        self.title.as_str()
    }

    /// Returns a mime content_type for this asset associated with this ingredient
    pub fn format(&self) -> &str {
        self.format.as_str()
    }

    /// Returns a document identifier if one exists
    pub fn document_id(&self) -> Option<&str> {
        self.document_id.as_deref()
    }

    /// Returns the instance identifier
    pub fn instance_id(&self) -> &str {
        self.instance_id.as_str()
    }

    /// Returns the provenance uri if available
    pub fn provenance(&self) -> Option<&str> {
        self.provenance.as_deref()
    }

    /// Returns a tuple with thumbnail format and image bytes or None
    pub fn thumbnail(&self) -> Option<(&str, &[u8])> {
        self.thumbnail
            .as_ref()
            .map(|(format, image)| (format.as_str(), image.deref()))
    }

    /// Returns an optional Blake3 hash made from the bits of the original image
    pub fn hash(&self) -> Option<&[u8]> {
        self.manifest_data.as_deref()
    }

    /// Returns true if this is labeled as the parent ingredient
    pub fn is_parent(&self) -> bool {
        self.is_parent.unwrap_or(false)
    }

    /// Returns an optional label for the active manifest in this ingredient
    /// If None, the ingredient has no Manifests
    pub fn active_manifest(&self) -> Option<&str> {
        self.active_manifest.as_deref()
    }

    /// Returns a reference the [ValidationStatus] Vec or None
    pub fn validation_status(&self) -> Option<&[ValidationStatus]> {
        self.validation_status.as_deref()
    }

    /// Returns an optional reference to [Metadata]
    /// todo: figure out how to not clone this
    pub fn metadata(&self) -> Option<Metadata> {
        self.metadata.clone()
    }

    /// Returns an optional reference to c2pa manifest data
    /// This is the binary form of a manifest store in .c2pa format
    pub fn manifest_data(&self) -> Option<&[u8]> {
        self.manifest_data.as_deref()
    }

    pub fn set_title(&mut self, title: String) -> &mut Self {
        self.title = title;
        self
    }

    /// Sets an optional document_id -- usually from XMP DocumentId.
    pub fn set_document_id(&mut self, document_id: String) -> &mut Self {
        self.document_id = Some(document_id);
        self
    }

    /// Use Manifest.set_parent() for this
    pub(crate) fn set_parent_state(&mut self, is_parent: bool) -> &mut Self {
        self.is_parent = if is_parent { Some(true) } else { None };
        self
    }

    /// set the thumbnail image
    pub fn set_thumbnail(&mut self, format: String, thumbnail: Vec<u8>) -> &mut Self {
        self.thumbnail = Some((format, BytesT(thumbnail)));
        self
    }

    // Add any desired metadata to this ingredient
    pub fn set_metadata(&mut self, metadata: Metadata) -> &mut Self {
        self.metadata = Some(metadata);
        self
    }

    // Gathers filename, extension and format from a file path
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
            "ico" => "image/vnd.microsoft.icon",
            "bmp" => "image/bmp",
            "webp" => "image/webp",
            _ => "application/octet-stream",
        }
        .to_owned();
        (title, extension, format)
    }

    /// Gets the basic info from a file path, including xmp info from the file if available
    /// This is used for making asset ingredients that should not load ManifestStores
    #[cfg(feature = "file_io")]

    pub fn from_file_info<P: AsRef<Path>>(path: P) -> Self {
        fn make_id(id_type: &str) -> String {
            use uuid::Uuid;
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
    /// Creates an Ingredient from a file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let options = IngredientOptions::default();
        Self::from_file_with_options(path.as_ref(), &options)
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

    /// Creates an Ingredient from a file path and options
    // TODO: Review possible error conditions. InvalidJumbfError no longer exists.
    #[cfg(feature = "file_io")]
    pub fn from_file_with_options<P: AsRef<Path>>(
        path: P,
        options: &IngredientOptions,
    ) -> Result<Self> {
        Self::from_file_impl(path.as_ref(), options)
    }

    // internal implementation to avoid code bloat
    #[cfg(feature = "file_io")]
    fn from_file_impl(path: &Path, options: &IngredientOptions) -> Result<Self> {
        // these are declared inside this function in order to isolate them for wasm builds
        use crate::jumbf_io;
        use crate::status_tracker::{DetailedStatusTracker, StatusTracker};

        #[cfg(feature = "diagnostics")]
        let _t = crate::utils::time_it::TimeIt::new("Ingredient:from_file_with_options");

        // from the source file we need to get the XMP, JUMBF and generate a thumbnail
        debug!("ingredient {:?}", path);

        // get required information from the file path
        let mut ingredient = Self::from_file_info(path);

        if !path.exists() {
            return Err(Error::FileNotFound(ingredient.title));
        }

        // if options includes a title, use it
        if let Some(opt_title) = options.title {
            ingredient.title = opt_title.to_string();
        }
        // read the file into a buffer for processing
        let buf = std::fs::read(path).map_err(wrap_io_err)?;

        // generate a hash so we know if the file has changed
        // todo:: make hash algorithm an option fn taking stream
        ingredient.hash = options
            .make_hash
            .then(|| blake3::hash(&buf).to_hex().as_str().to_owned());

        let mut report = DetailedStatusTracker::new();

        // generate a store from the buffer and then validate from the asset path
        // load and verify store in single call - no need to call low level jumbf_io functions
        match Store::load_from_memory(&ingredient.format, &buf, true, &mut report) {
            Ok(store) => {
                // generate ValidationStatus from ValidationItems filtering for only errors
                let statuses = status_for_store(&store, &mut report);

                if let Some(claim) = store.provenance_claim() {
                    // if the parent claim is valid and has a thumbnail, use it
                    if statuses.is_empty() {
                        //todo: need a better test here
                        if let Some(claim_assertion) =
                            claim.get_claim_assertion(labels::JPEG_CLAIM_THUMBNAIL, 0)
                        {
                            let (format, image) =
                                Self::thumbnail_from_assertion(claim_assertion.assertion());
                            ingredient.set_thumbnail(format, image);
                        }
                    }
                    ingredient.active_manifest = Some(claim.label().to_string());
                }
                ingredient.manifest_data =
                    jumbf_io::load_jumbf_from_memory(&ingredient.format, &buf).ok();
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
                let statuses: Vec<ValidationStatus> = report
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

        // create a thumbnail if we don't already have a claim with a thumb we can use
        if ingredient.thumbnail.is_none() {
            use crate::utils::thumbnail::make_thumbnail;
            if let Ok((format, image)) = make_thumbnail(path) {
                ingredient.set_thumbnail(format, image);
            }
        }

        Ok(ingredient)
    }

    /// Creates an Ingredient from a store and a uri to an ingredient assertion
    pub fn from_ingredient_uri(store: &Store, ingredient_uri: &str) -> Result<Self> {
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
            // if we have a relative thumbnail pass in URI and Claim to search
            match store.get_assertion_from_uri_and_claim(&hashed_uri.url(), ingredient_uri) {
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
        if let Some((format, image)) = thumbnail {
            ingredient.set_thumbnail(format, image);
        }

        ingredient.is_parent = is_parent;
        ingredient.active_manifest = active_manifest;
        ingredient.validation_status = ingredient_assertion.validation_status;
        ingredient.metadata = ingredient_assertion.metadata;
        Ok(ingredient)
    }

    pub fn add_to_claim(
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
                Store::load_ingredient_to_claim(claim, &manifest_label, buffer, redactions)?;

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
            if let Some((format, image)) = &self.thumbnail() {
                let hash_url = claim.add_assertion(&Thumbnail::new(
                    &labels::add_thumbnail_format(labels::INGREDIENT_THUMBNAIL, format),
                    image.to_vec(),
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

    pub fn stats(&self) -> usize {
        let thumb_size = self.thumbnail().map_or(0, |(_, image)| image.len());
        let manifest_data_size = self.manifest_data().map_or(0, |v| v.len());

        println!(
            "  {} instance_id: {}, thumb size: {}, manifest_data size: {}",
            self.title, self.instance_id, thumb_size, manifest_data_size,
        );
        self.title.len() + self.instance_id.len() + thumb_size + manifest_data_size
    }
}

impl std::fmt::Display for Ingredient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let report = serde_json::to_string_pretty(self).unwrap_or_default();
        f.write_str(&report)
    }
}

#[derive(Default)]
/// This defines optional actions when creating ingredients from files
pub struct IngredientOptions {
    /// This allows setting the title for the ingredient (the default is usually the file name)
    pub title: Option<&'static str>,
    /// If true, then generate a Blake3 hash over the source asset and store it here
    /// This can be used to test for duplicate ingredients or if a source file has changed
    pub make_hash: bool,
}

#[cfg(test)]
#[cfg(feature = "file_io")]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;

    use crate::utils::test::fixture_path;

    //use serde_cbor::{ser::IoWrite, Serializer};

    const MANIFEST_JPEG: &str = "C.jpg";
    const BAD_SIGNATURE_JPEG: &str = "CAICAI_BAD_SIG.jpg";
    const BAD_JUMBF_JPEG: &str = "bigjumbf.jpg";
    const PRERELEASE_JPEG: &str = "prerelease.jpg";

    #[test]
    fn test_psd() {
        // std::env::set_var("RUST_LOG", "debug");
        // env_logger::init();
        let ap = fixture_path("Purple Square.psd");
        let ingredient = Ingredient::from_file(&ap).expect("from_file");
        ingredient.stats();

        println!("ingredient = {}", ingredient);
        assert_eq!(&ingredient.title, "Purple Square.psd");
        assert_eq!(&ingredient.format, "image/vnd.adobe.photoshop");
        assert!(ingredient.thumbnail.is_none());
        assert!(ingredient.manifest_data.is_none());
    }

    #[test]
    fn test_jpg() {
        let ap = fixture_path(MANIFEST_JPEG);
        let ingredient = Ingredient::from_file(&ap).expect("from_file");
        ingredient.stats();

        println!("ingredient = {}", ingredient);
        assert_eq!(&ingredient.title, MANIFEST_JPEG);
        assert_eq!(&ingredient.format, "image/jpeg");
        assert!(ingredient.thumbnail.is_some());
        assert!(ingredient.provenance.is_some());
        assert!(ingredient.manifest_data.is_some());
        assert!(ingredient.metadata.is_none());
    }

    #[test]
    fn test_jpg_options() {
        let options = IngredientOptions {
            make_hash: true,
            title: Some("MyTitle"),
        };

        let ap = fixture_path(MANIFEST_JPEG);
        let ingredient = Ingredient::from_file_with_options(&ap, &options).expect("from_file");
        ingredient.stats();

        println!("ingredient = {}", ingredient);
        assert_eq!(&ingredient.title, "MyTitle");
        assert_eq!(&ingredient.format, "image/jpeg");
        assert!(ingredient.hash.is_some());
        assert!(ingredient.thumbnail.is_some());
        assert!(ingredient.provenance.is_some());
        assert!(ingredient.manifest_data.is_some());
        assert!(ingredient.metadata.is_none());
    }

    #[test]
    fn test_png_no_claim() {
        let ap = fixture_path("libpng-test.png");
        let ingredient = Ingredient::from_file(&ap).expect("from_file");
        ingredient.stats();

        println!("ingredient = {}", ingredient);
        assert_eq!(ingredient.title(), "libpng-test.png");
        assert!(ingredient.thumbnail().is_some());
        assert_eq!(ingredient.thumbnail().unwrap().0, "image/png");
        assert!(ingredient.manifest_data.is_none());
    }

    #[test]
    fn test_jpg_bad_signature() {
        let ap = fixture_path(BAD_SIGNATURE_JPEG);
        let ingredient = Ingredient::from_file(&ap).expect("from_file");
        ingredient.stats();

        println!("ingredient = {}", ingredient);
        assert_eq!(&ingredient.title, BAD_SIGNATURE_JPEG);
        assert_eq!(&ingredient.format, "image/jpeg");
        assert!(ingredient.thumbnail.is_some());
        assert!(ingredient.provenance.is_some());
        assert!(ingredient.manifest_data.is_some());
        assert!(ingredient.validation_status.is_some());
        assert!(ingredient
            .validation_status
            .unwrap()
            .iter()
            .any(|s| s.code() == validation_status::CLAIM_SIGNATURE_MISMATCH));
    }

    #[test]
    fn test_jpg_prerelease() {
        let ap = fixture_path(PRERELEASE_JPEG);
        let ingredient = Ingredient::from_file(&ap).expect("from_file");
        ingredient.stats();

        println!("ingredient = {}", ingredient);
        assert_eq!(&ingredient.title, PRERELEASE_JPEG);
        assert_eq!(&ingredient.format, "image/jpeg");
        assert!(ingredient.thumbnail.is_some());
        assert!(ingredient.provenance.is_some());
        assert!(ingredient.manifest_data.is_none());
        assert!(ingredient.validation_status.is_some());
        assert_eq!(
            ingredient.validation_status.unwrap()[0].code(),
            validation_status::STATUS_PRERELEASE
        );
    }

    #[test]
    fn test_jpg_bad_jumbf() {
        let ap = fixture_path(BAD_JUMBF_JPEG);
        let ingredient = Ingredient::from_file(&ap).expect("from_file");
        ingredient.stats();

        println!("ingredient = {}", ingredient);
        assert_eq!(&ingredient.title, BAD_JUMBF_JPEG);
        assert_eq!(&ingredient.format, "image/jpeg");
        assert!(ingredient.thumbnail.is_some());
        assert!(ingredient.provenance.is_some());
        assert!(ingredient.manifest_data.is_none());
        assert!(ingredient.validation_status.is_some());
        assert_eq!(
            ingredient.validation_status.unwrap()[0].code(),
            validation_status::STATUS_PRERELEASE
        );
    }

    #[test]
    fn test_jpg_nested() {
        let ap = fixture_path("CIE-sig-CA.jpg");
        let ingredient = Ingredient::from_file(&ap).expect("new_from_file");
        println!("ingredient = {}", ingredient);
        assert_eq!(ingredient.validation_status, None);
    }
}
