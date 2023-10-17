// Copyright 2023 Adobe. All rights reserved.
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

use std::{borrow::Cow, collections::HashMap};
#[cfg(feature = "file_io")]
use std::{
    fs::{create_dir_all, read, write},
    path::{Path, PathBuf},
};

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{assertions::AssetType, claim::Claim, hashed_uri::HashedUri, Error, Result};

/// Function that is used by serde to determine whether or not we should serialize
/// resources based on the `serialize_resources` flag.
/// (Serialization is disabled by default.)
pub(crate) fn skip_serializing_resources(_: &ResourceStore) -> bool {
    !cfg!(feature = "serialize_thumbnails") || cfg!(test)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
#[serde(untagged)]
pub enum UriOrResource {
    ResourceRef(ResourceRef),
    HashedUri(HashedUri),
}
impl UriOrResource {
    pub fn to_hashed_uri(
        &self,
        resources: &ResourceStore,
        claim: &mut Claim,
    ) -> Result<UriOrResource> {
        match self {
            UriOrResource::ResourceRef(r) => {
                let data = resources.get(&r.identifier)?;
                let hash_uri = claim.add_databox(&r.format, data.to_vec(), None)?;
                Ok(UriOrResource::HashedUri(hash_uri))
            }
            UriOrResource::HashedUri(h) => Ok(UriOrResource::HashedUri(h.clone())),
        }
    }

    pub fn to_resource_ref(
        &self,
        resources: &mut ResourceStore,
        claim: &Claim,
    ) -> Result<UriOrResource> {
        match self {
            UriOrResource::ResourceRef(r) => Ok(UriOrResource::ResourceRef(r.clone())),
            UriOrResource::HashedUri(h) => {
                let uri = crate::jumbf::labels::to_absolute_uri(claim.label(), &h.url());
                let data_box = claim.find_databox(&uri).ok_or(Error::MissingDataBox)?;
                let resource_ref =
                    resources.add_with(&h.url(), &data_box.format, data_box.data.clone())?;
                Ok(UriOrResource::ResourceRef(resource_ref))
            }
        }
    }
}

impl From<ResourceRef> for UriOrResource {
    fn from(r: ResourceRef) -> Self {
        Self::ResourceRef(r)
    }
}

impl From<HashedUri> for UriOrResource {
    fn from(h: HashedUri) -> Self {
        Self::HashedUri(h)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
/// A reference to a resource to be used in JSON serialization.
pub struct ResourceRef {
    /// The mime type of the referenced resource.
    pub format: String,

    /// A URI that identifies the resource as referenced from the manifest.
    ///
    /// This may be a JUMBF URI, a file path, a URL or any other string.
    /// Relative JUMBF URIs will be resolved with the manifest label.
    /// Relative file paths will be resolved with the base path if provided.
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]

    /// More detailed data types as defined in the C2PA spec.
    pub data_types: Option<Vec<AssetType>>,
    #[serde(skip_serializing_if = "Option::is_none")]

    /// The algorithm used to hash the resource (if applicable).
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]

    /// The hash of the resource (if applicable).
    pub hash: Option<String>,
}

impl ResourceRef {
    pub fn new<S: Into<String>, I: Into<String>>(format: S, identifier: I) -> Self {
        Self {
            format: format.into(),
            identifier: identifier.into(),
            data_types: None,
            alg: None,
            hash: None,
        }
    }
}

/// Resource store to contain binary objects referenced from JSON serializable structures
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ResourceStore {
    resources: HashMap<String, Vec<u8>>,
    #[cfg(feature = "file_io")]
    #[serde(skip_serializing_if = "Option::is_none")]
    base_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

impl ResourceStore {
    /// Create a new resource reference.
    pub fn new() -> Self {
        ResourceStore {
            resources: HashMap::new(),
            #[cfg(feature = "file_io")]
            base_path: None,
            label: None,
        }
    }

    /// Set a manifest label for this store used to resolve relative JUMBF URIs.
    pub fn set_label<S: Into<String>>(&mut self, label: S) -> &Self {
        self.label = Some(label.into());
        self
    }

    #[cfg(feature = "file_io")]
    // Returns the base path for relative file paths if it is set.
    pub fn base_path(&self) -> Option<&Path> {
        self.base_path.as_deref()
    }

    #[cfg(feature = "file_io")]
    /// Sets a base path for relative file paths.
    ///
    /// Identifiers will be interpreted as file paths and resources will be written to files if this is set.
    pub fn set_base_path<P: Into<PathBuf>>(&mut self, base_path: P) {
        self.base_path = Some(base_path.into());
    }

    #[cfg(feature = "file_io")]
    /// Returns and removes the base path.
    pub fn take_base_path(&mut self) -> Option<PathBuf> {
        self.base_path.take()
    }

    /// Generates a unique ID for a given content type (adds a file extension).
    pub fn id_from(&self, key: &str, format: &str) -> String {
        let ext = match format {
            "jpg" | "jpeg" | "image/jpeg" => ".jpg",
            "png" | "image/png" => ".png",
            //make "svg" | "image/svg+xml" => ".svg",
            "c2pa" | "application/x-c2pa-manifest-store" | "application/c2pa" => ".c2pa",
            _ => "",
        };
        // clean string for possible filesystem use
        let id_base = key.replace(['/', ':'], "-");

        // ensure it is unique in this store
        let mut count = 1;
        let mut id = format!("{id_base}{ext}");
        while self.exists(&id) {
            id = format!("{id_base}-{count}{ext}");
            count += 1;
        }
        id
    }

    /// Adds a resource, generating a [`ResourceRef`] from a key and format.
    ///
    /// The generated identifier may be different from the key.
    pub fn add_with<R>(&mut self, key: &str, format: &str, value: R) -> crate::Result<ResourceRef>
    where
        R: Into<Vec<u8>>,
    {
        let id = self.id_from(key, format);
        self.add(&id, value)?;
        Ok(ResourceRef::new(format, id))
    }

    /// Adds a resource from a URI, generating a [`ResourceRef`].
    ///
    /// The generated identifier may be different from the key.
    pub(crate) fn add_uri<R>(
        &mut self,
        uri: &str,
        format: &str,
        value: R,
    ) -> crate::Result<ResourceRef>
    where
        R: Into<Vec<u8>>,
    {
        #[cfg(feature = "file_io")]
        let mut id = uri.to_string();
        #[cfg(not(feature = "file_io"))]
        let id = uri.to_string();

        // if it isn't jumbf, assume it's an external uri and use it as is
        if id.starts_with("self#jumbf=") {
            #[cfg(feature = "file_io")]
            if self.base_path.is_some() {
                // convert to a file path always including the manifest label
                id = id.replace("self#jumbf=", "");
                if id.starts_with("/c2pa/") {
                    id = id.replacen("/c2pa/", "", 1);
                } else if let Some(label) = self.label.as_ref() {
                    id = format!("{}/{id}", label);
                }
                id = id.replace([':'], "_");
                // add a file extension if it doesn't have one
                if !(id.ends_with(".jpeg") || id.ends_with(".png")) {
                    if let Some(ext) = crate::utils::mime::format_to_extension(format) {
                        id = format!("{}.{}", id, ext);
                    }
                }
            }
            if !self.exists(&id) {
                self.add(&id, value)?;
            }
        }
        Ok(ResourceRef::new(format, id))
    }

    /// Adds a resource, using a given id value.
    pub fn add<S, R>(&mut self, id: S, value: R) -> crate::Result<&mut Self>
    where
        S: Into<String>,
        R: Into<Vec<u8>>,
    {
        #[cfg(feature = "file_io")]
        if let Some(base) = self.base_path.as_ref() {
            let path = base.join(id.into());
            create_dir_all(path.parent().unwrap_or(Path::new("")))?;
            write(path, value.into())?;
            return Ok(self);
        }
        self.resources.insert(id.into(), value.into());
        Ok(self)
    }

    /// Returns a [`HashMap`] of internal resources.
    pub fn resources(&self) -> &HashMap<String, Vec<u8>> {
        &self.resources
    }

    /// Returns a copy on write reference to the resource if found.
    ///
    /// Returns [`Error::ResourceNotFound`] if it cannot find a resource matching that ID.
    pub fn get(&self, id: &str) -> Result<Cow<Vec<u8>>> {
        #[cfg(feature = "file_io")]
        if !self.resources.contains_key(id) {
            match self.base_path.as_ref() {
                Some(base) => {
                    // read the file, save in Map and then return a reference
                    let path = base.join(id);
                    let value = read(path).map_err(|_| {
                        let path = base.join(id).to_string_lossy().into_owned();
                        Error::ResourceNotFound(path)
                    })?;
                    return Ok(Cow::Owned(value));
                }
                None => return Err(Error::ResourceNotFound(id.to_string())),
            }
        }
        self.resources.get(id).map_or_else(
            || Err(Error::ResourceNotFound(id.to_string())),
            |v| Ok(Cow::Borrowed(v)),
        )
    }

    /// Returns `true` if the resource has been added or exists as file.
    pub fn exists(&self, id: &str) -> bool {
        if !self.resources.contains_key(id) {
            #[cfg(feature = "file_io")]
            match self.base_path.as_ref() {
                Some(base) => {
                    let path = base.join(id);
                    path.exists()
                }
                None => false,
            }
            #[cfg(not(feature = "file_io"))]
            false
        } else {
            true
        }
    }

    #[cfg(feature = "file_io")]
    // Returns the full path for an ID.
    pub fn path_for_id(&self, id: &str) -> Option<PathBuf> {
        self.base_path.as_ref().map(|base| base.join(id))
    }
}

impl Default for ResourceStore {
    fn default() -> Self {
        ResourceStore::new()
    }
}

#[cfg(test)]
#[cfg(feature = "openssl_sign")]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{utils::test::temp_signer, Manifest};

    #[test]
    #[cfg(feature = "openssl_sign")]
    fn resource_store() {
        let mut c = ResourceStore::new();
        let value = b"my value";
        c.add("abc123.jpg", value.to_vec()).expect("add");
        let v = c.get("abc123.jpg").unwrap();
        assert_eq!(v.to_vec(), b"my value");
        c.add("cba321.jpg", value.to_vec()).expect("add");
        assert!(c.exists("cba321.jpg"));
        assert!(!c.exists("foo"));

        let json = r#"{
            "claim_generator": "test",
            "format" : "image/jpeg",
            "instance_id": "12345",
            "assertions": [],
            "thumbnail": {
                "format": "image/jpeg",
                "identifier": "abc123"
            },
            "ingredients": [{
                "title": "A.jpg",
                "format": "image/jpeg",
                "document_id": "xmp.did:813ee422-9736-4cdc-9be6-4e35ed8e41cb",
                "instance_id": "xmp.iid:813ee422-9736-4cdc-9be6-4e35ed8e41cb",
                "relationship": "parentOf",
                "thumbnail": {
                    "format": "image/jpeg",
                    "identifier": "cba321"
                }
            }]
        }"#;

        let mut manifest = Manifest::from_json(json).expect("from json");
        manifest
            .resources_mut()
            .add("abc123", *value)
            .expect("add_resource");
        let ingredient = &mut manifest.ingredients_mut()[0];
        ingredient
            .resources_mut()
            .add("cba321", *value)
            .expect("add_resource");
        println!("{manifest}");

        let image = include_bytes!("../tests/fixtures/earth_apollo17.jpg");

        let signer = temp_signer();
        // Embed a manifest using the signer.
        let output_image = manifest
            .embed_from_memory("jpeg", image, signer.as_ref())
            .expect("embed_stream");

        let _manifest_store =
            crate::ManifestStore::from_bytes("jpeg", &output_image, true).expect("from_bytes");
        // println!("{manifest_store}");
    }
}
