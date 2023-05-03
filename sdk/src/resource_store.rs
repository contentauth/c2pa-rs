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

#[cfg(feature = "file_io")]
use std::path::{Path, PathBuf};
use std::{borrow::Cow, collections::HashMap};

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Function that is used by serde to determine whether or not we should serialize
/// resources based on the `serialize_resources` flag.
/// (Serialization is disabled by default.)
pub(crate) fn skip_serializing_resources(_: &ResourceStore) -> bool {
    !cfg!(feature = "serialize_thumbnails") || cfg!(test)
}

/// A reference to a resource to be used in JSON serialization
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct ResourceRef {
    pub format: String,
    pub identifier: String,
}

impl ResourceRef {
    pub fn new<S: Into<String>, I: Into<String>>(format: S, identifier: I) -> Self {
        Self {
            format: format.into(),
            identifier: identifier.into(),
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
}

impl ResourceStore {
    pub fn new() -> Self {
        ResourceStore {
            resources: HashMap::new(),
            #[cfg(feature = "file_io")]
            base_path: None,
        }
    }

    #[cfg(feature = "file_io")]
    pub fn base_path(&self) -> Option<&Path> {
        self.base_path.as_deref()
    }

    #[cfg(feature = "file_io")]
    pub fn set_base_path<P: Into<PathBuf>>(&mut self, base_path: P) {
        self.base_path = Some(base_path.into());
    }

    #[cfg(feature = "file_io")]
    pub fn take_base_path(&mut self) -> Option<PathBuf> {
        self.base_path.take()
    }

    ///  generate a unique id for a given content type (adds a file extension)
    pub fn id_from(&self, key: &str, format: &str) -> String {
        let ext = match format {
            "jpg" | "jpeg" | "image/jpeg" => ".jpg",
            "png" | "image/png" => ".png",
            "c2pa" | "application/x-c2pa-manifest-store" => ".cp2a",
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

    /// Adds a resource, generating a resource ref from a key and format.
    ///
    /// The generated identifier may be different from the key
    pub fn add_with<R>(&mut self, key: &str, format: &str, value: R) -> crate::Result<ResourceRef>
    where
        R: Into<Vec<u8>>,
    {
        let id = self.id_from(key, format);
        self.add(&id, value)?;
        Ok(ResourceRef::new(format, id))
    }

    /// Adds a resource, using a given id value.
    pub fn add<S, R>(&mut self, id: S, value: R) -> crate::Result<()>
    where
        S: Into<String>,
        R: Into<Vec<u8>>,
    {
        #[cfg(feature = "file_io")]
        if let Some(base) = self.base_path.as_ref() {
            let path = base.join(id.into());
            std::fs::create_dir_all(path.parent().unwrap_or(Path::new("")))?;
            #[allow(clippy::expect_used)]
            std::fs::write(path, value.into())?;
            return Ok(());
        }
        self.resources.insert(id.into(), value.into());
        Ok(())
    }

    pub fn resources(&self) -> &HashMap<String, Vec<u8>> {
        &self.resources
    }

    /// Returns a copy on write reference to the resource if found.
    ///
    /// returns Error::NotFound if it cannot find a resource matching that id
    pub fn get(&self, id: &str) -> Result<Cow<Vec<u8>>> {
        #[cfg(feature = "file_io")]
        if !self.resources.contains_key(id) {
            match self.base_path.as_ref() {
                Some(base) => {
                    // read the file, save in Map and then return a reference
                    let path = base.join(id);
                    let value = std::fs::read(path)?;
                    return Ok(Cow::Owned(value));
                }
                None => return Err(Error::NotFound),
            }
        }
        self.resources
            .get(id)
            .map_or_else(|| Err(Error::NotFound), |v| Ok(Cow::Borrowed(v)))
    }

    /// Returns true if the resource has been added or exists as file.
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
    // return the full path for an id
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
        // convert buffer to cursor with Read/Write/Seek capability
        let mut stream = std::io::Cursor::new(image.to_vec());

        let signer = temp_signer();
        // Embed a manifest using the signer.
        let output_image = manifest
            .embed_stream("jpeg", &mut stream, signer.as_ref())
            .expect("embed_stream");

        let _manifest_store =
            crate::ManifestStore::from_bytes("jpeg", &output_image, true).expect("from_bytes");
        // println!("{manifest_store}");
    }
}
