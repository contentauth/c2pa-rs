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

use std::{borrow::Cow, collections::HashMap};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Function that is used by serde to determine whether or not we should serialize
/// thumbnail data based on the `serialize_thumbnails` flag.
/// (Serialization is disabled by default.)
pub(crate) fn skip_serializing_thumbnails(_: &AssetMap) -> bool {
    !cfg!(feature = "serialize_thumbnails")
}

/// A Manifest represents all the information in a c2pa manifest
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AssetRef {
    pub content_type: String,
    pub identifier: String,
}

impl AssetRef {
    pub fn new<S: Into<String>>(content_type: S, identifier: S) -> Self {
        Self {
            content_type: content_type.into(),
            identifier: identifier.into(),
        }
    }
}

pub trait AssetStore {
    fn add(&mut self, value: Vec<u8>) -> Result<String>;

    fn get(&self, id: &str) -> Result<Cow<[u8]>>;
}

#[derive(Debug, Default, Serialize)]
pub(crate) struct AssetMap {
    assets: HashMap<String, Vec<u8>>,
}

impl AssetMap {
    pub fn new() -> Self {
        Self {
            assets: HashMap::new(),
        }
    }
}

impl AssetStore for AssetMap {
    fn add(&mut self, value: Vec<u8>) -> Result<String> {
        let key = uuid_b64::UuidB64::new().to_string();
        self.assets.insert(key.clone(), value);
        Ok(key)
    }

    fn get(&self, id: &str) -> Result<Cow<[u8]>> {
        match self.assets.get(id) {
            Some(v) => Ok(v.into()),
            None => Err(Error::NotFound),
        }
    }
}

use std::path::{Path, PathBuf};
#[derive(Debug, Default, Serialize)]
pub(crate) struct AssetFolder {
    base_path: PathBuf,
}

impl AssetFolder {
    pub fn _new<P: AsRef<Path>>(base_path: P) -> Self {
        Self {
            base_path: PathBuf::from(base_path.as_ref()),
        }
    }
}

impl AssetStore for AssetFolder {
    fn add(&mut self, value: Vec<u8>) -> Result<String> {
        let id = uuid_b64::UuidB64::new().to_string();
        let path = self.base_path.join(&id);
        std::fs::write(path, value)?;
        Ok(id)
    }

    fn get(&self, id: &str) -> Result<Cow<[u8]>> {
        let path = self.base_path.join(id);
        Ok(std::fs::read(path)?.into())
    }
}

#[derive(Debug, Serialize)]
pub(crate) enum AssetThing {
    AssetMap(AssetMap),
}

impl AssetThing {
    pub fn get(&self, id: &str) -> Result<Cow<[u8]>> {
        match self {
            Self::AssetMap(m) => m.get(id),
        }
    }

    pub fn add(&mut self, value: Vec<u8>) -> Result<String> {
        match self {
            Self::AssetMap(m) => m.add(value),
        }
    }
}

impl Default for AssetThing {
    fn default() -> Self {
        Self::AssetMap(AssetMap::new())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn asset_folder() {
        const DATA: &[u8] = b"foo";
        let mut af = AssetFolder::_new("../target/tmp");
        let id = af.add(DATA.to_vec()).expect("add");
        let foo = af.get(&id).expect("get");
        assert_eq!(Cow::Borrowed(DATA), foo)
    }
}
