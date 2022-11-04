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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
    fn add<V: Into<Vec<u8>>>(&mut self, value: V) -> String;

    fn get(&self, id: &str) -> Option<&[u8]>;
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
    fn add<V: Into<Vec<u8>>>(&mut self, value: V) -> String {
        let key = uuid_b64::UuidB64::new().to_string();
        self.assets.insert(key.clone(), value.into());
        key
    }

    fn get(&self, id: &str) -> Option<&[u8]> {
        self.assets.get(id).map(|v| v as &[u8])
    }
}
