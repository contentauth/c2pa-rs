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

use std::fmt;

#[cfg(feature = "json_schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::utils::DebugByteSlice;

/// A `HashedUri` provides a reference to content available within the same
/// manifest store.
///
/// This is described in [§8.3, URI References], of the C2PA Technical
/// Specification.
///
/// [§8.3, URI References]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_uri_references
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "json_schema", derive(JsonSchema))]
pub struct HashedUri {
    /// JUMBF URI reference
    url: String,

    /// A string identifying the cryptographic hash algorithm used to compute
    /// the hash
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,

    /// Byte string containing the hash value
    #[serde(with = "serde_bytes")]
    #[cfg_attr(feature = "json_schema", schemars(with = "Vec<u8>"))]
    hash: Vec<u8>,

    /// Salt used to generate the hash
    #[serde(skip_deserializing, skip_serializing)]
    salt: Option<Vec<u8>>,
}

impl HashedUri {
    pub fn new(url: String, alg: Option<String>, hash_bytes: &[u8]) -> Self {
        Self {
            url,
            alg,
            hash: hash_bytes.to_vec(),
            salt: None,
        }
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn is_relative_url(&self) -> bool {
        crate::jumbf::labels::manifest_label_from_uri(&self.url).is_none()
    }

    pub fn alg(&self) -> Option<String> {
        self.alg.clone()
    }

    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }

    pub(crate) fn update_hash(&mut self, hash: Vec<u8>) {
        self.hash = hash;
    }

    pub fn add_salt(&mut self, salt: Option<Vec<u8>>) {
        self.salt = salt;
    }

    pub fn salt(&self) -> &Option<Vec<u8>> {
        &self.salt
    }
}

impl fmt::Debug for HashedUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("HashedUri")
            .field("url", &self.url)
            .field("alg", &self.alg)
            .field("hash", &DebugByteSlice(&self.hash))
            .finish()
    }
}

impl fmt::Display for HashedUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "url: {}, alg: {:?}, hash", self.url, self.alg)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::HashedUri;

    #[test]
    fn impl_clone() {
        let h = HashedUri::new(
            "self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/c2pa.hash.data".to_owned(),
             Some("sha256".to_owned()),
            &hex!("53d1b2cf4e6d9a97ed9281183fa5d836c32751b9d2fca724b40836befee7d67f"),
        );

        let h2 = h.clone();
        assert!(h == h2);
    }

    #[test]
    fn impl_debug() {
        let h = HashedUri::new(
            "self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/c2pa.hash.data".to_owned(),
             Some("sha256".to_owned()),
            &hex!("53d1b2cf4e6d9a97ed9281183fa5d836c32751b9d2fca724b40836befee7d67f"),
        );

        assert_eq!(format!("{:#?}", h), "HashedUri {\n    url: \"self#jumbf=c2pa/urn:uuid:F9168C5E-CEB2-4faa-B6BF-329BF39FA1E4/c2pa.assertions/c2pa.hash.data\",\n    alg: Some(\n        \"sha256\",\n    ),\n    hash: 32 bytes starting with [53, d1, b2, cf, 4e, 6d, 9a, 97, ed, 92, 81, 18, 3f, a5, d8, 36, c3, 27, 51, b9],\n}");
    }
}
