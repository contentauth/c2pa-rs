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

use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    error::Result,
    HashedUri,
};

/// A `MultiAssetHash` assertion provides information on hash values for multiple parts of an asset.
///
/// This assertion contains a list of parts, each one declaring a location within the asset and
/// the corresponding hash assertion for that part.
///
/// See <https://spec.c2pa.org/specifications/specifications/2.2/specs/C2PA_Specification.html#_multi_asset_hash>
#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct MultiAssetHash {
    pub parts: Vec<PartHashMap>,
}

impl MultiAssetHash {
    pub const LABEL: &'static str = labels::MULTI_ASSET_HASH;

    pub fn new(location: LocationMap, hash_assertion: HashedUri, optional: Option<bool>) -> Self {
        Self {
            parts: vec![PartHashMap::new(location, hash_assertion, optional)],
        }
    }

    pub fn add_part(
        mut self,
        location: LocationMap,
        hash_assertion: HashedUri,
        optional: Option<bool>,
    ) -> Self {
        self.parts
            .push(PartHashMap::new(location, hash_assertion, optional));
        self
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct PartHashMap {
    pub location: LocationMap,
    #[serde(rename = "hashAssertion")]
    pub hash_assertion: HashedUri,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

impl PartHashMap {
    pub fn new(location: LocationMap, hash_assertion: HashedUri, optional: Option<bool>) -> Self {
        Self {
            location,
            hash_assertion,
            optional,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct LocationMap {
    #[serde(rename = "byteOffset")]
    pub byte_offset: u64,
    pub length: u64,
}

impl LocationMap {
    pub fn new(byte_offset: u64, length: u64) -> Self {
        Self {
            byte_offset,
            length,
        }
    }
}

impl AssertionCbor for MultiAssetHash {}

impl AssertionBase for MultiAssetHash {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use crate::{assertion::AssertionBase, assertions::MultiAssetHash};

    #[test]
    fn test_json_round_trip() {
        let json = serde_json::json!({
            "parts": [
              {
                "location": {
                  "byteOffset": 0,
                  "length": 3211426
                },
                "hashAssertion": {
                  "url": "self#jumbf=c2pa.assertions/c2pa.hash.data.part",
                  "hash": "Lq2kdBpPG002xct74CAEOb93d/aRhDHhwzK0EGj9y98="
                },
                "optional": false
              },
              {
                "location": {
                  "byteOffset": 3211426,
                  "length": 38044
                },
                "hashAssertion": {
                  "url": "self#jumbf=c2pa.assertions/c2pa.hash.data.part__1",
                  "hash": "KlwzkqoUjclLdqKN0N+T3eGCd45iwGncE4lcwiGXlKs="
                },
                "optional": false
              },
              {
                "location": {
                  "byteOffset": 3249470,
                  "length": 1403182
                },
                "hashAssertion": {
                  "url": "self#jumbf=c2pa.assertions/c2pa.hash.data.part__2",
                  "hash": "GykUNh5wHwRVpfsduK2ylqY5IfuHZLyuwIkUTuD7O0E="
                },
                "optional": true
              }
            ]
        });

        let original: MultiAssetHash = serde_json::from_value(json).unwrap();
        let assertion = original.to_assertion().unwrap();
        let result = MultiAssetHash::from_assertion(&assertion).unwrap();

        assert_eq!(result, original);
    }
}
