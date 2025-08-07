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

use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{labels, BmffHash, DataHash},
    asset_io::CAIRead,
    claim::Claim,
    error::{Error, Result},
    utils::io_utils::{stream_len, ReaderUtils},
    validation_status::{
        ASSERTION_MULTI_ASSET_HASH_MALFORMED, ASSERTION_MULTI_ASSET_HASH_MISSING_PART,
    },
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

    pub fn verify_self(&self, total_size: u64) -> Result<()> {
        let mut expected_offset: u64 = 0;

        if self.parts.is_empty() {
            return Err(Error::C2PAValidation(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED.to_string(),
            ));
        }

        for part in &self.parts {
            if part.location.byte_offset != expected_offset {
                return Err(Error::C2PAValidation(
                    ASSERTION_MULTI_ASSET_HASH_MALFORMED.to_string(),
                ));
            }
            expected_offset += part.location.length;
        }

        if expected_offset != total_size {
            return Err(Error::C2PAValidation(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED.to_string(),
            ));
        }

        Ok(())
    }

    pub fn verify_stream_hash(&self, mut reader: &mut dyn CAIRead, claim: &Claim) -> Result<()> {
        let length = stream_len(reader)?;
        self.verify_self(length)?;

        for part in &self.parts {
            if let Some(optional) = part.optional {
                if optional {
                    continue;
                };
            }
            if let Some(assertion) = claim.get_assertion_from_link(&part.hash_assertion.url()) {
                let label = assertion.label();
                let offset = part.location.byte_offset;
                let length = part.location.length;

                reader.seek(std::io::SeekFrom::Start(offset))?;
                let buf = reader.read_to_vec(length)?;
                let mut part_reader = Cursor::new(buf);

                match label.as_str() {
                    // starts with for all
                    l if l.starts_with(DataHash::LABEL) => {
                        let dh = DataHash::from_assertion(assertion)?;
                        let alg = match &dh.alg {
                            Some(alg) => alg,
                            None => claim.alg(),
                        };
                        dh.verify_stream_hash(&mut part_reader, Some(alg))?;
                    }
                    l if l.starts_with(BmffHash::LABEL) => {}
                    _ => {}
                }
            }
        }
        Ok(())
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

    use std::io::Cursor;

    use crate::{assertion::AssertionBase, assertions::MultiAssetHash, status_tracker::StatusTracker, store::Store};

    const TEST_IMAGE: &[u8] = include_bytes!("../../tests/fixtures/multi_asset_hash_signed.jpg");
    
    #[test]
    fn test_validation() {
        let mut validation_log = StatusTracker::default();
        let source = Cursor::new(TEST_IMAGE);
        let store = Store::from_stream("image/jpeg", source, true, &mut validation_log).unwrap();
        let claim = store.provenance_claim().unwrap();
        let assertion = MultiAssetHash::from_assertion(claim.get_assertion(MultiAssetHash::LABEL, 0).unwrap()).unwrap();
        let mut source = Cursor::new(TEST_IMAGE);
        assertion.verify_stream_hash(&mut source, claim).unwrap();
    }

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
