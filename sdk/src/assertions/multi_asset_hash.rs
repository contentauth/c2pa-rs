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

#[cfg(feature = "file_io")]
use std::fs::File;
use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::{labels, BmffHash, BoxHash, DataHash},
    asset_io::{AssetIO, CAIRead},
    claim::{Claim, ClaimAssetData},
    error::{Error, Result},
    jumbf_io::get_assetio_handler,
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

    /// The parts within the parts array shall be listed in the order in which they appear in the file,
    /// and the parts shall be contiguous, non-overlapping, and cover every byte of the asset.
    fn verify_self(&self, total_size: u64) -> Result<()> {
        if self.parts.is_empty() {
            return Err(Error::C2PAValidation(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED.to_string(),
            ));
        }

        let mut expected_offset: u64 = 0;
        let mut optional_sizes: u64 = 0;

        for part in &self.parts {
            match &part.location {
                LocatorMap::ByteRangeLocator(locator) => {
                    if locator.byte_offset != expected_offset {
                        return Err(Error::C2PAValidation(
                            ASSERTION_MULTI_ASSET_HASH_MALFORMED.to_string(),
                        ));
                    }
                    // Keep track of the size of optional parts.
                    if part.optional.unwrap_or(false) {
                        optional_sizes += locator.length;
                    }
                    expected_offset += locator.length;
                }
                LocatorMap::BmffBox { .. } => {
                    return Err(Error::NotImplemented(
                        "BmffBox locators not yet implemented for Multi-Asset hashes".to_string(),
                    ));
                }
            }
        }

        // Deduct optional sizes and ensure that the offsets are less than the total size.
        if expected_offset - optional_sizes > total_size {
            return Err(Error::C2PAValidation(
                ASSERTION_MULTI_ASSET_HASH_MALFORMED.to_string(),
            ));
        }

        Ok(())
    }

    // Verifies the multi-asset hash assertion against the provided asset data.
    pub fn verify_hash(&self, asset_data: &mut ClaimAssetData<'_>, claim: &Claim) -> Result<()> {
        match asset_data {
            #[cfg(feature = "file_io")]
            ClaimAssetData::Path(asset_path) => {
                let mut file = File::open(&asset_path).map_err(Error::IoError)?;
                let asset_handler = crate::jumbf_io::get_assetio_handler_from_path(asset_path);
                self.verify_stream_hash(&mut file, claim, asset_handler)
            }
            ClaimAssetData::Bytes(asset_bytes, asset_type) => {
                let mut cursor = Cursor::new(*asset_bytes);
                let asset_handler = get_assetio_handler(asset_type);
                self.verify_stream_hash(&mut cursor, claim, asset_handler)
            }
            ClaimAssetData::Stream(stream_data, asset_type) => {
                let asset_handler = get_assetio_handler(asset_type);
                self.verify_stream_hash(*stream_data, claim, asset_handler)
            }
            _ => Err(Error::UnsupportedType),
        }
    }

    /// Verifies each part of the multi-asset hash through comparing computed hashes.
    /// Validates part locations, reads the specified byte ranges, and verifies against referenced hash assertions.
    fn verify_stream_hash(
        &self,
        mut reader: &mut dyn CAIRead,
        claim: &Claim,
        asset_handler: Option<&dyn AssetIO>,
    ) -> Result<()> {
        let length = stream_len(reader)?;
        self.verify_self(length)?;

        for part in &self.parts {
            if part.optional.unwrap_or(false) {
                continue;
            }

            // Retrieve the assertion linked in the multi-asset assertions.
            let assertion = claim
                .get_assertion_from_link(&part.hash_assertion.url())
                .ok_or_else(|| {
                    Error::C2PAValidation(ASSERTION_MULTI_ASSET_HASH_MISSING_PART.to_string())
                })?;

            let label = assertion.label();

            match &part.location {
                LocatorMap::ByteRangeLocator(locator) => {
                    let offset = locator.byte_offset;
                    let length = locator.length;

                    // Read only the specified parts within the larger stream.
                    reader.seek(std::io::SeekFrom::Start(offset))?;
                    let buf = reader.read_to_vec(length).map_err(|_| {
                        Error::C2PAValidation(ASSERTION_MULTI_ASSET_HASH_MISSING_PART.to_string())
                    })?;
                    let mut part_reader = Cursor::new(buf);

                    // Perform validation on each part depending on type of hash.
                    match label.as_str() {
                        l if l.starts_with(DataHash::LABEL) => {
                            let dh = DataHash::from_assertion(assertion)?;
                            let alg = match &dh.alg {
                                Some(alg) => alg,
                                None => claim.alg(),
                            };
                            dh.verify_stream_hash(&mut part_reader, Some(alg))?;
                        }
                        l if l.starts_with(BoxHash::LABEL) => {
                            let bh = BoxHash::from_assertion(assertion)?;
                            let box_hash_processor = asset_handler
                                .ok_or(Error::UnsupportedType)?
                                .asset_box_hash_ref()
                                .ok_or(Error::HashMismatch("Box hash not supported".to_string()))?;
                            bh.verify_stream_hash(
                                &mut part_reader,
                                Some(claim.alg()),
                                box_hash_processor,
                            )?;
                        }
                        l if l.starts_with(BmffHash::LABEL) => {
                            return Err(Error::NotImplemented(
                                "BmffHash not yet implemented for Multi-Asset hashes".to_string(),
                            ));
                        }
                        _ => {}
                    }
                }
                LocatorMap::BmffBox { .. } => {
                    return Err(Error::NotImplemented(
                        "BmffBox locators not yet implemented for Multi-Asset hashes".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PartHashMap {
    pub location: LocatorMap,
    pub hash_assertion: HashedUri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
#[serde(rename_all = "camelCase")]
pub enum LocatorMap {
    ByteRangeLocator(ByteRangeLocator),
    BmffBox { bmff_box: String },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ByteRangeLocator {
    pub byte_offset: u64,
    pub length: u64,
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

    use crate::{
        assertion::AssertionBase, assertions::MultiAssetHash, status_tracker::StatusTracker,
        store::Store,
    };

    const MOTION_PHOTO: &[u8] = include_bytes!("../../tests/fixtures/motion_photo.jpg");
    const MOTION_PHOTO_2: &[u8] = include_bytes!("../../tests/fixtures/motion_photo2.jpg");
    const NO_MOVIE_MOTION_PHOTO: &[u8] =
        include_bytes!("../../tests/fixtures/no_movie_motion_photo.jpg");
    const STRIPPED_PHOTO: &[u8] = include_bytes!("../../tests/fixtures/stripped.jpg");

    #[test]
    fn test_validation() {
        let mut validation_log = StatusTracker::default();
        let source = Cursor::new(MOTION_PHOTO);
        let store = Store::from_stream("image/jpeg", source, true, &mut validation_log).unwrap();
        let claim = store.provenance_claim().unwrap();
        let assertion =
            MultiAssetHash::from_assertion(claim.get_assertion(MultiAssetHash::LABEL, 0).unwrap())
                .unwrap();
        let mut source = Cursor::new(MOTION_PHOTO);
        assertion
            .verify_stream_hash(&mut source, claim, None)
            .unwrap();
    }

    #[test]
    fn test_multiple_parts_validation() {
        let mut validation_log = StatusTracker::default();
        let source = Cursor::new(MOTION_PHOTO_2);
        let store = Store::from_stream("image/jpeg", source, true, &mut validation_log).unwrap();
        let claim = store.provenance_claim().unwrap();
        let assertion =
            MultiAssetHash::from_assertion(claim.get_assertion(MultiAssetHash::LABEL, 0).unwrap())
                .unwrap();
        let mut source = Cursor::new(MOTION_PHOTO_2);
        assertion
            .verify_stream_hash(&mut source, claim, None)
            .unwrap();
    }

    #[test]
    fn test_stripped_validation() {
        let mut validation_log = StatusTracker::default();
        let source = Cursor::new(STRIPPED_PHOTO);
        let store = Store::from_stream("image/jpeg", source, true, &mut validation_log).unwrap();
        let claim = store.provenance_claim().unwrap();
        let assertion =
            MultiAssetHash::from_assertion(claim.get_assertion(MultiAssetHash::LABEL, 0).unwrap())
                .unwrap();
        let mut source = Cursor::new(STRIPPED_PHOTO);
        assertion
            .verify_stream_hash(&mut source, claim, None)
            .unwrap();
    }

    #[test]
    fn test_validation_with_exclusion_of_optional_data_hash() {
        let mut validation_log = StatusTracker::default();
        let source = Cursor::new(NO_MOVIE_MOTION_PHOTO);
        let store = Store::from_stream("image/jpeg", source, true, &mut validation_log).unwrap();
        let claim = store.provenance_claim().unwrap();
        let assertion =
            MultiAssetHash::from_assertion(claim.get_assertion(MultiAssetHash::LABEL, 0).unwrap())
                .unwrap();
        let mut source = Cursor::new(NO_MOVIE_MOTION_PHOTO);
        assertion
            .verify_stream_hash(&mut source, claim, None)
            .unwrap();
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
