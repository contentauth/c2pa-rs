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

use std::{fs::File, io::Cursor, path::*};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor, AssertionJson},
    assertions::labels,
    asset_io::{AssetBoxHash, CAIRead},
    error::{Error, Result},
    utils::hash_utils::{hash_stream_by_alg, verify_stream_by_alg, HashRange},
};

const ASSERTION_CREATION_VERSION: usize = 1;

pub const C2PA_BOXHASH: &str = "C2PA";

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BoxMap {
    pub names: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    pub hash: ByteBuf,
    pub pad: ByteBuf,

    #[serde(skip)]
    pub range_start: usize,

    #[serde(skip)]
    pub range_len: usize,
}

/// Helper class to create BoxHash assertion
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BoxHash {
    boxes: Vec<BoxMap>,
}

impl BoxHash {
    pub const LABEL: &'static str = labels::BOX_HASH;

    pub fn verify_hash(
        &self,
        asset_path: &Path,
        alg: Option<&str>,
        bhp: &dyn AssetBoxHash,
    ) -> Result<()> {
        let mut file = File::open(asset_path)?;

        self.verify_stream_hash(&mut file, alg, bhp)
    }

    pub fn verify_in_memory_hash(
        &self,
        data: &[u8],
        alg: Option<&str>,
        bhp: &dyn AssetBoxHash,
    ) -> Result<()> {
        let mut reader = Cursor::new(data);

        self.verify_stream_hash(&mut reader, alg, bhp)
    }

    pub fn verify_stream_hash(
        &self,
        reader: &mut dyn CAIRead,
        alg: Option<&str>,
        bhp: &dyn AssetBoxHash,
    ) -> Result<()> {
        // it is a failure if no hashes are listed
        if self.boxes.is_empty() {
            return Err(Error::HashMismatch("No box hash found".to_string()));
        }

        // get source box list
        let source_bms = bhp.get_box_map(reader)?;
        let mut source_index = 0;

        // check to see we source index starts at PNGh and skip if not included in the hash list
        if let Some(first_expected_bms) = source_bms.get(source_index) {
            if first_expected_bms.names[0] == "PNGh" && self.boxes[0].names[0] != "PNGh" {
                source_index += 1;
            }
        } else {
            return Err(Error::HashMismatch("No data boxes found".to_string()));
        }

        for bm in &self.boxes {
            let mut inclusions = Vec::new();

            // build up current inclusion, consuming all names in this BoxMap
            let mut skip_c2pa = false;
            let mut inclusion = HashRange::new(0, 0);
            for name in &bm.names {
                match source_bms.get(source_index) {
                    Some(next_source_bm) => {
                        if name == &next_source_bm.names[0] {
                            if inclusion.length() == 0 {
                                // this is a new item
                                inclusion.set_start(next_source_bm.range_start);
                                inclusion.set_length(next_source_bm.range_len);

                                if name == C2PA_BOXHASH {
                                    // there should only be 1 collapsed C2PA range
                                    if bm.names.len() != 1 {
                                        return Err(Error::HashMismatch(
                                            "Malformed C2PA box hash".to_owned(),
                                        ));
                                    }
                                    skip_c2pa = true;
                                }
                            } else {
                                // count any unknown data between named segments
                                let len_to_this_seg =
                                    next_source_bm.range_start - inclusion.start();
                                // update item
                                inclusion.set_length(len_to_this_seg + next_source_bm.range_len);
                            }
                        } else {
                            return Err(Error::HashMismatch(
                                "Box hash name out of order".to_owned(),
                            ));
                        }
                    }
                    None => return Err(Error::HashMismatch("Box hash name not found".to_owned())),
                }
                source_index += 1;
            }

            // C2PA chunks are skipped for hashing purposes
            if skip_c2pa {
                continue;
            }

            inclusions.push(inclusion);

            let curr_alg = match &bm.alg {
                Some(a) => a.clone(),
                None => match alg {
                    Some(a) => a.to_owned(),
                    None => return Err(Error::HashMismatch("No algorithm specified".to_string())),
                },
            };

            if !verify_stream_by_alg(&curr_alg, &bm.hash, reader, Some(inclusions), false) {
                return Err(Error::HashMismatch("Hashes do not match".to_owned()));
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn generate_box_hash_from_stream(
        &mut self,
        reader: &mut dyn CAIRead,
        alg: &str,
        bhp: &dyn AssetBoxHash,
        minimal_form: bool,
    ) -> Result<()> {
        // get source box list
        let source_bms = bhp.get_box_map(reader)?;

        if minimal_form {
            let mut before_c2pa = BoxMap {
                names: Vec::new(),
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 0,
            };

            let mut c2pa_box = BoxMap {
                names: Vec::new(),
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 0,
            };

            let mut after_c2pa = BoxMap {
                names: Vec::new(),
                alg: Some(alg.to_string()),
                hash: ByteBuf::from(vec![]),
                pad: ByteBuf::from(vec![]),
                range_start: 0,
                range_len: 0,
            };

            let mut is_before_c2pa = true;

            // collapse map list to minimal set
            for bm in source_bms.into_iter() {
                if bm.names[0] == "C2PA" {
                    // there should only be 1 collapsed C2PA range
                    if bm.names.len() != 1 {
                        return Err(Error::HashMismatch("Malformed C2PA box hash".to_owned()));
                    }

                    c2pa_box = bm;
                    is_before_c2pa = false;
                    continue;
                }

                if is_before_c2pa {
                    before_c2pa.names.extend(bm.names);
                    if before_c2pa.range_len == 0 {
                        before_c2pa.range_start = bm.range_start;
                        before_c2pa.range_len = bm.range_len;
                    } else {
                        before_c2pa.range_len += bm.range_len;
                    }
                } else {
                    after_c2pa.names.extend(bm.names);
                    if after_c2pa.range_len == 0 {
                        after_c2pa.range_start = bm.range_start;
                        after_c2pa.range_len = bm.range_len;
                    } else {
                        after_c2pa.range_len += bm.range_len;
                    }
                }
            }

            self.boxes = vec![before_c2pa, c2pa_box, after_c2pa];

            // compute the hashes
            for bm in self.boxes.iter_mut() {
                // skip c2pa box
                if bm.names[0] == C2PA_BOXHASH {
                    continue;
                }

                let mut inclusions = Vec::new();

                let inclusion = HashRange::new(bm.range_start, bm.range_len);
                inclusions.push(inclusion);

                bm.hash = ByteBuf::from(hash_stream_by_alg(alg, reader, Some(inclusions), false)?);
            }
        } else {
            for mut bm in source_bms {
                if bm.names[0] == "C2PA" {
                    // there should only be 1 collapsed C2PA range
                    if bm.names.len() != 1 {
                        return Err(Error::HashMismatch("Malformed C2PA box hash".to_owned()));
                    }
                    bm.hash = ByteBuf::from(vec![0]);
                    bm.pad = ByteBuf::from(vec![]);
                    self.boxes.push(bm);
                    continue;
                }

                // this is a new item
                let mut inclusions = Vec::new();

                let inclusion = HashRange::new(bm.range_start, bm.range_len);
                inclusions.push(inclusion);

                bm.alg = Some(alg.to_string());
                bm.hash = ByteBuf::from(hash_stream_by_alg(alg, reader, Some(inclusions), false)?);
                bm.pad = ByteBuf::from(vec![]);

                self.boxes.push(bm);
            }
        }

        Ok(())
    }
}

impl AssertionCbor for BoxHash {}

impl AssertionJson for BoxHash {}

impl AssertionBase for BoxHash {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    fn to_assertion(&self) -> crate::error::Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> crate::error::Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{jumbf_io::get_assetio_handler_from_path, utils::test::fixture_path};

    #[test]
    fn test_hash_verify_jpg() {
        let ap = fixture_path("CA.jpg");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, false)
            .unwrap();

        // see if they match reading
        bh.verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_hash_verify_jpg_reduced() {
        let ap = fixture_path("CA.jpg");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, true)
            .unwrap();

        // see if they match reading
        bh.verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_hash_verify_png() {
        let ap = fixture_path("libpng-test.png");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, false)
            .unwrap();

        // see if they match reading
        bh.verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_hash_verify_no_pngh() {
        let ap = fixture_path("libpng-test.png");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, false)
            .unwrap();

        bh.boxes.remove(0); // remove PNGh

        // see if they match reading
        bh.verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_json_round_trop() {
        let ap = fixture_path("CA.jpg");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, true)
            .unwrap();

        // save and reload JSON
        let bh_json_assertion = bh.to_json_assertion().unwrap();
        println!("Box hash json: {:?}", bh_json_assertion.decode_data());

        let reloaded_bh = BoxHash::from_json_assertion(&bh_json_assertion).unwrap();

        // see if they match reading
        reloaded_bh
            .verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }

    #[test]
    fn test_cbor_round_trop() {
        let ap = fixture_path("CA.jpg");

        let bhp = get_assetio_handler_from_path(&ap)
            .unwrap()
            .asset_box_hash_ref()
            .unwrap();

        let mut input = File::open(&ap).unwrap();

        let mut bh = BoxHash { boxes: Vec::new() };

        // generate box hashes
        bh.generate_box_hash_from_stream(&mut input, "sha256", bhp, true)
            .unwrap();

        // save and reload CBOR
        let bh_cbor_assertion = bh.to_cbor_assertion().unwrap();
        println!("Box hash cbor: {:?}", bh_cbor_assertion.decode_data());

        let reloaded_bh = BoxHash::from_cbor_assertion(&bh_cbor_assertion).unwrap();

        // see if they match reading
        reloaded_bh
            .verify_stream_hash(&mut input, Some("sha256"), bhp)
            .unwrap();
    }
}
