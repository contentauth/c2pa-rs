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

use std::{fs::File, io::Cursor, path::*};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    asset_io::{AssetBoxHash, CAIRead},
    error::{Error, Result},
    utils::hash_utils::{verify_stream_by_alg, HashRange},
};

const ASSERTION_CREATION_VERSION: usize = 1;

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
        // get source box list
        let source_bms = bhp.get_box_map(reader)?;
        let mut source_index = 0;

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

                                if name == "C2PA" {
                                    // there should only be 1 collapsed C2PA range
                                    if bm.names.len() != 1 {
                                        return Err(Error::HashMismatch(
                                            "Malformed C2PA box hash".to_owned(),
                                        ));
                                    }
                                    skip_c2pa = true;
                                }
                            } else {
                                // update item
                                inclusion.set_length(inclusion.length() + next_source_bm.range_len);
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
}

impl AssertionCbor for BoxHash {}

impl AssertionBase for BoxHash {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    // todo: this mechanism needs to change since a struct could support different versions

    fn to_assertion(&self) -> crate::error::Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> crate::error::Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}
