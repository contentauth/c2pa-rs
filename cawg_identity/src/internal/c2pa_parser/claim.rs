// Copyright 2024 Adobe. All rights reserved.
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

use std::fmt::Debug;

use hex_literal::hex;
use jumbf::parser::SuperBox;
use serde::Deserialize;

use crate::HashedUri;

pub(crate) const LABEL: &str = "c2pa.claim";
const UUID: &[u8; 16] = &hex!("6332636c 0011 0010 8000 00aa00389b71");

/// Partial parser for a single C2PA claim. Ignores some fields.
#[derive(Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct Claim {
    pub(crate) claim_generator: String,
    pub(crate) signature: String,
    pub(crate) assertions: Vec<HashedUri>,
    pub(crate) alg: Option<String>,

    #[serde(rename = "dc:format")]
    pub(crate) dc_format: Option<String>,

    #[serde(rename = "instanceID")]
    pub(crate) instance_id: String,

    #[serde(rename = "dc:title")]
    pub(crate) dc_title: Option<String>,
}

impl Claim {
    /// Parse the claim box from a C2PA Manifest.
    ///
    /// Returns `None` if unable to parse as a claim.
    pub(crate) fn from_super_box(sbox: &SuperBox<'_>) -> Option<Self> {
        // TO DO: Support C2PA v2 claims.

        // Enforced by Manifest find code.
        // if sbox.desc.label != Some(LABEL) {
        //     return None;
        // }

        if sbox.desc.uuid != UUID {
            return None;
        }

        let claim_dbox = sbox.data_box()?;
        if claim_dbox.tbox.0 != *b"cbor" {
            return None;
        }

        ciborium::from_reader(claim_dbox.data).ok()
    }
}
