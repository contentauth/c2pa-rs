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

use hex_literal::hex;
use jumbf::parser::{DataBox, SuperBox};

use super::{AssertionStore, Claim};

const UUID: &[u8; 16] = &hex!("63326d61 0011 0010 8000 00aa00389b71");

/// On-demand parser for a single C2PA Manifest.
pub(crate) struct Manifest<'a> {
    /// Parsed child boxes of C2PA Manifest
    sbox: SuperBox<'a>,

    /// Raw JUMBF data
    #[allow(dead_code)]
    jumbf: &'a [u8],
}

impl<'a> Manifest<'a> {
    /// Parse the top level of the JUMBF box into a manifest.
    ///
    /// Does not recurse into the child boxes of this manifest. That is done
    /// on-demand when requested.
    ///
    /// Returns `None` if unable to parse as a manifest.
    pub(crate) fn from_data_box(data_box: &DataBox<'a>) -> Option<Self> {
        let (_, sbox) = SuperBox::from_data_box_with_depth_limit(data_box, 2).ok()?;

        // NOTE: For now, we do not support update manifests.
        if sbox.desc.uuid != UUID {
            return None;
        }

        Some(Self {
            sbox,
            jumbf: data_box.original,
        })
    }

    /// Returns the claim from this manifest.
    ///
    /// Returns `None` if no claim is found or unable to parse it as a claim.
    pub(crate) fn claim(&self) -> Option<Claim> {
        self.sbox
            .find_by_label(super::claim::LABEL)
            .and_then(Claim::from_super_box)
    }

    /// Returns the assertion store from this manifest.
    ///
    /// Returns `None` if no assertion store box is found.
    pub(crate) fn assertion_store(&'a self) -> Option<AssertionStore<'a>> {
        self.sbox
            .find_by_label(super::assertion_store::LABEL)
            .and_then(AssertionStore::from_super_box)
    }
}
