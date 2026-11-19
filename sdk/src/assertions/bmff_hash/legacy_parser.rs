// Copyright 2026 Adobe. All rights reserved.
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

//! [`BmffHash`](super::BmffHash)'s view of an asset through the legacy BMFF
//! parser in `asset_handlers::bmff_io`. Used without the `unstable_asset_io` feature, and
//! by tests as the reference for the asset-io parser.

use std::io::{Read, Seek};

use super::{BmffLayout, BoxInfoLite};
use crate::{
    assertions::ExclusionsMap, asset_handlers::bmff_io, error::Result, utils::hash_utils::HashRange,
};

/// The asset's top-level boxes and C2PA Merkle proof boxes.
pub(crate) fn layout<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<BmffLayout> {
    let boxes = bmff_io::read_bmff_c2pa_boxes(reader)?;
    Ok(BmffLayout {
        box_infos: convert(boxes.box_infos),
        bmff_merkle: boxes.bmff_merkle,
        bmff_merkle_box_infos: convert(boxes.bmff_merkle_box_infos),
    })
}

/// The ranges `exclusions` exclude, then for a BMFF v2 hash a one-byte range at
/// each hashed top-level box carrying its offset.
pub(crate) fn exclusions<R: Read + Seek + ?Sized>(
    reader: &mut R,
    exclusions: &[ExclusionsMap],
    bmff_v2: bool,
) -> Result<Vec<HashRange>> {
    bmff_io::bmff_to_jumbf_exclusions(reader, exclusions, bmff_v2)
}

fn convert(boxes: Vec<bmff_io::BoxInfoLite>) -> Vec<BoxInfoLite> {
    boxes
        .into_iter()
        .map(|b| BoxInfoLite {
            path: b.path,
            offset: b.offset,
            size: b.size,
        })
        .collect()
}
