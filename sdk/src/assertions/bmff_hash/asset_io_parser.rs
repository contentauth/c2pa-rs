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

//! [`BmffHash`](super::BmffHash)'s view of an asset through asset-io: the box
//! tree from [`Structure::walk`], and the C2PA Merkle proof boxes from the
//! structure's items. Exclusion selectors are C2PA semantics and are evaluated
//! here for verification.

use std::io::{Read, Seek, SeekFrom};

use ::asset_io::{containers::bmff, labels::MERKLE, ByteRange, ItemKind, Name, Structure};

use super::{BmffLayout, BmffMerkleMap, BoxInfoLite};
use crate::{
    assertions::ExclusionsMap,
    error::{Error, Result},
    utils::hash_utils::HashRange,
};

fn asset_io_error(error: ::asset_io::Error) -> Error {
    match error {
        ::asset_io::Error::Io(error) => Error::IoError(error),
        ::asset_io::Error::UserCanceled => Error::OperationCancelled,
        ::asset_io::Error::Callback(error) => match error.downcast::<Error>() {
            Ok(error) => *error,
            Err(error) => Error::InvalidAsset(error.to_string()),
        },
        ::asset_io::Error::UnsupportedFormat => Error::UnsupportedType,
        ::asset_io::Error::UnsupportedFeature(feature) => {
            Error::NotImplemented(feature.to_string())
        }
        other => Error::InvalidAsset(other.to_string()),
    }
}

/// The asset's top-level boxes and C2PA Merkle proof boxes.
pub(crate) fn layout<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<BmffLayout> {
    let mut src = reader;
    let structure = parse(&mut src)?;
    let tree = BoxTree::walk(&structure, &mut src)?;
    let mut box_infos: Vec<BoxInfoLite> =
        tree.roots.iter().map(|&i| tree.nodes[i].info()).collect();
    box_infos.sort_by_key(|b| b.offset);

    let mut bmff_merkle = Vec::new();
    let mut bmff_merkle_box_infos = Vec::new();
    for item in structure.items_labelled(ItemKind::Other, MERKLE) {
        let payload = structure
            .read_item(&mut src, item)
            .map_err(asset_io_error)?;
        // Proof payloads are padded with zeros to one length; stop at the map.
        let mut deserializer = c2pa_cbor::de::Deserializer::from_slice(&payload);
        let map: BmffMerkleMap = serde::Deserialize::deserialize(&mut deserializer)?;
        bmff_merkle.push(map);
        let extent = item
            .extents()
            .next()
            .ok_or_else(|| Error::InvalidAsset("C2PA Merkle box has no payload".into()))?;
        let range = structure
            .segment(extent.segment())
            .map_err(asset_io_error)?
            .range();
        bmff_merkle_box_infos.push(BoxInfoLite {
            path: "uuid".to_owned(),
            offset: range.offset(),
            size: range.len(),
        });
    }
    Ok(BmffLayout {
        box_infos,
        bmff_merkle,
        bmff_merkle_box_infos,
    })
}

/// The ranges `exclusions` exclude, then for a BMFF v2 hash a one-byte range at
/// each hashed top-level box carrying its offset.
pub(crate) fn exclusions<R: Read + Seek + ?Sized>(
    reader: &mut R,
    exclusions: &[ExclusionsMap],
    bmff_v2: bool,
) -> Result<Vec<HashRange>> {
    let mut src = reader;
    let structure = parse(&mut src)?;
    let excluded = excluded(&structure, &mut src, exclusions, bmff_v2)?;
    let mut ranges: Vec<HashRange> = excluded
        .ranges
        .iter()
        .map(|r| HashRange::new(r.offset(), r.len()))
        .collect();
    for offset in excluded.offsets {
        let mut range = HashRange::new(offset, 1);
        range.set_bmff_offset(offset);
        ranges.push(range);
    }
    Ok(ranges)
}

/// What an exclusion list takes out of an asset's hash.
pub(crate) struct Excluded {
    /// Excluded bytes, by selector in list order, then boxes in file order.
    pub ranges: Vec<ByteRange>,
    /// Offsets of the hashed top-level boxes, ascending (BMFF hash v2 only).
    pub offsets: Vec<u64>,
}

/// Evaluate `exclusions` over `structure`, whose bytes `reader` reads: a parsed
/// asset or a planned output.
pub(crate) fn excluded<R: Read + Seek + ?Sized>(
    structure: &Structure,
    reader: &mut R,
    exclusions: &[ExclusionsMap],
    bmff_v2: bool,
) -> Result<Excluded> {
    let mut src = reader;
    let tree = BoxTree::walk(structure, &mut src)?;
    let total = structure.total_size();
    let mut offsets: Vec<u64> = tree
        .roots
        .iter()
        .map(|&i| tree.nodes[i].range.offset())
        .collect();
    offsets.sort_unstable();
    let mut ranges = Vec::new();
    for exclusion in exclusions {
        for index in tree.select(&exclusion.xpath).unwrap_or_default() {
            let node = &tree.nodes[index];
            if !matches_header(exclusion, node) || !matches_data(exclusion, node, &mut src, total)?
            {
                continue;
            }
            match &exclusion.subset {
                Some(subsets) => {
                    for subset in subsets {
                        if subset.offset > node.range.len() {
                            continue;
                        }
                        let available = node.range.len() - subset.offset;
                        let len = if subset.length == 0 {
                            available
                        } else {
                            available.min(subset.length)
                        };
                        ranges.push(
                            ByteRange::new(node.range.offset() + subset.offset, len)
                                .map_err(asset_io_error)?,
                        );
                    }
                }
                None => {
                    ranges.push(node.range);
                    // A box excluded whole contributes no offset to a v2 hash.
                    if let Some(i) = offsets.iter().position(|o| *o == node.range.offset()) {
                        offsets.remove(i);
                    }
                }
            }
        }
    }
    if !bmff_v2 {
        offsets.clear();
    }
    Ok(Excluded { ranges, offsets })
}

fn parse<R: Read + Seek + ?Sized>(reader: &mut &mut R) -> Result<Structure> {
    bmff::handler().parse(reader).map_err(asset_io_error)
}

/// A box met walking the asset.
struct BoxNode {
    /// The box type, as the legacy parser names it.
    name: String,
    range: ByteRange,
    version: Option<u8>,
    flags: Option<u32>,
    children: Vec<usize>,
}

impl BoxNode {
    fn info(&self) -> BoxInfoLite {
        BoxInfoLite {
            path: self.name.clone(),
            offset: self.range.offset(),
            size: self.range.len(),
        }
    }
}

/// The asset's box hierarchy, as [`Structure::walk`] reports it.
struct BoxTree {
    nodes: Vec<BoxNode>,
    roots: Vec<usize>,
}

impl BoxTree {
    fn walk<R: Read + Seek>(structure: &Structure, reader: &mut R) -> Result<Self> {
        let mut nodes: Vec<BoxNode> = Vec::new();
        let mut roots = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        structure
            .walk(reader, |node| {
                let depth = node.depth as usize;
                if depth == 0 || depth > stack.len() + 1 {
                    return Err(::asset_io::Error::UnsupportedFeature("BMFF box hierarchy"));
                }
                stack.truncate(depth - 1);
                let index = nodes.len();
                match stack.last() {
                    Some(&parent) => nodes[parent].children.push(index),
                    None => roots.push(index),
                }
                nodes.push(BoxNode {
                    name: match node.name {
                        Name::FourCC(cc) => String::from_utf8_lossy(&cc).into_owned(),
                        _ => String::new(),
                    },
                    range: node.range,
                    version: node.version,
                    flags: node.flags,
                    children: Vec::new(),
                });
                stack.push(index);
                Ok(())
            })
            .map_err(asset_io_error)?;
        Ok(Self { nodes, roots })
    }

    /// The boxes `xpath` selects, in file order: `/a/b` selects every `b` in
    /// every `a`, and `b[n]` the `n`th (from 1) of those `b`s. `None` for a
    /// malformed path, which selects nothing.
    fn select(&self, xpath: &str) -> Option<Vec<usize>> {
        let mut children = self.roots.clone();
        let mut current = Vec::new();
        for part in xpath.trim_start_matches('/').split('/') {
            if part.len() < 4 {
                return None;
            }
            if children.is_empty() {
                return Some(Vec::new());
            }
            let named = |name: &str, children: Vec<usize>| -> Vec<usize> {
                children
                    .into_iter()
                    .filter(|&c| self.nodes[c].name == name)
                    .collect()
            };
            if part.contains('[') {
                let mut pieces = part.split('[');
                let name = pieces.next()?;
                let index = pieces
                    .next()
                    .and_then(|s| s.trim_end_matches(']').parse::<usize>().ok())?;
                if name.len() < 4 || index == 0 {
                    return None;
                }
                let Some(&child) = named(name, children).get(index - 1) else {
                    return Some(Vec::new());
                };
                current = vec![child];
                children = self.nodes[child].children.clone();
            } else {
                current = named(part, children);
                children = current
                    .iter()
                    .flat_map(|&c| self.nodes[c].children.iter().copied())
                    .collect();
            }
        }
        Some(current)
    }
}

/// Whether `exclusion`'s length, version and flags match `node`. A version or
/// flags test passes for a box without them.
fn matches_header(exclusion: &ExclusionsMap, node: &BoxNode) -> bool {
    if exclusion.length.is_some_and(|len| len != node.range.len())
        || exclusion
            .version
            .zip(node.version)
            .is_some_and(|(want, actual)| want != actual)
    {
        return false;
    }
    let Some(want) = &exclusion.flags else {
        return true;
    };
    let mut bytes = [0; 4];
    if want.len() >= 3 {
        bytes[..3].copy_from_slice(&want[..3]);
    }
    let want = u32::from_be_bytes(bytes);
    !node.flags.is_some_and(|actual| {
        if exclusion.exact.unwrap_or(true) {
            actual != want
        } else {
            (want | actual) != want
        }
    })
}

/// Whether `exclusion`'s data predicates hold for `node`'s bytes.
fn matches_data<R: Read + Seek + ?Sized>(
    exclusion: &ExclusionsMap,
    node: &BoxNode,
    reader: &mut R,
    total: u64,
) -> Result<bool> {
    for data in exclusion.data.iter().flatten() {
        let start = node
            .range
            .offset()
            .checked_add(data.offset)
            .ok_or_else(|| Error::InvalidAsset("BMFF data map offset overflow".into()))?;
        let end = start
            .checked_add(data.value.len() as u64)
            .ok_or_else(|| Error::InvalidAsset("BMFF data map length overflow".into()))?;
        if end > total {
            return Err(Error::InvalidAsset(
                "BMFF data map past end of asset".into(),
            ));
        }
        reader.seek(SeekFrom::Start(start))?;
        let mut actual = vec![0; data.value.len()];
        reader.read_exact(&mut actual)?;
        if actual != data.value {
            return Ok(false);
        }
    }
    Ok(true)
}
