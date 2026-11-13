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

//! [`BmffHash`] as a binding of an asset-io planned output: the ISO BMFF box tree,
//! less the boxes its exclusion selectors match.

use std::io::{Read, Seek, SeekFrom};

use ::asset_io::{ByteRange, Structure};

use super::{BmffHash, ExclusionsMap};
use crate::{
    assertion::{Assertion, AssertionBase},
    assertions::asset_binding::{
        asset_io_error, AssetBinding, BindingKind, HashSpan, MaybeBinding, PlannedAsset,
    },
    claim::Claim,
    context::Context,
    error::{Error, Result},
    utils::hash_utils::hash_size_by_alg,
};

/// The name a new BMFF hash is given.
const NAME: &str = "jumbf manifest";

impl BmffHash {
    /// How a BMFF hash is found in a claim and chosen by default.
    pub(crate) const BINDING: BindingKind = BindingKind {
        from_claim,
        default_for,
    };
}

fn is_bmff(structure: &Structure) -> bool {
    structure.container_id() == ::asset_io::containers::bmff::ID
}

fn from_claim(claim: &Claim) -> MaybeBinding {
    let assertions = claim.bmff_hash_assertions();
    let Some(assertion) = assertions.first() else {
        return Ok(None);
    };
    let hash = BmffHash::from_assertion(assertion.assertion())?;
    if hash.is_remote_hash() || hash.merkle().is_some() {
        return Err(Error::NotImplemented(
            "remote or Merkle BMFF binding".into(),
        ));
    }
    Ok(Some(Box::new(hash)))
}

/// The default for ISO BMFF, with the settings' default exclusions.
fn default_for(structure: &Structure, context: &Context, claim: &Claim, alg: &str) -> MaybeBinding {
    if !is_bmff(structure) {
        return Ok(None);
    }
    if context
        .settings()
        .core
        .merkle_tree_chunk_size_in_kb
        .is_some()
    {
        return Err(Error::NotImplemented(
            "streaming BMFF Merkle generation".into(),
        ));
    }
    let mut hash = BmffHash::new(NAME, alg, None);
    hash.set_default_exclusions_with_options(context.settings());
    if claim.version() < 2 {
        hash.set_bmff_version(2);
    }
    Ok(Some(Box::new(hash)))
}

/// A box of the planned output, as an exclusion selector sees it.
struct BoxNode {
    path: String,
    range: ByteRange,
    version: Option<u8>,
    flags: Option<u32>,
    depth: u32,
}

impl ExclusionsMap {
    /// Whether this selector's version, flags and length match `node`.
    fn matches_header(&self, node: &BoxNode) -> bool {
        if self.xpath != node.path
            || self.length.is_some_and(|len| len != node.range.len())
            || self.version.zip(node.version).is_some_and(|(a, b)| a != b)
        {
            return false;
        }
        let Some(want) = &self.flags else {
            return true;
        };
        let mut bytes = [0; 4];
        if want.len() >= 3 {
            bytes[..3].copy_from_slice(&want[..3]);
        }
        let want = u32::from_be_bytes(bytes);
        !node.flags.is_some_and(|actual| {
            if self.exact.unwrap_or(true) {
                actual != want
            } else {
                (want | actual) != want
            }
        })
    }

    /// Whether this selector's data predicates hold for `node` in `output`, the
    /// bytes as they will be written (relocated offsets included).
    fn matches_data(
        &self,
        node: &BoxNode,
        output: &mut (impl Read + Seek),
        total: u64,
    ) -> Result<bool> {
        for data in self.data.iter().flatten() {
            let start = node
                .range
                .offset()
                .checked_add(data.offset)
                .ok_or_else(|| Error::BadParam("BMFF predicate offset overflow".into()))?;
            let end = start
                .checked_add(data.value.len() as u64)
                .ok_or_else(|| Error::BadParam("BMFF predicate length overflow".into()))?;
            if end > total {
                return Err(Error::BadParam("BMFF predicate past end of asset".into()));
            }
            output.seek(SeekFrom::Start(start))?;
            let mut actual = vec![0; data.value.len()];
            output.read_exact(&mut actual)?;
            if actual != data.value {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The ranges of `node` this selector excludes: its subsets, or all of it.
    fn excluded_ranges(&self, node: &BoxNode) -> Result<Vec<ByteRange>> {
        let Some(subsets) = &self.subset else {
            return Ok(vec![node.range]);
        };
        let mut ranges = Vec::new();
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
                ByteRange::new(node.range.offset() + subset.offset, len).map_err(asset_io_error)?,
            );
        }
        Ok(ranges)
    }
}

impl BmffHash {
    /// The ranges this hash excludes from `asset`, and the offsets of the
    /// top-level boxes it hashes (BMFF hash v2).
    fn planned_ranges(
        &self,
        asset: &mut PlannedAsset<'_, '_>,
    ) -> Result<(Vec<ByteRange>, Vec<u64>)> {
        let structure = asset.structure();
        let total = structure.total_size();
        let mut nodes = Vec::new();
        structure
            .walk(asset.reader(), |node| {
                nodes.push(BoxNode {
                    path: node.path.to_string(),
                    range: node.range,
                    version: node.version,
                    flags: node.flags,
                    depth: node.depth,
                });
                Ok(())
            })
            .map_err(asset_io_error)?;
        let mut offsets: Vec<u64> = nodes
            .iter()
            .filter(|n| n.depth == 1)
            .map(|n| n.range.offset())
            .collect();
        let mut ranges = Vec::new();
        for ex in self.exclusions() {
            if ex.xpath.contains('[') {
                return Err(Error::NotImplemented(
                    "indexed BMFF exclusion selectors".into(),
                ));
            }
            for node in &nodes {
                if !ex.matches_header(node) || !ex.matches_data(node, asset.reader(), total)? {
                    continue;
                }
                if ex.subset.is_none() {
                    offsets.retain(|offset| *offset != node.range.offset());
                }
                ranges.extend(ex.excluded_ranges(node)?);
            }
        }
        if self.bmff_version() < 2 {
            offsets.clear();
        }
        Ok((ranges, offsets))
    }
}

impl AssetBinding for BmffHash {
    fn assertion(&self) -> Result<Assertion> {
        self.to_assertion()
    }

    fn check_structure(&self, structure: &Structure) -> Result<()> {
        if !is_bmff(structure) {
            return Err(Error::NotImplemented(
                "BMFF binding requires a BMFF structure".into(),
            ));
        }
        Ok(())
    }

    fn plan_hashes(
        &mut self,
        asset: &mut PlannedAsset<'_, '_>,
        default_alg: &str,
    ) -> Result<Vec<HashSpan>> {
        let (exclusions, offsets) = self.planned_ranges(asset)?;
        let alg = self
            .alg()
            .cloned()
            .unwrap_or_else(|| default_alg.to_owned());
        self.set_hash(vec![0; hash_size_by_alg(&alg)?]);
        Ok(vec![HashSpan::new(asset.full_range()?, &alg)
            .excluding(exclusions)?
            .with_offsets(offsets)])
    }

    fn set_hashes(&mut self, digests: Vec<Vec<u8>>) {
        self.set_hash(digests.into_iter().next().unwrap_or_default());
    }
}
