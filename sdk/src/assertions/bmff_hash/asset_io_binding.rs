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

use ::asset_io::{ByteRange, SegmentId, Structure};

use super::{BmffHash, ExclusionsMap, MerkleMap, SubsetMap, VecByteBuf};
use crate::{
    assertion::{Assertion, AssertionBase},
    assertions::asset_binding::{
        asset_io_error, is_computed, AssetBinding, BindingKind, HashSpan, LeafDigests, LeafPlan,
        MaybeBinding, PlannedAsset, SuppliedBinding,
    },
    claim::Claim,
    context::Context,
    error::{Error, Result},
    utils::{
        hash_utils::{hash_by_alg, hash_size_by_alg},
        merkle::{C2PAMerkleTree, MerkleNode},
    },
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
    // The deprecated `url` field is ignored (C2PA 2.5 §BMFF hash): a hash built
    // from this one is written without it, and a supplied one keeps its bytes.
    // As in `save_to_stream`, a BMFF hash the caller already computed is signed
    // as given, including one with Merkle maps: its proof boxes are already in
    // the asset. One without a hash only requests a binding.
    if hash.hash().is_some_and(|hash| is_computed(hash)) {
        return Ok(Some(Box::new(SuppliedBinding::new(
            assertion.assertion().clone(),
            true,
        ))));
    }
    // Merkle maps without their hash would need proofs only the caller can place.
    if hash.merkle().is_some() {
        return Err(Error::NotImplemented(
            "Merkle BMFF binding without a computed hash".into(),
        ));
    }
    Ok(Some(Box::new(hash)))
}

/// The default for ISO BMFF, with the settings' default exclusions, and Merkle trees
/// over the `mdat` media when the settings ask for them.
fn default_for(structure: &Structure, context: &Context, claim: &Claim, alg: &str) -> MaybeBinding {
    if !is_bmff(structure) {
        return Ok(None);
    }
    let settings = context.settings();
    let mut hash = BmffHash::new(NAME, alg, None);
    hash.set_default_exclusions_with_options(settings);
    if claim.version() < 2 {
        hash.set_bmff_version(2);
    }
    let binding: Box<dyn AssetBinding> = match settings.core.merkle_tree_chunk_size_in_kb {
        Some(chunk_size_kb) => MerkleBmffHash::bind(
            structure,
            hash,
            alg,
            chunk_size_kb,
            settings.core.merkle_tree_max_proofs,
        )?,
        None => Box::new(hash),
    };
    Ok(Some(binding))
}

/// The bytes of an `mdat` box that its Merkle tree leaves do not cover: the first
/// 16, whether its header is 8 bytes or 16 (C2PA 2.5 §BMFF hash exclusions).
const MDAT_EXCLUDED: u64 = 16;

/// The `mdat` boxes of `structure`, in file order.
fn mdat_boxes(structure: &Structure) -> Result<Vec<ByteRange>> {
    let mut boxes = Vec::new();
    for (index, segment) in structure.segments().iter().enumerate() {
        let id = SegmentId::from_index(index).map_err(asset_io_error)?;
        if structure.box_name(id, segment).as_deref() == Some("mdat") {
            boxes.push(segment.range());
        }
    }
    Ok(boxes)
}

/// A BMFF hash whose `mdat` media is covered by Merkle trees instead of the flat
/// hash, with the proofs written in boxes after the last `mdat`.
///
/// The `mdat` boxes are the same in the output as in the source, so the shape of
/// every tree, and the size of every Merkle map and proof box, follow from the
/// source's structure. The maps and the proof boxes get their final size before
/// anything is written; the leaves are hashed as the output is written and fill
/// them in.
struct MerkleBmffHash {
    hash: BmffHash,
    alg: String,
    /// The size of a leaf block in bytes; none when each `mdat` is one leaf.
    block: Option<u64>,
    max_proofs: usize,
    /// The number of leaves of each `mdat`.
    leaf_counts: Vec<usize>,
    /// The payload of each proof box, zeros until the leaves are known.
    proofs: Vec<Vec<u8>>,
}

impl MerkleBmffHash {
    /// `hash` with Merkle maps for the `mdat` boxes of `structure`, or `hash` as it
    /// is when there are none.
    fn bind(
        structure: &Structure,
        mut hash: BmffHash,
        alg: &str,
        chunk_size_kb: usize,
        max_proofs: usize,
    ) -> Result<Box<dyn AssetBinding>> {
        let mdats = mdat_boxes(structure)?;
        if mdats.is_empty() {
            return Ok(Box::new(hash));
        }
        let block = (chunk_size_kb > 0).then(|| 1024 * chunk_size_kb as u64);
        let mut mdat = ExclusionsMap::new("/mdat".to_owned());
        mdat.subset = Some(vec![SubsetMap {
            offset: MDAT_EXCLUDED,
            length: 0,
        }]);
        hash.add_exclusions(&mut vec![mdat]);

        let leaf_counts = mdats
            .iter()
            .map(|mdat| match block {
                Some(block) => {
                    usize::try_from(mdat.len().saturating_sub(MDAT_EXCLUDED).div_ceil(block))
                        .map_err(|_| Error::BadParam("too many Merkle leaves".into()))
                }
                None => Ok(1),
            })
            .collect::<Result<Vec<_>>>()?;
        let mut binding = Self {
            hash,
            alg: alg.to_owned(),
            block,
            max_proofs,
            leaf_counts,
            proofs: Vec::new(),
        };
        // The leaves of every `mdat` must fit the memory budget before any are made.
        for (index, &count) in binding.leaf_counts.iter().enumerate() {
            binding
                .hash
                .check_merkle_leaf_memory(count as u64, &binding.empty_map(index))?;
        }
        // Trees of the right shape over placeholder digests give the final sizes of
        // the Merkle maps and the proof boxes.
        let hash_len = hash_size_by_alg(alg)?;
        let placeholders = binding
            .leaf_counts
            .iter()
            .map(|&count| vec![vec![0; hash_len]; count])
            .collect();
        binding.fill(placeholders)?;
        for proof in &mut binding.proofs {
            proof.fill(0);
        }
        Ok(Box::new(binding))
    }

    /// The Merkle map of the `index`th `mdat`, before its leaves are known.
    fn empty_map(&self, index: usize) -> MerkleMap {
        MerkleMap {
            unique_id: 0,
            local_id: index,
            count: 0,
            alg: Some(self.alg.clone()),
            init_hash: None,
            hashes: VecByteBuf(Vec::new()),
            fixed_block_size: self.block,
            variable_block_sizes: None,
        }
    }

    /// Build the Merkle maps and proofs from the leaf digests of each `mdat`.
    fn fill(&mut self, leaves: LeafDigests) -> Result<()> {
        let mut maps = Vec::with_capacity(leaves.len());
        let mut proofs = Vec::new();
        for (index, digests) in leaves.into_iter().enumerate() {
            let mut map = self.empty_map(index);
            self.hash
                .check_merkle_leaf_memory(digests.len() as u64, &map)?;
            let tree = C2PAMerkleTree::from_leaves(
                digests.into_iter().map(MerkleNode).collect(),
                &self.alg,
                false,
            );
            proofs.extend(BmffHash::merkle_map_from_tree(
                &tree,
                &mut map,
                self.max_proofs,
            )?);
            maps.push(map);
        }
        // Once planned, the proof boxes keep their size.
        if !self.proofs.is_empty()
            && !self
                .proofs
                .iter()
                .map(Vec::len)
                .eq(proofs.iter().map(Vec::len))
        {
            return Err(Error::JumbfCreationError);
        }
        self.hash.set_merkle(maps);
        self.proofs = proofs;
        Ok(())
    }
}

impl AssetBinding for MerkleBmffHash {
    fn assertion(&self) -> Result<Assertion> {
        self.hash.to_assertion()
    }

    fn check_structure(&self, structure: &Structure) -> Result<()> {
        self.hash.check_structure(structure)
    }

    fn plan_hashes(
        &mut self,
        asset: &mut PlannedAsset<'_, '_>,
        default_alg: &str,
    ) -> Result<Vec<HashSpan>> {
        self.hash.plan_hashes(asset, default_alg)
    }

    fn set_hashes(&mut self, digests: Vec<Vec<u8>>) {
        self.hash.set_hashes(digests);
    }

    fn merkle_proofs(&self) -> Option<&[Vec<u8>]> {
        Some(&self.proofs)
    }

    fn plan_leaves(&mut self, asset: &PlannedAsset<'_, '_>) -> Result<Option<LeafPlan>> {
        let regions = mdat_boxes(asset.structure())?
            .into_iter()
            .map(|mdat| {
                let skipped = mdat.len().min(MDAT_EXCLUDED);
                ByteRange::new(mdat.offset() + skipped, mdat.len() - skipped)
                    .map_err(asset_io_error)
            })
            .collect::<Result<Vec<_>>>()?;
        if regions.len() != self.leaf_counts.len() {
            return Err(Error::JumbfCreationError);
        }
        Ok(Some(LeafPlan {
            regions,
            block: self.block.unwrap_or(u64::MAX),
            alg: self.alg.clone(),
        }))
    }

    fn set_leaves(&mut self, mut leaves: LeafDigests) -> Result<()> {
        if leaves.len() != self.leaf_counts.len() {
            return Err(Error::JumbfCreationError);
        }
        for (digests, &count) in leaves.iter_mut().zip(&self.leaf_counts) {
            // A box with no media is still one leaf when it is not split in blocks.
            if digests.is_empty() && self.block.is_none() {
                digests.push(hash_by_alg(&self.alg, &[], None));
            }
            if digests.len() != count {
                return Err(Error::JumbfCreationError);
            }
        }
        self.fill(leaves)
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
        let excluded = super::asset_io_parser::excluded(
            structure,
            asset.reader(),
            self.exclusions(),
            self.bmff_version() > 1,
        )?;
        Ok((excluded.ranges, excluded.offsets))
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
