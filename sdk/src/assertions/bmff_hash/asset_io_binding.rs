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

use ::asset_io::{ByteRange, Structure};

use super::BmffHash;
use crate::{
    assertion::{Assertion, AssertionBase},
    assertions::asset_binding::{AssetBinding, BindingKind, HashSpan, MaybeBinding, PlannedAsset},
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
