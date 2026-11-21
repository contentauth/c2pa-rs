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

//! [`DataHash`] as a binding of an asset-io planned output: every byte except
//! the ranges the container excludes for the embedded manifest store.

use ::asset_io::Structure;

use super::DataHash;
use crate::{
    assertion::{Assertion, AssertionBase},
    assertions::asset_binding::{
        asset_io_error, normalize_ranges, AssetBinding, BindingKind, HashSpan, MaybeBinding,
        PlannedAsset,
    },
    claim::Claim,
    context::Context,
    error::{Error, Result},
    hash_utils::HashRange,
    utils::hash_utils::hash_size_by_alg,
};

/// The name a new data hash gives the manifest exclusion.
const NAME: &str = "jumbf manifest";

/// Padding reserved for the final exclusions' CBOR to grow into, as the legacy
/// save does.
const SLACK: usize = 10;

impl DataHash {
    /// How a data hash is found in a claim and chosen by default.
    pub(crate) const BINDING: BindingKind = BindingKind {
        from_claim,
        default_for,
    };

    /// A new data hash with `exclusions`, a zero hash of `alg`'s size and padding,
    /// so the assertion has its final size before the hash is known.
    pub(crate) fn placeholder(alg: &str, exclusions: Vec<HashRange>) -> Result<Self> {
        let mut hash = DataHash::new(NAME, alg);
        for exclusion in exclusions {
            hash.add_exclusion(exclusion);
        }
        hash.set_hash(vec![0; hash_size_by_alg(alg)?]);
        hash.add_padding(vec![0; SLACK]);
        Ok(hash)
    }

    fn resolved_alg(&self, default_alg: &str) -> String {
        self.alg.clone().unwrap_or_else(|| default_alg.to_owned())
    }
}

fn from_claim(claim: &Claim) -> MaybeBinding {
    let assertions = claim.data_hash_assertions();
    let Some(assertion) = assertions.first() else {
        return Ok(None);
    };
    let mut hash = DataHash::from_assertion(assertion.assertion())?;
    if hash.is_remote_hash() {
        return Err(Error::NotImplemented("remote data hash".into()));
    }
    if hash.pad.is_empty() && hash.pad2.is_none() {
        hash.add_padding(vec![0; SLACK]);
    }
    Ok(Some(Box::new(hash)))
}

/// The fallback: any asset can be bound by a data hash.
fn default_for(
    _structure: &Structure,
    _context: &Context,
    _claim: &Claim,
    alg: &str,
) -> MaybeBinding {
    Ok(Some(Box::new(DataHash::placeholder(alg, Vec::new())?)))
}

impl AssetBinding for DataHash {
    fn assertion(&self) -> Result<Assertion> {
        self.to_assertion()
    }

    fn check_structure(&self, _structure: &Structure) -> Result<()> {
        Ok(())
    }

    fn plan_hashes(
        &mut self,
        asset: &mut PlannedAsset<'_, '_>,
        default_alg: &str,
    ) -> Result<Vec<HashSpan>> {
        // Touching ranges (a store split across JPEG APP11 segments) are merged
        // into one exclusion, so their number does not depend on the store's size.
        let exclusions = match asset.store() {
            Some(store) => {
                let mut ranges = asset
                    .structure()
                    .c2pa_data_hash_exclusions(store)
                    .map_err(asset_io_error)?;
                normalize_ranges(&mut ranges)?;
                if ranges.is_empty() {
                    return Err(Error::EmbeddingError);
                }
                ranges
            }
            None => Vec::new(),
        };
        self.exclusions = (!exclusions.is_empty()).then(|| {
            exclusions
                .iter()
                .map(|range| HashRange::new(range.offset(), range.len()))
                .collect()
        });
        let alg = self.resolved_alg(default_alg);
        self.set_hash(vec![0; hash_size_by_alg(&alg)?]);
        Ok(vec![
            HashSpan::new(asset.full_range()?, &alg).excluding(exclusions)?
        ])
    }

    fn set_hashes(&mut self, digests: Vec<Vec<u8>>) {
        self.set_hash(digests.into_iter().next().unwrap_or_default());
    }

    fn fit_to_size(&mut self, len: usize) -> Result<()> {
        self.pad.clear();
        self.pad2 = None;
        self.pad_to_size(len)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::{Cursor, Seek};

    use super::*;

    #[test]
    fn placeholder_preserves_multiple_exclusions() {
        let exclusions = vec![HashRange::new(10, 10), HashRange::new(30, 10)];
        let mut hash = DataHash::placeholder("sha256", exclusions.clone()).unwrap();
        assert_eq!(hash.exclusions.as_ref(), Some(&exclusions));
        let mut input = Cursor::new(vec![0; 50]);
        hash.gen_hash_from_stream(&mut input).unwrap();
        input.rewind().unwrap();
        hash.verify_stream_hash(&mut input, Some("sha256")).unwrap();
        input.get_mut()[10] ^= 1;
        input.get_mut()[30] ^= 1;
        input.rewind().unwrap();
        hash.verify_stream_hash(&mut input, Some("sha256")).unwrap();
        input.get_mut()[25] ^= 1;
        input.rewind().unwrap();
        assert!(hash.verify_stream_hash(&mut input, Some("sha256")).is_err());
    }
}
