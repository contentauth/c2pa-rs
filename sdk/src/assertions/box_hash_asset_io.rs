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

//! [`BoxHash`] as a binding of an asset-io planned output: one hash per entry of
//! the box map, over the output's named boxes.

use ::asset_io::{ByteRange, Structure};

use super::{BoxHash, BoxMap};
use crate::{
    assertion::{Assertion, AssertionBase},
    assertions::asset_binding::{
        asset_io_error, AssetBinding, BindingKind, HashSpan, MaybeBinding, PlannedAsset,
    },
    asset_handlers::asset_io_adapter::box_map_from_structure,
    asset_io::C2PA_BOXHASH,
    claim::Claim,
    context::Context,
    error::{Error, Result},
    utils::hash_utils::hash_size_by_alg,
};

/// The name a box hash gives bytes past the end of the container's structure
/// (C2PA 18.7.2).
const AFTER_BOX: &str = "c2pa.after";

/// A named box of the output, with the metadata ranges a hash may exclude.
#[derive(Debug, Clone)]
pub(crate) struct OutputBox {
    pub name: String,
    pub range: ByteRange,
    pub metadata: Vec<ByteRange>,
}

impl BoxHash {
    /// How a box hash is found in a claim and chosen by default.
    pub(crate) const BINDING: BindingKind = BindingKind {
        from_claim,
        default_for,
    };

    /// Match the box map to the output's `boxes`, filling in each entry's range
    /// and a placeholder hash, and return a span per hashed entry. An empty map
    /// becomes one entry per box. Reads nothing.
    pub(crate) fn resolve(
        &mut self,
        boxes: &[OutputBox],
        default_alg: &str,
    ) -> Result<Vec<HashSpan>> {
        let mismatch =
            || Error::NotImplemented("requested box map does not match output boxes".into());
        if self.boxes.is_empty() {
            self.boxes = boxes
                .iter()
                .map(|b| BoxMap {
                    names: vec![b.name.clone()],
                    ..Default::default()
                })
                .collect();
        }
        let mut next = 0;
        let mut spans = Vec::new();
        for entry in &mut self.boxes {
            let end = next + entry.names.len();
            let named = boxes.get(next..end).ok_or_else(mismatch)?;
            if named.is_empty()
                || !entry
                    .names
                    .iter()
                    .zip(named)
                    .all(|(name, b)| name == &b.name)
            {
                return Err(mismatch());
            }
            let start = named[0].range.offset();
            let end_offset = named[named.len() - 1].range.end();
            entry.range_start = start;
            entry.range_len = end_offset - start;
            next = end;
            if entry.names != [C2PA_BOXHASH] && entry.names.iter().any(|n| n == C2PA_BOXHASH) {
                return Err(Error::NotImplemented(
                    "the C2PA box must be listed separately".into(),
                ));
            }
            if entry.exclusions.as_ref().is_some_and(Vec::is_empty) {
                return Err(Error::BadParam("box exclusions must not be empty".into()));
            }
            if entry.names == [C2PA_BOXHASH] || entry.excluded == Some(true) {
                entry.hash = Vec::new().into();
                continue;
            }
            let invalid_index = || Error::BadParam("invalid box exclusion index".into());
            let mut exclusions = Vec::new();
            for ex in entry.exclusions.iter().flatten() {
                let index = ex.box_index.unwrap_or(0);
                if index < 0 || (ex.box_index.is_none() && named.len() != 1) {
                    return Err(invalid_index());
                }
                let b = named.get(index as usize).ok_or_else(invalid_index)?;
                let offset = b
                    .range
                    .offset()
                    .checked_add(ex.start)
                    .ok_or_else(|| Error::BadParam("box exclusion offset overflow".into()))?;
                let range = ByteRange::new(offset, ex.length).map_err(asset_io_error)?;
                if !b.metadata.iter().any(|m| m.contains(&range)) {
                    return Err(Error::BadParam(
                        "box exclusion must be within asset metadata".into(),
                    ));
                }
                exclusions.push(range);
            }
            let alg = entry.alg.as_deref().unwrap_or(default_alg);
            entry.hash = vec![0; hash_size_by_alg(alg)?].into();
            let range = ByteRange::new(start, end_offset - start).map_err(asset_io_error)?;
            spans.push(HashSpan::new(range, alg).excluding(exclusions)?);
        }
        if next != boxes.len() {
            return Err(Error::NotImplemented(
                "requested box map does not cover output boxes".into(),
            ));
        }
        Ok(spans)
    }
}

fn from_claim(claim: &Claim) -> MaybeBinding {
    let assertions = claim.box_hash_assertions();
    Ok(match assertions.first() {
        Some(assertion) => Some(Box::new(BoxHash::from_assertion(assertion.assertion())?)),
        None => None,
    })
}

/// The default for a container made entirely of named boxes, except ISO BMFF,
/// whose binding C2PA defines separately.
fn default_for(
    structure: &Structure,
    _context: &Context,
    _claim: &Claim,
    _alg: &str,
) -> MaybeBinding {
    Ok((!is_bmff(structure) && structure.supports_named_boxes())
        .then(|| Box::new(BoxHash { boxes: Vec::new() }) as Box<dyn AssetBinding>))
}

fn is_bmff(structure: &Structure) -> bool {
    structure.container_id() == ::asset_io::containers::bmff::ID
}

/// The output's boxes, as the SDK's box map lists them (including its
/// established overlapping ranges for expanded elements).
fn output_boxes(asset: &PlannedAsset<'_, '_>) -> Result<Vec<OutputBox>> {
    let structure = asset.structure();
    let store = asset.store();
    // Fails for a structure that is not entirely named boxes.
    structure
        .complete_boxes(store.map(|item| (item, C2PA_BOXHASH)), AFTER_BOX)
        .map_err(asset_io_error)?;
    box_map_from_structure(structure, store)?
        .into_iter()
        .map(|map| {
            let name = map.names.first().ok_or(Error::EmbeddingError)?.clone();
            let range = ByteRange::new(map.range_start, map.range_len).map_err(asset_io_error)?;
            let metadata = map
                .allowed_exclusions
                .iter()
                .map(|ex| {
                    ByteRange::new(map.range_start + ex.start, ex.length).map_err(asset_io_error)
                })
                .collect::<Result<_>>()?;
            Ok(OutputBox {
                name,
                range,
                metadata,
            })
        })
        .collect()
}

impl AssetBinding for BoxHash {
    fn assertion(&self) -> Result<Assertion> {
        self.to_assertion()
    }

    fn check_structure(&self, structure: &Structure) -> Result<()> {
        if is_bmff(structure) {
            return Err(Error::NotImplemented(
                "BMFF requires the BMFF hard binding".into(),
            ));
        }
        Ok(())
    }

    fn plan_hashes(
        &mut self,
        asset: &mut PlannedAsset<'_, '_>,
        default_alg: &str,
    ) -> Result<Vec<HashSpan>> {
        let boxes = output_boxes(asset)?;
        self.resolve(&boxes, default_alg)
    }

    fn set_hashes(&mut self, digests: Vec<Vec<u8>>) {
        let mut digests = digests.into_iter();
        for entry in &mut self.boxes {
            if entry.names != [C2PA_BOXHASH] && entry.excluded != Some(true) {
                entry.hash = digests.next().unwrap_or_default().into();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::BoxExclusion;

    fn boxes() -> Vec<OutputBox> {
        let b = |name: &str, offset, len, metadata: &[(u64, u64)]| OutputBox {
            name: name.into(),
            range: ByteRange::new(offset, len).unwrap(),
            metadata: metadata
                .iter()
                .map(|&(o, l)| ByteRange::new(o, l).unwrap())
                .collect(),
        };
        vec![
            b("SOI", 0, 2, &[]),
            b("APP1", 2, 20, &[(6, 16)]),
            b(C2PA_BOXHASH, 22, 30, &[]),
            b("SOS", 52, 40, &[]),
            b("EOI", 92, 2, &[]),
        ]
    }

    #[test]
    fn an_empty_map_hashes_every_box_but_the_store() {
        let mut hash = BoxHash { boxes: Vec::new() };
        let spans = hash.resolve(&boxes(), "sha256").unwrap();
        assert_eq!(hash.boxes.len(), 5);
        assert_eq!(spans.len(), 4);
        assert!(hash.boxes[2].hash.is_empty());
        assert_eq!(spans[2].range, ByteRange::new(52, 40).unwrap());
    }

    #[test]
    fn grouped_entries_and_metadata_exclusions_resolve() {
        let mut hash = BoxHash {
            boxes: vec![
                BoxMap {
                    names: vec!["SOI".into(), "APP1".into()],
                    exclusions: Some(vec![BoxExclusion {
                        box_index: Some(1),
                        start: 4,
                        length: 16,
                    }]),
                    ..Default::default()
                },
                BoxMap {
                    names: vec![C2PA_BOXHASH.into()],
                    ..Default::default()
                },
                BoxMap {
                    names: vec!["SOS".into(), "EOI".into()],
                    alg: Some("sha512".into()),
                    ..Default::default()
                },
            ],
        };
        let spans = hash.resolve(&boxes(), "sha256").unwrap();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].range, ByteRange::new(0, 22).unwrap());
        assert_eq!(spans[0].exclusions, [ByteRange::new(6, 16).unwrap()]);
        assert_eq!(spans[1].alg, "sha512");
        assert_eq!(
            (hash.boxes[2].range_start, hash.boxes[2].range_len),
            (52, 42)
        );
    }

    #[test]
    fn mismatched_maps_and_bad_exclusions_are_rejected() {
        let reject = |boxes_map: Vec<BoxMap>| {
            BoxHash { boxes: boxes_map }
                .resolve(&boxes(), "sha256")
                .unwrap_err()
        };
        let map = |names: &[&str]| BoxMap {
            names: names.iter().map(|&n| n.into()).collect(),
            ..Default::default()
        };
        assert!(matches!(
            reject(vec![map(&["SOI"]), map(&["SOS"])]),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            reject(vec![map(&["SOI", "APP1", "C2PA", "SOS", "EOI"])]),
            Error::NotImplemented(_)
        ));
        assert!(matches!(
            reject(vec![map(&["SOI"]), map(&["APP1"])]),
            Error::NotImplemented(_)
        ));
        let mut outside = map(&["SOI", "APP1"]);
        outside.exclusions = Some(vec![BoxExclusion {
            box_index: Some(1),
            start: 0,
            length: 4,
        }]);
        assert!(matches!(reject(vec![outside]), Error::BadParam(_)));
    }
}
