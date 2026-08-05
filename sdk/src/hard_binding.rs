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

//! Generates a hard-binding assertion (`DataHash`, `BmffHash`, or `BoxHash`) directly from an
//! asset stream, for use with [`crate::ClaimBuilder::set_hard_binding`]/
//! [`crate::ClaimBuilder::update_hard_binding`].
//!
//! Unlike [`crate::Builder`]'s placeholder-based workflow, `HardBinding` never manages
//! placeholder embedding itself — the caller is expected to have already reserved space for,
//! and embedded, the manifest placeholder in the asset before generating the real hash from it.

use std::io::{Read, Seek};

use crate::{
    assertion::AssertionBase,
    assertions::{BmffHash, BoxHash, DataHash, ExclusionsMap, MerkleMap, SubsetMap},
    context::{Context, ProgressPhase},
    error::Result,
    hash_utils::hash_by_alg,
    jumbf_io,
    maybe_send_sync::MaybeSend,
    utils::merkle::MerkleAccumulator,
    HashRange, HashType,
};

/// The concrete hard-binding assertion produced by [`HardBinding::generate`].
#[derive(Debug)]
pub enum HardBindingAssertion {
    Data(DataHash),
    Bmff(BmffHash),
    Box(BoxHash),
}

impl HardBindingAssertion {
    /// Which kind of hard binding this is.
    pub fn hash_type(&self) -> HashType {
        match self {
            HardBindingAssertion::Data(_) => HashType::Data,
            HardBindingAssertion::Bmff(_) => HashType::Bmff,
            HardBindingAssertion::Box(_) => HashType::Box,
        }
    }

    /// The encoded byte length of this assertion's data, as it would be stored in the claim.
    ///
    /// Used by [`crate::ClaimBuilder::update_hard_binding`] to verify that a replacement
    /// binding doesn't change the claim's byte layout.
    pub fn byte_len(&self) -> Result<usize> {
        let assertion = match self {
            HardBindingAssertion::Data(dh) => dh.to_assertion()?,
            HardBindingAssertion::Bmff(bh) => bh.to_assertion()?,
            HardBindingAssertion::Box(bh) => bh.to_assertion()?,
        };
        Ok(assertion.data().len())
    }
}

impl From<DataHash> for HardBindingAssertion {
    fn from(value: DataHash) -> Self {
        Self::Data(value)
    }
}

impl From<BmffHash> for HardBindingAssertion {
    fn from(value: BmffHash) -> Self {
        Self::Bmff(value)
    }
}

impl From<BoxHash> for HardBindingAssertion {
    fn from(value: BoxHash) -> Self {
        Self::Box(value)
    }
}

/// Resolves which kind of hard binding a format uses, mirroring [`crate::Builder::hash_type`]
/// minus the "an explicit BoxHash assertion is already present" override (`HardBinding` has no
/// pre-existing claim state to check).
fn resolve_hash_type(format: &str, context: &Context) -> HashType {
    if jumbf_io::is_bmff_format(format) {
        return HashType::Bmff;
    }

    if context.settings().builder.prefer_box_hash {
        if let Some(handler) = jumbf_io::get_assetio_handler(format) {
            if handler.asset_box_hash_ref().is_some() {
                return HashType::Box;
            }
        }
    }

    HashType::Data
}

/// Computes a hard-binding assertion directly from an asset stream.
///
/// The caller is responsible for reserving space for, and embedding, the manifest placeholder
/// in the asset *before* calling [`HardBinding::generate`] — there is no placeholder step here,
/// unlike [`crate::Builder::placeholder`]/[`crate::Builder::update_hash_from_stream`].
pub struct HardBinding {
    format: String,
    hash_type: HashType,
    alg: String,
    exclusions: Vec<HashRange>,
    merkle: MerkleAccumulator,
}

impl HardBinding {
    /// Resolves the Data/Bmff/Box dispatch up front, using the same rules as
    /// [`crate::Builder::hash_type`] (BMFF formats always use `BmffHash`; otherwise `BoxHash`
    /// when `prefer_box_hash` is enabled and the format supports it; otherwise `DataHash`).
    pub fn new(format: &str, context: &Context) -> Self {
        Self {
            format: format.to_owned(),
            hash_type: resolve_hash_type(format, context),
            alg: "sha256".to_owned(),
            exclusions: Vec::new(),
            merkle: MerkleAccumulator::default(),
        }
    }

    /// Sets the hash algorithm (default `"sha256"`).
    pub fn set_alg(&mut self, alg: impl Into<String>) -> &mut Self {
        self.alg = alg.into();
        self
    }

    /// Sets the byte ranges to exclude when hashing — the region where the caller embedded the
    /// manifest placeholder. Only meaningful for the `DataHash` path: `BmffHash`/`BoxHash`
    /// derive their exclusions structurally instead.
    pub fn set_exclusions(&mut self, exclusions: Vec<HashRange>) -> &mut Self {
        self.exclusions = exclusions;
        self
    }

    /// Sets a fixed Merkle leaf size (in KB) for BMFF mdat hashing. Only meaningful for the
    /// `BmffHash` path. See [`crate::Builder::set_bmff_hash_fixed_leaf_size`].
    pub fn set_fixed_leaf_size(&mut self, leaf_size_in_kb: usize) -> &mut Self {
        self.merkle.set_fixed_size(leaf_size_in_kb);
        self
    }

    /// Hashes a chunk of mdat bytes as they're written, instead of re-reading the mdat content
    /// from the finished asset in [`HardBinding::generate`]. Only meaningful for the `BmffHash`
    /// path. See [`crate::Builder::hash_bmff_mdat_bytes`].
    pub fn hash_mdat_chunk(
        &mut self,
        mdat_id: usize,
        large_size: bool,
        data: &[u8],
    ) -> Result<&mut Self> {
        self.merkle.add_merkle_leaf(mdat_id, large_size, data)?;
        Ok(self)
    }

    /// Reads `stream` (the finished asset, with the manifest placeholder already embedded) and
    /// produces the hard-binding assertion.
    pub fn generate<R>(mut self, context: &Context, stream: &mut R) -> Result<HardBindingAssertion>
    where
        R: Read + Seek + MaybeSend,
    {
        match self.hash_type {
            HashType::Bmff => {
                self.merkle.alg = self.alg.clone();

                let mut bmff_hash = BmffHash::new("jumbf manifest", &self.alg, None);
                bmff_hash.set_default_exclusions();

                // Merge in any partially-filled fixed-size leaf remainders as the last leaf of
                // the Merkle leaves for that mdat_id (mirrors Builder::update_hash_from_stream).
                for (mdat_id, remainder) in &self.merkle.fixed_size_remainder {
                    let fragment_hash = hash_by_alg(self.merkle.alg.as_str(), remainder, None);
                    self.merkle
                        .merkle_leaves
                        .entry(*mdat_id)
                        .and_modify(|leaves| {
                            leaves.push((remainder.len() as u64, fragment_hash.clone()))
                        })
                        .or_insert(vec![(remainder.len() as u64, fragment_hash)]);
                }

                if !self.merkle.merkle_leaves.is_empty() {
                    let merkle_maps = MerkleMap::create_mms_from_mdat_leaves(
                        &self.merkle.alg,
                        &self.merkle.merkle_leaves,
                        self.merkle.fixed_size,
                    )?;

                    let mut mdat = ExclusionsMap::new("/mdat".to_owned());
                    mdat.subset = Some(vec![SubsetMap {
                        offset: 16,
                        length: 0,
                    }]);
                    bmff_hash.add_exclusions(&mut vec![mdat]);
                    bmff_hash.set_merkle(merkle_maps);
                }

                let mut cb =
                    |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
                bmff_hash.gen_hash_from_stream_with_progress(stream, &mut cb)?;

                Ok(HardBindingAssertion::Bmff(bmff_hash))
            }
            HashType::Box => {
                let handler = jumbf_io::get_assetio_handler(&self.format)
                    .ok_or(crate::Error::UnsupportedType)?;
                let bhp = handler.asset_box_hash_ref().ok_or_else(|| {
                    crate::Error::BadParam(format!(
                        "Format '{}' does not support BoxHash",
                        self.format
                    ))
                })?;

                let mut bh = BoxHash { boxes: Vec::new() };
                // minimal_form=false: hash each structural box independently rather than
                // summing ranges (see Builder::update_hash_from_stream for why).
                let cb: Box<dyn FnMut(u32, u32) -> Result<()>> = Box::new(|step, total| {
                    context.check_progress(ProgressPhase::Hashing, step, total)
                });
                bh.generate_box_hash_from_stream_with_progress(stream, &self.alg, bhp, false, cb)?;

                Ok(HardBindingAssertion::Box(bh))
            }
            HashType::Data => {
                let exclusion_arg = if self.exclusions.is_empty() {
                    None
                } else {
                    Some(self.exclusions.clone())
                };
                let mut cb =
                    |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
                let hash = crate::utils::hash_utils::hash_stream_by_alg_with_progress(
                    &self.alg,
                    stream,
                    exclusion_arg,
                    true,
                    &mut cb,
                )?;

                let mut dh = DataHash::new("jumbf manifest", &self.alg);
                for exclusion in self.exclusions {
                    dh.add_exclusion(exclusion);
                }
                dh.set_hash(hash);

                Ok(HardBindingAssertion::Data(dh))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use std::io::Cursor;

    use super::*;
    use crate::utils::test::test_context;

    const TEST_IMAGE_CLEAN: &[u8] = include_bytes!("../tests/fixtures/IMG_0003.jpg");

    #[test]
    fn test_hard_binding_dispatch_by_format() {
        let context = test_context();

        assert_eq!(
            HardBinding::new("image/jpeg", &context).hash_type,
            HashType::Data,
            "non-BMFF formats default to DataHash"
        );
        assert_eq!(
            HardBinding::new("video/mp4", &context).hash_type,
            HashType::Bmff,
            "BMFF formats always use BmffHash"
        );

        let pbh_context = Context::new()
            .with_settings(serde_json::json!({"builder": {"prefer_box_hash": true}}).to_string())
            .expect("valid settings");
        assert_eq!(
            HardBinding::new("image/jpeg", &pbh_context).hash_type,
            HashType::Box,
            "prefer_box_hash + a BoxHash-capable format should dispatch to BoxHash"
        );
    }

    #[test]
    fn test_hard_binding_generate_data_hash() {
        let context = test_context();
        let mut stream = Cursor::new(b"arbitrary asset bytes, not a real jpeg".to_vec());

        let binding = HardBinding::new("image/jpeg", &context)
            .generate(&context, &mut stream)
            .expect("generate DataHash");

        assert_eq!(binding.hash_type(), HashType::Data);
        match &binding {
            HardBindingAssertion::Data(dh) => {
                assert!(!dh.hash.is_empty(), "hash should be computed");
            }
            other => panic!("expected Data, got {other:?}"),
        }
        assert!(binding.byte_len().expect("byte_len") > 0);
    }

    #[test]
    fn test_hard_binding_generate_data_hash_with_exclusions() {
        let context = test_context();
        let mut stream = Cursor::new(vec![0u8; 100]);

        let mut hard_binding = HardBinding::new("image/jpeg", &context);
        hard_binding.set_exclusions(vec![HashRange::new(0, 10)]);
        let binding = hard_binding
            .generate(&context, &mut stream)
            .expect("generate DataHash with exclusions");

        match binding {
            HardBindingAssertion::Data(dh) => {
                assert_eq!(dh.exclusions.as_ref().map(|e| e.len()), Some(1));
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn test_hard_binding_generate_box_hash() {
        let pbh_context = Context::new()
            .with_settings(serde_json::json!({"builder": {"prefer_box_hash": true}}).to_string())
            .expect("valid settings");
        let mut stream = Cursor::new(TEST_IMAGE_CLEAN);

        let binding = HardBinding::new("image/jpeg", &pbh_context)
            .generate(&pbh_context, &mut stream)
            .expect("generate BoxHash");

        match binding {
            HardBindingAssertion::Box(bh) => {
                assert!(!bh.boxes.is_empty(), "BoxHash must have at least one box");
                assert!(
                    bh.boxes.iter().any(|bm| !bm.hash.is_empty()),
                    "at least one box should have a computed hash"
                );
            }
            other => panic!("expected Box, got {other:?}"),
        }
    }

    #[test]
    fn test_hard_binding_generate_bmff_hash() {
        let context = test_context();
        // A minimal-enough stream: BmffHash's own default exclusions/hashing don't require a
        // structurally valid BMFF file for this codepath (no mdat exclusions were registered).
        let mut stream = Cursor::new(vec![0u8; 64]);

        let binding = HardBinding::new("video/mp4", &context)
            .generate(&context, &mut stream)
            .expect("generate BmffHash");

        assert_eq!(binding.hash_type(), HashType::Bmff);
    }
}
