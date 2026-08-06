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
//! asset stream, for [`crate::ClaimBuilder`]'s hard-binding [`crate::ClaimAssertion`] labels.
//!
//! The caller is expected to have already reserved space for, and embedded, the manifest
//! placeholder in the asset before generating the real hash from it — there is no placeholder
//! management here, unlike [`crate::Builder`]'s workflow.

use crate::{
    assertions::{BmffHash, BoxHash, DataHash},
    asset_io::{CAIRead, CAIReadWrapper},
    context::{Context, ProgressPhase},
    error::Result,
    jumbf_io, HashRange, HashType,
};

/// The concrete hard-binding assertion produced by [`generate_hard_binding`].
#[derive(Debug)]
pub(crate) enum HardBindingAssertion {
    Data(DataHash),
    Bmff(BmffHash),
    Box(BoxHash),
}

impl HardBindingAssertion {
    /// Which kind of hard binding this is.
    pub(crate) fn hash_type(&self) -> HashType {
        match self {
            HardBindingAssertion::Data(_) => HashType::Data,
            HardBindingAssertion::Bmff(_) => HashType::Bmff,
            HardBindingAssertion::Box(_) => HashType::Box,
        }
    }
}

/// Fixed hash algorithm used for hard-binding generation (independent of
/// `ClaimBuilder::set_hash_alg`, which only affects the claim's own default).
const HARD_BINDING_ALG: &str = "sha256";

/// Reads `stream` (the finished asset, with the manifest placeholder already embedded) and
/// computes the hard-binding assertion of `hash_type`. `exclusions` is only meaningful for
/// `HashType::Data` — the region where the caller embedded the manifest placeholder.
pub(crate) fn generate_hard_binding(
    hash_type: HashType,
    format: &str,
    exclusions: Vec<HashRange>,
    context: &Context,
    stream: &mut dyn CAIRead,
) -> Result<HardBindingAssertion> {
    match hash_type {
        HashType::Bmff => {
            let mut bmff_hash = BmffHash::new("jumbf manifest", HARD_BINDING_ALG, None);
            bmff_hash.set_default_exclusions();

            let mut cb = |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
            bmff_hash.gen_hash_from_stream_with_progress(stream, &mut cb)?;

            Ok(HardBindingAssertion::Bmff(bmff_hash))
        }
        HashType::Box => {
            let handler =
                jumbf_io::get_assetio_handler(format).ok_or(crate::Error::UnsupportedType)?;
            let bhp = handler.asset_box_hash_ref().ok_or_else(|| {
                crate::Error::BadParam(format!("Format '{format}' does not support BoxHash"))
            })?;

            let mut bh = BoxHash { boxes: Vec::new() };
            // minimal_form=false: hash each structural box independently rather than summing
            // ranges (see Builder::update_hash_from_stream for why).
            let cb: Box<dyn FnMut(u32, u32) -> Result<()>> =
                Box::new(|step, total| context.check_progress(ProgressPhase::Hashing, step, total));
            // generate_box_hash_from_stream_with_progress requires a Sized stream type;
            // CAIReadWrapper gives `dyn CAIRead` a concrete Sized wrapper to satisfy that.
            let mut wrapper = CAIReadWrapper { reader: stream };
            bh.generate_box_hash_from_stream_with_progress(
                &mut wrapper,
                HARD_BINDING_ALG,
                bhp,
                false,
                cb,
            )?;

            Ok(HardBindingAssertion::Box(bh))
        }
        HashType::Data => {
            let exclusion_arg = if exclusions.is_empty() {
                None
            } else {
                Some(exclusions.clone())
            };
            let mut cb = |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
            let hash = crate::utils::hash_utils::hash_stream_by_alg_with_progress(
                HARD_BINDING_ALG,
                stream,
                exclusion_arg,
                true,
                &mut cb,
            )?;

            let mut dh = DataHash::new("jumbf manifest", HARD_BINDING_ALG);
            for exclusion in exclusions {
                dh.add_exclusion(exclusion);
            }
            dh.set_hash(hash);

            Ok(HardBindingAssertion::Data(dh))
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
    fn test_generate_hard_binding_data_hash() {
        let context = test_context();
        let mut stream = Cursor::new(b"arbitrary asset bytes, not a real jpeg".to_vec());

        let binding =
            generate_hard_binding(HashType::Data, "image/jpeg", vec![], &context, &mut stream)
                .expect("generate DataHash");

        assert_eq!(binding.hash_type(), HashType::Data);
        match &binding {
            HardBindingAssertion::Data(dh) => {
                assert!(!dh.hash.is_empty(), "hash should be computed");
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn test_generate_hard_binding_data_hash_with_exclusions() {
        let context = test_context();
        let mut stream = Cursor::new(vec![0u8; 100]);

        let binding = generate_hard_binding(
            HashType::Data,
            "image/jpeg",
            vec![HashRange::new(0, 10)],
            &context,
            &mut stream,
        )
        .expect("generate DataHash with exclusions");

        match binding {
            HardBindingAssertion::Data(dh) => {
                assert_eq!(dh.exclusions.as_ref().map(|e| e.len()), Some(1));
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[test]
    fn test_generate_hard_binding_box_hash() {
        let context = test_context();
        let mut stream = Cursor::new(TEST_IMAGE_CLEAN);

        let binding =
            generate_hard_binding(HashType::Box, "image/jpeg", vec![], &context, &mut stream)
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
    fn test_generate_hard_binding_bmff_hash() {
        let context = test_context();
        // A minimal-enough stream: BmffHash's own default exclusions/hashing don't require a
        // structurally valid BMFF file for this codepath (no mdat exclusions were registered).
        let mut stream = Cursor::new(vec![0u8; 64]);

        let binding =
            generate_hard_binding(HashType::Bmff, "video/mp4", vec![], &context, &mut stream)
                .expect("generate BmffHash");

        assert_eq!(binding.hash_type(), HashType::Bmff);
    }
}
