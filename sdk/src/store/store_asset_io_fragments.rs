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

//! Signing fragmented ISO BMFF assets, init segments with their fragment files,
//! through asset-io.
//!
//! Each fragment is a leaf of a Merkle tree, and carries the proof of its own
//! leaf in a `merkle` box immediately before its `moof` (C2PA 2.5 A.5.3). The
//! proofs depend on every fragment, so, as with the Merkle trees of a flat file,
//! the boxes are written as zeros of their final size while each fragment is
//! hashed in the same pass, and filled in once the tree is known. The manifest,
//! which holds the tree's row and the hash of every init segment, is written into
//! each init segment the same way: at its final size, to be patched once signed.

use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
};

use ::asset_io::{
    container_api::ContainerHandler, containers::bmff::BmffUpdates, labels::MERKLE, ItemKind,
    SegmentId, Structure, Updates,
};
use serde_bytes::ByteBuf;

use super::{
    store_asset_io::{open_structure, patch_merkle, patch_store, plan_write, write_plan},
    Store,
};
use crate::{
    assertion::AssertionBase,
    assertions::{
        asset_binding::{asset_io_error, PlannedAsset, SpanHasher},
        BmffHash, MerkleMap, VecByteBuf,
    },
    asset_io::{ReadSeek, ReadWriteSeek},
    context::{Context, ProgressPhase},
    error::{Error, Result},
    utils::{
        hash_utils::hash_size_by_alg,
        merkle::{C2PAMerkleTree, MerkleNode},
    },
    Signer,
};

/// An init segment, the directory its output goes in, and the identifiers of the
/// Merkle tree of its fragments.
struct Rendition {
    handler: Arc<dyn ContainerHandler>,
    init: PathBuf,
    dir: PathBuf,
    id: usize,
}

/// The number of boxes of `structure` named `name`.
fn count_boxes(structure: &Structure, name: &str) -> Result<usize> {
    let mut count = 0;
    for (index, segment) in structure.segments().iter().enumerate() {
        let id = SegmentId::from_index(index).map_err(asset_io_error)?;
        if structure.box_name(id, segment).as_deref() == Some(name) {
            count += 1;
        }
    }
    Ok(count)
}

/// The file name of `path`.
fn file_name(path: &Path) -> Result<&std::ffi::OsStr> {
    path.file_name()
        .ok_or_else(|| Error::BadParam(format!("{} has no file name", path.display())))
}

/// A new file at `path`, which must not exist.
fn create_new(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?)
}

/// Write `source`, whose structure is `structure`, to `dest` with `updates`, and
/// return the digest of what `hash` covers of the output, hashed as it is written.
fn write_hashed(
    structure: &Structure,
    source: &mut dyn ReadSeek,
    dest: &mut dyn ReadWriteSeek,
    updates: &Updates,
    hash: &BmffHash,
    alg: &str,
    context: &Context,
) -> Result<Vec<u8>> {
    let plan = plan_write(structure, &mut *source, updates)?;
    let span = {
        let mut planned = PlannedAsset::new(&plan, &mut *source)?;
        hash.plan_span(&mut planned, alg)?
    };
    let hasher = write_plan(
        &plan,
        source,
        dest,
        SpanHasher::new(vec![span])?,
        ProgressPhase::Hashing,
        context,
    )?;
    hasher.finish().pop().ok_or(Error::JumbfCreationError)
}

/// The fragment files of the init segment in `init_dir` that `fragment_glob` names.
fn fragments_of(init_dir: &Path, fragment_glob: &Path) -> Result<Vec<PathBuf>> {
    let pattern = init_dir.join(fragment_glob);
    let pattern = pattern
        .to_str()
        .ok_or_else(|| Error::BadParam("glob pattern is not valid".to_string()))?;
    glob::glob(pattern)
        .map_err(|e| Error::BadParam(format!("glob pattern is not valid: {e}")))?
        .map(|entry| {
            entry.map_err(|e| Error::BadParam(format!("error processing glob pattern: {e}")))
        })
        .collect()
}

/// Write each of `fragments` to `out_dir` with a `merkle` box in front of its
/// `moof`, as the leaves of one Merkle tree. Returns the tree's Merkle map, with
/// no init hash yet.
#[allow(clippy::too_many_arguments)]
fn write_fragments(
    handler: &Arc<dyn ContainerHandler>,
    fragments: &[PathBuf],
    out_dir: &Path,
    bmff_hash: &BmffHash,
    alg: &str,
    id: usize,
    max_proofs: usize,
    context: &Context,
) -> Result<MerkleMap> {
    if fragments.is_empty() {
        return Err(Error::BadParam(
            "at least one fragment path must be provided".to_string(),
        ));
    }
    // A tree of the right shape sizes the proof boxes, which are zeros until every
    // fragment is hashed.
    let dummy = C2PAMerkleTree::dummy_tree(fragments.len(), alg);
    let mut leaves = Vec::with_capacity(fragments.len());
    let mut written = Vec::with_capacity(fragments.len());
    for (location, fragment) in fragments.iter().enumerate() {
        let mut source = File::open(fragment)?;
        let structure = open_structure(Arc::clone(handler), &mut source)?;
        if count_boxes(&structure, "moof")? != 1 {
            return Err(Error::BadParam("expected 1 moof in fragment".to_string()));
        }
        if count_boxes(&structure, "mdat")? != 1 {
            return Err(Error::BadParam("expected 1 mdat in fragment".to_string()));
        }
        // Fragments that already have a manifest are not supported.
        if structure
            .items_labelled(ItemKind::Other, MERKLE)
            .next()
            .is_some()
        {
            return Err(Error::BadParam(
                "fragment already contains BmffMerkeMap".to_string(),
            ));
        }
        let size = BmffHash::merkle_proof_payload(&dummy, id, id, location, max_proofs)?.len();
        let dest_path = out_dir.join(file_name(fragment)?);
        let mut dest = create_new(&dest_path)?;
        let digest = write_hashed(
            &structure,
            &mut source,
            &mut dest,
            &Updates::new().set_merkle(vec![vec![0; size]]),
            bmff_hash,
            alg,
            context,
        )?;
        leaves.push(MerkleNode(digest));
        written.push((dest_path, size));
    }

    let tree = C2PAMerkleTree::from_leaves(leaves, alg, false);
    for (location, (path, size)) in written.iter().enumerate() {
        let proof = BmffHash::merkle_proof_payload(&tree, id, id, location, max_proofs)?;
        if proof.len() != *size {
            return Err(Error::JumbfCreationError);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let structure = open_structure(Arc::clone(handler), &mut file)?;
        patch_merkle(&structure, &mut file, &[proof])?;
    }

    let mut map = MerkleMap {
        unique_id: id,
        local_id: id,
        count: 0,
        alg: Some(alg.to_owned()),
        // The init segment's hash is known once its manifest is in it.
        init_hash: Some(ByteBuf::from(vec![0u8; hash_size_by_alg(alg)?])),
        hashes: VecByteBuf(Vec::new()),
        fixed_block_size: None,
        variable_block_sizes: None,
    };
    BmffHash::store_merkle_row(&tree, &mut map, max_proofs);
    Ok(map)
}

impl Store {
    /// Sign fragmented renditions: for each init segment in `init_paths`, the
    /// fragment files in its directory that `fragment_glob` names. Writes the init
    /// segment and its fragments to a directory of the same name in `output_path`,
    /// each fragment with a Merkle proof box and every init segment with the one
    /// manifest.
    pub(crate) fn sign_fragmented_asset_io<P: AsRef<Path>>(
        &mut self,
        init_paths: &[PathBuf],
        fragment_glob: P,
        output_path: P,
        signer: &dyn Signer,
        context: &Context,
    ) -> Result<()> {
        if init_paths.is_empty() {
            return Err(Error::BadParam(
                "at least one init segment path must be provided".to_string(),
            ));
        }
        let output_path = output_path.as_ref();
        if output_path.is_file() {
            return Err(Error::BadParam("output_path must be a folder".to_string()));
        }
        if !output_path.exists() {
            std::fs::create_dir_all(output_path).map_err(|e| {
                Error::BadParam(format!(
                    "failed to create output directory for fragments: {e}"
                ))
            })?;
        }

        // Add dynamic assertion placeholders, to be filled in just before signing.
        let dynamic_assertions = signer.dynamic_assertions();
        if !dynamic_assertions.is_empty() {
            self.add_dynamic_assertion_placeholders(&dynamic_assertions)?;
        }

        let max_proofs = context.settings().core.merkle_tree_max_proofs;
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.clear_data(); // the claim is reused
                         // The manifest is written before it is signed, so its size must not change.
        pc.set_compressed_manifest(false);
        let alg = pc.alg().to_owned();
        let (mut bmff_hash, existing) = match pc.bmff_hash_assertions().first() {
            Some(assertion) => (BmffHash::from_assertion(assertion.assertion())?, true),
            None => {
                let mut hash = BmffHash::new("jumbf manifest", &alg, None);
                hash.set_default_exclusions_with_options(context.settings());
                if pc.version() < 2 {
                    hash.set_bmff_version(2); // backcompat support
                }
                (hash, false)
            }
        };
        bmff_hash.clear_hash(); // a Merkle tree of fragments replaces the hash

        // Every fragment, as a leaf of the tree of its rendition.
        let mut renditions = Vec::with_capacity(init_paths.len());
        for (index, init) in init_paths.iter().enumerate() {
            let handler = context
                .io()
                .supported_extension(init)
                .filter(|ext| context.io().is_bmff_format(ext))
                .and_then(|ext| context.io().container_handler(&ext))
                .ok_or(Error::UnsupportedType)?;
            let init_dir = init.parent().ok_or_else(|| {
                Error::BadParam("failed to get parent directory for init segment".to_string())
            })?;
            let dir = output_path.join(file_name(init_dir)?);
            std::fs::create_dir_all(&dir)?;
            let id = index + 1;
            let map = write_fragments(
                &handler,
                &fragments_of(init_dir, fragment_glob.as_ref())?,
                &dir,
                &bmff_hash,
                &alg,
                id,
                max_proofs,
                context,
            )?;
            bmff_hash.merkle.get_or_insert_default().push(map);
            renditions.push(Rendition {
                handler,
                init: init.clone(),
                dir,
                id,
            });
        }

        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        if existing {
            pc.replace_assertion(bmff_hash.to_assertion()?)?;
        } else {
            pc.add_assertion(&bmff_hash)?;
        }

        // The manifest goes into each init segment, as it will be signed but for the
        // signature, and the hash of each init segment then completes the tree's map.
        let unsigned = self.to_jumbf_internal(signer.reserve_size())?;
        let mut outputs = Vec::with_capacity(renditions.len());
        for rendition in &renditions {
            let mut source = File::open(&rendition.init)?;
            let structure = open_structure(Arc::clone(&rendition.handler), &mut source)?;
            let dest_path = rendition.dir.join(file_name(&rendition.init)?);
            let mut dest = create_new(&dest_path)?;
            let digest = write_hashed(
                &structure,
                &mut source,
                &mut dest,
                &Updates::new().set_c2pa(unsigned.clone()),
                &bmff_hash,
                &alg,
                context,
            )?;
            bmff_hash
                .merkle
                .as_mut()
                .and_then(|maps| maps.iter_mut().find(|map| map.unique_id == rendition.id))
                .ok_or(Error::NotFound)?
                .init_hash = Some(ByteBuf::from(digest));
            outputs.push((rendition.handler.clone(), dest_path));
        }
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.replace_assertion(bmff_hash.to_assertion()?)?;

        let signed =
            self.sign_for_save(signer, &dynamic_assertions, context, Some(unsigned.len()))?;
        for (handler, path) in outputs {
            let mut file = OpenOptions::new().read(true).write(true).open(path)?;
            let structure = open_structure(handler, &mut file)?;
            patch_store(&structure, &mut file, &signed)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Seek;

    use super::*;
    use crate::{
        assertions::labels,
        status_tracker::StatusTracker,
        utils::{
            io_utils::tempdirectory,
            test::{create_test_claim, fixture_path},
            test_signer::test_cawg_signer,
        },
        SigningAlg,
    };

    fn inits() -> Vec<PathBuf> {
        glob::glob(&fixture_path("bunny/**/BigBuckBunny_2s_init.mp4").to_string_lossy())
            .unwrap()
            .flatten()
            .collect()
    }

    fn fragment_glob() -> PathBuf {
        PathBuf::from("BigBuckBunny_2s*.m4s")
    }

    fn store(context: &Context) -> Store {
        let mut store = Store::from_context(context);
        store.commit_claim(create_test_claim().unwrap()).unwrap();
        store
    }

    /// The Merkle maps of the store's BMFF hash, as they are written.
    fn maps(store: &Store) -> Vec<u8> {
        let hash = BmffHash::from_assertion(
            store.provenance_claim().unwrap().bmff_hash_assertions()[0].assertion(),
        )
        .unwrap();
        c2pa_cbor::to_vec(hash.merkle().unwrap()).unwrap()
    }

    /// The files of `dir`, with the directory of each rendition, by relative path.
    fn files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        for rendition in std::fs::read_dir(dir).unwrap().flatten() {
            for file in std::fs::read_dir(rendition.path()).unwrap().flatten() {
                files.push(file.path().strip_prefix(dir).unwrap().to_owned());
            }
        }
        files.sort();
        files
    }

    /// Fragments signed through asset-io are those the legacy code writes, bit for
    /// bit, with the same Merkle maps, and validate singly and together.
    #[test]
    fn fragments_match_the_legacy_signing_and_validate() {
        let context = Context::new();
        let signer = test_cawg_signer(SigningAlg::Ps256, &[labels::SCHEMA_ORG_INTERNAL]).unwrap();
        let inits = inits();
        let legacy_dir = tempdirectory().unwrap();
        let direct_dir = tempdirectory().unwrap();

        let mut legacy = store(&context);
        legacy
            .save_to_bmff_fragmented(
                &inits,
                &fragment_glob(),
                &legacy_dir.path().to_path_buf(),
                signer.as_ref(),
                &context,
            )
            .unwrap();
        let mut direct = store(&context);
        direct
            .sign_fragmented_asset_io(
                &inits,
                &fragment_glob(),
                &direct_dir.path().to_path_buf(),
                signer.as_ref(),
                &context,
            )
            .unwrap();

        assert_eq!(maps(&direct), maps(&legacy));
        let written = files(direct_dir.path());
        assert_eq!(written, files(legacy_dir.path()));
        assert!(written.len() > 2);
        for file in &written {
            let (direct_bytes, legacy_bytes) = (
                std::fs::read(direct_dir.path().join(file)).unwrap(),
                std::fs::read(legacy_dir.path().join(file)).unwrap(),
            );
            if file.extension().is_some_and(|ext| ext == "m4s") {
                assert_eq!(direct_bytes, legacy_bytes, "{}", file.display());
            } else {
                // The init segments differ only in the manifest.
                assert_eq!(direct_bytes.len(), legacy_bytes.len(), "{}", file.display());
            }
        }

        for init in &inits {
            let rendition = direct_dir
                .path()
                .join(init.parent().unwrap().file_name().unwrap());
            let mut init_stream = File::open(rendition.join(init.file_name().unwrap())).unwrap();
            let fragments: Vec<_> = glob::glob(&rendition.join(fragment_glob()).to_string_lossy())
                .unwrap()
                .flatten()
                .collect();
            assert!(!fragments.is_empty());
            for fragment in &fragments {
                let mut log = StatusTracker::default();
                Store::load_fragment_from_stream(
                    "mp4",
                    &mut init_stream,
                    File::open(fragment).unwrap(),
                    &mut log,
                    &context,
                )
                .unwrap();
                init_stream.rewind().unwrap();
                assert!(!log.has_any_error());
            }
            let mut log = StatusTracker::default();
            Store::load_from_file_and_fragments(
                "mp4",
                &mut init_stream,
                &fragments,
                &mut log,
                &context,
            )
            .unwrap();
            assert!(!log.has_any_error());
        }
    }

    #[test]
    fn fragments_that_cannot_be_signed_are_refused() {
        let context = Context::new();
        let signer = test_cawg_signer(SigningAlg::Ps256, &[labels::SCHEMA_ORG_INTERNAL]).unwrap();
        let inits = inits();
        let signed = tempdirectory().unwrap();
        store(&context)
            .sign_fragmented_asset_io(
                &inits,
                &fragment_glob(),
                &signed.path().to_path_buf(),
                signer.as_ref(),
                &context,
            )
            .unwrap();

        // Fragments that already have a Merkle box.
        let resigned = tempdirectory().unwrap();
        let signed_init = signed
            .path()
            .join(inits[0].parent().unwrap().file_name().unwrap())
            .join(inits[0].file_name().unwrap());
        let result = store(&context).sign_fragmented_asset_io(
            &[signed_init],
            &fragment_glob(),
            &resigned.path().to_path_buf(),
            signer.as_ref(),
            &context,
        );
        assert!(matches!(result, Err(Error::BadParam(_))), "{result:?}");

        // No fragments, and no init segments.
        for (inits, glob) in [(&inits[..], "none*.m4s"), (&[][..], "BigBuckBunny_2s*.m4s")] {
            let result = store(&context).sign_fragmented_asset_io(
                inits,
                &PathBuf::from(glob),
                &tempdirectory().unwrap().path().to_path_buf(),
                signer.as_ref(),
                &context,
            );
            assert!(matches!(result, Err(Error::BadParam(_))), "{result:?}");
        }
    }
}
