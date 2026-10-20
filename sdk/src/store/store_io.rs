// Copyright 2022 Adobe. All rights reserved.
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

use std::io::{Cursor, Read, Seek};
#[cfg(feature = "file_io")]
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use async_generic::async_generic;

#[cfg(feature = "fetch_remote_manifests")]
use super::store_core::DEFAULT_MANIFEST_RESPONSE_SIZE;
use crate::{
    assertion::AssertionBase,
    assertions::{BmffHash, BoxHash, CollectionHash, DataHash},
    asset_io::{ObjectLocations, ObjectType, ReadSeek, ReadWriteSeek},
    claim::{Claim, ClaimAssetData, RemoteManifest},
    context::{Context, ProgressPhase},
    dynamic_assertion::PartialClaim,
    error::{Error, Result},
    hash_utils::hash_size_by_alg,
    log_item,
    maybe_send_sync::MaybeSend,
    settings::Settings,
    status_tracker::StatusTracker,
    store::Store,
    utils::{
        hash_utils::HashRange,
        io_utils,
        io_utils::{insert_data_at, stream_len},
    },
    AsyncSigner, Signer,
};

impl Store {
    // generate a list of AssetHashes based on the location of objects in the stream
    fn generate_data_hashes_for_stream<R, F>(
        stream: &mut R,
        alg: &str,
        block_locations: &mut Vec<ObjectLocations>,
        calc_hashes: bool,
        progress: &mut F,
    ) -> Result<Vec<DataHash>>
    where
        R: Read + Seek + ?Sized,
        F: FnMut(u32, u32) -> Result<()>,
    {
        let stream_len = stream_len(stream)?;
        stream.rewind()?;

        let mut hashes: Vec<DataHash> = Vec::new();

        // Create a DataHash regardless of whether JUMBF is found or not...
        // For remote manifests with no embedded JUMBF, creates a hash with no exclusions,
        // because there is nothing to exclude from the hashing (since nothing is embedded)
        let mut dh = DataHash::new("jumbf manifest", alg);

        // sort blocks by offset
        block_locations.sort_by_key(|a| a.offset);

        // generate default data hash that excludes jumbf block
        // find the first jumbf block (ours are always in order)
        // find the first block after the jumbf blocks
        let mut block_start: u64 = 0;
        let mut block_end: u64 = 0;
        let mut found_jumbf = false;
        for item in block_locations {
            // find start of jumbf
            if !found_jumbf && item.htype == ObjectType::C2pa {
                block_start = item.offset;
                found_jumbf = true;
            }

            // find start of block after jumbf blocks
            if found_jumbf && item.htype == ObjectType::C2pa {
                block_end = item.offset + item.length;
            }

            // add explict exclusion ranges
            if item.htype == ObjectType::OtherExclusion {
                dh.add_exclusion(HashRange::new(item.offset, item.length));
            }
        }

        if found_jumbf {
            // add exclusion for embedded jumbf
            if calc_hashes {
                if block_end > block_start && block_end <= stream_len {
                    dh.add_exclusion(HashRange::new(block_start, block_end - block_start));
                }

                // this check is only valid on the final sized asset
                //
                // a case may occur where there is no existing manifest in the stream and the
                // asset handler creates a placeholder beyond the length of the stream
                if block_end > stream_len + (block_end - block_start) {
                    return Err(Error::BadParam(
                        "data hash exclusions out of range".to_string(),
                    ));
                }
            } else if block_end > block_start {
                dh.add_exclusion(HashRange::new(block_start, block_end - block_start));
            }
        }

        // Generate or set placeholder hash
        if calc_hashes {
            // Second signing pass: calcultate the actual real hash
            dh.gen_hash_from_stream_with_progress(stream, progress)?;
        } else {
            // First signing pass: zero-filled placeholder hash (to get to end size)
            dh.set_hash(vec![0u8; hash_size_by_alg(alg)?]);
        }

        hashes.push(dh);

        Ok(hashes)
    }

    fn generate_bmff_data_hash_for_stream(alg: &str, settings: &Settings) -> Result<BmffHash> {
        // The spec mandates BMFF exclusion ranges for certain atoms (/uuid,
        // /ftyp, /mfra) - those are always added below. /free and /skip are
        // only spec-*permitted* to exclude, not required, so whether to
        // exclude them is controlled by
        // `settings.builder.bmff_hash_exclude_free_and_skip_boxes`.

        let mut dh = BmffHash::new("jumbf manifest", alg, None);
        dh.set_default_exclusions_with_options(settings);

        // fill in temporary hash
        dh.set_hash(vec![0u8; hash_size_by_alg(alg)?]);

        Ok(dh)
    }

    // This function generates the BMFF hash for the 'mdat' boxes. This is used
    // in the case where the SDK is automatically generating the Merkle tree leaves.
    // If the user is supplying their own BmffHash they can specify the Merkle
    // tree leaves themselves and this function will not be called.
    fn generate_bmff_mdat_hashes(
        asset_stream: &mut dyn ReadSeek,
        bmff_hash: &mut BmffHash,
        settings: &Settings,
    ) -> Result<()> {
        if let Some(merkle_chunk_size) = settings.core.merkle_tree_chunk_size_in_kb {
            bmff_hash.add_merkle_map_for_mdats(
                asset_stream,
                merkle_chunk_size,
                settings.core.merkle_tree_max_proofs,
            )?;
        }
        Ok(())
    }

    /// Returns the supplied manifest composed to be directly compatible with the desired format.
    /// For example, if format is JPEG function will return the set of APP11 segments that contains
    /// the manifest.  Similarly for PNG it would be the PNG chunk complete with header and  CRC.
    ///
    /// Looks up the asset I/O handler via `context` first, so a handler registered with
    /// [`Context::with_io_handler`] is used instead of the built-in global registry.
    pub fn get_composed_manifest(
        manifest_bytes: &[u8],
        format: &str,
        context: &Context,
    ) -> Result<Vec<u8>> {
        if let Some(h) = context.io().handler(format) {
            if let Some(composed_data_handler) = h.composed_data_ref() {
                return composed_data_handler.compose_manifest(manifest_bytes, format);
            }
        }
        Err(Error::UnsupportedType)
    }

    #[cfg(feature = "file_io")]
    fn add_merkmap_for_rendition(
        &mut self,
        fragments: &[std::path::PathBuf],
        local_id: usize,
        unique_id: usize,
        output_dir: &Path,
        settings: &Settings,
    ) -> Result<()> {
        if fragments.is_empty() {
            return Err(Error::BadParam(
                "at least one fragment path must be provided".to_string(),
            ));
        }

        // get the provenance claim changing mutability
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.clear_data(); // clear since we are reusing an existing claim

        // get the BMFF hash assertion if it exists or create a new one if not
        let mut bmff_hash = if let Some(bmff_hash_assertion) = pc.bmff_hash_assertions().first() {
            BmffHash::from_assertion(bmff_hash_assertion.assertion())?
        } else {
            let mut bmff_hash = BmffHash::new("jumbf manifest", pc.alg(), None);

            bmff_hash.set_default_exclusions_with_options(settings);

            if pc.version() < 2 {
                bmff_hash.set_bmff_version(2); // backcompat support
            }

            pc.add_assertion(&bmff_hash)?;
            bmff_hash
        };
        bmff_hash.clear_hash(); // hash is not used when using fragmented Merkle tree approach

        // generate fragments and produce Merkle tree
        bmff_hash.add_merkle_for_fragmented(
            settings.core.merkle_tree_max_proofs,
            pc.alg(),
            fragments,
            output_dir,
            local_id,
            unique_id,
        )?;

        // update the BMFF hash assertion with the new Merkle tree information
        pc.update_bmff_hash(bmff_hash)?;

        /*
        // add in the BMFF assertion
        pc.add_assertion(&bmff_hash)?;

        // 3) Generate in memory CAI jumbf block
        // and write preliminary jumbf store to file
        // source and dest the same so save_jumbf_to_file will use the same file since we have already cloned
        data = self.to_jumbf_internal(reserve_size)?;
        let jumbf_size = data.len();
        save_jumbf_to_file(&data, &dest_path, Some(&dest_path))?;

        // generate actual hash values
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?; // reborrow to change mutability

        let bmff_hashes = pc.bmff_hash_assertions();

        if !bmff_hashes.is_empty() {
            let mut bmff_hash = BmffHash::from_assertion(bmff_hashes[0].assertion())?;
            bmff_hash.update_fragmented_inithash(&dest_path)?;
            pc.update_bmff_hash(bmff_hash)?;
        }

        // regenerate the jumbf because the cbor changed
        data = self.to_jumbf_internal(reserve_size)?;
        if jumbf_size != data.len() {
            return Err(Error::JumbfCreationError);
        }
        */

        Ok(())
    }

    /// Embed the claims store as jumbf into fragmented assets.
    #[cfg(feature = "file_io")]
    pub fn save_to_bmff_fragmented<P: AsRef<Path>>(
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

        let mut output_map = HashMap::new();

        // make sure output path is not a file
        if output_path.as_ref().is_file() {
            return Err(crate::Error::BadParam(
                "output_path must be a folder".to_string(),
            ));
        }

        // mak sure we can make the output folder
        if !output_path.as_ref().exists() {
            // ensure the path exists
            std::fs::create_dir_all(output_path.as_ref()).map_err(|e| {
                Error::BadParam(format!(
                    "failed to create output directory for fragments: {e}"
                ))
            })?;
        }

        // add dynamic assertions placeholders to the store
        let dynamic_assertions = signer.dynamic_assertions();
        if !dynamic_assertions.is_empty() {
            self.add_dynamic_assertion_placeholders(&dynamic_assertions)?;
        }

        // add a Merkle tree map for each init segment and its associated fragments
        for (i, init_path) in init_paths.iter().enumerate() {
            // make sure it is a supported BMFF format
            match context.io().supported_extension(init_path.as_ref()) {
                Some(ext) => {
                    if !context.io().is_bmff_format(&ext) {
                        return Err(Error::UnsupportedType);
                    }
                }
                None => return Err(Error::UnsupportedType),
            }

            // build the list of fragments for this init segment based on the glob pattern
            let mut fragments = Vec::new();
            let init_dir = init_path
                .parent()
                .ok_or(Error::BadParam(
                    "failed to get parent directory for init segment".to_string(),
                ))?
                .to_path_buf();
            let frag_glob = init_dir.join(fragment_glob.as_ref());
            let frag_glob_str = frag_glob
                .to_str()
                .ok_or(Error::BadParam("glob pattern is not valid".to_string()))?; // segment match pattern

            // grab the fragments that go with this init segment
            for entry in glob::glob(frag_glob_str)
                .map_err(|e| Error::BadParam(format!("glob pattern is not valid: {e}")))?
            {
                match entry {
                    Ok(path) => fragments.push(path),
                    Err(e) => {
                        return Err(Error::BadParam(format!(
                            "error processing glob pattern: {e}"
                        )))
                    }
                }
            }

            let new_output_path = output_path.as_ref().join(
                init_dir
                    .file_name()
                    .ok_or(Error::BadParam("init segment bad file name".to_string()))?,
            );

            // add the Merkle tree map for this rendition
            // creating fragments in the output location
            let unique_id = i + 1;
            let local_id = i + 1;
            self.add_merkmap_for_rendition(
                &fragments,
                local_id, // local id for this rendition (same as unique since we are only doing one rendition per claim for now)
                unique_id, // unique id for this rendition
                &new_output_path,
                context.settings(),
            )?;

            output_map.insert(init_path.to_owned(), (unique_id, local_id));
        }

        // now save the manifest to each output init segment (the manifest is the same for each segment per the spec to allow related rendtions to be validated as a set)
        let mut output_files = Vec::new();
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?; // reborrow to change mutability
        let bmff_hashes = pc.bmff_hash_assertions();
        let mut bmff_hash = BmffHash::from_assertion(bmff_hashes[0].assertion())?;
        let unsigned_jumbf = self.to_jumbf_internal(signer.reserve_size())?;
        for (init_path, (unique_id, local_id)) in output_map.iter() {
            let init_name = PathBuf::from(init_path.file_name().ok_or(Error::BadParam(
                "failed to get file name for init segment".to_string(),
            ))?);
            let init_dir = PathBuf::from(
                init_path
                    .parent()
                    .ok_or(Error::BadParam(
                        "failed to get parent directory for init segment".to_string(),
                    ))?
                    .file_name()
                    .ok_or(Error::BadParam(
                        "failed to get file name for init segment".to_string(),
                    ))?,
            );

            let output_file = output_path.as_ref().join(init_dir).join(init_name);

            // add manifest a placeholder that will be replaced with the final manifest after signing,
            // but we need to add it now to properly calculate the BMFF hash for each init segment
            context
                .io()
                .write_c2pa_to_file(&unsigned_jumbf, init_path, Some(&output_file))?;

            // update the initHash for each init segment
            bmff_hash.update_fragmented_inithash(*unique_id, *local_id, &output_file)?;

            output_files.push(output_file);
        }

        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?; // reborrow to change mutability

        // update the BMFF hash in the final BMFFHash assertion containing the unique initHash values for each rendition
        pc.update_bmff_hash(bmff_hash)?;

        // Write dynamic assertions only if placeholders were added during placeholder generation.
        // We check if the dynamic assertion labels exist in the claim - if not, placeholders
        // weren't added and we should skip writing to avoid size mismatches.
        let dynamic_assertions = signer.dynamic_assertions();
        if !dynamic_assertions.is_empty() {
            // Check if placeholders exist for these dynamic assertions
            let has_placeholders = {
                let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
                dynamic_assertions
                    .iter()
                    .all(|da| pc.assertion_hashed_uri_from_label(&da.label()).is_some())
            };

            if has_placeholders {
                let mut preliminary_claim = PartialClaim::default();
                {
                    let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
                    for assertion in pc.assertions() {
                        preliminary_claim.add_assertion(assertion);
                    }
                }

                self.write_dynamic_assertions(&dynamic_assertions, &mut preliminary_claim)?;
            }
        }

        // sign the claim
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self.sign_claim(pc, signer, signer.reserve_size(), context.settings())?;

        // update the provenance claim with the signature so it gets saved in the manifest
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.set_signature_val(sig);

        // regenerate the JUMBF with the signature
        let final_jumbf = self.to_jumbf_internal(signer.reserve_size())?;
        if final_jumbf.len() != unsigned_jumbf.len() {
            return Err(Error::JumbfCreationError);
        }

        // write the signed manifest to each output init segment
        for output_file in output_files.iter() {
            context
                .io()
                .write_c2pa_to_file(&final_jumbf, output_file, Some(output_file))?;
        }

        Ok(())
    }

    /// Embed the claims store as JUMBF into a stream. Updates XMP with provenance
    /// record.
    ///
    /// When called, the stream should contain an asset matching `format`.
    /// On return, the stream will contain the new manifest signed with `signer`.
    ///
    /// This directly modifies the asset in stream. Back up the stream first if
    /// you need to preserve it.
    ///
    /// This can also handle remote signing if `direct_cose_handling()` is `true`.
    #[allow(unused_variables)]
    #[async_generic(async_signature(
        &mut self,
        format: &str,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        signer: &dyn AsyncSigner,
        context: &Context,
    ))]
    pub(crate) fn save_to_stream(
        &mut self,
        format: &str,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        signer: &dyn Signer,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let settings = context.settings();
        let dynamic_assertions = signer.dynamic_assertions();

        // Add dynamic assertion placeholders (URIs no longer needed, we use da.label() directly)
        if _sync {
            self.add_dynamic_assertion_placeholders(&dynamic_assertions)?;
        } else {
            self.add_dynamic_assertion_placeholders_async(&dynamic_assertions)
                .await?;
        }

        let threshold = settings.core.backing_store_memory_threshold_in_mb;

        let input_len = io_utils::stream_len(input_stream)?;
        let mut intermediate_stream = io_utils::stream_with_fs_fallback(threshold, input_len)?;

        #[allow(unused_mut)] // Not mutable in the non-async case.
        self.start_save_stream(
            format,
            input_stream,
            &mut intermediate_stream,
            signer.reserve_size(),
            context,
        )?;
        intermediate_stream.rewind()?;

        let mut preliminary_claim = PartialClaim::default();
        {
            let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
            for assertion in pc.assertions() {
                preliminary_claim.add_assertion(assertion);
            }
        }

        // Now add the dynamic assertions and update the JUMBF.
        let modified = if _sync {
            self.write_dynamic_assertions(&dynamic_assertions, &mut preliminary_claim)
        } else {
            self.write_dynamic_assertions_async(&dynamic_assertions, &mut preliminary_claim)
                .await
        }?;

        context.check_progress(ProgressPhase::Signing, 1, 1)?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = if _sync {
            self.sign_claim(pc, signer, signer.reserve_size(), settings)
        } else {
            self.sign_claim_async(pc, signer, signer.reserve_size(), settings)
                .await
        }?;

        // update the signature
        let pc: &mut Claim = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.set_signature_val(sig.clone());

        // update the JUMBF with the signature
        let jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;

        output_stream.rewind()?;
        match self.finish_save_stream(
            jumbf_bytes,
            format,
            &mut intermediate_stream,
            output_stream,
            context,
        ) {
            Ok((s, m)) => {
                output_stream.flush()?;
                output_stream.rewind()?;

                context.check_progress(ProgressPhase::Embedding, 1, 1)?;

                // Sidecar/remote-only signing doesn't embed the manifest into
                // output_stream; anything else does.
                self.embedded = !matches!(
                    self.provenance_claim().map(|pc| pc.remote_manifest()),
                    Some(RemoteManifest::SideCar) | Some(RemoteManifest::Remote(_))
                );

                if context.settings().verify.verify_after_sign {
                    let output_len = stream_len(output_stream)?;
                    let validate_hash = context.settings().verify.verify_after_sign_hash;
                    let mut asset_data = if output_len > 0 && validate_hash {
                        Some(ClaimAssetData::Stream(output_stream, format))
                    } else {
                        None
                    };
                    if _sync {
                        self.verify_store_strict(asset_data.as_mut(), context)?;
                    } else {
                        self.verify_store_strict_async(asset_data.as_mut(), context)
                            .await?;
                    }
                }
                Ok(m)
            }
            Err(e) => Err(e),
        }
    }

    /// Start the save process for a stream, this will prepare the intermediate stream
    /// and return the JUMBF data that will be used to embed the manifest.
    fn start_save_stream(
        &mut self,
        format: &str,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        reserve_size: usize,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let settings = context.settings();
        let threshold = settings.core.backing_store_memory_threshold_in_mb;

        let input_len = io_utils::stream_len(input_stream)?;
        let mut intermediate_stream = io_utils::stream_with_fs_fallback(threshold, input_len)?;

        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // Add remote reference XMP if needed and strip out existing manifest
        // We don't need to strip manifests if we are replacing an existing one
        let (url, remove_manifests) = match pc.remote_manifest() {
            RemoteManifest::NoRemote => (None, false),
            RemoteManifest::SideCar => (None, true),
            RemoteManifest::Remote(url) => (Some(url), true),
            RemoteManifest::EmbedWithRemote(url) => (Some(url), false),
        };

        let io = context.io();
        let io_handler = io.handler(format);
        let is_bmff = io.is_bmff_format(format);
        let is_zip = io.is_zip_format(format);

        // fast_path applies to all formats: when there is no XMP embed and no manifest removal,
        // we can pass input_stream directly to the write/hash steps, skipping one full-file copy.
        let fast_path = url.is_none() && !remove_manifests;

        context.check_progress(ProgressPhase::Writing, 1, 2)?;

        if let Some(io_handler) = &io_handler {
            // Do not assume the handler supports XMP or removing manifests unless we need it to
            if let Some(url) = url {
                let external_ref_writer = io_handler
                    .remote_manifest_url_ref()
                    .ok_or(Error::XmpNotSupported)?;

                if remove_manifests {
                    let manifest_writer = io_handler
                        .get_writer(format)
                        .ok_or(Error::UnsupportedType)?;

                    let mut tmp_stream = io_utils::stream_with_fs_fallback(threshold, input_len)?;
                    manifest_writer.remove_c2pa(input_stream, &mut tmp_stream)?;

                    // add external ref if possible
                    tmp_stream.rewind()?;
                    external_ref_writer.write_remote_manifest_url(
                        &mut tmp_stream,
                        &mut intermediate_stream,
                        &url,
                    )?;
                } else {
                    // add external ref if possible
                    external_ref_writer.write_remote_manifest_url(
                        input_stream,
                        &mut intermediate_stream,
                        &url,
                    )?;
                }
            } else if remove_manifests {
                let manifest_writer = io_handler
                    .get_writer(format)
                    .ok_or(Error::UnsupportedType)?;

                manifest_writer.remove_c2pa(input_stream, &mut intermediate_stream)?;
            } else if !fast_path {
                // XMP or manifest-removal was NOT the trigger — but fast_path is false,
                // which can only happen if remove_manifests is true (already handled above).
                // This branch is a safety net; in practice it should be unreachable here.
                input_stream.rewind()?;
                std::io::copy(input_stream, &mut intermediate_stream)?;
            }
        } else {
            // No format handler — only sidecar mode (no_embed=true, no remote URL) is allowed.
            if url.is_some() {
                return Err(Error::XmpNotSupported);
            }
            if !remove_manifests {
                // The caller did not set no_embed=true, so they expected JUMBF to be embedded
                // in the output stream, which is impossible without a format handler.
                return Err(Error::UnsupportedType);
            }
            // Sidecar: output is a verbatim copy of the input; JUMBF is returned as sidecar data
            input_stream.rewind()?;
            std::io::copy(input_stream, &mut intermediate_stream)?;
        }

        // `source_is_intermediate` tracks whether intermediate_stream (true) or
        // input_stream (false) should be used as the asset source for this call.
        // When fast_path is true we skip the intermediate copy for ALL formats, not
        // just BMFF, saving one full-file read+write pass.
        let mut source_is_intermediate = !fast_path;

        let mut data;
        let jumbf_size;

        // Check to see if manifest compression is requested, BMFF and ZIP are not supported for compression since the manifest
        // needs to be in a specific location and compression would change the size of the manifest which would break the offsets
        if pc.compressed() {
            // If compression is desired use BoxHashing for compatible formats, otherwise fall back to regular hashing.
            match io_handler.and_then(|h| h.asset_box_hash_ref()) {
                Some(box_hash_handler) if !is_bmff && !is_zip => {
                    // if the user already has a box hash assertion we use that and ignore the compression setting
                    if pc.box_hash_assertions().is_empty() {
                        // no user box hash assertion, so use box hashing
                        let mut bh = BoxHash { boxes: Vec::new() };

                        if !source_is_intermediate {
                            // Box-hash generation requires a seekable intermediate; populate it
                            // from input_stream so generate_box_hash_from_stream_with_progress
                            // can make multiple passes over the data.
                            input_stream.rewind()?;
                            std::io::copy(input_stream, &mut intermediate_stream)?;
                            source_is_intermediate = true;
                        }

                        let mut cb = |step, total| {
                            context.check_progress(ProgressPhase::Hashing, step, total)
                        };
                        bh.generate_box_hash_from_stream_with_progress(
                            &mut intermediate_stream,
                            pc.alg(),
                            box_hash_handler,
                            false,
                            &mut cb,
                        )?;

                        // add the box hash assertion to the claim
                        pc.add_assertion(&bh)?;

                        intermediate_stream.rewind()?;
                    } else {
                        pc.set_compressed_manifest(false);
                    }
                }
                _ => {
                    // already have a box hash assertion so no compression will be performed
                    pc.set_compressed_manifest(false);
                }
            }
        }

        if is_bmff {
            // 2) Get hash ranges if needed, do not generate for update manifests
            let mut needs_hash = false;
            if !pc.update_manifest() && pc.bmff_hash_assertions().is_empty() {
                if source_is_intermediate {
                    intermediate_stream.rewind()?;
                } else {
                    input_stream.rewind()?;
                }
                let mut bmff_hash = Store::generate_bmff_data_hash_for_stream(pc.alg(), settings)?;

                if pc.version() < 2 {
                    bmff_hash.set_bmff_version(2); // backcompat support
                }

                // add Merkle mdats if requested
                if source_is_intermediate {
                    Store::generate_bmff_mdat_hashes(
                        &mut intermediate_stream,
                        &mut bmff_hash,
                        settings,
                    )?;
                } else {
                    Store::generate_bmff_mdat_hashes(input_stream, &mut bmff_hash, settings)?;
                }

                // insert Merkle UUID boxes at the correct location if required
                if let Some(merkle_uuid_boxes) = &bmff_hash.merkle_uuid_boxes {
                    let mut temp_stream = io_utils::stream_with_fs_fallback(threshold, input_len)?;

                    if !source_is_intermediate {
                        // Merkle insertion requires a writable source; populate intermediate
                        // from input_stream so we can call insert_data_at on it.
                        input_stream.rewind()?;
                        std::io::copy(input_stream, &mut intermediate_stream)?;
                        source_is_intermediate = true;
                    }

                    intermediate_stream.rewind()?;
                    insert_data_at(
                        &mut intermediate_stream,
                        &mut temp_stream,
                        bmff_hash.merkle_uuid_boxes_insertion_point,
                        merkle_uuid_boxes,
                    )?;

                    // this is the new intermediate stream with the UUID Merkle boxes inserted
                    temp_stream.rewind()?;
                    intermediate_stream = temp_stream;
                }
                pc.add_assertion(&bmff_hash)?;

                needs_hash = true;
            }

            // 3) Generate in memory CAI jumbf block
            // and write preliminary jumbf store to file
            // source and dest the same so save_jumbf_to_file will use the same file since we have already cloned
            data = self.to_jumbf_internal(reserve_size)?;
            jumbf_size = data.len();
            // write the jumbf to the output stream if we are embedding the manifest
            if !remove_manifests {
                if source_is_intermediate {
                    intermediate_stream.rewind()?;
                    io.write_c2pa(format, &mut intermediate_stream, output_stream, &data)?;
                } else {
                    input_stream.rewind()?;
                    io.write_c2pa(format, input_stream, output_stream, &data)?;
                }
            } else {
                // just copy the asset to the output stream without an embedded manifest (may be stripping one out here)
                // remove_manifests → fast_path is false → source_is_intermediate is true
                intermediate_stream.rewind()?;
                std::io::copy(&mut intermediate_stream, output_stream)?;
            }

            // Signal that the write pass is done; hash readback begins next.
            context.check_progress(ProgressPhase::Writing, 2, 2)?;

            // generate actual hash values
            let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?; // reborrow to change mutability

            if !pc.update_manifest() {
                let bmff_hashes = pc.bmff_hash_assertions();

                if !bmff_hashes.is_empty() && needs_hash {
                    let mut bmff_hash = BmffHash::from_assertion(bmff_hashes[0].assertion())?;

                    output_stream.rewind()?;
                    let mut cb =
                        |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
                    bmff_hash.gen_hash_from_stream_with_progress(output_stream, &mut cb)?;
                    pc.update_bmff_hash(bmff_hash)?;
                }
            }
        } else if is_zip {
            if pc.update_manifest() {
                // as of 08/28/2026, ZIP embedding does not support update manifests because it will
                // move the rest of the file down, changing offsets, and breaking the hashes
                return Err(Error::BadParam(
                    "update manifests are not supported for ZIP-based assets".to_string(),
                ));
            }

            // hash all of the existing files and embed a placeholder central directory hash.
            // this is okay because adding new file entries does not change the hashes of existing
            // file entries. when we insert the real manifest we can go back and hash the central directory.
            let mut new_collection_hash = None;
            if pc.collection_hash_assertions().is_empty() {
                let mut placeholder_collection_hash = CollectionHash::new(pc.alg().to_owned());
                if source_is_intermediate {
                    intermediate_stream.rewind()?;
                    placeholder_collection_hash.gen_zip_uri_hashes(&mut intermediate_stream)?;
                } else {
                    input_stream.rewind()?;
                    placeholder_collection_hash.gen_zip_uri_hashes(input_stream)?;
                }

                placeholder_collection_hash.set_placeholder_zip_central_directory_hash()?;
                pc.add_assertion(&placeholder_collection_hash)?;

                new_collection_hash = Some(placeholder_collection_hash);
            }

            data = self.to_jumbf_internal(reserve_size)?;
            jumbf_size = data.len();

            // we only need to compute the central directory hash here because everything else is
            // already hashed in the previous step.
            if let Some(mut collection_hash) = new_collection_hash {
                if !remove_manifests {
                    let mut scratch = io_utils::stream_with_fs_fallback(threshold, input_len)?;
                    if source_is_intermediate {
                        intermediate_stream.rewind()?;
                        io.write_c2pa(format, &mut intermediate_stream, &mut scratch, &data)?;
                    } else {
                        input_stream.rewind()?;
                        io.write_c2pa(format, input_stream, &mut scratch, &data)?;
                    }

                    scratch.rewind()?;
                    collection_hash.gen_zip_central_directory_hash(&mut scratch)?;
                } else {
                    if source_is_intermediate {
                        intermediate_stream.rewind()?;
                        collection_hash.gen_zip_central_directory_hash(&mut intermediate_stream)?;
                    } else {
                        input_stream.rewind()?;
                        collection_hash.gen_zip_central_directory_hash(input_stream)?;
                    }
                }

                let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc.replace_assertion(collection_hash.to_assertion()?)?;
            }

            if source_is_intermediate {
                intermediate_stream.rewind()?;
                std::io::copy(&mut intermediate_stream, output_stream)?;
            } else {
                input_stream.rewind()?;
                std::io::copy(input_stream, output_stream)?;
            }

            context.check_progress(ProgressPhase::Writing, 2, 2)?;
        } else {
            // we will not do automatic hashing if we detect a box hash present
            let mut needs_hashing = false;
            if pc.hash_assertions().is_empty() {
                // 2) Get hash ranges if needed, do not generate for update manifests.
                // When fast_path is true, source_is_intermediate is false and we read
                // input_stream directly, skipping the intermediate copy pass.
                let mut hash_ranges = if io_handler.is_none() {
                    Vec::new()
                } else if source_is_intermediate {
                    io.object_locations(format, &mut intermediate_stream)?
                } else {
                    io.object_locations(format, input_stream)?
                };
                let hashes: Vec<DataHash> = if pc.update_manifest() {
                    Vec::new()
                } else if source_is_intermediate {
                    Store::generate_data_hashes_for_stream(
                        &mut intermediate_stream,
                        pc.alg(),
                        &mut hash_ranges,
                        false,
                        &mut |_, _| Ok(()),
                    )?
                } else {
                    Store::generate_data_hashes_for_stream(
                        input_stream,
                        pc.alg(),
                        &mut hash_ranges,
                        false,
                        &mut |_, _| Ok(()),
                    )?
                };

                // add the placeholder data hashes to provenance claim so that the required space is reserved
                for mut hash in hashes {
                    // add padding to account for possible cbor expansion of final DataHash
                    let padding: Vec<u8> = vec![0x0; 10];
                    hash.add_padding(padding);

                    pc.add_assertion(&hash)?;
                }
                needs_hashing = true;
            }

            // 3) Generate in memory CAI jumbf block
            data = self.to_jumbf_internal(reserve_size)?;
            jumbf_size = data.len();

            // Embed the JUMBF only when we have a format handler that supports it.
            // Without a handler the output is always a verbatim copy of the asset and
            // the manifest is returned as sidecar data.
            if !remove_manifests && io_handler.is_some() {
                if source_is_intermediate {
                    intermediate_stream.rewind()?;
                    io.write_c2pa(format, &mut intermediate_stream, output_stream, &data)?;
                } else {
                    input_stream.rewind()?;
                    io.write_c2pa(format, input_stream, output_stream, &data)?;
                }
            } else {
                // just copy the asset to the output stream without an embedded manifest
                // remove_manifests → fast_path is false → source_is_intermediate is true
                intermediate_stream.rewind()?;
                std::io::copy(&mut intermediate_stream, output_stream)?;
            }

            // Signal that the asset write pass is complete, before the hash
            // readback pass begins.  This separates "Writing" (streaming
            // input → output with placeholder JUMBF) from "Hashing" (reading
            // output to compute the final content-hash binding).
            context.check_progress(ProgressPhase::Writing, 2, 2)?;

            // 4)  determine final object locations and patch the asset hashes with correct offset
            // replace the source with correct asset hashes so that the claim hash will be correct
            if needs_hashing {
                let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

                // Flush before seeking: FFI-backed streams (and any stream that
                // buffers writes) must be flushed before seeking back to read.
                output_stream.flush()?;

                // get the final hash ranges, but not for update manifests.
                // When there is no handler use empty ranges so the whole stream is hashed.
                output_stream.rewind()?;
                let mut new_hash_ranges = if io_handler.is_some() {
                    io.object_locations(format, output_stream)?
                } else {
                    Vec::new()
                };
                if !pc.update_manifest() {
                    // if we removed the manifest fixup the hash range to be empty
                    if remove_manifests {
                        new_hash_ranges.iter_mut().for_each(|h| {
                            if h.htype == ObjectType::C2pa || h.htype == ObjectType::OtherExclusion
                            {
                                h.offset = 0;
                                h.length = 0;
                            }
                        });
                    }

                    let mut cb =
                        |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
                    let updated_hashes = Store::generate_data_hashes_for_stream(
                        output_stream,
                        pc.alg(),
                        &mut new_hash_ranges,
                        true,
                        &mut cb,
                    )?;

                    // patch existing claim hash with updated data
                    for hash in updated_hashes {
                        pc.update_data_hash(hash)?;
                    }
                }
            }
        }

        // regenerate the jumbf because the cbor changed
        data = self.to_jumbf_internal(reserve_size)?;
        if jumbf_size != data.len() {
            return Err(Error::JumbfCreationError);
        }

        Ok(data) // return JUMBF data
    }

    fn finish_save_stream(
        &self,
        jumbf_bytes: Vec<u8>,
        format: &str,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        context: &Context,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // re-save to file
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        match pc.remote_manifest() {
            RemoteManifest::NoRemote | RemoteManifest::EmbedWithRemote(_) => {
                context
                    .io()
                    .write_c2pa(format, input_stream, output_stream, &jumbf_bytes)?;
            }
            RemoteManifest::SideCar | RemoteManifest::Remote(_) => {
                // just copy the asset to the output stream without an embedded manifest (may be stripping one out here)
                std::io::copy(input_stream, output_stream)?;
            }
        }

        output_stream.flush()?;
        Ok((pc.signature_val().to_vec(), jumbf_bytes))
    }

    // fetch remote manifest if possible
    #[cfg(feature = "fetch_remote_manifests")]
    #[async_generic]
    pub(super) fn fetch_remote_manifest(url: &str, context: &Context) -> Result<Vec<u8>> {
        //const MANIFEST_CONTENT_TYPE: &str = "application/x-c2pa-manifest-store"; // todo verify once these are served

        context.check_progress(ProgressPhase::FetchingRemoteManifest, 1, 1)?;

        let request = http::Request::get(url).body(Vec::new())?;
        let response = if _sync {
            context.resolver().http_resolve(request)
        } else {
            context.resolver_async().http_resolve_async(request).await
        };

        match response {
            Ok(response) => {
                if response.status() == 200 {
                    let len = response
                        .headers()
                        .get(http::header::CONTENT_LENGTH)
                        .and_then(|content_length| content_length.to_str().ok())
                        .and_then(|content_length| content_length.parse().ok())
                        .unwrap_or(DEFAULT_MANIFEST_RESPONSE_SIZE); // todo figure out good max to accept
                    let body = response.into_body();

                    let mut response_bytes: Vec<u8> = Vec::with_capacity(len);

                    let len64 = u64::try_from(len)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;

                    body.take(len64)
                        .read_to_end(&mut response_bytes)
                        .map_err(|_err| {
                            Error::RemoteManifestFetch("error reading content stream".to_string())
                        })?;

                    Ok(response_bytes)
                } else {
                    Err(Error::RemoteManifestFetch(format!(
                        "fetch failed: code: {}, status: {}",
                        response.status().as_u16(),
                        response.status().as_str()
                    )))
                }
            }
            Err(err) => Err(Error::RemoteManifestFetch(err.to_string())),
        }
    }

    /// Handles remote manifests when file_io/fetch_remote_manifests feature is enabled
    #[async_generic]
    fn handle_remote_manifest(ext_ref: &str, _context: &Context) -> Result<Vec<u8>> {
        // verify provenance path is remote url
        if Store::is_valid_remote_url(ext_ref) {
            #[cfg(feature = "fetch_remote_manifests")]
            {
                // Everything except browser wasm if fetch_remote_manifests is enabled
                if _context.settings().verify.remote_manifest_fetch {
                    if _sync {
                        Store::fetch_remote_manifest(ext_ref, _context)
                    } else {
                        Store::fetch_remote_manifest_async(ext_ref, _context).await
                    }
                } else {
                    Err(Error::RemoteManifestUrl(ext_ref.to_owned()))
                }
            }

            #[cfg(not(feature = "fetch_remote_manifests"))]
            Err(Error::RemoteManifestUrl(ext_ref.to_owned()))
        } else {
            Err(Error::JumbfNotFound)
        }
    }

    /// load jumbf given a stream
    ///
    /// This handles, embedded and remote manifests
    ///
    /// asset_type -  mime type of the stream
    /// stream - a readable stream of an asset
    ///
    /// Returns a tuple (jumbf_bytes, remote_url), returning a remote_url only
    /// if it was used to fetch the jumbf_bytes.
    #[async_generic(async_signature(
        asset_type: &str,
        stream: &mut dyn ReadSeek,
        context: &Context
    ))]
    pub fn load_jumbf_from_stream(
        asset_type: &str,
        stream: &mut dyn ReadSeek,
        context: &Context,
    ) -> Result<(Vec<u8>, Option<String>)> {
        match context.io().read_c2pa(asset_type, stream) {
            Ok(manifest_bytes) => Ok((manifest_bytes, None)),
            Err(Error::JumbfNotFound) => {
                stream.rewind()?;
                if let Some(ext_ref) =
                    crate::utils::xmp_inmemory_utils::XmpInfo::from_source(stream, asset_type)
                        .provenance
                {
                    let jumbf = if _sync {
                        Store::handle_remote_manifest(&ext_ref, context)?
                    } else {
                        Store::handle_remote_manifest_async(&ext_ref, context).await?
                    };
                    Ok((jumbf, Some(ext_ref)))
                } else {
                    Err(Error::JumbfNotFound)
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Returns embedded remote manifest URL if available
    /// asset_type: extensions or mime type of the data
    /// data: byte array containing the asset
    #[allow(unused)] // we don't use this anywhere now, but we should!
    pub fn get_remote_manifest_url(asset_type: &str, data: &[u8]) -> Option<String> {
        let mut buf_reader = Cursor::new(data);

        if let Some(ext_ref) =
            crate::utils::xmp_inmemory_utils::XmpInfo::from_source(&mut buf_reader, asset_type)
                .provenance
        {
            // make sure it parses
            let _u = url::Url::parse(&ext_ref).ok()?;
            Some(ext_ref)
        } else {
            None
        }
    }

    /// Load store from a stream
    #[async_generic]
    pub fn from_stream(
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Self> {
        let (manifest_bytes, remote_url) = if _sync {
            Store::load_jumbf_from_stream(format, &mut stream, context)
        } else {
            Store::load_jumbf_from_stream_async(format, &mut stream, context).await
        }
        .inspect_err(|e| {
            log_item!("asset", "error loading file", "load_from_asset")
                .failure_no_throw(validation_log, e);
        })?;

        // Known here, before verification runs, so verify_hash_binding can tell an
        // embedded manifest (this asset's own bytes) from a detached one.
        let embedded = remote_url.is_none();
        let store = if _sync {
            Self::from_manifest_data_and_stream_with_embedded(
                &manifest_bytes,
                format,
                &mut stream,
                validation_log,
                context,
                embedded,
            )
        } else {
            Self::from_manifest_data_and_stream_with_embedded_async(
                &manifest_bytes,
                format,
                &mut stream,
                validation_log,
                context,
                embedded,
            )
            .await
        };

        let mut store = store?;
        if !embedded {
            store.remote_url = remote_url;
        }

        Ok(store)
    }

    /// Load store from a manifest data and stream
    #[async_generic]
    pub fn from_manifest_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Self> {
        if _sync {
            Self::from_manifest_data_and_stream_with_embedded(
                c2pa_data,
                format,
                stream,
                validation_log,
                context,
                false,
            )
        } else {
            Self::from_manifest_data_and_stream_with_embedded_async(
                c2pa_data,
                format,
                stream,
                validation_log,
                context,
                false,
            )
            .await
        }
    }

    /// Load store from a manifest data and stream, marking whether `c2pa_data` was read out
    /// of `stream` itself (embedded) as opposed to supplied separately (sidecar/remote).
    #[async_generic]
    pub(crate) fn from_manifest_data_and_stream_with_embedded(
        c2pa_data: &[u8],
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
        validation_log: &mut StatusTracker,
        context: &Context,
        embedded: bool,
    ) -> Result<Self> {
        stream.rewind()?;

        // First we convert the JUMBF into a usable store.
        let mut store = Store::from_jumbf_with_context(c2pa_data, validation_log, context)
            .inspect_err(|e| {
                log_item!("asset", "error loading file", "load_from_asset")
                    .failure_no_throw(validation_log, e);
            })?;
        store.embedded = embedded;

        if context.settings().verify.verify_after_reading {
            stream.rewind()?;
            let mut asset_data = ClaimAssetData::Stream(&mut stream, format);
            if _sync {
                Store::verify_store(&store, Some(&mut asset_data), validation_log, context)
            } else {
                Store::verify_store_async(&store, Some(&mut asset_data), validation_log, context)
                    .await
            }?;
        }
        Ok(store)
    }

    /// Load Store from a init and fragments
    /// asset_type: asset extension or mime type
    /// init_segment: reader for the file containing the initialization segments
    /// fragments: list of paths to the fragments to verify
    /// verify: if true will run verification checks when loading, all fragments must verify for Ok status
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned
    #[cfg(feature = "file_io")]
    pub fn load_from_file_and_fragments(
        asset_type: &str,
        init_segment: &mut dyn ReadSeek,
        fragments: &Vec<PathBuf>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Store> {
        let manifest_bytes = Store::load_jumbf_from_stream(asset_type, init_segment, context)?.0;

        let store = Store::from_jumbf_with_context(&manifest_bytes, validation_log, context)?;
        let verify = context.settings().verify.verify_after_reading;

        if verify {
            init_segment.rewind()?;
            // verify store and claims
            Store::verify_store(
                &store,
                Some(&mut ClaimAssetData::StreamFragments(
                    init_segment,
                    fragments,
                    asset_type,
                )),
                validation_log,
                context,
            )?;
        }

        Ok(store)
    }

    /// Load Store from a stream and fragment stream
    ///
    /// asset_type: asset extension or mime type
    /// stream: reference to initial segment asset
    /// fragment: reference to fragment asset
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned
    #[async_generic(async_signature(
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
        mut fragment: impl Read + Seek + MaybeSend,
        validation_log: &mut StatusTracker,
        context: &Context,
    ))]
    pub fn load_fragment_from_stream(
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
        mut fragment: impl Read + Seek + MaybeSend,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Store> {
        let manifest_bytes = if _sync {
            Store::load_jumbf_from_stream(format, &mut stream, context)?.0
        } else {
            Store::load_jumbf_from_stream_async(format, &mut stream, context)
                .await?
                .0
        };

        let store = Store::from_jumbf_with_context(&manifest_bytes, validation_log, context)?;
        let verify = context.settings().verify.verify_after_reading;

        if verify {
            let mut fragment = ClaimAssetData::StreamFragment(&mut stream, &mut fragment, format);
            if _sync {
                Store::verify_store(&store, Some(&mut fragment), validation_log, context)
            } else {
                Store::verify_store_async(&store, Some(&mut fragment), validation_log, context)
                    .await
            }?;
        };
        Ok(store)
    }
}
