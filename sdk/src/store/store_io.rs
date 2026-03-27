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

use std::io::{Cursor, Read, Seek, SeekFrom};
#[cfg(feature = "file_io")]
use std::path::{Path, PathBuf};

use async_generic::async_generic;

#[cfg(feature = "fetch_remote_manifests")]
use super::DEFAULT_MANIFEST_RESPONSE_SIZE;
#[cfg(feature = "file_io")]
use super::MANIFEST_STORE_EXT;
use super::{Store, StoreValidationInfo};
#[cfg(feature = "file_io")]
use crate::jumbf_io::{
    get_file_extension, get_supported_file_extension, load_jumbf_from_file, save_jumbf_to_file,
};
use crate::{
    assertion::AssertionBase,
    assertions::{BmffHash, CertificateStatus, DataHash, Ingredient, Relationship, TimeStamp},
    asset_io::{
        CAIRead, CAIReadWrite, HashBlockObjectType, HashObjectPositions, RemoteRefEmbedType,
    },
    claim::{Claim, ClaimAssetData, RemoteManifest},
    context::{Context, ProgressPhase},
    crypto::{ocsp::OcspResponse, time_stamp::verify_time_stamp},
    dynamic_assertion::PartialClaim,
    error::{Error, Result},
    hash_utils::{vec_compare, verify_by_alg},
    jumbf::{self, labels::to_manifest_uri},
    jumbf_io::{
        get_assetio_handler, is_bmff_format, load_jumbf_from_stream, object_locations_from_stream,
        save_jumbf_to_stream,
    },
    log_item,
    maybe_send_sync::MaybeSend,
    settings::Settings,
    status_tracker::{ErrorBehavior, StatusTracker},
    utils::{
        hash_utils::HashRange,
        io_utils::{self, insert_data_at, stream_len},
        is_zero,
    },
    validation_status, AsyncSigner, Signer,
};

impl Store {
    // recursively walk the ingredients and validate
    fn ingredient_checks(
        store: &Store,
        claim: &Claim,
        svi: &StoreValidationInfo,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<()> {
        let settings = context.settings();

        // Pre-count verifiable ingredients so we can emit accurate step/total values.
        let total_ingredients = claim.ingredient_assertions().len() as u32;
        let mut ingredient_step = 0u32;

        // walk the ingredients
        for i in claim.ingredient_assertions() {
            ingredient_step += 1;
            context.check_progress(
                ProgressPhase::VerifyingIngredient,
                ingredient_step,
                total_ingredients,
            )?;

            // allow for zero out ingredient assertions
            if is_zero(i.assertion().data()) {
                continue;
            }

            let ingredient_assertion = Ingredient::from_assertion(i.assertion()).map_err(|e| {
                log_item!(
                    i.label().clone(),
                    "ingredient assertion could not be parsed",
                    "ingredient_checks"
                )
                .validation_status(validation_status::ASSERTION_INGREDIENT_MALFORMED)
                .failure_as_err(validation_log, e)
            })?;

            // we don't care about InputTo ingredients
            if ingredient_assertion.relationship == Relationship::InputTo {
                continue;
            }

            validation_log
                .push_ingredient_uri(jumbf::labels::to_assertion_uri(claim.label(), &i.label()));

            // is this an ingredient
            if let Some(c2pa_manifest) = ingredient_assertion.c2pa_manifest() {
                // if this is a v3 ingredient then it must have validation report indicating it was validated
                if let Some(ingredient_version) = ingredient_assertion.version() {
                    if ingredient_version >= 3 && ingredient_assertion.validation_results.is_none()
                    {
                        log_item!(
                            jumbf::labels::to_assertion_uri(claim.label(), &i.label()),
                            "ingredient V3 must have validation results",
                            "ingredient_checks"
                        )
                        .validation_status(validation_status::ASSERTION_INGREDIENT_MALFORMED)
                        .failure(
                            validation_log,
                            Error::HashMismatch(
                                "ingredient V3 missing validation status".to_string(),
                            ),
                        )?;
                    }
                }

                let label = Store::manifest_label_from_path(&c2pa_manifest.url());

                if let Some(ingredient) = store.get_claim(&label) {
                    let alg = match c2pa_manifest.alg() {
                        Some(a) => a,
                        None => ingredient.alg().to_owned(),
                    };

                    // are we evaluating a 2.x manifest, then use those rule
                    let ingredient_version = ingredient.version();
                    let has_redactions = svi.redactions.iter().any(|r| r.contains(&label));

                    // allow the extra ingredient trust checks
                    // these checks are to prevent the trust spoofing
                    let check_ingredient_trust: bool = settings.verify.verify_trust;

                    // get the 1.1-1.2 box hash
                    let ingredient_hashes = store.get_manifest_box_hashes(ingredient);

                    // since no redactions we can try manifest match method
                    let mut pre_v1_3_hash = false;
                    let manifests_match = if !has_redactions {
                        // test for 1.1 hash then 1.0 version
                        if !vec_compare(&c2pa_manifest.hash(), &ingredient_hashes.manifest_box_hash)
                        {
                            // try legacy hash
                            pre_v1_3_hash = true;
                            verify_by_alg(&alg, &c2pa_manifest.hash(), &ingredient.data()?, None)
                        } else {
                            true
                        }
                    } else {
                        false
                    };

                    // since the manifest hashes are equal we can short circuit the rest of the validation
                    // we can only do this for post 1.3 Claims since manfiest box hashing was not available
                    if manifests_match && !pre_v1_3_hash {
                        log_item!(
                            c2pa_manifest.url(),
                            "ingredient hash matched",
                            "ingredient_checks"
                        )
                        .validation_status(validation_status::INGREDIENT_MANIFEST_VALIDATED)
                        .success(validation_log);
                    }

                    // if mismatch is not because of a redaction this is a hard error
                    if !manifests_match && !has_redactions {
                        log_item!(
                            c2pa_manifest.url(),
                            "ingredient hash incorrect",
                            "ingredient_checks"
                        )
                        .validation_status(validation_status::INGREDIENT_MANIFEST_MISMATCH)
                        .failure(
                            validation_log,
                            Error::HashMismatch(
                                "ingredient hash does not match found ingredient".to_string(),
                            ),
                        )?;
                    }

                    // if manifest hash did not match because of redaction and this is a V2 or greater claim then we
                    // must try the signature validation method before proceeding
                    if !manifests_match && has_redactions && ingredient_version > 1 {
                        let claim_signature =
                            ingredient_assertion.signature().ok_or_else(|| {
                                log_item!(
                                    c2pa_manifest.url(),
                                    "ingredient claimSignature missing",
                                    "ingredient_checks"
                                )
                                .validation_status(
                                    validation_status::INGREDIENT_CLAIM_SIGNATURE_MISSING,
                                )
                                .failure_as_err(
                                    validation_log,
                                    Error::HashMismatch(
                                        "ingredient claimSignature missing".to_string(),
                                    ),
                                )
                            })?;

                        // compare the signature box hashes
                        if vec_compare(
                            &claim_signature.hash(),
                            &ingredient_hashes.signature_box_hash,
                        ) {
                            log_item!(
                                c2pa_manifest.url(),
                                "ingredient claimSignature validated",
                                "ingredient_checks"
                            )
                            .validation_status(
                                validation_status::INGREDIENT_CLAIM_SIGNATURE_VALIDATED,
                            )
                            .informational(validation_log);
                        } else {
                            log_item!(
                                c2pa_manifest.url(),
                                "ingredient claimSignature mismatch",
                                "ingredient_checks"
                            )
                            .validation_status(
                                validation_status::INGREDIENT_CLAIM_SIGNATURE_MISMATCH,
                            )
                            .failure(
                                validation_log,
                                Error::HashMismatch(
                                    "ingredient claimSignature mismatch".to_string(),
                                ),
                            )?;
                        }
                    }

                    Claim::verify_claim(
                        ingredient,
                        asset_data,
                        svi,
                        check_ingredient_trust,
                        &store.ctp,
                        validation_log,
                        context,
                    )?;

                    // recurse nested ingredients
                    Store::ingredient_checks(
                        store,
                        ingredient,
                        svi,
                        asset_data,
                        validation_log,
                        context,
                    )?;
                } else {
                    log_item!(label.clone(), "ingredient not found", "ingredient_checks")
                        .validation_status(validation_status::INGREDIENT_MANIFEST_MISSING)
                        .failure(
                            validation_log,
                            Error::ClaimVerification(format!("ingredient: {label} is missing")),
                        )?;
                }
            } else {
                let title = ingredient_assertion.title.unwrap_or("no title".into());
                let description = format!("{title}: ingredient does not have provenance");
                log_item!(
                    jumbf::labels::to_assertion_uri(claim.label(), &i.label()),
                    description,
                    "ingredient_checks"
                )
                .validation_status(validation_status::INGREDIENT_PROVENANCE_UNKNOWN)
                .informational(validation_log);
            }
            validation_log.pop_ingredient_uri();
        }

        Ok(())
    }

    // recursively walk the ingredients and validate
    async fn ingredient_checks_async(
        store: &Store,
        claim: &Claim,
        svi: &StoreValidationInfo<'_>,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<()> {
        let settings = context.settings();

        let total_ingredients = claim
            .ingredient_assertions()
            .iter()
            .filter(|i| !is_zero(i.assertion().data()))
            .count() as u32;
        let mut ingredient_step = 0u32;

        // walk the ingredients
        for i in claim.ingredient_assertions() {
            // allow for zero out ingredient assertions
            if is_zero(i.assertion().data()) {
                continue;
            }

            let ingredient_assertion = Ingredient::from_assertion(i.assertion()).map_err(|e| {
                log_item!(
                    i.label().clone(),
                    "ingredient assertion could not be parsed",
                    "ingredient_checks"
                )
                .validation_status(validation_status::ASSERTION_INGREDIENT_MALFORMED)
                .failure_as_err(validation_log, e)
            })?;

            // we don't care about InputTo ingredients
            if ingredient_assertion.relationship == Relationship::InputTo {
                continue;
            }

            ingredient_step += 1;
            context.check_progress(
                ProgressPhase::VerifyingIngredient,
                ingredient_step,
                total_ingredients,
            )?;

            validation_log
                .push_ingredient_uri(jumbf::labels::to_assertion_uri(claim.label(), &i.label()));

            // is this an ingredient
            if let Some(c2pa_manifest) = ingredient_assertion.c2pa_manifest() {
                // if this is a v3 ingredient then it must have validation report indicating it was validated
                if let Some(ingredient_version) = ingredient_assertion.version() {
                    if ingredient_version >= 3 && ingredient_assertion.validation_results.is_none()
                    {
                        log_item!(
                            jumbf::labels::to_assertion_uri(claim.label(), &i.label()),
                            "ingredient V3 must have validation results",
                            "ingredient_checks"
                        )
                        .validation_status(validation_status::ASSERTION_INGREDIENT_MALFORMED)
                        .failure(
                            validation_log,
                            Error::HashMismatch(
                                "ingredient V3 missing validation status".to_string(),
                            ),
                        )?;
                    }
                }

                let label = Store::manifest_label_from_path(&c2pa_manifest.url());

                if let Some(ingredient) = store.get_claim(&label) {
                    let alg = match c2pa_manifest.alg() {
                        Some(a) => a,
                        None => ingredient.alg().to_owned(),
                    };

                    // are we evaluating a 2.x manifest, then use those rule
                    let ingredient_version = ingredient.version();
                    let has_redactions = svi.redactions.iter().any(|r| r.contains(&label));

                    // allow the extra ingredient trust checks
                    // these checks are to prevent the trust spoofing
                    let check_ingredient_trust = settings.verify.verify_trust;

                    // get the 1.1-1.2 box hash
                    let ingredient_hashes = store.get_manifest_box_hashes(ingredient);

                    // since no redactions we can try manifest match method
                    let mut pre_v1_3_hash = false;
                    let manifests_match = if !has_redactions {
                        // test for 1.1 hash then 1.0 version
                        if !vec_compare(&c2pa_manifest.hash(), &ingredient_hashes.manifest_box_hash)
                        {
                            // try legacy hash
                            pre_v1_3_hash = true;
                            verify_by_alg(&alg, &c2pa_manifest.hash(), &ingredient.data()?, None)
                        } else {
                            true
                        }
                    } else {
                        false
                    };

                    // since the manifest hashes are equal we can short circuit the rest of the validation
                    // we can only do this for post 1.3 Claims since manfiest box hashing was not available
                    if manifests_match && !pre_v1_3_hash {
                        log_item!(
                            c2pa_manifest.url(),
                            "ingredient hash matched",
                            "ingredient_checks"
                        )
                        .validation_status(validation_status::INGREDIENT_MANIFEST_VALIDATED)
                        .success(validation_log);
                    }

                    // if mismatch is not because of a redaction this is a hard error
                    if !manifests_match && !has_redactions {
                        log_item!(
                            c2pa_manifest.url(),
                            "ingredient hash incorrect",
                            "ingredient_checks"
                        )
                        .validation_status(validation_status::INGREDIENT_MANIFEST_MISMATCH)
                        .failure(
                            validation_log,
                            Error::HashMismatch(
                                "ingredient hash does not match found ingredient".to_string(),
                            ),
                        )?;
                    }

                    // if manifest hash did not match and this is a V2 or greater claim then we
                    // must try the signature validation method before proceeding
                    if !manifests_match && has_redactions && ingredient_version > 1 {
                        let claim_signature =
                            ingredient_assertion.signature().ok_or_else(|| {
                                log_item!(
                                    c2pa_manifest.url(),
                                    "ingredient claimSignature missing",
                                    "ingredient_checks"
                                )
                                .validation_status(
                                    validation_status::INGREDIENT_CLAIM_SIGNATURE_MISSING,
                                )
                                .failure_as_err(
                                    validation_log,
                                    Error::HashMismatch(
                                        "ingredient claimSignature missing".to_string(),
                                    ),
                                )
                            })?;

                        // compare the signature box hashes
                        if vec_compare(
                            &claim_signature.hash(),
                            &ingredient_hashes.signature_box_hash,
                        ) {
                            log_item!(
                                c2pa_manifest.url(),
                                "ingredient claimSignature validated",
                                "ingredient_checks"
                            )
                            .validation_status(
                                validation_status::INGREDIENT_CLAIM_SIGNATURE_VALIDATED,
                            )
                            .informational(validation_log);
                        } else {
                            log_item!(
                                c2pa_manifest.url(),
                                "ingredient claimSignature mismatch",
                                "ingredient_checks"
                            )
                            .validation_status(
                                validation_status::INGREDIENT_CLAIM_SIGNATURE_MISMATCH,
                            )
                            .failure(
                                validation_log,
                                Error::HashMismatch(
                                    "ingredient claimSignature mismatch".to_string(),
                                ),
                            )?;
                        }
                    }

                    Claim::verify_claim_async(
                        ingredient,
                        asset_data,
                        svi,
                        check_ingredient_trust,
                        &store.ctp,
                        validation_log,
                        context,
                    )
                    .await?;

                    // recurse nested ingredients
                    Box::pin(Store::ingredient_checks_async(
                        store,
                        ingredient,
                        svi,
                        asset_data,
                        validation_log,
                        context,
                    ))
                    .await?;
                } else {
                    log_item!(label.clone(), "ingredient not found", "ingredient_checks")
                        .validation_status(validation_status::INGREDIENT_MANIFEST_MISSING)
                        .failure(
                            validation_log,
                            Error::ClaimVerification(format!("ingredient: {label} is missing")),
                        )?;
                }
            } else {
                let title = ingredient_assertion.title.unwrap_or("no title".into());
                let description = format!("{title}: ingredient does not have provenance");
                log_item!(
                    jumbf::labels::to_assertion_uri(claim.label(), &i.label()),
                    description,
                    "ingredient_checks"
                )
                .validation_status(validation_status::INGREDIENT_PROVENANCE_UNKNOWN)
                .informational(validation_log);
            }
            validation_log.pop_ingredient_uri();
        }

        Ok(())
    }

    fn get_store_validation_info<'a>(
        &'a self,
        claim: &'a Claim,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut StatusTracker,
    ) -> Result<StoreValidationInfo<'a>> {
        let mut svi = StoreValidationInfo::default();
        Store::get_claim_referenced_manifests(claim, self, &mut svi, true, validation_log)?;

        // find the manifest with the hash binding
        svi.binding_claim = self.get_hash_binding_manifest(claim).ok_or_else(|| {
            log_item!(
                to_manifest_uri(claim.label()),
                "could not find manifest with hard binding",
                "get_store_validation_info"
            )
            .validation_status(validation_status::HARD_BINDINGS_MISSING)
            .failure_as_err(validation_log, Error::ClaimMissingHardBinding)
        })?;

        // save the update manifest label if it exists
        if claim.update_manifest() {
            svi.update_manifest_label = Some(claim.label().to_owned());
        }

        // get the manifest offset position
        let locations = match asset_data {
            #[cfg(feature = "file_io")]
            ClaimAssetData::Path(path) => {
                let format = get_supported_file_extension(path).ok_or(Error::UnsupportedType)?;
                let mut reader = std::fs::File::open(path)?;

                object_locations_from_stream(&format, &mut reader)
            }
            ClaimAssetData::Bytes(items, typ) => {
                let format = typ.to_owned();
                let mut reader = Cursor::new(items);

                object_locations_from_stream(&format, &mut reader)
            }
            ClaimAssetData::Stream(reader, typ) => {
                let format = typ.to_owned();
                let positions = object_locations_from_stream(&format, reader);
                reader.rewind()?;
                positions
            }
            ClaimAssetData::StreamFragment(reader, _read1, typ) => {
                let format = typ.to_owned();
                object_locations_from_stream(&format, reader)
            }
            #[cfg(feature = "file_io")]
            ClaimAssetData::StreamFragments(reader, _path_bufs, typ) => {
                let format = typ.to_owned();
                object_locations_from_stream(&format, reader)
            }
        };

        if let Ok(locations) = locations {
            if let Some(manifest_loc) = locations
                .iter()
                .find(|o| o.htype == HashBlockObjectType::Cai)
            {
                svi.manifest_store_range = Some(HashRange::new(
                    manifest_loc.offset as u64,
                    manifest_loc.length as u64,
                ));
            }
        }

        for found_claim in svi.manifest_map.values() {
            // get the timestamp assertions
            let timestamp_assertions = found_claim.timestamp_assertions();
            for ta in timestamp_assertions {
                let timestamp_assertion =
                    TimeStamp::from_assertion(ta.assertion()).map_err(|_e| {
                        log_item!(
                            ta.label(),
                            "could not parse timestamp assertion",
                            "get_claim_referenced_manifests"
                        )
                        .validation_status(validation_status::ASSERTION_TIMESTAMP_MALFORMED)
                        .failure_as_err(
                            validation_log,
                            Error::ValidationRule("timestamp assertion malformed".into()),
                        )
                    })?;

                // save the valid timestamps stored in the StoreValidationInfo
                // we only use valid timestamps, otherwise just ignore
                for (referenced_claim, time_stamp_token) in timestamp_assertion.as_ref() {
                    let mut tmp_log = StatusTracker::default();
                    if let Some(rc) = svi.manifest_map.get(referenced_claim) {
                        if let Ok(sign1) = rc.cose_sign1() {
                            if let Ok(tst_info) = verify_time_stamp(
                                time_stamp_token,
                                &sign1.signature,
                                &self.ctp,
                                &mut tmp_log,
                                // no trust checks for leagacy timestamps
                                rc.version() != 1,
                            ) {
                                svi.timestamps.insert(rc.label().to_owned(), tst_info);
                            }
                        }
                    }
                }
            }

            // get the certificate status assertions
            let certificate_status_assertions = found_claim.certificate_status_assertions();
            for csa in certificate_status_assertions {
                let certificate_status_assertion =
                    CertificateStatus::from_assertion(csa.assertion())?;

                // save the ocsp_ders stored in the StoreValidationInfo
                for ocsp_der in certificate_status_assertion.as_ref() {
                    if let Ok(response) =
                        OcspResponse::from_der_checked(ocsp_der, None, validation_log)
                    {
                        let ocsp_ders = svi
                            .certificate_statuses
                            .entry(response.certificate_serial_num)
                            .or_insert(Vec::new());
                        ocsp_ders.push(response.ocsp_der);
                    }
                }
            }
        }

        Ok(svi)
    }

    /// Verify Store
    /// store: Store to validate
    /// xmp_str: String containing entire XMP block of the asset
    /// asset_bytes: bytes of the asset to be verified
    /// validation_log: If present all found errors are logged and returned, other wise first error causes exit and is returned
    #[async_generic(async_signature(
        store: &Store,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut StatusTracker,
        context: &Context,

    ))]
    pub fn verify_store(
        store: &Store,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<()> {
        context.check_progress(ProgressPhase::VerifyingManifest, 1, 1)?;
        let claim = match store.provenance_claim() {
            Some(c) => c,
            None => {
                log_item!("Unknown", "could not find active manifest", "verify_store")
                    .validation_status(validation_status::CLAIM_MISSING)
                    .failure_no_throw(validation_log, Error::ProvenanceMissing);

                return Err(Error::ProvenanceMissing);
            }
        };

        // get info needed to complete validation
        let svi = store.get_store_validation_info(claim, asset_data, validation_log)?;

        if _sync {
            // verify the provenance claim
            Claim::verify_claim(
                claim,
                asset_data,
                &svi,
                true,
                &store.ctp,
                validation_log,
                context,
            )?;

            Store::ingredient_checks(store, claim, &svi, asset_data, validation_log, context)?;
        } else {
            Claim::verify_claim_async(
                claim,
                asset_data,
                &svi,
                true,
                &store.ctp,
                validation_log,
                context,
            )
            .await?;

            Store::ingredient_checks_async(store, claim, &svi, asset_data, validation_log, context)
                .await?;
        }

        Ok(())
    }

    // generate a list of AssetHashes based on the location of objects in the stream
    fn generate_data_hashes_for_stream<R>(
        stream: &mut R,
        alg: &str,
        block_locations: &mut Vec<HashObjectPositions>,
        calc_hashes: bool,
        progress: Option<&mut dyn FnMut(u32, u32) -> Result<()>>,
    ) -> Result<Vec<DataHash>>
    where
        R: Read + Seek + ?Sized,
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
        let mut block_start: usize = 0;
        let mut block_end: usize = 0;
        let mut found_jumbf = false;
        for item in block_locations {
            // find start of jumbf
            if !found_jumbf && item.htype == HashBlockObjectType::Cai {
                block_start = item.offset;
                found_jumbf = true;
            }

            // find start of block after jumbf blocks
            if found_jumbf && item.htype == HashBlockObjectType::Cai {
                block_end = item.offset + item.length;
            }

            // add explict exclusion ranges
            if item.htype == HashBlockObjectType::OtherExclusion {
                dh.add_exclusion(HashRange::new(item.offset as u64, item.length as u64));
            }
        }

        if found_jumbf {
            // add exclusion for embedded jumbf
            if calc_hashes {
                if block_end > block_start && (block_end as u64) <= stream_len {
                    dh.add_exclusion(HashRange::new(
                        block_start as u64,
                        (block_end - block_start) as u64,
                    ));
                }

                // this check is only valid on the final sized asset
                //
                // a case may occur where there is no existing manifest in the stream and the
                // asset handler creates a placeholder beyond the length of the stream
                if block_end as u64 > stream_len + (block_end - block_start) as u64 {
                    return Err(Error::BadParam(
                        "data hash exclusions out of range".to_string(),
                    ));
                }
            } else if block_end > block_start {
                dh.add_exclusion(HashRange::new(
                    block_start as u64,
                    (block_end - block_start) as u64,
                ));
            }
        }

        // Generate or set placeholder hash
        if calc_hashes {
            // Second signing pass: calcultate the actual real hash
            dh.gen_hash_from_stream_with_progress(stream, progress)?;
        } else {
            // First signing pass: zero-filled placeholder hash (to get to end size)
            match alg {
                "sha256" => dh.set_hash([0u8; 32].to_vec()),
                "sha384" => dh.set_hash([0u8; 48].to_vec()),
                "sha512" => dh.set_hash([0u8; 64].to_vec()),
                _ => return Err(Error::UnsupportedType),
            }
        }

        hashes.push(dh);

        Ok(hashes)
    }

    fn generate_bmff_data_hash_for_stream(alg: &str) -> Result<BmffHash> {
        // The spec has mandatory BMFF exclusion ranges for certain atoms.
        // The function makes sure those are included.

        let mut dh = BmffHash::new("jumbf manifest", alg, None);
        dh.set_default_exclusions();

        // fill in temporary hash
        match alg {
            "sha256" => dh.set_hash([0u8; 32].to_vec()),
            "sha384" => dh.set_hash([0u8; 48].to_vec()),
            "sha512" => dh.set_hash([0u8; 64].to_vec()),
            _ => return Err(Error::UnsupportedType),
        }

        Ok(dh)
    }

    // This function generates the BMFF hash for the 'mdat' boxes. This is used
    // in the case where the SDK is automatically generating the Merkle tree leaves.
    // If the user is supplying their own BmffHash they can specify the Merkle
    // tree leaves themselves and this function will not be called.
    fn generate_bmff_mdat_hashes(
        asset_stream: &mut dyn CAIRead,
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

    /// This function is used to pre-generate a manifest with place holders for the final
    /// DataHash and Manifest Signature.  The DataHash will reserve space for at least 10
    /// Exclusion ranges.  The Signature box reserved size is based on the size required by
    /// the Signer you plan to use.  This function is not needed when using Box Hash. This function is used
    /// in conjunction with `get_data_hashed_embeddable_manifest`.  The manifest returned
    /// from `get_data_hashed_embeddable_manifest` will have a size that matches this function.
    /// Note: This function does not support dynamic assertions. Use `get_placeholder`
    /// if you need dynamic assertion support.
    pub fn get_data_hashed_manifest_placeholder(
        &mut self,
        reserve_size: usize,
        format: &str,
    ) -> Result<Vec<u8>> {
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // if user did not supply a hash
        if pc.hash_assertions().is_empty() {
            // create placeholder DataHash large enough for 10 Exclusions
            let mut ph = DataHash::new("jumbf manifest", pc.alg());
            for _ in 0..10 {
                ph.add_exclusion(HashRange::new(0u64, 2u64));
            }
            let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let mut stream = Cursor::new(data);
            ph.gen_hash_from_stream(&mut stream)?;

            pc.add_assertion(&ph)?;
        }

        let jumbf_bytes = self.to_jumbf_internal(reserve_size)?;

        let composed = Self::get_composed_manifest(&jumbf_bytes, format)?;

        Ok(composed)
    }

    fn prep_embeddable_store(
        &mut self,
        reserve_size: usize,
        dh: &DataHash,
        asset_reader: Option<&mut dyn CAIRead>,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // make sure there are data hashes present before generating
        if pc.hash_assertions().is_empty() {
            return Err(Error::BadParam(
                "Claim must have hash binding assertion".to_string(),
            ));
        }

        // don't allow BMFF assertions to be present
        if !pc.bmff_hash_assertions().is_empty() {
            return Err(Error::BadParam(
                "BMFF assertions not supported in embeddable manifests".to_string(),
            ));
        }

        let mut adjusted_dh = DataHash::new("jumbf manifest", pc.alg());
        adjusted_dh.exclusions.clone_from(&dh.exclusions);
        adjusted_dh.hash.clone_from(&dh.hash);

        if let Some(reader) = asset_reader {
            // calc hashes
            let mut cb = |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
            adjusted_dh.gen_hash_from_stream_with_progress(reader, Some(&mut cb))?;
        }

        // update the placeholder hash
        pc.update_data_hash(adjusted_dh)?;

        self.to_jumbf_internal(reserve_size)
    }

    fn finish_embeddable_store(
        &mut self,
        sig: &[u8],
        sig_placeholder: &[u8],
        jumbf_bytes: &mut Vec<u8>,
        format: &str,
    ) -> Result<Vec<u8>> {
        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(jumbf_bytes, sig_placeholder, sig).map_err(|_| Error::JumbfCreationError)?;

        Self::get_composed_manifest(jumbf_bytes, format)
    }

    /// Returns a finalized, signed manifest.  The manifest are only supported
    /// for cases when the client has provided a data hash content hash binding.  Note,
    /// this function will not work for cases like BMFF where the position
    /// of the content is also encoded.  This function is not compatible with
    /// BMFF hash binding.  If a BMFF data hash or box hash is detected that is
    /// an error.  The DataHash placeholder assertion will be  adjusted to the contain
    /// the correct values.  If the asset_reader value is supplied it will also perform
    /// the hash calculations, otherwise the function uses the caller supplied values.
    /// It is an error if `get_data_hashed_manifest_placeholder` was not called first
    /// as this call inserts the DataHash placeholder assertion to reserve space for the
    /// actual hash values not required when using BoxHashes.
    pub fn get_data_hashed_embeddable_manifest(
        &mut self,
        dh: &DataHash,
        signer: &dyn Signer,
        format: &str,
        asset_reader: Option<&mut dyn CAIRead>,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let mut jumbf_bytes =
            self.prep_embeddable_store(signer.reserve_size(), dh, asset_reader, context)?;

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

                let modified =
                    self.write_dynamic_assertions(&dynamic_assertions, &mut preliminary_claim)?;

                // Regenerate JUMBF if dynamic assertions were written
                if modified {
                    jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;
                }
            }
        }

        context.check_progress(ProgressPhase::Signing, 1, 1)?;

        // sign contents
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self.sign_claim(pc, signer, signer.reserve_size(), context.settings())?;

        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        self.finish_embeddable_store(&sig, &sig_placeholder, &mut jumbf_bytes, format)
    }

    /// Returns a finalized, signed manifest.  The manifest are only supported
    /// for cases when the client has provided a data hash content hash binding.  Note,
    /// this function will not work for cases like BMFF where the position
    /// of the content is also encoded.  This function is not compatible with
    /// BMFF hash binding.  If a BMFF data hash or box hash is detected that is
    /// an error.  The DataHash placeholder assertion will be  adjusted to the contain
    /// the correct values.  If the asset_reader value is supplied it will also perform
    /// the hash calculations, otherwise the function uses the caller supplied values.
    /// It is an error if `get_data_hashed_manifest_placeholder` was not called first
    /// as this call inserts the DataHash placeholder assertion to reserve space for the
    /// actual hash values not required when using BoxHashes.
    pub async fn get_data_hashed_embeddable_manifest_async(
        &mut self,
        dh: &DataHash,
        signer: &dyn AsyncSigner,
        format: &str,
        asset_reader: Option<&mut dyn CAIRead>,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let mut jumbf_bytes =
            self.prep_embeddable_store(signer.reserve_size(), dh, asset_reader, context)?;

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

                let modified = self
                    .write_dynamic_assertions_async(&dynamic_assertions, &mut preliminary_claim)
                    .await?;

                // Regenerate JUMBF if dynamic assertions were written
                if modified {
                    jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;
                }
            }
        }

        context.check_progress(ProgressPhase::Signing, 1, 1)?;

        // sign contents
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self
            .sign_claim_async(pc, signer, signer.reserve_size(), context.settings())
            .await?;

        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        self.finish_embeddable_store(&sig, &sig_placeholder, &mut jumbf_bytes, format)
    }

    /// Returns the supplied manifest composed to be directly compatible with the desired format.
    /// For example, if format is JPEG function will return the set of APP11 segments that contains
    /// the manifest.  Similarly for PNG it would be the PNG chunk complete with header and  CRC.
    pub fn get_composed_manifest(manifest_bytes: &[u8], format: &str) -> Result<Vec<u8>> {
        if let Some(h) = get_assetio_handler(format) {
            if let Some(composed_data_handler) = h.composed_data_ref() {
                return composed_data_handler.compose_manifest(manifest_bytes, format);
            }
        }
        Err(Error::UnsupportedType)
    }

    #[cfg(feature = "file_io")]
    fn start_save_bmff_fragmented(
        &mut self,
        asset_path: &Path,
        fragments: &Vec<std::path::PathBuf>,
        output_dir: &Path,
        reserve_size: usize,
        settings: &Settings,
    ) -> Result<Vec<u8>> {
        // get the provenance claim changing mutability
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.clear_data(); // clear since we are reusing an existing claim

        let output_filename = asset_path.file_name().ok_or(Error::NotFound)?;
        let dest_path = output_dir.join(output_filename);

        let mut data;

        // 2) Get hash ranges if needed
        let mut bmff_hash = Store::generate_bmff_data_hash_for_stream(pc.alg())?;

        bmff_hash.clear_hash();
        if pc.version() < 2 {
            bmff_hash.set_bmff_version(2); // backcompat support
        }

        // generate fragments and produce Merkle tree
        bmff_hash.add_merkle_for_fragmented(
            settings.core.merkle_tree_max_proofs,
            pc.alg(),
            asset_path,
            fragments,
            output_dir,
            1,
            None,
        )?;

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

        Ok(data) // return JUMBF data
    }

    /// Embed the claims store as jumbf into fragmented assets.
    #[cfg(feature = "file_io")]
    pub fn save_to_bmff_fragmented(
        &mut self,
        asset_path: &Path,
        fragments: &Vec<std::path::PathBuf>,
        output_path: &Path,
        signer: &dyn Signer,
        context: &Context,
    ) -> Result<()> {
        match get_supported_file_extension(asset_path) {
            Some(ext) => {
                if !is_bmff_format(&ext) {
                    return Err(Error::UnsupportedType);
                }
            }
            None => return Err(Error::UnsupportedType),
        }

        let output_filename = asset_path.file_name().ok_or(Error::NotFound)?;
        let dest_path = output_path.join(output_filename);

        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        // add dynamic assertions to the store
        let dynamic_assertions = signer.dynamic_assertions();
        let _ = self.add_dynamic_assertion_placeholders(&dynamic_assertions)?;

        // get temp store as JUMBF
        let jumbf = self.to_jumbf(signer)?;

        // use temp store so mulitple calls across renditions will work (the Store is not finalized this way)
        let mut temp_store = Store::from_jumbf_with_context(&jumbf, &mut validation_log, context)?;

        let mut jumbf_bytes = temp_store.start_save_bmff_fragmented(
            asset_path,
            fragments,
            output_path,
            signer.reserve_size(),
            context.settings(),
        )?;

        let mut preliminary_claim = PartialClaim::default();
        {
            let pc = temp_store.provenance_claim().ok_or(Error::ClaimEncoding)?;
            for assertion in pc.assertions() {
                preliminary_claim.add_assertion(assertion);
            }
        }

        // Now add the dynamic assertions and update the JUMBF.
        let modified =
            temp_store.write_dynamic_assertions(&dynamic_assertions, &mut preliminary_claim)?;

        // update the JUMBF if modified with dynamic assertions
        if modified {
            let pc = temp_store.provenance_claim().ok_or(Error::ClaimEncoding)?;
            match pc.remote_manifest() {
                RemoteManifest::NoRemote | RemoteManifest::EmbedWithRemote(_) => {
                    jumbf_bytes = temp_store.to_jumbf_internal(signer.reserve_size())?;

                    // save the jumbf to the output path
                    save_jumbf_to_file(&jumbf_bytes, &dest_path, Some(&dest_path))?;

                    let pc = temp_store
                        .provenance_claim_mut()
                        .ok_or(Error::ClaimEncoding)?;
                    // generate actual hash values
                    let bmff_hashes = pc.bmff_hash_assertions();

                    if !bmff_hashes.is_empty() {
                        let mut bmff_hash = BmffHash::from_assertion(bmff_hashes[0].assertion())?;
                        bmff_hash.update_fragmented_inithash(&dest_path)?;
                        pc.update_bmff_hash(bmff_hash)?;
                    }

                    // regenerate the jumbf because the cbor changed
                    jumbf_bytes = temp_store.to_jumbf_internal(signer.reserve_size())?;
                }
                _ => (),
            };
        }

        // sign the claim
        let pc = temp_store.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = temp_store.sign_claim(pc, signer, signer.reserve_size(), context.settings())?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        match temp_store.finish_save(jumbf_bytes, &dest_path, sig, &sig_placeholder) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
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
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn AsyncSigner,
        context: &Context,
    ))]
    pub(crate) fn save_to_stream(
        &mut self,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
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

        let mut intermediate_stream = io_utils::stream_with_fs_fallback(threshold);

        #[allow(unused_mut)] // Not mutable in the non-async case.
        let mut jumbf_bytes = self.start_save_stream(
            format,
            input_stream,
            &mut intermediate_stream,
            signer.reserve_size(),
            settings,
            context,
        )?;

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
        // update the JUMBF if modified with dynamic assertions
        if modified {
            let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
            match pc.remote_manifest() {
                RemoteManifest::NoRemote | RemoteManifest::EmbedWithRemote(_) => {
                    jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;

                    intermediate_stream.rewind()?;
                    save_jumbf_to_stream(
                        format,
                        &mut intermediate_stream,
                        output_stream,
                        &jumbf_bytes,
                    )?;
                }
                RemoteManifest::SideCar | RemoteManifest::Remote(_) => {
                    // we are going to handle the JUMBF like we'd embed, but we won't
                    // eventually we won't embed it, so this is a temporary hack to get the code to work

                    // Update the JUMBF like it would normally be done
                    jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;

                    // Intermediate stream goes to output, but still no embedding
                    intermediate_stream.rewind()?;
                    //std::io::copy(&mut intermediate_stream, output_stream)?;
                }
            };
            output_stream.rewind()?;
        }

        context.check_progress(ProgressPhase::Signing, 1, 1)?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = if _sync {
            self.sign_claim(pc, signer, signer.reserve_size(), settings)
        } else {
            self.sign_claim_async(pc, signer, signer.reserve_size(), settings)
                .await
        }?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        intermediate_stream.rewind()?;
        output_stream.rewind()?;
        match self.finish_save_stream(
            jumbf_bytes,
            format,
            &mut intermediate_stream,
            output_stream,
            sig,
            &sig_placeholder,
        ) {
            Ok((s, m)) => {
                // save sig so store is up to date
                let pc_mut = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc_mut.set_signature_val(s);

                output_stream.flush()?;
                output_stream.rewind()?;

                context.check_progress(ProgressPhase::Embedding, 1, 1)?;

                let verify_after_sign = settings.verify.verify_after_sign;
                // Also catch the case where we may have written to io::empty() or similar
                if verify_after_sign && output_stream.seek(SeekFrom::End(0))? > 0 {
                    // verify the store
                    let mut validation_log =
                        StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
                    if _sync {
                        Store::verify_store(
                            self,
                            &mut crate::claim::ClaimAssetData::Stream(output_stream, format),
                            &mut validation_log,
                            context,
                        )?;
                    } else {
                        Store::verify_store_async(
                            self,
                            &mut crate::claim::ClaimAssetData::Stream(output_stream, format),
                            &mut validation_log,
                            context,
                        )
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
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        reserve_size: usize,
        settings: &Settings,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let threshold = settings.core.backing_store_memory_threshold_in_mb;

        let mut intermediate_stream = io_utils::stream_with_fs_fallback(threshold);

        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // Add remote reference XMP if needed and strip out existing manifest
        // We don't need to strip manifests if we are replacing an existing one
        let (url, remove_manifests) = match pc.remote_manifest() {
            RemoteManifest::NoRemote => (None, false),
            RemoteManifest::SideCar => (None, true),
            RemoteManifest::Remote(url) => (Some(url), true),
            RemoteManifest::EmbedWithRemote(url) => (Some(url), false),
        };

        let io_handler = get_assetio_handler(format).ok_or(Error::UnsupportedType)?;

        // Do not assume the handler supports XMP or removing manifests unless we need it to
        if let Some(url) = url {
            let external_ref_writer = io_handler
                .remote_ref_writer_ref()
                .ok_or(Error::XmpNotSupported)?;

            if remove_manifests {
                let manifest_writer = io_handler
                    .get_writer(format)
                    .ok_or(Error::UnsupportedType)?;

                let mut tmp_stream = io_utils::stream_with_fs_fallback(threshold);
                manifest_writer.remove_cai_store_from_stream(input_stream, &mut tmp_stream)?;

                // add external ref if possible
                tmp_stream.rewind()?;
                external_ref_writer.embed_reference_to_stream(
                    &mut tmp_stream,
                    &mut intermediate_stream,
                    RemoteRefEmbedType::Xmp(url),
                )?;
            } else {
                // add external ref if possible
                external_ref_writer.embed_reference_to_stream(
                    input_stream,
                    &mut intermediate_stream,
                    RemoteRefEmbedType::Xmp(url),
                )?;
            }
        } else if remove_manifests {
            let manifest_writer = io_handler
                .get_writer(format)
                .ok_or(Error::UnsupportedType)?;

            manifest_writer.remove_cai_store_from_stream(input_stream, &mut intermediate_stream)?;
        } else {
            // just clone stream
            input_stream.rewind()?;
            std::io::copy(input_stream, &mut intermediate_stream)?;
        }

        let is_bmff = is_bmff_format(format);

        let mut data;
        let jumbf_size;

        if is_bmff {
            // 2) Get hash ranges if needed, do not generate for update manifests
            let mut needs_hash = false;
            if !pc.update_manifest() && pc.bmff_hash_assertions().is_empty() {
                intermediate_stream.rewind()?;
                let mut bmff_hash = Store::generate_bmff_data_hash_for_stream(pc.alg())?;

                if pc.version() < 2 {
                    bmff_hash.set_bmff_version(2); // backcompat support
                }

                // add Merkle mdats if requested
                Store::generate_bmff_mdat_hashes(
                    &mut intermediate_stream,
                    &mut bmff_hash,
                    settings,
                )?;

                // insert Merkle UUID boxes at the correct location if required
                if let Some(merkle_uuid_boxes) = &bmff_hash.merkle_uuid_boxes {
                    let mut temp_stream = io_utils::stream_with_fs_fallback(threshold);
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
                intermediate_stream.rewind()?;
                save_jumbf_to_stream(format, &mut intermediate_stream, output_stream, &data)?;
            } else {
                // just copy the asset to the output stream without an embedded manifest (may be stripping one out here)
                intermediate_stream.rewind()?;
                std::io::copy(&mut intermediate_stream, output_stream)?;
            }

            // Signal that the write pass is done; hash readback begins next.
            context.check_progress(ProgressPhase::Writing, 1, 1)?;

            // generate actual hash values
            let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?; // reborrow to change mutability

            if !pc.update_manifest() {
                let bmff_hashes = pc.bmff_hash_assertions();

                if !bmff_hashes.is_empty() && needs_hash {
                    let mut bmff_hash = BmffHash::from_assertion(bmff_hashes[0].assertion())?;

                    output_stream.rewind()?;
                    let mut cb =
                        |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
                    bmff_hash.gen_hash_from_stream_with_progress(output_stream, Some(&mut cb))?;
                    pc.update_bmff_hash(bmff_hash)?;
                }
            }
        } else {
            // we will not do automatic hashing if we detect a box hash present
            let mut needs_hashing = false;
            if pc.hash_assertions().is_empty() {
                // 2) Get hash ranges if needed, do not generate for update manifests
                let mut hash_ranges =
                    object_locations_from_stream(format, &mut intermediate_stream)?;
                let hashes: Vec<DataHash> = if pc.update_manifest() {
                    Vec::new()
                } else {
                    Store::generate_data_hashes_for_stream(
                        &mut intermediate_stream,
                        pc.alg(),
                        &mut hash_ranges,
                        false,
                        None,
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

            // write the jumbf to the output stream if we are embedding the manifest
            if !remove_manifests {
                intermediate_stream.rewind()?;
                save_jumbf_to_stream(format, &mut intermediate_stream, output_stream, &data)?;
            } else {
                // just copy the asset to the output stream without an embedded manifest (may be stripping one out here)
                intermediate_stream.rewind()?;
                std::io::copy(&mut intermediate_stream, output_stream)?;
            }

            // Signal that the asset write pass is complete, before the hash
            // readback pass begins.  This separates "Writing" (streaming
            // input → output with placeholder JUMBF) from "Hashing" (reading
            // output to compute the final content-hash binding).
            context.check_progress(ProgressPhase::Writing, 1, 1)?;

            // 4)  determine final object locations and patch the asset hashes with correct offset
            // replace the source with correct asset hashes so that the claim hash will be correct
            if needs_hashing {
                let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

                // get the final hash ranges, but not for update manifests
                output_stream.rewind()?;
                let mut new_hash_ranges = object_locations_from_stream(format, output_stream)?;
                if !pc.update_manifest() {
                    // if we removed the manifest fixup the hash range to be empty
                    if remove_manifests {
                        new_hash_ranges.iter_mut().for_each(|h| {
                            if h.htype == HashBlockObjectType::Cai
                                || h.htype == HashBlockObjectType::OtherExclusion
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
                        Some(&mut cb),
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
        mut jumbf_bytes: Vec<u8>,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        sig: Vec<u8>,
        sig_placeholder: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        // re-save to file
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        match pc.remote_manifest() {
            RemoteManifest::NoRemote | RemoteManifest::EmbedWithRemote(_) => {
                save_jumbf_to_stream(format, input_stream, output_stream, &jumbf_bytes)?;
            }
            RemoteManifest::SideCar | RemoteManifest::Remote(_) => {
                // just copy the asset to the output stream without an embedded manifest (may be stripping one out here)
                std::io::copy(input_stream, output_stream)?;
            }
        }

        output_stream.flush()?;
        Ok((sig, jumbf_bytes))
    }

    #[cfg(feature = "file_io")]
    fn finish_save(
        &self,
        mut jumbf_bytes: Vec<u8>,
        output_path: &Path,
        sig: Vec<u8>,
        sig_placeholder: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        // re-save to file
        save_jumbf_to_file(&jumbf_bytes, output_path, Some(output_path))?;

        Ok((sig, jumbf_bytes))
    }

    /// Verify Store from an existing asset
    /// asset_path: path to input asset
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned
    #[cfg(feature = "file_io")]
    pub fn verify_from_path(
        &mut self,
        asset_path: &'_ Path,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<()> {
        Store::verify_store(
            self,
            &mut ClaimAssetData::Path(asset_path),
            validation_log,
            context,
        )
    }

    // fetch remote manifest if possible
    #[cfg(feature = "fetch_remote_manifests")]
    #[async_generic]
    fn fetch_remote_manifest(url: &str, context: &Context) -> Result<Vec<u8>> {
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
        stream: &mut dyn CAIRead,
        context: &Context
    ))]
    pub fn load_jumbf_from_stream(
        asset_type: &str,
        stream: &mut dyn CAIRead,
        context: &Context,
    ) -> Result<(Vec<u8>, Option<String>)> {
        match load_jumbf_from_stream(asset_type, stream) {
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

    /// load jumbf given a file path
    ///
    /// This handles, embedded, sidecar and remote manifests
    ///
    /// in_path -  path to source file
    /// validation_log - optional vec to contain addition info about the asset
    #[cfg(feature = "file_io")]
    pub fn load_jumbf_from_path(in_path: &Path, context: &Context) -> Result<Vec<u8>> {
        let external_manifest = in_path.with_extension(MANIFEST_STORE_EXT);
        let external_exists = external_manifest.exists();

        match load_jumbf_from_file(in_path) {
            Ok(manifest_bytes) => Ok(manifest_bytes),
            Err(Error::UnsupportedType) => {
                if external_exists {
                    std::fs::read(external_manifest).map_err(Error::IoError)
                } else {
                    Err(Error::UnsupportedType)
                }
            }
            Err(Error::JumbfNotFound) => {
                if external_exists {
                    std::fs::read(external_manifest).map_err(Error::IoError)
                } else {
                    // check for remote manifest
                    let mut asset_reader = std::fs::File::open(in_path)?;
                    let ext = get_file_extension(in_path).ok_or(Error::UnsupportedType)?;
                    if let Some(ext_ref) = crate::utils::xmp_inmemory_utils::XmpInfo::from_source(
                        &mut asset_reader,
                        &ext,
                    )
                    .provenance
                    {
                        Store::handle_remote_manifest(&ext_ref, context)
                    } else {
                        Err(Error::JumbfNotFound)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Returns embedded remote manifest URL if available
    /// asset_type: extensions or mime type of the data
    /// data: byte array containing the asset
    #[allow(unused)]
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

        let store = if _sync {
            Self::from_manifest_data_and_stream(
                &manifest_bytes,
                format,
                &mut stream,
                validation_log,
                context,
            )
        } else {
            Self::from_manifest_data_and_stream_async(
                &manifest_bytes,
                format,
                &mut stream,
                validation_log,
                context,
            )
            .await
        };

        let mut store = store?;
        if remote_url.is_none() {
            store.embedded = true;
        } else {
            store.remote_url = remote_url;
        }

        Ok(store)
    }

    /// Load store from a manifest data and stream
    #[async_generic]
    pub fn from_manifest_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        mut stream: impl Read + Seek + MaybeSend,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Self> {
        stream.rewind()?;

        // First we convert the JUMBF into a usable store.
        let store = Store::from_jumbf_with_context(c2pa_data, validation_log, context)
            .inspect_err(|e| {
                log_item!("asset", "error loading file", "load_from_asset")
                    .failure_no_throw(validation_log, e);
            })?;

        if context.settings().verify.verify_after_reading {
            stream.rewind()?;
            let mut asset_data = ClaimAssetData::Stream(&mut stream, format);
            if _sync {
                Store::verify_store(&store, &mut asset_data, validation_log, context)
            } else {
                Store::verify_store_async(&store, &mut asset_data, validation_log, context).await
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
        init_segment: &mut dyn CAIRead,
        fragments: &Vec<PathBuf>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Store> {
        let verify = context.settings().verify.verify_after_reading;
        let (manifest_bytes, remote_url) =
            Store::load_jumbf_from_stream(asset_type, &mut *init_segment, context)?;
        let mut store = Store::from_jumbf_with_context(&manifest_bytes, validation_log, context)?;
        if remote_url.is_none() {
            store.embedded = true;
        } else {
            store.remote_url = remote_url;
        }

        // verify the store
        if verify {
            init_segment.rewind()?;
            // verify store and claims
            Store::verify_store(
                &store,
                &mut ClaimAssetData::StreamFragments(init_segment, fragments, asset_type),
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
                Store::verify_store(&store, &mut fragment, validation_log, context)
            } else {
                Store::verify_store_async(&store, &mut fragment, validation_log, context).await
            }?;
        };
        Ok(store)
    }
}

use crate::utils::patch::patch_bytes;
