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

use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Seek},
};

use async_generic::async_generic;

use super::store_core::MAX_INGREDIENT_DEPTH;
use crate::{
    assertion::AssertionBase,
    assertions::{CertificateStatus, Ingredient, Relationship, TimeStamp},
    asset_io::ObjectType,
    claim::{Claim, ClaimAssetData},
    context::{Context, ProgressPhase},
    crypto::{
        asn1::rfc3161::TstInfo,
        cose::{cert_chain_from_sign1, CertificateTrustPolicy},
        ocsp::OcspResponse,
        time_stamp::verify_time_stamp,
    },
    error::{Error, Result},
    hash_utils::{vec_compare, verify_by_alg},
    jumbf,
    jumbf::labels::to_manifest_uri,
    log_item,
    status_tracker::StatusTracker,
    store::Store,
    utils::{hash_utils::HashRange, is_zero},
    validation_status, ValidationResults, ValidationState,
};

// internal struct to pass around info needed to optimally complete validation
#[derive(Default)]
pub(crate) struct StoreValidationInfo<'a> {
    pub redactions: Vec<String>, // list of redactions found in claim hierarchy
    pub ingredient_references: HashMap<String, HashSet<String>>, // mapping in ingredients to list of claims that reference it
    pub manifest_map: HashMap<String, &'a Claim>, // list of the addressable items in ingredient, saves re-parsing the items during validation
    pub binding_claim: String,                    // name of the claim that has the hash binding
    pub timestamps: HashMap<String, TstInfo>,     // list of timestamp assertions for each claim
    pub update_manifest_label: Option<String>,    // label of the update manifest if it exists
    pub manifest_store_range: Option<HashRange>, // range of the manifest store in the asset for data hash exclusions
    pub certificate_statuses: HashMap<String, Vec<Vec<u8>>>, // list of certificate status assertions for each serial
    pub is_embedded: bool, // whether the manifest was read out of the asset being validated, vs. supplied separately (sidecar/remote)
}

impl Store {
    pub(crate) fn trusted_cawg_timestamp_for_assertion(
        &self,
        claim: &Claim,
        assertion_label: &str,
        validation_log: &mut StatusTracker,
    ) -> Result<Option<TstInfo>> {
        use crate::crypto::cose::{trusted_cawg_timestamp, trusted_cawg_timestamp_token, Verifier};

        let Some((signed_uri, _)) = claim.assertion_hashed_uri_from_label(assertion_label) else {
            return Ok(None);
        };
        let local_reference = crate::jumbf::labels::manifest_label_from_uri(&signed_uri.url())
            .is_none_or(|label| label == claim.label());
        if !local_reference
            || claim.get_claim_assertion_hash(assertion_label).as_deref()
                != Some(signed_uri.hash().as_slice())
        {
            // Claim validation already reports the assertion hash mismatch.
            return Ok(None);
        }

        let data = claim.data()?;
        // The timestamp attests to the claim signature, not directly to the
        // identity assertion. Verify that signature before reusing its time.
        let mut signature_log = StatusTracker::default();
        if Verifier::IgnoreProfileAndTrustPolicy
            .verify_signature(claim.signature_val(), &data, &[], None, &mut signature_log)
            .is_err()
        {
            log_item!(
                "",
                "manifest signature cannot establish the CAWG signing time",
                "trusted_cawg_timestamp_for_claim"
            )
            .validation_status("cawg.x509.time_stamp.mismatch")
            .informational(validation_log);
            return Ok(None);
        }

        let sign1 = claim.cose_sign1()?;
        if let Some(timestamp) = trusted_cawg_timestamp(&sign1, &data, &self.ctp, validation_log) {
            return Ok(Some(timestamp));
        }

        for source_claim in self.claims() {
            for assertion in source_claim.timestamp_assertions() {
                let timestamps = match TimeStamp::from_assertion(assertion.assertion()) {
                    Ok(timestamps) => timestamps,
                    Err(_) => {
                        log_item!(
                            assertion.label(),
                            "timestamp assertion malformed",
                            "trusted_cawg_timestamp_for_claim"
                        )
                        .validation_status("cawg.x509.time_stamp.malformed")
                        .informational(validation_log);
                        continue;
                    }
                };
                if let Some(token) = timestamps.as_ref().get(claim.label()) {
                    if let Some(timestamp) = trusted_cawg_timestamp_token(
                        token,
                        &sign1.signature,
                        &self.ctp,
                        validation_log,
                    ) {
                        return Ok(Some(timestamp));
                    }
                }
            }
        }

        Ok(None)
    }

    // Returns the timestamp info only if the token validates for the claim's signature.
    pub(crate) fn verified_timestamp_for_claim(
        claim: &Claim,
        time_stamp_token: &[u8],
        ctp: &CertificateTrustPolicy,
    ) -> Option<TstInfo> {
        let sign1 = claim.cose_sign1().ok()?;
        verify_time_stamp(
            time_stamp_token,
            &sign1.signature,
            ctp,
            &mut StatusTracker::default(),
            // no trust checks for legacy timestamps
            claim.version() != 1,
        )
        .ok()
    }

    // recursively walk the ingredients and validate
    #[async_generic]
    pub(super) fn ingredient_checks(
        store: &Store,
        claim: &Claim,
        svi: &StoreValidationInfo<'_>,
        validation_log: &mut StatusTracker,
        depth: usize,
        context: &Context,
        visited: &mut HashSet<String>,
    ) -> Result<()> {
        if depth >= MAX_INGREDIENT_DEPTH {
            return Err(Error::InvalidAsset(format!(
                "ingredient chain depth ({depth}) exceeds maximum ({MAX_INGREDIENT_DEPTH})"
            )));
        }

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

            if ingredient_assertion.active_manifest.is_some()
                && ingredient_assertion.digital_source_type.is_some()
            {
                log_item!(
                            jumbf::labels::to_assertion_uri(claim.label(), &i.label()),
                            "ingredient assertion cannot have both activeManifest and digitalSourceType",
                            "ingredient_checks"
                        )
                        .validation_status(validation_status::ASSERTION_INGREDIENT_MALFORMED)
                        .failure(
                            validation_log,
                            Error::ValidationRule(
                                "ingredient assertion cannot have both activeManifest and digitalSourceType".to_string(),
                            ),
                        )?;
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
                            Error::ValidationRule(
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

                    // Only ingredient assertions v3 and later support claimSignature.
                    // Require it regardless of the child claim version.
                    if !manifests_match && has_redactions && ingredient_assertion.version >= 3 {
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
                                    Error::ValidationRule(
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
                                Error::ValidationRule(
                                    "ingredient claimSignature mismatch".to_string(),
                                ),
                            )?;
                        }
                    }

                    if _sync {
                        Claim::verify_claim(
                            ingredient,
                            svi,
                            check_ingredient_trust,
                            &store.ctp,
                            validation_log,
                            context,
                        )?;
                    } else {
                        Claim::verify_claim_async(
                            ingredient,
                            svi,
                            check_ingredient_trust,
                            &store.ctp,
                            validation_log,
                            context,
                        )
                        .await?;
                    }

                    // Referenced ingredients (subgraphs) get verified once per store verify.
                    if visited.insert(ingredient.label().to_owned()) {
                        if _sync {
                            Store::ingredient_checks(
                                store,
                                ingredient,
                                svi,
                                validation_log,
                                depth.saturating_add(1),
                                context,
                                visited,
                            )?;
                        } else {
                            Box::pin(Store::ingredient_checks_async(
                                store,
                                ingredient,
                                svi,
                                validation_log,
                                depth.saturating_add(1),
                                context,
                                visited,
                            ))
                            .await?;
                        }
                    }
                } else {
                    log_item!(label.clone(), "ingredient not found", "ingredient_checks")
                        .validation_status(validation_status::INGREDIENT_MANIFEST_MISSING)
                        .failure(
                            validation_log,
                            Error::ClaimVerification(format!("ingredient: {label} is missing")),
                        )?;
                }
            } else if ingredient_assertion.relationship != Relationship::InputTo {
                // Per C2PA spec 15.11.3.3, record an unknownProvenance code for an
                // ingredient without provenance, unless its relationship is inputTo.
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
        asset_data: Option<&mut ClaimAssetData<'_>>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<StoreValidationInfo<'a>> {
        let io = context.io();
        let mut svi = StoreValidationInfo {
            is_embedded: self.embedded,
            ..Default::default()
        };
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
        if let Some(asset_data) = asset_data {
            let locations = match asset_data {
                #[cfg(feature = "file_io")]
                ClaimAssetData::Path(path) => {
                    let format = io.supported_extension(path).ok_or(Error::UnsupportedType)?;
                    let mut reader = std::fs::File::open(path)?;

                    io.object_locations(&format, &mut reader)
                }
                ClaimAssetData::Bytes(items, typ) => {
                    let format = typ.to_owned();
                    let mut reader = Cursor::new(items);

                    io.object_locations(&format, &mut reader)
                }
                ClaimAssetData::Stream(reader, typ) => {
                    let format = typ.to_owned();
                    let positions = io.object_locations(&format, reader);
                    reader.rewind()?;
                    positions
                }
                ClaimAssetData::StreamFragment(reader, _read1, typ) => {
                    let format = typ.to_owned();
                    io.object_locations(&format, reader)
                }
                #[cfg(feature = "file_io")]
                ClaimAssetData::StreamFragments(reader, _path_bufs, typ) => {
                    let format = typ.to_owned();
                    io.object_locations(&format, reader)
                }
            };

            if let Ok(locations) = locations {
                if let Some(manifest_loc) = locations.iter().find(|o| o.htype == ObjectType::C2pa) {
                    svi.manifest_store_range =
                        Some(HashRange::new(manifest_loc.offset, manifest_loc.length));
                }
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
                    if let Some(rc) = svi.manifest_map.get(referenced_claim) {
                        if let Some(tst_info) =
                            Self::verified_timestamp_for_claim(rc, time_stamp_token, &self.ctp)
                        {
                            svi.timestamps.insert(rc.label().to_owned(), tst_info);
                        }
                    }
                }
            }

            // get the certificate status assertions
            let certificate_status_assertions = found_claim.certificate_status_assertions();
            for csa in certificate_status_assertions {
                let certificate_status_assertion =
                    CertificateStatus::from_assertion(csa.assertion())?;

                // The certificate status assertion carries OCSP responses for
                // this manifest's own signing certificate, so bind each
                // response to that certificate's chain (RFC 6960 §4.1.1).
                let signing_cert_chain = found_claim
                    .cose_sign1()
                    .ok()
                    .and_then(|sign1| cert_chain_from_sign1(&sign1).ok())
                    .unwrap_or_default();

                // save the ocsp_ders stored in the StoreValidationInfo
                for ocsp_der in certificate_status_assertion.as_ref() {
                    // Collect evidence without reporting a current-time verdict.
                    // Claim verification selects the source and evaluates it at signing time.
                    let checked = OcspResponse::from_der_checked(
                        ocsp_der,
                        &signing_cert_chain,
                        None,
                        &mut StatusTracker::default(),
                    );

                    if let Ok(response) = checked {
                        let ocsp_ders = svi
                            .certificate_statuses
                            .entry(response.certificate_serial_num)
                            .or_default();
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
        mut asset_data: Option<&mut ClaimAssetData<'_>>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ))]
    pub fn verify_store(
        store: &Store,
        mut asset_data: Option<&mut ClaimAssetData<'_>>,
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
        let svi = store.get_store_validation_info(
            claim,
            asset_data.as_deref_mut(),
            validation_log,
            context,
        )?;

        // Per spec §15.11.3.3.1, any box present at a redacted URI must contain only 0x00
        // bytes, regardless of its JUMBF type — reject with `assertion.notRedacted` otherwise.
        // This is driven by the redaction list (not the box type), and is the compensating
        // control for suppressing the ingredient manifest hash mismatch in `ingredient_checks`:
        // without it, forged content planted in a redacted slot would surface as a genuine,
        // hash-unverified assertion.
        for redacted_uri in &svi.redactions {
            // A fully removed assertion (resolution fails) is a valid form of redaction;
            // only a *present* box with non-zero content is a violation.
            if let Ok(claim_assertion) = store.get_claim_assertion_from_uri(redacted_uri) {
                if !is_zero(claim_assertion.assertion().data()) {
                    log_item!(
                        redacted_uri.clone(),
                        "redacted assertion data must be zeros or empty",
                        "verify_store"
                    )
                    .validation_status(validation_status::ASSERTION_NOT_REDACTED)
                    .failure(
                        validation_log,
                        Error::OtherError("redacted assertion data must be zeros or empty".into()),
                    )?;
                }
            }
        }

        // keep track of already verified ingredients
        let mut visited = HashSet::new();
        visited.insert(claim.label().to_owned());

        if _sync {
            // verify the provenance claim
            Claim::verify_claim(claim, &svi, true, &store.ctp, validation_log, context)?;

            Store::ingredient_checks(store, claim, &svi, validation_log, 0, context, &mut visited)?;
        } else {
            Claim::verify_claim_async(claim, &svi, true, &store.ctp, validation_log, context)
                .await?;

            Store::ingredient_checks_async(
                store,
                claim,
                &svi,
                validation_log,
                0,
                context,
                &mut visited,
            )
            .await?;
        }

        // verify the asset hash binding once for the whole store, on the binding manifest
        if let Some(data) = asset_data {
            if let Some(binding_claim) = store.get_claim(&svi.binding_claim) {
                Claim::verify_hash_binding(binding_claim, data, &svi, validation_log, context)?;
            }
        }

        Ok(())
    }

    /// Verifies the store and returns [`Error::InvalidManifest`] if the validation state is
    /// invalid. Pass `asset_data` to also verify hash bindings against the asset.
    #[async_generic(async_signature(
        &mut self,
        asset_data: Option<&mut ClaimAssetData<'_>>,
        context: &Context,
    ))]
    pub(crate) fn verify_store_strict(
        &mut self,
        asset_data: Option<&mut ClaimAssetData<'_>>,
        context: &Context,
    ) -> Result<()> {
        let mut validation_log = StatusTracker::default();
        if _sync {
            Store::verify_store(self, asset_data, &mut validation_log, context)?;
        } else {
            Store::verify_store_async(self, asset_data, &mut validation_log, context).await?;
        }

        let validation_results = ValidationResults::from_store(self, &validation_log);
        if validation_results.validation_state() == ValidationState::Invalid {
            return Err(Error::InvalidManifest(Box::new(validation_results)));
        }

        Ok(())
    }
}

#[cfg(test)]
mod ocsp_reporting_tests {
    #![allow(clippy::unwrap_used)]

    use coset::{cbor::value::Value, CoseSign1, Label, TaggedCborSerializable};

    use super::*;
    use crate::{
        assertions::DataHash,
        cose_validator::{check_ocsp_status, check_ocsp_status_async, get_signing_cert_serial_num},
        crypto::{
            asn1::{rfc3161::MessageImprint, AlgorithmIdentifier, GeneralizedTime},
            cert_chain_pem_to_der,
            ocsp::test_responder::{encode_response, good_basic_response},
        },
        settings::Settings,
        utils::test::create_test_claim,
    };

    const GOOD: &[u8] = include_bytes!("../../tests/fixtures/crypto/ocsp/response_good.der");
    const REVOKED: &[u8] = include_bytes!("../../tests/fixtures/crypto/ocsp/response_revoked.der");

    fn context(override_assertion: bool) -> Context {
        let mut settings = Settings::default();
        settings.verify.ocsp_fetch = false;
        settings.verify.ocsp_fetch_should_override = false;
        settings.builder.certificate_status_should_override = Some(override_assertion);
        Context::new().with_settings(settings).unwrap()
    }

    fn store(responses: Vec<Vec<u8>>, staple: Option<&[u8]>, context: &Context) -> Store {
        let chain = cert_chain_pem_to_der(include_bytes!(
            "../../tests/fixtures/crypto/ocsp/ocsp_chain.pem"
        ))
        .unwrap();
        // Only the COSE headers are needed at this collection/OCSP boundary.
        // The OCSP responses themselves retain their real signatures.
        let mut sign1 = CoseSign1 {
            protected: coset::ProtectedHeader::default(),
            unprotected: coset::Header::default(),
            payload: None,
            signature: vec![0; 8],
        };
        sign1.unprotected.rest.push((
            Label::Text("x5chain".into()),
            Value::Array(chain.into_iter().map(Value::Bytes).collect()),
        ));

        if let Some(staple) = staple {
            sign1.unprotected.rest.push((
                Label::Text("rVals".into()),
                Value::Map(vec![(
                    Value::Text("ocspVals".into()),
                    Value::Array(vec![Value::Bytes(staple.to_vec())]),
                )]),
            ));
        }

        let mut claim = create_test_claim().unwrap();
        claim
            .add_assertion(&DataHash::new("test asset", "sha256"))
            .unwrap();
        claim
            .add_assertion(&CertificateStatus::new(responses))
            .unwrap();
        claim.set_signature_val(sign1.to_tagged_vec().unwrap());
        let mut store = Store::from_context(context);
        store.commit_claim(claim).unwrap();
        store
            .ctp
            .add_end_entity_credentials(include_bytes!(
                "../../tests/fixtures/crypto/ocsp/ocsp_responder.pem"
            ))
            .unwrap();
        store
    }

    fn signing_timestamp() -> TstInfo {
        // StoreValidationInfo holds already verified timestamps; timestamp
        // authentication is covered separately by verified_timestamp_for_claim.
        TstInfo {
            version: bcder::Integer::from(1u8),
            policy: "1.2.3.4".parse().unwrap(),
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifier {
                    algorithm: "2.16.840.1.101.3.4.2.1".parse().unwrap(),
                },
                hashed_message: bcder::OctetString::new(bytes::Bytes::from_static(&[0; 32])),
            },
            serial_number: bcder::Integer::from(1u8),
            gen_time: GeneralizedTime::from_der_bytes(b"\x18\x0f20250307150000Z").unwrap(),
            accuracy: None,
            ordering: None,
            nonce: None,
            tsa: None,
            extensions: None,
        }
    }

    #[async_generic]
    fn evaluate(
        store: &Store,
        svi: &StoreValidationInfo<'_>,
        log: &mut StatusTracker,
        context: &Context,
    ) -> Result<OcspResponse> {
        let claim = store.provenance_claim().unwrap();
        let sign1 = claim.cose_sign1().unwrap();
        let serial = get_signing_cert_serial_num(&sign1).unwrap().to_string();
        log.push_current_uri(claim.signature_uri());
        let data = claim.data().unwrap();
        let result = if _sync {
            check_ocsp_status(
                &sign1,
                &data,
                &store.ctp,
                svi.certificate_statuses.get(&serial),
                svi.timestamps.get(claim.label()),
                log,
                context,
            )
        } else {
            check_ocsp_status_async(
                &sign1,
                &data,
                &store.ctp,
                svi.certificate_statuses.get(&serial),
                svi.timestamps.get(claim.label()),
                log,
                context,
            )
            .await
        };
        log.pop_current_uri();
        result
    }

    fn assert_only_status(log: &StatusTracker, store: &Store, status: &str) {
        let statuses: Vec<_> = log
            .logged_items()
            .iter()
            .filter(|item| item.validation_status.is_some())
            .collect();
        assert_eq!(statuses.len(), 1, "{statuses:#?}");
        assert_eq!(statuses[0].validation_status.as_deref(), Some(status));
        assert_eq!(
            statuses[0].label,
            store.provenance_claim().unwrap().signature_uri()
        );
    }

    #[test]
    fn collection_does_not_duplicate_authoritative_revocation() {
        let context = context(true);
        let store = store(vec![REVOKED.to_vec(), REVOKED.to_vec()], None, &context);
        let claim = store.provenance_claim().unwrap();
        let mut log = StatusTracker::default();
        let mut svi = store
            .get_store_validation_info(claim, None, &mut log, &context)
            .unwrap();
        assert!(log.logged_items().is_empty());
        svi.timestamps
            .insert(claim.label().to_owned(), signing_timestamp());

        assert!(evaluate(&store, &svi, &mut log, &context).is_err());
        assert_only_status(&log, &store, validation_status::SIGNING_CREDENTIAL_REVOKED);
    }

    #[test]
    fn stale_good_uses_only_its_claims_signing_time() {
        let context = context(true);
        let store = store(vec![GOOD.to_vec()], None, &context);
        let claim = store.provenance_claim().unwrap();
        let mut log = StatusTracker::default();
        let mut svi = store
            .get_store_validation_info(claim, None, &mut log, &context)
            .unwrap();
        assert!(log.logged_items().is_empty());
        svi.timestamps
            .insert("another claim".into(), signing_timestamp());

        evaluate(&store, &svi, &mut log, &context).unwrap();
        assert!(log.logged_items().is_empty());
        svi.timestamps
            .insert(claim.label().to_owned(), signing_timestamp());

        evaluate(&store, &svi, &mut log, &context).unwrap();
        assert_only_status(
            &log,
            &store,
            validation_status::SIGNING_CREDENTIAL_NOT_REVOKED,
        );
    }

    #[test]
    fn unselected_assertion_does_not_report_revocation() {
        for override_assertion in [false, true] {
            let context = context(override_assertion);
            let store = store(vec![REVOKED.to_vec()], Some(GOOD), &context);
            let claim = store.provenance_claim().unwrap();
            let mut log = StatusTracker::default();
            let mut svi = store
                .get_store_validation_info(claim, None, &mut log, &context)
                .unwrap();
            assert!(log.logged_items().is_empty());
            svi.timestamps
                .insert(claim.label().to_owned(), signing_timestamp());

            if override_assertion {
                assert!(evaluate(&store, &svi, &mut log, &context).is_err());
                assert_only_status(&log, &store, validation_status::SIGNING_CREDENTIAL_REVOKED);
            } else {
                evaluate(&store, &svi, &mut log, &context).unwrap();
                assert_only_status(
                    &log,
                    &store,
                    validation_status::SIGNING_CREDENTIAL_NOT_REVOKED,
                );
            }
        }
    }

    #[test]
    fn malformed_and_unauthenticated_evidence_cannot_report_good() {
        let context = context(true);
        let mut tampered = good_basic_response();
        tampered.tbs_response_data.responses[0]
            .cert_id
            .serial_number = 1.into();
        let store = store(vec![vec![0], encode_response(&tampered)], None, &context);
        let claim = store.provenance_claim().unwrap();
        let mut log = StatusTracker::default();
        let mut svi = store
            .get_store_validation_info(claim, None, &mut log, &context)
            .unwrap();
        assert!(log.logged_items().is_empty());
        let serial = get_signing_cert_serial_num(&claim.cose_sign1().unwrap())
            .unwrap()
            .to_string();
        assert!(!svi.certificate_statuses.contains_key(&serial));
        svi.timestamps
            .insert(claim.label().to_owned(), signing_timestamp());

        evaluate(&store, &svi, &mut log, &context).unwrap();
        assert_only_status(
            &log,
            &store,
            validation_status::SIGNING_CREDENTIAL_OCSP_SKIPPED,
        );
    }

    #[test]
    fn collected_response_still_requires_authoritative_responder_trust() {
        let context = context(true);
        let mut store = store(vec![GOOD.to_vec()], None, &context);
        store.ctp = CertificateTrustPolicy::new();
        let claim = store.provenance_claim().unwrap();
        let mut log = StatusTracker::default();
        let mut svi = store
            .get_store_validation_info(claim, None, &mut log, &context)
            .unwrap();
        let serial = get_signing_cert_serial_num(&claim.cose_sign1().unwrap())
            .unwrap()
            .to_string();
        assert_eq!(svi.certificate_statuses[&serial], vec![GOOD.to_vec()]);
        svi.timestamps
            .insert(claim.label().to_owned(), signing_timestamp());

        evaluate(&store, &svi, &mut log, &context).unwrap();
        assert!(!log.has_status(validation_status::SIGNING_CREDENTIAL_NOT_REVOKED));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn asynchronous_validation_preserves_selection_and_failures() {
        for override_assertion in [false, true] {
            let context = context(override_assertion);
            let store = store(vec![REVOKED.to_vec()], Some(GOOD), &context);
            let claim = store.provenance_claim().unwrap();
            let mut log = StatusTracker::default();
            let mut svi = store
                .get_store_validation_info(claim, None, &mut log, &context)
                .unwrap();
            assert!(log.logged_items().is_empty());
            svi.timestamps
                .insert(claim.label().to_owned(), signing_timestamp());

            let result = evaluate_async(&store, &svi, &mut log, &context).await;
            let expected = if override_assertion {
                assert!(result.is_err());
                validation_status::SIGNING_CREDENTIAL_REVOKED
            } else {
                result.unwrap();
                validation_status::SIGNING_CREDENTIAL_NOT_REVOKED
            };
            assert_only_status(&log, &store, expected);
        }
    }

    #[cfg(feature = "openssl")]
    #[test]
    fn fresh_good_reports_once_after_collection() {
        use chrono::{DateTime, Duration, Utc};

        use crate::crypto::ocsp::test_responder::TestResponder;

        let context = context(true);
        let responder = TestResponder::new();
        let mut basic = good_basic_response();
        let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).unwrap();
        basic.tbs_response_data.produced_at = (now - Duration::hours(1)).fixed_offset();
        basic.tbs_response_data.responses[0].this_update =
            (now - Duration::hours(1)).fixed_offset();
        basic.tbs_response_data.responses[0].next_update =
            Some((now + Duration::hours(24)).fixed_offset());
        let mut store = store(vec![responder.sign(basic)], None, &context);
        store
            .ctp
            .add_end_entity_credentials(&responder.cert_pem())
            .unwrap();
        let claim = store.provenance_claim().unwrap();
        let mut log = StatusTracker::default();
        let svi = store
            .get_store_validation_info(claim, None, &mut log, &context)
            .unwrap();
        assert!(log.logged_items().is_empty());

        evaluate(&store, &svi, &mut log, &context).unwrap();
        assert_only_status(
            &log,
            &store,
            validation_status::SIGNING_CREDENTIAL_NOT_REVOKED,
        );
    }
}
