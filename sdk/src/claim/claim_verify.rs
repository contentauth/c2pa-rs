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

#[cfg(feature = "file_io")]
use std::path::Path;

use async_generic::async_generic;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionData},
    assertions::{
        self, c2pa_action, labels,
        labels::{CLAIM_THUMBNAIL, DATABOX_STORE},
        Actions, BmffHash, BoxHash, CollectionHash, DataHash, DataMap, Ingredient, Metadata,
        Relationship,
    },
    claim::Claim,
    context::{Context, ProgressPhase},
    cose_validator::{
        check_ocsp_status, check_ocsp_status_async, get_signing_cert_serial_num, verify_cose,
        verify_cose_async,
    },
    crypto::cose::{parse_cose_sign1, CertificateInfo, CertificateTrustPolicy},
    error::{Error, Result},
    hashed_uri::HashedUri,
    jumbf,
    jumbf::labels::{
        assertion_label_from_uri, manifest_label_from_uri, manifest_label_to_parts,
        to_absolute_uri, to_assertion_uri, to_manifest_uri, to_signature_uri,
    },
    log_item,
    read_seek::ReadSeek,
    resource_store::UriOrResource,
    settings::Settings,
    status_tracker::StatusTracker,
    store::StoreValidationInfo,
    utils::hash_utils::{vec_compare, HashRange},
    validation_status,
};

pub(super) const LEGACY_WATERMARKED_ACTION: &str = "c2pa.watermarked";

/// Failure codes that reject a claim because of its signing credential, before
/// the claim signature itself is validated.
///
/// `signingCredential.untrusted` is deliberately not included: a manifest whose
/// signer is not on a trust list can still be Valid (C2PA Trust Model, "Valid
/// Manifest"), which requires `claimSignature.validated`.
const SIGNING_CREDENTIAL_REJECTIONS: &[&str] = &[
    validation_status::SIGNING_CREDENTIAL_INVALID,
    validation_status::SIGNING_CREDENTIAL_REVOKED,
    validation_status::SIGNING_CREDENTIAL_EXPIRED,
    validation_status::CLAIM_SIGNATURE_OUTSIDE_VALIDITY,
    validation_status::ALGORITHM_UNSUPPORTED,
];

// Enum to encapsulate the data type of the source asset.  This simplifies
// having different implementations for functions as a single entry point can be
// used to handle different data types.
#[allow(dead_code)] // Bytes and third param in StreamFragment not used without v1_api feature
pub enum ClaimAssetData<'a> {
    #[cfg(feature = "file_io")]
    Path(&'a Path),
    Bytes(&'a [u8], &'a str),
    Stream(&'a mut dyn ReadSeek, &'a str),
    StreamFragment(&'a mut dyn ReadSeek, &'a mut dyn ReadSeek, &'a str),
    #[cfg(feature = "file_io")]
    StreamFragments(&'a mut dyn ReadSeek, &'a Vec<std::path::PathBuf>, &'a str),
}

impl ClaimAssetData<'_> {
    /// Returns the asset's format (MIME type or extension), if it can be determined.
    pub(crate) fn format(&self) -> Option<String> {
        match self {
            #[cfg(feature = "file_io")]
            ClaimAssetData::Path(path) => crate::format_from_path(path),
            ClaimAssetData::Bytes(_, asset_type)
            | ClaimAssetData::Stream(_, asset_type)
            | ClaimAssetData::StreamFragment(_, _, asset_type) => Some((*asset_type).to_owned()),
            #[cfg(feature = "file_io")]
            ClaimAssetData::StreamFragments(_, _, asset_type) => Some((*asset_type).to_owned()),
        }
    }
}

pub(crate) const ALLOWED_UPDATE_MANIFEST_ACTIONS: [&str; 4] = [
    "c2pa.edited.metadata",
    "c2pa.opened",
    "c2pa.published",
    "c2pa.redacted",
];

/// Per C2PA 15.12, the exclusion range containing the manifest store must hold only
/// the manifest store and padding. `manifest_store_range` is the manifest's real
/// location, found independently by re-parsing the asset; a legitimate exclusion
/// covers exactly it. A mismatch means the exclusion covers non-manifest bytes -- a
/// detached manifest applied to an unrelated asset, or content injected into the
/// space freed by shrinking the manifest.
fn data_hash_exclusions_match_manifest(
    exclusions: &[HashRange],
    manifest_store_range: Option<&HashRange>,
    is_embedded: bool,
) -> bool {
    // Remote/sidecar manifests carry a placeholder exclusion that excludes no
    // bytes; the whole asset is hashed, so there is nothing to police.
    if !exclusions.iter().any(|e| e.length() > 0) {
        return true;
    }

    match manifest_store_range {
        // Manifest present in this asset: an exclusion must cover exactly it.
        Some(range) => exclusions.contains(range),
        // Manifest not in this asset: allow only if it was read from here
        // (embedded); a detached manifest on an unrelated asset is rejected (#2643).
        None => is_embedded,
    }
}

impl Claim {
    /// Verify that the claim `signature` field points to the signature box of this manifest.
    ///
    /// The claim label comes from the JUMBF label of the manifest, which is outside the signed
    /// claim. For V2 and greater claims the `signature` field must be an absolute URI. That URI
    /// names the manifest label, so it binds the label to the signed claim. Without it, the label
    /// could be changed without invalidating the signature. V1 claims may use a relative URI.
    pub(crate) fn verify_signature_box_uri(
        claim: &Claim,
        validation_log: &mut StatusTracker,
    ) -> Result<()> {
        let is_signature_box = jumbf::labels::box_name_from_uri(&claim.signature)
            .unwrap_or_default()
            == jumbf::labels::SIGNATURE;

        let sig_box_err = match manifest_label_from_uri(&claim.signature) {
            Some(signature_url) if signature_url != claim.label() => true,
            Some(_) => !is_signature_box,
            // relative signature box
            None => claim.version() > 1 || !is_signature_box,
        };

        if sig_box_err {
            log_item!(
                to_signature_uri(claim.label()),
                "signature missing",
                "verify_claim"
            )
            .validation_status(validation_status::CLAIM_SIGNATURE_MISSING)
            .failure(validation_log, Error::ClaimMissingSignatureBox)?;
        }
        Ok(())
    }

    /// Verify claim signature, assertion store and asset hashes
    /// claim - claim to be verified
    /// asset_bytes - reference to bytes of the asset
    #[async_generic]
    pub(crate) fn verify_claim(
        claim: &Claim,
        svi: &StoreValidationInfo<'_>,
        cert_check: bool,
        ctp: &CertificateTrustPolicy,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<()> {
        // Parse COSE signed data (signature) and validate it.
        let sig = claim.signature_val();
        let additional_bytes: Vec<u8> = Vec::new();

        let mut adjusted_settings = context.settings().clone();
        if claim.version() == 1 {
            adjusted_settings.verify.verify_timestamp_trust = false;
        }

        // use the signature uri as the current uri while validating the signature info
        validation_log.push_current_uri(to_signature_uri(claim.label()));

        Claim::verify_signature_box_uri(claim, validation_log)?;

        // for V2 and greater claims the label must conform
        if claim.version() > 1 && manifest_label_to_parts(claim.label()).is_none() {
            log_item!(
                to_manifest_uri(claim.label()),
                "claim box label invalid",
                "verify_claim"
            )
            .validation_status(validation_status::CLAIM_MALFORMED)
            .failure(validation_log, Error::ClaimInvalidContent)?;
        }

        // If we are validating a claim that has been loaded from a file
        // we need the original data but if we are signing, we generate the data
        // This avoids cloning the data when we are only referencing it.
        let mut _generated_data = vec![];
        let data = match claim.original_bytes {
            Some(ref original_bytes) => original_bytes,
            None => {
                _generated_data = claim.data()?;
                &_generated_data
            }
        };

        let sign1 = parse_cose_sign1(sig, data, validation_log)?;

        let certificate_serial_num = get_signing_cert_serial_num(&sign1)?.to_string();
        // check certificate revocation (revocation/trust failures are already recorded in validation_log)
        let ocsp_result = if _sync {
            check_ocsp_status(
                &sign1,
                data,
                ctp,
                svi.certificate_statuses.get(&certificate_serial_num),
                svi.timestamps.get(claim.label()),
                validation_log,
                context,
            )
        } else {
            check_ocsp_status_async(
                &sign1,
                data,
                ctp,
                svi.certificate_statuses.get(&certificate_serial_num),
                svi.timestamps.get(claim.label()),
                validation_log,
                context,
            )
            .await
        };
        let mut ocsp_rejected = false;
        if let Err(err) = ocsp_result {
            if !matches!(err, Error::CertificateTrustError(_)) {
                validation_log.pop_current_uri();
                return Err(err);
            }
            ocsp_rejected = true;
        }

        context.check_progress(ProgressPhase::VerifyingSignature, 1, 1)?;
        let cose_log_start = validation_log.logged_items().len();
        let verified = if _sync {
            verify_cose(
                sig,
                data,
                &additional_bytes,
                cert_check,
                ctp,
                svi.timestamps.get(claim.label()),
                validation_log,
                &adjusted_settings,
            )
        } else {
            verify_cose_async(
                sig,
                data,
                &additional_bytes,
                cert_check,
                ctp,
                svi.timestamps.get(claim.label()),
                validation_log,
                &adjusted_settings,
            )
            .await
        };

        // The OCSP check found the signing credential revoked. That outranks
        // the certificate chain reaching a trust anchor, so do not report the
        // credential as trusted.
        if ocsp_rejected {
            validation_log.remove_status_since(
                cose_log_start,
                validation_status::SIGNING_CREDENTIAL_TRUSTED,
            );
        }

        let result = Claim::verify_internal(claim, svi, verified, validation_log, context);
        validation_log.pop_current_uri();
        result
    }

    // Build a diagnostic message for ingredientMismatch errors, showing the failing
    // action's index, type, each referenced ingredient URL, and the actual relationship
    // found (vs. the expected one).
    fn ingredient_mismatch_msg(
        claim: &Claim,
        action_index: usize,
        action_type: &str,
        params: &assertions::ActionParameters,
        expected_relationship: &str,
    ) -> String {
        let urls: Vec<String> = {
            let mut v = Vec::new();
            if let Some(h) = &params.ingredient {
                v.push(h.url());
            }
            if let Some(hs) = &params.ingredients {
                v.extend(hs.iter().map(|h| h.url()));
            }
            v
        };

        let details: Vec<String> = urls
            .iter()
            .map(|url| {
                let found = assertion_label_from_uri(url).and_then(|target| {
                    claim.ingredient_assertions().iter().find_map(|i| {
                        if i.label() == target {
                            Ingredient::from_assertion(i.assertion()).ok().map(|ing| {
                                let rel = ing.relationship.as_str();
                                let title = ing.title.as_deref().unwrap_or("<no title>");
                                format!("'{}' (title='{}', relationship='{}')", url, title, rel)
                            })
                        } else {
                            None
                        }
                    })
                });
                found.unwrap_or_else(|| format!("'{}' (not found in ingredient assertions)", url))
            })
            .collect();

        format!(
            "action[{}] ('{}') must have valid ingredient with {} relationship; ingredient(s): [{}]",
            action_index,
            action_type,
            expected_relationship,
            if details.is_empty() {
                "none".to_string()
            } else {
                details.join(", ")
            }
        )
    }

    // Perform 2.x action validation check, hashed URI references are only checked
    // to be present and to be valild references an actual manifest store object.
    //The hashed uri's hashes are are validated as part of the Claim assertions check.
    pub(super) fn verify_actions(
        claim: &Claim,
        svi: &StoreValidationInfo<'_>,
        validation_log: &mut StatusTracker,
        settings: &Settings,
    ) -> Result<()> {
        let all_actions = claim.action_assertions();
        let created_actions = claim.created_action_assertions();
        let gathered_actions = claim.gathered_action_assertions();
        let claim_label = claim.label().to_owned();

        // for v1 claims check the single actions assertion
        if claim.version() < 2 && all_actions.len() > 1 {
            log_item!(
                claim_label.clone(),
                "only one action assertion allowed for v1 claims",
                "verify_actions"
            )
            .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
            .failure(
                validation_log,
                Error::ValidationRule("No Action array in Actions".into()),
            )?;
        }

        // Skip further checks for v1 claims if not in strict validation mode
        if claim.version() == 1 && !settings.verify.strict_v1_validation {
            return Ok(()); // no further checks for v1 claims
        }

        // 1. make sure every action has an actions array that is not empty
        if let Some(bad_assertion) = all_actions.iter().find(|a| {
            if let Ok(actions) = Actions::from_assertion(a.assertion()) {
                actions.actions().is_empty()
            } else {
                false
            }
        }) {
            let label = to_assertion_uri(claim.label(), &bad_assertion.label());
            log_item!(label, "Actions missing action array", "verify_actions")
                .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                .failure(
                    validation_log,
                    Error::ValidationRule("No Action array in Actions".into()),
                )?;

            // failure full stop
            return Err(Error::ValidationRule("No Action array in Actions".into()));
        }

        // Skip further checks for v1 claims if not in strict validation mode
        if claim.version() == 1 && !settings.verify.strict_v1_validation {
            return Ok(()); // no further checks for v1 claims
        }

        let mut first_actions_assertion = None;

        // check created actions then gathered actions if not found in created actions
        // starting with 2.4 these assertion can only be in created assertions
        for actions in [&created_actions, &gathered_actions] {
            if let Some(assertion) = actions.first() {
                let first_actions = Actions::from_assertion(assertion.assertion())?;
                let first_actions_first_action = &first_actions.actions().first();

                if let Some(first_actions_first_action) = first_actions_first_action {
                    if first_actions_first_action.action() == c2pa_action::OPENED
                        || first_actions_first_action.action() == c2pa_action::CREATED
                    {
                        first_actions_assertion = Some(assertion);
                    }
                }
            }
        }

        // there can be only 1 of either c2pa.opened or c2pa.created, and they cannot both exist
        let inception_action_count = {
            let mut count = 0usize;
            for assertion in all_actions.iter() {
                let Ok(actions) = Actions::from_assertion(assertion.assertion()) else {
                    continue;
                };
                for action in actions.actions() {
                    if action.action() == c2pa_action::OPENED
                        || action.action() == c2pa_action::CREATED
                    {
                        count += 1;
                    }
                }
            }
            count
        };

        if inception_action_count > 1 {
            log_item!(
                claim_label.clone(),
                "cannot have more than one c2pa.created or c2pa.opened action",
                "verify_actions"
            )
            .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
            .failure(
                validation_log,
                Error::ValidationRule(
                    "cannot have more than one c2pa.created or c2pa.opened action".into(),
                ),
            )?;
        }

        // 2.a first actions assertion must start with an open or created action, do not apply to update manifests
        if first_actions_assertion.is_none() && !claim.update_manifest() {
            log_item!(
                claim_label,
                "first action must be created or opened",
                "verify_actions"
            )
            .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
            .failure(
                validation_log,
                Error::ValidationRule("first action must be created or opened".into()),
            )?;
        }

        // perform all actions checks
        for actions_assertion in all_actions.iter() {
            let actions = Actions::from_assertion(actions_assertion.assertion())?;
            let label = to_assertion_uri(claim.label(), &actions_assertion.label());

            // 1. Actions must have actions array
            if actions.actions().is_empty() {
                log_item!(
                    label.clone(),
                    "actions must have action array",
                    "verify_actions"
                )
                .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                .failure(
                    validation_log,
                    Error::ValidationRule("actions must have action array".into()),
                )?;
            }

            let mut icons = Vec::new();
            // 2.e.i Actions icons
            if let Some(cgi_vec) = actions.software_agents() {
                for cgi in cgi_vec {
                    if let Some(UriOrResource::HashedUri(icon)) = cgi.icon() {
                        icons.push(icon);
                    }
                }
            }
            // 2.f Template icons
            if let Some(template_vec) = actions.templates() {
                for template in template_vec {
                    if let Some(UriOrResource::HashedUri(icon)) = &template.icon {
                        icons.push(icon);
                    }
                }
            }
            // check top level icons
            if !icons.is_empty() {
                Claim::verify_icons(claim, &icons, validation_log)?;
            }

            for (action_index, action) in actions.actions().iter().enumerate() {
                //dbg!("action: {:?}", &action);
                // 2.a action must have an action
                if action.action().is_empty() {
                    log_item!(
                        label.clone(),
                        "action must have an action.",
                        "verify_actions"
                    )
                    .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                    .failure(
                        validation_log,
                        Error::ValidationRule("action must have an action".into()),
                    )?;
                }

                // 2.a any other actions assertions cannot contain created or opened actions (v2 claim)
                if let Some(fa) = first_actions_assertion {
                    if fa != actions_assertion
                        && (action.action() == c2pa_action::OPENED
                            || action.action() == c2pa_action::CREATED)
                    {
                        log_item!(
                            label.clone(),
                            "only first action can be created or opened",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                        .failure(
                            validation_log,
                            Error::ValidationRule(
                                "only first action can be created or opened".into(),
                            ),
                        )?;
                    }
                }

                // 2.a created or opened must be first action (within its own assertion — which
                // actions assertion is allowed to hold it at all is enforced by the
                // "only first action can be created or opened" check above; `index`, the
                // position of `actions_assertion` among `all_actions`, is irrelevant here).
                if action_index != 0
                    && (action.action() == c2pa_action::OPENED
                        || action.action() == c2pa_action::CREATED)
                {
                    log_item!(
                        label.clone(),
                        "created or opened must be first action",
                        "verify_actions"
                    )
                    .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                    .failure(
                        validation_log,
                        Error::ValidationRule("created or opened must be first action".into()),
                    )?;
                }

                // 2.b rules
                if action.action() == c2pa_action::OPENED
                    || action.action() == c2pa_action::PLACED
                    || action.action() == c2pa_action::REMOVED
                {
                    // 2.b.i must have parameters
                    let Some(params) = action.parameters() else {
                        log_item!(
                            label.clone(),
                            "opened, placed and removed items must have ingredient(s) parameters",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH)
                        .failure(
                            validation_log,
                            Error::ValidationRule(
                                "opened, placed and removed items must have ingredient(s) parameters".into(),
                            ),
                        )?;
                        continue; // Skip the parameter-dependent checks below
                    };

                    // 2.b.ii must have ingredient or ingredients param
                    if params.ingredients.is_none() && params.ingredient.is_none() {
                        log_item!(
                            label.clone(),
                            "opened, placed and removed items must have ingredient(s) parameters",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH)
                        .failure(
                            validation_log,
                            Error::ValidationRule("opened, placed and removed items must have ingredient(s) parameters".into()),
                        )?;
                        continue;
                    }

                    // 2.b.iii if ingredients, must be an array with at least one item
                    if let Some(h_vec) = &params.ingredients {
                        if h_vec.is_empty() {
                            log_item!(
                                label.clone(),
                                "opened, placed and removed items must have ingredients parameter must be non empty array",
                                "verify_actions"
                            )
                            .validation_status(validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH)
                            .failure(
                                validation_log,
                                Error::ValidationRule("opened, placed and removed items must have ingredients parameter must be non empty array".into()),
                            )?;
                        }
                    }

                    // 2.b.iv.A opened must have a parentOf
                    if action.action() == c2pa_action::OPENED {
                        let mut found_good = 0usize;

                        if let Some(h) = &params.ingredient {
                            // can we find a reference in the ingredient list
                            // is it referenced from this manifest
                            if claim.ingredient_assertions().iter().any(|i| {
                                if let Ok(ingredient) = Ingredient::from_assertion(i.assertion()) {
                                    if let Some(target_label) = assertion_label_from_uri(&h.url()) {
                                        return target_label == i.label()
                                            && ingredient.relationship == Relationship::ParentOf;
                                    }
                                }
                                false
                            }) {
                                found_good = 1;
                            }
                        } else if let Some(ingredients) = &params.ingredients {
                            for h in ingredients {
                                // can we find a reference in the ingredient list
                                // is it referenced from this manifest and only once
                                found_good = claim
                                    .ingredient_assertions()
                                    .iter()
                                    .filter(|i| {
                                        if let Ok(ingredient) =
                                            Ingredient::from_assertion(i.assertion())
                                        {
                                            if let Some(target_label) =
                                                assertion_label_from_uri(&h.url())
                                            {
                                                return target_label == i.label()
                                                    && ingredient.relationship
                                                        == Relationship::ParentOf;
                                            }
                                        }
                                        false
                                    })
                                    .count();
                            }
                        }

                        if found_good != 1 {
                            let msg = Self::ingredient_mismatch_msg(
                                claim,
                                action_index,
                                action.action(),
                                params,
                                "parentOf",
                            );
                            log_item!(label.clone(), msg.clone(), "verify_actions")
                                .validation_status(
                                    validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH,
                                )
                                .failure_no_throw(validation_log, Error::ValidationRule(msg));
                        }
                    }

                    // 2.b.iv.B, 2.b.iv.C must have a ComponentOf
                    if action.action() == c2pa_action::PLACED
                        || action.action() == c2pa_action::REMOVED
                    {
                        let mut found_good = 0usize;

                        if let Some(h) = &params.ingredient {
                            // can we find a reference in the ingredient list
                            // is it referenced from this manifest
                            if claim.ingredient_assertions().iter().any(|i| {
                                if let Ok(ingredient) = Ingredient::from_assertion(i.assertion()) {
                                    if let Some(target_label) = assertion_label_from_uri(&h.url()) {
                                        return target_label == i.label()
                                            && ingredient.relationship
                                                == Relationship::ComponentOf;
                                    }
                                }
                                false
                            }) {
                                found_good = 1;
                            }
                        } else if let Some(h_vec) = &params.ingredients {
                            for h in h_vec {
                                // can we find a reference in the ingredient list
                                // is it referenced from this manifest
                                if claim.ingredient_assertions().iter().any(|i| {
                                    if let Ok(ingredient) =
                                        Ingredient::from_assertion(i.assertion())
                                    {
                                        if let Some(target_label) =
                                            assertion_label_from_uri(&h.url())
                                        {
                                            return target_label == i.label()
                                                && ingredient.relationship
                                                    == Relationship::ComponentOf;
                                        }
                                    }
                                    false
                                }) {
                                    found_good = 1;
                                }
                            }
                        }

                        if found_good != 1 {
                            let msg = Self::ingredient_mismatch_msg(
                                claim,
                                action_index,
                                action.action(),
                                params,
                                "componentOf",
                            );
                            log_item!(label.clone(), msg.clone(), "verify_actions")
                                .validation_status(
                                    validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH,
                                )
                                .failure_no_throw(validation_log, Error::ValidationRule(msg));
                        }
                    }
                }

                // 2.b.v c2pa.created must have a digitalSourceType
                if action.action() == c2pa_action::CREATED && action.source_type().is_none() {
                    log_item!(
                        label.clone(),
                        "c2pa.created action must have a digitalSourceType",
                        "verify_actions"
                    )
                    .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                    .failure_no_throw(
                        validation_log,
                        Error::ValidationRule(
                            "c2pa.created action must have a digitalSourceType".into(),
                        ),
                    );
                }

                // c2pa.translated must have sourceLanguage and targetLanguage parameters.
                // Per the C2PA spec (18.15.4.7, Parameters): "When using a c2pa.translated
                // action, the sourceLanguage and targetLanguage fields in the parameters
                // object shall contain RFC 5646, BCP 47 language codes."
                if action.action() == c2pa_action::TRANSLATED {
                    let params = action.parameters();
                    let source_language = params
                        .and_then(|p| p.source_language.as_deref())
                        .unwrap_or("");
                    let target_language = params
                        .and_then(|p| p.target_language.as_deref())
                        .unwrap_or("");

                    if source_language.is_empty() || target_language.is_empty() {
                        log_item!(
                            label.clone(),
                            "c2pa.translated action must have sourceLanguage and targetLanguage parameters",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                        .failure_no_throw(
                            validation_log,
                            Error::ValidationRule(
                                "c2pa.translated action must have sourceLanguage and targetLanguage parameters".into(),
                            ),
                        );
                    }
                }

                // 2.c if ingredient is present it must be a valid parentOf reference
                if action.action() == c2pa_action::TRANSCODED
                    || action.action() == c2pa_action::REPACKAGED
                {
                    if let Some(params) = action.parameters() {
                        let mut parent_tested = None; // on exists if action actually pointed to an ingredient
                        if let Some(h) = &params.ingredient {
                            // can we find a reference in the ingredient list
                            // is it referenced from this manifest
                            if claim.ingredient_assertions().iter().any(|i| {
                                if let Ok(ingredient) = Ingredient::from_assertion(i.assertion()) {
                                    if let Some(target_label) = assertion_label_from_uri(&h.url()) {
                                        return target_label == i.label()
                                            && ingredient.relationship == Relationship::ParentOf;
                                    }
                                }
                                false
                            }) {
                                parent_tested = Some(true);
                            }

                            match parent_tested {
                                Some(v) => parent_tested = Some(v),
                                None => parent_tested = Some(false),
                            }
                        } else if let Some(h_vec) = &params.ingredients {
                            for h in h_vec {
                                // can we find a reference in the ingredient list
                                // is it referenced from this manifest
                                if claim.ingredient_assertions().iter().any(|i| {
                                    if let Ok(ingredient) =
                                        Ingredient::from_assertion(i.assertion())
                                    {
                                        if let Some(target_label) =
                                            assertion_label_from_uri(&h.url())
                                        {
                                            return target_label == i.label()
                                                && ingredient.relationship
                                                    == Relationship::ParentOf;
                                        }
                                    }
                                    false
                                }) {
                                    parent_tested = Some(true);
                                }
                            }
                            match parent_tested {
                                Some(v) => parent_tested = Some(v),
                                None => parent_tested = Some(false),
                            }
                        }
                        // will only exist if we actual tested for an ingredient
                        if let Some(false) = parent_tested {
                            let msg = Self::ingredient_mismatch_msg(
                                claim,
                                action_index,
                                action.action(),
                                params,
                                "parentOf",
                            );
                            log_item!(label.clone(), msg.clone(), "verify_actions")
                                .validation_status(
                                    validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH,
                                )
                                .failure_no_throw(validation_log, Error::ValidationRule(msg));
                        }
                    }
                }

                // 2.d if redacted actions contains a redacted parameter if must be a resolvable reference
                if action.action() == c2pa_action::REDACTED {
                    if let Some(params) = action.parameters() {
                        let mut parent_tested = None; // on exists if action actually pointed to an ingredient
                        if let Some(redacted_uri) = &params.redacted {
                            if let Some(ingredient_label) = manifest_label_from_uri(redacted_uri) {
                                // can we find a reference in the ingredient list
                                if let Some(ingredient_claim) =
                                    svi.manifest_map.get(&ingredient_label)
                                {
                                    // The referenced manifest exists, so far so good.
                                    // now get the assertion label and try to resolve it.
                                    if let Some(redaction_label) =
                                        assertion_label_from_uri(redacted_uri)
                                    {
                                        // The assertion may or may not be in the assertion store.
                                        // It can exist and be zeroed or be removed entirely
                                        // but it must be in the claim's assertions HashUri list.
                                        // For databox items, check the claim's redacted_assertions
                                        // since databox refs are not in the assertions list.
                                        let in_assertions = ingredient_claim
                                            .assertions()
                                            .iter()
                                            .any(|a| a.url().contains(&redaction_label));
                                        let in_redacted = redacted_uri.contains(DATABOX_STORE)
                                            && claim
                                                .redactions()
                                                .is_some_and(|r| r.contains(redacted_uri));
                                        parent_tested = Some(in_assertions || in_redacted);
                                    } else {
                                        parent_tested = Some(false);
                                    }
                                }
                            }
                        }
                        match parent_tested {
                            None => {
                                log_item!(
                                    label.clone(),
                                    "redaction uri must be a valid reference",
                                    "verify_actions"
                                )
                                .validation_status(
                                    validation_status::ASSERTION_ACTION_REDACTION_MISMATCH,
                                )
                                .failure_no_throw(
                                    validation_log,
                                    Error::ValidationRule(
                                        "redaction action must have valid ingredient".into(),
                                    ),
                                );
                            }
                            Some(false) => {
                                log_item!(
                                    label.clone(),
                                    "The assertion was not redacted",
                                    "verify_actions"
                                )
                                .validation_status(validation_status::ASSERTION_NOT_REDACTED)
                                .failure_no_throw(
                                    validation_log,
                                    Error::ValidationRule("the assertion was not redacted".into()),
                                );
                            }
                            Some(true) => {}
                        }
                    }
                }

                // 2.f if the action’s parameters field exists and contains a relatedAssertions field
                if let Some(related_assertions) = action.related_assertions() {
                    // 2.f.i if the value of relatedAssertions is not an array with at least one element,
                    //       the claim shall be rejected with a failure code of assertion.action.malformed
                    if related_assertions.is_empty() {
                        log_item!(
                            label.clone(),
                            "relatedAssertions must contain at least one entry",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                        .failure_no_throw(
                            validation_log,
                            Error::ValidationRule(
                                "relatedAssertions must contain at least one entry".into(),
                            ),
                        );
                    }

                    for related in related_assertions {
                        let url = related.url();

                        // 2.f.ii.B resolve the hashed URI to locate the referenced assertion
                        let (target_label, instance) = Claim::assertion_label_from_link(&url);

                        // 2.f.ii.C if the referenced assertion cannot be resolved, or does not
                        //          resolve to an assertion within the current manifest, the claim
                        //          shall be rejected with a failure code of assertion.action.malformed
                        let in_current_manifest = if related.is_relative_url() {
                            true
                        } else {
                            manifest_label_from_uri(&url).as_deref() == Some(claim.label())
                        };
                        let assertion = if in_current_manifest {
                            claim.get_claim_assertion(&target_label, instance)
                        } else {
                            None
                        };

                        if assertion.is_none() {
                            log_item!(
                                url.clone(),
                                format!("relatedAssertions reference could not be resolved within the current manifest: {url}"),
                                "verify_actions"
                            )
                            .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                            .failure_no_throw(
                                validation_log,
                                Error::ValidationRule(
                                format!("relatedAssertions reference could not be resolved within the current manifest: {url}"),
                                ),
                            );
                        }

                        // 2.f.ii.D If the referenced assertion is of of type c2pa.ingredients,
                        //          c2pa.ingredients.v2, c2pa.ingredients.v3, c2pa.actions, or
                        //          c2pa.actions.v2, the claim shall be rejected with a failure
                        //          code of assertion.action.malformed.
                        let base = labels::base(&target_label);
                        if base == labels::ACTIONS || base == labels::INGREDIENT {
                            log_item!(
                                url.clone(),
                                format!("relatedAssertions must not reference an actions or ingredient assertion: {url}"),
                                "verify_actions"
                            )
                            .validation_status(validation_status::ASSERTION_ACTION_MALFORMED)
                            .failure_no_throw(
                                validation_log,
                                Error::ValidationRule(
                                format!("relatedAssertions must not reference an actions or ingredient assertion: {url}"),
                                ),
                            );
                        }
                    }
                }

                // 2.h check softwareAgent icons
                let mut icons = Vec::new();
                if let Some(assertions::SoftwareAgent::ClaimGeneratorInfo(cgi)) =
                    action.software_agent()
                {
                    if let Some(UriOrResource::HashedUri(icon)) = cgi.icon() {
                        icons.push(icon);
                    }
                }
                if !icons.is_empty() {
                    Claim::verify_icons(claim, &icons, validation_log)?;
                }

                // check watermarks for required softbinding
                // Validators must still recognize the legacy action in existing manifests.
                if action.action() == LEGACY_WATERMARKED_ACTION
                    || action.action() == c2pa_action::WATERMARKED_BOUND
                {
                    // there must be at least one soft binding assertions, in the future there may be
                    // a requirement to reference the actual soft binding via parameters relatedAssertions field
                    if claim.soft_binding_assertions().is_empty() {
                        log_item!(
                            label.clone(),
                            "watermark action missing soft binding assertion",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ACTION_ASSERTION_SOFTBINDING_MISSING)
                        .failure_no_throw(
                            validation_log,
                            Error::ValidationRule(
                                "watermark action missing soft binding assertion".into(),
                            ),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    // check the validity of icons in a ClaimGeneratorInfo
    fn verify_icons(
        claim: &Claim,
        icon_uris: &[&HashedUri],
        validation_log: &mut StatusTracker,
    ) -> Result<()> {
        for icon in icon_uris {
            // make sure the icon uri is valid
            let (label, instance) = Claim::assertion_label_from_link(&icon.url());
            if let Some(ca) = claim.get_claim_assertion(&label, instance) {
                // verify the hashes match
                if !vec_compare(ca.hash(), &icon.hash()) {
                    log_item!(
                        icon.url(),
                        format!("hash does not match assertion data: {}", icon.url()),
                        "verify_icons"
                    )
                    .validation_status(validation_status::ASSERTION_HASHEDURI_MISMATCH)
                    .failure(
                        validation_log,
                        Error::HashMismatch(format!("Assertion hash failure: {}", icon.url(),)),
                    )?;
                }
            } else if claim.get_databox(icon).is_some() {
                // We have a databox with this icon
                // todo: check the hash on the databox?
                return Ok(());
            } else {
                log_item!(icon.url(), "could not resolve icon address", "verify_icons")
                    .validation_status(validation_status::ASSERTION_MISSING)
                    .failure(validation_log, Error::AssertionMissing { url: icon.url() })?;
            }
        }
        Ok(())
    }

    /// Classifies a hash-verification failure into its format's `malformed`
    /// or `mismatch` validation-status constant, based on whether `e` carries
    /// that format's own `malformed` code.
    fn classify_hash_verification_error(
        e: &Error,
        malformed: &'static str,
        mismatch: &'static str,
    ) -> &'static str {
        match e {
            Error::C2PAValidation(es) if es == malformed => malformed,
            _ => mismatch,
        }
    }

    pub(crate) fn verify_hash_binding(
        claim: &Claim,
        asset_data: &mut ClaimAssetData<'_>,
        svi: &StoreValidationInfo,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<()> {
        const UNNAMED: &str = "unnamed";
        let default_str = |s: &String| s.clone();

        // verify data hashes for provenance claims
        if claim.label() == svi.binding_claim {
            let hash_assertions = claim.hash_assertions();
            // must have at least one hard binding for normal manifests
            if hash_assertions.is_empty() && !claim.update_manifest() {
                log_item!(claim.uri(), "claim missing data binding", "verify_internal")
                    .validation_status(validation_status::HARD_BINDINGS_MISSING)
                    .failure(validation_log, Error::ClaimMissingHardBinding)?;
            }

            // must have exactly one hard binding for normal manifests
            if hash_assertions.len() != 1 && !claim.update_manifest() {
                log_item!(
                    claim.uri(),
                    "claim has multiple data bindings",
                    "verify_internal"
                )
                .validation_status(validation_status::HARD_BINDINGS_MULTIPLE)
                .failure(validation_log, Error::ClaimMultipleHardBinding)?;
            }

            // update manifests cannot have data hashes
            if !hash_assertions.is_empty() && claim.update_manifest() {
                log_item!(
                    claim.uri(),
                    "update manifests cannot contain data hash assertions",
                    "verify_internal"
                )
                .validation_status(validation_status::MANIFEST_UPDATE_INVALID)
                .failure(validation_log, Error::UpdateManifestInvalid)?;
            }

            // while this is a vec the spec only expects one at the moment and is checked above
            for hash_binding_assertion in hash_assertions {
                if hash_binding_assertion
                    .label_raw()
                    .starts_with(DataHash::LABEL)
                {
                    let mut dh = DataHash::from_assertion(hash_binding_assertion.assertion())?;
                    let name = dh.name.as_ref().map_or(UNNAMED.to_string(), default_str);

                    // update with any needed update hash adjustments
                    if svi.update_manifest_label.is_some() {
                        let mut start_adjust = 0;
                        let mut start_offset = 0;
                        if let Some(exclusions) = &mut dh.exclusions {
                            if let Some(range) = &svi.manifest_store_range {
                                // find the range that starts at the same position as the manifest store range
                                if let Some(pos) =
                                    exclusions.iter().position(|r| r.start() == range.start())
                                {
                                    // find the adjustment length
                                    start_offset = range.start();
                                    start_adjust =
                                        range.length().saturating_sub(exclusions[pos].length());

                                    // replace range using the size that covers entire manifest (including update manifests)
                                    exclusions[pos] = range.clone();
                                }
                            }
                            // fix up offsets affected by update manifest
                            if start_offset > 0 {
                                for exclusion in exclusions {
                                    if exclusion.start() > start_offset {
                                        exclusion.set_start(exclusion.start() + start_adjust);
                                    }
                                }
                            }
                        }
                    }

                    if !dh.is_remote_hash() {
                        if let Some(exclusions) = &dh.exclusions {
                            if !data_hash_exclusions_match_manifest(
                                exclusions,
                                svi.manifest_store_range.as_ref(),
                                svi.is_embedded,
                            ) {
                                log_item!(
                                    claim.assertion_uri(&hash_binding_assertion.label()),
                                    "data hash exclusion does not match the manifest location in the asset",
                                    "verify_internal"
                                )
                                .validation_status(validation_status::ASSERTION_DATAHASH_MISMATCH)
                                .failure(
                                    validation_log,
                                    Error::HashMismatch(
                                        "data hash exclusion does not match manifest location"
                                            .to_string(),
                                    ),
                                )?;
                            }

                            // there are extra exclusion then log the information code about extra exclusion
                            if exclusions.len() > 1 {
                                log_item!(
                                    claim.assertion_uri(&hash_binding_assertion.label()),
                                    "extra data hash exclusions found",
                                    "verify_internal"
                                )
                                .validation_status(
                                    validation_status::ASSERTION_DATAHASH_ADDITIONAL_EXCLUSIONS,
                                )
                                .informational(validation_log);
                            }
                        }

                        // only verify local hashes here
                        let mut cb = |step, total| {
                            context.check_progress(ProgressPhase::VerifyingAssetHash, step, total)
                        };
                        let hash_result = match asset_data {
                            #[cfg(feature = "file_io")]
                            ClaimAssetData::Path(asset_path) => {
                                let mut file = std::fs::File::open(asset_path)?;
                                dh.verify_stream_hash_with_progress(
                                    &mut file,
                                    Some(claim.alg()),
                                    &mut cb,
                                )
                            }
                            ClaimAssetData::Bytes(asset_bytes, _) => {
                                let mut cursor = std::io::Cursor::new(*asset_bytes);
                                dh.verify_stream_hash_with_progress(
                                    &mut cursor,
                                    Some(claim.alg()),
                                    &mut cb,
                                )
                            }
                            ClaimAssetData::Stream(stream_data, _) => dh
                                .verify_stream_hash_with_progress(
                                    *stream_data,
                                    Some(claim.alg()),
                                    &mut cb,
                                ),
                            _ => return Err(Error::UnsupportedType), /* this should never happen (coding error) */
                        };

                        match hash_result {
                            Ok(_a) => {
                                log_item!(
                                    claim.assertion_uri(&hash_binding_assertion.label()),
                                    "data hash valid",
                                    "verify_internal"
                                )
                                .validation_status(validation_status::ASSERTION_DATAHASH_MATCH)
                                .success(validation_log);

                                continue;
                            }
                            Err(e) => {
                                log_item!(
                                    claim.assertion_uri(&hash_binding_assertion.label()),
                                    format!("asset hash error, name: {name}, error: {e}"),
                                    "verify_internal"
                                )
                                .validation_status(validation_status::ASSERTION_DATAHASH_MISMATCH)
                                .failure(
                                    validation_log,
                                    Error::HashMismatch(format!("Asset hash failure: {e}")),
                                )?;
                            }
                        }
                    } else {
                        log_item!(
                            hash_binding_assertion.label(),
                            "remote data hash URIs are not supported",
                            "verify_internal"
                        )
                        .validation_status(validation_status::ASSERTION_DATAHASH_MISMATCH)
                        .failure(
                            validation_log,
                            Error::HashMismatch(
                                "remote data hash URIs are not supported".to_string(),
                            ),
                        )?;
                    }
                } else if hash_binding_assertion
                    .label_raw()
                    .starts_with(BmffHash::LABEL)
                {
                    let cp2a_id: [u8; 16] = [
                        216, 254, 195, 214, 27, 14, 72, 60, 146, 151, 88, 40, 135, 126, 196, 129,
                    ];
                    let c2pa_dm = DataMap {
                        offset: 8,
                        value: cp2a_id.to_vec(), // C2PA identifier
                    };

                    // handle BMFF data hashes
                    let dh = BmffHash::from_assertion(hash_binding_assertion.assertion())?;

                    let name = dh.name().map_or("unnamed".to_string(), default_str);

                    // are there addtional exclusions that are not manifests or ftyp
                    if dh.exclusions().iter().any(|e| {
                        if e.xpath == "/uuid" {
                            match &e.data {
                                Some(dm_vec) if dm_vec.len() == 1 => !(dm_vec[0] == c2pa_dm),
                                _ => true,
                            }
                        } else if e.xpath == "/ftyp" || e.xpath == "/mfra" {
                            false
                        } else {
                            true // not ftyp, mfra or uuid
                        }
                    }) {
                        log_item!(
                            claim.assertion_uri(&hash_binding_assertion.label()),
                            "extra BMFF hash exclusion(s) found",
                            "verify_internal"
                        )
                        .validation_status(
                            validation_status::ASSERTION_BMFFHASH_ADDITIONAL_EXCLUSIONS,
                        )
                        .informational(validation_log);
                    }

                    let mut step = 0u32;
                    let mut cb = |_s: u32, t: u32| {
                        step += 1;
                        context.check_progress(ProgressPhase::VerifyingAssetHash, step, t)
                    };
                    let hash_result = match asset_data {
                        #[cfg(feature = "file_io")]
                        ClaimAssetData::Path(asset_path) => {
                            dh.verify_hash_with_progress(asset_path, Some(claim.alg()), &mut cb)
                        }
                        ClaimAssetData::Bytes(asset_bytes, _) => dh
                            .verify_in_memory_hash_with_progress(
                                asset_bytes,
                                Some(claim.alg()),
                                &mut cb,
                            ),
                        ClaimAssetData::Stream(stream_data, _) => dh
                            .verify_stream_hash_with_progress(
                                *stream_data,
                                Some(claim.alg()),
                                &mut cb,
                            ),
                        ClaimAssetData::StreamFragment(initseg_data, fragment_data, _) => dh
                            .verify_stream_segment_with_progress(
                                *initseg_data,
                                *fragment_data,
                                Some(claim.alg()),
                                &mut cb,
                            ),
                        #[cfg(feature = "file_io")]
                        ClaimAssetData::StreamFragments(initseg_data, fragment_paths, _) => dh
                            .verify_stream_segments_with_progress(
                                *initseg_data,
                                fragment_paths,
                                Some(claim.alg()),
                                &mut cb,
                            ),
                    };

                    match hash_result {
                        Ok(_a) => {
                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                "BMFF hash valid",
                                "verify_internal"
                            )
                            .validation_status(validation_status::ASSERTION_BMFFHASH_MATCH)
                            .success(validation_log);

                            continue;
                        }
                        Err(e) => {
                            let err_str = Self::classify_hash_verification_error(
                                &e,
                                validation_status::ASSERTION_BMFFHASH_MALFORMED,
                                validation_status::ASSERTION_BMFFHASH_MISMATCH,
                            );

                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                format!("asset hash error, name: {name}, error: {e}"),
                                "verify_internal"
                            )
                            .validation_status(err_str)
                            .failure(
                                validation_log,
                                Error::HashMismatch(format!("Asset hash failure: {e}")),
                            )?;
                        }
                    }
                } else if hash_binding_assertion
                    .label_raw()
                    .starts_with(BoxHash::LABEL)
                {
                    // box hash case
                    // handle BMFF data hashes
                    let bh = BoxHash::from_assertion(hash_binding_assertion.assertion())?;

                    let mut cb = |step, total| {
                        context.check_progress(ProgressPhase::VerifyingAssetHash, step, total)
                    };
                    let hash_result = match asset_data {
                        #[cfg(feature = "file_io")]
                        ClaimAssetData::Path(asset_path) => {
                            let box_hash_processor = context
                                .io()
                                .handler_from_path(asset_path)
                                .ok_or(Error::UnsupportedType)?
                                .asset_box_hash_ref()
                                .ok_or(Error::HashMismatch("Box hash not supported".to_string()))?;

                            let mut file = std::fs::File::open(asset_path)?;
                            bh.verify_stream_hash_with_progress(
                                &mut file,
                                Some(claim.alg()),
                                box_hash_processor,
                                &mut cb,
                            )
                        }
                        ClaimAssetData::Bytes(asset_bytes, asset_type) => {
                            let box_hash_processor = context
                                .io()
                                .handler(asset_type)
                                .ok_or(Error::UnsupportedType)?
                                .asset_box_hash_ref()
                                .ok_or(Error::HashMismatch(format!(
                                    "Box hash not supported for: {asset_type}"
                                )))?;

                            let mut cursor = std::io::Cursor::new(*asset_bytes);
                            bh.verify_stream_hash_with_progress(
                                &mut cursor,
                                Some(claim.alg()),
                                box_hash_processor,
                                &mut cb,
                            )
                        }
                        ClaimAssetData::Stream(stream_data, asset_type) => {
                            let box_hash_processor = context
                                .io()
                                .handler(asset_type)
                                .ok_or(Error::UnsupportedType)?
                                .asset_box_hash_ref()
                                .ok_or(Error::HashMismatch(format!(
                                    "Box hash not supported for: {asset_type}"
                                )))?;

                            bh.verify_stream_hash_with_progress(
                                *stream_data,
                                Some(claim.alg()),
                                box_hash_processor,
                                &mut cb,
                            )
                        }
                        _ => return Err(Error::UnsupportedType),
                    };

                    match hash_result {
                        Ok(metadata_exclusion_used) => {
                            if metadata_exclusion_used {
                                log_item!(
                                    claim.assertion_uri(&hash_binding_assertion.label()),
                                    "additional box hash exclusions found",
                                    "verify_internal"
                                )
                                .validation_status(
                                    validation_status::ASSERTION_BOXHASH_ADDITIONAL_EXCLUSIONS,
                                )
                                .informational(validation_log);
                            }

                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                "boxes hash valid",
                                "verify_internal"
                            )
                            .validation_status(validation_status::ASSERTION_BOXHASH_MATCH)
                            .success(validation_log);

                            continue;
                        }
                        Err(e) => {
                            let err_str = Self::classify_hash_verification_error(
                                &e,
                                validation_status::ASSERTION_BOXESHASH_MALFORMED,
                                validation_status::ASSERTION_BOXHASH_MISMATCH,
                            );

                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                format!("asset hash error: {e}"),
                                "verify_internal"
                            )
                            .validation_status(err_str)
                            .failure(
                                validation_log,
                                Error::HashMismatch(format!("Asset hash failure: {e}")),
                            )?;
                        }
                    }
                } else if hash_binding_assertion
                    .label_raw()
                    .starts_with(CollectionHash::LABEL)
                {
                    let collection_hash =
                        CollectionHash::from_assertion(hash_binding_assertion.assertion())?;

                    let verify_result = if asset_data
                        .format()
                        .as_deref()
                        .is_some_and(|f| context.io().is_zip_format(f))
                    {
                        match asset_data {
                            #[cfg(feature = "file_io")]
                            ClaimAssetData::Path(asset_path) => {
                                let mut file = std::fs::File::open(asset_path)?;
                                collection_hash.verify_zip_stream_hash(&mut file, Some(claim.alg()))
                            }
                            ClaimAssetData::Bytes(asset_bytes, _) => {
                                let mut cursor = std::io::Cursor::new(*asset_bytes);
                                collection_hash
                                    .verify_zip_stream_hash(&mut cursor, Some(claim.alg()))
                            }
                            ClaimAssetData::Stream(stream_data, _) => collection_hash
                                .verify_zip_stream_hash(*stream_data, Some(claim.alg())),
                            _ => return Err(Error::UnsupportedType),
                        }
                    } else {
                        // we don't support multiple streams as input so the only option is paths for non-ZIP-based assets.
                        match asset_data {
                            #[cfg(feature = "file_io")]
                            ClaimAssetData::Path(asset_path) => collection_hash
                                .verify_hash(asset_path.parent().unwrap_or(asset_path)),
                            _ => return Err(Error::UnsupportedType),
                        }
                    };

                    match verify_result {
                        Ok(_) => {
                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                "collection hash valid",
                                "verify_internal"
                            )
                            .validation_status(validation_status::ASSERTION_COLLECTIONHASH_MATCH)
                            .success(validation_log);

                            continue;
                        }
                        Err(err) => {
                            let err_str = match &err {
                                Error::C2PAValidation(code)
                                    if code
                                        == validation_status::ASSERTION_COLLECTIONHASH_MALFORMED =>
                                {
                                    validation_status::ASSERTION_COLLECTIONHASH_MALFORMED
                                }
                                Error::C2PAValidation(code)
                                    if code
                                        == validation_status::ASSERTION_COLLECTIONHASH_INVALID_URI =>
                                {
                                    validation_status::ASSERTION_COLLECTIONHASH_INVALID_URI
                                }
                                Error::C2PAValidation(code)
                                    if code
                                        == validation_status::ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT =>
                                {
                                    validation_status::ASSERTION_COLLECTIONHASH_INCORRECT_FILE_COUNT
                                }
                                _ => validation_status::ASSERTION_COLLECTIONHASH_MISMATCH,
                            };

                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                format!("collection hash error: {err_str}"),
                                "verify_internal"
                            )
                            .validation_status(err_str)
                            .failure(
                                validation_log,
                                Error::HashMismatch(format!("asset hash failure: {err}")),
                            )?;
                        }
                    }
                } else {
                    log_item!(
                        claim.assertion_uri(&hash_binding_assertion.label()),
                        "hash binding unknown or not found",
                        "verify_internal"
                    )
                    .validation_status(validation_status::HARD_BINDINGS_MISSING)
                    .failure(
                        validation_log,
                        Error::HashMismatch("hash binding unknown format".into()),
                    )?;
                }
            }
        }

        Ok(())
    }

    pub(super) fn verify_internal(
        claim: &Claim,
        svi: &StoreValidationInfo,
        verified: Result<CertificateInfo>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<()> {
        // Statuses for this claim's signature are logged under its signature URI.
        let signature_uri = to_signature_uri(claim.label());
        let signature_has_status = |codes: &[&str]| {
            validation_log.logged_items().iter().any(|item| {
                item.label == signature_uri
                    && item
                        .validation_status
                        .as_deref()
                        .is_some_and(|code| codes.contains(&code))
            })
        };

        // C2PA only validates the claim signature, and issues
        // claimSignature.validated, "if the claim has not yet been rejected" by
        // the checks on its signing credential. An untrusted credential does not
        // count here; see SIGNING_CREDENTIAL_REJECTIONS.
        let credential_rejected = signature_has_status(SIGNING_CREDENTIAL_REJECTIONS);

        // signature check
        match verified {
            Ok(vi) => {
                if !vi.validated {
                    log_item!(
                        to_signature_uri(claim.label()),
                        "claim signature is not valid",
                        "verify_internal"
                    )
                    .validation_status(validation_status::CLAIM_SIGNATURE_MISMATCH)
                    .failure(validation_log, Error::CoseSignature)?;
                } else {
                    // signing cert has not expired
                    log_item!(
                        to_signature_uri(claim.label()),
                        "claim signature valid",
                        "verify_internal"
                    )
                    .validation_status(validation_status::CLAIM_SIGNATURE_INSIDE_VALIDITY)
                    .success(validation_log);

                    // add signature validated status
                    if !credential_rejected {
                        log_item!(
                            to_signature_uri(claim.label()),
                            "claim signature valid",
                            "verify_internal"
                        )
                        .validation_status(validation_status::CLAIM_SIGNATURE_VALIDATED)
                        .success(validation_log);
                    }
                }
            }
            Err(parse_err) => {
                // handle case where lower level failed to log
                log_item!(
                    to_signature_uri(claim.label()),
                    "claim signature is not valid",
                    "verify_internal"
                )
                .validation_status(validation_status::CLAIM_SIGNATURE_MISMATCH)
                .failure_no_throw(validation_log, parse_err);
            }
        };

        // if claim make sure we have a valid claim_generator_info
        // note that for 2.x claims this is a mandatory fields its presence
        // is checked during Claim cbor deserialization
        if let Some(cgi_vec) = claim.claim_generator_info() {
            let mut icons = Vec::new();
            for cgi in cgi_vec {
                if let Some(UriOrResource::HashedUri(icon)) = cgi.icon() {
                    icons.push(icon);
                }
            }
            if !icons.is_empty() {
                Claim::verify_icons(claim, &icons, validation_log)?;
            }
        }

        // check for self redacted assertions and illegal redactions
        if let Some(redactions) = claim.redactions() {
            for r in redactions {
                if r.contains(claim.label()) {
                    log_item!(
                        r.to_owned(),
                        "claim contains self redaction",
                        "verify_internal"
                    )
                    .validation_status(validation_status::ASSERTION_SELF_REDACTED)
                    .failure(validation_log, Error::ClaimSelfRedact)?;
                }

                if r.contains(labels::ACTIONS) {
                    log_item!(
                        r.to_owned(),
                        "redaction of action assertions disallowed",
                        "verify_internal"
                    )
                    .validation_status(validation_status::ASSERTION_ACTION_REDACTED)
                    .failure(validation_log, Error::ClaimDisallowedRedaction)?;
                }

                // check for disallowed hash redactions
                if labels::HASH_LABELS.iter().any(|label| r.contains(label)) {
                    log_item!(
                        r.to_owned(),
                        "redaction of disallowed hash assertion",
                        "verify_internal"
                    )
                    .validation_status(validation_status::ASSERTION_HARDBINDING_REDACTED)
                    .failure(validation_log, Error::ClaimDisallowedRedaction)?;
                }
            }
        }

        // get the parent count
        let parent_count = claim
            .ingredient_assertions()
            .iter()
            .filter(|a| {
                if let Ok(ingredient) = Ingredient::from_assertion(a.assertion()) {
                    let version = ingredient.version().unwrap_or(1);
                    let has_valid_parent = version <= 2 && ingredient.c2pa_manifest().is_some()
                        || ingredient.c2pa_manifest().is_some() && ingredient.signature().is_some();

                    return has_valid_parent && ingredient.relationship == Relationship::ParentOf;
                }
                false
            })
            .count();

        // check update manifest rules
        if claim.update_manifest() {
            // must be one of the allowed actions
            for aa in claim.action_assertions() {
                let actions = Actions::from_assertion(aa.assertion())?;
                for action in actions.actions() {
                    if !ALLOWED_UPDATE_MANIFEST_ACTIONS
                        .iter()
                        .any(|a| *a == action.action())
                    {
                        log_item!(
                            claim.uri(),
                            "update manifests contains disallowed actions assertion",
                            "verify_internal"
                        )
                        .validation_status(validation_status::MANIFEST_UPDATE_INVALID)
                        .failure(validation_log, Error::UpdateManifestInvalid)?;
                    }
                }
            }

            // make sure there are no thumbnail assertions
            if claim
                .claim_assertion_store()
                .iter()
                .any(|ca| ca.label_raw().contains(CLAIM_THUMBNAIL))
            {
                log_item!(
                    claim.uri(),
                    "update manifests cannot contain thumbnail assertions",
                    "verify_internal"
                )
                .validation_status(validation_status::MANIFEST_UPDATE_INVALID)
                .failure(validation_log, Error::UpdateManifestInvalid)?;
            }

            // make sure one ingredient parent
            match parent_count {
                0 => {
                    log_item!(
                        claim.uri(),
                        "update manifest must have ingredient with parentOf relationship",
                        "verify_internal"
                    )
                    .validation_status(validation_status::MANIFEST_UPDATE_WRONG_PARENTS)
                    .failure(validation_log, Error::UpdateManifestInvalid)?;
                }
                1 => (),
                _ => {
                    log_item!(
                        claim.uri(),
                        "update manifests can have one 1 ingredient ",
                        "verify_internal"
                    )
                    .validation_status(validation_status::MANIFEST_UPDATE_INVALID)
                    .failure(validation_log, Error::UpdateManifestInvalid)?;
                }
            }
        } else {
            // can only have zero or one parentOf
            if parent_count > 1 {
                log_item!(
                    claim.uri(),
                    "too many ingredient parents",
                    "ingredient_checks"
                )
                .validation_status(validation_status::MANIFEST_MULTIPLE_PARENTS)
                .failure(
                    validation_log,
                    Error::ClaimVerification("ingredient has more than one parent".to_string()),
                )?;
            }
        }

        // track list to make sure there are no extra assertions found in assertion store
        let mut ca_tracking_list = claim.claim_assertion_store().clone();

        // verify assertion structure comparing hashes from assertion list to contents of assertion store
        for assertion in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&assertion.url());
            let assertion_absolute_uri = if assertion.is_relative_url() {
                to_absolute_uri(claim.label(), &assertion.url())
            } else {
                // make sure the assertion points to this assertion store
                let Some(assertion_manifest) = manifest_label_from_uri(&assertion.url()) else {
                    log_item!(
                        assertion.url(),
                        format!("assertion URI malformed: {}", assertion.url()),
                        "verify_internal"
                    )
                    .validation_status(validation_status::ASSERTION_HASHEDURI_MISMATCH)
                    .failure_no_throw(
                        validation_log,
                        Error::AssertionMissing {
                            url: assertion.url(),
                        },
                    );
                    continue;
                };

                if assertion_manifest != claim.label() {
                    log_item!(
                        assertion.url(),
                        format!(
                            "assertion reference to external assertion store: {}",
                            assertion.url()
                        ),
                        "verify_internal"
                    )
                    .validation_status(validation_status::ASSERTION_OUTSIDE_MANIFEST)
                    .failure(
                        validation_log,
                        Error::AssertionMissing {
                            url: assertion.url(),
                        },
                    )?;
                };

                assertion.url()
            };

            // remove from tracking list
            if let Some(index) = ca_tracking_list
                .iter()
                .position(|v| v.label_raw().as_str() == label && v.instance() == instance)
            {
                ca_tracking_list.swap_remove(index);
            }

            // we can skip if this is a redacted assertion
            if svi.redactions.iter().any(|r| {
                let r_manifest = manifest_label_from_uri(r).unwrap_or_default();
                if r_manifest == claim.label() {
                    let (r_label, r_instance) = Claim::assertion_label_from_link(r);
                    r_label == label && r_instance == instance
                } else {
                    false
                }
            }) {
                continue;
            }

            // make sure assertion data has not changed
            match claim.get_claim_assertion(&label, instance) {
                // get the assertion if label and hash match
                Some(ca) => {
                    // if not a redaction then we must check the hash
                    if !vec_compare(ca.hash(), &assertion.hash()) {
                        log_item!(
                            assertion_absolute_uri.clone(),
                            format!("hash does not match assertion data: {}", assertion.url()),
                            "verify_internal"
                        )
                        .validation_status(validation_status::ASSERTION_HASHEDURI_MISMATCH)
                        .failure(
                            validation_log,
                            Error::HashMismatch(format!(
                                "Assertion hash failure: {}",
                                assertion_absolute_uri.clone(),
                            )),
                        )?;
                    } else {
                        log_item!(
                            assertion_absolute_uri,
                            format!("hashed uri matched: {}", assertion.url()),
                            "verify_internal"
                        )
                        .validation_status(validation_status::ASSERTION_HASHEDURI_MATCH)
                        .success(validation_log);
                    }
                }
                None => {
                    log_item!(
                        assertion_absolute_uri.clone(),
                        format!("cannot find matching assertion: {}", assertion.url()),
                        "verify_internal"
                    )
                    .validation_status(validation_status::ASSERTION_MISSING)
                    .failure_no_throw(
                        validation_log,
                        Error::AssertionMissing {
                            url: assertion_absolute_uri.clone(),
                        },
                    );
                }
            }
        }

        // we should have accounted for all assertions in the store
        if !ca_tracking_list.is_empty() {
            // log all unaccessed assertions and return err
            for undeclared in &ca_tracking_list {
                log_item!(
                    undeclared.label().clone(),
                    "assertion is not referenced by the claim",
                    "verify_internal"
                )
                .validation_status(validation_status::ASSERTION_UNDECLARED)
                .failure_no_throw(
                    validation_log,
                    Error::AssertionMissing {
                        url: undeclared.label(),
                    },
                );
            }
            return Err(Error::AssertionMissing {
                url: ca_tracking_list[0].label(),
            });
        }

        // check action rules
        Claim::verify_actions(claim, svi, validation_log, context.settings())?;

        // check metadata rules
        if claim.version() >= 2 {
            // only for claim version 2 or greater
            Claim::verify_metadata(claim, validation_log)?;
            Claim::verify_claim_generator_info(claim, validation_log)?;
        }

        // soft binding algorithm validation applies to all claim versions
        Claim::verify_soft_binding_alg(
            claim,
            context
                .settings()
                .soft_binding
                .soft_binding_algorithms
                .as_deref()
                .unwrap_or(&[]),
            validation_log,
        )?;

        // cloud-data assertion validation applies to all claim versions
        Claim::verify_cloud_data(claim, validation_log)?;

        // external-reference assertion validation applies to all claim versions
        Claim::verify_external_reference(claim, validation_log)?;

        Ok(())
    }

    // Validate claim_generator_info for v2+ claims per §10.2.2.
    // Must be present, non-empty, and have a non-empty name field.
    pub(super) fn verify_claim_generator_info(
        claim: &Claim,
        validation_log: &mut StatusTracker,
    ) -> Result<()> {
        match claim.claim_generator_info() {
            None | Some([]) => {
                log_item!(
                    claim.uri(),
                    "claim_generator_info is required for v2+ claims",
                    "verify_claim_generator_info"
                )
                .validation_status(validation_status::CLAIM_MALFORMED)
                .failure(
                    validation_log,
                    Error::ClaimDecoding("claim_generator_info is missing".to_string()),
                )?;
            }
            Some(cgi) => {
                if cgi[0].name.is_empty() {
                    log_item!(
                        claim.uri(),
                        "claim_generator_info name must not be empty",
                        "verify_claim_generator_info"
                    )
                    .validation_status(validation_status::CLAIM_MALFORMED)
                    .failure(
                        validation_log,
                        Error::ClaimDecoding("claim_generator_info name is empty".to_string()),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Validate that each soft binding assertion's effective algorithm is in the
    /// C2PA soft binding algorithm registry (§9.3.2).
    ///
    /// The effective algorithm is the assertion-level `alg` field when present,
    /// falling back to the claim-level `alg_soft` field. If neither is present
    /// the assertion is malformed.
    /// Starting with C2PA 2.4 we no longer require soft binding alg to be on the
    /// official list.  This allows for future algorithm support without code changes.
    /// The function now will only check the structure of the assertion.
    pub(super) fn verify_soft_binding_alg(
        claim: &Claim,
        _soft_binding_algs: &[String],
        validation_log: &mut StatusTracker,
    ) -> Result<()> {
        use assertions::SoftBinding;

        for ca in claim.soft_binding_assertions() {
            let label = to_assertion_uri(claim.label(), &ca.label());

            let _soft_binding = match SoftBinding::from_assertion(ca.assertion()) {
                Ok(soft_binding) => soft_binding,
                Err(_) => {
                    log_item!(
                        label.clone(),
                        "soft binding assertion could not be decoded",
                        "verify_soft_binding_alg"
                    )
                    .validation_status(validation_status::CLAIM_MALFORMED)
                    .failure_no_throw(validation_log, Error::ClaimDecoding(label.clone()));

                    // Malformed, but don't abort the whole verification over one
                    // bad soft binding assertion -- move on to the next one.
                    continue;
                }
            };

            /*
            // Effective alg: assertion field takes precedence over claim-level alg_soft.
            let effective_alg = soft_binding
                .alg
                .as_deref()
                .or_else(|| claim.alg_soft().map(String::as_str));

            match effective_alg {
                None => {
                    log_item!(
                        label.clone(),
                        "soft binding assertion has no algorithm (alg or alg_soft required)",
                        "verify_soft_binding_alg"
                    )
                    .validation_status(validation_status::CLAIM_MALFORMED)
                    .failure(
                        validation_log,
                        Error::ValidationRule("soft binding missing algorithm".into()),
                    )?;
                }
                Some(alg) if !soft_binding_algs.iter().any(|a| a == alg) => {
                    log_item!(
                        label.clone(),
                        format!("soft binding algorithm '{alg}' is not in the C2PA soft binding algorithm registry"),
                        "verify_soft_binding_alg"
                    )
                    .validation_status(validation_status::ALGORITHM_UNSUPPORTED)
                    .failure(
                        validation_log,
                        Error::ValidationRule(format!(
                            "unsupported soft binding algorithm: {alg}"
                        )),
                    )?;
                }
                Some(_) => {}
            }
            */
        }
        Ok(())
    }

    /// Validate each `c2pa.cloud-data` assertion per §15.10.3.2.1.
    ///
    /// Checks:
    /// 1. Required fields (`assertion`/label, `size`, `url`/location, `format`/content_type)
    ///    are present — failure code `assertion.cloud-data.malformed`.
    /// 2. The referenced assertion must not be a hard binding type — failure code
    ///    `assertion.cloud-data.hardBinding`.
    /// 3. In an update manifest the referenced assertion must not be an actions
    ///    assertion — failure code `assertion.cloud-data.actions`.
    ///
    /// No fetching of the cloud data is performed, only the structure of the assertion is checked.
    pub(super) fn verify_cloud_data(
        claim: &Claim,
        validation_log: &mut StatusTracker,
    ) -> Result<()> {
        use assertions::CloudData;

        for ca in claim.cloud_data_assertions() {
            let label = to_assertion_uri(claim.label(), &ca.label());

            let cloud_data = match CloudData::from_assertion(ca.assertion()) {
                Ok(cloud_data) => cloud_data,
                Err(_) => {
                    log_item!(
                        label.clone(),
                        "cloud-data assertion could not be decoded",
                        "verify_cloud_data"
                    )
                    .validation_status(validation_status::ASSERTION_CLOUD_DATA_MALFORMED)
                    .failure_no_throw(validation_log, Error::ClaimDecoding(label.clone()));

                    // Malformed, but don't abort the whole verification over one
                    // bad cloud-data assertion -- move on to the next one.
                    continue;
                }
            };

            // Step 1: size must be at least 1 byte.
            if cloud_data.size < 1 {
                log_item!(
                    label.clone(),
                    "cloud-data assertion has invalid size (must be >= 1)",
                    "verify_cloud_data"
                )
                .validation_status(validation_status::ASSERTION_CLOUD_DATA_MALFORMED)
                .failure_no_throw(validation_log, Error::ClaimDecoding(label.clone()));
            }

            // Step 2: hard binding assertions must not be stored as cloud data.
            if cloud_data.is_hard_binding() {
                log_item!(
                    label.clone(),
                    "cloud-data assertion references a hard binding assertion",
                    "verify_cloud_data"
                )
                .validation_status(validation_status::ASSERTION_CLOUD_DATA_HARD_BINDING)
                .failure_no_throw(validation_log, Error::ClaimDecoding(label.clone()));
            }

            // Step 3: actions assertions must not be stored as cloud data in update manifests.
            if claim.update_manifest() && cloud_data.is_actions() {
                log_item!(
                    label.clone(),
                    "cloud-data assertion references an actions assertion in an update manifest",
                    "verify_cloud_data"
                )
                .validation_status(validation_status::ASSERTION_CLOUD_DATA_ACTIONS)
                .failure_no_throw(validation_log, Error::ClaimDecoding(label.clone()));
            }

            // Check for forbbidden label types, including hard bindings and the cloud-data assertion itself.
            if cloud_data.is_forbidden().is_err() {
                log_item!(
                    label.clone(),
                    "cloud-data assertion references a forbidden label",
                    "verify_cloud_data"
                )
                .validation_status(validation_status::ASSERTION_CLOUD_DATA_MALFORMED)
                .failure_no_throw(validation_log, Error::ClaimDecoding(label.clone()));
            }
        }

        Ok(())
    }

    /// Validate each `c2pa.external-reference` assertion per C2PA 2.4.
    /// No fetching of the external reference is performed, only the structure of the assertion is checked.
    pub(super) fn verify_external_reference(
        claim: &Claim,
        validation_log: &mut StatusTracker,
    ) -> Result<()> {
        use assertions::ExternalReference;

        for ca in claim.assertions_by_type(
            &Assertion::new(
                assertions::labels::EXTERNAL_REFERENCE,
                None,
                AssertionData::Cbor(Vec::new()),
            ),
            None,
        ) {
            let label = to_assertion_uri(claim.label(), &ca.label());

            let external_reference = match ExternalReference::from_assertion(ca.assertion()) {
                Ok(external_reference) => external_reference,
                Err(_) => {
                    log_item!(
                        label.clone(),
                        "external-reference assertion could not be decoded",
                        "verify_external_reference"
                    )
                    .validation_status(validation_status::ASSERTION_EXTERNAL_REFERENCE_MALFORMED)
                    .failure_no_throw(validation_log, Error::ClaimDecoding(label.clone()));
                    continue;
                }
            };

            if let Err(err) = external_reference.validate() {
                log_item!(label.clone(), err.to_string(), "verify_external_reference")
                    .validation_status(validation_status::ASSERTION_EXTERNAL_REFERENCE_MALFORMED)
                    .failure_no_throw(validation_log, err);
            }
        }

        Ok(())
    }

    // Perform metadata validation check.
    // Check the structure only.  C2PA 2.4 no longer requires checking against allowed fields.
    fn verify_metadata(claim: &Claim, _validation_log: &mut StatusTracker) -> Result<()> {
        for metadata_assertion in claim.metadata_assertions() {
            Metadata::from_assertion(metadata_assertion.assertion())?;
        }
        Ok(())
    }
}
