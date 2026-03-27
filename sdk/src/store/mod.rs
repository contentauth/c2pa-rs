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
    io::Cursor,
};

use async_generic::async_generic;
use log::error;

use crate::{
    assertion::{Assertion, AssertionBase, AssertionData, AssertionDecodeError},
    assertions::{
        labels::{self, CLAIM},
        DataBox, Ingredient, Relationship, User, UserCbor,
    },
    claim::{check_ocsp_status, check_ocsp_status_async, Claim, ClaimAssertion},
    context::{Context, ProgressPhase},
    cose_sign::{cose_sign, cose_sign_async},
    cose_validator::{verify_cose, verify_cose_async},
    crypto::{
        asn1::rfc3161::TstInfo,
        cose::{
            fetch_and_check_ocsp_response, fetch_and_check_ocsp_response_async, parse_cose_sign1,
            CertificateTrustPolicy, TimeStampStorage,
        },
        hash::sha256,
    },
    dynamic_assertion::{
        AsyncDynamicAssertion, DynamicAssertion, DynamicAssertionContent, PartialClaim,
    },
    error::{Error, Result},
    hash_utils::{hash_by_alg, vec_compare},
    hashed_uri::HashedUri,
    jumbf::{
        self,
        boxes::*,
        labels::{
            manifest_label_from_uri, manifest_label_to_parts, to_assertion_uri, ASSERTIONS,
            CREDENTIALS, DATABOXES, SIGNATURE,
        },
    },
    log_item,
    manifest_store_report::ManifestStoreReport,
    settings::{builder::OcspFetchScope, Settings},
    status_tracker::{ErrorBehavior, StatusTracker},
    utils::{hash_utils::HashRange, is_zero, patch::patch_bytes},
    validation_results::validation_codes::{
        ASSERTION_CBOR_INVALID, ASSERTION_JSON_INVALID, ASSERTION_MISSING, CLAIM_MALFORMED,
    },
    validation_status::{self, ALGORITHM_UNSUPPORTED},
    AsyncSigner, Signer,
};

const MANIFEST_STORE_EXT: &str = "c2pa"; // file extension for external manifests
mod store_io;
#[cfg(feature = "fetch_remote_manifests")]
const DEFAULT_MANIFEST_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

pub(crate) struct ManifestHashes {
    pub manifest_box_hash: Vec<u8>,
    pub signature_box_hash: Vec<u8>,
}

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
}

/// A `Store` maintains a list of `Claim` structs.
///
/// Typically, this list of `Claim`s represents all of the claims in an asset.
#[derive(Debug)]
pub struct Store {
    claims_map: HashMap<String, Claim>,
    claims: Vec<String>, // maintains order of claims
    manifest_box_hash_cache: HashMap<String, (Vec<u8>, Vec<u8>)>,
    label: String,
    provenance_path: Option<String>,
    ctp: CertificateTrustPolicy,
    remote_url: Option<String>,
    embedded: bool,
}

struct ManifestInfo<'a> {
    pub desc_box: &'a JUMBFDescriptionBox,
    pub sbox: &'a JUMBFSuperBox,
}

impl Default for Store {
    fn default() -> Self {
        Self::from_context(&Context::new())
    }
}

impl Store {
    /// Create a new, empty claims store with default settings.
    pub fn new() -> Self {
        Store {
            claims_map: HashMap::new(),
            manifest_box_hash_cache: HashMap::new(),
            claims: Vec::new(),
            label: MANIFEST_STORE_EXT.to_string(),
            ctp: CertificateTrustPolicy::default(),
            provenance_path: None,
            remote_url: None,
            embedded: false,
        }
    }

    /// Create a new, empty claims store with the specified settings.
    pub fn from_context(context: &Context) -> Self {
        let mut store = Store::new();
        let settings = context.settings();

        // load the trust handler settings, don't worry about status as these are checked during setting generation
        if let Some(ta) = &settings.trust.trust_anchors {
            let _v = store.add_trust(ta.as_bytes());
        }

        if let Some(pa) = &settings.trust.user_anchors {
            let _v = store.add_user_trust_anchors(pa.as_bytes());
        }

        if let Some(tc) = &settings.trust.trust_config {
            let _v = store.add_trust_config(tc.as_bytes());
        }

        if let Some(al) = &settings.trust.allowed_list {
            let _v = store.add_trust_allowed_list(al.as_bytes());
        }

        store
    }

    // Append new Store to the current Store preserving the order from the new Store
    pub(crate) fn append_store(&mut self, store: &Store) {
        for claim in store.claims() {
            self.insert_restored_claim(claim.label().to_string(), claim.clone());
        }
    }

    /// Return label for the store
    #[allow(dead_code)] // doesn't harm to have this
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the remote url of the manifest if this [`Store`] was obtained remotely.
    pub fn remote_url(&self) -> Option<&str> {
        self.remote_url.as_deref()
    }

    /// Returns if the [`Store`] was created from an embedded manifest.
    pub fn is_embedded(&self) -> bool {
        self.embedded
    }

    /// Load set of trust anchors used for certificate validation. [u8] containing the
    /// trust anchors is passed in the trust_vec variable.
    pub fn add_trust(&mut self, trust_vec: &[u8]) -> Result<()> {
        Ok(self.ctp.add_trust_anchors(trust_vec)?)
    }

    // Load set of user trust anchors used for certificate validation. [u8] to the
    /// user trust anchors is passed in the trust_vec variable.  This can be called multiple times
    /// if there are additional trust stores.
    pub fn add_user_trust_anchors(&mut self, trust_vec: &[u8]) -> Result<()> {
        Ok(self.ctp.add_user_trust_anchors(trust_vec)?)
    }

    pub fn add_trust_config(&mut self, trust_vec: &[u8]) -> Result<()> {
        self.ctp.add_valid_ekus(trust_vec);
        Ok(())
    }

    pub fn add_trust_allowed_list(&mut self, allowed_vec: &[u8]) -> Result<()> {
        Ok(self.ctp.add_end_entity_credentials(allowed_vec)?)
    }

    /// Get the provenance if available.
    /// If loaded from an existing asset it will be provenance from the last claim.
    /// If a new claim is committed that will be the provenance claim
    pub fn provenance_path(&self) -> Option<String> {
        self.provenance_path.as_ref().cloned()
    }

    // set the path of the current provenance claim
    pub fn set_provenance_path(&mut self, claim: &Claim) {
        let path = claim.to_claim_uri();
        self.provenance_path = Some(path);
    }

    /// get the list of claims for this store in the order they were added
    pub fn claims(&self) -> Vec<&Claim> {
        self.claims
            .iter()
            .filter_map(|l| self.claims_map.get(l))
            .collect()
    }

    /// the JUMBF manifest box hash (spec 1.2) and signature box hash (2.x)
    pub(crate) fn get_manifest_box_hashes(&self, claim: &Claim) -> ManifestHashes {
        if let Some((mbh, sbh)) = self.manifest_box_hash_cache.get(claim.label()) {
            ManifestHashes {
                manifest_box_hash: mbh.clone(),
                signature_box_hash: sbh.clone(),
            }
        } else {
            ManifestHashes {
                manifest_box_hash: Store::calc_manifest_box_hash(claim, None, claim.alg())
                    .unwrap_or_default(),
                signature_box_hash: Claim::calc_sig_box_hash(claim, claim.alg())
                    .unwrap_or_default(),
            }
        }
    }

    // remove a claim from the store
    pub(crate) fn remove_claim(&mut self, label: &str) -> Option<Claim> {
        self.claims.retain(|l| l != label);
        self.claims_map.remove(label)
    }

    /// Add a new Claim to this Store. The function
    /// will return the label of the claim.
    pub fn commit_claim(&mut self, mut claim: Claim) -> Result<String> {
        // make sure there is no pending unsigned claim
        if let Some(pc) = self.provenance_claim() {
            if pc.signature_val().is_empty() {
                return Err(Error::ClaimUnsigned);
            }
        }
        // verify the claim is valid
        claim.build()?;

        // update the provenance path
        self.set_provenance_path(&claim);

        let claim_label = claim.label().to_string();

        // add ingredients claims to the store claims
        // replace any existing claims with the same label
        for ingredient in claim.claim_ingredients() {
            if self
                .claims_map
                .insert(ingredient.label().to_string(), ingredient.clone())
                .is_none()
            {
                self.claims.push(ingredient.label().to_string());
            }
        }

        // add to new claim to list of claims
        self.claims.push(claim_label.clone());
        self.claims_map.insert(claim_label.clone(), claim);

        Ok(claim_label)
    }

    /// Add a new update manifest to this Store. The manifest label
    /// may be updated to reflect is position in the manifest Store
    /// if there are conflicting label names.  The function
    /// will return the label of the claim used
    #[allow(unused)]
    pub fn update_manifest_test(&mut self, claim: &Claim) -> Result<()> {
        use crate::{
            assertions::{labels::CLAIM_THUMBNAIL, Actions},
            claim::ALLOWED_UPDATE_MANIFEST_ACTIONS,
        };

        // check for disallowed assertions
        if claim.has_assertion_type(labels::DATA_HASH)
            || claim.has_assertion_type(labels::BOX_HASH)
            || claim.has_assertion_type(labels::BMFF_HASH)
            || claim.has_assertion_type(labels::COLLECTION_HASH)
        {
            return Err(Error::ClaimInvalidContent);
        }

        // must have exactly one ingredient
        let ingredient_assertions = claim.ingredient_assertions();
        if ingredient_assertions.len() != 1 {
            return Err(Error::ClaimInvalidContent);
        }

        let ingredient = Ingredient::from_assertion(ingredient_assertions[0].assertion())?;

        // must have a parent relationship
        if ingredient.relationship != Relationship::ParentOf {
            return Err(Error::IngredientNotFound);
        }

        // make sure ingredient c2pa.manifest points to provenance claim
        if let Some(c2pa_manifest) = ingredient.c2pa_manifest() {
            // the manifest should refer to provenance claim
            if let Some(pc) = self.provenance_claim() {
                if !c2pa_manifest.url().contains(pc.label()) {
                    return Err(Error::IngredientNotFound);
                }
            } else {
                // when called from builder, there will be no provenance claim yet
                // so we cannot verify the manifest url, but we just created it.
                // return Err(Error::IngredientNotFound);
            }
        } else {
            return Err(Error::IngredientNotFound);
        }

        // must be one of the allowed actions
        for aa in claim.action_assertions() {
            let actions = Actions::from_assertion(aa.assertion())?;
            for action in actions.actions() {
                if !ALLOWED_UPDATE_MANIFEST_ACTIONS
                    .iter()
                    .any(|a| *a == action.action())
                {
                    return Err(Error::ClaimInvalidContent);
                }
            }
        }

        // thumbnail assertions are not allowed
        if claim
            .claim_assertion_store()
            .iter()
            .any(|ca| ca.label_raw().contains(CLAIM_THUMBNAIL))
        {
            return Err(Error::OtherError(
                "only one claim thumbnail assertion allowed".into(),
            ));
        }

        Ok(())
    }

    /// Add a new update manifest to this Store. The manifest label
    /// may be updated to reflect is position in the manifest Store
    /// if there are conflicting label names.  The function
    /// will return the label of the claim used
    #[allow(unused)]
    pub fn commit_update_manifest(&mut self, mut claim: Claim) -> Result<String> {
        self.update_manifest_test(&claim)?;

        claim.set_update_manifest(true);

        self.commit_claim(claim)
    }

    /// Get Claim by label
    // Returns Option<&Claim>
    pub fn get_claim(&self, label: &str) -> Option<&Claim> {
        self.claims_map.get(label)
    }

    /// Get Claim by label
    // Returns Option<&Claim>
    pub fn get_claim_mut(&mut self, label: &str) -> Option<&mut Claim> {
        self.claims_map.get_mut(label)
    }

    /// returns a Claim given a jumbf uri
    pub fn get_claim_from_uri(&self, uri: &str) -> Result<&Claim> {
        let claim_label = Store::manifest_label_from_path(uri);
        self.get_claim(&claim_label)
            .ok_or_else(|| Error::ClaimMissing {
                label: claim_label.to_owned(),
            })
    }

    /// returns a ClaimAssertion given a jumbf uri, resolving to the right claim in the store
    pub fn get_claim_assertion_from_uri(&self, uri: &str) -> Result<&ClaimAssertion> {
        // first find the right claim and then look for the assertion there
        let claim = self.get_claim_from_uri(uri)?;
        let (label, instance) = Claim::assertion_label_from_link(uri);
        claim
            .get_claim_assertion(&label, instance)
            .ok_or_else(|| Error::AssertionMissing {
                url: uri.to_owned(),
            })
    }

    /// Returns an Assertion referenced by JUMBF URI.  The URI should be absolute and include
    /// the desired Claim in the path. If you need to specify the Claim for this URI use
    /// get_assertion_from_uri_and_claim.
    /// uri - The JUMBF URI for desired Assertion.
    pub fn get_assertion_from_uri(&self, uri: &str) -> Option<&Assertion> {
        let claim_label = Store::manifest_label_from_path(uri);
        let (assertion_label, instance) = Claim::assertion_label_from_link(uri);

        if let Some(claim) = self.get_claim(&claim_label) {
            claim.get_assertion(&assertion_label, instance)
        } else {
            None
        }
    }

    /// Returns an Assertion referenced by JUMBF URI. Only the Claim specified by target_claim_label
    /// will be searched.  The target_claim_label can be a Claim label or JUMBF URI.
    /// uri - The JUMBF URI for desired Assertion.
    /// target_claim_label - Label or URI of the Claim to search for the case when the URI is a relative path.
    pub fn get_assertion_from_uri_and_claim(
        &self,
        uri: &str,
        target_claim_label: &str,
    ) -> Option<&Assertion> {
        let (assertion_label, instance) = Claim::assertion_label_from_link(uri);

        let label = Store::manifest_label_from_path(target_claim_label);

        if let Some(claim) = self.get_claim(&label) {
            claim.get_assertion(&assertion_label, instance)
        } else {
            None
        }
    }

    /// Returns a DataBox referenced by JUMBF URI if it exists.
    ///
    /// Relative paths will use the provenance claim to resolve the DataBox.d
    pub fn get_data_box_from_uri_and_claim(
        &self,
        hr: &HashedUri,
        target_claim_label: &str,
    ) -> Option<&DataBox> {
        match jumbf::labels::manifest_label_from_uri(&hr.url()) {
            Some(label) => self.get_claim(&label), // use the manifest label from the thumbnail uri
            None => self.get_claim(target_claim_label), //  relative so use the target claim label
        }
        .and_then(|claim| claim.get_databox(hr))
    }

    // Returns placeholder that will be searched for and replaced
    // with actual signature data.
    fn sign_claim_placeholder(claim: &Claim, min_reserve_size: usize) -> Vec<u8> {
        let placeholder_str = format!("signature placeholder:{}", claim.label());
        let mut placeholder = sha256(placeholder_str.as_bytes());

        use std::cmp::max;
        placeholder.resize(max(placeholder.len(), min_reserve_size), 0);

        placeholder
    }

    /// Return OCSP info if available
    // Currently only called from manifest_store behind a feature flag but this is allowable
    // anywhere so allow dead code here for future uses to compile
    #[allow(dead_code)]
    #[async_generic]
    pub fn get_ocsp_status(&self, context: &Context) -> Option<String> {
        let claim = self
            .provenance_claim()
            .ok_or(Error::ProvenanceMissing)
            .ok()?;

        let sig = claim.signature_val();
        let data = claim.data().ok()?;
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        let sign1 = parse_cose_sign1(sig, &data, &mut validation_log).ok()?;
        let ocsp_status = if _sync {
            check_ocsp_status(
                &sign1,
                &data,
                &self.ctp,
                None,
                None,
                &mut validation_log,
                context,
            )
        } else {
            check_ocsp_status_async(
                &sign1,
                &data,
                &self.ctp,
                None,
                None,
                &mut validation_log,
                context,
            )
            .await
        };
        if let Ok(info) = ocsp_status {
            if let Some(revoked_at) = &info.revoked_at {
                Some(format!(
                    "Certificate Status: Revoked, revoked at: {revoked_at}"
                ))
            } else {
                Some(format!(
                    "Certificate Status: Good, next update: {}",
                    info.next_update
                ))
            }
        } else {
            None
        }
    }

    /// Sign the claim and return signature.
    #[async_generic(async_signature(
        &self,
        claim: &Claim,
        signer: &dyn AsyncSigner,
        box_size: usize,
        settings: &Settings,
    ))]
    pub fn sign_claim(
        &self,
        claim: &Claim,
        signer: &dyn Signer,
        box_size: usize,
        settings: &Settings,
    ) -> Result<Vec<u8>> {
        let claim_bytes = claim.data()?;

        // no verification of timestamp trust while signing
        let mut adjusted_settings = settings.clone();
        adjusted_settings.verify.verify_timestamp_trust = false;

        let tss = if claim.version() > 1 {
            TimeStampStorage::V2_sigTst2_CTT
        } else {
            TimeStampStorage::V1_sigTst
        };

        let result = if _sync {
            if signer.direct_cose_handling() {
                // Let the signer do all the COSE processing and return the structured COSE data.
                return signer.sign(&claim_bytes); // do not verify remote signers (we never did)
            } else {
                cose_sign(signer, &claim_bytes, box_size, tss, &adjusted_settings)
            }
        } else {
            if signer.direct_cose_handling() {
                // Let the signer do all the COSE processing and return the structured COSE data.
                return signer.sign(claim_bytes.clone()).await;
            // do not verify remote signers (we never did)
            } else {
                cose_sign_async(signer, &claim_bytes, box_size, tss, settings).await
            }
        };
        match result {
            Ok(sig) => {
                // Sanity check: Ensure that this signature is valid.
                let verify_after_sign = settings.verify.verify_after_sign;

                if verify_after_sign {
                    let mut cose_log =
                        StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

                    let result = if _sync {
                        verify_cose(
                            &sig,
                            &claim_bytes,
                            b"",
                            false,
                            &self.ctp,
                            None,
                            &mut cose_log,
                            &adjusted_settings,
                        )
                    } else {
                        verify_cose_async(
                            &sig,
                            &claim_bytes,
                            b"",
                            false,
                            &self.ctp,
                            None,
                            &mut cose_log,
                            &adjusted_settings,
                        )
                        .await
                    };
                    if let Err(err) = result {
                        error!("Signature that was just generated does not validate: {err:#?}");
                        return Err(err);
                    }
                }

                Ok(sig)
            }
            Err(e) => Err(e),
        }
    }

    /// Retrieves all manifest labels that need to fetch ocsp responses.
    pub fn get_manifest_labels_for_ocsp(&self, settings: &Settings) -> Vec<String> {
        let labels = match settings.builder.certificate_status_fetch {
            Some(ocsp_fetch) => match ocsp_fetch {
                OcspFetchScope::All => self.claims.clone(),
                OcspFetchScope::Active => {
                    if let Some(active_label) = self.provenance_label() {
                        vec![active_label]
                    } else {
                        Vec::new()
                    }
                }
            },
            None => Vec::new(),
        };

        match settings.builder.certificate_status_should_override {
            Some(should_override) => {
                if !should_override {
                    labels
                        .into_iter()
                        .filter(|label| {
                            self.claims_map
                                .get(label)
                                .is_some_and(|claim| !claim.has_ocsp_vals())
                        })
                        .collect()
                } else {
                    labels
                }
            }
            _ => Vec::new(),
        }
    }

    /// return the current provenance claim label if available
    pub fn provenance_label(&self) -> Option<String> {
        self.provenance_path()
            .map(|provenance| Store::manifest_label_from_path(&provenance))
    }

    /// return the current provenance claim if available
    pub fn provenance_claim(&self) -> Option<&Claim> {
        match self.provenance_path() {
            Some(provenance) => {
                let claim_label = Store::manifest_label_from_path(&provenance);
                self.get_claim(&claim_label)
            }
            None => None,
        }
    }

    /// return the current provenance claim as mutable if available
    pub fn provenance_claim_mut(&mut self) -> Option<&mut Claim> {
        match self.provenance_path() {
            Some(provenance) => {
                let claim_label = Store::manifest_label_from_path(&provenance);
                self.get_claim_mut(&claim_label)
            }
            None => None,
        }
    }

    // add a restored claim
    pub(crate) fn insert_restored_claim(&mut self, label: String, claim: Claim) {
        self.set_provenance_path(&claim);
        self.claims_map.insert(label.clone(), claim);
        self.claims.push(label);
    }

    // replace a claim if it already exists
    pub(crate) fn replace_claim_or_insert(&mut self, label: String, claim: Claim) {
        if self.get_claim(&label).is_some() {
            self.claims_map.insert(label.clone(), claim);
        } else {
            self.insert_restored_claim(label, claim);
        }
    }

    fn add_assertion_to_jumbf_store(
        store: &mut CAIAssertionStore,
        claim_assertion: &ClaimAssertion,
    ) -> Result<()> {
        // Grab assertion data object.
        let d = claim_assertion.assertion().decode_data();

        match d {
            AssertionData::Json(_) => {
                let mut json_data = CAIJSONAssertionBox::new(&claim_assertion.label());
                json_data.add_json(claim_assertion.assertion().data().to_vec());
                if let Some(salt) = claim_assertion.salt() {
                    json_data.set_salt(salt.clone())?;
                }
                store.add_assertion(Box::new(json_data));
            }
            AssertionData::Binary(_) => {
                // TODO: Handle other binary box types if needed.
                let mut data = JumbfEmbeddedFileBox::new(&claim_assertion.label());
                data.add_data(
                    claim_assertion.assertion().data().to_vec(),
                    claim_assertion.assertion().mime_type(),
                    None,
                );
                if let Some(salt) = claim_assertion.salt() {
                    data.set_salt(salt.clone())?;
                }
                store.add_assertion(Box::new(data));
            }
            AssertionData::Cbor(_) => {
                let mut cbor_data = CAICBORAssertionBox::new(&claim_assertion.label());
                cbor_data.add_cbor(claim_assertion.assertion().data().to_vec());
                if let Some(salt) = claim_assertion.salt() {
                    cbor_data.set_salt(salt.clone())?;
                }
                store.add_assertion(Box::new(cbor_data));
            }
            AssertionData::Uuid(s, _) => {
                let mut uuid_data = CAIUUIDAssertionBox::new(&claim_assertion.label());
                uuid_data.add_uuid(s, claim_assertion.assertion().data().to_vec())?;
                if let Some(salt) = claim_assertion.salt() {
                    uuid_data.set_salt(salt.clone())?;
                }
                store.add_assertion(Box::new(uuid_data));
            }
        }
        Ok(())
    }

    // look for old style hashing to determine if this is a pre 1.0 claim
    fn is_old_assertion(alg: &str, data: &[u8], original_hash: &[u8]) -> bool {
        let old_hash = hash_by_alg(alg, data, None);
        vec_compare(&old_hash, original_hash)
    }

    fn get_assertion_from_jumbf_store(
        claim: &Claim,
        assertion_box: &JUMBFSuperBox,
        label: &str,
        check_for_legacy_assertion: bool,
        validation_log: &mut StatusTracker,
    ) -> Result<ClaimAssertion> {
        let assertion_desc_box = assertion_box.desc_box();

        let (raw_label, instance) = Claim::assertion_label_from_link(label);
        let instance_label = Claim::label_with_instance(&raw_label, instance);
        let (assertion_hashed_uri, claim_assertion_type) = claim
            .assertion_hashed_uri_from_label(&instance_label)
            .ok_or_else(|| {
                log_item!(
                    label.to_owned(),
                    "error loading assertion",
                    "get_assertion_from_jumbf_store"
                )
                .validation_status(ASSERTION_MISSING)
                .failure_as_err(
                    validation_log,
                    Error::AssertionMissing {
                        url: instance_label.to_string(),
                    },
                )
            })?;

        let alg = match assertion_hashed_uri.alg() {
            Some(ref a) => a.clone(),
            None => claim.alg().to_string(),
        };

        // get salt value if set
        let salt = assertion_desc_box.get_salt();

        let result = match assertion_desc_box.uuid().as_ref() {
            CAI_JSON_ASSERTION_UUID => {
                let json_box = assertion_box
                    .data_box_as_json_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;

                let assertion = Assertion::from_data_json(&raw_label, json_box.json())?;

                // make sure it is JSON
                if let Err(e) = serde_json::from_slice::<serde_json::Value>(json_box.json()) {
                    log_item!(
                        label.to_owned(),
                        "invalid assertion json",
                        "get_assertion_from_jumbf_store"
                    )
                    .validation_status(ASSERTION_JSON_INVALID)
                    .failure(
                        validation_log,
                        Error::AssertionDecoding(
                            AssertionDecodeError::from_assertion_and_json_err(&assertion, e),
                        ),
                    )?;
                }

                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(
                    assertion,
                    instance,
                    &hash,
                    &alg,
                    salt,
                    claim_assertion_type,
                ))
            }
            CAI_EMBEDDED_FILE_UUID => {
                let ef_box = assertion_box
                    .data_box_as_embedded_media_type_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let data_box = assertion_box
                    .data_box_as_embedded_file_content_box(1)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let media_type = ef_box.media_type();
                let assertion =
                    Assertion::from_data_binary(&raw_label, &media_type, data_box.data());
                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(
                    assertion,
                    instance,
                    &hash,
                    &alg,
                    salt,
                    claim_assertion_type,
                ))
            }
            CAI_CBOR_ASSERTION_UUID => {
                let cbor_box = assertion_box
                    .data_box_as_cbor_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let assertion = Assertion::from_data_cbor(&raw_label, cbor_box.cbor());

                // make sure it is CBOR
                if let Err(e) = c2pa_cbor::from_slice::<c2pa_cbor::Value>(cbor_box.cbor()) {
                    log_item!(
                        label.to_owned(),
                        "invalid assertion cbor",
                        "get_assertion_from_jumbf_store"
                    )
                    .validation_status(ASSERTION_CBOR_INVALID)
                    .failure(
                        validation_log,
                        Error::AssertionDecoding(
                            AssertionDecodeError::from_assertion_and_cbor_err(&assertion, e),
                        ),
                    )?;
                }

                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(
                    assertion,
                    instance,
                    &hash,
                    &alg,
                    salt,
                    claim_assertion_type,
                ))
            }
            CAI_UUID_ASSERTION_UUID => {
                let uuid_box = assertion_box
                    .data_box_as_uuid_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let uuid_str = hex::encode(uuid_box.uuid());
                let assertion = Assertion::from_data_uuid(&raw_label, &uuid_str, uuid_box.data());

                // if a redaction then make sure the data is zeros
                if uuid_str == C2PA_REDACTION_UUID {
                    let data = uuid_box.data();
                    if !is_zero(data) {
                        let assertion_absolute_uri =
                            to_assertion_uri(claim.label(), &instance_label);
                        log_item!(
                            assertion_absolute_uri,
                            "redacted assertion data must be zeros or empty",
                            "get_assertion_from_jumbf_store"
                        )
                        .validation_status(validation_status::ASSERTION_NOT_REDACTED)
                        .failure(
                            validation_log,
                            Error::OtherError(
                                "redacted assertion data must be zeros or empty".into(),
                            ),
                        )?;
                    }
                }

                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(
                    assertion,
                    instance,
                    &hash,
                    &alg,
                    salt,
                    claim_assertion_type,
                ))
            }
            _ => Err(Error::JumbfCreationError),
        };

        if check_for_legacy_assertion {
            // make sure this is not pre 1.0 data
            match result {
                Ok(r) => {
                    // look for old style hashing
                    if Store::is_old_assertion(
                        &alg,
                        r.assertion().data(),
                        &assertion_hashed_uri.hash(),
                    ) {
                        Err(Error::PrereleaseError)
                    } else {
                        Ok(r)
                    }
                }
                Err(e) => Err(e),
            }
        } else {
            result
        }
    }

    /// Convert this claims store to a JUMBF box.
    #[allow(unused)] // used in tests
    pub fn to_jumbf(&self, signer: &dyn Signer) -> Result<Vec<u8>> {
        self.to_jumbf_internal(signer.reserve_size())
    }

    /// Convert this claims store to a JUMBF box.
    #[allow(unused)]
    pub fn to_jumbf_async(&self, signer: &dyn AsyncSigner) -> Result<Vec<u8>> {
        self.to_jumbf_internal(signer.reserve_size())
    }

    pub(crate) fn to_jumbf_internal(&self, min_reserve_size: usize) -> Result<Vec<u8>> {
        // Create the CAI block.
        let mut cai_block = Cai::new();

        // Add claims and assertions in this store to the JUMBF store.
        for claim in self.claims() {
            let cai_store = Store::build_manifest_box(claim, min_reserve_size)?;

            // add the completed CAI store into the CAI block.
            cai_block.add_box(Box::new(cai_store));
        }

        // Write it to memory.
        let mut mem_box: Vec<u8> = Vec::new();
        cai_block.write_box(&mut mem_box)?;

        if mem_box.is_empty() {
            Err(Error::JumbfCreationError)
        } else {
            Ok(mem_box)
        }
    }

    fn build_manifest_box(claim: &Claim, min_reserve_size: usize) -> Result<CAIStore> {
        // box label
        let label = claim.label();

        let mut cai_store = CAIStore::new(label, claim.update_manifest());

        for manifest_box in claim.get_box_order() {
            match *manifest_box {
                ASSERTIONS => {
                    let mut a_store = CAIAssertionStore::new();

                    // add assertions to CAI assertion store.
                    let cas = claim.claim_assertion_store();
                    for assertion in cas {
                        Store::add_assertion_to_jumbf_store(&mut a_store, assertion)?;
                    }

                    cai_store.add_box(Box::new(a_store)); // add the assertion store to the manifest
                }
                CLAIM => {
                    let mut cb = CAIClaimBox::new(claim.version());

                    // Add the Claim json
                    let claim_cbor_bytes = claim.data()?;
                    let c_cbor = JUMBFCBORContentBox::new(claim_cbor_bytes);
                    cb.add_claim(Box::new(c_cbor));

                    cai_store.add_box(Box::new(cb)); // add claim to manifest
                }
                SIGNATURE => {
                    // create a signature and add placeholder data to the CAI store.
                    let mut sigb = CAISignatureBox::new();
                    let signed_data = match claim.signature_val().is_empty() {
                        false => claim.signature_val().clone(), // existing claims have sig values
                        true => Store::sign_claim_placeholder(claim, min_reserve_size), /* empty is the new sig to be replaced */
                    };

                    let sigc = JUMBFCBORContentBox::new(signed_data);
                    sigb.add_signature(Box::new(sigc));

                    cai_store.add_box(Box::new(sigb)); // add signature to manifest
                }
                CREDENTIALS => {
                    // add vc_store if needed
                    if !claim.get_verifiable_credentials().is_empty() && claim.version() < 2 {
                        let mut vc_store = CAIVerifiableCredentialStore::new();

                        // Add assertions to CAI assertion store.
                        let vcs = claim.get_verifiable_credentials_store();
                        for (uri, assertion_data) in vcs {
                            if let AssertionData::Json(j) = assertion_data {
                                let id = Claim::vc_id(j)?;
                                let mut json_data = CAIJSONAssertionBox::new(&id);
                                json_data.add_json(j.as_bytes().to_vec());

                                if let Some(salt) = uri.salt() {
                                    json_data.set_salt(salt.clone())?;
                                }

                                vc_store.add_credential(Box::new(json_data));
                            } else {
                                return Err(Error::BadParam("VC data must be JSON".to_string()));
                            }
                        }
                        cai_store.add_box(Box::new(vc_store)); // add the CAI assertion store to manifest
                    }
                }
                DATABOXES => {
                    // Add the data boxes
                    if !claim.databoxes().is_empty() {
                        let mut databoxes = CAIDataboxStore::new();

                        for (uri, db) in claim.databoxes() {
                            let db_cbor_bytes = c2pa_cbor::to_vec(db)
                                .map_err(|err| Error::AssertionEncoding(err.to_string()))?;

                            let (link, instance) = Claim::assertion_label_from_link(&uri.url());
                            let label = Claim::label_with_instance(&link, instance);

                            let mut db_cbor = CAICBORAssertionBox::new(&label);
                            db_cbor.add_cbor(db_cbor_bytes);

                            if let Some(salt) = uri.salt() {
                                db_cbor.set_salt(salt.clone())?;
                            }

                            databoxes.add_databox(Box::new(db_cbor));
                        }

                        cai_store.add_box(Box::new(databoxes)); // add claim to manifest
                    }
                }
                _ => return Err(Error::ClaimInvalidContent),
            }
        }

        Ok(cai_store)
    }

    // calculate the hash of the manifest JUMBF box
    pub fn calc_manifest_box_hash(
        claim: &Claim,
        salt: Option<Vec<u8>>,
        alg: &str,
    ) -> Result<Vec<u8>> {
        let mut hash_bytes = Vec::with_capacity(4096);

        // build box
        let mut cai_store = Store::build_manifest_box(claim, 0)?;

        // add salt if requested
        if let Some(salt) = salt {
            cai_store.set_salt(salt)?;
        }

        // box content as Vec
        cai_store.super_box().write_box_payload(&mut hash_bytes)?;

        Ok(hash_by_alg(alg, &hash_bytes, None))
    }

    fn manifest_map<'a>(sb: &'a JUMBFSuperBox) -> Result<HashMap<String, ManifestInfo<'a>>> {
        let mut box_info: HashMap<String, ManifestInfo<'a>> = HashMap::new();
        for i in 0..sb.data_box_count() {
            let sbox = sb.data_box_as_superbox(i).ok_or(Error::JumbfBoxNotFound)?;
            let desc_box = sbox.desc_box();

            let label = desc_box.uuid();

            let mi = ManifestInfo { desc_box, sbox };

            box_info.insert(label, mi);
        }

        Ok(box_info)
    }

    // Compare two version labels
    // base_version_label - is the source label
    // desired_version_label - is the label to compare to the base
    // returns true if desired version is <= base version
    fn check_label_version(base_version_label: &str, desired_version_label: &str) -> bool {
        labels::version(desired_version_label) <= labels::version(base_version_label)
    }

    #[inline]
    pub fn from_jumbf(buffer: &[u8], validation_log: &mut StatusTracker) -> Result<Store> {
        Self::from_jumbf_impl(Store::new(), buffer, validation_log)
    }

    #[inline]
    pub fn from_jumbf_with_context(
        buffer: &[u8],
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Store> {
        Self::from_jumbf_impl(Store::from_context(context), buffer, validation_log)
    }

    fn from_jumbf_impl(
        mut store: Store,
        buffer: &[u8],
        validation_log: &mut StatusTracker,
    ) -> Result<Store> {
        if buffer.is_empty() {
            return Err(Error::JumbfNotFound);
        }

        // setup a cursor for reading the buffer...
        let mut buf_reader = Cursor::new(buffer);

        // this loads up all the boxes...
        let super_box = BoxReader::read_super_box(&mut buf_reader)?;

        // this loads up all the boxes...
        let cai_block = Cai::from(super_box);

        // check the CAI Block
        let desc_box = cai_block.desc_box();
        if desc_box.uuid() != CAI_BLOCK_UUID {
            log_item!("JUMBF", "c2pa box not found", "from_jumbf").failure_no_throw(
                validation_log,
                Error::InvalidClaim(InvalidClaimError::C2paBlockNotFound),
            );

            return Err(Error::InvalidClaim(InvalidClaimError::C2paBlockNotFound));
        }

        let num_stores = cai_block.data_box_count();
        for idx in 0..num_stores {
            let cai_store_box = cai_block
                .data_box_as_superbox(idx)
                .ok_or(Error::JumbfBoxNotFound)?;
            let cai_store_desc_box = cai_store_box.desc_box();

            // ignore unknown boxes per the spec
            if cai_store_desc_box.uuid() != CAI_UPDATE_MANIFEST_UUID
                && cai_store_desc_box.uuid() != CAI_STORE_UUID
            {
                continue;
            }

            // remember the order of the boxes to insure the box hashes can be regenerated
            let mut box_order: Vec<&str> = Vec::new();

            // make sure there are not multiple claim boxes
            let mut claim_box_cnt = 0;
            for i in 0..cai_store_box.data_box_count() {
                let sbox = cai_store_box
                    .data_box_as_superbox(i)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let desc_box = sbox.desc_box();

                if desc_box.uuid() == CAI_CLAIM_UUID {
                    claim_box_cnt += 1;
                }

                if claim_box_cnt > 1 {
                    log_item!("JUMBF", "c2pa multiple claim boxes found", "from_jumbf")
                        .validation_status(validation_status::CLAIM_MULTIPLE)
                        .failure_no_throw(
                            validation_log,
                            Error::InvalidClaim(InvalidClaimError::C2paMultipleClaimBoxes),
                        );

                    return Err(Error::InvalidClaim(
                        InvalidClaimError::C2paMultipleClaimBoxes,
                    ));
                }

                let (box_label, _instance) =
                    Claim::box_name_label_instance(desc_box.label().as_ref());
                match box_label.as_ref() {
                    ASSERTIONS => box_order.push(ASSERTIONS),
                    CLAIM => box_order.push(CLAIM),
                    SIGNATURE => box_order.push(SIGNATURE),
                    CREDENTIALS => box_order.push(CREDENTIALS),
                    DATABOXES => box_order.push(DATABOXES),
                    _ => {
                        log_item!("JUMBF", "unrecognized manifest box", "from_jumbf")
                            .validation_status(validation_status::CLAIM_MULTIPLE)
                            .failure(
                                validation_log,
                                Error::InvalidClaim(InvalidClaimError::ClaimBoxData),
                            )?;
                    }
                }
            }

            let is_update_manifest = cai_store_desc_box.uuid() == CAI_UPDATE_MANIFEST_UUID;

            // get map of boxes in this manifest
            let manifest_boxes = Store::manifest_map(cai_store_box)?;

            // retrieve the claim & validate
            let claim_superbox = manifest_boxes
                .get(CAI_CLAIM_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::ClaimSuperboxNotFound,
                ))?
                .sbox;
            let claim_desc_box = manifest_boxes
                .get(CAI_CLAIM_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::ClaimDescriptionBoxNotFound,
                ))?
                .desc_box;

            // check if version is supported
            let claim_box_ver = claim_desc_box.label();
            if !Self::check_label_version(&Claim::build_version_support(), &claim_box_ver) {
                return Err(Error::InvalidClaim(InvalidClaimError::ClaimVersionTooNew));
            }

            // check box contents
            if claim_desc_box.uuid() == CAI_CLAIM_UUID {
                // must be have only one claim
                if claim_superbox.data_box_count() > 1 {
                    return Err(Error::InvalidClaim(InvalidClaimError::DuplicateClaimBox {
                        label: claim_desc_box.label(),
                    }));
                }
                // better be, but just in case...

                let cbor_box = match claim_superbox.data_box_as_cbor_box(0) {
                    Some(c) => c,
                    None => {
                        // check for old claims for reporting
                        match claim_superbox.data_box_as_json_box(0) {
                            Some(_c) => {
                                log_item!("JUMBF", "error loading claim data", "from_jumbf")
                                    .failure_no_throw(validation_log, Error::PrereleaseError);

                                return Err(Error::PrereleaseError);
                            }
                            None => {
                                log_item!("JUMBF", "error loading claim data", "from_jumbf")
                                    .failure_no_throw(
                                        validation_log,
                                        Error::InvalidClaim(InvalidClaimError::ClaimBoxData),
                                    );

                                return Err(Error::InvalidClaim(InvalidClaimError::ClaimBoxData));
                            }
                        }
                    }
                };

                if cbor_box.box_uuid() != JUMBF_CBOR_UUID {
                    return Err(Error::InvalidClaim(
                        InvalidClaimError::ClaimDescriptionBoxInvalid,
                    ));
                }
            }

            // retrieve the signature
            let sig_superbox = manifest_boxes
                .get(CAI_SIGNATURE_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::ClaimSignatureBoxNotFound,
                ))?
                .sbox;
            let sig_desc_box = manifest_boxes
                .get(CAI_SIGNATURE_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::ClaimSignatureDescriptionBoxNotFound,
                ))?
                .desc_box;

            // check box contents
            if sig_desc_box.uuid() == CAI_SIGNATURE_UUID {
                // better be, but just in case...
                let sig_box = sig_superbox
                    .data_box_as_cbor_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                if sig_box.box_uuid() != JUMBF_CBOR_UUID {
                    return Err(Error::InvalidClaim(
                        InvalidClaimError::ClaimSignatureDescriptionBoxInvalid,
                    ));
                }
            }
            // save signature to be validated on load
            let sig_data = sig_superbox
                .data_box_as_cbor_box(0)
                .ok_or(Error::JumbfBoxNotFound)?;

            // Create a new Claim object from jumbf data after validations
            let cbor_box = claim_superbox
                .data_box_as_cbor_box(0)
                .ok_or(Error::JumbfBoxNotFound)?;
            let mut claim = Claim::from_data(&cai_store_desc_box.label(), cbor_box.cbor())
                .map_err(|e| {
                    log_item!(CLAIM, "CLAIM CBOR could not be decoded", "from_jumbf")
                        .validation_status(CLAIM_MALFORMED)
                        .failure_as_err(validation_log, e)
                })?;

            // the claim must have an algorithm to be able to process internal hashes
            if claim.alg_raw().is_none() {
                return Err(log_item!(
                    claim.label().to_owned(),
                    "no hashing algorithm found for claim",
                    "from_jumbf"
                )
                .validation_status(ALGORITHM_UNSUPPORTED)
                .failure_as_err(validation_log, Error::UnknownAlgorithm));
            }

            // make sure box version label match the read Claim
            if claim.version() > 1 {
                match labels::version(&claim_box_ver) {
                    v if claim.version() >= v => (),
                    _ => return Err(Error::InvalidClaim(InvalidClaimError::ClaimBoxVersion)),
                }
            }

            // set the  type of manifest
            claim.set_update_manifest(is_update_manifest);

            // set order to process JUMBF boxes
            claim.set_box_order(box_order);

            // retrieve & set signature for each claim
            claim.set_signature_val(sig_data.cbor().clone()); // load the stored signature

            // retrieve the assertion store
            let assertion_store_box = manifest_boxes
                .get(CAI_ASSERTION_STORE_UUID)
                .ok_or(Error::InvalidClaim(
                    InvalidClaimError::AssertionStoreSuperboxNotFound,
                ))?
                .sbox;

            let num_assertions = assertion_store_box.data_box_count();

            // loop over all assertions in assertion store...
            let mut check_for_legacy_assertion = true;
            for idx in 0..num_assertions {
                let assertion_box = assertion_store_box
                    .data_box_as_superbox(idx)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let assertion_desc_box = assertion_box.desc_box();

                // Add assertions to claim after validation
                let label = assertion_desc_box.label();
                match Store::get_assertion_from_jumbf_store(
                    &claim,
                    assertion_box,
                    &label,
                    check_for_legacy_assertion,
                    validation_log,
                ) {
                    Ok(assertion) => {
                        claim.put_assertion_store(assertion); // restore assertion data to claim
                        check_for_legacy_assertion = false; // only need to check once
                    }
                    Err(e) => {
                        // if this is an old manifest always return
                        if std::mem::discriminant(&e)
                            == std::mem::discriminant(&Error::PrereleaseError)
                        {
                            log_item!("JUMBF", "error loading assertion", "from_jumbf")
                                .failure_no_throw(validation_log, e);

                            return Err(Error::PrereleaseError);
                        }
                        return Err(e);
                    }
                }
            }

            // load vc_store if available
            if let Some(mi) = manifest_boxes.get(CAI_VERIFIABLE_CREDENTIALS_STORE_UUID) {
                let vc_store = mi.sbox;
                let num_vcs = vc_store.data_box_count();

                // VC stores should not be in a 2.x claim
                if claim.version() > 1 {
                    return Err(Error::InvalidClaim(InvalidClaimError::UnsupportedFeature(
                        "Verifiable Credentials Store > v1 claim".to_string(),
                    )));
                }

                for idx in 0..num_vcs {
                    let vc_box = vc_store
                        .data_box_as_superbox(idx)
                        .ok_or(Error::JumbfBoxNotFound)?;
                    let vc_json = vc_box
                        .data_box_as_json_box(0)
                        .ok_or(Error::JumbfBoxNotFound)?;
                    let vc_desc_box = vc_box.desc_box();
                    let _id = vc_desc_box.label();

                    let json_str = String::from_utf8(vc_json.json().to_vec())
                        .map_err(|_| InvalidClaimError::VerifiableCredentialStoreInvalid)?;

                    let salt = vc_desc_box.get_salt();

                    claim.put_verifiable_credential(&json_str, salt)?;
                }
            }

            // load databox store if available
            if let Some(mi) = manifest_boxes.get(CAI_DATABOXES_STORE_UUID) {
                let databox_store = mi.sbox;
                let num_databoxes = databox_store.data_box_count();

                for idx in 0..num_databoxes {
                    let db_box = databox_store
                        .data_box_as_superbox(idx)
                        .ok_or(Error::JumbfBoxNotFound)?;
                    let db_cbor = db_box
                        .data_box_as_cbor_box(0)
                        .ok_or(Error::JumbfBoxNotFound)?;
                    let db_desc_box = db_box.desc_box();
                    let label = db_desc_box.label();

                    let salt = db_desc_box.get_salt();

                    claim.put_databox(&label, db_cbor.cbor(), salt)?;
                }
            }

            // save the hash of the loaded manifest for ingredient validation
            // and the signature box for Ingredient_v3
            store.manifest_box_hash_cache.insert(
                claim.label().to_owned(),
                (
                    Store::calc_manifest_box_hash(&claim, None, claim.alg())?,
                    Claim::calc_sig_box_hash(&claim, claim.alg())?,
                ),
            );

            // add claim to store
            store.insert_restored_claim(cai_store_desc_box.label(), claim);
        }

        Ok(store)
    }

    // Get the store label from jumbf path
    pub fn manifest_label_from_path(claim_path: &str) -> String {
        if let Some(s) = jumbf::labels::manifest_label_from_uri(claim_path) {
            s
        } else {
            claim_path.to_owned()
        }
    }

    /// This function is used to get a placeholder manifest with dynamic assertion support.
    /// The placeholder is then injected into the asset before calculating hashes.
    /// Unlike [`data_hashed_placeholder`], this function supports dynamic assertions
    /// (e.g., CAWG identity assertions) by accepting a signer.
    ///
    /// # Arguments
    /// * `context` - The context to use.
    /// # Returns
    /// * The bytes of the `c2pa_manifest` placeholder.
    /// # Errors
    /// * Returns an [`Error`] if the placeholder cannot be created.
    pub fn get_placeholder(&mut self, _format: &str, context: &Context) -> Result<Vec<u8>> {
        let signer = context.signer()?;
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // if user did not supply a hash
        if pc.hash_assertions().is_empty() {
            return Err(Error::BadParam(
                "Claim must have a hard binding assertion".to_string(),
            ));
        };

        // add dynamic assertions to the store
        let dynamic_assertions = signer.dynamic_assertions();
        let _da_uris = self.add_dynamic_assertion_placeholders(&dynamic_assertions)?;

        self.to_jumbf_internal(signer.reserve_size())
    }

    /// Signs an already hashed manifest with dynamic assertion support.
    ///
    /// # Arguments
    /// * `signer` - The signer to use.
    /// * `settings` - The settings to use.
    /// # Returns
    /// * The signed manifest bytes.
    /// # Errors
    /// * Returns an [`Error`] if the placeholder cannot be signed.
    pub fn sign_manifest(&mut self, signer: &dyn Signer, context: &Context) -> Result<Vec<u8>> {
        let settings = context.settings();
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // if user did not supply a hash
        if pc.hash_assertions().is_empty() {
            return Err(Error::BadParam(
                "Claim must have a valid hard binding assertion".to_string(),
            ));
        };

        // Write dynamic assertions only if placeholders were added during placeholder generation.
        // We check if the dynamic assertion labels exist in the claim - if not, placeholders
        // weren't added and we should skip writing to avoid size mismatches.
        let dynamic_assertions = signer.dynamic_assertions();
        if !dynamic_assertions.is_empty() {
            // Check if placeholders exist for these dynamic assertions
            let has_placeholders = {
                dynamic_assertions
                    .iter()
                    .all(|da| pc.assertion_hashed_uri_from_label(&da.label()).is_some())
            };

            if has_placeholders {
                let mut preliminary_claim = PartialClaim::default();
                {
                    for assertion in pc.assertions() {
                        preliminary_claim.add_assertion(assertion);
                    }
                }

                // Drop pc before calling write_dynamic_assertions
                let _ = pc;

                let _modified =
                    self.write_dynamic_assertions(&dynamic_assertions, &mut preliminary_claim)?;

                // Get pc again
                let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
                let sig = self.sign_claim(pc, signer, signer.reserve_size(), settings)?;
                let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

                if sig_placeholder.len() != sig.len() {
                    return Err(Error::CoseSigboxTooSmall);
                }

                let mut jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;
                patch_bytes(&mut jumbf_bytes, &sig_placeholder, &sig)
                    .map_err(|_| Error::JumbfCreationError)?;

                return Ok(jumbf_bytes);
            }
        }

        context.check_progress(ProgressPhase::Signing, 1, 1)?;

        // No dynamic assertions - sign directly
        // Drop pc and get an immutable reference for signing
        let _ = pc;
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self.sign_claim(pc, signer, signer.reserve_size(), settings)?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        let mut jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;
        patch_bytes(&mut jumbf_bytes, &sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        Ok(jumbf_bytes)
    }

    /// Returns a finalized, signed manifest.  The client is required to have
    /// included the necessary box hash assertion with the pregenerated hashes.
    pub fn get_box_hashed_embeddable_manifest(
        &mut self,
        signer: &dyn Signer,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;

        // make sure there is only one
        if pc.hash_assertions().len() != 1 {
            return Err(Error::BadParam(
                "Claim must have exactly one hash binding assertion".to_string(),
            ));
        }

        // only allow box hash assertions to be present
        if pc.box_hash_assertions().is_empty() {
            return Err(Error::BadParam("Missing box hash assertion".to_string()));
        }

        let mut jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;

        context.check_progress(ProgressPhase::Signing, 1, 1)?;

        // sign contents
        let sig = self.sign_claim(pc, signer, signer.reserve_size(), context.settings())?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, &sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        Ok(jumbf_bytes)
    }

    /// Returns a finalized, signed manifest.  The client is required to have
    /// included the necessary box hash assertion with the pregenerated hashes.
    pub async fn get_box_hashed_embeddable_manifest_async(
        &mut self,
        signer: &dyn AsyncSigner,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;

        // make sure there is only one
        if pc.hash_assertions().len() != 1 {
            return Err(Error::BadParam(
                "Claim must have exactly one hash binding assertion".to_string(),
            ));
        }

        // only allow box hash assertions to be present
        if pc.box_hash_assertions().is_empty() {
            return Err(Error::BadParam("Missing box hash assertion".to_string()));
        }

        let mut jumbf_bytes = self.to_jumbf_internal(signer.reserve_size())?;

        // sign contents
        let sig = self
            .sign_claim_async(pc, signer, signer.reserve_size(), context.settings())
            .await?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, &sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        Ok(jumbf_bytes)
    }

    /// Inserts placeholders for dynamic assertions to be updated later.
    #[async_generic(async_signature(
        &mut self,
        dyn_assertions: &[Box<dyn AsyncDynamicAssertion>],
    ))]
    pub(crate) fn add_dynamic_assertion_placeholders(
        &mut self,
        dyn_assertions: &[Box<dyn DynamicAssertion>],
    ) -> Result<Vec<HashedUri>> {
        if dyn_assertions.is_empty() {
            return Ok(Vec::new());
        }

        // Two passes since we are accessing two fields in self.
        let mut assertions = Vec::new();
        for da in dyn_assertions.iter() {
            let reserve_size = da.reserve_size()?;
            let data1 = c2pa_cbor::ser::to_vec_packed(&vec![0; reserve_size])?;
            let cbor_delta = data1.len() - reserve_size;
            let da_data = c2pa_cbor::ser::to_vec_packed(&vec![0; reserve_size - cbor_delta])?;
            assertions.push(UserCbor::new(&da.label(), da_data));
        }

        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        // add dynamic assertions (respects created_assertion_labels settings)
        assertions.iter().map(|a| pc.add_assertion(a)).collect()
    }

    /// Write the dynamic assertions to the manifest.
    /// Note: This assumes each dynamic assertion label is unique (no instance suffixes).
    /// Multiple dynamic assertions with different labels are supported.
    #[async_generic(async_signature(
        &mut self,
        dyn_assertions: &[Box<dyn AsyncDynamicAssertion>],
        preliminary_claim: &mut PartialClaim,
    ))]
    #[allow(unused_variables)]
    fn write_dynamic_assertions(
        &mut self,
        dyn_assertions: &[Box<dyn DynamicAssertion>],
        preliminary_claim: &mut PartialClaim,
    ) -> Result<bool> {
        if dyn_assertions.is_empty() {
            return Ok(false);
        }

        let mut final_assertions = Vec::new();

        for da in dyn_assertions.iter() {
            // Use the dynamic assertion's label directly.
            // This assumes each dynamic assertion label is unique (no instance suffixes needed).
            let label = da.label();

            let da_size = da.reserve_size()?;
            let da_data = if _sync {
                da.content(&label, Some(da_size), preliminary_claim)?
            } else {
                da.content(&label, Some(da_size), preliminary_claim).await?
            };

            match da_data {
                DynamicAssertionContent::Cbor(data) => {
                    final_assertions.push(UserCbor::new(&label, data).to_assertion()?);
                }
                DynamicAssertionContent::Json(data) => {
                    final_assertions.push(User::new(&label, &data).to_assertion()?);
                }
                DynamicAssertionContent::Binary(format, data) => {
                    //final_assertions.push(EmbeddedData::to_binary_assertion(&EmbeddedData::new(&label, format, data))?);
                }
            }
        }

        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        for assertion in final_assertions {
            pc.replace_assertion(assertion)?;
        }

        // clear the provenance claim data since the contents are now different
        pc.clear_data();

        Ok(true)
    }

    /// check the input url to see if it is a supported remotes URI
    pub fn is_valid_remote_url(url: &str) -> bool {
        match url::Url::parse(url) {
            Ok(u) => u.scheme() == "http" || u.scheme() == "https",
            Err(_) => false,
        }
    }

    // get the manifest that should be used for hash binding checks
    fn get_hash_binding_manifest(&self, claim: &Claim) -> Option<String> {
        // is this claim valid
        if !claim.update_manifest() && !claim.hash_assertions().is_empty() {
            return Some(claim.label().to_owned());
        }

        // walk the update manifests until you find an acceptable claim
        for i in claim.ingredient_assertions() {
            let ingredient = Ingredient::from_assertion(i.assertion()).ok()?;
            if ingredient.relationship == Relationship::ParentOf {
                if let Some(parent_uri) = ingredient.c2pa_manifest() {
                    let parent_label = manifest_label_from_uri(&parent_uri.url())?;
                    if let Some(parent) = self.get_claim(&parent_label) {
                        // recurse until we find
                        if parent.update_manifest() {
                            return self.get_hash_binding_manifest(parent);
                        } else if !parent.hash_assertions().is_empty() {
                            return Some(parent.label().to_owned());
                        }
                    }
                }
            }
        }
        None
    }

    // determine if the only changes are redacted assertions
    fn manifest_differs_by_redaction(
        c1: &Claim,
        c2: &Claim,
        redactions: &[String],
    ) -> Option<Vec<String>> {
        if let Ok(d1) = c1.data() {
            if let Ok(d2) = c2.data() {
                if d1 != d2 {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            return None;
        }

        if c1.signature_val() != c2.signature_val() {
            return None;
        }

        if c1.databoxes() != c2.databoxes() {
            return None;
        }

        // get the assertion store differences
        let c1_set: HashSet<&ClaimAssertion> = c1.claim_assertion_store().iter().collect();
        let c2_set: HashSet<&ClaimAssertion> = c2.claim_assertion_store().iter().collect();

        let differences = c1_set.symmetric_difference(&c2_set).collect::<Vec<_>>();

        // are the assertion differences listed in the redaction list
        let mut redact_matches = 0;
        let mut redactions_to_remove = Vec::new();
        for difference in &differences {
            let difference_uri = to_assertion_uri(c1.label(), &difference.label());

            // was the difference in the redacted list
            if redactions
                .iter()
                .any(|redaction_uri| redaction_uri.as_str() == difference_uri.as_str())
            {
                redact_matches += 1;
                redactions_to_remove.push(difference_uri);
            }
        }

        // if all mismatches are redactions we are good
        if redact_matches == differences.len() {
            return Some(redactions_to_remove);
        }

        None
    }

    // build ingredient lists for the Claim in the specified Store
    // the referenced_ingredients map the ingredient to the claims that reference it
    // the found_redactions are any redactions found
    fn get_claim_referenced_manifests<'a>(
        claim: &'a Claim,
        store: &'a Store,
        svi: &mut StoreValidationInfo<'a>,
        recurse: bool,
        validation_log: &mut StatusTracker,
    ) -> Result<()> {
        Self::get_claim_referenced_manifests_impl(
            claim,
            store,
            svi,
            recurse,
            validation_log,
            &mut Vec::new(),
        )
    }

    fn get_claim_referenced_manifests_impl<'a>(
        claim: &'a Claim,
        store: &'a Store,
        svi: &mut StoreValidationInfo<'a>,
        recurse: bool,
        validation_log: &mut StatusTracker,
        claim_label_path: &mut Vec<&'a str>,
    ) -> Result<()> {
        let claim_label = claim.label();

        if svi.manifest_map.contains_key(claim_label) {
            return Ok(());
        }

        claim_label_path.push(claim_label);

        // add in current redactions
        if let Some(c_redactions) = claim.redactions() {
            svi.redactions
                .append(&mut c_redactions.clone().into_iter().collect::<Vec<_>>());
        }

        // save the addressible claims for quicker lookup
        svi.manifest_map.insert(claim_label.to_owned(), claim);

        for i in claim.ingredient_assertions() {
            let ingredient_assertion = Ingredient::from_assertion(i.assertion())?;

            // get correct hashed URI
            let c2pa_manifest = match ingredient_assertion.c2pa_manifest() {
                Some(m) => m, // > v2 ingredient assertion
                None => continue,
            };

            // is this an ingredient
            let ingredient_label = Store::manifest_label_from_path(&c2pa_manifest.url());

            if let Some(ingredient) = store.get_claim(&ingredient_label) {
                if claim_label_path.contains(&ingredient.label()) {
                    return Err(log_item!(
                        jumbf::labels::to_assertion_uri(claim_label, &i.label()),
                        "ingredient cannot be cyclic",
                        "ingredient_checks"
                    )
                    .validation_status(validation_status::ASSERTION_INGREDIENT_MALFORMED)
                    .failure_as_err(
                        validation_log,
                        Error::CyclicIngredients {
                            claim_label_path: claim_label_path
                                .iter()
                                .map(|&label| label.to_owned())
                                .collect(),
                        },
                    ));
                }

                // build mapping of ingredients and those claims that reference it
                svi.ingredient_references
                    .entry(ingredient_label.clone())
                    .or_insert(HashSet::from_iter(vec![claim_label.to_owned()]))
                    .insert(claim_label.to_owned());

                // recurse nested ingredients
                if recurse {
                    Store::get_claim_referenced_manifests_impl(
                        ingredient,
                        store,
                        svi,
                        recurse,
                        validation_log,
                        claim_label_path,
                    )?;
                }
            } else {
                log_item!(
                    ingredient_label.clone(),
                    "ingredient missing missing",
                    "get_claim_referenced_manifests"
                )
                .validation_status(validation_status::CLAIM_MISSING)
                .failure(
                    validation_log,
                    Error::ClaimMissing {
                        label: ingredient_label,
                    },
                )?;
            }
        }

        claim_label_path.pop();

        Ok(())
    }

    /// Load Store from memory and add its content as a claim ingredient
    /// claim: claim to add an ingredient
    /// provenance_label: label of the provenance claim used as key into ingredient map
    /// data: jumbf data block
    /// returns new Store with ingredients loaded, claim is modified to include resolved
    /// ingredients conflicts
    pub fn load_ingredient_to_claim(
        claim: &mut Claim,
        data: &[u8],
        redactions: Option<Vec<String>>,
        context: &Context,
    ) -> Result<Store> {
        // constants for ingredient conflict reasons
        const CONFLICTING_MANIFEST: usize = 1; // Conflicts with another C2PA Manifest

        let mut to_both = Vec::new();
        let mut to_remove_from_incoming = Vec::new();

        let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
        let i_store = Store::from_jumbf_with_context(data, &mut report, context)?;

        let empty_store = Store::default();

        // make sure the claims stores are compatible
        let ingredient_pc = i_store.provenance_claim().ok_or(Error::OtherError(
            "ingredient missing provenace claim".into(),
        ))?;
        if claim.version() < ingredient_pc.version() {
            return Err(Error::OtherError("ingredient version too new".into()));
        }

        // get list of referenced manifests and redactions from ingredient provenance claim
        let mut validation_log = StatusTracker::default();
        let mut svi = StoreValidationInfo::default();
        Store::get_claim_referenced_manifests(
            ingredient_pc,
            &i_store,
            &mut svi,
            true,
            &mut validation_log,
        )?;

        // resolve conflicts
        // for 2.x perform ingredients conflict handling by making new label if needed
        let skip_resolution = context
            .settings()
            .verify
            .skip_ingredient_conflict_resolution;

        if claim.version() > 1 && !skip_resolution {
            // if the hashes match then the values are OK to add so remove form conflict list
            // matching manifests are automatically deduped in a later step
            let potential_conflicts: Vec<_> = i_store
                .claims()
                .iter()
                .filter_map(|i_claim| {
                    for c in claim.claim_ingredients() {
                        if c.label() == i_claim.label() {
                            let i_ingredient_hashes = i_store.get_manifest_box_hashes(i_claim);
                            let current_claim_hashes = empty_store.get_manifest_box_hashes(c);

                            // if they match there is no conflict
                            if !vec_compare(
                                &current_claim_hashes.manifest_box_hash,
                                &i_ingredient_hashes.manifest_box_hash,
                            ) {
                                return Some(c.label().to_owned());
                            }
                        }
                    }

                    None
                })
                .collect();

            if !potential_conflicts.is_empty() {
                // get info about conflicting Claim from current claim
                let mut claim_redactions: Vec<String> = redactions.clone().unwrap_or_default();
                for c in claim.claim_ingredients() {
                    if let Some(r) = c.redactions() {
                        claim_redactions.append(&mut r.clone().into_iter().collect::<Vec<_>>());
                    }
                }

                let combined_redactions = HashSet::<_>::from_iter(
                    vec![claim_redactions.clone(), svi.redactions.clone()]
                        .into_iter()
                        .flatten(),
                )
                .into_iter()
                .collect::<Vec<String>>();

                // do any of the conflicting manifests contain redactions
                for conflict_label in potential_conflicts {
                    // Step 1: was the conflict because of a redaction from the either the current
                    // claim or the incoming store

                    let conflict = i_store
                        .get_claim(&conflict_label)
                        .ok_or(Error::IngredientNotFound)?;

                    // can only resolve conflict if the changes were redaction differences
                    if let Some(curr_claim_ingredient_conflict) = claim
                        .claim_ingredients()
                        .iter()
                        .find(|c| c.label() == conflict_label)
                    {
                        if let Some(mut differences) = Store::manifest_differs_by_redaction(
                            curr_claim_ingredient_conflict,
                            conflict,
                            &combined_redactions,
                        ) {
                            if !claim_redactions.is_empty() && svi.redactions.is_empty() {
                                // if redactions were only in the claim we can skip bringing the ingredient
                                to_remove_from_incoming.push(conflict_label.clone());
                            } else if claim_redactions.is_empty() && !svi.redactions.is_empty() {
                                // if redactions were only from the incoming ingredient replace claim
                                // noting to do here since the incoming claim will just overwrite the current claim
                                continue;
                            } else {
                                to_both.append(&mut differences);
                            }
                        } else {
                            let new_version = match claim
                                .claim_ingredient_store()
                                .keys()
                                .filter_map(|label| match manifest_label_to_parts(label) {
                                    Some(mp) => mp.version,
                                    None => None,
                                })
                                .max()
                            {
                                Some(last_conflict_version) => last_conflict_version + 1,
                                None => {
                                    return Err(Error::OtherError(
                                        "ingredient label malformed".into(),
                                    ))
                                }
                            };

                            // make new ingredient label
                            let mut new_mp = manifest_label_to_parts(&conflict_label)
                                .ok_or(Error::OtherError("ingredient label malformed".into()))?;
                            new_mp.version = Some(new_version);
                            new_mp.reason = Some(CONFLICTING_MANIFEST);
                            let new_label = new_mp.to_string();

                            // update ingredient manifest label to new label
                            let mut fixup_claim = i_store
                                .get_claim(conflict.label())
                                .ok_or(Error::IngredientNotFound)?
                                .clone();
                            fixup_claim.set_conflict_label(new_label.clone());

                            // add relabeled manifest to store as new ingredient
                            claim.add_ingredient_data(
                                vec![fixup_claim],
                                None,
                                &svi.ingredient_references,
                            )?;
                        }
                    }
                }
            }
        }

        // make necessary changes to the incoming store
        let mut i_store_mut = Store::from_jumbf_with_context(data, &mut report, context)?;
        let mut final_redactions = Vec::new();
        if let Some(mut redactions) = redactions {
            final_redactions.append(&mut redactions);
        }

        // remove the claims from the incoming store as to not overwrite the current claim
        for label in to_remove_from_incoming {
            i_store_mut.remove_claim(&label);
        }

        // if there are redactions in both apply the current redaction to incoming claim
        if !to_both.is_empty() {
            // copy the redactions differences from current to incoming claim
            to_both.retain(|f| !svi.redactions.contains(f));
            final_redactions.append(&mut to_both);
        }

        let claims_to_add: Vec<Claim> = i_store_mut.claims().into_iter().cloned().collect();
        claim.add_ingredient_data(
            claims_to_add,
            Some(final_redactions),
            &svi.ingredient_references,
        )?;
        Ok(i_store)
    }

    /// Fetches ocsp response ders from the specified manifests.
    ///
    /// # Arguments
    /// * `manifest_labels` - Vector of manifest labels to check for ocsp responses
    /// * `validation_log` - Status tracker for logging validation events
    ///
    /// # Returns
    /// A `Result` containing tuples of manifest labels and their associated ocsp response
    #[async_generic(async_signature(
        &self,
        manifest_labels: Vec<String>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ))]
    pub fn get_ocsp_response_ders(
        &self,
        manifest_labels: Vec<String>,
        validation_log: &mut StatusTracker,
        context: &Context,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut oscp_response_ders = Vec::new();

        let mut adjusted_settings = context.settings().clone();
        let original_trust_val = adjusted_settings.verify.verify_timestamp_trust;

        for manifest_label in manifest_labels {
            if let Some(claim) = self.claims_map.get(&manifest_label) {
                let sig = claim.signature_val().clone();
                let data = claim.data()?;

                // no timestamp trust checks for 1.x manifests
                if claim.version() == 1 {
                    adjusted_settings.verify.verify_timestamp_trust = false;
                }

                let sign1 = parse_cose_sign1(&sig, &data, validation_log)?;
                let ocsp_response_der = if _sync {
                    fetch_and_check_ocsp_response(
                        &sign1,
                        &data,
                        &self.ctp,
                        None,
                        validation_log,
                        context,
                    )?
                    .ocsp_der
                } else {
                    fetch_and_check_ocsp_response_async(
                        &sign1,
                        &data,
                        &self.ctp,
                        None,
                        validation_log,
                        context,
                    )
                    .await?
                    .ocsp_der
                };

                if !ocsp_response_der.is_empty() {
                    oscp_response_ders.push((manifest_label, ocsp_response_der));
                }
            }
            adjusted_settings.verify.verify_timestamp_trust = original_trust_val;
        }

        Ok(oscp_response_ders)
    }
}

impl std::fmt::Display for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let report = &ManifestStoreReport::from_store(self).unwrap_or_default();
        f.write_str(&format!("{}", &report))
    }
}

/// `InvalidClaimError` provides additional detail on error cases for [`Store::from_jumbf`].
#[derive(Debug, thiserror::Error)]
pub enum InvalidClaimError {
    /// The "c2pa" block was not found in the asset.
    #[error("\"c2pa\" block not found")]
    C2paBlockNotFound,

    #[error("\"c2pa\" multiple claim boxes found in manifest")]
    C2paMultipleClaimBoxes,

    /// The claim superbox was not found.
    #[error("claim superbox not found")]
    ClaimSuperboxNotFound,

    /// The claim description box was not found.
    #[error("claim description box not found")]
    ClaimDescriptionBoxNotFound,

    /// More than one claim description box was found.
    #[error("more than one claim description box was found for {label}")]
    DuplicateClaimBox { label: String },

    /// The expected data not found in claim box.
    #[error("claim cbor box not valid")]
    ClaimBoxData,

    /// The claim has a version that is newer than supported by this crate.
    #[error("claim version is too new, not supported")]
    ClaimVersionTooNew,

    /// The claim has a version does not match JUMBF box label.
    #[error("claim version does not match JUMBF box label")]
    ClaimBoxVersion,

    /// The claim description box could not be parsed.
    #[error("claim description box was invalid")]
    ClaimDescriptionBoxInvalid,

    /// The claim signature box was not found.
    #[error("claim signature box was not found")]
    ClaimSignatureBoxNotFound,

    /// The claim signature description box was not found.
    #[error("claim signature description box was not found")]
    ClaimSignatureDescriptionBoxNotFound,

    /// The claim signature description box was invalid.
    #[error("claim signature description box was invalid")]
    ClaimSignatureDescriptionBoxInvalid,

    /// The assertion store superbox was not found.
    #[error("assertion store superbox not found")]
    AssertionStoreSuperboxNotFound,

    /// The verifiable credentials store could not be read.
    #[error("the verifiable credentials store could not be read")]
    VerifiableCredentialStoreInvalid,

    /// The feature is not supported by version
    #[error("the manifest contained a feature not support by version")]
    UnsupportedFeature(String),

    /// The assertion store does not contain the expected number of assertions.
    #[error(
        "unexpected number of assertions in assertion store (expected {expected}, found {found})"
    )]
    AssertionCountMismatch { expected: usize, found: usize },
}

#[cfg(test)]
pub mod tests;
