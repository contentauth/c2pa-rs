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
    collections::HashMap,
    io::{Cursor, Read, Seek},
};
#[cfg(feature = "file_io")]
use std::{
    fs,
    path::{Path, PathBuf},
};

use async_generic::async_generic;
use async_recursion::async_recursion;
use log::error;

#[cfg(feature = "file_io")]
use crate::jumbf_io::{
    get_file_extension, get_supported_file_extension, load_jumbf_from_file, object_locations,
    remove_jumbf_from_file, save_jumbf_to_file,
};
use crate::{
    assertion::{
        Assertion, AssertionBase, AssertionData, AssertionDecodeError, AssertionDecodeErrorCause,
    },
    assertions::{
        labels::{self, CLAIM},
        BmffHash, DataBox, DataHash, DataMap, ExclusionsMap, Ingredient, Relationship, SubsetMap,
    },
    asset_io::{
        CAIRead, CAIReadWrite, HashBlockObjectType, HashObjectPositions, RemoteRefEmbedType,
    },
    claim::{Claim, ClaimAssertion, ClaimAssetData, RemoteManifest},
    cose_sign::{cose_sign, cose_sign_async},
    cose_validator::{check_ocsp_status, verify_cose, verify_cose_async},
    error::{Error, Result},
    external_manifest::ManifestPatchCallback,
    hash_utils::{hash_by_alg, vec_compare, verify_by_alg},
    hashed_uri::HashedUri,
    jumbf::{
        self,
        boxes::*,
        labels::{ASSERTIONS, CREDENTIALS, DATABOXES, SIGNATURE},
    },
    jumbf_io::{
        get_assetio_handler, is_bmff_format, load_jumbf_from_stream, object_locations_from_stream,
        save_jumbf_to_memory, save_jumbf_to_stream,
    },
    manifest_store_report::ManifestStoreReport,
    salt::DefaultSalt,
    settings::get_settings_value,
    status_tracker::{log_item, DetailedStatusTracker, OneShotStatusTracker, StatusTracker},
    trust_handler::TrustHandlerConfig,
    utils::{
        hash_utils::{hash_sha256, HashRange},
        io_utils::stream_len,
        patch::patch_bytes,
    },
    validation_status, AsyncSigner, RemoteSigner, Signer,
};

const MANIFEST_STORE_EXT: &str = "c2pa"; // file extension for external manifests

/// A `Store` maintains a list of `Claim` structs.
///
/// Typically, this list of `Claim`s represents all of the claims in an asset.
#[derive(Debug)]
pub struct Store {
    claims_map: HashMap<String, usize>,
    manifest_box_hash_cache: HashMap<String, Vec<u8>>,
    claims: Vec<Claim>,
    label: String,
    provenance_path: Option<String>,
    trust_handler: Box<dyn TrustHandlerConfig>,
}

struct ManifestInfo<'a> {
    pub desc_box: &'a JUMBFDescriptionBox,
    pub sbox: &'a JUMBFSuperBox,
}

trait PushGetIndex {
    type Item;
    fn push_get_index(&mut self, item: Self::Item) -> usize;
}

impl<T> PushGetIndex for Vec<T> {
    type Item = T;

    fn push_get_index(&mut self, item: T) -> usize {
        let index = self.len();
        self.push(item);
        index
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// Create a new, empty claims store.
    pub fn new() -> Self {
        Self::new_with_label(MANIFEST_STORE_EXT)
    }

    /// Create a new, empty claims store with a custom label.
    ///
    /// In most cases, calling [`Store::new()`] is preferred.
    pub fn new_with_label(label: &str) -> Self {
        let mut store = Store {
            claims_map: HashMap::new(),
            manifest_box_hash_cache: HashMap::new(),
            claims: Vec::new(),
            label: label.to_string(),
            #[cfg(feature = "openssl")]
            trust_handler: Box::new(crate::openssl::OpenSSLTrustHandlerConfig::new()),
            #[cfg(all(
                not(feature = "openssl"),
                not(target_os = "wasi"),
                target_arch = "wasm32"
            ))]
            trust_handler: Box::new(crate::wasm::WebTrustHandlerConfig::new()),
            #[cfg(all(
                not(feature = "openssl"),
                any(not(target_arch = "wasm32"), target_os = "wasi")
            ))]
            trust_handler: Box::new(crate::trust_handler::TrustPassThrough::new()),
            provenance_path: None,
        };

        // load the trust handler settings, don't worry about status as these are checked during setting generation
        let _ = get_settings_value::<Option<String>>("trust.trust_anchors").map(|ta_opt| {
            if let Some(ta) = ta_opt {
                let _v = store.add_trust(ta.as_bytes());
            }
        });

        let _ = get_settings_value::<Option<String>>("trust.private_anchors").map(|pa_opt| {
            if let Some(pa) = pa_opt {
                let _v = store.add_private_trust_anchors(pa.as_bytes());
            }
        });

        let _ = get_settings_value::<Option<String>>("trust.trust_config").map(|tc_opt| {
            if let Some(tc) = tc_opt {
                let _v = store.add_trust_config(tc.as_bytes());
            }
        });

        let _ = get_settings_value::<Option<String>>("trust.allowed_list").map(|al_opt| {
            if let Some(al) = al_opt {
                let _v = store.add_trust_allowed_list(al.as_bytes());
            }
        });

        store
    }

    /// Return label for the store
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Load set of trust anchors used for certificate validation. [u8] containing the
    /// trust anchors is passed in the trust_vec variable.
    pub fn add_trust(&mut self, trust_vec: &[u8]) -> Result<()> {
        let mut trust_reader = Cursor::new(trust_vec);
        self.trust_handler
            .load_trust_anchors_from_data(&mut trust_reader)
    }

    // Load set of private trust anchors used for certificate validation. [u8] to the
    /// private trust anchors is passed in the trust_vec variable.  This can be called multiple times
    /// if there are additional trust stores.
    pub fn add_private_trust_anchors(&mut self, trust_vec: &[u8]) -> Result<()> {
        let mut trust_reader = Cursor::new(trust_vec);
        self.trust_handler
            .append_private_trust_data(&mut trust_reader)
    }

    pub fn add_trust_config(&mut self, trust_vec: &[u8]) -> Result<()> {
        let mut trust_reader = Cursor::new(trust_vec);
        self.trust_handler.load_configuration(&mut trust_reader)
    }

    pub fn add_trust_allowed_list(&mut self, allowed_vec: &[u8]) -> Result<()> {
        let mut trust_reader = Cursor::new(allowed_vec);
        self.trust_handler.load_allowed_list(&mut trust_reader)
    }

    /// Clear all existing trust anchors
    pub fn clear_trust_anchors(&mut self) {
        self.trust_handler.clear();
    }

    fn trust_handler(&self) -> &dyn TrustHandlerConfig {
        self.trust_handler.as_ref()
    }

    /// Get the provenance if available.
    /// If loaded from an existing asset it will be provenance from the last claim.
    /// If a new claim is committed that will be the provenance claim
    pub fn provenance_path(&self) -> Option<String> {
        if self.provenance_path.is_none() {
            // if we have claims and no provenance, return last claim
            if let Some(claim) = self.claims.last() {
                return Some(Claim::to_claim_uri(claim.label()));
            }
        }
        self.provenance_path.as_ref().cloned()
    }

    // set the path of the current provenance claim
    fn set_provenance_path(&mut self, claim_label: &str) {
        let path = Claim::to_claim_uri(claim_label);
        self.provenance_path = Some(path);
    }

    /// get the list of claims for this store
    pub fn claims(&self) -> &Vec<Claim> {
        &self.claims
    }

    /// the JUMBF manifest box hash (spec 1.2)
    pub fn get_manifest_box_hash(&self, claim: &Claim) -> Vec<u8> {
        if let Some(bh) = self.manifest_box_hash_cache.get(claim.label()) {
            bh.clone()
        } else {
            Store::calc_manifest_box_hash(claim, None, claim.alg()).unwrap_or_default()
        }
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

        // load the claim ingredients
        // parse first to make sure we can load them
        let mut ingredient_claims: Vec<Claim> = Vec::new();
        for (pc, claims) in claim.claim_ingredient_store() {
            let mut valid_pc = false;

            // expand for flat list insertion
            for ingredient_claim in claims {
                // recreate claim from original bytes
                let claim_clone = ingredient_claim.clone();
                if pc == claim_clone.label() {
                    valid_pc = true;
                }
                ingredient_claims.push(claim_clone);
            }
            if !valid_pc {
                return Err(Error::IngredientNotFound);
            }
        }

        // update the provenance path
        self.set_provenance_path(claim.label());

        let claim_label = claim.label().to_string();

        // insert ingredients if needed
        for ingredient_claim in ingredient_claims {
            let label = ingredient_claim.label().to_owned();

            if let std::collections::hash_map::Entry::Vacant(e) = self.claims_map.entry(label) {
                let index = self.claims.push_get_index(ingredient_claim);
                e.insert(index);
            }
        }

        // add claim to store after ingredients
        let index = self.claims.push_get_index(claim);
        self.claims_map.insert(claim_label.clone(), index);

        Ok(claim_label)
    }

    /// Add a new update manifest to this Store. The manifest label
    /// may be updated to reflect is position in the manifest Store
    /// if there are conflicting label names.  The function
    /// will return the label of the claim used
    pub fn commit_update_manifest(&mut self, mut claim: Claim) -> Result<String> {
        claim.set_update_manifest(true);

        // check for disallowed assertions
        if claim.has_assertion_type(labels::DATA_HASH)
            || claim.has_assertion_type(labels::ACTIONS)
            || claim.has_assertion_type(labels::BMFF_HASH)
        {
            return Err(Error::ClaimInvalidContent);
        }

        // must have exactly one ingredient
        let ingredient = match claim.get_assertion(Ingredient::LABEL, 0) {
            Some(i) => {
                if claim.count_instances(Ingredient::LABEL) > 1 {
                    return Err(Error::ClaimInvalidContent);
                } else {
                    i
                }
            }
            None => return Err(Error::ClaimInvalidContent),
        };

        let ingredient_helper = Ingredient::from_assertion(ingredient)?;

        // must have a parent relationship
        if ingredient_helper.relationship != Relationship::ParentOf {
            return Err(Error::IngredientNotFound);
        }

        // make sure ingredient c2pa.manifest points to provenance claim
        if let Some(c2pa_manifest) = ingredient_helper.c2pa_manifest {
            // the manifest should refer to provenance claim
            if let Some(pc) = self.provenance_claim() {
                if !c2pa_manifest.url().contains(pc.label()) {
                    return Err(Error::IngredientNotFound);
                }
            } else {
                return Err(Error::IngredientNotFound);
            }
        } else {
            return Err(Error::IngredientNotFound);
        }

        self.commit_claim(claim)
    }

    /// Get Claim by label
    // Returns Option<&Claim>
    pub fn get_claim(&self, label: &str) -> Option<&Claim> {
        #![allow(clippy::unwrap_used)] // since it's only in a debug_assert
        let index = self.claims_map.get(label)?;
        debug_assert!(self.claims.get(*index).unwrap().label() == label);
        self.claims.get(*index)
    }

    /// Get Claim by label
    // Returns Option<&Claim>
    pub fn get_claim_mut(&mut self, label: &str) -> Option<&mut Claim> {
        #![allow(clippy::unwrap_used)] // since it's only in a debug_assert
        let index = self.claims_map.get(label)?;
        debug_assert!(self.claims.get(*index).unwrap().label() == label);
        self.claims.get_mut(*index)
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
            .ok_or_else(|| Error::ClaimMissing {
                label: label.to_owned(),
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
        let mut placeholder = hash_sha256(placeholder_str.as_bytes());

        use std::cmp::max;
        placeholder.resize(max(placeholder.len(), min_reserve_size), 0);

        placeholder
    }

    /// Return certificate chain for the provenance claim
    #[cfg(feature = "v1_api")]
    pub(crate) fn get_provenance_cert_chain(&self) -> Result<String> {
        let claim = self.provenance_claim().ok_or(Error::ProvenanceMissing)?;

        match claim.get_cert_chain() {
            Ok(chain) => String::from_utf8(chain).map_err(|_e| Error::CoseInvalidCert),
            Err(e) => Err(e),
        }
    }

    /// Return OCSP info if available
    // Currently only called from manifest_store behind a feature flag but this is allowable
    // anywhere so allow dead code here for future uses to compile
    #[allow(dead_code)]
    pub(crate) fn get_ocsp_status(&self) -> Option<String> {
        let claim = self
            .provenance_claim()
            .ok_or(Error::ProvenanceMissing)
            .ok()?;

        let sig = claim.signature_val();
        let data = claim.data().ok()?;
        let mut validation_log = OneShotStatusTracker::new();

        if let Ok(info) = check_ocsp_status(sig, &data, self.trust_handler(), &mut validation_log) {
            if let Some(revoked_at) = &info.revoked_at {
                Some(format!(
                    "Certificate Status: Revoked, revoked at: {}",
                    revoked_at
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
    ))]
    pub fn sign_claim(
        &self,
        claim: &Claim,
        signer: &dyn Signer,
        box_size: usize,
    ) -> Result<Vec<u8>> {
        let claim_bytes = claim.data()?;

        let result = if _sync {
            if signer.direct_cose_handling() {
                // Let the signer do all the COSE processing and return the structured COSE data.
                return signer.sign(&claim_bytes); // do not verify remote signers (we never did)
            } else {
                cose_sign(signer, &claim_bytes, box_size)
            }
        } else {
            if signer.direct_cose_handling() {
                // Let the signer do all the COSE processing and return the structured COSE data.
                return signer.sign(claim_bytes.clone()).await; // do not verify remote signers (we never did)
            } else {
                cose_sign_async(signer, &claim_bytes, box_size).await
            }
        };
        match result {
            Ok(sig) => {
                // Sanity check: Ensure that this signature is valid.
                if let Ok(verify_after_sign) =
                    get_settings_value::<bool>("verify.verify_after_sign")
                {
                    if verify_after_sign {
                        let mut cose_log = OneShotStatusTracker::new();

                        let result = if _sync {
                            verify_cose(
                                &sig,
                                &claim_bytes,
                                b"",
                                false,
                                self.trust_handler(),
                                &mut cose_log,
                            )
                        } else {
                            verify_cose_async(
                                sig.clone(),
                                claim_bytes,
                                b"".to_vec(),
                                false,
                                self.trust_handler(),
                                &mut cose_log,
                            )
                            .await
                        };
                        if let Err(err) = result {
                            error!(
                                "Signature that was just generated does not validate: {:#?}",
                                err
                            );
                            return Err(err);
                        }
                    }
                }
                Ok(sig)
            }
            Err(e) => Err(e),
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
    fn insert_restored_claim(&mut self, label: String, claim: Claim) {
        let index = self.claims.push_get_index(claim);
        self.claims_map.insert(label, index);
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
    ) -> Result<ClaimAssertion> {
        let assertion_desc_box = assertion_box.desc_box();

        let (raw_label, instance) = Claim::assertion_label_from_link(label);
        let instance_label = Claim::label_with_instance(&raw_label, instance);
        let assertion_hashed_uri = claim
            .assertion_hashed_uri_from_label(&instance_label)
            .ok_or_else(|| {
                Error::AssertionDecoding(AssertionDecodeError {
                    label: instance_label.to_string(),
                    version: None, // TODO: Plumb this through
                    content_type: "TO DO: Get content type".to_string(),
                    source: AssertionDecodeErrorCause::AssertionDataIncorrect,
                })
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
                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
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
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
            }
            CAI_CBOR_ASSERTION_UUID => {
                let cbor_box = assertion_box
                    .data_box_as_cbor_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let assertion = Assertion::from_data_cbor(&raw_label, cbor_box.cbor());
                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
            }
            CAI_UUID_ASSERTION_UUID => {
                let uuid_box = assertion_box
                    .data_box_as_uuid_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let uuid_str = hex::encode(uuid_box.uuid());
                let assertion = Assertion::from_data_uuid(&raw_label, &uuid_str, uuid_box.data());

                let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
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
    pub fn to_jumbf(&self, signer: &dyn Signer) -> Result<Vec<u8>> {
        self.to_jumbf_internal(signer.reserve_size())
    }

    /// Convert this claims store to a JUMBF box.
    pub fn to_jumbf_async(&self, signer: &dyn AsyncSigner) -> Result<Vec<u8>> {
        self.to_jumbf_internal(signer.reserve_size())
    }

    fn to_jumbf_internal(&self, min_reserve_size: usize) -> Result<Vec<u8>> {
        // Create the CAI block.
        let mut cai_block = Cai::new();

        // Add claims and assertions in this store to the JUMBF store.
        for claim in &self.claims {
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
                    let mut cb = CAIClaimBox::new();

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
                    if !claim.get_verifiable_credentials().is_empty() {
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
                            let db_cbor_bytes =
                                serde_cbor::to_vec(db).map_err(|_err| Error::AssertionEncoding)?;

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
        if let Some(desired_version) = labels::version(desired_version_label) {
            if let Some(base_version) = labels::version(base_version_label) {
                if desired_version > base_version {
                    return false;
                }
            }
        }
        true
    }

    pub fn from_jumbf(buffer: &[u8], validation_log: &mut impl StatusTracker) -> Result<Store> {
        if buffer.is_empty() {
            return Err(Error::JumbfNotFound);
        }

        let mut store = Store::new();

        // setup a cursor for reading the buffer...
        let mut buf_reader = Cursor::new(buffer);

        // this loads up all the boxes...
        let super_box = BoxReader::read_super_box(&mut buf_reader)?;

        // this loads up all the boxes...
        let cai_block = Cai::from(super_box);

        // check the CAI Block
        let desc_box = cai_block.desc_box();
        if desc_box.uuid() != CAI_BLOCK_UUID {
            let log_item = log_item!("JUMBF", "c2pa box not found", "from_jumbf")
                .error(Error::InvalidClaim(InvalidClaimError::C2paBlockNotFound));
            validation_log.log(
                log_item,
                Some(Error::InvalidClaim(InvalidClaimError::C2paBlockNotFound)),
            )?;

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
                    let log_item =
                        log_item!("JUMBF", "c2pa multiple claim boxes found", "from_jumbf")
                            .error(Error::InvalidClaim(
                                InvalidClaimError::C2paMultipleClaimBoxes,
                            ))
                            .validation_status(validation_status::CLAIM_MULTIPLE);
                    validation_log.log(
                        log_item,
                        Some(Error::InvalidClaim(
                            InvalidClaimError::C2paMultipleClaimBoxes,
                        )),
                    )?;

                    return Err(Error::InvalidClaim(
                        InvalidClaimError::C2paMultipleClaimBoxes,
                    ));
                }

                match desc_box.label().as_ref() {
                    ASSERTIONS => box_order.push(ASSERTIONS),
                    CLAIM => box_order.push(CLAIM),
                    SIGNATURE => box_order.push(SIGNATURE),
                    CREDENTIALS => box_order.push(CREDENTIALS),
                    DATABOXES => box_order.push(DATABOXES),
                    _ => {
                        let log_item =
                            log_item!("JUMBF", "unrecognized manifest box", "from_jumbf")
                                .error(Error::InvalidClaim(InvalidClaimError::ClaimBoxData))
                                .validation_status(validation_status::CLAIM_MULTIPLE);
                        validation_log.log(
                            log_item,
                            Some(Error::InvalidClaim(InvalidClaimError::ClaimBoxData)),
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
            if !Self::check_label_version(Claim::build_version(), &claim_box_ver) {
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
                                let log_item =
                                    log_item!("JUMBF", "error loading claim data", "from_jumbf")
                                        .error(Error::PrereleaseError);
                                validation_log.log_silent(log_item);

                                return Err(Error::PrereleaseError);
                            }
                            None => {
                                let log_item =
                                    log_item!("JUMBF", "error loading claim data", "from_jumbf")
                                        .error(Error::InvalidClaim(
                                            InvalidClaimError::ClaimBoxData,
                                        ));
                                validation_log.log_silent(log_item);
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
            let mut claim = Claim::from_data(&cai_store_desc_box.label(), cbor_box.cbor())?;

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

            // loop over all assertions...
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
                            let log_item =
                                log_item!("JUMBF", "error loading assertion", "from_jumbf")
                                    .error(e);
                            validation_log.log_silent(log_item);
                            return Err(Error::PrereleaseError);
                        } else {
                            let log_item =
                                log_item!("JUMBF", "error loading assertion", "from_jumbf")
                                    .error(e);
                            validation_log.log(log_item, None)?;
                        }
                    }
                }
            }

            // load vc_store if available
            if let Some(mi) = manifest_boxes.get(CAI_VERIFIABLE_CREDENTIALS_STORE_UUID) {
                let vc_store = mi.sbox;
                let num_vcs = vc_store.data_box_count();

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
            store.manifest_box_hash_cache.insert(
                claim.label().to_owned(),
                Store::calc_manifest_box_hash(&claim, None, claim.alg())?,
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

    // wake the ingredients and validate
    fn ingredient_checks(
        store: &Store,
        claim: &Claim,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let mut num_parent_ofs = 0;

        // walk the ingredients
        for i in claim.ingredient_assertions() {
            let ingredient_assertion = Ingredient::from_assertion(i)?;

            // is this an ingredient
            if let Some(ref c2pa_manifest) = &ingredient_assertion.c2pa_manifest {
                let label = Store::manifest_label_from_path(&c2pa_manifest.url());

                // check for parentOf relationships
                if ingredient_assertion.relationship == Relationship::ParentOf {
                    num_parent_ofs += 1;
                }

                if let Some(ingredient) = store.get_claim(&label) {
                    let alg = match c2pa_manifest.alg() {
                        Some(a) => a,
                        None => ingredient.alg().to_owned(),
                    };

                    // get the 1.1-1.2 box hash
                    let box_hash = store.get_manifest_box_hash(ingredient);

                    // test for 1.1 hash then 1.0 version
                    if !vec_compare(&c2pa_manifest.hash(), &box_hash)
                        && !verify_by_alg(&alg, &c2pa_manifest.hash(), &ingredient.data()?, None)
                    {
                        let log_item = log_item!(
                            &c2pa_manifest.url(),
                            "ingredient hash incorrect",
                            "ingredient_checks"
                        )
                        .error(Error::HashMismatch(
                            "ingredient hash does not match found ingredient".to_string(),
                        ))
                        .validation_status(validation_status::INGREDIENT_HASHEDURI_MISMATCH);
                        validation_log.log(
                            log_item,
                            Some(Error::HashMismatch(
                                "ingredient hash does not match found ingredient".to_string(),
                            )),
                        )?;
                    }

                    let check_ingredient_trust: bool =
                        crate::settings::get_settings_value("verify.check_ingredient_trust")?;

                    // verify the ingredient claim
                    Claim::verify_claim(
                        ingredient,
                        asset_data,
                        false,
                        check_ingredient_trust,
                        store.trust_handler(),
                        validation_log,
                    )?;

                    // recurse nested ingredients
                    Store::ingredient_checks(store, ingredient, asset_data, validation_log)?;
                } else {
                    let log_item = log_item!(
                        &c2pa_manifest.url(),
                        "ingredient not found",
                        "ingredient_checks"
                    )
                    .error(Error::ClaimVerification(format!(
                        "ingredient: {label} is missing"
                    )))
                    .validation_status(validation_status::CLAIM_MISSING);
                    validation_log.log(
                        log_item,
                        Some(Error::ClaimVerification(format!(
                            "ingredient: {label} is missing"
                        ))),
                    )?;
                }
            }
        }

        // check ingredient rules
        if claim.update_manifest() {
            if !(num_parent_ofs == 1 && claim.ingredient_assertions().len() == 1) {
                let log_item = log_item!(
                    &claim.uri(),
                    "update manifest must have one parent",
                    "ingredient_checks"
                )
                .error(Error::ClaimVerification(
                    "update manifest must have one parent".to_string(),
                ))
                .validation_status(validation_status::MANIFEST_UPDATE_WRONG_PARENTS);
                validation_log.log(
                    log_item,
                    Some(Error::ClaimVerification(
                        "update manifest must have one parent".to_string(),
                    )),
                )?;
            }
        } else if num_parent_ofs > 1 {
            let log_item = log_item!(
                &claim.uri(),
                "too many ingredient parents",
                "ingredient_checks"
            )
            .error(Error::ClaimVerification(
                "ingredient has more than one parent".to_string(),
            ))
            .validation_status(validation_status::MANIFEST_MULTIPLE_PARENTS);
            validation_log.log(
                log_item,
                Some(Error::ClaimVerification(
                    "ingredient has more than one parent".to_string(),
                )),
            )?;
        }

        Ok(())
    }

    // wake the ingredients and validate
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    async fn ingredient_checks_async(
        store: &Store,
        claim: &Claim,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        // walk the ingredients
        for i in claim.ingredient_assertions() {
            let ingredient_assertion = Ingredient::from_assertion(i)?;

            // is this an ingredient
            if let Some(ref c2pa_manifest) = &ingredient_assertion.c2pa_manifest {
                let label = Store::manifest_label_from_path(&c2pa_manifest.url());

                if let Some(ingredient) = store.get_claim(&label) {
                    let alg = match c2pa_manifest.alg() {
                        Some(a) => a,
                        None => ingredient.alg().to_owned(),
                    };

                    // get the 1.1-1.2 box hash
                    let box_hash = store.get_manifest_box_hash(ingredient);

                    // test for 1.1 hash then 1.0 version
                    if !vec_compare(&c2pa_manifest.hash(), &box_hash)
                        && !verify_by_alg(&alg, &c2pa_manifest.hash(), &ingredient.data()?, None)
                    {
                        let log_item = log_item!(
                            &c2pa_manifest.url(),
                            "ingredient hash incorrect",
                            "ingredient_checks_async"
                        )
                        .error(Error::HashMismatch(
                            "ingredient hash does not match found ingredient".to_string(),
                        ))
                        .validation_status(validation_status::INGREDIENT_HASHEDURI_MISMATCH);
                        validation_log.log(
                            log_item,
                            Some(Error::HashMismatch(
                                "ingredient hash does not match found ingredient".to_string(),
                            )),
                        )?;
                    }

                    let check_ingredient_trust: bool =
                        get_settings_value("verify.check_ingredient_trust")?;

                    // verify the ingredient claim
                    Claim::verify_claim_async(
                        ingredient,
                        asset_data,
                        false,
                        check_ingredient_trust,
                        store.trust_handler(),
                        validation_log,
                    )
                    .await?;

                    // recurse nested ingredients
                    Store::ingredient_checks_async(store, ingredient, asset_data, validation_log)
                        .await?;
                } else {
                    let log_item = log_item!(
                        &c2pa_manifest.url(),
                        "ingredient not found",
                        "ingredient_checks_async"
                    )
                    .error(Error::ClaimVerification(format!(
                        "ingredient: {label} is missing"
                    )))
                    .validation_status(validation_status::CLAIM_MISSING);
                    validation_log.log(
                        log_item,
                        Some(Error::ClaimVerification(format!(
                            "ingredient: {label} is missing"
                        ))),
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Verify Store
    /// store: Store to validate
    /// xmp_str: String containing entire XMP block of the asset
    /// asset_bytes: bytes of the asset to be verified
    /// validation_log: If present all found errors are logged and returned, other wise first error causes exit and is returned  
    pub async fn verify_store_async(
        store: &Store,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let claim = match store.provenance_claim() {
            Some(c) => c,
            None => {
                let log_item =
                    log_item!("Unknown", "could not find active manifest", "verify_store")
                        .error(Error::ProvenanceMissing)
                        .validation_status(validation_status::CLAIM_MISSING);
                validation_log.log(log_item, Some(Error::ProvenanceMissing))?;

                return Err(Error::ProvenanceMissing);
            }
        };

        // verify the provenance claim
        Claim::verify_claim_async(
            claim,
            asset_data,
            true,
            true,
            store.trust_handler(),
            validation_log,
        )
        .await?;

        Store::ingredient_checks_async(store, claim, asset_data, validation_log).await?;

        Ok(())
    }

    /// Verify Store
    /// store: Store to validate
    /// xmp_str: String containing entire XMP block of the asset
    /// asset_bytes: bytes of the asset to be verified
    /// validation_log: If present all found errors are logged and returned, other wise first error causes exit and is returned  
    pub fn verify_store(
        store: &Store,
        asset_data: &mut ClaimAssetData<'_>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let claim = match store.provenance_claim() {
            Some(c) => c,
            None => {
                let log_item =
                    log_item!("Unknown", "could not find active manifest", "verify_store")
                        .error(Error::ProvenanceMissing)
                        .validation_status(validation_status::CLAIM_MISSING);
                validation_log.log(log_item, Some(Error::ProvenanceMissing))?;

                return Err(Error::ProvenanceMissing);
            }
        };

        // verify the provenance claim
        Claim::verify_claim(
            claim,
            asset_data,
            true,
            true,
            store.trust_handler(),
            validation_log,
        )?;

        Store::ingredient_checks(store, claim, asset_data, validation_log)?;

        Ok(())
    }

    // generate a list of AssetHashes based on the location of objects in the file
    #[cfg(feature = "file_io")]
    fn generate_data_hashes(
        asset_path: &Path,
        alg: &str,
        block_locations: &mut Vec<HashObjectPositions>,
        calc_hashes: bool,
    ) -> Result<Vec<DataHash>> {
        let mut file = std::fs::File::open(asset_path)?;
        Self::generate_data_hashes_for_stream(&mut file, alg, block_locations, calc_hashes)
    }

    // generate a list of AssetHashes based on the location of objects in the stream
    fn generate_data_hashes_for_stream<R>(
        stream: &mut R,
        alg: &str,
        block_locations: &mut Vec<HashObjectPositions>,
        calc_hashes: bool,
    ) -> Result<Vec<DataHash>>
    where
        R: Read + Seek + ?Sized,
    {
        if block_locations.is_empty() {
            let out: Vec<DataHash> = vec![];
            return Ok(out);
        }

        let stream_len = stream_len(stream)?;
        stream.rewind()?;

        let mut hashes: Vec<DataHash> = Vec::new();

        // sort blocks by offset
        block_locations.sort_by(|a, b| a.offset.cmp(&b.offset));

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
        }

        if found_jumbf {
            // add exclusion hash for bytes before and after jumbf
            let mut dh = DataHash::new("jumbf manifest", alg);

            if calc_hashes {
                if block_end > block_start && (block_end as u64) <= stream_len {
                    dh.add_exclusion(HashRange::new(block_start, block_end - block_start));
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

                dh.gen_hash_from_stream(stream)?;
            } else {
                if block_end > block_start {
                    dh.add_exclusion(HashRange::new(block_start, block_end - block_start));
                }

                match alg {
                    "sha256" => dh.set_hash([0u8; 32].to_vec()),
                    "sha384" => dh.set_hash([0u8; 48].to_vec()),
                    "sha512" => dh.set_hash([0u8; 64].to_vec()),
                    _ => return Err(Error::UnsupportedType),
                }
            }
            hashes.push(dh);
        }

        Ok(hashes)
    }

    fn generate_bmff_data_hash_for_stream(
        asset_stream: &mut dyn CAIRead,
        alg: &str,
        calc_hashes: bool,
        flat_fragmented_w_merkle: bool,
    ) -> Result<BmffHash> {
        // The spec has mandatory BMFF exclusion ranges for certain atoms.
        // The function makes sure those are included.

        let mut dh = BmffHash::new("jumbf manifest", alg, None);
        let exclusions = dh.exclusions_mut();

        // jumbf exclusion
        let mut uuid = ExclusionsMap::new("/uuid".to_owned());
        let data = DataMap {
            offset: 8,
            value: vec![
                216, 254, 195, 214, 27, 14, 72, 60, 146, 151, 88, 40, 135, 126, 196, 129,
            ], // C2PA identifier
        };
        let data_vec = vec![data];
        uuid.data = Some(data_vec);
        exclusions.push(uuid);

        // ftyp exclusion
        let ftyp = ExclusionsMap::new("/ftyp".to_owned());
        exclusions.push(ftyp);

        // /mfra/ exclusion
        let mfra = ExclusionsMap::new("/mfra".to_owned());
        exclusions.push(mfra);

        /*  no longer mandatory
        // meta/iloc exclusion
        let iloc = ExclusionsMap::new("/meta/iloc".to_owned());
        exclusions.push(iloc);

        // /mfra/tfra exclusion
        let tfra = ExclusionsMap::new("/mfra/tfra".to_owned());
        exclusions.push(tfra);

        // /moov/trak/mdia/minf/stbl/stco exclusion
        let mut stco = ExclusionsMap::new("/moov/trak/mdia/minf/stbl/stco".to_owned());
        let subset_stco = SubsetMap {
            offset: 16,
            length: 0,
        };
        let subset_stco_vec = vec![subset_stco];
        stco.subset = Some(subset_stco_vec);
        exclusions.push(stco);

        // /moov/trak/mdia/minf/stbl/co64 exclusion
        let mut co64 = ExclusionsMap::new("/moov/trak/mdia/minf/stbl/co64".to_owned());
        let subset_co64 = SubsetMap {
            offset: 16,
            length: 0,
        };
        let subset_co64_vec = vec![subset_co64];
        co64.subset = Some(subset_co64_vec);
        exclusions.push(co64);

        // /moof/traf/tfhd exclusion
        let mut tfhd = ExclusionsMap::new("/moof/traf/tfhd".to_owned());
        let subset_tfhd = SubsetMap {
            offset: 16,
            length: 8,
        };
        let subset_tfhd_vec = vec![subset_tfhd];
        tfhd.subset = Some(subset_tfhd_vec);
        tfhd.flags = Some(ByteBuf::from([1, 0, 0]));
        exclusions.push(tfhd);

        // /moof/traf/trun exclusion
        let mut trun = ExclusionsMap::new("/moof/traf/trun".to_owned());
        let subset_trun = SubsetMap {
            offset: 16,
            length: 4,
        };
        let subset_trun_vec = vec![subset_trun];
        trun.subset = Some(subset_trun_vec);
        trun.flags = Some(ByteBuf::from([1, 0, 0]));
        exclusions.push(trun);
        */

        // enable flat flat files with Merkle trees
        if flat_fragmented_w_merkle {
            let mut mdat = ExclusionsMap::new("/mdat".to_owned());
            let subset_mdat = SubsetMap {
                offset: 16,
                length: 0,
            };
            let subset_mdat_vec = vec![subset_mdat];
            mdat.subset = Some(subset_mdat_vec);
            exclusions.push(mdat);
        }

        if calc_hashes {
            dh.gen_hash_from_stream(asset_stream)?;
        } else {
            match alg {
                "sha256" => dh.set_hash([0u8; 32].to_vec()),
                "sha384" => dh.set_hash([0u8; 48].to_vec()),
                "sha512" => dh.set_hash([0u8; 64].to_vec()),
                _ => return Err(Error::UnsupportedType),
            }
        }

        Ok(dh)
    }

    // move or copy data from source to dest
    #[cfg(feature = "file_io")]
    fn move_or_copy(source: &Path, dest: &Path) -> Result<()> {
        // copy temp file to asset
        std::fs::rename(source, dest)
            // if rename fails, try to copy in case we are on different volumes or output does not exist
            .or_else(|_| std::fs::copy(source, dest).and(Ok(())))
            .map_err(Error::IoError)
    }

    // copy output and possibly the external manifest to final destination
    #[cfg(feature = "file_io")]
    fn copy_c2pa_to_output(source: &Path, dest: &Path, remote_type: RemoteManifest) -> Result<()> {
        match remote_type {
            RemoteManifest::NoRemote => Store::move_or_copy(source, dest)?,
            RemoteManifest::SideCar
            | RemoteManifest::Remote(_)
            | RemoteManifest::EmbedWithRemote(_) => {
                // make correct path names
                let source_asset = source;
                let source_cai = source_asset.with_extension(MANIFEST_STORE_EXT);
                let dest_cai = dest.with_extension(MANIFEST_STORE_EXT);

                Store::move_or_copy(&source_cai, &dest_cai)?; // copy manifest
                Store::move_or_copy(source_asset, dest)?; // copy asset
            }
        }
        Ok(())
    }

    /// This function is used to pre-generate a manifest with place holders for the final
    /// DataHash and Manifest Signature.  The DataHash will reserve space for at least 10
    /// Exclusion ranges.  The Signature box reserved size is based on the size required by
    /// the Signer you plan to use.  This function is not needed when using Box Hash. This function is used
    /// in conjunction with `get_data_hashed_embeddable_manifest`.  The manifest returned
    /// from `get_data_hashed_embeddable_manifest` will have a size that matches this function.
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
                ph.add_exclusion(HashRange::new(0, 2));
            }
            let data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let mut stream = Cursor::new(data);
            ph.gen_hash_from_stream(&mut stream)?;

            pc.add_assertion_with_salt(&ph, &DefaultSalt::default())?;
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
            adjusted_dh.gen_hash_from_stream(reader)?;
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
    ) -> Result<Vec<u8>> {
        let mut jumbf_bytes =
            self.prep_embeddable_store(signer.reserve_size(), dh, asset_reader)?;

        // sign contents
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self.sign_claim(pc, signer, signer.reserve_size())?;

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
    ) -> Result<Vec<u8>> {
        let mut jumbf_bytes =
            self.prep_embeddable_store(signer.reserve_size(), dh, asset_reader)?;

        // sign contents
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self
            .sign_claim_async(pc, signer, signer.reserve_size())
            .await?;

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
    pub async fn get_data_hashed_embeddable_manifest_remote(
        &mut self,
        dh: &DataHash,
        signer: &dyn RemoteSigner,
        format: &str,
        asset_reader: Option<&mut dyn CAIRead>,
    ) -> Result<Vec<u8>> {
        let mut jumbf_bytes =
            self.prep_embeddable_store(signer.reserve_size(), dh, asset_reader)?;

        // sign contents
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let claim_bytes = pc.data()?;
        let sig = signer.sign_remote(&claim_bytes).await?;

        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        self.finish_embeddable_store(&sig, &sig_placeholder, &mut jumbf_bytes, format)
    }

    /// Returns a finalized, signed manifest.  The client is required to have
    /// included the necessary box hash assertion with the pregenerated hashes.
    pub fn get_box_hashed_embeddable_manifest(&mut self, signer: &dyn Signer) -> Result<Vec<u8>> {
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
        let sig = self.sign_claim(pc, signer, signer.reserve_size())?;
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
            .sign_claim_async(pc, signer, signer.reserve_size())
            .await?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, &sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        Ok(jumbf_bytes)
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
    ) -> Result<Vec<u8>> {
        // get the provenance claim changing mutability
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        pc.clear_data(); // clear since we are reusing an existing claim

        let output_filename = asset_path.file_name().ok_or(Error::NotFound)?;
        let dest_path = output_dir.join(output_filename);

        let mut data;

        // 2) Get hash ranges if needed
        let mut asset_stream = std::fs::File::open(asset_path)?;
        let mut bmff_hash =
            Store::generate_bmff_data_hash_for_stream(&mut asset_stream, pc.alg(), false, false)?;
        bmff_hash.clear_hash();

        // generate fragments and produce Merkle tree
        bmff_hash.add_merkle_for_fragmented(
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
            let mut bmff_hash = BmffHash::from_assertion(bmff_hashes[0])?;
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
    ) -> Result<()> {
        match get_supported_file_extension(asset_path) {
            Some(ext) => {
                if !is_bmff_format(&ext) {
                    return Err(Error::UnsupportedType);
                }
            }
            None => return Err(Error::UnsupportedType),
        }

        let mut validation_log = OneShotStatusTracker::new();
        let jumbf = self.to_jumbf(signer)?;

        // use temp store so mulitple calls will work (the Store is not finalized this way)
        let mut temp_store = Store::from_jumbf(&jumbf, &mut validation_log)?;

        let jumbf_bytes = temp_store.start_save_bmff_fragmented(
            asset_path,
            fragments,
            output_path,
            signer.reserve_size(),
        )?;

        let pc = temp_store.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = temp_store.sign_claim(pc, signer, signer.reserve_size())?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        let output_filename = asset_path.file_name().ok_or(Error::NotFound)?;
        let dest_path = output_path.join(output_filename);

        match temp_store.finish_save(jumbf_bytes, &dest_path, sig, &sig_placeholder) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Embed the claims store as jumbf into a stream. Updates XMP with provenance record.
    /// When called, the stream should contain an asset matching format.
    /// on return, the stream will contain the new manifest signed with signer
    /// This directly modifies the asset in stream, backup stream first if you need to preserve it.
    /// This can also handle remote signing if direct_cose_handling() is true.
    #[async_generic(async_signature(
        &mut self,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn AsyncSigner,
    ))]
    pub fn save_to_stream(
        &mut self,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let intermediate_output: Vec<u8> = Vec::new();
        let mut intermediate_stream = Cursor::new(intermediate_output);

        let jumbf_bytes = self.start_save_stream(
            format,
            input_stream,
            &mut intermediate_stream,
            signer.reserve_size(),
        )?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = if _sync {
            self.sign_claim(pc, signer, signer.reserve_size())
        } else {
            self.sign_claim_async(pc, signer, signer.reserve_size())
                .await
        }?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        intermediate_stream.rewind()?;
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

                Ok(m)
            }
            Err(e) => Err(e),
        }
    }

    /// This function is used to pre-generate a manifest as if it were added to input_stream. All values
    /// are complete including the hash bindings, except for the signature.  The signature is completed during
    /// the actual embedding using `embed_placed_manifest `.   The Signature box reserve_size is based on the size required by
    /// the Signer you plan to use.  This function is not needed when using Box Hash. This function is used
    /// in conjunction with `embed_placed_manifest`.  `embed_placed_manifest` will accept the manifest to sign and place
    /// in the output.
    pub fn get_placed_manifest(
        &mut self,
        reserve_size: usize,
        format: &str,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<u8>> {
        let intermediate_output: Vec<u8> = Vec::new();
        let mut intermediate_stream = Cursor::new(intermediate_output);

        self.start_save_stream(format, input_stream, &mut intermediate_stream, reserve_size)
    }

    /// Embed the manifest store into an asset. If a ManifestPatchCallback is present the caller
    /// is given an opportunity to adjust most assertions.  This function will not generate hash
    /// binding for the manifest.  It is assumed the user called get_box_hashed_embeddable_manifest
    /// hash or provided a box hash binding.  The input stream should reference the same content used
    /// in the 'get_placed_manifest_call'.  Changes to the following assertions are disallowed
    /// when using 'ManifestPatchCallback':  ["c2pa.hash.data",  "c2pa.hash.boxes",  "c2pa.hash.bmff",
    ///  "c2pa.actions",  "c2pa.ingredient"].  Also the set of assertions cannot be changed, only the
    /// content of allowed assertions can be modified.  
    /// 'format' shoould match the type of the input stream..
    /// Upon return, the output stream will contain the new manifest signed with signer
    /// This directly modifies the asset in stream, backup stream first if you need to preserve it.

    #[async_generic(
        async_signature(
            manifest_bytes: &[u8],
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn AsyncSigner,
        manifest_callbacks: &[Box<dyn ManifestPatchCallback>],
        ))]
    pub fn embed_placed_manifest(
        manifest_bytes: &[u8],
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        signer: &dyn Signer,
        manifest_callbacks: &[Box<dyn ManifestPatchCallback>],
    ) -> Result<Vec<u8>> {
        // todo: Consider how we would add XMP for this case

        let disallowed_assertions = [
            labels::DATA_HASH,
            labels::BOX_HASH,
            labels::BMFF_HASH,
            labels::ACTIONS,
            labels::INGREDIENT,
        ];

        let mut validation_log = DetailedStatusTracker::new();
        let mut store = Store::from_jumbf(manifest_bytes, &mut validation_log)?;

        // todo: what kinds of validation can we do here since the file is not finailized;

        let pc_mut = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // save the current assertions set so that we can check them after callback;
        let claim_assertions = pc_mut.claim_assertion_store().clone();

        let manifest_bytes_updated = if !manifest_callbacks.is_empty() {
            let mut updated = manifest_bytes.to_vec();

            // callback to all patch functions
            for mpc in manifest_callbacks {
                updated = mpc.patch_manifest(&updated)?;
            }

            // make sure the size is correct
            if updated.len() != manifest_bytes.len() {
                return Err(Error::OtherError("patched manifest size incorrect".into()));
            }

            // make sure we can load the patched manifest
            let new_store = Store::from_jumbf(&updated, &mut validation_log)?;

            let new_pc = new_store.provenance_claim().ok_or(Error::ClaimEncoding)?;

            // make sure the claim has not changed
            if !vec_compare(&pc_mut.data()?, &new_pc.data()?) {
                return Err(Error::OtherError(
                    "patched manifest changed the Claim structure".into(),
                ));
            }

            // check that other manifests have not changed
            // check expected ingredients against those in the new updated store
            for i in pc_mut.ingredient_assertions() {
                let ingredient_assertion = Ingredient::from_assertion(i)?;

                // is this an ingredient
                if let Some(ref c2pa_manifest) = &ingredient_assertion.c2pa_manifest {
                    let label = Store::manifest_label_from_path(&c2pa_manifest.url());

                    if let Some(ingredient) = new_store.get_claim(&label) {
                        let alg = match c2pa_manifest.alg() {
                            Some(a) => a,
                            None => ingredient.alg().to_owned(),
                        };

                        // get the 1.1-1.2 box hash
                        let box_hash = new_store.get_manifest_box_hash(&ingredient.clone());

                        // test for 1.1 hash then 1.0 version
                        if !vec_compare(&c2pa_manifest.hash(), &box_hash)
                            && !verify_by_alg(
                                &alg,
                                &c2pa_manifest.hash(),
                                &ingredient.data()?,
                                None,
                            )
                        {
                            let log_item = log_item!(
                                &c2pa_manifest.url(),
                                "ingredient hash incorrect",
                                "embed_placed_manifest"
                            )
                            .error(Error::HashMismatch(
                                "ingredient hash does not match found ingredient".to_string(),
                            ))
                            .validation_status(validation_status::INGREDIENT_HASHEDURI_MISMATCH);
                            validation_log.log(
                                log_item,
                                Some(Error::HashMismatch(
                                    "ingredient hash does not match found ingredient".to_string(),
                                )),
                            )?;
                        }
                    }
                }
            }

            // check to make sure assertion changes are OK and nothing else changed.
            if claim_assertions.len() != new_pc.claim_assertion_store().len() {
                return Err(Error::OtherError(
                    "patched manifest assertion list has changed".into(),
                ));
            }

            // get the list of assertions that need patching
            for ca in claim_assertions {
                if let Some(updated_ca) = new_pc.get_claim_assertion(&ca.label_raw(), ca.instance())
                {
                    // if hashes are different then this assertion has changed so attempt fixup
                    if !vec_compare(ca.hash(), updated_ca.hash()) {
                        if disallowed_assertions
                            .iter()
                            .any(|&l| l == updated_ca.label_raw())
                        {
                            return Err(Error::OtherError(
                                "patched manifest changed a disallowed assertion".into(),
                            ));
                        }

                        // update original
                        pc_mut.update_assertion(
                            updated_ca.assertion().clone(),
                            |_: &ClaimAssertion| true,
                            |target_assertion: &ClaimAssertion, a: Assertion| {
                                if target_assertion.assertion().data().len() == a.data().len() {
                                    Ok(a)
                                } else {
                                    Err(Error::OtherError(
                                        "patched manifest assertion size differ in size".into(),
                                    ))
                                }
                            },
                        )?;
                    }
                } else {
                    return Err(Error::OtherError(
                        "patched manifest assertion list has changed".into(),
                    ));
                }
            }

            store.to_jumbf_internal(signer.reserve_size())?
        } else {
            manifest_bytes.to_vec()
        };

        // sign the updated manfiest
        let pc = store.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = if _sync {
            store.sign_claim(pc, signer, signer.reserve_size())?
        } else {
            store
                .sign_claim_async(pc, signer, signer.reserve_size())
                .await?
        };
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        match store.finish_save_stream(
            manifest_bytes_updated,
            format,
            input_stream,
            output_stream,
            sig,
            &sig_placeholder,
        ) {
            Ok((_, m)) => Ok(m),
            Err(e) => Err(e),
        }
    }

    /// Async RemoteSigner used to embed the claims store and  returns memory representation of the
    /// asset and manifest. Updates XMP with provenance record.
    /// When called, the stream should contain an asset matching format.
    /// Returns a tuple (output asset, manifest store) with a `Vec<u8>` containing the output asset and a `Vec<u8>` containing the insert manifest store.  (output asset, )
    pub(crate) async fn save_to_memory_remote_signed(
        &mut self,
        format: &str,
        asset: &[u8],
        remote_signer: &dyn crate::signer::RemoteSigner,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut input_stream = Cursor::new(asset);
        let output_vec: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_vec);

        let jumbf_bytes = self.start_save_stream(
            format,
            &mut input_stream,
            &mut output_stream,
            remote_signer.reserve_size(),
        )?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = remote_signer.sign_remote(&pc.data()?).await?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, remote_signer.reserve_size());

        match self.finish_save_to_memory(
            jumbf_bytes,
            format,
            &output_stream.into_inner(),
            sig,
            &sig_placeholder,
        ) {
            Ok((s, output_asset, output_jumbf)) => {
                // save sig so store is up to date
                let pc_mut = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc_mut.set_signature_val(s);

                Ok((output_asset, output_jumbf))
            }
            Err(e) => Err(e),
        }
    }

    /// Embed the claims store as jumbf into an asset. Updates XMP with provenance record.
    #[cfg(feature = "file_io")]
    pub fn save_to_asset(
        &mut self,
        asset_path: &Path,
        signer: &dyn Signer,
        dest_path: &Path,
    ) -> Result<Vec<u8>> {
        // set up temp dir, contents auto deleted
        let td = tempfile::TempDir::new()?;
        let temp_path = td.path();
        let temp_file = temp_path.join(
            dest_path
                .file_name()
                .ok_or_else(|| Error::BadParam("invalid destination path".to_string()))?,
        );

        let jumbf_bytes = self.start_save(asset_path, &temp_file, signer.reserve_size())?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self.sign_claim(pc, signer, signer.reserve_size())?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        // get correct output path for remote manifest
        let output_path = match pc.remote_manifest() {
            RemoteManifest::NoRemote | RemoteManifest::EmbedWithRemote(_) => {
                temp_file.to_path_buf()
            }
            RemoteManifest::SideCar | RemoteManifest::Remote(_) => {
                temp_file.with_extension(MANIFEST_STORE_EXT)
            }
        };

        match self.finish_save(jumbf_bytes, &output_path, sig, &sig_placeholder) {
            Ok((s, m)) => {
                // save sig so store is up to date
                let pc_mut = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc_mut.set_signature_val(s);

                // do we need to make a C2PA file in addition to standard embedded output
                if let RemoteManifest::EmbedWithRemote(_url) = pc_mut.remote_manifest() {
                    let c2pa = output_path.with_extension(MANIFEST_STORE_EXT);
                    std::fs::write(c2pa, &m)?;
                }

                // copy the correct files upon completion
                Store::copy_c2pa_to_output(&temp_file, dest_path, pc_mut.remote_manifest())?;

                Ok(m)
            }
            Err(e) => Err(e),
        }
    }

    /// Embed the claims store as jumbf into an asset using an async signer. Updates XMP with provenance record.
    #[cfg(feature = "file_io")]
    pub async fn save_to_asset_async(
        &mut self,
        asset_path: &Path,
        signer: &dyn AsyncSigner,
        dest_path: &Path,
    ) -> Result<Vec<u8>> {
        // set up temp dir, contents auto deleted
        let td = tempfile::TempDir::new()?;
        let temp_path = td.path();
        let temp_file = temp_path.join(
            dest_path
                .file_name()
                .ok_or_else(|| Error::BadParam("invalid destination path".to_string()))?,
        );

        let jumbf_bytes = self.start_save(asset_path, &temp_file, signer.reserve_size())?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self
            .sign_claim_async(pc, signer, signer.reserve_size())
            .await?;
        let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());

        // get correct output path for remote manifest
        let output_path = match pc.remote_manifest() {
            RemoteManifest::NoRemote | RemoteManifest::EmbedWithRemote(_) => {
                temp_file.to_path_buf()
            }
            RemoteManifest::SideCar | RemoteManifest::Remote(_) => {
                temp_file.with_extension(MANIFEST_STORE_EXT)
            }
        };

        match self.finish_save(jumbf_bytes, &output_path, sig, &sig_placeholder) {
            Ok((s, m)) => {
                // save sig so store is up to date
                let pc_mut = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc_mut.set_signature_val(s);

                // do we need to make a C2PA file in addition to standard embedded output
                if let RemoteManifest::EmbedWithRemote(_url) = pc_mut.remote_manifest() {
                    let c2pa = output_path.with_extension(MANIFEST_STORE_EXT);
                    std::fs::write(c2pa, &m)?;
                }

                // copy the correct files upon completion
                Store::copy_c2pa_to_output(&temp_file, dest_path, pc_mut.remote_manifest())?;

                Ok(m)
            }
            Err(e) => Err(e),
        }
    }

    /// Embed the claims store as jumbf into an asset using an CoseSign box generated remotely. Updates XMP with provenance record.
    #[cfg(feature = "file_io")]
    pub async fn save_to_asset_remote_signed(
        &mut self,
        asset_path: &Path,
        remote_signer: &dyn crate::signer::RemoteSigner,
        dest_path: &Path,
    ) -> Result<Vec<u8>> {
        // set up temp dir, contents auto deleted
        let td = tempfile::TempDir::new()?;
        let temp_path = td.path();
        let temp_file = temp_path.join(
            dest_path
                .file_name()
                .ok_or_else(|| Error::BadParam("invalid destination path".to_string()))?,
        );

        let jumbf_bytes = self.start_save(asset_path, &temp_file, remote_signer.reserve_size())?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = remote_signer.sign_remote(&pc.data()?).await?;

        let sig_placeholder = Store::sign_claim_placeholder(pc, remote_signer.reserve_size());

        // get correct output path for remote manifest
        let output_path = match pc.remote_manifest() {
            RemoteManifest::NoRemote | RemoteManifest::EmbedWithRemote(_) => {
                temp_file.to_path_buf()
            }
            RemoteManifest::SideCar | RemoteManifest::Remote(_) => {
                temp_file.with_extension(MANIFEST_STORE_EXT)
            }
        };

        match self.finish_save(jumbf_bytes, &output_path, sig, &sig_placeholder) {
            Ok((s, m)) => {
                // save sig so store is up to date
                let pc_mut = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc_mut.set_signature_val(s);

                // do we need to make a C2PA file in addition to standard embedded output
                if let RemoteManifest::EmbedWithRemote(_url) = pc_mut.remote_manifest() {
                    let c2pa = output_path.with_extension(MANIFEST_STORE_EXT);
                    std::fs::write(c2pa, &m)?;
                }

                // copy the correct files upon completion
                Store::copy_c2pa_to_output(&temp_file, dest_path, pc_mut.remote_manifest())?;

                Ok(m)
            }
            Err(e) => Err(e),
        }
    }

    fn start_save_stream(
        &mut self,
        format: &str,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        reserve_size: usize,
    ) -> Result<Vec<u8>> {
        let intermediate_output: Vec<u8> = Vec::new();
        let mut intermediate_stream = Cursor::new(intermediate_output);

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

                let tmp_output: Vec<u8> = Vec::new();
                let mut tmp_stream = Cursor::new(tmp_output);
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
            if !pc.update_manifest() {
                intermediate_stream.rewind()?;
                let bmff_hash = Store::generate_bmff_data_hash_for_stream(
                    &mut intermediate_stream,
                    pc.alg(),
                    false,
                    false,
                )?;
                pc.add_assertion(&bmff_hash)?;
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

            // generate actual hash values
            let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?; // reborrow to change mutability

            if !pc.update_manifest() {
                let bmff_hashes = pc.bmff_hash_assertions();

                if !bmff_hashes.is_empty() {
                    let mut bmff_hash = BmffHash::from_assertion(bmff_hashes[0])?;
                    output_stream.rewind()?;
                    bmff_hash.gen_hash_from_stream(output_stream)?;
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

            // 4)  determine final object locations and patch the asset hashes with correct offset
            // replace the source with correct asset hashes so that the claim hash will be correct
            if needs_hashing {
                let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

                // get the final hash ranges, but not for update manifests
                output_stream.rewind()?;
                let mut new_hash_ranges = object_locations_from_stream(format, output_stream)?;
                if !pc.update_manifest() {
                    let updated_hashes = Store::generate_data_hashes_for_stream(
                        output_stream,
                        pc.alg(),
                        &mut new_hash_ranges,
                        true,
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

        Ok((sig, jumbf_bytes))
    }

    fn finish_save_to_memory(
        &self,
        mut jumbf_bytes: Vec<u8>,
        format: &str,
        source_asset: &[u8],
        sig: Vec<u8>,
        sig_placeholder: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        // return sig and output
        Ok((
            sig,
            save_jumbf_to_memory(format, source_asset, &jumbf_bytes)?,
            jumbf_bytes,
        ))
    }

    #[cfg(feature = "file_io")]
    fn start_save(
        &mut self,
        asset_path: &Path,
        dest_path: &Path,
        reserve_size: usize,
    ) -> Result<Vec<u8>> {
        // force generate external manifests for unknown types

        let ext = match get_supported_file_extension(dest_path) {
            Some(ext) => ext,
            None => {
                let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc.set_external_manifest(); // generate external manifests for unknown types
                MANIFEST_STORE_EXT.to_owned()
            }
        };

        // clone the source to working copy if requested
        if asset_path != dest_path {
            fs::copy(asset_path, dest_path).map_err(Error::IoError)?;
        }

        //  update file following the steps outlined in CAI spec

        // 1) Add DC provenance XMP
        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let output_path = match pc.remote_manifest() {
            crate::claim::RemoteManifest::NoRemote => dest_path.to_path_buf(),
            crate::claim::RemoteManifest::SideCar => {
                // remove any previous c2pa manifest from the asset
                match remove_jumbf_from_file(dest_path) {
                    Ok(_) | Err(Error::UnsupportedType) => {
                        dest_path.with_extension(MANIFEST_STORE_EXT)
                    }
                    Err(e) => return Err(e),
                }
            }
            crate::claim::RemoteManifest::Remote(url) => {
                let d = dest_path.with_extension(MANIFEST_STORE_EXT);
                // remove any previous c2pa manifest from the asset
                remove_jumbf_from_file(dest_path)?;

                if let Some(h) = get_assetio_handler(&ext) {
                    if let Some(external_ref_writer) = h.remote_ref_writer_ref() {
                        external_ref_writer
                            .embed_reference(dest_path, RemoteRefEmbedType::Xmp(url))?;
                    } else {
                        return Err(Error::XmpNotSupported);
                    }
                } else {
                    return Err(Error::UnsupportedType);
                }

                d
            }
            crate::claim::RemoteManifest::EmbedWithRemote(url) => {
                if let Some(h) = get_assetio_handler(&ext) {
                    if let Some(external_ref_writer) = h.remote_ref_writer_ref() {
                        external_ref_writer
                            .embed_reference(dest_path, RemoteRefEmbedType::Xmp(url))?;
                    } else {
                        return Err(Error::XmpNotSupported);
                    }
                } else {
                    return Err(Error::UnsupportedType);
                }
                dest_path.to_path_buf()
            }
        };

        // get the provenance claim changing mutability
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        let is_bmff = is_bmff_format(&ext);

        let mut data;
        let jumbf_size;

        if is_bmff {
            // 2) Get hash ranges if needed, do not generate for update manifests
            if !pc.update_manifest() {
                let mut file = std::fs::File::open(asset_path)?;
                let bmff_hash =
                    Store::generate_bmff_data_hash_for_stream(&mut file, pc.alg(), false, false)?;
                pc.add_assertion(&bmff_hash)?;
            }

            // 3) Generate in memory CAI jumbf block
            // and write preliminary jumbf store to file
            // source and dest the same so save_jumbf_to_file will use the same file since we have already cloned
            data = self.to_jumbf_internal(reserve_size)?;
            jumbf_size = data.len();
            save_jumbf_to_file(&data, &output_path, Some(dest_path))?;

            // generate actual hash values
            let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?; // reborrow to change mutability

            if !pc.update_manifest() {
                let bmff_hashes = pc.bmff_hash_assertions();

                if !bmff_hashes.is_empty() {
                    let mut bmff_hash = BmffHash::from_assertion(bmff_hashes[0])?;
                    bmff_hash.gen_hash(dest_path)?;
                    pc.update_bmff_hash(bmff_hash)?;
                }
            }
        } else {
            // we will not do automatic hashing if we detect a box hash present
            let mut needs_hashing = false;
            if pc.box_hash_assertions().is_empty() {
                // 2) Get hash ranges if needed, do not generate for update manifests
                let mut hash_ranges = object_locations(&output_path)?;
                let hashes: Vec<DataHash> = if pc.update_manifest() {
                    Vec::new()
                } else {
                    Store::generate_data_hashes(dest_path, pc.alg(), &mut hash_ranges, false)?
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
            // and write preliminary jumbf store to file
            // source and dest the same so save_jumbf_to_file will use the same file since we have already cloned
            data = self.to_jumbf_internal(reserve_size)?;
            jumbf_size = data.len();
            save_jumbf_to_file(&data, &output_path, Some(&output_path))?;

            // 4)  determine final object locations and patch the asset hashes with correct offset
            // replace the source with correct asset hashes so that the claim hash will be correct
            // If box hash is present we don't do any other
            if needs_hashing {
                let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

                // get the final hash ranges, but not for update manifests
                let mut new_hash_ranges = object_locations(&output_path)?;
                let updated_hashes = if pc.update_manifest() {
                    Vec::new()
                } else {
                    Store::generate_data_hashes(dest_path, pc.alg(), &mut new_hash_ranges, true)?
                };

                // patch existing claim hash with updated data
                for hash in updated_hashes {
                    pc.update_data_hash(hash)?;
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
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        Store::verify_store(self, &mut ClaimAssetData::Path(asset_path), validation_log)
    }

    // verify from a buffer without file i/o
    pub fn verify_from_buffer(
        &mut self,
        buf: &[u8],
        asset_type: &str,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        Store::verify_store(
            self,
            &mut ClaimAssetData::Bytes(buf, asset_type),
            validation_log,
        )
    }

    // verify from a buffer without file i/o
    #[async_generic()]
    pub fn verify_from_stream(
        &mut self,
        reader: &mut dyn CAIRead,
        asset_type: &str,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        if _sync {
            Store::verify_store(
                self,
                &mut ClaimAssetData::Stream(reader, asset_type),
                validation_log,
            )
        } else {
            Store::verify_store_async(
                self,
                &mut ClaimAssetData::Stream(reader, asset_type),
                validation_log,
            )
            .await
        }
    }

    // fetch remote manifest if possible
    #[cfg(feature = "fetch_remote_manifests")]
    fn fetch_remote_manifest(url: &str) -> Result<Vec<u8>> {
        use conv::ValueFrom;
        use ureq::Error as uError;

        //const MANIFEST_CONTENT_TYPE: &str = "application/x-c2pa-manifest-store"; // todo verify once these are served
        const DEFAULT_MANIFEST_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

        match ureq::get(url).call() {
            Ok(response) => {
                if response.status() == 200 {
                    let len = response
                        .header("Content-Length")
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(DEFAULT_MANIFEST_RESPONSE_SIZE); // todo figure out good max to accept

                    let mut response_bytes: Vec<u8> = Vec::with_capacity(len);

                    let len64 = u64::value_from(len)
                        .map_err(|_err| Error::BadParam("value out of range".to_string()))?;

                    response
                        .into_reader()
                        .take(len64)
                        .read_to_end(&mut response_bytes)
                        .map_err(|_err| {
                            Error::RemoteManifestFetch("error reading content stream".to_string())
                        })?;

                    Ok(response_bytes)
                } else {
                    Err(Error::RemoteManifestFetch(format!(
                        "fetch failed: code: {}, status: {}",
                        response.status(),
                        response.status_text()
                    )))
                }
            }
            Err(uError::Status(code, resp)) => Err(Error::RemoteManifestFetch(format!(
                "code: {}, response: {}",
                code,
                resp.status_text()
            ))),
            Err(uError::Transport(_)) => Err(Error::RemoteManifestFetch(url.to_string())),
        }
    }

    /// Handles remote manifests when file_io/fetch_remote_manifests feature is enabled
    fn handle_remote_manifest(ext_ref: &str) -> Result<Vec<u8>> {
        // verify provenance path is remote url
        if Store::is_valid_remote_url(ext_ref) {
            #[cfg(feature = "fetch_remote_manifests")]
            {
                Store::fetch_remote_manifest(ext_ref)
            }
            #[cfg(not(feature = "fetch_remote_manifests"))]
            Err(Error::RemoteManifestUrl(ext_ref.to_owned()))
        } else {
            Err(Error::JumbfNotFound)
        }
    }

    /// Return Store from in memory asset
    fn load_cai_from_memory(
        asset_type: &str,
        data: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        let mut input_stream = Cursor::new(data);
        Store::load_jumbf_from_stream(asset_type, &mut input_stream)
            .map(|manifest_bytes| Store::from_jumbf(&manifest_bytes, validation_log))?
    }

    /// load jumbf given a stream
    ///
    /// This handles, embedded and remote manifests
    ///
    /// asset_type -  mime type of the stream
    /// stream - a readable stream of an asset
    pub fn load_jumbf_from_stream(asset_type: &str, stream: &mut dyn CAIRead) -> Result<Vec<u8>> {
        match load_jumbf_from_stream(asset_type, stream) {
            Ok(manifest_bytes) => Ok(manifest_bytes),
            Err(Error::JumbfNotFound) => {
                stream.rewind()?;
                if let Some(ext_ref) =
                    crate::utils::xmp_inmemory_utils::XmpInfo::from_source(stream, asset_type)
                        .provenance
                {
                    Store::handle_remote_manifest(&ext_ref)
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
    pub fn load_jumbf_from_path(in_path: &Path) -> Result<Vec<u8>> {
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
                        Store::handle_remote_manifest(&ext_ref)
                    } else {
                        Err(Error::JumbfNotFound)
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// load a CAI store from  a file
    ///
    /// in_path -  path to source file
    /// validation_log - optional vec to contain addition info about the asset
    #[cfg(feature = "file_io")]
    fn load_cai_from_file(
        in_path: &Path,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        match Self::load_jumbf_from_path(in_path) {
            Ok(manifest_bytes) => {
                // load and validate with CAI toolkit
                Store::from_jumbf(&manifest_bytes, validation_log)
            }
            Err(e) => Err(e),
        }
    }

    /// Load Store from claims in an existing asset
    /// asset_path: path to input asset
    /// verify: determines whether to verify the contents of the provenance claim.  Must be set true to use validation_log
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned  
    #[cfg(feature = "file_io")]
    pub fn load_from_asset(
        asset_path: &Path,
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        // load jumbf if available
        Self::load_cai_from_file(asset_path, validation_log)
            .and_then(|mut store| {
                // verify the store
                if verify {
                    store.verify_from_path(asset_path, validation_log)?;
                }

                Ok(store)
            })
            .inspect_err(|e| {
                validation_log.log_silent(
                    log_item!("asset", "error loading file", "load_from_asset").set_error(e),
                );
            })
    }

    pub fn get_store_from_memory(
        asset_type: &str,
        data: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        // load jumbf if available
        Self::load_cai_from_memory(asset_type, data, validation_log).inspect_err(|e| {
            validation_log.log_silent(
                log_item!("asset", "error loading asset", "get_store_from_memory").set_error(e),
            );
        })
    }

    /// Returns embedded remote manifest URL if available
    /// asset_type: extensions or mime type of the data
    /// data: byte array containing the asset
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

    /// check the input url to see if it is a supported remotes URI
    pub fn is_valid_remote_url(url: &str) -> bool {
        match url::Url::parse(url) {
            Ok(u) => u.scheme() == "http" || u.scheme() == "https",
            Err(_) => false,
        }
    }

    /// Load Store from a in-memory asset
    /// asset_type: asset extension or mime type
    /// data: reference to bytes of the the file
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned
    pub fn load_from_memory(
        asset_type: &str,
        data: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        Store::get_store_from_memory(asset_type, data, validation_log).and_then(|store| {
            // verify the store
            if verify {
                // verify store and claims
                Store::verify_store(
                    &store,
                    &mut ClaimAssetData::Bytes(data, asset_type),
                    validation_log,
                )?;
            }

            Ok(store)
        })
    }

    /// Load Store from a in-memory asset asynchronously validating
    /// asset_type: asset extension or mime type
    /// data: reference to bytes of the file
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned
    pub async fn load_from_memory_async(
        asset_type: &str,
        data: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        let store = Store::get_store_from_memory(asset_type, data, validation_log)?;

        // verify the store
        if verify {
            // verify store and claims
            Store::verify_store_async(
                &store,
                &mut ClaimAssetData::Bytes(data, asset_type),
                validation_log,
            )
            .await?;
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
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        let mut init_seg_data = Vec::new();
        init_segment.read_to_end(&mut init_seg_data)?;

        Store::get_store_from_memory(asset_type, &init_seg_data, validation_log).and_then(|store| {
            // verify the store
            if verify {
                // verify store and claims
                Store::verify_store(
                    &store,
                    &mut ClaimAssetData::StreamFragments(init_segment, fragments, asset_type),
                    validation_log,
                )?;
            }

            Ok(store)
        })
    }

    /// Load Store from a in-memory asset
    /// asset_type: asset extension or mime type
    /// data: reference to bytes of the the file
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned
    pub fn load_fragment_from_memory(
        asset_type: &str,
        init_segment: &[u8],
        fragment: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        Store::get_store_from_memory(asset_type, init_segment, validation_log).and_then(|store| {
            // verify the store
            if verify {
                let mut init_segment_stream = Cursor::new(init_segment);
                let mut fragment_stream = Cursor::new(fragment);

                // verify store and claims
                Store::verify_store(
                    &store,
                    &mut ClaimAssetData::StreamFragment(
                        &mut init_segment_stream,
                        &mut fragment_stream,
                        asset_type,
                    ),
                    validation_log,
                )?;
            }

            Ok(store)
        })
    }

    /// Load Store from a in-memory asset asynchronously validating
    /// asset_type: asset extension or mime type
    /// init_segment: reference to bytes of the init segment
    /// fragment: reference to bytes of the fragment to validate
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned
    pub async fn load_fragment_from_memory_async(
        asset_type: &str,
        init_segment: &[u8],
        fragment: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        let store = Store::get_store_from_memory(asset_type, init_segment, validation_log)?;

        // verify the store
        if verify {
            let mut init_segment_stream = Cursor::new(init_segment);
            let mut fragment_stream = Cursor::new(fragment);

            // verify store and claims
            Store::verify_store_async(
                &store,
                &mut ClaimAssetData::StreamFragment(
                    &mut init_segment_stream,
                    &mut fragment_stream,
                    asset_type,
                ),
                validation_log,
            )
            .await?;
        }

        Ok(store)
    }

    /// Load Store from memory and add its content as a claim ingredient
    /// claim: claim to add an ingredient
    /// provenance_label: label of the provenance claim used as key into ingredient map
    /// data: jumbf data block
    pub fn load_ingredient_to_claim(
        claim: &mut Claim,
        provenance_label: &str,
        data: &[u8],
        redactions: Option<Vec<String>>,
    ) -> Result<Store> {
        let mut report = OneShotStatusTracker::new();
        let store = Store::from_jumbf(data, &mut report)?;
        claim.add_ingredient_data(provenance_label, store.claims.clone(), redactions)?;
        Ok(store)
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

    /// The assertion store does not contain the expected number of assertions.
    #[error(
        "unexpected number of assertions in assertion store (expected {expected}, found {found})"
    )]
    AssertionCountMismatch { expected: usize, found: usize },
}

#[cfg(test)]
#[cfg(feature = "file_io")]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Write;

    use memchr::memmem;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::*;
    use crate::{
        assertion::AssertionJson,
        assertions::{labels::BOX_HASH, Action, Actions, BoxHash, Uuid},
        claim::AssertionStoreJsonFormat,
        hashed_uri::HashedUri,
        jumbf_io::{get_assetio_handler_from_path, update_file_jumbf},
        status_tracker::*,
        utils::{
            hash_utils::Hasher,
            patch::patch_file,
            test::{
                create_test_claim, fixture_path, temp_dir_path, temp_fixture_path, temp_signer,
                write_jpeg_placeholder_file,
            },
        },
        SigningAlg,
    };

    fn create_editing_claim(claim: &mut Claim) -> Result<&mut Claim> {
        let uuid_str = "deadbeefdeadbeefdeadbeefdeadbeef";

        // add a binary thumbnail assertion  ('deadbeefadbeadbe')
        let some_binary_data: Vec<u8> = vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ];

        let uuid_assertion = Uuid::new("test uuid", uuid_str.to_string(), some_binary_data);

        claim.add_assertion(&uuid_assertion)?;

        Ok(claim)
    }

    fn create_capture_claim(claim: &mut Claim) -> Result<&mut Claim> {
        let actions = Actions::new().add_action(Action::new("c2pa.created"));

        claim.add_assertion(&actions)?;

        Ok(claim)
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_jumbf_generation() {
        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "test-image.jpg");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"));
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Test generate JUMBF
        // Get labels for label test
        let claim1_label = claim1.label().to_string();
        let capture = claim_capture.label().to_string();
        let claim2_label = claim2.label().to_string();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

        // test finding claims by label
        let c1 = store.get_claim(&claim1_label);
        let c2 = store.get_claim(&capture);
        let c3 = store.get_claim(&claim2_label);
        assert_eq!(&claim1_label, c1.unwrap().label());
        assert_eq!(&capture, c2.unwrap().label());
        assert_eq!(claim2_label, c3.unwrap().label());

        // write to new file
        println!("Provenance: {}\n", store.provenance_path().unwrap());

        // read from new file
        let new_store =
            Store::load_from_asset(&op, true, &mut OneShotStatusTracker::new()).unwrap();

        // can  we get by the ingredient data back
        let _some_binary_data: Vec<u8> = vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ];

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            // these better match
            //assert_eq!(orig_json, restored_json);
            //assert_eq!(claim.hash(), store.claims()[idx].hash());

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim.get_claim_assertion(&label, instance).unwrap();
            }
        }

        // test patch file - bytes should be same so error should not be detected
        let mut splice_point =
            patch_file(&op, "thumbnail".as_bytes(), "testme".as_bytes()).unwrap();

        let mut restore_point =
            patch_file(&op, "testme".as_bytes(), "thumbnail".as_bytes()).unwrap();

        assert_eq!(splice_point, restore_point);

        Store::load_from_asset(&op, true, &mut OneShotStatusTracker::new())
            .expect("Should still verify");

        // test patching jumbf - error should be detected

        splice_point = update_file_jumbf(&op, "thumbnail".as_bytes(), "testme".as_bytes()).unwrap();
        restore_point =
            update_file_jumbf(&op, "testme".as_bytes(), "thumbnail.v1".as_bytes()).unwrap();

        assert_eq!(splice_point, restore_point);

        Store::load_from_asset(&op, true, &mut OneShotStatusTracker::new())
            .expect_err("Should not verify");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_unknown_asset_type_generation() {
        // test adding to actual image
        let ap = fixture_path("unsupported_type.txt");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "unsupported_type.txt");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"));
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        // read from new file
        let new_store =
            Store::load_from_asset(&op, true, &mut OneShotStatusTracker::new()).unwrap();

        // can  we get by the ingredient data back

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim.get_claim_assertion(&label, instance).unwrap();
            }
        }
    }

    struct BadSigner {}

    impl crate::Signer for BadSigner {
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
            Ok(b"not a valid signature".to_vec())
        }

        fn alg(&self) -> SigningAlg {
            SigningAlg::Ps256
        }

        fn certs(&self) -> Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }

        fn reserve_size(&self) -> usize {
            42
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_detects_unverifiable_signature() {
        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "test-image-unverified.jpg");

        let mut store = Store::new();

        let claim = create_test_claim().unwrap();

        let signer = BadSigner {};

        // JUMBF generation should fail because this signature won't validate.
        store.commit_claim(claim).unwrap();

        // TO DO: This generates a log spew when running this test.
        // I don't have time to fix this right now.
        // [(date) ERROR c2pa::store] Signature that was just generated does not validate: CoseCbor

        store.save_to_asset(&ap, &signer, &op).unwrap_err();
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_sign_with_expired_cert() {
        use crate::{openssl::RsaSigner, signer::ConfigurableSigner, SigningAlg};

        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "test-image-expired-cert.jpg");

        let mut store = Store::new();

        let claim = create_test_claim().unwrap();

        let signcert_path = fixture_path("rsa-pss256_key-expired.pub");
        let pkey_path = fixture_path("rsa-pss256-expired.pem");
        let signer =
            RsaSigner::from_files(signcert_path, pkey_path, SigningAlg::Ps256, None).unwrap();

        store.commit_claim(claim).unwrap();

        let r = store.save_to_asset(&ap, &signer, &op);
        assert!(r.is_err());
        assert_eq!(r.err().unwrap().to_string(), "COSE certificate has expired");
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_jumbf_replacement_generation() {
        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();
        store.commit_claim(claim1).unwrap();

        // do we generate JUMBF
        let jumbf_bytes = store.to_jumbf_internal(512).unwrap();
        assert!(!jumbf_bytes.is_empty());

        // test adding to actual image
        let ap = fixture_path("prerelease.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "replacement_test.jpg");

        // grab jumbf from original
        let original_jumbf = load_jumbf_from_file(&ap).unwrap();

        // replace with new jumbf
        save_jumbf_to_file(&jumbf_bytes, &ap, Some(&op)).unwrap();

        let saved_jumbf = load_jumbf_from_file(&op).unwrap();

        // saved data should be the new data
        assert_eq!(&jumbf_bytes, &saved_jumbf);

        // original data should not be in file anymore check for first 1k
        let buf = fs::read(&op).unwrap();
        assert!(memmem::find(&buf, &original_jumbf[0..1024]).is_none());
    }

    #[actix::test]
    async fn test_jumbf_generation_async() {
        let signer = crate::openssl::temp_signer_async::AsyncSignerAdapter::new(SigningAlg::Ps256);

        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "test-async.jpg");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"));
        create_capture_claim(&mut claim_capture).unwrap();

        // Test generate JUMBF
        // Get labels for label test
        let claim1_label = claim1.label().to_string();
        let capture = claim_capture.label().to_string();
        let claim2_label = claim2.label().to_string();

        store.commit_claim(claim1).unwrap();
        store.save_to_asset_async(&ap, &signer, &op).await.unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset_async(&ap, &signer, &op).await.unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset_async(&ap, &signer, &op).await.unwrap();

        // test finding claims by label
        let c1 = store.get_claim(&claim1_label);
        let c2 = store.get_claim(&capture);
        let c3 = store.get_claim(&claim2_label);
        assert_eq!(&claim1_label, c1.unwrap().label());
        assert_eq!(&capture, c2.unwrap().label());
        assert_eq!(claim2_label, c3.unwrap().label());

        // Do we generate JUMBF
        let jumbf_bytes = store.to_jumbf_async(&signer).unwrap();
        assert!(!jumbf_bytes.is_empty());

        // write to new file
        println!("Provenance: {}\n", store.provenance_path().unwrap());

        // make sure we can read from new file
        let mut report = DetailedStatusTracker::new();
        let new_store = Store::load_from_asset(&op, false, &mut report).unwrap();
        Store::verify_store_async(
            &new_store,
            &mut ClaimAssetData::Path(op.as_path()),
            &mut report,
        )
        .await
        .unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
    }

    #[actix::test]
    async fn test_jumbf_generation_remote() {
        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "test-async.jpg");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // create my remote signer to map the CoseSign1 data back into the asset
        let remote_signer = crate::utils::test::temp_remote_signer();

        store.commit_claim(claim1).unwrap();
        store
            .save_to_asset_remote_signed(&ap, remote_signer.as_ref(), &op)
            .await
            .unwrap();

        // make sure we can read from new file
        let mut report = DetailedStatusTracker::new();
        let new_store = Store::load_from_asset(&op, false, &mut report).unwrap();

        Store::verify_store_async(
            &new_store,
            &mut ClaimAssetData::Path(op.as_path()),
            &mut report,
        )
        .await
        .unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_png_jumbf_generation() {
        // test adding to actual image
        let ap = fixture_path("libpng-test.png");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "libpng-test-c2pa.png");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"));
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

        // write to new file
        println!("Provenance: {}\n", store.provenance_path().unwrap());

        let mut report = DetailedStatusTracker::new();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // can  we get by the ingredient data back
        let _some_binary_data: Vec<u8> = vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ];

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_get_data_boxes() {
        // Create a new claim.
        use crate::jumbf::labels::to_relative_uri;
        let claim1 = create_test_claim().unwrap();

        for (uri, db) in claim1.databoxes() {
            // test full path
            assert!(claim1.get_databox(uri).is_some());

            // test with relative path
            let rel_path = to_relative_uri(&uri.url());
            let rel_hr = HashedUri::new(rel_path, uri.alg(), &uri.hash());
            assert!(claim1.get_databox(&rel_hr).is_some());

            // test values
            assert_eq!(db, claim1.get_databox(uri).unwrap());
        }
    }

    /*  reenable this test once we place for large test files
        #[test]
        #[cfg(feature = "file_io")]
        fn test_arw_jumbf_generation() {
            let ap = fixture_path("sample1.arw");
            let temp_dir = tempdir().expect("temp dir");
            let op = temp_dir_path(&temp_dir, "ssample1.arw");

            // Create claims store.
            let mut store = Store::new();

            // Create a new claim.
            let claim1 = create_test_claim().unwrap();

            // Create a new claim.
            let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
            create_editing_claim(&mut claim2).unwrap();

            // Create a 3rd party claim
            let mut claim_capture = Claim::new("capture", Some("claim_capture"));
            create_capture_claim(&mut claim_capture).unwrap();

            // Do we generate JUMBF?
            let signer = temp_signer();

            // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commmits
            store.commit_claim(claim1).unwrap();
            store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
            store.commit_claim(claim_capture).unwrap();
            store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
            store.commit_claim(claim2).unwrap();
            store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

            // write to new file
            println!("Provenance: {}\n", store.provenance_path().unwrap());

            let mut report = DetailedStatusTracker::new();

            // read from new file
            let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

            // can  we get by the ingredient data back
            let _some_binary_data: Vec<u8> = vec![
                0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
                0x0b, 0x0e,
            ];

            // dump store and compare to original
            for claim in new_store.claims() {
                let _restored_json = claim
                    .to_json(AssertionStoreJsonFormat::OrderedList, false)
                    .unwrap();
                let _orig_json = store
                    .get_claim(claim.label())
                    .unwrap()
                    .to_json(AssertionStoreJsonFormat::OrderedList, false)
                    .unwrap();

                println!(
                    "Claim: {} \n{}",
                    claim.label(),
                    claim
                        .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                        .expect("could not restore from json")
                );

                for hashed_uri in claim.assertions() {
                    let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                    claim
                        .get_claim_assertion(&label, instance)
                        .expect("Should find assertion");
                }
            }
        }
        #[test]
        #[cfg(feature = "file_io")]
        fn test_nef_jumbf_generation() {
            let ap = fixture_path("sample1.nef");
            let temp_dir = tempdir().expect("temp dir");
            let op = temp_dir_path(&temp_dir, "ssample1.nef");

            // Create claims store.
            let mut store = Store::new();

            // Create a new claim.
            let claim1 = create_test_claim().unwrap();

            // Create a new claim.
            let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
            create_editing_claim(&mut claim2).unwrap();

            // Create a 3rd party claim
            let mut claim_capture = Claim::new("capture", Some("claim_capture"));
            create_capture_claim(&mut claim_capture).unwrap();

            // Do we generate JUMBF?
            let signer = temp_signer();

            // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commmits
            store.commit_claim(claim1).unwrap();
            store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
            store.commit_claim(claim_capture).unwrap();
            store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
            store.commit_claim(claim2).unwrap();
            store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

            // write to new file
            println!("Provenance: {}\n", store.provenance_path().unwrap());

            let mut report = DetailedStatusTracker::new();

            // read from new file
            let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

            // can  we get by the ingredient data back
            let _some_binary_data: Vec<u8> = vec![
                0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
                0x0b, 0x0e,
            ];

            // dump store and compare to original
            for claim in new_store.claims() {
                let _restored_json = claim
                    .to_json(AssertionStoreJsonFormat::OrderedList, false)
                    .unwrap();
                let _orig_json = store
                    .get_claim(claim.label())
                    .unwrap()
                    .to_json(AssertionStoreJsonFormat::OrderedList, false)
                    .unwrap();

                println!(
                    "Claim: {} \n{}",
                    claim.label(),
                    claim
                        .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                        .expect("could not restore from json")
                );

                for hashed_uri in claim.assertions() {
                    let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                    claim
                        .get_claim_assertion(&label, instance)
                        .expect("Should find assertion");
                }
            }
        }
    */
    #[test]
    #[cfg(feature = "file_io")]
    fn test_wav_jumbf_generation() {
        let ap = fixture_path("sample1.wav");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "ssample1.wav");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"));
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

        // write to new file
        println!("Provenance: {}\n", store.provenance_path().unwrap());

        let mut report = DetailedStatusTracker::new();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // can  we get by the ingredient data back
        let _some_binary_data: Vec<u8> = vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ];

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_avi_jumbf_generation() {
        let ap = fixture_path("test.avi");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "test.avi");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"));
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

        // write to new file
        println!("Provenance: {}\n", store.provenance_path().unwrap());

        let mut report = DetailedStatusTracker::new();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // can  we get by the ingredient data back
        let _some_binary_data: Vec<u8> = vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ];

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_webp_jumbf_generation() {
        let ap = fixture_path("sample1.webp");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "sample1.webp");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"));
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

        // write to new file
        println!("Provenance: {}\n", store.provenance_path().unwrap());

        let mut report = DetailedStatusTracker::new();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // can  we get by the ingredient data back
        let _some_binary_data: Vec<u8> = vec![
            0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
            0x0b, 0x0e,
        ];

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_heic() {
        let ap = fixture_path("sample1.heic");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "sample1.heic");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        let mut report = DetailedStatusTracker::new();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // dump store and compare to original
        for claim in new_store.claims() {
            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_avif() {
        let ap = fixture_path("sample1.avif");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "sample1.avif");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        let mut report = DetailedStatusTracker::new();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // dump store and compare to original
        for claim in new_store.claims() {
            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_heif() {
        let ap = fixture_path("sample1.heif");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "sample1.heif");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        let mut report = DetailedStatusTracker::new();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        // dump store and compare to original
        for claim in new_store.claims() {
            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }

    /*  todo: disable until we can generate a valid file with no xmp
    #[test]
    fn test_manifest_no_xmp() {
        let ap = fixture_path("CAICAI_NO_XMP.jpg");
        assert!(Store::load_from_asset(&ap, true, None).is_ok());
    }
    */

    #[test]
    fn test_manifest_bad_sig() {
        let ap = fixture_path("CE-sig-CA.jpg");
        assert!(Store::load_from_asset(&ap, true, &mut OneShotStatusTracker::new()).is_err());
    }

    #[test]
    fn test_unsupported_type_without_external_manifest() {
        let ap = fixture_path("Purple Square.psd");
        let mut report = DetailedStatusTracker::new();
        let result = Store::load_from_asset(&ap, true, &mut report);
        assert!(matches!(result, Err(Error::UnsupportedType)));
        println!("Error report for {}: {:?}", ap.display(), report);
        assert!(!report.get_log().is_empty());

        assert!(report_has_err(report.get_log(), Error::UnsupportedType));
    }

    #[test]
    fn test_bad_jumbf() {
        // test bad jumbf
        let ap = fixture_path("prerelease.jpg");
        let mut report = DetailedStatusTracker::new();
        let _r = Store::load_from_asset(&ap, true, &mut report);

        // error report
        println!("Error report for {}: {:?}", ap.display(), report);
        assert!(!report.get_log().is_empty());

        assert!(report_has_err(report.get_log(), Error::PrereleaseError));
    }

    #[test]
    fn test_detect_byte_change() {
        // test bad jumbf
        let ap = fixture_path("XCA.jpg");
        let mut report = DetailedStatusTracker::new();
        Store::load_from_asset(&ap, true, &mut report).unwrap();

        // error report
        println!("Error report for {}: {:?}", ap.display(), report);
        assert!(!report.get_log().is_empty());

        let errs = report_split_errors(report.get_log_mut());
        assert!(report_has_status(
            &errs,
            validation_status::ASSERTION_DATAHASH_MISMATCH
        ));
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_file_not_found() {
        let ap = fixture_path("this_does_not_exist.jpg");
        let mut report = DetailedStatusTracker::new();
        let _result = Store::load_from_asset(&ap, true, &mut report);

        println!("Error report for {}: {:?}", ap.display(), report.get_log());
        assert!(!report.get_log().is_empty());
        let errors = report_split_errors(report.get_log_mut());
        assert!(errors[0].error_str().unwrap().starts_with("IoError"));
    }

    #[test]
    fn test_old_manifest() {
        let ap = fixture_path("prerelease.jpg");
        let mut report = DetailedStatusTracker::new();
        let _r = Store::load_from_asset(&ap, true, &mut report);

        println!("Error report for {}: {:?}", ap.display(), report.get_log());
        assert!(!report.get_log().is_empty());
        let errors = report_split_errors(report.get_log_mut());
        assert!(errors[0].error_str().unwrap().starts_with("Prerelease"));
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_verifiable_credentials() {
        use crate::utils::test::create_test_store;

        let signer = temp_signer();

        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "earth_apollo17.jpg");

        // get default store with default claim
        let mut store = create_test_store().unwrap();

        // save to output
        store
            .save_to_asset(ap.as_path(), signer.as_ref(), op.as_path())
            .unwrap();

        // read back in
        let restored_store =
            Store::load_from_asset(op.as_path(), true, &mut OneShotStatusTracker::new()).unwrap();

        let pc = restored_store.provenance_claim().unwrap();

        let vc = pc.get_verifiable_credentials();

        assert!(!vc.is_empty());
        match &vc[0] {
            AssertionData::Json(s) => {
                assert!(s.contains("did:nppa:eb1bb9934d9896a374c384521410c7f14"))
            }
            _ => panic!("expected JSON assertion data"),
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_data_box_creation() {
        use crate::utils::test::create_test_store;

        let signer = temp_signer();

        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "earth_apollo17.jpg");

        // get default store with default claim
        let mut store = create_test_store().unwrap();

        // save to output
        store
            .save_to_asset(ap.as_path(), signer.as_ref(), op.as_path())
            .unwrap();

        // read back in
        let restored_store =
            Store::load_from_asset(op.as_path(), true, &mut OneShotStatusTracker::new()).unwrap();

        let pc = restored_store.provenance_claim().unwrap();

        let databoxes = pc.databoxes();

        assert!(!databoxes.is_empty());

        for (uri, db) in databoxes {
            println!(
                "URI: {}, data: {}",
                uri.url(),
                String::from_utf8_lossy(&db.data)
            );
        }
    }

    /// copies a fixture, replaces some bytes and returns a validation report
    fn patch_and_report(
        fixture_name: &str,
        search_bytes: &[u8],
        replace_bytes: &[u8],
    ) -> impl StatusTracker {
        let temp_dir = tempdir().expect("temp dir");
        let path = temp_fixture_path(&temp_dir, fixture_name);
        patch_file(&path, search_bytes, replace_bytes).expect("patch_file");
        let mut report = DetailedStatusTracker::default();
        let _r = Store::load_from_asset(&path, true, &mut report); // errs are in report
        println!("report: {report:?}");
        report
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_update_manifest() {
        use crate::{hashed_uri::HashedUri, utils::test::create_test_store};

        let signer = temp_signer();

        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "update_manifest.jpg");

        // get default store with default claim
        let mut store = create_test_store().unwrap();

        // save to output
        store
            .save_to_asset(ap.as_path(), signer.as_ref(), op.as_path())
            .unwrap();

        let mut report = OneShotStatusTracker::default();
        // read back in
        let mut restored_store = Store::load_from_asset(op.as_path(), true, &mut report).unwrap();

        let pc = restored_store.provenance_claim().unwrap();

        // should be a regular manifest
        assert!(!pc.update_manifest());

        // create a new update manifest
        let mut claim = Claim::new("adobe unit test", Some("update_manfifest"));

        // must contain an ingredient
        let parent_hashed_uri = HashedUri::new(
            restored_store.provenance_path().unwrap(),
            Some(pc.alg().to_string()),
            &pc.hash(),
        );

        let ingredient = Ingredient::new(
            "update_manifest.jpg",
            "image/jpeg",
            "xmp.iid:7b57930e-2f23-47fc-affe-0400d70b738d",
            Some("xmp.did:87d51599-286e-43b2-9478-88c79f49c347"),
        )
        .set_parent()
        .set_c2pa_manifest_from_hashed_uri(Some(parent_hashed_uri));

        claim.add_assertion(&ingredient).unwrap();

        restored_store.commit_update_manifest(claim).unwrap();
        restored_store
            .save_to_asset(op.as_path(), signer.as_ref(), op.as_path())
            .unwrap();

        // read back in store with update manifest
        let um_store = Store::load_from_asset(op.as_path(), true, &mut report).unwrap();

        let um = um_store.provenance_claim().unwrap();

        // should be an update manifest
        assert!(um.update_manifest());
    }

    #[test]
    fn test_claim_decoding() {
        // modify a required field label in the claim - causes failure to read claim from cbor
        let report = patch_and_report("C.jpg", b"claim_generator", b"claim_generatur");
        assert!(!report.get_log().is_empty());
        assert!(report.get_log()[0]
            .error_str()
            .unwrap()
            .starts_with("ClaimDecoding"))
    }

    #[test]
    fn test_claim_modified() {
        // replace the title that is inside the claim data - should cause signature to not match
        let mut report = patch_and_report("C.jpg", b"C.jpg", b"X.jpg");
        assert!(!report.get_log().is_empty());
        let errors = report_split_errors(report.get_log_mut());

        assert!(report_has_err(&errors, Error::CoseTimeStampMismatch));

        assert!(report_has_status(
            &errors,
            validation_status::TIMESTAMP_MISMATCH
        ));
    }

    #[test]
    fn test_assertion_hash_mismatch() {
        // modifies content of an action assertion - causes an assertion hashuri mismatch
        let mut report = patch_and_report("CA.jpg", b"brightnesscontrast", b"brightnesscontraxx");
        let errors = report_split_errors(report.get_log_mut());

        assert_eq!(
            errors[0].validation_status.as_deref(),
            Some(validation_status::ASSERTION_HASHEDURI_MISMATCH)
        );
    }

    #[test]
    fn test_claim_missing() {
        // patch jumbf url from c2pa_manifest field in an ingredient to cause claim_missing
        // note this includes hex for Jumbf blocks, so may need some manual tweaking
        const SEARCH_BYTES: &[u8] =
            b"c2pa_manifest\xA3\x63url\x78\x4aself#jumbf=/c2pa/contentauth:urn:uuid:";
        const REPLACE_BYTES: &[u8] =
            b"c2pa_manifest\xA3\x63url\x78\x4aself#jumbf=/c2pa/contentauth:urn:uuix:";
        let mut report = patch_and_report("CIE-sig-CA.jpg", SEARCH_BYTES, REPLACE_BYTES);
        let errors = report_split_errors(report.get_log_mut());
        assert_eq!(
            errors[0].validation_status.as_deref(),
            Some(validation_status::ASSERTION_HASHEDURI_MISMATCH)
        );
        assert_eq!(
            errors[1].validation_status.as_deref(),
            Some(validation_status::CLAIM_MISSING)
        );
    }

    #[test]
    fn test_display() {
        let ap = fixture_path("CA.jpg");
        let mut report = DetailedStatusTracker::new();
        let store = Store::load_from_asset(&ap, true, &mut report).expect("load_from_asset");
        let _errors = report_split_errors(report.get_log_mut());

        println!("store = {store}");
    }

    #[test]
    fn test_legacy_ingredient_hash() {
        // test 1.0 ingredient hash
        let ap = fixture_path("legacy_ingredient_hash.jpg");
        let mut report = DetailedStatusTracker::new();
        let store = Store::load_from_asset(&ap, true, &mut report).expect("load_from_asset");
        println!("store = {store}");
    }

    #[test]
    fn test_bmff_legacy() {
        // test 1.0 bmff hash
        let ap = fixture_path("legacy.mp4");
        let mut report = DetailedStatusTracker::new();
        let store = Store::load_from_asset(&ap, true, &mut report).expect("load_from_asset");
        println!("store = {store}");
    }

    /*
           #[test]
           fn test_bmff_fragments() {
               let init_stream_path = fixture_path("dashinit.mp4");
               let segment_stream_path = fixture_path("dash1.m4s");

               let init_stream = std::fs::read(init_stream_path).unwrap();
               let segment_stream = std::fs::read(segment_stream_path).unwrap();

               let mut report = DetailedStatusTracker::new();
               let store = Store::load_fragment_from_memory(
                   "mp4",
                   &init_stream,
                   &segment_stream,
                   true,
                   &mut report,
               )
               .expect("load_from_asset");
               println!("store = {store}");
           }
    */

    #[test]
    fn test_bmff_jumbf_generation() {
        // test adding to actual image
        let ap = fixture_path("video1.mp4");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "video1.mp4");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        let signer = temp_signer();

        // Move the claim to claims list.
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        let mut report = DetailedStatusTracker::new();

        // can we read back in
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        let errors = report_split_errors(report.get_log_mut());

        assert!(errors.is_empty());

        println!("store = {new_store}");
    }

    #[test]
    fn test_bmff_jumbf_stream_generation() {
        // test adding to actual image
        let ap = fixture_path("video1.mp4");
        let mut input_stream = std::fs::File::open(ap).unwrap();

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        let signer = temp_signer();

        let result: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(result);

        // Move the claim to claims list.
        store.commit_claim(claim1).unwrap();

        store
            .save_to_stream(
                "mp4",
                &mut input_stream,
                &mut output_stream,
                signer.as_ref(),
            )
            .unwrap();

        let mut report = DetailedStatusTracker::new();

        let output_data = output_stream.into_inner();

        // can we read back in
        let _new_store = Store::load_from_memory("mp4", &output_data, true, &mut report).unwrap();

        let errors = report_split_errors(report.get_log_mut());

        assert!(errors.is_empty());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_removed_jumbf() {
        // test adding to actual image
        let ap = fixture_path("no_manifest.jpg");

        let mut report = DetailedStatusTracker::new();

        // can we read back in
        let _store = Store::load_from_asset(&ap, true, &mut report);

        assert!(report_has_err(report.get_log(), Error::JumbfNotFound));
    }

    #[test]
    fn test_external_manifest_sidecar() {
        // test adding to actual image
        let ap = fixture_path("libpng-test.png");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "libpng-test-c2pa.png");

        let sidecar = op.with_extension(MANIFEST_STORE_EXT);

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let mut claim = create_test_claim().unwrap();

        // set claim for side car generation
        claim.set_external_manifest();

        // Do we generate JUMBF?
        let signer = temp_signer();

        store.commit_claim(claim).unwrap();

        let saved_manifest = store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        assert!(sidecar.exists());

        // load external manifest
        let loaded_manifest = std::fs::read(sidecar).unwrap();

        // compare returned to external
        assert_eq!(saved_manifest, loaded_manifest);

        // test auto loading of sidecar with validation
        let mut validation_log = OneShotStatusTracker::default();
        Store::load_from_asset(&op, true, &mut validation_log).unwrap();
    }

    // generalize test for multipe file types
    fn external_manifest_test(file_name: &str) {
        // test adding to actual image
        let ap = fixture_path(file_name);
        let extension = ap.extension().unwrap().to_str().unwrap();
        let temp_dir = tempdir().expect("temp dir");
        let mut op = temp_dir_path(&temp_dir, file_name);
        op.set_extension(extension);

        let sidecar = op.with_extension(MANIFEST_STORE_EXT);

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let mut claim = create_test_claim().unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // start with base url
        let fp = format!("file:/{}", sidecar.to_str().unwrap());
        let url = url::Url::parse(&fp).unwrap();

        let url_string: String = url.into();

        // set claim for side car with remote manifest embedding generation
        claim.set_remote_manifest(url_string.clone()).unwrap();

        store.commit_claim(claim).unwrap();

        let saved_manifest = store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        assert!(sidecar.exists());

        // load external manifest
        let loaded_manifest = std::fs::read(sidecar).unwrap();

        // compare returned to external
        assert_eq!(saved_manifest, loaded_manifest);

        // load the jumbf back into a store
        let mut asset_reader = std::fs::File::open(op.clone()).unwrap();
        let ext_ref =
            crate::utils::xmp_inmemory_utils::XmpInfo::from_source(&mut asset_reader, extension)
                .provenance
                .unwrap();

        assert_eq!(ext_ref, url_string);

        // make sure it validates
        let mut validation_log = OneShotStatusTracker::default();
        Store::load_from_asset(&op, true, &mut validation_log).unwrap();
    }

    #[test]
    fn test_external_manifest_embedded_png() {
        external_manifest_test("libpng-test.png");
    }

    #[test]
    fn test_external_manifest_embedded_tiff() {
        external_manifest_test("TUSCANY.TIF");
    }

    #[test]
    fn test_external_manifest_embedded_webp() {
        external_manifest_test("sample1.webp");
    }

    #[test]
    fn test_user_guid_external_manifest_embedded() {
        // test adding to actual image
        let ap = fixture_path("libpng-test.png");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "libpng-test-c2pa.png");

        let sidecar = op.with_extension(MANIFEST_STORE_EXT);

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let mut claim = create_test_claim().unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // start with base url
        let fp = format!("file:/{}", sidecar.to_str().unwrap());
        let url = url::Url::parse(&fp).unwrap();

        let url_string: String = url.into();

        // set claim for side car with remote manifest embedding generation
        claim.set_embed_remote_manifest(url_string.clone()).unwrap();

        store.commit_claim(claim).unwrap();

        let saved_manifest = store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        assert!(sidecar.exists());

        // load external manifest
        let loaded_manifest = std::fs::read(sidecar).unwrap();

        // compare returned to external
        assert_eq!(saved_manifest, loaded_manifest);

        let mut asset_reader = std::fs::File::open(op.clone()).unwrap();
        let ext_ref =
            crate::utils::xmp_inmemory_utils::XmpInfo::from_source(&mut asset_reader, "png")
                .provenance
                .unwrap();

        assert_eq!(ext_ref, url_string);

        // make sure it validates
        let mut validation_log = OneShotStatusTracker::default();
        Store::load_from_asset(&op, true, &mut validation_log).unwrap();
    }

    #[test]
    fn test_external_manifest_from_memory() {
        // test adding to actual image
        let ap = fixture_path("libpng-test.png");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "libpng-test-c2pa.png");

        let sidecar = op.with_extension(MANIFEST_STORE_EXT);

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let mut claim = create_test_claim().unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // start with base url
        let fp = format!("file:/{}", sidecar.to_str().unwrap());
        let url = url::Url::parse(&fp).unwrap();

        let url_string: String = url.into();

        // set claim for side car with remote manifest embedding generation
        claim.set_remote_manifest(url_string).unwrap();

        store.commit_claim(claim).unwrap();

        let saved_manifest = store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();

        // delete the sidecar so we can test for url only rea
        // std::fs::remove_file(sidecar);

        assert!(sidecar.exists());

        // load external manifest
        let loaded_manifest = std::fs::read(sidecar).unwrap();

        // compare returned to external
        assert_eq!(saved_manifest, loaded_manifest);

        // Load the exported file into a buffer
        let file_buffer = std::fs::read(&op).unwrap();

        let mut validation_log = OneShotStatusTracker::default();
        let result = Store::load_from_memory("png", &file_buffer, true, &mut validation_log);

        assert!(result.is_err());

        // We should get a `JumbfNotFound` error since the external reference points to a file URL, not a remote URL
        match result {
            Ok(_store) => panic!("did not expect to have a store"),
            Err(e) => match e {
                Error::JumbfNotFound => {}
                e => panic!("unexpected error: {e}"),
            },
        }
    }

    #[actix::test]
    async fn test_jumbf_generation_stream() {
        let file_buffer = include_bytes!("../tests/fixtures/earth_apollo17.jpg").to_vec();
        // convert buffer to cursor with Read/Write/Seek capability
        let mut buf_io = Cursor::new(file_buffer);

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        let signer = temp_signer();

        store.commit_claim(claim1).unwrap();

        let mut result: Vec<u8> = Vec::new();
        let mut result_stream = Cursor::new(result);

        store
            .save_to_stream("jpeg", &mut buf_io, &mut result_stream, signer.as_ref())
            .unwrap();

        // convert our cursor back into a buffer
        result = result_stream.into_inner();

        // make sure we can read from new file
        let mut report = DetailedStatusTracker::new();
        let new_store = Store::load_from_memory("jpeg", &result, false, &mut report).unwrap();

        Store::verify_store_async(
            &new_store,
            &mut ClaimAssetData::Bytes(&result, "jpg"),
            &mut report,
        )
        .await
        .unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
        // std::fs::write("target/test.jpg", result).unwrap();
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_tiff_jumbf_generation() {
        // test adding to actual image
        let ap = fixture_path("TUSCANY.TIF");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "TUSCANY-OUTPUT.TIF");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim1 = create_test_claim().unwrap();

        // Create a new claim.
        let mut claim2 = Claim::new("Photoshop", Some("Adobe"));
        create_editing_claim(&mut claim2).unwrap();

        // Create a 3rd party claim
        let mut claim_capture = Claim::new("capture", Some("claim_capture"));
        create_capture_claim(&mut claim_capture).unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, signer.as_ref(), &op).unwrap();

        println!("Provenance: {}\n", store.provenance_path().unwrap());

        let mut report = DetailedStatusTracker::new();

        // read from new file
        let new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());

        // dump store and compare to original
        for claim in new_store.claims() {
            let _restored_json = claim
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();
            let _orig_json = store
                .get_claim(claim.label())
                .unwrap()
                .to_json(AssertionStoreJsonFormat::OrderedList, false)
                .unwrap();

            println!(
                "Claim: {} \n{}",
                claim.label(),
                claim
                    .to_json(AssertionStoreJsonFormat::OrderedListNoBinary, true)
                    .expect("could not restore from json")
            );

            for hashed_uri in claim.assertions() {
                let (label, instance) = Claim::assertion_label_from_link(&hashed_uri.url());
                claim
                    .get_claim_assertion(&label, instance)
                    .expect("Should find assertion");
            }
        }
    }

    #[actix::test]
    #[cfg(feature = "file_io")]
    async fn test_boxhash_embeddable_manifest_async() {
        // test adding to actual image
        let ap = fixture_path("boxhash.jpg");
        let box_hash_path = fixture_path("boxhash.json");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let mut claim = create_test_claim().unwrap();

        // add box hash for CA.jpg
        let box_hash_data = std::fs::read(box_hash_path).unwrap();
        let assertion = Assertion::from_data_json(BOX_HASH, &box_hash_data).unwrap();
        let box_hash = BoxHash::from_json_assertion(&assertion).unwrap();
        claim.add_assertion(&box_hash).unwrap();

        store.commit_claim(claim).unwrap();

        // Do we generate JUMBF?
        let signer = crate::openssl::temp_signer_async::AsyncSignerAdapter::new(SigningAlg::Ps256);

        // get the embeddable manifest
        let em = store
            .get_box_hashed_embeddable_manifest_async(&signer)
            .await
            .unwrap();

        // get composed version for embedding to JPEG
        let cm = Store::get_composed_manifest(&em, "jpg").unwrap();

        // insert manifest into output asset
        let jpeg_io = get_assetio_handler_from_path(&ap).unwrap();
        let ol = jpeg_io.get_object_locations(&ap).unwrap();

        let cai_loc = ol
            .iter()
            .find(|o| o.htype == HashBlockObjectType::Cai)
            .unwrap();

        // remove any existing manifest
        jpeg_io.read_cai_store(&ap).unwrap();

        // build new asset in memory inserting new manifest
        let outbuf = Vec::new();
        let mut out_stream = Cursor::new(outbuf);
        let mut input_file = std::fs::File::open(&ap).unwrap();

        // write before
        let mut before = vec![0u8; cai_loc.offset];
        input_file.read_exact(before.as_mut_slice()).unwrap();
        out_stream.write_all(&before).unwrap();

        // write composed bytes
        out_stream.write_all(&cm).unwrap();

        // write bytes after
        let mut after_buf = Vec::new();
        input_file.read_to_end(&mut after_buf).unwrap();
        out_stream.write_all(&after_buf).unwrap();

        // save to output file
        let temp_dir = tempfile::tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
        let mut output_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output)
            .unwrap();
        output_file.write_all(&out_stream.into_inner()).unwrap();

        let mut report = DetailedStatusTracker::new();
        let new_store = Store::load_from_asset(&output, false, &mut report).unwrap();

        Store::verify_store_async(&new_store, &mut ClaimAssetData::Path(&output), &mut report)
            .await
            .unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_boxhash_embeddable_manifest() {
        // test adding to actual image
        let ap = fixture_path("boxhash.jpg");
        let box_hash_path = fixture_path("boxhash.json");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let mut claim = create_test_claim().unwrap();

        // add box hash for CA.jpg
        let box_hash_data = std::fs::read(box_hash_path).unwrap();
        let assertion = Assertion::from_data_json(BOX_HASH, &box_hash_data).unwrap();
        let box_hash = BoxHash::from_json_assertion(&assertion).unwrap();
        claim.add_assertion(&box_hash).unwrap();

        store.commit_claim(claim).unwrap();

        // Do we generate JUMBF?
        let signer = temp_signer();

        // get the embeddable manifest
        let em = store
            .get_box_hashed_embeddable_manifest(signer.as_ref())
            .unwrap();

        // get composed version for embedding to JPEG
        let cm = Store::get_composed_manifest(&em, "jpg").unwrap();

        // insert manifest into output asset
        let jpeg_io = get_assetio_handler_from_path(&ap).unwrap();
        let ol = jpeg_io.get_object_locations(&ap).unwrap();

        let cai_loc = ol
            .iter()
            .find(|o| o.htype == HashBlockObjectType::Cai)
            .unwrap();

        // remove any existing manifest
        jpeg_io.read_cai_store(&ap).unwrap();

        // build new asset in memory inserting new manifest
        let outbuf = Vec::new();
        let mut out_stream = Cursor::new(outbuf);
        let mut input_file = std::fs::File::open(&ap).unwrap();

        // write before
        let mut before = vec![0u8; cai_loc.offset];
        input_file.read_exact(before.as_mut_slice()).unwrap();
        out_stream.write_all(&before).unwrap();

        // write composed bytes
        out_stream.write_all(&cm).unwrap();

        // write bytes after
        let mut after_buf = Vec::new();
        input_file.read_to_end(&mut after_buf).unwrap();
        out_stream.write_all(&after_buf).unwrap();

        // save to output file
        let temp_dir = tempfile::tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
        let mut output_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output)
            .unwrap();
        output_file.write_all(&out_stream.into_inner()).unwrap();

        let mut report = DetailedStatusTracker::new();
        let _new_store = Store::load_from_asset(&output, true, &mut report).unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
    }

    #[actix::test]
    #[cfg(feature = "file_io")]
    async fn test_datahash_embeddable_manifest_async() {
        // test adding to actual image

        use std::io::SeekFrom;
        let ap = fixture_path("cloud.jpg");

        // Do we generate JUMBF?
        let signer = crate::openssl::temp_signer_async::AsyncSignerAdapter::new(SigningAlg::Ps256);

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim = create_test_claim().unwrap();

        store.commit_claim(claim).unwrap();

        // get a placeholder the manifest
        let placeholder = store
            .get_data_hashed_manifest_placeholder(signer.reserve_size(), "jpeg")
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
        let mut output_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output)
            .unwrap();

        // write a jpeg file with a placeholder for the manifest (returns offset of the placeholder)
        let offset =
            write_jpeg_placeholder_file(&placeholder, &ap, &mut output_file, None).unwrap();

        // build manifest to insert in the hole

        // create an hash exclusion for the manifest
        let exclusion = HashRange::new(offset, placeholder.len());
        let exclusions = vec![exclusion];

        let mut dh = DataHash::new("source_hash", "sha256");
        dh.exclusions = Some(exclusions);

        // get the embeddable manifest, letting API do the hashing
        output_file.rewind().unwrap();
        let cm = store
            .get_data_hashed_embeddable_manifest_async(&dh, &signer, "jpeg", Some(&mut output_file))
            .await
            .unwrap();

        // path in new composed manifest
        output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
        output_file.write_all(&cm).unwrap();

        let mut report = DetailedStatusTracker::new();
        let new_store = Store::load_from_asset(&output, false, &mut report).unwrap();

        Store::verify_store_async(&new_store, &mut ClaimAssetData::Path(&output), &mut report)
            .await
            .unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_datahash_embeddable_manifest() {
        // test adding to actual image

        use std::io::SeekFrom;
        let ap = fixture_path("cloud.jpg");

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim = create_test_claim().unwrap();

        store.commit_claim(claim).unwrap();

        // get a placeholder the manifest
        let placeholder = store
            .get_data_hashed_manifest_placeholder(signer.reserve_size(), "jpeg")
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
        let mut output_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output)
            .unwrap();

        // write a jpeg file with a placeholder for the manifest (returns offset of the placeholder)
        let offset =
            write_jpeg_placeholder_file(&placeholder, &ap, &mut output_file, None).unwrap();

        // build manifest to insert in the hole

        // create an hash exclusion for the manifest
        let exclusion = HashRange::new(offset, placeholder.len());
        let exclusions = vec![exclusion];

        let mut dh = DataHash::new("source_hash", "sha256");
        dh.exclusions = Some(exclusions);

        // get the embeddable manifest, letting API do the hashing
        output_file.rewind().unwrap();
        let cm = store
            .get_data_hashed_embeddable_manifest(
                &dh,
                signer.as_ref(),
                "jpeg",
                Some(&mut output_file),
            )
            .unwrap();

        // path in new composed manifest
        output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
        output_file.write_all(&cm).unwrap();

        let mut report = DetailedStatusTracker::new();
        let _new_store = Store::load_from_asset(&output, true, &mut report).unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_datahash_embeddable_manifest_user_hashed() {
        // test adding to actual image

        use std::io::SeekFrom;
        let ap = fixture_path("cloud.jpg");

        let mut hasher = Hasher::SHA256(Sha256::new());

        // Do we generate JUMBF?
        let signer = temp_signer();

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let claim = create_test_claim().unwrap();

        store.commit_claim(claim).unwrap();

        // get a placeholder for the manifest
        let placeholder = store
            .get_data_hashed_manifest_placeholder(signer.reserve_size(), "jpeg")
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let output = temp_dir_path(&temp_dir, "boxhash-out.jpg");
        let mut output_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output)
            .unwrap();

        // write a jpeg file with a placeholder for the manifest (returns offset of the placeholder)
        let offset =
            write_jpeg_placeholder_file(&placeholder, &ap, &mut output_file, Some(&mut hasher))
                .unwrap();

        // create target data hash
        // create an hash exclusion for the manifest
        let exclusion = HashRange::new(offset, placeholder.len());
        let exclusions = vec![exclusion];

        //input_file.rewind().unwrap();
        let mut dh = DataHash::new("source_hash", "sha256");
        dh.hash = Hasher::finalize(hasher);
        dh.exclusions = Some(exclusions);

        // get the embeddable manifest, using user hashing
        let cm = store
            .get_data_hashed_embeddable_manifest(&dh, signer.as_ref(), "jpeg", None)
            .unwrap();

        // path in new composed manifest
        output_file.seek(SeekFrom::Start(offset as u64)).unwrap();
        output_file.write_all(&cm).unwrap();

        let mut report = DetailedStatusTracker::new();
        let _new_store = Store::load_from_asset(&output, true, &mut report).unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
    }

    struct PlacedCallback {
        path: String,
    }

    impl ManifestPatchCallback for PlacedCallback {
        fn patch_manifest(&self, manifest_store: &[u8]) -> Result<Vec<u8>> {
            use ::jumbf::parser::SuperBox;

            if let Ok((_raw, sb)) = SuperBox::from_slice(manifest_store) {
                let components: Vec<&str> = self.path.trim_start_matches('/').split('/').collect();

                let mut current_box = &sb;
                for component in components[1..].iter() {
                    if let Some(next_box) = current_box.find_by_label(component) {
                        if let Some(box_name) = next_box.desc.label {
                            // find box I am looking for
                            if box_name == "com.mycompany.myassertion" {
                                if let Some(db) = next_box.data_box() {
                                    let data_offset = db.offset_within_superbox(&sb).unwrap();
                                    let replace_bytes =
                                        r#"{"my_tag": "some value was replaced!!"}"#.to_string();

                                    // I'm not checking here but data len must be same len as replacement bytes.
                                    let mut new_manifest_store = manifest_store.to_vec();
                                    new_manifest_store.splice(
                                        data_offset..data_offset + replace_bytes.len(),
                                        replace_bytes.as_bytes().iter().cloned(),
                                    );

                                    return Ok(new_manifest_store);
                                }
                            }
                        }
                        current_box = next_box;
                    } else {
                        break;
                    }
                }
                Err(Error::NotFound)
            } else {
                Err(Error::JumbfParseError(JumbfParseError::InvalidJumbBox))
            }
        }
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_placed_manifest() {
        use crate::jumbf::labels::to_normalized_uri;

        let signer = temp_signer();

        // test adding to actual image
        let ap = fixture_path("C.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "C-placed.jpg");

        // Create claims store.
        let mut store = Store::new();

        // Create a new claim.
        let mut claim = create_test_claim().unwrap();

        // add test assertion assertion with data I will replace
        let my_content = r#"{"my_tag": "some value I will replace"}"#;
        let my_label = "com.mycompany.myassertion";
        let user = crate::assertions::User::new(my_label, my_content);
        let my_assertion = claim.add_assertion(&user).unwrap();

        store.commit_claim(claim).unwrap();

        // get the embeddable manifest
        let mut input_stream = std::fs::File::open(ap).unwrap();
        let placed_manifest = store
            .get_placed_manifest(signer.reserve_size(), "jpg", &mut input_stream)
            .unwrap();

        // insert manifest into output asset
        let mut output_stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&op)
            .unwrap();
        input_stream.rewind().unwrap();

        // my manifest callback handler
        // set some data needed by callback to do what it needs to
        // for this example lets tell it which jumbf box we can to change
        let my_assertion_path = to_normalized_uri(&jumbf::labels::to_absolute_uri(
            &store.provenance_label().unwrap(),
            &my_assertion.url(),
        ));
        let my_callback = PlacedCallback {
            path: my_assertion_path,
        };

        let callbacks: Vec<Box<dyn ManifestPatchCallback>> = vec![Box::new(my_callback)];

        // add manifest back into data
        Store::embed_placed_manifest(
            &placed_manifest,
            "jpg",
            &mut input_stream,
            &mut output_stream,
            signer.as_ref(),
            &callbacks,
        )
        .unwrap();

        let mut report = DetailedStatusTracker::new();
        let _new_store = Store::load_from_asset(&op, true, &mut report).unwrap();

        let errors = report_split_errors(report.get_log_mut());
        assert!(errors.is_empty());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_fragmented_jumbf_generation() {
        // test adding to actual image

        let tempdir = tempdir().expect("temp dir");
        let output_path = tempdir.into_path();

        // search folders for init segments
        for init in glob::glob(
            fixture_path("bunny/**/BigBuckBunny_2s_init.mp4")
                .to_str()
                .unwrap(),
        )
        .unwrap()
        {
            match init {
                Ok(p) => {
                    let mut fragments = Vec::new();
                    let init_dir = p.parent().unwrap();
                    let seg_glob = init_dir.join("BigBuckBunny_2s*.m4s"); // segment match pattern

                    // grab the fragments that go with this init segment
                    for seg in glob::glob(seg_glob.to_str().unwrap()).unwrap().flatten() {
                        fragments.push(seg);
                    }

                    // Create claims store.
                    let mut store = Store::new();

                    // Create a new claim.
                    let claim = create_test_claim().unwrap();
                    store.commit_claim(claim).unwrap();

                    // Do we generate JUMBF?
                    let signer = temp_signer();

                    // add manifest based on
                    let new_output_path = output_path.join(init_dir.file_name().unwrap());
                    store
                        .save_to_bmff_fragmented(
                            p.as_path(),
                            &fragments,
                            new_output_path.as_path(),
                            signer.as_ref(),
                        )
                        .unwrap();

                    // verify the fragments
                    let output_init = new_output_path.join(p.file_name().unwrap());
                    let init_stream = std::fs::read(output_init).unwrap();

                    for entry in &fragments {
                        let file_path = new_output_path.join(entry.file_name().unwrap());

                        let mut validation_log = DetailedStatusTracker::new();

                        let fragment_stream = std::fs::read(&file_path).unwrap();
                        let _manifest = Store::load_fragment_from_memory(
                            "mp4",
                            &init_stream,
                            &fragment_stream,
                            true,
                            &mut validation_log,
                        )
                        .unwrap();

                        let errors = report_split_errors(validation_log.get_log_mut());
                        assert!(errors.is_empty());
                    }

                    // test verifying all at once
                    let mut output_fragments = Vec::new();
                    for entry in &fragments {
                        output_fragments.push(new_output_path.join(entry.file_name().unwrap()));
                    }

                    let mut reader = Cursor::new(init_stream);
                    let mut validation_log = DetailedStatusTracker::new();
                    let _manifest = Store::load_from_file_and_fragments(
                        "mp4",
                        &mut reader,
                        &output_fragments,
                        true,
                        &mut validation_log,
                    )
                    .unwrap();

                    let errors = report_split_errors(validation_log.get_log_mut());
                    assert!(errors.is_empty());
                }
                Err(_) => panic!("test misconfigures"),
            }
        }
    }
}
