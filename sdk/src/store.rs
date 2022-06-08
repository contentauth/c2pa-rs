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

use crate::{
    assertion::{Assertion, AssertionBase, AssertionDecodeError, AssertionDecodeErrorCause},
    assertions::{labels, Ingredient, Relationship},
    claim::{Claim, ClaimAssertion},
    error::{Error, Result},
    hash_utils::{hash_by_alg, vec_compare, verify_by_alg},
    jumbf::{self, boxes::*},
    jumbf_io::{get_cailoader_handler, load_cai_from_memory},
    status_tracker::{log_item, OneShotStatusTracker, StatusTracker},
    validation_status,
    xmp_inmemory_utils::extract_provenance,
};

#[cfg(feature = "file_io")]
use crate::{
    assertion::AssertionData,
    assertions::DataHash,
    asset_io::{HashBlockObjectType, HashObjectPositions},
    cose_sign::cose_sign,
    cose_validator::verify_cose,
    embedded_xmp,
    jumbf_io::{
        get_supported_file_extension, load_cai_from_file, object_locations, save_jumbf_to_file,
    },
    utils::{
        hash_utils::{hash256, Exclusion},
        patch::patch_bytes,
    },
    Signer,
};

#[cfg(feature = "async_signer")]
use crate::AsyncSigner;
use crate::ManifestStoreReport;
#[cfg(feature = "file_io")]
use log::error;
use std::{collections::HashMap, io::Cursor};
#[cfg(feature = "file_io")]
use std::{fs, path::Path};

/// A `Store` maintains a list of `Claim` structs.
///
/// Typically, this list of `Claim`s represents all of the claims in an asset.
#[derive(Debug, PartialEq)]
pub struct Store {
    claims_map: HashMap<String, usize>,
    claims: Vec<Claim>,
    label: String,
    provenance_path: Option<String>,
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
        Self::new_with_label(jumbf::labels::MANIFEST_STORE)
    }

    /// Create a new, empty claims store with a custom label.
    ///
    /// In most cases, calling [`Store::new()`] is preferred.
    pub fn new_with_label(label: &str) -> Self {
        Store {
            claims_map: HashMap::new(),
            claims: Vec::new(),
            label: label.to_string(),
            provenance_path: None,
        }
    }

    /// Return label for the store
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Get the provenance if available.
    /// If loaded from an existing asset it will be provenance from that XMP
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

    /// Add a new Claim to this Store. The claim label
    /// may be updated to reflect is position in the Claim Store
    /// if there are conflicting label names.  The function
    /// will return the label of the claim used
    pub fn commit_claim(&mut self, mut claim: Claim) -> Result<String> {
        // verify the claim is valid
        claim.build()?;

        // load the claim ingredients
        // preparse first to make sure we can load them
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

    // Returns placeholder that will be searched for and replaced
    // with actual signature data.
    #[cfg(feature = "file_io")]
    fn sign_claim_placeholder(&self, claim: &Claim, min_reserve_size: usize) -> Vec<u8> {
        let placeholder_str = format!("signature placeholder:{}", claim.label());
        let mut placeholder = hash256(placeholder_str.as_bytes()).as_bytes().to_vec();

        use std::cmp::max;
        placeholder.resize(max(placeholder.len(), min_reserve_size), 0);

        placeholder
    }

    /// Sign the claim and return signature.
    #[cfg(feature = "file_io")]
    pub fn sign_claim(
        &self,
        claim: &Claim,
        signer: &dyn Signer,
        box_size: usize,
    ) -> Result<Vec<u8>> {
        let claim_bytes = claim.data()?;

        cose_sign(signer, &claim_bytes, box_size).and_then(|sig| {
            // Sanity check: Ensure that this signature is valid.

            let mut cose_log = OneShotStatusTracker::new();
            match verify_cose(&sig, &claim_bytes, b"", false, &mut cose_log) {
                Ok(_) => Ok(sig),
                Err(err) => {
                    error!(
                        "Signature that was just generated does not validate: {:#?}",
                        err
                    );
                    Err(err)
                }
            }
        })
    }

    /// Sign the claim asynchronously and return signature.
    #[cfg(feature = "async_signer")]
    pub async fn sign_claim_async(
        &self,
        claim: &Claim,
        signer: &dyn AsyncSigner,
    ) -> Result<Vec<u8>> {
        let claim_bytes = claim.data()?;
        signer.sign(&claim_bytes).await
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

    #[cfg(feature = "file_io")]
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
                let hash = Claim::calc_box_hash(label, &assertion, salt.clone(), &alg)?;
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
                let hash = Claim::calc_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
            }
            CAI_CBOR_ASSERTION_UUID => {
                let cbor_box = assertion_box
                    .data_box_as_cbor_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let assertion = Assertion::from_data_cbor(&raw_label, cbor_box.cbor());
                let hash = Claim::calc_box_hash(label, &assertion, salt.clone(), &alg)?;
                Ok(ClaimAssertion::new(assertion, instance, &hash, &alg, salt))
            }
            CAI_UUID_ASSERTION_UUID => {
                let uuid_box = assertion_box
                    .data_box_as_uuid_box(0)
                    .ok_or(Error::JumbfBoxNotFound)?;
                let uuid_str = hex::encode(uuid_box.uuid());
                let assertion = Assertion::from_data_uuid(&raw_label, &uuid_str, uuid_box.data());

                let hash = Claim::calc_box_hash(label, &assertion, salt.clone(), &alg)?;
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
    #[cfg(feature = "file_io")]
    pub fn to_jumbf(&self, signer: &dyn Signer) -> Result<Vec<u8>> {
        self.to_jumbf_internal(signer.reserve_size())
    }

    /// Convert this claims store to a JUMBF box.
    #[cfg(feature = "async_signer")]
    pub fn to_jumbf_async(&self, signer: &dyn AsyncSigner) -> Result<Vec<u8>> {
        self.to_jumbf_internal(signer.reserve_size())
    }

    #[cfg(feature = "file_io")]
    fn to_jumbf_internal(&self, min_reserve_size: usize) -> Result<Vec<u8>> {
        // Create the CAI block.
        let mut cai_block = Cai::new();

        // Add claims and assertions in this store to the JUMBF store.
        for claim in &self.claims {
            let label = claim.label();

            let mut cai_store = CAIStore::new(label, claim.update_manifest());

            // Add claim box. Note the order of the boxes are set by the spec
            let mut cb = CAIClaimBox::new();

            // Create the CAI assertion store.
            let mut a_store = CAIAssertionStore::new();

            // Add assertions to CAI assertion store.
            let cas = claim.claim_assertion_store();
            for assertion in cas {
                Store::add_assertion_to_jumbf_store(&mut a_store, assertion)?;
            }

            // Add the CAI assertion store to the CAI store.
            cai_store.add_box(Box::new(a_store));

            // Add the Claim json
            let claim_cbor_bytes = claim.data()?;
            let c_cbor = JUMBFCBORContentBox::new(claim_cbor_bytes);
            cb.add_claim(Box::new(c_cbor));
            cai_store.add_box(Box::new(cb));

            // Create a signature and add placeholder data to the CAI store.
            let mut sigb = CAISignatureBox::new();
            let signed_data = match claim.signature_val().is_empty() {
                false => claim.signature_val().clone(), // existing claims have sig values
                true => self.sign_claim_placeholder(claim, min_reserve_size), // empty is the new sig to be replaced
            };

            let sigc = JUMBFCBORContentBox::new(signed_data);
            sigb.add_signature(Box::new(sigc));
            cai_store.add_box(Box::new(sigb));

            // add vc_store if needed
            if !claim.get_verifiable_credentials().is_empty() {
                // Create VC store.
                let mut vc_store = CAIVerifiableCredentialStore::new();

                // Add assertions to CAI assertion store.
                let vcs = claim.get_verifiable_credentials();
                for assertion_data in vcs {
                    if let AssertionData::Json(j) = assertion_data {
                        let id = Claim::vc_id(j)?;
                        let mut json_data = CAIJSONAssertionBox::new(&id);
                        json_data.add_json(j.as_bytes().to_vec());
                        vc_store.add_credential(Box::new(json_data));
                    } else {
                        return Err(Error::BadParam("VC data must be JSON".to_string()));
                    }
                }

                // Add the CAI assertion store to the CAI store.
                cai_store.add_box(Box::new(vc_store));
            }

            // Finally add the completed CAI store into the CAI block.
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

                    claim.add_verifiable_credential(&json_str)?;
                }
            }

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

    // verify the provenance of the claim
    fn provenance_checks<'a>(
        store: &'a Store,
        xmp_opt: Option<String>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<&'a Claim> {
        #[cfg(feature = "diagnostics")]
        let _t = crate::utils::time_it::TimeIt::new("verify_store");

        // look for the active manifest in xmp if available
        let provenance_claim = match xmp_opt {
            Some(xmp_str) => match extract_provenance(&xmp_str) {
                Some(c) => c,
                None => store.provenance_path().unwrap_or_else(|| "".to_string()), // if not explicitly set use active manifest
            },
            None => store.provenance_path().unwrap_or_else(|| "".to_string()), // if not explicitly set use active manifest
        };

        // get claim that matches the provenance label
        let claim_label = Store::manifest_label_from_path(&provenance_claim);
        let claim = match store.get_claim(&claim_label) {
            Some(c) => c,
            None => {
                let log_item = log_item!(
                    &claim_label,
                    "could not find active manifest",
                    "verify_store"
                )
                .error(Error::ProvenanceMissing)
                .validation_status(validation_status::CLAIM_MISSING);
                validation_log.log(log_item, Some(Error::ProvenanceMissing))?;

                return Err(Error::ProvenanceMissing);
            }
        };

        Ok(claim)
    }

    // wake the ingredients and validate
    fn ingredient_checks(
        store: &Store,
        claim: &Claim,
        asset_bytes: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let mut num_parent_ofs = 0;

        // walk the ingredients
        for i in claim.ingredient_assertions() {
            let ingredient_assertion = Ingredient::from_assertion(&i)?;

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
                    if !verify_by_alg(&alg, &c2pa_manifest.hash(), &ingredient.data()?, None) {
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

                    // make sure
                    // verify the ingredient claim
                    Claim::verify_claim(ingredient, asset_bytes, false, validation_log)?;
                } else {
                    let log_item = log_item!(
                        &c2pa_manifest.url(),
                        "ingredient not found",
                        "ingredient_checks"
                    )
                    .error(Error::ClaimVerification(format!(
                        "ingredient: {} is missing",
                        label
                    )))
                    .validation_status(validation_status::CLAIM_MISSING);
                    validation_log.log(
                        log_item,
                        Some(Error::ClaimVerification(format!(
                            "ingredient: {} is missing",
                            label
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
    async fn ingredient_checks_async(
        store: &Store,
        claim: &Claim,
        asset_bytes: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        // walk the ingredients
        for i in claim.ingredient_assertions() {
            let ingredient_assertion = Ingredient::from_assertion(&i)?;

            // is this an ingredient
            if let Some(ref c2pa_manifest) = &ingredient_assertion.c2pa_manifest {
                let label = Store::manifest_label_from_path(&c2pa_manifest.url());

                if let Some(ingredient) = store.get_claim(&label) {
                    if !verify_by_alg(
                        ingredient.alg(),
                        &c2pa_manifest.hash(),
                        &ingredient.data()?,
                        None,
                    ) {
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
                    // verify the ingredient claim
                    Claim::verify_claim_async(ingredient, asset_bytes, false, validation_log)
                        .await?;
                } else {
                    let log_item = log_item!(
                        &c2pa_manifest.url(),
                        "ingredient not found",
                        "ingredient_checks_async"
                    )
                    .error(Error::ClaimVerification(format!(
                        "ingredient: {} is missing",
                        label
                    )))
                    .validation_status(validation_status::CLAIM_MISSING);
                    validation_log.log(
                        log_item,
                        Some(Error::ClaimVerification(format!(
                            "ingredient: {} is missing",
                            label
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
        xmp_opt: Option<String>,
        asset_bytes: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let claim = Store::provenance_checks(store, xmp_opt, validation_log)?;

        // verify the provenance claim
        Claim::verify_claim_async(claim, asset_bytes, true, validation_log).await?;

        Store::ingredient_checks_async(store, claim, asset_bytes, validation_log).await?;

        Ok(())
    }

    /// Verify Store
    /// store: Store to validate
    /// xmp_str: String containing entire XMP block of the asset
    /// asset_bytes: bytes of the asset to be verified
    /// validation_log: If present all found errors are logged and returned, other wise first error causes exit and is returned  
    pub fn verify_store(
        store: &Store,
        xmp_opt: Option<String>,
        asset_bytes: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let claim = Store::provenance_checks(store, xmp_opt, validation_log)?;

        // verify the provenance claim
        Claim::verify_claim(claim, asset_bytes, true, validation_log)?;

        Store::ingredient_checks(store, claim, asset_bytes, validation_log)?;

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
        if block_locations.is_empty() {
            return Err(Error::BadParam(
                "No asset hash locations specified".to_owned(),
            ));
        }

        let metadata = asset_path.metadata().map_err(crate::error::wrap_io_err)?;
        let file_len: u64 = metadata.len();
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

        if block_end as u64 > file_len {
            return Err(Error::BadParam(
                "data hash exclusions out of range".to_string(),
            ));
        }

        if found_jumbf {
            // add exclusion hash for bytes before and after jumbf
            let mut dh = DataHash::new("jumbf manifest", alg, None);
            dh.add_exclusion(Exclusion::new(block_start, block_end - block_start));
            if calc_hashes {
                dh.gen_hash(asset_path)?;
            } else {
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

    /// Embed the claims store as jumbf into an asset. Updates XMP with provenance record.
    #[cfg(feature = "file_io")]
    pub fn save_to_asset(
        &mut self,
        asset_path: &Path,
        signer: &dyn Signer,
        output_path: &Path,
    ) -> Result<()> {
        let jumbf_bytes = self.start_save(asset_path, output_path, signer.reserve_size())?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self.sign_claim(pc, signer, signer.reserve_size())?;
        let sig_placeholder = self.sign_claim_placeholder(pc, signer.reserve_size());

        match self.finish_save(jumbf_bytes, output_path, sig, &sig_placeholder) {
            Ok(v) => {
                // save sig so store is up to date
                let pc_mut = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc_mut.set_signature_val(v);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Embed the claims store as jumbf into an asset using an async signer. Updates XMP with provenance record.
    #[cfg(feature = "async_signer")]
    pub async fn save_to_asset_async(
        &mut self,
        asset_path: &Path,
        signer: &dyn AsyncSigner,
        output_path: &Path,
    ) -> Result<()> {
        let jumbf_bytes = self.start_save(asset_path, output_path, signer.reserve_size())?;

        let pc = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let sig = self.sign_claim_async(pc, signer).await?;
        let sig_placeholder = self.sign_claim_placeholder(pc, signer.reserve_size());

        match self.finish_save(jumbf_bytes, output_path, sig, &sig_placeholder) {
            Ok(v) => {
                // save sig so store is up to date
                let pc_mut = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
                pc_mut.set_signature_val(v);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(feature = "file_io")]
    fn start_save(
        &mut self,
        asset_path: &Path,
        output_path: &Path,
        reserve_size: usize,
    ) -> Result<Vec<u8>> {
        // clone the source to working copy if requested
        get_supported_file_extension(asset_path).ok_or(Error::UnsupportedType)?; // verify extensions
        let _ext = get_supported_file_extension(output_path).ok_or(Error::UnsupportedType)?;
        if asset_path != output_path {
            fs::copy(&asset_path, &output_path).map_err(Error::IoError)?;
        }

        // get the provenance claim
        let pp = self.provenance_path();
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        //  update file following the steps outlined in CAI spec

        // 1) Add DC provenance XMP
        // update XMP info & add xmp hash to provenance claim
        if let Some(provenance) = pp {
            embedded_xmp::add_manifest_uri_to_file(output_path, &provenance)
                .map_err(|_err| Error::XmpWriteError)?;
        } else {
            return Err(Error::XmpWriteError);
        }

        // 2) Get hash ranges if needed, do not generate for update manifests
        let mut hash_ranges = object_locations(output_path)?;
        let hashes: Vec<DataHash> = if pc.update_manifest() {
            Vec::new()
        } else {
            Store::generate_data_hashes(output_path, pc.alg(), &mut hash_ranges, false)?
        };

        // add the placeholder data hashes to provenance claim so that the required space is reserved
        for mut hash in hashes {
            // add padding to account for possible cbor expansion of final DataHash
            let padding: Vec<u8> = vec![0x0; 10];
            hash.add_padding(padding);

            pc.add_assertion(&hash)?;
        }

        // 3) Generate in memory CAI jumbf block
        // and write preliminary jumbf store to file
        // source and dest the same so save_jumbf_to_file will use the same file since we have already cloned
        let mut data = self.to_jumbf_internal(reserve_size)?;
        let jumbf_size = data.len();
        save_jumbf_to_file(&data, output_path, Some(output_path))?;

        // 4)  determine final object locations and patch the asset hashes with correct offset
        // replace the source with correct asset hashes so that the claim hash will be correct
        let pc = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;

        // get the final hash ranges, but not for update manifests
        let mut new_hash_ranges = object_locations(output_path)?;
        let updated_hashes = if pc.update_manifest() {
            Vec::new()
        } else {
            Store::generate_data_hashes(output_path, pc.alg(), &mut new_hash_ranges, true)?
        };

        // patch existing claim hash with updated data
        for mut hash in updated_hashes {
            hash.gen_hash(output_path)?; // generate
            pc.update_data_hash(hash)?;
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
    ) -> Result<Vec<u8>> {
        if sig_placeholder.len() != sig.len() {
            return Err(Error::CoseSigboxTooSmall);
        }

        patch_bytes(&mut jumbf_bytes, sig_placeholder, &sig)
            .map_err(|_| Error::JumbfCreationError)?;

        // re-save to file
        save_jumbf_to_file(&jumbf_bytes, output_path, Some(output_path))?;

        Ok(sig)
    }

    /// Verify Store from an existing asset
    /// asset_path: path to input asset
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned  
    #[cfg(feature = "file_io")]
    pub fn verify_from_path(
        &mut self,
        asset_path: &Path,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let ext = get_supported_file_extension(asset_path).ok_or(Error::UnsupportedType)?;

        // load the bytes
        let buf = fs::read(asset_path).map_err(crate::error::wrap_io_err)?;

        self.verify_from_buffer(&buf, &ext, validation_log)
    }

    // verify from a buffer without file i/o
    pub fn verify_from_buffer(
        &mut self,
        buf: &[u8],
        asset_type: &str,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        let mut buf_reader = Cursor::new(buf);

        let cai_loader = get_cailoader_handler(asset_type).ok_or(Error::UnsupportedType)?;

        // read xmp if available
        let xmp_opt = cai_loader.read_xmp(&mut buf_reader);

        let xmp_copy = xmp_opt.clone();

        Store::verify_store(self, xmp_opt, buf_reader.get_ref(), validation_log)?;

        // set the provenance if there is xmp otherwise it will default to active manifest
        if let Some(xmp) = xmp_copy {
            if let Some(xmp_provenance) = extract_provenance(&xmp) {
                let claim_label = Store::manifest_label_from_path(&xmp_provenance);
                self.set_provenance_path(&claim_label);
            }
        }

        Ok(())
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
        load_cai_from_file(asset_path, validation_log)
            .and_then(|mut store| {
                // verify the store
                if verify {
                    store.verify_from_path(asset_path, validation_log)?;
                }

                Ok(store)
            })
            .map_err(|e| {
                let err = match e {
                    Error::PrereleaseError => Error::PrereleaseError,
                    Error::JumbfNotFound => Error::JumbfNotFound,
                    _ => Error::LogStop,
                };
                let log_item = log_item!("asset", "error loading file", "load_from_asset").error(e);
                validation_log.log_silent(log_item);
                err
            })
    }

    fn get_store_from_memory(
        asset_type: &str,
        data: &[u8],
        validation_log: &mut impl StatusTracker,
    ) -> Result<(Store, Option<String>)> {
        let cai_loader = get_cailoader_handler(asset_type).ok_or(Error::UnsupportedType)?;

        let mut buf_reader = Cursor::new(data);

        // check for xmp, error if not present
        let xmp = cai_loader.read_xmp(&mut buf_reader);

        // load jumbf if available
        load_cai_from_memory(asset_type, data, validation_log)
            .map(|store| (store, xmp))
            .map_err(|e| {
                let err = match e {
                    Error::PrereleaseError => Error::PrereleaseError,
                    Error::JumbfNotFound => Error::JumbfNotFound,
                    _ => Error::LogStop,
                };
                let log_item =
                    log_item!("asset", "error loading asset", "get_store_from_memory").error(e);
                validation_log.log_silent(log_item);
                err
            })
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
        Store::get_store_from_memory(asset_type, data, validation_log).and_then(
            |(mut store, xmp_opt)| {
                let buf_reader = Cursor::new(data);

                // verify the store
                if verify {
                    let xmp_copy = xmp_opt.clone();

                    // verify store and claims
                    Store::verify_store(&store, xmp_opt, buf_reader.get_ref(), validation_log)?;

                    // set the provenance if checks pass & has xmp, otherwise default to active manifest
                    if let Some(xmp) = xmp_copy {
                        if let Some(xmp_provenance) = extract_provenance(&xmp) {
                            let claim_label = Store::manifest_label_from_path(&xmp_provenance);
                            store.set_provenance_path(&claim_label);
                        }
                    }
                }

                Ok(store)
            },
        )
    }

    /// Load Store from a in-memory asset asychronously validating
    /// asset_type: asset extension or mime type
    /// data: reference to bytes of the the file
    /// verify: if true will run verification checks when loading
    /// validation_log: If present all found errors are logged and returned, otherwise first error causes exit and is returned
    pub async fn load_from_memory_async(
        asset_type: &str,
        data: &[u8],
        verify: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<Store> {
        let (mut store, xmp_opt) = Store::get_store_from_memory(asset_type, data, validation_log)?;

        let buf_reader = Cursor::new(data);

        // verify the store
        if verify {
            let xmp_copy = xmp_opt.clone();

            // verify store and claims
            Store::verify_store_async(&store, xmp_opt, buf_reader.get_ref(), validation_log)
                .await?;

            // set the provenance if checks pass & has xmp, otherwise default to active manifest
            if let Some(xmp) = xmp_copy {
                if let Some(xmp_provenance) = extract_provenance(&xmp) {
                    let claim_label = Store::manifest_label_from_path(&xmp_provenance);
                    store.set_provenance_path(&claim_label);
                }
            }
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
    ) -> Result<()> {
        let mut report = OneShotStatusTracker::new();
        let store = Store::from_jumbf(data, &mut report)?;
        claim.add_ingredient_data(provenance_label, store.claims, redactions)
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

    use super::*;

    use tempfile::tempdir;
    use thiserror::private::PathAsDisplay;
    use twoway::find_bytes;

    use crate::{
        assertions::{Action, Actions, Ingredient, Uuid},
        claim::Claim,
        jumbf_io::{load_jumbf_from_file, save_jumbf_to_file},
        status_tracker::*,
        utils::test::{create_test_claim, fixture_path, temp_dir_path, temp_fixture_path},
    };

    use crate::{
        claim::AssertionStoreJsonFormat, jumbf_io::update_file_jumbf,
        openssl::temp_signer::get_temp_signer, utils::patch::patch_file,
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
        let temp_dir = tempdir().unwrap();
        let (signer, _) = get_temp_signer(&temp_dir.path());

        // Test generate JUMBF
        // Get labels for label test
        let claim1_label = claim1.label().to_string();
        let capture = claim_capture.label().to_string();
        let claim2_label = claim2.label().to_string();

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commmits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, &signer, &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, &signer, &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, &signer, &op).unwrap();

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

    struct BadSigner {}

    impl crate::Signer for BadSigner {
        fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
            Ok(b"not a valid signature".to_vec())
        }

        fn alg(&self) -> Option<String> {
            None
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
        use crate::{openssl::RsaSigner, signer::ConfigurableSigner};

        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "test-image-expired-cert.jpg");

        let mut store = Store::new();

        let claim = create_test_claim().unwrap();

        let signcert_path = fixture_path("rsa-pss256_key-expired.pub");
        let pkey_path = fixture_path("rsa-pss256-expired.pem");
        let signer =
            RsaSigner::from_files(signcert_path, pkey_path, "ps256".to_string(), None).unwrap();

        store.commit_claim(claim).unwrap();

        // JUMBF generation should fail because the certificate won't validate.
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
        assert!(find_bytes(&buf, &original_jumbf[0..1024]).is_none());
    }

    /*  async signing not supported at the moment
        NOTE: Add this to Cargo.toml if this test is restored.

        [target.'cfg(not(target_arch = "wasm32"))'.dev-dependencies]
        actix = "0.11.0"

        #[cfg(feature = "async_signer")]
        #[actix::test]
        async fn test_jumbf_generation_async() {
            let signer = crate::AsyncPlaceholder {};

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

            /*
            Move the claim to claims list. Note this is not real, the claims would have to be signed in between commits
            */
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

            // read from new file
            let mut report: Vec<ValidationItem> = Vec::new();
            let new_store = Store::load_from_asset(&op, true, Some(&mut report)).unwrap();
            // Async placeholder signature won't verify. We need the load to complete,
            // but we ignore the validation log which we know will have errors.

            let claim = new_store.provenance_claim().unwrap();
            let sig = claim.signature_val();

            assert_eq!(&sig[0..19], b"invalid signature\0\0");
        }
    */
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
        let temp_dir = tempdir().unwrap();
        let (signer, _) = get_temp_signer(&temp_dir.path());

        // Move the claim to claims list. Note this is not real, the claims would have to be signed in between commmits
        store.commit_claim(claim1).unwrap();
        store.save_to_asset(&ap, &signer, &op).unwrap();
        store.commit_claim(claim_capture).unwrap();
        store.save_to_asset(&op, &signer, &op).unwrap();
        store.commit_claim(claim2).unwrap();
        store.save_to_asset(&op, &signer, &op).unwrap();

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
    fn test_unsupported_type() {
        // test bad xmp
        let ap = fixture_path("Purple Square.psd");
        let mut report = DetailedStatusTracker::new();
        let _r = Store::load_from_asset(&ap, true, &mut report);

        println!("Error report for {}: {:?}", ap.as_display(), report);
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
        println!("Error report for {}: {:?}", ap.as_display(), report);
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
        println!("Error report for {}: {:?}", ap.as_display(), report);
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

        println!(
            "Error report for {}: {:?}",
            ap.as_display(),
            report.get_log()
        );
        assert!(!report.get_log().is_empty());
        let errors = report_split_errors(report.get_log_mut());
        assert!(matches!(
            errors[0].err_val.as_ref(),
            Some(Error::IoError(_err))
        ));
    }

    #[test]
    fn test_old_manifest() {
        let ap = fixture_path("prerelease.jpg");
        let mut report = DetailedStatusTracker::new();
        let _r = Store::load_from_asset(&ap, true, &mut report);

        println!(
            "Error report for {}: {:?}",
            ap.as_display(),
            report.get_log()
        );
        assert!(!report.get_log().is_empty());
        let errors = report_split_errors(report.get_log_mut());
        assert!(matches!(
            errors[0].err_val.as_ref(),
            Some(Error::PrereleaseError)
        ));
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_verifiable_credentials() {
        use crate::utils::test::create_test_store;

        let temp_dir = tempdir().unwrap();
        let (signer, _) = get_temp_signer(&temp_dir.path());

        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "update_manifest.jpg");

        // get default store with default claim
        let mut store = create_test_store().unwrap();

        // save to output
        store
            .save_to_asset(ap.as_path(), &signer, op.as_path())
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
        println!("report: {:?}", report);
        report
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_update_manifest() {
        use crate::{hashed_uri::HashedUri, utils::test::create_test_store};

        let temp_dir = tempdir().unwrap();
        let (signer, _) = get_temp_signer(&temp_dir.path());

        // test adding to actual image
        let ap = fixture_path("earth_apollo17.jpg");
        let temp_dir = tempdir().expect("temp dir");
        let op = temp_dir_path(&temp_dir, "update_manifest.jpg");

        // get default store with default claim
        let mut store = create_test_store().unwrap();

        // save to output
        store
            .save_to_asset(ap.as_path(), &signer, op.as_path())
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
            .save_to_asset(op.as_path(), &signer, op.as_path())
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
        assert!(matches!(
            report.get_log()[0].err_val,
            Some(Error::ClaimDecoding)
        ));
        //assert_eq!(report[0].validation_status.as_deref(), Some(???));  // what validation status should we have for this?
    }

    #[test]
    fn test_modify_xmp() {
        // modify the XMP (change xmp magic id value) - this should cause a data hash mismatch (OTGP)
        let mut report = patch_and_report(
            "C.jpg",
            b"W5M0MpCehiHzreSzNTczkc9d",
            b"W5M0MpCehiHzreSzNTczkXXX",
        );
        assert!(!report.get_log().is_empty());
        let errors = report_split_errors(report.get_log_mut());

        assert!(matches!(errors[0].err_val, Some(Error::HashMismatch(_))));
        assert_eq!(
            errors[0].validation_status.as_deref(),
            Some(validation_status::ASSERTION_DATAHASH_MISMATCH)
        ); // what validation status should we have for this?
    }

    #[test]
    fn test_claim_modified() {
        // replace the title that is inside the claim data - should cause signature to not match
        let mut report = patch_and_report("C.jpg", b"C.jpg", b"X.jpg");
        assert!(!report.get_log().is_empty());
        let errors = report_split_errors(report.get_log_mut());

        assert!(report_has_err(&errors, Error::CoseSignature));
        assert!(report_has_err(&errors, Error::CoseTimeStampMismatch));

        assert!(report_has_status(
            &errors,
            validation_status::CLAIM_SIGNATURE_MISMATCH
        ));
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

    /* enable when we enable OCSP validation
    #[test]
    #[cfg(feature = "file_io")]
    fn test_ocsp() {
        let ap = fixture_path("ocsp_test.png");
        let mut report = DetailedStatusTracker::new();
        let _r = Store::load_from_asset(&ap, true, &mut report);

        println!(
            "Error report for {}: {:?}",
            ap.as_display(),
            report.get_log()
        );
        assert!(report.get_log().is_empty());
    }
    */

    #[test]
    fn test_display() {
        let ap = fixture_path("CA.jpg");
        let mut report = DetailedStatusTracker::new();
        let store = Store::load_from_asset(&ap, true, &mut report).expect("load_from_asset");
        println!("store = {}", store);
    }
}
