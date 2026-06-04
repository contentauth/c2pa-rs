// Copyright 2022 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::{collections::HashMap, io::Cursor};

use c2pa_claim::{
    assertion::{Assertion, AssertionData},
    Claim,
};

use crate::{
    error::{Error, Result},
    jumbf::boxes::{
        BMFFBox, BoxReader, CAIAssertionStore, CAICBORAssertionBox, CAIClaimBox,
        CAIJSONAssertionBox, CAIManifest, CAISignatureBox, CAIUUIDAssertionBox, Cai,
        JUMBFCBORContentBox, JumbfEmbeddedFileBox, JumbfParseError, ManifestType,
        CAI_ASSERTION_STORE_UUID, CAI_BLOCK_UUID, CAI_CBOR_ASSERTION_UUID, CAI_CLAIM_UUID,
        CAI_EMBEDDED_FILE_UUID, CAI_JSON_ASSERTION_UUID, CAI_MANIFEST_UUID, CAI_SIGNATURE_UUID,
        CAI_UPDATE_MANIFEST_UUID,
    },
};

/// A manifest store: an ordered collection of C2PA manifests with JUMBF I/O.
///
/// Each manifest is a [`c2pa_claim::Claim`] that holds assertions and a
/// signature. The store converts between its in-memory representation and raw
/// JUMBF bytes without touching asset streams or files.
pub struct Store {
    claims_map: HashMap<String, Claim>,
    /// Ordered list of claim labels (preserves JUMBF order).
    claims: Vec<String>,
    provenance_path: Option<String>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Store {
            claims_map: HashMap::new(),
            claims: Vec::new(),
            provenance_path: None,
        }
    }

    // ---- claim management ----

    /// Add a claim to the store. The claim becomes the new active (provenance) manifest.
    pub fn commit_claim(&mut self, claim: Claim) -> Result<String> {
        let label = claim.label().to_string();
        self.claims_map.insert(label.clone(), claim);
        self.claims.push(label.clone());
        self.provenance_path = Some(label.clone());
        Ok(label)
    }

    pub fn get_claim(&self, label: &str) -> Option<&Claim> {
        self.claims_map.get(label)
    }

    pub fn get_claim_mut(&mut self, label: &str) -> Option<&mut Claim> {
        self.claims_map.get_mut(label)
    }

    pub fn claims(&self) -> Vec<&Claim> {
        self.claims
            .iter()
            .filter_map(|l| self.claims_map.get(l))
            .collect()
    }

    pub fn provenance_claim(&self) -> Option<&Claim> {
        self.claims_map.get(self.provenance_path.as_deref()?)
    }

    pub fn provenance_claim_mut(&mut self) -> Option<&mut Claim> {
        // Clone avoids a simultaneous borrow of provenance_path and claims_map.
        let label = self.provenance_path.clone()?;
        self.claims_map.get_mut(&label)
    }

    pub fn provenance_label(&self) -> Option<&str> {
        self.provenance_path.as_deref()
    }

    // ---- ingredient manifests ----

    /// Add ingredient manifests from a re-serialised JUMBF byte slice.
    ///
    /// All claims parsed from `bytes` are inserted into the store **before**
    /// any subsequently committed claims, so the final JUMBF order is
    /// `[ingredient_claims…, active_manifest]` as required by the C2PA spec.
    ///
    /// Call this **before** [`commit_claim`] for the active manifest.
    ///
    /// # Phase 2 TODO
    /// Port conflict resolution (label versioning, redaction merging) from
    /// `sdk/src/store.rs::load_ingredient_to_claim`.
    pub fn add_ingredient_manifests(&mut self, bytes: &[u8]) -> Result<()> {
        let ingredient_store = Store::from_jumbf(bytes)?;
        for claim in ingredient_store.claims() {
            let label = claim.label().to_string();
            if !self.claims_map.contains_key(&label) {
                self.claims.push(label.clone());
            }
            self.claims_map.insert(label, claim.clone());
        }
        Ok(())
    }

    // ---- JUMBF serialization ----

    /// Serialize the store to raw JUMBF bytes.
    ///
    /// Unsigned claims produce a small placeholder in the signature box.
    /// For size-stable manifests (embedded workflow) use
    /// [`to_jumbf_with_reserve`] so the placeholder matches the real
    /// signature size.
    pub fn to_jumbf(&self) -> Result<Vec<u8>> {
        self.to_jumbf_with_reserve(0)
    }

    /// Serialize the store to raw JUMBF bytes, reserving `min_sig_size` bytes
    /// for each unsigned claim's signature box.
    ///
    /// ## Embedded-manifest workflow
    ///
    /// Call this with `signer.reserve_size()` to produce a placeholder JUMBF
    /// whose signature box is exactly the same size as the final signed one.
    /// Embed that placeholder in the asset, compute the hard-binding hash
    /// over the asset (with the placeholder in place), update the claim's hash
    /// assertion via [`Claim::replace_assertion`], set the real COSE bytes via
    /// [`Claim::set_signature_val`], then call `to_jumbf_with_reserve` again
    /// with the same `min_sig_size` to produce the final JUMBF.
    pub fn to_jumbf_with_reserve(&self, min_sig_size: usize) -> Result<Vec<u8>> {
        let mut cai_block = Cai::new();

        for claim in self.claims() {
            let manifest_box = build_manifest_box(claim, min_sig_size)?;
            cai_block.add_box(Box::new(manifest_box));
        }

        let mut out = Vec::new();
        cai_block
            .write_box(&mut out)
            .map_err(|e| Error::Jumbf(JumbfParseError::IoError(e)))?;

        Ok(out)
    }

    /// Deserialize a store from raw JUMBF bytes.
    ///
    /// Signatures and hash bindings are **not** verified here. Call a
    /// separate verifier with the asset bytes for full validation.
    pub fn from_jumbf(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::Jumbf(JumbfParseError::UnexpectedEof));
        }

        let mut reader = Cursor::new(bytes);
        let super_box = BoxReader::read_super_box(&mut reader)?;
        let cai_block = Cai::from(super_box);

        let block_uuid = cai_block.desc_box().uuid();
        if block_uuid != CAI_BLOCK_UUID {
            return Err(Error::UnexpectedBlockUuid(block_uuid));
        }

        let mut store = Store::new();

        for idx in 0..cai_block.data_box_count() {
            let sbox = cai_block
                .data_box_as_superbox(idx)
                .ok_or(JumbfParseError::InvalidJumbBox)?;

            let manifest_box = CAIManifest::from(sbox)?;
            let manifest_sbox = manifest_box.super_box();
            let manifest_uuid = manifest_sbox.desc_box().uuid();

            if manifest_uuid != CAI_MANIFEST_UUID && manifest_uuid != CAI_UPDATE_MANIFEST_UUID {
                continue;
            }

            let manifest_label = manifest_sbox.desc_box().label();

            let mut claim_cbor: Option<Vec<u8>> = None;
            let mut sig_data: Vec<u8> = Vec::new();

            // First pass: extract claim CBOR and signature
            for i in 0..manifest_sbox.data_box_count() {
                let child = manifest_sbox
                    .data_box_as_superbox(i)
                    .ok_or(JumbfParseError::InvalidJumbBox)?;
                let child_uuid = child.desc_box().uuid();

                if child_uuid == CAI_CLAIM_UUID {
                    if let Some(cbor_box) = child.data_box_as_cbor_box(0) {
                        claim_cbor = Some(cbor_box.cbor().clone());
                    }
                } else if child_uuid == CAI_SIGNATURE_UUID {
                    if let Some(cbor_box) = child.data_box_as_cbor_box(0) {
                        sig_data = cbor_box.cbor().clone();
                    }
                }
            }

            let cbor = claim_cbor.ok_or(Error::ClaimMissing)?;
            let mut claim = Claim::from_data(&manifest_label, &cbor)?;
            claim.set_signature_val(sig_data);

            // Second pass: load assertions
            for i in 0..manifest_sbox.data_box_count() {
                let child = manifest_sbox
                    .data_box_as_superbox(i)
                    .ok_or(JumbfParseError::InvalidJumbBox)?;

                if child.desc_box().uuid() != CAI_ASSERTION_STORE_UUID {
                    continue;
                }

                for j in 0..child.data_box_count() {
                    let a_box = match child.data_box_as_superbox(j) {
                        Some(b) => b,
                        None => continue,
                    };
                    let a_label = a_box.desc_box().label();
                    let a_uuid = a_box.desc_box().uuid();

                    let assertion = if a_uuid == CAI_CBOR_ASSERTION_UUID {
                        a_box
                            .data_box_as_cbor_box(0)
                            .map(|b| Assertion::from_data_cbor(&a_label, b.cbor()))
                    } else if a_uuid == CAI_JSON_ASSERTION_UUID {
                        a_box
                            .data_box_as_json_box(0)
                            .and_then(|b| Assertion::from_data_json(&a_label, b.json()).ok())
                    } else if a_uuid == CAI_EMBEDDED_FILE_UUID {
                        let media_type = a_box
                            .data_box_as_embedded_media_type_box(0)
                            .map(|b| b.media_type())
                            .unwrap_or_default();
                        a_box
                            .data_box_as_embedded_file_content_box(1)
                            .map(|b| Assertion::from_data_binary(&a_label, &media_type, b.data()))
                    } else {
                        None
                    };

                    if let Some(mut a) = assertion {
                        if let Some(salt) = a_box.desc_box().get_salt() {
                            a.set_salt(salt);
                        }
                        claim.restore_assertion(a);
                    }
                }
            }

            store.insert_claim(claim);
        }

        Ok(store)
    }

    // ---- internal ----

    fn insert_claim(&mut self, claim: Claim) {
        let label = claim.label().to_string();
        self.provenance_path = Some(label.clone());
        self.claims_map.insert(label.clone(), claim);
        self.claims.push(label);
    }
}

// ---- JUMBF writing helpers (ported from sdk/src/store.rs) ----

fn build_manifest_box(claim: &Claim, min_sig_size: usize) -> Result<CAIManifest> {
    let label = claim.label();
    let mut manifest = CAIManifest::new(label, ManifestType::Manifest, false);

    // 1. Assertion store
    let mut a_store = CAIAssertionStore::new();
    for assertion in claim.assertions() {
        add_assertion_to_jumbf_store(&mut a_store, assertion)?;
    }
    manifest.add_box(Box::new(a_store));

    // 2. Claim CBOR box
    let mut cb = CAIClaimBox::new(claim.version());
    let claim_cbor = claim.data()?;
    cb.add_claim(Box::new(JUMBFCBORContentBox::new(claim_cbor)));
    manifest.add_box(Box::new(cb));

    // 3. Signature box — real sig bytes if already signed, else a placeholder
    //    sized to max(placeholder_str, min_sig_size) so the JUMBF stays the
    //    same size between the placeholder and signed passes.
    let mut sigb = CAISignatureBox::new();
    let sig_bytes = if !claim.signature_val().is_empty() {
        claim.signature_val().to_vec()
    } else {
        let mut ph = format!("signature placeholder:{}", label).into_bytes();
        ph.resize(ph.len().max(min_sig_size), 0);
        ph
    };
    sigb.add_signature(Box::new(JUMBFCBORContentBox::new(sig_bytes)));
    manifest.add_box(Box::new(sigb));

    Ok(manifest)
}

fn add_assertion_to_jumbf_store(
    store: &mut CAIAssertionStore,
    assertion: &Assertion,
) -> Result<()> {
    let label = assertion.label();
    match assertion.decode_data() {
        AssertionData::Json(_) => {
            let mut json_box = CAIJSONAssertionBox::new(&label);
            json_box.add_json(assertion.data().to_vec());
            if let Some(salt) = assertion.salt() {
                json_box.set_salt(salt.clone()).map_err(Error::Jumbf)?;
            }
            store.add_assertion(Box::new(json_box));
        }
        AssertionData::Cbor(_) => {
            let mut cbor_box = CAICBORAssertionBox::new(&label);
            cbor_box.add_cbor(assertion.data().to_vec());
            if let Some(salt) = assertion.salt() {
                cbor_box.set_salt(salt.clone()).map_err(Error::Jumbf)?;
            }
            store.add_assertion(Box::new(cbor_box));
        }
        AssertionData::Binary(_) => {
            let mut file_box = JumbfEmbeddedFileBox::new(&label);
            file_box.add_data(
                assertion.data().to_vec(),
                assertion.content_type().to_string(),
                None,
            );
            store.add_assertion(Box::new(file_box));
        }
        AssertionData::Uuid(uuid_str, _) => {
            let mut uuid_box = CAIUUIDAssertionBox::new(&label);
            uuid_box
                .add_uuid(uuid_str, assertion.data().to_vec())
                .map_err(Error::Jumbf)?;
            store.add_assertion(Box::new(uuid_box));
        }
    }
    Ok(())
}
