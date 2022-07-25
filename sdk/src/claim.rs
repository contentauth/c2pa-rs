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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use uuid::Uuid;

use crate::assertion::{
    get_thumbnail_image_type, get_thumbnail_instance, get_thumbnail_type, Assertion, AssertionBase,
    AssertionData,
};
use crate::assertions::{self, labels, BmffHash, DataHash};
use crate::cose_validator::{get_signing_info, verify_cose, verify_cose_async};
use crate::hashed_uri::HashedUri;
use crate::jumbf::{
    self,
    boxes::{CAICBORAssertionBox, CAIJSONAssertionBox, CAIUUIDAssertionBox, JumbfEmbeddedFileBox},
};
use crate::salt::{SaltGenerator, NO_SALT};
use crate::utils::hash_utils::{hash_by_alg, vec_compare, verify_by_alg};

use crate::error::{Error, Result};
use crate::status_tracker::{log_item, OneShotStatusTracker, StatusTracker};
use crate::validation_status;
use crate::validator::ValidationInfo;

const BUILD_HASH_ALG: &str = "sha256";

/// JSON structure representing an Assertion reference in a Claim's "assertions" list
use HashedUri as C2PAAssertion;

const GH_FULL_VERSION_LIST: &str = "Sec-CH-UA-Full-Version-List";
const GH_UA: &str = "Sec-CH-UA";

pub enum ClaimAssetData<'a> {
    PathData(&'a Path),
    ByteData(&'a [u8]),
}

#[derive(PartialEq, Clone)]
// helper struct to allow arbitrary order for assertions stored in jumbf.  The instance is
// stored separate from the Assertion to allow for late binding to the label.  Also,
// we can load assertions in any order and know the position without re-parsing label. We also
// save on parsing the cbor assertion each time we need its contents
pub struct ClaimAssertion {
    assertion: Assertion,
    instance: usize,
    hash_val: Vec<u8>,
    hash_alg: String,
    salt: Option<Vec<u8>>,
}

impl ClaimAssertion {
    pub fn new(
        assertion: Assertion,
        instance: usize,
        hashval: &[u8],
        alg: &str,
        salt: Option<Vec<u8>>,
    ) -> ClaimAssertion {
        ClaimAssertion {
            assertion,
            instance,
            hash_val: hashval.to_vec(),
            hash_alg: alg.to_string(),
            salt,
        }
    }

    pub fn update_assertion(&mut self, assertion: Assertion, hash: Vec<u8>) -> Result<()> {
        self.hash_val = hash;
        self.assertion = assertion;
        Ok(())
    }

    pub fn label(&self) -> String {
        let al_ref = self.assertion.label();
        if self.instance > 0 {
            if get_thumbnail_type(&al_ref) == labels::INGREDIENT_THUMBNAIL {
                format!(
                    "{}__{}.{}",
                    get_thumbnail_type(&al_ref),
                    self.instance,
                    get_thumbnail_image_type(&al_ref)
                )
            } else {
                format!("{}__{}", al_ref, self.instance)
            }
        } else {
            self.assertion.label()
        }
    }

    pub fn instance(&self) -> usize {
        self.instance
    }

    pub fn instance_string(&self) -> String {
        format!("{}", self.instance)
    }

    pub fn label_raw(&self) -> String {
        self.assertion.label()
    }

    pub fn assertion(&self) -> &Assertion {
        &self.assertion
    }

    pub fn hash(&self) -> &[u8] {
        &self.hash_val
    }

    pub fn salt(&self) -> &Option<Vec<u8>> {
        &self.salt
    }

    pub fn hash_alg(&self) -> &str {
        &self.hash_alg
    }

    /// returns true if assertions are of the same enum variant
    pub fn is_same_type(&self, input_assertion: &Assertion) -> bool {
        Assertion::assertions_eq(&self.assertion, input_assertion)
    }
}

impl fmt::Debug for ClaimAssertion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}, instance: {}", self.assertion, self.instance)
    }
}
/// A `Claim` gathers together all the `Assertion`s about an asset
/// from an actor at a given time, and may also include one or more
/// hashes of the asset itself, and a reference to the previous `Claim`.
///
/// It has all the same properties as an `Assertion` including being
/// assigned a label (`c2pa.claim.v1`) and being either embedded into the
/// asset or in the cloud. The claim is cryptographically hashed and
/// that hash is signed to produce the claim signature.
#[derive(Deserialize, Serialize, Debug, PartialEq, Clone)]
pub struct Claim {
    // root of CAI store
    #[serde(skip_deserializing, skip_serializing)]
    update_manifest: bool,

    #[serde(skip_serializing_if = "Option::is_none", rename = "dc:title")]
    pub title: Option<String>, // title for this claim, generally the name of the containing asset

    #[serde(rename = "dc:format")]
    pub format: String, // mime format of document containing this claim

    #[serde(rename = "instanceID")]
    pub instance_id: String, // instance Id of document containing this claim

    // Internal list of ingredients
    #[serde(skip_deserializing, skip_serializing)]
    ingredients_store: HashMap<String, Vec<Claim>>,

    // internal scratch objects
    #[serde(skip_deserializing, skip_serializing)]
    box_prefix: String, // where in JUMBF heirachy should this claim exist

    #[serde(skip_deserializing, skip_serializing)]
    signature_val: Vec<u8>, // the signature of the loaded/saved claim

    // root of CAI store
    #[serde(skip_deserializing, skip_serializing)]
    root: String,

    // internal scratch objects
    #[serde(skip_deserializing, skip_serializing)]
    label: String, // label of claim

    // Internal list of assertions for claim.
    // These are serialized manually based on need.
    #[serde(skip_deserializing, skip_serializing)]
    assertion_store: Vec<ClaimAssertion>,

    // Internal list of verifiable credentials for claim.
    // These are serialized manually based on need.
    #[serde(skip_deserializing, skip_serializing)]
    vc_store: Vec<AssertionData>,

    claim_generator: String, // generator of this claim

    signature: String,              // link to signature box
    assertions: Vec<C2PAAssertion>, // list of assertion hashed URIs

    // original JSON bytes of claim; only present when reading from asset
    #[serde(skip_deserializing, skip_serializing)]
    original_bytes: Option<Vec<u8>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    redacted_assertions: Option<Vec<String>>, // list of redacted assertions

    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>, // hashing algorithm (default to Sha256)

    #[serde(skip_serializing_if = "Option::is_none")]
    alg_soft: Option<String>, // hashing algorithm for soft bindings

    #[serde(skip_serializing_if = "Option::is_none")]
    claim_generator_hints: Option<HashMap<String, Value>>,
}

/// Enum to define how assertions are are stored when output to json
pub enum AssertionStoreJsonFormat {
    None,                // no assertion store
    KeyValue,            // key (uri), value (Assertion json object)
    KeyValueNoBinary,    // KeyValue omitting binary results
    OrderedList,         // list of Assertions as json objects
    OrderedListNoBinary, // list of Assertions as json objects omitting binaries results
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonOrderedAssertionData {
    label: String,
    data: Value,
    hash: String,
    is_binary: bool,
    mime_type: String,
}

impl Claim {
    /// Label prefix for a claim assertion.
    ///
    /// See <https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_overview_4>.
    pub const LABEL: &'static str = assertions::labels::CLAIM;

    /// Create a new claim.
    /// vendor: name used to label the claim (unique instance number is automatically calculated)
    /// claim_generator: User agent see c2pa spec for format
    // #[cfg(not(target_arch = "wasm32"))]
    pub fn new(claim_generator: &str, vendor: Option<&str>) -> Self {
        let urn = Uuid::new_v4();
        let l = match vendor {
            Some(v) => format!(
                "{}:{}",
                v.to_lowercase(),
                urn.to_urn().encode_lower(&mut Uuid::encode_buffer())
            ),
            None => urn
                .to_urn()
                .encode_lower(&mut Uuid::encode_buffer())
                .to_string(),
        };

        Claim {
            box_prefix: "self#jumbf".to_string(),
            root: jumbf::labels::MANIFEST_STORE.to_string(),
            signature_val: Vec::new(),
            ingredients_store: HashMap::new(),
            label: l,
            signature: "".to_string(),

            claim_generator: claim_generator.to_string(),
            assertion_store: Vec::new(),
            vc_store: Vec::new(),
            assertions: Vec::new(),
            original_bytes: None,
            redacted_assertions: None,
            alg: Some(BUILD_HASH_ALG.to_string()),
            alg_soft: None,
            claim_generator_hints: None,

            title: None,
            format: "".to_string(),
            instance_id: "".to_string(),

            update_manifest: false,
        }
    }

    /// Build a claim and verify its integrity.
    pub fn build(&mut self) -> Result<()> {
        // A claim must have a signature box.
        if self.signature.is_empty() {
            self.add_signature_box_link();
        }

        Ok(())
    }

    /// return version this claim supports
    pub fn build_version() -> &'static str {
        Self::LABEL
    }

    /// Return the JUMBF label for this claim.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the JUMBF URI for this claim.
    pub fn uri(&self) -> String {
        jumbf::labels::to_manifest_uri(&self.label)
    }

    /// Return the JUMBF URI for an assertion on this claim.
    pub fn assertion_uri(&self, assertion_label: &str) -> String {
        jumbf::labels::to_assertion_uri(&self.label, assertion_label)
    }

    /// Return the JUMBF Signature URI for this claim.
    pub fn signature_uri(&self) -> String {
        jumbf::labels::to_signature_uri(&self.label)
    }

    // Add link to the signature box for this claim.
    fn add_signature_box_link(&mut self) {
        self.signature = format!("{}={}", self.box_prefix, jumbf::labels::SIGNATURE);
    }

    ///  set signature of the claim
    pub(crate) fn set_signature_val(&mut self, signature: Vec<u8>) {
        self.signature_val = signature;
    }

    ///  get signature of the claim
    pub fn signature_val(&self) -> &Vec<u8> {
        &self.signature_val
    }

    /// get claim generator
    pub fn claim_generator(&self) -> &str {
        &self.claim_generator
    }

    /// get format
    pub fn format(&self) -> &str {
        &self.format
    }

    /// get instance_id
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// set title
    pub fn set_title(&mut self, title: Option<String>) {
        self.title = title;
    }

    /// get title
    pub fn title(&self) -> Option<&String> {
        self.title.as_ref()
    }

    /// get algorithm
    pub fn alg(&self) -> &str {
        match self.alg.as_ref() {
            Some(alg) => alg,
            None => BUILD_HASH_ALG,
        }
    }

    /// get soft algorithm
    pub fn alg_soft(&self) -> Option<&String> {
        self.alg_soft.as_ref()
    }

    /// Is this an update manifest
    pub fn update_manifest(&self) -> bool {
        self.update_manifest
    }

    pub(crate) fn set_update_manifest(&mut self, is_update_manifest: bool) {
        self.update_manifest = is_update_manifest;
    }
    pub fn add_claim_generator_hint(&mut self, hint_key: &str, hint_value: Value) {
        if self.claim_generator_hints.is_none() {
            self.claim_generator_hints = Some(HashMap::new());
        }

        if let Some(map) = &mut self.claim_generator_hints {
            // if the key is already there do we need to merge the new value, so get its value
            let curr_val = match hint_key {
                // keys where new values should be merges
                GH_UA | GH_FULL_VERSION_LIST => {
                    if let Some(curr_ch_ua) = map.get(hint_key) {
                        curr_ch_ua.as_str().map(|curr_val| curr_val.to_owned())
                    } else {
                        None
                    }
                }
                _ => None,
            };

            // had an existing value so merge
            if let Some(curr_val) = curr_val {
                if let Some(append_val) = hint_value.as_str() {
                    map.insert(
                        hint_key.to_string(),
                        Value::String(format!("{}, {}", curr_val, append_val)),
                    );
                }
                return;
            }

            // all other keys treat as replacement
            map.insert(hint_key.to_string(), hint_value);
        }
    }

    pub fn get_claim_generator_hint_map(&self) -> Option<&HashMap<String, Value>> {
        self.claim_generator_hints.as_ref()
    }

    pub fn calc_box_hash(
        label: &str,
        assertion: &Assertion,
        salt: Option<Vec<u8>>,
        alg: &str,
    ) -> Result<Vec<u8>> {
        // Grab assertion data object.
        let d = assertion.decode_data();

        let mut hash_bytes = Vec::with_capacity(2048);

        match d {
            AssertionData::Json(_) => {
                let mut json_data = CAIJSONAssertionBox::new(label);
                json_data.add_json(assertion.data().to_vec());
                if let Some(salt) = salt {
                    json_data.set_salt(salt)?;
                }
                json_data.super_box().write_box_payload(&mut hash_bytes)?;
            }
            AssertionData::Binary(_) => {
                // TODO: Handle other binary box types if needed.
                let mut data = JumbfEmbeddedFileBox::new(label);
                data.add_data(assertion.data().to_vec(), assertion.mime_type(), None);
                if let Some(salt) = salt {
                    data.set_salt(salt)?;
                }
                data.super_box().write_box_payload(&mut hash_bytes)?;
            }
            AssertionData::Cbor(_) => {
                let mut cbor_data = CAICBORAssertionBox::new(label);
                cbor_data.add_cbor(assertion.data().to_vec());
                if let Some(salt) = salt {
                    cbor_data.set_salt(salt)?;
                }
                cbor_data.super_box().write_box_payload(&mut hash_bytes)?;
            }
            AssertionData::Uuid(uuid_str, _) => {
                let mut data = CAIUUIDAssertionBox::new(label);
                data.add_uuid(uuid_str, assertion.data().to_vec())?;
                if let Some(salt) = salt {
                    data.set_salt(salt)?;
                }
                data.super_box().write_box_payload(&mut hash_bytes)?;
            }
        }

        Ok(hash_by_alg(alg, &hash_bytes, None))
    }

    /// Add an assertion to this claim and verify
    pub fn add_assertion(
        &mut self,
        assertion_builder: &impl AssertionBase,
    ) -> Result<C2PAAssertion> {
        self.add_assertion_with_salt(assertion_builder, NO_SALT)
    }

    /// Add an assertion to this claim and verify with a salted assertion store
    /// This version should be used if the assertion may be redacted for addition protection.
    pub fn add_assertion_with_salt(
        &mut self,
        assertion_builder: &impl AssertionBase,
        salt_generator: &impl SaltGenerator,
    ) -> Result<C2PAAssertion> {
        // make sure the assertion is valid
        let assertion = assertion_builder.to_assertion()?;

        // Update label if there are multiple instances of
        // the same claim type.
        let as_label = self.make_assertion_instance_label(assertion.label().as_ref());

        // Get salted hash of the assertion's contents.
        let salt = salt_generator.generate_salt();

        let hash = Claim::calc_box_hash(&as_label, &assertion, salt.clone(), self.alg())?;

        // Build hash link.
        let link = jumbf::labels::to_assertion_uri(self.label(), &as_label);
        let link_relative = jumbf::labels::to_relative_uri(&link);

        let c2pa_assertion = C2PAAssertion::new(link_relative, None, &hash);

        // Add to assertion store.
        let (_l, instance) = Claim::assertion_label_from_link(&as_label);
        let ca = ClaimAssertion::new(assertion, instance, &hash, self.alg(), salt);
        self.assertion_store.push(ca);
        self.assertions.push(c2pa_assertion.clone());

        Ok(c2pa_assertion)
    }

    pub(crate) fn vc_id(vc_json: &str) -> Result<String> {
        let vc: Value =
            serde_json::from_str(vc_json).map_err(|_err| Error::VerifiableCredentialInvalid)?; // check for json validity

        let credential_subject = vc
            .get("credentialSubject")
            .ok_or(Error::VerifiableCredentialInvalid)?;
        let id = credential_subject
            .get("id")
            .ok_or(Error::VerifiableCredentialInvalid)?
            .as_str()
            .ok_or(Error::VerifiableCredentialInvalid)?;

        Ok(id.to_string())
    }

    /// Add a verifiable credential to vc store and return a JUMBF URI
    /// the credential json must contain "credentialsSubject" object like:
    /// ```json
    /// "credentialSubject": {
    ///    "id": "did:nppa:eb1bb9934d9896a374c384521410c7f14",
    ///    "name": "Bob Ross",
    ///    "memberOf": "https://nppa.org/"
    ///    },
    /// ```
    // the "id" value will be used as the label in the vcstore
    pub fn add_verifiable_credential(&mut self, vc_json: &str) -> Result<HashedUri> {
        let id = Claim::vc_id(vc_json)?;

        let hash = hash_by_alg(self.alg(), vc_json.as_bytes(), None);

        let link = jumbf::labels::to_verifiable_credential_uri(self.label(), &id);

        let c2pa_assertion = C2PAAssertion::new(link, Some(self.alg().to_string()), &hash);

        // add credential to vcstore
        let credential = AssertionData::Json(vc_json.to_string());
        self.vc_store.push(credential);

        Ok(c2pa_assertion)
    }

    pub fn get_verifiable_credentials(&self) -> &Vec<AssertionData> {
        &self.vc_store
    }

    /// Add directly to store during a reload of a claim
    pub(crate) fn put_assertion_store(&mut self, assertion: ClaimAssertion) {
        self.assertion_store.push(assertion);
    }

    // crate private function to allow for patching a data hash with final contents
    #[cfg(feature = "file_io")]
    pub(crate) fn update_data_hash(&mut self, mut data_hash: DataHash) -> Result<()> {
        let mut replacement_assertion = data_hash.to_assertion()?;

        match self.assertion_store.iter_mut().find(|assertion| {
            // is this a DataHash Assertion
            if !Assertion::assertions_eq(&replacement_assertion, assertion.assertion()) {
                return false;
            }

            if let Ok(dh) = DataHash::from_assertion(assertion.assertion()) {
                dh.name == data_hash.name
            } else {
                false
            }
        }) {
            Some(ref mut dh_assertion) => {
                let original_hash = dh_assertion.hash().to_vec();
                let original_len = dh_assertion.assertion().data().len();
                data_hash.pad_to_size(original_len)?;
                replacement_assertion = data_hash.to_assertion()?;

                let replacement_hash = Claim::calc_box_hash(
                    &dh_assertion.label(),
                    &replacement_assertion,
                    dh_assertion.salt().clone(),
                    dh_assertion.hash_alg(),
                )?;
                dh_assertion.update_assertion(replacement_assertion, replacement_hash)?;

                // fix up hashed uri
                match self.assertions.iter_mut().find_map(|f| {
                    if f.url().contains(&dh_assertion.label())
                        && vec_compare(&f.hash(), &original_hash)
                    {
                        // replace with newly updated hash
                        f.update_hash(dh_assertion.hash().to_vec());
                        Some(f)
                    } else {
                        None
                    }
                }) {
                    Some(_) => Ok(()),
                    None => Err(Error::NotFound),
                }
            }
            None => Err(Error::NotFound),
        }
    }

    // crate private function to allow for patching a BMFF hash with final contents
    #[cfg(feature = "file_io")]
    pub(crate) fn update_bmff_hash(&mut self, bmff_hash: BmffHash) -> Result<()> {
        let replacement_assertion = bmff_hash.to_assertion()?;

        match self.assertion_store.iter_mut().find(|assertion| {
            // is this a BMFFHash Assertion
            Assertion::assertions_eq(&replacement_assertion, assertion.assertion())
        }) {
            Some(ref mut bmff_assertion) => {
                let original_hash = bmff_assertion.hash().to_vec();

                let replacement_hash = Claim::calc_box_hash(
                    &bmff_assertion.label(),
                    &replacement_assertion,
                    bmff_assertion.salt().clone(),
                    bmff_assertion.hash_alg(),
                )?;
                bmff_assertion.update_assertion(replacement_assertion, replacement_hash)?;

                // fix up hashed uri
                match self.assertions.iter_mut().find_map(|f| {
                    if f.url().contains(&bmff_assertion.label())
                        && vec_compare(&f.hash(), &original_hash)
                    {
                        // replace with newly updated hash
                        f.update_hash(bmff_assertion.hash().to_vec());
                        Some(f)
                    } else {
                        None
                    }
                }) {
                    Some(_) => Ok(()),
                    None => Err(Error::NotFound),
                }
            }
            None => Err(Error::NotFound),
        }
    }

    /// Not ready for use!!!!!
    /// Redact an assertion from a prior claim.
    /// This will remove the assertion from the JUMBF
    fn redact_assertion(&mut self, assertion_uri: &str) -> Result<()> {
        // cannot redact action assertions per the spec
        let (label, _instance) = Claim::assertion_label_from_link(assertion_uri);
        if label == assertions::labels::ACTIONS {
            return Err(Error::AssertionInvalidRedaction);
        }

        // delete assertion
        if let Some(index) = self
            .assertion_store
            .iter()
            .position(|x| assertion_uri.contains(&x.label()))
        {
            self.assertion_store.remove(index);
            Ok(())
        } else {
            Err(Error::AssertionInvalidRedaction)
        }
    }

    /// Return a hash of this claim.
    pub fn hash(&self) -> Vec<u8> {
        match self.data() {
            Ok(claim_data) => hash_by_alg(self.alg(), &claim_data, None),
            Err(_) => Vec::new(), //  should never happen bug if it does just give no hash
        }
    }

    /// Return the signing date and time for this claim, if there is one.
    pub fn signing_time(&self) -> Option<DateTime<Utc>> {
        if let Some(validation_data) = self.signature_info() {
            validation_data.date
        } else {
            None
        }
    }

    /// Return the signing date and time for this claim, if there is one.
    pub fn signing_issuer(&self) -> Option<String> {
        if let Some(validation_data) = self.signature_info() {
            validation_data.issuer_org
        } else {
            None
        }
    }

    /// Return information about the signature
    pub fn signature_info(&self) -> Option<ValidationInfo> {
        let sig = self.signature_val();
        let data = self.data().ok()?;
        let mut validation_log = OneShotStatusTracker::new();

        Some(get_signing_info(sig, &data, &mut validation_log))
    }

    /// Verify claim signature, assertion store and asset hashes
    /// claim - claim to be verified
    /// asset_bytes - reference to bytes of the asset
    pub async fn verify_claim_async<'a>(
        claim: &Claim,
        asset_bytes: &'a [u8],
        is_provenance: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        // Parse COSE signed data (signature) and validate it.
        let sig = claim.signature_val().clone();
        let additional_bytes: Vec<u8> = Vec::new();
        let claim_data = claim.data()?;

        // make sure signature manifest if present points to this manifest
        let sig_box_err = match jumbf::labels::manifest_label_from_uri(&claim.signature) {
            Some(signature_url) if signature_url != claim.label() => true,
            _ => {
                jumbf::labels::box_name_from_uri(&claim.signature).unwrap_or_else(|| "".to_string())
                    != jumbf::labels::SIGNATURE
            } // relative signature box
        };

        if sig_box_err {
            let log_item = log_item!(
                claim.signature_uri(),
                "signature missing",
                "verify_claim_async"
            )
            .error(Error::ClaimMissingSignatureBox)
            .validation_status(validation_status::CLAIM_SIGNATURE_MISSING);

            validation_log.log(log_item, Some(Error::ClaimMissingSignatureBox))?;
        }

        let verified = verify_cose_async(
            sig,
            claim_data,
            additional_bytes,
            !is_provenance,
            validation_log,
        )
        .await;
        Claim::verify_internal(
            claim,
            &ClaimAssetData::ByteData(asset_bytes),
            is_provenance,
            verified,
            validation_log,
        )
    }

    /// Verify claim signature, assertion store and asset hashes
    /// claim - claim to be verified
    /// asset_bytes - reference to bytes of the asset
    pub fn verify_claim<'a>(
        claim: &Claim,
        asset_data: &ClaimAssetData<'a>,
        is_provenance: bool,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        // Parse COSE signed data (signature) and validate it.
        let sig = claim.signature_val();
        let additional_bytes: Vec<u8> = Vec::new();

        // make sure signature manifest if present points to this manifest
        let sig_box_err = match jumbf::labels::manifest_label_from_uri(&claim.signature) {
            Some(signature_url) if signature_url != claim.label() => true,
            _ => {
                jumbf::labels::box_name_from_uri(&claim.signature).unwrap_or_else(|| "".to_string())
                    != jumbf::labels::SIGNATURE
            } // relative signature box
        };

        if sig_box_err {
            let log_item = log_item!(claim.signature_uri(), "signature missing", "verify_claim")
                .error(Error::ClaimMissingSignatureBox)
                .validation_status(validation_status::CLAIM_SIGNATURE_MISSING);
            validation_log.log(log_item, Some(Error::ClaimMissingSignatureBox))?;
        }

        let data = if let Some(ref original_bytes) = claim.original_bytes {
            original_bytes
        } else {
            return Err(Error::ClaimDecoding);
        };

        let verified = verify_cose(sig, data, &additional_bytes, !is_provenance, validation_log);

        Claim::verify_internal(claim, asset_data, is_provenance, verified, validation_log)
    }

    fn verify_internal<'a>(
        claim: &Claim,
        asset_data: &ClaimAssetData<'a>,
        is_provenance: bool,
        verified: Result<ValidationInfo>,
        validation_log: &mut impl StatusTracker,
    ) -> Result<()> {
        const UNNAMED: &str = "unnamed";
        let default_str = |s: &String| s.clone();

        match verified {
            Ok(vi) => {
                if !vi.validated {
                    let log_item = log_item!(
                        claim.signature_uri(),
                        "claim signature is not valid",
                        "verify_internal"
                    )
                    .error(Error::CoseSignature)
                    .validation_status(validation_status::CLAIM_SIGNATURE_MISMATCH);
                    validation_log.log(log_item, Some(Error::CoseSignature))?;
                } else {
                    let log_item = log_item!(
                        claim.signature_uri(),
                        "claim signature valid",
                        "verify_internal"
                    )
                    .validation_status(validation_status::CLAIM_SIGNATURE_VALIDATED);
                    validation_log.log_silent(log_item);
                }
            }
            Err(parse_err) => {
                let log_item = log_item!(
                    claim.signature_uri(),
                    "claim signature is not valid",
                    "verify_internal"
                )
                .error(parse_err)
                .validation_status(validation_status::CLAIM_SIGNATURE_MISMATCH);
                validation_log.log(log_item, Some(Error::CoseSignature))?;
            }
        };

        // check for self redacted assertions and illegal readactions
        if let Some(redactions) = claim.redactions() {
            for r in redactions {
                let r_manifest = jumbf::labels::manifest_label_from_uri(r)
                    .ok_or(Error::AssertionInvalidRedaction)?;
                if claim.label().contains(&r_manifest) {
                    let log_item = log_item!(
                        claim.uri(),
                        "claim contains self redaction",
                        "verify_internal"
                    )
                    .error(Error::ClaimSelfRedact)
                    .validation_status(validation_status::ASSERTION_SELF_REDACTED);
                    validation_log.log(log_item, Some(Error::ClaimSelfRedact))?;
                }

                if r.contains(assertions::labels::ACTIONS) {
                    let log_item = log_item!(
                        claim.uri(),
                        "readaction of action assertions disallowed",
                        "verify_internal"
                    )
                    .error(Error::ClaimDisallowedRedaction)
                    .validation_status(validation_status::ACTION_ASSERTION_REDACTED);
                    validation_log.log(log_item, Some(Error::ClaimDisallowedRedaction))?;
                }
            }
        }

        // make sure UpdateManifests do not contain actions
        if claim.update_manifest() && claim.label().contains(assertions::labels::ACTIONS) {
            let log_item = log_item!(
                claim.uri(),
                "update manifests cannot contain actions",
                "verify_internal"
            )
            .error(Error::UpdateManifestInvalid)
            .validation_status(validation_status::MANIFEST_UPDATE_INVALID);
            validation_log.log(log_item, Some(Error::UpdateManifestInvalid))?;
        }
        // verify assertion structure comparing hashes from assertion list to contents of assertion store
        for assertion in claim.assertions() {
            let (label, instance) = Claim::assertion_label_from_link(&assertion.url());
            match claim.get_claim_assertion(&label, instance) {
                // get the assertion if label and hash match
                Some(ca) => {
                    if !vec_compare(ca.hash(), &assertion.hash()) {
                        let log_item = log_item!(
                            assertion.url(),
                            format!("hash does not match assertion data: {}", assertion.url()),
                            "verify_internal"
                        )
                        .error(Error::HashMismatch(format!(
                            "Assertion hash failure: {}",
                            assertion.url()
                        )))
                        .validation_status(validation_status::ASSERTION_HASHEDURI_MISMATCH);
                        validation_log.log(
                            log_item,
                            Some(Error::HashMismatch(format!(
                                "Assertion hash failure: {}",
                                assertion.url()
                            ))),
                        )?;
                    } else {
                        let log_item = log_item!(
                            assertion.url(),
                            format!("hashed uri matched: {}", assertion.url()),
                            "verify_internal"
                        )
                        .validation_status(validation_status::ASSERTION_HASHEDURI_MATCH);
                        validation_log.log_silent(log_item);
                    }
                }
                None => {
                    let log_item = log_item!(
                        assertion.url(),
                        format!("cannot find matching assertion: {}", assertion.url()),
                        "verify_internal"
                    )
                    .error(Error::AssertionMissing {
                        url: assertion.url(),
                    })
                    .validation_status(validation_status::ASSERTION_MISSING);
                    validation_log.log(
                        log_item,
                        Some(Error::AssertionMissing {
                            url: assertion.url(),
                        }),
                    )?;
                }
            }
        }

        // verify data hashes for provenance claims
        if is_provenance {
            // must have at least one hard binding for normal manifests
            if claim.data_hash_assertions().is_empty() && !claim.update_manifest() {
                let log_item = log_item!(
                    &claim.uri(),
                    "claim missing data binding",
                    "verify_internal"
                )
                .error(Error::ClaimMissingHardBinding)
                .validation_status(validation_status::HARD_BINDINGS_MISSING);
                validation_log.log(log_item, Some(Error::ClaimMissingHardBinding))?;
            }

            // update manifests cannot have data hashes
            if !claim.data_hash_assertions().is_empty() && claim.update_manifest() {
                let log_item = log_item!(
                    &claim.uri(),
                    "update manifests cannot contain data hash assertions",
                    "verify_internal"
                )
                .error(Error::UpdateManifestInvalid)
                .validation_status(validation_status::MANIFEST_UPDATE_INVALID);
                validation_log.log(log_item, Some(Error::UpdateManifestInvalid))?;
            }

            for dh_assertion in claim.data_hash_assertions() {
                if dh_assertion.label_root() == DataHash::LABEL {
                    let dh = DataHash::from_assertion(dh_assertion)?;
                    let name = dh.name.as_ref().map_or(UNNAMED.to_string(), default_str);
                    if !dh.is_remote_hash() {
                        // only verify local hashes here
                        let hash_result = match asset_data {
                            ClaimAssetData::PathData(asset_path) => {
                                dh.verify_hash(asset_path, Some(claim.alg().to_string()))
                            }
                            ClaimAssetData::ByteData(asset_bytes) => {
                                dh.verify_in_memory_hash(asset_bytes, Some(claim.alg().to_string()))
                            }
                        };

                        match hash_result {
                            Ok(_a) => {
                                let log_item = log_item!(
                                    claim.assertion_uri(&dh_assertion.label()),
                                    "data hash valid",
                                    "verify_internal"
                                )
                                .validation_status(validation_status::ASSERTION_DATAHASH_MATCH);
                                validation_log.log_silent(log_item);

                                continue;
                            }
                            Err(e) => {
                                let log_item = log_item!(
                                    claim.assertion_uri(&dh_assertion.label()),
                                    format!("asset hash error, name: {}, error: {}", name, e),
                                    "verify_internal"
                                )
                                .error(Error::HashMismatch(format!("Asset hash failure: {}", e)))
                                .validation_status(validation_status::ASSERTION_DATAHASH_MISMATCH);

                                validation_log.log(
                                    log_item,
                                    Some(Error::HashMismatch(format!("Asset hash failure: {}", e))),
                                )?;
                            }
                        }
                    }
                } else {
                    // handle BMFF data hashes
                    let dh = BmffHash::from_assertion(dh_assertion)?;

                    let name = dh.name().map_or("unnamed".to_string(), default_str);

                    let hash_result = match asset_data {
                        ClaimAssetData::PathData(asset_path) => {
                            dh.verify_hash(asset_path, Some(claim.alg().to_string()))
                        }
                        ClaimAssetData::ByteData(asset_bytes) => {
                            dh.verify_in_memory_hash(asset_bytes, Some(claim.alg().to_string()))
                        }
                    };

                    match hash_result {
                        Ok(_a) => {
                            let log_item = log_item!(
                                claim.assertion_uri(&dh_assertion.label()),
                                "data hash valid",
                                "verify_internal"
                            )
                            .validation_status(validation_status::ASSERTION_DATAHASH_MATCH);
                            validation_log.log_silent(log_item);

                            continue;
                        }
                        Err(e) => {
                            let log_item = log_item!(
                                claim.assertion_uri(&dh_assertion.label()),
                                format!("asset hash error, name: {}, error: {}", name, e),
                                "verify_internal"
                            )
                            .error(Error::HashMismatch(format!("Asset hash failure: {}", e)))
                            .validation_status(validation_status::ASSERTION_DATAHASH_MISMATCH);

                            validation_log.log(
                                log_item,
                                Some(Error::HashMismatch(format!("Asset hash failure: {}", e))),
                            )?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Verify hash against self.  True if match,
    /// false if no match or unsupported
    pub fn verify_hash(&self, hash: &[u8]) -> bool {
        // get hash of self for comparison
        if let Some(ref original_bytes) = self.original_bytes {
            verify_by_alg(self.alg(), hash, original_bytes, None)
        } else if let Ok(claim_data) = self.data() {
            verify_by_alg(self.alg(), hash, &claim_data, None)
        } else {
            false
        }
    }

    /// Return list of data hash assertions
    pub fn data_hash_assertions(&self) -> Vec<&Assertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_hash = Assertion::new(DataHash::LABEL, None, dummy_data);
        let mut data_hashes = self.assertions_by_type(&dummy_hash);

        // add in an BMFF hashes
        let dummy_bmff_data = AssertionData::Cbor(Vec::new());
        let dummy_bmff_hash = Assertion::new(assertions::labels::BMFF_HASH, None, dummy_bmff_data);
        data_hashes.append(&mut self.assertions_by_type(&dummy_bmff_hash));

        data_hashes
    }

    pub fn bmff_hash_assertions(&self) -> Vec<&Assertion> {
        // add in an BMFF hashes
        let dummy_bmff_data = AssertionData::Cbor(Vec::new());
        let dummy_bmff_hash = Assertion::new(assertions::labels::BMFF_HASH, None, dummy_bmff_data);
        self.assertions_by_type(&dummy_bmff_hash)
    }
    /// Return list of ingredient assertions. This function
    /// is only useful on commited or loaded claims since ingredients
    /// are resolved at commit time.
    pub fn ingredient_assertions(&self) -> Vec<&Assertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_ingredient = Assertion::new(labels::INGREDIENT, None, dummy_data);
        self.assertions_by_type(&dummy_ingredient)
    }

    /// Return reference to the internal claim assertion store.
    pub fn claim_assertion_store(&self) -> &Vec<ClaimAssertion> {
        &self.assertion_store
    }

    /// Return reference to the internal claim ingredient store.
    /// Used during generation
    pub fn claim_ingredient_store(&self) -> &HashMap<String, Vec<Claim>> {
        &self.ingredients_store
    }

    /// Return reference to the internal claim ingredient store matching this guid.
    /// Used during generation
    pub fn claim_ingredient(&self, claim_guid: &str) -> Option<&Vec<Claim>> {
        self.ingredients_store.get(claim_guid)
    }

    /// Adds ingredients, this data will be written out during commit of the Claim
    pub(crate) fn add_ingredient_data(
        &mut self,
        provenance_label: &str,
        mut ingredient: Vec<Claim>,
        redactions_opt: Option<Vec<String>>,
    ) -> Result<()> {
        // redact assertion from incoming ingredients
        if let Some(redactions) = &redactions_opt {
            for redaction in redactions {
                if let Some(claim) = ingredient
                    .iter_mut()
                    .find(|x| redaction.contains(&x.label()))
                {
                    claim.redact_assertion(redaction)?;
                } else {
                    return Err(Error::AssertionRedactionNotFound);
                }
            }
        }

        // all have been removed (if necessary) so replace redaction list
        self.redacted_assertions = redactions_opt;

        // add ingredients
        self.ingredients_store
            .insert(provenance_label.to_string(), ingredient);

        Ok(())
    }

    /// List of redactions
    pub fn redactions(&self) -> Option<&Vec<String>> {
        self.redacted_assertions.as_ref()
    }

    /// Return snapshot clone of the claim's assertions.
    pub fn assertion_store(&self) -> Vec<Assertion> {
        self.assertion_store
            .iter()
            .map(|x| x.assertion.clone())
            .collect()
    }

    pub fn assertions_by_type(&self, assertion_proto: &Assertion) -> Vec<&Assertion> {
        self.assertion_store
            .iter()
            .filter_map(|x| {
                if Assertion::assertions_eq(assertion_proto, x.assertion()) {
                    Some(&x.assertion)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return reference to the assertions list.
    ///
    /// This list matches item-for-item with the `Assertion`s
    /// stored in the assertion store.
    pub fn assertions(&self) -> &Vec<C2PAAssertion> {
        &self.assertions
    }

    /// Returns the cbor binary value of the claim data.
    /// If this claim was read from a file, returns the exact byte
    /// sequence that was read from the file. If this claim was
    /// constructed locally, contains the claim data that was/will be
    /// generated locally.
    pub fn data(&self) -> Result<Vec<u8>> {
        match self.original_bytes {
            Some(ref ob) => Ok(ob.clone()),
            None => Ok(serde_cbor::ser::to_vec(&self).map_err(|_err| Error::ClaimEncoding)?),
        }
    }

    /// Create claim from binary data (not including assertions).
    pub fn from_data(label: &str, data: &[u8]) -> Result<Claim> {
        let mut claim: Claim = serde_cbor::from_slice(data).map_err(|_err| Error::ClaimDecoding)?;

        claim.label = label.to_string();
        claim.original_bytes = Some(data.to_owned());

        Ok(claim)
    }

    /// Generate a JSON representation of the Claim
    /// returns Result as a String
    pub fn to_json(
        &self,
        assertion_store_format: AssertionStoreJsonFormat,
        pretty: bool,
    ) -> Result<String> {
        let mut v = serde_json::to_value(self)?;

        match assertion_store_format {
            AssertionStoreJsonFormat::None => {}
            AssertionStoreJsonFormat::KeyValue | AssertionStoreJsonFormat::KeyValueNoBinary => {
                // add additional data if needed to the assertion store
                if let Value::Object(ref mut map) = v {
                    // merge the label with the data
                    let mut json_map: Map<String, Value> = Map::new();
                    let iter = self.assertions.iter().zip(&self.assertion_store);

                    for (_key, claim_assertion) in iter {
                        let link = claim_assertion.label();
                        let (label, instance) = Self::assertion_label_from_link(&link);
                        let label = Self::label_with_instance(&label, instance);

                        match claim_assertion.assertion.decode_data() {
                            AssertionData::Json(x) => {
                                // json strings
                                let decoded = serde_json::from_str(x)?;
                                json_map.insert(label, decoded);
                            }
                            AssertionData::Cbor(x) => {
                                // some types are not translatable to json so explicitly convert
                                let buf: Vec<u8> = Vec::new();
                                let mut from = serde_cbor::Deserializer::from_slice(x);
                                let mut to = serde_json::Serializer::new(buf);

                                serde_transcode::transcode(&mut from, &mut to)
                                    .map_err(|_err| Error::AssertionEncoding)?;
                                let buf2 = to.into_inner();

                                let decoded: Value = serde_json::from_slice(&buf2)
                                    .map_err(|_err| Error::AssertionEncoding)?;

                                json_map.insert(label, decoded);
                            }
                            AssertionData::Binary(x) => {
                                // binary vecs
                                let d = match assertion_store_format {
                                    AssertionStoreJsonFormat::KeyValue => {
                                        Value::String(base64::encode(x))
                                    }
                                    AssertionStoreJsonFormat::KeyValueNoBinary => {
                                        Value::String("omitted".to_owned())
                                    }
                                    _ => Value::String("".to_owned()),
                                };
                                json_map.insert(label, d);
                                continue;
                            }
                            AssertionData::Uuid(s, x) => {
                                // binary vecs
                                let d = match assertion_store_format {
                                    AssertionStoreJsonFormat::KeyValue => {
                                        Value::String(base64::encode(x))
                                    }
                                    AssertionStoreJsonFormat::KeyValueNoBinary => {
                                        Value::String("omitted".to_owned())
                                    }
                                    _ => Value::String("".to_owned()),
                                };

                                let m = json!({
                                    "uuid": s,
                                    "data": d,
                                });

                                json_map.insert(label, m);
                                continue;
                            }
                        }
                    }
                    //let s = serde_json::to_string(&json_map)?;
                    //let as_val = serde_json::from_str(&s)?;
                    let as_val = serde_json::to_value(json_map)?;
                    map.insert("assertion_store".to_string(), as_val);

                    // add vcstore
                    map.insert(
                        "vc_store".to_string(),
                        serde_json::to_value(&self.vc_store)?,
                    );

                    // add claim label
                    map.insert("label".to_string(), Value::String(self.label.to_string()));
                }
            }
            AssertionStoreJsonFormat::OrderedList
            | AssertionStoreJsonFormat::OrderedListNoBinary => {
                // add additional data if needed to the assertion store
                if let Value::Object(ref mut map) = v {
                    let mut json_vec: Vec<Value> = Vec::new();

                    // assertion values
                    for claim_assertion in self.claim_assertion_store() {
                        match claim_assertion.assertion.decode_data() {
                            AssertionData::Json(x) => {
                                let d: Value = serde_json::from_str(x)
                                    .map_err(|_err| Error::AssertionEncoding)?;

                                let j = JsonOrderedAssertionData {
                                    label: claim_assertion.label().to_owned(),
                                    hash: base64::encode(claim_assertion.hash()),
                                    data: d,
                                    is_binary: false,
                                    mime_type: claim_assertion.assertion.mime_type(),
                                };

                                let new_val = serde_json::to_value(j)?;
                                json_vec.push(new_val);
                            }
                            AssertionData::Cbor(x) => {
                                // some types are not translatable to json so explicitly convert
                                let buf: Vec<u8> = Vec::new();
                                let mut from = serde_cbor::Deserializer::from_slice(x);
                                let mut to = serde_json::Serializer::new(buf);

                                serde_transcode::transcode(&mut from, &mut to)
                                    .map_err(|_err| Error::AssertionEncoding)?;
                                let buf2 = to.into_inner();

                                let d: Value = serde_json::from_slice(&buf2)
                                    .map_err(|_err| Error::AssertionEncoding)?;

                                let j = JsonOrderedAssertionData {
                                    label: claim_assertion.label().to_owned(),
                                    hash: base64::encode(claim_assertion.hash()),
                                    data: d,
                                    is_binary: false,
                                    mime_type: claim_assertion.assertion.mime_type(),
                                };

                                let new_val = serde_json::to_value(j)?;
                                json_vec.push(new_val);
                            }
                            AssertionData::Binary(x) => {
                                // binary data
                                let d = match assertion_store_format {
                                    AssertionStoreJsonFormat::OrderedList => {
                                        Value::String(base64::encode(x))
                                    }
                                    AssertionStoreJsonFormat::OrderedListNoBinary => {
                                        Value::String("omitted".to_owned())
                                    }
                                    _ => Value::String("".to_owned()),
                                };

                                let j = JsonOrderedAssertionData {
                                    label: claim_assertion.label().to_owned(),
                                    hash: base64::encode(claim_assertion.hash()),
                                    data: d,
                                    is_binary: true,
                                    mime_type: claim_assertion.assertion.mime_type(),
                                };

                                let new_val = serde_json::to_value(j)?;
                                json_vec.push(new_val);
                            }
                            AssertionData::Uuid(s, x) => {
                                // binary data
                                let d = match assertion_store_format {
                                    AssertionStoreJsonFormat::OrderedList => {
                                        Value::String(base64::encode(x))
                                    }
                                    AssertionStoreJsonFormat::OrderedListNoBinary => {
                                        Value::String("omitted".to_owned())
                                    }
                                    _ => Value::String("".to_owned()),
                                };

                                let m = json!({
                                    "uuid": s,
                                    "data": d,
                                });

                                let j = JsonOrderedAssertionData {
                                    label: claim_assertion.label().to_owned(),
                                    hash: base64::encode(claim_assertion.hash()),
                                    data: m,
                                    is_binary: true,
                                    mime_type: claim_assertion.assertion.mime_type(),
                                };

                                let new_val = serde_json::to_value(j)?;
                                json_vec.push(new_val);
                            }
                        }
                    }

                    let as_val = serde_json::to_value(json_vec)?;
                    map.insert("assertion_store".to_string(), as_val);

                    // add claim label
                    map.insert("label".to_string(), Value::String(self.label.to_string()));
                }
            }
        }

        if pretty {
            serde_json::to_string_pretty(&v).map_err(|e| e.into())
        } else {
            serde_json::to_string(&v).map_err(|e| e.into())
        }
    }

    /// Return the label for this assertion given its link
    pub fn assertion_label_from_link(assertion_link: &str) -> (String, usize) {
        let v = jumbf::labels::to_normalized_uri(assertion_link);

        let v2: Vec<&str> = v.split('/').collect();
        if let Some(s) = v2.last() {
            // treat ingredient thumbnails differently ingredient.thumbnail
            if get_thumbnail_type(s) == labels::INGREDIENT_THUMBNAIL {
                let instance = get_thumbnail_instance(s).unwrap_or(0);
                let label = match get_thumbnail_image_type(s).as_str() {
                    "none" => get_thumbnail_type(s),
                    image_type => format!("{}.{}", get_thumbnail_type(s), image_type),
                };
                (label, instance)
            } else {
                let label_parts: Vec<&str> = s.split("__").collect();
                let mut instance: usize = 0;

                if label_parts.len() == 2 {
                    match label_parts[1].parse::<usize>() {
                        Ok(i) => instance = i,
                        _ => instance = 0,
                    }
                }

                (label_parts[0].to_owned(), instance)
            }
        } else {
            (v2[0].to_owned(), 0)
        }
    }

    /// generates label with instance if needed
    pub fn label_with_instance(label: &str, instance: usize) -> String {
        if instance == 0 {
            label.to_string()
        } else if get_thumbnail_type(label) == labels::INGREDIENT_THUMBNAIL {
            let tn_type = get_thumbnail_image_type(label);
            format!("{}__{}.{}", get_thumbnail_type(label), instance, tn_type)
        } else {
            format!("{}__{}", label, instance)
        }
    }

    pub fn assertion_hashed_uri_from_label(&self, assertion_label: &str) -> Option<&C2PAAssertion> {
        self.assertions()
            .iter()
            .find(|hashed_uri| hashed_uri.url().contains(assertion_label))
    }

    // Given a proposed label, make a new label that is unique within this
    // assertion store. Typically this is done by adding `__{n}` where `n` is
    // an integer starting from 1. Ingredient thumbnails have special handling.
    fn make_assertion_instance_label(&self, assertion_label: &str) -> String {
        let cnt = self.next_instance(assertion_label);

        Claim::label_with_instance(assertion_label, cnt)
    }

    /// returns first instance of an assertion whose label and instance match
    pub fn get_assertion(&self, assertion_label: &str, instance: usize) -> Option<&Assertion> {
        let mut iter = self.claim_assertion_store().iter().filter_map(|ca| {
            if ca.label_raw() == assertion_label && ca.instance() == instance {
                Some(ca.assertion())
            } else {
                None
            }
        });

        iter.next()
    }

    /// returns instance of an assertion whose label and instance match
    pub fn get_claim_assertion(
        &self,
        assertion_label: &str,
        instance: usize,
    ) -> Option<&ClaimAssertion> {
        self.claim_assertion_store()
            .iter()
            .find(|ca| ca.label_raw() == assertion_label && ca.instance() == instance)
    }

    /// returns hash of an assertion whose label and instance match
    pub fn get_claim_assertion_hash(&self, assertion_label: &str) -> Option<Vec<u8>> {
        let (l, i) = Claim::assertion_label_from_link(assertion_label);
        self.get_claim_assertion(&l, i).map(|a| a.hash().to_vec())
    }

    /// Returns how many assertions of this assertion type exist?
    pub fn count_instances(&self, in_label: &str) -> usize {
        let (l, i) = Claim::assertion_label_from_link(in_label);
        let label = Claim::label_with_instance(&l, i);
        self.assertions
            .iter()
            .filter(|assertion| assertion.url().contains(&label))
            .count()
    }

    // Get the next highest instance label
    fn next_instance(&self, in_label: &str) -> usize {
        let (label, _) = Claim::assertion_label_from_link(in_label);
        match self
            .assertion_store
            .iter()
            .filter(|&x| x.assertion.label().contains(&label))
            .map(|x| {
                let (_l, i) = Claim::assertion_label_from_link(&x.label());
                i
            })
            .max()
        {
            Some(last_instance) => last_instance + 1,
            None => 0,
        }
    }

    // Do any assertions of this type exist?
    pub fn has_assertion_type(&self, in_label: &str) -> bool {
        let (label, _) = Claim::assertion_label_from_link(in_label);
        let found = self
            .assertion_store
            .iter()
            .find(|&x| x.assertion.label().starts_with(&label));

        !matches!(found, None)
    }

    // Create a JUMBF URI from a claim label.
    pub(crate) fn to_claim_uri(manifest_label: &str) -> String {
        format!(
            "{}/{}",
            jumbf::labels::to_manifest_uri(manifest_label),
            Self::LABEL
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::utils::test::create_test_claim;

    #[test]
    fn test_build_claim() {
        // Create a new claim.
        let mut claim = create_test_claim().expect("create test claim");

        // Add a redaction.
        // claim.redact_assertion("as_tp_1/c2pa.location.precise");

        // Build claim checking rules.
        claim.build().expect("bad claim");

        // Test round-tripping of binary.
        let orig_binary = claim.data().expect("failure returning data");
        let restored_claim =
            Claim::from_data("as_adbe_1", &orig_binary).expect("could not restore from binary");
        let restored_binary = restored_claim.data().expect("failure returning data");

        assert_eq!(orig_binary, restored_binary);
        println!("Restored Claim: {:?}", restored_claim);

        // NOTE: I added a separate mirror of original data because a third-party's
        // JSON serialization could differ from our re-serialization of that same data.
        // When reading claims from assets and verifying signatures of those claims,
        // we need the exact original bytes of the signed JSON or the signature verification
        // will fail.
        assert_eq!(orig_binary, restored_claim.original_bytes.unwrap());

        // JSON examples
        let json_str = claim
            .to_json(AssertionStoreJsonFormat::OrderedList, true)
            .expect("could not generate json");

        println!("Claim: {}", json_str);
    }

    #[test]
    fn test_build_claim_generator_hints() {
        // Create a new claim.
        let mut claim = create_test_claim().expect("create test claim");

        claim.add_claim_generator_hint(
            GH_FULL_VERSION_LIST,
            Value::String(r#""user app";v="2.3.4""#.to_string()),
        );
        claim.add_claim_generator_hint(
            GH_FULL_VERSION_LIST,
            Value::String(r#""some toolkit";v="1.0.0""#.to_string()),
        );

        let expected_value = r#""user app";v="2.3.4", "some toolkit";v="1.0.0""#;

        let cg_map = claim.get_claim_generator_hint_map().unwrap();
        let value = &cg_map[GH_FULL_VERSION_LIST];

        assert_eq!(expected_value, value.as_str().unwrap());
    }
}
