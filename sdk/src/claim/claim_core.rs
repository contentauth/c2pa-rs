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
    sync::Arc,
};

use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    assertion::{
        cbor_to_crjson, get_thumbnail_image_type, get_thumbnail_instance, get_thumbnail_type,
        Assertion, AssertionBase, AssertionData,
    },
    assertions::{
        self,
        labels::{
            self, ACTIONS, ASSERTION_METADATA, ASSERTION_STORE, BMFF_HASH, CLAIM_THUMBNAIL,
            DATABOX_STORE, METADATA_LABEL_REGEX,
        },
        Action, Actions, AssertionMetadata, AssetType, BmffHash, DataBox, DataHash, Ingredient,
        Relationship, V2_DEPRECATED_ACTIONS,
    },
    cbor_types::map_cbor_to_type,
    claim::{ClaimAssertion, ClaimAssertionType},
    context::Context,
    crypto::base64,
    error::{Error, Result},
    hashed_uri::HashedUri,
    jumbf::{
        self, c2pa_encoding,
        labels::{
            box_name_from_uri, manifest_label_from_uri, manifest_label_to_parts, to_databox_uri,
            to_normalized_uri, ASSERTIONS, CLAIM, CREDENTIALS, DATABOX, DATABOXES, SIGNATURE,
        },
    },
    salt::{DefaultSalt, SaltGenerator},
    settings::MAX_ASSERTIONS,
    utils::hash_utils::{hash_by_alg, vec_compare},
    ClaimGeneratorInfo,
};

const BUILD_HASH_ALG: &str = "sha256";
const BUILD_VER_SUPPORT: usize = 2;

/// JSON structure representing an Assertion reference in a Claim's "assertions" list.
use HashedUri as C2PAAssertion;

pub(super) const GH_FULL_VERSION_LIST: &str = "Sec-CH-UA-Full-Version-List";
const GH_UA: &str = "Sec-CH-UA";
const C2PA_NAMESPACE_V2: &str = "urn:c2pa";
const C2PA_NAMESPACE_V1: &str = "urn:uuid";

const _V2_SPEC_DEPRECATED_ASSERTIONS: [&str; 4] = [
    "stds.iptc",
    "stds.iptc.photo-metadata",
    "stds.exif",
    "c2pa.endorsement",
];

// Claim field names
const CLAIM_GENERATOR_F: &str = "claim_generator";
const CLAIM_GENERATOR_INFO_F: &str = "claim_generator_info";
const CLAIM_GENERATOR_HINTS_F: &str = "claim_generator_hints";
const SIGNATURE_F: &str = "signature";
const ASSERTIONS_F: &str = "assertions";
const DC_FORMAT_F: &str = "dc:format";
const INSTANCE_ID_F: &str = "instanceID";
const DC_TITLE_F: &str = "dc:title";
const REDACTED_ASSERTIONS_F: &str = "redacted_assertions";
const ALG_F: &str = "alg";
const ALG_SOFT_F: &str = "alg_soft";
const METADATA_F: &str = "metadata";
const CREATED_ASSERTIONS_F: &str = "created_assertions";
const GATHERED_ASSERTIONS_F: &str = "gathered_assertions";
pub(super) const SPEC_VERSION_F: &str = "specVersion";

/// A `Claim` gathers together all the `Assertion`s about an asset
/// from an actor at a given time, and may also include one or more
/// hashes of the asset itself, and a reference to the previous `Claim`.
///
/// It has all the same properties as an `Assertion` including being
/// assigned a label (`c2pa.claim.v1`) and being either embedded into the
/// asset or in the cloud. The claim is cryptographically hashed and
/// that hash is signed to produce the claim signature.
#[derive(Debug, Default, Clone)]
pub struct Claim {
    // external manifest
    remote_manifest: RemoteManifest,

    // root of CAI store
    pub(super) update_manifest: bool,

    // true if this claim was read from a `c2md`-tagged superbox (C2PA spec
    // 11.2.2) rather than an ordinary `c2ma` standard manifest. Preserved so
    // the original tag survives round-trips (e.g. ingredient copies).
    is_c2md: bool,

    // true if manifest is or will be stored compressed
    compressed: bool,

    pub title: Option<String>, // title for this claim, generally the name of the containing asset

    pub format: Option<String>, // mime format of document containing this claim

    pub instance_id: String, // instance Id of document containing this claim

    // Internal list of ingredients
    ingredients_store: HashMap<String, Claim>,

    // Internal ingredients order
    ingredients_list: Vec<String>,

    pub(super) signature_val: Vec<u8>, // the signature of the loaded/saved claim

    // root of CAI store
    #[allow(dead_code)]
    root: String,

    // internal scratch objects
    pub(super) label: String, // label of claim

    // relabel claim when there is an ingredient conflict
    conflict_label: Option<String>,

    // Internal list of assertions for claim.
    // These are serialized manually based on need.
    assertion_store: Vec<ClaimAssertion>,

    // Internal list of verifiable credentials for claim.
    // These are serialized manually based on need.
    vc_store: Vec<(HashedUri, AssertionData)>, //  V1 feature

    pub(super) claim_generator: Option<String>, // generator of this claim

    pub(crate) claim_generator_info: Option<Vec<ClaimGeneratorInfo>>, /* detailed generator info of this claim */

    pub(super) signature: String,              // link to signature box
    pub(super) assertions: Vec<C2PAAssertion>, // list of assertion or created_assertions (V1 assertions or V2 created and gathered combined) hashed URIs.
    created_assertions: Vec<C2PAAssertion>, // list of assertion or created_assertions (V1) hashed URIs.
    gathered_assertions: Option<Vec<C2PAAssertion>>, // list of gather_assertions (>= V2)

    // original JSON bytes of claim; only present when reading from asset
    pub(super) original_bytes: Option<Vec<u8>>,

    // original JUMBF box order need to recalculate JUMBF box hash
    original_box_order: Option<Vec<&'static str>>,

    pub(super) redacted_assertions: Option<Vec<String>>, // list of redacted assertions

    pub(crate) alg: Option<String>, // hashing algorithm (default to Sha256)

    pub(super) alg_soft: Option<String>, // hashing algorithm for soft bindings

    claim_generator_hints: Option<HashMap<String, Value>>,

    pub(super) metadata: Option<Vec<AssertionMetadata>>,

    data_boxes: Vec<(HashedUri, DataBox)>, /* list of the data boxes and their hashed URIs found for this manifest */

    claim_version: usize,

    // deprecated in C2PA 2.4
    pub(super) spec_version: Option<String>, // The version of the specification against which the validation was performed (SemVer formatted string)

    // Optional context for settings access (set when created from Builder)
    pub(super) context: Option<Arc<Context>>,
}

/// Enum to define how assertions are are stored when output to json
pub enum AssertionStoreJsonFormat {
    None,                // no assertion store
    KeyValue,            // key (uri), value (Assertion json object)
    KeyValueNoBinary,    // KeyValue omitting binary results
    OrderedList,         // list of Assertions as json objects
    OrderedListNoBinary, // list of Assertions as json objects omitting binaries results
}

/// Remote manifest options. Use 'set_remote_manifest' to generate external manifests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RemoteManifest {
    #[default]
    NoRemote, // No external manifest (default)
    SideCar,        // Manifest will be saved as a side car file, output asset is untouched.
    Remote(String), /* Manifest will be saved as a side car file, output asset will contain remote reference */
    EmbedWithRemote(String), /* Manifest will be embedded with a remote reference, sidecar will be generated */
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonOrderedAssertionData {
    label: String,
    data: Value,
    hash: String,
    is_binary: bool,
    mime_type: String,
}

impl Serialize for Claim {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.claim_version > 1 {
            self.serialize_v2(serializer)
        } else {
            self.serialize_v1(serializer)
        }
    }
}

/// Whether a `c2pa.hash.data` assertion's exclusions are acceptable for this asset.
impl Claim {
    /// Create a new claim.
    /// vendor: name used to label the claim (unique instance number is automatically calculated)
    /// claim_generator: User agent see c2pa spec for format
    /// claim_version: the Claim version to generate
    pub fn new<S: Into<String>>(
        claim_generator: S,
        vendor: Option<&str>,
        claim_version: usize,
    ) -> Self {
        let urn = Uuid::new_v4();
        let l = match vendor {
            Some(v) => {
                if claim_version == 1 {
                    format!(
                        "{}:{}:{}",
                        v.to_lowercase(),
                        C2PA_NAMESPACE_V1,
                        urn.hyphenated().encode_lower(&mut Uuid::encode_buffer())
                    )
                } else {
                    format!(
                        "{}:{}:{}",
                        C2PA_NAMESPACE_V2,
                        urn.hyphenated().encode_lower(&mut Uuid::encode_buffer()),
                        v.to_lowercase()
                    )
                }
            }
            None => {
                if claim_version == 1 {
                    urn.urn()
                        .encode_lower(&mut Uuid::encode_buffer())
                        .to_string()
                } else {
                    format!(
                        "{}:{}",
                        C2PA_NAMESPACE_V2,
                        urn.hyphenated().encode_lower(&mut Uuid::encode_buffer())
                    )
                }
            }
        };

        Claim {
            remote_manifest: RemoteManifest::NoRemote,
            root: jumbf::labels::MANIFEST_STORE.to_string(),
            signature_val: Vec::new(),
            ingredients_store: HashMap::new(),
            ingredients_list: Vec::new(),
            label: l,
            conflict_label: None,
            signature: "".to_string(),

            claim_generator: if claim_version == 1 {
                Some(claim_generator.into())
            } else {
                None
            },
            claim_generator_info: None,
            assertion_store: Vec::new(),
            vc_store: Vec::new(),
            assertions: Vec::new(),
            original_bytes: None,
            original_box_order: None,
            redacted_assertions: None,
            alg: Some(BUILD_HASH_ALG.to_string()),
            alg_soft: None,
            claim_generator_hints: None,

            title: None,
            format: Some("".to_string()),
            instance_id: "".to_string(),

            update_manifest: false,
            is_c2md: false,
            compressed: false,
            data_boxes: Vec::new(),
            metadata: None,
            claim_version,
            created_assertions: Vec::new(),
            gathered_assertions: None,
            context: None,
            spec_version: None,
        }
    }

    /// Create a new claim with a user supplied GUID.
    /// user_guid: is user supplied guid conforming the C2PA spec for manifest names
    /// claim_generator: User agent see c2pa spec for format
    /// claim_version: the Claim version to generate
    pub fn new_with_user_guid<S: Into<String>>(
        claim_generator: S,
        user_guid: S,
        claim_version: usize,
    ) -> Result<Self> {
        let mparts = manifest_label_to_parts(&user_guid.into())
            .ok_or(Error::BadParam("invalid Claim GUID".into()))?;

        if claim_version == 1 && !mparts.is_v1 || claim_version > 1 && mparts.is_v1 {
            return Err(Error::BadParam("invalid Claim GUID".into()));
        }

        let ug = &mparts.guid;
        let uuid =
            Uuid::try_parse(ug).map_err(|_e| Error::BadParam("invalid Claim GUID".into()))?;
        match uuid.get_version() {
            Some(uuid::Version::Random) => (),
            _ => return Err(Error::BadParam("invalid Claim GUID".into())),
        }

        let label = match mparts.cgi {
            Some(v) => {
                if mparts.is_v1 {
                    format!(
                        "{}:{}:{}",
                        v.to_lowercase(),
                        C2PA_NAMESPACE_V1,
                        uuid.hyphenated().encode_lower(&mut Uuid::encode_buffer())
                    )
                } else {
                    format!(
                        "{}:{}:{}",
                        C2PA_NAMESPACE_V2,
                        uuid.hyphenated().encode_lower(&mut Uuid::encode_buffer()),
                        v.to_lowercase()
                    )
                }
            }
            None => {
                if mparts.is_v1 {
                    format!(
                        "{}:{}",
                        C2PA_NAMESPACE_V1,
                        uuid.hyphenated().encode_lower(&mut Uuid::encode_buffer())
                    )
                } else {
                    format!(
                        "{}:{}",
                        C2PA_NAMESPACE_V2,
                        uuid.hyphenated().encode_lower(&mut Uuid::encode_buffer())
                    )
                }
            }
        };

        Ok(Claim {
            remote_manifest: RemoteManifest::NoRemote,
            root: jumbf::labels::MANIFEST_STORE.to_string(),
            signature_val: Vec::new(),
            ingredients_store: HashMap::new(),
            ingredients_list: Vec::new(),
            label,
            conflict_label: None,
            signature: "".to_string(),

            claim_generator: if claim_version == 1 {
                Some(claim_generator.into())
            } else {
                None
            },
            claim_generator_info: None,
            assertion_store: Vec::new(),
            vc_store: Vec::new(),
            assertions: Vec::new(),
            original_bytes: None,
            original_box_order: None,
            redacted_assertions: None,
            alg: Some(BUILD_HASH_ALG.into()),
            alg_soft: None,
            claim_generator_hints: None,

            title: None,
            format: None,
            instance_id: "".to_string(),

            update_manifest: false,
            is_c2md: false,
            compressed: false,
            data_boxes: Vec::new(),
            metadata: None,
            claim_version,
            created_assertions: Vec::new(),
            gathered_assertions: None,
            context: None,
            spec_version: None,
        })
    }

    /// Set the context for this claim, enabling access to settings.
    ///
    /// This is typically called by the Builder when creating a claim.
    pub fn with_context(mut self, context: Arc<Context>) -> Self {
        self.context = Some(context);
        self
    }

    // Deserializer that maps V1/V2 Claim object into our internal Claim representation.  Note:  Our Claim
    // structure is not the Claim from the spec but an amalgamation that allows us to represent any version
    pub fn from_value(claim_value: c2pa_cbor::Value, label: &str, data: &[u8]) -> Result<Self> {
        // populate claim from the map
        // parse possible fields to figure out which version of the claim is possible.
        let claim_version = if map_cbor_to_type::<Vec<HashedUri>>("assertions", &claim_value)
            .is_some()
            && map_cbor_to_type::<Vec<HashedUri>>("created_assertions", &claim_value).is_none()
        {
            1
        } else if map_cbor_to_type::<Vec<HashedUri>>("created_assertions", &claim_value).is_some()
            && map_cbor_to_type::<Vec<HashedUri>>("assertions", &claim_value).is_none()
        {
            2
        } else {
            return Err(Error::ClaimDecoding(
                "unsupported claim version".to_string(),
            ));
        };

        if claim_version == 1 {
            /* Claim V1 fields
            "claim_generator": tstr,
            "claim_generator_hints",
            "claim_generator_info": [1* generator-info-map],
            "signature": jumbf-uri-type,
            "assertions": [1* $hashed-uri-map],
            "dc:format": tstr, ;
            "instanceID": tstr .size (1..max-tstr-length),
            ? "dc:title": tstr .size (1..max-tstr-length),
            ? "redacted_assertions": [1* jumbf-uri-type],
            ? "alg": tstr .size (1..max-tstr-length),
            ? "alg_soft": tstr .size (1..max-tstr-length),
            ? "metadata": $assertion-metadata-map,
            */

            static V1_FIELDS: [&str; 12] = [
                CLAIM_GENERATOR_F,
                CLAIM_GENERATOR_HINTS_F,
                CLAIM_GENERATOR_INFO_F,
                SIGNATURE_F,
                ASSERTIONS_F,
                DC_FORMAT_F,
                INSTANCE_ID_F,
                DC_TITLE_F,
                REDACTED_ASSERTIONS_F,
                ALG_F,
                ALG_SOFT_F,
                METADATA_F,
            ];

            // make sure only V1 fields are present
            if let c2pa_cbor::Value::Map(m) = &claim_value {
                for v in m.keys() {
                    if let c2pa_cbor::Value::Text(t) = v {
                        if !V1_FIELDS.contains(&t.as_str()) {
                            return Err(Error::ClaimDecoding(format!(
                                "unknown V1 claim field: {t}"
                            )));
                        }
                    } else {
                        return Err(Error::ClaimDecoding("non-text key in V1 claim".to_string()));
                    }
                }
            } else {
                return Err(Error::ClaimDecoding("claim is not an object".to_string()));
            }

            let claim_generator: String = map_cbor_to_type(CLAIM_GENERATOR_F, &claim_value)
                .ok_or(Error::ClaimDecoding(CLAIM_GENERATOR_F.to_string()))?;
            let signature: String = map_cbor_to_type(SIGNATURE_F, &claim_value)
                .ok_or(Error::ClaimDecoding(SIGNATURE_F.to_string()))?;
            let assertions: Vec<HashedUri> = map_cbor_to_type(ASSERTIONS_F, &claim_value)
                .ok_or(Error::ClaimDecoding(ASSERTIONS_F.to_string()))?;
            let format: String = map_cbor_to_type(DC_FORMAT_F, &claim_value)
                .ok_or(Error::ClaimDecoding(DC_FORMAT_F.to_string()))?;
            let instance_id = map_cbor_to_type(INSTANCE_ID_F, &claim_value)
                .ok_or(Error::ClaimDecoding(INSTANCE_ID_F.to_string()))?;

            // optional V1 fields
            let claim_generator_info: Option<Vec<ClaimGeneratorInfo>> =
                map_cbor_to_type(CLAIM_GENERATOR_INFO_F, &claim_value);
            let claim_generator_hints: Option<HashMap<String, Value>> =
                map_cbor_to_type(CLAIM_GENERATOR_HINTS_F, &claim_value);
            let title: Option<String> = map_cbor_to_type(DC_TITLE_F, &claim_value);
            let redacted_assertions: Option<Vec<String>> =
                map_cbor_to_type(REDACTED_ASSERTIONS_F, &claim_value);
            let alg: Option<String> = map_cbor_to_type(ALG_F, &claim_value);
            let alg_soft: Option<String> = map_cbor_to_type(ALG_SOFT_F, &claim_value);
            let metadata: Option<Vec<AssertionMetadata>> =
                map_cbor_to_type(METADATA_F, &claim_value);

            Ok(Claim {
                remote_manifest: RemoteManifest::NoRemote,
                update_manifest: false,
                is_c2md: false,
                compressed: false,
                title,
                format: Some(format),
                instance_id,
                ingredients_store: HashMap::new(),
                ingredients_list: Vec::new(),
                signature_val: Vec::new(),
                root: jumbf::labels::MANIFEST_STORE.to_string(),
                label: label.to_string(),
                conflict_label: None,
                assertion_store: Vec::new(),
                vc_store: Vec::new(),
                claim_generator: Some(claim_generator),
                claim_generator_info,
                signature,
                assertions,
                original_bytes: Some(data.to_owned()),
                original_box_order: None,
                redacted_assertions,
                alg,
                alg_soft,
                claim_generator_hints,
                metadata,
                data_boxes: Vec::new(),
                claim_version,
                created_assertions: Vec::new(),
                gathered_assertions: None,
                context: None,
                spec_version: None,
            })
        } else {
            /* Claim V2 fields
            "instanceID": tstr .size (1..max-tstr-length),
            "claim_generator_info": $generator-info-map,
            "signature": jumbf-uri-type,
            "created_assertions": [1* $hashed-uri-map],
            ? "gathered_assertions": [1* $hashed-uri-map],
            ? "dc:title": tstr .size (1..max-tstr-length),
            ? "redacted_assertions": [1* jumbf-uri-type],
            ? "alg": tstr .size (1..max-tstr-length),
            ? "alg_soft": tstr .size (1..max-tstr-length),
            ? "metadata": $assertion-metadata-map,
            ? "spec_version": semver-string,
            ? any unknown fields
            */

            let instance_id = map_cbor_to_type(INSTANCE_ID_F, &claim_value).ok_or(
                Error::ClaimDecoding("instanceID is missing or invalid".to_string()),
            )?;
            let claim_generator_info: ClaimGeneratorInfo =
                map_cbor_to_type(CLAIM_GENERATOR_INFO_F, &claim_value).ok_or(
                    Error::ClaimDecoding("claim_generator_info is missing or invalid".to_string()),
                )?;
            let signature: String = map_cbor_to_type(SIGNATURE_F, &claim_value).ok_or(
                Error::ClaimDecoding("signature is missing or invalid".to_string()),
            )?;
            let created_assertions: Vec<HashedUri> =
                map_cbor_to_type(CREATED_ASSERTIONS_F, &claim_value).ok_or(
                    Error::ClaimDecoding("created_assertions is missing or invalid".to_string()),
                )?;

            // optional V2 fields
            let gathered_assertions: Option<Vec<HashedUri>> =
                map_cbor_to_type(GATHERED_ASSERTIONS_F, &claim_value);
            let title: Option<String> = map_cbor_to_type(DC_TITLE_F, &claim_value);
            let redacted_assertions: Option<Vec<String>> =
                map_cbor_to_type(REDACTED_ASSERTIONS_F, &claim_value);
            let alg: Option<String> = map_cbor_to_type(ALG_F, &claim_value);
            let alg_soft: Option<String> = map_cbor_to_type(ALG_SOFT_F, &claim_value);
            let metadata: Option<Vec<AssertionMetadata>> =
                map_cbor_to_type(METADATA_F, &claim_value);
            let spec_version: Option<String> = map_cbor_to_type(SPEC_VERSION_F, &claim_value);

            // create merged list of created and gathered assertions for processing compatibility
            // created are added first with highest priority than gathered
            let mut assertions = created_assertions.clone();
            if let Some(ga) = &gathered_assertions {
                assertions.append(&mut ga.clone());
            }

            Ok(Claim {
                remote_manifest: RemoteManifest::NoRemote,
                update_manifest: false,
                is_c2md: false,
                compressed: false,
                title,
                format: None,
                instance_id,
                ingredients_store: HashMap::new(),
                ingredients_list: Vec::new(),
                signature_val: Vec::new(),
                root: jumbf::labels::MANIFEST_STORE.to_string(),
                label: label.to_string(),
                conflict_label: None,
                assertion_store: Vec::new(),
                vc_store: Vec::new(),
                claim_generator: None,
                claim_generator_info: Some([claim_generator_info].to_vec()),
                signature,
                assertions,
                original_bytes: Some(data.to_owned()),
                original_box_order: None,
                redacted_assertions,
                alg,
                alg_soft,
                claim_generator_hints: None,
                metadata,
                data_boxes: Vec::new(),
                claim_version,
                created_assertions,
                gathered_assertions,
                spec_version,
                context: None,
            })
        }
    }

    fn serialize_v1<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        /* Claim V1 fields
            "claim_generator": tstr,
            "claim_generator_info": [1* generator-info-map],
            "signature": jumbf-uri-type,
            "assertions": [1* $hashed-uri-map],
            "dc:format": tstr, ;
            "instanceID": tstr .size (1..max-tstr-length),
            ? "dc:title": tstr .size (1..max-tstr-length),
            ? "redacted_assertions": [1* jumbf-uri-type],
            ? "alg": tstr .size (1..max-tstr-length),
            ? "alg_soft": tstr .size (1..max-tstr-length),
            ? "metadata": $assertion-metadata-map,
        */
        let mut claim_map_len = 6;
        if self.title().is_some() {
            claim_map_len += 1
        }
        if self.redactions().is_some() {
            claim_map_len += 1
        }
        if self.alg.is_some() {
            claim_map_len += 1
        }
        if self.alg_soft.is_some() {
            claim_map_len += 1
        }
        if self.metadata().is_some() {
            claim_map_len += 1
        }

        let mut claim_map = serializer.serialize_struct("Claim", claim_map_len)?;

        // serialize mandatory fields
        if let Some(cg) = self.claim_generator() {
            claim_map.serialize_field(CLAIM_GENERATOR_F, cg)?;
        } // todo: what if there is no claim_generator?

        if let Some(cgi) = self.claim_generator_info() {
            claim_map.serialize_field(CLAIM_GENERATOR_INFO_F, cgi)?;
        } else {
            let v: Vec<ClaimGeneratorInfo> = Vec::new();
            claim_map.serialize_field(CLAIM_GENERATOR_INFO_F, &v)?;
        }

        claim_map.serialize_field(SIGNATURE_F, &self.signature)?;
        claim_map.serialize_field(ASSERTIONS_F, self.assertions())?;
        if let Some(format) = self.format() {
            claim_map.serialize_field(DC_FORMAT_F, format)?;
        } //todo: what if there is no format?
        claim_map.serialize_field(INSTANCE_ID_F, self.instance_id())?;

        // serialize optional fields
        if let Some(title) = self.title() {
            claim_map.serialize_field(DC_TITLE_F, title)?;
        }
        if let Some(ra) = self.redactions() {
            claim_map.serialize_field(REDACTED_ASSERTIONS_F, ra)?;
        }
        claim_map.serialize_field(ALG_F, self.alg())?;
        if let Some(soft) = self.alg_soft() {
            claim_map.serialize_field(ALG_SOFT_F, soft)?;
        }
        if let Some(md) = self.metadata() {
            claim_map.serialize_field(METADATA_F, md)?;
        }

        claim_map.end()
    }

    fn serialize_v2<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        /* Claim V2 fields
        "instanceID": tstr .size (1..max-tstr-length),
        "claim_generator_info": $generator-info-map,
        "signature": jumbf-uri-type,
        "created_assertions": [1* $hashed-uri-map],
        ? "gathered_assertions": [1* $hashed-uri-map],
        ? "dc:title": tstr .size (1..max-tstr-length),
        ? "redacted_assertions": [1* jumbf-uri-type],
        ? "alg": tstr .size (1..max-tstr-length),
        ? "alg_soft": tstr .size (1..max-tstr-length),
        ? "spec_version": semver-string,
        ? "metadata": $assertion-metadata-map,
        */

        let mut claim_map_len = 4;

        if self.gathered_assertions.is_some() {
            claim_map_len += 1
        }
        if self.title.is_some() {
            claim_map_len += 1
        }
        if self.redacted_assertions.is_some() {
            claim_map_len += 1
        }
        if self.alg.is_some() {
            claim_map_len += 1
        }
        if self.alg_soft.is_some() {
            claim_map_len += 1
        }
        if self.metadata.is_some() {
            claim_map_len += 1
        }
        if self.spec_version.is_some() {
            claim_map_len += 1
        }

        let mut claim_map = serializer.serialize_struct("Claim", claim_map_len)?;

        // serialize mandatory fields
        claim_map.serialize_field(INSTANCE_ID_F, self.instance_id())?;

        if let Some(cgi) = self.claim_generator_info() {
            if !cgi.is_empty() {
                claim_map.serialize_field(CLAIM_GENERATOR_INFO_F, &cgi[0])?;
            } else {
                return Err(serde::ser::Error::custom(
                    "claim_generator_info is mandatory",
                ));
            }
        } else {
            return Err(serde::ser::Error::custom(
                "claim_generator_info is mandatory",
            ));
        }

        claim_map.serialize_field(SIGNATURE_F, &self.signature)?;
        claim_map.serialize_field(CREATED_ASSERTIONS_F, &self.created_assertions)?;

        // serialize optional fields
        if let Some(ga) = &self.gathered_assertions {
            claim_map.serialize_field(GATHERED_ASSERTIONS_F, ga)?;
        }
        if let Some(title) = self.title() {
            claim_map.serialize_field(DC_TITLE_F, title)?;
        }
        if let Some(ra) = self.redactions() {
            claim_map.serialize_field(REDACTED_ASSERTIONS_F, ra)?;
        }
        claim_map.serialize_field(ALG_F, self.alg())?;
        if let Some(soft) = self.alg_soft() {
            claim_map.serialize_field(ALG_SOFT_F, soft)?;
        }
        if let Some(md) = self.metadata() {
            claim_map.serialize_field(METADATA_F, md)?;
        }
        if let Some(spec_version) = &self.spec_version {
            claim_map.serialize_field(SPEC_VERSION_F, spec_version)?;
        }

        claim_map.end()
    }

    /// Build a claim and verify its integrity.
    pub fn build(&mut self) -> Result<()> {
        // A claim must have a signature box.
        if self.signature.is_empty() {
            self.add_signature_box_link();
        }

        // make sure we have a claim_generator_info for v2
        if self.claim_version > 1 {
            match &self.claim_generator_info {
                Some(cgi) => {
                    if cgi.len() > 1 {
                        return Err(Error::VersionCompatibility(
                            "only 1 claim_generator_info allowed".into(),
                        ));
                    }
                }
                None => {
                    return Err(Error::VersionCompatibility(
                        "claim_generator_info is mandatory".into(),
                    ))
                }
            }
        }

        // make sure there is only one claim thumbnail
        if self
            .claim_assertion_store()
            .iter()
            .filter(|ca| ca.label_raw().contains(CLAIM_THUMBNAIL))
            .count()
            > 1
        {
            return Err(Error::OtherError(
                "only one claim thumbnail assertion allowed".into(),
            ));
        }

        Ok(())
    }

    /// return max version this Claim supports
    pub fn build_version_support() -> String {
        format!("{CLAIM}.v{BUILD_VER_SUPPORT}")
    }

    /// Return the JUMBF label for this claim.
    pub fn label(&self) -> &str {
        if let Some(label) = &self.conflict_label {
            label
        } else {
            &self.label
        }
    }

    /// Return the alternate JUMBF label for this claim have a conflicting reference.
    pub fn conflict_label(&self) -> &Option<String> {
        &self.conflict_label
    }

    /// Set new label for ingredient conflict resolution
    pub fn set_conflict_label(&mut self, new_label: String) {
        self.conflict_label = Some(new_label);
    }

    // Return vendor if part of manifest label
    pub fn vendor(&self) -> Option<String> {
        let mp = manifest_label_to_parts(&self.uri())?;
        mp.cgi
    }

    // Return version if V2 claim and if part of manifest label
    pub fn claim_instance_version(&self) -> Option<usize> {
        let mp = manifest_label_to_parts(&self.uri())?;
        mp.version
    }

    // Return reason if V2 claim and if part of manifest label
    pub fn claim_instance_reason(&self) -> Option<usize> {
        let mp = manifest_label_to_parts(&self.uri())?;
        mp.reason
    }

    /// Return the JUMBF URI for this claim.
    pub fn uri(&self) -> String {
        jumbf::labels::to_manifest_uri(self.label())
    }

    /// Return the JUMBF URI for an assertion on this claim.
    pub fn assertion_uri(&self, assertion_label: &str) -> String {
        jumbf::labels::to_assertion_uri(self.label(), assertion_label)
    }

    /// Return the JUMBF Signature URI for this claim.
    pub fn signature_uri(&self) -> String {
        jumbf::labels::to_signature_uri(self.label())
    }

    // Add link to the signature box for this claim.
    fn add_signature_box_link(&mut self) {
        // full path to signature box
        self.signature = self.signature_uri();
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
    pub fn claim_generator(&self) -> Option<&str> {
        self.claim_generator.as_deref()
    }

    /// get format
    pub fn format(&self) -> Option<&str> {
        self.format.as_deref()
    }

    /// get instance_id
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// set title, deprecated in C2PA 2.4.  Claim generators should create a c2pa.metadata assertion containing the dc:title field.
    pub fn set_title(&mut self, title: Option<String>) {
        self.title = title;
    }

    /// get title
    pub fn title(&self) -> Option<&String> {
        self.title.as_ref()
    }

    /// order for which to generate the JUMBF boxes with writing manifest
    pub fn set_box_order(&mut self, box_order: Vec<&'static str>) {
        self.original_box_order = Some(box_order);
    }

    /// order to process
    pub fn get_box_order(&self) -> &[&str] {
        const DEFAULT_MANIFEST_ORDER: [&str; 5] =
            [ASSERTIONS, CLAIM, SIGNATURE, CREDENTIALS, DATABOXES];

        if let Some(bo) = &self.original_box_order {
            bo
        } else {
            &DEFAULT_MANIFEST_ORDER
        }
    }

    /// get algorithm
    pub fn alg(&self) -> &str {
        match self.alg.as_ref() {
            Some(alg) => alg,
            None => BUILD_HASH_ALG,
        }
    }

    /// true algorithm
    pub fn alg_raw(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// get soft algorithm
    pub fn alg_soft(&self) -> Option<&String> {
        self.alg_soft.as_ref()
    }

    /// Is this an update manifest
    pub fn update_manifest(&self) -> bool {
        self.update_manifest
    }

    /// True if this claim was read from a `c2md`-tagged superbox (C2PA spec
    /// 11.2.2) rather than an ordinary `c2ma` standard manifest.
    pub fn is_c2md(&self) -> bool {
        self.is_c2md
    }

    // get version of the Claim
    pub fn version(&self) -> usize {
        self.claim_version
    }

    // manifests compression enabled
    pub fn compressed(&self) -> bool {
        self.compressed
    }

    pub(crate) fn set_compressed_manifest(&mut self, compressed: bool) {
        self.compressed = compressed;
    }

    pub fn set_remote_manifest<S: Into<String> + AsRef<str>>(
        &mut self,
        remote_url: S,
    ) -> Result<()> {
        let url = url::Url::parse(remote_url.as_ref())
            .map_err(|_e| Error::BadParam("remote url is badly formed".to_string()))?;
        self.remote_manifest = RemoteManifest::Remote(url.to_string());

        Ok(())
    }

    pub fn set_embed_remote_manifest<S: Into<String> + AsRef<str>>(
        &mut self,
        remote_url: S,
    ) -> Result<()> {
        let url = url::Url::parse(remote_url.as_ref())
            .map_err(|_e| Error::BadParam("remote url is badly formed".to_string()))?;
        self.remote_manifest = RemoteManifest::EmbedWithRemote(url.to_string());

        Ok(())
    }

    pub fn set_external_manifest(&mut self) {
        self.remote_manifest = RemoteManifest::SideCar;
    }

    pub(crate) fn remote_manifest(&self) -> RemoteManifest {
        self.remote_manifest.clone()
    }

    pub(crate) fn set_update_manifest(&mut self, is_update_manifest: bool) {
        self.update_manifest = is_update_manifest;
    }

    pub(crate) fn set_is_c2md(&mut self, is_c2md: bool) {
        self.is_c2md = is_c2md;
    }

    /// Adds an action to the claim.
    ///
    /// If an Actions assertion already exists, the action is added to it.
    /// If not, a new Actions assertion is created and added to the claim.
    /// If multiple exist, this will update the first one found.
    pub fn add_action(&mut self, action: Action) -> Result<&mut Self> {
        match self.get_assertion(Actions::LABEL_VERSIONED, 0) {
            None => {
                let actions = Actions::new().add_action_checked(action)?;
                self.add_assertion(&actions)?;
            }
            Some(a) => {
                let actions = Actions::from_assertion(a)?;

                let actions = actions.add_action_checked(action)?;

                self.replace_assertion(actions.to_assertion()?)?;
            }
        };
        Ok(self)
    }

    pub fn add_claim_generator_info(&mut self, info: ClaimGeneratorInfo) -> &mut Self {
        match self.claim_generator_info.as_mut() {
            Some(cgi) => cgi.push(info),
            None => self.claim_generator_info = Some([info].to_vec()),
        }
        self
    }

    pub fn claim_generator_info(&self) -> Option<&[ClaimGeneratorInfo]> {
        self.claim_generator_info.as_deref()
    }

    pub fn add_claim_metadata(&mut self, md: AssertionMetadata) -> &mut Self {
        match self.metadata.as_mut() {
            Some(md_vec) => md_vec.push(md),
            None => self.metadata = Some([md].to_vec()),
        }
        self
    }

    pub fn metadata(&self) -> Option<&[AssertionMetadata]> {
        self.metadata.as_deref()
    }

    pub fn spec_version(&self) -> Option<&String> {
        match self.claim_generator_info() {
            // Spec 2.4 case
            Some(cgi) => {
                // for Claims V2 there must be a single CGI item
                if self.version() > 1 && cgi.len() == 1 {
                    return cgi[0].get_spec_version();
                }
                None
            }
            None => self.spec_version.as_ref(), // legacy case where SpecVersion was including in Claim map
        }
    }

    /// Deprecated in  C2PA 2.4 or greater compatible manifests. Replaced by equiveaent value in ClaimGeneratorInfo.
    #[deprecated(
        since = "0.91.0",
        note = "The `specVersion` claim field is deprecated from C2PA spec version 2.4. Use `ClaimGeneratorInfo::set_spec_version` instead. Will be removed in 0.92.0 (scheduled for mid-November 2026)."
    )]
    pub fn set_spec_version(&mut self, spec_version: Option<String>) {
        self.spec_version = spec_version;
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
                        Value::String(format!("{curr_val}, {append_val}")),
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

    pub fn calc_sig_box_hash(claim: &Claim, alg: &str) -> Result<Vec<u8>> {
        c2pa_encoding::calc_signature_box_hash(claim.signature_val().clone(), alg)
    }

    pub fn calc_assertion_box_hash(
        label: &str,
        assertion: &Assertion,
        salt: Option<Vec<u8>>,
        alg: &str,
    ) -> Result<Vec<u8>> {
        c2pa_encoding::calc_assertion_box_hash(label, assertion, salt, alg)
    }

    /// Add an assertion to this claim and verify
    /// This uses a default salt generator and will assumed gathered for Claims V2 except for HASH assertions.
    pub fn add_assertion(
        &mut self,
        assertion_builder: &impl AssertionBase,
    ) -> Result<C2PAAssertion> {
        self.add_assertion_impl(assertion_builder, &DefaultSalt::default(), false, None)
    }

    /// Same as add_assertion but forces addition to created_assertions for Claims V2
    pub fn add_created_assertion(
        &mut self,
        assertion_builder: &impl AssertionBase,
    ) -> Result<C2PAAssertion> {
        self.add_assertion_impl(assertion_builder, &DefaultSalt::default(), true, None)
    }

    /// Same as `add_assertion`/`add_created_assertion`, but reuses `preferred_label` verbatim
    /// (instead of assigning the next positional `__N` instance) when that label is a free slot
    /// for this assertion's base label.
    ///
    /// A round-tripped ingredient (rebuilt via [`crate::Ingredient::from_ingredient_uri`], e.g.
    /// through [`crate::Builder::with_archive`] or [`crate::Reader::into_builder`]) already carries
    /// the JUMBF label it was assigned the first time it was added to a claim. Re-adding it to a
    /// new claim via plain positional numbering can silently assign that label to a *different*
    /// ingredient whenever ingredients are re-processed in a different relative order — which
    /// happens whenever ingredients land in different created/gathered buckets, since a claim's
    /// V2 wire format only preserves order within each bucket, not the original interleaving
    /// across both (see `Claim::from_value`). Any reference to the old label that was already
    /// baked into a `HashedUri` (e.g. an action's `ingredientIds`) would then point at the wrong
    /// ingredient. Reusing the label keeps that identity stable across reloads.
    ///
    /// Falls back to positional numbering if `preferred_label` doesn't share this assertion's
    /// base label, or if it's already taken by another assertion in this claim.
    pub(crate) fn add_assertion_with_preferred_label(
        &mut self,
        assertion_builder: &impl AssertionBase,
        add_as_created_assertion: bool,
        preferred_label: Option<&str>,
    ) -> Result<C2PAAssertion> {
        self.add_assertion_impl(
            assertion_builder,
            &DefaultSalt::default(),
            add_as_created_assertion,
            preferred_label,
        )
    }

    fn compatibility_checks(&self, assertion: &Assertion) -> Result<()> {
        let assertion_version = assertion.get_ver();
        let assertion_label = assertion.label();

        if assertion_label == ACTIONS {
            // check for actions V1
            if assertion_version < 1 {
                return Err(Error::VersionCompatibility(
                    "action assertion version too low".into(),
                ));
            }

            // check for deprecated actions
            let ac = Actions::from_assertion(assertion)?;
            for action in ac.actions() {
                if V2_DEPRECATED_ACTIONS.contains(&action.action()) {
                    return Err(Error::VersionCompatibility(
                        "action assertion has been deprecated".into(),
                    ));
                }
            }
        }

        // version 1 BMFF hash is deprecated
        if assertion_label == BMFF_HASH && assertion_version < 2 {
            return Err(Error::VersionCompatibility(
                "BMFF hash assertion version too low".into(),
            ));
        }

        /*
        // only allow deprecated assertions in created_assertion list
        if V2_SPEC_DEPRECATED_ASSERTIONS.contains(&assertion.label().as_str()) {
            return Err(Error::VersionCompatibility(
                "C2PA deprecated assertion should be added to gather_assertions".into(),
            ));
        }
        */

        Ok(())
    }

    /// Determine if an assertion should be added as a created or gathered assertion
    /// for Claims V2 and later
    fn claim_assertion_type(
        &self,
        base_label: &str,
        add_as_created_assertion: bool,
    ) -> ClaimAssertionType {
        if self.version() > 1 {
            if labels::HASH_LABELS.contains(&base_label) || add_as_created_assertion {
                ClaimAssertionType::Created
            } else if let Some(created_assertions) = self
                .context
                .as_ref()
                .and_then(|c| c.settings().builder.created_assertion_labels.as_ref())
            {
                if created_assertions.iter().any(|label| label == base_label) {
                    ClaimAssertionType::Created
                } else {
                    ClaimAssertionType::Gathered
                }
            } else {
                ClaimAssertionType::Gathered
            }
        } else {
            ClaimAssertionType::V1
        }
    }

    /// Add an assertion to this claim
    /// Allows setting the salt generator and whether to add as created assertion for Claims V2
    fn add_assertion_impl(
        &mut self,
        assertion_builder: &impl AssertionBase,
        salt_generator: &impl SaltGenerator,
        add_as_created_assertion: bool,
        preferred_label: Option<&str>,
    ) -> Result<C2PAAssertion> {
        // Enforce the per-manifest assertion limit to prevent resource exhaustion
        // regardless of how the claim is constructed.
        if self.assertion_store.len() >= MAX_ASSERTIONS {
            return Err(Error::TooManyAssertions {
                max: MAX_ASSERTIONS,
            });
        }

        // make sure the assertion is valid
        let assertion = assertion_builder.to_assertion()?;
        let assertion_label = assertion.label();

        // Update label if there are multiple instances of the same claim type. Reuse
        // `preferred_label` verbatim when it names a free slot for this assertion's base label
        // (see `add_assertion_with_preferred_label`); otherwise fall back to the next positional
        // instance.
        let as_label = match preferred_label {
            Some(label)
                if labels::parse_label(label).0 == labels::parse_label(&assertion_label).0
                    && labels::parse_label(label).1 == labels::parse_label(&assertion_label).1
                    && !self.assertion_store.iter().any(|ca| ca.label() == label) =>
            {
                label.to_string()
            }
            _ => self.make_assertion_instance_label(assertion_label.as_ref()),
        };
        // get base label and instance
        let (base_label, _version, instance) = labels::parse_label(&as_label);

        // check for deprecated assertions when using Claims > V1
        if self.version() > 1 {
            self.compatibility_checks(&assertion)?
        }

        let salt = salt_generator.generate_salt();

        // Get hash of the assertion's contents.
        let hash = Claim::calc_assertion_box_hash(&as_label, &assertion, salt.clone(), self.alg())?;

        // Build hash link.
        let link = jumbf::labels::to_assertion_uri(self.label(), &as_label);
        let link_relative = jumbf::labels::to_relative_uri(&link);

        let mut c2pa_assertion = C2PAAssertion::new(link_relative, None, &hash);

        // Add salt
        c2pa_assertion.add_salt(salt.clone());

        // find the ClaimAssertionType and add to gathered or created lists if needed
        let assertion_type = self.claim_assertion_type(base_label, add_as_created_assertion);

        match assertion_type {
            ClaimAssertionType::Created => {
                self.created_assertions.push(c2pa_assertion.clone());
            }
            ClaimAssertionType::Gathered => self
                .gathered_assertions
                .get_or_insert_default()
                .push(c2pa_assertion.clone()),
            ClaimAssertionType::V1 => { /* not created or gathered */ }
        }

        let ca = ClaimAssertion::new(assertion, instance, &hash, self.alg(), salt, assertion_type);
        self.assertion_store.push(ca);
        self.assertions.push(c2pa_assertion.clone());

        Ok(c2pa_assertion)
    }

    // Add a new DataBox and return the HashedURI reference
    pub fn add_databox(
        &mut self,
        format: &str,
        data: Vec<u8>,
        data_types: Option<Vec<AssetType>>,
    ) -> Result<HashedUri> {
        // create data box
        let new_db = DataBox {
            format: format.to_string(),
            data,
            data_types,
        };

        // serialize to cbor
        let db_cbor =
            c2pa_cbor::to_vec(&new_db).map_err(|err| Error::AssertionEncoding(err.to_string()))?;

        // get the index for the new assertion
        let mut index = 0;
        for (uri, _db) in &self.data_boxes {
            let (_l, i) = Claim::assertion_label_from_link(&uri.url());
            if i >= index {
                index = i + 1;
            }
        }

        let label = Claim::label_with_instance(DATABOX, index);
        let link = jumbf::labels::to_databox_uri(self.label(), &label);

        // salt box for 1.2 VC redaction support
        let ds = DefaultSalt::default();
        let salt = ds.generate_salt();

        // assertion JUMBF box hash for 1.2 validation
        let assertion = Assertion::from_data_cbor(&label, &db_cbor);
        let hash = Claim::calc_assertion_box_hash(&label, &assertion, salt.clone(), self.alg())?;

        let mut databox_uri = C2PAAssertion::new(link, Some(self.alg().to_string()), &hash);
        databox_uri.add_salt(salt);

        // add databox to databox store
        self.data_boxes.push((databox_uri.clone(), new_db));

        Ok(databox_uri)
    }

    pub(crate) fn databoxes(&self) -> &Vec<(HashedUri, DataBox)> {
        &self.data_boxes
    }

    /// Load known VC with optional salt
    pub(crate) fn put_databox(
        &mut self,
        label: &str,
        databox_cbor: &[u8],
        salt: Option<Vec<u8>>,
    ) -> Result<()> {
        let link = jumbf::labels::to_databox_uri(self.label(), label);

        // assertion JUMBF box hash for 1.2 validation
        let assertion = Assertion::from_data_cbor(label, databox_cbor);
        let hash = Claim::calc_assertion_box_hash(label, &assertion, salt.clone(), self.alg())?;

        let mut uri = C2PAAssertion::new(link, Some(self.alg().to_string()), &hash);
        uri.add_salt(salt);

        let db: DataBox = c2pa_cbor::from_slice(databox_cbor)
            .map_err(|err| Error::AssertionEncoding(err.to_string()))?;

        // add data box  to data box store
        self.data_boxes.push((uri, db));

        Ok(())
    }

    pub fn get_databox(&self, hr: &HashedUri) -> Option<&DataBox> {
        // normalize uri
        let normalized_uri = if let Some(manifest) = manifest_label_from_uri(&hr.url()) {
            if manifest != self.label() {
                return None;
            }
            hr.url()
        } else {
            // make a full path
            let box_name = box_name_from_uri(&hr.url())?;
            to_databox_uri(self.label(), &box_name)
        };

        self.data_boxes.iter().find_map(|x| {
            if x.0.url() == normalized_uri && vec_compare(&x.0.hash(), &hr.hash()) {
                Some(&x.1)
            } else {
                None
            }
        })
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
        if self.claim_version > 1 {
            // VC store is not supported post version 1
            return Err(Error::VersionCompatibility(
                "verifiable credentials not supported".into(),
            ));
        }

        let id = Claim::vc_id(vc_json)?;
        let credential = AssertionData::Json(vc_json.to_string());

        let link = jumbf::labels::to_verifiable_credential_uri(self.label(), &id);

        // salt box for 1.2 VC redaction support
        let ds = DefaultSalt::default();
        let salt = ds.generate_salt();

        // assertion JUMBF box hash for 1.2 validation
        let assertion = Assertion::from_data_json(&id, vc_json.as_bytes())?;
        let hash = Claim::calc_assertion_box_hash(&id, &assertion, salt.clone(), self.alg())?;

        let mut c2pa_assertion = C2PAAssertion::new(link, Some(self.alg().to_string()), &hash);
        c2pa_assertion.add_salt(salt);

        // add credential to vcstore
        self.vc_store.push((c2pa_assertion.clone(), credential));

        Ok(c2pa_assertion)
    }

    /// Load known VC with optional salt
    pub(crate) fn put_verifiable_credential(
        &mut self,
        vc_json: &str,
        salt: Option<Vec<u8>>,
    ) -> Result<()> {
        let id = Claim::vc_id(vc_json)?;
        let credential = AssertionData::Json(vc_json.to_string());

        let link = jumbf::labels::to_verifiable_credential_uri(self.label(), &id);

        // assertion JUMBF box hash for 1.2 validation
        let assertion = Assertion::from_data_json(&id, vc_json.as_bytes())?;
        let hash = Claim::calc_assertion_box_hash(&id, &assertion, salt.clone(), self.alg())?;

        let mut c2pa_assertion = C2PAAssertion::new(link, Some(self.alg().to_string()), &hash);
        c2pa_assertion.add_salt(salt);

        // add credential to vcstore
        self.vc_store.push((c2pa_assertion, credential));

        Ok(())
    }

    pub fn get_verifiable_credentials(&self) -> Vec<&AssertionData> {
        self.vc_store.iter().map(|t| &t.1).collect::<Vec<_>>()
    }

    pub fn get_verifiable_credentials_store(&self) -> &Vec<(HashedUri, AssertionData)> {
        &self.vc_store
    }

    /// Add directly to store during a reload of a claim
    pub(crate) fn put_assertion_store(&mut self, assertion: ClaimAssertion) {
        self.assertion_store.push(assertion);
    }

    // Patch an existing assertion with new contents.
    //
    // `replace_with` should match in name and size of an existing assertion.
    pub(crate) fn update_assertion<MatchFn, PatchFn>(
        &mut self,
        replace_with: Assertion,
        match_fn: MatchFn,
        patch_fn: PatchFn,
    ) -> Result<()>
    where
        MatchFn: Fn(&ClaimAssertion) -> bool,
        PatchFn: FnOnce(&ClaimAssertion, Assertion) -> Result<Assertion>,
    {
        // Find the assertion that should be replaced.
        let Some(ref mut target_assertion) = self
            .assertion_store
            .iter_mut()
            .find(|ca| Assertion::assertions_eq(&replace_with, ca.assertion()) && match_fn(ca))
        else {
            return Err(Error::NotFound);
        };

        // Save off copy of original hash to cross-check before
        // replacing it.
        let original_hash = target_assertion.hash().to_vec();

        // Give caller a chance to patch/replace the assertion.
        let replace_with = patch_fn(target_assertion, replace_with)?;

        // Calculate new hash, given new content.
        let replacement_hash = Claim::calc_assertion_box_hash(
            &target_assertion.label(),
            &replace_with,
            target_assertion.salt().clone(),
            target_assertion.hash_alg(),
        )?;

        target_assertion.update_assertion(replace_with, replacement_hash)?;

        let target_label = target_assertion.label();
        let target_hash = target_assertion.hash();

        // Replace the existing hash in the hashed URI reference
        // with the newly-calculated hash.
        let Some(f) = self
            .assertions
            .iter_mut()
            .find(|f| f.url().contains(&target_label) && vec_compare(&f.hash(), &original_hash))
        else {
            return Err(Error::NotFound);
        };

        // Replace existing hash with newly-calculated hash.
        f.update_hash(target_hash.to_vec());

        // fix up ClaimV2 URI reference for created assertions
        if let Some(f) = self
            .created_assertions
            .iter_mut()
            .find(|f| f.url().contains(&target_label) && vec_compare(&f.hash(), &original_hash))
        {
            // Replace existing hash with newly-calculated hash.
            f.update_hash(target_hash.to_vec());
        };

        // fix up ClaimV2 URI reference for gathered assertions
        if let Some(f) = self.gathered_assertions.as_mut().and_then(|ga| {
            ga.iter_mut()
                .find(|f| f.url().contains(&target_label) && vec_compare(&f.hash(), &original_hash))
        }) {
            f.update_hash(target_hash.to_vec())
        };
        // clear original since content has changed
        self.clear_data();

        Ok(())
    }

    // Crate private function to allow for patching a data hash with final contents.
    pub(crate) fn update_data_hash(&mut self, mut data_hash: DataHash) -> Result<()> {
        let dh_name = data_hash.name.clone();

        self.update_assertion(
            data_hash.to_assertion()?,
            |ca: &ClaimAssertion| {
                if let Ok(dh) = DataHash::from_assertion(ca.assertion()) {
                    dh.name == dh_name
                } else {
                    false
                }
            },
            |target_assertion: &ClaimAssertion, _: Assertion| {
                let original_len = target_assertion.assertion().data().len();
                data_hash.pad_to_size(original_len)?;
                data_hash.to_assertion()
            },
        )
    }

    // Crate private function to allow for patching a BMFF hash with final contents.
    pub(crate) fn update_bmff_hash(&mut self, bmff_hash: BmffHash) -> Result<()> {
        self.replace_assertion(bmff_hash.to_assertion()?)
    }

    // Patch an existing assertion with new contents.
    //
    // `replace_with` should match in name and size of an existing assertion.
    pub(crate) fn replace_assertion(&mut self, replace_with: Assertion) -> Result<()> {
        self.update_assertion(
            replace_with,
            |_: &ClaimAssertion| true,
            |_: &ClaimAssertion, a: Assertion| Ok(a),
        )
    }

    /// Replace the assertion with the same label as `replace_with` AND the
    /// given instance number (0 = the first `label`, 1 = `label__1`, ...).
    pub(crate) fn replace_assertion_instance(
        &mut self,
        replace_with: Assertion,
        instance: usize,
    ) -> Result<()> {
        self.update_assertion(
            replace_with,
            |ca: &ClaimAssertion| ca.instance() == instance,
            |_: &ClaimAssertion, a: Assertion| Ok(a),
        )
    }

    /// Redact an assertion from a given claim.
    /// This will remove the assertion from the JUMBF.
    pub(super) fn redact_assertion(&mut self, assertion_uri: &str) -> Result<()> {
        // cannot redact action assertions per the spec
        // cannot redact hash bindings
        let (label, instance) = Claim::assertion_label_from_link(assertion_uri);
        if label.starts_with(assertions::labels::ACTIONS) || label.starts_with("c2pa.hash.") {
            return Err(Error::AssertionInvalidRedaction);
        }

        // A redaction URI may only target this claim.
        if let Some(manifest) = manifest_label_from_uri(assertion_uri) {
            if manifest != self.label() {
                return Err(Error::AssertionRedactionNotFound);
            }
        }

        // Delete assertion or databox
        if assertion_uri.contains(ASSERTION_STORE) {
            // Compare the assertion label strictly using label and instance,
            // with both sides normalized so they are comparable.
            // `assertion_label_from_link` truncates the URI's label at `__`.
            // Currently, the stored side is always normalized on ingest, and signing rejects
            // a non-numeric `__` suffix, so a manifest we read here can not hold such a label.
            let target = Claim::label_with_instance(&label, instance);
            if let Some(index) = self
                .assertion_store
                .iter()
                .position(|x| Claim::label_with_instance(&x.label_raw(), x.instance()) == target)
            {
                self.assertion_store.remove(index);
                return Ok(());
            }
        } else if assertion_uri.contains(DATABOX_STORE) {
            // Normalize to a (full) databox URI.
            let box_name =
                box_name_from_uri(assertion_uri).ok_or(Error::AssertionRedactionNotFound)?;
            let target = to_normalized_uri(&to_databox_uri(self.label(), &box_name));
            if let Some(index) = self
                .databoxes()
                .iter()
                .position(|(x, _d)| to_normalized_uri(&x.url()) == target)
            {
                self.data_boxes.remove(index);
                return Ok(());
            }
        }

        Err(Error::AssertionRedactionNotFound)
    }

    /// Return a hash of this claim.
    pub fn hash(&self) -> Vec<u8> {
        match self.data() {
            Ok(claim_data) => hash_by_alg(self.alg(), &claim_data, None),
            Err(_) => Vec::new(), //  should never happen bug if it does just give no hash
        }
    }

    ///Returns list of metadata assertions
    pub fn metadata_assertions(&self) -> Vec<&ClaimAssertion> {
        let mut mda: Vec<&ClaimAssertion> = self
            .assertion_store
            .iter()
            .filter(|x| METADATA_LABEL_REGEX.is_match(&x.label_raw()))
            .collect();

        // we don't include c2pa.assertion.metadata
        mda.retain(|a| a.label() != ASSERTION_METADATA);

        mda
    }

    /// Return list of data hash assertions.
    ///
    /// For v2+ claims, only created assertions are returned; gathered hash
    /// assertions are excluded because hard bindings must be in created_assertions.
    pub fn hash_assertions(&self) -> Vec<&ClaimAssertion> {
        let created_only = self.claim_version >= 2;

        self.assertion_store
            .iter()
            .filter(|ca| {
                labels::HASH_LABELS.contains(&ca.assertion().label_root().as_str())
                    && (!created_only || ca.assertion_type() == ClaimAssertionType::Created)
            })
            .collect()
    }

    /// Returns assertions whose label root (no version or instance suffix) equals `label`.
    fn assertions_by_label(
        &self,
        label: &str,
        assertion_type: Option<ClaimAssertionType>,
    ) -> Vec<&ClaimAssertion> {
        self.assertion_store
            .iter()
            .filter(|ca| {
                ca.assertion().label_root() == label
                    && assertion_type
                        .as_ref()
                        .is_none_or(|t| ca.assertion_type() == *t)
            })
            .collect()
    }

    pub fn bmff_hash_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::BMFF_HASH, None)
    }

    /// Return list of soft binding assertions.
    pub fn soft_binding_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::SOFT_BINDING, None)
    }

    /// Return list of cloud data assertions.
    pub fn cloud_data_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::CLOUD_DATA, None)
    }

    pub fn data_hash_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::DATA_HASH, None)
    }

    pub fn box_hash_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::BOX_HASH, None)
    }

    pub fn collection_hash_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::COLLECTION_HASH, None)
    }

    /// Return list of ingredient assertions. This function
    /// is only useful on committed or loaded claims since ingredients
    /// are resolved at commit time.
    pub fn ingredient_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::INGREDIENT, None)
    }

    /// Return list of timestamp assertions.
    pub fn timestamp_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::TIMESTAMP, None)
    }

    /// Returns list of certificate status assertions.
    pub fn certificate_status_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::CERTIFICATE_STATUS, None)
    }

    /// Return list of action assertions.
    /// Created assertions have higher priority than gathered assertions
    pub fn action_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::ACTIONS, None)
    }

    /// Return list of gathered action assertions.
    pub fn gathered_action_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::ACTIONS, Some(ClaimAssertionType::Gathered))
    }

    /// Return list of action assertions.
    pub fn created_action_assertions(&self) -> Vec<&ClaimAssertion> {
        self.assertions_by_label(labels::ACTIONS, Some(ClaimAssertionType::Created))
    }

    /// Return reference to the internal claim assertion store.
    pub fn claim_assertion_store(&self) -> &Vec<ClaimAssertion> {
        &self.assertion_store
    }

    /// Return reference to the internal claim ingredient store.
    /// Used during generation
    pub fn claim_ingredient_store(&self) -> &HashMap<String, Claim> {
        &self.ingredients_store
    }

    /// Return mutable reference to the internal claim ingredient store.
    /// Used during generation
    pub fn claim_ingredient_store_mut(&mut self) -> &mut HashMap<String, Claim> {
        &mut self.ingredients_store
    }

    /// Return reference to the internal claim ingredients.
    /// Used during generation
    pub fn claim_ingredients(&self) -> Vec<&Claim> {
        self.ingredients_list
            .iter()
            .filter_map(|l| self.ingredients_store.get(l))
            .collect()
    }

    /// Return reference to the internal claim ingredient store matching this guid.
    /// Used during generation
    pub fn claim_ingredient(&self, claim_guid: &str) -> Option<&Claim> {
        self.ingredients_store.get(claim_guid)
    }

    /// Return mutable reference to the internal claim ingredient store matching this guid.
    /// Used during generation
    pub fn claim_ingredient_mut(&mut self, claim_guid: &str) -> Option<&mut Claim> {
        self.ingredients_store.get_mut(claim_guid)
    }

    /// Adds ingredients, this data will be written out during commit of the Claim
    /// redactions are full uris since they refer to external assertions
    pub(crate) fn add_ingredient_data(
        &mut self,
        mut ingredient: Vec<Claim>,
        redactions_opt: Option<Vec<String>>,
        _referenced_ingredients: &HashMap<String, HashSet<String>>,
    ) -> Result<()> {
        // make sure the ingredient is version compatible
        if ingredient.iter().any(|x| x.claim_version > self.version()) {
            return Err(Error::VersionCompatibility(format!(
                "ingredient claim version is newer than claim version {}",
                self.version()
            )));
        }

        // Redact assertion from incoming ingredients
        // Only apply redactions that match claims in the current ingredient batch,
        // redactions targeting other ingredients will be applied when those are processed
        // (otherwise can't find them).
        // TODO: per C2PA 2.4 spec, when redacting an ingredient assertion that references
        // a C2PA Manifest, the associated manifest should be removed from the Manifest Store
        // if no other references to it remain. This was also TODO'ed before...
        let mut applied_redactions = Vec::new();
        if let Some(redactions) = &redactions_opt {
            for redaction in redactions {
                if let Some(claim) = ingredient
                    .iter_mut()
                    .find(|x| redaction.contains(x.label()))
                {
                    claim.redact_assertion(redaction)?;
                    applied_redactions.push(redaction.clone());
                }
            }
        }

        // accumulate applied redactions across multiple ingredient batches
        match &mut self.redacted_assertions {
            Some(existing) => existing.extend(applied_redactions),
            None if !applied_redactions.is_empty() => {
                self.redacted_assertions = Some(applied_redactions);
            }
            _ => {}
        }

        // just replace the ingredients with new once since conflicts are resolved by the caller
        for i in ingredient {
            self.replace_ingredient_or_insert(i.label().into(), i);
        }

        Ok(())
    }

    // insert new ingredient
    fn insert_ingredient(&mut self, label: String, claim: Claim) {
        self.ingredients_store.insert(label.clone(), claim);
        self.ingredients_list.push(label);
    }

    // insert an ingredient or replace if it already exists
    pub(crate) fn replace_ingredient_or_insert(&mut self, label: String, claim: Claim) {
        if self.ingredients_store.contains_key(&label) {
            self.ingredients_store.insert(label.clone(), claim);
        } else {
            self.insert_ingredient(label, claim);
        }
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

    // Return assertions matching pattern
    pub fn assertions_by_type(
        &self,
        assertion_proto: &Assertion,
        assertion_type: Option<ClaimAssertionType>,
    ) -> Vec<&ClaimAssertion> {
        self.assertion_store
            .iter()
            .filter(|x| {
                if Assertion::assertions_eq(assertion_proto, x.assertion()) {
                    if let Some(assertion_type) = &assertion_type {
                        x.assertion_type() == *assertion_type
                    } else {
                        true
                    }
                } else {
                    false
                }
            })
            .collect()
    }

    /// Return reference to the assertions list.
    ///
    /// This list matches item-for-item with the `Assertion`s
    /// stored in the assertion store. For Claim version > 1
    /// this list includes both created and gathered.  Use
    /// gathered_assertions() or created_assertions() for specific
    /// lists when Claim version is 2 or greater,
    pub fn assertions(&self) -> &Vec<C2PAAssertion> {
        &self.assertions
    }

    /// Returns list of created assertions for Claim V2
    pub fn created_assertions(&self) -> &Vec<C2PAAssertion> {
        &self.created_assertions
    }

    /// Returns list is Claim V2 gathered assertions if available
    pub fn gathered_assertions(&self) -> Option<&Vec<C2PAAssertion>> {
        self.gathered_assertions.as_ref()
    }

    /// Return the cbor binary value of the claim data.
    /// If this claim was read from a file, returns the exact byte
    /// sequence that was read from the file. If this claim was
    /// constructed locally, contains the claim data that was/will be
    /// generated locally.
    pub fn data(&self) -> Result<Vec<u8>> {
        match self.original_bytes {
            Some(ref ob) => Ok(ob.clone()),
            None => Ok(c2pa_cbor::ser::to_vec(&self).map_err(|_err| Error::ClaimEncoding)?),
        }
    }

    pub(crate) fn clear_data(&mut self) {
        self.original_bytes = None;
    }

    /// Create claim from binary data (not including assertions).
    pub fn from_data(label: &str, data: &[u8]) -> Result<Claim> {
        let claim_value: c2pa_cbor::Value = c2pa_cbor::from_slice(data)
            .map_err(|err| Error::ClaimDecoding(format!("claim_cbor: {err}")))?;

        Claim::from_value(claim_value, label, data)
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
                                let cbor_value: c2pa_cbor::Value = c2pa_cbor::from_slice(x)
                                    .map_err(|err| Error::AssertionEncoding(err.to_string()))?;

                                json_map.insert(label, cbor_to_crjson(&cbor_value));
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
                                    .map_err(|err| Error::AssertionEncoding(err.to_string()))?;

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
                                let cbor_value: c2pa_cbor::Value = c2pa_cbor::from_slice(x)
                                    .map_err(|err| Error::AssertionEncoding(err.to_string()))?;
                                let d = cbor_to_crjson(&cbor_value);

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

    pub fn box_name_label_instance(box_name: &str) -> (String, usize) {
        if let Some((l, v)) = box_name.rsplit_once(".") {
            if v.len() == 2 && v.as_bytes()[0] == b'v' {
                if let Some(i_str) = v.get(1..) {
                    if let Ok(i) = i_str.parse::<usize>() {
                        return (l.into(), i);
                    }
                }
            }
        }
        (box_name.into(), 0)
    }

    /// Return the label for this assertion given its link
    pub fn assertion_label_from_link(assertion_link: &str) -> (String, usize) {
        let v = jumbf::labels::to_normalized_uri(assertion_link);

        let v2: Vec<&str> = v.split('/').collect();
        if let Some(s) = v2.last() {
            // treat ingredient thumbnails differently ingredient.thumbnail
            if get_thumbnail_type(s) == assertions::labels::INGREDIENT_THUMBNAIL {
                let instance = get_thumbnail_instance(s).unwrap_or(0);
                let label = match get_thumbnail_image_type(s) {
                    None => get_thumbnail_type(s),
                    Some(image_type) => format!("{}.{}", get_thumbnail_type(s), image_type),
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
        } else if get_thumbnail_type(label) == assertions::labels::INGREDIENT_THUMBNAIL {
            let output_label = format!("{}__{}", get_thumbnail_type(label), instance);

            match get_thumbnail_image_type(label) {
                Some(image_type) => format!("{output_label}.{image_type}"),
                None => output_label,
            }
        } else {
            format!("{label}__{instance}")
        }
    }

    pub fn assertion_hashed_uri_from_label(
        &self,
        assertion_label: &str,
    ) -> Option<(&C2PAAssertion, ClaimAssertionType)> {
        // `assertion_label` is the full label (with version and instance). Every
        // assertion URL ends with `c2pa.assertions/<label>`, so match that suffix.
        let suffix = format!("{ASSERTIONS}/{assertion_label}");
        let is_exact_match = |hashed_uri: &&C2PAAssertion| hashed_uri.url().ends_with(&suffix);

        if self.version() < 2 {
            let a = self.assertions().iter().find(is_exact_match)?;
            Some((a, ClaimAssertionType::V1))
        } else if let Some(a) = self.created_assertions().iter().find(is_exact_match) {
            Some((a, ClaimAssertionType::Created))
        } else {
            let a = self.gathered_assertions()?.iter().find(is_exact_match)?;

            Some((a, ClaimAssertionType::Gathered))
        }
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

        self.assertion_store
            .iter()
            .any(|x| x.assertion.label().starts_with(&label))
    }

    // Create a JUMBF URI from a claim label.
    pub(crate) fn to_claim_uri(&self) -> String {
        let uri = format!("{}/{}", jumbf::labels::to_manifest_uri(self.label()), CLAIM);

        if self.claim_version > 1 {
            format!("{}.v{}", uri, self.claim_version)
        } else {
            uri
        }
    }

    /// Return the claim JUMBF URI of the ingredient with a ParentOf relationship.
    pub fn parent_claim_uri(&self) -> Result<Option<String>> {
        for i in self.ingredient_assertions() {
            let ingredient = Ingredient::from_assertion(i.assertion())?;
            if ingredient.relationship == Relationship::ParentOf {
                return Ok(ingredient
                    .c2pa_manifest()
                    .map(|hashed_uri| hashed_uri.url()));
            }
        }

        Ok(None)
    }

    // Returns a HashedUri to the claim thumbnail assertion, if it exists.
    pub fn thumbnail(&self) -> Option<HashedUri> {
        self.assertions()
            .iter()
            .find(|hashed_uri| hashed_uri.url().contains(CLAIM_THUMBNAIL))
            .map(|t| {
                // convert to absolute
                let url = crate::jumbf::labels::to_absolute_uri(self.label(), &t.url());
                HashedUri::new(url, t.alg(), &t.hash())
            })
    }
}
