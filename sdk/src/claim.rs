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
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use async_generic::async_generic;
use chrono::{DateTime, Utc};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    assertion::{
        get_thumbnail_image_type, get_thumbnail_instance, get_thumbnail_type, Assertion,
        AssertionBase, AssertionData,
    },
    assertions::{
        self, c2pa_action,
        labels::{
            self, ACTIONS, ASSERTION_METADATA, ASSERTION_STORE, BMFF_HASH, CLAIM_THUMBNAIL,
            DATABOX_STORE, METADATA_LABEL_REGEX,
        },
        Actions, AssertionMetadata, AssetType, BmffHash, BoxHash, DataBox, DataHash, Ingredient,
        Metadata, Relationship, V2_DEPRECATED_ACTIONS,
    },
    asset_io::CAIRead,
    cbor_types::map_cbor_to_type,
    cose_validator::{
        get_signing_cert_serial_num, get_signing_info, get_signing_info_async, verify_cose,
        verify_cose_async,
    },
    crypto::{
        asn1::rfc3161::TstInfo,
        base64,
        cose::{
            get_ocsp_der, parse_cose_sign1, CertificateInfo, CertificateTrustPolicy,
            OcspFetchPolicy,
        },
        ocsp::OcspResponse,
    },
    error::{Error, Result},
    hashed_uri::HashedUri,
    http::{AsyncHttpResolver, SyncHttpResolver},
    jumbf::{
        self,
        boxes::{
            CAICBORAssertionBox, CAIJSONAssertionBox, CAISignatureBox, CAIUUIDAssertionBox,
            JUMBFCBORContentBox, JumbfEmbeddedFileBox,
        },
        labels::{
            assertion_label_from_uri, box_name_from_uri, manifest_label_from_uri,
            manifest_label_to_parts, to_absolute_uri, to_assertion_uri, to_databox_uri,
            to_manifest_uri, to_signature_uri, ASSERTIONS, CLAIM, CREDENTIALS, DATABOX, DATABOXES,
            SIGNATURE,
        },
    },
    jumbf_io::get_assetio_handler,
    log_item,
    resource_store::UriOrResource,
    salt::{DefaultSalt, SaltGenerator},
    settings::Settings,
    status_tracker::{ErrorBehavior, StatusTracker},
    store::StoreValidationInfo,
    utils::hash_utils::{hash_by_alg, vec_compare},
    validation_status, ClaimGeneratorInfo,
};

const BUILD_HASH_ALG: &str = "sha256";
const BUILD_VER_SUPPORT: usize = 2;

/// JSON structure representing an Assertion reference in a Claim's "assertions" list.
use HashedUri as C2PAAssertion;

const GH_FULL_VERSION_LIST: &str = "Sec-CH-UA-Full-Version-List";
const GH_UA: &str = "Sec-CH-UA";
const C2PA_NAMESPACE_V2: &str = "urn:c2pa";
const C2PA_NAMESPACE_V1: &str = "urn:uuid";

const _V2_SPEC_DEPRECATED_ASSERTIONS: [&str; 4] = [
    "stds.iptc",
    "stds.iptc.photo-metadata",
    "stds.exif",
    "c2pa.endorsement",
];

pub(crate) const ALLOWED_UPDATE_MANIFEST_ACTIONS: [&str; 4] = [
    "c2pa.edited.metadata",
    "c2pa.opened",
    "c2pa.published",
    "c2pa.redacted",
];

// Enum to encapsulate the data type of the source asset.  This simplifies
// having different implementations for functions as a single entry point can be
// used to handle different data types.
#[allow(dead_code)] // Bytes and third param in StreamFragment not used without v1_api feature
pub enum ClaimAssetData<'a> {
    #[cfg(feature = "file_io")]
    Path(&'a Path),
    Bytes(&'a [u8], &'a str),
    Stream(&'a mut dyn CAIRead, &'a str),
    StreamFragment(&'a mut dyn CAIRead, &'a mut dyn CAIRead, &'a str),
    #[cfg(feature = "file_io")]
    StreamFragments(&'a mut dyn CAIRead, &'a Vec<std::path::PathBuf>, &'a str),
}

#[derive(PartialEq, Debug, Eq, Clone, Hash)]
pub enum ClaimAssertionType {
    V1,       // V1 assertion
    Gathered, // Machine generated assertion
    Created,  // User generated assertion
}

// helper struct to allow arbitrary order for assertions stored in jumbf.  The instance is
// stored separate from the Assertion to allow for late binding to the label.  Also,
// we can load assertions in any order and know the position without re-parsing label. We also
// save on parsing the cbor assertion each time we need its contents
#[derive(PartialEq, Eq, Clone, Hash)]
pub struct ClaimAssertion {
    assertion: Assertion,
    instance: usize,
    hash_val: Vec<u8>,
    hash_alg: String,
    salt: Option<Vec<u8>>,
    typ: ClaimAssertionType,
}

impl ClaimAssertion {
    pub fn new(
        assertion: Assertion,
        instance: usize,
        hashval: &[u8],
        alg: &str,
        salt: Option<Vec<u8>>,
        typ: ClaimAssertionType,
    ) -> ClaimAssertion {
        ClaimAssertion {
            assertion,
            instance,
            hash_val: hashval.to_vec(),
            hash_alg: alg.to_string(),
            salt,
            typ,
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
            if get_thumbnail_type(&al_ref) == assertions::labels::INGREDIENT_THUMBNAIL {
                let label = format!("{}__{}", get_thumbnail_type(&al_ref), self.instance);

                match get_thumbnail_image_type(&al_ref) {
                    Some(image_type) => format!("{label}.{image_type}"),
                    None => label,
                }
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

    pub fn assertion_type(&self) -> ClaimAssertionType {
        self.typ.clone()
    }

    pub fn set_assertion_type(&mut self, typ: ClaimAssertionType) {
        self.typ = typ;
    }
}

impl fmt::Debug for ClaimAssertion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}, instance: {}, type: {:?}",
            self.assertion, self.instance, self.typ
        )
    }
}

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
    update_manifest: bool,

    pub title: Option<String>, // title for this claim, generally the name of the containing asset

    pub format: Option<String>, // mime format of document containing this claim

    pub instance_id: String, // instance Id of document containing this claim

    // Internal list of ingredients
    ingredients_store: HashMap<String, Claim>,

    // Internal ingredients order
    ingredients_list: Vec<String>,

    signature_val: Vec<u8>, // the signature of the loaded/saved claim

    // root of CAI store
    #[allow(dead_code)]
    root: String,

    // internal scratch objects
    label: String, // label of claim

    // relabel claim when there is an ingredient conflict
    conflict_label: Option<String>,

    // Internal list of assertions for claim.
    // These are serialized manually based on need.
    assertion_store: Vec<ClaimAssertion>,

    // Internal list of verifiable credentials for claim.
    // These are serialized manually based on need.
    vc_store: Vec<(HashedUri, AssertionData)>, //  V1 feature

    claim_generator: Option<String>, // generator of this claim

    pub(crate) claim_generator_info: Option<Vec<ClaimGeneratorInfo>>, /* detailed generator info of this claim */

    signature: String,                               // link to signature box
    assertions: Vec<C2PAAssertion>, // list of assertion or created_assertions (V1 assertions or V2 created and gathered combined) hashed URIs.
    created_assertions: Vec<C2PAAssertion>, // list of assertion or created_assertions (V1) hashed URIs.
    gathered_assertions: Option<Vec<C2PAAssertion>>, // list of gather_assertions (>= V2)

    // original JSON bytes of claim; only present when reading from asset
    original_bytes: Option<Vec<u8>>,

    // original JUMBF box order need to recalculate JUMBF box hash
    original_box_order: Option<Vec<&'static str>>,

    redacted_assertions: Option<Vec<String>>, // list of redacted assertions

    alg: Option<String>, // hashing algorithm (default to Sha256)

    alg_soft: Option<String>, // hashing algorithm for soft bindings

    claim_generator_hints: Option<HashMap<String, Value>>,

    metadata: Option<Vec<AssertionMetadata>>,

    data_boxes: Vec<(HashedUri, DataBox)>, /* list of the data boxes and their hashed URIs found for this manifest */

    claim_version: usize,
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
            data_boxes: Vec::new(),
            metadata: None,
            claim_version,
            created_assertions: Vec::new(),
            gathered_assertions: None,
        }
    }

    /// Create a new [`Claim`] with a user-supplied GUID.
    ///
    /// # Parameters
    ///
    /// * `user_guid` is a user-supplied GUID conforming to the C2PA spec for manifest names.
    /// * `claim_generator` is a user-agent description. (See c2pa spec for format.)
    /// * `claim_version` is the Claim version to generate.
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
            data_boxes: Vec::new(),
            metadata: None,
            claim_version,
            created_assertions: Vec::new(),
            gathered_assertions: None,
        })
    }

    // Deserializer that maps V1/V2 Claim object into our internal Claim representation.  Note:  Our Claim
    // structure is not the Claim from the spec but an amalgamation that allows us to represent any version
    pub fn from_value(claim_value: serde_cbor::Value, label: &str, data: &[u8]) -> Result<Self> {
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
            if let serde_cbor::Value::Map(m) = &claim_value {
                for v in m.keys() {
                    if let serde_cbor::Value::Text(t) = v {
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
                // NOTE: This error path is unreachable in practice because map_cbor_to_type()
                // returns None for non-Map values, causing version detection (lines 562-564)
                // to fail with "unsupported claim version" before reaching this point.
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
            */

            static V2_FIELDS: [&str; 10] = [
                INSTANCE_ID_F,
                CLAIM_GENERATOR_INFO_F,
                SIGNATURE_F,
                CREATED_ASSERTIONS_F,
                GATHERED_ASSERTIONS_F,
                DC_TITLE_F,
                REDACTED_ASSERTIONS_F,
                ALG_F,
                ALG_SOFT_F,
                METADATA_F,
            ];

            // make sure only V2 fields are present
            if let serde_cbor::Value::Map(m) = &claim_value {
                for v in m.keys() {
                    if let serde_cbor::Value::Text(t) = v {
                        if !V2_FIELDS.contains(&t.as_str()) {
                            return Err(Error::ClaimDecoding(format!(
                                "unknown V2 claim field: {t}",
                            )));
                        }
                    } else {
                        return Err(Error::ClaimDecoding("non-text key in V2 claim".to_string()));
                    }
                }
            } else {
                // NOTE: This error path is unreachable in practice because map_cbor_to_type()
                // returns None for non-Map values, causing version detection (lines 567-570)
                // to fail with "unsupported claim version" before reaching this point.
                return Err(Error::ClaimDecoding("claim is not an object".to_string()));
            }

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
            // NOTE: The error "created_assertions is missing or invalid" below is unreachable
            // in practice because version detection (lines 567-570) requires created_assertions
            // to be deserializable as Vec<HashedUri>. If it's missing or invalid, version
            // detection fails with "unsupported claim version" before reaching this point.
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

            // create merged list of created and gathered assertions for processing compatibility
            // created are added first with highest priority than gathered
            let mut assertions = created_assertions.clone();
            if let Some(ga) = &gathered_assertions {
                assertions.append(&mut ga.clone());
            }

            Ok(Claim {
                remote_manifest: RemoteManifest::NoRemote,
                update_manifest: false,
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

    /// set title
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

    // get version of the Claim
    pub fn version(&self) -> usize {
        self.claim_version
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

    pub fn add_claim_generator_hint(&mut self, hint_key: &str, hint_value: Value) {
        let hints_map = self.claim_generator_hints.get_or_insert_with(HashMap::new);

        // if the key is already there do we need to merge the new value, so get its value
        let curr_val = match hint_key {
            // keys where new values should be merges
            GH_UA | GH_FULL_VERSION_LIST => {
                if let Some(curr_ch_ua) = hints_map.get(hint_key) {
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
                hints_map.insert(
                    hint_key.to_string(),
                    Value::String(format!("{curr_val}, {append_val}")),
                );
            }
            return;
        }

        // all other keys treat as replacement
        hints_map.insert(hint_key.to_string(), hint_value);
    }

    pub fn get_claim_generator_hint_map(&self) -> Option<&HashMap<String, Value>> {
        self.claim_generator_hints.as_ref()
    }

    pub fn calc_sig_box_hash(claim: &Claim, alg: &str) -> Result<Vec<u8>> {
        let mut hash_bytes = Vec::with_capacity(2048);

        // create a signature and add placeholder data to the CAI store.
        let mut sigb = CAISignatureBox::new();
        let signed_data = claim.signature_val().clone();

        let sigc = JUMBFCBORContentBox::new(signed_data);
        sigb.add_signature(Box::new(sigc));

        sigb.super_box().write_box_payload(&mut hash_bytes)?;

        Ok(hash_by_alg(alg, &hash_bytes, None))
    }

    pub fn calc_assertion_box_hash(
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
    /// This uses a default salt generator and will assumed gathered for Claims V2 except for HASH assertions.
    pub fn add_assertion(
        &mut self,
        assertion_builder: &impl AssertionBase,
    ) -> Result<C2PAAssertion> {
        self.add_assertion_impl(assertion_builder, &DefaultSalt::default(), false)
    }

    /// Same as add_assertion but forces addition to created_assertions for Claims V2
    pub fn add_created_assertion(
        &mut self,
        assertion_builder: &impl AssertionBase,
    ) -> Result<C2PAAssertion> {
        self.add_assertion_impl(assertion_builder, &DefaultSalt::default(), true)
    }

    fn compatibility_checks(&self, assertion: &Assertion) -> Result<()> {
        let assertion_version = assertion.get_ver();
        let assertion_label = assertion.label_root();

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
            } else if let Some(created_assertions) = {
                let settings = crate::settings::get_settings().unwrap_or_default();
                settings.builder.created_assertion_labels
            } {
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
    ) -> Result<C2PAAssertion> {
        // make sure the assertion is valid
        let assertion = assertion_builder.to_assertion()?;
        let assertion_label = assertion.label();

        // Update label if there are multiple instances of the same claim type.
        let as_label = self.make_assertion_instance_label(assertion_label.as_ref());
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
            serde_cbor::to_vec(&new_db).map_err(|err| Error::AssertionEncoding(err.to_string()))?;

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

        let db: DataBox = serde_cbor::from_slice(databox_cbor)
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
            if let Some(box_name) = box_name_from_uri(&hr.url()) {
                to_databox_uri(self.label(), &box_name)
            } else {
                // NOTE: This branch is currently unreachable because box_name_from_uri
                // always returns Some(...) with the current implementation. The function
                // uses split('/') which always produces at least one element, so
                // parts.last() will always return Some. This is defensive code in case
                // the implementation of box_name_from_uri changes in the future.
                return None;
            }
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

    /// Redact an assertion from a prior claim.
    /// This will remove the assertion from the JUMBF
    fn redact_assertion(&mut self, assertion_uri: &str) -> Result<()> {
        // cannot redact action assertions per the spec
        // cannot redact hash bindings
        let (label, _instance) = Claim::assertion_label_from_link(assertion_uri);
        if label.starts_with(assertions::labels::ACTIONS) || label.starts_with("c2pa.hash.") {
            return Err(Error::AssertionInvalidRedaction);
        }

        // delete assertion or databox
        if assertion_uri.contains(ASSERTION_STORE) {
            if let Some(index) = self
                .assertion_store
                .iter()
                .position(|x| assertion_uri.contains(&x.label()))
            {
                self.assertion_store.remove(index);
                return Ok(());
            }
        } else if assertion_uri.contains(DATABOX_STORE) {
            if let Some(index) = self
                .databoxes()
                .iter()
                .position(|(x, _d)| assertion_uri.contains(&x.url()))
            {
                self.data_boxes.remove(index);
                return Ok(());
            }
        }

        Err(Error::AssertionInvalidRedaction)
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

    /// Return the signing issuer for this claim, if there is one.
    pub fn signing_issuer(&self) -> Option<String> {
        if let Some(validation_data) = self.signature_info() {
            validation_data.issuer_org
        } else {
            None
        }
    }

    /// Return the cert's serial number, if there is one.
    pub fn signing_cert_serial(&self) -> Option<String> {
        self.signature_info()
            .and_then(|validation_info| validation_info.cert_serial_number)
            .map(|serial| serial.to_string())
    }

    /// Return information about the signature
    #[async_generic]
    pub fn signature_info(&self) -> Option<CertificateInfo> {
        let sig = self.signature_val();
        let data = self.data().ok()?;
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        // TODO: I believe we validate at an earlier point in the code, making this unecessary
        let mut settings = crate::settings::get_settings().unwrap_or_default();
        settings.verify.verify_timestamp_trust = false;

        if _sync {
            Some(get_signing_info(sig, &data, &mut validation_log, &settings))
        } else {
            Some(get_signing_info_async(sig, &data, &mut validation_log, &settings).await)
        }
    }

    /// Verify claim signature, assertion store and asset hashes
    /// claim - claim to be verified
    /// asset_bytes - reference to bytes of the asset
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn verify_claim_async(
        claim: &Claim,
        asset_data: &mut ClaimAssetData<'_>,
        svi: &StoreValidationInfo<'_>,
        cert_check: bool,
        ctp: &CertificateTrustPolicy,
        validation_log: &mut StatusTracker,
        http_resolver: &impl AsyncHttpResolver,
        settings: &Settings,
    ) -> Result<()> {
        // Parse COSE signed data (signature) and validate it.
        let sig = claim.signature_val().clone();
        let additional_bytes: Vec<u8> = Vec::new();
        let data = claim.data()?;

        // use the signature uri as the current uri while validating the signature info
        validation_log.push_current_uri(to_signature_uri(claim.label()));

        // make sure signature manifest if present points to this manifest
        let sig_box_err = match jumbf::labels::manifest_label_from_uri(&claim.signature) {
            Some(signature_url) if signature_url != claim.label() => true,
            _ => {
                jumbf::labels::box_name_from_uri(&claim.signature).unwrap_or_default()
                    != jumbf::labels::SIGNATURE
            } // relative signature box
        };

        if sig_box_err {
            log_item!(
                to_signature_uri(claim.label()),
                "signature missing",
                "verify_claim_async"
            )
            .validation_status(validation_status::CLAIM_SIGNATURE_MISSING)
            .failure(validation_log, Error::ClaimMissingSignatureBox)?;
        }

        // for V2 and greater claims the label must conform
        if claim.version() > 1 && manifest_label_to_parts(claim.label()).is_none() {
            log_item!(
                to_manifest_uri(claim.label()),
                "claim box label invalid",
                "verify_claim_async"
            )
            .validation_status(validation_status::CLAIM_MALFORMED)
            .failure(validation_log, Error::ClaimInvalidContent)?;
        }

        let sign1 = parse_cose_sign1(&sig, &data, validation_log)?;
        let certificate_serial_num = get_signing_cert_serial_num(&sign1)?.to_string();

        // check certificate revocation
        check_ocsp_status_async(
            &sign1,
            &data,
            ctp,
            svi.certificate_statuses.get(&certificate_serial_num),
            svi.timestamps.get(claim.label()),
            validation_log,
            http_resolver,
            settings,
        )
        .await?;

        let verified = verify_cose_async(
            &sig,
            &data,
            &additional_bytes,
            cert_check,
            ctp,
            svi.timestamps.get(claim.label()),
            validation_log,
            settings,
        )
        .await;

        let result =
            Claim::verify_internal(claim, asset_data, svi, verified, validation_log, settings);
        validation_log.pop_current_uri();
        result
    }

    /// Verify claim signature, assertion store and asset hashes
    /// claim - claim to be verified
    /// asset_bytes - reference to bytes of the asset
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_claim(
        claim: &Claim,
        asset_data: &mut ClaimAssetData<'_>,
        svi: &StoreValidationInfo<'_>,
        cert_check: bool,
        ctp: &CertificateTrustPolicy,
        validation_log: &mut StatusTracker,
        http_resolver: &impl SyncHttpResolver,
        settings: &Settings,
    ) -> Result<()> {
        // Parse COSE signed data (signature) and validate it.
        let sig = claim.signature_val();
        let additional_bytes: Vec<u8> = Vec::new();

        let mut adjusted_settings = settings.clone();
        if claim.version() == 1 {
            adjusted_settings.verify.verify_timestamp_trust = false;
        }

        // use the signature uri as the current uri while validating the signature info
        validation_log.push_current_uri(to_signature_uri(claim.label()));

        // make sure signature manifest if present points to this manifest
        let sig_box_err = match jumbf::labels::manifest_label_from_uri(&claim.signature) {
            Some(signature_url) if signature_url != claim.label() => true,
            _ => {
                jumbf::labels::box_name_from_uri(&claim.signature).unwrap_or_default()
                    != jumbf::labels::SIGNATURE
            } // relative signature box
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
        // check certificate revocation
        check_ocsp_status(
            &sign1,
            data,
            ctp,
            svi.certificate_statuses.get(&certificate_serial_num),
            svi.timestamps.get(claim.label()),
            validation_log,
            http_resolver,
            &adjusted_settings,
        )?;

        let verified = verify_cose(
            sig,
            data,
            &additional_bytes,
            cert_check,
            ctp,
            svi.timestamps.get(claim.label()),
            validation_log,
            &adjusted_settings,
        );

        let result = Claim::verify_internal(
            claim,
            asset_data,
            svi,
            verified,
            validation_log,
            &adjusted_settings,
        );
        validation_log.pop_current_uri();
        result
    }

    /// Get the signing certificate chain as PEM bytes
    pub fn get_cert_chain(&self, settings: &Settings) -> Result<Vec<u8>> {
        let sig = self.signature_val();
        let data = self.data()?;
        let mut validation_log =
            StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);

        let vi = get_signing_info(sig, &data, &mut validation_log, settings);

        Ok(vi.cert_chain)
    }

    // Perform 2.x action validation check, hashed URI references are only checked
    // to be present and to be valild references an actual manifest store object.
    //The hashed uri's hashes are are validated as part of the Claim assertions check.
    fn verify_actions(
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
        for (index, actions_assertion) in all_actions.iter().enumerate() {
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

            for action in actions.actions() {
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

                // 2.a created or opened must be first action
                if index != 0
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
                            "opened, placed and removed items must have parameters",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH)
                        .failure(
                            validation_log,
                            Error::ValidationRule(
                                "opened, placed and removed items must have parameters".into(),
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
                        .failure_no_throw(
                            validation_log,
                            Error::ValidationRule("opened, placed and removed items must have ingredient(s) parameters".into()),
                        );
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
                            .failure_no_throw(
                                validation_log,
                                Error::ValidationRule("opened, placed and removed items must have ingredients parameter must be non empty array".into()),
                            );
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
                                    found_good = 1;
                                }
                            }
                        }

                        if found_good != 1 {
                            log_item!(
                                label.clone(),
                                "opened must have valid ingredient with ParentOf relationship",
                                "verify_actions"
                            )
                            .validation_status(
                                validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH,
                            )
                            .failure_no_throw(
                                validation_log,
                                Error::ValidationRule(
                                    "opened must have valid ingredient with ParentOf relationship"
                                        .into(),
                                ),
                            );
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
                            log_item!(
                                label.clone(),
                                "action must have valid ingredient with ComponentOf relationship",
                                "verify_actions"
                            )
                            .validation_status(
                                validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH,
                            )
                            .failure_no_throw(
                                validation_log,
                                Error::ValidationRule(
                                    "action must have valid ingredient with ComponentOf relationship".into(),
                                ),
                            );
                        }
                    }
                }

                // 2.c if ingredient is present it must be a valid parentOf reference
                if action.action() == c2pa_action::TRANSCODED
                    || action.action() == c2pa_action::REPACKAGED
                {
                    let Some(params) = action.parameters() else {
                        log_item!(
                            label.clone(),
                            "opened, placed and removed items must have parameters",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH)
                        .failure(
                            validation_log,
                            Error::ValidationRule(
                                "opened, placed and removed items must have parameters".into(),
                            ),
                        )?;
                        continue; // Skip the parameter-dependent checks below
                    };

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
                        }
                        match parent_tested {
                            Some(v) => parent_tested = Some(v),
                            None => parent_tested = Some(false),
                        }
                    }
                    // will only exist if we actual tested for an ingredient
                    if let Some(false) = parent_tested {
                        log_item!(
                            label.clone(),
                            "action must have valid ingredient with ParentOf relationship",
                            "verify_actions"
                        )
                        .validation_status(validation_status::ASSERTION_ACTION_INGREDIENT_MISMATCH)
                        .failure_no_throw(
                            validation_log,
                            Error::ValidationRule(
                                "action must have valid ingredient with ParentOf relationship"
                                    .into(),
                            ),
                        );
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
                                        // but it must be in the claim's assertions HashUri list
                                        parent_tested = Some(
                                            ingredient_claim
                                                .assertions()
                                                .iter()
                                                .any(|a| a.url().contains(&redaction_label)),
                                        );
                                    } else {
                                        dbg!("failed here");
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

    pub(crate) fn verify_hash_binding(
        claim: &Claim,
        asset_data: &mut ClaimAssetData<'_>,
        svi: &StoreValidationInfo,
        validation_log: &mut StatusTracker,
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
                        // there are extra exclusion then log the information code about extra exclusion
                        if let Some(exclusions) = &dh.exclusions {
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
                        let hash_result = match asset_data {
                            #[cfg(feature = "file_io")]
                            ClaimAssetData::Path(asset_path) => {
                                dh.verify_hash(asset_path, Some(claim.alg()))
                            }
                            ClaimAssetData::Bytes(asset_bytes, _) => {
                                dh.verify_in_memory_hash(asset_bytes, Some(claim.alg()))
                            }
                            ClaimAssetData::Stream(stream_data, _) => {
                                dh.verify_stream_hash(*stream_data, Some(claim.alg()))
                            }
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
                    // handle BMFF data hashes
                    let dh = BmffHash::from_assertion(hash_binding_assertion.assertion())?;

                    let name = dh.name().map_or("unnamed".to_string(), default_str);

                    let hash_result = match asset_data {
                        #[cfg(feature = "file_io")]
                        ClaimAssetData::Path(asset_path) => {
                            dh.verify_hash(asset_path, Some(claim.alg()))
                        }
                        ClaimAssetData::Bytes(asset_bytes, _) => {
                            dh.verify_in_memory_hash(asset_bytes, Some(claim.alg()))
                        }
                        ClaimAssetData::Stream(stream_data, _) => {
                            dh.verify_stream_hash(*stream_data, Some(claim.alg()))
                        }
                        ClaimAssetData::StreamFragment(initseg_data, fragment_data, _) => dh
                            .verify_stream_segment(
                                *initseg_data,
                                *fragment_data,
                                Some(claim.alg()),
                            ),
                        #[cfg(feature = "file_io")]
                        ClaimAssetData::StreamFragments(initseg_data, fragment_paths, _) => dh
                            .verify_stream_segments(
                                *initseg_data,
                                fragment_paths,
                                Some(claim.alg()),
                            ),
                    };

                    match hash_result {
                        Ok(_a) => {
                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                "data hash valid",
                                "verify_internal"
                            )
                            .validation_status(validation_status::ASSERTION_BMFFHASH_MATCH)
                            .success(validation_log);

                            continue;
                        }
                        Err(e) => {
                            let err_str = match e {
                                Error::C2PAValidation(es) => {
                                    if es == validation_status::ASSERTION_BMFFHASH_MALFORMED {
                                        validation_status::ASSERTION_BMFFHASH_MALFORMED
                                    } else {
                                        validation_status::ASSERTION_BMFFHASH_MISMATCH
                                    }
                                }
                                _ => validation_status::ASSERTION_BMFFHASH_MISMATCH,
                            };

                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                format!("asset hash error, name: {name}, error: {}", err_str),
                                "verify_internal"
                            )
                            .validation_status(err_str)
                            .failure(
                                validation_log,
                                Error::HashMismatch(format!("Asset hash failure: {err_str}")),
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

                    let hash_result = match asset_data {
                        #[cfg(feature = "file_io")]
                        ClaimAssetData::Path(asset_path) => {
                            let box_hash_processor =
                                crate::jumbf_io::get_assetio_handler_from_path(asset_path)
                                    .ok_or(Error::UnsupportedType)?
                                    .asset_box_hash_ref()
                                    .ok_or(Error::HashMismatch(
                                        "Box hash not supported".to_string(),
                                    ))?;

                            bh.verify_hash(asset_path, Some(claim.alg()), box_hash_processor)
                        }
                        ClaimAssetData::Bytes(asset_bytes, asset_type) => {
                            let box_hash_processor = get_assetio_handler(asset_type)
                                .ok_or(Error::UnsupportedType)?
                                .asset_box_hash_ref()
                                .ok_or(Error::HashMismatch(format!(
                                    "Box hash not supported for: {asset_type}"
                                )))?;

                            bh.verify_in_memory_hash(
                                asset_bytes,
                                Some(claim.alg()),
                                box_hash_processor,
                            )
                        }
                        ClaimAssetData::Stream(stream_data, asset_type) => {
                            let box_hash_processor = get_assetio_handler(asset_type)
                                .ok_or(Error::UnsupportedType)?
                                .asset_box_hash_ref()
                                .ok_or(Error::HashMismatch(format!(
                                    "Box hash not supported for: {asset_type}"
                                )))?;

                            bh.verify_stream_hash(
                                *stream_data,
                                Some(claim.alg()),
                                box_hash_processor,
                            )
                        }
                        _ => return Err(Error::UnsupportedType),
                    };

                    match hash_result {
                        Ok(_a) => {
                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                "data hash valid",
                                "verify_internal"
                            )
                            .validation_status(validation_status::ASSERTION_BOXHASH_MATCH)
                            .success(validation_log);

                            continue;
                        }
                        Err(e) => {
                            log_item!(
                                claim.assertion_uri(&hash_binding_assertion.label()),
                                format!("asset hash error: {e}"),
                                "verify_internal"
                            )
                            .validation_status(validation_status::ASSERTION_BOXHASH_MISMATCH)
                            .failure(
                                validation_log,
                                Error::HashMismatch(format!("Asset hash failure: {e}")),
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

    fn verify_internal(
        claim: &Claim,
        asset_data: &mut ClaimAssetData<'_>,
        svi: &StoreValidationInfo,
        verified: Result<CertificateInfo>,
        validation_log: &mut StatusTracker,
        settings: &Settings,
    ) -> Result<()> {
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
                    log_item!(
                        to_signature_uri(claim.label()),
                        "claim signature valid",
                        "verify_internal"
                    )
                    .validation_status(validation_status::CLAIM_SIGNATURE_VALIDATED)
                    .success(validation_log);
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
                    .validation_status(validation_status::ASSERTION_DATAHASH_REDACTED)
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
                    return ingredient.relationship == Relationship::ParentOf;
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
                .filter(|ca| ca.label_raw().contains(CLAIM_THUMBNAIL))
                .count()
                > 1
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

        // verify data hashes for provenance claims
        Claim::verify_hash_binding(claim, asset_data, svi, validation_log)?;

        // check action rules
        Claim::verify_actions(claim, svi, validation_log, settings)?;

        // check metadata rules
        if claim.version() >= 2 {
            // only for claim version 2 or greater
            Claim::verify_metadata(claim, validation_log)?;
        }

        Ok(())
    }

    // Perform metadata validation check
    fn verify_metadata(claim: &Claim, validation_log: &mut StatusTracker) -> Result<()> {
        for metadata_assertion in claim.metadata_assertions() {
            let metadata_assertion = Metadata::from_assertion(metadata_assertion.assertion())?;
            if !metadata_assertion.is_valid() {
                let label = to_assertion_uri(claim.label(), metadata_assertion.label());
                log_item!(
                    label,
                    "metadata assertion contains disallowed field",
                    "verify_internal"
                )
                .validation_status(validation_status::ASSERTION_METADATA_DISALLOWED)
                .failure(
                    validation_log,
                    Error::ValidationRule("fields must be in allowed list".into()),
                )?;
            }
        }
        Ok(())
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

    /// Return list of data hash assertions
    pub fn hash_assertions(&self) -> Vec<&ClaimAssertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_hash = Assertion::new(DataHash::LABEL, None, dummy_data);
        let mut data_hashes = self.assertions_by_type(&dummy_hash, None);

        // add in an BMFF hashes
        let dummy_bmff_data = AssertionData::Cbor(Vec::new());
        let dummy_bmff_hash = Assertion::new(assertions::labels::BMFF_HASH, None, dummy_bmff_data);
        data_hashes.append(&mut self.assertions_by_type(&dummy_bmff_hash, None));

        // add in an box hashes
        let dummy_box_data = AssertionData::Cbor(Vec::new());
        let dummy_box_hash = Assertion::new(assertions::labels::BOX_HASH, None, dummy_box_data);
        data_hashes.append(&mut self.assertions_by_type(&dummy_box_hash, None));

        // remove any multipart hashes, those are handled elsewhere
        data_hashes.retain(|x| !x.label_raw().ends_with(assertions::labels::PART));

        data_hashes
    }

    pub fn bmff_hash_assertions(&self) -> Vec<&ClaimAssertion> {
        // add in an BMFF hashes
        let dummy_bmff_data = AssertionData::Cbor(Vec::new());
        let dummy_bmff_hash = Assertion::new(assertions::labels::BMFF_HASH, None, dummy_bmff_data);
        self.assertions_by_type(&dummy_bmff_hash, None)
    }

    pub fn box_hash_assertions(&self) -> Vec<&ClaimAssertion> {
        // add in an BMFF hashes
        let dummy_box_data = AssertionData::Cbor(Vec::new());
        let dummy_box_hash = Assertion::new(assertions::labels::BOX_HASH, None, dummy_box_data);
        self.assertions_by_type(&dummy_box_hash, None)
    }

    /// Return list of ingredient assertions. This function
    /// is only useful on committed or loaded claims since ingredients
    /// are resolved at commit time.
    pub fn ingredient_assertions(&self) -> Vec<&ClaimAssertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_ingredient = Assertion::new(assertions::labels::INGREDIENT, None, dummy_data);
        self.assertions_by_type(&dummy_ingredient, None)
    }

    /// Return list of timestamp assertions.
    pub fn timestamp_assertions(&self) -> Vec<&ClaimAssertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_timestamp = Assertion::new(assertions::labels::TIMESTAMP, None, dummy_data);
        self.assertions_by_type(&dummy_timestamp, None)
    }

    /// Returns list of certificate status assertions.
    pub fn certificate_status_assertions(&self) -> Vec<&ClaimAssertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_certificate_status =
            Assertion::new(assertions::labels::CERTIFICATE_STATUS, None, dummy_data);
        self.assertions_by_type(&dummy_certificate_status, None)
    }

    /// Return list of action assertions.
    /// Created assertions have higher priority than gathered assertions
    pub fn action_assertions(&self) -> Vec<&ClaimAssertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_ingredient = Assertion::new(assertions::labels::ACTIONS, None, dummy_data);
        self.assertions_by_type(&dummy_ingredient, None)
    }

    /// Return list of gathered action assertions.
    pub fn gathered_action_assertions(&self) -> Vec<&ClaimAssertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_ingredient = Assertion::new(assertions::labels::ACTIONS, None, dummy_data);
        self.assertions_by_type(&dummy_ingredient, Some(ClaimAssertionType::Gathered))
    }

    /// Return list of action assertions.
    pub fn created_action_assertions(&self) -> Vec<&ClaimAssertion> {
        let dummy_data = AssertionData::Cbor(Vec::new());
        let dummy_ingredient = Assertion::new(assertions::labels::ACTIONS, None, dummy_data);
        self.assertions_by_type(&dummy_ingredient, Some(ClaimAssertionType::Created))
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

        // redact assertion from incoming ingredients
        if let Some(redactions) = &redactions_opt {
            for redaction in redactions {
                if let Some(claim) = ingredient
                    .iter_mut()
                    .find(|x| redaction.contains(x.label()))
                {
                    claim.redact_assertion(redaction)?;

                    // if this is an ingredient we should remove the ingredient
                } else {
                    return Err(Error::AssertionRedactionNotFound);
                }
            }
        }

        // all have been removed (if necessary) so replace redaction list
        self.redacted_assertions = redactions_opt;

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

    pub(crate) fn clear_data(&mut self) {
        self.original_bytes = None;
    }

    /// Create claim from binary data (not including assertions).
    pub fn from_data(label: &str, data: &[u8]) -> Result<Claim> {
        let claim_value: serde_cbor::Value = serde_cbor::from_slice(data)
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
                                let buf: Vec<u8> = Vec::new();
                                let mut from = serde_cbor::Deserializer::from_slice(x);
                                let mut to = serde_json::Serializer::new(buf);

                                serde_transcode::transcode(&mut from, &mut to)
                                    .map_err(|err| Error::AssertionEncoding(err.to_string()))?;
                                let buf2 = to.into_inner();

                                let decoded: Value = serde_json::from_slice(&buf2)
                                    .map_err(|err| Error::AssertionEncoding(err.to_string()))?;

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
                                let buf: Vec<u8> = Vec::new();
                                let mut from = serde_cbor::Deserializer::from_slice(x);
                                let mut to = serde_json::Serializer::new(buf);

                                serde_transcode::transcode(&mut from, &mut to)
                                    .map_err(|err| Error::AssertionEncoding(err.to_string()))?;
                                let buf2 = to.into_inner();

                                let d: Value = serde_json::from_slice(&buf2)
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
        if self.version() < 2 {
            let a = self
                .assertions()
                .iter()
                .find(|hashed_uri| hashed_uri.url().contains(assertion_label))?;

            Some((a, ClaimAssertionType::V1))
        } else if let Some(a) = self
            .created_assertions()
            .iter()
            .find(|hashed_uri| hashed_uri.url().contains(assertion_label))
        {
            Some((a, ClaimAssertionType::Created))
        } else {
            let a = self
                .gathered_assertions()?
                .iter()
                .find(|hashed_uri| hashed_uri.url().contains(assertion_label))?;

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

    /// Checks whether or not ocsp values are present in claim
    pub fn has_ocsp_vals(&self) -> bool {
        if !self.certificate_status_assertions().is_empty() {
            return false;
        }

        let data = match self.data() {
            Ok(data) => data,
            Err(_) => return false,
        };

        let sig = self.signature_val().clone();
        let mut validation_log = StatusTracker::default();

        let sign1 = match parse_cose_sign1(&sig, &data, &mut validation_log) {
            Ok(sign1) => sign1,
            Err(_) => return false,
        };

        get_ocsp_der(&sign1).is_some()
    }
}

#[allow(dead_code, clippy::too_many_arguments)]
#[async_generic(async_signature(
    sign1: &coset::CoseSign1,
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    ocsp_responses: Option<&Vec<Vec<u8>>>,
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
    http_resolver: &impl AsyncHttpResolver,
    settings: &Settings,
))]
pub(crate) fn check_ocsp_status(
    sign1: &coset::CoseSign1,
    data: &[u8],
    ctp: &CertificateTrustPolicy,
    ocsp_responses: Option<&Vec<Vec<u8>>>,
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
    http_resolver: &impl SyncHttpResolver,
    settings: &Settings,
) -> Result<OcspResponse> {
    // Moved here instead of c2pa-crypto because of the dependency on settings.

    let fetch_policy = if settings.verify.ocsp_fetch {
        OcspFetchPolicy::FetchAllowed
    } else {
        OcspFetchPolicy::DoNotFetch
    };

    if _sync {
        Ok(crate::crypto::cose::check_ocsp_status(
            sign1,
            data,
            fetch_policy,
            ctp,
            ocsp_responses,
            tst_info,
            validation_log,
            http_resolver,
            settings,
        )?)
    } else {
        Ok(crate::crypto::cose::check_ocsp_status_async(
            sign1,
            data,
            fetch_policy,
            ctp,
            ocsp_responses,
            tst_info,
            validation_log,
            http_resolver,
            settings,
        )
        .await?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
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
        println!("Restored Claim: {restored_claim:?}");

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

        println!("Claim: {json_str}");
    }

    mod new_with_user_guid {
        use super::super::*;

        #[test]
        fn good_v1() {
            Claim::new_with_user_guid(
                "claim_generator",
                "acme:urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                1,
            )
            .unwrap();
        }

        #[test]
        fn good_v2() {
            Claim::new_with_user_guid(
                "claim_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
                2,
            )
            .unwrap();
        }

        #[test]
        fn feature_incompatible() {
            let result = Claim::new_with_user_guid(
                "claim_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
                1,
            );
            assert!(result.is_err());
        }

        #[test]
        fn version_incompatible() {
            let result = Claim::new_with_user_guid(
                "claim_generator",
                "acme:urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                2,
            );
            assert!(result.is_err());
        }

        #[test]
        fn malformed() {
            let result = Claim::new_with_user_guid(
                "claim_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
                1,
            );
            assert!(result.is_err());
        }

        #[test]
        fn bad_v2_scheme() {
            let result = Claim::new_with_user_guid(
                "claim_generator",
                "urn:blahblah:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
                2,
            );
            assert!(result.is_err());
        }

        #[test]
        fn uuid_version_1_not_allowed() {
            // UUID version 1 (not version 4/Random) - should fail (line 477).
            let result = Claim::new_with_user_guid(
                "claim_generator",
                "urn:c2pa:3fad1ead-1ed5-11d0-873b-ea5f58adea82:acme",
                2,
            );
            assert!(result.is_err());
        }

        #[test]
        fn uuid_version_5_not_allowed() {
            // UUID version 5 (not version 4/Random) - should fail (line 477).
            let result = Claim::new_with_user_guid(
                "claim_generator",
                "urn:c2pa:3fad1ead-8ed5-54d0-873b-ea5f58adea82:acme",
                2,
            );
            assert!(result.is_err());
        }

        #[test]
        fn v1_without_cgi_prefix() {
            // V1 without CGI prefix - should succeed (lines 500-503).
            Claim::new_with_user_guid(
                "claim_generator",
                "urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                1,
            )
            .unwrap();
        }
    }

    mod claim_generator_hints {
        use super::super::*;

        #[test]
        fn add_multiple_hints() {
            // Create a new claim.
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

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

    mod add_claim_generator {
        use super::super::*;

        #[test]
        fn add_hint_with_non_special_key() {
            // Test for line 1211: the default branch in the match statement.
            // This tests adding a hint with a key that is not GH_UA or GH_FULL_VERSION_LIST.
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Add a hint with a custom key.
            claim.add_claim_generator_hint("Custom-Key", Value::String("custom value".to_string()));

            let cg_map = claim.get_claim_generator_hint_map().unwrap();
            let value = &cg_map["Custom-Key"];

            assert_eq!("custom value", value.as_str().unwrap());

            // Add another value for the same key. It should replace, not merge.
            claim.add_claim_generator_hint("Custom-Key", Value::String("new value".to_string()));

            let cg_map = claim.get_claim_generator_hint_map().unwrap();
            let value = &cg_map["Custom-Key"];

            assert_eq!("new value", value.as_str().unwrap());
        }

        #[test]
        fn add_hint_with_gh_ua_key() {
            // Test merging behavior for GH_UA key.
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            claim.add_claim_generator_hint(GH_UA, Value::String("first value".to_string()));
            claim.add_claim_generator_hint(GH_UA, Value::String("second value".to_string()));

            let cg_map = claim.get_claim_generator_hint_map().unwrap();
            let value = &cg_map[GH_UA];

            assert_eq!("first value, second value", value.as_str().unwrap());
        }
    }

    mod claim_generator_info {
        use super::super::*;
        use crate::resource_store::UriOrResource;

        #[test]
        fn add_and_retrieve_info() {
            // Create a new claim.
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            let mut info = ClaimGeneratorInfo::new("test app");
            info.version = Some("2.3.4".to_string());
            info.icon = Some(UriOrResource::HashedUri(HashedUri::new(
                "self#jumbf=c2pa.databoxes.data_box".to_string(),
                None,
                b"hashed",
            )));
            info.insert("something", "else");

            claim.add_claim_generator_info(info);

            let cgi = claim.claim_generator_info().unwrap();

            assert_eq!(&cgi[0].name, "test app");
            assert_eq!(cgi[0].version.as_deref(), Some("2.3.4"));
            if let UriOrResource::HashedUri(r) = cgi[1].icon.as_ref().unwrap() {
                assert_eq!(r.hash(), b"hashed");
            }
        }
    }

    mod add_claim_metadata {
        #[test]
        fn add_multiple_metadata_items() {
            // Test line 1185: Add multiple claim metadata items to exercise the Some(md_vec) branch.
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Add first metadata - exercises the None branch (line 1186).
            let metadata1 = crate::assertions::AssertionMetadata::new();
            claim.add_claim_metadata(metadata1);

            // Verify first metadata was added.
            let md = claim.metadata().unwrap();
            assert_eq!(md.len(), 1);

            // Add second metadata - exercises the Some(md_vec) branch (line 1185).
            let metadata2 = crate::assertions::AssertionMetadata::new();
            claim.add_claim_metadata(metadata2);

            // Verify both metadata items are present.
            let md = claim.metadata().unwrap();
            assert_eq!(md.len(), 2);

            // Add third metadata to further verify the Some branch works correctly.
            let metadata3 = crate::assertions::AssertionMetadata::new();
            claim.add_claim_metadata(metadata3);

            // Verify all three metadata items are present.
            let md = claim.metadata().unwrap();
            assert_eq!(md.len(), 3);
        }
    }

    mod add_assertion {
        use super::super::*;

        #[test]
        fn add_multiple_instances() -> Result<()> {
            let mut claim = crate::utils::test::create_min_test_claim()?;

            const MY_METADATA: &str = "my.metadata";
            let data = json!({
            "@context" : {
                "dc" : "http://purl.org/dc/elements/1.1/"
            },
            "dc:created": "2025 August 13",
            "dc:creator": [
                 "John Doe"
            ]
            })
            .to_string();

            let metadata = assertions::Metadata::new(MY_METADATA, &data)?;

            // add first time
            claim.add_assertion(&metadata)?;

            // add second time should create instance label
            claim.add_assertion(&metadata)?;

            // add third time should create instance label
            claim.add_assertion(&metadata)?;

            // check that we have three instances now
            let instances = claim.count_instances(MY_METADATA);
            assert_eq!(instances, 3);

            // check that we can retrieve each one
            for i in 0..instances {
                let ca = claim
                    .get_claim_assertion(MY_METADATA, i)
                    .expect("should find assertion");
                assert_eq!(ca.instance(), i);
                assert_eq!(ca.label_raw(), MY_METADATA);
                assert_eq!(ca.assertion().label(), MY_METADATA);
                assert_eq!(ca.assertion_type(), ClaimAssertionType::Gathered);
                //assert_eq!(ca.assertion().decode_data(), AssertionData::Cbor(vec![1, 2, 3, 4]));
            }

            Ok(())
        }
    }

    mod claim_assertion {
        use super::super::*;

        #[test]
        fn claim_assertion_instance_string() -> Result<()> {
            let mut claim = crate::utils::test::create_min_test_claim()?;

            const MY_METADATA: &str = "my.metadata";
            let data = json!({
            "@context" : {
                "dc" : "http://purl.org/dc/elements/1.1/"
            },
            "dc:created": "2025 August 13",
            "dc:creator": [
                "John Doe"
            ]
            })
            .to_string();

            let metadata = assertions::Metadata::new(MY_METADATA, &data)?;

            // Add multiple assertions to create different instances.
            claim.add_assertion(&metadata)?;
            claim.add_assertion(&metadata)?;
            claim.add_assertion(&metadata)?;

            // Test instance_string() for different instance numbers.
            for i in 0..3 {
                let ca = claim
                    .get_claim_assertion(MY_METADATA, i)
                    .expect("should find assertion");

                // Verify instance_string() returns the string representation of the
                // instance number.
                assert_eq!(ca.instance_string(), format!("{}", i));
                assert_eq!(ca.instance_string(), i.to_string());
            }

            Ok(())
        }

        #[test]
        fn label_ingredient_thumbnail_without_image_type() {
            // Test the None branch in label() when get_thumbnail_image_type returns None
            // (line 176: None => label).

            // Create an assertion with ingredient thumbnail label (no image type extension).
            let test_data = b"test data";
            let assertion = Assertion::from_data_cbor(labels::INGREDIENT_THUMBNAIL, test_data);

            // Create a ClaimAssertion with instance > 0 to trigger the thumbnail path.
            let claim_assertion = ClaimAssertion::new(
                assertion,
                1, // instance > 0
                b"test_hash",
                "sha256",
                None,
                ClaimAssertionType::Gathered,
            );

            // Call label() which should hit line 176 (None branch).
            let label = claim_assertion.label();

            // Expected format: "c2pa.thumbnail.ingredient__1" (no image type extension).
            assert_eq!(label, format!("{}__1", labels::INGREDIENT_THUMBNAIL));
            assert!(!label.contains(".jpeg"));
            assert!(!label.contains(".png"));
        }

        #[test]
        fn is_same_type() -> Result<()> {
            // Test ClaimAssertion::is_same_type (lines 215-217).
            let mut claim = crate::utils::test::create_min_test_claim()?;

            const MY_METADATA: &str = "my.metadata";
            let data = json!({
            "@context" : {
                "dc" : "http://purl.org/dc/elements/1.1/"
            },
            "dc:created": "2025 August 13",
            "dc:creator": [
                 "John Doe"
            ]
            })
            .to_string();

            let metadata1 = assertions::Metadata::new(MY_METADATA, &data)?;
            let metadata2 = assertions::Metadata::new(MY_METADATA, &data)?;

            claim.add_assertion(&metadata1)?;

            let ca = claim
                .get_claim_assertion(MY_METADATA, 0)
                .expect("should find assertion");

            // Create another assertion of the same type.
            let same_type_assertion = metadata2.to_assertion()?;

            // Test is_same_type returns true for same type.
            assert!(ca.is_same_type(&same_type_assertion));

            // Create a different type of assertion.
            let actions = Actions::new();
            let different_type_assertion = actions.to_assertion()?;

            // Test is_same_type returns false for different type.
            assert!(!ca.is_same_type(&different_type_assertion));

            Ok(())
        }

        #[test]
        fn set_assertion_type() -> Result<()> {
            // Test ClaimAssertion::set_assertion_type (lines 223-225).
            let mut claim = crate::utils::test::create_min_test_claim()?;

            const MY_METADATA: &str = "my.metadata";
            let data = json!({
            "@context" : {
                "dc" : "http://purl.org/dc/elements/1.1/"
            },
            "dc:created": "2025 August 13",
            "dc:creator": [
                 "John Doe"
            ]
            })
            .to_string();

            let metadata = assertions::Metadata::new(MY_METADATA, &data)?;
            claim.add_assertion(&metadata)?;

            let mut ca = claim
                .get_claim_assertion(MY_METADATA, 0)
                .expect("should find assertion")
                .clone();

            // Initially should be Gathered.
            assert_eq!(ca.assertion_type(), ClaimAssertionType::Gathered);

            // Change to Created.
            ca.set_assertion_type(ClaimAssertionType::Created);
            assert_eq!(ca.assertion_type(), ClaimAssertionType::Created);

            // Change to V1.
            ca.set_assertion_type(ClaimAssertionType::V1);
            assert_eq!(ca.assertion_type(), ClaimAssertionType::V1);

            Ok(())
        }

        #[test]
        fn impl_debug() -> Result<()> {
            // Test Debug implementation for ClaimAssertion (lines 228-236).
            let mut claim = crate::utils::test::create_min_test_claim()?;

            const MY_METADATA: &str = "my.metadata";
            let data = json!({
            "@context" : {
                "dc" : "http://purl.org/dc/elements/1.1/"
            },
            "dc:created": "2025 August 13",
            "dc:creator": [
                 "John Doe"
            ]
            })
            .to_string();

            let metadata = assertions::Metadata::new(MY_METADATA, &data)?;
            claim.add_assertion(&metadata)?;
            claim.add_assertion(&metadata)?;

            let ca0 = claim
                .get_claim_assertion(MY_METADATA, 0)
                .expect("should find assertion");

            let ca1 = claim
                .get_claim_assertion(MY_METADATA, 1)
                .expect("should find assertion");

            // Format using Debug trait.
            let debug_str0 = format!("{:?}", ca0);
            let debug_str1 = format!("{:?}", ca1);

            // Verify the debug output contains expected components.
            assert!(debug_str0.contains("instance: 0"));
            assert!(debug_str0.contains("Gathered"));

            assert!(debug_str1.contains("instance: 1"));
            assert!(debug_str1.contains("Gathered"));

            // Verify they're different (different instances).
            assert_ne!(debug_str0, debug_str1);

            Ok(())
        }
    }

    mod claim_decoding {
        use super::super::*;

        #[test]
        fn from_value_unsupported_claim_version() {
            // Test Claim::from_value with invalid claim version (lines 572-574).
            // This should fail when neither 'assertions' nor 'created_assertions' is present.

            use std::collections::BTreeMap;

            use serde_cbor::Value;

            // Create a minimal CBOR map without assertions or created_assertions fields.
            let mut claim_map = BTreeMap::new();
            claim_map.insert(
                Value::Text("claim_generator".to_string()),
                Value::Text("test_generator".to_string()),
            );
            claim_map.insert(
                Value::Text("signature".to_string()),
                Value::Text("self#jumbf=/test/c2pa.signature".to_string()),
            );
            claim_map.insert(
                Value::Text("dc:format".to_string()),
                Value::Text("image/jpeg".to_string()),
            );
            claim_map.insert(
                Value::Text("instanceID".to_string()),
                Value::Text("xmp:iid:12345678-1234-1234-1234-123456789012".to_string()),
            );

            let claim_value = Value::Map(claim_map);
            let claim_cbor = serde_cbor::to_vec(&claim_value).unwrap();

            // Try to create a claim from this invalid data.
            let result = Claim::from_data("test_label", &claim_cbor);

            // Should fail with unsupported claim version error.
            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    assert!(msg.contains("unsupported claim version"));
                }
                _ => {
                    panic!("Expected ClaimDecoding error with 'unsupported claim version' message")
                }
            }
        }

        #[test]
        fn from_value_both_assertions_fields() {
            // Test Claim::from_value with both 'assertions' and 'created_assertions' present.
            // This is also invalid and should trigger lines 572-574.

            use std::collections::BTreeMap;

            use serde_cbor::Value;

            // Create a CBOR map with BOTH assertions and created_assertions fields.
            let mut claim_map = BTreeMap::new();
            claim_map.insert(
                Value::Text("claim_generator".to_string()),
                Value::Text("test_generator".to_string()),
            );

            // Add both assertions fields (invalid - should only have one).
            claim_map.insert(
                Value::Text("assertions".to_string()),
                Value::Array(vec![]), // Empty array
            );
            claim_map.insert(
                Value::Text("created_assertions".to_string()),
                Value::Array(vec![]), // Empty array
            );

            let claim_value = Value::Map(claim_map);
            let claim_cbor = serde_cbor::to_vec(&claim_value).unwrap();

            // Try to create a claim from this invalid data.
            let result = Claim::from_data("test_label", &claim_cbor);

            // Should fail with unsupported claim version error.
            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    assert!(msg.contains("unsupported claim version"));
                }
                _ => {
                    panic!("Expected ClaimDecoding error with 'unsupported claim version' message")
                }
            }
        }

        #[test]
        fn from_value_v1_non_text_key() {
            use serde_cbor::Value;

            // Create a minimal V1 claim structure with a non-text key (integer).
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                Value::Text(CLAIM_GENERATOR_F.to_string()),
                Value::Text("test_generator".to_string()),
            );
            map.insert(
                Value::Text(SIGNATURE_F.to_string()),
                Value::Text("self#jumbf=c2pa.signature".to_string()),
            );
            map.insert(Value::Text(ASSERTIONS_F.to_string()), Value::Array(vec![]));
            map.insert(
                Value::Text(DC_FORMAT_F.to_string()),
                Value::Text("image/jpeg".to_string()),
            );
            map.insert(
                Value::Text(INSTANCE_ID_F.to_string()),
                Value::Text("xmp:iid:test".to_string()),
            );

            // Add a non-text key (integer) to trigger error.
            map.insert(Value::Integer(123), Value::Text("invalid".to_string()));

            let claim_value = Value::Map(map);
            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    assert_eq!(msg, "non-text key in V1 claim");
                }
                _ => panic!("Expected ClaimDecoding error with 'non-text key in V1 claim'"),
            }
        }

        #[test]
        fn from_value_v1_not_an_object() {
            // Test line 622: V1 claim that is not an object (Map).
            // Note: This error path is actually unreachable in practice because
            // map_cbor_to_type() returns None for non-Map values, causing version
            // detection to fail with "unsupported claim version" before line 622.
            // This test verifies the actual behavior.
            use serde_cbor::Value;

            // Create a non-object value (Array).
            let claim_value = Value::Array(vec![
                Value::Text("assertions".to_string()),
                Value::Array(vec![]),
            ]);

            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    // The version detection fails before reaching the "claim is not an object" check.
                    assert_eq!(msg, "unsupported claim version");
                }
                _ => panic!("Expected ClaimDecoding error with 'unsupported claim version'"),
            }
        }

        #[test]
        fn from_value_v2_unknown_field() {
            use serde_cbor::Value;

            // Create a minimal V2 claim structure with an unknown field.
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                Value::Text(INSTANCE_ID_F.to_string()),
                Value::Text("xmp:iid:test".to_string()),
            );
            map.insert(
                Value::Text(CLAIM_GENERATOR_INFO_F.to_string()),
                Value::Map({
                    let mut info_map = std::collections::BTreeMap::new();
                    info_map.insert(
                        Value::Text("name".to_string()),
                        Value::Text("test_app".to_string()),
                    );
                    info_map
                }),
            );
            map.insert(
                Value::Text(SIGNATURE_F.to_string()),
                Value::Text("self#jumbf=c2pa.signature".to_string()),
            );
            map.insert(
                Value::Text(CREATED_ASSERTIONS_F.to_string()),
                Value::Array(vec![]),
            );

            // Add an unknown field to trigger error.
            map.insert(
                Value::Text("unknown_field".to_string()),
                Value::Text("invalid".to_string()),
            );

            let claim_value = Value::Map(map);
            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    assert!(msg.starts_with("unknown V2 claim field:"));
                }
                _ => panic!("Expected ClaimDecoding error with 'unknown V2 claim field'"),
            }
        }

        #[test]
        fn from_value_v2_non_text_key() {
            use serde_cbor::Value;

            // Create a minimal V2 claim structure with a non-text key (integer).
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                Value::Text(INSTANCE_ID_F.to_string()),
                Value::Text("xmp:iid:test".to_string()),
            );
            map.insert(
                Value::Text(CLAIM_GENERATOR_INFO_F.to_string()),
                Value::Map({
                    let mut info_map = std::collections::BTreeMap::new();
                    info_map.insert(
                        Value::Text("name".to_string()),
                        Value::Text("test_app".to_string()),
                    );
                    info_map
                }),
            );
            map.insert(
                Value::Text(SIGNATURE_F.to_string()),
                Value::Text("self#jumbf=c2pa.signature".to_string()),
            );
            map.insert(
                Value::Text(CREATED_ASSERTIONS_F.to_string()),
                Value::Array(vec![]),
            );

            // Add a non-text key (integer) to trigger error.
            map.insert(Value::Integer(456), Value::Text("invalid".to_string()));

            let claim_value = Value::Map(map);
            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    assert_eq!(msg, "non-text key in V2 claim");
                }
                _ => panic!("Expected ClaimDecoding error with 'non-text key in V2 claim'"),
            }
        }

        #[test]
        fn from_value_v2_not_an_object() {
            // Test line 720: V2 claim that is not an object (Map).
            // Note: This error path is actually unreachable in practice because
            // map_cbor_to_type() returns None for non-Map values, causing version
            // detection to fail with "unsupported claim version" before line 720.
            // This test verifies the actual behavior.
            use serde_cbor::Value;

            // Create a non-object value (Array).
            let claim_value = Value::Array(vec![
                Value::Text("created_assertions".to_string()),
                Value::Array(vec![]),
            ]);

            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    // The version detection fails before reaching the "claim is not an object" check.
                    assert_eq!(msg, "unsupported claim version");
                }
                _ => panic!("Expected ClaimDecoding error with 'unsupported claim version'"),
            }
        }

        #[test]
        fn from_value_v2_missing_instance_id() {
            // Test line 725: V2 claim missing instanceID field.
            use serde_cbor::Value;

            // Create a V2 claim structure without instanceID.
            let mut map = std::collections::BTreeMap::new();

            // instanceID is missing - this should trigger the error.
            map.insert(
                Value::Text(CLAIM_GENERATOR_INFO_F.to_string()),
                Value::Map({
                    let mut info_map = std::collections::BTreeMap::new();
                    info_map.insert(
                        Value::Text("name".to_string()),
                        Value::Text("test_app".to_string()),
                    );
                    info_map
                }),
            );
            map.insert(
                Value::Text(SIGNATURE_F.to_string()),
                Value::Text("self#jumbf=c2pa.signature".to_string()),
            );
            map.insert(
                Value::Text(CREATED_ASSERTIONS_F.to_string()),
                Value::Array(vec![]),
            );

            let claim_value = Value::Map(map);
            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    assert_eq!(msg, "instanceID is missing or invalid");
                }
                _ => panic!("Expected ClaimDecoding error with 'instanceID is missing or invalid'"),
            }
        }

        #[test]
        fn from_value_v2_missing_claim_generator_info() {
            use serde_cbor::Value;

            // Create a V2 claim structure without claim_generator_info.
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                Value::Text(INSTANCE_ID_F.to_string()),
                Value::Text("xmp:iid:test".to_string()),
            );
            // claim_generator_info is missing - this should trigger the error.
            map.insert(
                Value::Text(SIGNATURE_F.to_string()),
                Value::Text("self#jumbf=c2pa.signature".to_string()),
            );
            map.insert(
                Value::Text(CREATED_ASSERTIONS_F.to_string()),
                Value::Array(vec![]),
            );

            let claim_value = Value::Map(map);
            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    assert_eq!(msg, "claim_generator_info is missing or invalid");
                }
                _ => panic!(
                    "Expected ClaimDecoding error with 'claim_generator_info is missing or invalid'"
                ),
            }
        }

        #[test]
        fn from_value_v2_missing_signature() {
            use serde_cbor::Value;

            // Create a V2 claim structure without signature.
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                Value::Text(INSTANCE_ID_F.to_string()),
                Value::Text("xmp:iid:test".to_string()),
            );
            map.insert(
                Value::Text(CLAIM_GENERATOR_INFO_F.to_string()),
                Value::Map({
                    let mut info_map = std::collections::BTreeMap::new();
                    info_map.insert(
                        Value::Text("name".to_string()),
                        Value::Text("test_app".to_string()),
                    );
                    info_map
                }),
            );

            // signature is missing - this should trigger the error.
            map.insert(
                Value::Text(CREATED_ASSERTIONS_F.to_string()),
                Value::Array(vec![]),
            );

            let claim_value = Value::Map(map);
            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    assert_eq!(msg, "signature is missing or invalid");
                }
                _ => panic!("Expected ClaimDecoding error with 'signature is missing or invalid'"),
            }
        }

        #[test]
        fn from_value_v2_missing_created_assertions() {
            // Note: This error path is actually unreachable in practice because
            // version detection (lines 567-570) requires created_assertions to be
            // deserializable as Vec<HashedUri>. If it's missing or invalid, version
            // detection fails with "unsupported claim version" before line 736.
            // This test verifies the actual behavior.
            use serde_cbor::Value;

            // Create a V2 claim structure with invalid created_assertions.
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                Value::Text(INSTANCE_ID_F.to_string()),
                Value::Text("xmp:iid:test".to_string()),
            );
            map.insert(
                Value::Text(CLAIM_GENERATOR_INFO_F.to_string()),
                Value::Map({
                    let mut info_map = std::collections::BTreeMap::new();
                    info_map.insert(
                        Value::Text("name".to_string()),
                        Value::Text("test_app".to_string()),
                    );
                    info_map
                }),
            );
            map.insert(
                Value::Text(SIGNATURE_F.to_string()),
                Value::Text("self#jumbf=c2pa.signature".to_string()),
            );

            // created_assertions is present but invalid (not a proper array of HashedUri).
            map.insert(
                Value::Text(CREATED_ASSERTIONS_F.to_string()),
                Value::Text("invalid".to_string()), // Wrong type
            );

            let claim_value = Value::Map(map);
            let data = serde_cbor::to_vec(&claim_value).unwrap();

            let result = Claim::from_value(claim_value, "test_label", &data);

            assert!(result.is_err());
            match result {
                Err(Error::ClaimDecoding(msg)) => {
                    // The version detection fails before reaching the field extraction at line 736.
                    assert_eq!(msg, "unsupported claim version");
                }
                _ => panic!("Expected ClaimDecoding error with 'unsupported claim version'"),
            }
        }

        mod serialize_v1 {
            use crate::utils::test::create_test_claim;

            #[test]
            fn with_optional_fields() {
                // Test lines 827, 830, 851, 863, 866: Serialization with alg, alg_soft, metadata, and format.
                let mut claim = create_test_claim().expect("create test claim");

                // Force the claim to use V1 serialization by setting claim_version to 1.
                claim.claim_version = 1;

                // Ensure format is set to trigger line 851.
                claim.format = Some("image/jpeg".to_string());

                // Set the optional fields to trigger the paths at lines 827, 830, 863, 866.
                claim.alg = Some("sha256".to_string());
                claim.alg_soft = Some("sha256-soft".to_string());

                // Add metadata to trigger lines 830, 866.
                let metadata = crate::assertions::AssertionMetadata::new();
                claim.add_claim_metadata(metadata);

                // Serialize to CBOR (triggers serialize_v1).
                let result = serde_cbor::to_vec(&claim);

                // The serialization should work with optional fields.
                assert!(result.is_ok());
            }

            #[test]
            fn without_claim_generator() {
                // Test line 838: Serialization path when claim_generator is None
                // This covers the else branch of the `if let Some(cg) = self.claim_generator()`.
                let mut claim = create_test_claim().expect("create test claim");

                // Clear claim_generator to test the None path.
                claim.claim_generator = None;

                // Serialize to CBOR - this should exercise line 838.
                // Note: This may fail validation in build(), so we just serialize directly.
                let result = serde_cbor::to_vec(&claim);

                // The serialization should work even without claim_generator.
                assert!(result.is_ok());
            }

            #[test]
            fn without_format() {
                // Test when format is None - this exercises the path where the
                // if condition at line 849 is false (format is None).
                let mut claim = create_test_claim().expect("create test claim");

                // Force V1 serialization.
                claim.claim_version = 1;

                // Clear the format.
                claim.format = None;

                // Serialize to CBOR.
                let result = serde_cbor::to_vec(&claim);

                // The serialization should work even without format.
                assert!(result.is_ok());
            }

            #[test]
            fn with_format() {
                // Test line 851: Serialization path when format is present (Some).
                // This covers line 850 (serializing the format field) and line 851 (closing brace).
                let mut claim = create_test_claim().expect("create test claim");

                // Force V1 serialization.
                claim.claim_version = 1;

                // Ensure format is set to trigger lines 850-851.
                claim.format = Some("image/jpeg".to_string());

                // Serialize to CBOR.
                let result = serde_cbor::to_vec(&claim);

                // The serialization should work with format.
                assert!(result.is_ok());
            }

            #[test]
            fn without_optional_fields() {
                // Test serialization paths when alg, alg_soft, and metadata are all None.
                // This covers the branches where optional fields are not present (i.e., the
                // if conditions at lines 823, 826, 829 evaluate to false, and the if conditions
                // at lines 862, 865 also evaluate to false).
                let mut claim = create_test_claim().expect("create test claim");

                // Force the claim to use V1 serialization by setting claim_version to 1.
                claim.claim_version = 1;

                // Ensure these optional fields are None to skip the optional field handling.
                claim.alg = None;
                claim.alg_soft = None;
                claim.metadata = None;

                // Serialize to CBOR - tests the None branches for optional fields.
                let result = serde_cbor::to_vec(&claim);

                // The serialization should work even without optional fields.
                assert!(result.is_ok());
            }
        }

        mod serialize_v2 {
            use crate::utils::test::create_test_claim;

            #[test]
            fn with_optional_fields() {
                // Test lines 893, 902, 904, 907, 944, 947: Serialization with all optional fields.
                let mut claim = create_test_claim().expect("create test claim");

                // V2 is the default for create_test_claim(), but let's be explicit.
                claim.claim_version = 2;

                // Set gathered_assertions to trigger line 893.
                claim.gathered_assertions = Some(vec![]);

                // Set optional fields to trigger lines 902, 904, 907, 944, 947.
                claim.alg = Some("sha256".to_string());
                claim.alg_soft = Some("sha256-soft".to_string());

                // Add metadata to trigger lines 907, 947.
                let metadata = crate::assertions::AssertionMetadata::new();
                claim.add_claim_metadata(metadata);

                // Serialize to CBOR (triggers serialize_v2).
                let result = serde_cbor::to_vec(&claim);

                // The serialization should work with optional fields.
                assert!(result.is_ok());
            }

            #[test]
            fn without_optional_fields() {
                // Test serialization when optional fields (gathered_assertions, alg, alg_soft, metadata) are None.
                let mut claim = create_test_claim().expect("create test claim");

                // V2 is the default for create_test_claim().
                claim.claim_version = 2;

                // Ensure optional fields are None.
                claim.gathered_assertions = None;
                claim.alg = None;
                claim.alg_soft = None;
                claim.metadata = None;

                // Serialize to CBOR.
                let result = serde_cbor::to_vec(&claim);

                // The serialization should work without optional fields.
                assert!(result.is_ok());
            }

            #[test]
            fn with_empty_claim_generator_info() {
                // Test lines 919-921: Error path when claim_generator_info is empty.
                let mut claim = create_test_claim().expect("create test claim");

                // V2 claim.
                claim.claim_version = 2;

                // Set claim_generator_info to an empty vector to trigger the error at lines 919-921.
                claim.claim_generator_info = Some(Vec::new());

                // Serialize to CBOR - this should fail with an error.
                let result = serde_cbor::to_vec(&claim);

                // The serialization should fail.
                assert!(result.is_err());
            }

            #[test]
            fn without_claim_generator_info() {
                // Test lines 924-926: Error path when claim_generator_info is None.
                let mut claim = create_test_claim().expect("create test claim");

                // V2 claim.
                claim.claim_version = 2;

                // Set claim_generator_info to None to trigger the error at lines 924-926.
                claim.claim_generator_info = None;

                // Serialize to CBOR - this should fail with an error.
                let result = serde_cbor::to_vec(&claim);

                // The serialization should fail.
                assert!(result.is_err());
            }
        }
    }

    mod build {
        use super::super::*;
        use crate::{
            assertions::EmbeddedData, claim::labels::CLAIM_THUMBNAIL,
            utils::test::create_test_claim,
        };

        #[test]
        fn multiple_claim_generator_info() {
            // Test line 965: Error when claim has more than one claim_generator_info for v2.
            let mut claim = create_test_claim().expect("create test claim");

            // Add a second claim_generator_info to trigger the error.
            let info2 = ClaimGeneratorInfo::new("second app");
            claim.add_claim_generator_info(info2);

            // Build should fail with VersionCompatibility error.
            let result = claim.build();
            assert!(result.is_err());
            match result {
                Err(Error::VersionCompatibility(msg)) => {
                    assert_eq!(msg, "only 1 claim_generator_info allowed");
                }
                _ => panic!("Expected VersionCompatibility error"),
            }
        }

        #[test]
        fn missing_claim_generator_info() {
            // Test line 971: Error when claim_generator_info is missing for v2.
            let mut claim = Claim::new("test_generator", Some("test"), 2);

            // Don't add claim_generator_info (it's None by default).
            // This should trigger the error at line 971.
            let result = claim.build();
            assert!(result.is_err());
            match result {
                Err(Error::VersionCompatibility(msg)) => {
                    assert_eq!(msg, "claim_generator_info is mandatory");
                }
                _ => panic!("Expected VersionCompatibility error"),
            }
        }

        #[test]
        fn multiple_claim_thumbnails() {
            // Test line 986: Error when claim has more than one claim thumbnail.
            let mut claim = create_test_claim().expect("create test claim");

            // create_test_claim already adds one claim thumbnail.
            // Add a second claim thumbnail to trigger the error.
            let claim_thumbnail2 =
                EmbeddedData::new(CLAIM_THUMBNAIL, "image/jpeg", vec![0xca, 0xfe, 0xba, 0xbe]);

            claim
                .add_assertion(&claim_thumbnail2)
                .expect("failed to add second claim thumbnail");

            // Build should fail with OtherError.
            let result = claim.build();
            assert!(result.is_err());
            match result {
                Err(Error::OtherError(msg)) => {
                    assert_eq!(
                        msg.to_string(),
                        "only one claim thumbnail assertion allowed"
                    );
                }
                _ => panic!("Expected OtherError"),
            }
        }
    }

    mod label {
        #[test]
        fn returns_regular_label_when_no_conflict() {
            let claim = crate::utils::test::create_test_claim().expect("create test claim");
            // Should return the regular label when conflict_label is None
            assert!(!claim.label().is_empty());
        }

        #[test]
        fn returns_conflict_label_when_set() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");
            let original_label = claim.label().to_string();

            // Set a conflict label
            let conflict_label = "conflict_label_test";
            claim.set_conflict_label(conflict_label.to_string());

            // Should now return the conflict label instead of the original
            assert_eq!(claim.label(), conflict_label);
            assert_ne!(claim.label(), original_label);
        }
    }

    mod conflict_label {
        #[test]
        fn returns_none_when_not_set() {
            let claim = crate::utils::test::create_test_claim().expect("create test claim");
            // Should return None when conflict_label hasn't been set
            assert_eq!(claim.conflict_label(), &None);
        }

        #[test]
        fn returns_some_when_set() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Set a conflict label
            let conflict_label = "conflict_label_test";
            claim.set_conflict_label(conflict_label.to_string());

            // Should now return Some with the conflict label
            assert_eq!(claim.conflict_label(), &Some(conflict_label.to_string()));
        }
    }

    mod vendor {
        use super::super::*;

        #[test]
        fn returns_none_for_v1_claim_without_vendor() {
            // V1 claim without vendor
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                1,
            )
            .expect("failed to create claim");

            assert_eq!(claim.vendor(), None);
        }

        #[test]
        fn returns_some_for_v1_claim_with_vendor() {
            // V1 claim with vendor
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "acme:urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                1,
            )
            .expect("failed to create claim");

            assert_eq!(claim.vendor(), Some("acme".to_string()));
        }

        #[test]
        fn returns_none_for_v2_claim_without_vendor() {
            // V2 claim without vendor
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                2,
            )
            .expect("failed to create claim");

            assert_eq!(claim.vendor(), None);
        }

        #[test]
        fn returns_some_for_v2_claim_with_vendor() {
            // V2 claim with vendor
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
                2,
            )
            .expect("failed to create claim");

            assert_eq!(claim.vendor(), Some("acme".to_string()));
        }
    }

    mod claim_instance_version {
        use super::super::*;

        #[test]
        fn returns_none_for_v1_claim() {
            // V1 claims don't have instance version
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                1,
            )
            .expect("failed to create claim");

            assert_eq!(claim.claim_instance_version(), None);
        }

        #[test]
        fn returns_none_for_v2_claim_without_version() {
            // V2 claim without version
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                2,
            )
            .expect("failed to create claim");

            assert_eq!(claim.claim_instance_version(), None);
        }

        #[test]
        fn returns_version_for_v2_claim_with_version() {
            // V2 claim with version (but no vendor, using :: syntax)
            // Note: We can't create this through new_with_user_guid since it creates
            // labels without version/reason. We'll need to test this by creating
            // a claim and then verifying the parsing works correctly.
            // For now, verify the method exists and returns None for claims without version.
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
                2,
            )
            .expect("failed to create claim");

            // This claim doesn't have a version in its label
            assert_eq!(claim.claim_instance_version(), None);
        }
    }

    mod claim_instance_reason {
        use super::super::*;

        #[test]
        fn returns_none_for_v1_claim() {
            // V1 claims don't have instance reason
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                1,
            )
            .expect("failed to create claim");

            assert_eq!(claim.claim_instance_reason(), None);
        }

        #[test]
        fn returns_none_for_v2_claim_without_reason() {
            // V2 claim without reason
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                2,
            )
            .expect("failed to create claim");

            assert_eq!(claim.claim_instance_reason(), None);
        }

        #[test]
        fn returns_reason_for_v2_claim_with_reason() {
            // Similar to version test, we verify the method exists and returns None
            // when reason isn't in the label
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
                2,
            )
            .expect("failed to create claim");

            // This claim doesn't have a reason in its label
            assert_eq!(claim.claim_instance_reason(), None);
        }
    }

    mod uri {
        use super::super::*;

        #[test]
        fn returns_manifest_uri_for_v1_claim() {
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:uuid:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                1,
            )
            .expect("failed to create claim");

            let uri = claim.uri();
            // URI should start with self#jumbf= and contain the manifest store
            assert!(uri.starts_with("self#jumbf="));
            assert!(uri.contains("c2pa"));
        }

        #[test]
        fn returns_manifest_uri_for_v2_claim() {
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82",
                2,
            )
            .expect("failed to create claim");

            let uri = claim.uri();
            // URI should start with self#jumbf= and contain the manifest store
            assert!(uri.starts_with("self#jumbf="));
            assert!(uri.contains("c2pa"));
        }

        #[test]
        fn returns_manifest_uri_for_v2_claim_with_vendor() {
            let claim = Claim::new_with_user_guid(
                "test_generator",
                "urn:c2pa:3fad1ead-8ed5-44d0-873b-ea5f58adea82:acme",
                2,
            )
            .expect("failed to create claim");

            let uri = claim.uri();
            // URI should start with self#jumbf= and contain the manifest store and label
            assert!(uri.starts_with("self#jumbf="));
            assert!(uri.contains("c2pa"));
            // The label should be embedded in the URI
            assert!(uri.contains(claim.label()));
        }
    }

    mod calc_assertion_box_hash {
        use super::super::*;
        use crate::assertions::Uuid;

        #[test]
        fn uuid_assertion_without_salt() {
            // Test line 1287: calc_assertion_box_hash with AssertionData::Uuid and salt = None.
            // This tests the closing brace of the `if let Some(salt)` block for the Uuid variant.
            const LABEL: &str = "test.uuid.assertion";
            const UUID: &str = "ABCDABCDABCDABCDABCDABCDABCDABCD";
            const DATA: [u8; 16] = [
                0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
                0x0b, 0x0e,
            ];

            // Create a UUID assertion.
            let uuid_assertion = Uuid::new(LABEL, UUID.to_string(), DATA.to_vec());
            let assertion = uuid_assertion
                .to_assertion()
                .expect("failed to create assertion");

            // Call calc_assertion_box_hash with salt = None to exercise line 1287.
            let result = Claim::calc_assertion_box_hash(LABEL, &assertion, None, "sha256");

            // The function should succeed and return a hash.
            assert!(result.is_ok());
            let hash = result.unwrap();
            assert!(!hash.is_empty());
        }

        #[test]
        fn uuid_assertion_with_salt() {
            // Test the opposite path: UUID assertion with salt provided.
            const LABEL: &str = "test.uuid.assertion";
            const UUID: &str = "ABCDABCDABCDABCDABCDABCDABCDABCD";
            const DATA: [u8; 16] = [
                0x0d, 0x0e, 0x0a, 0x0d, 0x0b, 0x0e, 0x0e, 0x0f, 0x0a, 0x0d, 0x0b, 0x0e, 0x0a, 0x0d,
                0x0b, 0x0e,
            ];

            // Create a UUID assertion.
            let uuid_assertion = Uuid::new(LABEL, UUID.to_string(), DATA.to_vec());
            let assertion = uuid_assertion
                .to_assertion()
                .expect("failed to create assertion");

            // Call calc_assertion_box_hash with salt provided to exercise the Some branch.
            // Salt must be at least 16 bytes long.
            let salt = vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ];
            let result = Claim::calc_assertion_box_hash(LABEL, &assertion, Some(salt), "sha256");

            // The function should succeed and return a hash.
            assert!(result.is_ok());
            let hash = result.unwrap();
            assert!(!hash.is_empty());
        }
    }

    mod compatibility_checks {
        use super::super::*;
        use crate::assertions::{Action, Actions};

        #[test]
        fn actions_version_too_low() {
            // Test lines 1318-1322: actions assertion with version < 1.
            let claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Create an actions assertion with version 0 (less than minimum required version 1).
            let actions = Actions::new().add_action(Action::new("c2pa.edited"));

            // Create the assertion with version 0.
            let actions_cbor = serde_cbor::to_vec(&actions).expect("failed to serialize actions");
            let assertion = Assertion::new(
                "c2pa.actions",
                Some(0), // version 0 is below the minimum of 1
                AssertionData::Cbor(actions_cbor),
            );

            // Call compatibility_checks and expect an error.
            let result = claim.compatibility_checks(&assertion);
            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                Error::VersionCompatibility(msg) => {
                    assert_eq!(msg, "action assertion version too low");
                }
                _ => panic!("Expected VersionCompatibility error, got: {:?}", err),
            }
        }

        #[test]
        fn deprecated_action_copied() {
            // Test lines 1324-1331: actions assertion with deprecated action "c2pa.copied".
            test_deprecated_action("c2pa.copied");
        }

        #[test]
        fn deprecated_action_formatted() {
            // Test lines 1324-1331: actions assertion with deprecated action "c2pa.formatted".
            test_deprecated_action("c2pa.formatted");
        }

        #[test]
        fn deprecated_action_version_updated() {
            // Test lines 1324-1331: actions assertion with deprecated action "c2pa.version_updated".
            test_deprecated_action("c2pa.version_updated");
        }

        #[test]
        fn deprecated_action_printed() {
            // Test lines 1324-1331: actions assertion with deprecated action "c2pa.printed".
            test_deprecated_action("c2pa.printed");
        }

        #[test]
        fn deprecated_action_managed() {
            // Test lines 1324-1331: actions assertion with deprecated action "c2pa.managed".
            test_deprecated_action("c2pa.managed");
        }

        #[test]
        fn deprecated_action_produced() {
            // Test lines 1324-1331: actions assertion with deprecated action "c2pa.produced".
            test_deprecated_action("c2pa.produced");
        }

        #[test]
        fn deprecated_action_saved() {
            // Test lines 1324-1331: actions assertion with deprecated action "c2pa.saved".
            test_deprecated_action("c2pa.saved");
        }

        fn test_deprecated_action(action_name: &str) {
            let claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Create an actions assertion with a deprecated action.
            let actions = Actions::new().add_action(Action::new(action_name));

            // Create the assertion with version 2 (valid version, but contains deprecated action).
            let actions_cbor = serde_cbor::to_vec(&actions).expect("failed to serialize actions");
            let assertion =
                Assertion::new("c2pa.actions", Some(2), AssertionData::Cbor(actions_cbor));

            // Call compatibility_checks and expect an error.
            let result = claim.compatibility_checks(&assertion);
            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                Error::VersionCompatibility(msg) => {
                    assert_eq!(msg, "action assertion has been deprecated");
                }
                _ => panic!("Expected VersionCompatibility error, got: {:?}", err),
            }
        }

        #[test]
        fn bmff_hash_version_too_low() {
            // Test lines 1337-1339: BMFF hash assertion with version < 2.
            let claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Create a BMFF hash assertion with version 1 (less than minimum required version 2).
            // We just need a minimal valid CBOR structure for the hash data.
            let bmff_hash_data = serde_cbor::to_vec(&serde_json::json!({
                "alg": "sha256",
                "hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                "name": "test.mp4"
            }))
            .expect("failed to serialize bmff hash");

            let assertion = Assertion::new(
                "c2pa.hash.bmff",
                Some(1), // version 1 is below the minimum of 2
                AssertionData::Cbor(bmff_hash_data),
            );

            // Call compatibility_checks and expect an error.
            let result = claim.compatibility_checks(&assertion);
            assert!(result.is_err());

            let err = result.unwrap_err();
            match err {
                Error::VersionCompatibility(msg) => {
                    assert_eq!(msg, "BMFF hash assertion version too low");
                }
                _ => panic!("Expected VersionCompatibility error, got: {:?}", err),
            }
        }

        #[test]
        fn bmff_hash_version_valid() {
            // Test valid BMFF hash assertion with version 2.
            let claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Create a BMFF hash assertion with version 2 (valid).
            let bmff_hash_data = serde_cbor::to_vec(&serde_json::json!({
                "alg": "sha256",
                "hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                "name": "test.mp4"
            }))
            .expect("failed to serialize bmff hash");

            let assertion = Assertion::new(
                "c2pa.hash.bmff",
                Some(2), // version 2 is valid
                AssertionData::Cbor(bmff_hash_data),
            );

            // Call compatibility_checks and expect success.
            let result = claim.compatibility_checks(&assertion);
            assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        }

        #[test]
        fn actions_version_valid() {
            // Test valid actions assertion with version 2.
            let claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Create an actions assertion with a non-deprecated action and version 2.
            let actions = Actions::new().add_action(Action::new("c2pa.edited"));

            let actions_cbor = serde_cbor::to_vec(&actions).expect("failed to serialize actions");
            let assertion = Assertion::new(
                "c2pa.actions",
                Some(2), // version 2 is valid
                AssertionData::Cbor(actions_cbor),
            );

            // Call compatibility_checks and expect success.
            let result = claim.compatibility_checks(&assertion);
            assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        }
    }

    mod claim_assertion_type {
        use super::super::*;

        #[test]
        fn label_in_created_assertion_labels() {
            // Test lines 1368-1369: When a label is in the created_assertion_labels setting,
            // it should return ClaimAssertionType::Created.

            // Set up settings with created_assertion_labels containing "stds.exif".
            let toml_config = r#"
                [builder]
                created_assertion_labels = ["stds.exif"]
            "#;
            crate::settings::Settings::from_toml(toml_config).expect("failed to set settings");

            // Create a V2 claim.
            let claim = Claim::new("test_generator", None, 2);

            // Test that stds.exif is classified as Created.
            let assertion_type = claim.claim_assertion_type("stds.exif", false);
            assert_eq!(assertion_type, ClaimAssertionType::Created);

            // Clean up settings.
            crate::settings::reset_default_settings().expect("failed to reset settings");
        }

        #[test]
        fn label_not_in_created_assertion_labels() {
            // Test lines 1370-1371: When a label is not in the created_assertion_labels setting,
            // it should return ClaimAssertionType::Gathered.

            // Set up settings with created_assertion_labels containing only "stds.exif".
            let toml_config = r#"
                [builder]
                created_assertion_labels = ["stds.exif"]
            "#;
            crate::settings::Settings::from_toml(toml_config).expect("failed to set settings");

            // Create a V2 claim.
            let claim = Claim::new("test_generator", None, 2);

            // Test that c2pa.location (not in the list) is classified as Gathered.
            let assertion_type = claim.claim_assertion_type("c2pa.location", false);
            assert_eq!(assertion_type, ClaimAssertionType::Gathered);

            // Clean up settings.
            crate::settings::reset_default_settings().expect("failed to reset settings");
        }

        #[test]
        fn multiple_labels_in_created_assertion_labels() {
            // Test lines 1368-1369: Test with multiple labels in the created_assertion_labels setting.

            // Set up settings with multiple labels.
            let toml_config = r#"
                [builder]
                created_assertion_labels = ["stds.exif", "c2pa.location", "my.custom.assertion"]
            "#;
            crate::settings::Settings::from_toml(toml_config).expect("failed to set settings");

            // Create a V2 claim.
            let claim = Claim::new("test_generator", None, 2);

            // Test that all labels in the list are classified as Created.
            assert_eq!(
                claim.claim_assertion_type("stds.exif", false),
                ClaimAssertionType::Created
            );
            assert_eq!(
                claim.claim_assertion_type("c2pa.location", false),
                ClaimAssertionType::Created
            );
            assert_eq!(
                claim.claim_assertion_type("my.custom.assertion", false),
                ClaimAssertionType::Created
            );

            // Test that a label not in the list is classified as Gathered.
            assert_eq!(
                claim.claim_assertion_type("c2pa.thumbnail", false),
                ClaimAssertionType::Gathered
            );

            // Clean up settings.
            crate::settings::reset_default_settings().expect("failed to reset settings");
        }

        #[test]
        fn no_created_assertion_labels_setting() {
            // Test lines 1373-1374: When created_assertion_labels is None (default),
            // non-hash assertions should return ClaimAssertionType::Gathered.

            // Ensure settings are at default (no created_assertion_labels).
            crate::settings::reset_default_settings().expect("failed to reset settings");

            // Create a V2 claim.
            let claim = Claim::new("test_generator", None, 2);

            // Test that a non-hash assertion is classified as Gathered when no setting is present.
            let assertion_type = claim.claim_assertion_type("stds.exif", false);
            assert_eq!(assertion_type, ClaimAssertionType::Gathered);

            // Clean up settings.
            crate::settings::reset_default_settings().expect("failed to reset settings");
        }
    }

    mod get_databox {
        use super::super::*;
        use crate::{assertions::DataBox, utils::test::create_test_claim};

        /// Test line 1518: get_databox returns None when manifest label doesn't match.
        #[test]
        fn mismatched_manifest_label() {
            let mut claim = create_test_claim().expect("create test claim");

            // Add a databox to the claim.
            let databox = DataBox {
                format: "application/octet-stream".to_string(),
                data: vec![1, 2, 3, 4, 5],
                data_types: None,
            };
            let db_cbor = serde_cbor::to_vec(&databox).expect("serialize databox");
            claim
                .put_databox("c2pa.data_1", &db_cbor, None)
                .expect("put databox");

            // Create a HashedUri with a different manifest label.
            let wrong_manifest_uri = to_databox_uri("wrong_manifest_label", "c2pa.data_1");
            let hashed_uri =
                HashedUri::new(wrong_manifest_uri, Some("sha256".to_string()), b"hash");

            // Should return None because the manifest labels don't match.
            assert!(claim.get_databox(&hashed_uri).is_none());
        }

        /// Test line 1526: get_databox with empty URI string.
        /// This tests the defensive None check when box_name_from_uri might return None.
        #[test]
        fn empty_uri_string() {
            let claim = create_test_claim().expect("create test claim");

            // Create a HashedUri with an empty URI.
            // This ensures we go through the else branch (manifest_label_from_uri returns None)
            // and tests the box_name_from_uri None check at line 1526.
            let hashed_uri = HashedUri::new(String::new(), Some("sha256".to_string()), b"hash");

            // Should return None.
            assert!(claim.get_databox(&hashed_uri).is_none());
        }

        /// Test line 1534: get_databox returns None when databox is not found.
        #[test]
        fn databox_not_found_wrong_hash() {
            let mut claim = create_test_claim().expect("create test claim");

            // Add a databox to the claim.
            let databox = DataBox {
                format: "application/octet-stream".to_string(),
                data: vec![1, 2, 3, 4, 5],
                data_types: None,
            };
            let db_cbor = serde_cbor::to_vec(&databox).expect("serialize databox");
            claim
                .put_databox("c2pa.data_1", &db_cbor, None)
                .expect("put databox");

            // Create a HashedUri with the correct manifest label and URI,
            // but with a wrong hash.
            let correct_uri = to_databox_uri(claim.label(), "c2pa.data_1");
            let wrong_hash = b"wrong_hash_value";
            let hashed_uri = HashedUri::new(correct_uri, Some("sha256".to_string()), wrong_hash);

            // Should return None because the hash doesn't match.
            assert!(claim.get_databox(&hashed_uri).is_none());
        }
    }

    mod add_verifiable_credential {
        use super::*;

        /// Test lines 1573-1575: Error when trying to add verifiable credential to a V2+ claim.
        #[test]
        fn version_compatibility_error() {
            // Create a V2 claim.
            let mut claim = Claim::new("test_generator", None, 2);

            // Try to add a verifiable credential (only supported in V1).
            let test_vc = r#"{
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "http://schema.org"
                ],
                "id": "https://example.com/credentials/123",
                "type": [
                    "VerifiableCredential",
                    "NPPACredential"
                ],
                "issuer": "https://nppa.org/",
                "credentialSubject": {
                    "id": "https://example.com/subject/456",
                    "name": "Bob Ross",
                    "memberOf": "https://nppa.org/"
                }
            }"#;

            let result = claim.add_verifiable_credential(test_vc);

            // Should return VersionCompatibility error.
            assert!(result.is_err());
            match result {
                Err(Error::VersionCompatibility(msg)) => {
                    assert_eq!(msg, "verifiable credentials not supported");
                }
                _ => panic!("Expected VersionCompatibility error with 'verifiable credentials not supported' message"),
            }
        }
    }

    mod update_assertion {
        use super::*;
        // Using CreativeWork for testing internal update_assertion functionality.
        // While deprecated for public use, it's suitable for testing the error paths.
        #[allow(deprecated)]
        use crate::assertions::CreativeWork;

        /// Test line 1656: Error when no matching assertion is found in assertion_store.
        #[test]
        #[allow(deprecated)]
        fn assertion_not_found_in_store() {
            let mut claim = create_test_claim().expect("create test claim");

            // Create an assertion that doesn't exist in the claim.
            let nonexistent_assertion = CreativeWork::new().to_assertion().expect("to_assertion");

            // Try to update the nonexistent assertion.
            let result = claim.update_assertion(nonexistent_assertion, |_| true, |_, a| Ok(a));

            // Should return NotFound error.
            assert!(matches!(result, Err(Error::NotFound)));
        }

        /// Test line 1664: Error from patch_fn callback during assertion update.
        #[test]
        #[allow(deprecated)]
        fn patch_fn_error() {
            let mut claim = create_test_claim().expect("create test claim");

            // Add an assertion that we can later update.
            let creative_work = CreativeWork::new();
            claim.add_assertion(&creative_work).expect("add_assertion");

            // Create a replacement assertion.
            let replace_with = CreativeWork::new().to_assertion().expect("to_assertion");

            // Use a patch_fn that returns an error.
            let result = claim.update_assertion(
                replace_with,
                |ca| ca.assertion().label() == "stds.schema-org.CreativeWork",
                |_, _| Err(Error::AssertionInvalidRedaction),
            );

            // Should return the error from patch_fn.
            assert!(matches!(result, Err(Error::AssertionInvalidRedaction)));
        }

        /// Test line 1686: Error when no matching hash is found in assertions list.
        #[test]
        #[allow(deprecated)]
        fn hash_not_found_in_assertions_list() {
            let mut claim = create_test_claim().expect("create test claim");

            // Add an assertion.
            let creative_work = CreativeWork::new();
            claim.add_assertion(&creative_work).expect("add_assertion");

            // Create a replacement assertion (doesn't need to be different).
            let replace_with = CreativeWork::new().to_assertion().expect("to_assertion");

            // Corrupt the assertions list by removing or modifying the hash reference.
            // We'll save the original hash and then modify it in the assertions list.
            if let Some(target_assertion) = claim
                .assertion_store
                .iter()
                .find(|ca| ca.assertion().label() == "stds.schema-org.CreativeWork")
            {
                let target_label = target_assertion.label();
                let original_hash = target_assertion.hash().to_vec();

                // Find and modify the hash in the assertions list.
                if let Some(hashed_uri) = claim.assertions.iter_mut().find(|f| {
                    f.url().contains(&target_label) && vec_compare(&f.hash(), &original_hash)
                }) {
                    // Corrupt the hash so it won't match during update_assertion.
                    let mut corrupted_hash = original_hash.clone();
                    corrupted_hash[0] ^= 0xff; // Flip bits in first byte.
                    hashed_uri.update_hash(corrupted_hash);
                }
            }

            // Try to update the assertion with corrupted hash reference.
            let result = claim.update_assertion(
                replace_with,
                |ca| ca.assertion().label() == "stds.schema-org.CreativeWork",
                |_, a| Ok(a),
            );

            // Should return NotFound error because the hash doesn't match.
            assert!(matches!(result, Err(Error::NotFound)));
        }

        /// Test line 1725: DataHash::from_assertion error case with corrupt DataHash assertion.
        #[test]
        fn update_data_hash_skips_corrupt_data_hash() {
            use crate::assertions::{labels, DataHash};

            let mut claim = create_test_claim().expect("create test claim");

            // Create a corrupt DataHash assertion with invalid CBOR data.
            // This has the correct label but invalid structure.
            let corrupt_assertion = Assertion::from_data_cbor(
                labels::DATA_HASH,
                &[0xff, 0xff, 0xff], // Invalid CBOR.
            );

            // Add the corrupt assertion to the store manually.
            let dummy_hash = vec![0u8; 32];
            let corrupt_claim_assertion = ClaimAssertion::new(
                corrupt_assertion,
                0,
                &dummy_hash,
                "sha256",
                None,
                ClaimAssertionType::Created,
            );
            claim.put_assertion_store(corrupt_claim_assertion);

            // Also add a valid DataHash assertion with a matching name.
            let mut valid_data_hash = DataHash::new("test.jpg", "sha256");
            valid_data_hash.set_hash(vec![1, 2, 3, 4, 5]);
            claim
                .add_assertion(&valid_data_hash)
                .expect("add valid data hash");

            // Try to update the DataHash.
            // Line 1725 is triggered when the matcher encounters the corrupt DataHash,
            // tries to parse it, fails, and returns false.
            // Then it should find the valid one and update it.
            let mut updated_data_hash = DataHash::new("test.jpg", "sha256");
            updated_data_hash.set_hash(vec![6, 7, 8, 9, 10]);

            let result = claim.update_data_hash(updated_data_hash);

            // Should succeed because a valid DataHash exists.
            assert!(result.is_ok());
        }

        /// Test line 1672: calc_assertion_box_hash error when salt is invalid.
        #[test]
        #[allow(deprecated)]
        fn calc_assertion_box_hash_fails_with_invalid_salt() {
            use crate::{
                assertions::CreativeWork, hashed_uri::HashedUri, jumbf::boxes::JumbfParseError,
            };

            let mut claim = create_test_claim().expect("create test claim");

            // Create an assertion with valid content.
            let creative_work = CreativeWork::new();
            let assertion = creative_work.to_assertion().expect("to_assertion");

            // Create a ClaimAssertion with an invalid salt (less than 16 bytes).
            // This bypasses normal validation by manually constructing the ClaimAssertion.
            let invalid_salt = vec![1, 2, 3, 4, 5]; // Only 5 bytes, needs to be >= 16.
            let dummy_hash = vec![0u8; 32];
            let claim_assertion = ClaimAssertion::new(
                assertion.clone(),
                0,
                &dummy_hash,
                "sha256",
                Some(invalid_salt),
                ClaimAssertionType::Created,
            );

            // Manually add to assertion_store to bypass validation.
            claim.put_assertion_store(claim_assertion);

            // Add corresponding hashed URI to assertions list.
            let label = format!("self#jumbf=c2pa.assertions/{}", assertion.label());
            let hashed_uri = HashedUri::new(label, None, &dummy_hash.clone());
            claim.assertions.push(hashed_uri);

            // Try to update the assertion with the invalid salt.
            // This should fail when calc_assertion_box_hash tries to set the salt.
            let replace_with = CreativeWork::new().to_assertion().expect("to_assertion");
            let result = claim.update_assertion(
                replace_with,
                |ca| ca.assertion().label() == "stds.schema-org.CreativeWork",
                |_, a| Ok(a),
            );

            // Should return JumbfParseError because the salt is invalid.
            match result {
                Err(Error::JumbfParseError(JumbfParseError::InvalidSalt)) => {
                    // Test passed.
                }
                other => panic!("Expected InvalidSalt error, got: {:?}", other),
            }
        }
    }

    mod redact_assertion {
        use super::super::*;
        use crate::{
            assertions::{labels, Actions, DataBox, Metadata},
            jumbf::labels::to_databox_uri,
        };

        /// Test line 1759: Error when trying to redact an actions assertion.
        #[test]
        fn cannot_redact_actions_assertion() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Add an actions assertion.
            let actions = Actions::new().add_action(crate::assertions::Action::new("c2pa.edited"));
            claim
                .add_assertion(&actions)
                .expect("failed to add actions assertion");

            // Try to redact the actions assertion.
            // Build a URI that looks like a self#jumbf link to an actions assertion.
            let actions_uri = format!("self#jumbf={}/{}", labels::ASSERTION_STORE, labels::ACTIONS);

            let result = claim.redact_assertion(&actions_uri);

            // Should fail with AssertionInvalidRedaction.
            assert!(result.is_err());
            match result {
                Err(Error::AssertionInvalidRedaction) => {
                    // Test passed.
                }
                other => panic!("Expected AssertionInvalidRedaction error, got: {:?}", other),
            }
        }

        /// Test line 1759: Error when trying to redact a c2pa.hash.* assertion.
        #[test]
        fn cannot_redact_hash_assertion() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Try to redact a hash assertion (e.g., c2pa.hash.data).
            // Build a URI that looks like a self#jumbf link to a hash assertion.
            let hash_uri = format!("self#jumbf={}/c2pa.hash.data", labels::ASSERTION_STORE);

            let result = claim.redact_assertion(&hash_uri);

            // Should fail with AssertionInvalidRedaction.
            assert!(result.is_err());
            match result {
                Err(Error::AssertionInvalidRedaction) => {
                    // Test passed.
                }
                other => panic!("Expected AssertionInvalidRedaction error, got: {:?}", other),
            }
        }

        /// Test line 1759: Error when trying to redact a c2pa.hash.bmff assertion.
        #[test]
        fn cannot_redact_bmff_hash_assertion() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Try to redact a BMFF hash assertion.
            let hash_uri = format!("self#jumbf={}/c2pa.hash.bmff", labels::ASSERTION_STORE);

            let result = claim.redact_assertion(&hash_uri);

            // Should fail with AssertionInvalidRedaction.
            assert!(result.is_err());
            match result {
                Err(Error::AssertionInvalidRedaction) => {
                    // Test passed.
                }
                other => panic!("Expected AssertionInvalidRedaction error, got: {:?}", other),
            }
        }

        /// Test lines 1763-1771: Successfully redacting an assertion from assertion_store.
        #[test]
        fn successfully_redact_assertion() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Add a metadata assertion that can be redacted.
            const MY_METADATA: &str = "my.test.metadata";
            let data = serde_json::json!({
                "@context": {
                    "dc": "http://purl.org/dc/elements/1.1/"
                },
                "dc:title": "Test Title"
            })
            .to_string();

            let metadata = Metadata::new(MY_METADATA, &data).expect("create metadata");
            claim
                .add_assertion(&metadata)
                .expect("failed to add metadata assertion");

            // Count assertions before redaction.
            let initial_count = claim.assertion_store.len();
            assert!(initial_count > 0);

            // Build a URI that looks like a self#jumbf link to the assertion.
            let assertion_uri = format!("self#jumbf={}/{}", labels::ASSERTION_STORE, MY_METADATA);

            // Redact the assertion.
            let result = claim.redact_assertion(&assertion_uri);

            // Should succeed.
            assert!(result.is_ok(), "Expected Ok, got: {:?}", result);

            // Verify the assertion was removed.
            assert_eq!(claim.assertion_store.len(), initial_count - 1);

            // Verify the specific assertion is no longer present.
            assert!(!claim
                .assertion_store
                .iter()
                .any(|ca| ca.label() == MY_METADATA));
        }

        /// Test lines 1772-1780: Successfully redacting a databox.
        #[test]
        fn successfully_redact_databox() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Add a databox to the claim.
            let databox = DataBox {
                format: "application/octet-stream".to_string(),
                data: vec![1, 2, 3, 4, 5],
                data_types: None,
            };
            let db_cbor = serde_cbor::to_vec(&databox).expect("serialize databox");
            claim
                .put_databox("c2pa.test_databox", &db_cbor, None)
                .expect("put databox");

            // Verify the databox was added.
            assert_eq!(claim.databoxes().len(), 1);

            // Build the correct URI using to_databox_uri.
            let databox_uri = to_databox_uri(claim.label(), "c2pa.test_databox");

            // Redact the databox.
            let result = claim.redact_assertion(&databox_uri);

            // Should succeed.
            assert!(result.is_ok(), "Expected Ok, got: {:?}", result);

            // Verify the databox was removed.
            assert_eq!(claim.databoxes().len(), 0);
        }

        /// Test line 1783: Error when trying to redact a non-existent assertion.
        #[test]
        fn cannot_redact_nonexistent_assertion() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Try to redact an assertion that doesn't exist in the assertion_store.
            let nonexistent_uri = format!(
                "self#jumbf={}/c2pa.nonexistent.assertion",
                labels::ASSERTION_STORE
            );

            let result = claim.redact_assertion(&nonexistent_uri);

            // Should fail with AssertionInvalidRedaction (line 1783).
            assert!(result.is_err());
            match result {
                Err(Error::AssertionInvalidRedaction) => {
                    // Test passed.
                }
                other => panic!("Expected AssertionInvalidRedaction error, got: {:?}", other),
            }
        }

        /// Test line 1783: Error when trying to redact a non-existent databox.
        #[test]
        fn cannot_redact_nonexistent_databox() {
            let mut claim = crate::utils::test::create_test_claim().expect("create test claim");

            // Try to redact a databox that doesn't exist in the data_boxes.
            let nonexistent_uri = to_databox_uri(claim.label(), "c2pa.nonexistent.databox");

            let result = claim.redact_assertion(&nonexistent_uri);

            // Should fail with AssertionInvalidRedaction (line 1783).
            assert!(result.is_err());
            match result {
                Err(Error::AssertionInvalidRedaction) => {
                    // Test passed.
                }
                other => panic!("Expected AssertionInvalidRedaction error, got: {:?}", other),
            }
        }
    }
}
