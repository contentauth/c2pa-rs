// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing, this software
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
// OF ANY KIND, either express or implied. See the LICENSE-MIT and
// LICENSE-APACHE files for the specific language governing permissions and
// limitations under each license.

//! crJSON format exporter for C2PA manifests.
//!
//! This module converts a [`Reader`]'s manifest store into crJSON format
//! as described in the crJSON specification.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::{
    assertion::{AssertionBase, AssertionData},
    assertions::Ingredient,
    claim::Claim,
    crypto::{
        base64,
        cose::{
            cert_chain_from_sign1, parse_cose_sign1, signing_alg_from_sign1,
            signing_time_from_sign1, timestamp_token_bytes_from_sign1,
        },
        time_stamp::tsa_signer_cert_der_from_token,
    },
    error::{Error, Result},
    jumbf::labels::{manifest_label_from_uri, to_absolute_uri, to_assertion_uri},
    reader::Reader,
    status_tracker::StatusTracker,
    validation_results::{IngredientDeltaValidationResult, StatusCodes},
    validation_status::ValidationStatus,
};

// ── Constants ───────────────────────────────────────────────────────────────

/// Version of the crJSON specification implemented by this exporter.
const CRJSON_SPEC_VERSION: &str = "2.3.0";

// ── Output types ────────────────────────────────────────────────────────────

/// A `Vec<u8>` that always serializes as a `b64'`-prefixed base64 string.
struct Base64Bytes(Vec<u8>);

impl Serialize for Base64Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&format!("b64'{}", base64::encode(&self.0)))
    }
}

/// A `hashedURIMap` as defined in the crJSON specification: `{ url, hash, alg? }`.
#[derive(Serialize)]
struct HashedUriMap {
    url: String,
    hash: Base64Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
}

/// Validity period for a certificate.
#[derive(Serialize)]
struct CrJsonValidity {
    #[serde(rename = "notBefore")]
    not_before: String,
    #[serde(rename = "notAfter")]
    not_after: String,
}

/// Certificate details within a `signature` or `timeStampInfo` object.
#[derive(Serialize, Default)]
struct CrJsonCertInfo {
    #[serde(rename = "serialNumber", skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validity: Option<CrJsonValidity>,
}

/// Timestamp authority info embedded in a manifest signature.
#[derive(Serialize)]
struct CrJsonTimestampInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(rename = "certificateInfo", skip_serializing_if = "Option::is_none")]
    certificate_info: Option<CrJsonCertInfo>,
}

/// The crJSON `signature` object for a manifest.
#[derive(Serialize, Default)]
struct CrJsonSignature {
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    #[serde(rename = "certificateInfo", skip_serializing_if = "Option::is_none")]
    certificate_info: Option<CrJsonCertInfo>,
    #[serde(rename = "timeStampInfo", skip_serializing_if = "Option::is_none")]
    time_stamp_info: Option<CrJsonTimestampInfo>,
}

/// Validation results for a single manifest entry.
#[derive(Serialize)]
struct ManifestValidationResults {
    success: Vec<ValidationStatus>,
    informational: Vec<ValidationStatus>,
    failure: Vec<ValidationStatus>,
    #[serde(rename = "specVersion")]
    spec_version: &'static str,
    #[serde(rename = "validationTime")]
    validation_time: String,
}

/// A C2PA claim — shared struct for both v1 and v2 format.
///
/// Fields that only apply to one version are wrapped in `Option` and omitted when absent.
/// The parent `CrJsonManifest` places this under the `"claim"` key for v1 and `"claim.v2"` for v2.
#[derive(Serialize)]
struct CrJsonClaim {
    // ── Present in both versions ──────────────────────────────────────────
    #[serde(rename = "instanceID")]
    instance_id: String,
    /// JUMBF URI reference to the claim's COSE signature assertion.
    signature: String,
    claim_generator_info: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg_soft: Option<String>,
    #[serde(rename = "dc:title", skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(
        rename = "redacted_assertions",
        skip_serializing_if = "Option::is_none"
    )]
    redacted_assertions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,

    // ── V1 only ───────────────────────────────────────────────────────────
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_generator: Option<String>,
    #[serde(rename = "dc:format", skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    /// V1 assertion references — all assertions as a single hashed-URI array.
    #[serde(skip_serializing_if = "Option::is_none")]
    assertions: Option<Vec<HashedUriMap>>,

    // ── V2 only ───────────────────────────────────────────────────────────
    #[serde(rename = "created_assertions", skip_serializing_if = "Option::is_none")]
    created_assertions: Option<Vec<HashedUriMap>>,
    #[serde(
        rename = "gathered_assertions",
        skip_serializing_if = "Option::is_none"
    )]
    gathered_assertions: Option<Vec<HashedUriMap>>,
}

/// A single entry in the crJSON `manifests` array.
#[derive(Serialize)]
struct CrJsonManifest {
    label: String,
    /// Assertions map: `label -> assertion value`. Keys may include instance suffixes
    /// such as `c2pa.actions__2`.
    assertions: Map<String, Value>,
    /// Present only for v1 claims.
    #[serde(rename = "claim", skip_serializing_if = "Option::is_none")]
    claim_v1: Option<CrJsonClaim>,
    /// Present only for v2 claims.
    #[serde(rename = "claim.v2", skip_serializing_if = "Option::is_none")]
    claim_v2: Option<CrJsonClaim>,
    signature: CrJsonSignature,
    #[serde(rename = "validationResults")]
    validation_results: ManifestValidationResults,
    #[serde(rename = "ingredientDeltas", skip_serializing_if = "Option::is_none")]
    ingredient_deltas: Option<Vec<IngredientDeltaValidationResult>>,
}

/// crJSON generator identification block.
#[derive(Serialize)]
struct JsonGenerator {
    name: &'static str,
    version: &'static str,
}

/// The top-level crJSON document.
#[derive(Serialize)]
struct CrJsonDocument {
    #[serde(rename = "@context")]
    context: Value,
    manifests: Vec<CrJsonManifest>,
    #[serde(rename = "jsonGenerator")]
    json_generator: JsonGenerator,
}

// ── Public entry point ──────────────────────────────────────────────────────

/// Convert a Reader's manifest store to crJSON format.
pub fn from_reader(reader: &Reader) -> Result<Value> {
    CrJsonExporter::new(reader).to_value()
}

// ── Exporter ────────────────────────────────────────────────────────────────

struct CrJsonExporter<'a> {
    reader: &'a Reader,
}

impl<'a> CrJsonExporter<'a> {
    fn new(reader: &'a Reader) -> Self {
        Self { reader }
    }

    fn to_value(&self) -> Result<Value> {
        let doc = self.build_document()?;
        serde_json::to_value(doc).map_err(Error::JsonError)
    }

    fn build_document(&self) -> Result<CrJsonDocument> {
        let active_label = self.reader.active_label();
        let validation_map = self.build_validation_results_per_manifest();
        let claims = self.reader.store.claims();

        // Collect (store_index, manifest) so we can sort afterwards.
        let mut indexed: Vec<(usize, CrJsonManifest)> = Vec::with_capacity(claims.len());
        for (idx, claim) in claims.iter().enumerate() {
            indexed.push((idx, self.build_manifest(claim, &validation_map)?));
        }

        // Active manifest first; all others in reverse store order (newest first).
        indexed.sort_by(|(a_idx, _), (b_idx, _)| {
            let a_active = active_label.is_some_and(|l| l == claims[*a_idx].label());
            let b_active = active_label.is_some_and(|l| l == claims[*b_idx].label());
            match (a_active, b_active) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b_idx.cmp(a_idx),
            }
        });

        Ok(CrJsonDocument {
            context: json!({
                "@vocab": "https://contentcredentials.org/crjson",
                "extras": "https://contentcredentials.org/crjson/extras"
            }),
            manifests: indexed.into_iter().map(|(_, m)| m).collect(),
            json_generator: JsonGenerator {
                name: "c2pa-rs",
                version: env!("CARGO_PKG_VERSION"),
            },
        })
    }

    fn build_manifest(
        &self,
        claim: &Claim,
        validation_map: &HashMap<String, (StatusCodes, String)>,
    ) -> Result<CrJsonManifest> {
        let label = claim.label();
        let assertions = self.build_assertions(claim)?;
        let claim_obj = self.build_claim(claim)?;
        let signature = self.build_signature(claim)?;
        let validation_results = build_manifest_validation_results(label, validation_map);
        let ingredient_deltas = self.build_manifest_ingredient_deltas(label);

        let (claim_v1, claim_v2) = if claim.version() == 1 {
            (Some(claim_obj), None)
        } else {
            (None, Some(claim_obj))
        };

        Ok(CrJsonManifest {
            label: label.to_string(),
            assertions,
            claim_v1,
            claim_v2,
            signature,
            validation_results,
            ingredient_deltas,
        })
    }

    fn build_claim(&self, claim: &Claim) -> Result<CrJsonClaim> {
        let is_v1 = claim.version() == 1;
        let claim_generator_info = build_claim_generator_info(claim, is_v1);
        let (assertions, created_assertions, gathered_assertions) = build_assertion_refs(claim);

        Ok(CrJsonClaim {
            instance_id: claim.instance_id().to_string(),
            signature: format!("self#jumbf=/c2pa/{}/c2pa.signature", claim.label()),
            claim_generator_info,
            alg: Some(claim.alg().to_string()),
            alg_soft: claim.alg_soft().map(|s| s.to_string()),
            title: claim.title().map(|s| s.to_string()),
            redacted_assertions: claim.redactions().and_then(|r| {
                if r.is_empty() {
                    None
                } else {
                    Some(r.to_vec())
                }
            }),
            metadata: claim.metadata().and_then(|m| {
                if m.is_empty() {
                    None
                } else {
                    serde_json::to_value(m).ok()
                }
            }),
            claim_generator: if is_v1 {
                claim.claim_generator().map(|s| s.to_string())
            } else {
                None
            },
            format: if is_v1 {
                Some(claim.format().unwrap_or("").to_string())
            } else {
                None
            },
            assertions: if is_v1 { Some(assertions) } else { None },
            created_assertions: if !is_v1 {
                Some(created_assertions)
            } else {
                None
            },
            gathered_assertions: if !is_v1 {
                Some(gathered_assertions)
            } else {
                None
            },
        })
    }

    // ── Assertions ──────────────────────────────────────────────────────────

    fn build_assertions(&self, claim: &Claim) -> Result<Map<String, Value>> {
        let manifest_label = claim.label();
        let mut assertions_obj = Map::new();

        // Single pass over all physically stored assertions in this claim's JUMBF.
        // ClaimAssertion::label() already encodes the instance suffix as `base__N`.
        for ca in claim.claim_assertion_store() {
            let key = ca.label();
            if assertions_obj.contains_key(&key) {
                continue;
            }
            if let Some(value) = self.claim_assertion_to_value(manifest_label, ca)? {
                assertions_obj.insert(key, value);
            }
        }

        // V2 gathered assertions may reference assertions stored in OTHER claims.
        // Try to resolve them from the source claim; fall back to a reference object.
        if let Some(gathered) = claim.gathered_assertions() {
            for assertion_ref in gathered {
                let (label, instance) = Claim::assertion_label_from_link(&assertion_ref.url());
                let key = Claim::label_with_instance(&label, instance);
                if assertions_obj.contains_key(&key) {
                    continue;
                }
                let resolved = manifest_label_from_uri(&assertion_ref.url())
                    .and_then(|src_label| self.reader.store.get_claim(&src_label))
                    .and_then(|src_claim| {
                        src_claim
                            .get_claim_assertion(&label, instance)
                            .and_then(|src_ca| {
                                self.claim_assertion_to_value(manifest_label, src_ca)
                                    .ok()
                                    .flatten()
                            })
                    });

                if let Some(value) = resolved {
                    assertions_obj.insert(key, value);
                } else {
                    let absolute_uri = to_absolute_uri(manifest_label, &assertion_ref.url());
                    assertions_obj.insert(
                        key,
                        json!({
                            "identifier": absolute_uri,
                            "hash": format!("b64'{}", base64::encode(&assertion_ref.hash()))
                        }),
                    );
                }
            }
        }

        Ok(assertions_obj)
    }

    /// Serialize a single [`ClaimAssertion`] into a crJSON value.
    ///
    /// * Ingredient assertions use the internal [`assertions::Ingredient`] custom serializer,
    ///   which emits Dublin-Core field names (`dc:title`, `dc:format`, …).
    /// * Binary / UUID assertions emit the reference-object form `{format, identifier, hash}`.
    /// * Everything else is decoded via [`Assertion::as_json_object`] and passed through
    ///   [`fix_hash_encoding`] to convert byte arrays to base64.
    fn claim_assertion_to_value(
        &self,
        manifest_label: &str,
        ca: &crate::claim::ClaimAssertion,
    ) -> Result<Option<Value>> {
        use crate::assertions::labels as assertion_labels;

        let assertion = ca.assertion();

        if ca.label_raw().starts_with(assertion_labels::INGREDIENT) {
            return match Ingredient::from_assertion(assertion) {
                Ok(ingredient) => {
                    let v = serde_json::to_value(&ingredient).map_err(Error::JsonError)?;
                    Ok(Some(fix_hash_encoding(v)))
                }
                Err(_) => Ok(None),
            };
        }

        match assertion.decode_data() {
            AssertionData::Binary(_) | AssertionData::Uuid(_, _) => {
                let absolute_uri = to_assertion_uri(manifest_label, &ca.label());
                Ok(Some(json!({
                    "format": assertion.content_type(),
                    "identifier": absolute_uri,
                    "hash": format!("b64'{}", base64::encode(ca.hash()))
                })))
            }
            _ => Ok(assertion.as_json_object().ok().map(fix_hash_encoding)),
        }
    }

    // ── Signature ───────────────────────────────────────────────────────────

    /// Build the crJSON `signature` object by parsing the claim's COSE Sign1 bytes directly.
    fn build_signature(&self, claim: &Claim) -> Result<CrJsonSignature> {
        let sig_bytes = claim.signature_val();
        if sig_bytes.is_empty() {
            return Ok(CrJsonSignature::default());
        }
        let data = match claim.data() {
            Ok(d) => d,
            Err(_) => return Ok(CrJsonSignature::default()),
        };

        let mut log = StatusTracker::default();
        let sign1 = match parse_cose_sign1(sig_bytes, data.as_ref(), &mut log) {
            Ok(s) => s,
            Err(_) => return Ok(CrJsonSignature::default()),
        };

        let algorithm = signing_alg_from_sign1(&sign1).map(|a| a.to_string()).ok();

        let certificate_info = cert_chain_from_sign1(&sign1).ok().and_then(|chain| {
            chain
                .first()
                .and_then(|der| parse_certificate_from_der(der).ok().flatten())
        });

        let ts_time = signing_time_from_sign1(&sign1, data.as_ref(), false).map(|t| t.to_rfc3339());

        let tsa_cert_info = timestamp_token_bytes_from_sign1(&sign1).and_then(|token_bytes| {
            tsa_signer_cert_der_from_token(&token_bytes)
                .ok()
                .flatten()
                .and_then(|tsa_der| parse_certificate_from_der(&tsa_der).ok().flatten())
        });

        let time_stamp_info = if ts_time.is_some() || tsa_cert_info.is_some() {
            Some(CrJsonTimestampInfo {
                timestamp: ts_time,
                certificate_info: tsa_cert_info,
            })
        } else {
            None
        };

        Ok(CrJsonSignature {
            algorithm,
            certificate_info,
            time_stamp_info,
        })
    }

    // ── Validation ──────────────────────────────────────────────────────────

    /// Build a map from each manifest label to its (StatusCodes, validation_time).
    ///
    /// `validation_time` falls back to the current UTC time when the reader supplies none.
    fn build_validation_results_per_manifest(&self) -> HashMap<String, (StatusCodes, String)> {
        let mut map: HashMap<String, (StatusCodes, String)> = HashMap::new();
        let Some(vr) = self.reader.validation_results() else {
            return map;
        };
        let validation_time = vr
            .validation_time()
            .map(String::from)
            .unwrap_or_else(|| Utc::now().to_rfc3339());

        if let Some(active_label) = self.reader.active_label() {
            let codes = vr.active_manifest().cloned().unwrap_or_default();
            map.insert(active_label.to_string(), (codes, validation_time.clone()));
        }

        let Some(deltas) = vr.ingredient_deltas() else {
            return map;
        };
        for idv in deltas {
            let Some(target_label) =
                self.ingredient_assertion_uri_to_manifest_label(idv.ingredient_assertion_uri())
            else {
                continue;
            };
            let codes = idv.validation_deltas().clone();
            map.insert(target_label, (codes, validation_time.clone()));
        }
        map
    }

    fn ingredient_assertion_uri_to_manifest_label(&self, assertion_uri: &str) -> Option<String> {
        let parent_label = manifest_label_from_uri(assertion_uri)?;
        let claim = self.reader.store.get_claim(&parent_label)?;
        for ing_ref in claim.ingredient_assertions() {
            let build_uri = to_assertion_uri(claim.label(), ing_ref.label().as_str());
            if build_uri == assertion_uri
                || to_absolute_uri(&parent_label, &build_uri) == assertion_uri
            {
                let ingredient = Ingredient::from_assertion(ing_ref.assertion()).ok()?;
                let hashed = ingredient.c2pa_manifest()?;
                return manifest_label_from_uri(&hashed.url());
            }
        }
        None
    }

    fn build_manifest_ingredient_deltas(
        &self,
        label: &str,
    ) -> Option<Vec<IngredientDeltaValidationResult>> {
        let validation_results = self.reader.validation_results()?;
        let deltas = validation_results.ingredient_deltas()?;
        let for_manifest: Vec<IngredientDeltaValidationResult> = deltas
            .iter()
            .filter(|idv| {
                manifest_label_from_uri(idv.ingredient_assertion_uri()).as_deref() == Some(label)
            })
            .cloned()
            .collect();
        if for_manifest.is_empty() {
            None
        } else {
            Some(for_manifest)
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Serialize claim generator info into the crJSON shape: an array for v1, a single object for v2.
/// `fix_hash_encoding` is applied to convert the icon hash from a byte array to base64.
fn build_claim_generator_info(claim: &Claim, is_v1: bool) -> Value {
    let to_value = |info| {
        serde_json::to_value(info)
            .map(fix_hash_encoding)
            .unwrap_or_else(|_| json!({}))
    };

    if let Some(info_slice) = claim.claim_generator_info() {
        if is_v1 {
            let agents: Vec<Value> = info_slice.iter().map(to_value).collect();
            if !agents.is_empty() {
                return Value::Array(agents);
            }
        } else if let Some(first) = info_slice.first() {
            return to_value(first);
        }
    }

    let fallback = json!({ "name": claim.claim_generator().unwrap_or("Unknown") });
    if is_v1 {
        json!([fallback])
    } else {
        fallback
    }
}

/// Build the three assertion-reference lists for a claim.
///
/// Returns `(v1_assertions, created_assertions, gathered_assertions)`.
/// For v1 claims only the first list is populated; for v2 only the latter two.
fn build_assertion_refs(
    claim: &Claim,
) -> (Vec<HashedUriMap>, Vec<HashedUriMap>, Vec<HashedUriMap>) {
    let label = claim.label();
    if claim.version() == 1 {
        let v1 = claim
            .assertions()
            .iter()
            .map(|r| HashedUriMap {
                url: to_absolute_uri(label, &r.url()),
                hash: Base64Bytes(r.hash()),
                alg: r.alg(),
            })
            .collect();
        return (v1, Vec::new(), Vec::new());
    }

    let created = claim
        .created_assertions()
        .iter()
        .map(|r| HashedUriMap {
            url: r.url(),
            hash: Base64Bytes(r.hash()),
            alg: r.alg(),
        })
        .collect();

    let gathered = claim
        .gathered_assertions()
        .iter()
        .flat_map(|g| g.iter())
        .map(|r| HashedUriMap {
            url: r.url(),
            hash: Base64Bytes(r.hash()),
            alg: r.alg(),
        })
        .collect();

    (Vec::new(), created, gathered)
}

fn build_manifest_validation_results(
    label: &str,
    validation_map: &HashMap<String, (StatusCodes, String)>,
) -> ManifestValidationResults {
    let (codes, validation_time) = validation_map
        .get(label)
        .cloned()
        .unwrap_or_else(|| (StatusCodes::default(), Utc::now().to_rfc3339()));
    ManifestValidationResults {
        success: codes.success().clone(),
        informational: codes.informational().clone(),
        failure: codes.failure().clone(),
        spec_version: CRJSON_SPEC_VERSION,
        validation_time,
    }
}

/// Normalize byte-array hash/pad/signature fields to base64 strings after CBOR→JSON decoding.
///
/// This is applied to assertion values obtained via [`Assertion::as_json_object`] and to
/// ingredient assertions serialized via the internal [`Ingredient`] type.
/// All other output paths use typed structs with [`Base64Bytes`] serialization.
fn fix_hash_encoding(value: Value) -> Value {
    match value {
        Value::Object(mut map) => {
            // Canonicalize the legacy CBOR key for operating_system used in some claim generators.
            const SCHEMA_ORG_OS_KEY: &str = "schema.org.SoftwareApplication.operatingSystem";
            if let Some(os_value) = map.remove(SCHEMA_ORG_OS_KEY) {
                if !map.contains_key("operating_system") {
                    map.insert("operating_system".to_string(), os_value);
                }
            }

            for field in &["hash", "pad", "pad2"] {
                if let Some(arr_val) = map.get(*field) {
                    if let Some(arr) = arr_val.as_array() {
                        if arr.iter().all(|v| v.is_u64() || v.is_i64()) {
                            let bytes: Vec<u8> = arr
                                .iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect();
                            map.insert(
                                field.to_string(),
                                json!(format!("b64'{}", base64::encode(&bytes))),
                            );
                        }
                    }
                }
            }

            // Ensure hash-bearing objects also carry a (possibly empty) pad field.
            if map.contains_key("hash") && !map.contains_key("pad") {
                map.insert("pad".to_string(), json!("b64'"));
            }

            if let Some(sig_val) = map.get("signature") {
                if let Some(sig_arr) = sig_val.as_array() {
                    if sig_arr.iter().all(|v| v.is_u64() || v.is_i64()) {
                        let sig_bytes: Vec<u8> = sig_arr
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        let decoded = decode_cawg_signature(&sig_bytes).unwrap_or_else(|_| {
                            json!(format!("b64'{}", base64::encode(&sig_bytes)))
                        });
                        map.insert("signature".to_string(), decoded);
                    }
                }
            }

            // Recurse into nested objects/arrays.
            for val in map.values_mut() {
                *val = fix_hash_encoding(val.clone());
            }

            // Normalize icon fields inside assertion values (e.g. softwareAgent in actions).
            if let Some(icon_val) = map.get_mut("icon") {
                if let Some(icon_obj) = icon_val.as_object_mut() {
                    if !icon_obj.contains_key("url") {
                        if let Some(id_str) = icon_obj
                            .get("identifier")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                        {
                            icon_obj.insert("url".to_string(), json!(id_str));
                        }
                    }
                    icon_obj.retain(|k, _| matches!(k.as_str(), "url" | "hash" | "alg"));
                }
            }

            Value::Object(map)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(fix_hash_encoding).collect()),
        other => other,
    }
}

// ── Certificate parsing ─────────────────────────────────────────────────────

fn parse_certificate_from_der(der: &[u8]) -> Result<Option<CrJsonCertInfo>> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_e| Error::CoseInvalidCert)?;
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    let not_before_chrono: DateTime<Utc> =
        DateTime::from_timestamp(not_before.unix_timestamp(), 0).ok_or(Error::CoseInvalidCert)?;
    let not_after_chrono: DateTime<Utc> =
        DateTime::from_timestamp(not_after.unix_timestamp(), 0).ok_or(Error::CoseInvalidCert)?;
    Ok(Some(CrJsonCertInfo {
        serial_number: Some(format!("{:x}", cert.serial)),
        issuer: Some(extract_dn_components(cert.issuer())?),
        subject: Some(extract_dn_components(cert.subject())?),
        validity: Some(CrJsonValidity {
            not_before: not_before_chrono.to_rfc3339(),
            not_after: not_after_chrono.to_rfc3339(),
        }),
    }))
}

fn extract_dn_components(name: &x509_parser::x509::X509Name) -> Result<Map<String, Value>> {
    let mut components = Map::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid = attr.attr_type();
            let value = attr.as_str().map_err(|_| Error::CoseInvalidCert)?;
            let key = match oid.to_string().as_str() {
                "2.5.4.6" => "C",
                "2.5.4.8" => "ST",
                "2.5.4.7" => "L",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "2.5.4.3" => "CN",
                _ => continue,
            };
            components.insert(key.to_string(), json!(value));
        }
    }
    Ok(components)
}

fn decode_cawg_signature(signature_bytes: &[u8]) -> Result<Value> {
    use coset::{CoseSign1, TaggedCborSerializable};

    use crate::crypto::cose::{cert_chain_from_sign1, signing_alg_from_sign1};

    let sign1 = <CoseSign1 as TaggedCborSerializable>::from_tagged_slice(signature_bytes)
        .map_err(|_| Error::CoseSignature)?;

    let mut signature_obj = Map::new();

    if let Ok(alg) = signing_alg_from_sign1(&sign1) {
        signature_obj.insert("algorithm".to_string(), json!(alg.to_string()));
    }

    if let Ok(cert_chain) = cert_chain_from_sign1(&sign1) {
        if let Some(cert_info) = cert_chain
            .first()
            .and_then(|der| parse_certificate_from_der(der).ok().flatten())
        {
            if let Ok(v) = serde_json::to_value(cert_info) {
                signature_obj.insert("certificateInfo".to_string(), v);
            }
        }
    }

    if !signature_obj.contains_key("certificateInfo") {
        if let Some(payload) = sign1.payload.as_ref() {
            if let Ok(vc_value) = serde_json::from_slice::<Value>(payload) {
                if let Some(issuer) = vc_value.get("issuer") {
                    signature_obj.insert("issuer".to_string(), issuer.clone());
                }
                if let Some(valid_from) = vc_value.get("validFrom") {
                    signature_obj.insert("validFrom".to_string(), valid_from.clone());
                }
                if let Some(valid_until) = vc_value.get("validUntil") {
                    signature_obj.insert("validUntil".to_string(), valid_until.clone());
                }
                if let Some(cred_subject) = vc_value.get("credentialSubject") {
                    if let Some(verified_ids) = cred_subject.get("verifiedIdentities") {
                        signature_obj
                            .insert("verifiedIdentities".to_string(), verified_ids.clone());
                    }
                }
                signature_obj.insert(
                    "credentialType".to_string(),
                    json!("IdentityClaimsAggregation"),
                );
            }
        }
    }

    Ok(Value::Object(signature_obj))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{reader::Reader, validation_results::ValidationState};

    const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");

    #[test]
    fn test_jpeg_trust_reader_from_stream() -> Result<()> {
        let reader = Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_WITH_MANIFEST))?;

        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        Ok(())
    }

    #[test]
    fn test_jpeg_trust_format_json() -> Result<()> {
        let reader = Reader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_WITH_MANIFEST))?;

        let json_value = reader.to_crjson_value()?;

        // Verify required fields
        assert!(json_value.get("@context").is_some());
        assert!(json_value.get("manifests").is_some());
        assert!(
            json_value.get("jsonGenerator").is_some(),
            "jsonGenerator must be present"
        );

        // jsonGenerator is c2pa-rs (this library) with name and version
        let jg = &json_value["jsonGenerator"];
        assert_eq!(jg.get("name").and_then(|v| v.as_str()), Some("c2pa-rs"));
        assert!(
            jg.get("version").and_then(|v| v.as_str()).is_some(),
            "jsonGenerator.version required"
        );

        // Verify manifests is an array
        assert!(json_value["manifests"].is_array());

        // Verify first manifest structure (required: label, assertions, signature, validationResults; oneOf: claim or claim.v2)
        if let Some(manifest) = json_value["manifests"].as_array().and_then(|a| a.first()) {
            assert!(manifest.get("label").is_some());
            assert!(manifest.get("assertions").is_some());
            assert!(manifest.get("signature").is_some());
            assert!(manifest.get("validationResults").is_some());
            let has_claim = manifest.get("claim").is_some();
            let has_claim_v2 = manifest.get("claim.v2").is_some();
            assert!(
                has_claim != has_claim_v2,
                "manifest must have exactly one of claim (v1) or claim.v2"
            );

            // Verify assertions is an object (not array)
            assert!(manifest["assertions"].is_object());

            if let Some(claim_v2) = manifest.get("claim.v2") {
                assert!(claim_v2.get("instanceID").is_some());
                assert!(claim_v2.get("signature").is_some());
                assert!(claim_v2.get("created_assertions").is_some());
            } else if let Some(claim_v1) = manifest.get("claim") {
                assert!(claim_v1.get("claim_generator").is_some());
                assert!(claim_v1.get("claim_generator_info").is_some());
                assert!(claim_v1.get("signature").is_some());
                assert!(claim_v1.get("assertions").is_some());
                assert!(claim_v1.get("dc:format").is_some());
                assert!(claim_v1.get("instanceID").is_some());
            }
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_cr_json_reader_from_file() -> Result<()> {
        let reader = Reader::from_file("tests/fixtures/CA.jpg")?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);

        let json = reader.crjson();
        assert!(json.contains("@context"));
        assert!(json.contains("manifests"));

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_claim_signature_decoding() -> Result<()> {
        // Test that signature (manifest-level) is decoded with full certificate details
        let reader = Reader::from_file("tests/fixtures/CA.jpg")?;

        let json_value = reader.to_crjson_value()?;
        let manifests = json_value["manifests"].as_array().unwrap();
        // Every manifest has required "signature"; find one with decoded certificate details
        let manifest = manifests.iter().find(|m| {
            m.get("signature")
                .and_then(|s| s.get("algorithm"))
                .is_some()
        });
        assert!(
            manifest.is_some(),
            "Should have a manifest with signature containing algorithm"
        );

        let sig = &manifest.unwrap()["signature"];

        // Verify algorithm is present
        assert!(
            sig.get("algorithm").is_some(),
            "signature should have algorithm"
        );

        // Verify certificate details are decoded in certificateInfo (not just algorithm)
        let cert_info = sig.get("certificateInfo").and_then(|c| c.as_object());
        assert!(
            cert_info.is_some(),
            "signature should have certificateInfo from decoded certificate"
        );
        let cert_info = cert_info.unwrap();
        assert!(
            cert_info.get("serialNumber").is_some(),
            "certificateInfo should have serialNumber"
        );
        assert!(
            cert_info.get("issuer").is_some(),
            "certificateInfo should have issuer"
        );
        assert!(
            cert_info.get("subject").is_some(),
            "certificateInfo should have subject"
        );
        assert!(
            cert_info.get("validity").is_some(),
            "certificateInfo should have validity"
        );

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_cawg_identity_x509_signature_decoding() -> Result<()> {
        // Test that cawg.identity with X.509 signature is fully decoded
        let reader = Reader::from_file("tests/fixtures/C_with_CAWG_data.jpg")?;

        let json_value = reader.to_crjson_value()?;
        let manifests = json_value["manifests"].as_array().unwrap();

        // Find the manifest and its cawg.identity assertion
        let manifest = &manifests[0];
        let assertions = manifest["assertions"].as_object().unwrap();

        let cawg_identity = assertions.get("cawg.identity");
        assert!(
            cawg_identity.is_some(),
            "Should have cawg.identity assertion"
        );

        let cawg_identity = cawg_identity.unwrap();

        // Verify pad2 is a b64'-prefixed string if present (pad1 does not exist in the schema)
        if let Some(pad2) = cawg_identity.get("pad2").and_then(|v| v.as_str()) {
            assert!(
                pad2.starts_with("b64'"),
                "pad2 must start with \"b64'\" prefix, got: {pad2:?}"
            );
        }

        // Verify signature is decoded
        let signature = &cawg_identity["signature"];
        assert!(
            signature.is_object(),
            "signature should be an object, not an array"
        );

        // For X.509 signatures (sig_type: cawg.x509.cose), verify certificate details in certificateInfo
        let sig_type = cawg_identity["signer_payload"]["sig_type"]
            .as_str()
            .unwrap();
        if sig_type == "cawg.x509.cose" {
            assert!(
                signature.get("algorithm").is_some(),
                "signature should have algorithm"
            );
            let cert_info = signature.get("certificateInfo").and_then(|c| c.as_object());
            assert!(
                cert_info.is_some(),
                "X.509 signature should have certificateInfo"
            );
            let cert_info = cert_info.unwrap();
            assert!(
                cert_info.get("serialNumber").is_some(),
                "certificateInfo should have serialNumber"
            );
            assert!(
                cert_info.get("issuer").is_some(),
                "certificateInfo should have issuer DN components"
            );
            assert!(
                cert_info.get("subject").is_some(),
                "certificateInfo should have subject DN components"
            );
            assert!(
                cert_info.get("validity").is_some(),
                "certificateInfo should have validity period"
            );
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_cawg_identity_ica_signature_decoding() -> Result<()> {
        // Test that cawg.identity with ICA signature extracts VC information
        // Note: This test uses a fixture from the identity tests
        let test_image = include_bytes!(
            "identity/tests/fixtures/claim_aggregation/adobe_connected_identities.jpg"
        );

        let reader = Reader::from_stream("image/jpeg", std::io::Cursor::new(&test_image[..]))?;

        let json_value = reader.to_crjson_value()?;
        let manifests = json_value["manifests"].as_array().unwrap();

        // Find a manifest with cawg.identity assertion
        let manifest = manifests.iter().find(|m| {
            if let Some(assertions) = m.get("assertions").and_then(|a| a.as_object()) {
                assertions.keys().any(|k| k.starts_with("cawg.identity"))
            } else {
                false
            }
        });

        if let Some(manifest) = manifest {
            let assertions = manifest["assertions"].as_object().unwrap();
            let cawg_identity_key = assertions
                .keys()
                .find(|k| k.starts_with("cawg.identity"))
                .unwrap();
            let cawg_identity = &assertions[cawg_identity_key];

            // Verify pad2 is a b64'-prefixed string if present (pad1 does not exist in the schema)
            if let Some(pad2) = cawg_identity.get("pad2").and_then(|v| v.as_str()) {
                assert!(
                    pad2.starts_with("b64'"),
                    "pad2 must start with \"b64'\" prefix, got: {pad2:?}"
                );
            }

            // Verify signature is decoded
            let signature = &cawg_identity["signature"];
            assert!(signature.is_object(), "signature should be an object");

            // For ICA signatures (sig_type: cawg.identity_claims_aggregation),
            // verify VC information is extracted
            let sig_type = cawg_identity["signer_payload"]["sig_type"]
                .as_str()
                .unwrap();
            if sig_type == "cawg.identity_claims_aggregation" {
                assert!(
                    signature.get("algorithm").is_some(),
                    "ICA signature should have algorithm"
                );
                assert!(
                    signature.get("issuer").is_some(),
                    "ICA signature should have issuer (DID)"
                );

                // ICA signatures should have VC-specific fields
                // Note: Some of these may be optional depending on the VC
                let has_vc_info = signature.get("validFrom").is_some()
                    || signature.get("validUntil").is_some()
                    || signature.get("verifiedIdentities").is_some()
                    || signature.get("credentialType").is_some();

                assert!(
                    has_vc_info,
                    "ICA signature should have at least some VC information (validFrom, validUntil, verifiedIdentities, or credentialType)"
                );
            }
        }

        Ok(())
    }

    /// Test that claim_generator_info (including icon) is exported to claim.v2 when present.
    /// Uses an image produced by crTool with a claim generator icon.
    #[test]
    #[cfg(feature = "file_io")]
    fn test_claim_generator_info_with_icon_exported() -> Result<()> {
        use std::path::Path;

        let path = Path::new("/Users/lrosenth/Development/crTool/target/test_output/testset/p-actions-created-with-icon.jpg");
        if !path.exists() {
            eprintln!(
                "Skipping test_claim_generator_info_with_icon_exported: fixture not found at {:?}",
                path
            );
            return Ok(());
        }

        let reader = Reader::from_file(path)?;
        let json_value = reader.to_crjson_value()?;

        let manifests = json_value["manifests"]
            .as_array()
            .expect("manifests should be an array");
        let manifest = manifests
            .first()
            .expect("should have at least one manifest");

        let claim_block = manifest
            .get("claim.v2")
            .or_else(|| manifest.get("claim"))
            .expect("manifest should have claim or claim.v2");

        let claim_generator_info = claim_block
            .get("claim_generator_info")
            .expect("claim should include claim_generator_info when manifest has an icon");

        // claim.v2: single object; claim (v1): array — get first object for assertion
        let info_obj = claim_generator_info
            .as_object()
            .or_else(|| {
                claim_generator_info
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_object())
            })
            .expect("claim_generator_info should be an object or array of objects");

        // Icon must be hashedUriMap only (url, hash, optional alg) per schema; no format/identifier.
        let has_icon = match info_obj.get("icon") {
            Some(icon) => {
                icon.get("url").and_then(|v| v.as_str()).is_some()
                    && icon.get("hash").and_then(|v| v.as_str()).is_some()
            }
            None => false,
        };

        assert!(
            has_icon,
            "claim_generator_info should include icon as hashedUriMap (url, hash)"
        );

        Ok(())
    }
}
