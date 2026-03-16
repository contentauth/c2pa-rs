// Copyright 2024 Adobe. All rights reserved.
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

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use std::collections::HashMap;

use crate::{
    assertion::{AssertionBase, AssertionData},
    assertions::Ingredient,
    claim::Claim,
    crypto::{
        base64,
        cose::{parse_cose_sign1, timestamp_token_bytes_from_sign1},
        time_stamp::tsa_signer_cert_der_from_token,
    },
    error::{Error, Result},
    jumbf::labels::{manifest_label_from_uri, to_absolute_uri, to_assertion_uri},
    reader::Reader,
    status_tracker::StatusTracker,
    validation_results::StatusCodes,
    Manifest,
};

/// Convert a Reader's manifest store to crJSON format.
pub fn from_reader(reader: &Reader) -> Result<Value> {
    CrJsonExporter::new(reader).to_value()
}

struct CrJsonExporter<'a> {
    reader: &'a Reader,
}

impl<'a> CrJsonExporter<'a> {
    fn new(reader: &'a Reader) -> Self {
        Self { reader }
    }

    fn to_value(&self) -> Result<Value> {
        let mut result = json!({
            "@context": {
                "@vocab": "https://contentcredentials.org/crjson",
                "extras": "https://contentcredentials.org/crjson/extras"
            }
        });

        let manifests_array = self.convert_manifests_to_array()?;
        result["manifests"] = manifests_array;

        result["jsonGenerator"] = self.build_json_generator()?;

        Ok(result)
    }

    fn build_json_generator(&self) -> Result<Value> {
        Ok(json!({
            "name": "c2pa-rs",
            "version": env!("CARGO_PKG_VERSION"),
            "date": Utc::now().to_rfc3339()
        }))
    }

    fn convert_manifests_to_array(&self) -> Result<Value> {
        let active_label = self.reader.active_label();
        let validation_map = self.build_validation_results_per_manifest();
        let mut labeled: Vec<(String, Value)> = Vec::new();

        for (label, manifest) in self.reader.manifests().iter() {
            let mut manifest_obj = Map::new();
            manifest_obj.insert("label".to_string(), json!(label));

            let assertions_obj = self.convert_assertions(manifest, label)?;
            manifest_obj.insert("assertions".to_string(), json!(assertions_obj));

            let claim = self
                .reader
                .store
                .get_claim(label)
                .ok_or_else(|| Error::ClaimMissing {
                    label: label.to_owned(),
                })?;
            if claim.version() == 1 {
                let claim_v1 = self.build_claim_v1(manifest, label, claim)?;
                manifest_obj.insert("claim".to_string(), claim_v1);
            } else {
                let claim_v2 = self.build_claim_v2(manifest, label)?;
                manifest_obj.insert("claim.v2".to_string(), claim_v2);
            }

            let claim_ref = self.reader.store.get_claim(label);
            let signature = self
                .build_claim_signature(manifest, claim_ref)?
                .unwrap_or_else(|| Value::Object(Map::new()));
            manifest_obj.insert("signature".to_string(), signature);

            // Each manifest's validationResults holds the validation result for THAT manifest (active or ingredient).
            let validation_results =
                self.build_manifest_validation_results(label, &validation_map);
            manifest_obj.insert("validationResults".to_string(), validation_results);

            // Per-manifest ingredientDeltas: deltas whose ingredientAssertionURI belongs to this manifest
            if let Some(deltas) = self.build_manifest_ingredient_deltas(label) {
                manifest_obj.insert("ingredientDeltas".to_string(), deltas);
            }

            labeled.push((label.clone(), Value::Object(manifest_obj)));
        }

        let store_order: std::collections::HashMap<String, usize> = self
            .reader
            .store
            .claims()
            .into_iter()
            .enumerate()
            .map(|(i, claim)| (claim.label().to_string(), i))
            .collect();
        labeled.sort_by(|a, b| {
            let a_active = active_label.is_some_and(|l| l == a.0);
            let b_active = active_label.is_some_and(|l| l == b.0);
            match (a_active, b_active) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    let a_idx = store_order.get(&a.0).copied().unwrap_or(0);
                    let b_idx = store_order.get(&b.0).copied().unwrap_or(0);
                    b_idx.cmp(&a_idx)
                }
            }
        });

        let manifests_array = labeled.into_iter().map(|(_, v)| v).collect();
        Ok(Value::Array(manifests_array))
    }

    fn convert_assertions(
        &self,
        manifest: &Manifest,
        manifest_label: &str,
    ) -> Result<Map<String, Value>> {
        let mut assertions_obj = Map::new();

        for assertion in manifest.assertions() {
            let label = assertion.label().to_string();
            let value_result = if let Ok(value) = assertion.value() {
                Ok(value.clone())
            } else {
                decode_assertion_data(assertion)
            };

            if let Ok(value) = value_result {
                let fixed_value = fix_hash_encoding(value);
                assertions_obj.insert(label, fixed_value);
            }
        }

        if let Some(claim) = self.reader.store.get_claim(manifest_label) {
            for hash_assertion in claim.hash_assertions() {
                let label = hash_assertion.label_raw();
                let instance = hash_assertion.instance();
                if let Some(assertion) = claim.get_claim_assertion(&label, instance) {
                    if let Ok(assertion_obj) = assertion.assertion().as_json_object() {
                        let fixed_value = fix_hash_encoding(assertion_obj);
                        let final_label = if instance > 0 {
                            format!("{}_{}", label, instance + 1)
                        } else {
                            label
                        };
                        assertions_obj.insert(final_label, fixed_value);
                    }
                }
            }
        }

        for (index, ingredient) in manifest.ingredients().iter().enumerate() {
            if let Ok(ingredient_json) = serde_json::to_value(ingredient) {
                let mut fixed_ingredient = fix_hash_encoding(ingredient_json);
                let base_label = if let Some(label_value) = fixed_ingredient.get("label") {
                    label_value
                        .as_str()
                        .unwrap_or("c2pa.ingredient")
                        .to_string()
                } else {
                    "c2pa.ingredient".to_string()
                };
                if let Some(obj) = fixed_ingredient.as_object_mut() {
                    obj.remove("label");
                }
                let label = if manifest.ingredients().len() > 1 {
                    format!("{}__{}", base_label, index + 1)
                } else {
                    base_label
                };
                assertions_obj.insert(label, fixed_ingredient);
            }
        }

        if let Some(claim) = self.reader.store.get_claim(manifest_label) {
            if let Some(gathered) = claim.gathered_assertions() {
                for assertion_ref in gathered {
                    let (label, instance) = Claim::assertion_label_from_link(&assertion_ref.url());
                    let final_label = if instance > 0 {
                        format!("{}_{}", label, instance + 1)
                    } else {
                        label.clone()
                    };
                    if assertions_obj.contains_key(&final_label) {
                        continue;
                    }
                    if let Some(claim_assertion) = claim.get_claim_assertion(&label, instance) {
                        let assertion = claim_assertion.assertion();
                        let use_ref_format = matches!(
                            assertion.decode_data(),
                            AssertionData::Binary(_) | AssertionData::Uuid(_, _)
                        );
                        if use_ref_format {
                            let absolute_uri =
                                to_absolute_uri(manifest_label, &assertion_ref.url());
                            let mut ref_obj = Map::new();
                            ref_obj.insert("format".to_string(), json!(assertion.content_type()));
                            ref_obj.insert("identifier".to_string(), json!(absolute_uri));
                            ref_obj.insert(
                                "hash".to_string(),
                                json!(base64::encode(&assertion_ref.hash())),
                            );
                            assertions_obj.insert(final_label, Value::Object(ref_obj));
                        } else if let Ok(assertion_obj) = assertion.as_json_object() {
                            let fixed_value = fix_hash_encoding(assertion_obj);
                            assertions_obj.insert(final_label, fixed_value);
                        }
                    }
                }
            }
        }

        Ok(assertions_obj)
    }

    fn build_claim_v1(&self, manifest: &Manifest, label: &str, claim: &Claim) -> Result<Value> {
        let mut claim_v1 = Map::new();
        claim_v1.insert(
            "claim_generator".to_string(),
            json!(claim
                .claim_generator()
                .or_else(|| manifest.claim_generator())
                .unwrap_or("")),
        );

        if let Some(ref info_vec) = manifest.claim_generator_info {
            let mut info_array = Vec::new();
            for info in info_vec {
                if let Ok(info_value) = serde_json::to_value(info) {
                    let fixed_info = fix_hash_encoding(info_value);
                    let mut info_obj = match fixed_info {
                        Value::Object(m) => m,
                        _ => continue,
                    };
                    if let Some(icon_val) = info_obj.get_mut("icon") {
                        if let Some(resolved) =
                            resolve_icon_to_hashed_uri_map(claim, label, icon_val)
                        {
                            *icon_val = resolved;
                        }
                        if let Some(icon_obj) = icon_val.as_object_mut() {
                            icon_retain_only_hashed_uri_map_keys(icon_obj);
                        }
                    }
                    info_array.push(Value::Object(info_obj));
                }
            }
            if !info_array.is_empty() {
                claim_v1.insert("claim_generator_info".to_string(), Value::Array(info_array));
            }
        }
        if !claim_v1.contains_key("claim_generator_info") {
            claim_v1.insert(
                "claim_generator_info".to_string(),
                json!([{"name": claim.claim_generator().unwrap_or("")}]),
            );
        }

        let signature_ref = format!("self#jumbf=/c2pa/{}/c2pa.signature", label);
        claim_v1.insert("signature".to_string(), json!(signature_ref));

        let mut assertions_arr = Vec::new();
        for assertion_ref in claim.assertions() {
            let mut ref_obj = Map::new();
            ref_obj.insert(
                "url".to_string(),
                json!(to_absolute_uri(label, &assertion_ref.url())),
            );
            ref_obj.insert(
                "hash".to_string(),
                json!(base64::encode(&assertion_ref.hash())),
            );
            if let Some(alg) = assertion_ref.alg() {
                ref_obj.insert("alg".to_string(), json!(alg));
            }
            assertions_arr.push(Value::Object(ref_obj));
        }
        claim_v1.insert("assertions".to_string(), Value::Array(assertions_arr));

        claim_v1.insert(
            "dc:format".to_string(),
            json!(manifest.format().or_else(|| claim.format()).unwrap_or("")),
        );
        claim_v1.insert("instanceID".to_string(), json!(manifest.instance_id()));

        let title_str = manifest
            .title()
            .or_else(|| claim.title().map(|s| s.as_str()));
        if let Some(title) = title_str {
            claim_v1.insert("dc:title".to_string(), json!(title));
        }
        if let Some(redacted) = claim.redactions() {
            if !redacted.is_empty() {
                claim_v1.insert("redacted_assertions".to_string(), json!(redacted));
            }
        }
        claim_v1.insert("alg".to_string(), json!(claim.alg()));
        if let Some(alg_soft) = claim.alg_soft() {
            claim_v1.insert("alg_soft".to_string(), json!(alg_soft));
        }
        if let Some(metadata) = claim.metadata() {
            if !metadata.is_empty() {
                if let Ok(v) = serde_json::to_value(metadata) {
                    claim_v1.insert("metadata".to_string(), v);
                }
            }
        }

        Ok(Value::Object(claim_v1))
    }

    fn build_claim_v2(&self, manifest: &Manifest, label: &str) -> Result<Value> {
        let mut claim_v2 = Map::new();

        if let Some(title) = manifest.title() {
            claim_v2.insert("dc:title".to_string(), json!(title));
        }
        claim_v2.insert("instanceID".to_string(), json!(manifest.instance_id()));

        if let Some(claim_generator) = manifest.claim_generator() {
            claim_v2.insert("claim_generator".to_string(), json!(claim_generator));
        }

        if let Some(ref info_vec) = manifest.claim_generator_info {
            if let Some(first) = info_vec.first() {
                if let Ok(info_value) = serde_json::to_value(first) {
                    let fixed_info = fix_hash_encoding(info_value);
                    let mut info_for_claim = match &fixed_info {
                        Value::Array(arr) if !arr.is_empty() => arr[0].clone(),
                        _ => fixed_info,
                    };
                    if let Some(claim) = self.reader.store.get_claim(label) {
                        if let Some(info_obj) = info_for_claim.as_object_mut() {
                            if let Some(icon_val) = info_obj.get_mut("icon") {
                                if let Some(resolved) =
                                    resolve_icon_to_hashed_uri_map(claim, label, icon_val)
                                {
                                    *icon_val = resolved;
                                }
                            }
                        }
                    }
                    claim_v2.insert("claim_generator_info".to_string(), info_for_claim);
                }
            }
        }
        if !claim_v2.contains_key("claim_generator_info") {
            let fallback = manifest
                .claim_generator()
                .map_or_else(|| json!({"name": "Unknown"}), |cg| json!({"name": cg}));
            claim_v2.insert("claim_generator_info".to_string(), fallback);
        }

        claim_v2.insert("alg".to_string(), json!("SHA-256"));
        let signature_ref = format!("self#jumbf=/c2pa/{}/c2pa.signature", label);
        claim_v2.insert("signature".to_string(), json!(signature_ref));

        let (created_assertions, gathered_assertions) =
            self.build_assertion_references(manifest, label)?;
        claim_v2.insert("created_assertions".to_string(), created_assertions);
        claim_v2.insert("gathered_assertions".to_string(), gathered_assertions);
        claim_v2.insert("redacted_assertions".to_string(), json!([]));

        if let Some(existing) = claim_v2.get("claim_generator_info") {
            if let Some(arr) = existing.as_array() {
                if !arr.is_empty() {
                    claim_v2.insert("claim_generator_info".to_string(), arr[0].clone());
                }
            }
        }

        if let Some(claim) = self.reader.store.get_claim(label) {
            if let Some(cgi) = claim_v2.get_mut("claim_generator_info") {
                if let Some(info_obj) = cgi.as_object_mut() {
                    if let Some(icon_val) = info_obj.get_mut("icon") {
                        let is_hashed_uri_map = icon_val
                            .as_object()
                            .and_then(|o| o.get("url").and_then(|v| v.as_str()))
                            .is_some()
                            && icon_val
                                .as_object()
                                .and_then(|o| o.get("hash").and_then(|v| v.as_str()))
                                .is_some();
                        if !is_hashed_uri_map {
                            if let Some(resolved) =
                                resolve_icon_to_hashed_uri_map(claim, label, icon_val)
                            {
                                *icon_val = resolved;
                            }
                        }
                        if let Some(icon_obj) = icon_val.as_object_mut() {
                            icon_retain_only_hashed_uri_map_keys(icon_obj);
                        }
                    }
                }
            }
        }

        Ok(Value::Object(claim_v2))
    }

    fn build_assertion_references(
        &self,
        _manifest: &Manifest,
        label: &str,
    ) -> Result<(Value, Value)> {
        let claim = self
            .reader
            .store
            .get_claim(label)
            .ok_or_else(|| Error::ClaimMissing {
                label: label.to_owned(),
            })?;

        let mut created_refs = Vec::new();
        for assertion_ref in claim.created_assertions() {
            let mut ref_obj = Map::new();
            ref_obj.insert("url".to_string(), json!(assertion_ref.url()));
            let hash = assertion_ref.hash();
            ref_obj.insert("hash".to_string(), json!(base64::encode(&hash)));
            created_refs.push(Value::Object(ref_obj));
        }

        let mut gathered_refs = Vec::new();
        if let Some(gathered) = claim.gathered_assertions() {
            for assertion_ref in gathered {
                let mut ref_obj = Map::new();
                ref_obj.insert("url".to_string(), json!(assertion_ref.url()));
                let hash = assertion_ref.hash();
                ref_obj.insert("hash".to_string(), json!(base64::encode(&hash)));
                gathered_refs.push(Value::Object(ref_obj));
            }
        }

        if created_refs.is_empty() && gathered_refs.is_empty() && claim.version() == 1 {
            for assertion_ref in claim.assertions() {
                let mut ref_obj = Map::new();
                ref_obj.insert("url".to_string(), json!(assertion_ref.url()));
                let hash = assertion_ref.hash();
                ref_obj.insert("hash".to_string(), json!(base64::encode(&hash)));
                created_refs.push(Value::Object(ref_obj));
            }
        }

        Ok((Value::Array(created_refs), Value::Array(gathered_refs)))
    }

    fn build_claim_signature(
        &self,
        manifest: &Manifest,
        claim: Option<&Claim>,
    ) -> Result<Option<Value>> {
        let sig_info = match manifest.signature_info() {
            Some(info) => info,
            None => return Ok(None),
        };

        let mut claim_signature = Map::new();
        let alg_str = sig_info
            .alg
            .as_ref()
            .map_or_else(String::new, |a| a.to_string());
        claim_signature.insert("algorithm".to_string(), json!(alg_str));

        let mut cert_info_obj = Map::new();
        if let Some(cert_info) = parse_certificate(&sig_info.cert_chain)? {
            if let Some(serial) = cert_info.serial_number {
                cert_info_obj.insert("serialNumber".to_string(), json!(serial));
            }
            if let Some(issuer) = cert_info.issuer {
                cert_info_obj.insert("issuer".to_string(), json!(issuer));
            }
            if let Some(subject) = cert_info.subject {
                cert_info_obj.insert("subject".to_string(), json!(subject));
            }
            if let Some(validity) = cert_info.validity {
                cert_info_obj.insert("validity".to_string(), validity);
            }
        }
        claim_signature.insert("certificateInfo".to_string(), Value::Object(cert_info_obj));

        let has_ts_time = sig_info.time.is_some();
        let mut tsa_cert_info_obj = Map::new();
        if let Some(claim) = claim {
            if let Ok(data) = claim.data() {
                let sig_bytes = claim.signature_val();
                let mut log = StatusTracker::default();
                if let Ok(sign1) = parse_cose_sign1(sig_bytes, data.as_ref(), &mut log) {
                    if let Some(token_bytes) = timestamp_token_bytes_from_sign1(&sign1) {
                        if let Ok(Some(tsa_der)) = tsa_signer_cert_der_from_token(&token_bytes) {
                            if let Ok(Some(tsa_info)) = parse_certificate_from_der(&tsa_der) {
                                if let Some(serial) = tsa_info.serial_number {
                                    tsa_cert_info_obj
                                        .insert("serialNumber".to_string(), json!(serial));
                                }
                                if let Some(issuer) = tsa_info.issuer {
                                    tsa_cert_info_obj.insert("issuer".to_string(), json!(issuer));
                                }
                                if let Some(subject) = tsa_info.subject {
                                    tsa_cert_info_obj.insert("subject".to_string(), json!(subject));
                                }
                                if let Some(validity) = tsa_info.validity {
                                    tsa_cert_info_obj.insert("validity".to_string(), validity);
                                }
                            }
                        }
                    }
                }
            }
        }
        if has_ts_time || !tsa_cert_info_obj.is_empty() {
            let mut time_stamp_info = Map::new();
            if let Some(time) = &sig_info.time {
                time_stamp_info.insert("timestamp".to_string(), json!(time));
            }
            if !tsa_cert_info_obj.is_empty() {
                time_stamp_info.insert(
                    "certificateInfo".to_string(),
                    Value::Object(tsa_cert_info_obj),
                );
            }
            claim_signature.insert("timeStampInfo".to_string(), Value::Object(time_stamp_info));
        }

        Ok(Some(Value::Object(claim_signature)))
    }

    /// Build a map from each manifest label to its validation results (status codes + validation time).
    /// The document's active manifest gets active_manifest codes; each ingredient manifest gets the
    /// codes from the ingredient_delta that refers to it (resolved via the ingredient assertion's
    /// activeManifest/c2pa_manifest target).
    fn build_validation_results_per_manifest(
        &self,
    ) -> HashMap<String, (StatusCodes, Option<String>)> {
        let mut map: HashMap<String, (StatusCodes, Option<String>)> = HashMap::new();
        let Some(vr) = self.reader.validation_results() else {
            return map;
        };
        let validation_time = vr.validation_time().map(String::from);

        // Document active manifest
        if let Some(active_label) = self.reader.active_label() {
            let codes = vr
                .active_manifest()
                .cloned()
                .unwrap_or_default();
            map.insert(active_label.to_string(), (codes, validation_time.clone()));
        }

        // Each ingredient_delta: resolve its assertion URI to the target manifest label, then map that label to the delta's codes
        let Some(deltas) = vr.ingredient_deltas() else {
            return map;
        };
        for idv in deltas {
            let Some(target_label) = self.ingredient_assertion_uri_to_manifest_label(idv.ingredient_assertion_uri()) else {
                continue;
            };
            let codes = idv.validation_deltas().clone();
            map.insert(target_label, (codes, validation_time.clone()));
        }
        map
    }

    /// Resolve an ingredient assertion URI (in a parent manifest) to the target manifest label (the ingredient's active manifest).
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

    /// Build validationResults (statusCodes + validationTime) for one manifest. Each element of the
    /// manifests array gets the validation result for THAT manifest (active or ingredient).
    fn build_manifest_validation_results(
        &self,
        label: &str,
        validation_map: &HashMap<String, (StatusCodes, Option<String>)>,
    ) -> Value {
        let (codes, validation_time) = validation_map
            .get(label)
            .cloned()
            .unwrap_or_else(|| (StatusCodes::default(), None));
        let mut base = serde_json::to_value(&codes).unwrap_or_else(|_| {
            json!({
                "success": [],
                "informational": [],
                "failure": []
            })
        });
        if let (Some(t), Some(obj)) = (validation_time, base.as_object_mut()) {
            obj.insert("validationTime".to_string(), json!(t));
        }
        base
    }

    /// Build ingredientDeltas for a single manifest. Each delta is attributed to the manifest that
    /// declares the ingredient (ingredientAssertionURI identifies the assertion in a manifest),
    /// so ingredient manifest validation results are correctly reflected on the declaring manifest.
    fn build_manifest_ingredient_deltas(&self, label: &str) -> Option<Value> {
        let validation_results = self.reader.validation_results()?;
        let deltas = validation_results.ingredient_deltas()?;
        let for_manifest: Vec<_> = deltas
            .iter()
            .filter(|idv| {
                manifest_label_from_uri(idv.ingredient_assertion_uri()).as_deref() == Some(label)
            })
            .collect();
        if for_manifest.is_empty() {
            return None;
        }
        serde_json::to_value(&for_manifest).ok()
    }
}

fn decode_assertion_data(assertion: &crate::ManifestAssertion) -> Result<Value> {
    if let Ok(binary) = assertion.binary() {
        let cbor_value: c2pa_cbor::Value = c2pa_cbor::from_slice(binary)?;
        let json_value: Value = serde_json::to_value(&cbor_value)?;
        Ok(json_value)
    } else {
        Err(Error::UnsupportedType)
    }
}

fn fix_hash_encoding(value: Value) -> Value {
    match value {
        Value::Object(mut map) => {
            const SCHEMA_ORG_OS_KEY: &str = "schema.org.SoftwareApplication.operatingSystem";
            if let Some(os_value) = map.remove(SCHEMA_ORG_OS_KEY) {
                if !map.contains_key("operating_system") {
                    map.insert("operating_system".to_string(), os_value);
                }
            }

            if let Some(hash_value) = map.get("hash") {
                if let Some(hash_array) = hash_value.as_array() {
                    if hash_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                        let bytes: Vec<u8> = hash_array
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        let hash_b64 = base64::encode(&bytes);
                        map.insert("hash".to_string(), json!(hash_b64));
                    }
                }
            }

            if let Some(pad_value) = map.get("pad") {
                if let Some(pad_array) = pad_value.as_array() {
                    if pad_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                        let bytes: Vec<u8> = pad_array
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        let pad_b64 = base64::encode(&bytes);
                        map.insert("pad".to_string(), json!(pad_b64));
                    }
                }
            }

            if let Some(pad1_value) = map.get("pad1") {
                if let Some(pad1_array) = pad1_value.as_array() {
                    if pad1_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                        let bytes: Vec<u8> = pad1_array
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        let pad1_b64 = base64::encode(&bytes);
                        map.insert("pad1".to_string(), json!(pad1_b64));
                    }
                }
            }

            if let Some(pad2_value) = map.get("pad2") {
                if let Some(pad2_array) = pad2_value.as_array() {
                    if pad2_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                        let bytes: Vec<u8> = pad2_array
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        let pad2_b64 = base64::encode(&bytes);
                        map.insert("pad2".to_string(), json!(pad2_b64));
                    }
                }
            }

            if map.contains_key("hash") && !map.contains_key("pad") {
                map.insert("pad".to_string(), json!(""));
            }

            if let Some(signature_value) = map.get("signature") {
                if let Some(sig_array) = signature_value.as_array() {
                    if sig_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                        let sig_bytes: Vec<u8> = sig_array
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u8))
                            .collect();
                        if let Ok(decoded_sig) = decode_cawg_signature(&sig_bytes) {
                            map.insert("signature".to_string(), decoded_sig);
                        } else {
                            let sig_b64 = base64::encode(&sig_bytes);
                            map.insert("signature".to_string(), json!(sig_b64));
                        }
                    }
                }
            }

            for (_key, val) in map.iter_mut() {
                *val = fix_hash_encoding(val.clone());
            }

            if let Some(icon_val) = map.get_mut("icon") {
                if let Some(icon_obj) = icon_val.as_object_mut() {
                    if !icon_obj.contains_key("url") {
                        if let Some(id_val) = icon_obj.get("identifier") {
                            if let Some(id_str) = id_val.as_str() {
                                icon_obj.insert("url".to_string(), json!(id_str));
                            }
                        }
                    }
                    icon_retain_only_hashed_uri_map_keys(icon_obj);
                }
            }

            Value::Object(map)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(fix_hash_encoding).collect()),
        other => other,
    }
}

fn icon_retain_only_hashed_uri_map_keys(icon_obj: &mut Map<String, Value>) {
    const ALLOWED: &[&str] = &["url", "hash", "alg"];
    icon_obj.retain(|k, _| ALLOWED.contains(&k.as_str()));
}

fn resolve_icon_to_hashed_uri_map(
    claim: &Claim,
    manifest_label: &str,
    icon_val: &Value,
) -> Option<Value> {
    let icon_obj = icon_val.as_object()?;
    let url_str = icon_obj.get("url").and_then(|v| v.as_str());
    let hash_str = icon_obj.get("hash").and_then(|v| v.as_str());
    let identifier_str = icon_obj.get("identifier").and_then(|v| v.as_str());
    if url_str.is_some() && hash_str.is_some() {
        return None;
    }
    if let (Some(uri), Some(hash)) = (identifier_str.or(url_str), hash_str) {
        let mut map = Map::new();
        map.insert("url".to_string(), json!(uri));
        map.insert("hash".to_string(), json!(hash));
        if let Some(alg) = icon_obj.get("alg").and_then(|v| v.as_str()) {
            map.insert("alg".to_string(), json!(alg));
        }
        return Some(Value::Object(map));
    }
    let uri = identifier_str.or(url_str)?;
    let (label, instance) = Claim::assertion_label_from_link(uri);
    let (url, hash_b64, alg) = if let Some((hashed_uri, _)) =
        claim.assertion_hashed_uri_from_label(&Claim::label_with_instance(&label, instance))
    {
        (
            to_absolute_uri(manifest_label, &hashed_uri.url()),
            base64::encode(&hashed_uri.hash()),
            hashed_uri.alg(),
        )
    } else if let Some(ca) = claim.get_claim_assertion(&label, instance) {
        (uri.to_string(), base64::encode(ca.hash()), None)
    } else {
        return None;
    };
    let mut map = Map::new();
    map.insert("url".to_string(), json!(url));
    map.insert("hash".to_string(), json!(hash_b64));
    if let Some(alg) = alg {
        map.insert("alg".to_string(), json!(alg));
    }
    Some(Value::Object(map))
}

#[derive(Debug, Default)]
struct CertificateDetails {
    serial_number: Option<String>,
    issuer: Option<Map<String, Value>>,
    subject: Option<Map<String, Value>>,
    validity: Option<Value>,
}

fn parse_certificate(cert_chain: &str) -> Result<Option<CertificateDetails>> {
    let cert_der = parse_pem_to_der(cert_chain)?;
    if cert_der.is_empty() {
        return Ok(None);
    }
    let (_, cert) = X509Certificate::from_der(&cert_der[0]).map_err(|_e| Error::CoseInvalidCert)?;
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    let not_before_chrono: DateTime<Utc> =
        DateTime::from_timestamp(not_before.unix_timestamp(), 0).ok_or(Error::CoseInvalidCert)?;
    let not_after_chrono: DateTime<Utc> =
        DateTime::from_timestamp(not_after.unix_timestamp(), 0).ok_or(Error::CoseInvalidCert)?;
    let details = CertificateDetails {
        serial_number: Some(format!("{:x}", cert.serial)),
        issuer: Some(extract_dn_components(cert.issuer())?),
        subject: Some(extract_dn_components(cert.subject())?),
        validity: Some(json!({
            "notBefore": not_before_chrono.to_rfc3339(),
            "notAfter": not_after_chrono.to_rfc3339()
        })),
    };
    Ok(Some(details))
}

fn parse_certificate_from_der(der: &[u8]) -> Result<Option<CertificateDetails>> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_e| Error::CoseInvalidCert)?;
    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    let not_before_chrono: DateTime<Utc> =
        DateTime::from_timestamp(not_before.unix_timestamp(), 0).ok_or(Error::CoseInvalidCert)?;
    let not_after_chrono: DateTime<Utc> =
        DateTime::from_timestamp(not_after.unix_timestamp(), 0).ok_or(Error::CoseInvalidCert)?;
    let details = CertificateDetails {
        serial_number: Some(format!("{:x}", cert.serial)),
        issuer: Some(extract_dn_components(cert.issuer())?),
        subject: Some(extract_dn_components(cert.subject())?),
        validity: Some(json!({
            "notBefore": not_before_chrono.to_rfc3339(),
            "notAfter": not_after_chrono.to_rfc3339()
        })),
    };
    Ok(Some(details))
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

fn parse_pem_to_der(pem_chain: &str) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    for pem in pem_chain.split("-----BEGIN CERTIFICATE-----") {
        if let Some(end_idx) = pem.find("-----END CERTIFICATE-----") {
            let pem_data: String = pem[..end_idx]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if let Ok(der) = base64::decode(&pem_data) {
                certs.push(der);
            }
        }
    }
    Ok(certs)
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
        if !cert_chain.is_empty() {
            if let Ok((_rem, cert)) = X509Certificate::from_der(&cert_chain[0]) {
                let mut cert_info = Map::new();
                cert_info.insert(
                    "serialNumber".to_string(),
                    json!(format!("{:x}", cert.serial)),
                );
                if let Ok(issuer) = extract_dn_components(cert.issuer()) {
                    cert_info.insert("issuer".to_string(), json!(issuer));
                }
                if let Ok(subject) = extract_dn_components(cert.subject()) {
                    cert_info.insert("subject".to_string(), json!(subject));
                }
                let not_before = cert.validity().not_before.to_datetime();
                let not_after = cert.validity().not_after.to_datetime();
                if let Some(not_before_chrono) =
                    DateTime::<Utc>::from_timestamp(not_before.unix_timestamp(), 0)
                {
                    if let Some(not_after_chrono) =
                        DateTime::<Utc>::from_timestamp(not_after.unix_timestamp(), 0)
                    {
                        cert_info.insert(
                            "validity".to_string(),
                            json!({
                                "notBefore": not_before_chrono.to_rfc3339(),
                                "notAfter": not_after_chrono.to_rfc3339()
                            }),
                        );
                    }
                }
                signature_obj.insert("certificateInfo".to_string(), Value::Object(cert_info));
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

        // jsonGenerator is c2pa-rs (this library) with name, version, date
        let jg = &json_value["jsonGenerator"];
        assert_eq!(jg.get("name").and_then(|v| v.as_str()), Some("c2pa-rs"));
        assert!(
            jg.get("version").and_then(|v| v.as_str()).is_some(),
            "jsonGenerator.version required"
        );
        assert!(jg.get("date").is_some(), "jsonGenerator.date required");

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

        // Verify pad1 and pad2 are base64 strings, not arrays
        assert!(
            cawg_identity["pad1"].is_string(),
            "pad1 should be a base64 string, not an array"
        );
        if cawg_identity.get("pad2").is_some() {
            assert!(
                cawg_identity["pad2"].is_string(),
                "pad2 should be a base64 string, not an array"
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

            // Verify pad fields are base64 strings
            assert!(
                cawg_identity["pad1"].is_string(),
                "pad1 should be a base64 string"
            );

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
