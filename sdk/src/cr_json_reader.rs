// Copyright 2024 Adobe. All rights reserved.
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

//! crJSON format exporter for C2PA manifests.
//!
//! This module provides a Reader-like API that exports C2PA manifests in the
//! crJSON format as described in the crJSON specification.

use std::{
    io::{Read, Seek},
    sync::Arc,
};

use async_generic::async_generic;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use serde_with::skip_serializing_none;
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::{
    assertion::AssertionData,
    claim::Claim,
    context::Context,
    crypto::base64,
    error::{Error, Result},
    jumbf::labels::to_absolute_uri,
    reader::{AsyncPostValidator, MaybeSend, PostValidator, Reader},
    validation_results::{
        validation_codes::{
            SIGNING_CREDENTIAL_EXPIRED, SIGNING_CREDENTIAL_INVALID, SIGNING_CREDENTIAL_TRUSTED,
            SIGNING_CREDENTIAL_UNTRUSTED,
        },
        ValidationState,
    },
    validation_status::ValidationStatus,
    Manifest,
};

/// Use a CrJsonReader to read and validate a manifest store in crJSON format.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default)]
pub struct CrJsonReader {
    #[serde(skip)]
    inner: Reader,
}

impl CrJsonReader {
    /// Create a new CrJsonReader with the given [`Context`].
    pub fn from_context(context: Context) -> Self {
        Self {
            inner: Reader::from_context(context),
        }
    }

    /// Create a new CrJsonReader with a shared [`Context`].
    pub fn from_shared_context(context: &Arc<Context>) -> Self {
        Self {
            inner: Reader::from_shared_context(context),
        }
    }

    /// Add manifest store from a stream to the [`CrJsonReader`]
    #[async_generic]
    pub fn with_stream(
        mut self,
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        if _sync {
            self.inner = self.inner.with_stream(format, stream)?;
        } else {
            self.inner = self.inner.with_stream_async(format, stream).await?;
        }
        Ok(self)
    }

    /// Create a crJSON format [`CrJsonReader`] from a stream.
    #[async_generic]
    pub fn from_stream(format: &str, stream: impl Read + Seek + MaybeSend) -> Result<Self> {
        if _sync {
            Ok(Self {
                inner: Reader::from_stream(format, stream)?,
            })
        } else {
            Ok(Self {
                inner: Reader::from_stream_async(format, stream).await?,
            })
        }
    }

    /// Add manifest store from a file to the [`CrJsonReader`].
    #[cfg(feature = "file_io")]
    #[async_generic]
    pub fn with_file<P: AsRef<std::path::Path>>(mut self, path: P) -> Result<Self> {
        if _sync {
            self.inner = self.inner.with_file(path)?;
        } else {
            self.inner = self.inner.with_file_async(path).await?;
        }
        Ok(self)
    }

    /// Create a crJSON format [`CrJsonReader`] from a file.
    #[cfg(feature = "file_io")]
    #[async_generic]
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        if _sync {
            Ok(Self {
                inner: Reader::from_file(path)?,
            })
        } else {
            Ok(Self {
                inner: Reader::from_file_async(path).await?,
            })
        }
    }

    /// Add manifest store from existing `c2pa_data` and a stream to the [`CrJsonReader`].
    #[async_generic]
    pub fn with_manifest_data_and_stream(
        mut self,
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        if _sync {
            self.inner = self
                .inner
                .with_manifest_data_and_stream(c2pa_data, format, stream)?;
        } else {
            self.inner = self
                .inner
                .with_manifest_data_and_stream_async(c2pa_data, format, stream)
                .await?;
        }
        Ok(self)
    }

    /// Create a crJSON format [`CrJsonReader`] from existing `c2pa_data` and a stream.
    #[async_generic]
    pub fn from_manifest_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        if _sync {
            Ok(Self {
                inner: Reader::from_manifest_data_and_stream(c2pa_data, format, stream)?,
            })
        } else {
            Ok(Self {
                inner: Reader::from_manifest_data_and_stream_async(c2pa_data, format, stream)
                    .await?,
            })
        }
    }

    /// Post-validate the reader
    #[async_generic(async_signature(
        &mut self,
        validator: &impl AsyncPostValidator
    ))]
    pub fn post_validate(&mut self, validator: &impl PostValidator) -> Result<()> {
        if _sync {
            self.inner.post_validate(validator)
        } else {
            self.inner.post_validate_async(validator).await
        }
    }

    /// Returns the remote url of the manifest if this [`CrJsonReader`] obtained the manifest remotely.
    pub fn remote_url(&self) -> Option<&str> {
        self.inner.remote_url()
    }

    /// Returns if the [`CrJsonReader`] was created from an embedded manifest.
    pub fn is_embedded(&self) -> bool {
        self.inner.is_embedded()
    }

    /// Get the [`ValidationState`] of the manifest store.
    pub fn validation_state(&self) -> ValidationState {
        self.inner.validation_state()
    }

    /// Convert the reader to a crJSON format JSON value.
    pub fn to_json_value(&self) -> Result<Value> {
        let mut result = json!({
            "@context": {
                "@vocab": "https://contentcredentials.org/crjson",
                "extras": "https://contentcredentials.org/crjson/extras"
            }
        });

        // Convert manifests from HashMap to Array
        let manifests_array = self.convert_manifests_to_array()?;
        result["manifests"] = manifests_array;

        // Add validationResults (output of validation_results() method)
        if let Some(validation_results) = self.inner.validation_results() {
            result["validationResults"] = serde_json::to_value(validation_results)?;
        }

        Ok(result)
    }

    /// Get the CrJsonReader as a JSON string
    pub fn json(&self) -> String {
        match self.to_json_value() {
            Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_default(),
            Err(_) => "{}".to_string(),
        }
    }

    /// Convert manifests from HashMap to Array format.
    /// The first element is always the active manifest (if any); the rest are in manifest store order (most recent first, earliest last).
    fn convert_manifests_to_array(&self) -> Result<Value> {
        let active_label = self.inner.active_label();
        let mut labeled: Vec<(String, Value)> = Vec::new();

        for (label, manifest) in self.inner.manifests() {
            let mut manifest_obj = Map::new();
            manifest_obj.insert("label".to_string(), json!(label));

            // Convert assertions from array to object
            let assertions_obj = self.convert_assertions(manifest, label)?;
            manifest_obj.insert("assertions".to_string(), json!(assertions_obj));

            // Build claim.v2 object
            let claim_v2 = self.build_claim_v2(manifest, label)?;
            manifest_obj.insert("claim.v2".to_string(), claim_v2);

            // Build signature object (required per manifest schema; use empty object when no signature info)
            let signature = self
                .build_claim_signature(manifest)?
                .unwrap_or_else(|| Value::Object(Map::new()));
            manifest_obj.insert("signature".to_string(), signature);

            // Build status object (required; use empty object when no validation results)
            let status = self
                .build_manifest_status(manifest, label)?
                .unwrap_or_else(|| Value::Object(Map::new()));
            manifest_obj.insert("status".to_string(), status);

            labeled.push((label.clone(), Value::Object(manifest_obj)));
        }

        // Order: active manifest first, then others by manifest store order (most recent first)
        let store_order: std::collections::HashMap<String, usize> = self
            .inner
            .store
            .claims()
            .into_iter()
            .enumerate()
            .map(|(i, claim)| (claim.label().to_string(), i))
            .collect();
        labeled.sort_by(|a, b| {
            let a_active = active_label.map_or(false, |l| l == a.0);
            let b_active = active_label.map_or(false, |l| l == b.0);
            match (a_active, b_active) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    let a_idx = store_order.get(&a.0).copied().unwrap_or(0);
                    let b_idx = store_order.get(&b.0).copied().unwrap_or(0);
                    b_idx.cmp(&a_idx) // descending: most recent (higher index) first
                }
            }
        });

        let manifests_array = labeled.into_iter().map(|(_, v)| v).collect();
        Ok(Value::Array(manifests_array))
    }

    /// Convert assertions from array format to object format (keyed by label)
    fn convert_assertions(&self, manifest: &Manifest, manifest_label: &str) -> Result<Map<String, Value>> {
        let mut assertions_obj = Map::new();

        // Process regular assertions
        for assertion in manifest.assertions() {
            let label = assertion.label().to_string();
            
            // Try to get the value - if it fails (e.g., binary or CBOR), try to decode it
            let value_result = if let Ok(value) = assertion.value() {
                Ok(value.clone())
            } else {
                // For CBOR assertions (like ingredients), try to decode them
                self.decode_assertion_data(assertion)
            };
            
            if let Ok(value) = value_result {
                // Fix any byte array hashes to base64 strings
                let fixed_value = Self::fix_hash_encoding(value);
                assertions_obj.insert(label, fixed_value);
            }
        }
        
        // Add hash assertions (c2pa.hash.data, c2pa.hash.bmff, c2pa.hash.boxes)
        // These are filtered out by Manifest::from_store but we need them for crJSON format
        if let Some(claim) = self.inner.store.get_claim(manifest_label) {
            for hash_assertion in claim.hash_assertions() {
                let label = hash_assertion.label_raw();
                let instance = hash_assertion.instance();
                
                // Get the assertion and convert to JSON
                if let Some(assertion) = claim.get_claim_assertion(&label, instance) {
                    if let Ok(assertion_obj) = assertion.assertion().as_json_object() {
                        let fixed_value = Self::fix_hash_encoding(assertion_obj);
                        
                        // Handle instance numbers for multiple assertions with same label
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
        
        // Add ingredient assertions from the ingredients array
        // Each ingredient is itself an assertion that should be in the assertions object
        for (index, ingredient) in manifest.ingredients().iter().enumerate() {
            // Convert ingredient to JSON
            if let Ok(ingredient_json) = serde_json::to_value(ingredient) {
                // Fix any byte array hashes to base64 strings
                let mut fixed_ingredient = Self::fix_hash_encoding(ingredient_json);
                
                // Get the label from the ingredient (includes version if v2+)
                // The label field contains the correct versioned label like "c2pa.ingredient.v2"
                let base_label = if let Some(label_value) = fixed_ingredient.get("label") {
                    label_value
                        .as_str()
                        .unwrap_or("c2pa.ingredient")
                        .to_string()
                } else {
                    "c2pa.ingredient".to_string()
                };
                
                // Remove the label field since it's redundant (the label is the key in assertions object)
                if let Some(obj) = fixed_ingredient.as_object_mut() {
                    obj.remove("label");
                }
                
                // Add instance number if there are multiple ingredients
                let label = if manifest.ingredients().len() > 1 {
                    format!("{}__{}",  base_label, index + 1)
                } else {
                    base_label
                };
                
                assertions_obj.insert(label, fixed_ingredient);
            }
        }

        // Add gathered assertions (e.g. c2pa.icon) that are not in manifest.assertions().
        // Manifest::from_store skips binary assertions like icon (AssertionData::Binary => {}),
        // so they must be added from the claim's gathered_assertions for crJSON output.
        if let Some(claim) = self.inner.store.get_claim(manifest_label) {
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
                        // Binary/Uuid assertions (e.g. c2pa.icon EmbeddedData): emit format, identifier, hash
                        // instead of raw bytes so the output is usable and matches claim_generator_info icon refs
                        let use_ref_format = matches!(
                            assertion.decode_data(),
                            AssertionData::Binary(_) | AssertionData::Uuid(_, _)
                        );
                        if use_ref_format {
                            let absolute_uri =
                                to_absolute_uri(manifest_label, &assertion_ref.url());
                            let mut ref_obj = Map::new();
                            ref_obj.insert(
                                "format".to_string(),
                                json!(assertion.content_type()),
                            );
                            ref_obj.insert("identifier".to_string(), json!(absolute_uri));
                            ref_obj.insert(
                                "hash".to_string(),
                                json!(base64::encode(&assertion_ref.hash())),
                            );
                            assertions_obj.insert(final_label, Value::Object(ref_obj));
                        } else if let Ok(assertion_obj) = assertion.as_json_object() {
                            let fixed_value = Self::fix_hash_encoding(assertion_obj);
                            assertions_obj.insert(final_label, fixed_value);
                        }
                    }
                }
            }
        }

        Ok(assertions_obj)
    }
    
    /// Decode assertion data that's not in JSON format (e.g., CBOR)
    fn decode_assertion_data(&self, assertion: &crate::ManifestAssertion) -> Result<Value> {
        // Try to get binary data and decode as CBOR
        if let Ok(binary) = assertion.binary() {
            // Try to decode as CBOR to JSON
            let cbor_value: c2pa_cbor::Value = c2pa_cbor::from_slice(binary)?;
            let json_value: Value = serde_json::to_value(&cbor_value)?;
            Ok(json_value)
        } else {
            Err(Error::UnsupportedType)
        }
    }

    /// Recursively convert byte array hashes and pads to base64 strings
    ///
    /// This fixes the issue where hash and pad fields are serialized as byte arrays
    /// instead of base64 strings when converting from CBOR to JSON.
    fn fix_hash_encoding(value: Value) -> Value {
        match value {
            Value::Object(mut map) => {
                // Check if this object has a "hash" field that's an array
                if let Some(hash_value) = map.get("hash") {
                    if let Some(hash_array) = hash_value.as_array() {
                        // Check if it's an array of integers (byte array)
                        if hash_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                            // Convert to Vec<u8>
                            let bytes: Vec<u8> = hash_array
                                .iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect();

                            // Convert to base64
                            let hash_b64 = base64::encode(&bytes);
                            map.insert("hash".to_string(), json!(hash_b64));
                        }
                    }
                }

                // Check if this object has a "pad" field that's an array
                if let Some(pad_value) = map.get("pad") {
                    if let Some(pad_array) = pad_value.as_array() {
                        // Check if it's an array of integers (byte array)
                        if pad_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                            // Convert to Vec<u8>
                            let bytes: Vec<u8> = pad_array
                                .iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect();

                            // Convert to base64
                            let pad_b64 = base64::encode(&bytes);
                            map.insert("pad".to_string(), json!(pad_b64));
                        }
                    }
                }

                // Check if this object has a "pad1" field that's an array (cawg.identity)
                if let Some(pad1_value) = map.get("pad1") {
                    if let Some(pad1_array) = pad1_value.as_array() {
                        // Check if it's an array of integers (byte array)
                        if pad1_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                            // Convert to Vec<u8>
                            let bytes: Vec<u8> = pad1_array
                                .iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect();

                            // Convert to base64
                            let pad1_b64 = base64::encode(&bytes);
                            map.insert("pad1".to_string(), json!(pad1_b64));
                        }
                    }
                }

                // Check if this object has a "pad2" field that's an array (cawg.identity)
                if let Some(pad2_value) = map.get("pad2") {
                    if let Some(pad2_array) = pad2_value.as_array() {
                        // Check if it's an array of integers (byte array)
                        if pad2_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                            // Convert to Vec<u8>
                            let bytes: Vec<u8> = pad2_array
                                .iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect();

                            // Convert to base64
                            let pad2_b64 = base64::encode(&bytes);
                            map.insert("pad2".to_string(), json!(pad2_b64));
                        }
                    }
                }

                // Check if this object has a "signature" field that's an array (cawg.identity)
                // This should be decoded as COSE_Sign1 and expanded similar to claimSignature
                if let Some(signature_value) = map.get("signature") {
                    if let Some(sig_array) = signature_value.as_array() {
                        // Check if it's an array of integers (byte array)
                        if sig_array.iter().all(|v| v.is_u64() || v.is_i64()) {
                            // Convert to Vec<u8>
                            let sig_bytes: Vec<u8> = sig_array
                                .iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u8))
                                .collect();

                            // Try to decode as COSE_Sign1 and extract certificate info
                            if let Ok(decoded_sig) = Self::decode_cawg_signature(&sig_bytes) {
                                map.insert("signature".to_string(), decoded_sig);
                            } else {
                                // If decoding fails, fall back to base64
                                let sig_b64 = base64::encode(&sig_bytes);
                                map.insert("signature".to_string(), json!(sig_b64));
                            }
                        }
                    }
                }

                // Recursively process all values in the map
                for (_key, val) in map.iter_mut() {
                    *val = Self::fix_hash_encoding(val.clone());
                }

                Value::Object(map)
            }
            Value::Array(arr) => {
                // Recursively process all array elements
                Value::Array(arr.into_iter().map(Self::fix_hash_encoding).collect())
            }
            other => other,
        }
    }

    /// Build the claim.v2 object from scattered manifest properties
    fn build_claim_v2(&self, manifest: &Manifest, label: &str) -> Result<Value> {
        let mut claim_v2 = Map::new();

        // Add dc:title
        if let Some(title) = manifest.title() {
            claim_v2.insert("dc:title".to_string(), json!(title));
        }

        // Add instanceID
        claim_v2.insert("instanceID".to_string(), json!(manifest.instance_id()));

        // Add claim_generator (string, e.g. for V1)
        if let Some(claim_generator) = manifest.claim_generator() {
            claim_v2.insert("claim_generator".to_string(), json!(claim_generator));
        }

        // Add claim_generator_info (full info including name, version, icon) when present.
        // This ensures icons and other generator details are exported to crJSON format.
        if let Some(ref info_vec) = manifest.claim_generator_info {
            if let Ok(info_value) = serde_json::to_value(info_vec) {
                let fixed_info = Self::fix_hash_encoding(info_value);
                claim_v2.insert("claim_generator_info".to_string(), fixed_info);
            }
        }

        // Add algorithm (from data hash assertion if available)
        claim_v2.insert("alg".to_string(), json!("SHA-256"));

        // Add signature reference
        let signature_ref = format!("self#jumbf=/c2pa/{}/c2pa.signature", label);
        claim_v2.insert("signature".to_string(), json!(signature_ref));

        // Build created_assertions and gathered_assertions arrays with hashes from the underlying claim
        let (created_assertions, gathered_assertions) = self.build_assertion_references(manifest, label)?;
        claim_v2.insert("created_assertions".to_string(), created_assertions);
        claim_v2.insert("gathered_assertions".to_string(), gathered_assertions);

        // Add empty array for redacted assertions
        claim_v2.insert("redacted_assertions".to_string(), json!([]));

        Ok(Value::Object(claim_v2))
    }

    /// Build assertion references with hashes from manifest
    /// Returns a tuple of (created_assertions, gathered_assertions) arrays
    fn build_assertion_references(&self, _manifest: &Manifest, label: &str) -> Result<(Value, Value)> {
        // Get the underlying claim to access created_assertions and gathered_assertions separately
        let claim = self.inner.store.get_claim(label)
            .ok_or_else(|| Error::ClaimMissing { label: label.to_owned() })?;

        // Build created_assertions array
        let mut created_refs = Vec::new();
        for assertion_ref in claim.created_assertions() {
            let mut ref_obj = Map::new();
            ref_obj.insert("url".to_string(), json!(assertion_ref.url()));
            let hash = assertion_ref.hash();
            ref_obj.insert("hash".to_string(), json!(base64::encode(&hash)));
            created_refs.push(Value::Object(ref_obj));
        }

        // Build gathered_assertions array if available
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

        // For Claim V1, created_assertions and gathered_assertions will both be empty
        // In that case, populate created_assertions with all assertions (V1 doesn't distinguish)
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

    /// Build claim_signature object with detailed certificate information
    fn build_claim_signature(&self, manifest: &Manifest) -> Result<Option<Value>> {
        let sig_info = match manifest.signature_info() {
            Some(info) => info,
            None => return Ok(None),
        };

        let mut claim_signature = Map::new();

        // Add algorithm
        if let Some(alg) = &sig_info.alg {
            claim_signature.insert("algorithm".to_string(), json!(alg.to_string()));
        }

        // Parse certificate to get detailed DN components and validity
        if let Some(cert_info) = self.parse_certificate(&sig_info.cert_chain)? {
            // Add serial number (hex format)
            if let Some(serial) = cert_info.serial_number {
                claim_signature.insert("serial_number".to_string(), json!(serial));
            }

            // Add issuer DN components
            if let Some(issuer) = cert_info.issuer {
                claim_signature.insert("issuer".to_string(), json!(issuer));
            }

            // Add subject DN components
            if let Some(subject) = cert_info.subject {
                claim_signature.insert("subject".to_string(), json!(subject));
            }

            // Add validity period
            if let Some(validity) = cert_info.validity {
                claim_signature.insert("validity".to_string(), json!(validity));
            }
        }

        Ok(Some(Value::Object(claim_signature)))
    }

    /// Parse certificate to extract DN components and validity
    fn parse_certificate(&self, cert_chain: &str) -> Result<Option<CertificateDetails>> {
        // Parse PEM format certificate chain
        let cert_der = self.parse_pem_to_der(cert_chain)?;
        if cert_der.is_empty() {
            return Ok(None);
        }

        // Parse the first certificate (end entity)
        let (_, cert) = X509Certificate::from_der(&cert_der[0]).map_err(|_e| {
            Error::CoseInvalidCert // Use appropriate error type
        })?;

        let mut details = CertificateDetails::default();

        // Extract serial number in hex format
        details.serial_number = Some(format!("{:x}", cert.serial));

        // Extract issuer DN components
        details.issuer = Some(self.extract_dn_components(cert.issuer())?);

        // Extract subject DN components
        details.subject = Some(self.extract_dn_components(cert.subject())?);

        // Extract validity period
        let not_before = cert.validity().not_before.to_datetime();
        let not_after = cert.validity().not_after.to_datetime();
        // Convert OffsetDateTime to RFC3339 format using chrono
        let not_before_chrono: DateTime<Utc> =
            DateTime::from_timestamp(not_before.unix_timestamp(), 0)
                .ok_or(Error::CoseInvalidCert)?;
        let not_after_chrono: DateTime<Utc> =
            DateTime::from_timestamp(not_after.unix_timestamp(), 0)
                .ok_or(Error::CoseInvalidCert)?;
        details.validity = Some(json!({
            "not_before": not_before_chrono.to_rfc3339(),
            "not_after": not_after_chrono.to_rfc3339()
        }));

        Ok(Some(details))
    }

    /// Extract DN components from X.509 name
    fn extract_dn_components(
        &self,
        name: &x509_parser::x509::X509Name,
    ) -> Result<Map<String, Value>> {
        let mut components = Map::new();

        for rdn in name.iter() {
            for attr in rdn.iter() {
                let oid = attr.attr_type();
                let value = attr.as_str().map_err(|_| Error::CoseInvalidCert)?;

                // Map OIDs to standard abbreviations
                let key = match oid.to_string().as_str() {
                    "2.5.4.6" => "C",   // countryName
                    "2.5.4.8" => "ST",  // stateOrProvinceName
                    "2.5.4.7" => "L",   // localityName
                    "2.5.4.10" => "O",  // organizationName
                    "2.5.4.11" => "OU", // organizationalUnitName
                    "2.5.4.3" => "CN",  // commonName
                    _ => continue,      // Skip unknown OIDs
                };

                components.insert(key.to_string(), json!(value));
            }
        }

        Ok(components)
    }

    /// Parse PEM format certificate chain to DER format
    fn parse_pem_to_der(&self, pem_chain: &str) -> Result<Vec<Vec<u8>>> {
        let mut certs = Vec::new();

        for pem in pem_chain.split("-----BEGIN CERTIFICATE-----") {
            if let Some(end_idx) = pem.find("-----END CERTIFICATE-----") {
                // Extract PEM data and remove all whitespace (newlines, spaces, tabs)
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

    /// Decode cawg.identity signature field (COSE_Sign1) and extract certificate info
    /// Similar to build_claim_signature but for the signature field in cawg.identity assertions
    fn decode_cawg_signature(signature_bytes: &[u8]) -> Result<Value> {
        use coset::{CoseSign1, TaggedCborSerializable};
        use crate::crypto::cose::{cert_chain_from_sign1, signing_alg_from_sign1};

        // Parse COSE_Sign1
        let sign1 = <CoseSign1 as TaggedCborSerializable>::from_tagged_slice(signature_bytes)
            .map_err(|_| Error::CoseSignature)?;

        let mut signature_obj = Map::new();

        // Extract algorithm from protected headers
        if let Ok(alg) = signing_alg_from_sign1(&sign1) {
            signature_obj.insert("algorithm".to_string(), json!(alg.to_string()));
        }

        // Try to extract X.509 certificate chain (for cawg.x509.cose signatures)
        if let Ok(cert_chain) = cert_chain_from_sign1(&sign1) {
            if !cert_chain.is_empty() {
                // Parse the first certificate (end entity)
                if let Ok((_rem, cert)) = X509Certificate::from_der(&cert_chain[0]) {
                    // Extract serial number in hex format
                    signature_obj.insert("serial_number".to_string(), json!(format!("{:x}", cert.serial)));

                    // Extract issuer DN components
                    if let Ok(issuer) = Self::extract_dn_components_static(cert.issuer()) {
                        signature_obj.insert("issuer".to_string(), json!(issuer));
                    }

                    // Extract subject DN components
                    if let Ok(subject) = Self::extract_dn_components_static(cert.subject()) {
                        signature_obj.insert("subject".to_string(), json!(subject));
                    }

                    // Extract validity period
                    let not_before = cert.validity().not_before.to_datetime();
                    let not_after = cert.validity().not_after.to_datetime();
                    
                    if let Some(not_before_chrono) = DateTime::<Utc>::from_timestamp(not_before.unix_timestamp(), 0) {
                        if let Some(not_after_chrono) = DateTime::<Utc>::from_timestamp(not_after.unix_timestamp(), 0) {
                            signature_obj.insert("validity".to_string(), json!({
                                "not_before": not_before_chrono.to_rfc3339(),
                                "not_after": not_after_chrono.to_rfc3339()
                            }));
                        }
                    }
                }
            }
        }
        
        // If no certificate chain was found, try to extract Verifiable Credential
        // (for cawg.identity_claims_aggregation signatures)
        if !signature_obj.contains_key("serial_number") {
            if let Some(payload) = sign1.payload.as_ref() {
                // Try to parse payload as JSON (W3C Verifiable Credential)
                if let Ok(vc_value) = serde_json::from_slice::<Value>(payload) {
                    // Extract issuer (DID)
                    if let Some(issuer) = vc_value.get("issuer") {
                        signature_obj.insert("issuer".to_string(), issuer.clone());
                    }
                    
                    // Extract validity period
                    if let Some(valid_from) = vc_value.get("validFrom") {
                        signature_obj.insert("validFrom".to_string(), valid_from.clone());
                    }
                    if let Some(valid_until) = vc_value.get("validUntil") {
                        signature_obj.insert("validUntil".to_string(), valid_until.clone());
                    }
                    
                    // Extract verified identities from credential subject
                    if let Some(cred_subject) = vc_value.get("credentialSubject") {
                        if let Some(verified_ids) = cred_subject.get("verifiedIdentities") {
                            signature_obj.insert("verifiedIdentities".to_string(), verified_ids.clone());
                        }
                    }
                    
                    // Mark this as an ICA credential
                    signature_obj.insert("credentialType".to_string(), json!("IdentityClaimsAggregation"));
                }
            }
        }

        Ok(Value::Object(signature_obj))
    }

    /// Static version of extract_dn_components for use in decode_cawg_signature
    fn extract_dn_components_static(name: &x509_parser::x509::X509Name) -> Result<Map<String, Value>> {
        let mut components = Map::new();

        for rdn in name.iter() {
            for attr in rdn.iter() {
                let oid = attr.attr_type();
                let value = attr.as_str().map_err(|_| Error::CoseInvalidCert)?;

                // Map OIDs to standard abbreviations
                let key = match oid.to_string().as_str() {
                    "2.5.4.6" => "C",   // countryName
                    "2.5.4.8" => "ST",  // stateOrProvinceName
                    "2.5.4.7" => "L",   // localityName
                    "2.5.4.10" => "O",  // organizationName
                    "2.5.4.11" => "OU", // organizationalUnitName
                    "2.5.4.3" => "CN",  // commonName
                    _ => continue,      // Skip unknown OIDs
                };

                components.insert(key.to_string(), json!(value));
            }
        }

        Ok(components)
    }

    /// Build status object for a manifest
    fn build_manifest_status(&self, manifest: &Manifest, _label: &str) -> Result<Option<Value>> {
        let validation_results = match self.inner.validation_results() {
            Some(results) => results,
            None => return Ok(None),
        };

        let mut status = Map::new();

        // Extract key validation codes from results
        let active_manifest = match validation_results.active_manifest() {
            Some(am) => am,
            None => return Ok(None),
        };

        // Signature validation status
        if let Some(sig_code) =
            Self::find_validation_code(&active_manifest.success, "claimSignature")
        {
            status.insert("signature".to_string(), json!(sig_code));
        }

        // Trust status: prefer trusted, invalid, untrusted, expired; else first signingCredential code
        if let Some(trust_code) =
            Self::find_preferred_trust_code(&active_manifest)
        {
            status.insert("trust".to_string(), json!(trust_code));
        } else if let Some(trust_code) =
            Self::find_validation_code(&active_manifest.success, "signingCredential")
        {
            status.insert("trust".to_string(), json!(trust_code));
        } else if let Some(trust_code) =
            Self::find_validation_code(&active_manifest.failure, "signingCredential")
        {
            status.insert("trust".to_string(), json!(trust_code));
        }

        // Content validation status
        if let Some(content_code) =
            Self::find_validation_code(&active_manifest.success, "assertion.dataHash")
        {
            status.insert("content".to_string(), json!(content_code));
        }

        // Assertion-specific validation codes
        let mut assertion_status = Map::new();
        for assertion in manifest.assertions() {
            let assertion_label = assertion.label();
            if let Some(code) =
                Self::find_validation_code_for_assertion(&active_manifest.success, assertion_label)
            {
                assertion_status.insert(assertion_label.to_string(), json!(code));
            }
        }
        if !assertion_status.is_empty() {
            status.insert("assertion".to_string(), Value::Object(assertion_status));
        }

        Ok(Some(Value::Object(status)))
    }

    /// Find a preferred trust status (trusted, invalid, untrusted, expired) in the active manifest.
    /// Returns the first match in that order; if none found, returns None (caller should fall back
    /// to first signingCredential code).
    fn find_preferred_trust_code(active_manifest: &crate::validation_results::StatusCodes) -> Option<String> {
        // Trusted is in success
        if active_manifest.success.iter().any(|s| s.code() == SIGNING_CREDENTIAL_TRUSTED) {
            return Some(SIGNING_CREDENTIAL_TRUSTED.to_string());
        }
        // Invalid, untrusted, expired are in failure (check in that order)
        for code in &[
            SIGNING_CREDENTIAL_INVALID,
            SIGNING_CREDENTIAL_UNTRUSTED,
            SIGNING_CREDENTIAL_EXPIRED,
        ] {
            if active_manifest.failure.iter().any(|s| s.code() == *code) {
                return Some((*code).to_string());
            }
        }
        None
    }

    /// Find a validation code matching a prefix in a list of validation statuses
    fn find_validation_code(statuses: &[ValidationStatus], prefix: &str) -> Option<String> {
        statuses
            .iter()
            .find(|s| s.code().starts_with(prefix))
            .map(|s| s.code().to_string())
    }

    /// Find validation code for a specific assertion
    fn find_validation_code_for_assertion(
        statuses: &[ValidationStatus],
        assertion_label: &str,
    ) -> Option<String> {
        statuses
            .iter()
            .find(|s| {
                s.url()
                    .map(|u| u.contains(assertion_label))
                    .unwrap_or(false)
            })
            .map(|s| s.code().to_string())
    }

    /// Get a reference to the underlying Reader
    pub fn inner(&self) -> &Reader {
        &self.inner
    }

    /// Get a mutable reference to the underlying Reader
    pub fn inner_mut(&mut self) -> &mut Reader {
        &mut self.inner
    }
}

/// Certificate details extracted from X.509 certificate
#[derive(Debug, Default)]
struct CertificateDetails {
    serial_number: Option<String>,
    issuer: Option<Map<String, Value>>,
    subject: Option<Map<String, Value>>,
    validity: Option<Value>,
}

/// Prints the JSON of the crJSON format manifest data.
impl std::fmt::Display for CrJsonReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.json().as_str())
    }
}

/// Prints the full debug details of the crJSON format manifest data.
impl std::fmt::Debug for CrJsonReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = self.to_json_value().map_err(|_| std::fmt::Error)?;
        let output = serde_json::to_string_pretty(&json).map_err(|_| std::fmt::Error)?;
        f.write_str(&output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_WITH_MANIFEST: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");

    #[test]
    fn test_jpeg_trust_reader_from_stream() -> Result<()> {
        let reader =
            CrJsonReader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_WITH_MANIFEST))?;

        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        Ok(())
    }

    #[test]
    fn test_jpeg_trust_format_json() -> Result<()> {
        let reader =
            CrJsonReader::from_stream("image/jpeg", std::io::Cursor::new(IMAGE_WITH_MANIFEST))?;

        let json_value = reader.to_json_value()?;

        // Verify required fields
        assert!(json_value.get("@context").is_some());
        assert!(json_value.get("manifests").is_some());

        // Verify manifests is an array
        assert!(json_value["manifests"].is_array());

        // Verify first manifest structure (required: label, assertions, signature, status; oneOf: claim or claim.v2)
        if let Some(manifest) = json_value["manifests"].as_array().and_then(|a| a.first()) {
            assert!(manifest.get("label").is_some());
            assert!(manifest.get("assertions").is_some());
            assert!(manifest.get("signature").is_some());
            assert!(manifest.get("status").is_some());
            assert!(manifest.get("claim.v2").is_some());

            // Verify assertions is an object (not array)
            assert!(manifest["assertions"].is_object());

            // Verify claim.v2 has expected fields
            let claim_v2 = &manifest["claim.v2"];
            assert!(claim_v2.get("instanceID").is_some());
            assert!(claim_v2.get("signature").is_some());
            assert!(claim_v2.get("created_assertions").is_some());
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_cr_json_reader_from_file() -> Result<()> {
        let reader = CrJsonReader::from_file("tests/fixtures/CA.jpg")?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);

        let json = reader.json();
        assert!(json.contains("@context"));
        assert!(json.contains("manifests"));

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_claim_signature_decoding() -> Result<()> {
        // Test that signature (manifest-level) is decoded with full certificate details
        let reader = CrJsonReader::from_file("tests/fixtures/CA.jpg")?;

        let json_value = reader.to_json_value()?;
        let manifests = json_value["manifests"].as_array().unwrap();
        // Every manifest has required "signature"; find one with decoded certificate details
        let manifest = manifests
            .iter()
            .find(|m| m.get("signature").and_then(|s| s.get("algorithm")).is_some());
        assert!(
            manifest.is_some(),
            "Should have a manifest with signature containing algorithm"
        );

        let sig = &manifest.unwrap()["signature"];

        // Verify algorithm is present
        assert!(sig.get("algorithm").is_some(), "signature should have algorithm");

        // Verify certificate details are decoded (not just algorithm)
        // Should have serial_number, issuer, subject, and validity for X.509 certificates
        assert!(
            sig.get("serial_number").is_some(),
            "signature should have serial_number from decoded certificate"
        );
        assert!(
            sig.get("issuer").is_some(),
            "signature should have issuer from decoded certificate"
        );
        assert!(
            sig.get("subject").is_some(),
            "signature should have subject from decoded certificate"
        );
        assert!(
            sig.get("validity").is_some(),
            "signature should have validity from decoded certificate"
        );

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_cawg_identity_x509_signature_decoding() -> Result<()> {
        // Test that cawg.identity with X.509 signature is fully decoded
        let reader = CrJsonReader::from_file("tests/fixtures/C_with_CAWG_data.jpg")?;

        let json_value = reader.to_json_value()?;
        let manifests = json_value["manifests"].as_array().unwrap();
        
        // Find the manifest and its cawg.identity assertion
        let manifest = &manifests[0];
        let assertions = manifest["assertions"].as_object().unwrap();
        
        let cawg_identity = assertions.get("cawg.identity");
        assert!(cawg_identity.is_some(), "Should have cawg.identity assertion");
        
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
        assert!(signature.is_object(), "signature should be an object, not an array");
        
        // For X.509 signatures (sig_type: cawg.x509.cose), verify certificate details
        let sig_type = cawg_identity["signer_payload"]["sig_type"].as_str().unwrap();
        if sig_type == "cawg.x509.cose" {
            assert!(
                signature.get("algorithm").is_some(),
                "signature should have algorithm"
            );
            assert!(
                signature.get("serial_number").is_some(),
                "X.509 signature should have serial_number"
            );
            assert!(
                signature.get("issuer").is_some(),
                "X.509 signature should have issuer DN components"
            );
            assert!(
                signature.get("subject").is_some(),
                "X.509 signature should have subject DN components"
            );
            assert!(
                signature.get("validity").is_some(),
                "X.509 signature should have validity period"
            );
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_cawg_identity_ica_signature_decoding() -> Result<()> {
        // Test that cawg.identity with ICA signature extracts VC information
        // Note: This test uses a fixture from the identity tests
        let test_image = include_bytes!("identity/tests/fixtures/claim_aggregation/adobe_connected_identities.jpg");

        let reader = CrJsonReader::from_stream("image/jpeg", std::io::Cursor::new(&test_image[..]))?;

        let json_value = reader.to_json_value()?;
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
            let cawg_identity_key = assertions.keys().find(|k| k.starts_with("cawg.identity")).unwrap();
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
            let sig_type = cawg_identity["signer_payload"]["sig_type"].as_str().unwrap();
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
            eprintln!("Skipping test_claim_generator_info_with_icon_exported: fixture not found at {:?}", path);
            return Ok(());
        }

        let reader = CrJsonReader::from_file(path)?;
        let json_value = reader.to_json_value()?;

        let manifests = json_value["manifests"]
            .as_array()
            .expect("manifests should be an array");
        let manifest = manifests
            .first()
            .expect("should have at least one manifest");

        let claim_v2 = manifest
            .get("claim.v2")
            .expect("claim.v2 should be present");

        let claim_generator_info = claim_v2
            .get("claim_generator_info")
            .expect("claim.v2 should include claim_generator_info when manifest has an icon");

        let info_arr = claim_generator_info
            .as_array()
            .expect("claim_generator_info should be an array");
        assert!(
            !info_arr.is_empty(),
            "claim_generator_info should have at least one entry"
        );

        // At least one entry should have an icon. Icon may be serialized as:
        // - ResourceRef { format, identifier } (when resolved from HashedUri in reader), or
        // - HashedUri { url, alg?, hash } with hash as base64 string (not byte array)
        let has_icon = info_arr.iter().any(|entry| {
            let icon = match entry.get("icon") {
                Some(icon) => icon,
                None => return false,
            };
            // If icon has "hash" (HashedUri), it must be a base64 string after fix_hash_encoding
            if let Some(hash) = icon.get("hash") {
                return hash.is_string();
            }
            // ResourceRef has format and identifier
            icon.get("format").is_some() && icon.get("identifier").is_some()
        });

        assert!(
            has_icon,
            "claim_generator_info should include an entry with icon (ResourceRef or HashedUri with base64 hash)"
        );

        Ok(())
    }
}
