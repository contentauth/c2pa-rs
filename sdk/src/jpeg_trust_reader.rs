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

//! JPEG Trust format exporter for C2PA manifests.
//!
//! This module provides a Reader-like API that exports C2PA manifests in the
//! JPEG Trust format as described in the JPEG Trust specification.

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
    context::Context,
    crypto::base64,
    error::{Error, Result},
    reader::{AsyncPostValidator, MaybeSend, PostValidator, Reader},
    utils::hash_utils::hash_stream_by_alg,
    validation_results::ValidationState,
    validation_status::ValidationStatus,
    Manifest,
};

/// Use a JpegTrustReader to read and validate a manifest store in JPEG Trust format.
#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
#[derive(Default)]
pub struct JpegTrustReader {
    #[serde(skip)]
    inner: Reader,

    /// Optional asset hash computed from the original asset
    #[serde(skip)]
    asset_hash: Option<AssetHash>,
}

/// Represents the hash of an asset
#[derive(Debug, Clone)]
struct AssetHash {
    algorithm: String,
    hash: String,
}

impl JpegTrustReader {
    /// Create a new JpegTrustReader with the given [`Context`].
    pub fn from_context(context: Context) -> Self {
        Self {
            inner: Reader::from_context(context),
            asset_hash: None,
        }
    }

    /// Create a new JpegTrustReader with a shared [`Context`].
    pub fn from_shared_context(context: &Arc<Context>) -> Self {
        Self {
            inner: Reader::from_shared_context(context),
            asset_hash: None,
        }
    }

    /// Add manifest store from a stream to the [`JpegTrustReader`]
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

    /// Create a JPEG Trust format [`JpegTrustReader`] from a stream.
    #[async_generic]
    pub fn from_stream(format: &str, stream: impl Read + Seek + MaybeSend) -> Result<Self> {
        if _sync {
            Ok(Self {
                inner: Reader::from_stream(format, stream)?,
                asset_hash: None,
            })
        } else {
            Ok(Self {
                inner: Reader::from_stream_async(format, stream).await?,
                asset_hash: None,
            })
        }
    }

    /// Add manifest store from a file to the [`JpegTrustReader`].
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

    /// Create a JPEG Trust format [`JpegTrustReader`] from a file.
    #[cfg(feature = "file_io")]
    #[async_generic]
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        if _sync {
            Ok(Self {
                inner: Reader::from_file(path)?,
                asset_hash: None,
            })
        } else {
            Ok(Self {
                inner: Reader::from_file_async(path).await?,
                asset_hash: None,
            })
        }
    }

    /// Add manifest store from existing `c2pa_data` and a stream to the [`JpegTrustReader`].
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

    /// Create a JPEG Trust format [`JpegTrustReader`] from existing `c2pa_data` and a stream.
    #[async_generic]
    pub fn from_manifest_data_and_stream(
        c2pa_data: &[u8],
        format: &str,
        stream: impl Read + Seek + MaybeSend,
    ) -> Result<Self> {
        if _sync {
            Ok(Self {
                inner: Reader::from_manifest_data_and_stream(c2pa_data, format, stream)?,
                asset_hash: None,
            })
        } else {
            Ok(Self {
                inner: Reader::from_manifest_data_and_stream_async(c2pa_data, format, stream)
                    .await?,
                asset_hash: None,
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

    /// Returns the remote url of the manifest if this [`JpegTrustReader`] obtained the manifest remotely.
    pub fn remote_url(&self) -> Option<&str> {
        self.inner.remote_url()
    }

    /// Returns if the [`JpegTrustReader`] was created from an embedded manifest.
    pub fn is_embedded(&self) -> bool {
        self.inner.is_embedded()
    }

    /// Get the [`ValidationState`] of the manifest store.
    pub fn validation_state(&self) -> ValidationState {
        self.inner.validation_state()
    }

    /// Convert the reader to a JPEG Trust format JSON value.
    pub fn to_json_value(&self) -> Result<Value> {
        let mut result = json!({
            "@context": {
                "@vocab": "https://jpeg.org/jpegtrust",
                "extras": "https://jpeg.org/jpegtrust/extras"
            }
        });

        // Add asset_info if we have computed the hash
        if let Some(asset_info) = self.get_asset_hash_json() {
            result["asset_info"] = asset_info;
        }

        // Convert manifests from HashMap to Array
        let manifests_array = self.convert_manifests_to_array()?;
        result["manifests"] = manifests_array;

        // Add content (typically empty)
        result["content"] = json!({});

        // Add metadata if available
        if let Some(metadata) = self.extract_metadata()? {
            result["metadata"] = metadata;
        }

        // Add extras:validation_status
        if let Some(validation_status) = self.build_validation_status()? {
            result["extras:validation_status"] = validation_status;
        }

        Ok(result)
    }

    /// Get the JpegTrustReader as a JSON string
    pub fn json(&self) -> String {
        match self.to_json_value() {
            Ok(value) => serde_json::to_string_pretty(&value).unwrap_or_default(),
            Err(_) => "{}".to_string(),
        }
    }

    /// Compute and store the asset hash from a stream.
    ///
    /// This method computes the SHA-256 hash of the asset and stores it for inclusion
    /// in the JPEG Trust format output. The stream will be rewound to the beginning
    /// before computing the hash.
    ///
    /// # Arguments
    /// * `stream` - A readable and seekable stream containing the asset data
    ///
    /// # Returns
    /// The computed hash as a base64-encoded string
    ///
    /// # Example
    /// ```no_run
    /// # use c2pa::{JpegTrustReader, Result};
    /// # fn main() -> Result<()> {
    /// use std::fs::File;
    ///
    /// let mut reader = JpegTrustReader::from_file("image.jpg")?;
    /// 
    /// // Compute hash from the same file
    /// let mut file = File::open("image.jpg")?;
    /// let hash = reader.compute_asset_hash(&mut file)?;
    /// 
    /// // Now the JSON output will include asset_info
    /// let json = reader.json();
    /// # Ok(())
    /// # }
    /// ```
    pub fn compute_asset_hash(&mut self, stream: &mut (impl Read + Seek)) -> Result<String> {
        // Rewind to the beginning
        stream.rewind()?;

        // Compute SHA-256 hash of the entire stream
        let hash = hash_stream_by_alg("sha256", stream, None, true)?;
        let hash_b64 = base64::encode(&hash);

        // Store for later use
        self.asset_hash = Some(AssetHash {
            algorithm: "sha256".to_string(),
            hash: hash_b64.clone(),
        });

        Ok(hash_b64)
    }

    /// Compute and store the asset hash from a file.
    ///
    /// This is a convenience method that opens the file and computes its hash.
    ///
    /// # Arguments
    /// * `path` - Path to the asset file
    ///
    /// # Returns
    /// The computed hash as a base64-encoded string
    ///
    /// # Example
    /// ```no_run
    /// # use c2pa::{JpegTrustReader, Result};
    /// # fn main() -> Result<()> {
    /// let mut reader = JpegTrustReader::from_file("image.jpg")?;
    /// let hash = reader.compute_asset_hash_from_file("image.jpg")?;
    /// println!("Asset hash: {}", hash);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "file_io")]
    pub fn compute_asset_hash_from_file<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
    ) -> Result<String> {
        let mut file = std::fs::File::open(path)?;
        self.compute_asset_hash(&mut file)
    }

    /// Set the asset hash directly without computing it.
    ///
    /// This method allows you to provide a pre-computed hash, which can be useful
    /// if you've already computed the hash elsewhere or want to use a different
    /// algorithm.
    ///
    /// # Arguments
    /// * `algorithm` - The hash algorithm used (e.g., "sha256")
    /// * `hash` - The base64-encoded hash value
    ///
    /// # Example
    /// ```no_run
    /// # use c2pa::{JpegTrustReader, Result};
    /// # fn main() -> Result<()> {
    /// let mut reader = JpegTrustReader::from_file("image.jpg")?;
    /// reader.set_asset_hash("sha256", "JPkcXXC5DfT9IUUBPK5UaKxGsJ8YIE67BayL+ei3ats=");
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_asset_hash(&mut self, algorithm: &str, hash: &str) {
        self.asset_hash = Some(AssetHash {
            algorithm: algorithm.to_string(),
            hash: hash.to_string(),
        });
    }

    /// Get the currently stored asset hash, if any.
    ///
    /// # Returns
    /// A tuple of (algorithm, hash) if the hash has been set, or None
    pub fn asset_hash(&self) -> Option<(&str, &str)> {
        self.asset_hash
            .as_ref()
            .map(|h| (h.algorithm.as_str(), h.hash.as_str()))
    }

    /// Get asset hash info for JSON output
    fn get_asset_hash_json(&self) -> Option<Value> {
        self.asset_hash.as_ref().map(|h| {
            json!({
                "alg": h.algorithm,
                "hash": h.hash
            })
        })
    }

    /// Convert manifests from HashMap to Array format
    fn convert_manifests_to_array(&self) -> Result<Value> {
        let mut manifests_array = Vec::new();

        for (label, manifest) in self.inner.manifests() {
            let mut manifest_obj = Map::new();
            manifest_obj.insert("label".to_string(), json!(label));

            // Convert assertions from array to object
            let assertions_obj = self.convert_assertions(manifest)?;
            manifest_obj.insert("assertions".to_string(), json!(assertions_obj));

            // Build claim.v2 object
            let claim_v2 = self.build_claim_v2(manifest, label)?;
            manifest_obj.insert("claim.v2".to_string(), claim_v2);

            // Build claim_signature object
            if let Some(claim_signature) = self.build_claim_signature(manifest)? {
                manifest_obj.insert("claim_signature".to_string(), claim_signature);
            }

            // Build status object
            if let Some(status) = self.build_manifest_status(manifest, label)? {
                manifest_obj.insert("status".to_string(), status);
            }

            manifests_array.push(Value::Object(manifest_obj));
        }

        Ok(Value::Array(manifests_array))
    }

    /// Convert assertions from array format to object format (keyed by label)
    fn convert_assertions(&self, manifest: &Manifest) -> Result<Map<String, Value>> {
        let mut assertions_obj = Map::new();

        for assertion in manifest.assertions() {
            let label = assertion.label().to_string();
            if let Ok(value) = assertion.value() {
                assertions_obj.insert(label, value.clone());
            }
        }

        Ok(assertions_obj)
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

        // Add claim_generator
        if let Some(claim_generator) = manifest.claim_generator() {
            claim_v2.insert("claim_generator".to_string(), json!(claim_generator));
        }

        // Add algorithm (from data hash assertion if available)
        claim_v2.insert("alg".to_string(), json!("SHA-256"));

        // Add signature reference
        let signature_ref = format!("self#jumbf=/c2pa/{}/c2pa.signature", label);
        claim_v2.insert("signature".to_string(), json!(signature_ref));

        // Build created_assertions array with hashes
        let created_assertions = self.build_assertion_references(manifest, label)?;
        claim_v2.insert("created_assertions".to_string(), created_assertions);

        // Add empty arrays for gathered and redacted assertions
        claim_v2.insert("gathered_assertions".to_string(), json!([]));
        claim_v2.insert("redacted_assertions".to_string(), json!([]));

        Ok(Value::Object(claim_v2))
    }

    /// Build assertion references with hashes from manifest
    fn build_assertion_references(&self, manifest: &Manifest, _label: &str) -> Result<Value> {
        let mut references = Vec::new();

        for assertion_ref in manifest.assertion_references() {
            let mut ref_obj = Map::new();
            ref_obj.insert("url".to_string(), json!(assertion_ref.url()));
            // hash() returns Vec<u8>, not Option<Vec<u8>>
            let hash = assertion_ref.hash();
            ref_obj.insert("hash".to_string(), json!(base64::encode(&hash)));
            references.push(Value::Object(ref_obj));
        }

        Ok(Value::Array(references))
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
        let not_before_chrono: DateTime<Utc> = DateTime::from_timestamp(not_before.unix_timestamp(), 0)
            .ok_or(Error::CoseInvalidCert)?;
        let not_after_chrono: DateTime<Utc> = DateTime::from_timestamp(not_after.unix_timestamp(), 0)
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
                    "2.5.4.6" => "C",      // countryName
                    "2.5.4.8" => "ST",     // stateOrProvinceName
                    "2.5.4.7" => "L",      // localityName
                    "2.5.4.10" => "O",     // organizationName
                    "2.5.4.11" => "OU",    // organizationalUnitName
                    "2.5.4.3" => "CN",     // commonName
                    _ => continue,         // Skip unknown OIDs
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
                let pem_data = pem[..end_idx].trim();
                if let Ok(der) = base64::decode(pem_data) {
                    certs.push(der);
                }
            }
        }

        Ok(certs)
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
        if let Some(sig_code) = Self::find_validation_code(&active_manifest.success, "claimSignature")
        {
            status.insert("signature".to_string(), json!(sig_code));
        }

        // Trust status
        if let Some(trust_code) = Self::find_validation_code(&active_manifest.success, "signingCredential")
        {
            status.insert("trust".to_string(), json!(trust_code));
        } else if let Some(trust_code) =
            Self::find_validation_code(&active_manifest.failure, "signingCredential")
        {
            status.insert("trust".to_string(), json!(trust_code));
        }

        // Content validation status
        if let Some(content_code) = Self::find_validation_code(&active_manifest.success, "assertion.dataHash")
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
            .find(|s| s.url().map(|u| u.contains(assertion_label)).unwrap_or(false))
            .map(|s| s.code().to_string())
    }

    /// Extract metadata from manifest (placeholder - not fully available)
    fn extract_metadata(&self) -> Result<Option<Value>> {
        // TODO: This would require extracting EXIF/XMP metadata from the asset
        // which is not currently available from the Reader API.
        Ok(None)
    }

    /// Build extras:validation_status from validation results
    fn build_validation_status(&self) -> Result<Option<Value>> {
        let validation_results = match self.inner.validation_results() {
            Some(results) => results,
            None => return Ok(None),
        };

        let mut validation_status = Map::new();

        // Determine overall validity
        let is_valid = validation_results.validation_state() != ValidationState::Invalid;
        validation_status.insert("isValid".to_string(), json!(is_valid));

        // Add error field (null if valid, or first error message if not)
        let error_message = if !is_valid {
            if let Some(active_manifest) = validation_results.active_manifest() {
                active_manifest
                    .failure
                    .first()
                    .and_then(|s| s.explanation())
                    .map(|e| Value::String(e.to_string()))
                    .unwrap_or(Value::Null)
            } else {
                Value::Null
            }
        } else {
            Value::Null
        };
        validation_status.insert("error".to_string(), error_message);

        // Build validationErrors array from failures (as objects with code, message, severity)
        let mut errors = Vec::new();
        if let Some(active_manifest) = validation_results.active_manifest() {
            for status in active_manifest.failure.iter() {
                let mut error_obj = Map::new();
                error_obj.insert("code".to_string(), json!(status.code()));
                if let Some(explanation) = status.explanation() {
                    error_obj.insert("message".to_string(), json!(explanation));
                }
                error_obj.insert("severity".to_string(), json!("error"));
                errors.push(Value::Object(error_obj));
            }
        }
        validation_status.insert("validationErrors".to_string(), json!(errors));

        // Build entries array from all validation statuses
        let mut entries = Vec::new();

        if let Some(active_manifest) = validation_results.active_manifest() {
            // Add success entries
            for status in active_manifest.success.iter() {
                entries.push(self.build_validation_entry(status, "info")?);
            }

            // Add informational entries
            for status in active_manifest.informational.iter() {
                entries.push(self.build_validation_entry(status, "warning")?);
            }

            // Add failure entries
            for status in active_manifest.failure.iter() {
                entries.push(self.build_validation_entry(status, "error")?);
            }
        }

        validation_status.insert("entries".to_string(), json!(entries));

        Ok(Some(Value::Object(validation_status)))
    }

    /// Build a single validation entry for the entries array
    fn build_validation_entry(&self, status: &ValidationStatus, severity: &str) -> Result<Value> {
        let mut entry = Map::new();
        entry.insert("code".to_string(), json!(status.code()));
        if let Some(url) = status.url() {
            entry.insert("url".to_string(), json!(url));
        }
        if let Some(explanation) = status.explanation() {
            entry.insert("explanation".to_string(), json!(explanation));
        }
        entry.insert("severity".to_string(), json!(severity));
        Ok(Value::Object(entry))
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

/// Prints the JSON of the JPEG Trust format manifest data.
impl std::fmt::Display for JpegTrustReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.json().as_str())
    }
}

/// Prints the full debug details of the JPEG Trust format manifest data.
impl std::fmt::Debug for JpegTrustReader {
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
        let reader = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        assert_eq!(reader.validation_state(), ValidationState::Trusted);
        Ok(())
    }

    #[test]
    fn test_jpeg_trust_format_json() -> Result<()> {
        let reader = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        let json_value = reader.to_json_value()?;

        // Verify required fields
        assert!(json_value.get("@context").is_some());
        assert!(json_value.get("manifests").is_some());

        // Verify manifests is an array
        assert!(json_value["manifests"].is_array());

        // Verify first manifest structure
        if let Some(manifest) = json_value["manifests"].as_array().and_then(|a| a.first()) {
            assert!(manifest.get("label").is_some());
            assert!(manifest.get("assertions").is_some());
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
    fn test_jpeg_trust_reader_from_file() -> Result<()> {
        let reader = JpegTrustReader::from_file("tests/fixtures/CA.jpg")?;
        assert_eq!(reader.validation_state(), ValidationState::Trusted);

        let json = reader.json();
        assert!(json.contains("@context"));
        assert!(json.contains("manifests"));

        Ok(())
    }

    #[test]
    fn test_compute_asset_hash_from_stream() -> Result<()> {
        // Create reader
        let mut reader = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        // Initially no asset hash
        assert!(reader.asset_hash().is_none());

        // Compute hash from stream
        let mut stream = std::io::Cursor::new(IMAGE_WITH_MANIFEST);
        let hash = reader.compute_asset_hash(&mut stream)?;

        // Verify hash was computed
        assert!(!hash.is_empty());
        assert!(reader.asset_hash().is_some());

        // Verify hash is accessible
        let (alg, stored_hash) = reader.asset_hash().unwrap();
        assert_eq!(alg, "sha256");
        assert_eq!(stored_hash, hash);

        // Verify JSON output includes asset_info
        let json_value = reader.to_json_value()?;
        assert!(json_value.get("asset_info").is_some());

        let asset_info = &json_value["asset_info"];
        assert_eq!(asset_info["alg"], "sha256");
        assert_eq!(asset_info["hash"], hash);

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_compute_asset_hash_from_file() -> Result<()> {
        // Create reader
        let mut reader = JpegTrustReader::from_file("tests/fixtures/CA.jpg")?;

        // Compute hash from same file
        let hash = reader.compute_asset_hash_from_file("tests/fixtures/CA.jpg")?;

        // Verify hash was computed
        assert!(!hash.is_empty());
        assert!(reader.asset_hash().is_some());

        // Verify JSON includes asset_info
        let json_value = reader.to_json_value()?;
        assert!(json_value.get("asset_info").is_some());

        let asset_info = &json_value["asset_info"];
        assert_eq!(asset_info["alg"], "sha256");
        assert_eq!(asset_info["hash"], hash);

        Ok(())
    }

    #[test]
    fn test_set_asset_hash_directly() -> Result<()> {
        // Create reader
        let mut reader = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        // Set hash directly
        let test_hash = "JPkcXXC5DfT9IUUBPK5UaKxGsJ8YIE67BayL+ei3ats=";
        reader.set_asset_hash("sha256", test_hash);

        // Verify hash is set
        let (alg, hash) = reader.asset_hash().unwrap();
        assert_eq!(alg, "sha256");
        assert_eq!(hash, test_hash);

        // Verify JSON includes asset_info
        let json_value = reader.to_json_value()?;
        let asset_info = &json_value["asset_info"];
        assert_eq!(asset_info["alg"], "sha256");
        assert_eq!(asset_info["hash"], test_hash);

        Ok(())
    }

    #[test]
    fn test_asset_hash_consistency() -> Result<()> {
        // Create two readers from the same data
        let mut reader1 = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        let mut reader2 = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        // Compute hashes
        let mut stream1 = std::io::Cursor::new(IMAGE_WITH_MANIFEST);
        let hash1 = reader1.compute_asset_hash(&mut stream1)?;

        let mut stream2 = std::io::Cursor::new(IMAGE_WITH_MANIFEST);
        let hash2 = reader2.compute_asset_hash(&mut stream2)?;

        // Hashes should be identical
        assert_eq!(hash1, hash2);

        Ok(())
    }

    #[test]
    fn test_json_without_asset_hash() -> Result<()> {
        // Create reader without computing hash
        let reader = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        // JSON should not include asset_info
        let json_value = reader.to_json_value()?;
        assert!(json_value.get("asset_info").is_none());

        Ok(())
    }

    #[test]
    fn test_json_with_asset_hash() -> Result<()> {
        // Create reader and compute hash
        let mut reader = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        let mut stream = std::io::Cursor::new(IMAGE_WITH_MANIFEST);
        reader.compute_asset_hash(&mut stream)?;

        // JSON should include asset_info
        let json_value = reader.to_json_value()?;
        assert!(json_value.get("asset_info").is_some());

        // Verify structure
        let asset_info = &json_value["asset_info"];
        assert!(asset_info.get("alg").is_some());
        assert!(asset_info.get("hash").is_some());

        Ok(())
    }

    #[test]
    fn test_asset_hash_update() -> Result<()> {
        // Create reader
        let mut reader = JpegTrustReader::from_stream(
            "image/jpeg",
            std::io::Cursor::new(IMAGE_WITH_MANIFEST),
        )?;

        // Set initial hash
        reader.set_asset_hash("sha256", "hash1");
        assert_eq!(reader.asset_hash().unwrap().1, "hash1");

        // Update hash
        reader.set_asset_hash("sha512", "hash2");
        let (alg, hash) = reader.asset_hash().unwrap();
        assert_eq!(alg, "sha512");
        assert_eq!(hash, "hash2");

        Ok(())
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_asset_hash_with_different_files() -> Result<()> {
        // Test with two different files
        let mut reader1 = JpegTrustReader::from_file("tests/fixtures/CA.jpg")?;
        let hash1 = reader1.compute_asset_hash_from_file("tests/fixtures/CA.jpg")?;

        let mut reader2 = JpegTrustReader::from_file("tests/fixtures/C.jpg")?;
        let hash2 = reader2.compute_asset_hash_from_file("tests/fixtures/C.jpg")?;

        // Different files should have different hashes
        assert_ne!(hash1, hash2);

        Ok(())
    }
}

