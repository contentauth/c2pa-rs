// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(missing_docs)]

//! Holds Rust struct definitions for various ASN.1 primitives.

// This code is copied from a subset of version 0.22.0 of the
// cryptographic-message-syntax crate located at:
// https://github.com/indygreg/cryptography-rs/tree/main/cryptographic-message-syntax/src/asn1

// We can not incorporate the entire crate directly because it relies on x509-certificate which
// relies on ring.

// Migrating fully from bcder to der will eliminate the need for much of this code.

use std::io::Write;

use bcder::{
    decode::{Constructed, DecodeError, Source},
    encode::{self, PrimitiveContent, Values},
    Captured, Mode, Oid, Tag,
};
// Use der crate for time types to avoid custom date parsing
use der::{Decode, Encode};

// Common ASN.1 types shared across multiple RFCs

/// Helper function to reconstruct DER encoding from primitive content
/// (tag + length + content bytes)
pub(crate) fn reconstruct_der_bytes(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut der_bytes = Vec::with_capacity(2 + content.len());
    der_bytes.push(tag);
    der_bytes.push(content.len() as u8); // length (assumes < 128)
    der_bytes.extend_from_slice(content);
    der_bytes
}

/// Helper function to extract string content from DER bytes
/// DER format: tag (1 byte) + length (1 byte) + content
fn extract_der_content(der_bytes: &[u8]) -> &str {
    if der_bytes.len() >= 2 {
        let length = der_bytes[1] as usize;
        if length < 128 && der_bytes.len() >= 2 + length {
            if let Ok(s) = std::str::from_utf8(&der_bytes[2..2 + length]) {
                return s;
            }
        }
    }
    ""
}

/// Algorithm identifier for use with bcder
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmIdentifier {
    /// The algorithm OID
    pub algorithm: Oid,
}

impl AlgorithmIdentifier {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let algorithm = Oid::take_from(cons)?;
            // Skip any remaining content (parameters) - we only need the algorithm OID
            let _params = cons.capture_all();

            Ok(Self { algorithm })
        })
    }

    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| {
            let algorithm = Oid::take_from(cons)?;
            let _params = cons.capture_all();
            Ok(Self { algorithm })
        })
    }
}

impl Values for AlgorithmIdentifier {
    fn encoded_len(&self, mode: Mode) -> usize {
        encode::sequence(self.algorithm.encode_ref()).encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        encode::sequence(self.algorithm.encode_ref()).write_encoded(mode, target)
    }
}

/// Extensions for use with bcder  
#[derive(Clone, Debug)]
pub struct Extensions(Captured);

impl PartialEq for Extensions {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for Extensions {}

impl Extensions {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_constructed_if(Tag::SEQUENCE, |cons| cons.capture_all().map(Extensions))
    }

    pub fn encode_ref_as(&self, tag: Tag) -> Captured {
        Captured::from_values(Mode::Der, self.0.clone().encode_as(tag))
    }
}

/// General name for use with bcder
#[derive(Clone, Debug)]
pub struct GeneralName(Captured);

impl PartialEq for GeneralName {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for GeneralName {}

impl GeneralName {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.capture_all().map(GeneralName)
    }
}

impl PrimitiveContent for GeneralName {
    const TAG: Tag = Tag::CTX_0;

    fn encoded_len(&self, mode: Mode) -> usize {
        self.0.encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.0.write_encoded(mode, target)
    }
}

/// Generalized time structure - hybrid bcder/der approach
/// Uses der crate's GeneralizedTime internally for proper time handling
#[derive(Clone, Debug)]
pub struct GeneralizedTime {
    // Store the der type for proper time parsing
    der_time: der::asn1::GeneralizedTime,
    // Cache the DER encoding for bcder compatibility
    der_bytes: Vec<u8>,
}

impl PartialEq for GeneralizedTime {
    fn eq(&self, other: &Self) -> bool {
        self.der_time == other.der_time
    }
}

impl Eq for GeneralizedTime {}

impl std::fmt::Display for GeneralizedTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format the time string manually from DER bytes
        write!(f, "{}", self.as_str())
    }
}

impl GeneralizedTime {
    /// Create from der::asn1::GeneralizedTime
    pub fn from_der_time(der_time: der::asn1::GeneralizedTime) -> Result<Self, der::Error> {
        let mut der_bytes = Vec::new();
        der_time.encode_to_vec(&mut der_bytes)?;
        Ok(Self {
            der_time,
            der_bytes,
        })
    }

    /// Parse from DER bytes (for bcder compatibility)
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        let der_time = der::asn1::GeneralizedTime::from_der(bytes)?;
        Ok(Self {
            der_time,
            der_bytes: bytes.to_vec(),
        })
    }

    /// Get DER encoding for bcder
    pub fn as_der_bytes(&self) -> &[u8] {
        &self.der_bytes
    }

    /// Get the underlying der time
    pub fn as_der_time(&self) -> &der::asn1::GeneralizedTime {
        &self.der_time
    }

    /// Parse from bcder Constructed (allows fractional seconds and Z)
    pub fn take_from_allow_fractional_z<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        // Capture the raw DER bytes
        let captured = cons.capture_one()?;
        let bytes = captured.as_slice();

        // Parse with der crate - it will properly validate the time format
        Self::from_der_bytes(bytes).map_err(|_| cons.content_err("invalid GeneralizedTime"))
    }

    /// Parse from bcder Primitive (no fractional or timezone offsets)
    pub fn from_primitive_no_fractional_or_timezone_offsets<S: bcder::decode::Source>(
        prim: &mut bcder::decode::Primitive<S>,
    ) -> Result<Self, bcder::decode::DecodeError<S::Error>> {
        let bytes = prim.take_all()?;
        // Reconstruct DER encoding using helper (tag 0x18 = GENERALIZED_TIME)
        let der_bytes = reconstruct_der_bytes(0x18, bytes.as_ref());
        // Parse with der crate - it will properly validate the time format
        Self::from_der_bytes(&der_bytes)
            .map_err(|_| bcder::decode::DecodeError::content("invalid GeneralizedTime", prim.pos()))
    }

    /// Encode for bcder
    pub fn encode_ref(&self) -> Captured {
        // Return the raw DER bytes as a Captured value
        // These bytes already include tag, length, and content
        Captured::from_values(Mode::Der, bcder::OctetString::encode_slice(&self.der_bytes))
    }

    /// Get time string representation (for compatibility)
    pub fn as_str(&self) -> &str {
        extract_der_content(&self.der_bytes)
    }
}

impl From<GeneralizedTime> for chrono::DateTime<chrono::Utc> {
    fn from(gt: GeneralizedTime) -> Self {
        // Use der's conversion to SystemTime, then to chrono
        let system_time = gt.der_time.to_system_time();
        system_time.into()
    }
}

// impl From cannot return Result; conversions should never fail for valid dates
#[allow(clippy::expect_used)]
impl From<chrono::DateTime<chrono::Utc>> for GeneralizedTime {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        // Convert chrono to SystemTime, then to der's GeneralizedTime
        #[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
        let system_time: std::time::SystemTime = dt.into();

        #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
        let system_time: std::time::SystemTime = {
            let timestamp = dt.timestamp();
            let nanos = dt.timestamp_subsec_nanos();
            std::time::UNIX_EPOCH + std::time::Duration::new(timestamp as u64, nanos)
        };

        // Create GeneralizedTime from SystemTime
        // This should never fail for valid dates (der crate supports dates from 1970-2255)
        let der_time = der::asn1::GeneralizedTime::from_system_time(system_time)
            .expect("Failed to create GeneralizedTime from valid DateTime");

        // Convert to our wrapper type
        // Encoding should never fail for a valid GeneralizedTime
        Self::from_der_time(der_time).expect("Failed to encode GeneralizedTime (internal error)")
    }
}

#[allow(dead_code)]
pub mod rfc3161;
#[allow(dead_code)]
pub mod rfc3281;
#[allow(dead_code)]
pub mod rfc4210;
#[allow(dead_code)]
pub mod rfc5652;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]
    use bcder::{decode::Constructed, encode::Values, Mode, Oid};

    use super::*;

    // Helper to load test certificate
    fn load_test_cert_pem(name: &str) -> Vec<u8> {
        let path = format!("tests/fixtures/certs/{}", name);
        std::fs::read(&path).unwrap_or_else(|_| panic!("Failed to read test certificate: {}", path))
    }

    // Helper to parse PEM and extract DER certificate
    fn extract_cert_der_from_pem(pem_data: &[u8]) -> Vec<u8> {
        // Use the pem crate to parse
        let pems = pem::parse_many(pem_data).expect("Failed to parse PEM data");

        // Find the first certificate
        for p in pems {
            if p.tag() == "CERTIFICATE" {
                return p.contents().to_vec();
            }
        }

        panic!("No certificate found in PEM data");
    }

    #[test]
    fn test_algorithm_identifier_encoding() {
        // SHA-256 OID: 2.16.840.1.101.3.4.2.1
        let sha256_bytes = bytes::Bytes::from_static(&[96, 134, 72, 1, 101, 3, 4, 2, 1]);
        let sha256_oid = Oid(sha256_bytes.clone());
        let alg_id = AlgorithmIdentifier {
            algorithm: sha256_oid.clone(),
        };

        // Encode and verify
        let mut encoded = Vec::new();
        alg_id.write_encoded(Mode::Der, &mut encoded).unwrap();

        assert!(!encoded.is_empty());

        // Decode and verify round-trip
        let decoded = Constructed::decode(encoded.as_slice(), Mode::Der, |cons| {
            AlgorithmIdentifier::take_from(cons)
        })
        .unwrap();

        assert_eq!(decoded.algorithm.as_ref(), sha256_oid.as_ref());
    }

    #[test]
    fn test_algorithm_identifier_with_es256_cert() {
        // Load ES256 certificate to verify ECDSA-SHA256 algorithm handling
        let pem_data = load_test_cert_pem("es256.pub");
        let cert_der = extract_cert_der_from_pem(&pem_data);

        // Verify we got valid DER data (X.509 cert starts with SEQUENCE tag 0x30)
        assert!(!cert_der.is_empty(), "Certificate DER should not be empty");
        assert_eq!(
            cert_der[0], 0x30,
            "Certificate should start with SEQUENCE tag"
        );

        // Create an AlgorithmIdentifier manually from known ECDSA-SHA256 OID
        // (which the es256 cert uses)
        let ecdsa_sha256_oid = bytes::Bytes::from_static(&[
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, // 1.2.840.10045.4.3.2
        ]);
        let alg_id = AlgorithmIdentifier {
            algorithm: Oid(ecdsa_sha256_oid.clone()),
        };

        // Verify we can encode and decode it
        let mut encoded = Vec::new();
        alg_id.write_encoded(Mode::Der, &mut encoded).unwrap();

        let decoded = Constructed::decode(encoded.as_slice(), Mode::Der, |cons| {
            AlgorithmIdentifier::take_from(cons)
        })
        .unwrap();

        // Verify round-trip works
        assert_eq!(alg_id.algorithm.as_ref(), decoded.algorithm.as_ref());
    }

    #[test]
    fn test_algorithm_identifier_with_es384_cert() {
        // Load ES384 certificate to verify ECDSA-SHA384 algorithm handling
        let pem_data = load_test_cert_pem("es384.pub");
        let cert_der = extract_cert_der_from_pem(&pem_data);

        assert!(!cert_der.is_empty());
        assert_eq!(cert_der[0], 0x30);

        // ECDSA-SHA384 OID: 1.2.840.10045.4.3.3
        let ecdsa_sha384_oid =
            bytes::Bytes::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);
        let alg_id = AlgorithmIdentifier {
            algorithm: Oid(ecdsa_sha384_oid.clone()),
        };

        let mut encoded = Vec::new();
        alg_id.write_encoded(Mode::Der, &mut encoded).unwrap();

        let decoded = Constructed::decode(encoded.as_slice(), Mode::Der, |cons| {
            AlgorithmIdentifier::take_from(cons)
        })
        .unwrap();

        assert_eq!(alg_id.algorithm.as_ref(), decoded.algorithm.as_ref());
    }

    #[test]
    fn test_algorithm_identifier_with_es512_cert() {
        // Load ES512 certificate to verify ECDSA-SHA512 algorithm handling
        let pem_data = load_test_cert_pem("es512.pub");
        let cert_der = extract_cert_der_from_pem(&pem_data);

        assert!(!cert_der.is_empty());
        assert_eq!(cert_der[0], 0x30);

        // ECDSA-SHA512 OID: 1.2.840.10045.4.3.4
        let ecdsa_sha512_oid =
            bytes::Bytes::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]);
        let alg_id = AlgorithmIdentifier {
            algorithm: Oid(ecdsa_sha512_oid.clone()),
        };

        let mut encoded = Vec::new();
        alg_id.write_encoded(Mode::Der, &mut encoded).unwrap();

        let decoded = Constructed::decode(encoded.as_slice(), Mode::Der, |cons| {
            AlgorithmIdentifier::take_from(cons)
        })
        .unwrap();

        assert_eq!(alg_id.algorithm.as_ref(), decoded.algorithm.as_ref());
    }

    #[test]
    fn test_algorithm_identifier_with_rsa_pss_cert() {
        // Load PS256 certificate to verify RSA-PSS algorithm handling
        let pem_data = load_test_cert_pem("ps256.pub");
        let cert_der = extract_cert_der_from_pem(&pem_data);

        assert!(!cert_der.is_empty());
        assert_eq!(cert_der[0], 0x30);

        // RSA-PSS OID: 1.2.840.113549.1.1.10
        let rsa_pss_oid =
            bytes::Bytes::from_static(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]);
        let alg_id = AlgorithmIdentifier {
            algorithm: Oid(rsa_pss_oid.clone()),
        };

        let mut encoded = Vec::new();
        alg_id.write_encoded(Mode::Der, &mut encoded).unwrap();

        let decoded = Constructed::decode(encoded.as_slice(), Mode::Der, |cons| {
            AlgorithmIdentifier::take_from(cons)
        })
        .unwrap();

        assert_eq!(alg_id.algorithm.as_ref(), decoded.algorithm.as_ref());
    }

    #[test]
    fn test_algorithm_identifier_with_ed25519_cert() {
        // Load Ed25519 certificate to verify EdDSA algorithm handling
        let pem_data = load_test_cert_pem("ed25519.pub");
        let cert_der = extract_cert_der_from_pem(&pem_data);

        assert!(!cert_der.is_empty());
        assert_eq!(cert_der[0], 0x30);

        // Ed25519 OID: 1.3.101.112
        let ed25519_oid = bytes::Bytes::from_static(&[0x2b, 0x65, 0x70]);
        let alg_id = AlgorithmIdentifier {
            algorithm: Oid(ed25519_oid.clone()),
        };

        let mut encoded = Vec::new();
        alg_id.write_encoded(Mode::Der, &mut encoded).unwrap();

        let decoded = Constructed::decode(encoded.as_slice(), Mode::Der, |cons| {
            AlgorithmIdentifier::take_from(cons)
        })
        .unwrap();

        assert_eq!(alg_id.algorithm.as_ref(), decoded.algorithm.as_ref());
    }

    #[test]
    fn test_algorithm_identifier_with_rsa_cert() {
        // Load RS256 certificate to verify standard RSA algorithm handling
        let pem_data = load_test_cert_pem("rs256.pub");
        let cert_der = extract_cert_der_from_pem(&pem_data);

        assert!(!cert_der.is_empty());
        assert_eq!(cert_der[0], 0x30);

        // SHA256withRSA OID: 1.2.840.113549.1.1.11
        let sha256_rsa_oid =
            bytes::Bytes::from_static(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
        let alg_id = AlgorithmIdentifier {
            algorithm: Oid(sha256_rsa_oid.clone()),
        };

        let mut encoded = Vec::new();
        alg_id.write_encoded(Mode::Der, &mut encoded).unwrap();

        let decoded = Constructed::decode(encoded.as_slice(), Mode::Der, |cons| {
            AlgorithmIdentifier::take_from(cons)
        })
        .unwrap();

        assert_eq!(alg_id.algorithm.as_ref(), decoded.algorithm.as_ref());
    }

    #[test]
    fn test_generalized_time_from_chrono() {
        use chrono::{Datelike, TimeZone, Timelike, Utc};

        // Create a known timestamp: 2023-01-15 12:30:45 UTC
        let dt = Utc.with_ymd_and_hms(2023, 1, 15, 12, 30, 45).unwrap();

        // Convert to GeneralizedTime
        let gt = GeneralizedTime::from(dt);

        // Verify the time string format (should be "20230115123045Z")
        let time_str = gt.as_str();
        assert!(time_str.starts_with("20230115"));
        assert!(time_str.contains("123045"));

        // Convert back to chrono and verify
        let dt_back: chrono::DateTime<chrono::Utc> = gt.into();
        assert_eq!(dt_back.year(), 2023);
        assert_eq!(dt_back.month(), 1);
        assert_eq!(dt_back.day(), 15);
        assert_eq!(dt_back.hour(), 12);
        assert_eq!(dt_back.minute(), 30);
        assert_eq!(dt_back.second(), 45);
    }

    #[test]
    fn test_generalized_time_from_der_bytes() {
        // Load a real certificate to verify it contains valid time data
        let pem_data = load_test_cert_pem("es256.pub");
        let cert_der = extract_cert_der_from_pem(&pem_data);

        // Verify we got valid DER data
        assert!(!cert_der.is_empty(), "Certificate DER should not be empty");

        // Create a GeneralizedTime from a known timestamp and test roundtrip
        use chrono::{Datelike, TimeZone, Utc};
        let test_time = Utc.with_ymd_and_hms(2022, 6, 10, 18, 46, 40).unwrap();
        let gt = GeneralizedTime::from(test_time);

        // Get DER bytes and parse them back
        let der_bytes = gt.as_der_bytes();
        let gt_parsed = GeneralizedTime::from_der_bytes(der_bytes).unwrap();

        // Verify they match
        assert_eq!(gt, gt_parsed);

        // Convert back to DateTime
        let dt_back: chrono::DateTime<chrono::Utc> = gt_parsed.into();
        assert_eq!(dt_back.year(), 2022);
        assert_eq!(dt_back.month(), 6);
        assert_eq!(dt_back.day(), 10);
    }

    #[test]
    fn test_generalized_time_with_multiple_cert_types() {
        // Test that we can load and parse certificates with different algorithms
        // This verifies the der/bcder integration works across all supported cert types
        use chrono::{TimeZone, Utc};

        let cert_types = vec![
            "es256.pub",
            "es384.pub",
            "es512.pub",
            "ps256.pub",
            "rs256.pub",
            "ed25519.pub",
        ];

        for cert_name in cert_types {
            // Load the certificate
            let pem_data = load_test_cert_pem(cert_name);
            let cert_der = extract_cert_der_from_pem(&pem_data);

            // Verify we got valid DER data for each cert type
            assert!(
                !cert_der.is_empty(),
                "Certificate {} DER should not be empty",
                cert_name
            );
            assert_eq!(
                cert_der[0], 0x30,
                "Certificate {} should start with SEQUENCE tag",
                cert_name
            );
        }

        // Test GeneralizedTime roundtrip with a timestamp
        let test_time = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let gt = GeneralizedTime::from(test_time);
        let der_bytes = gt.as_der_bytes();
        let gt_parsed = GeneralizedTime::from_der_bytes(der_bytes).unwrap();
        assert_eq!(gt, gt_parsed);
    }

    #[test]
    fn test_generalized_time_invalid_der() {
        // Invalid format - should fail
        let invalid_der = vec![0x18, 0x05, b't', b'e', b's', b't', b'!'];
        assert!(GeneralizedTime::from_der_bytes(&invalid_der).is_err());
    }

    #[test]
    fn test_generalized_time_encode_decode_roundtrip() {
        use chrono::{TimeZone, Utc};

        let original_dt = Utc.with_ymd_and_hms(2025, 10, 29, 14, 30, 0).unwrap();
        let gt1 = GeneralizedTime::from(original_dt);

        // Get the DER bytes directly
        let der_bytes = gt1.as_der_bytes();

        // Decode from DER bytes
        let decoded = GeneralizedTime::from_der_bytes(der_bytes).unwrap();

        // Verify equality
        assert_eq!(gt1, decoded);

        // Also verify conversion back to chrono works
        let dt_back: chrono::DateTime<chrono::Utc> = decoded.into();
        // Times should be close (within 1 second due to potential precision loss)
        let diff = if original_dt > dt_back {
            original_dt.signed_duration_since(dt_back)
        } else {
            dt_back.signed_duration_since(original_dt)
        };
        assert!(diff.num_seconds().abs() <= 1);
    }

    #[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
    #[test]
    fn test_generalized_time_from_system_time() {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        // Create a SystemTime 1 day after epoch
        let system_time = UNIX_EPOCH + Duration::from_secs(86400);

        // Convert to chrono, then to GeneralizedTime
        let dt: chrono::DateTime<chrono::Utc> = system_time.into();
        let gt = GeneralizedTime::from(dt);

        // Convert back and verify
        let dt_back: chrono::DateTime<chrono::Utc> = gt.into();
        let system_time_back: SystemTime = dt_back.into();

        // Should be within 1 second (due to potential precision loss)
        let diff = system_time_back
            .duration_since(system_time)
            .unwrap_or_else(|_| system_time.duration_since(system_time_back).unwrap());
        assert!(diff.as_secs() < 1);
    }
}
