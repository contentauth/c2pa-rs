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
use chrono::{TimeZone, Timelike};
// Use der crate for time types to avoid custom date parsing
use der::{Decode, Encode};

// Common ASN.1 types shared across multiple RFCs

/// Helper function to reconstruct DER encoding from primitive content
/// (tag + length + content bytes)
///
/// Uses the `der` crate's `Header` type to ensure proper DER length encoding,
/// including support for long-form lengths (>= 128 bytes).
///
/// # Errors
///
/// Returns an error if:
/// - The tag value is invalid for DER encoding
/// - The content length exceeds the maximum supported by DER encoding
/// - The header cannot be encoded
pub(crate) fn reconstruct_der_bytes(tag: u8, content: &[u8]) -> Result<Vec<u8>, der::Error> {
    // Use der crate's Header which handles both short and long form length encoding
    let der_tag = der::Tag::try_from(tag)?;
    let header = der::Header::new(der_tag, content.len())?;

    // Encode the header (tag + length)
    let mut der_bytes = Vec::new();
    header.encode_to_vec(&mut der_bytes)?;
    der_bytes.extend_from_slice(content);
    Ok(der_bytes)
}

/// Helper function to extract string content from DER bytes
/// DER format: tag (1 byte) + length (variable) + content
///
/// Uses the `der` crate's `Header::decode()` and `SliceReader` to properly parse
/// DER-encoded data, supporting both short-form (< 128 bytes) and long-form (>= 128 bytes)
/// length encoding automatically.
///
/// # Errors
///
/// Returns an error if:
/// - The buffer is too short to contain a valid DER structure
/// - The DER header is malformed
/// - The content is not valid UTF-8
fn extract_der_content(der_bytes: &[u8]) -> Result<&str, der::Error> {
    // Use der crate to decode the header (tag + length)
    let mut reader = der::SliceReader::new(der_bytes)?;
    let header = der::Header::decode(&mut reader)?;

    // Get the content portion - header.encoded_len() gives a Length we need to convert
    let header_len: usize = header.encoded_len()?.try_into()?;
    let content_len: usize = header.length.try_into()?;

    if der_bytes.len() < header_len + content_len {
        Err(der::Tag::GeneralizedTime.length_error())?;
    }

    // Extract and validate UTF-8
    std::str::from_utf8(&der_bytes[header_len..header_len + content_len])
        .map_err(|_| der::Tag::Utf8String.value_error())
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
    /// Parse Extensions for IMPLICIT tagging context.
    ///
    /// This method is used when Extensions appears with IMPLICIT tagging (e.g., `[0] IMPLICIT Extensions`),
    /// where the SEQUENCE tag is replaced by the context-specific tag. The caller has already
    /// entered the context-specific tag, so we just capture the content directly.
    ///
    /// In RFC 3161, Extensions always appears with IMPLICIT tagging:
    /// - TimeStampReq: `extensions [0] IMPLICIT Extensions OPTIONAL`
    /// - TstInfo: `extensions [1] IMPLICIT Extensions OPTIONAL`
    pub fn from_constructed<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.capture_all().map(Extensions)
    }

    pub fn encode_ref_as(&self, tag: Tag) -> Captured {
        Captured::from_values(Mode::Der, self.0.clone().encode_as(tag))
    }
}

/// General name for use with bcder
///
/// Note: GeneralName is a CHOICE type (not a SEQUENCE), so it doesn't need separate
/// `from_constructed` and `take_from` methods. It can use the same implementation
/// for both IMPLICIT and EXPLICIT tagging contexts.
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
    // Store the der type for proper time parsing (without fractional seconds)
    der_time: der::asn1::GeneralizedTime,
    // Cache the DER encoding for bcder compatibility (may include fractional seconds)
    der_bytes: Vec<u8>,
    // Store nanoseconds separately to preserve fractional seconds from RFC 3161
    // (der::asn1::GeneralizedTime doesn't support fractional seconds per RFC 5280)
    nanoseconds: u32,
}

impl PartialEq for GeneralizedTime {
    fn eq(&self, other: &Self) -> bool {
        self.der_time == other.der_time && self.nanoseconds == other.nanoseconds
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
            nanoseconds: 0, // RFC 5280 GeneralizedTime has no fractional seconds
        })
    }

    /// Parse from DER bytes (for bcder compatibility) - RFC 5280 strict
    ///
    /// This enforces RFC 5280 rules: no fractional seconds allowed.
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, der::Error> {
        let der_time = der::asn1::GeneralizedTime::from_der(bytes)?;
        Ok(Self {
            der_time,
            der_bytes: bytes.to_vec(),
            nanoseconds: 0, // RFC 5280 has no fractional seconds
        })
    }

    /// Parse from DER bytes allowing fractional seconds (RFC 3161 compliant)
    ///
    /// RFC 3161 allows fractional seconds in GeneralizedTime, unlike RFC 5280.
    /// Format: YYYYMMDDHHmmss[.f*]Z
    /// Examples:
    ///   - "20231115183045Z" (no fractional, RFC 5280 compatible)
    ///   - "20231115183045.5Z" (half second)
    ///   - "20231115183045.643Z" (643 milliseconds)
    ///
    /// Real-world example from test data: "20251121125823.643Z"
    pub fn from_der_bytes_rfc3161(bytes: &[u8]) -> Result<Self, der::Error> {
        // First, try the strict RFC 5280 parser (for compatibility with times without fractions)
        if let Ok(result) = Self::from_der_bytes(bytes) {
            return Ok(result);
        }

        // If that fails, manually parse to allow fractional seconds
        // DER format: Tag (0x18) + Length + Content
        if bytes.len() < 2 {
            return Err(der::Tag::GeneralizedTime.length_error());
        }

        if bytes[0] != 0x18 {
            // 0x18 = GENERALIZED_TIME tag
            return Err(der::Tag::GeneralizedTime.value_error());
        }

        let length = bytes[1] as usize;
        if bytes.len() != length + 2 {
            return Err(der::Tag::GeneralizedTime.length_error());
        }

        let content = &bytes[2..];
        let time_str =
            std::str::from_utf8(content).map_err(|_| der::Tag::Utf8String.value_error())?;

        // Parse RFC 3161 format: YYYYMMDDHHmmss[.f*]Z
        // Minimum length: 15 chars (YYYYMMDDHHmmssZ)
        if time_str.len() < 15 || !time_str.ends_with('Z') {
            return Err(der::Tag::GeneralizedTime.value_error());
        }

        // Extract components
        let year = time_str
            .get(0..4)
            .and_then(|s| s.parse::<i32>().ok())
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?;
        let month = time_str
            .get(4..6)
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?;
        let day = time_str
            .get(6..8)
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?;
        let hour = time_str
            .get(8..10)
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?;
        let minute = time_str
            .get(10..12)
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?;
        let second = time_str
            .get(12..14)
            .and_then(|s| s.parse::<u32>().ok())
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?;

        // Parse fractional seconds if present (between position 14 and 'Z')
        let frac_part = &time_str[14..time_str.len() - 1]; // Everything between seconds and 'Z'
        let nanoseconds = if !frac_part.is_empty() {
            // Should start with a dot
            if !frac_part.starts_with('.') {
                return Err(der::Tag::GeneralizedTime.value_error());
            }

            let frac_digits = &frac_part[1..]; // Remove leading dot
            if frac_digits.is_empty() || !frac_digits.chars().all(|c| c.is_ascii_digit()) {
                return Err(der::Tag::GeneralizedTime.value_error());
            }

            // Convert fractional seconds to nanoseconds
            // The fractional part represents digits after the decimal point
            // e.g., ".5" = 0.5 seconds = 500000000 nanoseconds
            //       ".643" = 0.643 seconds = 643000000 nanoseconds
            // We need to pad with trailing zeros, not leading zeros
            let mut frac_str = frac_digits.to_string();
            // Pad to 9 digits with trailing zeros
            while frac_str.len() < 9 {
                frac_str.push('0');
            }
            // Truncate if longer than 9 digits
            frac_str.truncate(9);

            frac_str
                .parse::<u32>()
                .map_err(|_| der::Tag::GeneralizedTime.value_error())?
        } else {
            0
        };

        // Create a chrono DateTime
        let dt = chrono::Utc
            .with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?
            .with_nanosecond(nanoseconds)
            .ok_or_else(|| der::Tag::GeneralizedTime.value_error())?;

        // Convert to SystemTime for der crate compatibility
        let system_time: std::time::SystemTime = dt.into();

        // Create der::asn1::GeneralizedTime (this will lose fractional seconds in re-encoding)
        let der_time = der::asn1::GeneralizedTime::from_system_time(system_time)
            .map_err(|_| der::Tag::GeneralizedTime.value_error())?;

        // Store the original DER bytes to preserve fractional seconds
        Ok(Self {
            der_time,
            der_bytes: bytes.to_vec(),
            nanoseconds, // Store the parsed fractional seconds
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

    /// Parse from bcder Constructed (allows fractional seconds and Z per RFC 3161)
    ///
    /// RFC 3161 Section 2.4.2 states:
    /// "The ASN.1 GeneralizedTime syntax can include fraction-of-second details.
    ///  Such syntax, without the restrictions from [RFC 2459] Section 4.1.2.5.2,
    ///  where GeneralizedTime is limited to represent the time with a granularity
    ///  of one second, may be used here."
    ///
    /// This means we must accept formats like: "20231115183045.123Z"
    /// whereas RFC 5280 only allows: "20231115183045Z"
    pub fn take_from_allow_fractional_z<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        // Capture the raw DER bytes including tag and length
        let captured = cons.capture_one()?;
        let bytes = captured.as_slice();

        // Try parsing with RFC 3161-compliant parser (allows fractional seconds)
        Self::from_der_bytes_rfc3161(bytes).map_err(|_| cons.content_err("invalid GeneralizedTime"))
    }

    /// Parse from bcder Primitive (no fractional or timezone offsets)
    ///
    /// This is used by CMS Time structures (RFC 5652) which use strict DER encoding.
    #[allow(dead_code)] // Used by rfc5652::Time::take_from
    pub fn from_primitive_no_fractional_or_timezone_offsets<S: bcder::decode::Source>(
        prim: &mut bcder::decode::Primitive<S>,
    ) -> Result<Self, bcder::decode::DecodeError<S::Error>> {
        let bytes = prim.take_all()?;
        // Reconstruct DER encoding using helper (tag 0x18 = GENERALIZED_TIME)
        let der_bytes = reconstruct_der_bytes(0x18, bytes.as_ref()).map_err(|_| {
            bcder::decode::DecodeError::content("failed to reconstruct DER bytes", prim.pos())
        })?;
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
    ///
    /// Returns an empty string if the DER bytes cannot be decoded.
    /// This should never fail for valid GeneralizedTime instances.
    pub fn as_str(&self) -> &str {
        extract_der_content(&self.der_bytes).unwrap_or("")
    }
}

impl From<GeneralizedTime> for chrono::DateTime<chrono::Utc> {
    fn from(gt: GeneralizedTime) -> Self {
        // Use der's conversion to SystemTime, then to chrono
        let system_time = gt.der_time.to_system_time();
        let mut dt: chrono::DateTime<chrono::Utc> = system_time.into();

        // Add the fractional seconds that were parsed but not stored in der_time
        // (der::asn1::GeneralizedTime doesn't support fractional seconds per RFC 5280)
        if gt.nanoseconds > 0 {
            // with_nanosecond can only fail if nanoseconds >= 1_000_000_000,
            // but we validated this during parsing in from_der_bytes_rfc3161
            if let Some(dt_with_nanos) = dt.with_nanosecond(gt.nanoseconds) {
                dt = dt_with_nanos;
            }
            // If with_nanosecond fails, we silently use the time without fractional seconds
            // rather than panicking, as the timestamp is still valid
        }

        dt
    }
}

// impl From cannot return Result; conversions should never fail for valid dates
#[allow(clippy::expect_used)]
impl From<chrono::DateTime<chrono::Utc>> for GeneralizedTime {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        // Convert chrono to SystemTime, then to der's GeneralizedTime
        let system_time: std::time::SystemTime = dt.into();

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
    fn test_reconstruct_der_bytes_short_form() {
        // Test short form length encoding (< 128 bytes)
        let content = b"20231215120000Z"; // 15 bytes
        let der_bytes = reconstruct_der_bytes(0x18, content).unwrap();

        // Should be: tag (0x18) + length (0x0F = 15) + content (15 bytes)
        assert_eq!(der_bytes[0], 0x18, "Tag should be GeneralizedTime");
        assert_eq!(der_bytes[1], 0x0f, "Length should be 15 in short form");
        assert_eq!(
            der_bytes.len(),
            1 + 1 + 15,
            "Total length should be tag + len + content"
        );
        assert_eq!(&der_bytes[2..], content);
    }

    #[test]
    fn test_reconstruct_der_bytes_long_form() {
        // Test long form length encoding (>= 128 bytes)
        // Create content that's exactly 128 bytes
        let content = vec![b'X'; 128];
        let der_bytes = reconstruct_der_bytes(0x18, &content).unwrap();

        // Long form: tag (0x18) + length_encoding + content
        // For length 128: 0x81 0x80 (1 byte to encode the length, value 128)
        assert_eq!(der_bytes[0], 0x18, "Tag should be GeneralizedTime");
        assert_eq!(
            der_bytes[1], 0x81,
            "Should use long form with 1 byte for length"
        );
        assert_eq!(der_bytes[2], 0x80, "Length value should be 128");
        assert_eq!(
            der_bytes.len(),
            1 + 2 + 128,
            "Total length should be tag + length_encoding(2) + content"
        );
        assert_eq!(&der_bytes[3..], &content[..]);
    }

    #[test]
    fn test_reconstruct_der_bytes_very_long() {
        // Test with 256 bytes (requires 2 bytes for length in long form)
        let content = vec![b'Y'; 256];
        let der_bytes = reconstruct_der_bytes(0x18, &content).unwrap();

        // For length 256: 0x82 0x01 0x00 (2 bytes to encode the length, value 256)
        assert_eq!(der_bytes[0], 0x18, "Tag should be GeneralizedTime");
        assert_eq!(
            der_bytes[1], 0x82,
            "Should use long form with 2 bytes for length"
        );
        assert_eq!(der_bytes[2], 0x01, "Length high byte should be 1");
        assert_eq!(der_bytes[3], 0x00, "Length low byte should be 0");
        assert_eq!(
            der_bytes.len(),
            1 + 3 + 256,
            "Total length should be tag + length_encoding(3) + content"
        );
        assert_eq!(&der_bytes[4..], &content[..]);
    }

    #[test]
    fn test_reconstruct_der_bytes_invalid_tag() {
        // Test that invalid tags return an error
        let content = b"test";
        let result = reconstruct_der_bytes(0xff, content);
        assert!(result.is_err(), "Should fail with invalid tag");
    }

    #[test]
    fn test_extract_der_content_short_form() {
        // Test short form length encoding (< 128 bytes)
        // Tag 0x18 (GeneralizedTime), length 15, then content
        let der_bytes = vec![
            0x18, 0x0f, // tag + length (15 bytes)
            b'2', b'0', b'2', b'3', b'1', b'2', b'1', b'5', b'1', b'2', b'0', b'0', b'0', b'0',
            b'Z',
        ];

        let content = extract_der_content(&der_bytes).unwrap();
        assert_eq!(content, "20231215120000Z");
    }

    #[test]
    fn test_extract_der_content_long_form() {
        // Test long form length encoding (>= 128 bytes)
        // Create 128 bytes of content
        let mut content_bytes = vec![b'X'; 128];

        // Build DER: tag + long-form length + content
        let mut der_bytes = vec![
            0x18, // GeneralizedTime tag
            0x81, // Long form: 1 byte for length
            0x80, // Length value: 128
        ];
        der_bytes.append(&mut content_bytes);

        let content = extract_der_content(&der_bytes).unwrap();
        assert_eq!(content.len(), 128);
        assert_eq!(content, "X".repeat(128));
    }

    #[test]
    fn test_extract_der_content_very_long_form() {
        // Test with 256 bytes (2 bytes for length encoding)
        let mut content_bytes = vec![b'Y'; 256];

        let mut der_bytes = vec![
            0x18, // GeneralizedTime tag
            0x82, // Long form: 2 bytes for length
            0x01, 0x00, // Length value: 256
        ];
        der_bytes.append(&mut content_bytes);

        let content = extract_der_content(&der_bytes).unwrap();
        assert_eq!(content.len(), 256);
        assert_eq!(content, "Y".repeat(256));
    }

    #[test]
    fn test_extract_der_content_buffer_too_short() {
        // Buffer with only 1 byte
        let der_bytes = vec![0x18];
        assert!(extract_der_content(&der_bytes).is_err());

        // Length claims more data than available
        let der_bytes = vec![0x18, 0x10, b't', b'e', b's', b't'];
        assert!(extract_der_content(&der_bytes).is_err());
    }

    #[test]
    fn test_extract_der_content_invalid_utf8() {
        // Valid DER structure but invalid UTF-8
        let der_bytes = vec![0x18, 0x02, 0xff, 0xfe];
        assert!(extract_der_content(&der_bytes).is_err());
    }

    #[test]
    fn test_extract_der_content_invalid_long_form() {
        // Long form with 0 length bytes (0x80)
        let der_bytes = vec![0x18, 0x80, b't', b'e', b's', b't'];
        assert!(extract_der_content(&der_bytes).is_err());

        // Long form with too many length bytes (> 4)
        let der_bytes = vec![0x18, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(extract_der_content(&der_bytes).is_err());
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

    /// Test Extensions::from_constructed() with IMPLICIT tagging
    ///
    /// RFC 3161 specifies:  extensions [1] IMPLICIT Extensions OPTIONAL
    ///
    /// With IMPLICIT tagging, the SEQUENCE tag is REPLACED by the context tag.
    /// This test validates that from_constructed() correctly parses the content
    /// without expecting an inner SEQUENCE tag.
    ///
    /// ## Test Data Generation
    ///
    /// The DER data below was manually crafted according to ASN.1 DER encoding rules
    /// and can be validated using standard ASN.1 tools:
    ///
    /// ```bash
    /// # Verify with openssl asn1parse
    /// echo "300B300906032A0304040205 00" | xxd -r -p | openssl asn1parse -inform DER
    /// # Should show: SEQUENCE, SEQUENCE, OBJECT, OCTET STRING
    ///
    /// # Or with Python pyasn1:
    /// from pyasn1.codec.der import decoder
    /// from pyasn1_modules import rfc5280
    /// data = bytes.fromhex("300B300906032A030404020500")
    /// decoded, _ = decoder.decode(data, asn1Spec=rfc5280.Extensions())
    /// print(decoded[0]['extnID'])  # Should print: 1.2.3.4
    /// ```
    ///
    /// The IMPLICIT variant simply replaces the outer SEQUENCE tag (0x30) with [1] (0xA1).
    #[test]
    fn test_extensions_implicit_tagging() {
        use bcder::decode::Constructed;

        // Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
        // One Extension with OID 1.2.3.4 and NULL extnValue
        //
        // DER structure (hex: 300B300906032A030404020500):
        //   30 0b           SEQUENCE (11 bytes) - Extensions
        //      30 09        SEQUENCE (9 bytes) - Extension
        //         06 03     OBJECT IDENTIFIER (3 bytes)
        //            2a 03 04  = 1.2.3.4 (OID encoding: 40*1+2, 3, 4)
        //         04 02     OCTET STRING (2 bytes) - extnValue
        //            05 00  DER NULL
        const EXTENSIONS_DER: &[u8] = &[
            0x30, 0x0b, // SEQUENCE (11 bytes)
            0x30, 0x09, //   SEQUENCE (9 bytes) - Extension
            0x06, 0x03, 0x2a, 0x03, 0x04, //     OID 1.2.3.4
            0x04, 0x02, 0x05, 0x00, //     OCTET STRING containing NULL
        ];

        // Same Extensions with [1] IMPLICIT tagging (RFC 3161 format)
        // The outer SEQUENCE tag (0x30) is REPLACED by context tag [1] (0xA1)
        //
        // DER structure (hex: A10B300906032A030404020500):
        //   A1 0b           [1] IMPLICIT (11 bytes) - replaces SEQUENCE tag
        //      30 09        SEQUENCE (9 bytes) - Extension
        //         06 03     OBJECT IDENTIFIER (3 bytes)
        //            2a 03 04  = 1.2.3.4
        //         04 02     OCTET STRING (2 bytes)
        //            05 00  NULL
        const EXTENSIONS_IMPLICIT: &[u8] = &[
            0xa1, 0x0b, // [1] IMPLICIT (11 bytes)
            0x30, 0x09, //   SEQUENCE (9 bytes) - Extension
            0x06, 0x03, 0x2a, 0x03, 0x04, //     OID 1.2.3.4
            0x04, 0x02, 0x05, 0x00, //     OCTET STRING containing NULL
        ];

        // Test 1: Parse normal Extensions with SEQUENCE tag (baseline)
        let extensions_explicit = Constructed::decode(EXTENSIONS_DER, bcder::Mode::Der, |cons| {
            cons.take_constructed_if(Tag::SEQUENCE, |cons| cons.capture_all().map(Extensions))
        })
        .expect("Failed to parse Extensions with SEQUENCE tag");

        assert!(!extensions_explicit.0.as_slice().is_empty());

        // Test 2: Parse Extensions with IMPLICIT [1] tagging using from_constructed()
        // This is how RFC 3161 uses it: extensions [1] IMPLICIT Extensions
        let extensions_implicit =
            Constructed::decode(EXTENSIONS_IMPLICIT, bcder::Mode::Der, |cons| {
                cons.take_opt_constructed_if(Tag::CTX_1, Extensions::from_constructed)
            })
            .expect("Failed to parse Extensions with IMPLICIT tagging");

        assert!(
            extensions_implicit.is_some(),
            "Extensions should be present"
        );
        let extensions_implicit = extensions_implicit.unwrap();
        assert!(!extensions_implicit.0.as_slice().is_empty());

        // Verify the tag is CTX_1, not SEQUENCE
        let (tag, _) =
            bcder::Tag::take_from(&mut bcder::decode::SliceSource::new(EXTENSIONS_IMPLICIT))
                .expect("Failed to read tag");
        assert_eq!(
            tag,
            Tag::CTX_1,
            "First tag should be CTX_1 (0xA1), not SEQUENCE"
        );
    }

    /// Test GeneralName::take_from() with RFC 3161 TstInfo context
    ///
    /// In RFC 3161, GeneralName is used as: tsa [0] GeneralName OPTIONAL
    ///
    /// GeneralName is a CHOICE type from RFC 5280 with multiple alternatives,
    /// each having its own IMPLICIT tag. This test validates parsing GeneralName
    /// as it appears in the TstInfo structure with [0] EXPLICIT wrapping.
    ///
    /// ## Test Data Generation
    ///
    /// The DER data was generated using openssl and validated:
    ///
    /// ```bash
    /// # Inner GeneralName (dNSName [2]):
    /// echo "821574696d657374616d702e6578616d706c652e636f6d" | xxd -r -p | \
    ///   openssl asn1parse -inform DER -dump
    ///
    /// # Wrapped in [0] EXPLICIT for TstInfo:
    /// echo "A0178215...6d" | xxd -r -p | openssl asn1parse -inform DER -dump
    /// # Shows: [0] { [2] "timestamp.example.com" }
    /// ```
    #[test]
    fn test_general_name_in_tstinfo_context() {
        use bcder::decode::Constructed;

        // GeneralName with dNSName [2] IMPLICIT IA5String
        // Wrapped in [0] EXPLICIT as used in RFC 3161 TstInfo
        //
        // DER structure:
        //   A0 17     [0] EXPLICIT (23 bytes) - TstInfo's tsa context tag
        //      82 15  [2] IMPLICIT (21 bytes) - dNSName
        //         74 69 6d 65 73 74 61 6d 70 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d
        //         = "timestamp.example.com"
        const TSA_GENERAL_NAME_DNS: &[u8] = &[
            0xa0, 0x17, // [0] EXPLICIT (23 bytes)
            0x82, 0x15, //   [2] IMPLICIT dNSName (21 bytes)
            0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "timestamp.example.com"
        ];

        // GeneralName with URI [6] IMPLICIT IA5String
        // Wrapped in [0] EXPLICIT for TstInfo
        //
        // DER structure:
        //   A0 19     [0] EXPLICIT (25 bytes)
        //      86 17  [6] IMPLICIT uniformResourceIdentifier (23 bytes)
        //         "https://tsa.example.com"
        const TSA_GENERAL_NAME_URI: &[u8] = &[
            0xa0, 0x19, // [0] EXPLICIT (25 bytes)
            0x86, 0x17, //   [6] IMPLICIT URI (23 bytes)
            0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x74, 0x73, 0x61, 0x2e, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // "https://tsa.example.com"
        ];

        // Test parsing as it's done in TstInfo::take_from()
        let general_name_dns =
            Constructed::decode(TSA_GENERAL_NAME_DNS, bcder::Mode::Der, |cons| {
                cons.take_opt_constructed_if(Tag::CTX_0, GeneralName::take_from)
            })
            .expect("Failed to decode TSA with dNSName");

        assert!(general_name_dns.is_some(), "GeneralName should be present");
        let general_name_dns = general_name_dns.unwrap();
        // The captured data should be the inner [2] tagged value
        assert!(general_name_dns.0.as_slice().starts_with(&[0x82]));

        // Test URI variant
        let general_name_uri =
            Constructed::decode(TSA_GENERAL_NAME_URI, bcder::Mode::Der, |cons| {
                cons.take_opt_constructed_if(Tag::CTX_0, GeneralName::take_from)
            })
            .expect("Failed to decode TSA with URI");

        assert!(general_name_uri.is_some(), "GeneralName should be present");
        let general_name_uri = general_name_uri.unwrap();
        // The captured data should be the inner [6] tagged value
        assert!(general_name_uri.0.as_slice().starts_with(&[0x86]));

        // Verify outer tag is [0]
        let (tag, _) =
            bcder::Tag::take_from(&mut bcder::decode::SliceSource::new(TSA_GENERAL_NAME_DNS))
                .expect("Failed to read outer tag");
        assert_eq!(tag, Tag::CTX_0, "Outer tag should be [0] for TstInfo.tsa");
    }

    /// Test from_primitive_no_fractional_or_timezone_offsets via CMS Time
    ///
    /// This method is used by CMS Time structures (RFC 5652) for strict DER encoding.
    /// We test it indirectly through the Time::take_from() parser.
    ///
    /// ## Test Data
    ///
    /// Standard GeneralizedTime DER format: Tag(0x18) + Length + YYYYMMDDHHmmssZ
    /// Example: "20240115120000Z" = January 15, 2024, 12:00:00 UTC
    #[test]
    fn test_generalized_time_from_primitive_no_fractional() {
        use bcder::decode::Constructed;

        use super::rfc5652::Time;

        // GeneralizedTime in DER format (tag + length + content)
        // Tag: 0x18 (GENERALIZED_TIME)
        // Length: 0x0f (15 bytes)
        // Content: "20240115120000Z"
        const TIME_DER: &[u8] = &[
            0x18, 0x0f, // GENERALIZED_TIME, length 15
            b'2', b'0', b'2', b'4', b'0', b'1', b'1', b'5', b'1', b'2', b'0', b'0', b'0', b'0',
            b'Z',
        ];

        // Parse using Time::take_from which calls from_primitive_no_fractional_or_timezone_offsets
        let time = Constructed::decode(TIME_DER, bcder::Mode::Der, Time::take_from)
            .expect("Failed to parse CMS Time with GeneralizedTime");

        // Verify it's the GeneralizedTime variant
        let gen_time = match time {
            Time::GeneralizedTime(gt) => gt,
            Time::UtcTime(_) => panic!("Expected GeneralizedTime, got UtcTime"),
        };

        // Verify the time value
        let dt: chrono::DateTime<chrono::Utc> = gen_time.into();
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2024-01-15 12:00:00"
        );
    }

    /// Test RFC 3161 GeneralizedTime with fractional seconds
    ///
    /// Real-world test data extracted from ~/Downloads/test/test.jpeg
    /// C2PA manifest with timestamp from freetsa.org: "20251121125823.643Z"
    ///
    /// This test validates that we can parse RFC 3161 timestamps that include
    /// fractional seconds, which are explicitly allowed by RFC 3161 Section 2.4.2:
    ///
    /// > "The ASN.1 GeneralizedTime syntax can include fraction-of-second details.
    /// >  Such syntax, without the restrictions from [RFC 2459] Section 4.1.2.5.2,
    /// >  where GeneralizedTime is limited to represent the time with a granularity
    /// >  of one second, may be used here."
    ///
    /// The der crate's GeneralizedTime enforces RFC 5280's strict "no fractional"
    /// rule, so we need custom parsing for RFC 3161 compliance.
    #[test]
    fn test_generalized_time_rfc3161_fractional_seconds() {
        // Real-world DER data from ~/Downloads/test/test.jpeg (offset 0x00002e5d)
        // Timestamp from freetsa.org embedded in C2PA manifest
        // Tag: 0x18 (GENERALIZED_TIME)
        // Length: 0x13 (19 bytes)
        // Content: "20251121125823.643Z" (November 21, 2025, 12:58:23.643 UTC)
        const TIME_DER_FRACTIONAL: &[u8] = &[
            0x18, 0x13, // GENERALIZED_TIME, length 19
            b'2', b'0', b'2', b'5', b'1', b'1', b'2', b'1', // 20251121
            b'1', b'2', b'5', b'8', b'2', b'3', // 125823
            b'.', b'6', b'4', b'3', // .643 (fractional)
            b'Z',
        ];

        // Verify: `xxd` the test file to confirm:
        // $ xxd -s 0x00002e5d -l 21 ~/Downloads/test/test.jpeg
        // 00002e5d: 1813 3230 3235 3131 3231 3132 3538 3233  ..20251121125823
        // 00002e6d: 2e36 3433 5a                             .643Z

        // This should succeed with the RFC 3161 parser
        let gen_time = GeneralizedTime::from_der_bytes_rfc3161(TIME_DER_FRACTIONAL)
            .expect("Failed to parse RFC 3161 GeneralizedTime with fractional seconds");

        // Verify that the original DER bytes are preserved (important for signature validation)
        assert_eq!(gen_time.as_der_bytes(), TIME_DER_FRACTIONAL);

        // Convert to chrono DateTime
        let dt: chrono::DateTime<chrono::Utc> = gen_time.into();

        // Verify the parsed time
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2025-11-21 12:58:23"
        );

        // Verify fractional seconds: .643 seconds = 643 milliseconds = 643,000,000 nanoseconds
        assert_eq!(dt.timestamp_subsec_millis(), 643);
        assert_eq!(dt.timestamp_subsec_nanos(), 643_000_000);
    }

    /// Test that RFC 5280 strict format still works and is compatible
    ///
    /// RFC 5280 Section 4.1.2.5.2 requires GeneralizedTime without fractional seconds.
    /// Our RFC 3161 parser should also handle this format for backward compatibility.
    #[test]
    fn test_generalized_time_rfc5280_no_fractional() {
        // RFC 5280 format (no fractional seconds) - 15 bytes
        // Format: YYYYMMDDHHmmssZ
        const TIME_DER_NO_FRACTIONAL: &[u8] = &[
            0x18, 0x0f, // GENERALIZED_TIME, length 15
            b'2', b'0', b'2', b'5', b'1', b'1', b'2', b'1', b'1', b'2', b'5', b'8', b'2', b'3',
            b'Z',
        ];

        // Should work with both parsers
        let gen_time_strict = GeneralizedTime::from_der_bytes(TIME_DER_NO_FRACTIONAL)
            .expect("RFC 5280 parser should handle no-fractional format");

        let gen_time_rfc3161 = GeneralizedTime::from_der_bytes_rfc3161(TIME_DER_NO_FRACTIONAL)
            .expect("RFC 3161 parser should handle no-fractional format");

        // Both should produce the same result
        assert_eq!(gen_time_strict, gen_time_rfc3161);

        // Convert to DateTime and verify
        let dt: chrono::DateTime<chrono::Utc> = gen_time_rfc3161.into();
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2025-11-21 12:58:23"
        );
        assert_eq!(dt.timestamp_subsec_nanos(), 0); // No fractional seconds
    }

    /// Test various fractional second precisions
    #[test]
    fn test_generalized_time_fractional_precisions() {
        let test_cases = vec![
            ("20230101000000.5Z", 500_000_000u32, "half second"),
            ("20230101000000.1Z", 100_000_000u32, "one tenth second"),
            ("20230101000000.999Z", 999_000_000u32, "999 milliseconds"),
            (
                "20230101000000.123456789Z",
                123_456_789u32,
                "nanosecond precision",
            ),
        ];

        for (time_str, expected_nanos, desc) in test_cases {
            // Construct DER bytes
            let mut der_bytes = vec![0x18, time_str.len() as u8];
            der_bytes.extend_from_slice(time_str.as_bytes());

            let gen_time = GeneralizedTime::from_der_bytes_rfc3161(&der_bytes)
                .expect(&format!("Failed to parse: {}", desc));

            let dt: chrono::DateTime<chrono::Utc> = gen_time.into();
            assert_eq!(
                dt.timestamp_subsec_nanos(),
                expected_nanos,
                "Mismatch for: {}",
                desc
            );
        }
    }
}
