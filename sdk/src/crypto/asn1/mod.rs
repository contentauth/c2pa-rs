// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(missing_docs)]

//! Holds Rust struct definitions for various ASN.1 primitives.

// This code is copied from a subset of version 0.22.0 of the
// cryptographic-message-syntax crate located at:
// https://github.com/indygreg/cryptography-rs/tree/main/cryptographic-message-syntax/src/asn1

// We can not incorporate the entire crate directly because other parts of the
// crate contain dependencies on blocking calls in reqwest. Those calls are not
// available in WASM environment.

use std::io::Write;

use bcder::{
    decode::{Constructed, DecodeError, Source},
    encode::{self, PrimitiveContent, Values},
    Captured, Mode, Oid, Tag,
};
// Use der crate for time types to avoid custom date parsing
use der::{Decode, Encode};

// Common ASN.1 types shared across multiple RFCs

/// Algorithm identifier for use with bcder
#[derive(Clone, Debug)]
pub struct AlgorithmIdentifier {
    /// The algorithm OID
    pub algorithm: Oid,
}

impl PartialEq for AlgorithmIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
    }
}

impl Eq for AlgorithmIdentifier {}

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

        // Reconstruct the full DER encoding (tag + length + content)
        let mut der_bytes = Vec::with_capacity(2 + bytes.len());
        der_bytes.push(0x18); // GENERALIZED_TIME tag
        der_bytes.push(bytes.len() as u8); // length
        der_bytes.extend_from_slice(bytes.as_ref());

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
        // Extract the content from the DER encoding
        // DER format: tag (1 byte) + length (1 byte) + content
        if self.der_bytes.len() >= 2 {
            let length = self.der_bytes[1] as usize;
            if length < 128 && self.der_bytes.len() >= 2 + length {
                if let Ok(s) = std::str::from_utf8(&self.der_bytes[2..2 + length]) {
                    return s;
                }
            }
        }
        ""
    }
}

impl From<GeneralizedTime> for chrono::DateTime<chrono::Utc> {
    fn from(gt: GeneralizedTime) -> Self {
        // Use der's conversion to SystemTime, then to chrono
        let system_time = gt.der_time.to_system_time();
        system_time.into()
    }
}

impl From<chrono::DateTime<chrono::Utc>> for GeneralizedTime {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        // Convert chrono to SystemTime, then to der's GeneralizedTime
        let system_time: std::time::SystemTime = dt.into();

        // Try to convert to GeneralizedTime
        let der_time = if let Ok(time) = der::asn1::GeneralizedTime::from_system_time(system_time) {
            time
        } else {
            // Fallback to Unix epoch (1970-01-01 00:00:00 UTC)
            // This should never fail as epoch is always valid
            match der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(0))
            {
                Ok(epoch) => epoch,
                Err(_) => {
                    // If even epoch fails, we have a serious problem
                    // Use a compile-time known valid time: 2000-01-01 00:00:00Z
                    // This is a last resort and should never happen in practice
                    let bytes = b"\x18\x0f20000101000000Z";
                    match der::asn1::GeneralizedTime::from_der(bytes) {
                        Ok(t) => t,
                        // At this point we're out of options - this should be unreachable
                        Err(_) => {
                            // Safety: This path should be unreachable as we're using a known-valid constant
                            unreachable!(
                                "Failed to create GeneralizedTime from hardcoded valid constant"
                            )
                        }
                    }
                }
            }
        };

        // Convert to our wrapper type
        // This can only fail if encoding fails, which shouldn't happen for valid times
        match Self::from_der_time(der_time) {
            Ok(gt) => gt,
            Err(_) => {
                // If encoding fails, try with a minimal valid time
                let bytes = b"\x18\x0f20000101000000Z";
                if let Ok(fallback_der) = der::asn1::GeneralizedTime::from_der(bytes) {
                    if let Ok(fallback) = Self::from_der_time(fallback_der) {
                        return fallback;
                    }
                }
                // Safety: This should be unreachable
                unreachable!("Failed to create GeneralizedTime wrapper")
            }
        }
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
