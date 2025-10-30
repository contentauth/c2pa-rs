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

/// Generalized time structure compatible with bcder
#[derive(Clone, Debug)]
pub struct GeneralizedTime(pub Captured);

impl PartialEq for GeneralizedTime {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for GeneralizedTime {}

impl std::fmt::Display for GeneralizedTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl GeneralizedTime {
    pub fn take_from_allow_fractional_z<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.capture_one().map(GeneralizedTime)
    }

    pub fn from_primitive_no_fractional_or_timezone_offsets<S: bcder::decode::Source>(
        prim: &mut bcder::decode::Primitive<S>,
    ) -> Result<Self, bcder::decode::DecodeError<S::Error>> {
        use bcder::OctetString;
        let bytes = prim.take_all()?;
        Ok(GeneralizedTime(Captured::from_values(
            Mode::Der,
            OctetString::encode_slice_as(bytes.as_ref(), Tag::GENERALIZED_TIME),
        )))
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        &self.0
    }

    /// Parse the raw ASN.1 bytes to extract the time string
    pub fn as_str(&self) -> &str {
        // The Captured value contains the entire DER encoding: tag, length, and content
        let slice = self.0.as_slice();

        // For GeneralizedTime, we expect: tag (1 byte) + length (1 byte) + content
        // Most common case: length < 128 (short form)
        if slice.len() >= 2 {
            let length = slice[1] as usize;
            if length < 128 && slice.len() >= 2 + length {
                // Short form length - skip tag and length bytes
                if let Ok(s) = std::str::from_utf8(&slice[2..2 + length]) {
                    return s;
                }
            }
        }

        // Fallback for edge cases or invalid data
        ""
    }
}

impl From<GeneralizedTime> for chrono::DateTime<chrono::Utc> {
    fn from(gt: GeneralizedTime) -> Self {
        use chrono::TimeZone;

        // Parse GeneralizedTime format: YYYYMMDDHHmmSS[.f*]Z
        let time_str = gt.as_str();
        // TODO: Get rid of this fallback
        let time_str = if time_str.is_empty() {
            "19700101000000Z"
        } else {
            time_str
        };

        // Remove 'Z' suffix and fractional seconds for simplicity
        let time_str = time_str.trim_end_matches('Z');
        let (time_str, _frac) = time_str.split_once('.').unwrap_or((time_str, ""));

        // Parse: YYYYMMDDHHMMSS
        if time_str.len() >= 14 {
            let year = time_str[0..4].parse().unwrap_or(1970);
            let month = time_str[4..6].parse().unwrap_or(1);
            let day = time_str[6..8].parse().unwrap_or(1);
            let hour = time_str[8..10].parse().unwrap_or(0);
            let minute = time_str[10..12].parse().unwrap_or(0);
            let second = time_str[12..14].parse().unwrap_or(0);

            chrono::Utc
                .with_ymd_and_hms(year, month, day, hour, minute, second)
                .single()
                .unwrap_or_else(|| chrono::Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
        } else {
            // Default to epoch
            // TODO: Get rid of this fallback
            chrono::Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()
        }
    }
}

// Conversion from chrono DateTime for compatibility
impl From<chrono::DateTime<chrono::Utc>> for GeneralizedTime {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        use chrono::TimeZone;
        // Format to ASN.1 GeneralizedTime format
        let time_str = dt.format("%Y%m%d%H%M%SZ").to_string();
        let bytes = time_str.as_bytes();

        // Build the DER encoding manually: tag + length + content
        let mut der_bytes = Vec::with_capacity(2 + bytes.len());
        der_bytes.push(0x18); // GENERALIZED_TIME tag
        der_bytes.push(bytes.len() as u8);
        der_bytes.extend_from_slice(bytes);

        // Parse the DER bytes we just created to get a properly constructed Captured
        use bcder::decode::Constructed as DecodeConstructed;
        match DecodeConstructed::decode(der_bytes.as_ref(), Mode::Der, |cons| {
            cons.capture_one().map(GeneralizedTime)
        }) {
            Ok(gt) => gt,
            Err(_) => {
                // Fallback to epoch if parsing fails
                Self::from(chrono::Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
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
