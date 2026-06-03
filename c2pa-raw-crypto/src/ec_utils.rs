// Copyright 2025 Adobe. All rights reserved.
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

//! Utilities for working with the EC signatures used by C2PA in ECDSA
//! signatures.

use pkcs8::PrivateKeyInfo;
use spki::{der::Tagged, SubjectPublicKeyInfoRef};

use crate::{
    oids::{EC_PUBLICKEY_OID, PRIME256V1_OID, SECP384R1_OID, SECP521R1_OID},
    RawSignerError,
};

/// NIST curves supported by `EcdsaValidator`.
pub enum EcdsaCurve {
    /// NIST curve P-256
    P256,

    /// NIST curve P-384
    P384,

    /// NIST curve P-521
    P521,
}

impl EcdsaCurve {
    /// Return the IEEE P1363 `r‖s` signature size (in bytes) for this curve.
    pub fn p1363_sig_len(&self) -> usize {
        match self {
            EcdsaCurve::P256 => 64,
            EcdsaCurve::P384 => 96,
            EcdsaCurve::P521 => 132,
        }
    }
}

/// Parses an ASN.1 DER-encoded ECDSA signature (`SEQUENCE { r INTEGER, s
/// INTEGER }`) into its `r` and `s` integer components.
///
/// Returns `None` if `data` is not a syntactically valid DER ECDSA signature.
pub fn parse_ec_der_sig(data: &[u8]) -> Option<EcSigComps<'_>> {
    const SEQUENCE_TAG: u8 = 0x30;
    const INTEGER_TAG: u8 = 0x02;

    let (seq_content, _rest) = read_der_tlv(data, SEQUENCE_TAG)?;
    let (r, rest) = read_der_tlv(seq_content, INTEGER_TAG)?;
    let (s, _) = read_der_tlv(rest, INTEGER_TAG)?;

    Some(EcSigComps { r, s })
}

/// The `r` and `s` integer components of an ECDSA signature.
pub struct EcSigComps<'a> {
    /// The `r` component, as big-endian bytes.
    pub r: &'a [u8],

    /// The `s` component, as big-endian bytes.
    pub s: &'a [u8],
}

/// Reads a single DER TLV (tag-length-value) with the expected `tag`.
///
/// Returns the content slice and the trailing bytes after the TLV.
fn read_der_tlv(input: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    if *input.first()? != expected_tag {
        return None;
    }

    let (content_len, length_octets) = read_der_length(input.get(1..)?)?;
    let header_len = 1 + length_octets;
    let total = header_len.checked_add(content_len)?;
    if input.len() < total {
        return None;
    }

    Some((&input[header_len..total], &input[total..]))
}

/// Reads DER length octets.
///
/// Returns `(content_length, length_octet_count)`.
fn read_der_length(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first & 0x80 == 0 {
        // Short form: length fits in 7 bits.
        return Some((first as usize, 1));
    }

    // Long form: low 7 bits give the number of subsequent length octets.
    let n = (first & 0x7f) as usize;
    if n == 0 || n > core::mem::size_of::<usize>() {
        // Indefinite length (n == 0) is not valid in DER; values wider than
        // `usize` cannot be represented on this platform.
        return None;
    }
    let bytes = input.get(1..1 + n)?;
    let mut len: usize = 0;
    for &b in bytes {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

/// Converts an ASN.1 DER-encoded ECDSA signature to fixed-size IEEE P1363
/// (`r‖s`) form of length `sig_len` bytes.
pub fn der_to_p1363(data: &[u8], sig_len: usize) -> Result<Vec<u8>, RawSignerError> {
    // P1363 format: r | s

    let p = parse_ec_der_sig(data)
        .ok_or_else(|| RawSignerError::InternalError("invalid DER signature".to_string()))?;

    let mut r = const_hex::encode(p.r);
    let mut s = const_hex::encode(p.s);

    // Check against the supported signature sizes.
    if ![64usize, 96, 132].contains(&sig_len) {
        return Err(RawSignerError::InternalError(
            "unsupported algorithm for der_to_p1363".to_string(),
        ));
    }

    // Pad or truncate as needed.
    let rp = if r.len() > sig_len {
        let offset = r.len() - sig_len;
        &r[offset..r.len()]
    } else {
        while r.len() != sig_len {
            r.insert(0, '0');
        }
        r.as_ref()
    };

    let sp = if s.len() > sig_len {
        let offset = s.len() - sig_len;
        &s[offset..s.len()]
    } else {
        while s.len() != sig_len {
            s.insert(0, '0');
        }
        s.as_ref()
    };

    if rp.len() != sig_len || rp.len() != sp.len() {
        return Err(RawSignerError::InternalError(
            "invalid signature components".to_string(),
        ));
    }

    // Merge r and s strings.
    let new_sig = format!("{rp}{sp}");

    // Convert back from hex string to byte array.
    const_hex::decode(&new_sig)
        .map_err(|e| RawSignerError::InternalError(format!("invalid signature components {e}")))
}

/// Returns the [`EcdsaCurve`] for a DER-encoded SubjectPublicKeyInfo
/// or `None` if the key is not on a supported curve.
pub fn ec_curve_from_public_key_der(public_key: &[u8]) -> Option<EcdsaCurve> {
    let spki = SubjectPublicKeyInfoRef::try_from(public_key).ok()?;

    if spki.algorithm.oid.as_bytes() != EC_PUBLICKEY_OID.as_bytes() {
        return None;
    }

    // The `parameters` field of an `id-ecPublicKey` algorithm identifier is a
    // named-curve OID. Extract its DER content octets and compare.
    let params = spki.algorithm.parameters.as_ref()?;
    if params.tag() != spki::der::Tag::ObjectIdentifier {
        return None;
    }
    let curve_oid = params.value();

    if curve_oid == PRIME256V1_OID.as_bytes() {
        Some(EcdsaCurve::P256)
    } else if curve_oid == SECP384R1_OID.as_bytes() {
        Some(EcdsaCurve::P384)
    } else if curve_oid == SECP521R1_OID.as_bytes() {
        Some(EcdsaCurve::P521)
    } else {
        None
    }
}

/// Returns the [`EcdsaCurve`] for a DER-encoded PKCS#8 private key
/// or `None` if the key is not on a supported curve.
pub fn ec_curve_from_private_key_der(private_key: &[u8]) -> Option<EcdsaCurve> {
    use pkcs8::der::Decode;
    let ec_key = PrivateKeyInfo::from_der(private_key).ok()?;

    let p256_oid = pkcs8::ObjectIdentifier::from_bytes(PRIME256V1_OID.as_bytes()).ok()?;
    let p384_oid = pkcs8::ObjectIdentifier::from_bytes(SECP384R1_OID.as_bytes()).ok()?;
    let p521_oid = pkcs8::ObjectIdentifier::from_bytes(SECP521R1_OID.as_bytes()).ok()?;

    if ec_key.algorithm.assert_parameters_oid(p256_oid).is_ok() {
        return Some(EcdsaCurve::P256);
    } else if ec_key.algorithm.assert_parameters_oid(p384_oid).is_ok() {
        return Some(EcdsaCurve::P384);
    } else if ec_key.algorithm.assert_parameters_oid(p521_oid).is_ok() {
        return Some(EcdsaCurve::P521);
    }

    None
}
