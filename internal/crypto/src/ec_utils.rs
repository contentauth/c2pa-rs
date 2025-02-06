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

use asn1_rs::{FromDer, ToDer};
use pkcs8::PrivateKeyInfo;
use x509_parser::{
    der_parser::{
        der::{parse_der_integer, parse_der_sequence_defined_g},
        error::BerResult,
    },
    x509::SubjectPublicKeyInfo,
};

use crate::raw_signature::{
    oids::{EC_PUBLICKEY_OID, PRIME256V1_OID, SECP384R1_OID, SECP521R1_OID},
    RawSignerError,
};

/// NIST curves supported by `EcdsaValidator`.
pub(crate) enum EcdsaCurve {
    /// NIST curve P-256
    P256,

    /// NIST curve P-384
    P384,

    /// NIST curve P-521
    P521,
}

impl EcdsaCurve {
    // Returns the P1363 r|s signature size for a given curve.
    pub fn p1363_sig_len(&self) -> usize {
        match self {
            EcdsaCurve::P256 => 64,
            EcdsaCurve::P384 => 96,
            EcdsaCurve::P521 => 132,
        }
    }
}

/// Parse an ASN.1 DER object that contains a P1363 format into its components.
///
/// This format is used by C2PA to describe ECDSA signature keys.
pub(crate) fn parse_ec_der_sig(data: &[u8]) -> BerResult<EcSigComps> {
    parse_der_sequence_defined_g(|content: &[u8], _| {
        let (rem1, r) = parse_der_integer(content)?;
        let (_rem2, s) = parse_der_integer(rem1)?;

        Ok((
            data,
            EcSigComps {
                r: r.as_slice()?,
                s: s.as_slice()?,
            },
        ))
    })(data)
}

pub(crate) struct EcSigComps<'a> {
    pub r: &'a [u8],
    pub s: &'a [u8],
}

pub(crate) fn der_to_p1363(data: &[u8], sig_len: usize) -> Result<Vec<u8>, RawSignerError> {
    // P1363 format: r | s

    let (_, p) = parse_ec_der_sig(data)
        .map_err(|err| RawSignerError::InternalError(format!("invalid DER signature: {err}")))?;

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

// Returns supported EcdsaCurve for given public key.
#[allow(dead_code)]
pub(crate) fn ec_curve_from_public_key_der(public_key: &[u8]) -> Option<EcdsaCurve> {
    let (_, pk) = SubjectPublicKeyInfo::from_der(public_key).ok()?;

    let public_key_alg = &pk.algorithm;

    if public_key_alg.algorithm == EC_PUBLICKEY_OID {
        if let Some(parameters) = &public_key_alg.parameters {
            let named_curve_oid = parameters.as_oid().ok()?;

            // Find supported curve.
            if named_curve_oid == PRIME256V1_OID {
                return Some(EcdsaCurve::P256);
            } else if named_curve_oid == SECP384R1_OID {
                return Some(EcdsaCurve::P384);
            } else if named_curve_oid == SECP521R1_OID {
                return Some(EcdsaCurve::P521);
            }
        }
    }

    None
}

// Returns supported EcdsaCurve for given private key.
#[allow(dead_code)] // not used on WASM builds
pub(crate) fn ec_curve_from_private_key_der(private_key: &[u8]) -> Option<EcdsaCurve> {
    use pkcs8::der::Decode;
    let ec_key = PrivateKeyInfo::from_der(private_key).ok()?;

    let p256_oid = pkcs8::ObjectIdentifier::from_der(&PRIME256V1_OID.to_der_vec().ok()?).ok()?;
    let p384_oid = pkcs8::ObjectIdentifier::from_der(&SECP384R1_OID.to_der_vec().ok()?).ok()?;
    let p521_oid = pkcs8::ObjectIdentifier::from_der(&SECP521R1_OID.to_der_vec().ok()?).ok()?;

    if ec_key.algorithm.assert_parameters_oid(p256_oid).is_ok() {
        return Some(EcdsaCurve::P256);
    } else if ec_key.algorithm.assert_parameters_oid(p384_oid).is_ok() {
        return Some(EcdsaCurve::P384);
    } else if ec_key.algorithm.assert_parameters_oid(p521_oid).is_ok() {
        return Some(EcdsaCurve::P521);
    }

    None
}
