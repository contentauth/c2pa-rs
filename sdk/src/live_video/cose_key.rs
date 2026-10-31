// Copyright 2026 Adobe. All rights reserved.
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

//! Converts a COSE_Key ([RFC 9052]) stored as a [`c2pa_cbor::Value`] into a DER-encoded
//! SubjectPublicKeyInfo byte vector suitable for [`RawSignatureValidator::validate`].
//!
//! Supports EC2 keys (P-256, P-384, P-521), OKP keys (Ed25519) and RSA keys for RSASSA-PSS
//! ([RFC 8230]): every algorithm allowed for claim-signing certificates, which the Live Media
//! specification allows for session keys.
//!
//! [RFC 8230]: https://www.rfc-editor.org/rfc/rfc8230
//!
//! [RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052

use std::collections::BTreeMap;

use c2pa_cbor::Value as CborValue;
use ed25519_dalek::VerifyingKey;
use rasn::types::{Any, BitString, ObjectIdentifier};
use rasn_pkix::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::SigningAlg;

// COSE_Key common parameter labels (RFC 9052 §7.1).
const KTY: i128 = 1;
const KID: i128 = 2;
const ALG: i128 = 3;

// COSE_Key type values.
const KTY_EC2: i128 = 2;
const KTY_OKP: i128 = 1;
const KTY_RSA: i128 = 3;

// RSA key parameters (RFC 8230 §4).
const RSA_N: i128 = -1;
const RSA_E: i128 = -2;

/// The smallest RSA modulus accepted, as for claim-signing certificates.
const MIN_RSA_MODULUS_BITS: usize = 2048;

// EC2 key parameters (RFC 9052 §13.1.1).
const EC2_CRV: i128 = -1;
const EC2_X: i128 = -2;
const EC2_Y: i128 = -3;

// COSE EC2 curve identifiers.
const CRV_P256: i128 = 1;
const CRV_P384: i128 = 2;
const CRV_P521: i128 = 3;

// OKP key parameters.
const OKP_CRV: i128 = -1;
const OKP_X: i128 = -2;
const CRV_ED25519: i128 = 6;

// OIDs for SubjectPublicKeyInfo construction.
const EC_PUBLIC_KEY_OID: &[u32] = &[1, 2, 840, 10045, 2, 1];
const P256_OID: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];
const P384_OID: &[u32] = &[1, 3, 132, 0, 34];
const P521_OID: &[u32] = &[1, 3, 132, 0, 35];
const ED25519_OID: &[u32] = &[1, 3, 101, 112];
const RSA_ENCRYPTION_OID: &[u32] = &[1, 2, 840, 113549, 1, 1, 1];
const RSASSA_PSS_OID: &[u32] = &[1, 2, 840, 113549, 1, 1, 10];

/// The COSE algorithm identifier (RFC 9053, RFC 8230) for a signing algorithm.
pub(crate) fn cose_alg_id(alg: SigningAlg) -> Option<i128> {
    match alg {
        SigningAlg::Es256 => Some(-7),
        SigningAlg::Es384 => Some(-35),
        SigningAlg::Es512 => Some(-36),
        SigningAlg::Ps256 => Some(-37),
        SigningAlg::Ps384 => Some(-38),
        SigningAlg::Ps512 => Some(-39),
        SigningAlg::Ed25519 => Some(-8),
        _ => None,
    }
}

fn alg_from_cose_id(id: i128) -> Option<SigningAlg> {
    [
        SigningAlg::Es256,
        SigningAlg::Es384,
        SigningAlg::Es512,
        SigningAlg::Ps256,
        SigningAlg::Ps384,
        SigningAlg::Ps512,
        SigningAlg::Ed25519,
    ]
    .into_iter()
    .find(|alg| cose_alg_id(*alg) == Some(id))
}

/// Extracts the `kid` (key identifier) from a COSE_Key stored as a CBOR Value map.
pub(crate) fn kid_from_cose_key(cose_key: &CborValue) -> Option<Vec<u8>> {
    let map = as_cbor_int_map(cose_key)?;
    match map.get(&KID)? {
        CborValue::Bytes(b) => Some(b.clone()),
        CborValue::Text(s) => Some(s.as_bytes().to_vec()),
        value => cbor_as_bytes(value),
    }
}

/// Determines the [`SigningAlg`] for a COSE_Key.
///
/// EC2 and OKP keys imply their algorithm through the curve. An RSA key doesn't, so it needs
/// an `alg` of PS256, PS384 or PS512. When an `alg` is present it must agree with the key;
/// a key that declares a different algorithm, or an unknown one, is rejected.
pub(crate) fn signing_alg_from_cose_key(cose_key: &CborValue) -> Option<SigningAlg> {
    let map = as_cbor_int_map(cose_key)?;
    let kty = cbor_to_i128(map.get(&KTY)?)?;

    let implied = match kty {
        KTY_EC2 => {
            let crv = cbor_to_i128(map.get(&EC2_CRV)?)?;
            match crv {
                CRV_P256 => Some(SigningAlg::Es256),
                CRV_P384 => Some(SigningAlg::Es384),
                CRV_P521 => Some(SigningAlg::Es512),
                _ => return None,
            }
        }
        KTY_OKP => {
            let crv = cbor_to_i128(map.get(&OKP_CRV)?)?;
            match crv {
                CRV_ED25519 => Some(SigningAlg::Ed25519),
                _ => return None,
            }
        }
        KTY_RSA => None,
        _ => return None,
    };
    let declared = match map.get(&ALG) {
        Some(value) => Some(alg_from_cose_id(cbor_to_i128(value)?)?),
        None => None,
    };

    match (implied, declared) {
        (Some(implied), None) => Some(implied),
        (Some(implied), Some(declared)) => (implied == declared).then_some(implied),
        (None, Some(declared @ (SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512))) => {
            Some(declared)
        }
        (None, _) => None,
    }
}

/// Converts a COSE_Key (CBOR Value) to a DER-encoded SubjectPublicKeyInfo byte vector.
///
/// Returns `None` if the key type or curve is unsupported, or if required parameters are missing.
pub(crate) fn cose_key_to_der(cose_key: &CborValue) -> Option<Vec<u8>> {
    let map = as_cbor_int_map(cose_key)?;
    let kty = cbor_to_i128(map.get(&KTY)?)?;

    match kty {
        KTY_EC2 => ec2_to_der(&map),
        KTY_OKP => okp_to_der(&map),
        KTY_RSA => rsa_to_der(&map),
        _ => None,
    }
}

/// Builds the COSE_Key for a public key given as a DER-encoded SubjectPublicKeyInfo, for use
/// with `alg`: an OKP key for Ed25519, an EC2 key for ES256/384/512 (whose curve must match),
/// or an RSA key for PS256/384/512 (with a modulus of at least 2048 bits). The key carries
/// `kid` and `alg`. Returns `None` if the key doesn't fit `alg` or can't be parsed.
pub(crate) fn cose_key_from_spki(
    spki_der: &[u8],
    alg: SigningAlg,
    kid: &[u8],
) -> Option<CborValue> {
    use x509_parser::{
        prelude::FromDer,
        public_key::{PublicKey, RSAPublicKey},
        x509::SubjectPublicKeyInfo,
    };

    let (rest, spki) = SubjectPublicKeyInfo::from_der(spki_der).ok()?;
    if !rest.is_empty() {
        return None;
    }
    let algorithm = spki.algorithm.algorithm.to_id_string();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .map(|oid| oid.to_id_string());

    // COSE labels and values are small; they always fit an i64.
    let int = |v: i128| CborValue::Integer(v as i64);
    let mut map = BTreeMap::new();
    map.insert(KID, CborValue::Bytes(kid.to_vec()));
    map.insert(ALG, int(cose_alg_id(alg)?));
    match alg {
        SigningAlg::Ed25519 => {
            if algorithm != oid_string(ED25519_OID) {
                return None;
            }
            let x = spki.subject_public_key.data.to_vec();
            if x.len() != 32 {
                return None;
            }
            map.insert(KTY, int(KTY_OKP));
            map.insert(OKP_CRV, int(CRV_ED25519));
            map.insert(OKP_X, CborValue::Bytes(x));
        }
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
            let (crv, curve_oid, field_len) = match alg {
                SigningAlg::Es256 => (CRV_P256, P256_OID, 32),
                SigningAlg::Es384 => (CRV_P384, P384_OID, 48),
                _ => (CRV_P521, P521_OID, 66),
            };
            if algorithm != oid_string(EC_PUBLIC_KEY_OID)
                || curve.as_deref() != Some(oid_string(curve_oid).as_str())
            {
                return None;
            }
            let PublicKey::EC(point) = spki.parsed().ok()? else {
                return None;
            };
            // SEC1 uncompressed point: 0x04 || x || y.
            let point = point.data();
            if point.len() != 1 + 2 * field_len || point[0] != 0x04 {
                return None;
            }
            map.insert(KTY, int(KTY_EC2));
            map.insert(EC2_CRV, int(crv));
            map.insert(EC2_X, CborValue::Bytes(point[1..=field_len].to_vec()));
            map.insert(EC2_Y, CborValue::Bytes(point[1 + field_len..].to_vec()));
        }
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => {
            // RSA keys appear under rsaEncryption or, in PS* certificates, id-RSASSA-PSS
            // (RFC 4055 §1.2); both carry an RSAPublicKey.
            if algorithm != oid_string(RSA_ENCRYPTION_OID)
                && algorithm != oid_string(RSASSA_PSS_OID)
            {
                return None;
            }
            let (_, rsa) = RSAPublicKey::from_der(&spki.subject_public_key.data).ok()?;
            let n = strip_leading_zeros(rsa.modulus);
            let e = strip_leading_zeros(rsa.exponent);
            if modulus_bits(n) < MIN_RSA_MODULUS_BITS || e.is_empty() {
                return None;
            }
            map.insert(KTY, int(KTY_RSA));
            map.insert(RSA_N, CborValue::Bytes(n.to_vec()));
            map.insert(RSA_E, CborValue::Bytes(e.to_vec()));
        }
        _ => return None,
    }
    Some(CborValue::Map(
        map.into_iter().map(|(k, v)| (int(k), v)).collect(),
    ))
}

/// Builds an OKP COSE_Key (CBOR Value) for an Ed25519 public key ([RFC 9052] §7, §13.2).
///
/// [RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052
pub(super) fn build_ed25519_cose_key(verifying_key: &VerifyingKey, kid: &[u8]) -> CborValue {
    // OKP COSE_Key for Ed25519 (RFC 9052):
    //   1 (kty)  → 1 (OKP)
    //   2 (kid)  → bytes
    //   3 (alg)  → -8 (EdDSA)
    //  -1 (crv)  → 6 (Ed25519)
    //  -2 (x)   → public key bytes (32 bytes)
    let mut map = BTreeMap::new();
    map.insert(CborValue::Integer(1), CborValue::Integer(1)); // kty: OKP
    map.insert(CborValue::Integer(2), CborValue::Bytes(kid.to_vec())); // kid
    map.insert(CborValue::Integer(3), CborValue::Integer(-8)); // alg: EdDSA
    map.insert(CborValue::Integer(-1), CborValue::Integer(6)); // crv: Ed25519
    map.insert(
        CborValue::Integer(-2),
        CborValue::Bytes(verifying_key.as_bytes().to_vec()),
    ); // x
    CborValue::Map(map)
}

fn ec2_to_der(map: &BTreeMap<i128, &CborValue>) -> Option<Vec<u8>> {
    let crv = cbor_to_i128(map.get(&EC2_CRV)?)?;
    let x = cbor_as_bytes(map.get(&EC2_X)?)?;
    let y = cbor_as_bytes(map.get(&EC2_Y)?)?;

    // RFC 9053 §7.1.1 requires x/y to be exactly the curve's field-element length; a CBOR
    // encoder that strips leading zero bytes from the coordinate's big-endian encoding would
    // otherwise produce a shorter-than-expected SEC1 point here.
    let (curve_oid, field_len) = match crv {
        CRV_P256 => (P256_OID, 32),
        CRV_P384 => (P384_OID, 48),
        CRV_P521 => (P521_OID, 66),
        _ => return None,
    };
    let x = left_pad(&x, field_len)?;
    let y = left_pad(&y, field_len)?;

    // Build SEC1 uncompressed point: 0x04 || x || y
    let mut point = Vec::with_capacity(1 + x.len() + y.len());
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    // AlgorithmIdentifier for ecPublicKey carries the curve OID as its parameter (RFC 5480 §2.1.1).
    spki_to_der(
        AlgorithmIdentifier {
            algorithm: oid(EC_PUBLIC_KEY_OID)?,
            parameters: Some(Any::new(rasn::der::encode(&oid(curve_oid)?).ok()?)),
        },
        &point,
    )
}

fn okp_to_der(map: &BTreeMap<i128, &CborValue>) -> Option<Vec<u8>> {
    let crv = cbor_to_i128(map.get(&OKP_CRV)?)?;

    if crv != CRV_ED25519 {
        return None;
    }

    let x = cbor_as_bytes(map.get(&OKP_X)?)?;

    // Ed25519 public keys are exactly 32 bytes (RFC 8032 §5.1.5). Use `left_pad`
    // to enforce the length and reject both short and over-long `x` values,
    // matching the same guard applied to EC coordinates in `ec2_to_der`.
    let x = left_pad(&x, 32)?;

    // Ed25519 takes no AlgorithmIdentifier parameters (RFC 8410 §3).
    spki_to_der(
        AlgorithmIdentifier {
            algorithm: oid(ED25519_OID)?,
            parameters: None,
        },
        &x,
    )
}

fn rsa_to_der(map: &BTreeMap<i128, &CborValue>) -> Option<Vec<u8>> {
    let n = cbor_as_bytes(map.get(&RSA_N)?)?;
    let e = cbor_as_bytes(map.get(&RSA_E)?)?;
    let (n, e) = (strip_leading_zeros(&n), strip_leading_zeros(&e));
    if modulus_bits(n) < MIN_RSA_MODULUS_BITS || e.is_empty() {
        return None;
    }

    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } (RFC 8017 §A.1.1),
    // under rsaEncryption with NULL parameters (RFC 3279 §2.3.1).
    let rsa_public_key = der_tlv(
        0x30,
        &[der_unsigned_integer(n), der_unsigned_integer(e)].concat(),
    );
    spki_to_der(
        AlgorithmIdentifier {
            algorithm: oid(RSA_ENCRYPTION_OID)?,
            parameters: Some(Any::new(vec![0x05, 0x00])),
        },
        &rsa_public_key,
    )
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// Bit length of a big-endian unsigned integer without leading zero bytes.
fn modulus_bits(n: &[u8]) -> usize {
    n.first()
        .map_or(0, |b| n.len() * 8 - b.leading_zeros() as usize)
}

/// Left-pads `bytes` with zeros to exactly `len` bytes, or returns `None` if `bytes` is already
/// longer than `len` (an oversized, malformed coordinate).
fn left_pad(bytes: &[u8], len: usize) -> Option<Vec<u8>> {
    if bytes.len() > len {
        return None;
    }
    let mut padded = vec![0u8; len - bytes.len()];
    padded.extend_from_slice(bytes);
    Some(padded)
}

// ── DER encoding helpers ────────────────────────────────────────────────────

fn oid(components: &[u32]) -> Option<ObjectIdentifier> {
    ObjectIdentifier::new(components.to_vec())
}

fn oid_string(components: &[u32]) -> String {
    components
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// A DER tag-length-value with a definite length.
fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let len_bytes = len.to_be_bytes();
        let len_bytes = strip_leading_zeros(&len_bytes);
        out.push(0x80 | len_bytes.len() as u8);
        out.extend_from_slice(len_bytes);
    }
    out.extend_from_slice(value);
    out
}

/// A DER INTEGER for an unsigned big-endian value without leading zero bytes: a zero byte
/// is prepended when the high bit is set, so it stays positive.
fn der_unsigned_integer(value: &[u8]) -> Vec<u8> {
    if value.first().is_some_and(|b| b & 0x80 != 0) {
        der_tlv(0x02, &[&[0u8][..], value].concat())
    } else {
        der_tlv(0x02, value)
    }
}

fn spki_to_der(algorithm: AlgorithmIdentifier, public_key: &[u8]) -> Option<Vec<u8>> {
    rasn::der::encode(&SubjectPublicKeyInfo {
        algorithm,
        subject_public_key: BitString::from_slice(public_key),
    })
    .ok()
}

// ── CBOR helpers ────────────────────────────────────────────────────────────

/// Converts a CBOR Value map with integer keys into a BTreeMap<i128, &CborValue>.
fn as_cbor_int_map(value: &CborValue) -> Option<BTreeMap<i128, &CborValue>> {
    let map = match value {
        CborValue::Map(m) => m,
        _ => return None,
    };

    let mut result = BTreeMap::new();
    for (k, v) in map {
        let key = cbor_to_i128(k)?;
        result.insert(key, v);
    }
    Some(result)
}

fn cbor_to_i128(value: &CborValue) -> Option<i128> {
    match value {
        CborValue::Integer(n) => Some((*n).into()),
        // When CBOR is transcoded through JSON (as happens in the SDK's manifest read path),
        // integer map keys become text strings (e.g., -3 → "-3"). Accept those too.
        CborValue::Text(s) => s.parse().ok(),
        _ => None,
    }
}

/// Extracts bytes from a CBOR value.
///
/// Handles both native `Bytes` and the JSON-transcoded representation where bytes
/// are encoded as an array of unsigned integers (e.g., `[100, 101, 109, ...]`).
fn cbor_as_bytes(value: &CborValue) -> Option<Vec<u8>> {
    match value {
        CborValue::Bytes(b) => Some(b.clone()),
        // When CBOR bytes are transcoded through JSON, they become arrays of integers.
        CborValue::Array(arr) => arr
            .iter()
            .map(|v| {
                if let CborValue::Integer(n) = v {
                    u8::try_from(*n).ok()
                } else {
                    None
                }
            })
            .collect(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn cbor_int(val: i64) -> CborValue {
        CborValue::Integer(val)
    }

    fn make_ec2_cose_key(crv: i64, x: &[u8], y: &[u8], kid: &[u8]) -> CborValue {
        let mut map = BTreeMap::new();
        map.insert(cbor_int(KTY as i64), cbor_int(KTY_EC2 as i64));
        map.insert(cbor_int(KID as i64), CborValue::Bytes(kid.to_vec()));
        map.insert(cbor_int(EC2_CRV as i64), cbor_int(crv));
        map.insert(cbor_int(EC2_X as i64), CborValue::Bytes(x.to_vec()));
        map.insert(cbor_int(EC2_Y as i64), CborValue::Bytes(y.to_vec()));
        CborValue::Map(map)
    }

    /// The same EC2 key as [`make_ec2_cose_key`], but shaped the way it comes back after a
    /// round-trip through JSON (as happens in the SDK's manifest read path): integer map keys
    /// become text strings, and byte strings become arrays of integers.
    fn make_json_transcoded_ec2_cose_key(crv: i64, x: &[u8], y: &[u8], kid: &[u8]) -> CborValue {
        let ints = |b: &[u8]| CborValue::Array(b.iter().map(|&v| cbor_int(v as i64)).collect());
        let text_key = |k: i128| CborValue::Text(k.to_string());

        let mut map = BTreeMap::new();
        map.insert(text_key(KTY), cbor_int(KTY_EC2 as i64));
        map.insert(text_key(KID), ints(kid));
        map.insert(text_key(EC2_CRV), cbor_int(crv));
        map.insert(text_key(EC2_X), ints(x));
        map.insert(text_key(EC2_Y), ints(y));
        CborValue::Map(map)
    }

    #[test]
    fn kid_extraction_from_ec2_key() {
        let key = make_ec2_cose_key(CRV_P256 as i64, &[1; 32], &[2; 32], b"key-1");
        assert_eq!(kid_from_cose_key(&key).unwrap(), b"key-1");
    }

    #[test]
    fn signing_alg_p256() {
        let key = make_ec2_cose_key(CRV_P256 as i64, &[1; 32], &[2; 32], b"k");
        assert_eq!(signing_alg_from_cose_key(&key).unwrap(), SigningAlg::Es256);
    }

    #[test]
    fn signing_alg_p384() {
        let key = make_ec2_cose_key(CRV_P384 as i64, &[1; 48], &[2; 48], b"k");
        assert_eq!(signing_alg_from_cose_key(&key).unwrap(), SigningAlg::Es384);
    }

    #[test]
    fn signing_alg_p521() {
        let key = make_ec2_cose_key(CRV_P521 as i64, &[1; 66], &[2; 66], b"k");
        assert_eq!(signing_alg_from_cose_key(&key).unwrap(), SigningAlg::Es512);
    }

    #[test]
    fn ec2_p256_to_der_produces_valid_spki() {
        let x = [0xaa; 32];
        let y = [0xbb; 32];
        let key = make_ec2_cose_key(CRV_P256 as i64, &x, &y, b"test-kid");

        let der = cose_key_to_der(&key).unwrap();

        // DER should start with SEQUENCE tag.
        assert_eq!(der[0], 0x30);

        // The AlgorithmIdentifier must name ecPublicKey, parameterised by the P-256 curve.
        let spki: SubjectPublicKeyInfo = rasn::der::decode(&der).unwrap();
        assert_eq!(spki.algorithm.algorithm, oid(EC_PUBLIC_KEY_OID).unwrap());
        assert_eq!(
            spki.algorithm.parameters.as_ref().unwrap().as_bytes(),
            rasn::der::encode(&oid(P256_OID).unwrap())
                .unwrap()
                .as_slice()
        );

        // Should contain the uncompressed point (0x04 || x || y).
        let mut expected_point = vec![0x04];
        expected_point.extend_from_slice(&x);
        expected_point.extend_from_slice(&y);
        assert!(der
            .windows(expected_point.len())
            .any(|w| w == expected_point.as_slice()));
    }

    /// Regression test: per RFC 9053 §7.1.1, EC2 x/y must be exactly the curve's field-element
    /// length. An encoder that strips a coordinate's leading zero byte (a common minimal-length
    /// big-integer encoding) must still produce a correctly-sized, left-zero-padded SEC1 point.
    #[test]
    fn ec2_p256_to_der_pads_short_coordinates() {
        let short_x = [0xaa; 31]; // one byte short of P-256's 32-byte field length
        let y = [0xbb; 32];
        let key = make_ec2_cose_key(CRV_P256 as i64, &short_x, &y, b"test-kid");

        let der = cose_key_to_der(&key).unwrap();

        let mut expected_point = vec![0x04, 0x00]; // leading zero pad byte for x
        expected_point.extend_from_slice(&short_x);
        expected_point.extend_from_slice(&y);
        assert!(
            der.windows(expected_point.len())
                .any(|w| w == expected_point.as_slice()),
            "expected a zero-padded 32-byte x coordinate in the SEC1 point"
        );
    }

    // ── JSON-transcoded input ────────────────────────────────────────────────
    //
    // `cbor_to_i128` accepts `Text` map keys and `cbor_as_bytes` accepts integer arrays
    // specifically to survive a CBOR -> JSON -> CBOR round-trip. These pin that behavior,
    // since it's the shape that actually reaches this code from the manifest read path.

    /// A JSON-transcoded key must produce byte-identical DER to its native-CBOR equivalent.
    #[test]
    fn json_transcoded_ec2_key_matches_native_der() {
        let (x, y) = ([0xaa; 32], [0xbb; 32]);
        let native = make_ec2_cose_key(CRV_P256 as i64, &x, &y, b"test-kid");
        let transcoded = make_json_transcoded_ec2_cose_key(CRV_P256 as i64, &x, &y, b"test-kid");

        assert_eq!(
            cose_key_to_der(&transcoded).unwrap(),
            cose_key_to_der(&native).unwrap(),
            "a JSON round-trip must not change the DER encoding"
        );
    }

    #[test]
    fn json_transcoded_key_resolves_kid_and_alg() {
        let transcoded =
            make_json_transcoded_ec2_cose_key(CRV_P256 as i64, &[1; 32], &[2; 32], b"key-1");

        assert_eq!(kid_from_cose_key(&transcoded).unwrap(), b"key-1");
        assert_eq!(
            signing_alg_from_cose_key(&transcoded).unwrap(),
            SigningAlg::Es256
        );
    }

    /// A text key that isn't a number at all must not be silently treated as absent.
    #[test]
    fn non_numeric_text_key_is_rejected() {
        let mut map = BTreeMap::new();
        map.insert(CborValue::Text("kty".to_string()), cbor_int(KTY_EC2 as i64));
        let key = CborValue::Map(map);

        assert!(cose_key_to_der(&key).is_none());
        assert!(signing_alg_from_cose_key(&key).is_none());
    }

    /// An integer array carrying a value outside the byte range isn't a transcoded bstr.
    #[test]
    fn out_of_range_integer_array_is_rejected() {
        let mut map = BTreeMap::new();
        map.insert(cbor_int(KTY as i64), cbor_int(KTY_EC2 as i64));
        map.insert(cbor_int(EC2_CRV as i64), cbor_int(CRV_P256 as i64));
        map.insert(
            cbor_int(EC2_X as i64),
            CborValue::Array(vec![cbor_int(300)]), // > u8::MAX
        );
        map.insert(cbor_int(EC2_Y as i64), CborValue::Bytes(vec![2; 32]));

        assert!(cose_key_to_der(&CborValue::Map(map)).is_none());
    }

    #[test]
    fn ec2_to_der_rejects_oversized_coordinate() {
        let oversized_x = [0xaa; 33]; // one byte over P-256's 32-byte field length
        let y = [0xbb; 32];
        let key = make_ec2_cose_key(CRV_P256 as i64, &oversized_x, &y, b"test-kid");

        assert!(cose_key_to_der(&key).is_none());
    }

    #[test]
    fn ed25519_to_der_produces_valid_spki() {
        let x = [0xcc; 32];
        let mut map = BTreeMap::new();
        map.insert(cbor_int(KTY as i64), cbor_int(KTY_OKP as i64));
        map.insert(cbor_int(OKP_CRV as i64), cbor_int(CRV_ED25519 as i64));
        map.insert(cbor_int(OKP_X as i64), CborValue::Bytes(x.to_vec()));
        let key = CborValue::Map(map);

        let der = cose_key_to_der(&key).unwrap();

        assert_eq!(der[0], 0x30);
        let spki: SubjectPublicKeyInfo = rasn::der::decode(&der).unwrap();
        assert_eq!(spki.algorithm.algorithm, oid(ED25519_OID).unwrap());
        assert!(spki.algorithm.parameters.is_none());
        assert!(der.windows(x.len()).any(|w| w == x));
    }

    #[test]
    fn unsupported_kty_returns_none() {
        let mut map = BTreeMap::new();
        map.insert(cbor_int(KTY as i64), cbor_int(99));
        let key = CborValue::Map(map);

        assert!(cose_key_to_der(&key).is_none());
        assert!(signing_alg_from_cose_key(&key).is_none());
    }

    #[test]
    fn missing_parameters_returns_none() {
        let mut map = BTreeMap::new();
        map.insert(cbor_int(KTY as i64), cbor_int(KTY_EC2 as i64));
        // Missing crv, x, y
        let key = CborValue::Map(map);

        assert!(cose_key_to_der(&key).is_none());
    }

    fn cert_spki(chain_pem: &[u8]) -> Vec<u8> {
        let pem = x509_parser::pem::Pem::iter_from_buffer(chain_pem)
            .next()
            .unwrap()
            .unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
        cert.tbs_certificate.subject_pki.raw.to_vec()
    }

    fn make_rsa_cose_key(n: &[u8], alg: Option<i64>) -> CborValue {
        let mut map = vec![
            (cbor_int(1), cbor_int(3)), // kty: RSA
            (cbor_int(2), CborValue::Bytes(b"rsa".to_vec())),
            (cbor_int(-1), CborValue::Bytes(n.to_vec())),
            (cbor_int(-2), CborValue::Bytes(vec![1, 0, 1])),
        ];
        if let Some(alg) = alg {
            map.push((cbor_int(3), cbor_int(alg)));
        }
        CborValue::Map(map.into_iter().collect())
    }

    /// EC and Ed25519 keys round-trip from a certificate's SubjectPublicKeyInfo to a COSE_Key
    /// and back to the same DER.
    #[test]
    fn spki_round_trips_for_ec_and_ed25519_keys() {
        for (chain, alg) in [
            (
                &include_bytes!("../../tests/fixtures/certs/es256.pub")[..],
                SigningAlg::Es256,
            ),
            (
                &include_bytes!("../../tests/fixtures/certs/es384.pub")[..],
                SigningAlg::Es384,
            ),
            (
                &include_bytes!("../../tests/fixtures/certs/es512.pub")[..],
                SigningAlg::Es512,
            ),
            (
                &include_bytes!("../../tests/fixtures/certs/ed25519.pub")[..],
                SigningAlg::Ed25519,
            ),
        ] {
            let spki = cert_spki(chain);
            let cose_key = cose_key_from_spki(&spki, alg, b"k").unwrap();
            assert_eq!(signing_alg_from_cose_key(&cose_key), Some(alg));
            assert_eq!(kid_from_cose_key(&cose_key), Some(b"k".to_vec()));
            assert_eq!(cose_key_to_der(&cose_key), Some(spki), "{alg:?}");
        }
    }

    /// A PS* certificate's key (under id-RSASSA-PSS) becomes an RSA COSE_Key, whose DER is an
    /// rsaEncryption SubjectPublicKeyInfo with the same modulus and exponent.
    #[test]
    fn rsa_pss_spki_becomes_rsa_cose_key() {
        let spki = cert_spki(include_bytes!("../../tests/fixtures/certs/ps256.pub"));
        let cose_key = cose_key_from_spki(&spki, SigningAlg::Ps256, b"k").unwrap();
        assert_eq!(
            signing_alg_from_cose_key(&cose_key),
            Some(SigningAlg::Ps256)
        );
        let der = cose_key_to_der(&cose_key).unwrap();
        let (_, parsed) =
            <x509_parser::x509::SubjectPublicKeyInfo as x509_parser::prelude::FromDer<_>>::from_der(
                &der,
            )
            .unwrap();
        assert_eq!(
            parsed.algorithm.algorithm.to_id_string(),
            oid_string(RSA_ENCRYPTION_OID)
        );
        let x509_parser::public_key::PublicKey::RSA(rsa) = parsed.parsed().unwrap() else {
            unreachable!("expected an RSA key");
        };
        assert_eq!(rsa.key_size(), 4096);
        // The wrong algorithm for the key is refused.
        assert!(cose_key_from_spki(&spki, SigningAlg::Es256, b"k").is_none());
    }

    /// An RSA key needs a PS* `alg`; an `alg` that contradicts the key is rejected.
    #[test]
    fn declared_alg_must_fit_the_key() {
        let n = [&[0xc0u8][..], &[0x11; 255]].concat(); // 2048-bit modulus
        assert_eq!(
            signing_alg_from_cose_key(&make_rsa_cose_key(&n, None)),
            None
        );
        assert_eq!(
            signing_alg_from_cose_key(&make_rsa_cose_key(&n, Some(-38))),
            Some(SigningAlg::Ps384)
        );
        assert_eq!(
            signing_alg_from_cose_key(&make_rsa_cose_key(&n, Some(-7))),
            None
        );
        assert_eq!(
            signing_alg_from_cose_key(&make_rsa_cose_key(&n, Some(-999))),
            None
        );

        let ec = make_ec2_cose_key(1, &[1; 32], &[2; 32], b"k");
        let CborValue::Map(mut map) = ec else {
            unreachable!()
        };
        map.insert(cbor_int(3), cbor_int(-35)); // ES384 on a P-256 key
        assert_eq!(
            signing_alg_from_cose_key(&CborValue::Map(map.clone())),
            None
        );
        map.insert(cbor_int(3), cbor_int(-7));
        assert_eq!(
            signing_alg_from_cose_key(&CborValue::Map(map)),
            Some(SigningAlg::Es256)
        );
    }

    /// RSA moduli under 2048 bits are rejected, as for claim-signing certificates.
    #[test]
    fn short_rsa_modulus_is_rejected() {
        let n2048 = [&[0x80u8][..], &[0x11; 255]].concat();
        assert!(cose_key_to_der(&make_rsa_cose_key(&n2048, Some(-37))).is_some());
        let n2047 = [&[0x40u8][..], &[0x11; 255]].concat();
        assert!(cose_key_to_der(&make_rsa_cose_key(&n2047, Some(-37))).is_none());
        // Leading zero bytes don't count towards the size.
        let padded = [&[0u8, 0][..], &n2047].concat();
        assert!(cose_key_to_der(&make_rsa_cose_key(&padded, Some(-37))).is_none());
    }
}
