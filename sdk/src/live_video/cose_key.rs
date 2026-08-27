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
//! Supports EC2 keys (P-256, P-384, P-521) and OKP keys (Ed25519).
//!
//! [RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052

use std::collections::BTreeMap;

use c2pa_cbor::Value as CborValue;
use ed25519_dalek::VerifyingKey;

use crate::SigningAlg;

// COSE_Key common parameter labels (RFC 9052 §7.1).
const KTY: i128 = 1;
const KID: i128 = 2;

// COSE_Key type values.
const KTY_EC2: i128 = 2;
const KTY_OKP: i128 = 1;

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

// DER-encoded OID constants for SubjectPublicKeyInfo construction.
// ecPublicKey: 1.2.840.10045.2.1
const EC_PUBLIC_KEY_OID: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

// P-256: 1.2.840.10045.3.1.7
const P256_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

// P-384: 1.3.132.0.34
const P384_OID: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

// P-521: 1.3.132.0.35
const P521_OID: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

// Ed25519: 1.3.101.112
const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

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
pub(crate) fn signing_alg_from_cose_key(cose_key: &CborValue) -> Option<SigningAlg> {
    let map = as_cbor_int_map(cose_key)?;
    let kty = cbor_to_i128(map.get(&KTY)?)?;

    match kty {
        KTY_EC2 => {
            let crv = cbor_to_i128(map.get(&EC2_CRV)?)?;
            match crv {
                CRV_P256 => Some(SigningAlg::Es256),
                CRV_P384 => Some(SigningAlg::Es384),
                CRV_P521 => Some(SigningAlg::Es512),
                _ => None,
            }
        }
        KTY_OKP => {
            let crv = cbor_to_i128(map.get(&OKP_CRV)?)?;
            match crv {
                CRV_ED25519 => Some(SigningAlg::Ed25519),
                _ => None,
            }
        }
        _ => None,
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
        _ => None,
    }
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

    // Build DER SubjectPublicKeyInfo:
    //   SEQUENCE {
    //     SEQUENCE { OID ecPublicKey, OID curve }
    //     BIT STRING { uncompressed point }
    //   }
    let algorithm_seq = der_sequence(&[EC_PUBLIC_KEY_OID, curve_oid])?;
    let bit_string = der_bit_string(&point)?;
    let spki = der_sequence(&[&algorithm_seq, &bit_string])?;

    Some(spki)
}

fn okp_to_der(map: &BTreeMap<i128, &CborValue>) -> Option<Vec<u8>> {
    let crv = cbor_to_i128(map.get(&OKP_CRV)?)?;

    if crv != CRV_ED25519 {
        return None;
    }

    let x = cbor_as_bytes(map.get(&OKP_X)?)?;

    // Build DER SubjectPublicKeyInfo:
    //   SEQUENCE {
    //     SEQUENCE { OID ed25519 }
    //     BIT STRING { public key bytes }
    //   }
    let algorithm_seq = der_sequence(&[ED25519_OID])?;
    let bit_string = der_bit_string(&x)?;
    let spki = der_sequence(&[&algorithm_seq, &bit_string])?;

    Some(spki)
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

/// DER definite-length encoding, up to the two-byte long form (65535 bytes).
///
/// Returns `None` beyond that rather than silently truncating `len` into two bytes. Every key
/// this module encodes is far below the limit (the largest, a P-521 SPKI, is a few hundred
/// bytes), so this is a guard against a future caller rather than a reachable case today.
fn der_length(len: usize) -> Option<Vec<u8>> {
    if len < 128 {
        Some(vec![len as u8])
    } else if len < 256 {
        Some(vec![0x81, len as u8])
    } else if len < 65536 {
        Some(vec![0x82, (len >> 8) as u8, (len & 0xff) as u8])
    } else {
        None
    }
}

fn der_sequence(items: &[&[u8]]) -> Option<Vec<u8>> {
    let total: usize = items.iter().map(|i| i.len()).sum();
    let mut out = vec![0x30]; // SEQUENCE tag
    out.extend(der_length(total)?);
    for item in items {
        out.extend_from_slice(item);
    }
    Some(out)
}

fn der_bit_string(data: &[u8]) -> Option<Vec<u8>> {
    // BIT STRING: tag 0x03, length = data.len() + 1 (for unused-bits byte), 0x00 (unused bits), data
    let content_len = data.len() + 1;
    let mut out = vec![0x03];
    out.extend(der_length(content_len)?);
    out.push(0x00); // zero unused bits
    out.extend_from_slice(data);
    Some(out)
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

        // Should contain the EC public key OID.
        assert!(der
            .windows(EC_PUBLIC_KEY_OID.len())
            .any(|w| w == EC_PUBLIC_KEY_OID));

        // Should contain the P-256 curve OID.
        assert!(der.windows(P256_OID.len()).any(|w| w == P256_OID));

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

    // ── DER length encoding ──────────────────────────────────────────────────

    #[test]
    fn der_length_covers_short_and_long_forms() {
        assert_eq!(der_length(10).unwrap(), vec![10]); // short form
        assert_eq!(der_length(200).unwrap(), vec![0x81, 200]); // one-byte long form
        assert_eq!(der_length(1000).unwrap(), vec![0x82, 0x03, 0xe8]); // two-byte long form
    }

    /// The encoder tops out at the two-byte long form; beyond that it must refuse rather than
    /// truncate the length into two bytes. Unreachable for these curves, but the guard is the
    /// documented contract.
    #[test]
    fn der_length_refuses_beyond_two_byte_form() {
        assert_eq!(der_length(65535).unwrap(), vec![0x82, 0xff, 0xff]);
        assert!(der_length(65536).is_none());
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
        assert!(der.windows(ED25519_OID.len()).any(|w| w == ED25519_OID));
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
}
