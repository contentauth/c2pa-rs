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

//! Utilities for computing COSE signature reserve sizes.
//!
//! Three independent quantities make up the total space that must be reserved
//! in an asset before signing:
//!
//! 1. **Raw signature bytes** — exact, derivable from the algorithm and the
//!    signing certificate (see [`raw_sig_len`]).
//! 2. **Embedded certificate chain** — exact, the DER bytes COSE includes in
//!    the unprotected headers (see [`cert_chain_der_len`]).
//! 3. **COSE/CBOR framing** — small, bounded constant (see [`COSE_OVERHEAD`]).
//! 4. **Timestamp token** — only when a TSA URL is configured; the size
//!    depends on the TSA's response and cannot be determined in advance
//!    (see [`TIMESTAMP_RESERVE`] for a conservative estimate).
//!
//! Use [`cose_reserve_size`] to combine all four into a single estimate.

use x509_parser::{
    certificate::X509Certificate, der_parser::ber::parse_ber_sequence, prelude::FromDer,
};

use crate::crypto::raw_signature::SigningAlg;

/// Returns the exact byte length of the raw signature produced by `alg` for
/// the key in `cert_chain_pem`.
///
/// COSE uses fixed-length raw encoding (not DER) for all supported algorithms:
///
/// | Algorithm | Encoding              | Size      |
/// |-----------|----------------------|-----------|
/// | `Ed25519` | raw scalar pair      | 64 bytes  |
/// | `Es256`   | P-256 raw r\|s       | 64 bytes  |
/// | `Es384`   | P-384 raw r\|s       | 96 bytes  |
/// | `Es512`   | P-521 raw r\|s       | 132 bytes |
/// | `Ps256`   | RSA-PSS = modulus len | key-size  |
/// | `Ps384`   | RSA-PSS = modulus len | key-size  |
/// | `Ps512`   | RSA-PSS = modulus len | key-size  |
///
/// For ECDSA and EdDSA the cert is not inspected — the size is fixed by the
/// named curve.  For RSA-PSS the RSA modulus is read from the end-entity
/// certificate in `cert_chain_pem`; returns `None` if the cert cannot be
/// parsed.
pub fn raw_sig_len(alg: SigningAlg, cert_chain_pem: &[u8]) -> Option<usize> {
    match alg {
        SigningAlg::Ed25519 => Some(64),
        SigningAlg::Es256 => Some(64),
        SigningAlg::Es384 => Some(96),
        SigningAlg::Es512 => Some(132),
        SigningAlg::Ps256 | SigningAlg::Ps384 | SigningAlg::Ps512 => {
            rsa_key_len_from_cert_chain(cert_chain_pem)
        }
    }
}

/// Parses the end-entity certificate from `cert_chain_pem` and returns the
/// RSA modulus length in bytes, which equals the RSA-PSS signature length.
fn rsa_key_len_from_cert_chain(cert_chain_pem: &[u8]) -> Option<usize> {
    let pems = pem::parse_many(cert_chain_pem).ok()?;
    let cert_der = pems.into_iter().next()?.into_contents();
    let (_, cert) = X509Certificate::from_der(&cert_der).ok()?;

    // RSAPublicKey is a DER SEQUENCE { modulus INTEGER, exponent INTEGER }.
    let pub_key_bytes = &cert.subject_pki.subject_public_key.data;
    let (_, seq) = parse_ber_sequence(pub_key_bytes).ok()?;
    let items = seq.as_sequence().ok()?;

    // The modulus is the first INTEGER.  Its bit length equals the RSA key
    // size; RSA-PSS always produces a signature of exactly that many bytes.
    let modulus = items.first()?.as_biguint().ok()?;
    Some((modulus.bits() as usize).div_ceil(8))
}

/// Returns the total byte length of all DER-encoded certificates in the PEM
/// chain.
///
/// COSE embeds raw DER bytes in the `x5chain` unprotected header, not the
/// base64-encoded PEM form, so this — not `cert_chain_pem.len()` — is the
/// value to use when estimating the COSE payload size.
///
/// Returns 0 if the PEM cannot be parsed; callers should treat this as a
/// signal that the cert chain is unavailable.
pub fn cert_chain_der_len(cert_chain_pem: &[u8]) -> usize {
    pem::parse_many(cert_chain_pem)
        .unwrap_or_default()
        .iter()
        .map(|p| p.contents().len())
        .sum()
}

/// Byte overhead of the COSE_Sign1 CBOR envelope, excluding the certificate
/// chain, the raw signature bytes, and any timestamp token.
///
/// The COSE_Sign1 framing adds overhead beyond the raw certificate chain and
/// signature bytes.  This includes the CBOR tag, array and map headers, the
/// bstr length prefixes for the protected header and each certificate, the
/// null detached-payload byte, and the CBOR length prefixes whose sizes depend
/// on the exact byte counts involved (CBOR encodes integers up to 23 in one
/// byte, 24–255 in two bytes, etc.).  Empirically, the framing for a two-cert
/// Ed25519 chain totals roughly 255 bytes.
///
/// 512 is chosen to stay well above the observed framing cost (≈ 255 bytes)
/// while leaving room for the `pad_cose_sig` minimum-padding requirement
/// (`PAD_OFFSET = 7`) and any additional unprotected headers (`x5t`, `kid`,
/// etc.) that an implementation may add.  The cert chain and signature sizes
/// are tracked exactly via `cert_chain_der_len` and `raw_sig_len`, so the only
/// uncertainty this constant needs to absorb is the variable CBOR framing.
pub const COSE_OVERHEAD: usize = 512;

/// Conservative byte allowance for an RFC 3161 timestamp token when a TSA URL
/// is configured.
///
/// Actual token sizes depend on the TSA's own certificate chain.  Tokens from
/// a TSA with a single intermediate CA in its chain are typically 2–4 KB;
/// 5 KB is a safe upper bound for most production TSAs.
///
/// There is no way to determine the exact size before making the TSA request.
/// Production TSAs vary considerably: tokens from Digicert's TSA (which embeds
/// multiple intermediate certificates) have been observed at roughly 5.8 KB
/// after CBOR wrapping; 8 KB provides a safe margin for TSAs with up to two
/// intermediate certificates in their chain.  If your TSA consistently returns
/// smaller or larger tokens, supply a custom value instead of this constant.
pub const TIMESTAMP_RESERVE: usize = 8192;

/// Returns the total byte reserve needed for a `COSE_Sign1` signature block.
///
/// This is the primary entry point for computing `reserve_size`.  It combines:
///
/// - Exact raw signature size (from algorithm + certificate public key)
/// - DER certificate chain length (actual bytes embedded in COSE headers)
/// - Fixed COSE/CBOR framing overhead ([`COSE_OVERHEAD`])
/// - Caller-supplied timestamp allowance
///
/// For the timestamp, pass [`TIMESTAMP_RESERVE`] when a TSA URL is configured
/// and `0` otherwise.  If you know your TSA's typical token size, pass that
/// value instead.
///
/// Returns `None` when `alg` is an RSA variant and the end-entity certificate
/// in `cert_chain_pem` cannot be parsed to determine the key size.  In that
/// case, substitute a safe upper bound such as 512 (RSA-4096 signature size)
/// for the raw signature component.
pub fn cose_reserve_size(
    alg: SigningAlg,
    cert_chain_pem: &[u8],
    timestamp_len: usize,
) -> Option<usize> {
    let sig = raw_sig_len(alg, cert_chain_pem)?;
    let certs = cert_chain_der_len(cert_chain_pem);
    Some(COSE_OVERHEAD + sig + certs + timestamp_len)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::crypto::raw_signature::SigningAlg;

    const ED25519_CERT: &[u8] = include_bytes!("../../../tests/fixtures/certs/ed25519.pub");
    const ES256_CERT: &[u8] = include_bytes!("../../../tests/fixtures/certs/es256.pub");
    const ES384_CERT: &[u8] = include_bytes!("../../../tests/fixtures/certs/es384.pub");
    const ES512_CERT: &[u8] = include_bytes!("../../../tests/fixtures/certs/es512.pub");
    const PS256_CERT: &[u8] = include_bytes!("../../../tests/fixtures/certs/ps256.pub");
    const PS384_CERT: &[u8] = include_bytes!("../../../tests/fixtures/certs/ps384.pub");
    const PS512_CERT: &[u8] = include_bytes!("../../../tests/fixtures/certs/ps512.pub");

    #[test]
    fn ecdsa_and_eddsa_sig_sizes_are_fixed() {
        assert_eq!(raw_sig_len(SigningAlg::Ed25519, ED25519_CERT), Some(64));
        assert_eq!(raw_sig_len(SigningAlg::Es256, ES256_CERT), Some(64));
        assert_eq!(raw_sig_len(SigningAlg::Es384, ES384_CERT), Some(96));
        assert_eq!(raw_sig_len(SigningAlg::Es512, ES512_CERT), Some(132));
    }

    #[test]
    fn ecdsa_sig_size_ignores_cert_content() {
        // For ECDSA/EdDSA the size is fixed by the curve; the cert is irrelevant.
        assert_eq!(raw_sig_len(SigningAlg::Es256, b"garbage cert"), Some(64));
        assert_eq!(raw_sig_len(SigningAlg::Ed25519, b""), Some(64));
    }

    #[test]
    fn rsa_sig_size_matches_key_size() {
        // Test certs use 4096-bit RSA keys → 512 bytes.
        assert_eq!(raw_sig_len(SigningAlg::Ps256, PS256_CERT), Some(512));
        assert_eq!(raw_sig_len(SigningAlg::Ps384, PS384_CERT), Some(512));
        assert_eq!(raw_sig_len(SigningAlg::Ps512, PS512_CERT), Some(512));
    }

    #[test]
    fn rsa_sig_size_returns_none_for_unparseable_cert() {
        assert_eq!(raw_sig_len(SigningAlg::Ps256, b"not a cert"), None);
    }

    #[test]
    fn cert_chain_der_len_is_less_than_pem_len() {
        // PEM is base64 + headers; DER is the raw binary — always smaller.
        let der_len = cert_chain_der_len(ED25519_CERT);
        assert!(der_len > 0);
        assert!(der_len < ED25519_CERT.len());
    }

    #[test]
    fn cert_chain_der_len_returns_zero_for_garbage() {
        assert_eq!(cert_chain_der_len(b"not a pem"), 0);
    }

    #[test]
    fn cose_reserve_size_without_timestamp() {
        let r = cose_reserve_size(SigningAlg::Ed25519, ED25519_CERT, 0).unwrap();
        let expected = COSE_OVERHEAD + 64 + cert_chain_der_len(ED25519_CERT);
        assert_eq!(r, expected);
    }

    #[test]
    fn cose_reserve_size_with_timestamp() {
        let r = cose_reserve_size(SigningAlg::Es256, ES256_CERT, TIMESTAMP_RESERVE).unwrap();
        let expected = COSE_OVERHEAD + 64 + cert_chain_der_len(ES256_CERT) + TIMESTAMP_RESERVE;
        assert_eq!(r, expected);
    }

    #[test]
    fn cose_reserve_size_rsa_without_timestamp() {
        let r = cose_reserve_size(SigningAlg::Ps256, PS256_CERT, 0).unwrap();
        let expected = COSE_OVERHEAD + 512 + cert_chain_der_len(PS256_CERT);
        assert_eq!(r, expected);
    }

    #[test]
    fn cose_reserve_size_returns_none_for_bad_rsa_cert() {
        assert_eq!(
            cose_reserve_size(SigningAlg::Ps256, b"garbage", TIMESTAMP_RESERVE),
            None
        );
    }
}
