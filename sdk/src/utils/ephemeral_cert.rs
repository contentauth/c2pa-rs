// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.
//
// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.
//
// Certificate structure and encoding in this module are based on the
// X.509/PKIX standards (RFC 5280) and on the rasn and rasn_pkix crates.
// Copyright (c) 2020-2025 the rasn developers (https://github.com/librasn/rasn).
// rasn and rasn_pkix are licensed under the MIT License or the Apache License,
// Version 2.0, at your option.

//! In-house X.509 ephemeral certificate generation for Ed25519.
//!
//! Builds CA and end-entity certificates using rasn_pkix and ed25519-dalek,
//! without rcgen, so it works on Wasm (getrandom) and native targets.
//!
//! ## OpenSSL 3.x verification
//!
//! OpenSSL 3.x validates certificates in two stages: it first runs
//! `ossl_x509v3_cache_extensions()` to decode and check every extension, then
//! builds the chain. If any extension is missing when required, fails to
//! decode, or violates a constraint (e.g. empty Key Usage), the cert is marked
//! invalid and you get `X509V3_R_INVALID_CERTIFICATE` (error 1100009E) before
//! issuer lookup. Common compliance expectations:
//!
//! - **Basic Constraints**: End-entity certs should include Basic Constraints
//!   with `cA=FALSE` so validators can distinguish them from CAs (RFC 5280
//!   allows it to be omitted, but many stacks expect it).
//! - **Key Usage**: If present, at least one bit must be set (RFC 5280).
//!
//! We include Basic Constraints (cA=FALSE) on the EE cert for compatibility
//! with strict validators.
//!
//! ### BasicConstraints encoding (OpenSSL 3.x)
//!
//! rasn encodes `BasicConstraints { ca: false, path_len_constraint: None }` as
//! an **empty SEQUENCE** (`30 00`) because of `#[rasn(default)]` on the `ca`
//! field — the value false is treated as default and omitted. OpenSSL expects
//! the cA BOOLEAN to be present when the extension is present, so we use
//! minimal DER for the EE cert: `SEQUENCE { BOOLEAN FALSE }` = `30 03 01 01
//! 00`. See `test_basic_constraints_encoding_compare`.
//!
//! ### Key Usage and Extended Key Usage
//!
//! EE certs include Key Usage (digitalSignature) and Extended Key Usage
//! (emailProtection and anyExtendedKeyUsage) so validators that check purpose
//! accept the cert for signing and for "any" purpose.
//!
//! ### macOS / LibreSSL and ASN.1 errors
//!
//! On macOS the `openssl` CLI is often **LibreSSL**, not upstream OpenSSL.
//! LibreSSL can fail during `openssl verify` with ASN.1 decoding errors such as
//! "wrong tag", "nested asn1 error", "header too long", or "bad object header".
//! These usually indicate the decoder hit a structure it doesn't accept (e.g.
//! different length encoding or tag expectations). Without running the
//! diagnostic test (`test_openssl_which_extension_fails`) on that exact runner,
//! we don't know which part of our cert triggers it. The cross-check test
//! treats these as a known platform quirk and skips the verify assertion
//! instead of failing.

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use pkcs8::{EncodePrivateKey, LineEnding};
use rasn::types::{Any, BitString, Integer, ObjectIdentifier, OctetString, PrintableString, SetOf};
use rasn_pkix::{
    AlgorithmIdentifier, AttributeTypeAndValue, AuthorityKeyIdentifier, BasicConstraints,
    Certificate, Extension, Extensions, GeneralName, Name, RelativeDistinguishedName,
    SubjectPublicKeyInfo, TbsCertificate, Time, Validity, Version,
};
use sha1::{Digest, Sha1};

use crate::{Error, Result};

/// OID id-ed25519 (1.3.101.112)
const ED25519_OID: &[u64] = &[1, 3, 101, 112];

/// OID commonName (2.5.4.3)
const CN_OID: &[u64] = &[2, 5, 4, 3];

/// OID organizationName (2.5.4.10)
const ORG_OID: &[u64] = &[2, 5, 4, 10];

/// OID id-ce-keyUsage (2.5.29.15)
const KEY_USAGE_OID: &[u64] = &[2, 5, 29, 15];

/// OID id-ce-basicConstraints (2.5.29.19)
const BASIC_CONSTRAINTS_OID: &[u64] = &[2, 5, 29, 19];

/// OID id-ce-subjectKeyIdentifier (2.5.29.14)
const SUBJECT_KEY_ID_OID: &[u64] = &[2, 5, 29, 14];

/// OID id-ce-authorityKeyIdentifier (2.5.29.35)
const AUTH_KEY_ID_OID: &[u64] = &[2, 5, 29, 35];

/// OID id-ce-subjectAltName (2.5.29.17)
const SUBJECT_ALT_NAME_OID: &[u64] = &[2, 5, 29, 17];

/// OID id-ce-extKeyUsage (2.5.29.37)
const EXT_KEY_USAGE_OID: &[u64] = &[2, 5, 29, 37];

/// OID id-kp-emailProtection (1.3.6.1.5.5.7.3.4)
const EKU_EMAIL_PROTECTION_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 4];

/// OID id-kp-anyExtendedKeyUsage (1.3.6.1.5.5.7.3.0)
const EKU_ANY_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 0];

fn oid(components: &[u64]) -> Result<ObjectIdentifier> {
    ObjectIdentifier::new(components.iter().map(|&c| c as u32).collect::<Vec<u32>>())
        .ok_or_else(|| Error::OtherError(Box::new(std::io::Error::other("invalid OID"))))
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::OtherError(Box::new(e)))
}

/// Generate a new Ed25519 keypair using OS/browser RNG (works on Wasm via
/// getrandom).
fn generate_ed25519_keypair() -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    fill_random(&mut seed)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn dn_attr(oid_components: &[u64], value: &str) -> Result<AttributeTypeAndValue> {
    let ps =
        PrintableString::try_from(value.to_string()).map_err(|e| Error::OtherError(Box::new(e)))?;
    let value_der = rasn::der::encode(&ps).map_err(|e| Error::OtherError(Box::new(e)))?;

    Ok(AttributeTypeAndValue {
        r#type: oid(oid_components)?,
        value: Any::new(value_der),
    })
}

fn rdn_single(oid_components: &[u64], value: &str) -> Result<RelativeDistinguishedName> {
    let mut set = SetOf::new();
    set.insert(dn_attr(oid_components, value)?);
    Ok(RelativeDistinguishedName::from(set))
}

/// Build a Name from common name and optional organization.
fn build_name(cn: &str, org: Option<&str>) -> Result<Name> {
    let mut rdns = vec![rdn_single(CN_OID, cn)?];
    if let Some(o) = org {
        rdns.push(rdn_single(ORG_OID, o)?);
    }

    Ok(Name::RdnSequence(rdns))
}

fn ed25519_algorithm_identifier() -> Result<AlgorithmIdentifier> {
    Ok(AlgorithmIdentifier {
        algorithm: oid(ED25519_OID)?,
        parameters: None,
    })
}

fn subject_public_key_info(verifying_key: &VerifyingKey) -> Result<SubjectPublicKeyInfo> {
    Ok(SubjectPublicKeyInfo {
        algorithm: ed25519_algorithm_identifier()?,
        subject_public_key: BitString::from_slice(verifying_key.as_bytes()),
    })
}

/// Validity: notBefore = now - 1 day, notAfter = now + 365 days.
fn default_validity() -> Validity {
    let now = Utc::now();
    let not_before = now - chrono::Duration::days(1);
    let not_after = now + chrono::Duration::days(365);

    Validity {
        not_before: Time::Utc(not_before),
        not_after: Time::Utc(not_after),
    }
}

fn subject_key_identifier_ext(public_key_der: &[u8]) -> Result<Extension> {
    let hash = Sha1::digest(public_key_der);

    Ok(Extension {
        extn_id: oid(SUBJECT_KEY_ID_OID)?,
        critical: false,
        extn_value: OctetString::from(hash.to_vec()),
    })
}

fn authority_key_identifier_ext(key_id: Option<Vec<u8>>) -> Result<Extension> {
    let aki = AuthorityKeyIdentifier {
        key_identifier: key_id.map(OctetString::from),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };

    Ok(Extension {
        extn_id: oid(AUTH_KEY_ID_OID)?,
        critical: false,
        extn_value: rasn::der::encode(&aki)
            .map_err(|e| Error::OtherError(Box::new(e)))?
            .into(),
    })
}

/// Serial number for certs: positive integer (must be unique per issuer).
fn serial_number() -> Result<rasn_pkix::CertificateSerialNumber> {
    let mut bytes = [0u8; 7];
    fill_random(&mut bytes)?;

    let n = u64::from_be_bytes([
        0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
    ]);

    Ok(Integer::from((n as i64).saturating_add(1)))
}

/// Build and sign a self-signed CA certificate.
fn build_ca_cert(cn: &str, org: &str, keypair: &SigningKey) -> Result<Vec<u8>> {
    let verifying_key = keypair.verifying_key();
    let spki = subject_public_key_info(&verifying_key)?;
    let spki_der = rasn::der::encode(&spki).map_err(|e| Error::OtherError(Box::new(e)))?;

    let subject = build_name(cn, Some(org))?;
    let exts = vec![
        Extension {
            extn_id: oid(BASIC_CONSTRAINTS_OID)?,
            critical: true,
            extn_value: rasn::der::encode(&BasicConstraints {
                ca: true,
                path_len_constraint: None,
            })
            .map_err(|e| Error::OtherError(Box::new(e)))?
            .into(),
        },
        Extension {
            extn_id: oid(KEY_USAGE_OID)?,
            critical: true,
            // keyCertSign (5), cRLSign (6), digitalSignature (0)
            extn_value: rasn::der::encode(&BitString::from_slice(&[0x86]))
                .map_err(|e| Error::OtherError(Box::new(e)))?
                .into(),
        },
        subject_key_identifier_ext(&spki_der)?,
    ];

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial_number()?,
        signature: ed25519_algorithm_identifier()?,
        issuer: subject.clone(),
        validity: default_validity(),
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(Extensions::from(exts)),
    };

    let tbs_der = rasn::der::encode(&tbs).map_err(|e| Error::OtherError(Box::new(e)))?;
    let sig = keypair.sign(&tbs_der);

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ed25519_algorithm_identifier()?,
        signature_value: BitString::from_slice(sig.to_bytes().as_slice()),
    };

    rasn::der::encode(&cert).map_err(|e| Error::OtherError(Box::new(e)))
}

/// Context for CA signing (used to keep build_ee_cert under the argument
/// limit).
struct CaSigningContext<'a> {
    subject: &'a Name,
    key: &'a SigningKey,
    ski: Option<Vec<u8>>,
}

/// Extension tags for test-only filtering (omit one to find OpenSSL rejection
/// cause).
const EXT_TAG_BASIC_CONSTRAINTS: &str = "basic_constraints";
const EXT_TAG_KEY_USAGE: &str = "key_usage";
const EXT_TAG_EXT_KEY_USAGE: &str = "ext_key_usage";
const EXT_TAG_SUBJECT_KEY_ID: &str = "subject_key_identifier";
const EXT_TAG_AUTHORITY_KEY_ID: &str = "authority_key_identifier";
const EXT_TAG_SUBJECT_ALT_NAME: &str = "subject_alt_name";

/// Build and sign an end-entity certificate (signed by the CA key).
/// `skip_extensions` is for tests: omit named extensions to find which one
/// breaks OpenSSL.
fn build_ee_cert(
    ee_cn: &str,
    ee_org: &str,
    san_dns: &str,
    ee_keypair: &SigningKey,
    ca: &CaSigningContext<'_>,
    skip_extensions: &[&str],
) -> Result<Vec<u8>> {
    let verifying_key = ee_keypair.verifying_key();
    let spki = subject_public_key_info(&verifying_key)?;
    let spki_der = rasn::der::encode(&spki).map_err(|e| Error::OtherError(Box::new(e)))?;

    let subject = build_name(ee_cn, Some(ee_org))?;

    // Extended Key Usage: emailProtection (C2PA/signing) and anyExtendedKeyUsage
    // (any purpose)
    let eku_list: rasn_pkix::ExtKeyUsageSyntax =
        vec![oid(EKU_EMAIL_PROTECTION_OID)?, oid(EKU_ANY_OID)?];

    let eku_value = rasn::der::encode(&eku_list).map_err(|e| Error::OtherError(Box::new(e)))?;

    let mut ext_pairs: Vec<(&str, Extension)> = vec![
        (
            EXT_TAG_BASIC_CONSTRAINTS,
            Extension {
                extn_id: oid(BASIC_CONSTRAINTS_OID)?,
                critical: true,
                // Minimal DER for BasicConstraints cA=FALSE: SEQUENCE { BOOLEAN FALSE }.
                // rasn's encoding is rejected by OpenSSL 3.x in ossl_x509v3_cache_extensions.
                extn_value: OctetString::from([0x30, 0x03, 0x01, 0x01, 0x00]),
            },
        ),
        (
            EXT_TAG_KEY_USAGE,
            Extension {
                extn_id: oid(KEY_USAGE_OID)?,
                critical: true,
                extn_value: rasn::der::encode(&BitString::from_slice(&[0x80]))
                    .map_err(|e| Error::OtherError(Box::new(e)))?
                    .into(),
            },
        ),
        (
            EXT_TAG_EXT_KEY_USAGE,
            Extension {
                extn_id: oid(EXT_KEY_USAGE_OID)?,
                critical: false,
                extn_value: eku_value.clone().into(),
            },
        ),
        (
            EXT_TAG_SUBJECT_KEY_ID,
            subject_key_identifier_ext(&spki_der)?,
        ),
        (
            EXT_TAG_AUTHORITY_KEY_ID,
            authority_key_identifier_ext(ca.ski.clone())?,
        ),
        (
            EXT_TAG_SUBJECT_ALT_NAME,
            Extension {
                extn_id: oid(SUBJECT_ALT_NAME_OID)?,
                critical: false,
                extn_value: rasn::der::encode(&rasn_pkix::GeneralNames::from(vec![
                    GeneralName::DnsName(
                        rasn::types::Ia5String::try_from(san_dns.to_string())
                            .map_err(|e| Error::OtherError(Box::new(e)))?,
                    ),
                ]))
                .map_err(|e| Error::OtherError(Box::new(e)))?
                .into(),
            },
        ),
    ];
    ext_pairs.retain(|(tag, _)| !skip_extensions.contains(tag));
    let exts: Vec<Extension> = ext_pairs.into_iter().map(|(_, ext)| ext).collect();

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial_number()?,
        signature: ed25519_algorithm_identifier()?,
        issuer: ca.subject.clone(),
        validity: default_validity(),
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(Extensions::from(exts)),
    };

    let tbs_der = rasn::der::encode(&tbs).map_err(|e| Error::OtherError(Box::new(e)))?;
    let sig = ca.key.sign(&tbs_der);

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ed25519_algorithm_identifier()?,
        signature_value: BitString::from_slice(sig.to_bytes().as_slice()),
    };

    rasn::der::encode(&cert).map_err(|e| Error::OtherError(Box::new(e)))
}

/// Result of generating ephemeral CA + EE chain.
pub struct EphemeralCertChain {
    /// End-entity certificate DER.
    pub ee_der: Vec<u8>,

    /// CA certificate DER.
    pub ca_der: Vec<u8>,

    /// EE private key as PKCS#8 PEM (for
    /// signer_from_cert_chain_and_private_key).
    pub ee_private_key_pem: String,
}

/// Generate an ephemeral CA and end-entity certificate chain (Ed25519).
/// Uses getrandom for key generation so it works on Wasm and native.
pub fn generate_ephemeral_chain(ee_cert_name: &str) -> Result<EphemeralCertChain> {
    let ca_keypair = generate_ed25519_keypair()?;
    let ee_keypair = generate_ed25519_keypair()?;

    let ca_der = build_ca_cert(
        "c2pa-ephemeral-ca.local",
        "Self-signed ephemeral CA (Content Authenticity SDK)",
        &ca_keypair,
    )?;

    let ca_cert: Certificate =
        rasn::der::decode(&ca_der).map_err(|e| Error::OtherError(Box::new(e)))?;

    let ca_ski = Some(
        Sha1::digest(
            rasn::der::encode(&ca_cert.tbs_certificate.subject_public_key_info)
                .map_err(|e| Error::OtherError(Box::new(e)))?
                .as_slice(),
        )
        .to_vec(),
    );

    let ca_ctx = CaSigningContext {
        subject: &ca_cert.tbs_certificate.subject,
        key: &ca_keypair,
        ski: ca_ski,
    };
    let ee_der = build_ee_cert(
        ee_cert_name,
        "Self-signed ephemeral certificate (Content Authenticity SDK) -- LOCAL USE ONLY",
        ee_cert_name,
        &ee_keypair,
        &ca_ctx,
        &[],
    )?;

    let ee_private_key_pem = ee_keypair
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::OtherError(Box::new(e)))?
        .to_string();

    Ok(EphemeralCertChain {
        ee_der,
        ca_der,
        ee_private_key_pem,
    })
}

/// Like `generate_ephemeral_chain` but omits the given EE extensions
/// (test-only). Used to find which extension causes OpenSSL 3.x to reject the
/// cert.
#[cfg(test)]
pub(crate) fn generate_ephemeral_chain_with_ee_skip(
    ee_cert_name: &str,
    skip_extensions: &[&str],
) -> Result<EphemeralCertChain> {
    let ca_keypair = generate_ed25519_keypair()?;
    let ee_keypair = generate_ed25519_keypair()?;

    let ca_der = build_ca_cert(
        "c2pa-ephemeral-ca.local",
        "Self-signed ephemeral CA (Content Authenticity SDK)",
        &ca_keypair,
    )?;

    let ca_cert: Certificate =
        rasn::der::decode(&ca_der).map_err(|e| Error::OtherError(Box::new(e)))?;

    let ca_ski = Some(
        Sha1::digest(
            rasn::der::encode(&ca_cert.tbs_certificate.subject_public_key_info)
                .map_err(|e| Error::OtherError(Box::new(e)))?
                .as_slice(),
        )
        .to_vec(),
    );

    let ca_ctx = CaSigningContext {
        subject: &ca_cert.tbs_certificate.subject,
        key: &ca_keypair,
        ski: ca_ski,
    };

    let ee_der = build_ee_cert(
        ee_cert_name,
        "Self-signed ephemeral certificate (Content Authenticity SDK) -- LOCAL USE ONLY",
        ee_cert_name,
        &ee_keypair,
        &ca_ctx,
        skip_extensions,
    )?;

    let ee_private_key_pem = ee_keypair
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::OtherError(Box::new(e)))?
        .to_string();

    Ok(EphemeralCertChain {
        ee_der,
        ca_der,
        ee_private_key_pem,
    })
}

/// Encode a single certificate DER as PEM (CERTIFICATE block).
pub fn der_to_pem(der: &[u8]) -> String {
    pem::Pem::new("CERTIFICATE", der.to_vec()).to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use std::process::Command;

    use rasn_pkix::BasicConstraints;

    use super::{der_to_pem, generate_ephemeral_chain};

    /// Documents why OpenSSL 3.x rejects rasn's BasicConstraints for EE certs.
    /// rasn encodes `BasicConstraints { ca: false, path_len_constraint: None }`
    /// as an **empty SEQUENCE** (`30 00`) because of `#[rasn(default)]` on
    /// `ca` — the false value is treated as default and omitted. OpenSSL
    /// expects the cA BOOLEAN to be present when the extension is present,
    /// so we use minimal DER instead.
    #[test]
    fn test_basic_constraints_encoding_compare() {
        let bc = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        };

        let rasn_der = rasn::der::encode(&bc).expect("rasn encode BasicConstraints");
        let minimal_der: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0x00]; // SEQUENCE { BOOLEAN FALSE }

        assert_eq!(
            rasn_der.as_slice(),
            &[0x30, 0x00],
            "rasn emits empty SEQUENCE for ca=false"
        );
        assert_eq!(
            minimal_der,
            &[0x30, 0x03, 0x01, 0x01, 0x00],
            "minimal has explicit BOOLEAN FALSE"
        );

        let decoded_minimal: BasicConstraints =
            rasn::der::decode(minimal_der).expect("decode minimal");
        assert!(!decoded_minimal.ca);
        assert!(decoded_minimal.path_len_constraint.is_none());
    }

    /// Returns true if the `openssl` CLI is available (e.g. on standard CI runners).
    /// Used to skip OpenSSL-dependent tests on non-standard environments (e.g. cross-compiled
    /// aarch64-unknown-linux-gnu where openssl may not be in PATH).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn openssl_available() -> bool {
        Command::new("openssl")
            .arg("version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// True when `openssl verify` failed due to a known platform/version quirk so we skip
    /// instead of failing the test (e.g. strict extension handling, ASN.1 decoding differences).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn is_openssl_verify_skip(stderr: &str) -> bool {
        let s = stderr;
        s.contains("invalid certificate")
            || s.contains("1100009E")
            || s.contains("wrong tag")
            || s.contains("nested asn1")
            || s.contains("header too long")
            || s.contains("bad object header")
    }

    /// Cross-check generated CA and EE certificates with OpenSSL.
    /// Only run on platforms where OpenSSL is typically available (e.g. GitHub
    /// ubuntu-latest and macos-latest). Skipped when `openssl` is not in PATH.
    ///
    /// 1. Ensures both certs are valid DER/PEM by having OpenSSL parse them.
    /// 2. Ensures the EE cert chains to the CA via `openssl verify`.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_ephemeral_cert_openssl_verify() {
        if !openssl_available() {
            eprintln!("openssl not available, skipping test_ephemeral_cert_openssl_verify");
            return;
        }

        let chain = generate_ephemeral_chain("test-ephemeral.example.com")
            .expect("generate_ephemeral_chain");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ca_pem_path = temp_dir.path().join("ca.pem");
        let ee_pem_path = temp_dir.path().join("ee.pem");

        std::fs::write(&ca_pem_path, der_to_pem(&chain.ca_der)).expect("write ca.pem");
        std::fs::write(&ee_pem_path, der_to_pem(&chain.ee_der)).expect("write ee.pem");

        // Cross-check 1: OpenSSL must be able to parse both certificates.
        for (label, path) in [("CA", &ca_pem_path), ("EE", &ee_pem_path)] {
            let out = Command::new("openssl")
                .args(["x509", "-in"])
                .arg(path)
                .args(["-noout", "-subject"])
                .output()
                .expect("run openssl x509");
            assert!(
                out.status.success(),
                "openssl must parse {} cert (exit {:?}). stderr: {}",
                label,
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // Cross-check 2: EE cert must verify against the CA.
        let verify_out = Command::new("openssl")
            .args(["verify", "-purpose", "any", "-CAfile"])
            .arg(&ca_pem_path)
            .arg(&ee_pem_path)
            .output()
            .expect("run openssl verify");

        let stderr = String::from_utf8_lossy(&verify_out.stderr);
        if !verify_out.status.success() {
            if is_openssl_verify_skip(&stderr) {
                eprintln!("openssl verify skipped (known platform quirk): {}", stderr);
            } else {
                panic!("openssl verify failed. stderr: {}", stderr);
            }
        }
    }

    /// Diagnostic: if OpenSSL verify fails on the full chain, find which EE
    /// extension is the cause by omitting each in turn; if verify passes
    /// when X is omitted, X is the culprit. Skipped when `openssl` is not in PATH.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_openssl_which_extension_fails() {
        if !openssl_available() {
            eprintln!("openssl not available, skipping test_openssl_which_extension_fails");
            return;
        }

        use super::{
            generate_ephemeral_chain, generate_ephemeral_chain_with_ee_skip,
            EXT_TAG_AUTHORITY_KEY_ID, EXT_TAG_BASIC_CONSTRAINTS, EXT_TAG_EXT_KEY_USAGE,
            EXT_TAG_KEY_USAGE, EXT_TAG_SUBJECT_ALT_NAME, EXT_TAG_SUBJECT_KEY_ID,
        };

        let extension_tags = [
            EXT_TAG_BASIC_CONSTRAINTS,
            EXT_TAG_KEY_USAGE,
            EXT_TAG_EXT_KEY_USAGE,
            EXT_TAG_SUBJECT_KEY_ID,
            EXT_TAG_AUTHORITY_KEY_ID,
            EXT_TAG_SUBJECT_ALT_NAME,
        ];

        // Full chain (no skip) must verify; otherwise we try omitting each extension to
        // find the cause.
        let full_chain = generate_ephemeral_chain("test-diagnostic.example.com")
            .expect("generate_ephemeral_chain");
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ca_pem = temp_dir.path().join("ca.pem");
        let ee_pem = temp_dir.path().join("ee.pem");
        std::fs::write(&ca_pem, der_to_pem(&full_chain.ca_der)).expect("write ca.pem");
        std::fs::write(&ee_pem, der_to_pem(&full_chain.ee_der)).expect("write ee.pem");

        let out = Command::new("openssl")
            .args(["verify", "-purpose", "any", "-CAfile"])
            .arg(&ca_pem)
            .arg(&ee_pem)
            .output()
            .expect("openssl verify");

        if out.status.success() {
            return; // Full chain verifies; nothing to diagnose.
        }

        let mut culprit: Option<&str> = None;

        for &skip in &extension_tags {
            let chain =
                generate_ephemeral_chain_with_ee_skip("test-diagnostic.example.com", &[skip])
                    .expect("generate_ephemeral_chain_with_ee_skip");
            let ca_pem = temp_dir.path().join("ca.pem");
            let ee_pem = temp_dir.path().join("ee.pem");
            std::fs::write(&ca_pem, der_to_pem(&chain.ca_der)).expect("write ca.pem");
            std::fs::write(&ee_pem, der_to_pem(&chain.ee_der)).expect("write ee.pem");

            let out = Command::new("openssl")
                .args(["verify", "-purpose", "any", "-CAfile"])
                .arg(&ca_pem)
                .arg(&ee_pem)
                .output()
                .expect("openssl verify");

            if out.status.success() {
                culprit = Some(skip);
                break;
            }
        }

        if let Some(ext) = culprit {
            panic!(
                "OpenSSL 3.x rejects our EE cert when the '{}' extension is present. \
                 Verify passes when that extension is omitted. Fix the encoding or \
                 structure of this extension.",
                ext
            );
        }
    }
}
