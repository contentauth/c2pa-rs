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

/// Context for CA signing (used to keep build_ee_cert under the argument limit).
struct CaSigningContext<'a> {
    subject: &'a Name,
    key: &'a SigningKey,
    ski: Option<Vec<u8>>,
}

/// Build and sign an end-entity certificate (signed by the CA key).
fn build_ee_cert(
    ee_cn: &str,
    ee_org: &str,
    san_dns: &str,
    ee_keypair: &SigningKey,
    ca: &CaSigningContext<'_>,
) -> Result<Vec<u8>> {
    let verifying_key = ee_keypair.verifying_key();
    let spki = subject_public_key_info(&verifying_key)?;
    let spki_der = rasn::der::encode(&spki).map_err(|e| Error::OtherError(Box::new(e)))?;

    let subject = build_name(ee_cn, Some(ee_org))?;

    // Extended Key Usage: emailProtection
    let eku_oid = oid(EKU_EMAIL_PROTECTION_OID)?;
    let eku_list: rasn_pkix::ExtKeyUsageSyntax = vec![eku_oid];
    let eku_value = rasn::der::encode(&eku_list).map_err(|e| Error::OtherError(Box::new(e)))?;

    let exts = vec![
        Extension {
            extn_id: oid(KEY_USAGE_OID)?,
            critical: true,
            // digitalSignature (0) only
            extn_value: rasn::der::encode(&BitString::from_slice(&[0x80]))
                .map_err(|e| Error::OtherError(Box::new(e)))?
                .into(),
        },
        Extension {
            extn_id: oid(EXT_KEY_USAGE_OID)?,
            critical: false,
            extn_value: eku_value.into(),
        },
        subject_key_identifier_ext(&spki_der)?,
        authority_key_identifier_ext(ca.ski.clone())?,
        // SubjectAltName: dNSName
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
    ];

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
