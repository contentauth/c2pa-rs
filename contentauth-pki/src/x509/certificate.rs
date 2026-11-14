// Copyright 2022 Adobe. All rights reserved.
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

use std::str::FromStr;

use asn1_rs::{Any, Class, FromDer, Header, Tag};
use c2pa_raw_crypto::{
    oids::*, validator_for_sig_and_hash_algs, RawSignatureValidationError, SigningAlg,
};
#[cfg(any(feature = "rust_native_crypto", test))]
use x509_parser::certificate::TbsCertificate;
use x509_parser::{certificate::X509Certificate, x509::AlgorithmIdentifier};

use super::{
    chain::ChainError,
    profile::{CertificateProfileError, ProfileError},
};

/// A parsed X.509 certificate borrowing its original DER encoding.
///
/// Parsing establishes no signature, profile, or trust guarantee. The parser
/// representation remains private so hosts can reuse checks without depending
/// on ASN.1 implementation types.
pub struct ParsedCertificate<'a> {
    der: &'a [u8],
    certificate: X509Certificate<'a>,
}

impl<'a> ParsedCertificate<'a> {
    /// Parse a certificate without verifying its signature, profile, or trust.
    ///
    /// Trailing bytes are retained in the DER accessor and ignored during
    /// parsing, preserving the existing certificate-checking behavior.
    pub fn from_der(der: &'a [u8]) -> Result<Self, ProfileError> {
        let (_, certificate) = X509Certificate::from_der(der).map_err(|_| ProfileError {
            kind: CertificateProfileError::InvalidCertificate,
            diagnostic: Some("certificate could not be parsed"),
        })?;

        Ok(Self { der, certificate })
    }

    /// Original encoding, including any trailing bytes; no trust is implied.
    pub fn certificate_der(&self) -> &'a [u8] {
        self.der
    }

    /// Reject certificate purposes explicitly forbidden by a host-selected role.
    ///
    /// This checks exclusions only, not a full profile. Missing EKUs are
    /// evaluated separately by the selected profile. No application role is
    /// inferred and neither configuration nor trust can bypass this check.
    pub fn check_disallowed_ekus(
        &self,
        disallowed: &[&str],
    ) -> Result<(), CertificateProfileError> {
        let eku = self
            .certificate
            .extended_key_usage()
            .map_err(|_| CertificateProfileError::InvalidCertificate)?;

        if let Some(eku) = eku {
            let present = |oid: &&str| match *oid {
                "1.3.6.1.5.5.7.3.1" => eku.value.server_auth,
                "1.3.6.1.5.5.7.3.2" => eku.value.client_auth,
                "1.3.6.1.5.5.7.3.3" => eku.value.code_signing,
                "1.3.6.1.5.5.7.3.4" => eku.value.email_protection,
                "1.3.6.1.5.5.7.3.8" => eku.value.time_stamping,
                "1.3.6.1.5.5.7.3.9" => eku.value.ocsp_signing,
                "2.5.29.37.0" => eku.value.any,
                _ => eku
                    .value
                    .other
                    .iter()
                    .any(|other| other.to_id_string() == *oid),
            };

            if disallowed.iter().any(present) {
                return Err(CertificateProfileError::InvalidEku);
            }
        }

        Ok(())
    }

    /// Check direct issuance, certificate signature, and the issuer's CA authority.
    ///
    /// This establishes no path trust, validity time, role, or profile. It retains
    /// the OCSP direct-issuance algorithm compatibility, including strict SHA-2
    /// RSA-PSS digest, MGF, salt-length, and trailer checks. Path-length constraints
    /// are evaluated separately when building a full chain.
    pub fn is_issued_by(&self, issuer: &ParsedCertificate<'_>) -> bool {
        let cert = &self.certificate;
        let issuer = &issuer.certificate;

        if cert.issuer() != issuer.subject()
            || cert.tbs_certificate.signature != cert.signature_algorithm
            || !issuer
                .basic_constraints()
                .is_ok_and(|bc| bc.is_some_and(|bc| bc.value.ca))
            || !issuer
                .key_usage()
                .is_ok_and(|ku| ku.is_none_or(|ku| ku.value.key_cert_sign()))
        {
            return false;
        }

        // Preserve the OCSP certificate-codec compatibility before signature checks.
        if rasn::der::decode::<rasn_pkix::Certificate>(self.der).is_err() {
            return false;
        }

        let algorithms = if cert.signature_algorithm.algorithm.as_bytes() == RSA_PSS_OID.as_bytes()
        {
            use x509_parser::signature_algorithm::SignatureAlgorithm;

            let Ok(SignatureAlgorithm::RSASSA_PSS(params)) =
                SignatureAlgorithm::try_from(&cert.signature_algorithm)
            else {
                return false;
            };

            let hash_oid = params.hash_algorithm_oid().to_id_string();

            let digest_len = match hash_oid.as_str() {
                "2.16.840.1.101.3.4.2.1" => 32,
                "2.16.840.1.101.3.4.2.2" => 48,
                "2.16.840.1.101.3.4.2.3" => 64,
                _ => return false,
            };

            let Ok(mgf) = params.mask_gen_algorithm() else {
                return false;
            };

            if mgf.mgf.to_id_string() != "1.2.840.113549.1.1.8"
                || mgf.hash.to_id_string() != hash_oid
                || params.salt_length() != digest_len
                || params.trailer_field() != 1
            {
                return false;
            }

            bcder::Oid::from_str(&hash_oid)
                .ok()
                .map(|hash| (raw_crypto_oid_to_bcder_oid(&RSA_PSS_OID), hash))
        } else {
            cert_signing_alg(cert)
                .as_deref()
                .and_then(signing_alg_to_sig_and_hash_oid)
        };

        let Some((signature, hash)) = algorithms else {
            return false;
        };

        let Some(validator) = validator_for_sig_and_hash_algs(
            &c2pa_raw_crypto::Oid::new(signature.as_ref()),
            &c2pa_raw_crypto::Oid::new(hash.as_ref()),
        ) else {
            return false;
        };

        validator
            .validate(
                cert.signature_value.as_ref(),
                cert.tbs_certificate.as_ref(),
                issuer.public_key().raw,
            )
            .is_ok()
    }

    pub(super) fn parsed(&self) -> &X509Certificate<'a> {
        &self.certificate
    }
}

/// Convert a [`c2pa_raw_crypto::Oid`] into a `bcder::Oid` by reusing the OID's
/// DER content octets directly.
fn raw_crypto_oid_to_bcder_oid(oid: &c2pa_raw_crypto::Oid) -> bcder::Oid {
    bcder::Oid(bytes::Bytes::copy_from_slice(oid.as_bytes()))
}

/// Verifies the chain is cryptographically valid (each certificate's
/// signature validates against the next certificate's public key) and that
/// every issuing certificate is actually authorized to act as a CA. Without
/// the latter, a valid cryptographic signature chain alone would let any
/// ordinary end-entity certificate be used to self-issue a forged certificate
/// that then chains up to a real trust anchor.
#[cfg(any(feature = "rust_native_crypto", test))]
pub(super) fn check_chain_order_and_ca_authorization(certs: &[Vec<u8>]) -> Result<(), ChainError> {
    let chain_length = certs.len();

    if chain_length < 2 {
        return Ok(());
    }

    for i in 1..chain_length {
        let (_, current_cert) = X509Certificate::from_der(&certs[i - 1])
            .map_err(|_e| ChainError::NoAnchorAssociation)?;

        let issuer_der = &certs[i];

        let (_, issuer_cert) =
            X509Certificate::from_der(issuer_der).map_err(|_e| ChainError::NoAnchorAssociation)?;

        let data = current_cert.tbs_certificate.as_ref();
        let sig = current_cert.signature_value.as_ref();
        let sig_alg = cert_signing_alg(&current_cert);

        if !verify_data(issuer_der, sig_alg, sig, data)? {
            return Err(ChainError::NoAnchorAssociation);
        }

        // Number of CA certificates between the issuer and the leaf.
        let certs_below = (i - 1) as u32;
        check_ca_authorization(&issuer_cert.tbs_certificate, certs_below)?;
    }

    Ok(())
}

/// Checks that `issuer_tbscert` is authorized to act as a CA (RFC 5280
/// 6.1.4(k)/(l)/(n)): `basicConstraints.cA` must be asserted,
/// `pathLenConstraint` (if declared) must not be exceeded by `certs_below`
/// (the number of CA certificates between this issuer and the leaf), and
/// `keyUsage.keyCertSign` must be set when a `keyUsage` extension is present.
#[cfg(any(feature = "rust_native_crypto", test))]
fn check_ca_authorization(
    issuer_tbscert: &TbsCertificate,
    certs_below: u32,
) -> Result<(), ChainError> {
    let basic_constraints = issuer_tbscert
        .basic_constraints()
        .map_err(|_e| ChainError::NoAnchorAssociation)?
        .ok_or(ChainError::NoAnchorAssociation)?;

    if !basic_constraints.value.ca {
        return Err(ChainError::NoAnchorAssociation);
    }

    if let Some(path_len) = basic_constraints.value.path_len_constraint {
        if certs_below > path_len {
            return Err(ChainError::NoAnchorAssociation);
        }
    }

    if let Some(key_usage) = issuer_tbscert
        .key_usage()
        .map_err(|_e| ChainError::NoAnchorAssociation)?
    {
        if !key_usage.value.key_cert_sign() {
            return Err(ChainError::NoAnchorAssociation);
        }
    }

    Ok(())
}

fn signing_alg_to_sig_and_hash_oid(alg: &str) -> Option<(bcder::Oid, bcder::Oid)> {
    let pair = |sig: &c2pa_raw_crypto::Oid, hash: &c2pa_raw_crypto::Oid| {
        Some((
            raw_crypto_oid_to_bcder_oid(sig),
            raw_crypto_oid_to_bcder_oid(hash),
        ))
    };

    match alg {
        "rsa256" => pair(&RSA_OID, &SHA256_OID),
        "rsa384" => pair(&RSA_OID, &SHA384_OID),
        "rsa512" => pair(&RSA_OID, &SHA512_OID),
        "es256" => pair(&EC_PUBLICKEY_OID, &SHA256_OID),
        "es384" => pair(&EC_PUBLICKEY_OID, &SHA384_OID),
        "es512" => pair(&EC_PUBLICKEY_OID, &SHA512_OID),
        "ps256" => pair(&RSA_PSS_OID, &SHA256_OID),
        "ps384" => pair(&RSA_PSS_OID, &SHA384_OID),
        "ps512" => pair(&RSA_PSS_OID, &SHA512_OID),
        "ed25519" => pair(&ED25519_OID, &SHA512_OID),
        _ => None,
    }
}

pub(super) fn cert_signing_alg(cert: &X509Certificate) -> Option<String> {
    let cert_alg = cert.signature_algorithm.algorithm.as_bytes();

    if cert_alg == SHA256_WITH_RSAENCRYPTION_OID.as_bytes() {
        Some("rsa256".to_string())
    } else if cert_alg == SHA384_WITH_RSAENCRYPTION_OID.as_bytes() {
        Some("rsa384".to_string())
    } else if cert_alg == SHA512_WITH_RSAENCRYPTION_OID.as_bytes() {
        Some("rsa512".to_string())
    } else if cert_alg == ECDSA_WITH_SHA256_OID.as_bytes() {
        Some(SigningAlg::Es256.to_string())
    } else if cert_alg == ECDSA_WITH_SHA384_OID.as_bytes() {
        Some(SigningAlg::Es384.to_string())
    } else if cert_alg == ECDSA_WITH_SHA512_OID.as_bytes() {
        Some(SigningAlg::Es512.to_string())
    } else if cert_alg == RSA_PSS_OID.as_bytes() {
        signing_alg_from_rsapss_alg(&cert.signature_algorithm)
    } else if cert_alg == ED25519_OID.as_bytes() {
        Some(SigningAlg::Ed25519.to_string())
    } else {
        None
    }
}

pub(super) fn rsa_pss_algorithms<'a>(
    parameters: &Any<'a>,
) -> Option<(AlgorithmIdentifier<'a>, AlgorithmIdentifier<'a>)> {
    parameters.as_sequence().ok()?;

    let (input, header) = Header::from_der(parameters.data).ok()?;

    if header.class() != Class::ContextSpecific || header.tag() != Tag(0) {
        return None;
    }

    let (input, hash) = AlgorithmIdentifier::from_der(input).ok()?;
    let (input, header) = Header::from_der(input).ok()?;

    if header.class() != Class::ContextSpecific || header.tag() != Tag(1) {
        return None;
    }

    let (_, mask) = AlgorithmIdentifier::from_der(input).ok()?;

    // Preserve the certificate parser's compatibility: trailing parameters
    // are ignored here, unlike the strict CMS timestamp signature parser.
    Some((hash, mask))
}

fn signing_alg_from_rsapss_alg(alg: &AlgorithmIdentifier) -> Option<String> {
    let (ha_alg, mgf_ai) = rsa_pss_algorithms(alg.parameters.as_ref()?)?;

    let mgf_ai_parameters = mgf_ai.parameters?;

    let Ok(mgf_ai_parameters) = mgf_ai_parameters.as_sequence() else {
        return None;
    };

    let Ok((_i, mgf_ai_params_algorithm)) =
        <Any as asn1_rs::FromDer>::from_der(&mgf_ai_parameters.content)
    else {
        return None;
    };

    let Ok(mgf_ai_params_algorithm) = mgf_ai_params_algorithm.as_oid() else {
        return None;
    };

    // Algorithms must be the same.
    if ha_alg.algorithm.to_id_string() != mgf_ai_params_algorithm.to_id_string() {
        return None;
    }

    // We only recognize a few specific algorithm types.
    let ha_alg_bytes = ha_alg.algorithm.as_bytes();

    if ha_alg_bytes == SHA256_OID.as_bytes() {
        Some("ps256".to_string())
    } else if ha_alg_bytes == SHA384_OID.as_bytes() {
        Some("ps384".to_string())
    } else if ha_alg_bytes == SHA512_OID.as_bytes() {
        Some("ps512".to_string())
    } else {
        None
    }
}

pub(super) fn verify_data(
    cert_der: &[u8],
    sig_alg: Option<String>,
    sig: &[u8],
    data: &[u8],
) -> Result<bool, ChainError> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|_e| ChainError::InvalidCertificate)?;

    let certificate_public_key = cert.public_key();

    let Some(cert_alg_string) = sig_alg else {
        return Err(ChainError::InvalidCertificate);
    };

    let (sig_alg, hash_alg) =
        signing_alg_to_sig_and_hash_oid(&cert_alg_string).ok_or(ChainError::InvalidCertificate)?;

    let result = if let Some(validator) = validator_for_sig_and_hash_algs(
        &c2pa_raw_crypto::Oid::new(sig_alg.as_ref()),
        &c2pa_raw_crypto::Oid::new(hash_alg.as_ref()),
    ) {
        validator.validate(sig, data, certificate_public_key.raw.as_ref())
    } else {
        return Err(ChainError::InvalidCertificate);
    };

    match result {
        Ok(()) => Ok(true),
        Err(RawSignatureValidationError::SignatureMismatch) => Ok(false),
        Err(_err) => Err(ChainError::InvalidCertificate),
    }
}

pub(crate) fn subject_key_identifier_matches(encoded: &[u8], identifier: &[u8]) -> bool {
    use asn1_rs::{Class, Tag};

    asn1_rs::Any::from_der(encoded).is_ok_and(|(rest, value)| {
        rest.is_empty()
            && value.class() == Class::Universal
            && value.tag() == Tag::OctetString
            && !value.header.is_constructed()
            && value.data == identifier
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rasn::{types, Encoder};
    use rasn_pkix::Certificate;

    use super::*;

    fn cert_chain_pem_to_der(pem: &[u8]) -> Result<Vec<Vec<u8>>, pem::PemError> {
        Ok(pem::parse_many(pem)?
            .into_iter()
            .map(|pem| pem.into_contents())
            .collect())
    }

    fn oid(value: &[u32]) -> types::ObjectIdentifier {
        types::ObjectIdentifier::new(value.to_vec()).unwrap()
    }

    fn certificate() -> Certificate {
        let pem = include_bytes!("../../tests/fixtures/certs/ed25519.pub");

        rasn::der::decode(&cert_chain_pem_to_der(pem).unwrap()[0]).unwrap()
    }

    fn pss_algorithm(parameters: Option<Vec<u8>>) -> Option<String> {
        let algorithm = rasn_pkix::AlgorithmIdentifier {
            algorithm: oid(&[1, 2, 840, 113549, 1, 1, 10]),
            parameters: parameters.map(types::Any::new),
        };

        let der = rasn::der::encode(&algorithm).unwrap();
        let (_, algorithm) = AlgorithmIdentifier::from_der(&der).unwrap();

        signing_alg_from_rsapss_alg(&algorithm)
    }

    #[test]
    fn certificate_signature_algorithms_and_raw_validator_selection_agree() {
        for (id, name, sig_oid, hash_oid) in [
            (
                vec![1, 2, 840, 113549, 1, 1, 11],
                "rsa256",
                &RSA_OID,
                &SHA256_OID,
            ),
            (
                vec![1, 2, 840, 113549, 1, 1, 12],
                "rsa384",
                &RSA_OID,
                &SHA384_OID,
            ),
            (
                vec![1, 2, 840, 113549, 1, 1, 13],
                "rsa512",
                &RSA_OID,
                &SHA512_OID,
            ),
            (
                vec![1, 2, 840, 10045, 4, 3, 2],
                "es256",
                &EC_PUBLICKEY_OID,
                &SHA256_OID,
            ),
            (
                vec![1, 2, 840, 10045, 4, 3, 3],
                "es384",
                &EC_PUBLICKEY_OID,
                &SHA384_OID,
            ),
            (
                vec![1, 2, 840, 10045, 4, 3, 4],
                "es512",
                &EC_PUBLICKEY_OID,
                &SHA512_OID,
            ),
            (vec![1, 3, 101, 112], "ed25519", &ED25519_OID, &SHA512_OID),
        ] {
            let mut cert = certificate();
            cert.signature_algorithm.algorithm = oid(&id);

            let der = rasn::der::encode(&cert).unwrap();
            let (_, parsed) = X509Certificate::from_der(&der).unwrap();

            assert_eq!(cert_signing_alg(&parsed).as_deref(), Some(name));

            let (sig, hash) = signing_alg_to_sig_and_hash_oid(name).unwrap();

            assert_eq!(sig.as_ref(), sig_oid.as_bytes());
            assert_eq!(hash.as_ref(), hash_oid.as_bytes());
        }

        for (name, hash_oid) in [
            ("ps256", &SHA256_OID),
            ("ps384", &SHA384_OID),
            ("ps512", &SHA512_OID),
        ] {
            let (sig, hash) = signing_alg_to_sig_and_hash_oid(name).unwrap();

            assert_eq!(sig.as_ref(), RSA_PSS_OID.as_bytes());
            assert_eq!(hash.as_ref(), hash_oid.as_bytes());
        }

        assert!(signing_alg_to_sig_and_hash_oid("unknown").is_none());

        let mut cert = certificate();
        cert.signature_algorithm.algorithm = oid(&[1, 2, 3, 4]);

        let der = rasn::der::encode(&cert).unwrap();
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();

        assert!(cert_signing_alg(&parsed).is_none());
    }

    #[test]
    fn pss_requires_well_formed_matching_sha2_parameters() {
        #[derive(rasn::AsnType, rasn::Encode)]
        struct Parameters {
            #[rasn(tag(explicit(0)))]
            hash: rasn_pkix::AlgorithmIdentifier,
            #[rasn(tag(explicit(1)))]
            mask: rasn_pkix::AlgorithmIdentifier,
            #[rasn(tag(explicit(2)))]
            salt_length: Option<types::Integer>,
        }

        let alg = |id: &[u32]| rasn_pkix::AlgorithmIdentifier {
            algorithm: oid(id),
            parameters: None,
        };

        let sha256 = vec![2, 16, 840, 1, 101, 3, 4, 2, 1];
        let sha384 = vec![2, 16, 840, 1, 101, 3, 4, 2, 2];
        let sha512 = vec![2, 16, 840, 1, 101, 3, 4, 2, 3];
        let sha1 = vec![1, 3, 14, 3, 2, 26];

        for (hash, mask_hash, expected) in [
            (&sha256, &sha256, Some("ps256")),
            (&sha384, &sha384, Some("ps384")),
            (&sha512, &sha512, Some("ps512")),
            (&sha256, &sha384, None),
            (&sha1, &sha1, None),
        ] {
            let mut parameters = Parameters {
                hash: alg(hash),
                mask: rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 113549, 1, 1, 8]),
                    parameters: Some(types::Any::new(rasn::der::encode(&alg(mask_hash)).unwrap())),
                },
                salt_length: None,
            };

            let params = rasn::der::encode(&parameters).unwrap();

            assert_eq!(pss_algorithm(Some(params.clone())).as_deref(), expected);

            for salt_length in [0, 1, 32, 64] {
                parameters.salt_length = Some(salt_length.into());

                assert_eq!(
                    pss_algorithm(Some(rasn::der::encode(&parameters).unwrap())).as_deref(),
                    expected,
                );
            }

            let mut cert = certificate();

            cert.signature_algorithm = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&[1, 2, 840, 113549, 1, 1, 10]),
                parameters: Some(types::Any::new(params)),
            };

            let der = rasn::der::encode(&cert).unwrap();
            let (_, parsed) = X509Certificate::from_der(&der).unwrap();

            assert_eq!(cert_signing_alg(&parsed).as_deref(), expected);
        }

        assert!(pss_algorithm(None).is_none());

        for value in [
            vec![5, 0],
            vec![0x30, 0],
            vec![0x30, 2, 0xa1, 0],
            vec![0x30, 2, 0xa0, 0],
        ] {
            assert!(pss_algorithm(Some(value)).is_none());
        }

        for mask_params in [
            None,
            Some(vec![5, 0]),
            Some(vec![0x30, 0]),
            Some(vec![0x30, 2, 5, 0]),
            Some(vec![0x30, 3, 2, 1, 1]),
        ] {
            let params = Parameters {
                hash: alg(&sha256),
                mask: rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 113549, 1, 1, 8]),
                    parameters: mask_params.map(types::Any::new),
                },
                salt_length: None,
            };

            assert!(pss_algorithm(Some(rasn::der::encode(&params).unwrap())).is_none());
        }

        let hash = rasn::der::encode(&alg(&sha256)).unwrap();

        for tag in [0xa0, 0x81, 0xa1] {
            let mut body = vec![0xa0, hash.len() as u8];
            body.extend_from_slice(&hash);
            body.extend_from_slice(&[tag, 0]);

            let mut params = vec![0x30, body.len() as u8];
            params.extend_from_slice(&body);

            assert!(pss_algorithm(Some(params)).is_none());
        }
    }

    #[test]
    fn raw_verification_distinguishes_mismatch_from_invalid_inputs() {
        let pem = include_bytes!("../../tests/fixtures/certs/ed25519.pub");
        let chain = cert_chain_pem_to_der(pem).unwrap();
        let cert = &chain[1];

        let (_, leaf) = X509Certificate::from_der(&chain[0]).unwrap();

        let signature = leaf.signature_value.as_ref();
        let data = leaf.tbs_certificate.as_ref();

        assert_eq!(
            verify_data(cert, Some("ed25519".into()), signature, data),
            Ok(true)
        );

        assert_eq!(
            verify_data(cert, Some("ed25519".into()), signature, b"changed"),
            Ok(false)
        );

        assert_eq!(
            verify_data(b"invalid", Some("ed25519".into()), signature, data),
            Err(ChainError::InvalidCertificate)
        );

        assert_eq!(
            verify_data(cert, None, signature, data),
            Err(ChainError::InvalidCertificate)
        );

        assert_eq!(
            verify_data(cert, Some("unknown".into()), signature, data),
            Err(ChainError::InvalidCertificate)
        );

        assert_ne!(
            verify_data(cert, Some("ed25519".into()), &[], b"data"),
            Ok(true)
        );

        let mut chain = cert_chain_pem_to_der(pem).unwrap();
        *chain[0].last_mut().unwrap() ^= 1;

        assert_eq!(
            check_chain_order_and_ca_authorization(&chain),
            Err(ChainError::NoAnchorAssociation)
        );
    }

    #[test]
    fn ca_key_usage_is_optional_but_must_authorize_signing_when_present() {
        let pem = include_bytes!("../../tests/fixtures/certs/ca_authorization_root.pub");
        let root_der = cert_chain_pem_to_der(pem).unwrap().remove(0);
        let root: Certificate = rasn::der::decode(&root_der).unwrap();
        let key_usage = oid(&[2, 5, 29, 15]);
        let constraints = oid(&[2, 5, 29, 19]);

        for (omit_usage, valid) in [(true, true), (false, false)] {
            let mut cert = root.clone();
            let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();

            if omit_usage {
                extensions.retain(|ext| ext.extn_id != key_usage);
            } else {
                extensions
                    .iter_mut()
                    .find(|ext| ext.extn_id == key_usage)
                    .unwrap()
                    .extn_value = vec![3, 2, 7, 0x80].into();
            }

            let der = rasn::der::encode(&cert).unwrap();
            let (_, parsed) = X509Certificate::from_der(&der).unwrap();

            assert_eq!(
                check_ca_authorization(&parsed.tbs_certificate, 0).is_ok(),
                valid
            );
        }

        let mut cert = root;

        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|ext| ext.extn_id != constraints);

        let der = rasn::der::encode(&cert).unwrap();
        let (_, parsed) = X509Certificate::from_der(&der).unwrap();

        assert_eq!(
            check_ca_authorization(&parsed.tbs_certificate, 0),
            Err(ChainError::NoAnchorAssociation)
        );

        assert!(check_chain_order_and_ca_authorization(&[vec![0], root_der.clone()]).is_err());
        assert!(check_chain_order_and_ca_authorization(&[root_der, vec![0]]).is_err());
    }
}
