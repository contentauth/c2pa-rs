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

use asn1_rs::{Any, Class, FromDer, Header, Tag};
use c2pa_raw_crypto::{
    oids::*, validator_for_sig_and_hash_algs, RawSignatureValidationError, SigningAlg,
};
use web_time::{SystemTime, UNIX_EPOCH};
use x509_parser::{
    certificate::{TbsCertificate, X509Certificate},
    x509::AlgorithmIdentifier,
};

use crate::crypto::cose::{CertificateTrustError, CertificateTrustPolicy, TrustAnchorType};

/// Convert a [`c2pa_raw_crypto::Oid`] into a `bcder::Oid` by reusing the OID's
/// DER content octets directly.
fn raw_crypto_oid_to_bcder_oid(oid: &c2pa_raw_crypto::Oid) -> bcder::Oid {
    bcder::Oid(bytes::Bytes::copy_from_slice(oid.as_bytes()))
}

pub(crate) fn check_certificate_trust(
    ctp: &CertificateTrustPolicy,
    anchor_type: Option<TrustAnchorType>,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    signing_time_epoch: Option<i64>,
) -> Result<(TrustAnchorType, String), CertificateTrustError> {
    if ctp.anchor_sets_of_type(anchor_type).count() == 0 {
        return Err(CertificateTrustError::CertificateNotTrusted);
    }

    let Ok((_rem, cert)) = X509Certificate::from_der(cert_der) else {
        return Err(CertificateTrustError::InvalidCertificate);
    };

    let Ok(Some(eku)) = cert.extended_key_usage() else {
        return Err(CertificateTrustError::InvalidEku);
    };

    let Some(_approved_oid) = ctp.has_allowed_eku(eku.value) else {
        return Err(CertificateTrustError::InvalidEku);
    };

    // Add end-entity cert to the chain if not already there.
    let full_chain = if !chain_der.is_empty() && cert_der == chain_der[0] {
        chain_der.to_vec()
    } else {
        let mut full_chain: Vec<Vec<u8>> = Vec::new();
        full_chain.push(cert_der.to_vec());
        let mut in_chain = chain_der.to_vec();
        full_chain.append(&mut in_chain);
        full_chain
    };

    // Make sure chain is in the correct order, cryptographically valid, and
    // every issuer is authorized to act as a CA.
    check_chain_order_and_ca_authorization(&full_chain)?;

    // Make sure every cert in the chain was valid at signing time - as its
    // own pass over the whole chain, independent of where a trust anchor
    // match is found below. The trust-anchor search returns as soon as it
    // finds a match, so a check placed inside that loop would only ever run
    // for the certs from the anchor match onward, silently skipping every
    // cert between that match and the leaf.
    let check_time = match signing_time_epoch {
        Some(t) => t,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CertificateTrustError::InternalError("system time invalid".to_string()))?
            .as_secs() as i64,
    };
    let check_time = x509_parser::time::ASN1Time::from_timestamp(check_time)
        .map_err(|_| CertificateTrustError::CertificateNotTrusted)?;
    // The end-entity certificate's validity is reported by the certificate
    // profile check. A CA certificate outside its validity is reported as such
    // only if the chain otherwise reaches a trust anchor, as OpenSSL does;
    // otherwise the chain is simply not trusted.
    let mut ca_outside_validity = false;
    for (depth, cert) in full_chain.iter().enumerate() {
        let (_, chain_cert) = X509Certificate::from_der(cert)
            .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;
        if !chain_cert.validity().is_valid_at(check_time) {
            if depth == 0 {
                return Err(CertificateTrustError::CertificateNotTrusted);
            }
            ca_outside_validity = true;
        }
    }

    for anchor_set in ctp.anchor_sets_of_type(anchor_type) {
        // Process each anchor set

        // Build anchors and check against trust anchors.
        let anchors: Vec<(X509Certificate, &Vec<u8>)> = anchor_set
            .trust_anchor_ders
            .iter()
            .filter_map(|anchor_der| {
                let (_, cert) = X509Certificate::from_der(anchor_der)
                    .map_err(|_e| CertificateTrustError::CertificateNotTrusted)
                    .ok()?;
                Some((cert, anchor_der))
            })
            .collect();

        // Work back from last cert in chain against the trust anchors.
        for cert in full_chain.iter().rev() {
            let (_, chain_cert) = X509Certificate::from_der(cert)
                .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;

            // Check against trust anchors.
            for (anchor_cert, anchor_der) in &anchors {
                if chain_cert.issuer() == anchor_cert.subject() {
                    let data = chain_cert.tbs_certificate.as_ref();
                    let sig = chain_cert.signature_value.as_ref();

                    let sig_alg = cert_signing_alg(&chain_cert);

                    let result = verify_data(anchor_der, sig_alg, sig, data);

                    match result {
                        Ok(b) => {
                            if b {
                                if ca_outside_validity {
                                    return Err(
                                        CertificateTrustError::CaCertificateOutsideValidity,
                                    );
                                }
                                return Ok((
                                    anchor_set.trust_anchor_type,
                                    anchor_set.trust_anchor_uri.clone(),
                                ));
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    }

    Err(CertificateTrustError::CertificateNotTrusted)
}

/// Verifies the chain is cryptographically valid (each certificate's
/// signature validates against the next certificate's public key) and that
/// every issuing certificate is actually authorized to act as a CA. Without
/// the latter, a valid cryptographic signature chain alone would let any
/// ordinary end-entity certificate be used to self-issue a forged certificate
/// that then chains up to a real trust anchor.
fn check_chain_order_and_ca_authorization(certs: &[Vec<u8>]) -> Result<(), CertificateTrustError> {
    let chain_length = certs.len();
    if chain_length < 2 {
        return Ok(());
    }

    for i in 1..chain_length {
        let (_, current_cert) = X509Certificate::from_der(&certs[i - 1])
            .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;

        let issuer_der = &certs[i];
        let (_, issuer_cert) = X509Certificate::from_der(issuer_der)
            .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;

        let data = current_cert.tbs_certificate.as_ref();
        let sig = current_cert.signature_value.as_ref();
        let sig_alg = cert_signing_alg(&current_cert);

        if !verify_data(issuer_der, sig_alg, sig, data)? {
            return Err(CertificateTrustError::CertificateNotTrusted);
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
fn check_ca_authorization(
    issuer_tbscert: &TbsCertificate,
    certs_below: u32,
) -> Result<(), CertificateTrustError> {
    let basic_constraints = issuer_tbscert
        .basic_constraints()
        .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?
        .ok_or(CertificateTrustError::CertificateNotTrusted)?;
    if !basic_constraints.value.ca {
        return Err(CertificateTrustError::CertificateNotTrusted);
    }
    if let Some(path_len) = basic_constraints.value.path_len_constraint {
        if certs_below > path_len {
            return Err(CertificateTrustError::CertificateNotTrusted);
        }
    }

    if let Some(key_usage) = issuer_tbscert
        .key_usage()
        .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?
    {
        if !key_usage.value.key_cert_sign() {
            return Err(CertificateTrustError::CertificateNotTrusted);
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

fn cert_signing_alg(cert: &X509Certificate) -> Option<String> {
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

fn signing_alg_from_rsapss_alg(alg: &AlgorithmIdentifier) -> Option<String> {
    let Some(parameters) = &alg.parameters else {
        return None;
    };

    let Ok(seq) = parameters.as_sequence() else {
        return None;
    };

    let Ok((_i, (ha_alg, mgf_ai))) = seq.parse(|i| {
        let (i, h) = <Header as asn1_rs::FromDer>::from_der(i)?;
        if h.class() != Class::ContextSpecific || h.tag() != Tag(0) {
            return Err(nom::Err::Error(asn1_rs::Error::BerValueError));
        }

        let (i, ha_alg) = AlgorithmIdentifier::from_der(i)
            .map_err(|_| nom::Err::Error(asn1_rs::Error::BerValueError))?;

        let (i, h) = <Header as asn1_rs::FromDer>::from_der(i)?;
        if h.class() != Class::ContextSpecific || h.tag() != Tag(1) {
            return Err(nom::Err::Error(asn1_rs::Error::BerValueError));
        }

        let (i, mgf_ai) = AlgorithmIdentifier::from_der(i)
            .map_err(|_| nom::Err::Error(asn1_rs::Error::BerValueError))?;

        // Ignore anything that follows these two parameters.

        Ok((i, (ha_alg, mgf_ai)))
    }) else {
        return None;
    };

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

fn verify_data(
    cert_der: &[u8],
    sig_alg: Option<String>,
    sig: &[u8],
    data: &[u8],
) -> Result<bool, CertificateTrustError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|_e| CertificateTrustError::InvalidCertificate)?;

    let certificate_public_key = cert.public_key();

    let Some(cert_alg_string) = sig_alg else {
        return Err(CertificateTrustError::InvalidCertificate);
    };

    let (sig_alg, hash_alg) = signing_alg_to_sig_and_hash_oid(&cert_alg_string)
        .ok_or(CertificateTrustError::InvalidCertificate)?;

    let result = if let Some(validator) = validator_for_sig_and_hash_algs(
        &c2pa_raw_crypto::Oid::new(sig_alg.as_ref()),
        &c2pa_raw_crypto::Oid::new(hash_alg.as_ref()),
    ) {
        validator.validate(sig, data, certificate_public_key.raw.as_ref())
    } else {
        return Err(CertificateTrustError::InvalidCertificate);
    };

    match result {
        Ok(()) => Ok(true),
        Err(RawSignatureValidationError::SignatureMismatch) => Ok(false),
        Err(_err) => Err(CertificateTrustError::InvalidCertificate),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rasn::{types, Encoder};
    use rasn_pkix::Certificate;

    use super::*;
    use crate::{
        crypto::cert_chain_pem_to_der, utils::test_signer::cert_chain_and_private_key_for_alg,
    };

    fn oid(value: &[u32]) -> types::ObjectIdentifier {
        types::ObjectIdentifier::new(value.to_vec()).unwrap()
    }

    fn certificate() -> Certificate {
        let (pem, _) = cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);
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
            let params = rasn::der::encode(&Parameters {
                hash: alg(hash),
                mask: rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 113549, 1, 1, 8]),
                    parameters: Some(types::Any::new(rasn::der::encode(&alg(mask_hash)).unwrap())),
                },
            })
            .unwrap();
            assert_eq!(pss_algorithm(Some(params.clone())).as_deref(), expected);
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
        let (pem, key) = cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);
        let cert = &cert_chain_pem_to_der(pem).unwrap()[0];
        let signer = c2pa_raw_crypto::signer_from_private_key(key, SigningAlg::Ed25519).unwrap();
        let signature = signer.sign(b"data").unwrap();
        assert_eq!(
            verify_data(cert, Some("ed25519".into()), &signature, b"data"),
            Ok(true)
        );
        assert_eq!(
            verify_data(cert, Some("ed25519".into()), &signature, b"changed"),
            Ok(false)
        );
        assert_eq!(
            verify_data(b"invalid", Some("ed25519".into()), &signature, b"data"),
            Err(CertificateTrustError::InvalidCertificate)
        );
        assert_eq!(
            verify_data(cert, None, &signature, b"data"),
            Err(CertificateTrustError::InvalidCertificate)
        );
        assert_eq!(
            verify_data(cert, Some("unknown".into()), &signature, b"data"),
            Err(CertificateTrustError::InvalidCertificate)
        );
        assert!(verify_data(cert, Some("ed25519".into()), &[], b"data").is_err());

        let mut chain = cert_chain_pem_to_der(pem).unwrap();
        *chain[0].last_mut().unwrap() ^= 1;
        assert_eq!(
            check_chain_order_and_ca_authorization(&chain),
            Err(CertificateTrustError::CertificateNotTrusted)
        );
    }

    #[test]
    fn ca_key_usage_is_optional_but_must_authorize_signing_when_present() {
        let pem =
            include_bytes!("../../../../tests/fixtures/crypto/cose/ca_authorization_root.pub");
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
            Err(CertificateTrustError::CertificateNotTrusted)
        );

        assert!(check_chain_order_and_ca_authorization(&[vec![0], root_der.clone()]).is_err());
        assert!(check_chain_order_and_ca_authorization(&[root_der, vec![0]]).is_err());
    }

    #[test]
    fn leaf_eku_failures_are_distinct_from_untrusted_chain() {
        let mut policy = CertificateTrustPolicy::new();
        policy
            .add_trust_anchors(
                include_bytes!(
                    "../../../../tests/fixtures/crypto/raw_signature/test_cert_root_bundle.pem"
                ),
                "urn:test:roots",
                TrustAnchorType::Manifest,
                None,
            )
            .unwrap();
        for remove_eku in [false, true] {
            let mut cert = certificate();
            let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
            if remove_eku {
                extensions.retain(|ext| ext.extn_id != oid(&[2, 5, 29, 37]));
            } else {
                extensions
                    .iter_mut()
                    .find(|ext| ext.extn_id == oid(&[2, 5, 29, 37]))
                    .unwrap()
                    .extn_value = rasn::der::encode(&vec![oid(&[1, 2, 3, 4])]).unwrap().into();
            }

            assert_eq!(
                check_certificate_trust(
                    &policy,
                    None,
                    &[],
                    &rasn::der::encode(&cert).unwrap(),
                    None
                ),
                Err(CertificateTrustError::InvalidEku)
            );
        }

        assert_eq!(
            check_certificate_trust(&policy, None, &[], &[0], None),
            Err(CertificateTrustError::InvalidCertificate)
        );
    }
}
