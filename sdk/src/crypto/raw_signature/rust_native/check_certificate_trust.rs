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
use nom::AsBytes;
use x509_parser::{
    certificate::X509Certificate, der_parser::oid, oid_registry::Oid, x509::AlgorithmIdentifier,
};

use super::validators::validator_for_sig_and_hash_algs;
use crate::crypto::{
    cose::{CertificateTrustError, CertificateTrustPolicy, TrustAnchorType},
    raw_signature::{oids::*, RawSignatureValidationError, SigningAlg},
};

pub(crate) fn check_certificate_trust(
    ctp: &CertificateTrustPolicy,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    signing_time_epoch: Option<i64>,
) -> Result<TrustAnchorType, CertificateTrustError> {
    if ctp.trust_anchor_ders().count() == 0 && ctp.user_trust_anchor_ders().count() == 0 {
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

    // Make sure chain is in the correct order and valid.
    check_chain_order(&full_chain)?;

    // Build anchors and check against trust anchors.
    let anchors: Vec<(X509Certificate, &Vec<u8>)> = ctp
        .trust_anchor_ders()
        .filter_map(|anchor_der| {
            let (_, cert) = X509Certificate::from_der(anchor_der)
                .map_err(|_e| CertificateTrustError::CertificateNotTrusted)
                .ok()?;
            Some((cert, anchor_der))
        })
        .collect();

    // Build anchors and check against user provided trust anchors.
    let user_anchors: Vec<(X509Certificate, &Vec<u8>)> = ctp
        .user_trust_anchor_ders()
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

        // Make sure the certificate was not expired.
        if let Some(signing_time) = signing_time_epoch {
            if !chain_cert.validity().is_valid_at(
                x509_parser::time::ASN1Time::from_timestamp(signing_time)
                    .map_err(|_| CertificateTrustError::CertificateNotTrusted)?,
            ) {
                return Err(CertificateTrustError::CertificateNotTrusted);
            }
        }

        // Check against C2PA trust anchors.
        for (anchor_cert, anchor_der) in &anchors {
            if chain_cert.issuer() == anchor_cert.subject() {
                let data = chain_cert.tbs_certificate.as_ref();
                let sig = chain_cert.signature_value.as_ref();

                let sig_alg = cert_signing_alg(anchor_cert);

                let result = verify_data(anchor_der, sig_alg, sig, data);

                match result {
                    Ok(b) => {
                        if b {
                            return Ok(TrustAnchorType::System);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        // Check against user provided trust anchors.
        for (anchor_cert, anchor_der) in &user_anchors {
            if chain_cert.issuer() == anchor_cert.subject() {
                let data = chain_cert.tbs_certificate.as_ref();
                let sig = chain_cert.signature_value.as_ref();

                let sig_alg = cert_signing_alg(anchor_cert);

                let result = verify_data(anchor_der, sig_alg, sig, data);

                match result {
                    Ok(b) => {
                        if b {
                            return Ok(TrustAnchorType::User);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    Err(CertificateTrustError::CertificateNotTrusted)
}

fn check_chain_order(certs: &[Vec<u8>]) -> Result<(), CertificateTrustError> {
    let chain_length = certs.len();
    if chain_length < 2 {
        return Ok(());
    }

    for i in 1..chain_length {
        let (_, current_cert) = X509Certificate::from_der(&certs[i - 1])
            .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;

        let issuer_der = &certs[i];
        let data = current_cert.tbs_certificate.as_ref();
        let sig = current_cert.signature_value.as_ref();
        let sig_alg = cert_signing_alg(&current_cert);

        if !verify_data(issuer_der, sig_alg, sig, data)? {
            return Err(CertificateTrustError::CertificateNotTrusted);
        }
    }

    Ok(())
}

fn signing_alg_to_sig_and_hash_oid(alg: &str) -> Option<(bcder::Oid, bcder::Oid)> {
    if alg == "rsa256" {
        Some((
            ans1_oid_bcder_oid(&RSA_OID)?,
            ans1_oid_bcder_oid(&SHA256_OID)?,
        ))
    } else if alg == "rsa384" {
        Some((
            ans1_oid_bcder_oid(&RSA_OID)?,
            ans1_oid_bcder_oid(&SHA384_OID)?,
        ))
    } else if alg == "rsa512" {
        Some((
            ans1_oid_bcder_oid(&RSA_OID)?,
            ans1_oid_bcder_oid(&SHA512_OID)?,
        ))
    } else if alg == "es256" {
        Some((
            ans1_oid_bcder_oid(&EC_PUBLICKEY_OID)?,
            ans1_oid_bcder_oid(&SHA256_OID)?,
        ))
    } else if alg == "es384" {
        Some((
            ans1_oid_bcder_oid(&EC_PUBLICKEY_OID)?,
            ans1_oid_bcder_oid(&SHA384_OID)?,
        ))
    } else if alg == "es512" {
        Some((
            ans1_oid_bcder_oid(&EC_PUBLICKEY_OID)?,
            ans1_oid_bcder_oid(&SHA512_OID)?,
        ))
    } else if alg == "ps256" {
        Some((
            ans1_oid_bcder_oid(&RSA_PSS_OID)?,
            ans1_oid_bcder_oid(&SHA256_OID)?,
        ))
    } else if alg == "ps384" {
        Some((
            ans1_oid_bcder_oid(&RSA_PSS_OID)?,
            ans1_oid_bcder_oid(&SHA384_OID)?,
        ))
    } else if alg == "ps512" {
        Some((
            ans1_oid_bcder_oid(&RSA_PSS_OID)?,
            ans1_oid_bcder_oid(&SHA512_OID)?,
        ))
    } else if alg == "ed25519" {
        Some((
            ans1_oid_bcder_oid(&ED25519_OID)?,
            ans1_oid_bcder_oid(&SHA512_OID)?,
        ))
    } else {
        None
    }
}

fn cert_signing_alg(cert: &X509Certificate) -> Option<String> {
    let cert_alg = &cert.signature_algorithm.algorithm;

    if *cert_alg == SHA256_WITH_RSAENCRYPTION_OID {
        Some("rsa256".to_string())
    } else if *cert_alg == SHA384_WITH_RSAENCRYPTION_OID {
        Some("rsa384".to_string())
    } else if *cert_alg == SHA512_WITH_RSAENCRYPTION_OID {
        Some("rsa512".to_string())
    } else if *cert_alg == ECDSA_WITH_SHA256_OID {
        Some(SigningAlg::Es256.to_string())
    } else if *cert_alg == ECDSA_WITH_SHA384_OID {
        Some(SigningAlg::Es384.to_string())
    } else if *cert_alg == ECDSA_WITH_SHA512_OID {
        Some(SigningAlg::Es512.to_string())
    } else if *cert_alg == RSA_PSS_OID {
        signing_alg_from_rsapss_alg(&cert.signature_algorithm)
    } else if *cert_alg == ED25519_OID {
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
    if ha_alg.algorithm == SHA256_OID {
        Some("ps256".to_string())
    } else if ha_alg.algorithm == SHA384_OID {
        Some("ps384".to_string())
    } else if ha_alg.algorithm == SHA512_OID {
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

    let result = if let Some(validator) = validator_for_sig_and_hash_algs(&sig_alg, &hash_alg) {
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
