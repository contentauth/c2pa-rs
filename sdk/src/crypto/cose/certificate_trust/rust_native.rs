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
    for cert in &full_chain {
        let (_, chain_cert) = X509Certificate::from_der(cert)
            .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;
        if !chain_cert.validity().is_valid_at(check_time) {
            return Err(CertificateTrustError::CertificateNotTrusted);
        }
    }

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
    // (Validity was already checked for the whole chain above.)
    for cert in full_chain.iter().rev() {
        let (_, chain_cert) = X509Certificate::from_der(cert)
            .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;

        // Check against C2PA trust anchors.
        for (anchor_cert, anchor_der) in &anchors {
            if chain_cert.issuer() == anchor_cert.subject() {
                let data = chain_cert.tbs_certificate.as_ref();
                let sig = chain_cert.signature_value.as_ref();

                let sig_alg = cert_signing_alg(&chain_cert);

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
        if !ctp.trust_anchors_only() {
            for (anchor_cert, anchor_der) in &user_anchors {
                if chain_cert.issuer() == anchor_cert.subject() {
                    let data = chain_cert.tbs_certificate.as_ref();
                    let sig = chain_cert.signature_value.as_ref();

                    let sig_alg = cert_signing_alg(&chain_cert);

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
