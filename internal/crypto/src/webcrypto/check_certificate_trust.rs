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
use nom::AsBytes;
use x509_parser::{
    certificate::X509Certificate, der_parser::oid, oid_registry::Oid, x509::AlgorithmIdentifier,
};

use crate::{
    cose::{CertificateTrustError, CertificateTrustPolicy},
    p1363::der_to_p1363,
    raw_signature::{RawSignatureValidationError, SigningAlg},
    webcrypto::async_validator_for_signing_alg,
};

pub(crate) async fn check_certificate_trust(
    ctp: &CertificateTrustPolicy,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    _signing_time_epoch: Option<i64>,
) -> Result<(), CertificateTrustError> {
    let Ok((_rem, cert)) = X509Certificate::from_der(cert_der) else {
        return Err(CertificateTrustError::InvalidCertificate);
    };

    let Ok(Some(eku)) = cert.extended_key_usage() else {
        return Err(CertificateTrustError::InvalidEku);
    };

    let Some(_approved_oid) = ctp.has_allowed_eku(&eku.value) else {
        return Err(CertificateTrustError::InvalidEku);
    };

    // Add end-entity cert to the chain if not already there.
    let full_chain = if !chain_der.is_empty() && cert_der == &chain_der[0] {
        chain_der.to_vec()
    } else {
        let mut full_chain: Vec<Vec<u8>> = Vec::new();
        full_chain.push(cert_der.to_vec());
        let mut in_chain = chain_der.to_vec();
        full_chain.append(&mut in_chain);
        full_chain
    };

    // Make sure chain is in the correct order and valid.
    check_chain_order(&full_chain).await?;

    // Build anchors and check against trust anchors.
    let anchors = ctp
        .trust_anchor_ders()
        .map(|anchor_der| {
            X509Certificate::from_der(anchor_der)
                .map_err(|_e| CertificateTrustError::CertificateNotTrusted)
                .map(|r| r.1)
        })
        .collect::<Result<Vec<X509Certificate>, CertificateTrustError>>()?;

    if anchors.is_empty() {
        return Err(CertificateTrustError::CertificateNotTrusted);
    }

    // Work back from last cert in chain against the trust anchors.
    for cert in chain_der.iter().rev() {
        let (_, chain_cert) = X509Certificate::from_der(cert)
            .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;

        for anchor in ctp.trust_anchor_ders() {
            let data = chain_cert.tbs_certificate.as_ref();
            let sig = chain_cert.signature_value.as_ref();

            let sig_alg = cert_signing_alg(&chain_cert);

            let (_, anchor_cert) = X509Certificate::from_der(anchor)
                .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;

            if chain_cert.issuer() == anchor_cert.subject() {
                let result =
                    verify_data(anchor.clone(), sig_alg, sig.to_vec(), data.to_vec()).await;

                match result {
                    Ok(b) => {
                        if b {
                            return Ok(());
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }

    // TO DO: Consider path check and names restrictions.
    return Err(CertificateTrustError::CertificateNotTrusted);
}

async fn check_chain_order(certs: &[Vec<u8>]) -> Result<(), CertificateTrustError> {
    let chain_length = certs.len();
    if chain_length < 2 {
        return Ok(());
    }

    for i in 1..chain_length {
        let (_, current_cert) = X509Certificate::from_der(&certs[i - 1])
            .map_err(|_e| CertificateTrustError::CertificateNotTrusted)?;

        let issuer_der = certs[i].to_vec();
        let data = current_cert.tbs_certificate.as_ref();
        let sig = current_cert.signature_value.as_ref();
        let sig_alg = cert_signing_alg(&current_cert);

        if !verify_data(issuer_der, sig_alg, sig.to_vec(), data.to_vec()).await? {
            return Err(CertificateTrustError::CertificateNotTrusted);
        }
    }

    Ok(())
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
    } else if *cert_alg == RSASSA_PSS_OID {
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

    let Some(mgf_ai_parameters) = mgf_ai.parameters else {
        return None;
    };

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

async fn verify_data(
    cert_der: Vec<u8>,
    sig_alg: Option<String>,
    sig: Vec<u8>,
    data: Vec<u8>,
) -> Result<bool, CertificateTrustError> {
    let (_, cert) = X509Certificate::from_der(cert_der.as_bytes())
        .map_err(|_e| CertificateTrustError::InvalidCertificate)?;

    let certificate_public_key = cert.public_key();

    let Some(cert_alg_string) = sig_alg else {
        return Err(CertificateTrustError::InvalidCertificate);
    };

    let signing_alg: SigningAlg = cert_alg_string
        .parse()
        .map_err(|_| CertificateTrustError::InvalidCertificate)?;

    // Not sure this is needed any more. Leaving this for now, but I think this
    // should be handled in c2pa_crypto's raw signature code.

    // TO REVIEW: For now, this is needed because this function could validate C2PA
    // signatures (P1363) or those from certificates which are ASN.1 DER. I don't
    // know if the new code is only used for DER now.
    let adjusted_sig = if cert_alg_string.starts_with("es") {
        match der_to_p1363(&sig, signing_alg) {
            Ok(p1363) => p1363,
            Err(_) => sig,
        }
    } else {
        sig
    };

    let Some(validator) = async_validator_for_signing_alg(signing_alg) else {
        return Err(CertificateTrustError::InvalidCertificate);
    };

    let result = validator
        .validate_async(&adjusted_sig, &data, certificate_public_key.raw.as_ref())
        .await;

    match result {
        Ok(()) => Ok(true),
        Err(RawSignatureValidationError::SignatureMismatch) => Ok(false),
        Err(_err) => Err(CertificateTrustError::InvalidCertificate),
    }
}

const RSASSA_PSS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10);
const ECDSA_WITH_SHA256_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .2);
const ECDSA_WITH_SHA384_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .3);
const ECDSA_WITH_SHA512_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .4);
const SHA256_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .11);
const SHA384_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .12);
const SHA512_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .13);
const ED25519_OID: Oid<'static> = oid!(1.3.101 .112);
const SHA256_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .1);
const SHA384_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .2);
const SHA512_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .3);
