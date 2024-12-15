// Copyright 2023 Adobe. All rights reserved.
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

use asn1_rs::{nom::AsBytes, Any, Class, Header, Tag};
use c2pa_crypto::{
    cose::CertificateAcceptancePolicy, raw_signature::RawSignatureValidationError,
    webcrypto::async_validator_for_signing_alg, SigningAlg,
};
use x509_parser::{
    der_parser::der::{parse_der_integer, parse_der_sequence_of},
    prelude::*,
};

use crate::{cose_validator::*, hash_utils::vec_compare};

fn cert_signing_alg(cert: &x509_parser::certificate::X509Certificate) -> Option<String> {
    let cert_alg = cert.signature_algorithm.algorithm.clone();

    let signing_alg = if cert_alg == SHA256_WITH_RSAENCRYPTION_OID {
        "rsa256".to_string()
    } else if cert_alg == SHA384_WITH_RSAENCRYPTION_OID {
        "rsa384".to_string()
    } else if cert_alg == SHA512_WITH_RSAENCRYPTION_OID {
        "rsa512".to_string()
    } else if cert_alg == ECDSA_WITH_SHA256_OID {
        SigningAlg::Es256.to_string()
    } else if cert_alg == ECDSA_WITH_SHA384_OID {
        SigningAlg::Es384.to_string()
    } else if cert_alg == ECDSA_WITH_SHA512_OID {
        SigningAlg::Es512.to_string()
    } else if cert_alg == RSASSA_PSS_OID {
        if let Some(parameters) = &cert.signature_algorithm.parameters {
            let seq = match parameters.as_sequence() {
                Ok(s) => s,
                Err(_) => return None,
            };

            let (_i, (ha_alg, mgf_ai)) = match seq.parse(|i| {
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
            }) {
                Ok((ii, (h, m))) => (ii, (h, m)),
                Err(_) => return None,
            };

            let mgf_ai_parameters = match mgf_ai.parameters {
                Some(m) => m,
                None => return None,
            };

            let mgf_ai_parameters = match mgf_ai_parameters.as_sequence() {
                Ok(m) => m,
                Err(_) => return None,
            };

            let (_i, mgf_ai_params_algorithm) =
                match <Any as asn1_rs::FromDer>::from_der(&mgf_ai_parameters.content) {
                    Ok((i, m)) => (i, m),
                    Err(_) => return None,
                };

            let mgf_ai_params_algorithm = match mgf_ai_params_algorithm.as_oid() {
                Ok(m) => m,
                Err(_) => return None,
            };

            // must be the same
            if ha_alg.algorithm.to_id_string() != mgf_ai_params_algorithm.to_id_string() {
                return None;
            }

            // check for one of the mandatory types
            if ha_alg.algorithm == SHA256_OID {
                "ps256".to_string()
            } else if ha_alg.algorithm == SHA384_OID {
                "ps384".to_string()
            } else if ha_alg.algorithm == SHA512_OID {
                "ps512".to_string()
            } else {
                return None;
            }
        } else {
            return None;
        }
    } else if cert_alg == ED25519_OID {
        SigningAlg::Ed25519.to_string()
    } else {
        return None;
    };

    Some(signing_alg)
}

async fn verify_data(
    cert_der: Vec<u8>,
    sig_alg: Option<String>,
    sig: Vec<u8>,
    data: Vec<u8>,
) -> crate::Result<bool> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der.as_bytes())
        .map_err(|_e| crate::Error::CoseCertUntrusted)?;

    let certificate_public_key = cert.public_key();

    let Some(cert_alg_string) = sig_alg else {
        return Err(crate::Error::BadParam(
            "unknown alg processing cert".to_string(),
        ));
    };

    let signing_alg: SigningAlg = cert_alg_string
        .parse()
        .map_err(|_| crate::Error::UnknownAlgorithm)?;

    // Not sure this is needed any more. Leaving this for now, but I think this should be handled in c2pa_crypto's raw signature code.
    let adjusted_sig = if cert_alg_string.starts_with("es") {
        match der_to_p1363(&sig, signing_alg) {
            Some(p1363) => p1363,
            None => sig,
        }
    } else {
        sig
    };

    let Some(validator) = async_validator_for_signing_alg(signing_alg) else {
        return Err(crate::Error::UnknownAlgorithm);
    };

    let result = validator
        .validate_async(&adjusted_sig, &data, certificate_public_key.raw.as_ref())
        .await;

    match result {
        Ok(()) => Ok(true),
        Err(RawSignatureValidationError::SignatureMismatch) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

// convert der signatures to P1363 format: r | s
fn der_to_p1363(data: &[u8], alg: SigningAlg) -> Option<Vec<u8>> {
    // handle if this is a der sequence
    if let Ok((_, bo)) = parse_der_sequence_of(parse_der_integer)(data) {
        let seq = bo.as_sequence().ok()?;

        if seq.len() != 2 {
            return None;
        }

        let rp = seq[0].as_bigint().ok()?;
        let sp = seq[1].as_bigint().ok()?;

        let mut r = rp.to_str_radix(16);
        let mut s = sp.to_str_radix(16);

        let sig_len: usize = match alg {
            SigningAlg::Es256 => 64,
            SigningAlg::Es384 => 96,
            SigningAlg::Es512 => 132,
            _ => return None,
        };

        // pad or truncate as needed
        let rp = if r.len() > sig_len {
            // truncate
            let offset = r.len() - sig_len;
            &r[offset..r.len()]
        } else {
            // pad
            while r.len() != sig_len {
                r.insert(0, '0');
            }
            r.as_ref()
        };

        let sp = if s.len() > sig_len {
            // truncate
            let offset = s.len() - sig_len;
            &s[offset..s.len()]
        } else {
            // pad
            while s.len() != sig_len {
                s.insert(0, '0');
            }
            s.as_ref()
        };

        if rp.len() != sig_len || rp.len() != sp.len() {
            return None;
        }

        // merge r and s strings
        let mut new_sig = rp.to_string();
        new_sig.push_str(sp);

        // convert back from hex string to byte array
        let result = (0..new_sig.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&new_sig[i..i + 2], 16)
                    .map_err(|_err| crate::Error::InvalidEcdsaSignature)
            })
            .collect();

        if let Ok(p1363) = result {
            Some(p1363)
        } else {
            None
        }
    } else {
        Some(data.to_vec())
    }
}

async fn check_chain_order(certs: &[Vec<u8>]) -> crate::Result<()> {
    use x509_parser::prelude::*;

    let chain_length = certs.len();
    if chain_length < 2 {
        return Ok(());
    }

    for i in 1..chain_length {
        let (_, current_cert) = X509Certificate::from_der(&certs[i - 1])
            .map_err(|_e| crate::Error::CoseCertUntrusted)?;

        let issuer_der = certs[i].to_vec();
        let data = current_cert.tbs_certificate.as_ref();
        let sig = current_cert.signature_value.as_ref();

        let sig_alg = cert_signing_alg(&current_cert);

        let result = verify_data(issuer_der, sig_alg, sig.to_vec(), data.to_vec()).await;

        // keep going as long as it validate
        match result {
            Ok(b) => {
                if !b {
                    return Err(crate::Error::OtherError("cert chain order invalid".into()));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

async fn on_trust_list(
    cap: &CertificateAcceptancePolicy,
    certs: &[Vec<u8>],
    ee_der: &[u8],
) -> crate::Result<bool> {
    use x509_parser::prelude::*;

    // check the cert against the allowed list first
    if cap.end_entity_cert_ders().any(|cert| cert == ee_der) {
        return Ok(true);
    }

    // add ee cert if needed to the chain
    let full_chain = if !certs.is_empty() && vec_compare(ee_der, &certs[0]) {
        certs.to_vec()
    } else {
        let mut full_chain: Vec<Vec<u8>> = Vec::new();
        full_chain.push(ee_der.to_vec());
        let mut in_chain = certs.to_vec();
        full_chain.append(&mut in_chain);
        full_chain
    };

    // make sure chain is in the correct order and valid
    check_chain_order(&full_chain).await?;

    // build anchors and check against trust anchors,
    let mut anchors: Vec<X509Certificate> = Vec::new();
    for anchor_der in cap.trust_anchor_ders() {
        let (_, anchor) =
            X509Certificate::from_der(anchor_der).map_err(|_e| crate::Error::CoseCertUntrusted)?;
        anchors.push(anchor);
    }

    if anchors.is_empty() {
        return Ok(false);
    }

    // work back from last cert in chain against the trust anchors
    for cert in certs.iter().rev() {
        let (_, chain_cert) =
            X509Certificate::from_der(cert).map_err(|_e| crate::Error::CoseCertUntrusted)?;

        for anchor in cap.trust_anchor_ders() {
            let data = chain_cert.tbs_certificate.as_ref();
            let sig = chain_cert.signature_value.as_ref();

            let sig_alg = cert_signing_alg(&chain_cert);

            let (_, anchor_cert) =
                X509Certificate::from_der(anchor).map_err(|_e| crate::Error::CoseCertUntrusted)?;

            if chain_cert.issuer() == anchor_cert.subject() {
                let result =
                    verify_data(anchor.clone(), sig_alg, sig.to_vec(), data.to_vec()).await;

                match result {
                    Ok(b) => {
                        if b {
                            return Ok(true);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }
    // todo: consider (path check and names restrictions)

    Ok(false)
}

// verify certificate and trust chain
pub(crate) async fn verify_trust_async(
    cap: &CertificateAcceptancePolicy,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    _signing_time_epoc: Option<i64>,
) -> crate::Result<bool> {
    // check configured EKUs against end-entity cert
    let Ok((_rem, cert)) = X509Certificate::from_der(cert_der) else {
        return Err(crate::Error::CoseCertUntrusted);
    };

    let Ok(Some(eku)) = cert.extended_key_usage() else {
        return Err(crate::Error::CoseCertUntrusted);
    };

    let Some(_approved_oid) = cap.has_allowed_eku(&eku.value) else {
        return Err(crate::Error::CoseCertUntrusted);
    };

    on_trust_list(cap, chain_der, cert_der).await
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use wasm_bindgen_test::*;

    use super::*;

    #[wasm_bindgen_test]
    async fn test_trust_store() {
        let mut cap = CertificateAcceptancePolicy::default();

        cap.add_trust_anchors(include_bytes!(
            "../../tests/fixtures/certs/trust/test_cert_root_bundle.pem"
        ))
        .unwrap();

        // test all the certs
        let ps256 = include_bytes!("../../tests/fixtures/certs/ps256.pub");
        let ps384 = include_bytes!("../../tests/fixtures/certs/ps384.pub");
        let ps512 = include_bytes!("../../tests/fixtures/certs/ps512.pub");
        let es256 = include_bytes!("../../tests/fixtures/certs/es256.pub");
        let es384 = include_bytes!("../../tests/fixtures/certs/es384.pub");
        let es512 = include_bytes!("../../tests/fixtures/certs/es512.pub");
        let ed25519 = include_bytes!("../../tests/fixtures/certs/ed25519.pub");

        let ps256_certs = load_trust_from_data(ps256).unwrap();
        let ps384_certs = load_trust_from_data(ps384).unwrap();
        let ps512_certs = load_trust_from_data(ps512).unwrap();
        let es256_certs = load_trust_from_data(es256).unwrap();
        let es384_certs = load_trust_from_data(es384).unwrap();
        let es512_certs = load_trust_from_data(es512).unwrap();
        let ed25519_certs = load_trust_from_data(ed25519).unwrap();

        assert!(
            verify_trust_async(&cap, &ps256_certs[1..], &ps256_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            verify_trust_async(&cap, &ps384_certs[1..], &ps384_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            verify_trust_async(&cap, &ps512_certs[1..], &ps512_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            verify_trust_async(&cap, &es256_certs[1..], &es256_certs[0], None)
                .await
                .unwrap()
        );

        assert!(
            verify_trust_async(&cap, &es384_certs[1..], &es384_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            verify_trust_async(&cap, &es512_certs[1..], &es512_certs[0], None)
                .await
                .unwrap()
        );

        assert!(
            verify_trust_async(&cap, &ed25519_certs[1..], &ed25519_certs[0], None)
                .await
                .unwrap()
        );
    }

    #[wasm_bindgen_test]
    async fn test_broken_trust_chain() {
        let mut cap = CertificateAcceptancePolicy::default();

        cap.add_trust_anchors(include_bytes!(
            "../../tests/fixtures/certs/trust/test_cert_root_bundle.pem"
        ))
        .unwrap();

        let ps256 = include_bytes!("../../tests/fixtures/certs/ps256.pub");
        let ps384 = include_bytes!("../../tests/fixtures/certs/ps384.pub");
        let ps512 = include_bytes!("../../tests/fixtures/certs/ps512.pub");
        let es256 = include_bytes!("../../tests/fixtures/certs/es256.pub");
        let es384 = include_bytes!("../../tests/fixtures/certs/es384.pub");
        let es512 = include_bytes!("../../tests/fixtures/certs/es512.pub");
        let ed25519 = include_bytes!("../../tests/fixtures/certs/ed25519.pub");

        let ps256_certs = load_trust_from_data(ps256).unwrap();
        let ps384_certs = load_trust_from_data(ps384).unwrap();
        let ps512_certs = load_trust_from_data(ps512).unwrap();
        let es256_certs = load_trust_from_data(es256).unwrap();
        let es384_certs = load_trust_from_data(es384).unwrap();
        let es512_certs = load_trust_from_data(es512).unwrap();
        let ed25519_certs = load_trust_from_data(ed25519).unwrap();

        assert!(
            !verify_trust_async(&cap, &ps256_certs[2..], &ps256_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            !verify_trust_async(&cap, &ps384_certs[2..], &ps384_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            !verify_trust_async(&cap, &ps512_certs[2..], &ps512_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            !verify_trust_async(&cap, &es256_certs[2..], &es256_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            !verify_trust_async(&cap, &es384_certs[2..], &es384_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            !verify_trust_async(&cap, &es512_certs[2..], &es512_certs[0], None)
                .await
                .unwrap()
        );
        assert!(
            !verify_trust_async(&cap, &ed25519_certs[2..], &ed25519_certs[0], None)
                .await
                .unwrap()
        );
    }

    // Temporarily moved here because we don't have signing
    // implementations for all algorithms on WASM yet.
    fn load_trust_from_data(trust_data: &[u8]) -> crate::Result<Vec<Vec<u8>>> {
        let mut certs = Vec::new();

        for pem_result in x509_parser::pem::Pem::iter_from_buffer(trust_data) {
            let pem = pem_result.map_err(|_e| crate::Error::CoseInvalidCert)?;
            certs.push(pem.contents);
        }
        Ok(certs)
    }
}
