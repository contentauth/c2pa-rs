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

use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Cursor, Read},
    str::FromStr,
};

use asn1_rs::{nom::AsBytes, Any, Class, Header, Tag};
use x509_parser::{
    der_parser::der::{parse_der_integer, parse_der_sequence_of},
    oid_registry::Oid,
    prelude::*,
};

use crate::{
    cose_validator::*,
    error::{Error, Result},
    hash_utils::hash_sha256,
    trust_handler::{
        has_allowed_oid, load_eku_configuration, load_trust_from_data, TrustHandlerConfig,
    },
    utils::base64,
    wasm::webcrypto_validator::async_validate,
    SigningAlg,
};

// Struct to handle verification of trust chains using WebPki
pub(crate) struct WebTrustHandlerConfig {
    pub trust_anchors: Vec<Vec<u8>>,
    pub private_anchors: Vec<Vec<u8>>,
    allowed_cert_set: HashSet<String>,
    config_store: Vec<u8>,
}

impl std::fmt::Debug for WebTrustHandlerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} trust anchors, {} private anchors.",
            self.trust_anchors.len(),
            self.private_anchors.len()
        )
    }
}

impl WebTrustHandlerConfig {
    pub fn load_default_trust(&mut self) -> Result<()> {
        // load config store
        let config = include_bytes!("../../tests/fixtures/certs/trust/store.cfg");
        let mut config_reader = Cursor::new(config);
        self.load_configuration(&mut config_reader)?;

        // load debug/test private trust anchors
        if cfg!(test) {
            let pa = include_bytes!("../../tests/fixtures/certs/trust/test_cert_root_bundle.pem");
            let mut pa_reader = Cursor::new(pa);

            self.append_private_trust_data(&mut pa_reader)?;
        }

        Ok(())
    }
}

impl TrustHandlerConfig for WebTrustHandlerConfig {
    fn new() -> Self {
        let mut th = WebTrustHandlerConfig {
            trust_anchors: Vec::new(),
            private_anchors: Vec::new(),
            allowed_cert_set: HashSet::new(),
            config_store: Vec::new(),
        };

        if th.load_default_trust().is_err() {
            th.clear(); // just use empty trust handler to fail automatically
        }

        th
    }

    // add trust anchors
    fn load_trust_anchors_from_data(&mut self, trust_data_reader: &mut dyn Read) -> Result<()> {
        let mut trust_data = Vec::new();
        trust_data_reader.read_to_end(&mut trust_data)?;

        let mut anchors = load_trust_from_data(&trust_data)?;
        self.trust_anchors.append(&mut anchors);
        Ok(())
    }

    // append private trust anchors
    fn append_private_trust_data(&mut self, private_anchors_reader: &mut dyn Read) -> Result<()> {
        let mut private_anchors_data = Vec::new();
        private_anchors_reader.read_to_end(&mut private_anchors_data)?;

        let mut anchors = load_trust_from_data(&private_anchors_data)?;
        self.private_anchors.append(&mut anchors);

        Ok(())
    }

    fn clear(&mut self) {
        self.trust_anchors = Vec::new();
        self.private_anchors = Vec::new();
    }

    // load EKU configuration
    fn load_configuration(&mut self, config_data: &mut dyn Read) -> Result<()> {
        config_data.read_to_end(&mut self.config_store)?;
        Ok(())
    }

    // list off auxillary allowed EKU Oid
    fn get_auxillary_ekus(&self) -> Vec<Oid> {
        let mut oids = Vec::new();
        if let Ok(oid_strings) = load_eku_configuration(&mut Cursor::new(&self.config_store)) {
            for oid_str in &oid_strings {
                if let Ok(oid) = Oid::from_str(oid_str) {
                    oids.push(oid);
                }
            }
        }
        oids
    }

    fn get_anchors(&self) -> Vec<Vec<u8>> {
        let mut anchors = Vec::new();

        anchors.append(&mut self.trust_anchors.clone());
        anchors.append(&mut self.private_anchors.clone());

        anchors
    }

    // add allowed list entries
    fn load_allowed_list(&mut self, allowed_list: &mut dyn Read) -> Result<()> {
        let mut buffer = Vec::new();
        allowed_list.read_to_end(&mut buffer)?;

        if let Ok(cert_list) = load_trust_from_data(&buffer) {
            for cert_der in &cert_list {
                let cert_sha256 = hash_sha256(cert_der);
                let cert_hash_base64 = base64::encode(&cert_sha256);

                self.allowed_cert_set.insert(cert_hash_base64);
            }
        }

        // try to load the of base64 encoded encoding of the sha256 hash of the certificate DER encoding
        let reader = Cursor::new(buffer);
        let buf_reader = BufReader::new(reader);

        let mut inside_cert_block = false;
        for l in buf_reader.lines().flatten() {
            if l.contains("-----BEGIN") {
                inside_cert_block = true;
            }
            if l.contains("-----END") {
                inside_cert_block = false;
            }

            // sanity check that data is base64 encoded and outside of certificate block
            if !inside_cert_block && base64::decode(&l).is_ok() && !l.is_empty() {
                self.allowed_cert_set.insert(l);
            }
        }

        Ok(())
    }

    // set of allowed cert hashes
    fn get_allowed_list(&self) -> &HashSet<String> {
        &self.allowed_cert_set
    }
}

fn find_allowed_eku<'a>(cert_der: &'a [u8], allowed_ekus: &'a Vec<Oid<'a>>) -> Option<&'a Oid<'a>> {
    if let Ok((_rem, cert)) = X509Certificate::from_der(cert_der) {
        if let Ok(Some(eku)) = cert.extended_key_usage() {
            if let Some(o) = has_allowed_oid(eku.value, allowed_ekus) {
                return Some(o);
            }
        }
    }
    None
}
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
                let (i, h) = Header::from_der(i)?;
                if h.class() != Class::ContextSpecific || h.tag() != Tag(0) {
                    return Err(nom::Err::Error(asn1_rs::Error::BerValueError));
                }

                let (i, ha_alg) = AlgorithmIdentifier::from_der(i)
                    .map_err(|_| nom::Err::Error(asn1_rs::Error::BerValueError))?;

                let (i, h) = Header::from_der(i)?;
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

            let (_i, mgf_ai_params_algorithm) = match Any::from_der(&mgf_ai_parameters.content) {
                Ok((i, m)) => (i, m),
                Err(_) => return None,
            };

            let mgf_ai_params_algorithm = match mgf_ai_params_algorithm.as_oid() {
                Ok(m) => m,
                Err(_) => return None,
            };

            // must be the same
            if ha_alg.algorithm != mgf_ai_params_algorithm {
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
) -> Result<bool> {
    use x509_parser::prelude::*;

    let (_, cert) =
        X509Certificate::from_der(cert_der.as_bytes()).map_err(|_e| Error::CoseCertUntrusted)?;

    let certificate_public_key = cert.public_key();
    if let Some(cert_alg_string) = sig_alg {
        let (algo, hash, salt_len) = match cert_alg_string.as_str() {
            "rsa256" => (
                "RSASSA-PKCS1-v1_5".to_string(),
                "SHA-256".to_string().to_string(),
                0,
            ),
            "rsa384" => ("RSASSA-PKCS1-v1_5".to_string(), "SHA-384".to_string(), 0),
            "rsa512" => ("RSASSA-PKCS1-v1_5".to_string(), "SHA-512".to_string(), 0),
            "es256" => ("ECDSA".to_string(), "SHA-256".to_string().to_string(), 0),
            "es384" => ("ECDSA".to_string(), "SHA-384".to_string(), 0),
            "es512" => ("ECDSA".to_string(), "SHA-512".to_string(), 0),
            "ps256" => ("RSA-PSS".to_string(), "SHA-256".to_string(), 32),
            "ps384" => ("RSA-PSS".to_string(), "SHA-384".to_string(), 48),
            "ps512" => ("RSA-PSS".to_string(), "SHA-512".to_string(), 64),
            "ed25519" => ("ED25519".to_string(), "SHA-512".to_string(), 0),
            _ => return Err(Error::UnsupportedType),
        };

        let adjusted_sig = if cert_alg_string.starts_with("es") {
            let parsed_alg_string: SigningAlg = cert_alg_string
                .parse()
                .map_err(|_| Error::UnknownAlgorithm)?;
            match der_to_p1363(&sig, parsed_alg_string) {
                Some(p1363) => p1363,
                None => sig.to_vec(),
            }
        } else {
            sig.to_vec()
        };

        async_validate(
            algo,
            hash,
            salt_len,
            certificate_public_key.raw.to_vec(),
            adjusted_sig,
            data,
        )
        .await
    } else {
        return Err(Error::CoseInvalidCert);
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

async fn check_chain_order(certs: &[Vec<u8>]) -> Result<()> {
    use x509_parser::prelude::*;

    let chain_length = certs.len();
    if chain_length < 2 {
        return Ok(());
    }

    for i in 1..chain_length {
        let (_, current_cert) =
            X509Certificate::from_der(&certs[i - 1]).map_err(|_e| Error::CoseCertUntrusted)?;

        let issuer_der = certs[i].to_vec();
        let data = current_cert.tbs_certificate.as_ref();
        let sig = current_cert.signature_value.as_ref();

        let sig_alg = cert_signing_alg(&current_cert);

        let result = verify_data(issuer_der, sig_alg, sig.to_vec(), data.to_vec()).await;

        // keep going as long as it validate
        match result {
            Ok(b) => {
                if !b {
                    return Err(Error::CoseInvalidCert);
                }
            }
            Err(_) => return Err(Error::CoseInvalidCert),
        }
    }
    Ok(())
}

async fn on_trust_list(
    th: &dyn TrustHandlerConfig,
    certs: &[Vec<u8>],
    ee_der: &[u8],
) -> Result<bool> {
    use x509_parser::prelude::*;

    // check the cert against the allowed list first
    let cert_sha256 = hash_sha256(ee_der);
    let cert_hash_base64 = base64::encode(&cert_sha256);
    if th.get_allowed_list().contains(&cert_hash_base64) {
        return Ok(true);
    }

    let mut full_chain: Vec<Vec<u8>> = Vec::new();
    full_chain.push(ee_der.to_vec());
    let mut in_chain = certs.to_vec();
    full_chain.append(&mut in_chain);

    // make sure chain is in the correct order and valid
    check_chain_order(&full_chain).await?;

    // build anchors and check against trust anchors,
    let mut anchors: Vec<X509Certificate> = Vec::new();
    let source_anchors = th.get_anchors();
    for anchor_der in &source_anchors {
        let (_, anchor) =
            X509Certificate::from_der(anchor_der).map_err(|_e| Error::CoseCertUntrusted)?;
        anchors.push(anchor);
    }

    if anchors.is_empty() {
        return Ok(false);
    }

    // work back from last cert in chain against the trust anchors
    for cert in certs.iter().rev() {
        let (_, chain_cert) =
            X509Certificate::from_der(cert).map_err(|_e| Error::CoseCertUntrusted)?;

        for anchor in &source_anchors {
            let data = chain_cert.tbs_certificate.as_ref();
            let sig = chain_cert.signature_value.as_ref();

            let sig_alg = cert_signing_alg(&chain_cert);

            let (_, anchor_cert) =
                X509Certificate::from_der(anchor).map_err(|_e| Error::CoseCertUntrusted)?;

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
    th: &dyn TrustHandlerConfig,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
) -> Result<bool> {
    // check configured EKUs against end-entity cert
    find_allowed_eku(cert_der, &th.get_auxillary_ekus()).ok_or(Error::CoseCertUntrusted)?;

    on_trust_list(th, chain_der, cert_der).await
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    use super::*;
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[wasm_bindgen_test]
    async fn test_trust_store() {
        let mut th = WebTrustHandlerConfig::new();
        th.clear();

        th.load_default_trust().unwrap();

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

        assert!(verify_trust_async(&th, &ps256_certs[1..], &ps256_certs[0])
            .await
            .unwrap());
        assert!(verify_trust_async(&th, &ps384_certs[1..], &ps384_certs[0])
            .await
            .unwrap());
        assert!(verify_trust_async(&th, &ps512_certs[1..], &ps512_certs[0])
            .await
            .unwrap());
        assert!(verify_trust_async(&th, &es256_certs[1..], &es256_certs[0])
            .await
            .unwrap());
        assert!(verify_trust_async(&th, &es384_certs[1..], &es384_certs[0])
            .await
            .unwrap());
        assert!(verify_trust_async(&th, &es512_certs[1..], &es512_certs[0])
            .await
            .unwrap());
        assert!(
            verify_trust_async(&th, &ed25519_certs[1..], &ed25519_certs[0])
                .await
                .unwrap()
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[wasm_bindgen_test]
    async fn test_broken_trust_chain() {
        let mut th = WebTrustHandlerConfig::new();
        th.clear();

        th.load_default_trust().unwrap();

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

        assert!(!verify_trust_async(&th, &ps256_certs[2..], &ps256_certs[0])
            .await
            .unwrap());
        assert!(!verify_trust_async(&th, &ps384_certs[2..], &ps384_certs[0])
            .await
            .unwrap());
        assert!(!verify_trust_async(&th, &ps512_certs[2..], &ps512_certs[0])
            .await
            .unwrap());
        assert!(!verify_trust_async(&th, &es256_certs[2..], &es256_certs[0])
            .await
            .unwrap());
        assert!(!verify_trust_async(&th, &es384_certs[2..], &es384_certs[0])
            .await
            .unwrap());
        assert!(!verify_trust_async(&th, &es512_certs[2..], &es512_certs[0])
            .await
            .unwrap());
        assert!(
            !verify_trust_async(&th, &ed25519_certs[2..], &ed25519_certs[0])
                .await
                .unwrap()
        );
    }
}
