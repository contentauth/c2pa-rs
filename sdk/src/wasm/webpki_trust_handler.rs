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
    io::{Cursor, Read},
    str::FromStr,
};

use asn1_rs::{nom::AsBytes, Any, Class, Header, Tag};
use x509_certificate::certificate::X509Certificate;
use x509_parser::{oid_registry::Oid, prelude::*};

use crate::{
    cose_validator::*,
    error::{Error, Result},
    trust_handler::{has_allowed_oid, load_eku_configuration, TrustHandlerConfig},
    wasm::webcrypto_validator::async_validate,
    SigningAlg,
};

fn load_trust_from_data(trust_data: &[u8]) -> Result<Vec<X509Certificate>> {
    X509Certificate::from_pem_multiple(trust_data).map_err(|_e| Error::WasmNoCrypto)
}

// Struct to handle verification of trust chains using WebPki
pub(crate) struct WebTrustHandlerConfig {
    pub trust_anchors: Vec<Vec<u8>>,
    pub private_anchors: Vec<Vec<u8>>,
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

#[allow(dead_code)]
impl WebTrustHandlerConfig {
    pub fn load_default_trust(&mut self) -> Result<()> {
        // load default trust anchors
        let ts = include_bytes!("../../tests/fixtures/certs/trust/trust_anchors.pem");
        let mut reader = Cursor::new(ts);

        // load the trust store
        self.load_trust_anchors_from_data(&mut reader)?;

        // load config store
        let config = include_bytes!("../../tests/fixtures/certs/trust/store.cfg");
        let mut config_reader = Cursor::new(config);
        self.load_configuration(&mut config_reader)?;

        // load debug/test private trust anchors
        #[cfg(test)]
        {
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
            config_store: Vec::new(),
        };

        if th.load_default_trust().is_err() {
            th.clear(); // just use empty trust handler to fail automatically
        }

        th
    }

    fn is_empty(&self) -> bool {
        self.trust_anchors.is_empty() && self.private_anchors.is_empty()
    }

    // add trust anchors
    fn load_trust_anchors_from_data(&mut self, trust_data_reader: &mut dyn Read) -> Result<()> {
        let mut trust_data = Vec::new();
        trust_data_reader.read_to_end(&mut trust_data)?;

        let anchors = load_trust_from_data(&trust_data)?;
        for anchor in anchors {
            let der = anchor.encode_der().map_err(|_e| Error::WasmNoCrypto)?;
            self.trust_anchors.push(der);
        }
        Ok(())
    }

    // append private trust anchors
    fn append_private_trust_data(&mut self, private_anchors_reader: &mut dyn Read) -> Result<()> {
        let mut private_anchors_data = Vec::new();
        private_anchors_reader.read_to_end(&mut private_anchors_data)?;

        let anchors = load_trust_from_data(&private_anchors_data)?;
        for anchor in anchors {
            let der = anchor.encode_der().map_err(|_e| Error::WasmNoCrypto)?;
            self.private_anchors.push(der);
        }
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
}

fn find_allowed_eku<'a>(cert_der: &'a [u8], allowed_ekus: &'a Vec<Oid<'a>>) -> Option<&'a Oid<'a>> {
    use x509_parser::prelude::X509Certificate;
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

async fn verify_data(cert_der: Vec<u8>, sig: Vec<u8>, data: Vec<u8>) -> Result<bool> {
    use x509_parser::prelude::*;

    let (_, cert) =
        X509Certificate::from_der(cert_der.as_bytes()).map_err(|_e| Error::CoseCertUntrusted)?;

    let certificate_public_key = cert.public_key();
    if let Some(cert_alg_string) = cert_signing_alg(&cert) {
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
            //"Ed25519" => return false,
            _ => return Err(Error::UnsupportedType),
        };

        async_validate(
            algo,
            hash,
            salt_len,
            certificate_public_key.raw.to_vec(),
            sig,
            data,
        )
        .await
    } else {
        return Err(Error::CoseInvalidCert);
    }
}

async fn check_chain_order(certs: &[Vec<u8>]) -> Result<()> {
    use x509_parser::prelude::*;

    let chain_length = certs.len();
    if chain_length < 2 {
        return Ok(());
    }

    for i in 1..chain_length {
        let (_, issuer_cert) =
            X509Certificate::from_der(&certs[i]).map_err(|_e| Error::CoseCertUntrusted)?;
        let (_, current_cert) =
            X509Certificate::from_der(&certs[i - 1]).map_err(|_e| Error::CoseCertUntrusted)?;

        let issuer_der = certs[i].to_vec();
        let data = current_cert.tbs_certificate.as_ref();
        let sig = current_cert.signature_value.as_ref();

        let result = verify_data(issuer_der, sig.to_vec(), data.to_vec()).await;

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

    let mut full_chain: Vec<Vec<u8>> = Vec::new();
    full_chain.push(ee_der.to_vec());
    let mut in_chain = certs.clone().to_vec();
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

    // work back from last cert in chain against the trust anchors
    for cert in certs.iter().rev() {
        let (_, chain_cert) =
            X509Certificate::from_der(cert).map_err(|_e| Error::CoseCertUntrusted)?;

        for anchor in anchors.iter() {
            if chain_cert.issuer() == anchor.subject() {
                let data = chain_cert.tbs_certificate.as_ref();
                let sig = chain_cert.signature_value.as_ref();

                let result =
                    verify_data(anchor.as_ref().to_vec(), sig.to_vec(), data.to_vec()).await;

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

        let x509_ps256_certs = load_trust_from_data(ps256).unwrap();
        let x509_ps384_certs = load_trust_from_data(ps384).unwrap();
        let x509_ps512_certs = load_trust_from_data(ps512).unwrap();
        let x509_es256_certs = load_trust_from_data(es256).unwrap();
        let x509_es384_certs = load_trust_from_data(es384).unwrap();
        let x509_es512_certs = load_trust_from_data(es512).unwrap();
        let x509_ed25519_certs = load_trust_from_data(ed25519).unwrap();

        let ps256_certs: Vec<Vec<u8>> = x509_ps256_certs
            .iter()
            .map(|x| x.encode_der().unwrap())
            .collect();
        let ps384_certs: Vec<Vec<u8>> = x509_ps384_certs
            .iter()
            .map(|x| x.encode_der().unwrap())
            .collect();
        let ps512_certs: Vec<Vec<u8>> = x509_ps512_certs
            .iter()
            .map(|x| x.encode_der().unwrap())
            .collect();
        let es256_certs: Vec<Vec<u8>> = x509_es256_certs
            .iter()
            .map(|x| x.encode_der().unwrap())
            .collect();
        let es384_certs: Vec<Vec<u8>> = x509_es384_certs
            .iter()
            .map(|x| x.encode_der().unwrap())
            .collect();
        let es512_certs: Vec<Vec<u8>> = x509_es512_certs
            .iter()
            .map(|x| x.encode_der().unwrap())
            .collect();
        let _ed25519_cert: Vec<Vec<u8>> = x509_ed25519_certs
            .iter()
            .map(|x| x.encode_der().unwrap())
            .collect();

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
        //assert!(verify_trust_async(&th, &ed25519_certs[1..], &ed25519_certs[0]).await..unwrap());
    }

    /*
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[wasm_bindgen_test]
    async fn test_broken_trust_chain() {
        let cert_dir = crate::utils::test::fixture_path("certs");
        let th = WebTrustHandlerConfig::new();

        // test all the certs
        let (ps256, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps256, None);
        let (ps384, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps384, None);
        let (ps512, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps512, None);
        let (es256, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es256, None);
        let (es384, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es384, None);
        let (es512, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es512, None);
        let (ed25519, _) = temp_signer::get_ed_signer(&cert_dir, SigningAlg::Ed25519, None);

        let ps256_certs = ps256.certs().unwrap();
        let ps384_certs = ps384.certs().unwrap();
        let ps512_certs = ps512.certs().unwrap();
        let es256_certs = es256.certs().unwrap();
        let es384_certs = es384.certs().unwrap();
        let es512_certs = es512.certs().unwrap();
        let _ed25519_certs = ed25519.certs().unwrap();

        assert!(!verify_trust_async(&th, &ps256_certs[2..], &ps256_certs[0]).await.unwrap());
        assert!(!verify_trust_async(&th, &ps384_certs[2..], &ps384_certs[0]).await.unwrap());
        assert!(!verify_trust_async(&th, &ps512_certs[2..], &ps512_certs[0]).await.unwrap());
        assert!(!verify_trust_async(&th, &es256_certs[2..], &es256_certs[0]).await.unwrap());
        assert!(!verify_trust_async(&th, &es384_certs[2..], &es384_certs[0]).await.unwrap());
        assert!(!verify_trust_async(&th, &es512_certs[2..], &es512_certs[0]).await.unwrap());
        //assert!(!verify_trust_async(&th, &ed25519_certs[2..], &ed25519_certs[0]).unwrap());
    }*/
}
