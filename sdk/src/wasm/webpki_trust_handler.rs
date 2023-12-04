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

use asn1_rs::{FromDer, Oid};

//use webpki::{KeyUsage, types::{CertificateDer, UnixTime}, ALL_VERIFICATION_ALGS, anchor_from_trusted_cert};
use x509_certificate::certificate::X509Certificate;
use x509_parser::der_parser::ber::parse_ber_sequence;

use crate::{
    cose_validator::*,
    error::{Error, Result},
    trust_handler::{has_allowed_oid, load_eku_configuration, TrustHandler},
    SigningAlg,
};

/*
static ALL_SIGALGS: &[&webpki::Sig] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];
*/

fn load_trust_from_data(trust_data: &[u8]) -> Result<Vec<X509Certificate>> {
    X509Certificate::from_pem_multiple(trust_data).map_err(|_e| Error::WasmNoCrypto)
}

// Struct to handle verification of trust chains using WebPki
pub(crate) struct WebPkiTrustHandler<'a> {
    trust_anchors: Vec<Vec<u8>>,
    private_anchors: Vec<Vec<u8>>,
    oid_strings: Vec<String>,
    config_store: Vec<Oid<'a>>,
}

impl<'a> std::fmt::Debug for WebPkiTrustHandler<'a> {
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
impl<'a> WebPkiTrustHandler<'a> {
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

    fn find_allowed_eku(&self, cert_der: &[u8]) -> Option<&Oid<'_>> {
        use x509_parser::prelude::X509Certificate;
        if let Ok((_rem, cert)) = X509Certificate::from_der(cert_der) {
            if let Ok(Some(eku)) = cert.extended_key_usage() {
                let config_store = self.get_auxillary_ekus();
                if let Some(o) = has_allowed_oid(eku.value, config_store) {
                    return Some(o);
                }
            }
        }
        None
    }

    fn check_chain_order(&self, certs: &[Vec<u8>]) -> Result<()> {
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

            if current_cert.issuer() != issuer_cert.subject() {
                return Err(Error::CoseCertUntrusted);
            }

            let issuer_public_key = issuer_cert.public_key();
            current_cert
                .verify_signature(Some(issuer_public_key))
                .map_err(|_e| Error::CoseCertUntrusted)?;
        }
        Ok(())
    }

    fn on_trust_list(&self, certs: &[Vec<u8>], ee_der: &[u8]) -> Result<()> {
        use x509_parser::prelude::*;

        let mut full_chain: Vec<Vec<u8>> = Vec::new();
        full_chain.push(ee_der.to_vec());
        let mut in_chain = certs.clone().to_vec();
        full_chain.append(&mut in_chain);

        // make sure chain is in the correct order and valid
        self.check_chain_order(&full_chain)?;

        // build anchors and check against trust anchors,
        let mut anchors: Vec<X509Certificate> = Vec::new();
        for anchor_der in &self.trust_anchors {
            let (_, anchor) =
                X509Certificate::from_der(&anchor_der).map_err(|_e| Error::CoseCertUntrusted)?;
            anchors.push(anchor);
        }

        for anchor_der in &self.private_anchors {
            let (_, anchor) =
                X509Certificate::from_der(&anchor_der).map_err(|_e| Error::CoseCertUntrusted)?;
            anchors.push(anchor);
        }

        // work back from last cert in chain against the trust anchors
        for cert in certs.iter().rev() {
            let (_, chain_cert) =
                X509Certificate::from_der(cert).map_err(|_e| Error::CoseCertUntrusted)?;

            if anchors.iter().any(|anchor| {
                if chain_cert.issuer() == anchor.subject() {
                    let anchor_public_key = anchor.public_key();
                    let _tbs = chain_cert.tbs_certificate.as_ref();
                    let _signature = chain_cert.signature_value.as_ref();

                    let _signing_alg = if anchor_public_key.algorithm.algorithm == EC_PUBLICKEY_OID
                    {
                        if let Some(parameters) = &anchor_public_key.algorithm.parameters {
                            let named_curve_oid = match parameters.as_oid() {
                                Ok(p) => p,
                                Err(_) => return false,
                            };

                            if named_curve_oid == PRIME256V1_OID {
                                SigningAlg::Es256
                            } else if named_curve_oid == SECP384R1_OID {
                                SigningAlg::Es384
                            } else if named_curve_oid == SECP521R1_OID {
                                SigningAlg::Es512
                            } else {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else if anchor_public_key.algorithm.algorithm == SHA256_WITH_RSAENCRYPTION_OID
                    {
                        SigningAlg::Ps256
                    } else if anchor_public_key.algorithm.algorithm == SHA384_WITH_RSAENCRYPTION_OID
                    {
                        SigningAlg::Ps384
                    } else if anchor_public_key.algorithm.algorithm == SHA512_WITH_RSAENCRYPTION_OID
                    {
                        SigningAlg::Ps512
                    } else if anchor_public_key.algorithm.algorithm == ECDSA_WITH_SHA256_OID {
                        SigningAlg::Es256
                    } else if anchor_public_key.algorithm.algorithm == ECDSA_WITH_SHA384_OID {
                        SigningAlg::Es384
                    } else if anchor_public_key.algorithm.algorithm == ECDSA_WITH_SHA512_OID {
                        SigningAlg::Es512
                    } else if anchor_public_key.algorithm.algorithm == RSASSA_PSS_OID {
                        let skpi_ber = match parse_ber_sequence(&anchor_public_key.raw) {
                            Ok((_, skpi_ber)) => skpi_ber,
                            Err(_) => return false,
                        };

                        let seq = match skpi_ber.as_sequence() {
                            Ok(s) => s,
                            Err(_) => return false,
                        };

                        if seq.len() < 2 {
                            return false;
                        }

                        let hash_alg = match seq[0].as_oid_val() {
                            Ok(o) => o,
                            Err(_) => return false,
                        };

                        let param = match seq[1].as_sequence() {
                            Ok(s) => s,
                            Err(_) => return false,
                        };

                        let _mfg1 = match param[0].as_oid() {
                            Ok(o) => o,
                            Err(_) => return false,
                        };

                        let other_param = match param[1].as_sequence() {
                            Ok(s) => s,
                            Err(_) => return false,
                        };

                        let mfg1_hash = match other_param[0].as_oid_val() {
                            Ok(o) => o,
                            Err(_) => return false,
                        };

                        let _salt_len = match seq[2].as_i32() {
                            Ok(i) => i,
                            Err(_) => return false,
                        };

                        if hash_alg != mfg1_hash {
                            return false;
                        }

                        if hash_alg == SHA256_OID {
                            SigningAlg::Ps256
                        } else if hash_alg == SHA384_OID {
                            SigningAlg::Ps384
                        } else if hash_alg == SHA256_OID {
                            SigningAlg::Ps512
                        } else {
                            return false;
                        }
                    } else if anchor_public_key.algorithm.algorithm == ED25519_OID {
                        SigningAlg::Ed25519
                    } else {
                        return false;
                    };

                    chain_cert.verify_signature(Some(anchor_public_key)).is_ok()
                } else {
                    false
                }
            }) {
                return Ok(());
            }
        }

        // todo: consider (path check and names restrictions)

        Err(Error::CoseCertUntrusted)
    }
}

impl<'a> TrustHandler for WebPkiTrustHandler<'a> {
    fn new() -> Self {
        let mut th = WebPkiTrustHandler {
            trust_anchors: Vec::new(),
            private_anchors: Vec::new(),
            oid_strings: Vec::new(),
            config_store: Vec::new(),
        };
        th.load_default_trust().expect("build config is broken");

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

    // verify certificate and trust chain
    fn verify_trust(&self, chain_der: &[Vec<u8>], cert_der: &[u8]) -> Result<bool> {
        // check configured EKUs against end-entity cert
        self.find_allowed_eku(cert_der)
            .ok_or(Error::CoseCertUntrusted)?;

        let result = self.on_trust_list(chain_der, cert_der).is_ok();

        /*
         let chain_der_ref: Vec<CertificateDer> = chain_der.iter().map(|x| {
             CertificateDer::from(x.as_slice())
         }).collect();


         let time = UnixTime::now();

         let _allowed_oid = self.find_allowed_eku(cert_der).ok_or(Error::WasmNoCrypto)?;
         let cert_der_clone = cert_der.to_vec();

         let mut trust_anchor = Vec::new();
         let anchor_certs: Vec<CertificateDer<'_>> = self.trust_anchors.iter().map(|x| CertificateDer::from(x.as_slice())).collect();
         for anchor_der in &anchor_certs {
             let anchor = anchor_from_trusted_cert(anchor_der).map_err(|_e| Error::WasmNoCrypto)?;

             trust_anchor.push(anchor);
         }

         let private_certs: Vec<CertificateDer<'_>> = self.private_anchors.iter().map(|x| CertificateDer::from(x.as_slice())).collect();
         for anchor_der in &private_certs {
             let anchor = anchor_from_trusted_cert(&anchor_der).map_err(|_e| Error::WasmNoCrypto)?;

             trust_anchor.push(anchor);
         }

         let result = {
             let ku = KeyUsage::required(crate::trust_handler::EMAIL_PROTECTION_OID.as_bytes());
             let cert_der = CertificateDer::from(cert_der_clone.as_slice());
             let cert = webpki::EndEntityCert::try_from(&cert_der).unwrap();

             cert.verify_for_usage(ALL_VERIFICATION_ALGS, &trust_anchor, &chain_der_ref, time, ku, None, None)
                 .is_ok()
         };
        */

        Ok(result)
    }

    // load EKU configuration
    fn load_configuration(&mut self, config_data: &mut dyn Read) -> Result<()> {
        self.oid_strings = load_eku_configuration(config_data)?;

        for oid_str in &self.oid_strings {
            if let Ok(oid) = Oid::from_str(oid_str) {
                self.config_store.push(oid);
            }
        }
        Ok(())
    }

    // list off auxillary allowed EKU Oid
    fn get_auxillary_ekus(&self) -> &Vec<Oid<'_>> {
        &self.config_store
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{
        openssl::temp_signer::{self},
        Signer, SigningAlg,
    };

    #[test]
    fn test_trust_store() {
        let cert_dir = crate::utils::test::fixture_path("certs");

        let mut th = WebPkiTrustHandler::new();
        th.clear();

        th.load_default_trust().unwrap();

        // test all the certs
        let (ps256, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps256, None);
        let (ps384, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps384, None);
        let (ps512, _) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps512, None);
        let (es256, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es256, None);
        let (es384, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es384, None);
        //let (es512, _) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es512, None);
        let (ed25519, _) = temp_signer::get_ed_signer(&cert_dir, SigningAlg::Ed25519, None);

        let _ps256_certs = ps256.certs().unwrap();
        let _ps384_certs = ps384.certs().unwrap();
        let _ps512_certs = ps512.certs().unwrap();
        let es256_certs = es256.certs().unwrap();
        let es384_certs = es384.certs().unwrap();
        // let es512_certs = es512.certs().unwrap();
        let ed25519_certs = ed25519.certs().unwrap();

        //assert!(th.verify_trust(&ps256_certs[1..], &ps256_certs[0]).unwrap());
        //assert!(th.verify_trust(&ps384_certs[1..], &ps384_certs[0]).unwrap());
        //assert!(th.verify_trust(&ps512_certs[1..], &ps512_certs[0]).unwrap());
        assert!(th.verify_trust(&es256_certs[1..], &es256_certs[0]).unwrap());
        assert!(th.verify_trust(&es384_certs[1..], &es384_certs[0]).unwrap());
        // assert!(th.verify_trust(&es512_certs[1..], &es512_certs[0]).unwrap()); Not supported by ring
        assert!(th
            .verify_trust(&ed25519_certs[1..], &ed25519_certs[0])
            .unwrap());
    }

    #[test]
    fn test_broken_trust_chain() {
        let cert_dir = crate::utils::test::fixture_path("certs");
        let th = WebPkiTrustHandler::new();

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
        let ed25519_certs = ed25519.certs().unwrap();

        assert!(!th.verify_trust(&ps256_certs[2..], &ps256_certs[0]).unwrap());
        assert!(!th.verify_trust(&ps384_certs[2..], &ps384_certs[0]).unwrap());
        assert!(!th.verify_trust(&ps512_certs[2..], &ps512_certs[0]).unwrap());
        assert!(!th.verify_trust(&es256_certs[2..], &es256_certs[0]).unwrap());
        assert!(!th.verify_trust(&es384_certs[2..], &es384_certs[0]).unwrap());
        assert!(!th.verify_trust(&es512_certs[2..], &es512_certs[0]).unwrap());
        assert!(!th
            .verify_trust(&ed25519_certs[2..], &ed25519_certs[0])
            .unwrap());
    }
}
