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

use std::{
    io::{Cursor, Read},
    str::FromStr,
};

use asn1_rs::Oid;

use crate::{
    error::{wrap_openssl_err, Result},
    trust_handler::{load_eku_configuration, TrustHandlerConfig},
};

fn certs_der_to_x509(ders: &[Vec<u8>]) -> Result<Vec<openssl::x509::X509>> {
    let mut certs: Vec<openssl::x509::X509> = Vec::new();

    for d in ders {
        let cert = openssl::x509::X509::from_der(d).map_err(wrap_openssl_err)?;
        certs.push(cert);
    }

    Ok(certs)
}

fn load_trust_from_data(trust_data: &[u8]) -> Result<Vec<openssl::x509::X509>> {
    openssl::x509::X509::stack_from_pem(trust_data).map_err(wrap_openssl_err)
}

// Struct to handle verification of trust chains
pub(crate) struct OpenSSLTrustHandlerConfig {
    trust_anchors: Vec<openssl::x509::X509>,
    private_anchors: Vec<openssl::x509::X509>,
    trust_store: Option<openssl::x509::store::X509Store>,
    config_store: Vec<u8>,
}

impl OpenSSLTrustHandlerConfig {
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

    fn update_store(&mut self) -> Result<()> {
        let mut builder =
            openssl::x509::store::X509StoreBuilder::new().map_err(wrap_openssl_err)?;

        // add trust anchors
        for t in &self.trust_anchors {
            builder.add_cert(t.clone())?;
        }

        // add private anchors
        for t in &self.private_anchors {
            builder.add_cert(t.clone())?;
        }

        self.trust_store = Some(builder.build());

        Ok(())
    }
}

impl std::fmt::Debug for OpenSSLTrustHandlerConfig {
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
impl TrustHandlerConfig for OpenSSLTrustHandlerConfig {
    fn new() -> Self {
        let mut th = OpenSSLTrustHandlerConfig {
            trust_anchors: Vec::new(),
            private_anchors: Vec::new(),
            trust_store: None,
            config_store: Vec::new(),
        };
        if th.load_default_trust().is_err() {
            th.clear(); // just use empty trust handler to fail automatically
        }

        th
    }

    fn is_empty(&self) -> bool {
        self.trust_store.is_none()
    }

    // add trust anchors
    fn load_trust_anchors_from_data(&mut self, trust_data_reader: &mut dyn Read) -> Result<()> {
        let mut trust_data = Vec::new();
        trust_data_reader.read_to_end(&mut trust_data)?;

        self.trust_anchors = load_trust_from_data(&trust_data)?;
        self.update_store()
    }

    // append private trust anchors
    fn append_private_trust_data(&mut self, private_anchors_reader: &mut dyn Read) -> Result<()> {
        let mut private_anchors_data = Vec::new();
        private_anchors_reader.read_to_end(&mut private_anchors_data)?;

        let mut pa = load_trust_from_data(&private_anchors_data)?;
        self.private_anchors.append(&mut pa);
        self.update_store()
    }

    fn clear(&mut self) {
        self.trust_anchors = Vec::new();
        self.private_anchors = Vec::new();
        self.trust_store = None;
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

        for a in &self.private_anchors {
            if let Ok(der) = a.to_der() {
                anchors.push(der)
            }
        }

        for a in &self.trust_anchors {
            if let Ok(der) = a.to_der() {
                anchors.push(der)
            }
        }
        anchors
    }
}

// verify certificate and trust chain
pub(crate) fn verify_trust(
    th: &dyn TrustHandlerConfig,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
) -> Result<bool> {
    let mut cert_chain = openssl::stack::Stack::new().map_err(wrap_openssl_err)?;
    let mut store_ctx = openssl::x509::X509StoreContext::new().map_err(wrap_openssl_err)?;

    let chain = certs_der_to_x509(chain_der)?;
    for c in chain {
        cert_chain.push(c).map_err(wrap_openssl_err)?;
    }
    let cert = openssl::x509::X509::from_der(cert_der).map_err(wrap_openssl_err)?;

    let mut builder = openssl::x509::store::X509StoreBuilder::new().map_err(wrap_openssl_err)?;

    // todo: figure out the passthrough case
    if th.get_anchors().is_empty() {
        return Ok(true);
    }

    // add trust anchors
    for d in th.get_anchors() {
        let c = openssl::x509::X509::from_der(&d).map_err(wrap_openssl_err)?;
        builder.add_cert(c)?;
    }
    // finalize store
    let store = builder.build();

    match store_ctx.init(&store, cert.as_ref(), &cert_chain, |f| f.verify_cert()) {
        Ok(trust) => Ok(trust),
        Err(_) => Ok(false),
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

        let mut th = OpenSSLTrustHandlerConfig::new();
        th.clear();

        th.load_default_trust().unwrap();

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

        assert!(verify_trust(&th, &ps256_certs[1..], &ps256_certs[0]).unwrap());
        assert!(verify_trust(&th, &ps384_certs[1..], &ps384_certs[0]).unwrap());
        assert!(verify_trust(&th, &ps512_certs[1..], &ps512_certs[0]).unwrap());
        assert!(verify_trust(&th, &es256_certs[1..], &es256_certs[0]).unwrap());
        assert!(verify_trust(&th, &es384_certs[1..], &es384_certs[0]).unwrap());
        assert!(verify_trust(&th, &es512_certs[1..], &es512_certs[0]).unwrap());
        assert!(verify_trust(&th, &ed25519_certs[1..], &ed25519_certs[0]).unwrap());
    }

    #[test]
    fn test_broken_trust_chain() {
        let cert_dir = crate::utils::test::fixture_path("certs");
        let ta = include_bytes!("../../tests/fixtures/certs/trust/test_cert_root_bundle.pem");

        let mut th = OpenSSLTrustHandlerConfig::new();
        th.clear();

        // load the trust store
        let mut reader = Cursor::new(ta);
        th.load_trust_anchors_from_data(&mut reader).unwrap();

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

        assert!(!verify_trust(&th, &ps256_certs[2..], &ps256_certs[0]).unwrap());
        assert!(!verify_trust(&th, &ps384_certs[2..], &ps384_certs[0]).unwrap());
        assert!(!verify_trust(&th, &ps512_certs[2..], &ps512_certs[0]).unwrap());
        assert!(!verify_trust(&th, &es256_certs[2..], &es256_certs[0]).unwrap());
        assert!(!verify_trust(&th, &es384_certs[2..], &es384_certs[0]).unwrap());
        assert!(!verify_trust(&th, &es512_certs[2..], &es512_certs[0]).unwrap());
        assert!(!verify_trust(&th, &ed25519_certs[2..], &ed25519_certs[0]).unwrap());
    }
}
