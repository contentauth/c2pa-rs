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
    collections::HashSet,
    io::{BufRead, BufReader, Cursor, Read},
    str::FromStr,
};

use asn1_rs::Oid;
use openssl::x509::verify::X509VerifyFlags;

use crate::{
    internal::{base64, hash_utils::hash_sha256},
    trust_config::trust_handler_config::{load_eku_configuration, TrustHandlerConfig},
    Error, Result,
};

fn certs_der_to_x509(ders: &[Vec<u8>]) -> Result<Vec<openssl::x509::X509>> {
    // IMPORTANT: OpenSslMutex::acquire() should have been called by calling fn.
    // Please don't make this pub or pub(crate) without finding a way to ensure
    // that precondition.

    let mut certs: Vec<openssl::x509::X509> = Vec::new();

    for d in ders {
        let cert = openssl::x509::X509::from_der(d).map_err(Error::OpenSslError)?;
        certs.push(cert);
    }

    Ok(certs)
}

fn load_trust_from_pem_data(trust_data: &[u8]) -> Result<Vec<openssl::x509::X509>> {
    let _openssl = super::OpenSslMutex::acquire()?;
    openssl::x509::X509::stack_from_pem(trust_data).map_err(Error::OpenSslError)
}

// Struct to handle verification of trust chains
// [scouten 2024-06-27]: Hacking to make public.
pub struct OpenSSLTrustHandlerConfig {
    trust_anchors: Vec<openssl::x509::X509>,
    private_anchors: Vec<openssl::x509::X509>,
    allowed_cert_set: HashSet<String>,
    trust_store: Option<openssl::x509::store::X509Store>,
    config_store: Vec<u8>,
}

impl OpenSSLTrustHandlerConfig {
    pub fn load_default_trust(&mut self) -> Result<()> {
        // load config store
        let config = include_bytes!("./store.cfg");
        let mut config_reader = Cursor::new(config);
        self.load_configuration(&mut config_reader)?;

        // load debug/test private trust anchors
        if cfg!(test) {
            let pa = include_bytes!("./test_cert_root_bundle.pem");
            let mut pa_reader = Cursor::new(pa);

            self.append_private_trust_data(&mut pa_reader)?;
        }

        Ok(())
    }

    fn update_store(&mut self) -> Result<()> {
        let _openssl = super::OpenSslMutex::acquire()?;

        let mut builder =
            openssl::x509::store::X509StoreBuilder::new().map_err(Error::OpenSslError)?;

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
            allowed_cert_set: HashSet::new(),
            trust_store: None,
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

        self.trust_anchors = load_trust_from_pem_data(&trust_data)?;
        if self.trust_anchors.is_empty() {
            return Err(Error::NotFound); // catch silent failure
        }

        self.update_store()
    }

    // add allowed list entries
    fn load_allowed_list(&mut self, allowed_list: &mut dyn Read) -> Result<()> {
        let mut buffer = Vec::new();
        allowed_list.read_to_end(&mut buffer)?;

        {
            let _openssl = super::OpenSslMutex::acquire()?;
            if let Ok(cert_list) = openssl::x509::X509::stack_from_pem(&buffer) {
                for cert in &cert_list {
                    let cert_der = cert.to_der().map_err(Error::OpenSslError)?;
                    let cert_sha256 = hash_sha256(&cert_der);
                    let cert_hash_base64 = base64::encode(&cert_sha256);

                    self.allowed_cert_set.insert(cert_hash_base64);
                }
            }
        }

        // try to load the of base64 encoded encoding of the sha256 hash of the
        // certificate DER encoding
        let reader = Cursor::new(buffer);
        let buf_reader = BufReader::new(reader);

        let mut inside_cert_block = false;
        for l in buf_reader.lines().map_while(|v| v.ok()) {
            if l.contains("-----BEGIN") {
                inside_cert_block = true;
            }
            if l.contains("-----END") {
                inside_cert_block = false;
            }

            // sanity check that that is is base64 encoded and outside of certificate block
            if !inside_cert_block && base64::decode(&l).is_ok() && !l.is_empty() {
                self.allowed_cert_set.insert(l);
            }
        }

        Ok(())
    }

    // append private trust anchors
    fn append_private_trust_data(&mut self, private_anchors_reader: &mut dyn Read) -> Result<()> {
        let mut private_anchors_data = Vec::new();
        private_anchors_reader.read_to_end(&mut private_anchors_data)?;

        let mut pa = load_trust_from_pem_data(&private_anchors_data)?;
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

    // list off auxiliary allowed EKU Oid
    fn get_auxiliary_ekus(&self) -> Vec<Oid> {
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

    // set of allowed cert hashes
    fn get_allowed_list(&self) -> &HashSet<String> {
        &self.allowed_cert_set
    }
}

// verify certificate and trust chain
pub(crate) fn verify_trust(
    th: &dyn TrustHandlerConfig,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    signing_time_epoc: Option<i64>,
) -> Result<bool> {
    // check the cert against the allowed list first
    let cert_sha256 = hash_sha256(cert_der);
    let cert_hash_base64 = base64::encode(&cert_sha256);
    if th.get_allowed_list().contains(&cert_hash_base64) {
        return Ok(true);
    }

    let _openssl = super::OpenSslMutex::acquire()?;

    let mut cert_chain = openssl::stack::Stack::new().map_err(Error::OpenSslError)?;
    let mut store_ctx = openssl::x509::X509StoreContext::new().map_err(Error::OpenSslError)?;

    let chain = certs_der_to_x509(chain_der)?;
    for c in chain {
        cert_chain.push(c).map_err(Error::OpenSslError)?;
    }
    let cert = openssl::x509::X509::from_der(cert_der).map_err(Error::OpenSslError)?;

    let mut builder = openssl::x509::store::X509StoreBuilder::new().map_err(Error::OpenSslError)?;

    let mut verify_param =
        openssl::x509::verify::X509VerifyParam::new().map_err(Error::OpenSslError)?;
    if let Some(st) = signing_time_epoc {
        verify_param.set_time(st);
    } else {
        verify_param
            .set_flags(X509VerifyFlags::NO_CHECK_TIME)
            .map_err(Error::OpenSslError)?;
    }
    builder
        .set_param(&verify_param)
        .map_err(Error::OpenSslError)?;

    // todo: figure out the passthrough case
    if th.get_anchors().is_empty() {
        return Ok(false);
    }

    // add trust anchors
    for d in th.get_anchors() {
        let c = openssl::x509::X509::from_der(&d).map_err(Error::OpenSslError)?;
        builder.add_cert(c)?;
    }
    // finalize store
    let store = builder.build();

    match store_ctx.init(&store, cert.as_ref(), &cert_chain, |f| f.verify_cert()) {
        Ok(trust) => Ok(trust),
        Err(_) => Ok(false),
    }
}
