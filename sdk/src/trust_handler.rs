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
    io::{read_to_string, Cursor, Read},
    str::FromStr,
};

use asn1_rs::{oid, Oid};

use crate::{hash_utils::hash_sha256, utils::base64, Error, Result};

pub(crate) static EMAIL_PROTECTION_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .4);
pub(crate) static TIMESTAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .8);
pub(crate) static OCSP_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .9);
pub(crate) static DOCUMENT_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .36);

// Trait for supply configuration and handling of trust lists and EKU configuration store
pub(crate) trait TrustHandlerConfig: Sync + Send {
    fn new() -> Self
    where
        Self: Sized;

    // add trust anchors
    fn load_trust_anchors_from_data(&mut self, trust_data: &mut dyn Read) -> Result<()>;

    // add allowed list
    fn load_allowed_list(&mut self, allowed_list: &mut dyn Read) -> Result<()>;

    // append private trust anchors
    fn append_private_trust_data(&mut self, private_anchors_data: &mut dyn Read) -> Result<()>;

    // clear all entries in trust handler list
    fn clear(&mut self);

    // load EKU configuration
    fn load_configuration(&mut self, config_data: &mut dyn Read) -> Result<()>;

    // list off auxillary allowed EKU Oid
    fn get_auxillary_ekus(&self) -> Vec<Oid>;

    // list of all anchors
    #[allow(dead_code)] // Only used in calls with allow dead_code
    fn get_anchors(&self) -> Vec<Vec<u8>>;

    // set of allowed cert hashes
    #[allow(dead_code)] // Only used in calls with allow dead_code
    fn get_allowed_list(&self) -> &HashSet<String>;
}

impl std::fmt::Debug for dyn TrustHandlerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TrustHandler Installed")
    }
}

pub(crate) fn has_allowed_oid<'a>(
    eku: &x509_parser::extensions::ExtendedKeyUsage,
    allowed_ekus: &'a [Oid],
) -> Option<&'a Oid<'a>> {
    if eku.email_protection {
        return Some(&EMAIL_PROTECTION_OID);
    }

    if eku.time_stamping {
        return Some(&TIMESTAMPING_OID);
    }

    if eku.ocsp_signing {
        return Some(&OCSP_SIGNING_OID);
    }

    let mut last_oid = None;
    if eku.other.iter().any(|v| {
        allowed_ekus.iter().any(|oid| {
            if oid == v {
                last_oid = Some(oid);
                true
            } else {
                false
            }
        })
    }) {
        return last_oid;
    }
    None
}

// load set of validation EKUs, ignoring unrecognized Oid lines
#[allow(dead_code)]
pub(crate) fn load_eku_configuration(config_data: &mut dyn Read) -> Result<Vec<String>> {
    let mut oid_vec = Vec::new();

    for line in read_to_string(config_data)?.lines() {
        if Oid::from_str(line).is_ok() {
            oid_vec.push(line.to_owned());
        }
    }
    Ok(oid_vec)
}

pub(crate) fn load_trust_from_data(trust_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();

    for pem_result in x509_parser::pem::Pem::iter_from_buffer(trust_data) {
        let pem = pem_result.map_err(|_e| Error::CoseInvalidCert)?;
        certs.push(pem.contents);
    }
    Ok(certs)
}

// Pass through trust for the case of claim signer usage since it has known trust with context
// configured to all email protection, timestamping, ocsp signing and document signing
pub(crate) struct TrustPassThrough {
    allowed_cert_set: HashSet<String>,
    config_store: Vec<u8>,
}

impl TrustHandlerConfig for TrustPassThrough {
    fn new() -> Self
    where
        Self: Sized,
    {
        TrustPassThrough {
            allowed_cert_set: HashSet::new(),
            config_store: Vec::new(),
        }
    }

    fn load_trust_anchors_from_data(&mut self, _trust_data: &mut dyn std::io::Read) -> Result<()> {
        Ok(())
    }

    fn append_private_trust_data(
        &mut self,
        _private_anchors_data: &mut dyn std::io::Read,
    ) -> Result<()> {
        Ok(())
    }

    fn clear(&mut self) {}

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
        if oids.is_empty() {
            // return default
            vec![
                EMAIL_PROTECTION_OID.to_owned(),
                TIMESTAMPING_OID.to_owned(),
                OCSP_SIGNING_OID.to_owned(),
                DOCUMENT_SIGNING_OID.to_owned(),
            ]
        } else {
            oids
        }
    }

    fn get_anchors(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    fn load_allowed_list(&mut self, allowed_list: &mut dyn std::io::prelude::Read) -> Result<()> {
        let mut buffer = Vec::new();
        allowed_list.read_to_end(&mut buffer)?;

        if let Ok(cert_list) = load_trust_from_data(&buffer) {
            for cert_der in &cert_list {
                let cert_sha256 = hash_sha256(cert_der);
                let cert_hash_base64 = base64::encode(&cert_sha256);

                self.allowed_cert_set.insert(cert_hash_base64);
            }
        }
        Ok(())
    }

    fn get_allowed_list(&self) -> &std::collections::HashSet<String> {
        &self.allowed_cert_set
    }
}
