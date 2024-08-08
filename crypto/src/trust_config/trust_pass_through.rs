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
    io::{Cursor, Read},
    str::FromStr,
};

use asn1_rs::Oid;

use crate::{
    internal::{base64, hash_utils::hash_sha256},
    trust_config::trust_handler_config::*,
    Result, TrustHandlerConfig,
};

/// Trust handler configuration instance for use cases where the signer has
/// known trust relationships with specific providers.
#[derive(Debug)]
pub struct TrustPassThrough {
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
        unimplemented!();
    }

    fn append_private_trust_data(
        &mut self,
        _private_anchors_data: &mut dyn std::io::Read,
    ) -> Result<()> {
        unimplemented!();
    }

    fn clear(&mut self) {}

    fn load_configuration(&mut self, config_data: &mut dyn Read) -> Result<()> {
        config_data.read_to_end(&mut self.config_store)?;
        Ok(())
    }

    fn get_auxiliary_ekus(&self) -> Vec<Oid> {
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
