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
    io::{read_to_string, Read},
    str::FromStr,
};

use asn1_rs::{oid, Oid};

use crate::Result;

pub(crate) static EMAIL_PROTECTION_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .4);
pub(crate) static TIMESTAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .8);
pub(crate) static OCSP_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .9);
pub(crate) static DOCUMENT_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .36);

// Trait for supply configuration and handling of trust lists and EKU configuration store
pub(crate) trait TrustHandlerConfig {
    fn new() -> Self
    where
        Self: Sized;

    // return list of
    fn is_empty(&self) -> bool {
        true
    }

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
    fn get_anchors(&self) -> Vec<Vec<u8>>;

    // set of allowed cert hashes
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
    if eku.email_protection && allowed_ekus.iter().any(|oid| *oid == EMAIL_PROTECTION_OID) {
        return allowed_ekus.iter().find(|v| **v == EMAIL_PROTECTION_OID);
    }

    if eku.time_stamping && allowed_ekus.iter().any(|oid| *oid == TIMESTAMPING_OID) {
        return allowed_ekus.iter().find(|v| **v == TIMESTAMPING_OID);
    }

    if eku.ocsp_signing && allowed_ekus.iter().any(|oid| *oid == OCSP_SIGNING_OID) {
        return allowed_ekus.iter().find(|v| **v == OCSP_SIGNING_OID);
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
pub(crate) fn load_eku_configuration(config_data: &mut dyn Read) -> Result<Vec<String>> {
    let mut oid_vec = Vec::new();

    for line in read_to_string(config_data)?.lines() {
        if Oid::from_str(line).is_ok() {
            oid_vec.push(line.to_owned());
        }
    }
    Ok(oid_vec)
}
