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
    panic::{RefUnwindSafe, UnwindSafe},
    str::FromStr,
};

use asn1_rs::{oid, Oid};

use crate::{Error, Result};

pub(crate) static EMAIL_PROTECTION_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .4);
pub(crate) static TIMESTAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .8);
pub(crate) static OCSP_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .9);
pub(crate) static DOCUMENT_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .36);

/// An implementation of `TrustHandlerConfig` provides a trust list (known
/// certificate authorities) and allowed EKUs for a given context.
pub trait TrustHandlerConfig: RefUnwindSafe + UnwindSafe + Sync + Send {
    /// Create a new instance of [`TrustHandlerConfig`].
    fn new() -> Self
    where
        Self: Sized;

    /// Load trust anchors from an input source.
    ///
    /// The input source should contain a UTF-8 text file containing zero or
    /// more valid certificates in PEM format.
    ///
    /// This function will ignore all text outside of the `---- BEGIN
    /// CERTIFICATE ----` / `---- END CERTIFICATE ----` line pairs.
    ///
    /// This function will return [`Error::CoseInvalidCert`] if any certificate
    /// can not be parsed.
    fn load_trust_anchors_from_data(&mut self, trust_data: &mut dyn Read) -> Result<()>;

    /// Load a set of explicitly trusted certificates from an input source.
    ///
    /// The input source should contain a UTF-8 text file containing zero or
    /// more valid certificates in PEM format.
    ///
    /// This function will ignore all text outside of the `---- BEGIN
    /// CERTIFICATE ----` / `---- END CERTIFICATE ----` line pairs.
    ///
    /// This function will return [`Error::CoseInvalidCert`] if any certificate
    /// can not be parsed.
    fn load_allowed_list(&mut self, allowed_list: &mut dyn Read) -> Result<()>;

    /// TO DO: I don't understand what "private" means in this context.
    fn append_private_trust_data(&mut self, private_anchors_data: &mut dyn Read) -> Result<()>;

    /// Clear all entries in the trust handler list.
    fn clear(&mut self);

    /// Load validation EKUs from an input source.
    ///
    /// The input source should contain lines of text with one OID per line.
    ///
    /// This function will ignore any lines that do not contain valid OIDs.
    fn load_configuration(&mut self, config_data: &mut dyn Read) -> Result<()>;

    /// Return the list of EKUs that should be accepted.
    fn get_auxiliary_ekus(&self) -> Vec<Oid>;

    /// Return the list of accepted trust anchors.
    ///
    /// This will be a list of DER-encoded certificates for the approved trust
    /// roots.
    fn get_anchors(&self) -> Vec<Vec<u8>>;

    /// Return the list of specifically-allowed certificates.
    ///
    /// This will be a [`HashSet`] of Base64-encoded DER certificates.
    fn get_allowed_list(&self) -> &HashSet<String>;
}

impl std::fmt::Debug for dyn TrustHandlerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TrustHandler Installed")
    }
}

/// Verifies that the given OID is among the EKUs approved for use in C2PA claim
/// generator signatures or in an outside list of allowed EKUs.
///
/// Returns `Some(oid)` if the OID is approved.
///
/// Returns `None` if not approved.
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

/// Load validation EKUs from an input source.
///
/// The input source should contain lines of text with one OID per line.
///
/// This function will ignore any lines that do not contain valid OIDs.
pub(crate) fn load_eku_configuration(
    config_data: &mut dyn Read,
) -> std::result::Result<Vec<String>, std::io::Error> {
    Ok(read_to_string(config_data)?
        .lines()
        .filter(|line| Oid::from_str(line).is_ok())
        .map(|line| line.to_owned())
        .collect())
}

/// Load trust anchors from a byte slice.
///
/// The byte slice should be a UTF-8 text file containing zero or more valid
/// certificates in PEM format.
///
/// This function will ignore all text outside of the `---- BEGIN CERTIFICATE
/// ----` / `---- END CERTIFICATE ----` line pairs.
///
/// This function will return [`Error::CoseInvalidCert`] if any certificate can
/// not be parsed.
pub(crate) fn load_trust_from_data(trust_data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();

    for pem_result in x509_parser::pem::Pem::iter_from_buffer(trust_data) {
        let pem = pem_result.map_err(|_e| Error::CoseInvalidCert)?;
        certs.push(pem.contents);
    }
    Ok(certs)
}
