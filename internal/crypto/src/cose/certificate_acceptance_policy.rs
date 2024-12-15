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

#![allow(clippy::doc_lazy_continuation)] // Clippy and rustfmt aren't agreeing at the moment. :-(

use std::{collections::HashSet, error::Error, fmt, str::FromStr};

use asn1_rs::{oid, Oid};
use x509_parser::{extensions::ExtendedKeyUsage, pem::Pem};

/// A `CertificateAcceptancePolicy` retains information about trust anchors and
/// allowed EKUs to be used when verifying C2PA signing certificates.
#[derive(Debug)]
pub struct CertificateAcceptancePolicy {
    /// Trust anchors (root X.509 certificates) in DER format.
    trust_anchor_ders: Vec<Vec<u8>>,

    /// End-entity certificaters (root X.509 certificates) in DER format.
    end_entity_cert_ders: Vec<Vec<u8>>,

    /// Additional extended key usage (EKU) OIDs.
    additional_ekus: HashSet<String>,
}

impl Default for CertificateAcceptancePolicy {
    fn default() -> Self {
        let mut this = CertificateAcceptancePolicy {
            trust_anchor_ders: vec![],
            end_entity_cert_ders: vec![],
            additional_ekus: HashSet::default(),
        };

        this.add_valid_ekus(include_bytes!("./valid_eku_oids.cfg"));

        // In testing configs, also add debug/trust anchors.
        #[cfg(test)]
        {
            let _ = this.add_trust_anchors(include_bytes!(
                "../tests/fixtures/raw_signature/test_cert_root_bundle.pem"
            ));
        }

        this
    }
}

impl CertificateAcceptancePolicy {
    /// Create a new certificate acceptance policy with no preconfigured trust
    /// roots.
    ///
    /// Use [`default()`] if you want a typical built-in configuration.
    ///
    /// [`default()`]: Self::default()
    pub fn new() -> Self {
        CertificateAcceptancePolicy {
            trust_anchor_ders: vec![],
            end_entity_cert_ders: vec![],
            additional_ekus: HashSet::default(),
        }
    }

    /// Add trust anchors (root X.509 certificates) that shall be accepted when
    /// verifying COSE signatures.
    ///
    /// From [§14.4.1, C2PA Signers], of the C2PA Technical Specification:
    ///
    /// > A validator shall maintain the following lists for C2PA signers:
    /// >
    /// > * The list of X.509 certificate trust anchors provided by the C2PA
    /// > (i.e., the C2PA Trust List).
    /// > * A list of additional X.509 certificate trust anchors.
    /// > * ~~A list of accepted Extended Key Usage (EKU) values.~~ _(not
    /// > relevant for this API)_
    /// >
    /// > NOTE: Some of these lists can be empty.
    /// >
    /// > In addition to the list of trust anchors provided in the C2PA Trust
    /// > List, a validator should allow a user to configure additional trust
    /// > anchor stores, and should provide default options or offer lists
    /// > maintained by external parties that the user may opt into to populate
    /// > the validator’s trust anchor store for C2PA signers.
    ///
    /// This function reads zero or more X.509 root certificates in PEM format
    /// and configures the trust handler to accept certificates that chain up to
    /// these trust anchors.
    ///
    /// [§14.4.1, C2PA Signers]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_c2pa_signers
    pub fn add_trust_anchors(
        &mut self,
        trust_anchor_pems: &[u8],
    ) -> Result<(), InvalidCertificateError> {
        for maybe_pem in Pem::iter_from_buffer(trust_anchor_pems) {
            // NOTE: The `x509_parser::pem::Pem` struct's `contents` field contains the
            // decoded PEM content, which is expected to be in DER format.
            match maybe_pem {
                Ok(pem) => self.trust_anchor_ders.push(pem.contents),
                Err(e) => {
                    return Err(InvalidCertificateError(e.to_string()));
                }
            }
        }

        Ok(())
    }

    /// Add individual end-entity credentials that shall be accepted when
    /// verifying COSE signatures.
    ///
    /// From [§14.4.3, Private Credential Storage], of the C2PA Technical
    /// Specification:
    ///
    /// > A validator may also allow the user to create and maintain a private
    /// > credential store of signing credentials. This store is intended as an
    /// > "address book" of credentials they have chosen to trust based on an
    /// > out-of-band relationship. If present, the private credential store
    /// > shall only apply to validating signed C2PA manifests, and shall not
    /// > apply to validating time-stamps. If present, the private credential
    /// > store shall only allow trust in signer certificates directly; entries
    /// > in the private credential store cannot issue credentials and shall not
    /// > be included as trust anchors during validation.
    ///
    /// This function reads zero or more X.509 end-entity certificates in PEM
    /// format and configures the trust handler to accept those specific
    /// certificates, regardless of how they may or may not chain up to other
    /// trust anchors.
    ///
    /// [§14.4.3, Private Credential Storage]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_private_credential_storage
    pub fn add_end_entity_credentials(
        &mut self,
        end_entity_cert_pems: &[u8],
    ) -> Result<(), InvalidCertificateError> {
        for maybe_pem in Pem::iter_from_buffer(end_entity_cert_pems) {
            // NOTE: The `x509_parser::pem::Pem` struct's `contents` field contains the
            // decoded PEM content, which is expected to be in DER format.
            match maybe_pem {
                Ok(pem) => self.end_entity_cert_ders.push(pem.contents),
                Err(e) => {
                    return Err(InvalidCertificateError(e.to_string()));
                }
            }
        }

        Ok(())
    }

    /// Add extended key usage (EKU) values that shall be accepted when
    /// verifying COSE signatures.
    ///
    /// From [§14.4.1, C2PA Signers], of the C2PA Technical Specification:
    ///
    /// > A validator shall maintain the following lists for C2PA signers:
    /// >
    /// > * ~~The list of X.509 certificate trust anchors provided by the C2PA
    /// > (i.e., the C2PA Trust List).~~ _(not relevant for this API)_
    /// > * ~~A list of additional X.509 certificate trust anchors.~~ _(not
    /// > relevant for this API)_
    /// > * A list of accepted Extended Key Usage (EKU) values.
    /// >
    /// > NOTE: Some of these lists can be empty.
    ///
    /// This function reads zero or more EKU object identifiers (OIDs) in
    /// dotted-decimal notation (one per line) and configures the trust handler
    /// to accept certificates that are issued with one of those EKUs.
    ///
    /// IMPORTANT: The trust configuration will always accept the default set of
    /// OIDs descfibed in the C2PA Technical Specification.
    ///
    /// This function will quietly ignore any invalid input, such as a non-UTF8
    /// input or lines within the input such as comments or blank lines that can
    /// not be parsed as OIDs.
    ///
    /// [§14.4.1, C2PA Signers]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_c2pa_signers
    pub fn add_valid_ekus(&mut self, eku_oids: &[u8]) {
        let Ok(eku_oids) = std::str::from_utf8(eku_oids) else {
            return;
        };

        for line in eku_oids.lines() {
            if let Ok(_oid) = Oid::from_str(line) {
                self.additional_ekus.insert(line.to_string());
            }
        }
    }

    /// Return an iterator over the trust anchors.
    ///
    /// Each anchor will be returned in DER format.
    pub fn trust_anchor_ders(&self) -> impl Iterator<Item = &'_ Vec<u8>> {
        self.trust_anchor_ders.iter()
    }

    /// Return an iterator over the allowed end-entity certificates.
    ///
    /// Each end-entity certificate will be returned in DER format.
    pub fn end_entity_cert_ders(&self) -> impl Iterator<Item = &'_ Vec<u8>> {
        self.end_entity_cert_ders.iter()
    }

    /// Return `true` if the EKU OID is allowed.
    pub fn has_allowed_eku<'a>(&self, eku: &'a ExtendedKeyUsage) -> Option<Oid<'a>> {
        if eku.email_protection {
            return Some(EMAIL_PROTECTION_OID.clone());
        }

        if eku.time_stamping {
            return Some(TIMESTAMPING_OID.clone());
        }

        if eku.ocsp_signing {
            return Some(OCSP_SIGNING_OID.clone());
        }

        // TO REVIEW: Earlier implementation used the last match; this one uses the
        // first. Does that make a difference?

        for extra_oid in eku.other.iter().as_ref() {
            let extra_oid_str = extra_oid.to_string();
            if self.additional_ekus.contains(&extra_oid_str) {
                return Some(extra_oid.clone());
            }
        }

        None
    }
}

/// This error can occur when adding certificates to a
/// [`CertificateAcceptancePolicy`].
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidCertificateError(String);

impl fmt::Display for InvalidCertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to parse certificate list: {}", self.0)
    }
}

impl Error for InvalidCertificateError {}

static EMAIL_PROTECTION_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .4);
static TIMESTAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .8);
static OCSP_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .9);
