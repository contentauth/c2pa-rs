// Copyright 2024 Adobe. All rights reserved.
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

use std::{collections::HashSet, error::Error, fmt, io::BufRead, str::FromStr};

use asn1_rs::{oid, Oid};
use async_generic::async_generic;
use thiserror::Error;
use x509_parser::{extensions::ExtendedKeyUsage, pem::Pem};

use crate::{base64, hash::sha256};

/// A `CertificateTrustPolicy` is configured with information about trust
/// anchors, privately-accepted end-entity certificates, and allowed EKUs. It
/// can be used to evaluate a signing certificate against those policies.
#[derive(Debug)]
pub struct CertificateTrustPolicy {
    /// Trust anchors (root X.509 certificates) in DER format.
    trust_anchor_ders: Vec<Vec<u8>>,

    /// Base-64 encoded SHA-256 hash of end-entity certificates (root X.509
    /// certificates) in DER format.
    end_entity_cert_set: HashSet<String>,

    /// Additional extended key usage (EKU) OIDs.
    additional_ekus: HashSet<String>,
}

impl Default for CertificateTrustPolicy {
    fn default() -> Self {
        let mut this = CertificateTrustPolicy {
            trust_anchor_ders: vec![],
            end_entity_cert_set: HashSet::default(),
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

impl CertificateTrustPolicy {
    /// Create a new certificate acceptance policy with no preconfigured trust
    /// roots.
    ///
    /// Use [`default()`] if you want a typical built-in configuration.
    ///
    /// [`default()`]: Self::default()
    pub fn new() -> Self {
        CertificateTrustPolicy {
            trust_anchor_ders: vec![],
            end_entity_cert_set: HashSet::default(),
            additional_ekus: HashSet::default(),
        }
    }

    /// Evaluate a certificate against the trust policy described by this
    /// struct.
    ///
    /// Returns `Ok(())` if the certificate appears on the end-entity
    /// certificate list or has a valid chain to one of the trust anchors that
    /// was provided and that it has a valid extended key usage (EKU).
    ///
    /// If `signing_time_epoch` is provided, evaluates the signing time (which
    /// must be in Unix seconds since the epoch) against the certificate's
    /// period of validity.
    #[allow(unused)] // parameters may be unused in some cases
    #[async_generic]
    pub fn check_certificate_trust(
        &self,
        chain_der: &[Vec<u8>],
        end_entity_cert_der: &[u8],
        signing_time_epoch: Option<i64>,
    ) -> Result<(), CertificateTrustError> {
        // First check to see if the certificate appears in the allowed set of
        // end-entity certificates.
        let cert_hash = base64_sha256_cert_der(end_entity_cert_der);
        if self.end_entity_cert_set.contains(&cert_hash) {
            return Ok(());
        }

        if _async {
            #[cfg(target_arch = "wasm32")]
            {
                return crate::raw_signature::webcrypto::check_certificate_trust::check_certificate_trust(
                    self,
                    chain_der,
                    end_entity_cert_der,
                    signing_time_epoch,
                )
                .await;
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            return crate::raw_signature::openssl::check_certificate_trust::check_certificate_trust(
                self,
                chain_der,
                end_entity_cert_der,
                signing_time_epoch,
            );
        }

        Err(CertificateTrustError::InternalError(
            "no implementation for certificate evaluation available".to_string(),
        ))
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
    /// As an optimization, this function also accepts standalone lines (outside
    /// of the X.509 PEM blocks). Each such line must contain a Base-64 encoded
    /// SHA_256 hash value over the value of a PEM certificate.
    ///
    /// Lines that match neither format (PEM or hash) are ignored.
    ///
    /// [§14.4.3, Private Credential Storage]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_private_credential_storage
    pub fn add_end_entity_credentials(
        &mut self,
        end_entity_cert_pems: &[u8],
    ) -> Result<(), InvalidCertificateError> {
        let mut inside_pem_block = false;

        for line in end_entity_cert_pems.lines().map_while(Result::ok) {
            if line.contains("-----BEGIN") {
                inside_pem_block = true;
            }
            if line.contains("-----END") {
                inside_pem_block = false;
            }
            if !inside_pem_block && line.len() == 44 && base64::decode(&line).is_ok() {
                self.end_entity_cert_set.insert(line);
            }
        }

        for maybe_pem in Pem::iter_from_buffer(end_entity_cert_pems) {
            // NOTE: The `x509_parser::pem::Pem` struct's `contents` field contains the
            // decoded PEM content, which is expected to be in DER format.
            match maybe_pem {
                Ok(pem) => {
                    self.end_entity_cert_set
                        .insert(base64_sha256_cert_der(&pem.contents));
                }
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

    /// Remove all trust anchors, private credentials, and EKUs previously
    /// configured.
    pub fn clear(&mut self) {
        self.trust_anchor_ders.clear();
        self.end_entity_cert_set.clear();
        self.additional_ekus.clear();
    }

    /// Return an iterator over the trust anchors.
    ///
    /// Each anchor will be returned in DER format.
    pub(crate) fn trust_anchor_ders(&self) -> impl Iterator<Item = &'_ Vec<u8>> {
        self.trust_anchor_ders.iter()
    }

    /// Return `true` if the EKU OID is allowed.
    pub(crate) fn has_allowed_eku<'a>(&self, eku: &'a ExtendedKeyUsage) -> Option<Oid<'a>> {
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

fn base64_sha256_cert_der(cert_der: &[u8]) -> String {
    let cert_sha256 = sha256(cert_der);
    base64::encode(&cert_sha256)
}

/// Describes errors that can be identified when evaluating a certificate's
/// trust.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CertificateTrustError {
    /// The certificate does not appear on any trust list that has been
    /// configured.
    ///
    /// A certificate can be approved either by adding one or more trust anchors
    /// via a call to [`CertificateTrustPolicy::add_trust_anchors`] or by
    /// adding one or more end-entity certificates via
    /// [`CertificateTrustPolicy::add_end_entity_credentials`].
    ///
    /// If the certificate that was presented doesn't match either of these
    /// conditions, this error will be returned.
    #[error("the certificate is not trusted")]
    CertificateNotTrusted,

    /// The certificate contains an invalid extended key usage (EKU) value.
    #[error("the certificate contains an invalid extended key usage (EKU) value")]
    InvalidEku,

    /// An error was reported by the underlying cryptography implementation.
    #[error("an error was reported by the cryptography library: {0}")]
    CryptoLibraryError(String),

    /// The certificate (or certificate chain) that was presented is invalid.
    #[error("the certificate or certificate chain is invalid")]
    InvalidCertificate,

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
    #[error("internal error ({0})")]
    InternalError(String),
}

#[cfg(not(target_arch = "wasm32"))]
impl From<openssl::error::ErrorStack> for CertificateTrustError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::CryptoLibraryError(err.to_string())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<crate::raw_signature::openssl::OpenSslMutexUnavailable> for CertificateTrustError {
    fn from(err: crate::raw_signature::openssl::OpenSslMutexUnavailable) -> Self {
        Self::InternalError(err.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
impl From<crate::raw_signature::webcrypto::WasmCryptoError> for CertificateTrustError {
    fn from(err: crate::raw_signature::webcrypto::WasmCryptoError) -> Self {
        match err {
            crate::raw_signature::webcrypto::WasmCryptoError::UnknownContext => {
                Self::InternalError("unknown WASM context".to_string())
            }
            crate::raw_signature::webcrypto::WasmCryptoError::NoCryptoAvailable => {
                Self::InternalError("WASM crypto unavailable".to_string())
            }
        }
    }
}

/// This error can occur when adding certificates to a
/// [`CertificateTrustPolicy`].
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidCertificateError(pub(crate) String);

impl fmt::Display for InvalidCertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to parse certificate list: {}", self.0)
    }
}

impl Error for InvalidCertificateError {}

static EMAIL_PROTECTION_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .4);
static TIMESTAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .8);
static OCSP_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .9);
