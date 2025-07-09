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

use crate::crypto::{base64, hash::sha256};

/// Enum to describe the type of trust anchor that validated the certificate.
#[derive(Debug, Eq, PartialEq)]
pub enum TrustAnchorType {
    /// Trust anchors provided by sanctioned authority.
    System,

    /// User provided trust anchor.
    User,

    /// End-entity certificate.
    EndEntity,

    /// No check performed
    NoCheck,
}

/// A `CertificateTrustPolicy` is configured with information about trust
/// anchors, privately-accepted end-entity certificates, and allowed EKUs. It
/// can be used to evaluate a signing certificate against those policies.
#[derive(Debug)]
pub struct CertificateTrustPolicy {
    /// Trust anchors (root X.509 certificates) in DER format.
    trust_anchor_ders: Vec<Vec<u8>>,

    // User provided trust anchors in DER format.
    user_trust_anchor_ders: Vec<Vec<u8>>,

    /// Base-64 encoded SHA-256 hash of end-entity certificates (root X.509
    /// certificates) in DER format.
    end_entity_cert_set: HashSet<String>,

    /// Additional extended key usage (EKU) OIDs.
    additional_ekus: HashSet<String>,

    /// passthrough mode
    passthrough: bool,
}

impl Default for CertificateTrustPolicy {
    fn default() -> Self {
        let mut this = CertificateTrustPolicy {
            trust_anchor_ders: vec![],
            user_trust_anchor_ders: vec![],
            end_entity_cert_set: HashSet::default(),
            additional_ekus: HashSet::default(),
            passthrough: false,
        };

        this.add_valid_ekus(include_bytes!("./valid_eku_oids.cfg"));

        // In testing configs, also add debug/trust anchors.
        #[cfg(test)]
        {
            let _ = this.add_user_trust_anchors(include_bytes!(
                "../../../tests/fixtures/crypto/raw_signature/test_cert_root_bundle.pem"
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
            user_trust_anchor_ders: vec![],
            end_entity_cert_set: HashSet::default(),
            additional_ekus: HashSet::default(),
            passthrough: false,
        }
    }

    /// Creates a passthrough policy checker for cases when trust checks should not be performed
    pub fn passthrough() -> Self {
        Self {
            trust_anchor_ders: vec![],
            user_trust_anchor_ders: vec![],
            end_entity_cert_set: HashSet::default(),
            additional_ekus: HashSet::default(),
            passthrough: true,
        }
    }

    /// Evaluate a certificate against the trust policy described by this
    /// struct.
    ///
    /// Returns `Ok(TrustAnchorType)` if the certificate appears on the end-entity
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
    ) -> Result<TrustAnchorType, CertificateTrustError> {
        if self.passthrough {
            return Ok(TrustAnchorType::NoCheck);
        }

        // First check to see if the certificate appears in the allowed set of
        // end-entity certificates.
        let cert_hash = base64_sha256_cert_der(end_entity_cert_der);
        if self.end_entity_cert_set.contains(&cert_hash) {
            return Ok(TrustAnchorType::EndEntity);
        }

        #[cfg(feature = "rust_native_crypto")]
        {
            return crate::crypto::raw_signature::rust_native::check_certificate_trust::check_certificate_trust(
                self,
                chain_der,
                end_entity_cert_der,
                signing_time_epoch,
            );
        }

        #[cfg(feature = "openssl")]
        {
            return crate::crypto::raw_signature::openssl::check_certificate_trust::check_certificate_trust(
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
    ///  The function can be called multiple times to add multiple trust anchors. For example,
    ///  the C2PA trust anchors and timestamping trust anchors can be added separately.
    /// [§14.4.1, C2PA Signers]: <https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_c2pa_signers>
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

    /// Add user provided trust anchors that shall be accepted when verifying COSE signatures.
    /// These anchors are distinct from the C2PA trust anchors and are used to validate certificates
    /// that are not part of the C2PA trust anchors.  
    pub fn add_user_trust_anchors(
        &mut self,
        trust_anchor_pems: &[u8],
    ) -> Result<(), InvalidCertificateError> {
        for maybe_pem in Pem::iter_from_buffer(trust_anchor_pems) {
            match maybe_pem {
                Ok(pem) => self.user_trust_anchor_ders.push(pem.contents),
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

    /// Return an iterator over the user trust anchors.
    ///
    /// Each anchor will be returned in DER format.
    pub(crate) fn user_trust_anchor_ders(&self) -> impl Iterator<Item = &'_ Vec<u8>> {
        self.user_trust_anchor_ders.iter()
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
    /// via a call to [`CertificateTrustPolicy::add_trust_anchors`] or
    /// [`CertificateTrustPolicy::add_user_trust_anchors`] or by
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

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for CertificateTrustError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::CryptoLibraryError(err.to_string())
    }
}

#[cfg(feature = "openssl")]
impl From<crate::crypto::raw_signature::openssl::OpenSslMutexUnavailable>
    for CertificateTrustError
{
    fn from(err: crate::crypto::raw_signature::openssl::OpenSslMutexUnavailable) -> Self {
        Self::InternalError(err.to_string())
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use asn1_rs::{oid, Oid};
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;
    use x509_parser::{extensions::ExtendedKeyUsage, pem::Pem};

    use crate::crypto::{
        cose::{
            CertificateTrustError, CertificateTrustPolicy, InvalidCertificateError, TrustAnchorType,
        },
        raw_signature::{signer::test_signer, SigningAlg},
    };

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn impl_debug() {
        let ctp = CertificateTrustPolicy::new();
        let _ = format!("{ctp:#?}");
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn new() {
        let ctp = CertificateTrustPolicy::new();

        assert_eq!(
            ctp.has_allowed_eku(&email_eku()).unwrap(),
            EMAIL_PROTECTION_OID
        );

        assert!(ctp.has_allowed_eku(&document_signing_eku()).is_none());

        assert_eq!(
            ctp.has_allowed_eku(&time_stamping_eku()).unwrap(),
            TIME_STAMPING_OID
        );

        assert_eq!(
            ctp.has_allowed_eku(&ocsp_signing_eku()).unwrap(),
            OCSP_SIGNING_OID
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn default() {
        let ctp = CertificateTrustPolicy::default();

        assert_eq!(
            ctp.has_allowed_eku(&email_eku()).unwrap(),
            EMAIL_PROTECTION_OID
        );

        assert_eq!(
            ctp.has_allowed_eku(&document_signing_eku()).unwrap(),
            DOCUMENT_SIGNING_OID
        );

        assert_eq!(
            ctp.has_allowed_eku(&time_stamping_eku()).unwrap(),
            TIME_STAMPING_OID
        );

        assert_eq!(
            ctp.has_allowed_eku(&ocsp_signing_eku()).unwrap(),
            OCSP_SIGNING_OID
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn clear() {
        let mut ctp = CertificateTrustPolicy::default();
        ctp.clear();

        assert_eq!(
            ctp.has_allowed_eku(&email_eku()).unwrap(),
            EMAIL_PROTECTION_OID
        );

        assert!(ctp.has_allowed_eku(&document_signing_eku()).is_none());

        assert_eq!(
            ctp.has_allowed_eku(&time_stamping_eku()).unwrap(),
            TIME_STAMPING_OID
        );

        assert_eq!(
            ctp.has_allowed_eku(&ocsp_signing_eku()).unwrap(),
            OCSP_SIGNING_OID
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn add_valid_ekus_err_bad_utf8() {
        let mut ctp = CertificateTrustPolicy::new();
        ctp.add_valid_ekus(&[128, 0]);

        assert_eq!(
            ctp.has_allowed_eku(&email_eku()).unwrap(),
            EMAIL_PROTECTION_OID
        );

        assert!(ctp.has_allowed_eku(&document_signing_eku()).is_none());

        assert_eq!(
            ctp.has_allowed_eku(&time_stamping_eku()).unwrap(),
            TIME_STAMPING_OID
        );

        assert_eq!(
            ctp.has_allowed_eku(&ocsp_signing_eku()).unwrap(),
            OCSP_SIGNING_OID
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn add_trust_anchors_err_bad_pem() {
        let mut ctp = CertificateTrustPolicy::new();
        assert!(ctp.add_trust_anchors(BAD_PEM.as_bytes()).is_err());
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn add_end_entity_credentials_err_bad_pem() {
        let mut ctp = CertificateTrustPolicy::new();
        assert!(ctp.add_end_entity_credentials(BAD_PEM.as_bytes()).is_err());
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn err_to_string() {
        let ice = InvalidCertificateError("foo".to_string());
        assert_eq!(ice.to_string(), "Unable to parse certificate list: foo");
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn err_debug() {
        let ice = InvalidCertificateError("foo".to_string());
        assert_eq!(
            format!("{ice:#?}"),
            "InvalidCertificateError(\n    \"foo\",\n)"
        );
    }

    fn email_eku() -> ExtendedKeyUsage<'static> {
        ExtendedKeyUsage {
            any: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: true,
            time_stamping: false,
            ocsp_signing: false,
            other: vec![],
        }
    }

    fn document_signing_eku() -> ExtendedKeyUsage<'static> {
        ExtendedKeyUsage {
            any: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: false,
            other: vec![DOCUMENT_SIGNING_OID.clone()],
        }
    }

    fn time_stamping_eku() -> ExtendedKeyUsage<'static> {
        ExtendedKeyUsage {
            any: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: true,
            ocsp_signing: false,
            other: vec![],
        }
    }

    fn ocsp_signing_eku() -> ExtendedKeyUsage<'static> {
        ExtendedKeyUsage {
            any: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: true,
            other: vec![],
        }
    }

    static EMAIL_PROTECTION_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .4);
    static DOCUMENT_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .36);
    static TIME_STAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .8);
    static OCSP_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .9);

    static BAD_PEM: &str = r#"
-----BEGIN CERTIFICATE-----
µIICEzCCAcWgAwIBAgIUW4fUnS38162x10PCnB8qFsrQuZgwBQYDK2VwMHcxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU29tZXdoZXJlMRowGAYD
VQQKDBFDMlBBIFRlc3QgUm9vdCBDQTEZMBcGA1UECwwQRk9SIFRFU1RJTkdfT05M
WTEQMA4GA1UEAwwHUm9vdCBDQTAeFw0yMjA2MTAxODQ2NDFaFw0zMjA2MDcxODQ2
NDFaMHcxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU29tZXdo
ZXJlMRowGAYDVQQKDBFDMlBBIFRlc3QgUm9vdCBDQTEZMBcGA1UECwwQRk9SIFRF
U1RJTkdfT05MWTEQMA4GA1UEAwwHUm9vdCBDQTAqMAUGAytlcAMhAGPUgK9q1H3D
eKMGqLGjTXJSpsrLpe0kpxkaFMe7KUAuo2MwYTAdBgNVHQ4EFgQUXuZWArP1jiRM
fgye6ZqRyGupTowwHwYDVR0jBBgwFoAUXuZWArP1jiRMfgye6ZqRyGupTowwDwYD
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwBQYDK2VwA0EA8E79g54u2fUy
dfVLPyqKmtjenOUMvVQD7waNbetLY7kvUJZCd5eaDghk30/Q1RaNjiP/2RfA/it8
zGxQnM2hCA==
-----END CERTIFICATE-----
"#;

    #[test]
    fn test_system_trust_store() {
        let mut ctp = CertificateTrustPolicy::new();
        ctp.add_trust_anchors(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/test_cert_root_bundle.pem"
        ))
        .unwrap();

        let ps256 = test_signer(SigningAlg::Ps256);
        let ps384 = test_signer(SigningAlg::Ps384);
        let ps512 = test_signer(SigningAlg::Ps512);
        let es256 = test_signer(SigningAlg::Es256);
        let es384 = test_signer(SigningAlg::Es384);
        let es512 = test_signer(SigningAlg::Es512);
        let ed25519 = test_signer(SigningAlg::Ed25519);

        let ps256_certs = ps256.cert_chain().unwrap();
        let ps384_certs = ps384.cert_chain().unwrap();
        let ps512_certs = ps512.cert_chain().unwrap();
        let es256_certs = es256.cert_chain().unwrap();
        let es384_certs = es384.cert_chain().unwrap();
        let es512_certs = es512.cert_chain().unwrap();
        let ed25519_certs = ed25519.cert_chain().unwrap();

        assert!(
            ctp.check_certificate_trust(&ps256_certs[1..], &ps256_certs[0], None)
                .unwrap()
                == TrustAnchorType::System
        );
        assert!(
            ctp.check_certificate_trust(&ps384_certs[1..], &ps384_certs[0], None)
                .unwrap()
                == TrustAnchorType::System
        );
        assert!(
            ctp.check_certificate_trust(&ps512_certs[1..], &ps512_certs[0], None)
                .unwrap()
                == TrustAnchorType::System
        );
        assert!(
            ctp.check_certificate_trust(&es256_certs[1..], &es256_certs[0], None)
                .unwrap()
                == TrustAnchorType::System
        );
        assert!(
            ctp.check_certificate_trust(&es384_certs[1..], &es384_certs[0], None)
                .unwrap()
                == TrustAnchorType::System
        );
        assert!(
            ctp.check_certificate_trust(&es512_certs[1..], &es512_certs[0], None)
                .unwrap()
                == TrustAnchorType::System
        );
        assert!(
            ctp.check_certificate_trust(&ed25519_certs[1..], &ed25519_certs[0], None)
                .unwrap()
                == TrustAnchorType::System
        );
    }

    #[test]
    fn test_user_trust_store() {
        let ctp = CertificateTrustPolicy::default();

        let ps256 = test_signer(SigningAlg::Ps256);
        let ps384 = test_signer(SigningAlg::Ps384);
        let ps512 = test_signer(SigningAlg::Ps512);
        let es256 = test_signer(SigningAlg::Es256);
        let es384 = test_signer(SigningAlg::Es384);
        let es512 = test_signer(SigningAlg::Es512);
        let ed25519 = test_signer(SigningAlg::Ed25519);

        let ps256_certs = ps256.cert_chain().unwrap();
        let ps384_certs = ps384.cert_chain().unwrap();
        let ps512_certs = ps512.cert_chain().unwrap();
        let es256_certs = es256.cert_chain().unwrap();
        let es384_certs = es384.cert_chain().unwrap();
        let es512_certs = es512.cert_chain().unwrap();
        let ed25519_certs = ed25519.cert_chain().unwrap();

        assert!(
            ctp.check_certificate_trust(&ps256_certs[1..], &ps256_certs[0], None)
                .unwrap()
                == TrustAnchorType::User
        );
        assert!(
            ctp.check_certificate_trust(&ps384_certs[1..], &ps384_certs[0], None)
                .unwrap()
                == TrustAnchorType::User
        );
        assert!(
            ctp.check_certificate_trust(&ps512_certs[1..], &ps512_certs[0], None)
                .unwrap()
                == TrustAnchorType::User
        );
        assert!(
            ctp.check_certificate_trust(&es256_certs[1..], &es256_certs[0], None)
                .unwrap()
                == TrustAnchorType::User
        );
        assert!(
            ctp.check_certificate_trust(&es384_certs[1..], &es384_certs[0], None)
                .unwrap()
                == TrustAnchorType::User
        );
        assert!(
            ctp.check_certificate_trust(&es512_certs[1..], &es512_certs[0], None)
                .unwrap()
                == TrustAnchorType::User
        );
        assert!(
            ctp.check_certificate_trust(&ed25519_certs[1..], &ed25519_certs[0], None)
                .unwrap()
                == TrustAnchorType::User
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn test_trust_store_async() {
        let ctp = CertificateTrustPolicy::default();

        let ps256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ));
        let ps384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps384.pub"
        ));
        let ps512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps512.pub"
        ));
        let es256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ));
        let es384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ));
        let es512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ));
        let ed25519_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ed25519.pub"
        ));

        ctp.check_certificate_trust_async(&ps256_certs[1..], &ps256_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&ps384_certs[1..], &ps384_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&ps512_certs[1..], &ps512_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&es256_certs[1..], &es256_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&es384_certs[1..], &es384_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&es512_certs[1..], &es512_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&ed25519_certs[1..], &ed25519_certs[0], None)
            .await
            .unwrap();
    }

    #[test]
    fn test_broken_trust_chain() {
        let ctp = CertificateTrustPolicy::default();

        let ps256 = test_signer(SigningAlg::Ps256);
        let ps384 = test_signer(SigningAlg::Ps384);
        let ps512 = test_signer(SigningAlg::Ps512);
        let es256 = test_signer(SigningAlg::Es256);
        let es384 = test_signer(SigningAlg::Es384);
        let es512 = test_signer(SigningAlg::Es512);
        let ed25519 = test_signer(SigningAlg::Ed25519);

        let ps256_certs = ps256.cert_chain().unwrap();
        let ps384_certs = ps384.cert_chain().unwrap();
        let ps512_certs = ps512.cert_chain().unwrap();
        let es256_certs = es256.cert_chain().unwrap();
        let es384_certs = es384.cert_chain().unwrap();
        let es512_certs = es512.cert_chain().unwrap();
        let ed25519_certs = ed25519.cert_chain().unwrap();

        // Break the trust chain by skipping the first intermediate CA.
        assert_eq!(
            ctp.check_certificate_trust(&ps256_certs[2..], &ps256_certs[0], None)
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust(&ps384_certs[2..], &ps384_certs[0], None)
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust(&ps384_certs[2..], &ps384_certs[0], None)
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust(&ps512_certs[2..], &ps512_certs[0], None)
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust(&es256_certs[2..], &es256_certs[0], None)
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust(&es384_certs[2..], &es384_certs[0], None)
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust(&es512_certs[2..], &es512_certs[0], None)
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust(&ed25519_certs[2..], &ed25519_certs[0], None)
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn test_broken_trust_chain_async() {
        let ctp = CertificateTrustPolicy::default();

        let ps256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ));
        let ps384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps384.pub"
        ));
        let ps512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps512.pub"
        ));
        let es256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ));
        let es384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ));
        let es512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ));
        let ed25519_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ed25519.pub"
        ));

        // Break the trust chain by skipping the first intermediate CA.
        assert_eq!(
            ctp.check_certificate_trust_async(&ps256_certs[2..], &ps256_certs[0], None)
                .await
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust_async(&ps384_certs[2..], &ps384_certs[0], None)
                .await
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust_async(&ps384_certs[2..], &ps384_certs[0], None)
                .await
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust_async(&ps512_certs[2..], &ps512_certs[0], None)
                .await
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust_async(&es256_certs[2..], &es256_certs[0], None)
                .await
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust_async(&es384_certs[2..], &es384_certs[0], None)
                .await
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust_async(&es512_certs[2..], &es512_certs[0], None)
                .await
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );

        assert_eq!(
            ctp.check_certificate_trust_async(&ed25519_certs[2..], &ed25519_certs[0], None)
                .await
                .unwrap_err(),
            CertificateTrustError::CertificateNotTrusted
        );
    }

    #[test]
    fn test_allowed_list() {
        let mut ctp = CertificateTrustPolicy::new();

        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ed25519.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps384.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps512.pub"
        ))
        .unwrap();

        let ps256 = test_signer(SigningAlg::Ps256);
        let ps384 = test_signer(SigningAlg::Ps384);
        let ps512 = test_signer(SigningAlg::Ps512);
        let es256 = test_signer(SigningAlg::Es256);
        let es384 = test_signer(SigningAlg::Es384);
        let es512 = test_signer(SigningAlg::Es512);
        let ed25519 = test_signer(SigningAlg::Ed25519);

        assert_eq!(ps256.alg(), SigningAlg::Ps256);
        assert_eq!(ps384.alg(), SigningAlg::Ps384);
        assert_eq!(ps512.alg(), SigningAlg::Ps512);
        assert_eq!(es256.alg(), SigningAlg::Es256);
        assert_eq!(es384.alg(), SigningAlg::Es384);
        assert_eq!(es512.alg(), SigningAlg::Es512);
        assert_eq!(ed25519.alg(), SigningAlg::Ed25519);

        let ps256_certs = ps256.cert_chain().unwrap();
        let ps384_certs = ps384.cert_chain().unwrap();
        let ps512_certs = ps512.cert_chain().unwrap();
        let es256_certs = es256.cert_chain().unwrap();
        let es384_certs = es384.cert_chain().unwrap();
        let es512_certs = es512.cert_chain().unwrap();
        let ed25519_certs = ed25519.cert_chain().unwrap();

        ctp.check_certificate_trust(&ps256_certs[1..], &ps256_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ps384_certs[1..], &ps384_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ps512_certs[1..], &ps512_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es256_certs[1..], &es256_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es384_certs[1..], &es384_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es512_certs[1..], &es512_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ed25519_certs[1..], &ed25519_certs[0], None)
            .unwrap();
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn test_allowed_list_async() {
        let mut ctp = CertificateTrustPolicy::new();

        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ed25519.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps384.pub"
        ))
        .unwrap();
        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps512.pub"
        ))
        .unwrap();

        let ps256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ));
        let ps384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps384.pub"
        ));
        let ps512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps512.pub"
        ));
        let es256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ));
        let es384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ));
        let es512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ));
        let ed25519_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ed25519.pub"
        ));

        ctp.check_certificate_trust_async(&ps256_certs[1..], &ps256_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&ps384_certs[1..], &ps384_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&ps512_certs[1..], &ps512_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&es256_certs[1..], &es256_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&es384_certs[1..], &es384_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&es512_certs[1..], &es512_certs[0], None)
            .await
            .unwrap();
        ctp.check_certificate_trust_async(&ed25519_certs[1..], &ed25519_certs[0], None)
            .await
            .unwrap();
    }

    #[test]
    fn test_allowed_list_hashes() {
        let mut ctp = CertificateTrustPolicy::new();

        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/allowed_list.hash"
        ))
        .unwrap();

        let ps256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ));
        let ps384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps384.pub"
        ));
        let ps512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps512.pub"
        ));
        let es256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ));
        let es384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ));
        let es512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ));
        let ed25519_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ed25519.pub"
        ));

        ctp.check_certificate_trust(&ps256_certs[1..], &ps256_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ps384_certs[1..], &ps384_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ps512_certs[1..], &ps512_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es256_certs[1..], &es256_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es384_certs[1..], &es384_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es512_certs[1..], &es512_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ed25519_certs[1..], &ed25519_certs[0], None)
            .unwrap();
    }

    #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    #[cfg_attr(target_os = "wasi", wstd::test)]
    async fn test_allowed_list_hashes_async() {
        let mut ctp = CertificateTrustPolicy::new();

        ctp.add_end_entity_credentials(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/allowed_list.hash"
        ))
        .unwrap();

        let ps256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ));
        let ps384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps384.pub"
        ));
        let ps512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps512.pub"
        ));
        let es256_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ));
        let es384_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ));
        let es512_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ));
        let ed25519_certs = cert_ders_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ed25519.pub"
        ));

        ctp.check_certificate_trust(&ps256_certs[1..], &ps256_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ps384_certs[1..], &ps384_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ps512_certs[1..], &ps512_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es256_certs[1..], &es256_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es384_certs[1..], &es384_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&es512_certs[1..], &es512_certs[0], None)
            .unwrap();
        ctp.check_certificate_trust(&ed25519_certs[1..], &ed25519_certs[0], None)
            .unwrap();
    }

    fn cert_ders_from_pem(cert_chain: &[u8]) -> Vec<Vec<u8>> {
        Pem::iter_from_buffer(cert_chain)
            .map(|r| r.unwrap().contents)
            .collect()
    }
}
