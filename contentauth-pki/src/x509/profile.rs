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

//! Certificate profile checks with explicit host policy and time.

use std::collections::HashSet;

use asn1_rs::{Any, FromDer};
use thiserror::Error;
use x509_parser::{
    certificate::{BasicExtension, X509Certificate},
    der_parser::{ber::parse_ber_sequence, oid},
    extensions::{ExtendedKeyUsage, ParsedExtension},
    num_bigint::BigInt,
    oid_registry::Oid,
    x509::X509Version,
};

use super::certificate::rsa_pss_algorithms;

/// Concrete constraints chosen by the host for a certificate's role.
///
/// No built-in EKUs, application roles or configuration defaults are selected
/// here. Hosts may preserve an explicitly selected legacy empty-list fallback.
pub struct ProfilePolicy<'a> {
    /// Effective accepted purposes, after host configuration composition.
    pub allowed_ekus: &'a HashSet<String>,

    /// Every listed purpose must be present on an end-entity certificate.
    pub mandatory_ekus: &'a HashSet<String>,

    /// Accept emailProtection when the effective allowed set is empty.
    pub allow_email_protection_when_empty: bool,

    /// Accept timeStamping and OCSPSigning in the shared profile matcher.
    /// A host must separately reject them for roles that forbid these purposes.
    pub allow_specialty_purposes: bool,

    /// Reject CA certificates and require every mandatory purpose.
    pub end_entity: bool,
}

impl ProfilePolicy<'_> {
    /// Check a certificate's profile using Unix seconds selected by the host.
    ///
    /// Diagnostic/error precedence is retained. Passing this check alone cannot
    /// establish cryptographic validity or trust.
    pub fn check_certificate<'a>(
        &self,
        certificate_der: &'a [u8],
        validation_time: i64,
    ) -> Result<ProfileValidCertificate<'a>, ProfileError> {
        let mut diagnostic = None;
        let mut report = |description| diagnostic = Some(description);

        let result = if self.end_entity {
            check_end_entity_certificate_profile(
                certificate_der,
                self,
                &mut report,
                validation_time,
            )
        } else {
            check_certificate_profile(certificate_der, self, &mut report, validation_time)
        };

        result
            .map(|()| ProfileValidCertificate {
                der: certificate_der,
            })
            .map_err(|kind| ProfileError { kind, diagnostic })
    }

    fn has_mandatory_ekus(&self) -> bool {
        !self.mandatory_ekus.is_empty()
    }

    fn verify_mandatory_ekus(&self, eku: &ExtendedKeyUsage<'_>) -> bool {
        self.mandatory_ekus.iter().all(|oid| match oid.as_str() {
            "1.3.6.1.5.5.7.3.4" => eku.email_protection,
            "1.3.6.1.5.5.7.3.8" => eku.time_stamping,
            "1.3.6.1.5.5.7.3.9" => eku.ocsp_signing,
            _ => eku.other.iter().any(|other| other.to_id_string() == *oid),
        })
    }

    fn allowed_eku(&self, eku: &ExtendedKeyUsage<'_>) -> Option<()> {
        let email = eku.email_protection
            && ((self.allow_email_protection_when_empty && self.allowed_ekus.is_empty())
                || self.allowed_ekus.contains("1.3.6.1.5.5.7.3.4"));

        let specialty = self.allow_specialty_purposes && (eku.time_stamping || eku.ocsp_signing);

        (email
            || specialty
            || eku
                .other
                .iter()
                .any(|oid| self.allowed_ekus.contains(&oid.to_id_string())))
        .then_some(())
    }
}

/// A certificate satisfying the supplied profile constraints at the supplied time.
/// This does not verify its signature, chain, anchor trust or revocation.
#[derive(Debug)]
pub struct ProfileValidCertificate<'a> {
    der: &'a [u8],
}

impl ProfileValidCertificate<'_> {
    /// Original certificate encoding; no authenticity or trust is implied.
    pub fn certificate_der(&self) -> &[u8] {
        self.der
    }
}

/// Profile rejection with the optional diagnostic emitted by the original check.
#[derive(Debug, Error)]
#[error("{kind}")]
pub struct ProfileError {
    /// Typed profile failure.
    pub kind: CertificateProfileError,

    /// Diagnostic for host reporting; never an application status code.
    pub diagnostic: Option<&'static str>,
}

/// Reject certificate purposes explicitly forbidden by a host-selected role.
///
/// This is only a purpose exclusion check, not a full profile check. Missing
/// EKUs are evaluated separately by the selected profile. No application role
/// is inferred and neither configuration nor trust can bypass this check.
pub fn check_disallowed_ekus(
    certificate_der: &[u8],
    disallowed: &[&str],
) -> Result<(), CertificateProfileError> {
    let (_, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|_| CertificateProfileError::InvalidCertificate)?;

    let eku = certificate
        .extended_key_usage()
        .map_err(|_| CertificateProfileError::InvalidCertificate)?;

    if let Some(eku) = eku {
        let present = |oid: &&str| match *oid {
            "1.3.6.1.5.5.7.3.1" => eku.value.server_auth,
            "1.3.6.1.5.5.7.3.2" => eku.value.client_auth,
            "1.3.6.1.5.5.7.3.3" => eku.value.code_signing,
            "1.3.6.1.5.5.7.3.4" => eku.value.email_protection,
            "1.3.6.1.5.5.7.3.8" => eku.value.time_stamping,
            "1.3.6.1.5.5.7.3.9" => eku.value.ocsp_signing,
            "2.5.29.37.0" => eku.value.any,
            _ => eku
                .value
                .other
                .iter()
                .any(|other| other.to_id_string() == *oid),
        };

        if disallowed.iter().any(present) {
            return Err(CertificateProfileError::InvalidEku);
        }
    }

    Ok(())
}

fn check_end_entity_certificate_profile(
    certificate_der: &[u8],
    ctp: &ProfilePolicy<'_>,
    report: &mut impl FnMut(&'static str),
    validation_time: i64,
) -> Result<(), CertificateProfileError> {
    check_certificate_profile(certificate_der, ctp, report, validation_time)?;

    let (_rem, signcert) = X509Certificate::from_der(certificate_der).map_err(|_err| {
        report("certificate could not be parsed");

        CertificateProfileError::InvalidCertificate
    })?;

    // Role-specific policies require every mandatory EKU, not just an allowed one.
    if ctp.has_mandatory_ekus() {
        if let Ok(Some(BasicExtension { value: eku, .. })) = signcert.extended_key_usage() {
            if !ctp.verify_mandatory_ekus(eku) {
                report("certificate missing mandatory EKU");

                return Err(CertificateProfileError::InvalidEku);
            }
        } else {
            report("certificate missing mandatory EKU");

            return Err(CertificateProfileError::InvalidEku);
        }
    }

    let tbscert = &signcert.tbs_certificate;

    // If we are expecting an end-entity cert, make sure that is so
    if tbscert.is_ca() {
        report("expected end-entity certificate");

        return Err(CertificateProfileError::InvalidCertificate);
    }

    Ok(())
}

fn check_certificate_profile(
    certificate_der: &[u8],
    ctp: &ProfilePolicy<'_>,
    report: &mut impl FnMut(&'static str),
    validation_time: i64,
) -> Result<(), CertificateProfileError> {
    let (_rem, signcert) = X509Certificate::from_der(certificate_der).map_err(|_err| {
        report("certificate could not be parsed");

        CertificateProfileError::InvalidCertificate
    })?;

    // Version shall be v3 as per RFC 5280, section 4.1.2.1.
    if signcert.version() != X509Version::V3 {
        report("certificate version incorrect");

        return Err(CertificateProfileError::InvalidCertificateVersion);
    }

    if !signcert.validity().is_valid_at(
        x509_parser::time::ASN1Time::from_timestamp(validation_time)
            .map_err(|_| CertificateProfileError::InvalidCertificate)?,
    ) {
        report("certificate expired");

        return Err(CertificateProfileError::CertificateNotValidAtTime);
    }

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.3
    // The outer signatureAlgorithm MUST match the signed tbsCertificate.signature field.
    if signcert.tbs_certificate.signature != signcert.signature_algorithm {
        report("certificate signature algorithm does not match tbsCertificate signature algorithm");

        return Err(CertificateProfileError::InvalidCertificate);
    }

    let cert_alg = &signcert.signature_algorithm.algorithm;

    // Certificate must be signed with one of the following algorithms.
    if !(*cert_alg == SHA256_WITH_RSAENCRYPTION_OID
        || *cert_alg == SHA384_WITH_RSAENCRYPTION_OID
        || *cert_alg == SHA512_WITH_RSAENCRYPTION_OID
        || *cert_alg == ECDSA_WITH_SHA256_OID
        || *cert_alg == ECDSA_WITH_SHA384_OID
        || *cert_alg == ECDSA_WITH_SHA512_OID
        || *cert_alg == RSASSA_PSS_OID
        || *cert_alg == ED25519_OID)
    {
        report("certificate algorithm not supported");

        return Err(CertificateProfileError::UnsupportedAlgorithm);
    }

    // https://datatracker.ietf.org/doc/html/rfc8410#section-3
    // Ed25519 spec: "For all of the OIDs, the parameters MUST be absent."
    if *cert_alg == ED25519_OID && signcert.signature_algorithm.parameters.is_some() {
        report("certificate Ed25519 signature algorithm parameters must be absent");

        return Err(CertificateProfileError::InvalidCertificate);
    }

    // Verify RSA_PSS parameters.
    if *cert_alg == RSASSA_PSS_OID {
        if let Some(parameters) = &signcert.signature_algorithm.parameters {
            let (ha_alg, mgf_ai) = rsa_pss_algorithms(parameters)
                .ok_or(CertificateProfileError::InvalidCertificate)?;

            let mgf_ai_parameters = mgf_ai
                .parameters
                .ok_or(CertificateProfileError::InvalidCertificate)?;

            let mgf_ai_parameters = mgf_ai_parameters
                .as_sequence()
                .map_err(|_| CertificateProfileError::InvalidCertificate)?;

            let (_i, mgf_ai_params_algorithm) =
                <Any as asn1_rs::FromDer>::from_der(&mgf_ai_parameters.content)
                    .map_err(|_| CertificateProfileError::InvalidCertificate)?;

            let mgf_ai_params_algorithm = mgf_ai_params_algorithm
                .as_oid()
                .map_err(|_| CertificateProfileError::InvalidCertificate)?;

            if ha_alg.algorithm.to_id_string() != mgf_ai_params_algorithm.to_id_string() {
                report("certificate algorithm error");

                return Err(CertificateProfileError::InvalidCertificate);
            }

            // check for one of the mandatory types
            if !(ha_alg.algorithm == SHA256_OID
                || ha_alg.algorithm == SHA384_OID
                || ha_alg.algorithm == SHA512_OID)
            {
                report("certificate hash algorithm not supported");

                return Err(CertificateProfileError::InvalidCertificate);
            }
        } else {
            report("certificate missing algorithm parameters");

            return Err(CertificateProfileError::InvalidCertificate);
        }
    }

    // CHeck curves for SPKI EC algorithms.
    let pk = signcert.public_key();
    let skpi_alg = &pk.algorithm;

    if skpi_alg.algorithm == EC_PUBLICKEY_OID {
        if let Some(parameters) = &skpi_alg.parameters {
            let named_curve_oid = parameters
                .as_oid()
                .map_err(|_err| CertificateProfileError::InvalidCertificate)?;

            // Must be one of these named curves.
            if !(named_curve_oid == PRIME256V1_OID
                || named_curve_oid == SECP384R1_OID
                || named_curve_oid == SECP521R1_OID)
            {
                report("certificate unsupported EC curve");

                return Err(CertificateProfileError::InvalidCertificate);
            }
        } else {
            return Err(CertificateProfileError::InvalidCertificate);
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc8410#section-3
    // Ed25519 spec: "For all of the OIDs, the parameters MUST be absent."
    if skpi_alg.algorithm == ED25519_OID && skpi_alg.parameters.is_some() {
        report("certificate Ed25519 public key parameters must be absent");

        return Err(CertificateProfileError::InvalidCertificate);
    }

    // Check modulus minimum length for RSA & PSS algorithms.
    if skpi_alg.algorithm == RSA_OID || skpi_alg.algorithm == RSASSA_PSS_OID {
        let (_, skpi_ber) = parse_ber_sequence(&pk.subject_public_key.data)
            .map_err(|_err| CertificateProfileError::InvalidCertificate)?;

        let seq = skpi_ber
            .as_sequence()
            .map_err(|_err| CertificateProfileError::InvalidCertificate)?;

        if seq.len() < 2 {
            return Err(CertificateProfileError::InvalidCertificate);
        }

        let modulus = seq[0]
            .as_bigint()
            .map_err(|_| CertificateProfileError::InvalidCertificate)?;

        let exponent = seq[1]
            .as_bigint()
            .map_err(|_| CertificateProfileError::InvalidCertificate)?;

        if modulus.bits() < 2048 {
            report("certificate key length too short");

            return Err(CertificateProfileError::InvalidCertificate);
        }

        if !is_valid_rsa_public_exponent(&exponent) {
            report("certificate RSA public exponent is invalid");

            return Err(CertificateProfileError::InvalidCertificate);
        }
    }

    let tbscert = &signcert.tbs_certificate;

    // Disallow self-signed certificates.
    if tbscert.is_ca() && tbscert.issuer() == tbscert.subject() {
        report("certificate issuer and subject cannot be the same (self-signed disallowed)");

        return Err(CertificateProfileError::SelfSignedCertificate);
    }

    // Disallow unique IDs.
    if signcert.issuer_uid.is_some() || signcert.subject_uid.is_some() {
        report("certificate issuer/subject unique ids are not allowed");

        return Err(CertificateProfileError::InvalidCertificate);
    }

    let mut aki_good = false;
    let mut ski_good = false;
    let mut key_usage_good = false;
    let mut handled_all_critical = true;

    let extended_key_usage_good = match tbscert
        .extended_key_usage()
        .map_err(|_| CertificateProfileError::InvalidCertificate)?
    {
        Some(BasicExtension { value: eku, .. }) => {
            if eku.any {
                report("certificate 'any' EKU not allowed");

                return Err(CertificateProfileError::InvalidCertificate);
            }

            if ctp.allowed_eku(eku).is_none() {
                report("certificate missing required EKU");

                return Err(CertificateProfileError::InvalidCertificate);
            }

            // one or the other || either of these two, and no others field
            if (eku.ocsp_signing && eku.time_stamping)
                || ((eku.ocsp_signing ^ eku.time_stamping)
                    && (eku.client_auth
                        | eku.code_signing
                        | eku.email_protection
                        | eku.server_auth
                        | !eku.other.is_empty()))
            {
                report("certificate invalid set of EKUs");

                return Err(CertificateProfileError::InvalidCertificate);
            }

            true
        }

        None => tbscert.is_ca(), // if is not ca it must be present
    };

    // Time-stamping and OCSP signing certificates are valid for exactly one of
    // those purposes (checked above).
    let signs_time_stamps_or_ocsp = matches!(
        tbscert.extended_key_usage(),
        Ok(Some(BasicExtension { value: eku, .. })) if eku.time_stamping || eku.ocsp_signing
    );

    // Populate needed extension info.
    for e in signcert.extensions() {
        match e.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(_aki) => {
                aki_good = true;
            }

            ParsedExtension::SubjectKeyIdentifier(_spki) => {
                ski_good = true;
            }

            ParsedExtension::KeyUsage(ku) => {
                // "The keyCertSign bit shall only be asserted if the cA boolean is
                // asserted in the Basic Constraints extension."
                if ku.key_cert_sign() && !tbscert.is_ca() {
                    report("certificate asserts keyCertSign key usage but is not a CA");

                    return Err(CertificateProfileError::InvalidCertificate);
                }

                // "Certificates used to sign C2PA manifests shall assert the
                // digitalSignature bit." Time-stamping and OCSP signing certificates
                // may assert nonRepudiation instead (RFC 3161, section 2.3).
                if !tbscert.is_ca() && !signs_time_stamps_or_ocsp && !ku.digital_signature() {
                    report("certificate missing digitalSignature key usage");

                    return Err(CertificateProfileError::InvalidCertificate);
                }

                if ku.digital_signature() || ku.key_cert_sign() || ku.non_repudiation() {
                    key_usage_good = true;
                }

                // TO DO: warn if not marked critical.
                // if !e.critical { // warn here somehow}
            }

            ParsedExtension::CertificatePolicies(_) => (),
            ParsedExtension::PolicyMappings(_) => (),
            ParsedExtension::SubjectAlternativeName(_) => (),
            ParsedExtension::BasicConstraints(_) => (),
            ParsedExtension::NameConstraints(_) => (),
            ParsedExtension::PolicyConstraints(_) => (),
            ParsedExtension::ExtendedKeyUsage(_) => (),
            ParsedExtension::CRLDistributionPoints(_) => (),
            ParsedExtension::InhibitAnyPolicy(_) => (),
            ParsedExtension::AuthorityInfoAccess(_) => (),
            ParsedExtension::NSCertType(_) => (),
            ParsedExtension::CRLNumber(_) => (),
            ParsedExtension::ReasonCode(_) => (),
            ParsedExtension::InvalidityDate(_) => (),

            ParsedExtension::Unparsed => {
                if e.critical {
                    // Unhandled critical extension.
                    handled_all_critical = false;
                }
            }

            _ => {
                if e.critical {
                    //println!("Oid: {}", e.oid.to_id_string());
                    // Unhandled critical extension.
                    handled_all_critical = false;
                }
            }
        }
    }

    // If cert is a CA must have valid SubjectKeyIdentifier.
    ski_good = if tbscert.is_ca() { ski_good } else { true };

    // Check all flags.
    if aki_good && ski_good && key_usage_good && extended_key_usage_good && handled_all_critical {
        Ok(())
    } else {
        report("certificate params incorrect");

        Err(CertificateProfileError::InvalidCertificate)
    }
}

/// Describes errors that can be identified when checking a certificate's
/// profile.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CertificateProfileError {
    /// The certificate (or certificate chain) that was presented is invalid.
    ///
    /// This often occurs when the data presented isn't a valid X.509
    /// certificate in DER format.
    #[error("the certificate is invalid")]
    InvalidCertificate,

    /// The certificate must be a version 3 certificate per [RFC 5280, section
    /// 4.1.2.1].
    ///
    /// [RFC 5280, section 4.1.2.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1
    #[error("the certificate must be a `v3` certificate")]
    InvalidCertificateVersion,

    /// The certificate was used outside of its period of validity.
    #[error("the certificate was not valid at time of signing")]
    CertificateNotValidAtTime,

    /// The certificate was signed with an unsupported algorithm.
    #[error("the certificate was signed with an unsupported algorithm")]
    UnsupportedAlgorithm,

    /// The certificate contains an invalid extended key usage (EKU) value.
    #[error("the certificate contains an invalid extended key usage (EKU) value")]
    InvalidEku,

    /// The certificate was signed by the same entity as the certificate itself.
    #[error("the certificate was self-signed")]
    SelfSignedCertificate,

    /// An unexpected internal error occurred while selecting profile inputs.
    #[error("internal error ({0})")]
    InternalError(String),
}

const RSA_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .1);
const EC_PUBLICKEY_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
const RSASSA_PSS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10);

const ECDSA_WITH_SHA256_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .2);
const ECDSA_WITH_SHA384_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .3);
const ECDSA_WITH_SHA512_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .4);
const SHA256_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .11);
const SHA384_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .12);
const SHA512_WITH_RSAENCRYPTION_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .13);
const ED25519_OID: Oid<'static> = oid!(1.3.101 .112);
const SHA256_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .1);
const SHA384_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .2);
const SHA512_OID: Oid<'static> = oid!(2.16.840 .1 .101 .3 .4 .2 .3);
const SECP521R1_OID: Oid<'static> = oid!(1.3.132 .0 .35);
const SECP384R1_OID: Oid<'static> = oid!(1.3.132 .0 .34);
const PRIME256V1_OID: Oid<'static> = oid!(1.2.840 .10045 .3 .1 .7);

fn is_valid_rsa_public_exponent(exponent: &BigInt) -> bool {
    exponent >= &BigInt::from(3u32)
        && exponent
            .magnitude()
            .to_u32_digits()
            .first()
            .is_some_and(|least_significant| least_significant % 2 == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_public_exponent_profile() {
        assert!(!is_valid_rsa_public_exponent(&BigInt::from(1u32)));
        assert!(!is_valid_rsa_public_exponent(&BigInt::from(2u32)));
        assert!(!is_valid_rsa_public_exponent(&BigInt::from(4u32)));
        assert!(!is_valid_rsa_public_exponent(&BigInt::from(-3)));
        assert!(is_valid_rsa_public_exponent(&BigInt::from(3u32)));
        assert!(is_valid_rsa_public_exponent(&BigInt::from(65537u32)));
    }
}
