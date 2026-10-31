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

use asn1_rs::{Any, Class, FromDer, Header, Tag};
use chrono::{DateTime, Utc};
use thiserror::Error;
use web_time::SystemTime;
use x509_parser::{
    certificate::{BasicExtension, X509Certificate},
    der_parser::{ber::parse_ber_sequence, oid},
    extensions::ParsedExtension,
    num_bigint::BigInt,
    oid_registry::Oid,
    x509::{AlgorithmIdentifier, X509Version},
};

use crate::{
    crypto::{asn1::rfc3161::TstInfo, cose::CertificateTrustPolicy},
    log_item,
    status_tracker::StatusTracker,
    validation_results::validation_codes::*,
};

/// Verify that an end-entity X.509 certificate meets the requirements stated in
/// [§14.5. X.509 Certificates].
///
/// [§14.5. X.509 Certificates]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#x509_certificates
pub fn check_end_entity_certificate_profile(
    certificate_der: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    tst_info_opt: Option<&TstInfo>,
) -> Result<(), CertificateProfileError> {
    check_certificate_profile(certificate_der, ctp, validation_log, tst_info_opt)?;

    let (_rem, signcert) = X509Certificate::from_der(certificate_der).map_err(|_err| {
        log_item!(
            "",
            "certificate could not be parsed",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

        CertificateProfileError::InvalidCertificate
    })?;

    // makes sure the certificate has any mandatory EKU values
    if ctp.has_mandatory_ekus() {
        if let Ok(Some(BasicExtension { value: eku, .. })) = signcert.extended_key_usage() {
            if !ctp.verify_mandatory_ekus(eku) {
                log_item!(
                    "",
                    "certificate missing mandatory EKU",
                    "check_certificate_profile"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidEku);
            }
        } else {
            log_item!(
                "",
                "certificate missing mandatory EKU",
                "check_certificate_profile"
            )
            .validation_status(SIGNING_CREDENTIAL_INVALID)
            .failure_no_throw(validation_log, CertificateProfileError::InvalidEku);
        }
    }

    let tbscert = &signcert.tbs_certificate;

    // If we are expecting an end-entity cert, make sure that is so
    if tbscert.is_ca() {
        log_item!(
            "",
            "expected end-entity certificate",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

        return Err(CertificateProfileError::InvalidCertificate);
    }

    Ok(())
}

/// Verify that an X.509 certificate meets the requirements stated in [§14.5.1,
/// Certificate Profiles].
///
/// [§14.5.1, Certificate Profiles]: https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_certificate_profiles
pub fn check_certificate_profile(
    certificate_der: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut StatusTracker,
    _tst_info_opt: Option<&TstInfo>,
) -> Result<(), CertificateProfileError> {
    let (_rem, signcert) = X509Certificate::from_der(certificate_der).map_err(|_err| {
        log_item!(
            "",
            "certificate could not be parsed",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

        CertificateProfileError::InvalidCertificate
    })?;

    // Version shall be v3 as per RFC 5280, section 4.1.2.1.
    if signcert.version() != X509Version::V3 {
        log_item!(
            "",
            "certificate version incorrect",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(
            validation_log,
            CertificateProfileError::InvalidCertificateVersion,
        );

        return Err(CertificateProfileError::InvalidCertificateVersion);
    }

    // Was the certificate valid at time of signing?
    if let Some(tst_info) = _tst_info_opt {
        // A valid time stamp was associated with this signature: Ensure that the
        // timestamp was valid at that time.
        let signing_time: DateTime<Utc> = tst_info.gen_time.clone().into();
        if !signcert.validity().is_valid_at(
            x509_parser::time::ASN1Time::from_timestamp(signing_time.timestamp())
                .map_err(|_| CertificateProfileError::InvalidCertificate)?,
        ) {
            log_item!("", "certificate expired", "check_certificate_profile")
                .validation_status(SIGNING_CREDENTIAL_EXPIRED)
                .failure_no_throw(
                    validation_log,
                    CertificateProfileError::CertificateNotValidAtTime,
                );

            return Err(CertificateProfileError::CertificateNotValidAtTime);
        }
    } else {
        // No valid time stamp was associated with this signature: Ensure that the
        // timestamp is valid now.
        let Ok(now) = SystemTime::now().duration_since(web_time::UNIX_EPOCH) else {
            return Err(CertificateProfileError::InternalError(
                "system time invalid".to_string(),
            ));
        };

        if !signcert.validity().is_valid_at(
            x509_parser::time::ASN1Time::from_timestamp(now.as_secs() as i64)
                .map_err(|_| CertificateProfileError::InvalidCertificate)?,
        ) {
            log_item!("", "certificate expired", "check_certificate_profile")
                .validation_status(SIGNING_CREDENTIAL_EXPIRED)
                .failure_no_throw(
                    validation_log,
                    CertificateProfileError::CertificateNotValidAtTime,
                );

            return Err(CertificateProfileError::CertificateNotValidAtTime);
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.3
    // The outer signatureAlgorithm MUST match the signed tbsCertificate.signature field.
    if signcert.tbs_certificate.signature != signcert.signature_algorithm {
        log_item!(
            "",
            "certificate signature algorithm does not match tbsCertificate signature algorithm",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

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
        log_item!(
            "",
            "certificate algorithm not supported",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(
            validation_log,
            CertificateProfileError::UnsupportedAlgorithm,
        );

        return Err(CertificateProfileError::UnsupportedAlgorithm);
    }

    // https://datatracker.ietf.org/doc/html/rfc8410#section-3
    // Ed25519 spec: "For all of the OIDs, the parameters MUST be absent."
    if *cert_alg == ED25519_OID && signcert.signature_algorithm.parameters.is_some() {
        log_item!(
            "",
            "certificate Ed25519 signature algorithm parameters must be absent",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

        return Err(CertificateProfileError::InvalidCertificate);
    }

    // Verify RSA_PSS parameters.
    if *cert_alg == RSASSA_PSS_OID {
        if let Some(parameters) = &signcert.signature_algorithm.parameters {
            let seq = parameters
                .as_sequence()
                .map_err(|_err| CertificateProfileError::InvalidCertificate)?;

            let (_i, (ha_alg, mgf_ai)) = seq
                .parse(|i| {
                    let (i, h) = <Header as asn1_rs::FromDer>::from_der(i)?;
                    if h.class() != Class::ContextSpecific || h.tag() != Tag(0) {
                        return Err(nom::Err::Error(asn1_rs::Error::BerValueError));
                    }

                    let (i, ha_alg) = AlgorithmIdentifier::from_der(i)
                        .map_err(|_| nom::Err::Error(asn1_rs::Error::BerValueError))?;

                    let (i, h) = <Header as asn1_rs::FromDer>::from_der(i)?;
                    if h.class() != Class::ContextSpecific || h.tag() != Tag(1) {
                        return Err(nom::Err::Error(asn1_rs::Error::BerValueError));
                    }

                    let (i, mgf_ai) = AlgorithmIdentifier::from_der(i)
                        .map_err(|_| nom::Err::Error(asn1_rs::Error::BerValueError))?;

                    // Ignore anything that follows these two parameters.

                    Ok((i, (ha_alg, mgf_ai)))
                })
                .map_err(|_| CertificateProfileError::InvalidCertificate)?;

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
                log_item!(
                    "",
                    "certificate algorithm error",
                    "check_certificate_profile"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                return Err(CertificateProfileError::InvalidCertificate);
            }

            // check for one of the mandatory types
            if !(ha_alg.algorithm == SHA256_OID
                || ha_alg.algorithm == SHA384_OID
                || ha_alg.algorithm == SHA512_OID)
            {
                log_item!(
                    "",
                    "certificate hash algorithm not supported",
                    "check_certificate_profile"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                return Err(CertificateProfileError::InvalidCertificate);
            }
        } else {
            log_item!(
                "",
                "certificate missing algorithm parameters",
                "check_certificate_profile"
            )
            .validation_status(SIGNING_CREDENTIAL_INVALID)
            .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

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
                log_item!(
                    "",
                    "certificate unsupported EC curve",
                    "check_certificate_profile"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                return Err(CertificateProfileError::InvalidCertificate);
            }
        } else {
            return Err(CertificateProfileError::InvalidCertificate);
        }
    }

    // https://datatracker.ietf.org/doc/html/rfc8410#section-3
    // Ed25519 spec: "For all of the OIDs, the parameters MUST be absent."
    if skpi_alg.algorithm == ED25519_OID && skpi_alg.parameters.is_some() {
        log_item!(
            "",
            "certificate Ed25519 public key parameters must be absent",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

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
            log_item!(
                "",
                "certificate key length too short",
                "check_certificate_profile"
            )
            .validation_status(SIGNING_CREDENTIAL_INVALID)
            .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

            return Err(CertificateProfileError::InvalidCertificate);
        }

        if !is_valid_rsa_public_exponent(&exponent) {
            log_item!(
                "",
                "certificate RSA public exponent is invalid",
                "check_certificate_profile"
            )
            .validation_status(SIGNING_CREDENTIAL_INVALID)
            .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

            return Err(CertificateProfileError::InvalidCertificate);
        }
    }

    let tbscert = &signcert.tbs_certificate;

    // Disallow self-signed certificates.
    if tbscert.is_ca() && tbscert.issuer() == tbscert.subject() {
        log_item!(
            "",
            "certificate issuer and subject cannot be the same (self-signed disallowed)",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(
            validation_log,
            CertificateProfileError::SelfSignedCertificate,
        );

        return Err(CertificateProfileError::SelfSignedCertificate);
    }

    // Disallow unique IDs.
    if signcert.issuer_uid.is_some() || signcert.subject_uid.is_some() {
        log_item!(
            "",
            "certificate issuer/subject unique ids are not allowed",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

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
                log_item!(
                    "",
                    "certificate 'any' EKU not allowed",
                    "check_certificate_profile"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                return Err(CertificateProfileError::InvalidCertificate);
            }

            if ctp.has_allowed_eku(eku).is_none() {
                log_item!(
                    "",
                    "certificate missing required EKU",
                    "check_certificate_profile"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

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
                log_item!(
                    "",
                    "certificate invalid set of EKUs",
                    "check_certificate_profile"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

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
                    log_item!(
                        "",
                        "certificate asserts keyCertSign key usage but is not a CA",
                        "check_certificate_profile"
                    )
                    .validation_status(SIGNING_CREDENTIAL_INVALID)
                    .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                    return Err(CertificateProfileError::InvalidCertificate);
                }

                // "Certificates used to sign C2PA manifests shall assert the
                // digitalSignature bit." Time-stamping and OCSP signing certificates
                // may assert nonRepudiation instead (RFC 3161, section 2.3).
                if !tbscert.is_ca() && !signs_time_stamps_or_ocsp && !ku.digital_signature() {
                    log_item!(
                        "",
                        "certificate missing digitalSignature key usage",
                        "check_certificate_profile"
                    )
                    .validation_status(SIGNING_CREDENTIAL_INVALID)
                    .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

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
        log_item!(
            "",
            "certificate params incorrect",
            "check_certificate_profile"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

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

    /// An unexpected internal error occured while requesting the time stamp
    /// response.
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
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use rasn::{types::Any, Decoder, Encoder};
    use rasn_pkix::Certificate;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::wasm_bindgen_test;
    use x509_parser::{num_bigint::BigInt, pem::Pem, prelude::FromDer};

    use super::is_valid_rsa_public_exponent;
    use crate::{
        crypto::cose::{check_end_entity_certificate_profile, CertificateTrustPolicy},
        status_tracker::StatusTracker,
        utils::ephemeral_cert::generate_ephemeral_chain,
        validation_results::validation_codes::{
            SIGNING_CREDENTIAL_EXPIRED, SIGNING_CREDENTIAL_INVALID,
        },
    };

    #[test]
    fn rsa_public_exponent_profile() {
        assert!(!is_valid_rsa_public_exponent(&BigInt::from(1u32)));
        assert!(!is_valid_rsa_public_exponent(&BigInt::from(2u32)));
        assert!(!is_valid_rsa_public_exponent(&BigInt::from(4u32)));
        assert!(!is_valid_rsa_public_exponent(&BigInt::from(-3)));
        assert!(is_valid_rsa_public_exponent(&BigInt::from(3u32)));
        assert!(is_valid_rsa_public_exponent(&BigInt::from(65537u32)));
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn expired_cert() {
        let ctp = CertificateTrustPolicy::default();
        let mut validation_log = StatusTracker::default();

        let cert_der = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/cose/rsa-pss256_key-expired.pub"
        ));

        assert!(
            check_end_entity_certificate_profile(&cert_der, &ctp, &mut validation_log, None)
                .is_err()
        );

        assert!(!validation_log.logged_items().is_empty());

        assert_eq!(
            validation_log.logged_items()[0].validation_status,
            Some(SIGNING_CREDENTIAL_EXPIRED.into())
        );
    }

    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn cert_algorithms() {
        let ctp = CertificateTrustPolicy::default();

        let mut validation_log = StatusTracker::default();

        let es256_cert = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es256.pub"
        ));
        let es384_cert = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es384.pub"
        ));
        let es512_cert = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/es512.pub"
        ));
        let ps256_cert = x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/crypto/raw_signature/ps256.pub"
        ));

        check_end_entity_certificate_profile(&es256_cert, &ctp, &mut validation_log, None).unwrap();
        check_end_entity_certificate_profile(&es384_cert, &ctp, &mut validation_log, None).unwrap();
        check_end_entity_certificate_profile(&es512_cert, &ctp, &mut validation_log, None).unwrap();
        check_end_entity_certificate_profile(&ps256_cert, &ctp, &mut validation_log, None).unwrap();
    }

    // https://datatracker.ietf.org/doc/html/rfc8410#section-3
    // Ed25519 spec: "For all of the OIDs, the parameters MUST be absent."
    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn ed25519_algorithm_parameters_must_be_absent() {
        let der_null = Any::new(vec![0x05, 0x00]);
        let ctp = CertificateTrustPolicy::default();

        let chain = generate_ephemeral_chain("ed25519-profile.local").unwrap();

        let mut validation_log = StatusTracker::default();
        check_end_entity_certificate_profile(&chain.ee_der, &ctp, &mut validation_log, None)
            .unwrap();

        let assert_rejected = |cert: &Certificate, expected_description: &str| {
            let der = rasn::der::encode(cert).unwrap();
            let mut validation_log = StatusTracker::default();
            assert!(
                check_end_entity_certificate_profile(&der, &ctp, &mut validation_log, None)
                    .is_err()
            );
            let item = &validation_log.logged_items()[0];
            assert_eq!(
                item.validation_status,
                Some(SIGNING_CREDENTIAL_INVALID.into())
            );
            assert_eq!(item.description, expected_description);
        };

        // Parameters in the subject public key info algorithm.
        let mut cert: Certificate = rasn::der::decode(&chain.ee_der).unwrap();
        cert.tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(der_null.clone());
        assert_rejected(
            &cert,
            "certificate Ed25519 public key parameters must be absent",
        );

        // Parameters in both the outer and the signed (tbsCertificate) signature algorithm.
        let mut cert: Certificate = rasn::der::decode(&chain.ee_der).unwrap();
        cert.signature_algorithm.parameters = Some(der_null.clone());
        cert.tbs_certificate.signature.parameters = Some(der_null.clone());
        assert_rejected(
            &cert,
            "certificate Ed25519 signature algorithm parameters must be absent",
        );
    }

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.3
    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn signature_algorithm_must_match_tbs_signature() {
        let der_null = Any::new(vec![0x05, 0x00]);
        let ctp = CertificateTrustPolicy::default();

        let chain = generate_ephemeral_chain("ed25519-profile.local").unwrap();

        let expected =
            "certificate signature algorithm does not match tbsCertificate signature algorithm";

        // Parameters only in the outer signature algorithm.
        let mut cert: Certificate = rasn::der::decode(&chain.ee_der).unwrap();
        cert.signature_algorithm.parameters = Some(der_null.clone());

        // Parameters only in the signed (tbsCertificate) signature algorithm.
        let mut cert_inner: Certificate = rasn::der::decode(&chain.ee_der).unwrap();
        cert_inner.tbs_certificate.signature.parameters = Some(der_null);

        for cert in [cert, cert_inner] {
            let der = rasn::der::encode(&cert).unwrap();
            let mut validation_log = StatusTracker::default();
            assert!(
                check_end_entity_certificate_profile(&der, &ctp, &mut validation_log, None)
                    .is_err()
            );
            let item = &validation_log.logged_items()[0];
            assert_eq!(
                item.validation_status,
                Some(SIGNING_CREDENTIAL_INVALID.into())
            );
            assert_eq!(item.description, expected);
        }
    }

    // C2PA Trust Model, Certificate Profiles: "Certificates used to sign C2PA
    // manifests shall assert the digitalSignature bit. The keyCertSign bit shall
    // only be asserted if the cA boolean is asserted."
    #[test]
    #[cfg_attr(
        all(target_arch = "wasm32", not(target_os = "wasi")),
        wasm_bindgen_test
    )]
    fn end_entity_key_usage() {
        let ctp = CertificateTrustPolicy::default();

        for (cert_pem, expected_description) in [
            (
                include_bytes!("../../../tests/fixtures/crypto/cose/ku_keycertsign_not_ca.pub")
                    .as_slice(),
                "certificate asserts keyCertSign key usage but is not a CA",
            ),
            (
                include_bytes!("../../../tests/fixtures/crypto/cose/ku_nonrepudiation_only.pub")
                    .as_slice(),
                "certificate missing digitalSignature key usage",
            ),
        ] {
            let mut validation_log = StatusTracker::default();
            assert!(check_end_entity_certificate_profile(
                &x509_der_from_pem(cert_pem),
                &ctp,
                &mut validation_log,
                None
            )
            .is_err());

            let item = &validation_log.logged_items()[0];
            assert_eq!(
                item.validation_status,
                Some(SIGNING_CREDENTIAL_INVALID.into())
            );
            assert_eq!(item.description, expected_description);
        }

        // A time-stamping certificate may assert nonRepudiation without
        // digitalSignature (RFC 3161, section 2.3).
        let mut validation_log = StatusTracker::default();
        check_end_entity_certificate_profile(
            &x509_der_from_pem(include_bytes!(
                "../../../tests/fixtures/crypto/cose/ku_nonrepudiation_tsa.pub"
            )),
            &ctp,
            &mut validation_log,
            None,
        )
        .unwrap();
    }

    fn x509_der_from_pem(cert_pem: &[u8]) -> Vec<u8> {
        let mut pems = Pem::iter_from_buffer(cert_pem);
        let pem = pems.next().unwrap().unwrap();
        pem.contents
    }

    fn profile_cert() -> Certificate {
        rasn::der::decode(&x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/certs/ed25519.pub"
        )))
        .unwrap()
    }

    fn oid(value: &[u32]) -> rasn::types::ObjectIdentifier {
        rasn::types::ObjectIdentifier::new(value.to_vec()).unwrap()
    }

    fn extension(cert: &mut Certificate, id: &[u32], value: Vec<u8>) {
        let extensions = cert.tbs_certificate.extensions.as_mut().unwrap();
        let existing = extensions
            .iter_mut()
            .find(|e| e.extn_id == oid(id))
            .unwrap();
        existing.extn_value = value.into();
    }

    fn assert_profile_error(cert: &Certificate, expected: super::CertificateProfileError) {
        // These mutations test profile validation, not certificate signature verification.
        let der = rasn::der::encode(cert).unwrap();
        let mut log = StatusTracker::default();
        let result = super::check_certificate_profile(
            &der,
            &CertificateTrustPolicy::default(),
            &mut log,
            None,
        );
        assert_eq!(result, Err(expected));
    }

    #[test]
    fn malformed_version_algorithm_curve_and_unique_ids_are_rejected() {
        let mut log = StatusTracker::default();
        assert_eq!(
            check_end_entity_certificate_profile(
                b"invalid DER",
                &CertificateTrustPolicy::default(),
                &mut log,
                None,
            ),
            Err(super::CertificateProfileError::InvalidCertificate)
        );
        assert!(log.has_status(SIGNING_CREDENTIAL_INVALID));

        let mut cert = profile_cert();
        cert.tbs_certificate.version = rasn_pkix::Version::V2;
        assert_profile_error(
            &cert,
            super::CertificateProfileError::InvalidCertificateVersion,
        );

        let mut cert = profile_cert();
        cert.signature_algorithm.algorithm = oid(&[1, 2, 3, 4]);
        cert.tbs_certificate.signature = cert.signature_algorithm.clone();
        assert_profile_error(&cert, super::CertificateProfileError::UnsupportedAlgorithm);

        for issuer in [false, true] {
            let mut cert = profile_cert();
            if issuer {
                cert.tbs_certificate.issuer_unique_id =
                    Some(rasn::types::BitString::from_slice(&[1]));
            } else {
                cert.tbs_certificate.subject_unique_id =
                    Some(rasn::types::BitString::from_slice(&[1]));
            }
            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }

        for parameters in [
            None,
            Some(Any::new(vec![5, 0])),
            Some(Any::new(rasn::der::encode(&oid(&[1, 2, 3, 4])).unwrap())),
        ] {
            let mut cert = profile_cert();
            cert.tbs_certificate.subject_public_key_info.algorithm =
                rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 10045, 2, 1]),
                    parameters,
                };
            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }
    }

    #[test]
    fn eku_combinations_and_required_extensions_are_enforced() {
        for ekus in [
            vec![oid(&[2, 5, 29, 37, 0])],
            vec![oid(&[1, 2, 3, 4])],
            vec![
                oid(&[1, 3, 6, 1, 5, 5, 7, 3, 8]),
                oid(&[1, 3, 6, 1, 5, 5, 7, 3, 9]),
            ],
            vec![
                oid(&[1, 3, 6, 1, 5, 5, 7, 3, 8]),
                oid(&[1, 3, 6, 1, 5, 5, 7, 3, 4]),
            ],
        ] {
            let mut cert = profile_cert();
            extension(
                &mut cert,
                &[2, 5, 29, 37],
                rasn::der::encode(&ekus).unwrap(),
            );
            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }

        for removed in [&[2, 5, 29, 35][..], &[2, 5, 29, 15], &[2, 5, 29, 37]] {
            let mut cert = profile_cert();
            cert.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .retain(|e| e.extn_id != oid(removed));
            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }

        for usage in [vec![3, 2, 2, 0x84], vec![3, 2, 0, 0]] {
            let mut cert = profile_cert();
            extension(&mut cert, &[2, 5, 29, 15], usage);
            assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
        }

        for critical in [false, true] {
            let mut cert = profile_cert();
            cert.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(rasn_pkix::Extension {
                    extn_id: oid(&[1, 2, 3, 4]),
                    critical,
                    extn_value: vec![5, 0].into(),
                });
            let mut log = StatusTracker::default();
            let result = super::check_certificate_profile(
                &rasn::der::encode(&cert).unwrap(),
                &CertificateTrustPolicy::default(),
                &mut log,
                None,
            );
            assert_eq!(result.is_err(), critical);
            assert_eq!(log.has_status(SIGNING_CREDENTIAL_INVALID), critical);
        }
    }

    #[test]
    fn mandatory_ekus_are_reported_and_ca_is_not_an_end_entity() {
        let mut ctp = CertificateTrustPolicy::default();
        ctp.add_mandatory_ekus(b"1.3.6.1.5.5.7.3.8");
        let cert = profile_cert();
        let mut log = StatusTracker::default();
        // Mandatory EKU failures are currently logged, not returned as an error.
        check_end_entity_certificate_profile(
            &rasn::der::encode(&cert).unwrap(),
            &ctp,
            &mut log,
            None,
        )
        .unwrap();
        assert!(log.has_status(SIGNING_CREDENTIAL_INVALID));
        assert!(log
            .logged_items()
            .iter()
            .any(|item| item.description == "certificate missing mandatory EKU"));

        let mut cert = profile_cert();
        extension(&mut cert, &[2, 5, 29, 19], vec![0x30, 3, 1, 1, 0xff]);
        extension(&mut cert, &[2, 5, 29, 15], vec![3, 2, 1, 6]);
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .retain(|e| e.extn_id != oid(&[2, 5, 29, 37]));
        let der = rasn::der::encode(&cert).unwrap();
        let mut log = StatusTracker::default();
        assert_eq!(
            check_end_entity_certificate_profile(&der, &ctp, &mut log, None),
            Err(super::CertificateProfileError::InvalidCertificate)
        );
        assert!(log
            .logged_items()
            .iter()
            .any(|item| item.description == "expected end-entity certificate"));
        assert!(log
            .logged_items()
            .iter()
            .any(|item| item.description == "certificate missing mandatory EKU"));

        cert.tbs_certificate.issuer = cert.tbs_certificate.subject.clone();
        assert_profile_error(&cert, super::CertificateProfileError::SelfSignedCertificate);
    }

    #[test]
    fn rsa_public_key_shape_size_and_exponent_are_checked() {
        for key in [
            vec![0x30, 0],
            vec![0x30, 3, 2, 1, 3],
            vec![0x30, 6, 2, 1, 3, 2, 1, 3],
        ] {
            let mut cert = profile_cert();
            cert.tbs_certificate.subject_public_key_info.algorithm =
                rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 113549, 1, 1, 1]),
                    parameters: Some(Any::new(vec![5, 0])),
                };
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key = rasn::types::BitString::from_slice(&key);
            let der = rasn::der::encode(&cert).unwrap();
            assert_eq!(
                super::check_certificate_profile(
                    &der,
                    &CertificateTrustPolicy::default(),
                    &mut StatusTracker::default(),
                    None
                ),
                Err(super::CertificateProfileError::InvalidCertificate)
            );
        }

        #[derive(rasn::AsnType, rasn::Encode, rasn::Decode)]
        struct RsaKey {
            modulus: rasn::types::Integer,
            exponent: rasn::types::Integer,
        }

        let mut cert: Certificate = rasn::der::decode(&x509_der_from_pem(include_bytes!(
            "../../../tests/fixtures/certs/ps256.pub"
        )))
        .unwrap();
        let key: RsaKey = rasn::der::decode(
            cert.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_raw_slice(),
        )
        .unwrap();
        let invalid = RsaKey {
            modulus: key.modulus,
            exponent: 2.into(),
        };
        cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key =
            rasn::types::BitString::from_slice(&rasn::der::encode(&invalid).unwrap());

        assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
    }

    #[test]
    fn pss_parameters_require_matching_supported_hashes() {
        #[derive(rasn::AsnType, rasn::Encode)]
        struct PssParameters {
            #[rasn(tag(explicit(0)))]
            hash: rasn_pkix::AlgorithmIdentifier,
            #[rasn(tag(explicit(1)))]
            mask: rasn_pkix::AlgorithmIdentifier,
        }

        for (hash, mask_hash, valid) in [
            (
                vec![2, 16, 840, 1, 101, 3, 4, 2, 1],
                vec![2, 16, 840, 1, 101, 3, 4, 2, 1],
                true,
            ),
            (
                vec![2, 16, 840, 1, 101, 3, 4, 2, 2],
                vec![2, 16, 840, 1, 101, 3, 4, 2, 2],
                true,
            ),
            (
                vec![2, 16, 840, 1, 101, 3, 4, 2, 3],
                vec![2, 16, 840, 1, 101, 3, 4, 2, 3],
                true,
            ),
            (vec![1, 3, 14, 3, 2, 26], vec![1, 3, 14, 3, 2, 26], false),
            (
                vec![2, 16, 840, 1, 101, 3, 4, 2, 1],
                vec![2, 16, 840, 1, 101, 3, 4, 2, 2],
                false,
            ),
        ] {
            let hash_alg = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&hash),
                parameters: None,
            };

            let mask_alg = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&mask_hash),
                parameters: None,
            };

            let params = rasn::der::encode(&PssParameters {
                hash: hash_alg,
                mask: rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[1, 2, 840, 113549, 1, 1, 8]),
                    parameters: Some(Any::new(rasn::der::encode(&mask_alg).unwrap())),
                },
            })
            .unwrap();

            let mut cert = profile_cert();
            cert.signature_algorithm = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&[1, 2, 840, 113549, 1, 1, 10]),
                parameters: Some(Any::new(params)),
            };
            cert.tbs_certificate.signature = cert.signature_algorithm.clone();
            let mut log = StatusTracker::default();
            let result = super::check_certificate_profile(
                &rasn::der::encode(&cert).unwrap(),
                &CertificateTrustPolicy::default(),
                &mut log,
                None,
            );
            assert_eq!(
                result.is_ok(),
                valid,
                "{hash:?} / {mask_hash:?}: {result:?}"
            );
            assert_eq!(log.has_status(SIGNING_CREDENTIAL_INVALID), !valid);
        }

        let mut cert = profile_cert();
        cert.signature_algorithm = rasn_pkix::AlgorithmIdentifier {
            algorithm: oid(&[1, 2, 840, 113549, 1, 1, 10]),
            parameters: None,
        };
        cert.tbs_certificate.signature = cert.signature_algorithm.clone();
        assert_profile_error(&cert, super::CertificateProfileError::InvalidCertificate);
    }

    fn timestamp_at(seconds: i64) -> crate::crypto::asn1::rfc3161::TstInfo {
        use bcder::decode::Constructed;
        #[derive(rasn::AsnType, rasn::Encode)]
        struct Imprint {
            algorithm: rasn_pkix::AlgorithmIdentifier,
            digest: rasn::types::OctetString,
        }
        #[derive(rasn::AsnType, rasn::Encode)]
        struct Timestamp {
            version: rasn::types::Integer,
            policy: rasn::types::ObjectIdentifier,
            imprint: Imprint,
            serial: rasn::types::Integer,
            time: rasn::types::GeneralizedTime,
        }

        let bytes = rasn::der::encode(&Timestamp {
            version: 1.into(),
            policy: oid(&[1, 2, 3]),
            imprint: Imprint {
                algorithm: rasn_pkix::AlgorithmIdentifier {
                    algorithm: oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]),
                    parameters: None,
                },
                digest: vec![0; 32].into(),
            },
            serial: 1.into(),
            time: chrono::DateTime::from_timestamp(seconds, 0).unwrap().into(),
        })
        .unwrap();
        Constructed::decode(
            bytes.as_slice(),
            bcder::Mode::Der,
            crate::crypto::asn1::rfc3161::TstInfo::take_from,
        )
        .unwrap()
    }

    #[test]
    fn supplied_timestamp_checks_both_validity_boundaries_inclusively() {
        let cert = profile_cert();
        let der = rasn::der::encode(&cert).unwrap();
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        let start = parsed.validity().not_before.timestamp();
        let end = parsed.validity().not_after.timestamp();
        let ctp = CertificateTrustPolicy::default();
        for (time, valid) in [
            (start - 1, false),
            (start, true),
            (end, true),
            (end + 1, false),
        ] {
            let timestamp = timestamp_at(time);
            let mut log = StatusTracker::default();
            let result =
                check_end_entity_certificate_profile(&der, &ctp, &mut log, Some(&timestamp));
            if valid {
                assert_eq!(result, Ok(()));
                assert!(!log.has_any_error());
            } else {
                assert_eq!(
                    result,
                    Err(super::CertificateProfileError::CertificateNotValidAtTime)
                );
                assert!(log.has_status(SIGNING_CREDENTIAL_EXPIRED));
                assert_eq!(log.logged_items()[0].description, "certificate expired");
            }
        }
    }

    #[test]
    fn malformed_pss_parameter_structures_fail_closed() {
        let sha256 = rasn_pkix::AlgorithmIdentifier {
            algorithm: oid(&[2, 16, 840, 1, 101, 3, 4, 2, 1]),
            parameters: None,
        };

        let hash = rasn::der::encode(&sha256).unwrap();
        let mut malformed = vec![
            vec![5, 0],
            vec![0x30, 0],
            vec![0x30, 2, 0xa1, 0],
            vec![0x30, 2, 0xa0, 0],
        ];
        for tag in [0xa0, 0x81, 0xa1] {
            let second = if tag == 0xa1 {
                vec![tag, 0]
            } else {
                vec![tag, 2, 5, 0]
            };

            let mut body = vec![0xa0, hash.len() as u8];
            body.extend_from_slice(&hash);
            body.extend_from_slice(&second);
            let mut sequence = vec![0x30, body.len() as u8];
            sequence.extend_from_slice(&body);
            malformed.push(sequence);
        }

        for params in malformed {
            let mut cert = profile_cert();
            cert.signature_algorithm = rasn_pkix::AlgorithmIdentifier {
                algorithm: oid(&[1, 2, 840, 113549, 1, 1, 10]),
                parameters: Some(Any::new(params)),
            };
            cert.tbs_certificate.signature = cert.signature_algorithm.clone();
            let result = super::check_certificate_profile(
                &rasn::der::encode(&cert).unwrap(),
                &CertificateTrustPolicy::default(),
                &mut StatusTracker::default(),
                None,
            );
            assert_eq!(
                result,
                Err(super::CertificateProfileError::InvalidCertificate)
            );
        }
    }

    #[test]
    fn recognized_critical_extensions_do_not_look_like_unknown_extensions() {
        use x509_parser::extensions::ParsedExtension;
        let fixtures = [
            (
                vec![2, 5, 29, 33],
                vec![0x30, 10, 0x30, 8, 6, 2, 42, 3, 6, 2, 42, 4],
                "PolicyMappings",
            ),
            (
                vec![2, 5, 29, 30],
                [
                    &[0x30, 17, 0xa0, 15, 0x30, 13, 0x82, 11][..],
                    b"example.com",
                ]
                .concat(),
                "NameConstraints",
            ),
            (
                vec![2, 5, 29, 36],
                vec![0x30, 3, 0x80, 1, 0],
                "PolicyConstraints",
            ),
            (vec![2, 5, 29, 54], vec![2, 1, 0], "InhibitAnyPolicy"),
            (
                vec![2, 16, 840, 1, 113730, 1, 1],
                vec![3, 2, 0, 0x80],
                "NSCertType",
            ),
            (vec![2, 5, 29, 20], vec![2, 1, 1], "CRLNumber"),
            (vec![2, 5, 29, 21], vec![10, 1, 0], "ReasonCode"),
            (
                vec![2, 5, 29, 24],
                [&[0x18, 15][..], b"20200101000000Z"].concat(),
                "InvalidityDate",
            ),
        ];
        for (id, value, expected) in fixtures {
            let mut cert = profile_cert();
            let id = oid(&id);
            cert.tbs_certificate
                .extensions
                .as_mut()
                .unwrap()
                .push(rasn_pkix::Extension {
                    extn_id: id.clone(),
                    critical: true,
                    extn_value: value.into(),
                });
            let der = rasn::der::encode(&cert).unwrap();
            let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
            let parsed_extension = parsed
                .extensions()
                .iter()
                .find(|extension| extension.oid.to_id_string() == id.to_string())
                .unwrap();
            let actual = match parsed_extension.parsed_extension() {
                ParsedExtension::PolicyMappings(_) => "PolicyMappings",
                ParsedExtension::NameConstraints(_) => "NameConstraints",
                ParsedExtension::PolicyConstraints(_) => "PolicyConstraints",
                ParsedExtension::InhibitAnyPolicy(_) => "InhibitAnyPolicy",
                ParsedExtension::NSCertType(_) => "NSCertType",
                ParsedExtension::CRLNumber(_) => "CRLNumber",
                ParsedExtension::ReasonCode(_) => "ReasonCode",
                ParsedExtension::InvalidityDate(_) => "InvalidityDate",
                other => panic!("unexpected extension: {other:?}"),
            };

            assert_eq!(actual, expected);
            let mut log = StatusTracker::default();
            check_end_entity_certificate_profile(
                &der,
                &CertificateTrustPolicy::default(),
                &mut log,
                None,
            )
            .unwrap();
            assert!(!log.has_any_error(), "{expected}");
        }
    }
}
