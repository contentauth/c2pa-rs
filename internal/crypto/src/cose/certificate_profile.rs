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
use c2pa_status_tracker::{log_item, validation_codes::*, StatusTracker};
use chrono::{DateTime, Utc};
use thiserror::Error;
use web_time::SystemTime;
use x509_certificate::asn1time::GeneralizedTime;
use x509_parser::{
    certificate::{BasicExtension, X509Certificate},
    der_parser::{ber::parse_ber_sequence, oid},
    extensions::ParsedExtension,
    oid_registry::Oid,
    x509::{AlgorithmIdentifier, X509Version},
};

use crate::{asn1::rfc3161::TstInfo, cose::CertificateTrustPolicy};

/// Verify that an X.509 certificate meets the requirements stated in [§14.5.1,
/// Certificate Profiles].
///
/// [§14.5.1, Certificate Profiles]: https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_certificate_profiles
pub fn check_certificate_profile(
    certificate_der: &[u8],
    ctp: &CertificateTrustPolicy,
    validation_log: &mut impl StatusTracker,
    _tst_info_opt: Option<&TstInfo>,
) -> Result<(), CertificateProfileError> {
    let (_rem, signcert) = X509Certificate::from_der(certificate_der).map_err(|_err| {
        log_item!(
            "Cose_Sign1",
            "certificate could not be parsed",
            "check_cert_alg"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

        CertificateProfileError::InvalidCertificate
    })?;

    // Version shall be v3 as per RFC 5280, section 4.1.2.1.
    if signcert.version() != X509Version::V3 {
        log_item!(
            "Cose_Sign1",
            "certificate version incorrect",
            "check_cert_alg"
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
        let signing_time = generalized_time_to_datetime(tst_info.gen_time.clone());
        if !signcert.validity().is_valid_at(
            x509_parser::time::ASN1Time::from_timestamp(signing_time.timestamp())
                .map_err(|_| CertificateProfileError::InvalidCertificate)?,
        ) {
            log_item!("Cose_Sign1", "certificate expired", "check_cert_alg")
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
            log_item!("Cose_Sign1", "certificate expired", "check_cert_alg")
                .validation_status(SIGNING_CREDENTIAL_EXPIRED)
                .failure_no_throw(
                    validation_log,
                    CertificateProfileError::CertificateNotValidAtTime,
                );

            return Err(CertificateProfileError::CertificateNotValidAtTime);
        }
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
            "Cose_Sign1",
            "certificate algorithm not supported",
            "check_cert_alg"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(
            validation_log,
            CertificateProfileError::UnsupportedAlgorithm,
        );

        return Err(CertificateProfileError::UnsupportedAlgorithm);
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
                    "Cose_Sign1",
                    "certificate algorithm error",
                    "check_cert_alg"
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
                    "Cose_Sign1",
                    "certificate hash algorithm not supported",
                    "check_cert_alg"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                return Err(CertificateProfileError::InvalidCertificate);
            }
        } else {
            log_item!(
                "Cose_Sign1",
                "certificate missing algorithm parameters",
                "check_cert_alg"
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
                    "Cose_Sign1",
                    "certificate unsupported EC curve",
                    "check_cert_alg"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                return Err(CertificateProfileError::InvalidCertificate);
            }
        } else {
            return Err(CertificateProfileError::InvalidCertificate);
        }
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

        if modulus.bits() < 2048 {
            log_item!(
                "Cose_Sign1",
                "certificate key length too short",
                "check_cert_alg"
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
            "Cose_Sign1",
            "certificate issuer and subject cannot be the same (self-signed disallowed)",
            "check_cert_alg"
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
            "Cose_Sign1",
            "certificate issuer/subject unique ids are not allowed",
            "check_cert_alg"
        )
        .validation_status(SIGNING_CREDENTIAL_INVALID)
        .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

        return Err(CertificateProfileError::InvalidCertificate);
    }

    let mut aki_good = false;
    let mut ski_good = false;
    let mut key_usage_good = false;
    let extended_key_usage_good = match tbscert
        .extended_key_usage()
        .map_err(|_| CertificateProfileError::InvalidCertificate)?
    {
        Some(BasicExtension { value: eku, .. }) => {
            if eku.any {
                log_item!(
                    "Cose_Sign1",
                    "certificate 'any' EKU not allowed",
                    "check_cert_alg"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                return Err(CertificateProfileError::InvalidCertificate);
            }

            if ctp.has_allowed_eku(eku).is_none() {
                log_item!(
                    "Cose_Sign1",
                    "certificate missing required EKU",
                    "check_cert_alg"
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
                    "Cose_Sign1",
                    "certificate invalid set of EKUs",
                    "check_cert_alg"
                )
                .validation_status(SIGNING_CREDENTIAL_INVALID)
                .failure_no_throw(validation_log, CertificateProfileError::InvalidCertificate);

                return Err(CertificateProfileError::InvalidCertificate);
            }

            true
        }

        None => tbscert.is_ca(), // if is not ca it must be present
    };

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
                if ku.digital_signature() {
                    if ku.key_cert_sign() && !tbscert.is_ca() {
                        log_item!(
                            "Cose_Sign1",
                            "certificate missing digitalSignature EKU",
                            "check_cert_alg"
                        )
                        .validation_status(SIGNING_CREDENTIAL_INVALID)
                        .failure_no_throw(
                            validation_log,
                            CertificateProfileError::InvalidCertificate,
                        );

                        return Err(CertificateProfileError::InvalidCertificate);
                    }
                    key_usage_good = true;
                }
                if ku.key_cert_sign() || ku.non_repudiation() {
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
            _ => (),
        }
    }

    // If cert is a CA must have valid SubjectKeyIdentifier.
    ski_good = if tbscert.is_ca() { ski_good } else { true };

    // Check all flags.
    if aki_good && ski_good && key_usage_good && extended_key_usage_good {
        Ok(())
    } else {
        log_item!(
            "Cose_Sign1",
            "certificate params incorrect",
            "check_cert_alg"
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

fn generalized_time_to_datetime(gt: GeneralizedTime) -> DateTime<Utc> {
    gt.into()
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
