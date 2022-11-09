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

use ciborium::value::Value;
use conv::*;
use coset::{sig_structure_data, Label, TaggedCborSerializable};
use x509_parser::{
    der_parser::{ber::parse_ber_sequence, oid},
    oid_registry::Oid,
    prelude::*,
};

#[cfg(not(target_arch = "wasm32"))]
use crate::validator::{get_validator, CoseValidator};
#[cfg(target_arch = "wasm32")]
use crate::wasm::webcrypto_validator::validate_async;
use crate::{
    asn1::rfc3161::TstInfo,
    error::{Error, Result},
    status_tracker::{log_item, StatusTracker},
    time_stamp::gt_to_datetime,
    validation_status,
    validator::ValidationInfo,
    SigningAlg,
};

const RSA_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .1);
const EC_PUBLICKEY_OID: Oid<'static> = oid!(1.2.840 .10045 .2 .1);
const ECDSA_WITH_SHA256_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .2);
const ECDSA_WITH_SHA384_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .3);
const ECDSA_WITH_SHA512_OID: Oid<'static> = oid!(1.2.840 .10045 .4 .3 .4);
const RSASSA_PSS_OID: Oid<'static> = oid!(1.2.840 .113549 .1 .1 .10);
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

/********************** Supported Valiators ***************************************
    RS256	RSASSA-PKCS1-v1_5 using SHA-256 - not recommended
    RS384	RSASSA-PKCS1-v1_5 using SHA-384 - not recommended
    RS512	RSASSA-PKCS1-v1_5 using SHA-512 - not recommended
    PS256	RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS384	RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS512	RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    ES256	ECDSA using P-256 and SHA-256
    ES384	ECDSA using P-384 and SHA-384
    ES512	ECDSA using P-521 and SHA-512
    ED25519 Edwards Curve 25519
**********************************************************************************/

fn get_cose_sign1(
    cose_bytes: &[u8],
    data: &[u8],
    validation_log: &mut impl StatusTracker,
) -> Result<coset::CoseSign1> {
    match <coset::CoseSign1 as TaggedCborSerializable>::from_tagged_slice(cose_bytes) {
        Ok(mut sign1) => {
            sign1.payload = Some(data.to_vec()); // restore payload for verification check

            Ok(sign1)
        }
        Err(coset_error) => {
            let log_item = log_item!(
                "Cose_Sign1",
                "could not deserialize signature",
                "get_cose_sign1"
            )
            .error(Error::InvalidCoseSignature { coset_error })
            .validation_status(validation_status::CLAIM_SIGNATURE_MISMATCH);

            validation_log.log_silent(log_item);

            Err(Error::CoseSignature)
        }
    }
}
fn check_cert(
    _alg: SigningAlg,
    ca_der_bytes: &[u8],
    validation_log: &mut impl StatusTracker,
    _tst_info_opt: Option<&TstInfo>,
) -> Result<()> {
    // get the cert in der format
    let (_rem, signcert) = X509Certificate::from_der(ca_der_bytes).map_err(|_err| {
        let log_item = log_item!(
            "Cose_Sign1",
            "certificate could not be parsed",
            "check_cert_alg"
        )
        .error(Error::CoseInvalidCert)
        .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
        validation_log.log_silent(log_item);
        Error::CoseInvalidCert
    })?;

    // cert version must be 3
    if signcert.version() != X509Version::V3 {
        let log_item = log_item!(
            "Cose_Sign1",
            "certificate version incorrect",
            "check_cert_alg"
        )
        .error(Error::CoseInvalidCert)
        .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
        validation_log.log_silent(log_item);

        return Err(Error::CoseInvalidCert);
    }

    // check for cert expiration
    if let Some(tst_info) = _tst_info_opt {
        // was there a time stamp associtation with this signature, is verify against that time
        let signing_time = gt_to_datetime(tst_info.gen_time.clone());
        if !signcert
            .validity()
            .is_valid_at(x509_parser::time::ASN1Time::from_timestamp(
                signing_time.timestamp(),
            ))
        {
            let log_item = log_item!("Cose_Sign1", "certificate expired", "check_cert_alg")
                .error(Error::CoseCertExpiration)
                .validation_status(validation_status::SIGNING_CREDENTIAL_EXPIRED);
            validation_log.log_silent(log_item);

            return Err(Error::CoseCertExpiration);
        }
    } else {
        // no timestamp so check against current time
        // use instant to avoid wasm issues
        let now_f64 = instant::now() / 1000.0;
        let now: i64 = now_f64
            .approx_as::<i64>()
            .map_err(|_e| Error::BadParam("system time invalid".to_string()))?;

        if !signcert
            .validity()
            .is_valid_at(x509_parser::time::ASN1Time::from_timestamp(now))
        {
            let log_item = log_item!("Cose_Sign1", "certificate expired", "check_cert_alg")
                .error(Error::CoseCertExpiration)
                .validation_status(validation_status::SIGNING_CREDENTIAL_EXPIRED);
            validation_log.log_silent(log_item);

            return Err(Error::CoseCertExpiration);
        }
    }

    let cert_alg = signcert.signature_algorithm.algorithm.clone();

    // check algorithm needed from cert

    // cert must be signed with one the following algorithm
    if !(cert_alg == SHA256_WITH_RSAENCRYPTION_OID
        || cert_alg == SHA384_WITH_RSAENCRYPTION_OID
        || cert_alg == SHA512_WITH_RSAENCRYPTION_OID
        || cert_alg == ECDSA_WITH_SHA256_OID
        || cert_alg == ECDSA_WITH_SHA384_OID
        || cert_alg == ECDSA_WITH_SHA512_OID
        || cert_alg == RSASSA_PSS_OID
        || cert_alg == ED25519_OID)
    {
        let log_item = log_item!(
            "Cose_Sign1",
            "certificate algorithm not supported",
            "check_cert_alg"
        )
        .error(Error::CoseInvalidCert)
        .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
        validation_log.log_silent(log_item);

        return Err(Error::CoseInvalidCert);
    }

    // verify rsassa_pss parameters
    if cert_alg == RSASSA_PSS_OID {
        if let Some(parameters) = &signcert.signature_algorithm.parameters {
            let seq = parameters
                .as_sequence()
                .map_err(|_err| Error::CoseInvalidCert)?;
            if seq.len() < 3 {
                let log_item = log_item!(
                    "Cose_Sign1",
                    "certificate incorrect rsapss algorithm",
                    "check_cert_alg"
                )
                .error(Error::CoseInvalidCert)
                .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
                validation_log.log_silent(log_item);

                return Err(Error::CoseInvalidCert);
            }

            // get hash algorithm
            let (_b, ha_alg) = AlgorithmIdentifier::from_der(
                seq[0]
                    .content
                    .as_slice()
                    .map_err(|_err| Error::CoseInvalidCert)?,
            )
            .map_err(|_err| Error::CoseInvalidCert)?;

            let (_b, mgf_ai) = AlgorithmIdentifier::from_der(
                seq[1]
                    .content
                    .as_slice()
                    .map_err(|_err| Error::CoseInvalidCert)?,
            )
            .map_err(|_err| Error::CoseInvalidCert)?;

            let mgf_ai_parameters = mgf_ai.parameters.ok_or(Error::CoseInvalidCert)?;
            let s = mgf_ai_parameters
                .as_sequence()
                .map_err(|_err| Error::CoseInvalidCert)?;
            let t0 = &s[0];
            //let _t1 = &s[1];
            let mfg_ai_params_algorithm = t0.as_oid_val().map_err(|_err| Error::CoseInvalidCert)?;

            // must be the same
            if ha_alg.algorithm != mfg_ai_params_algorithm {
                let log_item = log_item!(
                    "Cose_Sign1",
                    "certificate algorithm error",
                    "check_cert_alg"
                )
                .error(Error::CoseInvalidCert)
                .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
                validation_log.log_silent(log_item);

                return Err(Error::CoseInvalidCert);
            }

            // check for one of the mandatory types
            if !(ha_alg.algorithm == SHA256_OID
                || ha_alg.algorithm == SHA384_OID
                || ha_alg.algorithm == SHA512_OID)
            {
                let log_item = log_item!(
                    "Cose_Sign1",
                    "certificate hash algorithm not supported",
                    "check_cert_alg"
                )
                .error(Error::CoseInvalidCert)
                .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
                validation_log.log_silent(log_item);

                return Err(Error::CoseInvalidCert);
            }
        } else {
            let log_item = log_item!(
                "Cose_Sign1",
                "certificate missing algorithm parameters",
                "check_cert_alg"
            )
            .error(Error::CoseInvalidCert)
            .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
            validation_log.log_silent(log_item);

            return Err(Error::CoseInvalidCert);
        }
    }

    // check curves for SPKI EC algorithms
    let pk = signcert.public_key();
    let skpi_alg = &pk.algorithm;

    if skpi_alg.algorithm == EC_PUBLICKEY_OID {
        if let Some(parameters) = &skpi_alg.parameters {
            let named_curve_oid = parameters
                .as_oid_val()
                .map_err(|_err| Error::CoseInvalidCert)?;

            // must be one of these named curves
            if !(named_curve_oid == PRIME256V1_OID
                || named_curve_oid == SECP384R1_OID
                || named_curve_oid == SECP521R1_OID)
            {
                let log_item = log_item!(
                    "Cose_Sign1",
                    "certificate unsupported EC curve",
                    "check_cert_alg"
                )
                .error(Error::CoseInvalidCert)
                .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
                validation_log.log_silent(log_item);

                return Err(Error::CoseInvalidCert);
            }
        } else {
            return Err(Error::CoseInvalidCert);
        }
    }

    // check modulus minimum length (for RSA & PSS algorithms)
    if skpi_alg.algorithm == RSA_OID || skpi_alg.algorithm == RSASSA_PSS_OID {
        let (_, skpi_ber) = parse_ber_sequence(pk.subject_public_key.data)
            .map_err(|_err| Error::CoseInvalidCert)?;

        let seq = skpi_ber
            .as_sequence()
            .map_err(|_err| Error::CoseInvalidCert)?;
        if seq.len() < 2 {
            return Err(Error::CoseInvalidCert);
        }

        let modulus = seq[0].as_bigint().ok_or(Error::CoseInvalidCert)?;

        if modulus.bits() < 2048 {
            let log_item = log_item!(
                "Cose_Sign1",
                "certificate key length too short",
                "check_cert_alg"
            )
            .error(Error::CoseInvalidCert)
            .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
            validation_log.log_silent(log_item);

            return Err(Error::CoseInvalidCert);
        }
    }

    // check cert values
    let tbscert = &signcert.tbs_certificate;

    let is_self_signed = tbscert.is_ca() && tbscert.issuer_uid == tbscert.subject_uid;

    // self signed certs are disallowed
    if is_self_signed {
        let log_item = log_item!(
            "Cose_Sign1",
            "certificate issuer and subject cannot be the same {self-signed disallowed}",
            "check_cert_alg"
        )
        .error(Error::CoseInvalidCert)
        .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
        validation_log.log_silent(log_item);

        return Err(Error::CoseInvalidCert);
    }

    let mut aki_good = false;
    let mut ski_good = false;
    let mut key_usage_good = false;
    let mut handled_all_critical = true;
    let extended_key_usage_good = match tbscert.extended_key_usage() {
        Some((_critical, eku)) => {
            if eku.any {
                let log_item = log_item!(
                    "Cose_Sign1",
                    "certificate 'any' EKU not allowed",
                    "check_cert_alg"
                )
                .error(Error::CoseInvalidCert)
                .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
                validation_log.log_silent(log_item);

                return Err(Error::CoseInvalidCert);
            }

            if !(eku.email_protection || eku.ocsp_signing || eku.time_stamping) {
                let log_item = log_item!(
                    "Cose_Sign1",
                    "certificate missing required EKU",
                    "check_cert_alg"
                )
                .error(Error::CoseInvalidCert)
                .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
                validation_log.log_silent(log_item);

                return Err(Error::CoseInvalidCert);
            }

            // one or the other || either of these two, and no others field
            if (eku.ocsp_signing && eku.time_stamping)
                || ((eku.ocsp_signing ^ eku.time_stamping)
                    && (eku.client_auth
                        | eku.code_signing
                        | eku.email_protection
                        | eku.server_auth))
            {
                let log_item = log_item!(
                    "Cose_Sign1",
                    "certificate invalid set of EKUs",
                    "check_cert_alg"
                )
                .error(Error::CoseInvalidCert)
                .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
                validation_log.log_silent(log_item);

                return Err(Error::CoseInvalidCert);
            }

            true
        }
        None => tbscert.is_ca(), // if is not ca it must be present
    };

    // populate needed extension info
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
                        let log_item = log_item!(
                            "Cose_Sign1",
                            "certificate missing digitalSignature EKU",
                            "check_cert_alg"
                        )
                        .error(Error::CoseInvalidCert)
                        .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
                        validation_log.log_silent(log_item);

                        return Err(Error::CoseInvalidCert);
                    }
                    key_usage_good = true;
                }
                if ku.key_cert_sign() {
                    key_usage_good = true;
                }
                // todo: warn if not marked critical
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
                    // unhandled critical extension
                    handled_all_critical = false;
                }
            }
            _ => {
                if e.critical {
                    // unhandled critical extension
                    handled_all_critical = false;
                }
            }
        }
    }

    // if cert is a CA must have valid SubjectKeyIdentifier
    ski_good = if tbscert.is_ca() { ski_good } else { true };

    // check all flags
    if aki_good && ski_good && key_usage_good && extended_key_usage_good && handled_all_critical {
        Ok(())
    } else {
        let log_item = log_item!(
            "Cose_Sign1",
            "certificate params incorrect",
            "check_cert_alg"
        )
        .error(Error::CoseInvalidCert)
        .validation_status(validation_status::SIGNING_CREDENTIAL_INVALID);
        validation_log.log_silent(log_item);

        Err(Error::CoseInvalidCert)
    }
}

pub(crate) fn get_signing_alg(cs1: &coset::CoseSign1) -> Result<SigningAlg> {
    // find the supported handler for the algorithm
    match cs1.protected.header.alg {
        Some(ref alg) => match alg {
            coset::RegisteredLabelWithPrivate::PrivateUse(a) => match a {
                -39 => Ok(SigningAlg::Ps512),
                -38 => Ok(SigningAlg::Ps384),
                -37 => Ok(SigningAlg::Ps256),
                -36 => Ok(SigningAlg::Es512),
                -35 => Ok(SigningAlg::Es384),
                -7 => Ok(SigningAlg::Es256),
                -8 => Ok(SigningAlg::Ed25519),
                _ => Err(Error::CoseSignatureAlgorithmNotSupported),
            },
            coset::RegisteredLabelWithPrivate::Assigned(a) => match a {
                coset::iana::Algorithm::PS512 => Ok(SigningAlg::Ps512),
                coset::iana::Algorithm::PS384 => Ok(SigningAlg::Ps384),
                coset::iana::Algorithm::PS256 => Ok(SigningAlg::Ps256),
                coset::iana::Algorithm::ES512 => Ok(SigningAlg::Es512),
                coset::iana::Algorithm::ES384 => Ok(SigningAlg::Es384),
                coset::iana::Algorithm::ES256 => Ok(SigningAlg::Es256),
                coset::iana::Algorithm::EdDSA => Ok(SigningAlg::Ed25519),
                _ => Err(Error::CoseSignatureAlgorithmNotSupported),
            },
            coset::RegisteredLabelWithPrivate::Text(a) => a
                .parse()
                .map_err(|_| Error::CoseSignatureAlgorithmNotSupported),
        },
        None => Err(Error::CoseSignatureAlgorithmNotSupported),
    }
}

fn get_sign_cert(sign1: &coset::CoseSign1) -> Result<Vec<u8>> {
    // element 0 is the signing cert
    let certs = get_sign_certs(sign1)?;
    Ok(certs[0].clone())
}
// get the public key der
fn get_sign_certs(sign1: &coset::CoseSign1) -> Result<Vec<Vec<u8>>> {
    let mut certs: Vec<Vec<u8>> = Vec::new();

    // get the public key der
    if let Some(der) = sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("x5chain".to_string()) {
                Some(x.1.clone())
            } else {
                None
            }
        })
    {
        match der {
            Value::Array(cert_chain) => {
                // handle array of certs
                for c in cert_chain {
                    if let Value::Bytes(der_bytes) = c {
                        certs.push(der_bytes.clone());
                    }
                }
                Ok(certs)
            }
            Value::Bytes(ref der_bytes) => {
                // handle single cert case
                certs.push(der_bytes.clone());
                Ok(certs)
            }
            _ => Err(Error::CoseX5ChainMissing),
        }
    } else {
        Err(Error::CoseX5ChainMissing)
    }
}

// internal util function to dump the cert chain in PEM format
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "file_io")]
#[allow(dead_code)]
fn dump_cert_chain(certs: &[Vec<u8>], output_path: &std::path::Path) -> Result<()> {
    let mut out_buf: Vec<u8> = Vec::new();

    for der_bytes in certs {
        let c = openssl::x509::X509::from_der(der_bytes).map_err(|_e| Error::UnsupportedType)?;
        let mut c_pem = c.to_pem().map_err(|_e| Error::UnsupportedType)?;

        out_buf.append(&mut c_pem);
    }

    std::fs::write(output_path, &out_buf).map_err(Error::IoError)
}

// Note: this function is only used to get the display string and not for cert validation.
fn get_signing_time(
    sign1: &coset::CoseSign1,
    data: &[u8],
) -> Option<chrono::DateTime<chrono::Utc>> {
    // get timestamp info if available

    if let Ok(tst_info) = get_timestamp_info(sign1, data) {
        Some(gt_to_datetime(tst_info.gen_time))
    } else {
        None
    }
}

// return appropriate TstInfo if available
fn get_timestamp_info(sign1: &coset::CoseSign1, data: &[u8]) -> Result<TstInfo> {
    // parse the temp timestamp
    if let Some(t) = &sign1
        .unprotected
        .rest
        .iter()
        .find_map(|x: &(Label, Value)| {
            if x.0 == Label::Text("sigTst".to_string()) {
                Some(x.1.clone())
            } else {
                None
            }
        })
    {
        let alg = get_signing_alg(sign1)?;
        let time_cbor = serde_cbor::to_vec(t)?;
        let tst_infos = crate::time_stamp::cose_sigtst_to_tstinfos(&time_cbor, data, alg)?;

        // there should only be one but consider handling more in the future since it is technically ok
        if !tst_infos.is_empty() {
            return Ok(tst_infos[0].clone());
        }
    }
    Err(Error::NotFound)
}

fn extract_subject_from_cert(cert: &X509Certificate) -> Result<String> {
    cert.subject()
        .iter_organization()
        .map(|attr| attr.as_str())
        .last()
        .ok_or(Error::CoseX5ChainMissing)?
        .map(|attr| attr.to_string())
        .map_err(|_e| Error::CoseX5ChainMissing)
}

/// Asynchronously validate a COSE_SIGN1 byte vector and verify against expected data
/// cose_bytes - byte array containing the raw COSE_SIGN1 data
/// data:  data that was used to create the cose_bytes, these must match
/// addition_data: additional optional data that may have been used during signing
/// returns - Ok on success
pub async fn verify_cose_async(
    cose_bytes: Vec<u8>,
    data: Vec<u8>,
    additional_data: Vec<u8>,
    signature_only: bool,
    validation_log: &mut impl StatusTracker,
) -> Result<ValidationInfo> {
    let mut sign1 = get_cose_sign1(&cose_bytes, &data, validation_log)?;

    let alg = match get_signing_alg(&sign1) {
        Ok(a) => a,
        Err(_) => {
            let log_item = log_item!(
                "Cose_Sign1",
                "unsupported or missing Cose algorithhm",
                "verify_cose_async"
            )
            .error(Error::CoseSignatureAlgorithmNotSupported)
            .validation_status(validation_status::ALGORITHM_UNSUPPORTED);
            validation_log.log(log_item, Some(Error::CoseSignatureAlgorithmNotSupported))?;

            // one of these must exist
            return Err(Error::CoseSignatureAlgorithmNotSupported);
        }
    };

    // build result structure
    let mut result = ValidationInfo::default();

    // get the public key der
    let der_bytes = get_sign_cert(&sign1)?;

    // verify cert matches requested algorithm
    if !signature_only {
        // verify certs
        match get_timestamp_info(&sign1, &data) {
            Ok(tst_info) => check_cert(alg, &der_bytes, validation_log, Some(&tst_info))?,
            Err(e) => {
                // log timestamp errors
                match e {
                    Error::NotFound => check_cert(alg, &der_bytes, validation_log, None)?,
                    Error::CoseTimeStampMismatch => {
                        let log_item = log_item!(
                            "Cose_Sign1",
                            "timestamp message imprint did not match",
                            "verify_cose"
                        )
                        .error(Error::CoseTimeStampMismatch)
                        .validation_status(validation_status::TIMESTAMP_MISMATCH);
                        validation_log.log(log_item, Some(Error::CoseTimeStampMismatch))?;
                    }
                    Error::CoseTimeStampValidity => {
                        let log_item =
                            log_item!("Cose_Sign1", "timestamp outside of validity", "verify_cose")
                                .error(Error::CoseTimeStampValidity)
                                .validation_status(validation_status::TIMESTAMP_OUTSIDE_VALIDITY);
                        validation_log.log(log_item, Some(Error::CoseTimeStampValidity))?;
                    }
                    _ => {
                        let log_item =
                            log_item!("Cose_Sign1", "error parsing timestamp", "verify_cose")
                                .error(Error::CoseInvalidTimeStamp);
                        validation_log.log(log_item, Some(Error::CoseInvalidTimeStamp))?;

                        return Err(Error::CoseInvalidTimeStamp);
                    }
                }
            }
        }
    }

    // Check the signature, which needs to have the same `additional_data` provided, by
    // providing a closure that can do the verify operation.
    sign1.payload = Some(data.clone()); // restore payload

    let p_header = sign1.protected.clone();

    let tbs = sig_structure_data(
        coset::SignatureContext::CoseSign1,
        p_header,
        None,
        &additional_data,
        sign1.payload.as_ref().unwrap_or(&vec![]),
    ); // get "to be signed" bytes

    if let Ok(issuer) = validate_with_cert_async(alg, &sign1.signature, &tbs, &der_bytes).await {
        result.issuer_org = Some(issuer);
        result.validated = true;
        result.alg = Some(alg);

        // parse the temp time for now util we have TA
        result.date = get_signing_time(&sign1, &data);
    }

    Ok(result)
}

pub fn get_signing_info(
    cose_bytes: &[u8],
    data: &[u8],
    validation_log: &mut impl StatusTracker,
) -> ValidationInfo {
    let mut date = None;
    let mut issuer_org = None;
    let mut alg: Option<SigningAlg> = None;

    let _ = get_cose_sign1(cose_bytes, data, validation_log).and_then(|sign1| {
        // get the public key der
        let der_bytes = get_sign_cert(&sign1)?;

        let _ = X509Certificate::from_der(&der_bytes).map(|(_rem, signcert)| {
            date = get_signing_time(&sign1, data);
            issuer_org = extract_subject_from_cert(&signcert).ok();
            if let Ok(a) = get_signing_alg(&sign1) {
                alg = Some(a);
            }

            (_rem, signcert)
        });

        Ok(sign1)
    });

    ValidationInfo {
        issuer_org,
        date,
        alg,
        validated: false,
    }
}

/// Validate a COSE_SIGN1 byte vector and verify against expected data
/// cose_bytes - byte array containing the raw COSE_SIGN1 data
/// data:  data that was used to create the cose_bytes, these must match
/// addition_data: additional optional data that may have been used during signing
/// returns - Ok on success
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_cose(
    cose_bytes: &[u8],
    data: &[u8],
    additional_data: &[u8],
    signature_only: bool,
    validation_log: &mut impl StatusTracker,
) -> Result<ValidationInfo> {
    let sign1 = get_cose_sign1(cose_bytes, data, validation_log)?;

    let alg = match get_signing_alg(&sign1) {
        Ok(a) => a,
        Err(_) => {
            let log_item = log_item!(
                "Cose_Sign1",
                "unsupported or missing Cose algorithhm",
                "verify_cose"
            )
            .error(Error::CoseSignatureAlgorithmNotSupported)
            .validation_status(validation_status::ALGORITHM_UNSUPPORTED);

            validation_log.log(log_item, Some(Error::CoseSignatureAlgorithmNotSupported))?;

            return Err(Error::CoseSignatureAlgorithmNotSupported);
        }
    };

    let validator = get_validator(alg);

    // build result structure
    let mut result = ValidationInfo::default();

    // get the cert chain
    let certs = get_sign_certs(&sign1)?;

    // get the public key der
    let der_bytes = &certs[0];

    if !signature_only {
        // verify certs
        match get_timestamp_info(&sign1, data) {
            Ok(tst_info) => check_cert(alg, der_bytes, validation_log, Some(&tst_info))?,
            Err(e) => {
                // log timestamp errors
                match e {
                    Error::NotFound => check_cert(alg, der_bytes, validation_log, None)?,
                    Error::CoseTimeStampMismatch => {
                        let log_item = log_item!(
                            "Cose_Sign1",
                            "timestamp message imprint did not match",
                            "verify_cose"
                        )
                        .error(Error::CoseTimeStampMismatch)
                        .validation_status(validation_status::TIMESTAMP_MISMATCH);
                        validation_log.log(log_item, Some(Error::CoseTimeStampMismatch))?;
                    }
                    Error::CoseTimeStampValidity => {
                        let log_item =
                            log_item!("Cose_Sign1", "timestamp outside of validity", "verify_cose")
                                .error(Error::CoseTimeStampValidity)
                                .validation_status(validation_status::TIMESTAMP_OUTSIDE_VALIDITY);
                        validation_log.log(log_item, Some(Error::CoseTimeStampValidity))?;
                    }
                    _ => {
                        let log_item =
                            log_item!("Cose_Sign1", "error parsing timestamp", "verify_cose")
                                .error(Error::CoseInvalidTimeStamp);
                        validation_log.log(log_item, Some(Error::CoseInvalidTimeStamp))?;

                        return Err(Error::CoseInvalidTimeStamp);
                    }
                }
            }
        }
    }

    // Check the signature, which needs to have the same `additional_data` provided, by
    // providing a closure that can do the verify operation.
    sign1.verify_signature(additional_data, |sig, verify_data| -> Result<()> {
        if let Ok(issuer) = validate_with_cert(validator, sig, verify_data, der_bytes) {
            result.issuer_org = Some(issuer);
            result.validated = true;
            result.alg = Some(alg);

            // parse the temp time for now util we have TA
            result.date = get_signing_time(&sign1, data);
        }
        // Note: not adding validation_log entry here since caller will supply claim specific info to log
        Ok(())
    })?;

    Ok(result)
}

#[cfg(target_arch = "wasm32")]
pub fn verify_cose(
    _cose_bytes: &[u8],
    _data: &[u8],
    _additional_data: &[u8],
    _signature_only: bool,
    _validation_log: &mut impl StatusTracker,
) -> Result<ValidationInfo> {
    Err(Error::CoseVerifier)
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_with_cert(
    validator: Box<dyn CoseValidator>,
    sig: &[u8],
    data: &[u8],
    der_bytes: &[u8],
) -> Result<String> {
    // get the cert in der format
    let (_rem, signcert) =
        X509Certificate::from_der(der_bytes).map_err(|_err| Error::CoseInvalidCert)?;
    let pk = signcert.public_key();
    let pk_der = pk.raw;

    if validator.validate(sig, data, pk_der)? {
        Ok(extract_subject_from_cert(&signcert).unwrap_or_default())
    } else {
        Err(Error::CoseSignature)
    }
}

#[cfg(target_arch = "wasm32")]
async fn validate_with_cert_async(
    signing_alg: SigningAlg,
    sig: &[u8],
    data: &[u8],
    der_bytes: &[u8],
) -> Result<String> {
    let (_rem, signcert) =
        X509Certificate::from_der(der_bytes).map_err(|_err| Error::CoseMissingKey)?;
    let pk = signcert.public_key();
    let pk_der = pk.raw;

    if validate_async(signing_alg, sig, data, pk_der).await? {
        Ok(extract_subject_from_cert(&signcert).unwrap_or_default())
    } else {
        Err(Error::CoseSignature)
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn validate_with_cert_async(
    signing_alg: SigningAlg,
    sig: &[u8],
    data: &[u8],
    der_bytes: &[u8],
) -> Result<String> {
    // get the cert in der format
    let (_rem, signcert) =
        X509Certificate::from_der(der_bytes).map_err(|_err| Error::CoseInvalidCert)?;
    let pk = signcert.public_key();
    let pk_der = pk.raw;

    let validator = get_validator(signing_alg);

    if validator.validate(sig, data, pk_der)? {
        Ok(extract_subject_from_cert(&signcert).unwrap_or_default())
    } else {
        Err(Error::CoseSignature)
    }
}
#[allow(unused_imports)]
#[cfg(feature = "file_io")]
#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]

    use sha2::digest::generic_array::sequence::Shorten;

    use super::*;
    use crate::{status_tracker::DetailedStatusTracker, SigningAlg};

    #[test]
    #[cfg(feature = "file_io")]
    fn test_expired_cert() {
        let mut validation_log = DetailedStatusTracker::new();

        let mut cert_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cert_path.push("tests/fixtures/rsa-pss256_key-expired.pub");

        let expired_cert = std::fs::read(&cert_path).unwrap();

        if let Ok(signcert) = openssl::x509::X509::from_pem(&expired_cert) {
            let der_bytes = signcert.to_der().unwrap();
            assert!(check_cert(SigningAlg::Ps256, &der_bytes, &mut validation_log, None).is_err());

            assert!(!validation_log.get_log().is_empty());

            assert_eq!(
                validation_log.get_log()[0].validation_status,
                Some(validation_status::SIGNING_CREDENTIAL_EXPIRED.to_string())
            );
        }
    }

    #[test]
    fn test_verify_cose_good() {
        let validator = get_validator(SigningAlg::Ps256);

        let sig_bytes = include_bytes!("../tests/fixtures/sig_ps256.data");
        let data_bytes = include_bytes!("../tests/fixtures/data_ps256.data");
        let key_bytes = include_bytes!("../tests/fixtures/key_ps256.data");

        assert!(validator
            .validate(sig_bytes, data_bytes, key_bytes)
            .unwrap());
    }

    #[test]
    fn test_verify_ec_good() {
        // EC signatures
        let mut validator = get_validator(SigningAlg::Es384);

        let sig_es384_bytes = include_bytes!("../tests/fixtures/sig_es384.data");
        let data_es384_bytes = include_bytes!("../tests/fixtures/data_es384.data");
        let key_es384_bytes = include_bytes!("../tests/fixtures/key_es384.data");

        assert!(validator
            .validate(sig_es384_bytes, data_es384_bytes, key_es384_bytes)
            .unwrap());

        validator = get_validator(SigningAlg::Es512);

        let sig_es512_bytes = include_bytes!("../tests/fixtures/sig_es512.data");
        let data_es512_bytes = include_bytes!("../tests/fixtures/data_es512.data");
        let key_es512_bytes = include_bytes!("../tests/fixtures/key_es512.data");

        assert!(validator
            .validate(sig_es512_bytes, data_es512_bytes, key_es512_bytes)
            .unwrap());
    }

    #[test]
    fn test_verify_cose_bad() {
        let validator = get_validator(SigningAlg::Ps256);

        let sig_bytes = include_bytes!("../tests/fixtures/sig_ps256.data");
        let data_bytes = include_bytes!("../tests/fixtures/data_ps256.data");
        let key_bytes = include_bytes!("../tests/fixtures/key_ps256.data");

        let mut bad_bytes = data_bytes.to_vec();
        bad_bytes[0] = b'c';
        bad_bytes[1] = b'2';
        bad_bytes[2] = b'p';
        bad_bytes[3] = b'a';

        assert!(!validator
            .validate(sig_bytes, &bad_bytes, key_bytes)
            .unwrap());
    }

    #[test]
    #[cfg(feature = "file_io")]
    fn test_cert_algorithms() {
        let cert_dir = crate::utils::test::fixture_path("certs");

        use crate::openssl::temp_signer;

        let mut validation_log = DetailedStatusTracker::new();

        let (_, cert_path) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es256, None);
        let es256_cert = std::fs::read(&cert_path).unwrap();

        let (_, cert_path) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es384, None);
        let es384_cert = std::fs::read(&cert_path).unwrap();

        let (_, cert_path) = temp_signer::get_ec_signer(&cert_dir, SigningAlg::Es512, None);
        let es512_cert = std::fs::read(&cert_path).unwrap();

        let (_, cert_path) = temp_signer::get_rsa_signer(&cert_dir, SigningAlg::Ps256, None);
        let rsa_pss256_cert = std::fs::read(&cert_path).unwrap();

        if let Ok(signcert) = openssl::x509::X509::from_pem(&es256_cert) {
            let der_bytes = signcert.to_der().unwrap();
            assert!(check_cert(SigningAlg::Es256, &der_bytes, &mut validation_log, None).is_ok());
        }

        if let Ok(signcert) = openssl::x509::X509::from_pem(&es384_cert) {
            let der_bytes = signcert.to_der().unwrap();
            assert!(check_cert(SigningAlg::Es384, &der_bytes, &mut validation_log, None).is_ok());
        }

        if let Ok(signcert) = openssl::x509::X509::from_pem(&es512_cert) {
            let der_bytes = signcert.to_der().unwrap();
            assert!(check_cert(SigningAlg::Es512, &der_bytes, &mut validation_log, None).is_ok());
        }

        if let Ok(signcert) = openssl::x509::X509::from_pem(&rsa_pss256_cert) {
            let der_bytes = signcert.to_der().unwrap();
            assert!(check_cert(SigningAlg::Ps256, &der_bytes, &mut validation_log, None).is_ok());
        }
    }

    #[test]
    fn test_no_timestamp() {
        let mut validation_log = DetailedStatusTracker::new();

        let mut claim = crate::claim::Claim::new("extern_sign_test", Some("contentauth"));
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let box_size = 10000;

        let signer = crate::utils::test::temp_signer();

        let cose_bytes = crate::cose_sign::sign_claim(&claim_bytes, &signer, box_size).unwrap();

        let cose_sign1 = get_cose_sign1(&cose_bytes, &claim_bytes, &mut validation_log).unwrap();

        let signing_time = get_signing_time(&cose_sign1, &claim_bytes);

        assert_eq!(signing_time, None);
    }
}
