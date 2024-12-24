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

use std::io::Cursor;

use async_generic::async_generic;
use c2pa_crypto::{
    cose::{
        cert_chain_from_sign1, parse_cose_sign1, signing_alg_from_sign1, validate_cose_tst_info,
        validate_cose_tst_info_async, CertificateTrustPolicy, Verifier,
    },
    p1363::parse_ec_der_sig,
    raw_signature::{validator_for_signing_alg, RawSignatureValidator},
    SigningAlg, ValidationInfo,
};
use c2pa_status_tracker::{log_item, validation_codes::*, StatusTracker};
use coset::sig_structure_data;
use x509_parser::{num_bigint::BigUint, prelude::*};

use crate::{
    error::{Error, Result},
    settings::get_settings_value,
};

fn get_sign_cert(sign1: &coset::CoseSign1) -> Result<Vec<u8>> {
    // element 0 is the signing cert
    let certs = cert_chain_from_sign1(sign1)?;
    Ok(certs[0].clone())
}

// internal util function to dump the cert chain in PEM format
fn dump_cert_chain(certs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut out_buf: Vec<u8> = Vec::new();
    let mut writer = Cursor::new(out_buf);

    for der_bytes in certs {
        let c = x509_certificate::X509Certificate::from_der(der_bytes)
            .map_err(|_e| Error::UnsupportedType)?;
        c.write_pem(&mut writer)?;
    }
    out_buf = writer.into_inner();
    Ok(out_buf)
}

// Note: this function is only used to get the display string and not for cert validation.
#[async_generic]
fn get_signing_time(
    sign1: &coset::CoseSign1,
    data: &[u8],
) -> Option<chrono::DateTime<chrono::Utc>> {
    // get timestamp info if available

    let time_stamp_info = if _sync {
        validate_cose_tst_info(sign1, data)
    } else {
        validate_cose_tst_info_async(sign1, data).await
    };

    if let Ok(tst_info) = time_stamp_info {
        Some(gt_to_datetime(tst_info.gen_time))
    } else {
        None
    }
}

// test for unrecognized signatures
fn check_sig(sig: &[u8], alg: SigningAlg) -> Result<()> {
    match alg {
        SigningAlg::Es256 | SigningAlg::Es384 | SigningAlg::Es512 => {
            if parse_ec_der_sig(sig).is_ok() {
                // expected P1363 format
                return Err(Error::InvalidEcdsaSignature);
            }
        }
        _ => (),
    }
    Ok(())
}

/// A wrapper containing information of the signing cert.
pub(crate) struct CertInfo {
    /// The name of the identity the certificate is issued to.
    pub subject: String,
    /// The serial number of the cert. Will be unique to the CA.
    pub serial_number: BigUint,
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

/// Returns the unique serial number from the provided cert.
fn extract_serial_from_cert(cert: &X509Certificate) -> BigUint {
    cert.serial.clone()
}

/// Asynchronously validate a COSE_SIGN1 byte vector and verify against expected data
/// cose_bytes - byte array containing the raw COSE_SIGN1 data
/// data:  data that was used to create the cose_bytes, these must match
/// addition_data: additional optional data that may have been used during signing
/// returns - Ok on success
pub(crate) async fn verify_cose_async(
    cose_bytes: Vec<u8>,
    data: Vec<u8>,
    additional_data: Vec<u8>,
    cert_check: bool,
    ctp: &CertificateTrustPolicy,
    validation_log: &mut impl StatusTracker,
) -> Result<ValidationInfo> {
    let mut sign1 = parse_cose_sign1(&cose_bytes, &data, validation_log)?;

    let alg = match signing_alg_from_sign1(&sign1) {
        Ok(a) => a,
        Err(_) => {
            log_item!(
                "Cose_Sign1",
                "unsupported or missing Cose algorithm",
                "verify_cose_async"
            )
            .validation_status(ALGORITHM_UNSUPPORTED)
            .failure_no_throw(validation_log, Error::CoseSignatureAlgorithmNotSupported);

            // one of these must exist
            return Err(Error::CoseSignatureAlgorithmNotSupported);
        }
    };

    // build result structure
    let mut result = ValidationInfo::default();

    // get the cert chain
    let certs = cert_chain_from_sign1(&sign1)?;

    // get the public key der
    let der_bytes = &certs[0];

    let tst_info_res = validate_cose_tst_info_async(&sign1, &data).await;

    let verifier = if cert_check {
        match get_settings_value::<bool>("verify.verify_trust") {
            Ok(true) => Verifier::VerifyTrustPolicy(ctp),
            _ => Verifier::VerifyCertificateProfileOnly(ctp),
        }
    } else {
        Verifier::IgnoreProfileAndTrustPolicy
    };

    verifier
        .verify_profile_async(&sign1, &tst_info_res, validation_log)
        .await?;

    // TO REVIEW: Do we need the async case on non-WASM platforms?
    verifier
        .verify_trust_async(&sign1, &tst_info_res, validation_log)
        .await?;

    // check signature format
    if let Err(_e) = check_sig(&sign1.signature, alg) {
        log_item!("Cose_Sign1", "unsupported signature format", "verify_cose")
            .validation_status(SIGNING_CREDENTIAL_INVALID)
            .failure_no_throw(validation_log, Error::CoseSignatureAlgorithmNotSupported);

        // TO REVIEW: This could return e if OneShotStatusTracker is used. Hmmm.
        // validation_log.log(log_item, e)?;

        return Err(Error::CoseSignatureAlgorithmNotSupported);
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

    if let Ok(CertInfo {
        subject,
        serial_number,
    }) = validate_with_cert_async(alg, &sign1.signature, &tbs, der_bytes).await
    {
        result.issuer_org = Some(subject);
        result.cert_serial_number = Some(serial_number);
        result.validated = true;
        result.alg = Some(alg);

        result.date = tst_info_res.ok().map(|t| gt_to_datetime(t.gen_time));

        // return cert chain
        result.cert_chain = dump_cert_chain(&cert_chain_from_sign1(&sign1)?)?;
    }

    Ok(result)
}

#[allow(unused_variables)]
#[async_generic]
pub(crate) fn get_signing_info(
    cose_bytes: &[u8],
    data: &[u8],
    validation_log: &mut impl StatusTracker,
) -> ValidationInfo {
    let mut date = None;
    let mut issuer_org = None;
    let mut alg: Option<SigningAlg> = None;
    let mut cert_serial_number = None;

    let sign1 = match parse_cose_sign1(cose_bytes, data, validation_log) {
        Ok(sign1) => {
            // get the public key der
            match get_sign_cert(&sign1) {
                Ok(der_bytes) => {
                    if let Ok((_rem, signcert)) = X509Certificate::from_der(&der_bytes) {
                        date = if _sync {
                            get_signing_time(&sign1, data)
                        } else {
                            get_signing_time_async(&sign1, data).await
                        };
                        issuer_org = extract_subject_from_cert(&signcert).ok();
                        cert_serial_number = Some(extract_serial_from_cert(&signcert));
                        if let Ok(a) = signing_alg_from_sign1(&sign1) {
                            alg = Some(a);
                        }
                    };

                    Ok(sign1)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e.into()),
    };

    let certs = match sign1 {
        Ok(s) => match cert_chain_from_sign1(&s) {
            Ok(c) => dump_cert_chain(&c).unwrap_or_default(),
            Err(_) => Vec::new(),
        },
        Err(_e) => Vec::new(),
    };

    ValidationInfo {
        issuer_org,
        date,
        alg,
        validated: false,
        cert_chain: certs,
        cert_serial_number,
        revocation_status: None,
    }
}

/// Validate a COSE_SIGN1 byte vector and verify against expected data
/// cose_bytes - byte array containing the raw COSE_SIGN1 data
/// data:  data that was used to create the cose_bytes, these must match
/// addition_data: additional optional data that may have been used during signing
/// returns - Ok on success
pub(crate) fn verify_cose(
    cose_bytes: &[u8],
    data: &[u8],
    additional_data: &[u8],
    cert_check: bool,
    ctp: &CertificateTrustPolicy,
    validation_log: &mut impl StatusTracker,
) -> Result<ValidationInfo> {
    let sign1 = parse_cose_sign1(cose_bytes, data, validation_log)?;

    let alg = match signing_alg_from_sign1(&sign1) {
        Ok(a) => a,
        Err(_) => {
            log_item!(
                "Cose_Sign1",
                "unsupported or missing Cose algorithm",
                "verify_cose"
            )
            .validation_status(ALGORITHM_UNSUPPORTED)
            .failure_no_throw(validation_log, Error::CoseSignatureAlgorithmNotSupported);

            return Err(Error::CoseSignatureAlgorithmNotSupported);
        }
    };

    let Some(validator) = validator_for_signing_alg(alg) else {
        return Err(Error::CoseSignatureAlgorithmNotSupported);
    };

    // build result structure
    let mut result = ValidationInfo::default();

    // get the cert chain
    let certs = cert_chain_from_sign1(&sign1)?;

    // get the public key der
    let der_bytes = &certs[0];

    let tst_info_res = validate_cose_tst_info(&sign1, data);

    let verifier = if cert_check {
        match get_settings_value::<bool>("verify.verify_trust") {
            Ok(true) => Verifier::VerifyTrustPolicy(ctp),
            _ => Verifier::VerifyCertificateProfileOnly(ctp),
        }
    } else {
        Verifier::IgnoreProfileAndTrustPolicy
    };

    verifier.verify_profile(&sign1, &tst_info_res, validation_log)?;
    verifier.verify_trust(&sign1, &tst_info_res, validation_log)?;

    // check signature format
    if let Err(e) = check_sig(&sign1.signature, alg) {
        log_item!("Cose_Sign1", "unsupported signature format", "verify_cose")
            .validation_status(SIGNING_CREDENTIAL_INVALID)
            .failure_no_throw(validation_log, e);

        return Err(Error::CoseSignatureAlgorithmNotSupported);
    }

    // Check the signature, which needs to have the same `additional_data` provided, by
    // providing a closure that can do the verify operation.
    sign1.verify_signature(additional_data, |sig, verify_data| -> Result<()> {
        if let Ok(CertInfo {
            subject,
            serial_number,
        }) = validate_with_cert(validator, sig, verify_data, der_bytes)
        {
            result.issuer_org = Some(subject);
            result.cert_serial_number = Some(serial_number);
            result.validated = true;
            result.alg = Some(alg);

            result.date = tst_info_res.map(|t| gt_to_datetime(t.gen_time)).ok();

            // return cert chain
            result.cert_chain = dump_cert_chain(&certs)?;

            result.revocation_status = Some(true);
        }
        // Note: not adding validation_log entry here since caller will supply claim specific info to log
        Ok(())
    })?;

    Ok(result)
}

fn validate_with_cert(
    validator: Box<dyn RawSignatureValidator>,
    sig: &[u8],
    data: &[u8],
    der_bytes: &[u8],
) -> Result<CertInfo> {
    // get the cert in der format
    let (_rem, signcert) =
        X509Certificate::from_der(der_bytes).map_err(|_err| Error::CoseInvalidCert)?;
    let pk = signcert.public_key();
    let pk_der = pk.raw;

    validator.validate(sig, data, pk_der)?;

    Ok(CertInfo {
        subject: extract_subject_from_cert(&signcert).unwrap_or_default(),
        serial_number: extract_serial_from_cert(&signcert),
    })
}

#[cfg(target_arch = "wasm32")]
async fn validate_with_cert_async(
    signing_alg: SigningAlg,
    sig: &[u8],
    data: &[u8],
    der_bytes: &[u8],
) -> Result<CertInfo> {
    let (_rem, signcert) =
        X509Certificate::from_der(der_bytes).map_err(|_err| Error::CoseMissingKey)?;
    let pk = signcert.public_key();
    let pk_der = pk.raw;

    let Some(validator) = c2pa_crypto::webcrypto::async_validator_for_signing_alg(signing_alg)
    else {
        return Err(Error::UnknownAlgorithm);
    };

    validator.validate_async(sig, data, pk_der).await?;

    Ok(CertInfo {
        subject: extract_subject_from_cert(&signcert).unwrap_or_default(),
        serial_number: extract_serial_from_cert(&signcert),
    })
}

#[cfg(not(target_arch = "wasm32"))]
async fn validate_with_cert_async(
    signing_alg: SigningAlg,
    sig: &[u8],
    data: &[u8],
    der_bytes: &[u8],
) -> Result<CertInfo> {
    let Some(validator) = validator_for_signing_alg(signing_alg) else {
        return Err(Error::CoseSignatureAlgorithmNotSupported);
    };

    validate_with_cert(validator, sig, data, der_bytes)
}

fn gt_to_datetime(
    gt: x509_certificate::asn1time::GeneralizedTime,
) -> chrono::DateTime<chrono::Utc> {
    gt.into()
}

#[allow(unused_imports)]
#[allow(clippy::unwrap_used)]
#[cfg(feature = "openssl_sign")]
#[cfg(test)]
pub mod tests {
    use c2pa_crypto::SigningAlg;
    use c2pa_status_tracker::DetailedStatusTracker;
    use ciborium::Value;
    use coset::Label;
    use sha2::digest::generic_array::sequence::Shorten;
    use x509_parser::{certificate::X509Certificate, pem::Pem};

    use super::*;
    use crate::{utils::test_signer::test_signer, Signer};

    #[test]
    fn test_no_timestamp() {
        let mut validation_log = DetailedStatusTracker::default();

        let mut claim = crate::claim::Claim::new("extern_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let box_size = 10000;

        let signer = test_signer(SigningAlg::Ps256);

        let cose_bytes =
            crate::cose_sign::sign_claim(&claim_bytes, signer.as_ref(), box_size).unwrap();

        let cose_sign1 = parse_cose_sign1(&cose_bytes, &claim_bytes, &mut validation_log).unwrap();

        let signing_time = get_signing_time(&cose_sign1, &claim_bytes);

        assert_eq!(signing_time, None);
    }
    #[test]
    #[cfg(feature = "openssl_sign")]
    fn test_stapled_ocsp() {
        use c2pa_crypto::raw_signature::{
            signer_from_cert_chain_and_private_key, RawSigner, RawSignerError,
        };

        let mut validation_log = DetailedStatusTracker::default();

        let mut claim = crate::claim::Claim::new("ocsp_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let sign_cert = include_bytes!("../tests/fixtures/certs/ps256.pub").to_vec();
        let pem_key = include_bytes!("../tests/fixtures/certs/ps256.pem").to_vec();
        let ocsp_rsp_data = include_bytes!("../tests/fixtures/ocsp_good.data");

        let signer =
            signer_from_cert_chain_and_private_key(&sign_cert, &pem_key, SigningAlg::Ps256, None)
                .unwrap();

        // create a test signer that supports stapling
        struct OcspSigner {
            pub signer: Box<dyn crate::Signer>,
            pub ocsp_rsp: Vec<u8>,
        }

        impl crate::Signer for OcspSigner {
            fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
                self.signer.sign(data)
            }

            fn alg(&self) -> SigningAlg {
                SigningAlg::Ps256
            }

            fn certs(&self) -> Result<Vec<Vec<u8>>> {
                self.signer.certs()
            }

            fn reserve_size(&self) -> usize {
                self.signer.reserve_size()
            }

            fn ocsp_val(&self) -> Option<Vec<u8>> {
                Some(self.ocsp_rsp.clone())
            }
        }

        let ocsp_signer = OcspSigner {
            signer: Box::new(crate::signer::RawSignerWrapper(signer)),
            ocsp_rsp: ocsp_rsp_data.to_vec(),
        };

        // sign and staple
        let cose_bytes =
            crate::cose_sign::sign_claim(&claim_bytes, &ocsp_signer, ocsp_signer.reserve_size())
                .unwrap();

        let cose_sign1 = parse_cose_sign1(&cose_bytes, &claim_bytes, &mut validation_log).unwrap();
        let ocsp_stapled = get_ocsp_der(&cose_sign1).unwrap();

        assert_eq!(ocsp_rsp_data, ocsp_stapled.as_slice());
    }

    // get OCSP der
    fn get_ocsp_der(sign1: &coset::CoseSign1) -> Option<Vec<u8>> {
        if let Some(der) = sign1
            .unprotected
            .rest
            .iter()
            .find_map(|x: &(Label, Value)| {
                if x.0 == Label::Text("rVals".to_string()) {
                    Some(x.1.clone())
                } else {
                    None
                }
            })
        {
            match der {
                Value::Map(rvals_map) => {
                    // find OCSP value if available
                    rvals_map.iter().find_map(|x: &(Value, Value)| {
                        if x.0 == Value::Text("ocspVals".to_string()) {
                            x.1.as_array()
                                .and_then(|ocsp_rsp_val| ocsp_rsp_val.first())
                                .and_then(Value::as_bytes)
                                .cloned()
                        } else {
                            None
                        }
                    })
                }
                _ => None,
            }
        } else {
            None
        }
    }
}
