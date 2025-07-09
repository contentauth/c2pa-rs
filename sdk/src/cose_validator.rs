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

use std::io::Write;

use async_generic::async_generic;
use x509_parser::{num_bigint::BigUint, prelude::*};

use crate::{
    crypto::{
        asn1::rfc3161::TstInfo,
        base64,
        cose::{
            cert_chain_from_sign1, parse_cose_sign1, signing_alg_from_sign1,
            signing_time_from_sign1, signing_time_from_sign1_async, validate_cose_tst_info,
            validate_cose_tst_info_async, CertificateInfo, CertificateTrustPolicy, Verifier,
        },
        raw_signature::SigningAlg,
    },
    error::{Error, Result},
    settings::get_settings_value,
    status_tracker::StatusTracker,
};

fn get_sign_cert(sign1: &coset::CoseSign1) -> Result<Vec<u8>> {
    // element 0 is the signing cert
    let certs = cert_chain_from_sign1(sign1)?;
    Ok(certs[0].clone())
}

/// Validate a COSE_SIGN1 byte vector and verify against expected data
/// cose_bytes - byte array containing the raw COSE_SIGN1 data
/// data:  data that was used to create the cose_bytes, these must match
/// addition_data: additional optional data that may have been used during signing
/// tst_info allows for overriding the timestamp, this is used by the timestamp assertion
/// returns - Ok on success
#[async_generic]
pub(crate) fn verify_cose(
    cose_bytes: &[u8],
    data: &[u8],
    additional_data: &[u8],
    cert_check: bool,
    ctp: &CertificateTrustPolicy,
    tst_info: Option<&TstInfo>,
    validation_log: &mut StatusTracker,
) -> Result<CertificateInfo> {
    let verifier = if cert_check {
        match get_settings_value::<bool>("verify.verify_trust") {
            Ok(true) => Verifier::VerifyTrustPolicy(ctp),
            _ => Verifier::VerifyCertificateProfileOnly(ctp),
        }
    } else {
        Verifier::IgnoreProfileAndTrustPolicy
    };

    let sign1 = parse_cose_sign1(cose_bytes, data, validation_log)?;

    // Timestamps failures are not fatal according to C2PA spec, we just need to log the state and use
    // the returned value unless an alternate timestamp is provided.  Timestamp certs are subject to the same
    // trust list checks as the signing certificate.
    let tst_info = match tst_info {
        Some(tst_info) => Some(tst_info.clone()),
        None => {
            if _sync {
                validate_cose_tst_info(&sign1, data, ctp, validation_log).ok()
            } else {
                validate_cose_tst_info_async(&sign1, data, ctp, validation_log)
                    .await
                    .ok()
            }
        }
    };

    if _sync {
        Ok(verifier.verify_signature(
            cose_bytes,
            data,
            additional_data,
            tst_info.as_ref(),
            validation_log,
        )?)
    } else {
        Ok(verifier
            .verify_signature_async(
                cose_bytes,
                data,
                additional_data,
                tst_info.as_ref(),
                validation_log,
            )
            .await?)
    }
}

// internal util function to dump the cert chain in PEM format
fn dump_cert_chain(certs: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut writer = Vec::new();

    let line_len = 64;
    let cert_begin = "-----BEGIN CERTIFICATE-----";
    let cert_end = "-----END CERTIFICATE-----";

    for der_bytes in certs {
        let cert_base_str = base64::encode(der_bytes);

        // break line into fixed len lines
        let cert_lines = cert_base_str
            .chars()
            .collect::<Vec<char>>()
            .chunks(line_len)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>();

        // write lines
        writer
            .write_fmt(format_args!("{cert_begin}\n"))
            .map_err(|_e| Error::UnsupportedType)?;
        for l in cert_lines {
            writer
                .write_fmt(format_args!("{l}\n"))
                .map_err(|_e| Error::UnsupportedType)?;
        }
        writer
            .write_fmt(format_args!("{cert_end}\n"))
            .map_err(|_e| Error::UnsupportedType)?;
    }

    Ok(writer)
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

#[allow(unused_variables)]
#[async_generic]
pub(crate) fn get_signing_info(
    cose_bytes: &[u8],
    data: &[u8],
    validation_log: &mut StatusTracker,
) -> CertificateInfo {
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
                            signing_time_from_sign1(&sign1, data)
                        } else {
                            signing_time_from_sign1_async(&sign1, data).await
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

    CertificateInfo {
        issuer_org,
        date,
        alg,
        validated: false,
        cert_chain: certs,
        cert_serial_number,
        revocation_status: None,
        iat: None,
    }
}

#[allow(unused_imports)]
#[allow(clippy::unwrap_used)]
#[cfg(test)]
pub mod tests {
    use ciborium::Value;
    use coset::Label;
    use sha2::digest::generic_array::sequence::Shorten;
    use x509_parser::{certificate::X509Certificate, pem::Pem};

    use super::*;
    use crate::{
        crypto::raw_signature::SigningAlg, status_tracker::StatusTracker,
        utils::test_signer::test_signer, Signer,
    };

    #[test]
    fn test_no_timestamp() {
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let mut validation_log = StatusTracker::default();

        let mut claim = crate::claim::Claim::new("extern_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let box_size = 10000;

        let signer = test_signer(SigningAlg::Ps256);

        let cose_bytes =
            crate::cose_sign::sign_claim(&claim_bytes, signer.as_ref(), box_size).unwrap();

        let cose_sign1 = parse_cose_sign1(&cose_bytes, &claim_bytes, &mut validation_log).unwrap();

        let signing_time = signing_time_from_sign1(&cose_sign1, &claim_bytes);

        assert_eq!(signing_time, None);
    }
    #[test]
    fn test_stapled_ocsp() {
        use crate::crypto::{
            raw_signature::{signer_from_cert_chain_and_private_key, RawSigner, RawSignerError},
            time_stamp::{TimeStampError, TimeStampProvider},
        };

        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let mut validation_log = StatusTracker::default();

        let mut claim = crate::claim::Claim::new("ocsp_sign_test", Some("contentauth"), 1);
        claim.build().unwrap();

        let claim_bytes = claim.data().unwrap();

        let sign_cert = include_bytes!("../tests/fixtures/certs/ps256.pub").to_vec();
        let pem_key = include_bytes!("../tests/fixtures/certs/ps256.pem").to_vec();
        let ocsp_rsp_data = include_bytes!("../tests/fixtures/ocsp_good.data");

        let raw_signer =
            signer_from_cert_chain_and_private_key(&sign_cert, &pem_key, SigningAlg::Ps256, None)
                .unwrap();

        // create a test signer that supports stapling
        struct OcspSigner {
            pub raw_signer: Box<dyn RawSigner>,
            pub ocsp_rsp: Vec<u8>,
        }

        impl crate::Signer for OcspSigner {
            fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
                Ok(self.raw_signer.sign(data)?)
            }

            fn alg(&self) -> SigningAlg {
                SigningAlg::Ps256
            }

            fn certs(&self) -> Result<Vec<Vec<u8>>> {
                Ok(self.raw_signer.cert_chain()?)
            }

            fn reserve_size(&self) -> usize {
                self.raw_signer.reserve_size()
            }

            fn ocsp_val(&self) -> Option<Vec<u8>> {
                Some(self.ocsp_rsp.clone())
            }
        }

        let ocsp_signer = OcspSigner {
            raw_signer,
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
