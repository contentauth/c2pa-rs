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
        cert_chain_from_sign1, parse_cose_sign1, signing_alg_from_sign1, signing_time_from_sign1,
        signing_time_from_sign1_async, CertificateTrustPolicy, ValidationInfo, Verifier,
    },
    raw_signature::SigningAlg,
};
use c2pa_status_tracker::StatusTracker;
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

/// Validate a COSE_SIGN1 byte vector and verify against expected data
/// cose_bytes - byte array containing the raw COSE_SIGN1 data
/// data:  data that was used to create the cose_bytes, these must match
/// addition_data: additional optional data that may have been used during signing
/// returns - Ok on success
#[async_generic]
pub(crate) fn verify_cose(
    cose_bytes: &[u8],
    data: &[u8],
    additional_data: &[u8],
    cert_check: bool,
    ctp: &CertificateTrustPolicy,
    validation_log: &mut impl StatusTracker,
) -> Result<ValidationInfo> {
    let verifier = if cert_check {
        match get_settings_value::<bool>("verify.verify_trust") {
            Ok(true) => Verifier::VerifyTrustPolicy(ctp),
            _ => Verifier::VerifyCertificateProfileOnly(ctp),
        }
    } else {
        Verifier::IgnoreProfileAndTrustPolicy
    };

    Ok(verifier.verify_signature(cose_bytes, data, additional_data, validation_log)?)
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

#[allow(unused_imports)]
#[allow(clippy::unwrap_used)]
#[cfg(feature = "openssl_sign")]
#[cfg(test)]
pub mod tests {
    use c2pa_crypto::raw_signature::SigningAlg;
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

        let mut claim = crate::claim::Claim::new("extern_sign_test", Some("contentauth"));
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
    #[cfg(feature = "openssl_sign")]
    fn test_stapled_ocsp() {
        use c2pa_crypto::{
            raw_signature::{signer_from_cert_chain_and_private_key, RawSigner, RawSignerError},
            time_stamp::{TimeStampError, TimeStampProvider},
        };

        let mut validation_log = DetailedStatusTracker::default();

        let mut claim = crate::claim::Claim::new("ocsp_sign_test", Some("contentauth"));
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

            fn raw_signer(&self) -> Box<&dyn RawSigner> {
                Box::new(self)
            }
        }

        impl RawSigner for OcspSigner {
            fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
                self.raw_signer.sign(data)
            }

            fn alg(&self) -> SigningAlg {
                self.raw_signer.alg()
            }

            fn cert_chain(&self) -> std::result::Result<Vec<Vec<u8>>, RawSignerError> {
                self.raw_signer.cert_chain()
            }

            fn reserve_size(&self) -> usize {
                self.raw_signer.reserve_size()
            }

            fn ocsp_response(&self) -> Option<Vec<u8>> {
                eprintln!("THE ONE I WANTED @ 287");
                Some(self.ocsp_rsp.clone())
            }
        }

        impl TimeStampProvider for OcspSigner {
            fn time_stamp_service_url(&self) -> Option<String> {
                self.raw_signer.time_stamp_service_url()
            }

            fn time_stamp_request_headers(&self) -> Option<Vec<(String, String)>> {
                self.raw_signer.time_stamp_request_headers()
            }

            fn time_stamp_request_body(
                &self,
                message: &[u8],
            ) -> std::result::Result<Vec<u8>, TimeStampError> {
                self.raw_signer.time_stamp_request_body(message)
            }

            fn send_time_stamp_request(
                &self,
                message: &[u8],
            ) -> Option<std::result::Result<Vec<u8>, TimeStampError>> {
                self.raw_signer.send_time_stamp_request(message)
            }
        }

        let ocsp_signer = OcspSigner {
            raw_signer,
            ocsp_rsp: ocsp_rsp_data.to_vec(),
        };

        // sign and staple
        let cose_bytes = crate::cose_sign::sign_claim(
            &claim_bytes,
            &ocsp_signer,
            RawSigner::reserve_size(&ocsp_signer),
        )
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
