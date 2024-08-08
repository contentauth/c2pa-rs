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

#![cfg(feature = "openssl")] // TO DO: Can we remove this?

use crate::{
    cose_validator::check_cert,
    status_tracker::{DetailedStatusTracker, StatusTracker},
    tests::openssl::temp_signer,
    validation_status,
    validator::get_validator,
    Signer, SigningAlg, TrustHandlerConfig,
};

#[test]
fn test_expired_cert() {
    let mut validation_log = DetailedStatusTracker::new();
    let th = crate::openssl::OpenSSLTrustHandlerConfig::new();

    let expired_cert = include_bytes!("fixtures/test_certs/rsa-pss256_key-expired.pub");

    if let Ok(signcert) = openssl::x509::X509::from_pem(expired_cert) {
        let der_bytes = signcert.to_der().unwrap();
        assert!(check_cert(&der_bytes, &th, &mut validation_log, None).is_err());

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

    let sig_bytes = include_bytes!("fixtures/test_certs/sig_ps256.data");
    let data_bytes = include_bytes!("fixtures/test_certs/data_ps256.data");
    let key_bytes = include_bytes!("fixtures/test_certs/key_ps256.data");

    assert!(validator
        .validate(sig_bytes, data_bytes, key_bytes)
        .unwrap());
}

#[test]
fn test_verify_ec_good() {
    // EC signatures
    let mut validator = get_validator(SigningAlg::Es384);

    let sig_es384_bytes = include_bytes!("fixtures/test_certs/sig_es384.data");
    let data_es384_bytes = include_bytes!("fixtures/test_certs/data_es384.data");
    let key_es384_bytes = include_bytes!("fixtures/test_certs/key_es384.data");

    assert!(validator
        .validate(sig_es384_bytes, data_es384_bytes, key_es384_bytes)
        .unwrap());

    validator = get_validator(SigningAlg::Es512);

    let sig_es512_bytes = include_bytes!("fixtures/test_certs/sig_es512.data");
    let data_es512_bytes = include_bytes!("fixtures/test_certs/data_es512.data");
    let key_es512_bytes = include_bytes!("fixtures/test_certs/key_es512.data");

    assert!(validator
        .validate(sig_es512_bytes, data_es512_bytes, key_es512_bytes)
        .unwrap());
}

#[test]
fn test_verify_cose_bad() {
    let validator = get_validator(SigningAlg::Ps256);

    let sig_bytes = include_bytes!("fixtures/test_certs/sig_ps256.data");
    let data_bytes = include_bytes!("fixtures/test_certs/data_ps256.data");
    let key_bytes = include_bytes!("fixtures/test_certs/key_ps256.data");

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
#[cfg(feature = "openssl")]
fn test_cert_algorithms() {
    let th = crate::openssl::OpenSSLTrustHandlerConfig::new();

    let mut validation_log = DetailedStatusTracker::new();

    let es256_cert = include_bytes!("../tests/fixtures/test_certs/es256.pub");
    let es384_cert = include_bytes!("../tests/fixtures/test_certs/es384.pub");
    let es512_cert = include_bytes!("../tests/fixtures/test_certs/es512.pub");

    if let Ok(signcert) = openssl::x509::X509::from_pem(es256_cert) {
        let der_bytes = signcert.to_der().unwrap();
        assert!(check_cert(&der_bytes, &th, &mut validation_log, None).is_ok());
    }

    if let Ok(signcert) = openssl::x509::X509::from_pem(es384_cert) {
        let der_bytes = signcert.to_der().unwrap();
        assert!(check_cert(&der_bytes, &th, &mut validation_log, None).is_ok());
    }

    if let Ok(signcert) = openssl::x509::X509::from_pem(es512_cert) {
        let der_bytes = signcert.to_der().unwrap();
        assert!(check_cert(&der_bytes, &th, &mut validation_log, None).is_ok());
    }

    let ps256_signer = temp_signer::get_rsa_signer(SigningAlg::Ps256, None);

    let ps256_cert = ps256_signer
        .certs()
        .ok()
        .and_then(|certs| certs.first().map(|s| s.to_owned()));

    if let Some(ps256_cert) = ps256_cert {
        if let Ok(signcert) = openssl::x509::X509::from_pem(&ps256_cert) {
            let der_bytes = signcert.to_der().unwrap();
            assert!(check_cert(&der_bytes, &th, &mut validation_log, None).is_ok());
        }
    }
}

/* TODO [scouten 2024-07-13]: Restore this w/o Claim.
#[test]
fn test_no_timestamp() {
    let mut validation_log = DetailedStatusTracker::new();

    let mut claim = crate::claim::Claim::new("extern_sign_test", Some("contentauth"));
    claim.build().unwrap();

    let claim_bytes = claim.data().unwrap();

    let box_size = 10000;

    let signer = crate::utils::test::temp_signer();

    let cose_bytes =
        crate::cose_sign::sign_claim(&claim_bytes, signer.as_ref(), box_size).unwrap();

    let cose_sign1 = get_cose_sign1(&cose_bytes, &claim_bytes, &mut validation_log).unwrap();

    let signing_time = get_signing_time(&cose_sign1, &claim_bytes);

    assert_eq!(signing_time, None);
}
*/

/* TODO [scouten 2024-07-13]: Restore this w/o Claim.
#[test]
#[cfg(feature = "openssl")]
fn test_stapled_ocsp() {
    let mut validation_log = DetailedStatusTracker::new();

    let mut claim = crate::claim::Claim::new("ocsp_sign_test", Some("contentauth"));
    claim.build().unwrap();

    let claim_bytes = claim.data().unwrap();

    let sign_cert = include_bytes!("../tests/fixtures/certs/ps256.pub").to_vec();
    let pem_key = include_bytes!("../tests/fixtures/certs/ps256.pem").to_vec();
    let ocsp_rsp_data = include_bytes!("../tests/fixtures/ocsp_good.data");

    let signer = crate::openssl::RsaSigner::from_signcert_and_pkey(
        &sign_cert,
        &pem_key,
        SigningAlg::Ps256,
        None,
    )
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
        signer: Box::new(signer),
        ocsp_rsp: ocsp_rsp_data.to_vec(),
    };

    // sign and staple
    let cose_bytes =
        crate::cose_sign::sign_claim(&claim_bytes, &ocsp_signer, ocsp_signer.reserve_size())
            .unwrap();

    let cose_sign1 = get_cose_sign1(&cose_bytes, &claim_bytes, &mut validation_log).unwrap();
    let ocsp_stapled = get_ocsp_der(&cose_sign1).unwrap();

    assert_eq!(ocsp_rsp_data, ocsp_stapled.as_slice());
}
*/
