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

use c2pa_status_tracker::{validation_codes::SIGNING_CREDENTIAL_EXPIRED, StatusTracker};
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;
use x509_parser::pem::Pem;

use crate::cose::{check_certificate_profile, CertificateTrustPolicy};

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn expired_cert() {
    let ctp = CertificateTrustPolicy::default();
    let mut validation_log = StatusTracker::default();

    let cert_der = x509_der_from_pem(include_bytes!(
        "../fixtures/cose/rsa-pss256_key-expired.pub"
    ));

    assert!(check_certificate_profile(&cert_der, true, &ctp, &mut validation_log, None).is_err());

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

    let es256_cert = x509_der_from_pem(include_bytes!("../fixtures/raw_signature/es256.pub"));
    let es384_cert = x509_der_from_pem(include_bytes!("../fixtures/raw_signature/es384.pub"));
    let es512_cert = x509_der_from_pem(include_bytes!("../fixtures/raw_signature/es512.pub"));
    let ps256_cert = x509_der_from_pem(include_bytes!("../fixtures/raw_signature/ps256.pub"));

    check_certificate_profile(&es256_cert, true, &ctp, &mut validation_log, None).unwrap();
    check_certificate_profile(&es384_cert, true, &ctp, &mut validation_log, None).unwrap();
    check_certificate_profile(&es512_cert, true, &ctp, &mut validation_log, None).unwrap();
    check_certificate_profile(&ps256_cert, true, &ctp, &mut validation_log, None).unwrap();
}

fn x509_der_from_pem(cert_pem: &[u8]) -> Vec<u8> {
    let mut pems = Pem::iter_from_buffer(cert_pem);
    let pem = pems.next().unwrap().unwrap();
    pem.contents
}
