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

use c2pa_status_tracker::StatusTracker;
use chrono::{TimeZone, Utc};
#[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
use wasm_bindgen_test::wasm_bindgen_test;

use crate::ocsp::{make_ocsp_cert_id, OcspError, OcspResponse};

fn get_ocsp_certs() -> Vec<Vec<u8>> {
    let cert_contents = include_bytes!("fixtures/ocsp/ocsp_chain.pem");

    let cert_chain = x509_parser::pem::Pem::iter_from_buffer(cert_contents)
        .map(|r| match r {
            Ok(pem) => Ok(pem.contents),
            Err(_e) => Ok(Vec::new()),
        })
        .collect::<Result<Vec<Vec<u8>>, x509_parser::error::PEMError>>();

    cert_chain.unwrap_or_default()
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn good() {
    let rsp_data = include_bytes!("fixtures/ocsp/response_good.der");

    let cert_id = make_ocsp_cert_id(&get_ocsp_certs());

    let mut validation_log = StatusTracker::default();

    let test_time = Utc.with_ymd_and_hms(2023, 2, 1, 8, 0, 0).unwrap();

    let ocsp_data =
        OcspResponse::from_der_checked(rsp_data, cert_id, Some(test_time), &mut validation_log)
            .unwrap();

    assert_eq!(ocsp_data.revoked_at, None);
    assert!(ocsp_data.ocsp_certs.is_some());
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn revoked() {
    let rsp_data = include_bytes!("fixtures/ocsp/response_revoked.der");
    let cert_id = make_ocsp_cert_id(&get_ocsp_certs());

    let mut validation_log = StatusTracker::default();

    let test_time = Utc.with_ymd_and_hms(2024, 2, 1, 8, 0, 0).unwrap();

    let ocsp_data =
        OcspResponse::from_der_checked(rsp_data, cert_id, Some(test_time), &mut validation_log)
            .unwrap();

    assert!(ocsp_data.revoked_at.is_some());
    assert!(validation_log.has_error(OcspError::CertificateRevoked));
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
fn unknown() {
    let rsp_data = include_bytes!("fixtures/ocsp/response_unknown.der");
    let cert_id = make_ocsp_cert_id(&get_ocsp_certs());

    let mut validation_log = StatusTracker::default();

    let test_time = Utc.with_ymd_and_hms(2024, 2, 1, 8, 0, 0).unwrap();

    let _ocsp_data =
        OcspResponse::from_der_checked(rsp_data, cert_id, Some(test_time), &mut validation_log);

    assert!(validation_log.has_error(OcspError::CertificateStatusUnknown));
}
