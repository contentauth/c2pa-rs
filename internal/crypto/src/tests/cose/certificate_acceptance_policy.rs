// Copyright 2024 Adobe. All rights reserved.
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

use asn1_rs::{oid, Oid};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;
use x509_parser::prelude::ExtendedKeyUsage;

use crate::{
    cose::{CertificateAcceptancePolicy, InvalidCertificateError},
    raw_signature::signer::test_signer,
    SigningAlg,
};

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn impl_debug() {
    let cap = CertificateAcceptancePolicy::new();
    let _ = format!("{cap:#?}");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn new() {
    let cap = CertificateAcceptancePolicy::new();

    assert_eq!(
        cap.has_allowed_eku(&email_eku()).unwrap(),
        EMAIL_PROTECTION_OID
    );

    assert!(cap.has_allowed_eku(&document_signing_eku()).is_none());

    assert_eq!(
        cap.has_allowed_eku(&time_stamping_eku()).unwrap(),
        TIME_STAMPING_OID
    );

    assert_eq!(
        cap.has_allowed_eku(&ocsp_signing_eku()).unwrap(),
        OCSP_SIGNING_OID
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn default() {
    let cap = CertificateAcceptancePolicy::default();

    assert_eq!(
        cap.has_allowed_eku(&email_eku()).unwrap(),
        EMAIL_PROTECTION_OID
    );

    assert_eq!(
        cap.has_allowed_eku(&document_signing_eku()).unwrap(),
        DOCUMENT_SIGNING_OID
    );

    assert_eq!(
        cap.has_allowed_eku(&time_stamping_eku()).unwrap(),
        TIME_STAMPING_OID
    );

    assert_eq!(
        cap.has_allowed_eku(&ocsp_signing_eku()).unwrap(),
        OCSP_SIGNING_OID
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn clear() {
    let mut cap = CertificateAcceptancePolicy::default();
    cap.clear();

    assert_eq!(
        cap.has_allowed_eku(&email_eku()).unwrap(),
        EMAIL_PROTECTION_OID
    );

    assert!(cap.has_allowed_eku(&document_signing_eku()).is_none());

    assert_eq!(
        cap.has_allowed_eku(&time_stamping_eku()).unwrap(),
        TIME_STAMPING_OID
    );

    assert_eq!(
        cap.has_allowed_eku(&ocsp_signing_eku()).unwrap(),
        OCSP_SIGNING_OID
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn add_valid_ekus_err_bad_utf8() {
    let mut cap = CertificateAcceptancePolicy::new();
    cap.add_valid_ekus(&[128, 0]);

    assert_eq!(
        cap.has_allowed_eku(&email_eku()).unwrap(),
        EMAIL_PROTECTION_OID
    );

    assert!(cap.has_allowed_eku(&document_signing_eku()).is_none());

    assert_eq!(
        cap.has_allowed_eku(&time_stamping_eku()).unwrap(),
        TIME_STAMPING_OID
    );

    assert_eq!(
        cap.has_allowed_eku(&ocsp_signing_eku()).unwrap(),
        OCSP_SIGNING_OID
    );
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn add_trust_anchors_err_bad_pem() {
    let mut cap = CertificateAcceptancePolicy::new();
    assert!(cap.add_trust_anchors(BAD_PEM.as_bytes()).is_err());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn add_end_entity_credentials_err_bad_pem() {
    let mut cap = CertificateAcceptancePolicy::new();
    assert!(cap.add_end_entity_credentials(BAD_PEM.as_bytes()).is_err());
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn err_to_string() {
    let ice = InvalidCertificateError("foo".to_string());
    assert_eq!(ice.to_string(), "Unable to parse certificate list: foo");
}

#[test]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
fn err_debug() {
    let ice = InvalidCertificateError("foo".to_string());
    assert_eq!(
        format!("{ice:#?}"),
        "InvalidCertificateError(\n    \"foo\",\n)"
    );
}

fn email_eku() -> ExtendedKeyUsage<'static> {
    ExtendedKeyUsage {
        any: false,
        server_auth: false,
        client_auth: false,
        code_signing: false,
        email_protection: true,
        time_stamping: false,
        ocsp_signing: false,
        other: vec![],
    }
}

fn document_signing_eku() -> ExtendedKeyUsage<'static> {
    ExtendedKeyUsage {
        any: false,
        server_auth: false,
        client_auth: false,
        code_signing: false,
        email_protection: false,
        time_stamping: false,
        ocsp_signing: false,
        other: vec![DOCUMENT_SIGNING_OID.clone()],
    }
}

fn time_stamping_eku() -> ExtendedKeyUsage<'static> {
    ExtendedKeyUsage {
        any: false,
        server_auth: false,
        client_auth: false,
        code_signing: false,
        email_protection: false,
        time_stamping: true,
        ocsp_signing: false,
        other: vec![],
    }
}

fn ocsp_signing_eku() -> ExtendedKeyUsage<'static> {
    ExtendedKeyUsage {
        any: false,
        server_auth: false,
        client_auth: false,
        code_signing: false,
        email_protection: false,
        time_stamping: false,
        ocsp_signing: true,
        other: vec![],
    }
}

static EMAIL_PROTECTION_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .4);
static DOCUMENT_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .36);
static TIME_STAMPING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .8);
static OCSP_SIGNING_OID: Oid<'static> = oid!(1.3.6 .1 .5 .5 .7 .3 .9);

static BAD_PEM: &str = r#"
-----BEGIN CERTIFICATE-----
µIICEzCCAcWgAwIBAgIUW4fUnS38162x10PCnB8qFsrQuZgwBQYDK2VwMHcxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU29tZXdoZXJlMRowGAYD
VQQKDBFDMlBBIFRlc3QgUm9vdCBDQTEZMBcGA1UECwwQRk9SIFRFU1RJTkdfT05M
WTEQMA4GA1UEAwwHUm9vdCBDQTAeFw0yMjA2MTAxODQ2NDFaFw0zMjA2MDcxODQ2
NDFaMHcxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTESMBAGA1UEBwwJU29tZXdo
ZXJlMRowGAYDVQQKDBFDMlBBIFRlc3QgUm9vdCBDQTEZMBcGA1UECwwQRk9SIFRF
U1RJTkdfT05MWTEQMA4GA1UEAwwHUm9vdCBDQTAqMAUGAytlcAMhAGPUgK9q1H3D
eKMGqLGjTXJSpsrLpe0kpxkaFMe7KUAuo2MwYTAdBgNVHQ4EFgQUXuZWArP1jiRM
fgye6ZqRyGupTowwHwYDVR0jBBgwFoAUXuZWArP1jiRMfgye6ZqRyGupTowwDwYD
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwBQYDK2VwA0EA8E79g54u2fUy
dfVLPyqKmtjenOUMvVQD7waNbetLY7kvUJZCd5eaDghk30/Q1RaNjiP/2RfA/it8
zGxQnM2hCA==
-----END CERTIFICATE-----
"#;

#[test]
fn test_trust_store() {
    let cap = CertificateAcceptancePolicy::default();

    let ps256 = test_signer(SigningAlg::Ps256);
    let ps384 = test_signer(SigningAlg::Ps384);
    let ps512 = test_signer(SigningAlg::Ps512);
    let es256 = test_signer(SigningAlg::Es256);
    let es384 = test_signer(SigningAlg::Es384);
    let es512 = test_signer(SigningAlg::Es512);
    let ed25519 = test_signer(SigningAlg::Ed25519);

    let ps256_certs = ps256.cert_chain().unwrap();
    let ps384_certs = ps384.cert_chain().unwrap();
    let ps512_certs = ps512.cert_chain().unwrap();
    let es256_certs = es256.cert_chain().unwrap();
    let es384_certs = es384.cert_chain().unwrap();
    let es512_certs = es512.cert_chain().unwrap();
    let ed25519_certs = ed25519.cert_chain().unwrap();

    assert!(cap
        .validate_certificate(&ps256_certs[1..], &ps256_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&ps384_certs[1..], &ps384_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&ps512_certs[1..], &ps512_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&es256_certs[1..], &es256_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&es384_certs[1..], &es384_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&es512_certs[1..], &es512_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&ed25519_certs[1..], &ed25519_certs[0], None)
        .unwrap());
}

#[test]
fn test_broken_trust_chain() {
    let cap = CertificateAcceptancePolicy::default();

    let ps256 = test_signer(SigningAlg::Ps256);
    let ps384 = test_signer(SigningAlg::Ps384);
    let ps512 = test_signer(SigningAlg::Ps512);
    let es256 = test_signer(SigningAlg::Es256);
    let es384 = test_signer(SigningAlg::Es384);
    let es512 = test_signer(SigningAlg::Es512);
    let ed25519 = test_signer(SigningAlg::Ed25519);

    let ps256_certs = ps256.cert_chain().unwrap();
    let ps384_certs = ps384.cert_chain().unwrap();
    let ps512_certs = ps512.cert_chain().unwrap();
    let es256_certs = es256.cert_chain().unwrap();
    let es384_certs = es384.cert_chain().unwrap();
    let es512_certs = es512.cert_chain().unwrap();
    let ed25519_certs = ed25519.cert_chain().unwrap();

    // Break the trust chain by skipping the first intermediate CA.
    assert!(!cap
        .validate_certificate(&ps256_certs[2..], &ps256_certs[0], None)
        .unwrap());
    assert!(!cap
        .validate_certificate(&ps384_certs[2..], &ps384_certs[0], None)
        .unwrap());
    assert!(!cap
        .validate_certificate(&ps384_certs[2..], &ps384_certs[0], None)
        .unwrap());
    assert!(!cap
        .validate_certificate(&ps512_certs[2..], &ps512_certs[0], None)
        .unwrap());
    assert!(!cap
        .validate_certificate(&es256_certs[2..], &es256_certs[0], None)
        .unwrap());
    assert!(!cap
        .validate_certificate(&es384_certs[2..], &es384_certs[0], None)
        .unwrap());
    assert!(!cap
        .validate_certificate(&es512_certs[2..], &es512_certs[0], None)
        .unwrap());
    assert!(!cap
        .validate_certificate(&ed25519_certs[2..], &ed25519_certs[0], None)
        .unwrap());
}

#[test]
fn test_allowed_list() {
    let mut cap = CertificateAcceptancePolicy::new();

    cap.add_end_entity_credentials(include_bytes!("../fixtures/raw_signature/ed25519.pub"))
        .unwrap();
    cap.add_end_entity_credentials(include_bytes!("../fixtures/raw_signature/es256.pub"))
        .unwrap();
    cap.add_end_entity_credentials(include_bytes!("../fixtures/raw_signature/es384.pub"))
        .unwrap();
    cap.add_end_entity_credentials(include_bytes!("../fixtures/raw_signature/es512.pub"))
        .unwrap();
    cap.add_end_entity_credentials(include_bytes!("../fixtures/raw_signature/ps256.pub"))
        .unwrap();
    cap.add_end_entity_credentials(include_bytes!("../fixtures/raw_signature/ps384.pub"))
        .unwrap();
    cap.add_end_entity_credentials(include_bytes!("../fixtures/raw_signature/ps512.pub"))
        .unwrap();

    let ps256 = test_signer(SigningAlg::Ps256);
    let ps384 = test_signer(SigningAlg::Ps384);
    let ps512 = test_signer(SigningAlg::Ps512);
    let es256 = test_signer(SigningAlg::Es256);
    let es384 = test_signer(SigningAlg::Es384);
    let es512 = test_signer(SigningAlg::Es512);
    let ed25519 = test_signer(SigningAlg::Ed25519);

    let ps256_certs = ps256.cert_chain().unwrap();
    let ps384_certs = ps384.cert_chain().unwrap();
    let ps512_certs = ps512.cert_chain().unwrap();
    let es256_certs = es256.cert_chain().unwrap();
    let es384_certs = es384.cert_chain().unwrap();
    let es512_certs = es512.cert_chain().unwrap();
    let ed25519_certs = ed25519.cert_chain().unwrap();

    assert!(cap
        .validate_certificate(&ps256_certs[1..], &ps256_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&ps384_certs[1..], &ps384_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&ps512_certs[1..], &ps512_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&es256_certs[1..], &es256_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&es384_certs[1..], &es384_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&es512_certs[1..], &es512_certs[0], None)
        .unwrap());
    assert!(cap
        .validate_certificate(&ed25519_certs[1..], &ed25519_certs[0], None)
        .unwrap());
}
