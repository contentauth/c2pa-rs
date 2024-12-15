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

use crate::cose::CertificateAcceptancePolicy;

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

    // assert!(cap.has_allowed_eku(OCSP_SIGNING_OID).is_some());
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
