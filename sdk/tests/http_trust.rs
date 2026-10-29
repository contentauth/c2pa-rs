// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

#![cfg(all(
    not(target_arch = "wasm32"),
    any(
        feature = "http_ureq",
        feature = "http_reqwest",
        feature = "http_reqwest_blocking"
    )
))]

use std::time::Duration;

use rustls_pki_types::{CertificateDer, UnixTime};

// Public diagnostic chains captured on 2026-10-20 from
// https://emudhra.we-have-a-problem.com/chains.zip; roots from its roots.json.
const CHAINS: [(&str, &[u8], &[u8]); 2] = [
    (
        "emSign",
        include_bytes!("fixtures/http_trust/emsign-chain.pem"),
        include_bytes!("fixtures/http_trust/emsign-root.pem"),
    ),
    (
        "Sectigo",
        include_bytes!("fixtures/http_trust/sectigo-chain.pem"),
        include_bytes!("fixtures/http_trust/sectigo-root.pem"),
    ),
];

fn certificates(pem_data: &[u8]) -> Vec<CertificateDer<'static>> {
    pem::parse_many(pem_data)
        .expect("valid public certificate fixtures")
        .into_iter()
        .map(|pem| CertificateDer::from(pem.into_contents()))
        .collect()
}

#[test]
fn https_roots_exclude_compromised_chain_issuers() {
    for (name, _, root_pem) in CHAINS {
        let roots = certificates(root_pem);
        let issuer = webpki::anchor_from_trusted_cert(&roots[0]).unwrap();
        assert!(
            !webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .any(|root| root.subject_public_key_info == issuer.subject_public_key_info),
            "{name} issuer must not be a bundled HTTPS trust anchor"
        );
    }
}

#[test]
fn https_verifier_rejects_compromised_keys_even_with_trusted_issuers() {
    for (name, chain_pem, root_pem) in CHAINS {
        let chain = certificates(chain_pem);
        let roots = certificates(root_pem);
        let anchors = [webpki::anchor_from_trusted_cert(&roots[0]).unwrap()];
        let leaf = webpki::EndEntityCert::try_from(&chain[0]).unwrap();

        // Evaluate within the fixture validity period so expiration cannot mask
        // missing key distrust. Restore the issuer to exercise both trust paths.
        let time = UnixTime::since_unix_epoch(Duration::from_secs(1_792_497_600));
        let result = leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &chain[1..],
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        );

        assert_eq!(
            result.err(),
            Some(webpki::Error::CertDistrusted),
            "{name} chain must be rejected because its key is distrusted"
        );
    }
}
