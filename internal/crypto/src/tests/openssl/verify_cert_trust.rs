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

use crate::{
    cose::CertificateAcceptancePolicy, openssl::verify_cert_trust::verify_cert_trust,
    raw_signature::signer::test_signer, SigningAlg,
};

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

    assert!(verify_cert_trust(&cap, &ps256_certs[1..], &ps256_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &ps384_certs[1..], &ps384_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &ps512_certs[1..], &ps512_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &es256_certs[1..], &es256_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &es384_certs[1..], &es384_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &es512_certs[1..], &es512_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &ed25519_certs[1..], &ed25519_certs[0], None).unwrap());
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
    assert!(!verify_cert_trust(&cap, &ps256_certs[2..], &ps256_certs[0], None).unwrap());
    assert!(!verify_cert_trust(&cap, &ps384_certs[2..], &ps384_certs[0], None).unwrap());
    assert!(!verify_cert_trust(&cap, &ps384_certs[2..], &ps384_certs[0], None).unwrap());
    assert!(!verify_cert_trust(&cap, &ps512_certs[2..], &ps512_certs[0], None).unwrap());
    assert!(!verify_cert_trust(&cap, &es256_certs[2..], &es256_certs[0], None).unwrap());
    assert!(!verify_cert_trust(&cap, &es384_certs[2..], &es384_certs[0], None).unwrap());
    assert!(!verify_cert_trust(&cap, &es512_certs[2..], &es512_certs[0], None).unwrap());
    assert!(!verify_cert_trust(&cap, &ed25519_certs[2..], &ed25519_certs[0], None).unwrap());
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

    assert!(verify_cert_trust(&cap, &ps256_certs[1..], &ps256_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &ps384_certs[1..], &ps384_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &ps512_certs[1..], &ps512_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &es256_certs[1..], &es256_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &es384_certs[1..], &es384_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &es512_certs[1..], &es512_certs[0], None).unwrap());
    assert!(verify_cert_trust(&cap, &ed25519_certs[1..], &ed25519_certs[0], None).unwrap());
}
