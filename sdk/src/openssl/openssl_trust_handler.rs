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

use c2pa_crypto::{cose::CertificateAcceptancePolicy, openssl::OpenSslMutex};
use openssl::x509::verify::X509VerifyFlags;

use crate::Error;

fn certs_der_to_x509(ders: &[Vec<u8>]) -> crate::Result<Vec<openssl::x509::X509>> {
    // IMPORTANT: ffi_mutex::acquire() should have been called by calling fn. Please
    // don't make this pub or pub(crate) without finding a way to ensure that
    // precondition.

    let mut certs: Vec<openssl::x509::X509> = Vec::new();

    for d in ders {
        let cert = openssl::x509::X509::from_der(d)?;
        certs.push(cert);
    }

    Ok(certs)
}

// verify certificate and trust chain
pub(crate) fn verify_trust(
    cap: &CertificateAcceptancePolicy,
    chain_der: &[Vec<u8>],
    cert_der: &[u8],
    signing_time_epoc: Option<i64>,
) -> crate::Result<bool> {
    // check the cert against the allowed list first
    // TO DO: optimize by hashing the cert?
    if cap.end_entity_cert_ders().any(|der| der == cert_der) {
        return Ok(true);
    }

    let _openssl = OpenSslMutex::acquire()?;

    let mut cert_chain = openssl::stack::Stack::new().map_err(Error::OpenSslError)?;
    let mut store_ctx = openssl::x509::X509StoreContext::new().map_err(Error::OpenSslError)?;

    let chain = certs_der_to_x509(chain_der)?;
    for c in chain {
        cert_chain.push(c).map_err(Error::OpenSslError)?;
    }
    let cert = openssl::x509::X509::from_der(cert_der).map_err(Error::OpenSslError)?;

    let mut builder = openssl::x509::store::X509StoreBuilder::new().map_err(Error::OpenSslError)?;

    let mut verify_param =
        openssl::x509::verify::X509VerifyParam::new().map_err(Error::OpenSslError)?;
    if let Some(st) = signing_time_epoc {
        verify_param.set_time(st);
    } else {
        verify_param
            .set_flags(X509VerifyFlags::NO_CHECK_TIME)
            .map_err(Error::OpenSslError)?;
    }
    builder
        .set_param(&verify_param)
        .map_err(Error::OpenSslError)?;

    // add trust anchors
    let mut has_anchors = false;
    for der in cap.trust_anchor_ders() {
        let c = openssl::x509::X509::from_der(der).map_err(Error::OpenSslError)?;
        builder.add_cert(c)?;
        has_anchors = true
    }

    // finalize store
    let store = builder.build();

    if !has_anchors {
        return Ok(false);
    }

    match store_ctx.init(&store, cert.as_ref(), &cert_chain, |f| f.verify_cert()) {
        Ok(trust) => Ok(trust),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use c2pa_crypto::SigningAlg;

    use super::*;
    use crate::{utils::test_signer::test_signer, Signer};

    #[test]
    fn test_trust_store() {
        let mut cap = CertificateAcceptancePolicy::default();

        cap.add_trust_anchors(include_bytes!(
            "../../tests/fixtures/certs/trust/test_cert_root_bundle.pem"
        ))
        .unwrap();

        // test all the certs
        let ps256 = test_signer(SigningAlg::Ps256);
        let ps384 = test_signer(SigningAlg::Ps384);
        let ps512 = test_signer(SigningAlg::Ps512);
        let es256 = test_signer(SigningAlg::Es256);
        let es384 = test_signer(SigningAlg::Es384);
        let es512 = test_signer(SigningAlg::Es512);
        let ed25519 = test_signer(SigningAlg::Ed25519);

        let ps256_certs = ps256.certs().unwrap();
        let ps384_certs = ps384.certs().unwrap();
        let ps512_certs = ps512.certs().unwrap();
        let es256_certs = es256.certs().unwrap();
        let es384_certs = es384.certs().unwrap();
        let es512_certs = es512.certs().unwrap();
        let ed25519_certs = ed25519.certs().unwrap();

        assert!(verify_trust(&cap, &ps256_certs[1..], &ps256_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ps384_certs[1..], &ps384_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ps512_certs[1..], &ps512_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es256_certs[1..], &es256_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es384_certs[1..], &es384_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es512_certs[1..], &es512_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ed25519_certs[1..], &ed25519_certs[0], None).unwrap());
    }

    #[test]
    fn test_broken_trust_chain() {
        let cap = CertificateAcceptancePolicy::default();

        // test all the certs
        let ps256 = test_signer(SigningAlg::Ps256);
        let ps384 = test_signer(SigningAlg::Ps384);
        let ps512 = test_signer(SigningAlg::Ps512);
        let es256 = test_signer(SigningAlg::Es256);
        let es384 = test_signer(SigningAlg::Es384);
        let es512 = test_signer(SigningAlg::Es512);
        let ed25519 = test_signer(SigningAlg::Ed25519);

        let ps256_certs = ps256.certs().unwrap();
        let ps384_certs = ps384.certs().unwrap();
        let ps512_certs = ps512.certs().unwrap();
        let es256_certs = es256.certs().unwrap();
        let es384_certs = es384.certs().unwrap();
        let es512_certs = es512.certs().unwrap();
        let ed25519_certs = ed25519.certs().unwrap();

        assert!(!verify_trust(&cap, &ps256_certs[2..], &ps256_certs[0], None).unwrap());
        assert!(!verify_trust(&cap, &ps384_certs[2..], &ps384_certs[0], None).unwrap());
        assert!(!verify_trust(&cap, &ps384_certs[2..], &ps384_certs[0], None).unwrap());
        assert!(!verify_trust(&cap, &ps512_certs[2..], &ps512_certs[0], None).unwrap());
        assert!(!verify_trust(&cap, &es256_certs[2..], &es256_certs[0], None).unwrap());
        assert!(!verify_trust(&cap, &es384_certs[2..], &es384_certs[0], None).unwrap());
        assert!(!verify_trust(&cap, &es512_certs[2..], &es512_certs[0], None).unwrap());
        assert!(!verify_trust(&cap, &ed25519_certs[2..], &ed25519_certs[0], None).unwrap());
    }

    #[test]
    fn test_allowed_list() {
        let mut cap = CertificateAcceptancePolicy::default();

        cap.add_entity_credentials(include_bytes!(
            "../../tests/fixtures/certs/trust/allowed_list.pem"
        ))
        .unwrap();

        // test all the certs
        let ps256 = test_signer(SigningAlg::Ps256);
        let ps384 = test_signer(SigningAlg::Ps384);
        let ps512 = test_signer(SigningAlg::Ps512);
        let es256 = test_signer(SigningAlg::Es256);
        let es384 = test_signer(SigningAlg::Es384);
        let es512 = test_signer(SigningAlg::Es512);
        let ed25519 = test_signer(SigningAlg::Ed25519);

        let ps256_certs = ps256.certs().unwrap();
        let ps384_certs = ps384.certs().unwrap();
        let ps512_certs = ps512.certs().unwrap();
        let es256_certs = es256.certs().unwrap();
        let es384_certs = es384.certs().unwrap();
        let es512_certs = es512.certs().unwrap();
        let ed25519_certs = ed25519.certs().unwrap();

        assert!(verify_trust(&cap, &ps256_certs[1..], &ps256_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ps384_certs[1..], &ps384_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ps512_certs[1..], &ps512_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es256_certs[1..], &es256_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es384_certs[1..], &es384_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es512_certs[1..], &es512_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ed25519_certs[1..], &ed25519_certs[0], None).unwrap());
    }

    #[test]
    fn test_allowed_list_hashes() {
        let mut cap = CertificateAcceptancePolicy::default();

        cap.add_entity_credentials(include_bytes!(
            "../../tests/fixtures/certs/trust/allowed_list.hash"
        ))
        .unwrap();

        // test all the certs
        let ps256 = test_signer(SigningAlg::Ps256);
        let ps384 = test_signer(SigningAlg::Ps384);
        let ps512 = test_signer(SigningAlg::Ps512);
        let es256 = test_signer(SigningAlg::Es256);
        let es384 = test_signer(SigningAlg::Es384);
        let es512 = test_signer(SigningAlg::Es512);
        let ed25519 = test_signer(SigningAlg::Ed25519);

        let ps256_certs = ps256.certs().unwrap();
        let ps384_certs = ps384.certs().unwrap();
        let ps512_certs = ps512.certs().unwrap();
        let es256_certs = es256.certs().unwrap();
        let es384_certs = es384.certs().unwrap();
        let es512_certs = es512.certs().unwrap();
        let ed25519_certs = ed25519.certs().unwrap();

        assert!(verify_trust(&cap, &ps256_certs[1..], &ps256_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ps384_certs[1..], &ps384_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ps512_certs[1..], &ps512_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es256_certs[1..], &es256_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es384_certs[1..], &es384_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &es512_certs[1..], &es512_certs[0], None).unwrap());
        assert!(verify_trust(&cap, &ed25519_certs[1..], &ed25519_certs[0], None).unwrap());
    }
}
