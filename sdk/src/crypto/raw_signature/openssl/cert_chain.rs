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

use openssl::x509::X509;

/// Macro for converting X509 certificate stack to DER format
macro_rules! cert_chain_to_der {
    ($cert_chain:expr) => {{
        $cert_chain
            .iter()
            .map(|cert| {
                cert.to_der().map_err(|_| {
                    crate::crypto::raw_signature::RawSignerError::CryptoLibraryError(
                        "could not encode certificate to DER".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<_>, crate::crypto::raw_signature::RawSignerError>>()
    }};
}

// Export cert_chain_to_der! macro
pub(crate) use cert_chain_to_der;

// Verify the certificate chain order.
//
// Return `true` if each cert in the chain can be verified as issued by the next
// issuer.
pub(crate) fn check_chain_order(certs: &[X509]) -> bool {
    // IMPORTANT: ffi_mutex::acquire() should have been called by calling fn. Please
    // don't make this pub or pub(crate) without finding a way to ensure that
    // precondition.

    let mut iter = certs.iter().peekable();

    while let Some(cert) = iter.next() {
        let Some(next) = iter.peek() else {
            break;
        };

        let Ok(pkey) = next.public_key() else {
            return false;
        };

        let Ok(verified) = cert.verify(&pkey) else {
            return false;
        };

        if !verified {
            return false;
        }
    }

    true
}

#[test]
#[cfg_attr(
    all(target_arch = "wasm32", not(target_os = "wasi")),
    wasm_bindgen_test
)]
#[cfg(feature = "openssl")]
fn cert_chain_to_der_macro() {
    use openssl::x509::X509;

    use crate::crypto::raw_signature::openssl::OpenSslMutex;

    let _openssl = OpenSslMutex::acquire().unwrap();

    let cert_chain_pem =
        include_bytes!("../../../../tests/fixtures/crypto/raw_signature/es256.pub");
    let cert_stack =
        X509::stack_from_pem(cert_chain_pem).expect("Certificate chain should be parsed to DER");

    assert!(
        !cert_stack.is_empty(),
        "Certificate stack should not be empty"
    );
    assert_eq!(
        cert_stack.len(),
        2,
        "Certificate stack should have two certificates"
    );
}
