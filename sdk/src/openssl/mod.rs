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

#[cfg(feature = "_anyssl_sign")]
mod rsa_signer;
#[cfg(feature = "_anyssl_sign")]
pub(crate) use rsa_signer::RsaSigner;

#[cfg(feature = "_anyssl_sign")]
mod ec_signer;
#[cfg(feature = "_anyssl_sign")]
pub(crate) use ec_signer::EcSigner;

#[cfg(feature = "_anyssl_sign")]
mod ed_signer;
#[cfg(feature = "_anyssl_sign")]
pub(crate) use ed_signer::EdSigner;

#[cfg(feature = "_anyssl")]
mod openssl_trust_handler;
#[cfg(test)]
pub(crate) mod temp_signer;

#[cfg(feature = "_anyssl")]
pub(crate) use openssl_trust_handler::verify_trust;
#[cfg(feature = "_anyssl")]
pub(crate) use openssl_trust_handler::OpenSSLTrustHandlerConfig;

#[cfg(test)]
pub(crate) mod temp_signer_async;

#[cfg(feature = "_anyssl")]
#[cfg(feature = "boringssl")]
use boring as openssl;
use openssl::x509::X509;
#[cfg(test)]
#[allow(unused_imports)]
#[cfg(feature = "_anyssl_sign")]
pub(crate) use temp_signer_async::AsyncSignerAdapter;

#[cfg(feature = "_anyssl")]
fn check_chain_order(certs: &[X509]) -> bool {
    // IMPORTANT: ffi_mutex::acquire() should have been called by calling fn. Please
    // don't make this pub or pub(crate) without finding a way to ensure that
    // precondition.

    {
        if certs.len() > 1 {
            for (i, c) in certs.iter().enumerate() {
                if let Some(next_c) = certs.get(i + 1) {
                    if let Ok(pkey) = next_c.public_key() {
                        if let Ok(verified) = c.verify(&pkey) {
                            if !verified {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    } else {
                        if cfg!(all(test, feature = "boringssl")) {
                            // public_key() will fail on RSA-PSS in Boring.
                            // It's OK to skip this function, it's only a config sanity check.
                            continue;
                        }
                        return false;
                    }
                }
            }
        }
        true
    }
}

#[cfg(not(feature = "_anyssl"))]
fn check_chain_order(certs: &[X509]) -> bool {
    true
}

#[cfg(feature = "_anyssl")]
#[allow(dead_code)]
fn check_chain_order_der(cert_ders: &[Vec<u8>]) -> bool {
    // IMPORTANT: ffi_mutex::acquire() should have been called by calling fn. Please
    // don't make this pub or pub(crate) without finding a way to ensure that
    // precondition.

    let mut certs: Vec<X509> = Vec::new();
    for cert_der in cert_ders {
        if let Ok(cert) = X509::from_der(cert_der) {
            certs.push(cert);
        } else {
            return false;
        }
    }

    check_chain_order(&certs)
}

#[cfg(not(feature = "_anyssl"))]
fn check_chain_order_der(cert_ders: &[Vec<u8>]) -> bool {
    true
}
