#![cfg(not(target_os = "wasi"))]
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

#[cfg(feature = "openssl_sign")]
mod rsa_signer;
#[cfg(feature = "openssl_sign")]
pub(crate) use rsa_signer::RsaSigner;

#[cfg(feature = "openssl")]
mod rsa_validator;
#[cfg(feature = "openssl")]
pub(crate) use rsa_validator::RsaLegacyValidator;
#[cfg(feature = "openssl")]
pub(crate) use rsa_validator::RsaValidator;

#[cfg(feature = "openssl_sign")]
mod ec_signer;
#[cfg(feature = "openssl_sign")]
pub(crate) use ec_signer::EcSigner;

#[cfg(feature = "openssl")]
mod ec_validator;
#[cfg(feature = "openssl")]
pub(crate) use ec_validator::EcValidator;

#[cfg(feature = "openssl_sign")]
mod ed_signer;
#[cfg(feature = "openssl_sign")]
pub(crate) use ed_signer::EdSigner;

#[cfg(feature = "openssl")]
mod ed_validator;
#[cfg(feature = "openssl")]
pub(crate) use ed_validator::EdValidator;

#[cfg(feature = "openssl")]
mod openssl_trust_handler;
#[cfg(test)]
pub(crate) mod temp_signer;

#[cfg(feature = "openssl")]
pub(crate) use openssl_trust_handler::verify_trust;
#[cfg(feature = "openssl")]
pub(crate) use openssl_trust_handler::OpenSSLTrustHandlerConfig;

mod ffi_mutex;
pub(crate) use ffi_mutex::OpenSslMutex;

#[cfg(test)]
pub(crate) mod temp_signer_async;

#[cfg(feature = "openssl")]
use openssl::x509::X509;
#[cfg(test)]
#[allow(unused_imports)]
#[cfg(feature = "openssl")]
pub(crate) use temp_signer_async::AsyncSignerAdapter;

#[cfg(feature = "openssl")]
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
                        return false;
                    }
                }
            }
        }
        true
    }
}

#[cfg(not(feature = "openssl"))]
fn check_chain_order(certs: &[X509]) -> bool {
    true
}

#[cfg(feature = "openssl")]
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

#[cfg(not(feature = "openssl"))]
fn check_chain_order_der(cert_ders: &[Vec<u8>]) -> bool {
    true
}
