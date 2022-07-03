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

#![allow(dead_code)]

mod rsa_signer;
#[allow(unused_imports)]
pub(crate) use rsa_signer::RsaSigner;

mod rsa_validator;
#[allow(unused_imports)]
pub(crate) use rsa_validator::RsaValidator;

mod ec_signer;
#[allow(unused_imports)]
pub(crate) use ec_signer::EcSigner;

mod ec_validator;
#[allow(unused_imports)]
pub(crate) use ec_validator::EcValidator;

mod ed_signer;
#[allow(unused_imports)]
pub(crate) use ed_signer::EdSigner;

mod ed_validator;
#[allow(unused_imports)]
pub(crate) use ed_validator::EdValidator;

#[cfg(test)]
pub(crate) mod temp_signer;

#[cfg(test)]
pub(crate) mod temp_signer_async;

use openssl::x509::X509;
#[cfg(test)]
#[allow(unused_imports)]
#[cfg(feature = "async_signer")]
pub(crate) use temp_signer_async::AsyncSignerAdapter;

pub(crate) fn check_chain_order(certs: &[X509]) -> bool {
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

pub(crate) fn check_chain_order_der(cert_ders: &[Vec<u8>]) -> bool {
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
