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

mod rsa_signer;
pub(crate) use rsa_signer::RsaSigner;

mod rsa_validator;
pub(crate) use rsa_validator::{RsaLegacyValidator, RsaValidator};

mod ec_signer;
pub(crate) use ec_signer::EcSigner;

mod ec_validator;
pub(crate) use ec_validator::EcValidator;

mod ed_signer;
pub(crate) use ed_signer::EdSigner;

mod ed_validator;
pub(crate) use ed_validator::EdValidator;

mod openssl_trust_handler;

pub(crate) use openssl_trust_handler::verify_trust;
pub use openssl_trust_handler::OpenSSLTrustHandlerConfig; // [scouten 2024-06-27: Hacking to make public.]

mod ffi_mutex;
pub(crate) use ffi_mutex::OpenSslMutex;
use openssl::x509::X509;

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
