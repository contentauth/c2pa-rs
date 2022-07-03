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

mod common;
pub mod rustls_signer;
pub mod signer;
pub mod temp_signer;
pub mod validator;
pub(crate) use rustls_signer::RustlsSigner;
pub(crate) use validator::Validator;
use x509_parser::prelude::{FromDer, X509Certificate};

use rustls::Certificate;

pub(crate) fn check_chain_order(certs: &Vec<Certificate>) -> bool {
    let chain_length = certs.len();
    if chain_length < 2 {
        return true;
    }

    for i in 1..(chain_length - 1) {
        let verifier_certificate = match X509Certificate::from_der(&certs[i].0) {
            Ok((_rem, verifier_certificate)) => verifier_certificate,
            Err(_) => {
                return false;
            }
        };
        let verified_certificate = match X509Certificate::from_der(&certs[i - 1].0) {
            Ok((_rem, verified_certificate)) => verified_certificate,
            Err(_) => {
                return false;
            }
        };
        let verifier_public_key = verifier_certificate.public_key();

        if verified_certificate
            .verify_signature(Some(verifier_public_key))
            .is_err()
        {
            return false;
        }
    }
    true
}
