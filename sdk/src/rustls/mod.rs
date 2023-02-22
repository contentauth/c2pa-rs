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
// use crate::{error::Result, Error};
use ring::signature;
use rustls::Certificate;
pub(crate) use rustls_signer::RustlsSigner;
pub(crate) use validator::Validator;
use x509_parser::parse_x509_certificate;

use self::common::certificate_to_alg;
use crate::rustls::common::get_algorithm_data;

pub(crate) fn check_chain_order(certs: &Vec<Certificate>) -> bool {
    match _check_chain_order_to_result(certs) {
        Ok(res) => res,
        Err(res) => res,
    }
}

pub(crate) fn _check_chain_order_to_result(certs: &Vec<Certificate>) -> Result<bool, bool> {
    let chain_length = certs.len();
    if chain_length < 2 {
        return Ok(true);
    }

    for i in 1..(chain_length - 1) {
        let (_, verifier_cert) = parse_x509_certificate(&certs[i].0).map_err(|_| false)?;
        let (_, verified_cert) = parse_x509_certificate(&certs[i - 1].0).map_err(|_| false)?;

        let alg_id = certificate_to_alg(&certs[i].0).map_err(|_| false)?;
        let algorithm_data = get_algorithm_data(&alg_id).map_err(|_| false)?;

        let verifier_spki = verifier_cert.public_key();
        let verifier_key = signature::UnparsedPublicKey::new(
            algorithm_data.verification_alg,
            &verifier_spki.subject_public_key.data,
        );

        let verified_sig = &verified_cert.signature_value.data;

        verifier_key
            .verify(verified_cert.tbs_certificate.as_ref(), verified_sig)
            .map_err(|_| false)?
    }
    Ok(true)
}
