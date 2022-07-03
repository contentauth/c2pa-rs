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

use crate::Error;
use rustls::Certificate;
use rustls_pemfile::{read_one, Item};
use std::{
    io::{self, BufReader},
    iter,
};

pub(crate) struct AlgorithmData {
    pub rustls_id: rustls::SignatureScheme,
    pub verification_alg: &'static dyn ring::signature::VerificationAlgorithm,
    // This is because the Ring verification algorithm expects the key in a SubjectPublicKey, Openssl gives it in a SubjectPublicKeyInfo.
    // We can ask Openssl to give us that with RSAPublicKey_out, but that's (i) only for RSA, (ii) not what happens in existing tests.
    // https://github.com/briansmith/ring/issues/881#issuecomment-592749266
    pub spk_offset: usize,
}

pub(crate) fn get_algorithm_data(alg: &str) -> Result<AlgorithmData, Error> {
    match alg {
        "ps256" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PSS_SHA256,
            verification_alg: &ring::signature::RSA_PSS_2048_8192_SHA256,
            spk_offset: 24,
        }),
        "ps384" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PSS_SHA384,
            verification_alg: &ring::signature::RSA_PSS_2048_8192_SHA384,
            spk_offset: 24,
        }),
        "ps512" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PSS_SHA512,
            verification_alg: &ring::signature::RSA_PSS_2048_8192_SHA512,
            spk_offset: 24,
        }),
        "rs256" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PKCS1_SHA256,
            verification_alg: &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            spk_offset: 24,
        }),
        "rs384" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PKCS1_SHA384,
            verification_alg: &ring::signature::RSA_PKCS1_2048_8192_SHA384,
            spk_offset: 24,
        }),
        "rs512" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::RSA_PKCS1_SHA512,
            verification_alg: &ring::signature::RSA_PKCS1_2048_8192_SHA512,
            spk_offset: 24,
        }),
        "es256" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            verification_alg: &ring::signature::ECDSA_P256_SHA256_ASN1,
            spk_offset: 26,
        }),
        "es384" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            verification_alg: &ring::signature::ECDSA_P384_SHA384_ASN1,
            spk_offset: 23,
        }),
        "ed25519" => Ok(AlgorithmData {
            rustls_id: rustls::SignatureScheme::ED25519,
            verification_alg: &ring::signature::ED25519,
            spk_offset: 0,
        }),
        _ => Err(Error::RustlsUnknownAlgorithmError),
    }
}

/// Extract all certificates `signcert`.
///
/// This function returns at least an empty vector.
pub(crate) fn get_certificates(signcert: &[u8]) -> Vec<Certificate> {
    let mut pem_sections = BufReader::new(signcert);
    let mut signcerts = vec![];
    for item in iter::from_fn(|| read_one(&mut pem_sections).transpose()) {
        match item {
            Ok(item) => {
                if let Item::X509Certificate(cert) = item {
                    signcerts.push(Certificate(cert));
                }
            }
            Err(_e) => {}
        }
    }
    signcerts
}

/// Extract all ec-encoded private keys from `rd`, and return a vec of
/// Certificates containing the der-format contents.
///
/// This function returns at least an empty vector
pub(crate) fn get_ec_private_keys(pkey: &[u8]) -> Result<Vec<Certificate>, io::Error> {
    let mut reader = BufReader::new(pkey);
    let mut pkeys = vec![];

    // Get private key
    for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
        match item {
            Ok(item) => {
                if let Item::ECKey(cert) = item {
                    pkeys.push(Certificate(cert));
                }
            }
            Err(_e) => {}
        }
    }

    Ok(pkeys)
}
