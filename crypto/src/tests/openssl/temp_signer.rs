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
    openssl::{EcSigner, EdSigner, RsaSigner},
    signer::ConfigurableSigner,
    SigningAlg,
};

/// Create an OpenSSL ES256 signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `alg` - A format for signing. Must be one of the `SigningAlg::Es*`
///   variants.
/// * `tsa_url` - Optional URL for a timestamp authority.
///
/// # Returns
///
/// Returns a tuple of `(signer, sign_cert_path)` where `signer` is
/// the [`Signer`] instance and `sign_cert_path` is the path to the
/// signing certificate.
///
/// # Panics
///
/// Can panic if unable to invoke OpenSSL executable properly.
pub(crate) fn get_ec_signer(alg: SigningAlg, tsa_url: Option<String>) -> EcSigner {
    let (sign_cert, pem_key) = match alg {
        SigningAlg::Es256 => (
            include_bytes!("../fixtures/test_certs/es256.pub").to_vec(),
            include_bytes!("../fixtures/test_certs/es256.pem").to_vec(),
        ),
        SigningAlg::Es384 => (
            include_bytes!("../fixtures/test_certs/es384.pub").to_vec(),
            include_bytes!("../fixtures/test_certs/es384.pem").to_vec(),
        ),
        SigningAlg::Es512 => (
            include_bytes!("../fixtures/test_certs/es512.pub").to_vec(),
            include_bytes!("../fixtures/test_certs/es512.pem").to_vec(),
        ),
        _ => {
            panic!("Unknown EC signer alg {alg:#?}");
        }
    };

    EcSigner::from_signcert_and_pkey(&sign_cert, &pem_key, alg, tsa_url).unwrap()
}

/// Create an OpenSSL ES256 signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `alg` - A format for signing. Must be `ed25519`.
/// * `tsa_url` - Optional URL for a timestamp authority.
///
/// # Returns
///
/// Returns a tuple of `(signer, sign_cert_path)` where `signer` is
/// the [`Signer`] instance and `sign_cert_path` is the path to the
/// signing certificate.
///
/// # Panics
///
/// Can panic if unable to invoke OpenSSL executable properly.
pub(crate) fn get_ed_signer(alg: SigningAlg, tsa_url: Option<String>) -> EdSigner {
    let (sign_cert, pem_key) = match alg {
        SigningAlg::Ed25519 => (
            include_bytes!("../fixtures/test_certs/ed25519.pub").to_vec(),
            include_bytes!("../fixtures/test_certs/ed25519.pem").to_vec(),
        ),
        _ => {
            panic!("Unknown ED signer alg {alg:#?}");
        }
    };

    EdSigner::from_signcert_and_pkey(&sign_cert, &pem_key, alg, tsa_url).unwrap()
}

/// Create an OpenSSL SHA+RSA signer that can be used for testing purposes.
///
/// # Arguments
///
/// * `alg` - A format for signing. Must be one of the `SignerAlg::Ps*` options.
/// * `tsa_url` - Optional URL for a timestamp authority.
///
/// # Returns
///
/// Returns a tuple of `(signer, sign_cert_path)` where `signer` is
/// the [`Signer`] instance and `sign_cert_path` is the path to the
/// signing certificate.
///
/// # Panics
///
/// Can panic if unable to invoke OpenSSL executable properly.
pub(crate) fn get_rsa_signer(alg: SigningAlg, tsa_url: Option<String>) -> RsaSigner {
    let (sign_cert, pem_key) = match alg {
        SigningAlg::Ps256 => (
            include_bytes!("../fixtures/test_certs/ps256.pub").to_vec(),
            include_bytes!("../fixtures/test_certs/ps256.pem").to_vec(),
        ),
        SigningAlg::Ps384 => (
            include_bytes!("../fixtures/test_certs/ps384.pub").to_vec(),
            include_bytes!("../fixtures/test_certs/ps384.pem").to_vec(),
        ),
        SigningAlg::Ps512 => (
            include_bytes!("../fixtures/test_certs/ps512.pub").to_vec(),
            include_bytes!("../fixtures/test_certs/ps512.pem").to_vec(),
        ),
        _ => {
            panic!("Unknown RSA signer alg {alg:#?}");
        }
    };

    RsaSigner::from_signcert_and_pkey(&sign_cert, &pem_key, alg, tsa_url).unwrap()
}
