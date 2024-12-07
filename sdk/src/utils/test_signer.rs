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

use c2pa_crypto::{raw_signature::signer_from_cert_chain_and_private_key, SigningAlg};

use crate::{signer::RawSignerWrapper, Signer};

/// Creates a [`Signer`] instance for testing purposes using test credentials.
pub(crate) fn test_signer(alg: SigningAlg) -> Box<dyn Signer> {
    let (cert_chain, private_key) = cert_chain_and_private_key_for_alg(alg);

    Box::new(RawSignerWrapper(
        signer_from_cert_chain_and_private_key(&cert_chain, &private_key, alg, None).unwrap(),
    ))
}

fn cert_chain_and_private_key_for_alg(alg: SigningAlg) -> (Vec<u8>, Vec<u8>) {
    match alg {
        SigningAlg::Ps256 => (
            include_bytes!("../../tests/fixtures/certs/ps256.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/ps256.pem").to_vec(),
        ),

        SigningAlg::Ps384 => (
            include_bytes!("../../tests/fixtures/certs/ps384.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/ps384.pem").to_vec(),
        ),

        SigningAlg::Ps512 => (
            include_bytes!("../../tests/fixtures/certs/ps512.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/ps512.pem").to_vec(),
        ),

        SigningAlg::Es256 => (
            include_bytes!("../../tests/fixtures/certs/es256.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/es256.pem").to_vec(),
        ),

        SigningAlg::Es384 => (
            include_bytes!("../../tests/fixtures/certs/es384.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/es384.pem").to_vec(),
        ),

        SigningAlg::Es512 => (
            include_bytes!("../../tests/fixtures/certs/es512.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/es512.pem").to_vec(),
        ),

        SigningAlg::Ed25519 => (
            include_bytes!("../../tests/fixtures/certs/ed25519.pub").to_vec(),
            include_bytes!("../../tests/fixtures/certs/ed25519.pem").to_vec(),
        ),
    }
}
