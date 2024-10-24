// Copyright 2024 Adobe. All rights reserved.
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

use rsa::{
    pss::Signature,
    sha2::Sha256,
    signature::{Keypair, Verifier},
};

use crate::{signer::ConfigurableSigner, wasm::RsaWasmSigner, Signer, SigningAlg};

#[test]
fn sign_ps256() {
    let cert_bytes = include_bytes!("../fixtures/test_certs/rs256.pub");
    let key_bytes = include_bytes!("../fixtures/test_certs/rs256.pem");

    let signer =
        RsaWasmSigner::from_signcert_and_pkey(cert_bytes, key_bytes, SigningAlg::Ps256, None)
            .unwrap();

    let data = b"some sample content to sign";

    let sig = signer.sign(data).unwrap();
    println!("signature len = {}", sig.len());
    assert!(sig.len() <= signer.reserve_size());

    let sk = rsa::pss::SigningKey::<Sha256>::new(signer.pkey.clone());
    let vk = sk.verifying_key();

    let signature: Signature = sig.as_slice().try_into().unwrap();
    assert!(vk.verify(data, &signature).is_ok());
}
