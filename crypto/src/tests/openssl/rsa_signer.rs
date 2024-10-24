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
    openssl::RsaSigner, signer::ConfigurableSigner, tests::test_utils::temp_signer, Signer,
    SigningAlg,
};

#[test]
fn signer_from_files() {
    let signer = temp_signer();
    let data = b"some sample content to sign";

    let signature = signer.sign(data).unwrap();
    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());
}

#[test]
fn sign_ps256() {
    let cert_bytes = include_bytes!("../fixtures/test_certs/temp_cert.data");
    let key_bytes = include_bytes!("../fixtures/test_certs/temp_priv_key.data");

    let signer =
        RsaSigner::from_signcert_and_pkey(cert_bytes, key_bytes, SigningAlg::Ps256, None).unwrap();

    let data = b"some sample content to sign";

    let signature = signer.sign(data).unwrap();
    println!("signature len = {}", signature.len());
    assert!(signature.len() <= signer.reserve_size());
}

// #[test]
// fn sign_rs256() {
//     let cert_bytes =
// include_bytes!("../../tests/fixtures/temp_cert.data");
//     let key_bytes =
// include_bytes!("../../tests/fixtures/temp_priv_key.data");

//     let signer =
//         RsaSigner::from_signcert_and_pkey(cert_bytes, key_bytes,
// "rs256".to_string(), None)             .unwrap();

//     let data = b"some sample content to sign";

//     let signature = signer.sign(data).unwrap();
//     println!("signature len = {}", signature.len());
//     assert!(signature.len() <= signer.reserve_size());
// }
