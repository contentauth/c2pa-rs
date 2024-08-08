// Copyright 2023 Adobe. All rights reserved.
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

use wasm_bindgen_test::*;

use crate::{
    trust_config::trust_handler_config::{load_trust_from_data, TrustHandlerConfig},
    wasm::{webpki_trust_handler::verify_trust_async, WebTrustHandlerConfig},
};

#[wasm_bindgen_test]
async fn test_trust_store() {
    let mut th = WebTrustHandlerConfig::new();
    th.clear();

    th.load_default_trust().unwrap();

    // test all the certs
    let ps256 = include_bytes!("../fixtures/test_certs/ps256.pub");
    let ps384 = include_bytes!("../fixtures/test_certs/ps384.pub");
    let ps512 = include_bytes!("../fixtures/test_certs/ps512.pub");
    let es256 = include_bytes!("../fixtures/test_certs/es256.pub");
    let es384 = include_bytes!("../fixtures/test_certs/es384.pub");
    let es512 = include_bytes!("../fixtures/test_certs/es512.pub");
    let ed25519 = include_bytes!("../fixtures/test_certs/ed25519.pub");

    let ps256_certs = load_trust_from_data(ps256).unwrap();
    let ps384_certs = load_trust_from_data(ps384).unwrap();
    let ps512_certs = load_trust_from_data(ps512).unwrap();
    let es256_certs = load_trust_from_data(es256).unwrap();
    let es384_certs = load_trust_from_data(es384).unwrap();
    let es512_certs = load_trust_from_data(es512).unwrap();
    let ed25519_certs = load_trust_from_data(ed25519).unwrap();

    assert!(
        verify_trust_async(&th, &ps256_certs[1..], &ps256_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        verify_trust_async(&th, &ps384_certs[1..], &ps384_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        verify_trust_async(&th, &ps512_certs[1..], &ps512_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        verify_trust_async(&th, &es256_certs[1..], &es256_certs[0], None)
            .await
            .unwrap()
    );

    assert!(
        verify_trust_async(&th, &es384_certs[1..], &es384_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        verify_trust_async(&th, &es512_certs[1..], &es512_certs[0], None)
            .await
            .unwrap()
    );

    assert!(
        verify_trust_async(&th, &ed25519_certs[1..], &ed25519_certs[0], None)
            .await
            .unwrap()
    );
}

#[wasm_bindgen_test]
async fn test_trust_list_with_ee_cert() {
    // Coverage for case where verify_trust_async gets called
    // with end entity cert as part of the chain.
    let mut th = WebTrustHandlerConfig::new();
    th.clear();

    th.load_default_trust().unwrap();

    // Testing only one cert; this isn't about sig algorityms.
    let ps256 = include_bytes!("../fixtures/test_certs/ps256.pub");
    let ps256_certs = load_trust_from_data(ps256).unwrap();

    assert!(verify_trust_async(&th, &ps256_certs, &ps256_certs[0], None)
        .await
        .unwrap());
}

#[wasm_bindgen_test]
async fn test_broken_trust_chain() {
    let mut th = WebTrustHandlerConfig::new();
    th.clear();

    th.load_default_trust().unwrap();

    // test all the certs
    let ps256 = include_bytes!("../fixtures/test_certs/ps256.pub");
    let ps384 = include_bytes!("../fixtures/test_certs/ps384.pub");
    let ps512 = include_bytes!("../fixtures/test_certs/ps512.pub");
    let es256 = include_bytes!("../fixtures/test_certs/es256.pub");
    let es384 = include_bytes!("../fixtures/test_certs/es384.pub");
    let es512 = include_bytes!("../fixtures/test_certs/es512.pub");
    let ed25519 = include_bytes!("../fixtures/test_certs/ed25519.pub");

    let ps256_certs = load_trust_from_data(ps256).unwrap();
    let ps384_certs = load_trust_from_data(ps384).unwrap();
    let ps512_certs = load_trust_from_data(ps512).unwrap();
    let es256_certs = load_trust_from_data(es256).unwrap();
    let es384_certs = load_trust_from_data(es384).unwrap();
    let es512_certs = load_trust_from_data(es512).unwrap();
    let ed25519_certs = load_trust_from_data(ed25519).unwrap();

    assert!(
        !verify_trust_async(&th, &ps256_certs[2..], &ps256_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        !verify_trust_async(&th, &ps384_certs[2..], &ps384_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        !verify_trust_async(&th, &ps512_certs[2..], &ps512_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        !verify_trust_async(&th, &es256_certs[2..], &es256_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        !verify_trust_async(&th, &es384_certs[2..], &es384_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        !verify_trust_async(&th, &es512_certs[2..], &es512_certs[0], None)
            .await
            .unwrap()
    );
    assert!(
        !verify_trust_async(&th, &ed25519_certs[2..], &ed25519_certs[0], None)
            .await
            .unwrap()
    );
}
