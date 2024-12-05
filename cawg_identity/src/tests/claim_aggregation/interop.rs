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

use c2pa::ManifestStore;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

use crate::IdentityAssertion;

#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
async fn adobe_connected_identities() {
    let test_image = include_bytes!("../fixtures/claim_aggregation/adobe_connected_identities.jpg");

    let manifest_store = ManifestStore::from_bytes("jpg", test_image, true).unwrap();
    let validation_status = manifest_store.validation_status();

    #[cfg(target_arch = "wasm32")]
    {
        let log_str = format!("MS validation status = {validation_status:#?}");
        log(&log_str);
    }

    assert!(validation_status.is_none());

    let manifest = manifest_store.get_active().unwrap();
    let identity: IdentityAssertion = manifest.find_assertion("cawg.identity").unwrap();

    let _sp = identity.check_signer_payload(manifest).unwrap();
    identity.check_padding().unwrap();

    let report = identity.validate(manifest).await.unwrap();

    let sp = report.signer_payload;
    let ra = &sp.referenced_assertions;
    assert_eq!(ra.len(), 1);

    let ra1 = ra.first().unwrap();
    assert_eq!(ra1.url, "self#jumbf=c2pa.assertions/c2pa.hash.data");
    assert_eq!(ra1.alg, Some("sha256".to_owned()));

    assert_eq!(
        report.signer_payload.sig_type,
        "cawg.identity_claims_aggregation"
    );

    dbg!(&report.named_actor);

    for vi in report.named_actor.verified_identities() {
        dbg!(vi.type_());
    }
}
