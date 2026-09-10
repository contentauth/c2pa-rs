// Copyright 2026 Adobe. All rights reserved.
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

//! Builds and reads back a claim using only `c2pa_claim_builder`'s public surface (no direct
//! `use c2pa::...`), proving the re-export set is self-sufficient for an end-to-end
//! build-sign-embed-read-verify flow.

use std::{io::Cursor, sync::Arc};

use c2pa_claim_builder::{
    assertions::{c2pa_action, Action, Actions, BoxHash, DigitalSourceType},
    jumbf_io, ClaimAssertionBuilder, ClaimBuilder, Context, EphemeralSigner, StoreReader,
    ValidationState,
};

const TEST_IMAGE_CLEAN: &[u8] = include_bytes!("../../sdk/tests/fixtures/IMG_0003.jpg");

#[test]
fn roundtrip_via_claim_builder_public_api_only() {
    let signer = EphemeralSigner::new("c2pa-claim-builder-test").expect("ephemeral signer");
    let context = Arc::new(Context::new().with_signer(signer));

    let mut stream = Cursor::new(TEST_IMAGE_CLEAN);

    let mut claim_builder = ClaimBuilder::new(context.clone());
    claim_builder.set_title("c2pa_claim_builder roundtrip");

    let action = Action::new(c2pa_action::CREATED).set_source_type(DigitalSourceType::Empty);
    claim_builder
        .add_gathered_assertion(
            ClaimAssertionBuilder::from_assertion(&Actions::new().add_action(action))
                .expect("with_assertion"),
        )
        .expect("add actions assertion");

    claim_builder
        .add_created_assertion(
            ClaimAssertionBuilder::new(BoxHash::LABEL).with_stream("image/jpeg", &mut stream),
        )
        .expect("set hard binding");

    let jumbf = claim_builder.sign().expect("sign");

    let embedded = jumbf_io::save_jumbf_to_memory("image/jpeg", TEST_IMAGE_CLEAN, &jumbf)
        .expect("save jumbf to memory");

    let store_reader = StoreReader::new(context)
        .with_stream("image/jpeg", Cursor::new(embedded))
        .expect("read signed asset");

    // `EphemeralSigner`'s self-signed cert isn't in any trust list, so this is `Valid` (the
    // signature and structure check out) rather than `Trusted`.
    assert_eq!(store_reader.validation_state(), ValidationState::Valid);
    assert!(store_reader.is_embedded());

    let claim = store_reader.active_claim().expect("active claim");
    assert_eq!(claim.title(), Some("c2pa_claim_builder roundtrip"));
}
