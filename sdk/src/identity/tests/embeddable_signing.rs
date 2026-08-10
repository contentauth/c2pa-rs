// Copyright 2025 Adobe. All rights reserved.
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

//! Regression tests for issue #2055: identity assertions were silently dropped
//! by the split-signing (embeddable) paths because
//! `IdentityAssertionSigner::dynamic_assertions()` drained its list on the
//! first call.

use std::io::{Cursor, Seek, SeekFrom, Write};

use crate::{
    assertions::DataHash,
    crypto::raw_signature,
    identity::{
        builder::{IdentityAssertionBuilder, IdentityAssertionSigner},
        x509::X509CredentialHolder,
    },
    utils::test::write_jpeg_placeholder_stream,
    Builder, Context, HashRange, Reader, SigningAlg,
};

// A clean JPEG (no embedded manifest) used as the asset we sign.
const TEST_IMAGE: &[u8] = include_bytes!("../../../tests/fixtures/cloud.jpg");

// A JPEG that already carries a manifest, used as a parent ingredient so the v3
// ingredient requirements are satisfied.
const TEST_INGREDIENT: &[u8] = include_bytes!("../../../tests/fixtures/CA.jpg");
const TEST_THUMBNAIL: &[u8] = include_bytes!("../../../tests/fixtures/thumbnail.jpg");

/// Build an [`IdentityAssertionSigner`] (PS256 claim signer) that carries a
/// single CAWG X.509 (Ed25519) identity assertion.
fn identity_signer() -> IdentityAssertionSigner {
    let mut c2pa_signer = IdentityAssertionSigner::from_test_credentials(SigningAlg::Ps256);

    let (cawg_cert_chain, cawg_private_key) =
        super::fixtures::cert_chain_and_private_key_for_alg(SigningAlg::Ed25519);

    let cawg_raw_signer = raw_signature::signer_from_cert_chain_and_private_key(
        &cawg_cert_chain,
        &cawg_private_key,
        SigningAlg::Ed25519,
        None,
    )
    .unwrap();

    let x509_holder = X509CredentialHolder::from_raw_signer(cawg_raw_signer);
    c2pa_signer
        .add_identity_assertion(IdentityAssertionBuilder::for_credential_holder(x509_holder));

    c2pa_signer
}

/// A context whose signer is an [`IdentityAssertionSigner`] and whose settings
/// preserve raw `cawg.identity` assertion bytes so we can confirm the assertion
/// is present after signing.
fn identity_context() -> std::sync::Arc<Context> {
    let settings = crate::settings::Settings::default()
        .with_value("core.decode_identity_assertions", false)
        .unwrap();

    Context::new()
        .with_settings(settings)
        .unwrap()
        .with_signer(identity_signer())
        .into_shared()
}

fn has_identity_assertion(reader: &Reader) -> bool {
    reader
        .active_manifest()
        .unwrap()
        .assertions()
        .iter()
        .any(|a| a.label().starts_with("cawg.identity"))
}

/// Regression test for issue #2055.
///
/// The split-signing path (`Builder::placeholder` + `Builder::sign_embeddable`)
/// must include the `cawg.identity` assertion, matching what `Builder::sign`
/// produces. Before the fix, `dynamic_assertions()` drained on the first call,
/// so the second call (which writes the assertion content) saw an empty list
/// and the identity assertion was silently dropped.
#[test]
fn sign_embeddable_includes_identity_assertion() {
    let format = "image/jpeg";
    let context = identity_context();

    let mut builder = Builder::from_shared_context(&context)
        .with_definition(super::fixtures::manifest_json())
        .unwrap();
    builder
        .add_ingredient_from_stream(
            super::fixtures::parent_json(),
            format,
            &mut Cursor::new(TEST_INGREDIENT),
        )
        .unwrap();
    builder
        .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
        .unwrap();

    // Reserve placeholder space (this is the first `dynamic_assertions()` call).
    let composed_placeholder = builder.placeholder(format).unwrap();
    assert!(!composed_placeholder.is_empty());

    // Embed the composed placeholder in a real JPEG.
    let mut input_stream = Cursor::new(TEST_IMAGE);
    let mut output_stream = Cursor::new(Vec::new());
    let offset = write_jpeg_placeholder_stream(
        &composed_placeholder,
        format,
        &mut input_stream,
        &mut output_stream,
        None,
    )
    .unwrap();

    builder
        .set_data_hash_exclusions(vec![HashRange::new(
            offset as u64,
            composed_placeholder.len() as u64,
        )])
        .unwrap();
    output_stream.rewind().unwrap();
    builder
        .update_hash_from_stream(format, &mut output_stream)
        .unwrap();

    // Sign (this is the second `dynamic_assertions()` call, which must still
    // return the identity assertion).
    let signed_manifest = builder.sign_embeddable(format).unwrap();
    assert!(signed_manifest.len() <= composed_placeholder.len());

    // Patch the signed manifest over the placeholder.
    output_stream.seek(SeekFrom::Start(offset as u64)).unwrap();
    output_stream.write_all(&signed_manifest).unwrap();
    output_stream.rewind().unwrap();

    let reader = Reader::from_shared_context(&context)
        .with_stream(format, &mut output_stream)
        .unwrap();

    assert_eq!(reader.validation_status(), None);
    assert!(
        has_identity_assertion(&reader),
        "cawg.identity assertion missing from sign_embeddable() output"
    );
}

/// The data-hashed placeholder workflow cannot reserve space for dynamic
/// assertions, so signing with an [`IdentityAssertionSigner`] must fail loudly
/// rather than silently emit a manifest without the identity assertion.
#[test]
fn data_hashed_embeddable_rejects_identity_signer() {
    let format = "application/c2pa";
    let signer = identity_signer();

    let mut builder = Builder::default()
        .with_definition(super::fixtures::manifest_json())
        .unwrap();
    builder
        .add_ingredient_from_stream(
            super::fixtures::parent_json(),
            "image/jpeg",
            &mut Cursor::new(TEST_INGREDIENT),
        )
        .unwrap();
    builder
        .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
        .unwrap();

    let placeholder = builder
        .data_hashed_placeholder(crate::Signer::reserve_size(&signer), format)
        .unwrap();

    let mut dh = DataHash::new("source_hash", "sha256");
    dh.exclusions = Some(vec![HashRange::new(0, placeholder.len() as u64)]);
    let mut ph_stream = Cursor::new(placeholder.clone());
    dh.gen_hash_from_stream(&mut ph_stream).unwrap();

    let result = builder.sign_data_hashed_embeddable(&signer, &dh, format);

    assert!(
        result.is_err(),
        "sign_data_hashed_embeddable must reject a signer with dynamic assertions instead of \
         silently dropping them"
    );
}

/// The signer must return its identity assertions on every call, not just the
/// first (the root cause of issue #2055).
#[test]
fn dynamic_assertions_are_not_drained() {
    use crate::Signer;

    let signer = identity_signer();

    assert_eq!(signer.dynamic_assertions().len(), 1);
    assert_eq!(
        signer.dynamic_assertions().len(),
        1,
        "dynamic_assertions() must be idempotent across repeated calls"
    );
}
