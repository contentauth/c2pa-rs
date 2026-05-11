// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Heap-attribution test for `Builder::sign`.  Mirrors the c2pa-python
// `tests/benchmark_stress.py::test_stress_repeated_sign_no_leak`
// harness: 5 warmup signs, then 50 instrumented signs.  After the
// profiler drops, `dhat-heap.json` lands in the working directory
// — open it in the Firefox Profiler and sort by `t-gmax` (peak
// retained) to identify call sites responsible for residual RSS
// growth.
//
// Run with:
//     cd sdk && cargo test --release \
//       --features "dhat-heap,add_thumbnails,rust_native_crypto,http_reqwest_blocking" \
//       --test dhat_sign_loop -- --nocapture

#![cfg(feature = "dhat-heap")]

use std::io::{Cursor, Seek};

use c2pa::{
    crypto::raw_signature::{RawSignerError, SigningAlg},
    Builder, CallbackSigner,
};
use serde_json::json;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/C.jpg");
const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn ed_sign(data: &[u8], private_key: &[u8]) -> c2pa::Result<Vec<u8>> {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use pem::parse;

    let pem = parse(private_key).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    let key_bytes = &pem.contents()[16..];
    let signing_key = SigningKey::try_from(key_bytes)
        .map_err(|e| RawSignerError::InternalError(e.to_string()))?;
    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

fn make_signer() -> CallbackSigner {
    let cb = |_ctx: *const _, data: &[u8]| ed_sign(data, PRIVATE_KEY);
    CallbackSigner::new(cb, SigningAlg::Ed25519, CERTS)
        .set_tsa_url("http://timestamp.digicert.com")
}

fn manifest_def() -> String {
    json!({
        "claim_generator": "c2pa_dhat_test",
        "claim_generator_info": [{
            "name": "c2pa_dhat_test",
            "version": "0.0.1",
        }],
        "format": "image/jpeg",
        "title": "dhat sign loop",
        "ingredients": [],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {
                            "action": "c2pa.created",
                            "digitalSourceType":
                                "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation"
                        }
                    ]
                }
            }
        ]
    })
    .to_string()
}

fn do_sign_once(signer: &CallbackSigner, manifest: &str) {
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::<u8>::new());
    let mut builder = Builder::from_json(manifest).expect("builder from json");
    builder
        .sign(signer, "image/jpeg", &mut source, &mut dest)
        .expect("sign ok");
    // Match the Python harness: drop builder + bufs at end of loop body.
    drop(builder);
    let _ = dest.rewind();
}

#[test]
fn dhat_sign_loop() {
    let signer = make_signer();
    let manifest = manifest_def();

    // Warmup BEFORE the profiler so process-lifetime statics
    // (lazy resolvers, EKU sets, allocator pages) are not attributed
    // to the loop.
    for _ in 0..5 {
        do_sign_once(&signer, &manifest);
    }

    let _profiler = dhat::Profiler::new_heap();
    for _ in 0..50 {
        do_sign_once(&signer, &manifest);
    }
    drop(_profiler);
}
