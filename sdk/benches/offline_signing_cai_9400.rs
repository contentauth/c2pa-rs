// Refine the previous sign.rs example to test a broader suite of
// offline signing scenarios. (See CAI-9400 for details.)

// Invoke with:
//      cargo bench -p c2pa --bench offline_signing_cai_9400 -- --nocapture

use std::io::Cursor;
use std::fs::File;

use c2pa::{Builder, CallbackSigner, SigningAlg};
use criterion::{criterion_group, criterion_main, Criterion};

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
const MANIFEST_JSON: &str = include_str!("../tests/fixtures/simple_manifest.json");

fn create_signer() -> CallbackSigner {
    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS)
}

fn create_builder() -> Builder {
    Builder::from_json(MANIFEST_JSON).expect("failed to create builder from manifest JSON")
}

fn sign_jpeg_in_memory(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.jpg"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/jpeg";

    c.bench_function("Sign 100K JPEG in memory (Ed25519)", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_jpeg_on_disk(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let format = "image/jpeg";

    c.bench_function("Sign 100K JPEG to/from disk (Ed25519)", |b| {
        b.iter(|| {
            let mut source = File::open("/Users/scouten/Adobe/c2pa-rs/sdk/benches/fixtures/100kb.jpg").expect("Failed to open source file");
            let mut dest = File::create("/Users/scouten/Desktop/output.jpg").expect("Failed to create output file");
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_17mb_jpeg_in_memory(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("/Users/scouten/Adobe/cai-9400-benchmark-files/R-es-253-3578.jpg"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/jpeg";

    c.bench_function("Sign 17MB JPEG in memory (Ed25519)", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}
fn sign_17mb_jpeg_on_disk(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let format = "image/jpeg";

    c.bench_function("Sign 17MB JPEG to/from disk (Ed25519)", |b| {
        b.iter(|| {
            let mut source = File::open("/Users/scouten/Adobe/cai-9400-benchmark-files/R-es-253-3578.jpg").expect("Failed to open source file");
            let mut dest = File::create("/Users/scouten/Desktop/output.jpg").expect("Failed to create output file");
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

/*
fn sign_mp4(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let mut source = Cursor::new(include_bytes!("fixtures/100kb.mp4"));
    let mut dest = Cursor::new(Vec::new());
    let format = "video/mp4";

    c.bench_function("sign 100kb mp4", |b| {
        b.iter(|| {
            source.set_position(0);
            dest.set_position(0);
            dest.get_mut().clear();
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}
*/

criterion_group!(
    benches,
    sign_jpeg_in_memory,
    sign_jpeg_on_disk,
    sign_17mb_jpeg_in_memory,
    sign_17mb_jpeg_on_disk,
    /* sign_mp4, */
);

criterion_main!(benches);
