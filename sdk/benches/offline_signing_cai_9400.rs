// Refine the previous sign.rs example to test a broader suite of
// offline signing scenarios. (See CAI-9400 for details.)

// Invoke with:
//      cargo bench -p c2pa --bench offline_signing_cai_9400 -- --nocapture

use std::fs::File;

use c2pa::{Builder, CallbackSigner, SigningAlg};
use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

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

fn sign_jpeg(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let format = "image/jpeg";

    c.bench_function("Sign 100K JPEG (Ed25519)", |b| {
        b.iter(|| {
            let mut source = File::open("/Users/scouten/Adobe/c2pa-rs/sdk/benches/fixtures/100kb.jpg").expect("Failed to open source file");
            let mut dest = File::create("/Users/scouten/Desktop/output.jpg").expect("Failed to create output file");
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_17mb_jpeg(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let format = "image/jpeg";

    c.bench_function("Sign 17MB JPEG (Ed25519)", |b| {
        b.iter(|| {
            let mut source = File::open("/Users/scouten/Library/CloudStorage/OneDrive-Adobe/CAI-9400-assets/R-es-253-3578.jpg").expect("Failed to open source file");
            let mut dest = File::create("/Users/scouten/Desktop/output.jpg").expect("Failed to create output file");
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_148mb_mp4(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let format = "video/mp4";

    c.bench_function("Sign 148MB MP4 (Ed25519)", |b| {
        b.iter(|| {
            let mut source = File::open("/Users/scouten/Library/CloudStorage/OneDrive-Adobe/CAI-9400-assets/R-es-4642-097.mp4").expect("Failed to open source file");
            let mut dest = File::create("/Users/scouten/Desktop/output.jpg").expect("Failed to create output file");
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn sign_683mb_mp4(c: &mut Criterion) {
    let mut builder = create_builder();
    let signer = create_signer();
    let format = "video/mp4";

    c.bench_function("Sign 683MB MP4 (Ed25519)", |b| {
        b.iter(|| {
            let mut source = File::open("/Users/scouten/Library/CloudStorage/OneDrive-Adobe/CAI-9400-assets/R-es-4428-055.mp4").expect("Failed to open source file");
            let mut dest = File::create("/Users/scouten/Desktop/output.jpg").expect("Failed to create output file");
            builder.sign(&signer, format, &mut source, &mut dest)
        })
    });
}

fn custom_criterion() -> Criterion {
    Criterion::default().measurement_time(Duration::from_secs(30))
}

criterion_group! {
    name = benches;
    config = custom_criterion();
    targets = sign_jpeg,
    sign_17mb_jpeg,
    sign_148mb_mp4,
    sign_683mb_mp4,
}

criterion_main!(benches);
