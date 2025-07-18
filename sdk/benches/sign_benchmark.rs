use std::io::Cursor;

use c2pa::{Builder, CallbackSigner, SigningAlg};
use criterion::{criterion_group, criterion_main, Criterion};
const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
fn sign_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    let mut builder = Builder::new();

    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);
    let mut source= Cursor::new(include_bytes!("100_kb.jpg"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/jpeg";

    group.sample_size(500);
    group.bench_function("sign 100kb jpeg", |b| b.iter(||builder.sign(&signer, format,&mut source,&mut dest)));
}

criterion_group!(benches, sign_benchmark);
criterion_main!(benches);