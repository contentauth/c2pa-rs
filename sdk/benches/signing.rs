use std::io::Cursor;

use c2pa::{Builder, CallbackSigner, SigningAlg};
use criterion::{criterion_group, criterion_main, Criterion};
const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
fn signing(c: &mut Criterion) {
    let mut builder = Builder::new();

    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    let mut source = Cursor::new(include_bytes!("fixtures/100_kb.jpg"));
    let mut dest = Cursor::new(Vec::new());
    let format = "image/jpeg";

    c.bench_function("sign 100kb jpeg", |b| {
        b.iter(|| builder.sign(&signer, format, &mut source, &mut dest))
    });
}

criterion_group!(benches, signing);
criterion_main!(benches);
