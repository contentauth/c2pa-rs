use std::{
    fs,
    io::{self, Cursor},
    path::Path,
    sync::Arc,
};

use c2pa::{Builder, CallbackSigner, Context, SigningAlg};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use serde_json::json;

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
const MANIFEST_JSON: &str = include_str!("../tests/fixtures/simple_manifest.json");

const SIZES: &[&str] = &["small", "medium", "large"];

fn create_signer() -> CallbackSigner {
    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS)
}

fn context() -> Arc<Context> {
    Context::new()
        .with_settings(json!({
            "verify": {
                "verify_after_sign": false
            }
        }))
        .unwrap()
        .into_shared()
}

fn load(label: &str, ext: &str) -> Option<Vec<u8>> {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/fixtures");
    let path = fixtures_dir.join(format!("{label}-{ext}.{ext}"));
    fs::read(&path).ok()
}

fn sign_jpeg(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign jpeg");
    let signer = create_signer();
    let context = context();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(MANIFEST_JSON)
        .unwrap();

    for label in SIZES {
        let Some(data) = load(label, "jpg") else {
            continue;
        };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut src = Cursor::new(data);
                builder.sign(&signer, "image/jpeg", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_png(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign png");
    let signer = create_signer();
    let context = context();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(MANIFEST_JSON)
        .unwrap();

    for label in SIZES {
        let Some(data) = load(label, "png") else {
            continue;
        };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut src = Cursor::new(data);
                builder
                    .sign(&signer, "image/png", &mut src, &mut io::empty())
                    .unwrap();
            })
        });
    }
    group.finish();
}

fn sign_gif(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign gif");
    let signer = create_signer();
    let context = context();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(MANIFEST_JSON)
        .unwrap();

    for label in SIZES {
        let Some(data) = load(label, "gif") else {
            continue;
        };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut src = Cursor::new(data);
                builder.sign(&signer, "image/gif", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_tiff(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign tiff");
    let signer = create_signer();
    let context = context();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(MANIFEST_JSON)
        .unwrap();

    for label in SIZES {
        let Some(data) = load(label, "tiff") else {
            continue;
        };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut src = Cursor::new(data);
                builder.sign(&signer, "image/tiff", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_wav(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign wav");
    let signer = create_signer();
    let context = context();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(MANIFEST_JSON)
        .unwrap();

    for label in SIZES {
        let Some(data) = load(label, "wav") else {
            continue;
        };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut src = Cursor::new(data);
                builder.sign(&signer, "audio/wav", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_svg(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign svg");
    let signer = create_signer();
    let context = context();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(MANIFEST_JSON)
        .unwrap();

    // TODO: add back large SVG when optimized, CI takes ~2 hours otherwise
    for label in &["small", "medium"] {
        let Some(data) = load(label, "svg") else {
            continue;
        };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut src = Cursor::new(data);
                builder.sign(&signer, "image/svg+xml", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_mp3(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign mp3");
    let signer = create_signer();
    let context = context();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(MANIFEST_JSON)
        .unwrap();

    for label in SIZES {
        let Some(data) = load(label, "mp3") else {
            continue;
        };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut src = Cursor::new(data);
                builder.sign(&signer, "audio/mpeg", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_mp4(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign mp4");
    let signer = create_signer();
    let context = context();
    let mut builder = Builder::from_shared_context(&context)
        .with_definition(MANIFEST_JSON)
        .unwrap();

    for label in SIZES {
        let Some(data) = load(label, "mp4") else {
            continue;
        };
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut src = Cursor::new(data);
                builder.sign(&signer, "video/mp4", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches, sign_png, sign_jpeg, sign_gif, sign_tiff, sign_wav, sign_svg, sign_mp3, sign_mp4
);
criterion_main!(benches);
