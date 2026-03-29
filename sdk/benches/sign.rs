use std::{
    fs,
    io::{self, Cursor},
    path::Path,
};

use c2pa::{Builder, CallbackSigner, SigningAlg};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
const MANIFEST_JSON: &str = include_str!("../tests/fixtures/simple_manifest.json");

const SIZES: &[&str] = &["small", "medium", "large"];

fn create_signer() -> CallbackSigner {
    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS)
}

// TODO: load into memory or as stream?
fn load(label: &str, ext: &str) -> Vec<u8> {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/fixtures");
    let path = fixtures_dir.join(format!("{label}-{ext}.{ext}"));
    assert!(path.exists(), "{label}-{ext}.{ext} not found");
    fs::read(&path).unwrap()
}

fn sign_jpeg(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign jpeg");
    let signer = create_signer();
    let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let data = load(label, "jpg");
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
    let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let data = load(label, "png");
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
    let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let data = load(label, "gif");
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
    let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let data = load(label, "tiff");
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
    let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let data = load(label, "wav");
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
    let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let data = load(label, "svg");
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
    let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let data = load(label, "mp3");
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
    let mut builder = Builder::from_json(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let data = load(label, "mp4");
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
