use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[path = "common/mod.rs"]
mod common;
use common::{Size, SIZES};

use c2pa::{Builder, CallbackSigner, SigningAlg};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
const MANIFEST_JSON: &str = include_str!("../tests/fixtures/simple_manifest.json");

fn create_signer() -> CallbackSigner {
    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS)
}

fn fixture(label: &str, ext: &str) -> Option<(PathBuf, u64)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches/fixtures")
        .join(format!("{label}-{ext}.{ext}"));
    match fs::metadata(&path) {
        Ok(metadata) => Some((path, metadata.len())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => panic!("{err}"),
    }
}

fn sign_jpeg(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign jpeg");
    let signer = create_signer();
    let mut builder = Builder::default().with_definition(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "jpg") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut src = fs::File::open(path).unwrap();
                builder.sign(&signer, "image/jpeg", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_png(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign png");
    let signer = create_signer();
    let mut builder = Builder::default().with_definition(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "png") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut src = fs::File::open(path).unwrap();
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
    let mut builder = Builder::default().with_definition(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "gif") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut src = fs::File::open(path).unwrap();
                builder.sign(&signer, "image/gif", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_tiff(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign tiff");
    let signer = create_signer();
    let mut builder = Builder::default().with_definition(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "tiff") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut src = fs::File::open(path).unwrap();
                builder.sign(&signer, "image/tiff", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_wav(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign wav");
    let signer = create_signer();
    let mut builder = Builder::default().with_definition(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "wav") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut src = fs::File::open(path).unwrap();
                builder.sign(&signer, "audio/wav", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_svg(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign svg");
    let signer = create_signer();
    let mut builder = Builder::default().with_definition(MANIFEST_JSON).unwrap();

    // TODO: add back large SVG when optimized, CI takes ~2 hours otherwise
    for label in &[Size::Small, Size::Medium] {
        let Some((path, size)) = fixture(label.as_str(), "svg") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut src = fs::File::open(path).unwrap();
                builder.sign(&signer, "image/svg+xml", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_mp3(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign mp3");
    let signer = create_signer();
    let mut builder = Builder::default().with_definition(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "mp3") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut src = fs::File::open(path).unwrap();
                builder.sign(&signer, "audio/mpeg", &mut src, &mut io::empty())
            })
        });
    }
    group.finish();
}

fn sign_mp4(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign mp4");
    let signer = create_signer();
    let mut builder = Builder::default().with_definition(MANIFEST_JSON).unwrap();

    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "mp4") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut src = fs::File::open(path).unwrap();
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
