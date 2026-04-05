// Benchmarks comparing standard Builder::sign() vs fast single-pass signing
// for BMFF (MP4), RIFF (WAV), and TIFF formats.

use std::io::Cursor;
use std::path::Path;

use c2pa::{
    sign_bmff_fast, sign_riff_fast, sign_tiff_fast, Builder, BuilderIntent, CallbackSigner,
    DigitalSourceType, SigningAlg,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn create_signer() -> CallbackSigner {
    let ed_signer =
        |_context: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS)
}

fn bench_mp4(c: &mut Criterion) {
    let source_bytes: &[u8] = include_bytes!("fixtures/100kb.mp4");
    let signer = create_signer();
    let mut group = c.benchmark_group("sign_mp4_100kb");

    group.bench_function("standard", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            let mut source = Cursor::new(source_bytes);
            let mut dest = Cursor::new(Vec::new());
            builder.sign(&signer, "video/mp4", &mut source, &mut dest).unwrap()
        })
    });

    group.bench_function("fast", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
            let mut source = Cursor::new(source_bytes);
            let mut dest = Cursor::new(Vec::new());
            sign_bmff_fast(&mut builder, &signer, "video/mp4", &mut source, &mut dest).unwrap()
        })
    });

    group.finish();
}

fn bench_wav(c: &mut Criterion) {
    let source_bytes: &[u8] = include_bytes!("fixtures/100kb.wav");
    let signer = create_signer();
    let mut group = c.benchmark_group("sign_wav_100kb");

    group.bench_function("standard", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            let mut source = Cursor::new(source_bytes);
            let mut dest = Cursor::new(Vec::new());
            builder.sign(&signer, "audio/wav", &mut source, &mut dest).unwrap()
        })
    });

    group.bench_function("fast", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
            let mut source = Cursor::new(source_bytes);
            let mut dest = Cursor::new(Vec::new());
            sign_riff_fast(&mut builder, &signer, "wav", &mut source, &mut dest).unwrap()
        })
    });

    group.finish();
}

fn bench_tiff(c: &mut Criterion) {
    let source_bytes: &[u8] = include_bytes!("fixtures/100kb.tiff");
    let signer = create_signer();
    let mut group = c.benchmark_group("sign_tiff_100kb");

    group.bench_function("standard", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            let mut source = Cursor::new(source_bytes);
            let mut dest = Cursor::new(Vec::new());
            builder.sign(&signer, "image/tiff", &mut source, &mut dest).unwrap()
        })
    });

    group.bench_function("fast", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
            let mut source = Cursor::new(source_bytes);
            let mut dest = Cursor::new(Vec::new());
            sign_tiff_fast(&mut builder, &signer, "tiff", &mut source, &mut dest).unwrap()
        })
    });

    group.finish();
}

fn bench_large_mp4(c: &mut Criterion) {
    let path = Path::new("/tmp/test_large.mp4");
    if !path.exists() {
        eprintln!("Skipping large MP4 benchmark: /tmp/test_large.mp4 not found");
        return;
    }
    let source_bytes = std::fs::read(path).unwrap();
    let size_mb = source_bytes.len() / (1024 * 1024);
    let signer = create_signer();
    let mut group = c.benchmark_group(format!("sign_mp4_{size_mb}mb"));
    group.sample_size(10);

    group.bench_function("standard", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            let mut source = Cursor::new(&source_bytes);
            let mut dest = Cursor::new(Vec::with_capacity(source_bytes.len() + 65536));
            builder.sign(&signer, "video/mp4", &mut source, &mut dest).unwrap()
        })
    });

    group.bench_function("fast", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
            let mut source = Cursor::new(&source_bytes);
            let mut dest = Cursor::new(Vec::with_capacity(source_bytes.len() + 65536));
            sign_bmff_fast(&mut builder, &signer, "video/mp4", &mut source, &mut dest).unwrap()
        })
    });

    group.finish();
}

fn bench_large_wav(c: &mut Criterion) {
    let path = Path::new("/tmp/test_large.wav");
    if !path.exists() {
        eprintln!("Skipping large WAV benchmark: /tmp/test_large.wav not found");
        return;
    }
    let source_bytes = std::fs::read(path).unwrap();
    let size_mb = source_bytes.len() / (1024 * 1024);
    let signer = create_signer();
    let mut group = c.benchmark_group(format!("sign_wav_{size_mb}mb"));
    group.sample_size(10);

    group.bench_function("standard", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            let mut source = Cursor::new(&source_bytes);
            let mut dest = Cursor::new(Vec::with_capacity(source_bytes.len() + 65536));
            builder.sign(&signer, "audio/wav", &mut source, &mut dest).unwrap()
        })
    });

    group.bench_function("fast", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
            let mut source = Cursor::new(&source_bytes);
            let mut dest = Cursor::new(Vec::with_capacity(source_bytes.len() + 65536));
            sign_riff_fast(&mut builder, &signer, "wav", &mut source, &mut dest).unwrap()
        })
    });

    group.finish();
}

fn bench_large_tiff(c: &mut Criterion) {
    let path = Path::new("/tmp/test_large.tif");
    if !path.exists() {
        eprintln!("Skipping large TIFF benchmark: /tmp/test_large.tif not found");
        return;
    }
    let source_bytes = std::fs::read(path).unwrap();
    let size_mb = source_bytes.len() / (1024 * 1024);
    let signer = create_signer();
    let mut group = c.benchmark_group(format!("sign_tiff_{size_mb}mb"));
    group.sample_size(10);

    group.bench_function("standard", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            let mut source = Cursor::new(&source_bytes);
            let mut dest = Cursor::new(Vec::with_capacity(source_bytes.len() + 65536));
            builder.sign(&signer, "image/tiff", &mut source, &mut dest).unwrap()
        })
    });

    group.bench_function("fast", |b| {
        b.iter(|| {
            let mut builder = Builder::from_json(include_str!("../tests/fixtures/simple_manifest.json")).unwrap();
            builder.set_intent(BuilderIntent::Create(DigitalSourceType::DigitalCapture));
            let mut source = Cursor::new(&source_bytes);
            let mut dest = Cursor::new(Vec::with_capacity(source_bytes.len() + 65536));
            sign_tiff_fast(&mut builder, &signer, "tiff", &mut source, &mut dest).unwrap()
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_mp4,
    bench_wav,
    bench_tiff,
    bench_large_mp4,
    bench_large_wav,
    bench_large_tiff
);
criterion_main!(benches);
