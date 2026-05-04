use std::{fs, io::Cursor, path::Path};

use c2pa::Reader;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

// const SIZES: &[&str] = &["small", "medium", "large"];
const SIZES: &[&str] = &["small"];

fn load(label: &str, ext: &str) -> Vec<u8> {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/fixtures");
    let path = fixtures_dir.join(format!("{label}-{ext}-signed.{ext}"));
    assert!(path.exists(), "{label}-{ext}-signed.{ext} not found");
    fs::read(&path).unwrap()
}

fn read_jpeg(c: &mut Criterion) {
    let mut group = c.benchmark_group("read jpeg");
    for label in SIZES {
        let data = load(label, "jpg");
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut stream = Cursor::new(data);
                Reader::default().with_stream("image/jpeg", &mut stream)
            })
        });
    }
    group.finish();
}

fn read_png(c: &mut Criterion) {
    let mut group = c.benchmark_group("read png");
    for label in SIZES {
        let data = load(label, "png");
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut stream = Cursor::new(data);
                Reader::default().with_stream("image/png", &mut stream)
            })
        });
    }
    group.finish();
}

fn read_gif(c: &mut Criterion) {
    let mut group = c.benchmark_group("read gif");
    for label in SIZES {
        let data = load(label, "gif");
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut stream = Cursor::new(data);
                Reader::default().with_stream("image/gif", &mut stream)
            })
        });
    }
    group.finish();
}

fn read_tiff(c: &mut Criterion) {
    let mut group = c.benchmark_group("read tiff");
    for label in SIZES {
        let data = load(label, "tiff");
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut stream = Cursor::new(data);
                Reader::default().with_stream("image/tiff", &mut stream)
            })
        });
    }
    group.finish();
}

fn read_svg(c: &mut Criterion) {
    let mut group = c.benchmark_group("read svg");
    for label in SIZES {
        let data = load(label, "svg");
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut stream = Cursor::new(data);
                Reader::default().with_stream("image/svg+xml", &mut stream)
            })
        });
    }
    group.finish();
}

fn read_mp3(c: &mut Criterion) {
    let mut group = c.benchmark_group("read mp3");
    for label in SIZES {
        let data = load(label, "mp3");
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut stream = Cursor::new(data);
                Reader::default().with_stream("audio/mpeg", &mut stream)
            })
        });
    }
    group.finish();
}

fn read_mp4(c: &mut Criterion) {
    let mut group = c.benchmark_group("read mp4");
    for label in SIZES {
        let data = load(label, "mp4");
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut stream = Cursor::new(data);
                Reader::default().with_stream("video/mp4", &mut stream)
            })
        });
    }
    group.finish();
}

fn read_wav(c: &mut Criterion) {
    let mut group = c.benchmark_group("read wav");
    for label in SIZES {
        let data = load(label, "wav");
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(*label, &data, |b, data| {
            b.iter(|| {
                let mut stream = Cursor::new(data);
                Reader::default().with_stream("audio/wav", &mut stream)
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches, read_jpeg, read_png, read_gif, read_tiff, read_svg, read_mp3, read_mp4, read_wav
);
criterion_main!(benches);
