use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[path = "common/mod.rs"]
mod common;
use common::{Size, SIZES};

use c2pa::Reader;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

fn fixture(label: &str, ext: &str) -> Option<(PathBuf, u64)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("benches/fixtures")
        .join(format!("{label}-{ext}-signed.{ext}"));
    match fs::metadata(&path) {
        Ok(metadata) => Some((path, metadata.len())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(err) => panic!("{err}"),
    }
}

fn read_jpeg(c: &mut Criterion) {
    let mut group = c.benchmark_group("read jpeg");
    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "jpg") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut file = fs::File::open(path).unwrap();
                Reader::default().with_stream("image/jpeg", &mut file)
            })
        });
    }
    group.finish();
}

fn read_png(c: &mut Criterion) {
    let mut group = c.benchmark_group("read png");
    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "png") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut file = fs::File::open(path).unwrap();
                Reader::default().with_stream("image/png", &mut file)
            })
        });
    }
    group.finish();
}

fn read_gif(c: &mut Criterion) {
    let mut group = c.benchmark_group("read gif");
    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "gif") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut file = fs::File::open(path).unwrap();
                Reader::default().with_stream("image/gif", &mut file)
            })
        });
    }
    group.finish();
}

fn read_tiff(c: &mut Criterion) {
    let mut group = c.benchmark_group("read tiff");
    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "tiff") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut file = fs::File::open(path).unwrap();
                Reader::default().with_stream("image/tiff", &mut file)
            })
        });
    }
    group.finish();
}

fn read_svg(c: &mut Criterion) {
    let mut group = c.benchmark_group("read svg");
    // TODO: add back large SVG when optimized, CI takes ~2 hours otherwise
    for label in &[Size::Small, Size::Medium] {
        let Some((path, size)) = fixture(label.as_str(), "svg") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut file = fs::File::open(path).unwrap();
                Reader::default().with_stream("image/svg+xml", &mut file)
            })
        });
    }
    group.finish();
}

fn read_mp3(c: &mut Criterion) {
    let mut group = c.benchmark_group("read mp3");
    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "mp3") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut file = fs::File::open(path).unwrap();
                Reader::default().with_stream("audio/mpeg", &mut file)
            })
        });
    }
    group.finish();
}

fn read_mp4(c: &mut Criterion) {
    let mut group = c.benchmark_group("read mp4");
    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "mp4") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut file = fs::File::open(path).unwrap();
                Reader::default().with_stream("video/mp4", &mut file)
            })
        });
    }
    group.finish();
}

fn read_wav(c: &mut Criterion) {
    let mut group = c.benchmark_group("read wav");
    for label in SIZES {
        let Some((path, size)) = fixture(label.as_str(), "wav") else {
            continue;
        };
        group.sample_size(label.sample_size());
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(label.as_str(), &path, |b, path| {
            b.iter(|| {
                let mut file = fs::File::open(path).unwrap();
                Reader::default().with_stream("audio/wav", &mut file)
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches, read_jpeg, read_png, read_gif, read_tiff, read_svg, read_mp3, read_mp4, read_wav
);
criterion_main!(benches);
