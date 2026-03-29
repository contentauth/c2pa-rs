use std::{fs, io::Cursor, path::Path};

use c2pa::Reader;
use criterion::{criterion_group, criterion_main, Criterion};

fn load_signed(label: &str, ext: &str) -> Vec<u8> {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/fixtures");
    let path = fixtures_dir.join(format!("{label}-signed.{ext}"));
    assert!(path.exists(), "{label}-signed.{ext} not found");
    fs::read(&path).unwrap()
}

fn wide_assertions(c: &mut Criterion) {
    let signed = load_signed("wide-assertions", "svg");
    c.bench_function("wide-assertions/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::from_stream("svg", &mut stream)
        })
    });
}

fn wide_ingredients(c: &mut Criterion) {
    let signed = load_signed("wide-ingredients", "svg");
    c.bench_function("wide-ingredients/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::from_stream("svg", &mut stream)
        })
    });
}

fn deep_ingredients(c: &mut Criterion) {
    let signed = load_signed("deep-ingredients", "svg");
    c.bench_function("deep-ingredients/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::from_stream("svg", &mut stream)
        })
    });
}

fn update_manifests(c: &mut Criterion) {
    let signed = load_signed("update-manifests", "svg");
    c.bench_function("update-manifests/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::from_stream("svg", &mut stream)
        })
    });
}

fn large_cbor_assertion(c: &mut Criterion) {
    let signed = load_signed("large-cbor-assertion", "svg");
    c.bench_function("large-cbor-assertion/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::from_stream("svg", &mut stream)
        })
    });
}

fn large_json_assertion(c: &mut Criterion) {
    let signed = load_signed("large-json-assertion", "svg");
    c.bench_function("large-json-assertion/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::from_stream("svg", &mut stream)
        })
    });
}

criterion_group!(
    benches,
    wide_assertions,
    wide_ingredients,
    deep_ingredients,
    update_manifests,
    large_cbor_assertion,
    large_json_assertion,
);
criterion_main!(benches);
