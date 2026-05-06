use std::{fs, io::Cursor, path::Path};

use c2pa::Reader;
use criterion::{criterion_group, criterion_main, Criterion};

fn load_signed(label: &str, ext: &str) -> Option<Vec<u8>> {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("benches/fixtures");
    let path = fixtures_dir.join(format!("{label}-signed.{ext}"));
    fs::read(&path).ok()
}

fn wide_assertions(c: &mut Criterion) {
    let Some(signed) = load_signed("wide-assertions", "c2pa") else {
        return;
    };
    c.bench_function("wide-assertions/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::default().with_stream("application/c2pa", &mut stream)
        })
    });
}

fn wide_ingredients(c: &mut Criterion) {
    let Some(signed) = load_signed("wide-ingredients", "c2pa") else {
        return;
    };
    c.bench_function("wide-ingredients/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::default().with_stream("application/c2pa", &mut stream)
        })
    });
}

fn deep_ingredients(c: &mut Criterion) {
    let Some(signed) = load_signed("deep-ingredients", "c2pa") else {
        return;
    };
    c.bench_function("deep-ingredients/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::default().with_stream("application/c2pa", &mut stream)
        })
    });
}

fn update_manifests(c: &mut Criterion) {
    let Some(signed) = load_signed("update-manifests", "c2pa") else {
        return;
    };
    c.bench_function("update-manifests/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::default().with_stream("application/c2pa", &mut stream)
        })
    });
}

fn large_cbor_assertion(c: &mut Criterion) {
    let Some(signed) = load_signed("large-cbor-assertion", "c2pa") else {
        return;
    };
    c.bench_function("large-cbor-assertion/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::default().with_stream("application/c2pa", &mut stream)
        })
    });
}

fn large_json_assertion(c: &mut Criterion) {
    let Some(signed) = load_signed("large-json-assertion", "c2pa") else {
        return;
    };
    c.bench_function("large-json-assertion/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::default().with_stream("application/c2pa", &mut stream)
        })
    });
}

fn binary_ingredient_tree(c: &mut Criterion) {
    let Some(signed) = load_signed("binary-ingredient-tree", "c2pa") else {
        return;
    };
    c.bench_function("binary-ingredient-tree/read", |b| {
        b.iter(|| {
            let mut stream = Cursor::new(&signed);
            Reader::default().with_stream("application/c2pa", &mut stream)
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
    binary_ingredient_tree,
);
criterion_main!(benches);
