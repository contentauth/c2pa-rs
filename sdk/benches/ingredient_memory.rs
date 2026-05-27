// Measures heap allocations when reading a signed manifest that contains
// thumbnail-bearing ingredients. Run with:
//
//   cargo bench -p c2pa --features="file_io" --bench ingredient_memory

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use std::io::Cursor;

use c2pa::{Builder, CallbackSigner, Ingredient, Reader, SigningAlg};
use dhat::{HeapStats, Profiler};

const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");
const SOURCE_JPEG: &[u8] = include_bytes!("../tests/fixtures/C.jpg");

fn make_signer() -> CallbackSigner {
    let sign = |_ctx: *const (), data: &[u8]| CallbackSigner::ed25519_sign(data, PRIVATE_KEY);
    CallbackSigner::new(sign, SigningAlg::Ed25519, CERTS)
}

fn build_signed(n: usize, thumb_size: usize) -> Vec<u8> {
    let thumb = vec![0xabu8; thumb_size];
    let mut builder = Builder::default()
        .with_definition(r#"{"title":"bench"}"#)
        .unwrap();
    for i in 0..n {
        let mut ing = Ingredient::new_v2(format!("Ingredient {i}"), "image/jpeg");
        ing.set_thumbnail("image/jpeg", thumb.clone()).unwrap();
        builder.add_ingredient(ing);
    }
    let signer = make_signer();
    let mut src = Cursor::new(SOURCE_JPEG);
    let mut out = Cursor::new(Vec::new());
    builder
        .sign(&signer, "image/jpeg", &mut src, &mut out)
        .unwrap();
    out.into_inner()
}

fn report(label: &str, stats: HeapStats) {
    println!(
        "{label}\n  total: {:>10} bytes ({} blocks)\n  peak:  {:>10} bytes ({} blocks)",
        stats.total_bytes, stats.total_blocks, stats.max_bytes, stats.max_blocks,
    );
}

fn bench_read(label: &str, signed: &[u8]) {
    let _profiler = Profiler::builder().testing().build();
    let mut stream = Cursor::new(signed);
    let _ = Reader::default()
        .with_stream("image/jpeg", &mut stream)
        .unwrap();
    report(label, HeapStats::get());
}

fn main() {
    const THUMB_SIZE: usize = 10 * 1024; // 10 KB per thumbnail

    println!("=== ingredient thumbnail memory (10 KB thumbnails) ===\n");
    for n in [1, 5, 20] {
        let signed = build_signed(n, THUMB_SIZE);
        bench_read(
            &format!("read {n} ingredient(s) with {THUMB_SIZE}B thumbnail"),
            &signed,
        );
    }
}
