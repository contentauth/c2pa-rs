// EXPERIMENT (local only, do not commit).
//
// Timing of the asset-io adapter against the handlers it replaces (`JpegIO`, `PngIO`),
// through the same traits the SDK uses. Not run by default: it only reports.
//
//   cargo test --release --features asset_io asset_io_perf -- --ignored --nocapture
//
// Environment:
//   ASSET_IO_CORPUS=<dir>   also time every JPEG and PNG under <dir>
//   ASSET_IO_PERF_FILE=1    read from files on disk (many small reads and seeks) instead
//                           of from memory
//   ASSET_IO_SYNTH_MB=<n>   also time synthetic PNGs of <n> MB with 8 KB, 64 KB and 1 MB
//                           IDAT chunks, to tell per-byte cost from per-chunk cost
//   ASSET_IO_SYNTH_ONLY=1   skip the fixtures
//
// Rows prefixed `floor` are not handlers: a plain memcpy, and `io::copy` through `dyn`
// streams. They bound what any handler can do for the same bytes.
//
// Each operation is run on each file by both implementations, alternating, and the best
// of several runs is kept, which filters out scheduling noise. Parsing in memory
// isolates the parsers; reading from disk adds the cost of their I/O pattern.

#![cfg(all(test, feature = "asset_io"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    hint::black_box,
    io::{self, Cursor},
    path::PathBuf,
    time::{Duration, Instant},
};

use crate::{
    asset_handlers::{asset_io_adapter::AssetIoAdapter, jpeg_io::JpegIO, png_io::PngIO},
    asset_io::AssetIO,
    asset_io_adapter_test::{fixture_paths, store},
    read_seek::{ReadSeek, ReadWriteSeek},
};

struct Case {
    /// Rows are totalled per group: the format, or a synthetic set.
    group: String,
    name: String,
    path: PathBuf,
    ext: &'static str,
    bytes: Vec<u8>,
    /// The file with a manifest written by the old handler, when it accepts the file.
    managed: Option<Vec<u8>>,
}

fn open(c: &Case, file: bool) -> Box<dyn ReadSeek + '_> {
    if file {
        Box::new(fs::File::open(&c.path).unwrap())
    } else {
        Box::new(Cursor::new(&c.bytes[..]))
    }
}

thread_local! {
    static SCRATCH: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

/// An empty output buffer with at least `cap` bytes reserved, reused between runs so
/// first-touch page faults and kernel zeroing of a fresh allocation are not timed.
fn scratch(cap: usize) -> Cursor<Vec<u8>> {
    let mut v = SCRATCH.with(Cell::take);
    v.clear();
    v.reserve(cap);
    Cursor::new(v)
}

fn recycle(c: Cursor<Vec<u8>>) {
    SCRATCH.with(|s| s.set(c.into_inner()));
}

type Op = fn(&dyn AssetIO, &Case, bool, &[u8]) -> bool;

fn op_read_c2pa(h: &dyn AssetIO, c: &Case, f: bool, _: &[u8]) -> bool {
    let mut s = open(c, f);
    black_box(h.get_reader().read_c2pa(&mut *s).is_ok());
    true
}

fn op_read_xmp(h: &dyn AssetIO, c: &Case, f: bool, _: &[u8]) -> bool {
    let mut s = open(c, f);
    black_box(h.get_reader().read_xmp(&mut *s).is_some());
    true
}

fn op_locations(h: &dyn AssetIO, c: &Case, f: bool, _: &[u8]) -> bool {
    let Some(w) = h.get_writer("x") else {
        return false;
    };
    let mut s = open(c, f);
    black_box(w.get_object_locations(&mut *s).is_ok());
    true
}

fn op_box_map(h: &dyn AssetIO, c: &Case, f: bool, _: &[u8]) -> bool {
    let Some(b) = h.asset_box_hash_ref() else {
        return false;
    };
    let mut s = open(c, f);
    black_box(b.get_box_map(&mut *s).is_ok());
    true
}

fn op_write_c2pa(h: &dyn AssetIO, c: &Case, f: bool, store: &[u8]) -> bool {
    let Some(w) = h.get_writer("x") else {
        return false;
    };
    let mut s = open(c, f);
    let mut out = scratch(c.bytes.len() + store.len() + 1024);
    black_box(w.write_c2pa(&mut *s, &mut out, store).is_ok());
    black_box(out.get_ref().len());
    recycle(out);
    true
}

fn op_remove_c2pa(h: &dyn AssetIO, c: &Case, _: bool, _: &[u8]) -> bool {
    let (Some(w), Some(m)) = (h.get_writer("x"), c.managed.as_ref()) else {
        return false;
    };
    let mut out = scratch(m.len());
    black_box(w.remove_c2pa(&mut Cursor::new(&m[..]), &mut out).is_ok());
    black_box(out.get_ref().len());
    recycle(out);
    true
}

const OPS: [(&str, Op); 6] = [
    ("read_c2pa", op_read_c2pa),
    ("read_xmp", op_read_xmp),
    ("object_locations", op_locations),
    ("box_map", op_box_map),
    ("write_c2pa", op_write_c2pa),
    ("remove_c2pa", op_remove_c2pa),
];

fn handlers(ext: &str) -> (Box<dyn AssetIO>, Box<dyn AssetIO>) {
    if ext == "png" {
        (
            Box::new(PngIO::new("png")),
            Box::new(AssetIoAdapter::new("png")),
        )
    } else {
        (
            Box::new(JpegIO::new("jpg")),
            Box::new(AssetIoAdapter::new("jpg")),
        )
    }
}

/// A PNG of about `total` bytes of image data in IDAT chunks of `idat` bytes. CRCs are
/// zero: neither parser checks them.
fn synth_png(total: usize, idat: usize) -> Vec<u8> {
    fn chunk(v: &mut Vec<u8>, ty: &[u8; 4], data: &[u8]) {
        v.extend_from_slice(&(data.len() as u32).to_be_bytes());
        v.extend_from_slice(ty);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0; 4]);
    }
    let mut v = Vec::with_capacity(total + total / idat * 12 + 64);
    v.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);
    let mut ihdr = [0u8; 13];
    ihdr[3] = 1; // width 1
    ihdr[7] = 1; // height 1
    ihdr[8] = 8; // bit depth
    chunk(&mut v, b"IHDR", &ihdr);
    let pattern: Vec<u8> = (0..idat)
        .map(|i| (i.wrapping_mul(31) ^ 0x5a) as u8)
        .collect();
    let mut done = 0;
    while done < total {
        let n = idat.min(total - done);
        chunk(&mut v, b"IDAT", &pattern[..n]);
        done += n;
    }
    chunk(&mut v, b"IEND", &[]);
    v
}

fn cases() -> Vec<Case> {
    let store = store(&[0x5a; 10_000]);
    let mut v = Vec::new();

    if let Some(mb) = std::env::var("ASSET_IO_SYNTH_MB")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        for idat in [8 * 1024, 64 * 1024, 1024 * 1024] {
            let name = format!("synth-{mb}MB-idat{}K.png", idat / 1024);
            let bytes = synth_png(mb * 1024 * 1024, idat);
            let path = std::env::temp_dir().join(&name);
            fs::write(&path, &bytes).unwrap();
            let (old, _) = handlers("png");
            let managed = old.get_writer("x").and_then(|w| {
                let mut out = Cursor::new(Vec::new());
                w.write_c2pa(&mut Cursor::new(&bytes[..]), &mut out, &store)
                    .ok()
                    .map(|()| out.into_inner())
            });
            v.push(Case {
                group: format!("png-{}K", idat / 1024),
                name,
                path,
                ext: "png",
                bytes,
                managed,
            });
        }
        if std::env::var_os("ASSET_IO_SYNTH_ONLY").is_some() {
            return v;
        }
    }

    for path in fixture_paths() {
        let ext = match path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("jpg" | "jpeg" | "mpo") => "jpg",
            Some("png") => "png",
            _ => continue,
        };
        let Ok(bytes) = fs::read(&path) else { continue };
        let (old, _) = handlers(ext);
        let managed = old.get_writer("x").and_then(|w| {
            let mut out = Cursor::new(Vec::new());
            w.write_c2pa(&mut Cursor::new(&bytes[..]), &mut out, &store)
                .ok()
                .map(|()| out.into_inner())
        });
        v.push(Case {
            group: ext.to_string(),
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            path,
            ext,
            bytes,
            managed,
        });
    }
    v
}

fn reps(size: usize) -> usize {
    match size {
        0..=65_535 => 200,
        65_536..=1_048_575 => 40,
        1_048_576..=8_388_607 => 10,
        _ => 5,
    }
}

fn time(f: impl FnOnce()) -> Duration {
    let t = Instant::now();
    f();
    t.elapsed()
}

/// Best time of `f` over `n` runs.
fn best_of(n: usize, mut f: impl FnMut()) -> Duration {
    (0..n).map(|_| time(&mut f)).min().unwrap_or_default()
}

/// One copy of the bytes into a pre-sized buffer: the least any handler can do.
fn floor_memcpy(c: &Case) -> Duration {
    let mut out = vec![0u8; c.bytes.len()];
    best_of(reps(c.bytes.len()), || {
        out.copy_from_slice(&c.bytes);
        black_box(&out);
    })
}

/// The same copy into a fresh allocation each run: the cost the handlers paid before
/// the output buffer was recycled.
fn floor_memcpy_fresh(c: &Case) -> Duration {
    best_of(reps(c.bytes.len()), || {
        let mut out = Vec::with_capacity(c.bytes.len());
        out.extend_from_slice(&c.bytes);
        black_box(&out);
    })
}

/// `io::copy` between `dyn` streams: what the old handlers did for the bulk of a file.
fn floor_io_copy(c: &Case) -> Duration {
    best_of(reps(c.bytes.len()), || {
        let mut src: Box<dyn ReadSeek + '_> = Box::new(Cursor::new(&c.bytes[..]));
        let mut out = scratch(c.bytes.len());
        let dst: &mut dyn ReadWriteSeek = &mut out;
        black_box(io::copy(&mut *src, dst).unwrap());
        black_box(out.get_ref().len());
        recycle(out);
    })
}

struct Row {
    group: String,
    op: &'static str,
    name: String,
    size: usize,
    old: Duration,
    new: Duration,
}

#[test]
#[ignore = "reports timings; run with --release --ignored --nocapture"]
fn asset_io_perf() {
    if cfg!(debug_assertions) {
        eprintln!("warning: a debug build; use --release for meaningful numbers");
    }
    let from_file = std::env::var_os("ASSET_IO_PERF_FILE").is_some();
    let store = store(&[0x5a; 10_000]);
    let cases = cases();
    println!(
        "{} files, reading from {}",
        cases.len(),
        if from_file { "disk" } else { "memory" }
    );

    let mut rows: Vec<Row> = Vec::new();
    for c in &cases {
        let (old, new) = handlers(c.ext);
        for (op_name, op) in OPS {
            // Both must support the operation; this also warms both.
            if !op(&*old, c, from_file, &store) || !op(&*new, c, from_file, &store) {
                continue;
            }
            let (mut bo, mut bn) = (Duration::MAX, Duration::MAX);
            for _ in 0..reps(c.bytes.len()) {
                bo = bo.min(time(|| {
                    op(&*old, c, from_file, &store);
                }));
                bn = bn.min(time(|| {
                    op(&*new, c, from_file, &store);
                }));
            }
            rows.push(Row {
                group: c.group.clone(),
                op: op_name,
                name: c.name.clone(),
                size: c.bytes.len(),
                old: bo,
                new: bn,
            });
        }
    }

    // Totals per format and operation.
    let mut total: BTreeMap<(String, &str), (usize, usize, Duration, Duration)> = BTreeMap::new();
    for r in &rows {
        let t = total.entry((r.group.clone(), r.op)).or_default();
        t.0 += 1;
        t.1 += r.size;
        t.2 += r.old;
        t.3 += r.new;
    }
    let gbps = |bytes: usize, d: Duration| bytes as f64 / d.as_secs_f64().max(1e-12) / 1e9;
    println!(
        "\n{:<9} {:<17} {:>5} {:>9} {:>11} {:>11} {:>8} {:>8} {:>7}",
        "group", "operation", "files", "MB", "old", "new", "old GB/s", "new GB/s", "new/old"
    );
    for ((group, op), (n, bytes, o, w)) in &total {
        println!(
            "{group:<9} {op:<17} {n:>5} {:>9.2} {:>11.2?} {:>11.2?} {:>8.1} {:>8.1} {:>6.2}x",
            *bytes as f64 / 1e6,
            o,
            w,
            gbps(*bytes, *o),
            gbps(*bytes, *w),
            w.as_secs_f64() / o.as_secs_f64().max(1e-12)
        );
    }

    // Floors, from memory only: the same bytes moved with no handler at all.
    if !from_file {
        let mut floors: BTreeMap<String, (usize, usize, [Duration; 3])> = BTreeMap::new();
        for c in &cases {
            let t = floors.entry(c.group.clone()).or_default();
            t.0 += 1;
            t.1 += c.bytes.len();
            t.2[0] += floor_memcpy(c);
            t.2[1] += floor_memcpy_fresh(c);
            t.2[2] += floor_io_copy(c);
        }
        println!("\nfloors (GB/s): memcpy into a reused buffer | memcpy into a fresh Vec | io::copy over dyn into a reused buffer");
        for (group, (n, bytes, d)) in &floors {
            println!(
                "{group:<9} {n:>3} files {:>9.2} MB   {:>7.1}   {:>7.1}   {:>7.1}",
                *bytes as f64 / 1e6,
                gbps(*bytes, d[0]),
                gbps(*bytes, d[1]),
                gbps(*bytes, d[2])
            );
        }
    }

    // The files where the new one is slowest relative to the old, ignoring runs too
    // short to measure.
    let mut slow: Vec<&Row> = rows
        .iter()
        .filter(|r| r.old > Duration::from_micros(20) && r.new > r.old.mul_f64(1.5))
        .collect();
    slow.sort_by_key(|r| std::cmp::Reverse(r.new.saturating_sub(r.old)));
    if slow.is_empty() {
        println!("\nno file is more than 1.5x slower with the new handler");
    } else {
        println!("\nslowest relative to the old handler (new > 1.5x old):");
        for r in slow.iter().take(15) {
            println!(
                "  {:<17} {:<40} {:>9} B  old {:>10.2?}  new {:>10.2?}  {:.1}x",
                r.op,
                r.name,
                r.size,
                r.old,
                r.new,
                r.new.as_secs_f64() / r.old.as_secs_f64()
            );
        }
    }
}
