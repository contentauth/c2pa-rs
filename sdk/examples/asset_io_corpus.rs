// EXPERIMENT (local only, do not commit).
//
//! Run asset-io's invariants over a folder of media files.
//!
//! For every file the container is detected from its bytes, then:
//!
//! 1. the layout tiles the file, and `read` delivers every byte once, in order;
//! 2. copying with no updates reproduces the file byte for byte, and the layout `write`
//!    reports equals the layout of what it wrote;
//! 3. editing (set a manifest, set XMP, both, remove everything) either is refused or
//!    writes a file that parses, has the planned layout, reads back what was set, and
//!    is unchanged by a further copy.
//!
//! A file that is not a media file, or that asset-io rejects, is counted, not failed:
//! corrupt inputs are expected in a corpus. A failure is an invariant that does not
//! hold, or a panic.
//!
//! Run: `cargo run --release --example asset_io_corpus --features asset_io -- [options] <dir|file>...`
//!
//! The comparison with the handlers asset-io replaces is a test, because those are not
//! public: `ASSET_IO_CORPUS=<dir> cargo test --features asset_io asset_io_adapter`.
//!
//! Options:
//!   --collect DIR    copy files that fail or panic, and structurally interesting ones
//!                    (several images, data beyond the structure, edit refused), into
//!                    subfolders of DIR, as candidates for test fixtures or fuzz seeds
//!   --max-size MB    skip files larger than this (default 256)
//!   -v               print a line for every file

use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use asset_io::{Chunk, Error, HandlerRegistry, SegmentKind, Structure, Updates};
use sha2::{Digest, Sha256};

/// Files that take longer than this to check are reported: a sign of work that is not
/// linear in the input.
const SLOW: Duration = Duration::from_secs(5);

const C2PA_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

#[derive(Default)]
struct Report {
    failures: Vec<String>,
    notes: Vec<String>,
    refused: Vec<String>,
    multi: bool,
    trailing: bool,
    manifest: bool,
}

enum Outcome {
    NotMedia,
    Rejected(String),
    Checked(Report),
}

fn main() {
    let mut paths = Vec::new();
    let mut collect: Option<PathBuf> = None;
    let mut max_size: u64 = 256;
    let mut verbose = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--collect" => collect = args.next().map(PathBuf::from),
            "--max-size" => max_size = args.next().and_then(|v| v.parse().ok()).unwrap_or(256),
            "-v" => verbose = true,
            "-h" | "--help" => return usage(),
            _ => paths.push(PathBuf::from(a)),
        }
    }
    if paths.is_empty() {
        return usage();
    }

    let mut files = Vec::new();
    let mut missing = false;
    for p in &paths {
        if fs::symlink_metadata(p).is_err() {
            eprintln!("not found: {}", p.display());
            missing = true;
            continue;
        }
        walk(p, 0, &mut files);
    }
    if missing {
        std::process::exit(2);
    }
    if files.is_empty() {
        eprintln!("no files under the given paths");
        std::process::exit(2);
    }
    files.sort();

    // A panic is a result here, not noise.
    std::panic::set_hook(Box::new(|_| {}));

    let mut tally = Tally::default();
    for path in &files {
        tally.files += 1;
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size > max_size * 1024 * 1024 {
            tally.skipped += 1;
            continue;
        }
        let Ok(bytes) = fs::read(path) else {
            tally.skipped += 1;
            continue;
        };
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| check(&bytes)));
        let elapsed = started.elapsed();
        let shown = path.display();

        match result {
            Err(p) => {
                tally.panicked += 1;
                println!("PANIC  {shown}: {}", panic_message(&*p));
                keep(&collect, "panic", path);
            }
            Ok(Outcome::NotMedia) => {
                tally.not_media += 1;
                if verbose {
                    println!("skip   {shown}: not recognised");
                }
            }
            Ok(Outcome::Rejected(why)) => {
                tally.rejected += 1;
                *tally.rejected_by.entry(variant(&why)).or_default() += 1;
                if verbose {
                    println!("reject {shown}: {why}");
                }
            }
            Ok(Outcome::Checked(mut r)) => {
                tally.checked += 1;
                tally.multi += r.multi as usize;
                tally.trailing += r.trailing as usize;
                tally.manifest += r.manifest as usize;
                if elapsed > SLOW {
                    r.notes.push(format!("slow: {:.1}s", elapsed.as_secs_f32()));
                }
                for why in &r.refused {
                    *tally.refused_by.entry(without_numbers(why)).or_default() += 1;
                }
                tally.notes += r.notes.len();
                if !r.failures.is_empty() {
                    tally.failed += 1;
                    println!("FAIL   {shown}: {}", r.failures.join("; "));
                    keep(&collect, "fail", path);
                } else if verbose || !r.notes.is_empty() || !r.refused.is_empty() {
                    let mut extra = r.notes.clone();
                    extra.extend(r.refused.iter().map(|w| format!("edit refused: {w}")));
                    println!("ok     {shown} {}", extra.join("; "));
                }
                if r.multi {
                    keep(&collect, "multi-image", path);
                }
                if r.trailing {
                    keep(&collect, "trailing-data", path);
                }
                if !r.refused.is_empty() {
                    keep(&collect, "edit-refused", path);
                }
            }
        }
    }

    tally.print();
    if tally.failed + tally.panicked > 0 {
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!("Usage: corpus [--collect DIR] [--max-size MB] [-v] <dir|file>...");
}

#[derive(Default)]
struct Tally {
    files: usize,
    skipped: usize,
    not_media: usize,
    rejected: usize,
    rejected_by: BTreeMap<String, usize>,
    checked: usize,
    failed: usize,
    panicked: usize,
    notes: usize,
    multi: usize,
    trailing: usize,
    manifest: usize,
    refused_by: BTreeMap<String, usize>,
}

impl Tally {
    fn print(&self) {
        println!("\n{} files", self.files);
        println!("  checked          {}", self.checked);
        println!("    with manifest  {}", self.manifest);
        println!("    several images {}", self.multi);
        println!("    trailing data  {}", self.trailing);
        println!("    notes          {}", self.notes);
        println!(
            "  rejected         {}  {:?}",
            self.rejected, self.rejected_by
        );
        println!("  not media        {}", self.not_media);
        println!("  skipped          {}", self.skipped);
        println!("  edits refused (files, by reason)");
        for (why, n) in &self.refused_by {
            println!("    {n:4}  {why}");
        }
        println!("  FAILED           {}", self.failed);
        println!("  PANICKED         {}", self.panicked);
    }
}

/// Every regular file under `path`. Symlinks are not followed.
fn walk(path: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_file() {
        out.push(path.to_owned());
    } else if meta.is_dir() && depth < 32 {
        let Ok(rd) = fs::read_dir(path) else { return };
        let mut children: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        children.sort();
        for c in children {
            walk(&c, depth + 1, out);
        }
    }
}

fn keep(collect: &Option<PathBuf>, category: &str, path: &Path) {
    let Some(dir) = collect else { return };
    let dir = dir.join(category);
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let name = path
        .file_name()
        .map_or_else(|| "file".to_string(), |n| n.to_string_lossy().into_owned());
    let mut to = dir.join(&name);
    let mut n = 1;
    while to.exists() {
        to = dir.join(format!("{n}-{name}"));
        n += 1;
    }
    let _ = fs::copy(path, to);
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    p.downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panic".into())
}

/// The kind of an error message, without the numbers that differ between files.
fn variant(msg: &str) -> String {
    msg.split(':').next().unwrap_or(msg).trim().to_string()
}

/// A message with its numbers removed, so the same reason in different files tallies
/// together.
fn without_numbers(msg: &str) -> String {
    let mut out = String::new();
    let mut in_number = false;
    for c in msg.chars() {
        if c.is_ascii_digit() {
            if !in_number {
                out.push('#');
            }
            in_number = true;
        } else {
            in_number = false;
            out.push(c);
        }
    }
    out
}

fn describe(e: &Error) -> String {
    match e {
        Error::Io(io) => format!("I/O error: {io}"),
        Error::InvalidFormat(m) => format!("InvalidFormat: {m}"),
        Error::InvalidSegment { reason, .. } => format!("InvalidSegment: {reason}"),
        Error::LimitExceeded { what, .. } => format!("LimitExceeded: {what}"),
        Error::Ambiguous { what, .. } => format!("Ambiguous: {what}"),
        other => format!("{other}"),
    }
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

fn check(bytes: &[u8]) -> Outcome {
    let registry = HandlerRegistry::builtin();
    let s = match registry.parse_detect(&mut Cursor::new(bytes)) {
        Ok(s) => s,
        Err(Error::UnsupportedFormat) => return Outcome::NotMedia,
        Err(e) => return Outcome::Rejected(describe(&e)),
    };

    let mut r = Report {
        multi: s.subassets().len() > 1,
        trailing: s.trailing().is_some(),
        manifest: s.entities(SegmentKind::Jumbf).next().is_some(),
        ..Report::default()
    };

    check_layout(&s, bytes, &mut r);
    check_read(&s, bytes, &mut r);
    check_copy(&s, bytes, &mut r);
    check_edits(&s, bytes, &mut r);
    Outcome::Checked(r)
}

fn check_layout(s: &Structure, bytes: &[u8], r: &mut Report) {
    if s.total_size() != bytes.len() as u64 {
        r.failures.push(format!(
            "total size {} but the file is {}",
            s.total_size(),
            bytes.len()
        ));
    }
    let mut at = 0u64;
    for (i, seg) in s.segments().iter().enumerate() {
        if seg.extent().offset() != at {
            r.failures.push(format!(
                "segment {i} starts at {}, expected {at}",
                seg.extent().offset()
            ));
            return;
        }
        at = seg.extent().end();
    }
    if at != s.total_size() {
        r.failures
            .push(format!("segments end at {at}, not the end of the file"));
    }
    let mut at = 0u64;
    for (i, a) in s.subassets().iter().enumerate() {
        if a.range().offset() != at {
            r.failures.push(format!(
                "part {i} starts at {}, expected {at}",
                a.range().offset()
            ));
            return;
        }
        at = a.range().end();
    }
    if at != s.total_size() {
        r.failures.push("parts do not cover the file".into());
    }
    if let Some(t) = s.trailing() {
        if t.end() != s.total_size() {
            r.failures
                .push("trailing data does not run to the end of the file".into());
        }
    }
}

fn check_read(s: &Structure, bytes: &[u8], r: &mut Report) {
    let mut seen = 0u64;
    let mut hash = Sha256::new();
    let mut ordered = true;
    let res = s.read(&mut Cursor::new(bytes), &mut |c: Chunk<'_>| {
        ordered &= c.offset == seen;
        seen += c.data.len() as u64;
        hash.update(c.data);
        Ok(())
    });
    match res {
        Err(e) => r.failures.push(format!("read: {}", describe(&e))),
        Ok(()) => {
            if !ordered || seen != bytes.len() as u64 {
                r.failures.push(format!(
                    "read delivered {seen} bytes out of order or short of {}",
                    bytes.len()
                ));
            } else if hash.finalize()[..] != Sha256::digest(bytes)[..] {
                r.failures.push("read delivered different bytes".into());
            }
        }
    }
}

fn write(s: &Structure, src: &[u8], updates: &Updates) -> Result<(Vec<u8>, Structure, u64), Error> {
    let mut out = Cursor::new(Vec::new());
    let mut seen = 0u64;
    let dest = s.write(&mut Cursor::new(src), &mut out, updates, &mut |c: Chunk<
        '_,
    >| {
        seen += c.data.len() as u64;
        Ok(())
    })?;
    Ok((out.into_inner(), dest, seen))
}

fn check_copy(s: &Structure, bytes: &[u8], r: &mut Report) {
    match write(s, bytes, &Updates::new()) {
        Err(e) => r.failures.push(format!("copy: {}", describe(&e))),
        Ok((out, dest, seen)) => {
            if out != bytes {
                r.failures.push(format!(
                    "copy changed the file ({} -> {} bytes)",
                    bytes.len(),
                    out.len()
                ));
            }
            if seen != out.len() as u64 {
                r.failures
                    .push("copy: the sink did not see every byte".into());
            }
            if dest.segments() != s.segments() || dest.subassets() != s.subassets() {
                r.failures
                    .push("copy: the reported layout differs from the parsed one".into());
            }
            if dest.trailing() != s.trailing() {
                r.failures.push("copy: trailing data differs".into());
            }
        }
    }
}

fn fake_store() -> Vec<u8> {
    fn boxed(ty: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut v = ((body.len() + 8) as u32).to_be_bytes().to_vec();
        v.extend_from_slice(ty);
        v.extend_from_slice(body);
        v
    }
    let mut d = C2PA_STORE_UUID.to_vec();
    d.push(3);
    d.extend_from_slice(b"c2pa\0");
    let mut body = boxed(b"jumd", &d);
    body.extend(boxed(b"json", &[0x5a; 1001]));
    boxed(b"jumb", &body)
}

const XMP: &[u8] = b"<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><!-- corpus --></x:xmpmeta>";

fn check_edits(s: &Structure, bytes: &[u8], r: &mut Report) {
    let store = fake_store();
    let cases: [(&str, Updates); 4] = [
        ("set manifest", Updates::new().set_jumbf(store.clone())),
        ("set xmp", Updates::new().set_xmp(XMP.to_vec())),
        (
            "set both",
            Updates::new()
                .set_jumbf(store.clone())
                .set_xmp(XMP.to_vec()),
        ),
        ("remove all", Updates::remove_all()),
    ];

    let mut with_manifest = None;
    for (name, updates) in &cases {
        let (out, dest, seen) = match write(s, bytes, updates) {
            Ok(v) => v,
            // Refusing an edit it cannot do safely is allowed; anything else is not.
            Err(
                e @ (Error::InvalidFormat(_)
                | Error::InvalidSegment { .. }
                | Error::LimitExceeded { .. }
                | Error::Ambiguous { .. }
                | Error::UnsupportedFormat),
            ) => {
                let why = describe(&e);
                if !r.refused.contains(&why) {
                    r.refused.push(why);
                }
                continue;
            }
            Err(e) => {
                r.failures.push(format!("{name}: {}", describe(&e)));
                continue;
            }
        };
        if seen != out.len() as u64 {
            r.failures
                .push(format!("{name}: the sink did not see every byte"));
        }
        verify_output(name, s, bytes, updates, &out, &dest, r);

        let Ok(re) = HandlerRegistry::builtin().parse_detect(&mut Cursor::new(&out[..])) else {
            continue;
        };
        match *name {
            "set manifest" | "set both" => {
                let found = re.entities(SegmentKind::Jumbf).any(|e| {
                    re.read_entity(&mut Cursor::new(&out[..]), e)
                        .is_ok_and(|b| b == store)
                });
                if !found {
                    r.failures
                        .push(format!("{name}: the manifest does not read back"));
                }
                if *name == "set manifest" {
                    with_manifest = Some(out.clone());
                }
            }
            _ => {}
        }
        if matches!(*name, "set xmp" | "set both") {
            match re.xmp(&mut Cursor::new(&out[..])) {
                Ok(Some(x)) if x.starts_with(XMP) => {}
                other => r.failures.push(format!(
                    "{name}: xmp does not read back ({:?})",
                    other.map(|o| o.map(|v| v.len()))
                )),
            }
        }
        if *name == "remove all" && re.entities(SegmentKind::Jumbf).next().is_some() {
            r.failures.push("remove all: a manifest is left".into());
        }
    }

    // Take the manifest back out. A file that had none is expected to return to
    // what it was; a difference is worth a look, not a failure.
    if let Some(edited) = with_manifest {
        let Ok(re) = HandlerRegistry::builtin().parse_detect(&mut Cursor::new(&edited[..])) else {
            return;
        };
        match write(&re, &edited, &Updates::new().remove_jumbf()) {
            Ok((back, _, _)) => {
                if !r.manifest && back != bytes {
                    let detail = if back.len() == bytes.len() {
                        let differ: Vec<usize> = (0..bytes.len())
                            .filter(|&i| bytes[i] != back[i])
                            .take(65)
                            .collect();
                        format!(
                            "same length, {}{} bytes differ, first at {}",
                            differ.len().min(64),
                            if differ.len() > 64 { "+" } else { "" },
                            differ[0]
                        )
                    } else {
                        format!("{} -> {} bytes", bytes.len(), back.len())
                    };
                    r.notes.push(format!(
                        "removing the manifest again does not restore the file ({detail})"
                    ));
                }
            }
            Err(e) => r
                .notes
                .push(format!("removing the added manifest: {}", describe(&e))),
        }
    }
}

/// What an accepted edit must have produced.
fn verify_output(
    name: &str,
    s: &Structure,
    src: &[u8],
    updates: &Updates,
    out: &[u8],
    dest: &Structure,
    r: &mut Report,
) {
    if dest.total_size() != out.len() as u64 {
        r.failures.push(format!(
            "{name}: reported size {} but wrote {}",
            dest.total_size(),
            out.len()
        ));
    }
    let re = match HandlerRegistry::builtin().parse_detect(&mut Cursor::new(out)) {
        Ok(re) => re,
        Err(e) => {
            r.failures.push(format!(
                "{name}: the output does not parse ({})",
                describe(&e)
            ));
            return;
        }
    };
    if re.container_id() != s.container_id() {
        r.failures
            .push(format!("{name}: the output is a different container"));
    }
    if dest.segments() != re.segments() {
        r.failures.push(format!(
            "{name}: the reported layout is not the written one"
        ));
    }
    if dest.subassets() != re.subassets() {
        r.failures.push(format!(
            "{name}: the reported parts are not the written ones"
        ));
    }
    if dest.trailing() != re.trailing() {
        r.failures.push(format!(
            "{name}: the reported trailing data is not the written one"
        ));
    }
    if entity_layout(dest) != entity_layout(&re) {
        r.notes.push(format!(
            "{name}: the reported entities differ from the written ones"
        ));
    }

    // `plan` must say what `write` did.
    match s.plan(&mut Cursor::new(src), updates) {
        Ok(planned) => {
            if planned.segments() != dest.segments() {
                r.failures.push(format!("{name}: plan differs from write"));
            }
        }
        Err(Error::UnsupportedFormat) => {}
        Err(e) => r.failures.push(format!(
            "{name}: plan failed after write succeeded ({})",
            describe(&e)
        )),
    }

    // Copying the result changes nothing.
    match write(&re, out, &Updates::new()) {
        Ok((again, _, _)) if again == out => {}
        Ok(_) => r
            .failures
            .push(format!("{name}: copying the output changes it")),
        Err(e) => r.failures.push(format!(
            "{name}: copying the output failed ({})",
            describe(&e)
        )),
    }
}

type EntityLayout = Vec<(SegmentKind, Option<[u8; 16]>, Vec<(u64, u64)>)>;

fn entity_layout(s: &Structure) -> EntityLayout {
    [
        SegmentKind::Xmp,
        SegmentKind::Jumbf,
        SegmentKind::Exif,
        SegmentKind::Thumbnail,
    ]
    .into_iter()
    .flat_map(|k| {
        s.entities(k).map(move |e| {
            (
                k,
                e.jumbf_type(),
                e.parts()
                    .map(|p| (p.range().offset(), p.range().len()))
                    .collect(),
            )
        })
    })
    .collect()
}
