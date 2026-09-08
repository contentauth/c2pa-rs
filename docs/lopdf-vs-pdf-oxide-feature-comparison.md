# `lopdf` vs `pdf_oxide`: feature comparison

**Date:** 2026-09-08 · **Repo:** `c2pa-rs` (`unstable-pdf-oxide-backend`) · **Scope:** a side-by-side functional and non-functional comparison of the two PDF backends as they are actually wired into c2pa-rs today (`sdk/src/asset_handlers/pdf.rs`, `pdf_io.rs`, `pdf_oxide.rs`).

This is a reference matrix, not a recommendation memo — for the "should we replace `lopdf`" decision and its rationale, see [`pdf-oxide-vs-lopdf-analysis.md`](pdf-oxide-vs-lopdf-analysis.md). That analysis predates the PDF write path being wired up; this document reflects the current state, where **both** backends now implement the full read+write `C2paPdf` trait (embed, read, remove manifest; `AssetIO`'s `save_cai_store`/`get_object_locations`/`remove_cai_store` are live for both).

## At a glance

| | `lopdf` | `pdf_oxide` |
|---|---|---|
| Role in c2pa-rs | Default, stable backend (`pdf` feature) | Experimental, opt-in backend (`unstable_pdf_oxide` feature; selected at runtime via `core.pdf_backend`) |
| Object-graph mutation | **Native** (`Document::add_object`/`delete_object`/`catalog_mut`, etc.) | **None in the public API** — c2pa-rs hand-rolls its own mutable graph and serializer on top (`pdf_oxide.rs`'s `WorkingGraph`) |
| Write mechanism | `Document::save_to` — full re-serialization via `lopdf`'s own writer | Hand-written in c2pa-rs: BFS the reachable object graph, splice in changes, emit a classic xref table by hand, using `pdf_oxide::writer::ObjectSerializer` only to serialize individual objects |
| Malformed/broken-xref recovery | No (hard error on unparsable trailer/xref) | Yes (`xref_reconstruction.rs`) |
| Incremental (byte-preserving) update | Available in the library (`IncrementalDocument`), **not used** by c2pa-rs's current write path | Not available at all — would require building an appender from scratch, on top of code that's already hand-rolled |
| Release binary size (stripped, minimal parse app)* | 0.89 MB | 2.59 MB (~2.9×) |
| Dependency tree* | 52 crates | 141 crates (~2.7×) |
| First published / latest version* | 2016 / 0.44.0 | 2025 / 0.3.77 |

*Binary size, dependency count, and version metadata are carried over from the 2026-08-31 measurement in [`pdf-oxide-vs-lopdf-analysis.md`](pdf-oxide-vs-lopdf-analysis.md#measured-footprint-real-build-this-machine); not re-measured for this document. They predate the write path, which pulls no new dependencies on either side, so the ratios should still hold.

## Functional comparison

Capabilities are scoped to what c2pa-rs's own `C2paPdf` trait (`pdf.rs:79-102`) and its two implementations (`pdf.rs`'s `Pdf`, `pdf_oxide.rs`'s `PdfOxideDoc`) actually expose and exercise — both are covered by the same mirrored unit-test suite (20 tests in `pdf.rs`, 19 in `pdf_oxide.rs`, all currently green) plus a shared `PdfIO`/`AssetIO` layer.

| Capability | `lopdf` backend | `pdf_oxide` backend | Notes |
|---|:---:|:---:|---|
| Read: detect embedded C2PA manifest (`/AF` + `AFRelationship=C2PA_Manifest`) | ✅ | ✅ | Same logic, reimplemented per backend's object model |
| Read: manifest stored as `EmbeddedFile` | ✅ | ✅ | |
| Read: manifest stored as page `Annotation` (`FileAttachment`) | ✅ | ✅ | |
| Read: XMP metadata | ✅ (`Document.catalog → Metadata` stream) | ✅ (`pdf_oxide::extractors::xmp::XmpExtractor`) | |
| Read: detect password-protection | ✅ (`Document::is_encrypted`) | ✅ (`PdfDocument::is_encrypted`) | Both are detect-and-reject in c2pa-rs; neither backend's *write* path is exercised against an encrypted PDF — `write_cai` rejects password-protected PDFs outright |
| Read: malformed/broken xref recovery | ❌ (hard error if trailer/xref won't parse; no scan-and-rebuild salvage) | ✅ (`xref_reconstruction.rs`) | Real advantage for `pdf_oxide` on ingesting arbitrary/damaged real-world PDFs |
| Write: embed manifest as `EmbeddedFile` | ✅ (`Document::add_object` + dict mutation) | ✅ (hand-rolled `WorkingGraph::add_manifest_objects`/`add_embedded_file_entry`) | `pdf_oxide`'s own `writer::EmbeddedFile` builder can't be used — its typed `AFRelationship` enum has no custom/`Other(String)` variant, so both backends end up hand-authoring the Filespec dict via the raw object model |
| Write: embed manifest as page `Annotation` | ✅ | ✅ (hand-rolled `WorkingGraph::add_file_attachment_annotation`) | |
| Write: remove manifest (from `/AF`, `/Names/EmbeddedFiles`, and/or `/Annots`) | ✅ | ✅ | |
| Write: same-length in-place patch (byte-offset stable) | ✅ — via a raw byte splice in `pdf_io.rs`'s `write_cai` fast path (format-agnostic; not a `lopdf` feature per se) | ✅ — same `pdf_io.rs` fast path; works identically since it operates on raw bytes, independent of which backend parsed them | Only used when a same-length manifest is already embedded (the two-phase placeholder → final-signature flow); first embed still goes through the full backend-specific rewrite |
| Write: full-document rewrite mechanism | `Document::save_to` (`lopdf`'s own writer; handles xref/trailer/object-stream form) | Fully hand-rolled in c2pa-rs (`WorkingGraph::serialize_to`): manual header, per-object `ObjectSerializer::serialize_indirect` calls, hand-written classic xref table + trailer | `pdf_oxide` provides no document-level save; c2pa-rs owns this code and its correctness on this backend |
| Write: incremental (byte-preserving) update | Not wired up, but `lopdf::IncrementalDocument` exists and could be adopted later | Not available; no analog exists to build on | Neither backend does this *today* in c2pa-rs; `lopdf` has a path to it, `pdf_oxide` does not |
| Write: modern xref / object streams | `lopdf` supports writing these (`save_modern`), unused by c2pa-rs today | Always emits a classic (non-compressed) xref table; no object-stream writing | Neither is exercised by c2pa-rs's current (classic-xref) output today |
| Object-graph reachability on rewrite | Rewrites `Document`'s full object table as loaded | `WorkingGraph` only includes objects reachable (via dict/array/stream recursion) from the trailer's `/Root` and `/Info` | Functionally equivalent for well-formed PDFs; an edge case if a PDF depends on an object unreachable from `/Root`/`/Info` (uncommon and typically not spec-conformant) |
| Native PDF digital signatures (`/Sig`, PKCS#7/PAdES) | ❌ | Present in `pdf_oxide::signatures`, but orthogonal — C2PA PDF provenance doesn't use native `/Sig` | Neither backend's C2PA integration touches this |
| Rendering / text extraction / redaction / font subsetting | ❌ (not `lopdf`'s purpose) | Present in `pdf_oxide` proper, but entirely unused by c2pa-rs's integration | Would only become relevant if c2pa-rs's PDF scope grew beyond manifest embedding |

## Non-functional comparison

| Attribute | `lopdf` | `pdf_oxide` | Notes |
|---|---|---|---|
| Binary size impact (stripped release, minimal parse app) | +0.53 MB over baseline | +2.23 MB over baseline (~4.2×) | 2026-08-31 measurement; read-only workload — a write-capable binary pulls more of both, ratio direction should hold |
| Dependency tree | 52 crates, 18 always-on (trimmed via `default-features = false`) | 141 crates, ~39 always-on even at lean `default = ["icc","legacy-crypto"]` (`image`, `taffy`, `ttf-parser`, `regex`, `chrono`, `libc`, `env_logger`, …) | Larger supply-chain / audit surface for `pdf_oxide` regardless of which features c2pa-rs actually exercises |
| WASM fit | Works under c2pa-rs's existing rayon carve-out (`target.'cfg(any(not(wasm32), atomics))'`) | No `no_std`; `libc`/`env_logger` always-on; WASM support exists behind a feature but is unverified against c2pa-rs's build matrix | Relevant since c2pa-rs ships a WASM target |
| Memory model | Whole-file, in-memory object graph (`load_mem`); scales with file size | Same class of parser (whole-document object model); no streaming mode surfaced to c2pa-rs either | Neither backend streams; fine for typical asset sizes |
| API ergonomics for this workload | Verbose, low-level (manual reference-following, byte-key dict mutation); no typed embedded-file/annotation builders | Nominally has typed builders (`EmbeddedFile`, `FileAttachmentAnnotation`), but they're **unusable for C2PA** (no custom `AFRelationship`) and don't support mutating an already-parsed document — so c2pa-rs ends up at the same raw-object-model level of effort, *plus* the burden of writing and maintaining its own graph-walker and serializer | The `pdf_oxide` backend's write path (`WorkingGraph`, ~350 LOC in `pdf_oxide.rs`) is c2pa-rs-owned code with no upstream analog; a bug there is c2pa-rs's to find and fix, not `pdf_oxide`'s |
| Maintenance burden (as integrated) | Lower — write logic sits on top of `lopdf`'s own mutation/serialization primitives | Higher — c2pa-rs owns the entire mutable-graph-and-serializer implementation; upstream `pdf_oxide` changes to its (unstable, 0.x) object model or `ObjectSerializer` could break this code with no equivalent safety net from the library itself | Directly visible from the module doc in `pdf_oxide.rs:14-23` |
| Maturity / stability guarantees | Established (2016), used as-is; `pdf` is a normal, stable feature | Young (2025, 0.3.x), explicitly gated `unstable_pdf_oxide` per c2pa-rs's [experimental features policy](experimental-features.md) — no semver guarantees, may change/be removed in any release | `pdf_oxide` backend is not yet listed in the experimental-features registry table (a process gap, not evaluated further here) |
| License | MIT | MIT OR Apache-2.0 | Both compatible |
| MSRV | 1.88 | 1.88 | Equal |
| Encrypted-PDF handling | Can decrypt (RC4/AES) given a password for reading; writing/round-tripping encrypted PDFs is limited | Detects encryption (`is_encrypted`); decryption/round-trip depth not verified in this pass | c2pa-rs itself rejects password-protected PDFs for writing on both backends, so this gap is currently moot in practice |
| Untrusted-input hardening | Ships decompression-bomb caps (`LoadOptions::with_max_decompressed_size`) and reference-limit guards | Ships its own xref-reconstruction/parsing hardening (not itemized here); not independently audited in this pass | Both should be kept current via `cargo audit`; neither has been fuzzed by c2pa-rs itself |

## Bottom line

Functionally, both backends now reach parity on the operations c2pa-rs actually needs (embed/read/remove a manifest as an embedded file or annotation, detect XMP/encryption). The material difference is *where the write-path code lives and who owns it*: with `lopdf`, document mutation and serialization are the library's job; with `pdf_oxide`, they are hand-rolled inside c2pa-rs (`WorkingGraph` + a hand-written classic xref/trailer writer) because `pdf_oxide`'s public API has no document-mutation primitive. That, plus the ~3× binary size and ~2.7× dependency-tree cost, is the crux of why [`pdf-oxide-vs-lopdf-analysis.md`](pdf-oxide-vs-lopdf-analysis.md) recommends staying on `lopdf` as the default and keeping `pdf_oxide` experimental. `pdf_oxide`'s genuine edge — tolerant xref reconstruction for malformed real-world PDFs — is a read-side benefit that doesn't currently require adopting it as the write backend too.
