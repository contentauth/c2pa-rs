# Evaluating `pdf_oxide` as a replacement for `lopdf` in c2pa-rs

**Date:** 2026-08-31 · **Repo:** `contentauth/c2pa-rs` @ `main` · **Scope:** dependency-replacement feasibility analysis (no code change proposed here).

## Problem Statement

A newer Rust PDF library, [`pdf_oxide`](https://github.com/yfedoseev/pdf_oxide), was proposed as a possible replacement for `lopdf`, which c2pa-rs uses for PDF manifest embedding/reading. This doc establishes what c2pa-rs actually depends on `lopdf` for, what `pdf_oxide` is and offers, and whether a swap is warranted. The short answer is **no** — but the reasoning matters, because the question conflates two separate things: the choice of PDF library, and the (currently unimplemented) PDF *write* path.

## Current Behavior / Root Cause

### How `lopdf` is wired in

- `lopdf = "0.44.0"` is an **optional** dependency behind the `pdf` feature ([sdk/Cargo.toml:45](sdk/Cargo.toml), [:125](sdk/Cargo.toml)), with an explicit WASM carve-out because `lopdf`'s `rayon` needs real threads ([sdk/Cargo.toml:164-166](sdk/Cargo.toml)). c2pa-rs pulls it with `default-features = false` to keep the surface minimal.
- All PDF logic lives in two files: [sdk/src/asset_handlers/pdf.rs](sdk/src/asset_handlers/pdf.rs) (object-graph manipulation) and [sdk/src/asset_handlers/pdf_io.rs](sdk/src/asset_handlers/pdf_io.rs) (the `AssetIO` glue).

### `lopdf` is used as a low-level PDF object model, not a document API

`Pdf` wraps a `lopdf::Document` ([pdf.rs:92-94](sdk/src/asset_handlers/pdf.rs)) and drives the raw PDF object graph directly. The dependency surface is specifically:

- **Types:** `Document`, `Object` (+ variants `Array`/`Integer`/`Name`/`Reference`), `ObjectId`, `Stream`, `Dictionary` (via the `dictionary!` macro), `lopdf::Error` ([pdf.rs:19-23](sdk/src/asset_handlers/pdf.rs)).
- **Document ops:** `load_mem` / `load_from` ([pdf.rs:301-309](sdk/src/asset_handlers/pdf.rs)), `save_to` ([pdf.rs:98-100](sdk/src/asset_handlers/pdf.rs)), `is_encrypted` ([pdf.rs:102-104](sdk/src/asset_handlers/pdf.rs)), `add_object` / `get_object` / `get_object_mut` / `delete_object`, `catalog` / `catalog_mut`, `page_iter` / `get_pages`, and the public `objects` field.
- **Object ops:** `as_dict[_mut]`, `as_array[_mut]`, `as_stream`, `as_reference`, `as_name`, `as_str`, `get_deref` (reference-following on dictionaries), `string_literal`.

It uses these to construct the C2PA embedding by hand: an EmbeddedFile stream + FileSpec with `AFRelationship = C2PA_Manifest`, the catalog `/AF` associated-files array, the `/Names → /EmbeddedFiles → /Names` tree, and a first-page `FileAttachment` annotation ([pdf.rs:115-202](sdk/src/asset_handlers/pdf.rs), [:369-469](sdk/src/asset_handlers/pdf.rs)). This is a **PDF DOM editor** workload — exactly `lopdf`'s stated purpose (crates.io keywords: *editing, manipulation, merge, pdf*).

### Only the read path is actually live

This is the crucial context. Despite the write/remove code existing and being unit-tested, it is **not exposed**:

- `PdfIO::get_writer` returns `None` ([pdf_io.rs:87-89](sdk/src/asset_handlers/pdf_io.rs)).
- `save_cai_store`, `get_object_locations`, and `remove_cai_store` all return `NotImplemented("PDF write functionality will be added in a future release")` ([pdf_io.rs:96-106](sdk/src/asset_handlers/pdf_io.rs)).
- [pdf.rs:14-15](sdk/src/asset_handlers/pdf.rs) carries `#![allow(dead_code)]` with `// TODO: Remove this after we finish the PDF write feature.`

So today c2pa-rs can **read** a C2PA manifest from a PDF and detect XMP/encryption, but cannot **sign** one. The real open work is not "which library parses the PDF" — it's implementing the **write path** (`get_writer`/`save_cai_store`/`get_object_locations`), which is c2pa-rs's own work regardless of the underlying crate. Note the scope split:

- **Current/near-term (incremental update *not* required):** author the manifest objects and save. A full re-serialization is acceptable — which `lopdf::save_to` already does.
- **Future (if/when incremental-update signing is required):** append the manifest via a PDF incremental update that preserves the original bytes so the byte-range hard binding stays valid ([pdf.rs:214-216](sdk/src/asset_handlers/pdf.rs) references the spec's PDF-embedding section). The convenient `Document::save_to` re-serializes the whole file (not byte-preserving) — **but `lopdf` already ships `IncrementalDocument`** (`src/incremental_document.rs`: keeps the original bytes in `bytes_documents` and appends a new revision as `new_document`, written via its own `save_to`), so c2pa would switch the write path from `Document` to `IncrementalDocument` rather than build an appender from scratch. *(This corrects an earlier draft of this doc, which wrongly claimed `lopdf` had no incremental support.)*

## Spec Alignment

PDF manifest embedding is spec-governed: the C2PA spec defines embedding a manifest store as an associated file with `AFRelationship = C2PA_Manifest` (the construct built at [pdf.rs:440-452](sdk/src/asset_handlers/pdf.rs)), and PDF hard binding relies on a byte-range data hash over an incrementally-updated file. Any library used here must therefore support: (a) reading/writing the associated-files + embedded-file object structures, and (b) a write mode that preserves prior bytes for the hard binding. The exact governing section numbers were not re-derived for this dependency analysis (it is an implementation/supply-chain question, not a conformance one); use `/c2pa-spec-lookup lookup "embedding manifests into pdfs"` if a spec cross-check is needed before implementing write.

### Limitations of `lopdf`

Source-checked against `lopdf` 0.44. Most don't affect the current embed-a-manifest job; flagged where they do.

- **No broken-xref reconstruction.** `reader.rs` follows the xref/`/Prev` chain but returns a hard `Xref` error if startxref/trailer won't parse — there is no "scan the file and rebuild the xref" salvage path (which `pdf_oxide` has via `xref_reconstruction.rs`). Malformed real-world PDFs that viewers tolerate may fail to load. **Matters** for ingesting arbitrary user PDFs. (Parsing is lenient by default — `LoadOptions.strict = false` — which handles minor issues but not a destroyed xref.)
- **Default `Document::save_to` is a full re-serialization.** Object numbering, xref form, and object streams can change and exact prior bytes aren't preserved, which **invalidates any pre-existing PDF digital signatures**. c2pa's current code uses this path. *Mitigation:* `IncrementalDocument` (below) preserves prior bytes and appends.
- **Whole-file, in-memory, non-streaming.** `load_mem` parses the entire document and builds the full object graph; memory scales with file size. Fine for typical assets, a limit for very large PDFs.
- **Low-level DOM only.** No rendering, text extraction, layout, font subsetting, redaction, or native `/Sig` (CMS/PAdES) sign/verify — the flip side of its small footprint, and the same tradeoff described above. Fine for manifest embedding.
- **Verbose, footgun-prone object API.** Manual reference-following (`get_deref` / `as_reference` → `get_object_mut`), byte-key dictionary mutation, direct-vs-indirect handling — as [pdf.rs](sdk/src/asset_handlers/pdf.rs) shows. No typed builders for embedded files/annotations (`pdf_oxide` has those, modulo the `AFRelationship` gap).
- **Encrypted PDFs are read-mostly.** It can *decrypt* with a password (RC4/AES via `EncryptionState`/crypt filters), but writing/round-tripping encrypted PDFs is limited; c2pa deliberately rejects password-protected PDFs (`is_encrypted()` → bail).
- **Untrusted-input attack surface.** Like any PDF parser it faces malformed input; it *does* ship guards (`LoadOptions::with_max_decompressed_size` decompression-bomb cap, `ReferenceLimit`), but keep it current and fuzzed (`cargo audit`).
- **WASM:** rayon parallelism is off under c2pa's `default-features = false`; parsing is single-threaded there. Minor.

**What `lopdf` does *not* lack** (stated because an earlier draft got one wrong): byte-preserving **incremental updates** via `IncrementalDocument`; real **encryption** support; **object-stream / modern-xref** writing (`save_modern` / `SaveOptions` / `ObjectStream`); and decompression-bomb / reference-limit **safety guards**.

## Options Considered

| Option | Summary | Verdict |
|---|---|---|
| **Keep `lopdf`** | Mature focused PDF DOM already integrated; provides everything the current read path (and near-term non-incremental write) needs | **Recommended** |
| Rewrite `pdf.rs` against `pdf_oxide` | Mechanically **feasible** — `pdf_oxide` *does* expose the object model + embedded-file/annotation authoring (source-verified below) — but costs ~3× binary size and ~2.7× dependency crates for no capability gain | Not recommended (footprint) |
| Use `lopdf`'s `IncrementalDocument` for byte-preserving writes | Only if/when incremental signing becomes a requirement (**not currently** per updated direction); already available in `lopdf` | Future work |

> **Scope note (updated direction):** rewriting `pdf.rs` is acceptable; library *age* is set aside; and **incremental-update signing is not a current requirement** (possible future). So the decision rests on **(a) capability fit** and **(b) dependency footprint** — both now verified against `pdf_oxide` 0.3.77's actual source and a real build, not just docs.

### Capability review of `pdf_oxide` (source-verified, v0.3.77)

**Correction to the first pass:** an earlier draft concluded from docs.rs *index* pages that `pdf_oxide` lacked the low-level authoring APIs. Reading the **actual crate source** (extracted from crates.io) shows that is wrong — the capability is present:

- **It has a constructible object model.** `pdf_oxide::object::Object` is an enum with `Name(String)`, `String(Vec<u8>)`, `Integer(i64)`, `Reference(ObjectRef)`, `Dictionary(HashMap<String, Object>)`, and `Stream`, plus helpers like `Object::text_string` and `as_dict`. It is a genuine read/**write** DOM, comparable to `lopdf`'s `Object`/`Dictionary`/`Stream` (HashMap-based/unordered vs `lopdf`'s ordered dictionaries).
- **It has first-class embedded-file and annotation authoring** — exactly the two C2PA embedding modes:
  - `writer::embedded_files::EmbeddedFile::new(name, data).with_description(..).with_mime_type(..).with_af_relationship(..)`, with `build_stream_dict()` / `build_filespec()` and an `EmbeddedFilesBuilder` that wires the `/Names → /EmbeddedFiles` tree.
  - `writer::special_annotations::FileAttachmentAnnotation` + `add_file_attachment(..)` on the annotation/document builders and `editor::DocumentEditor` (which also exposes embedded-file + add-annotation methods on an *existing* parsed document, plus `ObjectSerializer`).
  So the constructs c2pa-rs hand-builds today ([pdf.rs:115-202](sdk/src/asset_handlers/pdf.rs), [:369-468](sdk/src/asset_handlers/pdf.rs)) are expressible — in places more ergonomically than the raw `lopdf` graph work.

**Two real caveats remain (capability is present, but not friction-free):**

- **The typed `AFRelationship` cannot emit `C2PA_Manifest`.** `AFRelationship` is a fixed PDF-2.0 enum (`Source`/`Data`/`Alternative`/`Supplement`/`EncryptedPayload`/`FormData`/`Schema`/`Unspecified`) serialized via `pdf_name()`, with **no custom/`Other(String)` variant** (`writer/embedded_files.rs:47-82`, `:206-212`). C2PA requires `AFRelationship = C2PA_Manifest`, so the nice typed `EmbeddedFile` helper is unusable for the manifest; c2pa would hand-author the Filespec dict via the raw `Object` model (feasible — `Object::Name("C2PA_Manifest".into())`, `Object::Dictionary(..)`) — i.e. the *same* hand-rolled approach it already uses with `lopdf` — or contribute an `AFRelationship::Other(String)` upstream.
- **Round-trip fidelity of the re-serialize/edit path is unverified** and is the security-relevant risk: the manifest must hard-bind to the file, so the writer must not silently reorder/alter/drop content. `save_incremental` exists but byte-preservation isn't documented and it does **not** preserve source encryption. This needs a real correctness spike before trusting it on the provenance path.

(The `signatures` module — `PdfSigner`, `ByteRangeCalculator`, PKCS#7/PAdES/RFC-3161 — is genuine and interesting, but it targets native PDF `/Sig` digital signatures, which C2PA PDF provenance does not use; it is orthogonal to associated-file embedding.)

### Measured footprint (real build, this machine)

Built three minimal binaries (empty baseline; `lopdf` with `default-features=false` as c2pa uses it; `pdf_oxide` with its lean `default` features), each parsing `basic.pdf` and reading structure. macOS arm64, `cargo build`/`--release`, default profiles (no fat LTO); stripped = `strip -x`.

| Binary | debug | release | release + strip |
|---|---|---|---|
| baseline (no PDF dep) | 0.47 MB | 0.41 MB | 0.36 MB |
| **`lopdf`** (`default-features=false`) | 4.31 MB | 1.03 MB | **0.89 MB** |
| **`pdf_oxide`** (default features) | 10.27 MB | 3.13 MB | **2.59 MB** |

- **Whole-binary, stripped release:** `pdf_oxide` **2.59 MB vs `lopdf` 0.89 MB — ~2.9×** (+1.70 MB).
- **Marginal library footprint** (over the 0.36 MB empty baseline): `lopdf` **+0.53 MB** vs `pdf_oxide` **+2.23 MB — ~4.2×**.
- **Dependency tree:** `lopdf` pulls **52** crates; `pdf_oxide` pulls **141** (~2.7×).

Caveats: default release (fat LTO would shrink both); the workload is read-only — a write path would pull *more* of `pdf_oxide`; WASM sizes not measured but the ratio would likely hold and matters more there (download size). Numbers are directional but the ~3× gap is large and consistent across debug/release/stripped.

### `lopdf` vs `pdf_oxide` — grounded comparison (capability & footprint)

Metadata from crates.io / docs.rs. Age/downloads shown as neutral facts only (not weighted, per the scope note).

| | `lopdf` | `pdf_oxide` |
|---|---|---|
| Latest version / first published *(neutral)* | 0.44.0 / 2016 | 0.3.77 / 2025 |
| Identity (crates.io categories/keywords) | *pdf, editing, manipulation, merge* — **a PDF DOM editor** | *Parsing tools, Text processing; pdf-to-markdown, text-extraction* — **an extraction/conversion library** |
| **Public object-authoring API** (build dict/stream, references, embedded files, annotations) | **Yes** — the API c2pa-rs already builds on | **Yes** (source-verified) — `object::Object` DOM + `EmbeddedFile`/`FileAttachmentAnnotation`/`DocumentEditor`. *Caveat:* typed `AFRelationship` can't emit `C2PA_Manifest`, so the Filespec must be hand-authored via raw `Object` |
| **Release binary (stripped), minimal parse app** | **0.89 MB** | **2.59 MB (~2.9×)** |
| **Dependency tree (crates)** | **52** | **141 (~2.7×)** |
| Always-on dependencies | **18 total, trimmed via `default-features=false`** | **~39 non-optional** even at lean `default=["icc","legacy-crypto"]`: `image`, `jpeg-decoder`, `taffy`, `subsetter`, `ttf-parser`, `office_oxide`, `fax`, `brotli`, `qcms`, `regex`, `chrono`, `env_logger`, `libc`, … |
| Feature-gated heavyweights | — | `pdfium-render` (C++), `ort`/`tract-onnx` (ONNX), `pyo3`, `linfa`, `tokenizers` — off by default (good); crate is built primarily as a polyglot lib (`crate-type = ["cdylib","rlib","staticlib"]`) |
| `no_std` / WASM | Works under c2pa's rayon carve-out | No `no_std`; `libc`/`env_logger` always-on; WASM behind a feature; fit under c2pa's build matrix unverified |
| License / MSRV | MIT / 1.88 | MIT OR Apache-2.0 / 1.88 |

## Recommendation

**Keep `lopdf`.** With capability now confirmed on *both* sides, the decision comes down to footprint and risk-vs-benefit — and `lopdf` wins on all three:

1. **No capability gain.** `pdf_oxide` can express the C2PA constructs — but so does `lopdf`, which c2pa-rs already uses for exactly this. With incremental-update signing **not currently required**, the near-term write path is just *author the objects + save* (a full re-serialize is acceptable), which `lopdf` already does. `pdf_oxide` adds nothing for the current or near-term scope; its real differentiators (extraction/markdown/OCR/rendering/`/Sig` signatures) are orthogonal to manifest embedding.
2. **Measured footprint cost.** Swapping in `pdf_oxide` roughly **triples** the release binary (2.59 MB vs 0.89 MB stripped) and grows the dependency tree **~2.7×** (141 vs 52 crates), even at its lean default features. For a security-critical, WASM-targeting, size-conscious SDK, that is a real, quantified regression for zero functional gain.
3. **Migration friction, no upside.** Even accepting the rewrite, `pdf_oxide`'s typed `EmbeddedFile` helper can't emit `AFRelationship = C2PA_Manifest`, so you'd hand-author the Filespec via its raw object model anyway — the same shape as the current `lopdf` code — while also taking on an unverified re-serialize/round-trip-fidelity risk on the hard-binding path.

So the productive path is unchanged: keep `lopdf`, and wire up the write path (`get_writer` / `save_cai_store` / `get_object_locations`, currently `NotImplemented` at [pdf_io.rs:96-106](sdk/src/asset_handlers/pdf_io.rs)) on it when PDF signing is scheduled. If/when byte-preserving **incremental** update becomes a requirement, `lopdf`'s `IncrementalDocument` already provides it (keep original bytes, append a new revision) — c2pa switches the write path from `Document` to `IncrementalDocument` rather than building an appender.

**When `pdf_oxide` *would* become the better choice:** if c2pa-rs's PDF roadmap expands to need its broader strengths (rendering, extraction, redaction, or native `/Sig` signing) so its footprint is already "paid for" by other features — then consolidating on it and rewriting `pdf.rs` against its (verified-capable) object model becomes reasonable. For today's embed-a-manifest job alone, it isn't worth ~3× the size.

## Open Questions

- **Resolved:** `pdf_oxide` *does* expose the object model + embedded-file/annotation authoring (source-verified in 0.3.77), so a `pdf.rs` rewrite against it is mechanically possible; and the footprint is now measured (~3× binary, ~2.7× deps). The blocker is footprint/benefit, not capability.
- **Only relevant if `pdf_oxide` is ever adopted:** does its `DocumentEditor` edit-path allow injecting a Filespec with a *custom* `AFRelationship` name (`C2PA_Manifest`) into an existing document via the raw `Object` API, or would it need an upstream `AFRelationship::Other(String)`? And does its re-serialize / `save_incremental` preserve prior content faithfully enough for hard binding? Both need a small correctness spike.
- The real work item regardless of library: implement the write path + `get_object_locations` byte ranges (currently `NotImplemented` at [pdf_io.rs:96-106](sdk/src/asset_handlers/pdf_io.rs)); add incremental-update support only if/when required. Is there a CAI ticket to link this analysis to? (None supplied; not linked.)

---

*Not linked to a Jira ticket — none was supplied. Say the key if you want it added locally to this doc.*
