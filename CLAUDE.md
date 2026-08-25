# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About This Project

`c2pa-rs` is a Rust implementation of the [C2PA (Coalition for Content Provenance and Authenticity)](https://c2pa.org/) specification. It enables embedding, reading, and validating cryptographically signed provenance manifests in media files (images, video, audio, PDF, etc.).

- Workspace version: **0.79.5** | MSRV: **1.88.0** | Status: **Beta** (minor versions may break)
- Primary crate (`c2pa`) lives in `sdk/`

## Workspace Structure

```
sdk/          - Core C2PA library (crate name: "c2pa")
cli/          - c2patool command-line tool
c2pa_c_ffi/   - C FFI bindings
macros/       - Procedural macros
make_test_images/ - Test asset generator
export_schema/    - JSON schema export
```

## Commands

The `Makefile` is the canonical way to run common tasks. It uses `cargo-nextest` when available, falling back to `cargo test`.

```bash
# Run full local validation (format + docs + clippy + tests + WASM)
make test

# Fast SDK-only loop (format check + docs + clippy + unit/integration tests)
make test-sdk

# Quick local tests with common features enabled
make test-local

# WASM tests (Node environment)
make test-wasm

# Format & lint
make check-format
make fmt          # Uses nightly
make clippy

# Docs
make check-docs
make doc          # Build and open docs

# Build test images / export schemas
make images
make schema
```

### Running a single test

```bash
# Run a specific test by name
cargo test -p c2pa <test_name>

# With features
cargo test -p c2pa --features file_io,fetch_remote_manifests <test_name>

# With nextest
cargo nextest run -p c2pa <test_name>
```

### Common feature combinations

```bash
# Standard development
--features file_io,fetch_remote_manifests,add_thumbnails

# Pure Rust crypto (no OpenSSL)
--no-default-features --features rust_native_crypto,file_io
```

## Architecture

### Core Abstractions

**`Context`** (`sdk/src/context.rs`) — thread-safe (`Arc<Context>`) configuration container. Controls signers, settings, progress callbacks. Replaces legacy global `Settings`.

**`Reader`** (`sdk/src/reader.rs`) — entry point for parsing/validating C2PA manifests from assets. Key methods: `Reader::from_stream()`, `Reader::from_context()`.

**`Builder`** (`sdk/src/builder.rs`) — entry point for creating and signing manifests. Fluent API, streaming-capable. Finalizes with `builder.save_to_stream()`.

**`Store`** (`sdk/src/store.rs`) — low-level binary manifest storage in JUMBF format. `Manifest` and `Claim` types live here and in `manifest.rs`/`claim.rs`.

### Key Subsystems

- **Assertions** (`sdk/src/assertions/`) — 25+ standard C2PA assertion types (Actions, DataHash, BoxHash, Ingredient, CreativeWork, etc.) plus CAWG identity assertions.
- **Asset Handlers** (`sdk/src/asset_handlers/`) — per-format I/O: JPEG, PNG, GIF, TIFF, WebP, MP4/BMFF, MP3/FLAC, PDF, SVG, JPEG XL. Each format has a dedicated `*_io.rs`.
- **Cryptography** (`sdk/src/crypto/`) — two backends selectable via features:
  - `openssl` (default, C library, vendored)
  - `rust_native_crypto` (pure Rust: RSA, ECDSA, Ed25519)
  - COSE signing/validation lives here.
- **HTTP** (`sdk/src/http/`) — pluggable HTTP resolver trait with implementations: `reqwest` (async), `ureq` (sync), `wasi`, `wstd`.
- **Settings** (`sdk/src/settings/`) — JSON/TOML configuration for trust anchors, certificate paths, signer config.

### Signer Traits

- `Signer` — synchronous signing
- `AsyncSigner` — async signing
- Both support callback-based and ephemeral (test) implementations

### Platform Support via Feature Flags

| Feature | Purpose |
|---|---|
| `openssl` | Default crypto backend (C, vendored) |
| `rust_native_crypto` | Pure-Rust crypto alternative |
| `file_io` | Filesystem access |
| `fetch_remote_manifests` | Network manifest fetching |
| `add_thumbnails` | Image thumbnail generation |
| `pdf` | PDF format support |
| `http_reqwest` / `http_ureq` | HTTP implementations |

WASM (`wasm32-unknown-unknown`) and WASI (`wasm32-wasip2`) are supported targets with platform-specific feature flags.

## Testing

- Unit and integration tests: `sdk/tests/` and inline `#[cfg(test)]` modules
- Fixtures: `sdk/tests/fixtures/`
- Benchmarks (criterion): `sign` and `read` in `sdk/benches/`
- CI runs tier-1a (standard), tier-1b (extended, triggered by label), and tier-2 (additional platforms)

## Release Process

Releases use `release-plz` (see `.github/workflows/release.yml`). The `CHANGELOG.md` is auto-maintained.
