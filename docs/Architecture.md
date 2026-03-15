# C2PA-RS Architecture

This document provides a comprehensive overview of the c2pa-rs project architecture.

## Overview

The c2pa-rs project is organized as a **Cargo workspace** with multiple specialized crates that work together to provide C2PA (Coalition for Content Provenance and Authenticity) functionality. The architecture enables applications to create, sign, embed, parse, and validate C2PA manifests in various media formats.

## Workspace Structure

```
c2pa-rs/
├── sdk/              # Core Rust library (c2pa crate)
├── cli/              # Command-line tool (c2patool)
├── c2pa_c_ffi/       # C language bindings
├── macros/           # Procedural macros
├── export_schema/    # JSON schema exporter
└── make_test_images/ # Test fixture generator
```

## Core Components

### 1. SDK (`sdk/`) - The Core Library

The main Rust library (`c2pa` crate) implements the C2PA specification. It's organized into several architectural layers:

#### Public API Layer

The library provides a high-level, stream-based API:

- **`Builder`**: Creates and signs C2PA manifests with a fluent API
- **`Reader`**: Reads and validates manifests from media files
- **`Context`**: Thread-safe configuration system (replaces older global Settings)
- **`Ingredient`**: Represents source materials used to create content
- **`Manifest`**: Represents a complete C2PA manifest with claims and assertions
- **`Signer` / `AsyncSigner`**: Traits for cryptographic signing operations

#### Core Domain Modules

```
sdk/src/
├── assertions/          # C2PA assertion types (23 files)
│   ├── actions.rs       # Content creation/editing actions
│   ├── creative_work.rs # Creative metadata (schema.org)
│   ├── exif.rs         # EXIF metadata assertions
│   ├── thumbnail.rs    # Thumbnail assertions
│   ├── data_hash.rs    # Data hashing assertions
│   ├── ingredient.rs   # Ingredient assertions
│   ├── metadata.rs     # General metadata
│   └── ...
│
├── asset_handlers/     # Format-specific I/O (12 files)
│   ├── jpeg_io.rs      # JPEG format handler
│   ├── png_io.rs       # PNG format handler
│   ├── bmff_io.rs      # MP4/MOV/video format handler
│   ├── pdf_io.rs       # PDF format handler
│   ├── riff_io.rs      # WAV/WebP format handler
│   ├── tiff_io.rs      # TIFF format handler
│   └── ...
│
├── crypto/             # Cryptographic operations
│   ├── cose/           # COSE signature handling
│   ├── raw_signature/  # Low-level signing implementations
│   │   ├── openssl/    # OpenSSL-based crypto backend
│   │   └── rust_native/# Pure Rust crypto backend
│   ├── time_stamp/     # RFC 3161 timestamp verification
│   ├── ocsp/           # OCSP certificate validation
│   └── asn1/           # ASN.1 utilities
│
├── identity/           # CAWG identity assertion support
│   └── tests/          # Identity validation tests
│
├── jumbf/              # JUMBF container format
├── jumbf_io.rs         # JUMBF I/O operations
├── settings/           # Configuration management
├── utils/              # Utility functions
│   ├── hash_utils.rs   # Hashing utilities
│   ├── mime.rs         # MIME type detection
│   ├── cbor_types.rs   # CBOR helpers
│   └── ...
│
├── builder.rs          # Manifest builder implementation
├── reader.rs           # Manifest reader implementation
├── manifest.rs         # Manifest data structures
├── claim.rs            # C2PA claim structures
├── store.rs            # Internal manifest store
├── signer.rs           # Signer traits and implementations
├── validation_results.rs  # Validation result types
└── context.rs          # Configuration context
```

### 2. CLI Tool (`cli/`) - Command-Line Interface

A standalone executable (`c2patool`) built on top of the SDK:

```
cli/src/
├── main.rs              # CLI entry point and argument parsing
├── info.rs              # Display manifest information
├── signer.rs            # Certificate and key handling
├── callback_signer.rs   # Custom signing callbacks
└── tree.rs              # Manifest tree visualization

cli/
├── docs/                # CLI documentation
├── sample/              # Sample certificates and images
└── schemas/             # JSON schemas
```

**Capabilities:**
- Read and validate manifests from media files
- Create and embed signed manifests
- Generate JSON reports
- Display human-readable manifest trees
- Support for manifest definition files (JSON)

### 3. C FFI Bindings (`c2pa_c_ffi/`)

Provides a C-compatible API wrapper around the SDK, enabling integration with:
- C/C++ applications
- Languages with C FFI support (Python, Go, etc.)
- Native mobile applications

### 4. Supporting Crates

- **`macros/`**: Procedural macros for internal SDK use
- **`export_schema/`**: Tool to export JSON schemas for manifest definitions
- **`make_test_images/`**: Utility to generate test fixtures with C2PA data

## Architectural Patterns

### 1. Stream-Based Processing

The library operates on streams (`Read + Seek`) rather than requiring full files in memory:

```rust
let stream = std::fs::File::open("image.jpg")?;
let reader = Reader::from_stream("image/jpeg", stream)?;
```

This enables efficient handling of large media assets (e.g., multi-GB video files) without loading entire files into memory.

### 2. Format Abstraction

Asset handlers provide a unified interface for different media formats. Each handler implements format-specific logic for:
- Locating manifest data within the file
- Embedding manifests in the appropriate container
- Preserving format-specific metadata

**Supported Formats:**
- **Images**: JPEG, PNG, GIF, TIFF, WebP, SVG
- **Video**: MP4, MOV, HEIF, HEIC, fragmented MP4
- **Audio**: WAV, MP3
- **Documents**: PDF
- **Container**: C2PA standalone format

### 3. Pluggable Cryptography

The library supports multiple cryptographic backends through feature flags:

- **OpenSSL backend** (default): Uses vendored OpenSSL
- **Rust native crypto**: Pure Rust implementation using RustCrypto crates
- **WASM compatibility**: Special handling for browser environments

Both backends support:
- RSA (2048, 3072, 4096-bit)
- ECDSA (P-256, P-384, P-521)
- EdDSA (Ed25519)

### 4. Thread-Safe Configuration

The `Context` struct provides thread-safe configuration:

```rust
let context = Context::new()
    .with_settings(include_str!("settings.toml"))?;

// Share across threads
let context = Arc::new(context);
```

Benefits:
- Multiple configurations can coexist
- Safe sharing across threads using `Arc<Context>`
- Backwards compatible with existing Settings files
- Automatic signer creation from settings

### 5. Resource Management

The `ResourceStore` abstraction handles various resource types:

- **JUMBF references**: `self#jumbf=...` - Embedded resources
- **HTTP(S) references**: Remote manifests and ingredients
- **Local file references**: `file:///path/to/resource`
- **Application references**: `app://contentauth/...` - Working store references
- **In-memory data**: Direct binary data

## Data Flow Architecture

### Reading a Manifest (Validation Flow)

```
┌─────────────┐
│ Media File  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Reader    │ ◄── Context (config)
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Asset Handler   │ (format-specific)
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│  JUMBF Parser   │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│   Manifest      │
│   + Claims      │
│   + Assertions  │
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│   Validation    │
│   - Signatures  │
│   - Timestamps  │
│   - Certificates│
│   - Hashes      │
└──────┬──────────┘
       │
       ▼
┌─────────────────────┐
│ ValidationResults   │
└─────────────────────┘
```

### Creating a Manifest (Signing Flow)

```
┌──────────────────┐
│ Manifest         │
│ Definition (JSON)│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│    Builder       │ ◄── Context (config, signer)
│  + add_assertion│
│  + add_ingredient│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Generate Claim  │
│  + Assertions    │
│  + Ingredients   │
│  + Resources     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│     Signer       │ (cryptographic signing)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ COSE Signature   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ JUMBF Container  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Asset Handler   │ (format-specific embedding)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Signed Media File│
└──────────────────┘
```

## Key Architectural Decisions

### 1. Feature Flags for Modularity

The SDK uses extensive cargo features to enable optional functionality:

```toml
[features]
default = ["openssl", "default_http"]

# Cryptography backends
openssl = ["dep:openssl"]
rust_native_crypto = ["dep:p256", "dep:p384", "dep:rsa", ...]

# Optional capabilities
file_io = []
add_thumbnails = ["image"]
pdf = ["dep:lopdf"]
fetch_remote_manifests = ["dep:wasi"]
json_schema = ["dep:schemars"]

# HTTP clients
http_reqwest = ["dep:reqwest"]
http_ureq = ["dep:ureq"]
http_wasi = ["dep:wasi"]
http_wstd = ["dep:wstd"]
```

This allows users to:
- Minimize binary size by excluding unused features
- Choose cryptographic backends
- Select appropriate HTTP clients for their environment

### 2. Cross-Platform Support

The library supports multiple platforms with platform-specific optimizations:

- **Native platforms**: 
  - Windows (x86_64, MSVC)
  - macOS (x86_64, Apple Silicon with SHA2 ASM optimization)
  - Linux (x86_64, ARM v8)
  
- **WebAssembly (WASM32)**:
  - Browser environments with JS interop
  - Special handling for crypto APIs (SubtleCrypto)
  - WASM-specific dependencies (wasm-bindgen, js-sys)
  
- **WASI (WebAssembly System Interface)**:
  - Server-side WASM with system access
  - File I/O and network support

Platform-specific dependencies are configured via:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
# macOS-specific optimizations

[target.'cfg(target_arch = "wasm32")'.dependencies]
# WASM-specific dependencies
```

### 3. Async/Sync Duality

The library supports both synchronous and asynchronous operations:

- **Sync API**: Uses `ureq` or WASI HTTP for blocking requests
- **Async API**: Uses `reqwest` or `wstd` for non-blocking requests

This is particularly important for:
- Network requests (fetching remote manifests)
- OCSP validation
- Timestamp authority requests

### 4. Validation and Error Handling

The library uses a layered validation approach:

1. **Hard failures**: Cryptographic signature failures, invalid manifest structure
2. **Validation status**: Tracked per-assertion and per-claim
3. **Warnings**: Non-critical issues (e.g., missing recommended fields)

Results are aggregated into `ValidationResults` with detailed status tracking.

## Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `builder` | Fluent API for constructing manifests |
| `reader` | Parse and validate manifests from media |
| `manifest` | Core manifest data structures |
| `claim` | C2PA claim generation and validation |
| `store` | Internal manifest store (multiple manifests) |
| `signer` | Signing abstraction and trait definitions |
| `context` | Thread-safe configuration management |
| `assertions` | All standard C2PA assertion types |
| `asset_handlers` | Format-specific read/write operations |
| `crypto` | Cryptographic primitives and validation |
| `jumbf` / `jumbf_io` | JUMBF container format handling |
| `validation_status` | Validation state tracking |
| `validation_results` | Validation result aggregation |
| `ingredient` | Parent ingredient handling |
| `resource_store` | Resource reference management |
| `utils` | Hash utilities, MIME detection, etc. |

## External Dependencies

The project relies on several key categories of external crates:

### Cryptography
- **OpenSSL**: `openssl` (vendored)
- **Rust Native**: `rsa`, `ed25519-dalek`, `ecdsa`, `p256`, `p384`, `p521`
- **Standards**: `coset` (COSE), `x509-parser`, `rasn` (ASN.1), `der`, `pkcs8`

### Media Format Handling
- **Images**: `img-parts`, `png_pong`, `jfifdump`
- **Video**: `mp4`, `byteordered`
- **Audio**: `id3`, `riff`
- **PDF**: `lopdf` (optional)
- **Image processing**: `image` (optional, for thumbnails)

### Serialization
- **General**: `serde`, `serde_json`, `toml`
- **CBOR**: `c2pa_cbor`
- **XML**: `quick-xml`

### HTTP Clients (optional)
- **Async**: `reqwest`
- **Sync**: `ureq`
- **WASI**: `wasi`, `wstd`

### Utilities
- **Hashing**: `sha2`, `sha1`
- **Random**: `rand`, `rand_chacha`
- **Time**: `chrono`, `web-time`
- **Compression**: `zip`

## Testing Strategy

The project uses multiple testing approaches:

1. **Unit tests**: Inline tests in each module
2. **Integration tests**: `sdk/tests/` directory
3. **Example programs**: `sdk/examples/` demonstrating API usage
4. **CI/CD**: Multi-tier testing (Tier 1A, 1B, Tier 2) across platforms
5. **Test fixtures**: Generated via `make_test_images` utility

## Performance Considerations

1. **Streaming I/O**: Avoids loading entire files into memory
2. **SHA2 ASM**: Hardware acceleration on ARM64 macOS
3. **Link-time optimization**: Enabled in release builds (`lto = "thin"`)
4. **Lazy validation**: Only validates when requested
5. **Efficient hashing**: Range-based hashing for large assets

## Security Considerations

1. **No panics**: `#![deny(clippy::unwrap_used)]` enforced
2. **Zeroization**: Sensitive data (keys) zeroized after use
3. **Certificate validation**: Full chain validation with OCSP support
4. **Timestamp verification**: RFC 3161 timestamp validation
5. **Hash verification**: All referenced resources validated by hash

## Future Architecture Notes

- The library is in beta (0.x.x versions)
- Breaking API changes occur on minor version bumps
- Migration from v1 to v2 claims complete
- New `Context` API replaces global Settings pattern
- Async API expansion ongoing

## Related Documentation

- [Usage Guide](usage.md)
- [Supported Formats](supported-formats.md)
- [CAWG Identity](cawg-identity.md)
- [Contributing](../CONTRIBUTING.md)
- [Release Notes](release-notes.md)
