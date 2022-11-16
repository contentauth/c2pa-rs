# C2PA Rust SDK

[![CI](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa.svg)](https://crates.io/crates/c2pa) [![docs.rs](https://img.shields.io/docsrs/c2pa)](https://docs.rs/c2pa/) [![codecov](https://codecov.io/gh/contentauth/c2pa-rs/branch/main/graph/badge.svg?token=YVHWI19EGN)](https://codecov.io/gh/contentauth/c2pa-rs)

The **[Coalition for Content Provenance and Authenticity](https://c2pa.org)** (C2PA) addresses the prevalence of misleading information online through the development of technical standards for certifying the source and history (or provenance) of media content. Adobe and other contributors created the C2PA Rust SDK as part of the [Content Authenticity Initiative](https://contentauthenticity.org) and [released it to open source](https://contentauthenticity.org/blog/cai-releases-suite-of-open-source-tools-to-advance-digital-content-provenance) in June, 2022. 

## Key features

The C2PA Rust SDK implements a subset of the [C2PA 1.0 technical specification](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html). 

The SDK enables a desktop, mobile, or embedded application to: 
* Create and sign C2PA [claims](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_claims) and [manifests](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_manifests).
* Embed manifests in certain file formats.
* Parse and validate manifests found in certain file formats.

The SDK supports several common C2PA [assertions](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_standard_assertions) and [hard bindings](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_hard_bindings).

## State of the project

This is an early release (version 0.x.x) of the project. The minor version number (0.x.0) is incremented when there are breaking API changes, which may happen frequently.

The SDK:
* Supports a variety of image and video formats. For details, see [c2patool supported file formats](https://opensource.contentauthenticity.org/docs/c2patool/#supported-file-formats).
* Does not parse identity structures (verifiable credentials).

### Contributions and feedback

We welcome contributions to this project.  For information on contributing, providing feedback, and about ongoing work, see [Contributing](https://github.com/contentauth/c2pa-js/blob/main/CONTRIBUTING.md).

## Requirements

The SDK requires **Rust version 1.61.0** or newer.

### Supported platforms

The SDK has been tested on the following operating systems:

* Windows
* MacOS (Intel and Apple silicon)
* Ubuntu Linux
* WebAssembly (Wasm); NOTE: claim _generation_ is not available on Wasm.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
c2pa = "0.15.0"
```

If you want to read or write a manifest file, add the `file_io` dependency to your `Cargo.toml`. For example:
```
c2pa = { version = "0.11.0", features = ["file_io"] }
```

NOTE: If you are building for WASM, omit the `file_io` dependency.

## Crate features

The Rust SDK crate provides:

* `async_signer` enables signing via asynchronous services which require `async` support.
* `bmff` enables handling of ISO base media file formats (BMFF) used for video. Currently only MP4, M4A, and MOV are enabled for writing.
* `file_io` enables manifest generation, signing via OpenSSL, and embedding manifests in various file formats.
* `serialize_thumbnails` includes binary thumbnail data in the [Serde](https://serde.rs/) serialization output.
* `xmp_write` enables updating XMP on embed with the `dcterms:provenance` field. (Requires [xmp_toolkit](https://crates.io/crates/xmp_toolkit).)
* `no_interleaved_io` forces fully-synchronous I/O; otherwise, the SDK uses threaded I/O for some operations to improve performance.
* `fetch_remote_manifests` enables the verification step to retrieve externally referenced manifest stores.  External manifests are only fetched if there is no embedded manifest store and no locally adjacent .c2pa manifest store file of the same name.

## License

The `c2pa` crate is distributed under the terms of both the [MIT license](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-MIT) and the [Apache License (Version 2.0)](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-APACHE).

Note that some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.
