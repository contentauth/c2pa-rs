# C2PA Rust SDK

[![CI](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa.svg)](https://crates.io/crates/c2pa) [![docs.rs](https://img.shields.io/docsrs/c2pa)](https://docs.rs/c2pa/) [![codecov](https://codecov.io/gh/contentauth/c2pa-rs/branch/main/graph/badge.svg?token=YVHWI19EGN)](https://codecov.io/gh/contentauth/c2pa-rs)

The **[Coalition for Content Provenance and Authenticity](https://c2pa.org)** (C2PA) addresses the prevalence of misleading information online through the development of technical standards for certifying the source and history (or provenance) of media content. The C2PA Rust SDK was created by Adobe and other contributors as part of the [Content Authenticity Initiative](https://contentauthenticity.org) and [released to open source](https://contentauthenticity.org/blog/cai-releases-suite-of-open-source-tools-to-advance-digital-content-provenance) in June, 2022. 

## Key features

The C2PA Rust SDK implements a subset of the [C2PA 1.0 technical specification](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html). 

The SDK enables a desktop, mobile, or embedded application to: 
* Create and sign C2PA [claims](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_claims) and [manifests](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_manifests).
* Embed manifests in certain file formats.
* Parse and validate manifests found in certain file formats.

The SDK supports several common C2PA [assertions](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_standard_assertions) and [hard bindings](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_hard_bindings).

## State of the project

This project is an early pre-release version and has unimplemented features and may have outstanding issues or bugs. While in prerelease form, the minor version number (0.x.0) will be incremented when there are breaking API changes, which may happen frequently.

The SDK:
* Currently supports only still image formats (JPEG and PNG).
* Does not parse identity structures (verifiable credentials).

### Contributions and feedback

We welcome contributions to this project.  For information on contributing, providing feedback, and about ongoing work, see [Contributing](https://github.com/contentauth/c2pa-js/blob/main/CONTRIBUTING.md).

## Requirements

The SDK requires **Rust version 1.58.0** or newer.

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
c2pa = "0.11.0"
```

## Crate features

The Rust SDK crate provides:

* `async_signer` enables signing via asynchronous services which require `async` support.
* `bmff` enables handling of BMFF file formats. Currently only MP4, M4A, and MOV are enabled for writing.
* `file_io` enables manifest generation, signing via OpenSSL, and embedding manifests in various file formats.
* `serialize_thumbnails` includes binary thumbnail data in the [Serde](https://serde.rs/) serialization output.
* `xmp_write` enables updating XMP on embed with the `dcterms:provenance` field. (Requires [xmp_toolkit](https://crates.io/crates/xmp_toolkit).)
* `no_interleaved_io` the SDK uses threaded I/O for some operations to improve performance. Using this feature will force fully synchronous I/O.


## License

The `c2pa` crate is distributed under the terms of both the [MIT license](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-MIT) and the [Apache License (Version 2.0)](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-APACHE).

Note that some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.
