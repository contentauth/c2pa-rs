# C2PA Rust SDK

[![CI](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa.svg)](https://crates.io/crates/c2pa) [![docs.rs](https://img.shields.io/docsrs/c2pa)](https://docs.rs/c2pa/) [![codecov](https://codecov.io/gh/contentauth/c2pa-rs/branch/main/graph/badge.svg?token=YVHWI19EGN)](https://codecov.io/gh/contentauth/c2pa-rs)

The **[Coalition for Content Provenance and Authenticity](https://c2pa.org)** (C2PA) addresses the prevalence of misleading information online through the development of technical standards for certifying the source and history (or provenance) of media content. C2PA is a Joint Development Foundation project, formed through an alliance between Adobe, Arm, Intel, Microsoft and Truepic.

This Rust library for creating and inspecting C2PA data structures is created by Adobe and other contributors as part of our work on the [Content Authenticity Initiative](https://contentauthenticity.org).

## Key features

* Creation and signing of C2PA [claims](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_claims) and [manifests](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_manifests)
* Embedding manifests in certain file formats
* Parsing and validation of manifests found in certain file formats
* Support for several common C2PA [assertions](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_c2pa_standard_assertions)
* [Hard binding](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_hard_bindings) support

## State of the project

This project is in a "soft launch" state as of May 2022.

We have been using this crate as the foundation of our Content Authenticity Initiative-related products and services since late 2020, so we have considerable experience with this code ourselves.

That said, we spent most of that time focused on our own internal requirements. As we shift toward making this crate available for open usage, we're aware that there is quite a bit of work to do to create what we'd feel comfortable calling a 1.0 release. We've decided to err on the side of releasing earlier so that people can experiment with it and give us feedback.

We expect to do work on a number of areas in the next few months while we remain in prerelease (0.x) versions. Some broad categories of work (and thus things you might expect to change) are:

* We'll be reviewing and refining our APIs for ease of use and comprehension. We'd appreciate feedback on areas that you find confusing or unnecessarily difficult.
* We'll also be reviewing our APIs for compliance with Rust community best practices. There are some areas (for example, use of public fields and how we take ownership vs references) where we know some work is required.
* Our documentation is incomplete. We'll be working on refining the documentation.
* Our testing infrastructure is incomplete. We'll be working on improving test coverage, memory efficiency, and performance benchmarks.

While in prerelease form, we'll increment the minor version number (0.x.0) when we make breaking API changes and we expect that this will happen with some frequency.

## What's implemented and not implemented?

* This crate implements a subset of the [C2PA 1.0 technical specification](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html).
* This crate currently only supports still image formats (JPEG and PNG).
* We haven't yet implemented parsing of identity structures (verifiable credentials).

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
c2pa = "0.5.2"
```

## Crate features

* `async_signer` enables signing via asynchronous services which require `async` support.
* `bmff` enables handling of BMFF file formats. Currently only MP4, M4A, and MOV are enabled for writing.
* `file_io` enables manifest generation, signing via OpenSSL, and embedding manifests in various file formats.
* `serialize_thumbnails` includes binary thumbnail data in the [Serde](https://serde.rs/) serialization output.
* `xmp_write` enables updating XMP on embed with the `dcterms:provenance` field (requires [xmp_toolkit](https://crates.io/crates/xmp_toolkit)).

## Rust version requirements

This crate requires **Rust version 1.58.0** or newer.

## Supported platforms

We have tested it on recent versions of the following operating systems:

* Windows
* MacOS (Intel and Apple Silicon)
* Ubuntu Linux
* WASM (note that claim _generation_ is not available on WASM)

## What feedback do we seek?

We would welcome feedback on:

* API design
* prioritization of upcoming development, especially:
  * file format support
  * assertion support
* optimizations and performance concerns
* bugs or non-compliance with the C2PA spec
* additional platform support

If you would like to contribute to this crate, please read our [code of conduct](./CODE_OF_CONDUCT.md) and [contribution guidelines](./CONTRIBUTING.md).

## License

The `c2pa` crate is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](./LICENSE-APACHE) and [LICENSE-MIT](./LICENSE-MIT).

Note that some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.
