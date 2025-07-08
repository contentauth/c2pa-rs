# C2PA Rust library

[![CI](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa.svg)](https://crates.io/crates/c2pa) [![docs.rs](https://img.shields.io/docsrs/c2pa)](https://docs.rs/c2pa/) [![codecov](https://codecov.io/gh/contentauth/c2pa-rs/branch/main/graph/badge.svg?token=YVHWI19EGN)](https://codecov.io/gh/contentauth/c2pa-rs)

<div style={{display: 'none'}}>

The **[Coalition for Content Provenance and Authenticity](https://c2pa.org)** (C2PA) addresses the prevalence of misleading information online through the development of technical standards for certifying the source and history (or provenance) of media content. The C2PA Rust library is part of the [Content Authenticity Initiative](https://contentauthenticity.org) open-source SDK.

For the best experience, read the docs on the [CAI Open Source SDK documentation website](https://opensource.contentauthenticity.org/docs/rust-sdk/).  

You can also read the documentation directly in GitHub:

- [Usage](https://github.com/contentauth/c2pa-rs/blob/main/docs/usage.md)
- [Supported formats](https://github.com/contentauth/c2pa-rs/blob/main/docs/supported-formats.md)
- [Using the CAWG identity assertion](https://github.com/contentauth/c2pa-rs/blob/main/docs/cawg-identity.md)
- [Release notes](https://github.com/contentauth/c2pa-rs/blob/main/docs/release-notes.md)
- [Contributing to the project](https://github.com/contentauth/c2pa-rs/blob/main/docs/project-contributions.md)

- [C2PA Tool](https://github.com/contentauth/c2pa-rs/blob/main/cli/README.md) documentation:
  - [Using C2PA Tool](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/usage.md)
  - [Manifest definition file](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/manifest.md)
  - [Using an X.509 certificate](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/x_509.md)
  - [Change log](https://github.com/contentauth/c2pa-rs/blob/main/cli/CHANGELOG.md)

</div>

## Key features

The [`c2pa` crate](https://crates.io/crates/c2pa) implements a subset of the [C2PA technical specification](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html) and the [CAWG identity assertion specification](https://cawg.io/identity) in the Rust programming language.

The library enables a desktop, mobile, or embedded application to:
* Create and sign C2PA [claims](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_claims) and [manifests](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_manifests).
* Create, sign, and validate [CAWG identity assertions](https://cawg.io/identity) in C2PA manifests.  See [Using the CAWG identity assertion](docs/cawg-identity.md) for more information.
* Embed manifests in [supported file formats](docs/supported-formats.md).
* Parse and validate manifests found in [supported file formats](docs/supported-formats.md).

The library supports several common C2PA [assertions](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_c2pa_standard_assertions) and [hard bindings](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_hard_bindings).

For details on what you can do with the library, see [Using the Rust library](https://opensource.contentauthenticity.org/docs/rust-sdk/docs/usage).

## State of the project

This is a beta release (version 0.x.x) of the project. The minor version number (0.x.0) is incremented when there are breaking API changes, which may happen frequently.

**NOTE**: The library now supports [C2PA v2 claims](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_claims), however development is still in progress and all features are not fully implemented yet. While you can experiment with this functionality, it is not recommended for production use at this time.  For details, see [C2PA v2 claims](https://opensource.contentauthenticity.org/docs/rust-sdk/docs/release-notes#c2pa-v2-claims).

### New API

NOTE: The current release includes a new API that replaces old methods of reading and writing C2PA data, which are deprecated.  See the [release notes](https://opensource.contentauthenticity.org/docs/rust-sdk/docs/release-notes) for more information. 

## Installation

### Prerequisites

**Install Rust and Cargo**

To use the CAI Rust library, you must install [Rust and Cargo](https://doc.rust-lang.org/cargo/index.html).

Minimal supported Rust version (MSRV): The `c2pa` crate requires Rust version 1.85.0 or newer. When a newer version of Rust becomes required, a new minor (0.x.0) version of this crate will be released.

**Install C build tools**

Install the C build tools for your development platoform"

- macOS: XCode with command-line tools
- Windows: Microsoft Visual C++ (MSVC)

### Build

The easiest way to build the library is by using the `Makefile`.

To build unit tests, use this command:

```
make test
```

To build the binary libraries, use this command:

```
make release
```

### Add dependency

Add the following line to your `Cargo.toml`:

```
c2pa = "<VERSION_NUMBER>"
```

Where `<VERSION_NUMBER>` is the [latest version of the crate as shown on crates.io](https://crates.io/crates/c2pa).

## Contributions and feedback

We welcome contributions to this project.  For information on contributing, providing feedback, and about ongoing work, see [Contributing](https://github.com/contentauth/c2pa-rs/blob/main/CONTRIBUTING.md).  For additional information on testing, see [Contributing to the project](https://github.com/contentauth/c2pa-rs/blob/main/docs/project-contributions.md).

## License

The `c2pa` crate is distributed under the terms of both the [MIT license](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-MIT) and the [Apache License (Version 2.0)](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-APACHE).

Some components and dependent crates are licensed under different terms; please check their licenses for details.
