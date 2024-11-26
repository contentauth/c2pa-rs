# C2PA Rust library

[![CI](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa.svg)](https://crates.io/crates/c2pa) [![docs.rs](https://img.shields.io/docsrs/c2pa)](https://docs.rs/c2pa/) [![codecov](https://codecov.io/gh/contentauth/c2pa-rs/branch/main/graph/badge.svg?token=YVHWI19EGN)](https://codecov.io/gh/contentauth/c2pa-rs)

<div style={{display: 'none'}}>

The **[Coalition for Content Provenance and Authenticity](https://c2pa.org)** (C2PA) addresses the prevalence of misleading information online through the development of technical standards for certifying the source and history (or provenance) of media content. The C2PA Rust library is part of the [Content Authenticity Initiative](https://contentauthenticity.org) open-source SDK.

For the best experience, read the docs on the [CAI Open Source SDK documentation website](https://opensource.contentauthenticity.org/docs/c2pa-node/).  Some additional documentation for this repository is also available on GitHub:

- [Usage](docs/usage.md)
- [Supported formats](docs/supported-formats.md)
- [Release notes](docs/release-notes.md)
- [Contributing to the project](docs/project-contributions.md)

</div>

## Key features

[The c2pa-rs repository](https://github.com/contentauth/c2pa-rs) implements a subset of the [C2PA technical specification](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html) in the Rust programming language.

The library enables a desktop, mobile, or embedded application to:
* Create and sign C2PA [claims](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_claims) and [manifests](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_manifests).
* Embed manifests in [supported file formats](docs/supported-formats.md).
* Parse and validate manifests found in [supported file formats](docs/supported-formats.md).

The library supports several common C2PA [assertions](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_c2pa_standard_assertions) and [hard bindings](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_hard_bindings).

For details on what you can do with the library, see [Using the Rust library](docs/usage.md).

## State of the project

This is a beta release (version 0.x.x) of the project. The minor version number (0.x.0) is incremented when there are breaking API changes, which may happen frequently.  

### New API

NOTE: The current release includes a new API that replaces old methods of reading and writing C2PA data, which are deprecated.  See the [release notes](docs/release-notes.md) for more information. 

### Contributions and feedback

We welcome contributions to this project.  For information on contributing, providing feedback, and about ongoing work, see [Contributing](https://github.com/contentauth/c2pa-rs/blob/main/CONTRIBUTING.md).  For additional information on nightly builds and testing, see [Contributing to the project](docs/project-contributions.md).

## License

The `c2pa` crate is distributed under the terms of both the [MIT license](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-MIT) and the [Apache License (Version 2.0)](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-APACHE).

Some components and dependent crates are licensed under different terms; please check their licenses for details.
