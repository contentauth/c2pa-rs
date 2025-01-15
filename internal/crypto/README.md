# C2PA cryptography implementation

[![CI](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa-crypto.svg)](https://crates.io/crates/c2pa-crypto) [![docs.rs](https://img.shields.io/docsrs/c2pa-crypto)](https://docs.rs/c2pa-crypto/) [![![codecov](https://codecov.io/gh/contentauth/c2pa-rs/branch/main/graph/badge.svg?token=YVHWI19EGN)](https://codecov.io/gh/contentauth/c2pa-rs)

This crate contains some of the internal cryptography implementation that is shared between the [c2pa crate](https://crates.io/crates/c2pa) and the [CAWG identity SDK crate](https://crates.io/crates/cawg-identity). It is not intended to be used directly in most cases.

### Contributions and feedback

We welcome contributions to this project. For information on contributing, providing feedback, and about ongoing work, see [Contributing](https://github.com/contentauth/c2pa-rs/blob/main/CONTRIBUTING.md). For additional information on nightly builds and testing, see [Contributing to the project](docs/project-contributions.md).

## Crate features

This crate has two features, neither of which are enabled by default:

* `json_schema`: Used by c2pa-rs documentation code to generate JSON schema for types defined in this crate.
* `rust_native_crypto`: Where available, prefer Rust-native cryptography libraries for raw signature and validation implementations. (Experimental)

## License

The `c2pa-crypto` crate is distributed under the terms of both the [MIT license](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-MIT) and the [Apache License (Version 2.0)](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-APACHE).

Some components and dependent crates are licensed under different terms; please check their licenses for details.
