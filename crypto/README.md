# C2PA Cryptography implementation

[![CI](https://github.com/scouten-adobe/TEMP-c2pa-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/scouten-adobe/TEMP-c2pa-crypto/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa-crypto.svg)](https://crates.io/crates/c2pa-crypto) [![docs.rs](https://img.shields.io/docsrs/c2pa-crypto)](https://docs.rs/c2pa-crypto/) [![codecov](https://codecov.io/github/scouten-adobe/TEMP-c2pa-crypto/graph/badge.svg?token=NxwUjwv0j5)](https://codecov.io/github/scouten-adobe/TEMP-c2pa-crypto)

TO DO: New README for c2pa-crypto

## State of the project

This is a beta release (version 0.x.x) of the project. The minor version number (0.x.0) is incremented when there are breaking API changes, which may happen frequently.

### Contributions and feedback

We welcome contributions to this project.  For information on contributing, providing feedback, and about ongoing work, see [Contributing](https://github.com/contentauth/c2pa-js/blob/main/CONTRIBUTING.md).

## Requirements

The library requires **Rust version 1.74.0** or newer.

### Supported platforms

The library has been tested on the following operating systems:

* Windows (Intel only)
* MacOS (Intel and Apple silicon)
* Ubuntu Linux (64-bit Intel and ARM v8)
* WebAssembly (Wasm)

## Crate features

The Rust library crate provides:

* `psxxx_ocsp_stapling_experimental` this is an demonstration feature that will attempt to fetch the OCSP data from the OCSP responders listed in the manifest signing certificate. The response becomes part of the manifest and is used to prove the certificate was not revoked at the time of signing. This is only implemented for PS256, PS384 and PS512 signatures and is intended as a demonstration.
* `openssl_ffi_mutex` prevents multiple threads from accessing the C OpenSSL library simultaneously. (This library is not re-entrant.) In a multi-threaded process (such as Cargo's test runner), this can lead to unpredictable behavior.
## License

The `c2pa-crypto` crate is distributed under the terms of both the [MIT license](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-MIT) and the [Apache License (Version 2.0)](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-APACHE).

Some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.

## Nightly builds

In most cases, you should depend on this crate as published via [crates.io](https://crates.io/crates/c2pa-crypto).

The Adobe team produces nightly snapshots of this crate via a `nightly` branch, which we use for testing the impact of pending changes to upstream dependencies.

You may wish to use these builds for your own testing ahead of our releases, you may include the library via the following `Cargo.toml` entry:

```toml
c2pa-crypto = { git = "https://github.com/contentauth/c2pa-crypto.git", branch = "nightly", features = [...]}
```

Commits in this branch have a modified `sdk/Cargo.toml` entry which includes a version number similar to the following:

```toml
version = "0.25.3-nightly+2023-08-28-2f33ab3"
```

Please note that there is no formal support for code from a nightly release, but if you become aware of any issues, we would appreciate a bug report including this version number.

## Changelog

Refer to the [CHANGELOG](https://github.com/contentauth/c2pa-crypto/blob/main/CHANGELOG.md) for detailed changes derived from Git commit history.
