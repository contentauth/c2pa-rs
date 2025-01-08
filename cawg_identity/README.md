# Implementation of CAWG identity assertion specification

[![CI](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/cawg-identity.svg)](https://crates.io/crates/cawg-identity) [![docs.rs](https://img.shields.io/docsrs/cawg-identity)](https://docs.rs/cawg-identity/) [![codecov](https://codecov.io/gh/contentauth/c2pa-rs/branch/main/graph/badge.svg?token=YVHWI19EGN)](https://codecov.io/gh/contentauth/c2pa-rs)

Implementation of the core of the [Creator Assertions Working Group identity assertion draft specification](https://cawg.io/identity/).

## Contributions and feedback

We welcome contributions to this project. For information on contributing, providing feedback, and about ongoing work, see [Contributing](../CONTRIBUTING.md).

## Known limitations

This is very early days for this crate. Many things are subject to change at this point.

## Requirements

The toolkit requires **Rust version 1.81.0** or newer. When a newer version of Rust becomes required, a new minor (0.x.0) version of this crate will be released.

### Supported platforms

The toolkit has been tested on the following operating systems:

* Windows
  * Only the MSVC build chain is supported on Windows. We would welcome a PR to enable GNU build chain support on Windows.

* MacOS (Intel and Apple silicon)

* Ubuntu Linux on x86 and ARM v8 (aarch64)

## License

The `cawg-identity` crate is distributed under the terms of both the MIT license and the Apache License (Version 2.0).

Some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.
