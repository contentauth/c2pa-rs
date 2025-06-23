# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.57.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.56.2...c2pa-c-ffi-v0.57.0)
_19 June 2025_

### Added

* C FFI API should be usable in other Rust projects too ([#1173](https://github.com/contentauth/c2pa-rs/pull/1173))

## [0.56.1](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-c-ffi-v0.56.1)
_18 June 2025_

### Added

* Rename c_api to c2pa_c_ffi and publish ([#1159](https://github.com/contentauth/c2pa-rs/pull/1159))

### Fixed

* Move `rust_native_crypto` feature from Cargo.toml default to release-plz config
* Set `rust_native_crypto` as default feature for c2pa-c-ffi
* Add required entries to Cargo.toml ([#1166](https://github.com/contentauth/c2pa-rs/pull/1166))
* Fix c2pa_c_ffi Cargo.toml to allow `cargo publish` to succeed ([#1164](https://github.com/contentauth/c2pa-rs/pull/1164))

## [0.49.5](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-c-v0.49.5)
_14 May 2025_

### Added

* Adds c_api for dynamic library releases ([#1047](https://github.com/contentauth/c2pa-rs/pull/1047))
