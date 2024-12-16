# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

The format of this changelog is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.2.0...c2pa-crypto-v0.3.0)
_16 December 2024_

### Added

* Bump MSRV to 1.81.0 (#781)

### Updated dependencies

* Bump thiserror from 1.0.69 to 2.0.6 (#770)

## [0.2.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.1.2...c2pa-crypto-v0.2.0)
_12 December 2024_

### Added

* Add `RawSigner` trait to `c2pa-crypto` (derived from `c2pa::Signer`) (#716)
* Move time stamp code into c2pa-crypto (#696)

### Fixed

* Compile `c2pa-crypto` with `cargo check` (#768)
* Verbose assertions for `is_none()` (#704)
* Remove `c2pa::Signer` dependency on `c2pa_crypto::TimeStampProvider` (#718)
* Treat Unicode-3.0 license as approved; unpin related dependencies (#693)

### Updated dependencies

* Bump chrono from 0.4.38 to 0.4.39 (#763)

## [0.1.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.1.1...c2pa-crypto-v0.1.2)
_24 October 2024_

### Fixed

* Fix badges in README

## [0.1.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.1.0...c2pa-crypto-v0.1.1)
_24 October 2024_

### Fixed

* Tweak changelog format

## [0.1.0](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-crypto-v0.1.0)
_24 October 2024_

### Added

* Create placeholders for forthcoming crates ([#645](https://github.com/contentauth/c2pa-rs/pull/645))
