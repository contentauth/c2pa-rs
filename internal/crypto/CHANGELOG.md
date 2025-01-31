# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

The format of this changelog is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.6.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.6.0...c2pa-crypto-v0.6.1)
_31 January 2025_

### Fixed

* Remove dependency on SubtleCrypto (#881)

## [0.6.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.5.0...c2pa-crypto-v0.6.0)
_29 January 2025_

### Added

* Claim v2 (#707)

## [0.5.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.4.0...c2pa-crypto-v0.5.0)
_24 January 2025_

### Added

* *(crypto)* Make `box_size` parameter on `c2pa_crypto::cose::sign` an `Option` (#879)

### Fixed

* Bump coset requirement to 0.3.8 (#883)

## [0.4.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.3.1...c2pa-crypto-v0.4.0)
_22 January 2025_

### Added

* Change the definition of `Signer.raw_signer()` to return an `Option` defaulting to `None` (#869)

## [0.3.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.3.0...c2pa-crypto-v0.3.1)
_22 January 2025_

### Fixed

* Make alg enum exhaustive (#866)

## [0.3.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-crypto-v0.2.0...c2pa-crypto-v0.3.0)
_16 January 2025_

### Added

* Add `rsa` crate support to `rust_native_crypto` feature (#853)
* Introduce new (experimental) `rust_native_crypto` feature (#850)
* Review `c2pa-crypto` crate API (#813)
* Add new function `c2pa_crypto::cose::signing_time_from_sign1` (#812)
* Move COSE signing into `c2pa_crypto` crate (#807)
* Move COSE timestamp generation into `c2pa_crypto` (#803)
* Move COSE signature verification into `c2pa_crypto` (#801)
* Make `AsyncRawSignatureValidator` available on all platforms (#800)
* Introduce `c2pa_crypto::Verifier::verify_trust` (#798)
* Introduce `c2pa_crypto::cose::Verifier` (#797)
* Consolidate implementations of `cert_chain_from_sign1` in `c2pa_crypto` (#796)
* Move `signing_alg_from_sign1` into `c2pa-crypto` (#795)
* Move `get_cose_sign1` into `c2pa-crypto` crate (#794)
* Move COSE OCSP support into c2pa-crypto (#793)
* Move `verify_trust` into `c2pa_crypto` (#784)
* Introduce `c2pa_crypto::CertificateAcceptancePolicy` (#779)
* Bump MSRV to 1.81.0 (#781)

### Fixed

* Disable the built-in async validators on non-WASM platforms (#855)
* Bring `claim_v2` changes from #707 into `c2pa_crypto` (#811)
* Improve usage of `#[cfg]` directives (#783)

### Updated dependencies

* Bump thiserror from 2.0.6 to 2.0.8 (#787)
* Bump rasn from 0.18.0 to 0.22.0 (#727)
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
