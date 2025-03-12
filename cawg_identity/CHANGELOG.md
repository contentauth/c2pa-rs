# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

The format of this changelog is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.10.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.9.0...cawg-identity-v0.10.0)
_12 March 2025_

### Added

* Add `StatusTracker` to `IdentityAssertion` parsing and validation APIs (#943)
* Simplify `StatusTracker` interface (#937)
* Add WASI support to cawg_identity (#942)
* Adds validation_state to the json reports from the Reader (#930)

### Fixed

* Add example file with CAWG X.509 signing (#948)
* Update CAWG SDK README to reflect current status (#947)

### Other

* Remove `openssl` feature flag (#940)

## [0.9.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.8.0...cawg-identity-v0.9.0)
_15 February 2025_

### Added

* Add support for DynamicAssertions in JSON format (#924)

## [0.8.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.7.0...cawg-identity-v0.8.0)
_12 February 2025_

### Added

* *(cawg_identity)* Add new functions for generating a `Serialize`-able report for entire manifest store (#920)

## [0.7.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.6.1...cawg-identity-v0.7.0)
_11 February 2025_

### Added

* *(cawg_identity)* Add `IdentityAssertion::to_summary` and `IdentityAssertion::summarize_all` (#913)

## [0.6.1](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.6.0...cawg-identity-v0.6.1)
_11 February 2025_

### Fixed

* *(cawg_identity)* No-op change to trigger re-release of cawg-identity crate (#918)

## [0.6.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.5.0...cawg-identity-v0.6.0)
_30 January 2025_

### Added

* *(cawg_identity)* Split `CredentialHolder` into sync and async versions (#891)

## [0.5.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.4.0...cawg-identity-v0.5.0)
_29 January 2025_

### Added

* Allow synchronous DynamicAssertion (#889)
* Claim v2 (#707)
* X.509 support for CAWG identity SDK (#880)

## [0.4.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.3.0...cawg-identity-v0.4.0)
_24 January 2025_

### Fixed

* Remove `Debug` supertrait from `DynamicAssertion` and `CredentialHolder` traits (#876)

## [0.3.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.2.2...cawg-identity-v0.3.0)
_22 January 2025_

### Added

* Change the definition of `Signer.raw_signer()` to return an `Option` defaulting to `None` (#869)

## [0.2.2](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.2.1...cawg-identity-v0.2.2)
_22 January 2025_

### Fixed

* Make alg enum exhaustive (#866)

## [0.2.1](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.2.0...cawg-identity-v0.2.1)
_18 January 2025_

### Fixed

* Add support for WASM to CAWG SDK (#861)

## [0.2.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.1.1...cawg-identity-v0.2.0)
_16 January 2025_

### Added

* Implement identity claims aggregation validator (#846)
* Minimal implementation of W3C VC specification (#845)
* Implement identity assertion validation (#843)
* Add `SignatureVerifier` trait and `ValidationError` enum (#844)
* Add `IdentityAssertionBuilder` struct (#840)
* Introduce `IdentityAssertionSigner` (#827)
* Define `CredentialHolder` trait (#821)
* Add `SignerPayload` struct (#817)
* Bump MSRV to 1.81.0 (#781)

## [0.1.1](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.1.0...cawg-identity-v0.1.1)
_24 October 2024_

### Fixed

* Tweak changelog format

## [0.1.0](https://github.com/contentauth/c2pa-rs/releases/tag/cawg-identity-v0.1.0)
_24 October 2024_

### Added

* Create placeholders for forthcoming crates ([#645](https://github.com/contentauth/c2pa-rs/pull/645))
