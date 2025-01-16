# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

The format of this changelog is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.2.0](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.1.1...cawg-identity-v0.2.0)
_16 January 2025_

### Added

* *(cawg_identity)* Implement identity claims aggregation validator (#846)
* *(cawg_identity)* Minimal implementation of W3C VC specification (#845)
* *(cawg_identity)* Implement identity assertion validation (#843)
* *(cawg_identity)* Add `SignatureVerifier` trait and `ValidationError` enum (#844)
* *(cawg_identity)* Add `IdentityAssertionBuilder` struct (#840)
* *(cawg_identity)* Introduce `IdentityAssertionSigner` (#827)
* *(cawg_identity)* Define `CredentialHolder` trait (#821)
* *(cawg_identity)* Add `SignerPayload` struct (#817)
* Bump MSRV to 1.81.0 (#781)

## [0.1.1](https://github.com/contentauth/c2pa-rs/compare/cawg-identity-v0.1.0...cawg-identity-v0.1.1)
_24 October 2024_

### Fixed

* Tweak changelog format

## [0.1.0](https://github.com/contentauth/c2pa-rs/releases/tag/cawg-identity-v0.1.0)
_24 October 2024_

### Added

* Create placeholders for forthcoming crates ([#645](https://github.com/contentauth/c2pa-rs/pull/645))
