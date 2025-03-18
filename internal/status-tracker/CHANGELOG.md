# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

The format of this changelog is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.6.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-status-tracker-v0.5.0...c2pa-status-tracker-v0.6.0)
_18 March 2025_

### Added

* Adds `reader.post_validate` method for CAWG validation support (#976)
* Simplify `StatusTracker` interface (#937)

## [0.5.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-status-tracker-v0.4.0...c2pa-status-tracker-v0.5.0)
_06 February 2025_

### Fixed

* Update error reporting (#906)

## [0.4.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-status-tracker-v0.3.0...c2pa-status-tracker-v0.4.0)
_29 January 2025_

### Added

* Claim v2 (#707)

## [0.3.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-status-tracker-v0.2.0...c2pa-status-tracker-v0.3.0)
_16 January 2025_

### Added

* *(cawg_identity)* Implement identity assertion validation (#843)
* Bump MSRV to 1.81.0 (#781)

## [0.2.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-status-tracker-v0.1.0...c2pa-status-tracker-v0.2.0)
_11 December 2024_

### Added

* Move `validation_codes` from `c2pa-crypto` to `c2pa-status-tracker`

## [0.1.0](https://github.com/contentauth/c2pa-rs/releases/tag/c2pa-status-tracker-v0.1.0)
_13 November 2024_

### Added

* Factor status tracking infrastructure into its own crate ([#665](https://github.com/contentauth/c2pa-rs/pull/665))
