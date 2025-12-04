# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.72.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.72.1...c2pa-c-ffi-v0.72.2)
_04 December 2025_

## [0.72.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.72.0...c2pa-c-ffi-v0.72.1)
_04 December 2025_

## [0.71.4](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.71.3...c2pa-c-ffi-v0.71.4)
_17 November 2025_

## [0.71.3](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.71.2...c2pa-c-ffi-v0.71.3)
_17 November 2025_

## [0.71.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.71.1...c2pa-c-ffi-v0.71.2)
_13 November 2025_

## [0.71.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.71.0...c2pa-c-ffi-v0.71.1)
_12 November 2025_

### Fixed

* Use Digitalsourcetype with Builder intents ([#1586](https://github.com/contentauth/c2pa-rs/pull/1586))

## [0.71.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.70.0...c2pa-c-ffi-v0.71.0)
_07 November 2025_

### Added

* Builder setIntent API exposed in C2PA C FFI ([#1574](https://github.com/contentauth/c2pa-rs/pull/1574))

## [0.70.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.69.0...c2pa-c-ffi-v0.70.0)
_06 November 2025_

### Added

* Sync/async HTTP resolvers API ([#1355](https://github.com/contentauth/c2pa-rs/pull/1355))

### Updated dependencies

* Bump thiserror from 1.0.69 to 2.0.17 ([#1562](https://github.com/contentauth/c2pa-rs/pull/1562))

## [0.69.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.68.0...c2pa-c-ffi-v0.69.0)
_04 November 2025_

### Added

* Adds support and documentation for JSON formatted Settings ([#1533](https://github.com/contentauth/c2pa-rs/pull/1533))
* Allow reading a manifest store as a Builder to continue editing ([#1476](https://github.com/contentauth/c2pa-rs/pull/1476))

### Other

* Revert "chore: release ([#1535](https://github.com/contentauth/c2pa-rs/pull/1535))"

## [0.68.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.67.1...c2pa-c-ffi-v0.68.0)
_24 October 2025_

### Fixed

* Turn on trust by default ([#1483](https://github.com/contentauth/c2pa-rs/pull/1483))
* Add linker flags to Android library builds ([#1463](https://github.com/contentauth/c2pa-rs/pull/1463))

### Updated dependencies

* Bump cbindgen from 0.28.0 to 0.29.2 ([#1500](https://github.com/contentauth/c2pa-rs/pull/1500))

## [0.67.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.67.0...c2pa-c-ffi-v0.67.1)
_02 October 2025_

## [0.67.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.66.0...c2pa-c-ffi-v0.67.0)
_30 September 2025_

### Added

* Fix ARM builds ([#1456](https://github.com/contentauth/c2pa-rs/pull/1456))

## [0.66.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.65.1...c2pa-c-ffi-v0.66.0)
_24 September 2025_

### Fixed

* We lost the ability to read the deprecated instanceId actions parameters field. ([#1443](https://github.com/contentauth/c2pa-rs/pull/1443))

## [0.65.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.65.0...c2pa-c-ffi-v0.65.1)
_23 September 2025_

### Fixed

* Add checks at C API level ([#1438](https://github.com/contentauth/c2pa-rs/pull/1438))

## [0.65.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.64.0...c2pa-c-ffi-v0.65.0)
_19 September 2025_

### Added

* Expose add_action from the Builder at the C level ([#1425](https://github.com/contentauth/c2pa-rs/pull/1425))
* *(sdk)* Introduce new API to retrieve detailed manifest JSON ([#1406](https://github.com/contentauth/c2pa-rs/pull/1406))

## [0.63.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.63.0...c2pa-c-ffi-v0.63.1)
_15 September 2025_

## [0.63.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.62.0...c2pa-c-ffi-v0.63.0)
_10 September 2025_

### Added

* Remove the v1_api feature and all associated code ([#1387](https://github.com/contentauth/c2pa-rs/pull/1387))

### Fixed

* Make zip script syntax change ([#1399](https://github.com/contentauth/c2pa-rs/pull/1399))

## [0.61.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.61.0...c2pa-c-ffi-v0.61.1)
_06 September 2025_

## [0.60.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.60.1...c2pa-c-ffi-v0.60.2)
_03 September 2025_

## [0.60.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.60.0...c2pa-c-ffi-v0.60.1)
_27 August 2025_

## [0.60.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.59.1...c2pa-c-ffi-v0.60.0)
_26 August 2025_

### Fixed

* Fix a regression for invalid manifest handling and reader creation ([#1312](https://github.com/contentauth/c2pa-rs/pull/1312))

## [0.59.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.59.0...c2pa-c-ffi-v0.59.1)
_15 August 2025_
# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.59.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.58.0...c2pa-c-ffi-v0.59.0)
_14 August 2025_

### Added

* Add option for configuring trust when validating identity assertions (CAI-7980) ([#1239](https://github.com/contentauth/c2pa-rs/pull/1239))
* V2 Claims are now generated by default ([#1266](https://github.com/contentauth/c2pa-rs/pull/1266))
* Expand settings API ([#1192](https://github.com/contentauth/c2pa-rs/pull/1192))

### Fixed

* Enable additional features on c2pa-c-ffi ([#1287](https://github.com/contentauth/c2pa-rs/pull/1287))

## [0.58.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.57.0...c2pa-c-ffi-v0.58.0)
_18 July 2025_

### Added

* Add C binding for setting the base path ([#1237](https://github.com/contentauth/c2pa-rs/pull/1237))
* Add `Reader::remote_url` and `Reader::is_embedded` ([#1150](https://github.com/contentauth/c2pa-rs/pull/1150))
* Store icon references into c2pa.icon assertions for v2 instead of using data_boxes. ([#1235](https://github.com/contentauth/c2pa-rs/pull/1235))

### Fixed

* Clean up logs ([#1181](https://github.com/contentauth/c2pa-rs/pull/1181))
* Clippy warnings for Rust 1.88 ([#1204](https://github.com/contentauth/c2pa-rs/pull/1204))

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
