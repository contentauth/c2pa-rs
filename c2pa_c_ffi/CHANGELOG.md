# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.75.19](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.18...c2pa-c-ffi-v0.75.19)
_09 February 2026_

### Fixed

* Vec_to_tracked_ptr macro merged with to_c_bytes ([#1834](https://github.com/contentauth/c2pa-rs/pull/1834))

## [0.75.18](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.17...c2pa-c-ffi-v0.75.18)
_06 February 2026_

## [0.75.17](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.16...c2pa-c-ffi-v0.75.17)
_06 February 2026_

### Fixed

* Bump max settings string limit to 1MB ([#1833](https://github.com/contentauth/c2pa-rs/pull/1833))

## [0.75.16](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.15...c2pa-c-ffi-v0.75.16)
_05 February 2026_

### Fixed

* Add additional conversions for C FFI Errors ([#1829](https://github.com/contentauth/c2pa-rs/pull/1829))

## [0.75.15](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.14...c2pa-c-ffi-v0.75.15)
_05 February 2026_

### Fixed

* C_ffi bindings were not returning C2paErrors correctly ([#1825](https://github.com/contentauth/c2pa-rs/pull/1825))

## [0.75.14](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.13...c2pa-c-ffi-v0.75.14)
_05 February 2026_

### Fixed

* Restores empty string return on c2pa_sign_file, and c2pa_release_string ([#1821](https://github.com/contentauth/c2pa-rs/pull/1821))

## [0.75.13](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.12...c2pa-c-ffi-v0.75.13)
_03 February 2026_

## [0.75.12](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.11...c2pa-c-ffi-v0.75.12)
_03 February 2026_

## [0.75.11](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.10...c2pa-c-ffi-v0.75.11)
_03 February 2026_

### Added

* Adds thread safe Settings and Context support to c_ffi_api ([#1783](https://github.com/contentauth/c2pa-rs/pull/1783))

### Other

* Only use `reqwest` for `c2pa-c-ffi` networking ([#1807](https://github.com/contentauth/c2pa-rs/pull/1807))

## [0.75.10](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.9...c2pa-c-ffi-v0.75.10)
_02 February 2026_

## [0.75.9](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.8...c2pa-c-ffi-v0.75.9)
_30 January 2026_

## [0.75.8](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.7...c2pa-c-ffi-v0.75.8)
_28 January 2026_

## [0.75.7](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.6...c2pa-c-ffi-v0.75.7)
_27 January 2026_

## [0.75.6](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.5...c2pa-c-ffi-v0.75.6)
_22 January 2026_

## [0.75.5](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.4...c2pa-c-ffi-v0.75.5)
_21 January 2026_

## [0.75.4](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.3...c2pa-c-ffi-v0.75.4)
_16 January 2026_

## [0.75.3](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.2...c2pa-c-ffi-v0.75.3)
_16 January 2026_

## [0.75.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.1...c2pa-c-ffi-v0.75.2)
_15 January 2026_

## [0.75.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.75.0...c2pa-c-ffi-v0.75.1)
_15 January 2026_

### Fixed

* Verify after sign not executing ([#1638](https://github.com/contentauth/c2pa-rs/pull/1638))

## [0.75.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.74.0...c2pa-c-ffi-v0.75.0)
_14 January 2026_

### Added

* Deeper integration of Context into the SDK ([#1710](https://github.com/contentauth/c2pa-rs/pull/1710))

## [0.73.3](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.73.2...c2pa-c-ffi-v0.73.3)
_07 January 2026_

## [0.73.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.73.1...c2pa-c-ffi-v0.73.2)
_22 December 2025_

## [0.73.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-c-ffi-v0.73.0...c2pa-c-ffi-v0.73.1)
_19 December 2025_

### Fixed

* Cbindgen change for C2PA_DYNAMIC_LOADING variable ([#1679](https://github.com/contentauth/c2pa-rs/pull/1679))

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
