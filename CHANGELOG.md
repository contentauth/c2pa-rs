# Changelog

All changes to this project are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

Do not manually edit this file. It will be automatically updated when a new release is published.

## 0.13.2
_21 September 2022_

* manifest_data was missing for remote manifests ([#135](https://github.com/contentauth/c2pa-rs/pull/135))

## 0.13.1
_13 September 2022_

* Add ManifestStore::from_manifest_and_asset_bytes_async ([#130](https://github.com/contentauth/c2pa-rs/pull/130))

## 0.13.0
_26 August 2022_

* Add RemoteManifestUrl Error, returning url ([#120](https://github.com/contentauth/c2pa-rs/pull/120))
* Convert status_log error val to a string so that we can return full errors ([#121](https://github.com/contentauth/c2pa-rs/pull/121))
* Report failures from remote manifest fetch ([#116](https://github.com/contentauth/c2pa-rs/pull/116))
* Fast XMP extraction from PNG ([#117](https://github.com/contentauth/c2pa-rs/pull/117))
* Bump MSRV to 1.59.0 ([#118](https://github.com/contentauth/c2pa-rs/pull/118))
* Make sure there is  a single manifest store in the asset ([#114](https://github.com/contentauth/c2pa-rs/pull/114))
* (MINOR) Switch to "lib" for crate-type ([#113](https://github.com/contentauth/c2pa-rs/pull/113))

## 0.12.0
_16 August 2022_

* Update C2PA manifest store mime type ([#112](https://github.com/contentauth/c2pa-rs/pull/112))
* Updates Manifest API to support remote and external manifests ([#107](https://github.com/contentauth/c2pa-rs/pull/107))
* Support validating remote and external manifest stores ([#108](https://github.com/contentauth/c2pa-rs/pull/108))
* Fix build error when xmp_write is not defined ([#105](https://github.com/contentauth/c2pa-rs/pull/105))
* Fix box order for BMFF ([#104](https://github.com/contentauth/c2pa-rs/pull/104))
* Added support for external manifests ([#101](https://github.com/contentauth/c2pa-rs/pull/101))

## 0.11.3
_03 August 2022_

* Remove inadvertent 1.0.0 release from changelog ([#97](https://github.com/contentauth/c2pa-rs/pull/97))
* Treat 'meta' box as standard container ([#95](https://github.com/contentauth/c2pa-rs/pull/95))
* Fix for `sign_claim` masking error ([#96](https://github.com/contentauth/c2pa-rs/pull/96))

## 0.11.1
_01 August 2022_

* Bug fix: Ingredients with valid claims not reporting correct thumbnails ([#94](https://github.com/contentauth/c2pa-rs/pull/94))
* Update `make_test_images` to use timestamp authority ([#90](https://github.com/contentauth/c2pa-rs/pull/90))
* Fix bad response for case when there is no timestamp ([#89](https://github.com/contentauth/c2pa-rs/pull/89))

## 0.11.0
_21 July 2022_

* (MINOR) Add support for remotely generated CoseSign1 signatures ([#87](https://github.com/contentauth/c2pa-rs/pull/87))
* Optimize performance of large assets ([#84](https://github.com/contentauth/c2pa-rs/pull/84))

## 0.10.0
_20 July 2022_

* Add Unicode license to allow-list ([#85](https://github.com/contentauth/c2pa-rs/pull/85))
* (MINOR) `IngredientOptions` allow override of hash and thumbnail generation; image library is now a default feature ([#79](https://github.com/contentauth/c2pa-rs/pull/79))

## 0.9.1
_19 July 2022_

* Fix publish workflow ([#82](https://github.com/contentauth/c2pa-rs/pull/82))

## 0.9.0
_19 July 2022_

* (MINOR) Introduce a new `SigningAlg` enum ([#76](https://github.com/contentauth/c2pa-rs/pull/76))
* Support for asynchronous signing of claims ([#57](https://github.com/contentauth/c2pa-rs/pull/57))
* Adds an add_validation_status method to Ingredient ([#68](https://github.com/contentauth/c2pa-rs/pull/68))

## 0.8.1
_15 July 2022_

* Use rsa crate for RSA-PSS verification in Wasm ([#77](https://github.com/contentauth/c2pa-rs/pull/77))

## 0.8.0
_15 July 2022_

* Add a new API to provide access to COSE signing logic for external signers ([#75](https://github.com/contentauth/c2pa-rs/pull/75))
* (MINOR) Move crate-level functions for creating signers to new public `create_signer` mod ([#72](https://github.com/contentauth/c2pa-rs/pull/72))

## 0.7.2
_14 July 2022_

* Fix broken documentation build ([#74](https://github.com/contentauth/c2pa-rs/pull/74))

## 0.7.1
_14 July 2022_

* Configure docs.rs to include feature-gated items ([#73](https://github.com/contentauth/c2pa-rs/pull/73))
* Update XMP Toolkit to 0.5.0 ([#71](https://github.com/contentauth/c2pa-rs/pull/71))
* Refactor code to limit memory usage and remove data copies during hash generation ([#67](https://github.com/contentauth/c2pa-rs/pull/67))

## 0.7.0
_29 June 2022_

* (MINOR) Return specific errors for FileNotFound and UnsupportedType ([#62](https://github.com/contentauth/c2pa-rs/pull/62))

## 0.6.1
_28 June 2022_

* Fix up changelog noise
* Fix bug with multiple ingredients in `Manifest::from_store` ([#61](https://github.com/contentauth/c2pa-rs/pull/61))

## 0.6.0
_28 June 2022_

* (MINOR) Initial BMFF support ([#39](https://github.com/contentauth/c2pa-rs/pull/39))

## 0.5.2
_23 June 2022_

* Return assertion instance values starting at `1` instead of `2` ([#60](https://github.com/contentauth/c2pa-rs/pull/60))

## 0.5.1
_22 June 2022_

* Update thumbnail to be `Vec<u8>`, add serialization feature ([#59](https://github.com/contentauth/c2pa-rs/pull/59))
* Adds xmp_write feature to make xmp-toolkit inclusion optional ([#53](https://github.com/contentauth/c2pa-rs/pull/53))

## 0.5.0
_20 June 2022_

* (MINOR) Add asset attribute getters for manifest ([#56](https://github.com/contentauth/c2pa-rs/pull/56))
* (MINOR) Remove temp_signer from sdk; update docs and examples to use get_signer_from_files ([#52](https://github.com/contentauth/c2pa-rs/pull/52))
* (MINOR) Clean up client example; update actions and schema ([#51](https://github.com/contentauth/c2pa-rs/pull/51))

## 0.4.2
_16 June 2022_

* Fix bug in updating crate reference in README ([#50](https://github.com/contentauth/c2pa-rs/pull/50))

## 0.4.1
_16 June 2022_

* Fix bug in Cargo.toml updates ([#49](https://github.com/contentauth/c2pa-rs/pull/49))

## 0.4.0
_16 June 2022_

* Add status badges for CI validation, crates.io, and code coverage ([#46](https://github.com/contentauth/c2pa-rs/pull/46))
* Remove self-signed end-entity cert support ([#48](https://github.com/contentauth/c2pa-rs/pull/48))
* Add rustfmt toml to get edition 2018 formatting ([#36](https://github.com/contentauth/c2pa-rs/pull/36))
* (MINOR) Update from_bytes(_async) to return a Result ([#43](https://github.com/contentauth/c2pa-rs/pull/43))
* Adjust temp signer reserved sizes to account for large timestamps ([#45](https://github.com/contentauth/c2pa-rs/pull/45))
* Fix bug in verify_from_buffer ([#44](https://github.com/contentauth/c2pa-rs/pull/44))
* Remove cargo edit from publish workflow ([#42](https://github.com/contentauth/c2pa-rs/pull/42))
* Apply fix from c2patool publish workflow ([#40](https://github.com/contentauth/c2pa-rs/pull/40))
* Remove need for using OpenSSL to generate certs by using pre-generated certs ([#41](https://github.com/contentauth/c2pa-rs/pull/41))
* Update README and pull request template with formatting changes ([#38](https://github.com/contentauth/c2pa-rs/pull/38))

## 0.3.0
_08 June 2022_

* Make most jumbf_io functions crate private and move Store dependencies to Store ([#37](https://github.com/contentauth/c2pa-rs/pull/37))
* Remove c2patool source now that it's in its own repo ([#35](https://github.com/contentauth/c2pa-rs/pull/35))
* (MINOR) Update ManifestAssertion supporting instances ([#34](https://github.com/contentauth/c2pa-rs/pull/34))
* Export top level signing functions, hide other signature details ([#32](https://github.com/contentauth/c2pa-rs/pull/32))
* Add documentation for the `Actions` and `Metadata` assertions ([#30](https://github.com/contentauth/c2pa-rs/pull/30))
* Rework how c2patool is configured ([#28](https://github.com/contentauth/c2pa-rs/pull/28))
* Convert make_tests into a scriptable engine; rename to make_test_images ([#29](https://github.com/contentauth/c2pa-rs/pull/29))
* Update thiserror requirement from >= 1.0.20, < 1.0.26 to >= 1.0.20, < 1.0.32 in /sdk ([#9](https://github.com/contentauth/c2pa-rs/pull/9))
* Update base64 requirement from 0.12.2 to 0.13.0 in /sdk ([#10](https://github.com/contentauth/c2pa-rs/pull/10))
* Update range-set requirement from 0.0.7 to 0.0.9 in /sdk ([#13](https://github.com/contentauth/c2pa-rs/pull/13))
* Make Assertions opaque in the public SDK ([#22](https://github.com/contentauth/c2pa-rs/pull/22))
* Update c2pa requirement from 0.1 to 0.2 in /c2patool ([#23](https://github.com/contentauth/c2pa-rs/pull/23))

## 0.2.0
_26 May 2022_

* Fix dependency reference from c2patool crate to c2pa crate ([#21](https://github.com/contentauth/c2pa-rs/pull/21))
* (MINOR) Detailed API review for Ingredient struct ([#17](https://github.com/contentauth/c2pa-rs/pull/17))

## 0.1.3
_26 May 2022_

* Publish c2patool crate ([#20](https://github.com/contentauth/c2pa-rs/pull/20))
* Improve documentation ([#14](https://github.com/contentauth/c2pa-rs/pull/14))

## 0.1.2
_26 May 2022_

* No-op change to verify correct handling of PR numbers ([#19](https://github.com/contentauth/c2pa-rs/pull/19))
* Fix error in formatting changelog
* Fix missing links in changelog

## 0.1.1
_26 May 2022_

* Add Makefile for local testing ([#18](https://github.com/contentauth/c2pa-rs/pull/18))
* Add workflow for automatically releasing c2pa crate ([#16](https://github.com/contentauth/c2pa-rs/pull/16))
* Reduce fixtures size ([#15](https://github.com/contentauth/c2pa-rs/pull/15))
* Add codecov.io integration ([#4](https://github.com/contentauth/c2pa-rs/pull/4))
* Configure dependabot ([#8](https://github.com/contentauth/c2pa-rs/pull/8))
* Configure dependabot ([#7](https://github.com/contentauth/c2pa-rs/pull/7))
* Remove unnecessary steps from cargo-deny job ([#6](https://github.com/contentauth/c2pa-rs/pull/6))
* Update to latest GH Actions checkout action ([#5](https://github.com/contentauth/c2pa-rs/pull/5))
* Change ring license hash to decimal ([#3](https://github.com/contentauth/c2pa-rs/pull/3))

## 0.1.0
_23 May 2022_

* Initial public release
