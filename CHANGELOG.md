# Changelog

All changes to this project are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

Do not manually edit this file. It will be automatically updated when a new release is published.

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
