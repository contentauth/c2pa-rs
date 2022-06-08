# Changelog

All changes to this project are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

Do not manually edit this file. It will be automatically updated when a new release is published.

## 0.3.0
_ 8 June 2022_

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
