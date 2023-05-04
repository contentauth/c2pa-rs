# Changelog

All changes to this project are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

Do not manually edit this file. It will be automatically updated when a new release is published.

## 0.5.3
_04 May 2023_

* Parent Ingredient JSON ([contentauth/c2patool#123](https://github.com/contentauth/c2patool/pull/123))

## 0.5.2
_19 April 2023_

* Ingredient thumbnails, extension cleanup, toolkit update ([contentauth/c2patool#120](https://github.com/contentauth/c2patool/pull/120))

## 0.5.1
_10 April 2023_

* Update README.md ([contentauth/c2patool#118](https://github.com/contentauth/c2patool/pull/118))
* Update expired sample certs ([contentauth/c2patool#113](https://github.com/contentauth/c2patool/pull/113))

## 0.5.0
_28 March 2023_

* (MINOR) New ingredient support and c2pa file formats ([contentauth/c2patool#111](https://github.com/contentauth/c2patool/pull/111))
* Leverage new Manifest & Ingredient, add Ingredient creation. ([contentauth/c2patool#107](https://github.com/contentauth/c2patool/pull/107))

## 0.4.0
_01 March 2023_

* (MINOR) Add --certs and --tree options ([contentauth/c2patool#106](https://github.com/contentauth/c2patool/pull/106))
* update to cp2pa 0.17.0 ([contentauth/c2patool#105](https://github.com/contentauth/c2patool/pull/105))
* Update for Clippy in Rust 1.67 ([contentauth/c2patool#101](https://github.com/contentauth/c2patool/pull/101))

## 0.3.9
_06 December 2022_

* update to c2pa-rs 0.16.0
* allows clients to output manifest report to specified directory ([contentauth/c2patool#91](https://github.com/contentauth/c2patool/pull/91))

## 0.3.8
_09 November 2022_

* Bump c2pa from 0.13.2 to 0.15.0 ([contentauth/c2patool#87](https://github.com/contentauth/c2patool/pull/87))
* Build infrastructure improvements ([contentauth/c2patool#85](https://github.com/contentauth/c2patool/pull/85))
* Fix new Clippy warning in Rust 1.65 ([contentauth/c2patool#84](https://github.com/contentauth/c2patool/pull/84))
* Readme updates ([contentauth/c2patool#62](https://github.com/contentauth/c2patool/pull/62))

## 0.3.7
_22 September 2022_

* Treat a source asset with a manifest store as a default parent ([contentauth/c2patool#76](https://github.com/contentauth/c2patool/pull/76))
* Fetch remote manifests for --info ([contentauth/c2patool#75](https://github.com/contentauth/c2patool/pull/75))

## 0.3.6
_16 September 2022_

* Update Cargo.lock when publishing crate ([contentauth/c2patool#71](https://github.com/contentauth/c2patool/pull/71))
* [IGNORE] update readme --info ([contentauth/c2patool#70](https://github.com/contentauth/c2patool/pull/70))
* Update Cargo.lock to 0.3.5

## 0.3.5
_15 September 2022_

* Upgrade cpufeatures to non-yanked version ([contentauth/c2patool#68](https://github.com/contentauth/c2patool/pull/68))
* Add --info option  ([contentauth/c2patool#65](https://github.com/contentauth/c2patool/pull/65))
* Updated publish workflow to upload binaries to GitHub ([contentauth/c2patool#58](https://github.com/contentauth/c2patool/pull/58))
* Fix Make release script & update readme ([contentauth/c2patool#55](https://github.com/contentauth/c2patool/pull/55))
* (Some version history omitted as we worked on some release process issues)

## 0.3.0
_18 August 2022_

* (MINOR) Rework c2patool parameters ([contentauth/c2patool#53](https://github.com/contentauth/c2patool/pull/53))
* Update to 0.11.0 c2pa-rs ([contentauth/c2patool#38](https://github.com/contentauth/c2patool/pull/38))
* Remove Homebrew, Git installation methods, and add "update" wording ([contentauth/c2patool#33](https://github.com/contentauth/c2patool/pull/33))

## 0.2.1
_29 June 2022_

* Add BMFF support for video & etc ([contentauth/c2patool#25](https://github.com/contentauth/c2patool/pull/25))

## 0.2.0
_28 June 2022_

* (MINOR) Upgrade to c2pa Rust SDK version 0.6.0 ([contentauth/c2patool#24](https://github.com/contentauth/c2patool/pull/24))
* Fix an error in the README documentation ([contentauth/c2patool#23](https://github.com/contentauth/c2patool/pull/23))
* Display help if there are no arguments on the command line ([contentauth/c2patool#21](https://github.com/contentauth/c2patool/pull/21))
* Bump anyhow from 1.0.57 to 1.0.58 ([contentauth/c2patool#17](https://github.com/contentauth/c2patool/pull/17))
* Updates examples to use ta_url instead of ta ([contentauth/c2patool#15](https://github.com/contentauth/c2patool/pull/15))

## 0.1.3
_17 June 2022_

* Update to latest c2pa Rust SDK ([contentauth/c2patool#12](https://github.com/contentauth/c2patool/pull/12))
* Add built-in default certs to make getting started easier ([contentauth/c2patool#9](https://github.com/contentauth/c2patool/pull/9))

## 0.1.2
_10 June 2022_

* Update crate's description field

## 0.1.1
_10 June 2022_

* Initial public release
