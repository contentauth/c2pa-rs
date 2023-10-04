# Changelog

All changes to this project are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

Do not manually edit this file. It will be automatically updated when a new release is published.

## 0.27.1
_04 October 2023_

* Support for validating JPEGs that contain MPF (multi-picture format). ([#317](https://github.com/contentauth/c2pa-rs/pull/317))
* Add ability to customize HTTP headers on timestamp request to Signer and AsyncSigner traits ([#315](https://github.com/contentauth/c2pa-rs/pull/315))
* Add all of the MIME types that are associated with WAV files ([#316](https://github.com/contentauth/c2pa-rs/pull/316))
* Allow MS_C2PA_SIGNING OID to pass ([#314](https://github.com/contentauth/c2pa-rs/pull/314))
## 0.27.0
_29 September 2023_

* supports removal of manifests from pdf ([#312](https://github.com/contentauth/c2pa-rs/pull/312))
* Support for MP3 ([#295](https://github.com/contentauth/c2pa-rs/pull/295))
* (MINOR) Signer can call timestamp authority directly ([#311](https://github.com/contentauth/c2pa-rs/pull/311))
* implements pdf read support ([#309](https://github.com/contentauth/c2pa-rs/pull/309))
## 0.26.0
_13 September 2023_

* Add support for default SVG MIME type ([#305](https://github.com/contentauth/c2pa-rs/pull/305))
* Support for writing and reading manifest data from simple PDFs (without incremental updates or signatures) ([#249](https://github.com/contentauth/c2pa-rs/pull/249))
* Increase actix requirement to 0.13.1 ([#304](https://github.com/contentauth/c2pa-rs/pull/304))
* (MINOR) Expose HashRange ([#300](https://github.com/contentauth/c2pa-rs/pull/300))
* Lock openssl-sys version to 0.9.92 ([#302](https://github.com/contentauth/c2pa-rs/pull/302))
* Update links to C2PA spec to 1.3 ([#292](https://github.com/contentauth/c2pa-rs/pull/292))
* Error saving stream writes ([#290](https://github.com/contentauth/c2pa-rs/pull/290))
* Fix for overly harsh checks when checking Merkle trees. ([#289](https://github.com/contentauth/c2pa-rs/pull/289))
## 0.25.2
_02 August 2023_

* Adds a way to force no claim thumbnail generation ([#288](https://github.com/contentauth/c2pa-rs/pull/288))
* adds ManifestStoreReport::cert_chain_from_bytes ([#286](https://github.com/contentauth/c2pa-rs/pull/286))

## 0.25.1
_14 July 2023_

* Expose DataHash and BoxHash to public SDK ([#284](https://github.com/contentauth/c2pa-rs/pull/284))
* Remove debug statement ([#283](https://github.com/contentauth/c2pa-rs/pull/283))

## 0.25.0
_14 July 2023_

* (MINOR) User, UserCbor and Uuid assertions removed from SDK ([#141](https://github.com/contentauth/c2pa-rs/pull/141))
* Fix for #195 make_test_images missing ingredient references ([#254](https://github.com/contentauth/c2pa-rs/pull/254))
* Return ResourceNotFound  instead of NotFound for resource get ([#279](https://github.com/contentauth/c2pa-rs/pull/279))
* (MINOR) Minor improvements for Wasm and Node.js interoperability ([#276](https://github.com/contentauth/c2pa-rs/pull/276))
* Fix iloc extent_offsets when offset_size is 0 ([#277](https://github.com/contentauth/c2pa-rs/pull/277))
* (MINOR) Converts DataHash and BoxHash methods to use RemoteSigner instead of AsyncSigner ([#280](https://github.com/contentauth/c2pa-rs/pull/280))
* (MINOR) Embeddable manifest support ([#266](https://github.com/contentauth/c2pa-rs/pull/266))
* Repair CI tests ([#278](https://github.com/contentauth/c2pa-rs/pull/278))

## 0.24.0
_21 June 2023_

* (MINOR) force minor version change ([#273](https://github.com/contentauth/c2pa-rs/pull/273))

## 0.23.3
_21 June 2023_

* Bump minor version and update README.md ([#272](https://github.com/contentauth/c2pa-rs/pull/272))
* Updates ([#270](https://github.com/contentauth/c2pa-rs/pull/270))
* Add `Send` to `CAIRead` trait so that it can be used across threads ([#271](https://github.com/contentauth/c2pa-rs/pull/271))
* Generate old COSE headers for temporary backwards support ([#269](https://github.com/contentauth/c2pa-rs/pull/269))

## 0.23.2
_19 June 2023_

* Fix for returning input stream data when using `embed_from_memory` ([#268](https://github.com/contentauth/c2pa-rs/pull/268))

## 0.23.1
_13 June 2023_

* Remove no-default ci test ([#259](https://github.com/contentauth/c2pa-rs/pull/259))
* includes the cert serial number in the ValidationInfo output ([#263](https://github.com/contentauth/c2pa-rs/pull/263))
* adds ManifestStoreReport::cert_chain ([#265](https://github.com/contentauth/c2pa-rs/pull/265))
* Update Timestamp message imprint to include entire protected header ([#264](https://github.com/contentauth/c2pa-rs/pull/264))

## 0.23.0
_09 June 2023_

* Box hash support ([#261](https://github.com/contentauth/c2pa-rs/pull/261))
* Fix timestamp Accuracy decoding ([#262](https://github.com/contentauth/c2pa-rs/pull/262))
* Make remote manifest handling consistent across input types ([#260](https://github.com/contentauth/c2pa-rs/pull/260))
* (MINOR) Support for Ingredients V2 and Actions V2 ([#258](https://github.com/contentauth/c2pa-rs/pull/258))
* Generate and validate 1.3 Cose signatures ([#256](https://github.com/contentauth/c2pa-rs/pull/256))
* Add type exports via JSON Schema ([#255](https://github.com/contentauth/c2pa-rs/pull/255))
* Bmff v2 ([#251](https://github.com/contentauth/c2pa-rs/pull/251))

## 0.22.0
_18 May 2023_

* (MINOR) Improved Remote Manifest handling ([#250](https://github.com/contentauth/c2pa-rs/pull/250))
* Riff streaming support ([#248](https://github.com/contentauth/c2pa-rs/pull/248))

## 0.21.0
_04 May 2023_

* (MINOR) Added ResourceNotFound error ([#244](https://github.com/contentauth/c2pa-rs/pull/244))

## 0.20.3
_03 May 2023_

* backed out calls to set_memory_thumbnail ([#243](https://github.com/contentauth/c2pa-rs/pull/243))
* Revert "backed out calls to set_memory_thumbnail"
* backed out calls to set_memory_thumbnail This was causing thumbnail files to not be generated.

## 0.20.2
_24 April 2023_

* Fixes bug in Ingredient_from_stream_info ([#241](https://github.com/contentauth/c2pa-rs/pull/241))

## 0.20.1
_20 April 2023_

* Ingredient async and thumbnail support ([#240](https://github.com/contentauth/c2pa-rs/pull/240))
* Update actix requirement from 0.11.0 to 0.13.0 in /sdk ([#209](https://github.com/contentauth/c2pa-rs/pull/209))
* Update uuid requirement from 0.8.1 to 1.3.1 in /sdk ([#237](https://github.com/contentauth/c2pa-rs/pull/237))
* Upgrade x509-parser to 0.15.0 ([#229](https://github.com/contentauth/c2pa-rs/pull/229))
* Add support for ARM on Linux ([#233](https://github.com/contentauth/c2pa-rs/pull/233))

## 0.20.0
_05 April 2023_

* (MINOR) SVG support ([#226](https://github.com/contentauth/c2pa-rs/pull/226))
* (MINOR) Update several X509-related crate dependencies ([#225](https://github.com/contentauth/c2pa-rs/pull/225))
* Update thiserror to 1.0.40 in /sdk ([#223](https://github.com/contentauth/c2pa-rs/pull/223))
* Avoid chrono's transitive dependency on time crate ([#222](https://github.com/contentauth/c2pa-rs/pull/222))
* Require openssl >0.10.48 to address multiple RUSTSEC warnings ([#221](https://github.com/contentauth/c2pa-rs/pull/221))
* Apply code format to doc comments ([#220](https://github.com/contentauth/c2pa-rs/pull/220))

## 0.19.1
_28 March 2023_

* Update README ([#215](https://github.com/contentauth/c2pa-rs/pull/215))

## 0.19.0
_23 March 2023_

* Makefile update ([#213](https://github.com/contentauth/c2pa-rs/pull/213))
* Streaming enhancement  ([#212](https://github.com/contentauth/c2pa-rs/pull/212))
* Adds base_path_take to ResourceStore ([#205](https://github.com/contentauth/c2pa-rs/pull/205))
* Add write support for HEIC, HEIF, AVIF ([#210](https://github.com/contentauth/c2pa-rs/pull/210))
* (MINOR) Riff support with refactored AssetIO ([#203](https://github.com/contentauth/c2pa-rs/pull/203))
* (MINOR) Resource format and is_parent / relationship changes ([#202](https://github.com/contentauth/c2pa-rs/pull/202))
* Fix hash algo warning in Wasm and hashing for RSA-PSS SHA-384/512 ([#206](https://github.com/contentauth/c2pa-rs/pull/206))
* Derive impl of Default for Relationship enum ([#204](https://github.com/contentauth/c2pa-rs/pull/204))

## 0.18.1
_07 March 2023_

* Update Validation Status codes ([#200](https://github.com/contentauth/c2pa-rs/pull/200))
* Fix async path to support ingredient box hashing ([#201](https://github.com/contentauth/c2pa-rs/pull/201))

## 0.18.0
_02 March 2023_

* Fix issue where value was inadvertently included in Exclusion structure ([#197](https://github.com/contentauth/c2pa-rs/pull/197))
* (MINOR) Bump MSRV to 1.63.0 ([#198](https://github.com/contentauth/c2pa-rs/pull/198))
* Fixed unit test failure (invalid unique name generation). ([#190](https://github.com/contentauth/c2pa-rs/pull/190))

## 0.17.0
_22 February 2023_

* Disable mdat exclusion ([#187](https://github.com/contentauth/c2pa-rs/pull/187))
* Bmff v2 ([#186](https://github.com/contentauth/c2pa-rs/pull/186))
* Fix for using non-c2pa segment when add required segments ([#185](https://github.com/contentauth/c2pa-rs/pull/185))
* Update Ingredient and VC hashes to 1.2 spec ([#184](https://github.com/contentauth/c2pa-rs/pull/184))
* (MINOR) Create a ResourceStore for binary assets  ([#180](https://github.com/contentauth/c2pa-rs/pull/180))
* Fix Clippy warnings from new Rust 1.67 ([#182](https://github.com/contentauth/c2pa-rs/pull/182))
* Visualizations ([#163](https://github.com/contentauth/c2pa-rs/pull/163))

## 0.16.1
_19 December 2022_

* Update xmp-toolkit from 0.6.0 to 1.0.0 ([#165](https://github.com/contentauth/c2pa-rs/pull/165))
* Prepare 0.16.1 release
* Address new Clippy warnings for Rust 1.66 ([#164](https://github.com/contentauth/c2pa-rs/pull/164))
* Create external manifests for unknown types ([#162](https://github.com/contentauth/c2pa-rs/pull/162))

## 0.16.1
_19 December 2022_

* Address new Clippy warnings for Rust 1.66 ([#164](https://github.com/contentauth/c2pa-rs/pull/164))
* Create external manifests for unknown types ([#162](https://github.com/contentauth/c2pa-rs/pull/162))

## 0.16.0
_03 December 2022_

* Updates some cargo dependencies ([#159](https://github.com/contentauth/c2pa-rs/pull/159))
* makes manifest#add_redaction public; adds test ([#156](https://github.com/contentauth/c2pa-rs/pull/156))
* Fixes support for instanceId on action and generate parameters.ingredient field when possible ([#158](https://github.com/contentauth/c2pa-rs/pull/158))
* Support digitalSourceType field in Action ([#154](https://github.com/contentauth/c2pa-rs/pull/154))
* (MINOR) Add sign feature for signing manifests without file I/O ([#125](https://github.com/contentauth/c2pa-rs/pull/125))
* TIFF/DNG support ([#152](https://github.com/contentauth/c2pa-rs/pull/152))

## 0.15.0
_09 November 2022_

* Fix bad error response when manifest is stripped ([#153](https://github.com/contentauth/c2pa-rs/pull/153))
* (MINOR) Bump MSRV to 1.61 ([#142](https://github.com/contentauth/c2pa-rs/pull/142))
* Fix new Clippy warnings generated by Rust 1.65 ([#151](https://github.com/contentauth/c2pa-rs/pull/151))
* Build infrastructure improvements ([#150](https://github.com/contentauth/c2pa-rs/pull/150))
* Fix manifest.set_thumbnail when add_thumbnails is enabled ([#148](https://github.com/contentauth/c2pa-rs/pull/148))
* Fix for XMP links being mistaken for remote URLs ([#147](https://github.com/contentauth/c2pa-rs/pull/147))
* Upgrade xmp_toolkit to 0.6.0 ([#146](https://github.com/contentauth/c2pa-rs/pull/146))
* create jpeg thumbnails for pngs without alpha ([#145](https://github.com/contentauth/c2pa-rs/pull/145))
* Add test_embed_with_ingredient_err ([#134](https://github.com/contentauth/c2pa-rs/pull/134))

## 0.14.1
_04 October 2022_

* Add homepage and repository links to crates.io ([#132](https://github.com/contentauth/c2pa-rs/pull/132))
* Add Exif Assertion support ([#140](https://github.com/contentauth/c2pa-rs/pull/140))

## 0.14.0
_23 September 2022_

* (MINOR) Remove previously embedded manifests for remote manifests ([#136](https://github.com/contentauth/c2pa-rs/pull/136))
* (MINOR) Add support for manifest removal ([#123](https://github.com/contentauth/c2pa-rs/pull/123))

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
