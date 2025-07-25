# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that – as is typical in the Rust community – the minimum supported Rust version may be increased without a major version increase.

Since version 0.36.2, the format of this changelog is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.58.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.57.0...c2pa-v0.58.0)
_18 July 2025_

### Added

* Add C binding for setting the base path ([#1237](https://github.com/contentauth/c2pa-rs/pull/1237))
* Asset reference assertion ([#1203](https://github.com/contentauth/c2pa-rs/pull/1203))
* Add `Reader::remote_url` and `Reader::is_embedded` ([#1150](https://github.com/contentauth/c2pa-rs/pull/1150))
* Store icon references into c2pa.icon assertions for v2 instead of using data_boxes. ([#1235](https://github.com/contentauth/c2pa-rs/pull/1235))
* Remove file type from thumbnail names ([#1187](https://github.com/contentauth/c2pa-rs/pull/1187))
* Update MSRV to 1.85 ([#1208](https://github.com/contentauth/c2pa-rs/pull/1208))

### Documented

* Fix spec link for EmbeddedData ([#1226](https://github.com/contentauth/c2pa-rs/pull/1226))
* API doc clean up and improvement ([#1178](https://github.com/contentauth/c2pa-rs/pull/1178))
* Fix formatting of top level example. ([#1161](https://github.com/contentauth/c2pa-rs/pull/1161))

### Fixed

* Panic when adding empty actions assertion ([#1227](https://github.com/contentauth/c2pa-rs/pull/1227))
* Generated JPEG thumbnail incorrectly rotated ([#1233](https://github.com/contentauth/c2pa-rs/pull/1233))
* Unfreeze dependency on base64ct crate now that we're up to MSRV 1.85 ([#1228](https://github.com/contentauth/c2pa-rs/pull/1228))
* Clean up logs ([#1181](https://github.com/contentauth/c2pa-rs/pull/1181))
* Change timestamp validation to return new required info fields ([#1191](https://github.com/contentauth/c2pa-rs/pull/1191))
* Xmp jpeg write ([#1156](https://github.com/contentauth/c2pa-rs/pull/1156))
* Clippy warnings for Rust 1.88 ([#1204](https://github.com/contentauth/c2pa-rs/pull/1204))

### Other

* Move uri_to_path into utils ([#1186](https://github.com/contentauth/c2pa-rs/pull/1186))

## [0.57.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.56.2...c2pa-v0.57.0)
_19 June 2025_

### Fixed

* No-op change to trigger c2pa core crate publish

## [0.56.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.56.1...c2pa-v0.56.2)
_18 June 2025_

### Fixed

* No-op change to trigger rebuild

## [0.56.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.56.0...c2pa-v0.56.1)
_18 June 2025_

### Fixed

* To_archive does not store resources associated with ingredients ([#1151](https://github.com/contentauth/c2pa-rs/pull/1151))

## [0.56.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.55.0...c2pa-v0.56.0)
_17 June 2025_

### Added

* *(sdk)* Introduces get_supported_types api ([#1138](https://github.com/contentauth/c2pa-rs/pull/1138))
* Update Validation for 2.2 spec compliance ([#1144](https://github.com/contentauth/c2pa-rs/pull/1144))

### Documented

* Doc cleanup ([#1143](https://github.com/contentauth/c2pa-rs/pull/1143))

### Fixed

* Freeze base64ct crate at 1.7.3 for now ([#1163](https://github.com/contentauth/c2pa-rs/pull/1163))
* C2patool reports cawg.ica.credential_valid for valid CAWG X.509 signature (CAI-8751) ([#1155](https://github.com/contentauth/c2pa-rs/pull/1155))
* Docs.rs build using openssl and rust_native_crypto simulatenously ([#1139](https://github.com/contentauth/c2pa-rs/pull/1139))

## [0.55.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.54.0...c2pa-v0.55.0)
_27 May 2025_

### Added

* Es512 support without new dependencies ([#1130](https://github.com/contentauth/c2pa-rs/pull/1130))

## [0.54.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.53.0...c2pa-v0.54.0)
_27 May 2025_

### Added

* Make OpenSSL a default feature ([#1118](https://github.com/contentauth/c2pa-rs/pull/1118))

### Fixed

* Add CAWG support for fragmented BMFF ([#1114](https://github.com/contentauth/c2pa-rs/pull/1114))

### Other

* Integrates prebuilt library release workflow ([#1126](https://github.com/contentauth/c2pa-rs/pull/1126))

## [0.53.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.52.0...c2pa-v0.53.0)
_20 May 2025_

### Added

* [**breaking**] Merge `c2pa-status-tracker` crate into `c2pa` ([#1115](https://github.com/contentauth/c2pa-rs/pull/1115))

### Fixed

* Avoid yanked version of `windows-core` crate ([#1116](https://github.com/contentauth/c2pa-rs/pull/1116))

## [0.52.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.51.1...c2pa-v0.52.0)
_16 May 2025_

### Added

* [**breaking**] Merge c2pa-crypto crate into core c2pa crate ([#1099](https://github.com/contentauth/c2pa-rs/pull/1099))

## [0.51.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.51.0...c2pa-v0.51.1)
_16 May 2025_

### Fixed

* Switch zip dependency to a non-yanked version ([#1101](https://github.com/contentauth/c2pa-rs/pull/1101))
* Fix Clippy warnings for Rust 1.87 ([#1103](https://github.com/contentauth/c2pa-rs/pull/1103))

## [0.51.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.50.0...c2pa-v0.51.0)
_14 May 2025_

### Added

* [**breaking**] Merge CAWG identity SDK into main C2PA crate ([#1089](https://github.com/contentauth/c2pa-rs/pull/1089))

### Fixed

* Trigger re-publish of c2pa crate

## [0.50.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.49.5...c2pa-v0.50.0)
_14 May 2025_

### Added

* Adds c_api for dynamic library releases ([#1047](https://github.com/contentauth/c2pa-rs/pull/1047))
* SVG thumbnails with a fix to the ingredient thumbnail format detection ([#722](https://github.com/contentauth/c2pa-rs/pull/722))
* *(sdk)* Support setting the Ingredient manifest_data field for remote manifests using Builder ([#1091](https://github.com/contentauth/c2pa-rs/pull/1091))

### Fixed

* Ingredient from_stream/memory not loading remote manifests ([#1061](https://github.com/contentauth/c2pa-rs/pull/1061))

## [0.49.5](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.49.4...c2pa-v0.49.5)
_25 April 2025_

### Fixed

* Return an error if a manifest cannot be read ([#1051](https://github.com/contentauth/c2pa-rs/pull/1051))

## [0.49.4](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.49.3...c2pa-v0.49.4)
_24 April 2025_

### Fixed

* Fix missing Action fields ([#1050](https://github.com/contentauth/c2pa-rs/pull/1050))

## [0.49.3](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.49.2...c2pa-v0.49.3)
_16 April 2025_

### Fixed

* Dynamic assertions should be gathered assertions ([#1005](https://github.com/contentauth/c2pa-rs/pull/1005))

## [0.49.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.49.1...c2pa-v0.49.2)
_07 April 2025_

### Fixed

* Populates claim signature field in ingredient v3. ([#1027](https://github.com/contentauth/c2pa-rs/pull/1027))
* Adjust dependencies to avoid security warnings and yanked versions ([#1031](https://github.com/contentauth/c2pa-rs/pull/1031))
* Enable trust checks for all unit tests ([#1022](https://github.com/contentauth/c2pa-rs/pull/1022))

## [0.49.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.49.0...c2pa-v0.49.1)
_04 April 2025_

### Fixed

* Update openssl to address a recently-announced vulnerability ([#1024](https://github.com/contentauth/c2pa-rs/pull/1024))

## [0.49.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.48.2...c2pa-v0.49.0)
_03 April 2025_

### Added

* *(cawg_identity)* Add `BuiltInSignatureVerifier` ([#978](https://github.com/contentauth/c2pa-rs/pull/978))

### Fixed

* Thread safe version of settings.rs ([#1018](https://github.com/contentauth/c2pa-rs/pull/1018))
* Fix support for user supplied labels ([#1017](https://github.com/contentauth/c2pa-rs/pull/1017))
* Sig check fix ([#1016](https://github.com/contentauth/c2pa-rs/pull/1016))

## [0.48.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.48.1...c2pa-v0.48.2)
_26 March 2025_

### Fixed

* Make sure manifests are signed with end-entity certs ([#997](https://github.com/contentauth/c2pa-rs/pull/997))

### Other

* Revert "chore: publish c2patool and cawg_identity updates ([#992](https://github.com/contentauth/c2pa-rs/pull/992))"

## [0.48.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.48.0...c2pa-v0.48.1)
_20 March 2025_

### Fixed

* *(c2patool)* Fixes crash and improves cawg support (#989)

## [0.48.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.47.0...c2pa-v0.48.0)
_19 March 2025_

### Added

* Adds allActionsIncluded flag to Actions Assertion (#986)

### Fixed

* Generate gathered assertions for v2 claims (#985)

## [0.47.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.46.0...c2pa-v0.47.0)
_18 March 2025_

### Added

* Adds `reader.post_validate` method for CAWG validation support (#976)
* Add `StatusTracker` to `IdentityAssertion` parsing and validation APIs (#943)
* Add `Sync` to `AsyncDynamicAssertion` (#953)
* Simplify `StatusTracker` interface (#937)
* Add WASI to c2patool (#945)
* Add WASI support to cawg_identity (#942)
* Add ES256 and ES384 Rust native signing (#941)
* Adds validation_state to the json reports from the Reader (#930)
* Wasm32 wasi 0.41.0 (#888)

### Fixed

* Remove circular dependency between C2PA and CAWG crates (#982)
* ISSUE-967: Remove the `RST0..=RST7` check from the `has_length` method for the JPEG asset handler. (#968)
* Fix broken c2patool fragment feature (#960)
* Feature flag `v1_api` without `file_io` didn't compile (#944)
* Use older version of x509-certificate for wasm32-unknown (#934)
* Fix new Clippy warnings for Rust 1.85.0 (#933)

### Other

* Remove `openssl` feature flag (#940)

### Updated dependencies

* Bump zip crate to 2.4.1 (#981)
* Bump x509-certificate to 0.24.0 (#957)

## [0.46.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.45.3...c2pa-v0.46.0)
_15 February 2025_

### Added

* Add support for DynamicAssertions in JSON format (#924)

### Fixed

* Panic in decoding of GIF chunks (#873)
* Use correct byte label for GIF Plain Text Extension (#864)
* Panic in slicing of empty XMP data (#872)

### Other

* Use `AsRef<Path>` in `jumbf_io` functions (#910)

## [0.45.3](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.45.2...c2pa-v0.45.3)
_11 February 2025_

### Fixed

* Restore support for claim_generator_hints (#915)

## [0.45.2](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.45.1...c2pa-v0.45.2)
_06 February 2025_

### Documented

* Fix reported errors for docs (#903)

### Fixed

* Update error reporting (#906)
* Repair cargo test (#898)

## [0.45.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.45.0...c2pa-v0.45.1)
_31 January 2025_

### Fixed

* Remove dependency on SubtleCrypto (#881)

## [0.45.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.44.0...c2pa-v0.45.0)
_30 January 2025_

### Added

* *(cawg_identity)* Split `CredentialHolder` into sync and async versions (#891)

## [0.44.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.43.0...c2pa-v0.44.0)
_29 January 2025_

### Added

* Allow synchronous DynamicAssertion (#889)
* Claim v2 (#707)

## [0.43.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.42.0...c2pa-v0.43.0)
_24 January 2025_

### Added

* *(crypto)* Make `box_size` parameter on `c2pa_crypto::cose::sign` an `Option` (#879)

### Fixed

* Bump coset requirement to 0.3.8 (#883)
* Update id3 crate (#875)
* Remove `Debug` supertrait from `DynamicAssertion` and `CredentialHolder` traits (#876)

## [0.42.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.41.1...c2pa-v0.42.0)
_22 January 2025_

### Added

* Change the definition of `Signer.raw_signer()` to return an `Option` defaulting to `None` (#869)

## [0.41.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.41.0...c2pa-v0.41.1)
_22 January 2025_

### Fixed

* Make alg enum exhaustive (#866)

## [0.41.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.40.0...c2pa-v0.41.0)
_16 January 2025_

### Added

* *(crypto)* Add `rsa` crate support to `rust_native_crypto` feature (#853)
* *(cawg_identity)* Implement identity assertion validation (#843)
* Remove writing of native camera RAW formats from SDK (#814)
* Review `c2pa-crypto` crate API (#813)
* Add new function `c2pa_crypto::cose::signing_time_from_sign1` (#812)
* Move COSE signing into `c2pa_crypto` crate (#807)
* Move COSE timestamp generation into `c2pa_crypto` (#803)
* Move COSE signature verification into `c2pa_crypto` (#801)
* Introduce `c2pa_crypto::Verifier::verify_trust` (#798)
* Introduce `c2pa_crypto::cose::Verifier` (#797)
* Consolidate implementations of `cert_chain_from_sign1` in `c2pa_crypto` (#796)
* Move `signing_alg_from_sign1` into `c2pa-crypto` (#795)
* Move `get_cose_sign1` into `c2pa-crypto` crate (#794)
* Move COSE OCSP support into c2pa-crypto (#793)
* Move `verify_trust` into `c2pa_crypto` (#784)
* Introduce `c2pa_crypto::CertificateAcceptancePolicy` (#779)
* Bump MSRV to 1.81.0 (#781)

### Fixed

* Make sure `DynamicAssertion::content` gets a properly populated `PartialClaim` (#842)
* Switch to from fast_xml to quick_xml (#805)
* Update img-parts for jpeg segment underflow fix (#806)
* Bring `claim_v2` changes from #707 into `c2pa_crypto` (#811)
* Improve usage of `#[cfg]` directives (#783)
* OOB read attempt in jpeg_io asset handler in get_cai_segments function (#719)
* Prevent negative length value for SVG object locations (#766)
* JPEG `write_cai` OOB insertion (#762)
* Add support XMP in SVG (#771)
* Possible overflow for TIFF (#760)
* Resolve new Clippy issues (#776)

### Updated dependencies

* Bump jfifdump from 0.5.1 to 0.6.0 (#785)
* Bump serde-wasm-bindgen from 0.5.0 to 0.6.5 (#786)
* Bump thiserror from 2.0.6 to 2.0.8 (#787)
* Bump rasn from 0.18.0 to 0.22.0 (#727)
* Bump thiserror from 1.0.69 to 2.0.6 (#770)

## [0.40.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.39.0...c2pa-v0.40.0)
_12 December 2024_

### Added

* Add `RawSigner` trait to `c2pa-crypto` (derived from `c2pa::Signer`) (#716)
* Move time stamp code into c2pa-crypto (#696)
* Adds ValidationState support (#701)
* Introduce `DynamicAssertion` trait (#566)

### Fixed

* Compile `c2pa-crypto` with `cargo check` (#768)
* Verbose assertions for `is_none()` (#704)
* Remove `c2pa::Signer` dependency on `c2pa_crypto::TimeStampProvider` (#718)
* Add support for MP3 without ID3 header (#652)
* Treat Unicode-3.0 license as approved; unpin related dependencies (#693)
* Remote manifest fetch test was not using full path (#675)
* Fix #624 (edge cases when combining the box hashes) (#625)
* Fix #672, Callback is unsound (#674)
* Support "remote_manifest_fetch" verify setting (#667)

### Updated dependencies

* Bump chrono from 0.4.38 to 0.4.39 (#763)
* Bump asn1-rs from 0.5.2 to 0.6.2 (#724)
* Bump mockall requirement from 0.11.2 to 0.13.1 in /sdk (#685)
* Update zip requirement from 0.6.6 to 2.2.1 in /sdk (#698)

## [0.39.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.38.0...c2pa-v0.39.0)
_13 November 2024_

### Added

* Factor status tracking infrastructure into its own crate ([#665](https://github.com/contentauth/c2pa-rs/pull/665))

### Fixed

* Fixed a typo in ManifestDefinition docstring ([#639](https://github.com/contentauth/c2pa-rs/pull/639))

## [0.38.0](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.37.1...c2pa-v0.38.0)
_06 November 2024_

### Added

* Add fragmented mp4 Builder and Reader support ([#649](https://github.com/contentauth/c2pa-rs/pull/649))
* Associate ingredients with actions using parameters.org.cai.ingredientsIds array ([#627](https://github.com/contentauth/c2pa-rs/pull/627))

### Fixed

* Stay on url version 2.5.2 until Unicode-3.0 license can be approved ([#654](https://github.com/contentauth/c2pa-rs/pull/654))

## [0.37.1](https://github.com/contentauth/c2pa-rs/compare/c2pa-v0.37.0...c2pa-v0.37.1)
_24 October 2024_

### Documented

* Update API documentation ([#621](https://github.com/contentauth/c2pa-rs/pull/621))

## [0.37.0](https://github.com/contentauth/c2pa-rs/compare/v0.36.4...v0.37.0)
_17 October 2024_

### Fixed

* Adds identified RangeType to region of interest ([#631](https://github.com/contentauth/c2pa-rs/pull/631))

## [0.36.4](https://github.com/contentauth/c2pa-rs/compare/v0.36.3...v0.36.4)
_15 October 2024_

### Fixed

* Harden SDK against attempting buffers that are too large ([#628](https://github.com/contentauth/c2pa-rs/pull/628))

## [0.36.3](https://github.com/contentauth/c2pa-rs/compare/v0.36.2...v0.36.3)
_07 October 2024_

### Fixed

* Changelog contained duplicate entries for 0.16.1 ([#618](https://github.com/contentauth/c2pa-rs/pull/618))

## [0.36.2](https://github.com/contentauth/c2pa-rs/compare/v0.36.1...v0.36.2)
_07 October 2024_

* No-op change to start using release-plz to manage releases

## 0.36.1
_04 October 2024_

* fix: Make sure algorithm is being respected in data_hash.rs ([#613](https://github.com/contentauth/c2pa-rs/pull/613))
* fix: Make sure RSTn segment names are included in the data box hashes list ([#612](https://github.com/contentauth/c2pa-rs/pull/612))
* Update mp4 requirement from 0.13.0 to 0.14.0 in /sdk ([#595](https://github.com/contentauth/c2pa-rs/pull/595))
* chore: Add m4a test ([#606](https://github.com/contentauth/c2pa-rs/pull/606))
* fix: Write absolute urls to manifest store resource references. ([#603](https://github.com/contentauth/c2pa-rs/pull/603))
* doc: Removes xmp_write feature from README.md.
* chore: Remove deprecated actions-rs/clippy-check action ([#601](https://github.com/contentauth/c2pa-rs/pull/601))
* chore: bump stefanzweifel/git-auto-commit-action from 4 to 5 ([#600](https://github.com/contentauth/c2pa-rs/pull/600))
* chore: bump actions/github-script from 3 to 7 ([#599](https://github.com/contentauth/c2pa-rs/pull/599))
* chore: bump paulhatch/semantic-version from 5.2.1 to 5.4.0 ([#598](https://github.com/contentauth/c2pa-rs/pull/598))
* chore: Use Dependabot to upgrade GitHub Actions steps ([#597](https://github.com/contentauth/c2pa-rs/pull/597))
* chore: Fix dependabot issues ([#594](https://github.com/contentauth/c2pa-rs/pull/594))
* Fixes issue where nested assertion-uri-hash errors were being reported at the active manifest level. ([#593](https://github.com/contentauth/c2pa-rs/pull/593))
* Feature/add content length to tsa request ([#587](https://github.com/contentauth/c2pa-rs/pull/587))

## 0.36.0
_23 September 2024_

* (MINOR) ensures release bumps minor version ([#592](https://github.com/contentauth/c2pa-rs/pull/592))
* fix: requires "StatusTracker" to implement "Send" ([#589](https://github.com/contentauth/c2pa-rs/pull/589))

## 0.35.1
_17 September 2024_

* Fix error when trying to sign BMFF content with Builder. ([#582](https://github.com/contentauth/c2pa-rs/pull/582))

## 0.35.0
_12 September 2024_

* upgrades to riff@2.0.0, preventing panic on invalid riff files ([#579](https://github.com/contentauth/c2pa-rs/pull/579))
* EC signature DER support ([#581](https://github.com/contentauth/c2pa-rs/pull/581))
* Update base64 requirement from 0.21.2 to 0.22.1 in /sdk ([#519](https://github.com/contentauth/c2pa-rs/pull/519))
* (MINOR) Rust API enhancements and fixes. ([#575](https://github.com/contentauth/c2pa-rs/pull/575))
* Fix GIF off by one with XMP ([#562](https://github.com/contentauth/c2pa-rs/pull/562))

## 0.34.0
_30 August 2024_

* (MINOR) Fragmented BMFF media ([#572](https://github.com/contentauth/c2pa-rs/pull/572))

## 0.33.4
_29 August 2024_

* Depend on url crate version 2.5.2 or newer ([#573](https://github.com/contentauth/c2pa-rs/pull/573))

## 0.33.3
_17 August 2024_

* Inline certs for wasm test signer ([#564](https://github.com/contentauth/c2pa-rs/pull/564))

## 0.33.2
_15 August 2024_

* Bmff write fix ([#552](https://github.com/contentauth/c2pa-rs/pull/552))
* Fix remote embedding RIFF when specifying mime type ([#551](https://github.com/contentauth/c2pa-rs/pull/551))
* Fix data hash out of bounds when using placeholder beyond stream length ([#546](https://github.com/contentauth/c2pa-rs/pull/546))
* Adds embeddable apis and remote_url/no_embed options ([#537](https://github.com/contentauth/c2pa-rs/pull/537))
* export_schema: add unstable_api feature ([#542](https://github.com/contentauth/c2pa-rs/pull/542))
* Ingredient checks ([#529](https://github.com/contentauth/c2pa-rs/pull/529))
* Add base_path field to Builder ([#539](https://github.com/contentauth/c2pa-rs/pull/539))
* Export `AssertionDefinition` and `ActionTemplate` in public API ([#522](https://github.com/contentauth/c2pa-rs/pull/522))

## 0.33.1
_30 July 2024_

* Use timestamp with OpenSSL validation to prevent check chain check er… ([#531](https://github.com/contentauth/c2pa-rs/pull/531))
* Fix GIF `remove_cai_store_from_stream` behavior ([#524](https://github.com/contentauth/c2pa-rs/pull/524))

## 0.33.0
_26 July 2024_

* Update crate to fix bad certificate dump content ([#525](https://github.com/contentauth/c2pa-rs/pull/525))
* Introduce a mutex around the FFI calls to OpenSSL ([#516](https://github.com/contentauth/c2pa-rs/pull/516))
* Bump bcder minimum version to 0.7.3 ([#526](https://github.com/contentauth/c2pa-rs/pull/526))
* (MINOR) Updates needed for v2 JavaScript SDK ([#521](https://github.com/contentauth/c2pa-rs/pull/521))
* Add region of interest assertion definition ([#506](https://github.com/contentauth/c2pa-rs/pull/506))
* Fix CI tests ([#520](https://github.com/contentauth/c2pa-rs/pull/520))
* Builder Archive update ([#507](https://github.com/contentauth/c2pa-rs/pull/507))
* Update range-set requirement from 0.0.9 to 0.0.11 in /sdk ([#442](https://github.com/contentauth/c2pa-rs/pull/442))
* Make sure reading past end of JUMBF box is an error ([#518](https://github.com/contentauth/c2pa-rs/pull/518))
* added final details ([#517](https://github.com/contentauth/c2pa-rs/pull/517))

## 0.32.7
_18 July 2024_

* Ensure Ingredient data_types make it to the store and back. ([#514](https://github.com/contentauth/c2pa-rs/pull/514))
* draft security md ([#508](https://github.com/contentauth/c2pa-rs/pull/508))
* Make data_types field optional when serializing data-box-map ([#512](https://github.com/contentauth/c2pa-rs/pull/512))
* Fix box hash placeholder len (set to 1) ([#511](https://github.com/contentauth/c2pa-rs/pull/511))
* Set data box placeholder len to at least 1 for GIF ([#510](https://github.com/contentauth/c2pa-rs/pull/510))
* Rewind mp3 streams when reading/writing ([#509](https://github.com/contentauth/c2pa-rs/pull/509))
* Update README.md ([#351](https://github.com/contentauth/c2pa-rs/pull/351))
* Add GIF support ([#489](https://github.com/contentauth/c2pa-rs/pull/489))
* Update image requirement from 0.24.7 to 0.25.1 in /make_test_images ([#445](https://github.com/contentauth/c2pa-rs/pull/445))
* Upgrade uuid to 1.7.0 & fix removed wasm-bindgen feature ([#450](https://github.com/contentauth/c2pa-rs/pull/450))
* Expose `SignatureInfo` publicly ([#501](https://github.com/contentauth/c2pa-rs/pull/501))
* Cleanup empty/unused files + lints ([#500](https://github.com/contentauth/c2pa-rs/pull/500))

## 0.32.6
_15 July 2024_

* Fetching of databoxes must always use HashedURI to enforce hash checks. ([#505](https://github.com/contentauth/c2pa-rs/pull/505))
* Temporarily allow unused `JsonAssertionData` to fix unused error in CI ([#498](https://github.com/contentauth/c2pa-rs/pull/498))
* Add remote manifest support to MP3 ([#496](https://github.com/contentauth/c2pa-rs/pull/496))

## 0.32.5
_28 June 2024_

* (PATCH) ensures temp files are removed ([#494](https://github.com/contentauth/c2pa-rs/pull/494))
* Update async_generic to 1.1 ([#493](https://github.com/contentauth/c2pa-rs/pull/493))

## 0.32.4
_25 June 2024_

* Add data_type (future) to Ingredient_V2 ([#490](https://github.com/contentauth/c2pa-rs/pull/490))
* Let's not assume that third-party assertions are using serde_cbor ([#491](https://github.com/contentauth/c2pa-rs/pull/491))

## 0.32.3
_24 June 2024_

* External placed manifest ([#472](https://github.com/contentauth/c2pa-rs/pull/472))
* Support metadata field in claims. ([#488](https://github.com/contentauth/c2pa-rs/pull/488))

## 0.32.2
_19 June 2024_

* Add iterators over manifests and resources in unstable API ([#482](https://github.com/contentauth/c2pa-rs/pull/482))
* OCSP certificate should be valid at signing time ([#481](https://github.com/contentauth/c2pa-rs/pull/481))
* url crate version 2.5.1 introduces new license "Unicode-3.0" ([#483](https://github.com/contentauth/c2pa-rs/pull/483))
* Implement `Debug` w/ detailed manifest for `Reader` ([#473](https://github.com/contentauth/c2pa-rs/pull/473))
* Bump MSRV to 1.74 ([#478](https://github.com/contentauth/c2pa-rs/pull/478))
* Allow empty Merkle proof for last leaf node. ([#470](https://github.com/contentauth/c2pa-rs/pull/470))

## 0.32.1
_10 May 2024_

* Steps toward removing RemoteSigner APIs. ([#466](https://github.com/contentauth/c2pa-rs/pull/466))

## 0.32.0
_07 May 2024_

* (Minor) Additional unit tests and fixes for injection (or previously untested) issues. ([#464](https://github.com/contentauth/c2pa-rs/pull/464))
* Expose authoring support in WASM ([#369](https://github.com/contentauth/c2pa-rs/pull/369))
* Move signer to first parameter on Builder.sign ([#457](https://github.com/contentauth/c2pa-rs/pull/457))
* Gpeacock/embed_remote_settings ([#460](https://github.com/contentauth/c2pa-rs/pull/460))
* (MINOR) Removes xmp_write feature and xmp_toolkit ([#461](https://github.com/contentauth/c2pa-rs/pull/461))
* Async Signer: add support for async OCSP call ([#458](https://github.com/contentauth/c2pa-rs/pull/458))
* Use cargo test in CI ([#459](https://github.com/contentauth/c2pa-rs/pull/459))
* (MINOR) Initial V2 API work ([#437](https://github.com/contentauth/c2pa-rs/pull/437))

## 0.31.3
_05 April 2024_

* Add `video/quicktime` to the list of BMFF MIME types ([#441](https://github.com/contentauth/c2pa-rs/pull/441))
* Streaming XMP write support for PNG ([#439](https://github.com/contentauth/c2pa-rs/pull/439))

## 0.31.2
_03 April 2024_

* Fixed temp file auto delete ([#438](https://github.com/contentauth/c2pa-rs/pull/438))
* Add `Sync` trait to `TrustHandlerConfig` ([#440](https://github.com/contentauth/c2pa-rs/pull/440))
* remove file_io dependency on fetch_remote_manifests ([#434](https://github.com/contentauth/c2pa-rs/pull/434))
* Remove verify after signing when compiling without openssl ([#404](https://github.com/contentauth/c2pa-rs/pull/404))
* Streaming write support for BMFF ([#435](https://github.com/contentauth/c2pa-rs/pull/435))
* Added support for XMP streaming writes for TIFF/DNG ([#433](https://github.com/contentauth/c2pa-rs/pull/433))
* Implements embed_reference_to_stream for jpeg ([#430](https://github.com/contentauth/c2pa-rs/pull/430))

## 0.31.1
_25 March 2024_

* Adds Action changes field as option vec of serde_json value ([#431](https://github.com/contentauth/c2pa-rs/pull/431))

## 0.31.0
_13 March 2024_

* (MINOR) Adds Send trait to TrustHandlerConfig ([#426](https://github.com/contentauth/c2pa-rs/pull/426))

## 0.30.3
_12 March 2024_

* Roll back rasn-* version requirements since 0.12.6 was yanked ([#425](https://github.com/contentauth/c2pa-rs/pull/425))

## 0.30.2
_12 March 2024_

* Adds a Manifest::composed manifest method ([#424](https://github.com/contentauth/c2pa-rs/pull/424))
* Allow cert dump to work in WASM ([#420](https://github.com/contentauth/c2pa-rs/pull/420))
* Update minimum dependency of rasn-* crates ([#423](https://github.com/contentauth/c2pa-rs/pull/423))

## 0.30.1
_08 March 2024_

* Fix include_byte references that were not available in external crate builds

## 0.30.0
_08 March 2024_

* (MINOR) Remove testing function that was inadvertently public ([#421](https://github.com/contentauth/c2pa-rs/pull/421))

## 0.29.3
_08 March 2024_

* Trust support ([#415](https://github.com/contentauth/c2pa-rs/pull/415))

## 0.29.2
_08 March 2024_

* add a thumb resource when referencing an embedded uri ([#419](https://github.com/contentauth/c2pa-rs/pull/419))

## 0.29.1
_07 March 2024_

* Adds Manifest.remote_manifest_url() (CAI-5437) ([#418](https://github.com/contentauth/c2pa-rs/pull/418))
* Fix use of deprecated method `chrono::NaiveDateTime::timestamp` ([#417](https://github.com/contentauth/c2pa-rs/pull/417))
* Fix up some random typos. ([#353](https://github.com/contentauth/c2pa-rs/pull/353))

## 0.29.0
_26 February 2024_

* SDK configuration settings support (infrastructure) ([#408](https://github.com/contentauth/c2pa-rs/pull/408))
* Support streaming writes for TIFF ([#410](https://github.com/contentauth/c2pa-rs/pull/410))
* Fixed typo in comment ([#409](https://github.com/contentauth/c2pa-rs/pull/409))
* (MINOR) Update `xmp_toolkit` to v1.7.1, remove Ring dependency, fix build errors ([#407](https://github.com/contentauth/c2pa-rs/pull/407))
* Crate udate to fix jpeg parsing error ([#402](https://github.com/contentauth/c2pa-rs/pull/402))
* allows builds to pass ([#403](https://github.com/contentauth/c2pa-rs/pull/403))
* Ocsp support ([#371](https://github.com/contentauth/c2pa-rs/pull/371))

## 0.28.5
_06 February 2024_

* Finish async signing implementation for cose_sign ([#370](https://github.com/contentauth/c2pa-rs/pull/370))
* adds read_cai test for PDF with content credentials ([#366](https://github.com/contentauth/c2pa-rs/pull/366))
* [IGNORE] README edits ([#356](https://github.com/contentauth/c2pa-rs/pull/356))
* Update ci.yml
* Remove deprecated twoway crate ([#361](https://github.com/contentauth/c2pa-rs/pull/361))
* Fix response strings for BMFF and Box hash statuses ([#360](https://github.com/contentauth/c2pa-rs/pull/360))
* Restore correct 1.3 CoseSign1 headers ([#359](https://github.com/contentauth/c2pa-rs/pull/359))
* Openssl update to version 3.x ([#357](https://github.com/contentauth/c2pa-rs/pull/357))
* Add support for ARW and NEF ([#355](https://github.com/contentauth/c2pa-rs/pull/355))

## 0.28.4
_04 December 2023_

* CAI-5041 Clear Windows temp attribute ([#352](https://github.com/contentauth/c2pa-rs/pull/352))

## 0.28.3
_22 November 2023_

* Remove Blake3 dependency from c2pa-rs ([#348](https://github.com/contentauth/c2pa-rs/pull/348))

## 0.28.2
_21 November 2023_

* Fix PDF reading of manifest from wrong key ([#346](https://github.com/contentauth/c2pa-rs/pull/346))

## 0.28.1
_17 November 2023_

* readme update ([#345](https://github.com/contentauth/c2pa-rs/pull/345))
* Add support for embeddable manifests with RemoteSigner ([#344](https://github.com/contentauth/c2pa-rs/pull/344))
* Blake build fix ([#343](https://github.com/contentauth/c2pa-rs/pull/343))
* Update image crate dependency and limit features ([#341](https://github.com/contentauth/c2pa-rs/pull/341))
* Bump xmp_toolkit requirement to 1.6 ([#339](https://github.com/contentauth/c2pa-rs/pull/339))
* Disable Windows builds with latest Rust version ([#342](https://github.com/contentauth/c2pa-rs/pull/342))

## 0.28.0
_01 November 2023_

* (PATCH) switches af relationship for a reference to the c2pa data to an array of references, one of which is the c2pa spec ([#333](https://github.com/contentauth/c2pa-rs/pull/333))
* Restore async versions of embed functions ([#327](https://github.com/contentauth/c2pa-rs/pull/327))
* (MINOR) Support databox thumbnails CAI-4142 ([#325](https://github.com/contentauth/c2pa-rs/pull/325))
* (MINOR) Reuse claim thumbnail as ingredient thumbnail if the store is valid ([#322](https://github.com/contentauth/c2pa-rs/pull/322))
* (MINOR) Use JUMBF URIs for ManifestStore identifiers ([#323](https://github.com/contentauth/c2pa-rs/pull/323))
* Add ManifestStore::from_stream ([#319](https://github.com/contentauth/c2pa-rs/pull/319))
* Adds embed_to_stream ([#313](https://github.com/contentauth/c2pa-rs/pull/313))

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
