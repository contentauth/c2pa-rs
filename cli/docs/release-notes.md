# Release notes

This page highlights noteworthy changes in each release.

Refer to the [CHANGELOG](https://github.com/contentauth/c2patool/blob/main/CHANGELOG.md) for detailed Git changes.

## 0.9.x

* Update c2pa-rs for RegionOfInterest support. ([#269](https://github.com/contentauth/c2patool/pull/269))
* Fix broken link that was causing os site workflow to fail ([#266](https://github.com/contentauth/c2patool/pull/266))
* Document fragment subcommand ([#236](https://github.com/contentauth/c2patool/pull/236))
* Initial fragment support ([#230](https://github.com/contentauth/c2patool/pull/230))
* Add warning about accessing a private key directly ([#218](https://github.com/contentauth/c2patool/pull/218))
* Update c2patool with c2pa-rs fixes ([#190](https://github.com/contentauth/c2patool/pull/190)):
    - Merkle trees with empty proofs
    - Support for missing metadata for Claims object
    - OCSP fixes
* Document how to specify an icon ([#182](https://github.com/contentauth/c2patool/pull/182))
* Add better support for cargo-binstall ([#177](https://github.com/contentauth/c2patool/pull/177))
* Add HTTP source option for trust config ([#174](https://github.com/contentauth/c2patool/pull/174))

## 0.8.x

* fixed c2patool asset name ([#171](https://github.com/contentauth/c2patool/pull/171))
* Allow clients to sign with a process outside of c2patool ([#169](https://github.com/contentauth/c2patool/pull/169))
* Add trust and verification options to c2pa_tool ([#168](https://github.com/contentauth/c2patool/pull/168))
* Add version to c2patool artifact names ([#158](https://github.com/contentauth/c2patool/pull/158))

## 0.7.x

* Update to c2pa-rs v0.28.2 ([#153](https://github.com/contentauth/c2patool/pull/153))
* Fix windows release ([#132](https://github.com/contentauth/c2patool/pull/132))
* Use compress-archive instead of tar ([#130](https://github.com/contentauth/c2patool/pull/130))

## 0.6.0

* Validates 1.3 signatures but will not generate them.
* Supports other 1.3 features such as actions v2 and ingredients v2.
* Supports adding `claim_generator_info` to a manifest.
* Icons for `claim_generator_info` can be added as resource references.
* The SDK will create v2 actions or ingredients if required, but defaults to v1.

## 0.5.4

NOTE: This release introduced a 1.3 required change in signature format that is not compatible with previous verify code.
We want to give some time for developers to integrate 1.3 validation before using 1.3 signatures.
Please avoid using 0.5.4 and update to 0.6.0 which can validate the new format but does not create it.

## 0.5.3

* Fixes a bug where ingredient thumbnails were not generated.
* You can now pass an `ingredient.json` file or folder using the command line `--parent` option. If a folder is passed as an ingredient, the tool will look for an ingredient.json fle in that folder.
* Fixes `--parent` is no longer relative to the `--manifest` path

## 0.5.2

* Removes manifest preview feature
* Tests for similar extensions
* Adds `.svg` support

## 0.5.1

* Updates the sample certs which had expired
* Updates to the README for 0.5.0 changes

## 0.5.0

* Adds support for many new file formats, see [supported file formats](https://opensource.contentauthenticity.org/docs/c2patool/#supported-file-formats).
* Manifests and Ingredients can read and write thumbnail and c2pa resource files.
* Adds `-i/--ingredient` option to generate an ingredient report or folder.
* Changes to Manifest Definition:
    * `ingredients` now requires JSON Ingredient definitions.
	* `ingredient_paths` accepts file paths, including JSON Ingredient definitions.
    * `base_path` no longer supported. File paths are relative to the containing JSON file.
