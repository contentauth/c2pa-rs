# C2PA Rust library

[![CI](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/contentauth/c2pa-rs/actions/workflows/ci.yml) [![Latest Version](https://img.shields.io/crates/v/c2pa.svg)](https://crates.io/crates/c2pa) [![docs.rs](https://img.shields.io/docsrs/c2pa)](https://docs.rs/c2pa/) [![codecov](https://codecov.io/gh/contentauth/c2pa-rs/branch/main/graph/badge.svg?token=YVHWI19EGN)](https://codecov.io/gh/contentauth/c2pa-rs)

<div style={{display: 'none'}}>

The **[Coalition for Content Provenance and Authenticity](https://c2pa.org)** (C2PA) addresses the prevalence of misleading information online through the development of technical standards for certifying the source and history (or provenance) of media content. Adobe and other contributors created the C2PA Rust library as part of the [Content Authenticity Initiative](https://contentauthenticity.org) and [released it to open source](https://contentauthenticity.org/blog/cai-releases-suite-of-open-source-tools-to-advance-digital-content-provenance) in June, 2022.

</div>

## Key features

The C2PA Rust library (previously referred to as the "Rust SDK") implements a subset of the [C2PA technical specification](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html).

The library enables a desktop, mobile, or embedded application to:
* Create and sign C2PA [claims](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_claims) and [manifests](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_manifests).
* Embed manifests in certain file formats.
* Parse and validate manifests found in certain file formats.

The library supports several common C2PA [assertions](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_c2pa_standard_assertions) and [hard bindings](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_hard_bindings).

## State of the project

This is a beta release (version 0.x.x) of the project. The minor version number (0.x.0) is incremented when there are breaking API changes, which may happen frequently.

### Contributions and feedback

We welcome contributions to this project.  For information on contributing, providing feedback, and about ongoing work, see [Contributing](https://github.com/contentauth/c2pa-js/blob/main/CONTRIBUTING.md).

## Requirements

The library requires **Rust version 1.73.0** or newer.

### Supported platforms

The library has been tested on the following operating systems:

* Windows (Intel only)
* MacOS (Intel and Apple silicon)
* Ubuntu Linux (64-bit Intel and ARM v8)
* WebAssembly (Wasm)

## Supported file formats

 | Extensions    | MIME type                                           |
 | ------------- | --------------------------------------------------- |
 | `avi`         | `video/msvideo`, `video/avi`, `application-msvideo` |
 | `avif`        | `image/avif`                                        |
 | `c2pa`        | `application/x-c2pa-manifest-store`                 |
 | `dng`         | `image/x-adobe-dng`                                 |
 | `heic`        | `image/heic`                                        |
 | `heif`        | `image/heif`                                        |
 | `jpg`, `jpeg` | `image/jpeg`                                        |
 | `m4a`         | `audio/mp4`                                         |
 | `mp4`         | `video/mp4`, `application/mp4`                      |
 | `mov`         | `video/quicktime`                                   |
 | `png`         | `image/png`                                         |
 | `svg`         | `image/svg+xml`                                     |
 | `tif`,`tiff`  | `image/tiff`                                        |
 | `wav`         | `audio/wav`                                         |
 | `webp`        | `image/webp`                                        |

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
c2pa = "0.28.5"
```

If you want to read or write a manifest file, add the `file_io` dependency to your `Cargo.toml`.
The `add_thumbnails` feature will generate thumbnails for JPEG and PNG files.
 For example:
```
c2pa = { version = "0.25.0", features = ["file_io", "add_thumbnails"] }
```

NOTE: If you are building for WASM, omit the `file_io` dependency.

## Crate features

The Rust library crate provides:

* `file_io` enables manifest generation, signing via OpenSSL, and embedding manifests in various file formats.
* `add_thumbnails` will generate thumbnails automatically for JPEG and PNG files. (no longer included with `file_io`)
* `serialize_thumbnails` includes binary thumbnail data in the [Serde](https://serde.rs/) serialization output.
* `xmp_write` enables updating XMP on embed with the `dcterms:provenance` field. (Requires [xmp_toolkit](https://crates.io/crates/xmp_toolkit).)
* `no_interleaved_io` forces fully-synchronous I/O; otherwise, the library uses threaded I/O for some operations to improve performance.
* `fetch_remote_manifests` enables the verification step to retrieve externally referenced manifest stores.  External manifests are only fetched if there is no embedded manifest store and no locally adjacent .c2pa manifest store file of the same name.
* `json_schema` is used by `make schema` to produce a JSON schema document that represents the `ManifestStore` data structures.
* `fetch_ocsp_response` if the feature is enabled, during manifest validation if an OCSP response is not present in the manifest we will attempt a network call to fetch it.  OCSP is used to check the revocation status of the manifest signing certificate.  
* `psxxx_ocsp_stapling_experimental` this is an demonstration feature that will attempt to fetch the OCSP data from the OCSP responders listed in the manifest signing certificate.  The response becomes part of the manifest and is used to prove the certificate was not revoked at the time of signing.  This is only implemented for PS256, PS384 and PS512 signatures and is intended as a demonstration.


## Example code

The [sdk/examples](https://github.com/contentauth/c2pa-rs/tree/main/sdk/examples) directory contains some minimal example code.  The [client/client.rs](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/client/client.rs) is the most instructive and provides and example of reading the contents of a manifest store, recursively displaying nested manifests.

## License

The `c2pa` crate is distributed under the terms of both the [MIT license](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-MIT) and the [Apache License (Version 2.0)](https://github.com/contentauth/c2pa-rs/blob/main/LICENSE-APACHE).

Some components and dependent crates are licensed under different terms; please check the license terms for each crate and component for details.

## Nightly builds

In most cases, you should depend on this crate as published via [crates.io](https://crates.io/crates/c2pa).

The Adobe team produces nightly snapshots of this crate via a `nightly` branch, which we use for testing the impact of pending changes to upstream dependencies.

You may wish to use these builds for your own testing ahead of our releases, you may include the library via the following `Cargo.toml` entry:

```toml
c2pa = { git = "https://github.com/contentauth/c2pa-rs.git", branch = "nightly", features = [...]}
```

Commits in this branch have a modified `sdk/Cargo.toml` entry which includes a version number similar to the following:

```toml
version = "0.25.3-nightly+2023-08-28-2f33ab3"
```

Please note that there is no formal support for code from a nightly release, but if you become aware of any issues, we would appreciate a bug report including this version number.

## Release notes

This section gives a highlight of noteworthy changes.

Refer to the [CHANGELOG](https://github.com/contentauth/c2pa-rs/blob/main/CHANGELOG.md) for detailed changes derived from Git commit history.

### 0.29.0

_17 November 2023_
* PDF read support
* MP3 support
* new and enhanced manifest APIs
* thumbnail databox support
* bug fixes and optimizations

### 0.25.0

_14 July 2023_
* (important!) the `add_thumbnails` feature is no longer tied to `file_io`, so you will need to specify it or thumbnails will not be generated.
* removed `User` and `UserCbor` assertions from public API. They were not generating correct manifest data.
* use `manifest_add_labeled_assertion` instead - see docs on `manifest.embed` for an example.
* `DataHash` and `BoxHash` library support (generates a signed manifest ready to write into a file without writing to the file)
* The library will no longer remove duplicate ingredients based on hash
* `make_test_images` updated to fix issue 195, actions without required ingredients
* updated the test fixtures generated by make_test_images
* Expose `CAIRead` and `CAIWrite` traits required by some library calls.
* Bug fix for certain BMFF formats (AVIF) that causes images to be unreadable

### 0.24.0

_21 June 2023_
* Bump minor version to 0.24.0 to signify change in signature (back to the compatible one)
* Reverts to 1.2 Cose signatures when signing while still validating 1.3 Cose signatures
* We want to allow some time for clients to upgrade to validating 1.3 before writing this breaking change.
* Fix embed_from_memory to correctly return the updated image
* includes the cert serial number in the ValidationInfo output
* support adding claim_generator_info field
* support Actions V2 and Ingredients V2
* BMFF V2
* Json Schema generation

### 0.19.0

_23 March 2023_

* Added support for many new file formats, see Supported File Formats above.
* New api to return supported formats.
* Streaming APIs for manifest creation without file_io for some formats.
* Manifest and Ingredient JSON formats replace the `is_parent` field with `relationship`.
* ResourceRef replaces `content-type` with `format`.
* The `bmff` feature no longer required.
